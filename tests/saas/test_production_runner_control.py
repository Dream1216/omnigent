from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from omnigent.runner.identity import token_bound_runner_id
from saas.control_plane.execution import RunLease, RunMutation
from saas.control_plane.preview_tunnel_registration import (
    PreviewTunnelRegistrationGrant,
)
from saas.control_plane.runner_execution_spec import managed_execution_spec
from saas.control_plane.scheduling import (
    FairRunLease,
    RunnerExecutionEnvelope,
    SchedulingError,
    VerifiedCapability,
)
from saas.production.runner_control import (
    MutualTlsRunnerControlClient,
    MutualTlsRunnerControlServer,
    ProductionRunnerMachineAuthority,
    RunnerControlError,
    RunnerControlPolicy,
    TlsRunnerControlReadinessServer,
    load_production_runner_control_config,
    verify_installed_runner_control_lineage,
)
from saas.production.runner_readiness import (
    RemoteTlsRunnerControlReadiness,
    RunnerReadinessError,
    build_remote_tls_runner_control_readiness,
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
RUNNER_ID = UUID("10000000-0000-4000-8000-000000000001")
RUN_ID = UUID("20000000-0000-4000-8000-000000000002")
LEASE_TOKEN = UUID("30000000-0000-4000-8000-000000000003")
CAPABILITY_ID = UUID("40000000-0000-4000-8000-000000000004")
CONNECTION_TOKEN = "runner-connection-token-" + "x" * 40
CAPABILITY_TOKEN = "runner-capability-token-" + "y" * 40
EXECUTION_SPEC = managed_execution_spec(
    kind="omnigent.agent.v1",
    agent_path="agents/review.yaml",
    prompt="Review the managed change set",
)
ENVELOPE = RunnerExecutionEnvelope(
    change_set_id=UUID("50000000-0000-4000-8000-000000000005"),
    tenant_id=UUID("60000000-0000-4000-8000-000000000006"),
    space_id=UUID("70000000-0000-4000-8000-000000000007"),
    project_id=UUID("80000000-0000-4000-8000-000000000008"),
    run_id=RUN_ID,
    runner_id=RUNNER_ID,
    fence_token=7,
    execution_profile_id=UUID("90000000-0000-4000-8000-000000000009"),
    execution_profile_hash="a" * 64,
    egress_policy_id=UUID("a0000000-0000-4000-8000-00000000000a"),
    egress_policy_hash="b" * 64,
    product_revision="c" * 40,
    image_digest="sha256:" + "d" * 64,
    execution_spec_hash=EXECUTION_SPEC.spec_hash,
    launch_argv=EXECUTION_SPEC.launch_argv,
)


def test_control_config_rejects_product_source_revision_drift() -> None:
    with pytest.raises(RunnerControlError, match="release identity"):
        load_production_runner_control_config(
            {
                "OMNIGENT_SAAS_PRODUCT_REVISION": "a" * 40,
                "OMNIGENT_SAAS_SOURCE_SHA": "b" * 40,
                "OMNIGENT_SAAS_IMAGE_DIGEST": "sha256:" + "c" * 64,
            }
        )


def test_runner_control_rejects_wrong_installed_build_before_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from omnigent import _build_info

    monkeypatch.setattr(_build_info, "COMMIT_SHA", "a" * 40)
    config = SimpleNamespace(product_revision="b" * 40)
    with pytest.raises(RunnerControlError, match="installed build revision does not match"):
        verify_installed_runner_control_lineage(config)  # type: ignore[arg-type]

    config.product_revision = "a" * 40
    verify_installed_runner_control_lineage(config)  # type: ignore[arg-type]


class _Scheduling:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def heartbeat_runner(self, **values) -> str:
        self.calls.append(("heartbeat_runner", values))
        if values["connection_token"] != CONNECTION_TOKEN:
            raise SchedulingError("runner_connection_stale", "stale")
        return "online"

    def claim_fair_run(self, **values) -> FairRunLease:
        self.calls.append(("claim_fair_run", values))
        return FairRunLease(
            run_id=RUN_ID,
            runner_id=RUNNER_ID,
            lease_token=LEASE_TOKEN,
            fence_token=7,
            dispatch_generation=3,
            failure_domain="cn-east-1a",
            expires_at=NOW + timedelta(seconds=45),
            capability_id=CAPABILITY_ID,
            capability_token=CAPABILITY_TOKEN,
            execution_envelope=ENVELOPE,
        )

    def verify_capability(self, **values) -> VerifiedCapability:
        self.calls.append(("verify_capability", values))
        return VerifiedCapability(
            capability_id=CAPABILITY_ID,
            run_id=RUN_ID,
            runner_id=RUNNER_ID,
            tenant_id=uuid4(),
            space_id=uuid4(),
            project_id=uuid4(),
            fence_token=7,
            allowed_actions=("run.execute",),
            resource_scope={},
            expires_at=NOW + timedelta(seconds=45),
        )

    def release_dispatch(self, **values) -> bool:
        self.calls.append(("release_dispatch", values))
        return False

    def authenticated_run_heartbeat(self, execution, **values) -> RunLease:
        self.calls.append(("authenticated_run_heartbeat", values))
        if values["connection_token"] != CONNECTION_TOKEN:
            raise SchedulingError("runner_connection_stale", "stale")
        return execution.heartbeat(
            run_id=values["run_id"],
            lease_token=values["lease_token"],
            fence_token=values["fence_token"],
            lease_duration=values["lease_duration"],
        )

    def authenticated_run_transition(self, execution, **values) -> RunMutation:
        self.calls.append(("authenticated_run_transition", values))
        return execution.transition_run(
            run_id=values["run_id"],
            lease_token=values["lease_token"],
            fence_token=values["fence_token"],
            target_status=values["target_status"],
            payload=None,
            trace_id=values["trace_id"],
        )


class _Execution:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def heartbeat(self, **values) -> RunLease:
        self.calls.append(("heartbeat", values))
        return RunLease(
            run_id=RUN_ID,
            lease_token=LEASE_TOKEN,
            fence_token=7,
            status="running",
            expires_at=NOW + timedelta(seconds=45),
            version=8,
        )

    def transition_run(self, **values) -> RunMutation:
        self.calls.append(("transition_run", values))
        return RunMutation(
            run_id=RUN_ID,
            status=str(values["target_status"]),
            version=9,
            event_sequence=11,
        )


def test_domain_uses_server_owned_lease_scope_and_existing_fenced_authorities() -> None:
    scheduling = _Scheduling()
    execution = _Execution()
    authority = ProductionRunnerMachineAuthority(  # type: ignore[arg-type]
        scheduling,
        execution,
        policy=RunnerControlPolicy(
            lease_duration=timedelta(seconds=45),
            heartbeat_timeout=timedelta(seconds=20),
        ),
    )

    lease = authority.claim_run(
        runner_id=RUNNER_ID,
        connection_generation=2,
        connection_token=CONNECTION_TOKEN,
    )
    assert lease is not None
    claim = scheduling.calls[-1][1]
    assert claim["capability_actions"] == (
        "preview.serve",
        "run.execute",
        "sandbox.launch",
        "worktree.read",
        "worktree.write",
    )
    assert claim["capability_resource_scope"] == {"control_plane": "runner_control"}
    assert claim["lease_duration"] == timedelta(seconds=45)
    assert claim["heartbeat_timeout"] == timedelta(seconds=20)

    heartbeat = authority.heartbeat_run(
        runner_id=RUNNER_ID,
        connection_generation=2,
        connection_token=CONNECTION_TOKEN,
        run_id=RUN_ID,
        lease_token=LEASE_TOKEN,
        fence_token=7,
        capability_token=CAPABILITY_TOKEN,
    )
    assert heartbeat.version == 8
    assert scheduling.calls[-1][0] == "authenticated_run_heartbeat"
    assert execution.calls[-1][1]["lease_duration"] == timedelta(seconds=45)

    transition = authority.transition_run(
        runner_id=RUNNER_ID,
        connection_generation=2,
        connection_token=CONNECTION_TOKEN,
        run_id=RUN_ID,
        lease_token=LEASE_TOKEN,
        fence_token=7,
        capability_token=CAPABILITY_TOKEN,
        target_status="succeeded",
    )
    assert transition.version == 9
    assert execution.calls[-1][1]["trace_id"] == f"runner:{RUNNER_ID}"
    assert execution.calls[-1][1]["payload"] is None

    replayed = authority.release_run(
        runner_id=RUNNER_ID,
        connection_generation=2,
        connection_token=CONNECTION_TOKEN,
        run_id=RUN_ID,
        fence_token=7,
    )
    assert not replayed
    assert scheduling.calls[-1][1]["requeue"] is False


def test_domain_rejects_runner_selected_transition_and_stale_connection() -> None:
    scheduling = _Scheduling()
    authority = ProductionRunnerMachineAuthority(  # type: ignore[arg-type]
        scheduling, _Execution()
    )

    with pytest.raises(RunnerControlError, match="denied"):
        authority.transition_run(
            runner_id=RUNNER_ID,
            connection_generation=2,
            connection_token=CONNECTION_TOKEN,
            run_id=RUN_ID,
            lease_token=LEASE_TOKEN,
            fence_token=7,
            capability_token=CAPABILITY_TOKEN,
            target_status="queued",
        )
    with pytest.raises(SchedulingError) as stale:
        authority.heartbeat_run(
            runner_id=RUNNER_ID,
            connection_generation=2,
            connection_token="wrong-connection-token-" + "z" * 40,
            run_id=RUN_ID,
            lease_token=LEASE_TOKEN,
            fence_token=7,
            capability_token=CAPABILITY_TOKEN,
        )
    assert stale.value.code == "runner_connection_stale"


@dataclass(frozen=True, slots=True)
class _CertificateFiles:
    ca: Path
    certificate: Path
    private_key: Path


def _write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _certificates(
    root: Path,
    *,
    runner_id: UUID,
    extra_runner_uri: bool = False,
) -> dict[str, _CertificateFiles]:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Runner Control Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = root / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def issue(
        name: str,
        *,
        san: x509.SubjectAlternativeName,
        eku: ObjectIdentifier,
    ) -> _CertificateFiles:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(minutes=1))
            .not_valid_after(NOW + timedelta(minutes=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(san, critical=False)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        certificate_path = root / f"{name}.pem"
        key_path = root / f"{name}-key.pem"
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        _write_private_key(key_path, key)
        return _CertificateFiles(ca_path, certificate_path, key_path)

    values = {
        "server": issue(
            "runner-control",
            san=x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            eku=ExtendedKeyUsageOID.SERVER_AUTH,
        )
    }
    uris = [x509.UniformResourceIdentifier(f"spiffe://omnigent/runner/{runner_id}")]
    if extra_runner_uri:
        uris.append(x509.UniformResourceIdentifier("spiffe://omnigent/runner/extra"))
    values["runner"] = issue(
        "runner",
        san=x509.SubjectAlternativeName(uris),
        eku=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    return values


def _server_context(files: _CertificateFiles) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(files.ca))
    context.load_cert_chain(str(files.certificate), str(files.private_key))
    return context


def _readiness_server_context(files: _CertificateFiles) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(str(files.certificate), str(files.private_key))
    return context


def _client_context(files: _CertificateFiles) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(files.ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(files.certificate), str(files.private_key))
    return context


class _CertificateAuthorizer:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[UUID, str, int]] = []

    def is_runner_machine_certificate_authorized(
        self,
        *,
        runner_id: UUID,
        certificate_der: bytes,
        purpose: str,
    ) -> bool:
        self.calls.append((runner_id, purpose, len(certificate_der)))
        return self.allowed


class _TransportAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, UUID, dict[str, object]]] = []

    def heartbeat_runner(self, *, runner_id: UUID, **values) -> str:
        self.calls.append(("heartbeat_runner", runner_id, values))
        return "online"

    def claim_run(self, *, runner_id: UUID, **values) -> FairRunLease:
        self.calls.append(("claim_run", runner_id, values))
        return FairRunLease(
            RUN_ID,
            runner_id,
            LEASE_TOKEN,
            7,
            3,
            "cn-east-1a",
            NOW + timedelta(seconds=45),
            CAPABILITY_ID,
            CAPABILITY_TOKEN,
            ENVELOPE,
        )

    def heartbeat_run(self, *, runner_id: UUID, **values) -> RunLease:
        self.calls.append(("heartbeat_run", runner_id, values))
        return RunLease(RUN_ID, LEASE_TOKEN, 7, "running", NOW + timedelta(seconds=45), 8)

    def transition_run(self, *, runner_id: UUID, **values) -> RunMutation:
        self.calls.append(("transition_run", runner_id, values))
        return RunMutation(RUN_ID, str(values["target_status"]), 9, 11)

    def release_run(self, *, runner_id: UUID, **values) -> bool:
        self.calls.append(("release_run", runner_id, values))
        return False

    def mint_preview_tunnel(self, *, runner_id: UUID, **values) -> PreviewTunnelRegistrationGrant:
        self.calls.append(("mint_preview_tunnel", runner_id, values))
        token = "preview-registration-" + "z" * 40
        issued_at = datetime.now(timezone.utc).replace(microsecond=0)
        return PreviewTunnelRegistrationGrant(
            registration_id=uuid4(),
            runner_id=runner_id,
            connection_generation=int(values["connection_generation"]),
            placement_id=uuid4(),
            official_runner_id=token_bound_runner_id(token),
            endpoint_host="owner.preview.svc.cluster.local",
            endpoint_port=9442,
            server_name="owner.preview.svc.cluster.local",
            audience="owner.preview.svc.cluster.local",
            registration_token=token,
            expires_at=issued_at + timedelta(seconds=60),
        )


@pytest.mark.asyncio
async def test_mtls_transport_derives_runner_and_carries_fenced_lifecycle(tmp_path: Path) -> None:
    certificates = _certificates(tmp_path, runner_id=RUNNER_ID)
    authority = _TransportAuthority()
    certificates_authority = _CertificateAuthorizer()
    server = MutualTlsRunnerControlServer(  # type: ignore[arg-type]
        authority,
        _server_context(certificates["server"]),
        certificates_authority,
    )
    await server.start()
    client = MutualTlsRunnerControlClient(
        connect_host="localhost",
        port=server.port,
        server_name="localhost",
        tls_context=_client_context(certificates["runner"]),
        connection_generation=2,
        connection_token=CONNECTION_TOKEN,
    )
    try:
        assert await client.heartbeat_runner() == "online"
        lease = await client.claim_run()
        assert lease is not None
        heartbeat = await client.heartbeat_run(lease)
        transition = await client.transition_run(lease, target_status="succeeded")
        assert not await client.release_run(lease)
        preview_tunnel = await client.mint_preview_tunnel()
    finally:
        await server.aclose()

    assert heartbeat["run_version"] == 8
    assert transition["run_version"] == 9
    assert [name for name, _, _ in authority.calls] == [
        "heartbeat_runner",
        "claim_run",
        "heartbeat_run",
        "transition_run",
        "release_run",
        "mint_preview_tunnel",
    ]
    assert all(runner_id == RUNNER_ID for _, runner_id, _ in authority.calls)
    assert certificates_authority.calls
    assert all(purpose == "runner_control" for _, purpose, _ in certificates_authority.calls)
    assert "runner_id" not in authority.calls[0][2]
    assert authority.calls[1][2] == {
        "connection_generation": 2,
        "connection_token": CONNECTION_TOKEN,
    }
    assert preview_tunnel.runner_id == RUNNER_ID
    assert preview_tunnel.connection_generation == 2
    assert preview_tunnel.official_runner_id == token_bound_runner_id(
        preview_tunnel.registration_token
    )
    mint_values = authority.calls[-1][2]
    assert set(mint_values) == {
        "certificate_fingerprint_sha256",
        "connection_generation",
        "connection_token",
    }


@pytest.mark.asyncio
async def test_server_readiness_uses_tls13_server_auth_without_runner_identity(
    tmp_path: Path,
) -> None:
    certificates = _certificates(tmp_path, runner_id=RUNNER_ID)
    server = TlsRunnerControlReadinessServer(
        _readiness_server_context(certificates["server"]),
        lambda: None,
    )
    await server.start()
    ready = RemoteTlsRunnerControlReadiness(
        connect_host="localhost",
        port=server.port,
        server_name="localhost",
        ca_certificate_path=certificates["server"].ca,
    )
    wrong_name = RemoteTlsRunnerControlReadiness(
        connect_host="localhost",
        port=server.port,
        server_name="wrong.internal",
        ca_certificate_path=certificates["server"].ca,
    )
    try:
        await asyncio.to_thread(ready.assert_production_ready)
        with pytest.raises(RunnerReadinessError, match="TLS readiness"):
            await asyncio.to_thread(wrong_name.assert_production_ready)
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_server_readiness_fails_closed_without_exposing_probe_error(
    tmp_path: Path,
) -> None:
    certificates = _certificates(tmp_path, runner_id=RUNNER_ID)

    def unavailable() -> None:
        raise RuntimeError("database-secret-must-not-cross-boundary")

    server = TlsRunnerControlReadinessServer(
        _readiness_server_context(certificates["server"]),
        unavailable,
    )
    await server.start()
    ready = RemoteTlsRunnerControlReadiness(
        connect_host="localhost",
        port=server.port,
        server_name="localhost",
        ca_certificate_path=certificates["server"].ca,
    )
    try:
        with pytest.raises(RunnerReadinessError, match="response is invalid") as denied:
            await asyncio.to_thread(ready.assert_production_ready)
    finally:
        await server.aclose()
    assert "database-secret" not in str(denied.value)


def test_server_readiness_factory_accepts_only_fixed_internal_server_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificates = _certificates(tmp_path, runner_id=RUNNER_ID)
    values = {
        "OMNIGENT_SAAS_RUNNER_READINESS_HOST": ("omnigent-saas-runner-control.omnigent.svc"),
        "OMNIGENT_SAAS_RUNNER_READINESS_PORT": "9445",
        "OMNIGENT_SAAS_RUNNER_READINESS_SERVER_NAME": (
            "omnigent-saas-runner-control.omnigent.svc"
        ),
        "OMNIGENT_SAAS_RUNNER_READINESS_CA_CERTIFICATE_FILE": str(certificates["server"].ca),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    adapter = build_remote_tls_runner_control_readiness(config=object())
    assert adapter.connect_host == values["OMNIGENT_SAAS_RUNNER_READINESS_HOST"]
    assert adapter.server_name == adapter.connect_host
    assert not hasattr(adapter, "executor_database_url")
    assert not hasattr(adapter, "client_certificate_path")

    monkeypatch.setenv("OMNIGENT_SAAS_RUNNER_READINESS_HOST", "runner.example.com")
    monkeypatch.setenv("OMNIGENT_SAAS_RUNNER_READINESS_SERVER_NAME", "runner.example.com")
    with pytest.raises(RunnerReadinessError, match="endpoint is invalid"):
        build_remote_tls_runner_control_readiness(config=object())


@pytest.mark.asyncio
async def test_mtls_transport_denies_wrong_profile_and_revoked_leaf(tmp_path: Path) -> None:
    certificates = _certificates(tmp_path, runner_id=RUNNER_ID, extra_runner_uri=True)
    authority = _TransportAuthority()
    certificate_authority = _CertificateAuthorizer(allowed=False)
    server = MutualTlsRunnerControlServer(  # type: ignore[arg-type]
        authority,
        _server_context(certificates["server"]),
        certificate_authority,
    )
    await server.start()
    client = MutualTlsRunnerControlClient(
        connect_host="localhost",
        port=server.port,
        server_name="localhost",
        tls_context=_client_context(certificates["runner"]),
        connection_generation=2,
        connection_token=CONNECTION_TOKEN,
    )
    try:
        with pytest.raises(RunnerControlError) as denied:
            await client.heartbeat_runner()
    finally:
        await server.aclose()
    assert denied.value.code == "runner_control_identity_invalid"
    assert not authority.calls


@pytest.mark.asyncio
async def test_mtls_transport_denies_leaf_at_external_purpose_authority(tmp_path: Path) -> None:
    certificates = _certificates(tmp_path, runner_id=RUNNER_ID)
    authority = _TransportAuthority()
    certificate_authority = _CertificateAuthorizer(allowed=False)
    server = MutualTlsRunnerControlServer(  # type: ignore[arg-type]
        authority,
        _server_context(certificates["server"]),
        certificate_authority,
    )
    await server.start()
    client = MutualTlsRunnerControlClient(
        connect_host="localhost",
        port=server.port,
        server_name="localhost",
        tls_context=_client_context(certificates["runner"]),
        connection_generation=2,
        connection_token=CONNECTION_TOKEN,
    )
    try:
        with pytest.raises(RunnerControlError) as denied:
            await client.heartbeat_runner()
    finally:
        await server.aclose()
    assert denied.value.code == "runner_control_certificate_denied"
    assert not authority.calls
