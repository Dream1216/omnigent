from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    PreviewGatewayCertificateAuthority,
    PreviewGatewayDirectoryAuthority,
    SaasBase,
)
from saas.preview_gateway_control_transport import (
    MutualTlsPreviewGatewayControlClient,
    MutualTlsPreviewGatewayControlServer,
    PreviewGatewayControlTransportError,
)


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


def _control_certificates(
    root: Path, gateway_ids: tuple[str, ...]
) -> dict[str, _CertificateFiles]:
    root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gateway Control CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
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
    ca_path = root / "control-ca.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))

    def issue(
        name: str,
        *,
        names: list[x509.GeneralName],
        extended_usage: ObjectIdentifier,
        key_agreement: bool = False,
    ) -> _CertificateFiles:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([extended_usage]), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=key_agreement,
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
        private_key_path = root / f"{name}-key.pem"
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        _write_private_key(private_key_path, key)
        return _CertificateFiles(ca_path, certificate_path, private_key_path)

    certificates = {
        "server": issue(
            "gateway-control",
            names=[
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ],
            extended_usage=ExtendedKeyUsageOID.SERVER_AUTH,
        )
    }
    for index, gateway_id in enumerate(gateway_ids):
        certificates[f"gateway-{index}"] = issue(
            f"gateway-{index}",
            names=[
                x509.UniformResourceIdentifier(
                    f"spiffe://omnigent/preview-gateway-control/{gateway_id}"
                )
            ],
            extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        )
    certificates["relay-role"] = issue(
        "relay-role",
        names=[
            x509.UniformResourceIdentifier("spiffe://omnigent/preview-gateway/gateway-relay-role")
        ],
        extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    certificates["surplus-key-usage"] = issue(
        "surplus-key-usage",
        names=[
            x509.UniformResourceIdentifier(
                f"spiffe://omnigent/preview-gateway-control/{gateway_ids[0]}"
            )
        ],
        extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        key_agreement=True,
    )
    return certificates


def _server_context(files: _CertificateFiles) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(files.ca))
    context.load_cert_chain(str(files.certificate), str(files.private_key))
    return context


def _client_context(files: _CertificateFiles) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(files.ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(files.certificate), str(files.private_key))
    return context


def _relay_certificate(gateway_id: str, *, purpose: str, serial: int) -> bytes:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(f"spiffe://omnigent/preview-gateway/{gateway_id}")
    ]
    extended_usage = ExtendedKeyUsageOID.CLIENT_AUTH
    if purpose == "preview_relay_server":
        names.append(x509.DNSName("gateway.internal"))
        extended_usage = ExtendedKeyUsageOID.SERVER_AUTH
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gateway Relay")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Relay CA")]))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([extended_usage]), critical=True)
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
    return certificate.public_bytes(serialization.Encoding.DER)


class _ControlIdentityAuthorizer:
    def __init__(self, denied_actions: tuple[str, ...] = ()) -> None:
        self.denied_actions = frozenset(denied_actions)
        self.calls: list[tuple[str, str, int]] = []

    def is_preview_gateway_control_identity_authorized(
        self,
        *,
        gateway_instance_id: str,
        certificate_der: bytes,
        action: str,
    ) -> bool:
        self.calls.append((gateway_instance_id, action, len(certificate_der)))
        return action not in self.denied_actions


class _ControlServerThread:
    def __init__(self, server: MutualTlsPreviewGatewayControlServer) -> None:
        self._server = server
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run, name="test-preview-gateway-control", daemon=False
        )

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._server.start())
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            self._loop.close()
            return
        self._ready.set()
        self._loop.run_forever()
        self._loop.close()

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise TimeoutError("Preview Gateway control test server did not start")
        if self._startup_error is not None:
            raise RuntimeError(
                "Preview Gateway control test server failed"
            ) from self._startup_error

    def close(self) -> None:
        future = asyncio.run_coroutine_threadsafe(self._server.aclose(), self._loop)
        try:
            future.result(timeout=5)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise TimeoutError("Preview Gateway control test server did not stop")


@dataclass(frozen=True, slots=True)
class _StartedControl:
    server: MutualTlsPreviewGatewayControlServer
    thread: _ControlServerThread
    directory: PreviewGatewayDirectoryAuthority
    certificates: PreviewGatewayCertificateAuthority
    identity_authorizer: _ControlIdentityAuthorizer
    tls_files: dict[str, _CertificateFiles]


def _started_control(
    tmp_path: Path,
    *,
    gateway_ids: tuple[str, ...],
    denied_actions: tuple[str, ...] = (),
) -> _StartedControl:
    engine = sa.create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
    directory = PreviewGatewayDirectoryAuthority(factory, service_session_factory=factory)
    certificate_authority = PreviewGatewayCertificateAuthority(
        factory, accepted_trust_bundle_versions=("bundle-v1",)
    )
    tls_files = _control_certificates(tmp_path, gateway_ids)
    identity_authorizer = _ControlIdentityAuthorizer(denied_actions)
    server = MutualTlsPreviewGatewayControlServer(
        directory,
        certificate_authority,
        _server_context(tls_files["server"]),
        identity_authorizer,
    )
    thread = _ControlServerThread(server)
    thread.start()
    return _StartedControl(
        server,
        thread,
        directory,
        certificate_authority,
        identity_authorizer,
        tls_files,
    )


def _client(started: _StartedControl, gateway_id: str, certificate_index: int):
    return MutualTlsPreviewGatewayControlClient(
        base_url=f"https://127.0.0.1:{started.server.port}",
        gateway_instance_id=gateway_id,
        tls_context=_client_context(started.tls_files[f"gateway-{certificate_index}"]),
    )


def _register(client: MutualTlsPreviewGatewayControlClient, gateway_id: str, token: str):
    return client.register_gateway(
        gateway_instance_id=gateway_id,
        connect_host="gateway.internal",
        connect_port=9443,
        server_name="gateway.internal",
        failure_domain="cn-east-1a",
        source_revision="a" * 40,
        adapter_contract_version="0.2.0",
        registration_token=token,
        lease_duration=timedelta(seconds=45),
    )


def test_mtls_gateway_control_client_runs_full_lifecycle_without_database_credentials(
    tmp_path: Path,
) -> None:
    gateway_id = "gateway-control-a"
    token = "gateway-control-token-" + "x" * 40
    started = _started_control(tmp_path, gateway_ids=(gateway_id,))
    client = _client(started, gateway_id, 0)
    try:
        registered = _register(client, gateway_id, token)
        assert registered.status == "starting"
        client_leaf = client.activate_certificate(
            gateway_instance_id=gateway_id,
            purpose="preview_relay_client",
            certificate_der=_relay_certificate(
                gateway_id, purpose="preview_relay_client", serial=101
            ),
            trust_bundle_version="bundle-v1",
            rotation_overlap=timedelta(0),
        )
        server_leaf = client.activate_certificate(
            gateway_instance_id=gateway_id,
            purpose="preview_relay_server",
            certificate_der=_relay_certificate(
                gateway_id, purpose="preview_relay_server", serial=102
            ),
            trust_bundle_version="bundle-v1",
            rotation_overlap=timedelta(minutes=5),
        )
        active = client.activate_gateway(gateway_instance_id=gateway_id, registration_token=token)
        heartbeat = client.heartbeat_gateway(
            gateway_instance_id=gateway_id,
            registration_token=token,
            lease_duration=timedelta(seconds=45),
        )
        assert active.status == heartbeat.status == "active"
        assert client.begin_draining(gateway_instance_id=gateway_id, registration_token=token)
        assert client.revoke_certificate(
            fingerprint_sha256=client_leaf.fingerprint_sha256,
            reason="planned shutdown",
        )
        assert client.revoke_certificate(
            fingerprint_sha256=server_leaf.fingerprint_sha256,
            reason="planned shutdown",
        )
        assert client.release_gateway(
            gateway_instance_id=gateway_id,
            registration_token=token,
            reason="planned shutdown",
        )
    finally:
        client.close()
        started.thread.close()

    assert [action for _, action, _ in started.identity_authorizer.calls] == [
        "register",
        "certificate_activate",
        "certificate_activate",
        "activate",
        "heartbeat",
        "drain",
        "certificate_revoke",
        "certificate_revoke",
        "release",
    ]


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for Gateway control acceptance")
    return value


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _role_factory(engine: sa.Engine, role: str) -> sessionmaker[Session]:
    factory = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(factory, "after_begin")
    def _bind_role(
        _session: Session,
        _transaction: object,
        connection: sa.Connection,
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")

    return factory


def test_mtls_gateway_control_reaches_real_postgresql_with_split_service_roles(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    gateway_id = f"gateway-control-pg-{uuid4().hex[:12]}"
    token = f"gateway-control-pg-token-{uuid4().hex}" + "x" * 16
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
    platform_factory = _role_factory(engine, "saas_platform")
    gateway_factory = _role_factory(engine, "saas_preview_gateway")
    directory = PreviewGatewayDirectoryAuthority(
        platform_factory, service_session_factory=gateway_factory
    )
    certificates = PreviewGatewayCertificateAuthority(
        platform_factory, accepted_trust_bundle_versions=("bundle-v1",)
    )
    tls_files = _control_certificates(tmp_path, (gateway_id,))
    server = MutualTlsPreviewGatewayControlServer(
        directory,
        certificates,
        _server_context(tls_files["server"]),
        _ControlIdentityAuthorizer(),
    )
    thread = _ControlServerThread(server)
    thread.start()
    client = MutualTlsPreviewGatewayControlClient(
        base_url=f"https://127.0.0.1:{server.port}",
        gateway_instance_id=gateway_id,
        tls_context=_client_context(tls_files["gateway-0"]),
    )
    try:
        _register(client, gateway_id, token)
        client_leaf = client.activate_certificate(
            gateway_instance_id=gateway_id,
            purpose="preview_relay_client",
            certificate_der=_relay_certificate(
                gateway_id, purpose="preview_relay_client", serial=301
            ),
            trust_bundle_version="bundle-v1",
        )
        client.activate_certificate(
            gateway_instance_id=gateway_id,
            purpose="preview_relay_server",
            certificate_der=_relay_certificate(
                gateway_id, purpose="preview_relay_server", serial=302
            ),
            trust_bundle_version="bundle-v1",
        )
        assert (
            client.activate_gateway(
                gateway_instance_id=gateway_id, registration_token=token
            ).status
            == "active"
        )
        assert (
            client.heartbeat_gateway(
                gateway_instance_id=gateway_id,
                registration_token=token,
                lease_duration=timedelta(seconds=45),
            ).status
            == "active"
        )
        assert client.begin_draining(gateway_instance_id=gateway_id, registration_token=token)
        assert client.revoke_certificate(
            fingerprint_sha256=client_leaf.fingerprint_sha256,
            reason="PostgreSQL transport acceptance",
        )
        assert client.release_gateway(
            gateway_instance_id=gateway_id,
            registration_token=token,
            reason="PostgreSQL transport acceptance",
        )
    finally:
        client.close()
        thread.close()
        engine.dispose()


def test_gateway_control_binds_request_and_method_to_exact_control_leaf(
    tmp_path: Path,
) -> None:
    gateway_a = "gateway-control-a"
    gateway_b = "gateway-control-b"
    started = _started_control(
        tmp_path,
        gateway_ids=(gateway_a, gateway_b),
        denied_actions=("release",),
    )
    mismatched = _client(started, gateway_b, 0)
    correct = _client(started, gateway_a, 0)
    token = "gateway-control-token-" + "x" * 40
    try:
        with pytest.raises(PreviewGatewayControlTransportError) as mismatch:
            _register(mismatched, gateway_b, token)
        assert mismatch.value.code == "preview_gateway_control_identity_mismatch"

        _register(correct, gateway_a, token)
        with pytest.raises(PreviewGatewayControlTransportError) as denied:
            correct.release_gateway(
                gateway_instance_id=gateway_a,
                registration_token=token,
                reason="must be denied by method policy",
            )
        assert denied.value.code == "preview_gateway_control_identity_denied"
    finally:
        mismatched.close()
        correct.close()
        started.thread.close()


def test_gateway_control_identity_cannot_revoke_another_gateways_leaf(
    tmp_path: Path,
) -> None:
    gateway_a = "gateway-control-a"
    gateway_b = "gateway-control-b"
    token_b = "gateway-b-token-" + "x" * 40
    started = _started_control(tmp_path, gateway_ids=(gateway_a, gateway_b))
    client_a = _client(started, gateway_a, 0)
    client_b = _client(started, gateway_b, 1)
    try:
        _register(client_b, gateway_b, token_b)
        leaf_b = client_b.activate_certificate(
            gateway_instance_id=gateway_b,
            purpose="preview_relay_client",
            certificate_der=_relay_certificate(
                gateway_b, purpose="preview_relay_client", serial=201
            ),
            trust_bundle_version="bundle-v1",
        )
        assert not client_a.revoke_certificate(
            fingerprint_sha256=leaf_b.fingerprint_sha256,
            reason="cross identity attempt",
        )
        assert started.certificates.revoke_certificate(
            gateway_instance_id=gateway_b,
            fingerprint_sha256=leaf_b.fingerprint_sha256,
            reason="server-side cleanup",
        )
    finally:
        client_a.close()
        client_b.close()
        started.thread.close()


def test_gateway_control_rejects_relay_role_and_duplicate_json_members(
    tmp_path: Path,
) -> None:
    gateway_id = "gateway-control-a"
    started = _started_control(tmp_path, gateway_ids=(gateway_id,))
    relay_context = _client_context(started.tls_files["relay-role"])
    surplus_usage_context = _client_context(started.tls_files["surplus-key-usage"])
    valid_context = _client_context(started.tls_files["gateway-0"])

    def raw(context: ssl.SSLContext, body: bytes) -> bytes:
        request = (
            "POST /internal/v1/preview-gateways/register HTTP/1.1\r\n"
            "host: preview-gateway-control.internal\r\n"
            "content-type: application/json\r\n"
            f"content-length: {len(body)}\r\n\r\n"
        ).encode() + body
        with socket.create_connection(("127.0.0.1", started.server.port), timeout=5) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname="localhost") as tls_socket:
                tls_socket.sendall(request)
                return tls_socket.recv(8_192)

    try:
        relay_response = raw(relay_context, b"{}")
        assert b"HTTP/1.1 403 Forbidden" in relay_response
        assert b"preview_gateway_control_identity_invalid" in relay_response

        surplus_usage_response = raw(surplus_usage_context, b"{}")
        assert b"HTTP/1.1 403 Forbidden" in surplus_usage_response
        assert b"preview_gateway_control_identity_invalid" in surplus_usage_response

        duplicate = (
            b'{"gateway_instance_id":"gateway-control-a",'
            b'"gateway_instance_id":"gateway-control-a"}'
        )
        duplicate_response = raw(valid_context, duplicate)
        assert b"HTTP/1.1 400 Bad Request" in duplicate_response
        assert b"preview_gateway_control_request_invalid" in duplicate_response
    finally:
        started.thread.close()


def test_gateway_control_rejects_weak_tls_client_time_and_local_identity_mismatch(
    tmp_path: Path,
) -> None:
    gateway_id = "gateway-control-a"
    files = _control_certificates(tmp_path, (gateway_id,))
    weak_server = _server_context(files["server"])
    weak_server.minimum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises(ValueError, match=r"TLS 1\.3"):
        MutualTlsPreviewGatewayControlServer(
            object(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            weak_server,
            _ControlIdentityAuthorizer(),
        )

    weak_client = _client_context(files["gateway-0"])
    weak_client.check_hostname = False
    with pytest.raises(ValueError, match="hostname"):
        MutualTlsPreviewGatewayControlClient(
            base_url="https://127.0.0.1:8443",
            gateway_instance_id=gateway_id,
            tls_context=weak_client,
        )

    started = _started_control(tmp_path / "live", gateway_ids=(gateway_id,))
    client = _client(started, gateway_id, 0)
    try:
        with pytest.raises(PreviewGatewayControlTransportError) as time_forbidden:
            client.register_gateway(
                gateway_instance_id=gateway_id,
                connect_host="gateway.internal",
                connect_port=9443,
                server_name="gateway.internal",
                failure_domain="cn-east-1a",
                source_revision="a" * 40,
                adapter_contract_version="0.2.0",
                registration_token="token-" + "x" * 40,
                now=datetime.now(timezone.utc),
            )
        assert time_forbidden.value.code == "preview_gateway_control_client_time_forbidden"

        with pytest.raises(PreviewGatewayControlTransportError) as local_mismatch:
            client.heartbeat_gateway(
                gateway_instance_id="other-gateway",
                registration_token="token-" + "x" * 40,
            )
        assert local_mismatch.value.code == "preview_gateway_control_identity_mismatch"
    finally:
        client.close()
        started.thread.close()
