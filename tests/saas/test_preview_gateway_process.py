from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import ssl
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from saas.preview_gateway_process import (
    PreviewGatewayHealthServer,
    PreviewGatewayProcessComponents,
    PreviewGatewayProcessConfig,
    PreviewGatewayProcessError,
    _load_factory,
    check_preview_gateway_health,
    load_preview_gateway_process_config,
    run_preview_gateway_process,
)
from saas.preview_gateway_runtime import (
    MutualTlsPreviewGatewayReadinessProbe,
    PreviewGatewayRuntime,
    PreviewGatewayRuntimeCertificateSet,
    PreviewGatewayRuntimeError,
    PreviewGatewayRuntimeLeaf,
)


def _config_document() -> dict[str, object]:
    return {
        "adapter_contract_version": "0.2.0",
        "bind_host": "0.0.0.0",
        "bind_port": 9443,
        "connect_host": "gateway.internal.example",
        "connect_port": 9443,
        "drain_timeout_seconds": 30,
        "failure_domain": "cn-east-1a",
        "health_host": "127.0.0.1",
        "health_port": 9080,
        "heartbeat_seconds": 15,
        "instance_id_prefix": "gateway-a",
        "lease_seconds": 45,
        "readiness_timeout_seconds": 10,
        "renewal_before_seconds": 600,
        "rotation_overlap_seconds": 300,
        "server_name": "gateway.internal.example",
        "source_revision": "a" * 40,
    }


def _write_config(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)


def test_process_config_generates_runtime_identity_outside_the_document(tmp_path: Path) -> None:
    path = tmp_path / "gateway.json"
    _write_config(path, _config_document())

    config = load_preview_gateway_process_config(path.resolve())
    runtime = config.runtime_config(
        gateway_instance_id="gateway-a-0123456789abcdef",
        registration_token="process-token-" + "x" * 40,
    )

    assert config.connect_port == runtime.advertised_connect_port == 9443
    assert runtime.gateway_instance_id == "gateway-a-0123456789abcdef"
    assert "process-token" not in repr(runtime)


@pytest.mark.parametrize(
    "change",
    [
        {"gateway_instance_id": "static-id"},
        {"registration_token": "persisted-secret"},
        {"health_host": "0.0.0.0"},
        {"heartbeat_seconds": 16},
        {"rotation_overlap_seconds": 600},
        {"bind_port": True},
        {"connect_host": 42},
        {"lease_seconds": float("nan")},
        {"readiness_timeout_seconds": float("inf")},
    ],
)
def test_process_config_rejects_secret_static_identity_or_unsafe_values(
    change: dict[str, object],
) -> None:
    document = _config_document()
    document.update(change)

    with pytest.raises(PreviewGatewayProcessError):
        PreviewGatewayProcessConfig.from_mapping(document)


def test_process_config_file_rejects_group_writes_and_symlinks(tmp_path: Path) -> None:
    path = tmp_path / "gateway.json"
    _write_config(path, _config_document())
    path.chmod(0o620)
    with pytest.raises(PreviewGatewayProcessError) as writable:
        load_preview_gateway_process_config(path.resolve())
    assert writable.value.code == "preview_gateway_process_config_file_invalid"

    path.chmod(0o600)
    alias = tmp_path / "gateway-alias.json"
    alias.symlink_to(path)
    with pytest.raises(PreviewGatewayProcessError) as symlinked:
        load_preview_gateway_process_config(alias.absolute())
    assert symlinked.value.code == "preview_gateway_process_config_unavailable"


def test_process_config_rejects_duplicate_json_members(tmp_path: Path) -> None:
    path = tmp_path / "gateway.json"
    path.write_text(
        json.dumps(_config_document())[:-1] + ', "bind_port": 9444}',
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(PreviewGatewayProcessError) as duplicate:
        load_preview_gateway_process_config(path.resolve())

    assert duplicate.value.code == "preview_gateway_process_config_invalid"


class _Factory:
    def build(self, **_values: object) -> object:
        return object()


@pytest.mark.parametrize("candidate", [_Factory, _Factory(), lambda: _Factory()])
def test_factory_loader_accepts_trusted_class_instance_or_factory(
    monkeypatch: pytest.MonkeyPatch, candidate: object
) -> None:
    monkeypatch.setattr(
        "saas.preview_gateway_process.importlib.import_module",
        lambda _module: SimpleNamespace(candidate=candidate),
    )

    assert isinstance(_load_factory("deployment_module:candidate"), _Factory)


class _ProcessFactory:
    def __init__(self) -> None:
        self.gateway_ids: list[str] = []

    def build(
        self, *, config: PreviewGatewayProcessConfig, gateway_instance_id: str
    ) -> PreviewGatewayProcessComponents:
        del config
        self.gateway_ids.append(gateway_instance_id)
        directory = SimpleNamespace(
            register_gateway=lambda **_values: None,
            activate_gateway=lambda **_values: None,
            heartbeat_gateway=lambda **_values: None,
            begin_draining=lambda **_values: None,
            release_gateway=lambda **_values: None,
        )
        certificates = SimpleNamespace(
            activate_certificate=lambda **_values: None,
            revoke_certificate=lambda **_values: None,
        )
        provider = SimpleNamespace(
            prepare=lambda **_values: None,
            install=lambda _certificates: None,
            discard=lambda _certificates: None,
        )
        relay = SimpleNamespace(start=lambda **_values: None, aclose=lambda: None)
        probe = SimpleNamespace(verify=lambda **_values: None)
        drain = SimpleNamespace(wait_until_drained=lambda **_values: None)
        return PreviewGatewayProcessComponents(
            directory=cast(Any, directory),
            certificate_lifecycle=cast(Any, certificates),
            certificate_provider=cast(Any, provider),
            relay_server=cast(Any, relay),
            readiness_probe=cast(Any, probe),
            drain_observer=cast(Any, drain),
        )


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@pytest.mark.asyncio
async def test_process_generates_fresh_identity_and_token_and_binds_health_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _config_document()
    document["health_port"] = _unused_loopback_port()
    config = PreviewGatewayProcessConfig.from_mapping(document)
    factory = _ProcessFactory()
    registration_tokens: list[str] = []

    async def fake_run(runtime: PreviewGatewayRuntime) -> None:
        runtime_config = runtime._config
        registration_tokens.append(runtime_config.registration_token)
        assert await check_preview_gateway_health(
            host=config.health_host,
            port=config.health_port,
            readiness=False,
        )

    monkeypatch.setattr(
        "saas.preview_gateway_process.run_preview_gateway_runtime",
        fake_run,
    )

    await run_preview_gateway_process(config, factory)
    await run_preview_gateway_process(config, factory)

    assert len(set(factory.gateway_ids)) == 2
    assert all(identifier.startswith("gateway-a-") for identifier in factory.gateway_ids)
    assert len(set(registration_tokens)) == 2
    assert all(len(token) >= 32 for token in registration_tokens)
    assert not await check_preview_gateway_health(
        host=config.health_host,
        port=config.health_port,
        readiness=False,
    )


@dataclass
class _HealthRuntime:
    state: str = "starting"
    ready: bool = False
    fatal_error: BaseException | None = None


@pytest.mark.asyncio
async def test_loopback_health_server_reports_runtime_readiness_without_details() -> None:
    runtime = _HealthRuntime()
    server = PreviewGatewayHealthServer(runtime, host="127.0.0.1", port=0)
    await server.start()
    try:
        assert await check_preview_gateway_health(
            host="127.0.0.1", port=server.port, readiness=False
        )
        assert not await check_preview_gateway_health(
            host="127.0.0.1", port=server.port, readiness=True
        )
        runtime.state = "active"
        runtime.ready = True
        assert await check_preview_gateway_health(
            host="127.0.0.1", port=server.port, readiness=True
        )
        runtime.fatal_error = RuntimeError("internal detail must not be exposed")
        assert not await check_preview_gateway_health(
            host="127.0.0.1", port=server.port, readiness=False
        )
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_loopback_health_server_bounds_headers_and_preserves_head_length() -> None:
    runtime = _HealthRuntime(state="active", ready=True)
    server = PreviewGatewayHealthServer(runtime, host="127.0.0.1", port=0)
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"HEAD /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        response = await reader.read()
        assert b"HTTP/1.1 200 OK\r\n" in response
        assert b"Content-Length: 3\r\n" in response
        assert response.endswith(b"\r\n\r\n")
        writer.close()
        await writer.wait_closed()

        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"GET /readyz HTTP/1.1\r\nX-Large: " + b"x" * 2_048 + b"\r\n\r\n")
        await writer.drain()
        response = await reader.read()
        assert b"HTTP/1.1 400 Bad Request\r\n" in response
        assert b"unavailable\n" in response
        writer.close()
        await writer.wait_closed()
    finally:
        await server.aclose()


@dataclass(frozen=True, slots=True)
class _IssuedCertificate:
    certificate: x509.Certificate
    certificate_path: Path
    key_path: Path


def _certificate_material(
    root: Path,
) -> tuple[
    Path,
    _IssuedCertificate,
    _IssuedCertificate,
    _IssuedCertificate,
    x509.Certificate,
]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gateway Health CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = root / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def issue(
        name: str,
        *,
        sans: list[x509.GeneralName],
        usage: x509.ObjectIdentifier,
    ) -> _IssuedCertificate:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
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
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return _IssuedCertificate(certificate, certificate_path, key_path)

    server = issue(
        "server",
        sans=[
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.UniformResourceIdentifier(
                "spiffe://omnigent/preview-gateway/gateway-health-test"
            ),
        ],
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    health = issue(
        "health",
        sans=[
            x509.UniformResourceIdentifier(
                "spiffe://omnigent/platform/preview-health/ci-probe"
            )
        ],
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    gateway_client = issue(
        "gateway-client",
        sans=[
            x509.UniformResourceIdentifier(
                "spiffe://omnigent/preview-gateway/gateway-health-test"
            )
        ],
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    unrelated_server = issue(
        "unrelated-server",
        sans=[x509.DNSName("localhost")],
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    ).certificate
    return ca_path, server, health, gateway_client, unrelated_server


def _runtime_leaf(
    certificate: x509.Certificate, *, purpose: str
) -> PreviewGatewayRuntimeLeaf:
    return PreviewGatewayRuntimeLeaf(
        purpose=purpose,
        certificate_der=certificate.public_bytes(serialization.Encoding.DER),
        trust_bundle_version="bundle-v1",
        not_after=certificate.not_valid_after_utc,
    )


@pytest.mark.asyncio
async def test_readiness_probe_uses_real_tls13_and_pins_the_exact_server_leaf(
    tmp_path: Path,
) -> None:
    (
        ca_path,
        server_certificate,
        health_certificate,
        gateway_client_certificate,
        unrelated_server,
    ) = _certificate_material(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_verify_locations(cafile=str(ca_path))
    server_context.load_cert_chain(
        str(server_certificate.certificate_path), str(server_certificate.key_path)
    )
    observed_health_identity = asyncio.Event()

    async def handle(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ssl_object = writer.get_extra_info("ssl_object")
        peer = ssl_object.getpeercert() if ssl_object is not None else {}
        if (
            "URI",
            "spiffe://omnigent/platform/preview-health/ci-probe",
        ) in peer.get("subjectAltName", ()):
            observed_health_identity.set()
        writer.close()
        with suppress(ConnectionError, ssl.SSLError):
            await writer.wait_closed()

    server = await asyncio.start_server(
        handle,
        "127.0.0.1",
        0,
        ssl=server_context,
        ssl_handshake_timeout=2,
    )
    assert server.sockets is not None
    port = int(server.sockets[0].getsockname()[1])
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    client_context.load_cert_chain(
        str(health_certificate.certificate_path), str(health_certificate.key_path)
    )
    probe = MutualTlsPreviewGatewayReadinessProbe(client_context)
    gateway_client = _runtime_leaf(
        gateway_client_certificate.certificate,
        purpose="preview_relay_client",
    )
    certificates = PreviewGatewayRuntimeCertificateSet(
        client=gateway_client,
        server=_runtime_leaf(server_certificate.certificate, purpose="preview_relay_server"),
    )
    try:
        await probe.verify(
            gateway_instance_id="gateway-health-test",
            connect_host="127.0.0.1",
            connect_port=port,
            server_name="localhost",
            certificates=certificates,
        )
        await asyncio.wait_for(observed_health_identity.wait(), timeout=1)
        wrong_pin = PreviewGatewayRuntimeCertificateSet(
            client=gateway_client,
            server=_runtime_leaf(unrelated_server, purpose="preview_relay_server"),
        )
        with pytest.raises(PreviewGatewayRuntimeError) as mismatch:
            await probe.verify(
                gateway_instance_id="gateway-health-test",
                connect_host="127.0.0.1",
                connect_port=port,
                server_name="localhost",
                certificates=wrong_pin,
            )
        assert mismatch.value.code == "preview_gateway_readiness_identity_mismatch"
    finally:
        server.close()
        await server.wait_closed()


def test_deployment_assets_keep_secrets_out_and_default_to_hardened_boundaries() -> None:
    root = Path(__file__).resolve().parents[2]
    deployment = root / "saas/deployment/preview_gateway"
    systemd_unit = (deployment / "omnigent-saas-preview-gateway@.service").read_text()
    kubernetes = (deployment / "kubernetes.yaml").read_text()
    readme = (deployment / "README.md").read_text()

    assert "DynamicUser=yes" in systemd_unit
    assert "NoNewPrivileges=yes" in systemd_unit
    assert "ProtectSystem=strict" in systemd_unit
    assert "CapabilityBoundingSet=" in systemd_unit
    assert "OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL" not in systemd_unit + kubernetes
    assert 'drop: ["ALL"]' in kubernetes
    assert "readOnlyRootFilesystem: true" in kubernetes
    assert "automountServiceAccountToken: false" in kubernetes
    assert "topology.kubernetes.io/zone" in kubernetes
    assert "replicas: 1" in kubernetes
    assert "replicas: 2" not in kubernetes
    assert 'policyTypes: ["Ingress", "Egress"]' in kubernetes
    assert "saas_platform" in readme and "must not" in readme


def test_example_config_matches_the_closed_process_schema() -> None:
    root = Path(__file__).resolve().parents[2]
    example = root / "saas/deployment/preview_gateway/config.example.json"

    config = load_preview_gateway_process_config(example)

    assert config.health_host == "127.0.0.1"
    assert config.instance_id_prefix == "preview-gateway-a"
    assert "registration_token" not in json.loads(example.read_text())
    assert os.stat(example).st_mode & 0o022 == 0
