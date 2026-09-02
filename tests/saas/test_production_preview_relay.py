from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from omnigent.runner.transports.ws_tunnel.frames import HelloFrame
from saas.control_plane import PreviewRouteGrant
from saas.control_plane.preview_sessions import PreviewSessionAuthority
from saas.preview_relay_transport import PreviewRelayEndpointPolicy
from saas.preview_tunnel import PreviewTunnelAdapterError
from saas.production import preview_relay
from saas.production.preview_relay import (
    ProductionPreviewRelayError,
    ProductionPreviewRelayOwner,
    ProductionPreviewRelayOwnerConfig,
    load_production_preview_relay_owner_config,
)


class _NoopWebSocket:
    async def send_text(self, data: str) -> None:
        del data

    async def receive_text(self) -> str:
        return await asyncio.Future()


def _hello() -> HelloFrame:
    return HelloFrame(
        runner_version="0.9.0.dev0",
        frame_protocol_version=1,
        harnesses=["codex"],
        envs=["local"],
    )


def _route(runner_id=None) -> PreviewRouteGrant:
    return PreviewRouteGrant(
        preview_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        runner_id=runner_id or uuid4(),
        runner_connection_generation=7,
        run_id=uuid4(),
        run_fence_token=11,
        worktree_id=uuid4(),
        worktree_lease_generation=5,
        opaque_preview_key="pvr_production_owner",
        preview_token_hash="a" * 64,
        upstream_request_headers={},
        response_headers={"Content-Security-Policy": "sandbox"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _certificate_files(root: Path, gateway_instance_id: str) -> dict[str, Path]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Preview Production CA")])
    ca = (
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
    ca_path = root / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def issue(name: str, *, server: bool) -> tuple[Path, Path]:
        key = ec.generate_private_key(ec.SECP256R1())
        san_names: list[x509.GeneralName] = [
            x509.UniformResourceIdentifier(
                f"spiffe://omnigent/preview-gateway/{gateway_instance_id}"
            )
        ]
        if server:
            san_names.extend(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if server
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    ]
                ),
                critical=True,
            )
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
        key_path.chmod(0o600)
        return certificate_path, key_path

    client_certificate, client_key = issue("client", server=False)
    server_certificate, server_key = issue("server", server=True)
    return {
        "ca": ca_path,
        "client_certificate": client_certificate,
        "client_key": client_key,
        "server_certificate": server_certificate,
        "server_key": server_key,
    }


def _owner_config(tmp_path: Path) -> ProductionPreviewRelayOwnerConfig:
    gateway_instance_id = "gateway-owner-a"
    certificates = _certificate_files(tmp_path, gateway_instance_id)
    return ProductionPreviewRelayOwnerConfig(
        source_revision="a" * 40,
        product_revision="a" * 40,
        preview_database_url="sqlite+pysqlite:///:memory:",
        expected_preview_login="preview-test",
        gateway_instance_id=gateway_instance_id,
        relay_ca_path=certificates["ca"],
        relay_client_certificate_path=certificates["client_certificate"],
        relay_client_key_path=certificates["client_key"],
        relay_server_certificate_path=certificates["server_certificate"],
        relay_server_key_path=certificates["server_key"],
        relay_trust_bundle_versions=("test-bundle",),
        relay_endpoint_policy=PreviewRelayEndpointPolicy.from_strings(
            allowed_dns_suffixes=("omnigent.svc.cluster.local",),
            allowed_cidrs=("10.42.0.0/16",),
            allowed_ports=(9443,),
        ),
        bind_host="127.0.0.1",
        bind_port=_free_port(),
        maximum_request_bytes=1_048_576,
        maximum_response_bytes=10_485_760,
    )


@pytest.mark.asyncio
async def test_production_relay_owner_starts_tls13_listener_with_owned_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _owner_config(tmp_path)
    owner = ProductionPreviewRelayOwner(
        config,
        sa.create_engine(config.preview_database_url, connect_args={"check_same_thread": False}),
    )
    assert isinstance(owner._placements, PreviewSessionAuthority)
    monkeypatch.setattr(
        owner._certificates,
        "is_preview_gateway_certificate_authorized",
        lambda **_values: True,
    )

    await owner.start()
    assert owner.port == config.bind_port
    assert owner._listening is True
    await owner.aclose()
    assert owner._listening is False
    owner.close()


@pytest.mark.asyncio
async def test_production_relay_owner_requires_explicit_exact_generation_binding(
    tmp_path: Path,
) -> None:
    config = _owner_config(tmp_path)
    owner = ProductionPreviewRelayOwner(
        config,
        sa.create_engine(config.preview_database_url, connect_args={"check_same_thread": False}),
    )
    registry = owner.registry
    route = _route()
    official_id = f"official-{route.runner_id}"
    session = registry.register(official_id, _NoopWebSocket(), _hello())

    with pytest.raises(PreviewTunnelAdapterError) as unbound:
        owner.bindings.resolve(route)
    assert unbound.value.code == "preview_runner_tunnel_stale"

    binding = owner.bindings.bind(
        runner_id=route.runner_id,
        connection_generation=route.runner_connection_generation,
        official_runner_id=official_id,
    )
    assert binding.session is session
    assert owner.bindings.resolve(route) is binding

    registry.deregister(official_id, session)
    with pytest.raises(PreviewTunnelAdapterError) as disconnected:
        owner.bindings.resolve(route)
    assert disconnected.value.code == "preview_runner_tunnel_stale"
    owner.close()


@pytest.mark.asyncio
async def test_production_relay_owner_rejects_second_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _owner_config(tmp_path)
    owner = ProductionPreviewRelayOwner(
        config,
        sa.create_engine(config.preview_database_url, connect_args={"check_same_thread": False}),
    )
    monkeypatch.setattr(
        owner._certificates,
        "is_preview_gateway_certificate_authorized",
        lambda **_values: True,
    )
    try:
        await owner.start()
        with pytest.raises(ProductionPreviewRelayError, match="already started"):
            await owner.start()
    finally:
        await owner.aclose()
        owner.close()


def test_production_relay_owner_rejects_source_product_revision_drift() -> None:
    with pytest.raises(ProductionPreviewRelayError, match="release identity"):
        load_production_preview_relay_owner_config(
            {
                "OMNIGENT_SAAS_SOURCE_SHA": "a" * 40,
                "OMNIGENT_SAAS_PRODUCT_REVISION": "b" * 40,
            }
        )


class _ReachedBindings(RuntimeError):
    pass


class _ReachedReceipt(RuntimeError):
    pass


def _owner_release() -> dict[str, str]:
    return {
        "OMNIGENT_SAAS_SOURCE_SHA": "a" * 40,
        "OMNIGENT_SAAS_PRODUCT_REVISION": "a" * 40,
        "OMNIGENT_SAAS_IMAGE_DIGEST": "sha256:" + "b" * 64,
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": "official0001",
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": "p0s000000011",
    }


def test_production_relay_owner_exact_release_reaches_narrow_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        preview_relay,
        "load_production_service_role_bindings",
        lambda _source: (_ for _ in ()).throw(_ReachedBindings()),
    )

    with pytest.raises(_ReachedBindings):
        load_production_preview_relay_owner_config(_owner_release())


def test_production_relay_owner_requires_receipt_bound_to_ten_role_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bindings = SimpleNamespace(
        sha256="d" * 64,
        login_for=lambda service: (
            "preview_owner_login" if service == "preview_owner" else "unexpected"
        ),
    )
    monkeypatch.setattr(
        preview_relay, "load_production_service_role_bindings", lambda _source: bindings
    )
    monkeypatch.setattr(
        preview_relay,
        "load_production_database_url_file",
        lambda _source, _service: (
            "postgresql+psycopg://redacted",
            SimpleNamespace(username="preview_owner_login"),
            Path("/runtime/preview-owner-database-url"),
        ),
    )
    monkeypatch.setattr(
        preview_relay,
        "load_production_migration_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(_ReachedReceipt()),
    )

    with pytest.raises(_ReachedReceipt):
        load_production_preview_relay_owner_config(_owner_release())


def test_production_relay_owner_rejects_other_service_database_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        preview_relay,
        "load_production_service_role_bindings",
        lambda _source: (_ for _ in ()).throw(_ReachedBindings()),
    )
    source = _owner_release()
    source["OMNIGENT_SAAS_PREVIEW_EDGE_DATABASE_URL_FILE"] = "/runtime/edge-url"

    with pytest.raises(ProductionPreviewRelayError, match="must not receive"):
        load_production_preview_relay_owner_config(source)
