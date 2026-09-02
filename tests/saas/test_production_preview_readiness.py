from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from saas.preview_relay_transport import PreviewRelayEndpointPolicy
from saas.production import preview_readiness
from saas.production.preview_readiness import (
    PreviewReadinessError,
    RemoteTlsPreviewReadiness,
    TlsPreviewReadinessServer,
    build_preview_readiness_server_tls_context,
    build_remote_tls_preview_readiness,
)

_READY = (
    b"HTTP/1.1 200 OK\r\n"
    b"content-type: text/plain; charset=utf-8\r\n"
    b"content-length: 6\r\n"
    b"cache-control: no-store\r\n"
    b"connection: close\r\n\r\n"
    b"ready\n"
)


@dataclass(frozen=True)
class _Release:
    product_revision: str


def _tls_files(root: Path, server_name: str) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Preview Readiness CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(server_name),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = root / "readiness-ca.pem"
    certificate_path = root / "readiness-server.pem"
    key_path = root / "readiness-server-key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return ca_path, certificate_path, key_path


def _answer(address: str) -> tuple[int, int, int, str, tuple[object, ...]]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 8443)


def _policy() -> PreviewRelayEndpointPolicy:
    return PreviewRelayEndpointPolicy.from_strings(
        allowed_dns_suffixes=("omnigent.svc.cluster.local",),
        allowed_cidrs=("10.42.0.0/16",),
        allowed_ports=(8443,),
    )


def test_remote_preview_readiness_pins_policy_checked_numeric_address(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("test-ca", encoding="utf-8")
    calls: list[tuple[str, int, str, Path, float]] = []

    def probe(host: str, port: int, name: str, path: Path, timeout: float) -> bytes:
        calls.append((host, port, name, path, timeout))
        return _READY

    readiness = RemoteTlsPreviewReadiness(
        connect_host="preview-edge.omnigent.svc.cluster.local",
        port=8443,
        server_name="preview-edge.omnigent.svc.cluster.local",
        ca_certificate_path=ca,
        endpoint_policy=_policy(),
        getaddrinfo=lambda *_args, **_kwargs: [_answer("10.42.7.19")],
        probe=probe,
    )

    readiness.assert_production_ready()

    assert calls == [
        (
            "10.42.7.19",
            8443,
            "preview-edge.omnigent.svc.cluster.local",
            ca,
            2.0,
        )
    ]


@pytest.mark.parametrize(
    "answers",
    (
        [_answer("127.0.0.1")],
        [_answer("169.254.169.254")],
        [_answer("10.43.7.19")],
        [_answer("10.42.7.19"), _answer("169.254.169.254")],
    ),
)
def test_remote_preview_readiness_rejects_every_unallowed_or_mixed_answer(
    tmp_path: Path,
    answers: list[tuple[int, int, int, str, tuple[object, ...]]],
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("test-ca", encoding="utf-8")
    readiness = RemoteTlsPreviewReadiness(
        connect_host="preview-edge.omnigent.svc.cluster.local",
        port=8443,
        server_name="preview-edge.omnigent.svc.cluster.local",
        ca_certificate_path=ca,
        endpoint_policy=_policy(),
        getaddrinfo=lambda *_args, **_kwargs: answers,
        probe=lambda *_values: pytest.fail("denied address reached TLS probe"),
    )

    with pytest.raises(PreviewReadinessError, match="unavailable"):
        readiness.assert_production_ready()


def test_remote_preview_readiness_requires_exact_content_blind_response(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("test-ca", encoding="utf-8")
    readiness = RemoteTlsPreviewReadiness(
        connect_host="preview-edge.omnigent.svc.cluster.local",
        port=8443,
        server_name="preview-edge.omnigent.svc.cluster.local",
        ca_certificate_path=ca,
        endpoint_policy=_policy(),
        getaddrinfo=lambda *_args, **_kwargs: [_answer("10.42.7.19")],
        probe=lambda *_values: _READY + b"topology",
    )

    with pytest.raises(PreviewReadinessError, match="response"):
        readiness.assert_production_ready()


def test_preview_readiness_factory_rejects_release_drift_before_files() -> None:
    release = _Release(product_revision="b" * 40)

    with pytest.raises(PreviewReadinessError, match="release identity"):
        build_remote_tls_preview_readiness(
            config=release,
            environ={"OMNIGENT_SAAS_SOURCE_SHA": "a" * 40},
        )


def test_preview_readiness_factory_has_no_database_or_caller_url_input(
    tmp_path: Path,
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("test-ca", encoding="utf-8")
    release = _Release(product_revision="a" * 40)
    readiness = build_remote_tls_preview_readiness(
        config=release,
        environ={
            "OMNIGENT_SAAS_SOURCE_SHA": "a" * 40,
            "OMNIGENT_SAAS_PREVIEW_READINESS_HOST": ("preview-edge.omnigent.svc.cluster.local"),
            "OMNIGENT_SAAS_PREVIEW_READINESS_PORT": "8443",
            "OMNIGENT_SAAS_PREVIEW_READINESS_SERVER_NAME": (
                "preview-edge.omnigent.svc.cluster.local"
            ),
            "OMNIGENT_SAAS_PREVIEW_READINESS_CA_CERTIFICATE_FILE": str(ca.resolve()),
            "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_DNS_SUFFIXES": ("omnigent.svc.cluster.local"),
            "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_CIDRS": "10.42.0.0/16",
            "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_PORTS": "8443",
            "DATABASE_URL": "must-not-be-read",
            "CALLER_PREVIEW_URL": "https://attacker.invalid",
        },
    )

    assert readiness.connect_host == "preview-edge.omnigent.svc.cluster.local"
    assert readiness.server_name == "preview-edge.omnigent.svc.cluster.local"
    assert readiness.port == 8443


@pytest.mark.asyncio
async def test_tls_preview_readiness_server_closes_the_fixed_https_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_name = "preview-edge.omnigent.svc.cluster.local"
    ca, certificate, key = _tls_files(tmp_path, server_name)
    context = build_preview_readiness_server_tls_context(
        certificate_path=certificate,
        key_path=key,
    )
    server = TlsPreviewReadinessServer(
        context,
        server_name=server_name,
        readiness_probe=lambda: None,
    )
    await server.start(host="127.0.0.1", port=0)
    real_connect = socket.create_connection

    def routed_connect(address: tuple[str, int], timeout: float | None = None) -> socket.socket:
        assert address == ("10.42.7.19", server.port)
        return real_connect(("127.0.0.1", server.port), timeout)

    monkeypatch.setattr(preview_readiness.socket, "create_connection", routed_connect)
    readiness = RemoteTlsPreviewReadiness(
        connect_host=server_name,
        port=server.port,
        server_name=server_name,
        ca_certificate_path=ca,
        endpoint_policy=PreviewRelayEndpointPolicy.from_strings(
            allowed_dns_suffixes=("omnigent.svc.cluster.local",),
            allowed_cidrs=("10.42.0.0/16",),
            allowed_ports=(server.port,),
        ),
        getaddrinfo=lambda *_args, **_kwargs: [_answer("10.42.7.19")],
    )
    try:
        await asyncio.to_thread(readiness.assert_production_ready)
    finally:
        await server.aclose()
