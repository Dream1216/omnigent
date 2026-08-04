from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from saas.control_plane.isolation import IsolationControlPlaneError, SecretMaterial
from saas.secret_broker_transport import (
    MutualTlsSecretBrokerClient,
    MutualTlsSecretBrokerServer,
    SecretBrokerTransportError,
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


def _certificate_fixture(root: Path, runner_ids: tuple[UUID, ...]) -> dict[str, _CertificateFiles]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Omnigent Test CA")])
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
    ca_path = root / "ca.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))

    def issue(
        name: str,
        *,
        san: x509.SubjectAlternativeName,
        extended_usage: ObjectIdentifier,
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
            .add_extension(san, critical=False)
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
        certificate_path = root / f"{name}.pem"
        private_key_path = root / f"{name}-key.pem"
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        _write_private_key(private_key_path, key)
        return _CertificateFiles(ca_path, certificate_path, private_key_path)

    certificates = {
        "server": issue(
            "secret-broker",
            san=x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            extended_usage=ExtendedKeyUsageOID.SERVER_AUTH,
        )
    }
    for index, runner_id in enumerate(runner_ids):
        certificates[f"runner-{index}"] = issue(
            f"runner-{index}",
            san=x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"spiffe://omnigent/runner/{runner_id}")]
            ),
            extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
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


def _client_context(files: _CertificateFiles, *, with_certificate: bool = True) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(files.ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    if with_certificate:
        context.load_cert_chain(str(files.certificate), str(files.private_key))
    return context


class _ServerSecretProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str:
        self.calls.append((provider, vault_ref, version_ref))
        return "broker-only-plaintext"


class _RunnerProviderMustNotRun:
    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str:
        del provider, vault_ref, version_ref
        raise AssertionError("Runner-side provider must never resolve Vault material")


class _Authority:
    def __init__(self, *, expected_runner_id: UUID, provider: _ServerSecretProvider) -> None:
        self.expected_runner_id = expected_runner_id
        self.provider = provider
        self.calls: list[tuple[str, UUID, UUID]] = []

    def redeem_secret(
        self, *, token: str, runner_id: UUID, run_id: UUID, provider
    ) -> SecretMaterial:
        self.calls.append((token, runner_id, run_id))
        if runner_id != self.expected_runner_id:
            raise IsolationControlPlaneError(
                "secret_lease_stale", "certificate Runner does not match the lease"
            )
        if token != "lease-token-once":
            raise IsolationControlPlaneError("secret_lease_invalid", "secret lease is invalid")
        value = provider.resolve(provider="vault", vault_ref="kv/team/api", version_ref="v7")
        return SecretMaterial(
            binding_id=UUID("00000000-0000-4000-8000-000000000123"),
            name="API_TOKEN",
            host="api.example.test",
            credential_scheme="bearer",
            username=None,
            inject_env=("API_TOKEN",),
            value=value,
        )


class _BrokerThread:
    def __init__(self, server: MutualTlsSecretBrokerServer) -> None:
        self._server = server
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run,
            name="test-secret-broker",
            daemon=False,
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
            raise TimeoutError("Secret Broker test thread did not start")
        if self._startup_error is not None:
            raise RuntimeError("Secret Broker test thread failed") from self._startup_error

    def close(self) -> None:
        future = asyncio.run_coroutine_threadsafe(self._server.aclose(), self._loop)
        try:
            future.result(timeout=5)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise TimeoutError("Secret Broker test thread did not stop")


def _started_broker(
    tmp_path: Path,
    *,
    runner_ids: tuple[UUID, ...],
    expected_runner_id: UUID,
    max_replay_entries: int = 4096,
) -> tuple[
    MutualTlsSecretBrokerServer,
    _BrokerThread,
    _Authority,
    _ServerSecretProvider,
    dict[str, _CertificateFiles],
]:
    certificates = _certificate_fixture(tmp_path, runner_ids)
    provider = _ServerSecretProvider()
    authority = _Authority(expected_runner_id=expected_runner_id, provider=provider)
    server = MutualTlsSecretBrokerServer(
        authority,
        provider,
        _server_context(certificates["server"]),
        max_replay_entries=max_replay_entries,
    )
    broker_thread = _BrokerThread(server)
    broker_thread.start()
    return server, broker_thread, authority, provider, certificates


def test_mtls_secret_broker_binds_certificate_runner_and_keeps_vault_server_side(
    tmp_path: Path,
) -> None:
    runner_id = uuid4()
    run_id = uuid4()
    server, broker_thread, authority, provider, certificates = _started_broker(
        tmp_path,
        runner_ids=(runner_id,),
        expected_runner_id=runner_id,
    )
    client = MutualTlsSecretBrokerClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"]),
    )
    try:
        material = client.redeem_secret(
            token="lease-token-once",
            runner_id=runner_id,
            run_id=run_id,
            provider=_RunnerProviderMustNotRun(),
        )
    finally:
        client.close()
        broker_thread.close()

    assert material.value == "broker-only-plaintext"
    assert authority.calls == [("lease-token-once", runner_id, run_id)]
    assert provider.calls == [("vault", "kv/team/api", "v7")]


def test_mtls_secret_broker_bounds_replay_cache_and_rejects_duplicate_json_members(
    tmp_path: Path,
) -> None:
    runner_id = uuid4()
    run_id = uuid4()
    server, broker_thread, authority, _, certificates = _started_broker(
        tmp_path,
        runner_ids=(runner_id,),
        expected_runner_id=runner_id,
        max_replay_entries=1,
    )
    client = MutualTlsSecretBrokerClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"]),
    )
    try:
        client.redeem_secret(
            token="lease-token-once",
            runner_id=runner_id,
            run_id=run_id,
            provider=_RunnerProviderMustNotRun(),
        )
        with pytest.raises(SecretBrokerTransportError) as cache_full:
            client.redeem_secret(
                token="lease-token-once",
                runner_id=runner_id,
                run_id=run_id,
                provider=_RunnerProviderMustNotRun(),
            )
        assert cache_full.value.code == "secret_broker_busy"

        request_id = uuid4()
        body = (
            '{"lease_token":"lease-token-once","request_id":"'
            f'{request_id}","request_id":"{request_id}","run_id":"{run_id}"}}'
        ).encode()
        request = (
            "POST /v1/secret-leases/redeem HTTP/1.1\r\n"
            "host: secret-broker.internal\r\n"
            "content-type: application/json\r\n"
            f"content-length: {len(body)}\r\n\r\n"
        ).encode() + body
        with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw_socket:
            with _client_context(certificates["runner-0"]).wrap_socket(
                raw_socket,
                server_hostname="127.0.0.1",
            ) as tls_socket:
                tls_socket.sendall(request)
                response_parts: list[bytes] = []
                while part := tls_socket.recv(65_536):
                    response_parts.append(part)
        response = b"".join(response_parts)
        assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")
        assert b"secret_broker_request_invalid" in response
    finally:
        client.close()
        broker_thread.close()

    assert authority.calls == [("lease-token-once", runner_id, run_id)]


def test_mtls_secret_broker_same_request_replays_only_to_same_certificate_authority(
    tmp_path: Path,
) -> None:
    runner_id = uuid4()
    run_id = uuid4()
    server, broker_thread, authority, _, certificates = _started_broker(
        tmp_path,
        runner_ids=(runner_id,),
        expected_runner_id=runner_id,
    )
    client = MutualTlsSecretBrokerClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"]),
    )
    request_id = uuid4()
    try:
        first = client.redeem_secret(
            token="lease-token-once",
            runner_id=runner_id,
            run_id=run_id,
            provider=_RunnerProviderMustNotRun(),
            request_id=request_id,
        )
        replay = client.redeem_secret(
            token="lease-token-once",
            runner_id=runner_id,
            run_id=run_id,
            provider=_RunnerProviderMustNotRun(),
            request_id=request_id,
        )
        with pytest.raises(SecretBrokerTransportError) as mismatch:
            client.redeem_secret(
                token="lease-token-once",
                runner_id=runner_id,
                run_id=uuid4(),
                provider=_RunnerProviderMustNotRun(),
                request_id=request_id,
            )
        assert mismatch.value.code == "secret_broker_request_replay_mismatch"
    finally:
        client.close()
        broker_thread.close()

    assert first == replay
    assert authority.calls == [("lease-token-once", runner_id, run_id)]


def test_mtls_secret_broker_rejects_wrong_runner_certificate_and_missing_client_cert(
    tmp_path: Path,
) -> None:
    expected_runner_id = uuid4()
    wrong_runner_id = uuid4()
    server, broker_thread, authority, _, certificates = _started_broker(
        tmp_path,
        runner_ids=(expected_runner_id, wrong_runner_id),
        expected_runner_id=expected_runner_id,
    )
    wrong_client = MutualTlsSecretBrokerClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=wrong_runner_id,
        tls_context=_client_context(certificates["runner-1"]),
    )
    no_certificate_client = MutualTlsSecretBrokerClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=expected_runner_id,
        tls_context=_client_context(certificates["runner-0"], with_certificate=False),
    )
    try:
        with pytest.raises(SecretBrokerTransportError) as wrong_identity:
            wrong_client.redeem_secret(
                token="lease-token-once",
                runner_id=wrong_runner_id,
                run_id=uuid4(),
                provider=_RunnerProviderMustNotRun(),
            )
        assert wrong_identity.value.code == "secret_broker_redemption_denied"

        with pytest.raises(SecretBrokerTransportError) as missing_certificate:
            no_certificate_client.redeem_secret(
                token="lease-token-once",
                runner_id=expected_runner_id,
                run_id=uuid4(),
                provider=_RunnerProviderMustNotRun(),
            )
        assert missing_certificate.value.code == "secret_broker_unavailable"
    finally:
        wrong_client.close()
        no_certificate_client.close()
        broker_thread.close()

    assert authority.calls[0][1] == wrong_runner_id


def test_mtls_secret_broker_rejects_weak_or_nonverifying_tls_context(tmp_path: Path) -> None:
    runner_id = uuid4()
    certificates = _certificate_fixture(tmp_path, (runner_id,))
    provider = _ServerSecretProvider()
    authority = _Authority(expected_runner_id=runner_id, provider=provider)

    weak_server_context = _server_context(certificates["server"])
    weak_server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises(ValueError, match=r"TLS 1\.3"):
        MutualTlsSecretBrokerServer(authority, provider, weak_server_context)

    weak_client_context = _client_context(certificates["runner-0"])
    weak_client_context.check_hostname = False
    with pytest.raises(ValueError, match="hostname"):
        MutualTlsSecretBrokerClient(
            base_url="https://127.0.0.1:8443",
            runner_id=runner_id,
            tls_context=weak_client_context,
        )

    broad_client_context = _client_context(certificates["runner-0"])
    broad_client_context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    with pytest.raises(ValueError, match=r"only TLS 1\.3"):
        MutualTlsSecretBrokerClient(
            base_url="https://127.0.0.1:8443",
            runner_id=runner_id,
            tls_context=broad_client_context,
        )
