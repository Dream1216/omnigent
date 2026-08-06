from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from saas.billing_metering_transport import (
    BillingMeteringTransportError,
    MutualTlsBillingMeteringClient,
    MutualTlsBillingMeteringServer,
)
from saas.control_plane import MeteredUsage


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


def _certificate_fixture(
    root: Path,
    runner_ids: tuple[UUID, ...],
    *,
    extra_runner_uri: bool = False,
) -> dict[str, _CertificateFiles]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Omnigent Metering CA")])
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
    ca_path = root / "metering-ca.pem"
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
            "billing-metering",
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
        uris = [x509.UniformResourceIdentifier(f"spiffe://omnigent/runner/{runner_id}")]
        if extra_runner_uri and index == 0:
            uris.append(x509.UniformResourceIdentifier("spiffe://omnigent/runner/extra"))
        certificates[f"runner-{index}"] = issue(
            f"metering-runner-{index}",
            san=x509.SubjectAlternativeName(uris),
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


class _Authority:
    def __init__(self, *, fail: bool = False, oversized_response: bool = False) -> None:
        self.fail = fail
        self.oversized_response = oversized_response
        self.calls: list[dict[str, object]] = []
        self._receipts: dict[str, MeteredUsage] = {}

    def record_usage(
        self,
        *,
        runner_id: UUID,
        certificate_fingerprint_sha256: str,
        capability_token: str,
        run_id: UUID,
        meter: str,
        quantity: Decimal | str | int,
        unit: str,
        provider: str,
        provider_request_id: str,
        idempotency_key: str,
        occurred_at: datetime,
        attributes: dict[str, object] | None = None,
        now: datetime | None = None,
    ) -> MeteredUsage:
        assert now is None
        self.calls.append(
            {
                "attributes": attributes,
                "capability_token": capability_token,
                "certificate_fingerprint_sha256": certificate_fingerprint_sha256,
                "idempotency_key": idempotency_key,
                "meter": meter,
                "provider": provider,
                "provider_request_id": provider_request_id,
                "quantity": str(quantity),
                "run_id": run_id,
                "runner_id": runner_id,
                "unit": unit,
            }
        )
        if self.fail:
            raise RuntimeError("must not escape the server")
        existing = self._receipts.get(idempotency_key)
        if existing is not None:
            return replace(existing, replayed=True)
        usage = MeteredUsage(
            receipt_id=uuid4(),
            usage_event_id=uuid4(),
            tenant_id=uuid4(),
            space_id=uuid4(),
            project_id=uuid4(),
            run_id=run_id,
            runner_id=runner_id,
            pricing_snapshot_id=uuid4(),
            meter="x" * 9_000 if self.oversized_response else meter,
            quantity=Decimal(str(quantity)),
            unit=unit,
            currency="USD",
            customer_charge_minor=38,
            occurred_at=occurred_at,
            recorded_at=occurred_at + timedelta(milliseconds=1),
        )
        self._receipts[idempotency_key] = usage
        return usage


class _CertificateAuthorizer:
    def __init__(self, allowed_runner_ids: tuple[UUID, ...]) -> None:
        self.allowed_runner_ids = frozenset(allowed_runner_ids)
        self.calls: list[tuple[UUID, str, bytes]] = []

    def is_runner_certificate_authorized(
        self,
        *,
        runner_id: UUID,
        certificate_der: bytes,
        purpose: str,
    ) -> bool:
        self.calls.append((runner_id, purpose, certificate_der))
        return runner_id in self.allowed_runner_ids


class _ServerThread:
    def __init__(self, server: MutualTlsBillingMeteringServer) -> None:
        self._server = server
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run, name="test-billing-metering", daemon=False
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
            raise TimeoutError("Billing Metering test thread did not start")
        if self._startup_error is not None:
            raise RuntimeError("Billing Metering test thread failed") from self._startup_error

    def close(self) -> None:
        future = asyncio.run_coroutine_threadsafe(self._server.aclose(), self._loop)
        try:
            future.result(timeout=5)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise TimeoutError("Billing Metering test thread did not stop")


def _started_server(
    tmp_path: Path,
    *,
    runner_ids: tuple[UUID, ...],
    allowed_runner_ids: tuple[UUID, ...] | None = None,
    fail: bool = False,
    oversized_response: bool = False,
    extra_runner_uri: bool = False,
) -> tuple[
    MutualTlsBillingMeteringServer,
    _ServerThread,
    _Authority,
    _CertificateAuthorizer,
    dict[str, _CertificateFiles],
]:
    certificates = _certificate_fixture(
        tmp_path,
        runner_ids,
        extra_runner_uri=extra_runner_uri,
    )
    authority = _Authority(fail=fail, oversized_response=oversized_response)
    authorizer = _CertificateAuthorizer(
        runner_ids if allowed_runner_ids is None else allowed_runner_ids
    )
    server = MutualTlsBillingMeteringServer(
        authority,
        _server_context(certificates["server"]),
        authorizer,
    )
    thread = _ServerThread(server)
    thread.start()
    return server, thread, authority, authorizer, certificates


def _record(client: MutualTlsBillingMeteringClient, runner_id: UUID, run_id: UUID):
    return client.record_usage(
        runner_id=runner_id,
        capability_token="capability-token",
        run_id=run_id,
        meter="llm.input_tokens",
        quantity="1500",
        unit="tokens",
        provider="openai",
        provider_request_id="provider-request-1",
        idempotency_key="stable-metering-key",
        occurred_at=datetime.now(timezone.utc).replace(microsecond=0),
        attributes={"model": "gpt-5"},
    )


def test_mtls_metering_derives_certificate_identity_and_replays_in_authority(
    tmp_path: Path,
) -> None:
    runner_id, run_id = uuid4(), uuid4()
    server, thread, authority, authorizer, certificates = _started_server(
        tmp_path,
        runner_ids=(runner_id,),
    )
    client = MutualTlsBillingMeteringClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"]),
    )
    try:
        created = _record(client, runner_id, run_id)
        replayed = _record(client, runner_id, run_id)
    finally:
        client.close()
        thread.close()

    certificate = x509.load_pem_x509_certificate(certificates["runner-0"].certificate.read_bytes())
    fingerprint = sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    assert created.replayed is False
    assert replayed.receipt_id == created.receipt_id
    assert replayed.replayed is True
    assert len(authority.calls) == 2
    assert all(call["runner_id"] == runner_id for call in authority.calls)
    assert all(call["certificate_fingerprint_sha256"] == fingerprint for call in authority.calls)
    assert all(
        "tenant_id" not in call and "pricing_snapshot_id" not in call for call in authority.calls
    )
    assert [(runner, purpose) for runner, purpose, _der in authorizer.calls] == [
        (runner_id, "billing_metering"),
        (runner_id, "billing_metering"),
    ]


def test_mtls_metering_rejects_duplicate_json_and_caller_scope(tmp_path: Path) -> None:
    runner_id, run_id = uuid4(), uuid4()
    server, thread, authority, _, certificates = _started_server(
        tmp_path,
        runner_ids=(runner_id,),
    )
    occurred_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    duplicate = (
        '{"attributes":{},"capability_token":"capability-token",'
        '"idempotency_key":"stable","meter":"llm.input_tokens",'
        f'"occurred_at":"{occurred_at}","provider":"openai",'
        '"provider_request_id":"provider-request",'
        '"quantity":"1","quantity":"2",'
        f'"run_id":"{run_id}","unit":"tokens"}}'
    ).encode()
    caller_scope = duplicate.replace(
        b'"unit":"tokens"',
        b'"tenant_id":"00000000-0000-4000-8000-000000000001","unit":"tokens"',
    ).replace(b'"quantity":"1","quantity":"2",', b'"quantity":"1",')

    try:
        requests = [
            (
                "POST /internal/v1/billing/usage HTTP/1.1\r\n"
                "host: billing-metering.internal\r\n"
                "content-type: application/json\r\n"
                f"content-length: {len(body)}\r\n\r\n"
            ).encode()
            + body
            for body in (duplicate, caller_scope)
        ]
        requests.append(
            (
                "POST /internal/v1/billing/usage HTTP/1.1\r\n"
                "host: billing-metering.internal\r\n"
                "content-type: application/json\r\n"
                f"content-length: +{len(caller_scope)}\r\n\r\n"
            ).encode()
            + caller_scope
        )
        for request in requests:
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
            assert b"billing_metering_request_invalid" in response
    finally:
        thread.close()
    assert authority.calls == []


def test_mtls_metering_checks_durable_certificate_and_does_not_hide_retry(tmp_path: Path) -> None:
    runner_id, run_id = uuid4(), uuid4()
    denied_root = tmp_path / "denied"
    denied_root.mkdir()
    server, thread, authority, authorizer, certificates = _started_server(
        denied_root,
        runner_ids=(runner_id,),
        allowed_runner_ids=(),
    )
    client = MutualTlsBillingMeteringClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"]),
    )
    try:
        with pytest.raises(BillingMeteringTransportError) as denied:
            _record(client, runner_id, run_id)
        assert denied.value.code == "billing_metering_runner_certificate_denied"
    finally:
        client.close()
        thread.close()
    assert authority.calls == []
    assert authorizer.calls[0][1] == "billing_metering"

    failing_root = tmp_path / "failing"
    failing_root.mkdir()
    server, thread, authority, _, certificates = _started_server(
        failing_root,
        runner_ids=(runner_id,),
        fail=True,
    )
    client = MutualTlsBillingMeteringClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"]),
    )
    try:
        with pytest.raises(BillingMeteringTransportError) as failed:
            _record(client, runner_id, run_id)
        assert failed.value.code == "billing_metering_internal_error"
    finally:
        client.close()
        thread.close()
    assert len(authority.calls) == 1


def test_mtls_metering_bounds_response_before_buffering(tmp_path: Path) -> None:
    runner_id, run_id = uuid4(), uuid4()
    server, thread, authority, _, certificates = _started_server(
        tmp_path,
        runner_ids=(runner_id,),
        oversized_response=True,
    )
    client = MutualTlsBillingMeteringClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"]),
    )
    try:
        with pytest.raises(BillingMeteringTransportError) as oversized:
            _record(client, runner_id, run_id)
        assert oversized.value.code == "billing_metering_response_invalid"
    finally:
        client.close()
        thread.close()
    assert len(authority.calls) == 1


def test_mtls_metering_rejects_ambiguous_identity_missing_certificate_and_wrong_runner(
    tmp_path: Path,
) -> None:
    runner_id = uuid4()
    server, thread, authority, _, certificates = _started_server(
        tmp_path,
        runner_ids=(runner_id,),
        extra_runner_uri=True,
    )
    ambiguous = MutualTlsBillingMeteringClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"]),
    )
    missing = MutualTlsBillingMeteringClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=runner_id,
        tls_context=_client_context(certificates["runner-0"], with_certificate=False),
    )
    try:
        with pytest.raises(BillingMeteringTransportError) as identity:
            _record(ambiguous, runner_id, uuid4())
        assert identity.value.code == "billing_metering_runner_identity_invalid"
        with pytest.raises(BillingMeteringTransportError) as no_certificate:
            _record(missing, runner_id, uuid4())
        assert no_certificate.value.code == "billing_metering_unavailable"
        with pytest.raises(BillingMeteringTransportError) as wrong_runner:
            _record(ambiguous, uuid4(), uuid4())
        assert wrong_runner.value.code == "billing_metering_runner_identity_mismatch"
    finally:
        ambiguous.close()
        missing.close()
        thread.close()
    assert authority.calls == []


def test_mtls_metering_rejects_weak_or_nonverifying_tls_context(tmp_path: Path) -> None:
    runner_id = uuid4()
    certificates = _certificate_fixture(tmp_path, (runner_id,))
    authority = _Authority()
    authorizer = _CertificateAuthorizer((runner_id,))

    weak_server = _server_context(certificates["server"])
    weak_server.minimum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises(ValueError, match=r"TLS 1\.3"):
        MutualTlsBillingMeteringServer(authority, weak_server, authorizer)

    weak_client = _client_context(certificates["runner-0"])
    weak_client.check_hostname = False
    with pytest.raises(ValueError, match="hostname"):
        MutualTlsBillingMeteringClient(
            base_url="https://127.0.0.1:8443",
            runner_id=runner_id,
            tls_context=weak_client,
        )

    broad_client = _client_context(certificates["runner-0"])
    broad_client.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    with pytest.raises(ValueError, match=r"only TLS 1\.3"):
        MutualTlsBillingMeteringClient(
            base_url="https://127.0.0.1:8443",
            runner_id=runner_id,
            tls_context=broad_client,
        )
