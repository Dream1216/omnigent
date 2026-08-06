"""TLS 1.3 mutual-authentication transport for execution-bound billing usage."""

from __future__ import annotations

import asyncio
import json
import re
import ssl
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import Protocol, TypedDict
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from saas.control_plane.billing_metering import (
    BillingMeteringError,
    MeteredUsage,
)

_RECORD_USAGE_PATH = "/internal/v1/billing/usage"
_RUNNER_SPIFFE_ID = re.compile(
    r"^spiffe://omnigent/runner/"
    r"(?P<runner>[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
_INTERNAL_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_REQUEST_HEAD_BYTES = 16_384
_MAX_REQUEST_BODY_BYTES = 8_192
_MAX_RESPONSE_BODY_BYTES = 8_192
_REQUEST_FIELDS = frozenset(
    {
        "attributes",
        "capability_token",
        "idempotency_key",
        "meter",
        "occurred_at",
        "provider",
        "provider_request_id",
        "quantity",
        "run_id",
        "unit",
    }
)
_RESPONSE_FIELDS = frozenset(
    {
        "currency",
        "customer_charge_minor",
        "meter",
        "occurred_at",
        "pricing_snapshot_id",
        "project_id",
        "quantity",
        "receipt_id",
        "recorded_at",
        "replayed",
        "run_id",
        "runner_id",
        "space_id",
        "tenant_id",
        "unit",
        "usage_event_id",
    }
)


class BillingMeteringRecorder(Protocol):
    """Server-side authority; scope and price are deliberately not caller inputs."""

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
    ) -> MeteredUsage: ...


class MeteringCertificateAuthorizer(Protocol):
    """Durable certificate-revocation and Runner-generation authority."""

    def is_runner_certificate_authorized(
        self,
        *,
        runner_id: UUID,
        certificate_der: bytes,
        purpose: str,
    ) -> bool: ...


class BillingMeteringTransportError(RuntimeError):
    """Stable fail-closed error that never contains certificate or capability data."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _MeteringRequest(TypedDict):
    attributes: dict[str, object]
    capability_token: str
    idempotency_key: str
    meter: str
    occurred_at: datetime
    provider: str
    provider_request_id: str
    quantity: str
    run_id: UUID
    unit: str


def _require_tls13(context: ssl.SSLContext, *, server: bool) -> None:
    if (
        context.minimum_version != ssl.TLSVersion.TLSv1_3
        or context.maximum_version != ssl.TLSVersion.TLSv1_3
    ):
        raise ValueError("Billing Metering TLS context must allow only TLS 1.3")
    if context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("Billing Metering TLS context must require peer certificates")
    if not server and not context.check_hostname:
        raise ValueError("Billing Metering client TLS context must verify the server hostname")


def _runner_certificate(writer: asyncio.StreamWriter) -> tuple[UUID, bytes]:
    ssl_object = writer.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject | ssl.SSLSocket):
        raise BillingMeteringTransportError(
            "billing_metering_mtls_required", "Billing Metering requires mutual TLS"
        )
    certificate = ssl_object.getpeercert()
    certificate_der = ssl_object.getpeercert(binary_form=True)
    subject_alt_names = certificate.get("subjectAltName", ()) if certificate else ()
    uri_identities = [
        value for kind, value in subject_alt_names if kind == "URI" and isinstance(value, str)
    ]
    if (
        len(uri_identities) != 1
        or not _RUNNER_SPIFFE_ID.fullmatch(uri_identities[0])
        or not isinstance(certificate_der, bytes)
        or not certificate_der
    ):
        raise BillingMeteringTransportError(
            "billing_metering_runner_identity_invalid",
            "Runner certificate identity is invalid",
        )
    matched = _RUNNER_SPIFFE_ID.fullmatch(uri_identities[0])
    assert matched is not None
    return UUID(matched.group("runner")), certificate_der


def _parse_headers(encoded: bytes) -> tuple[str, str, dict[str, list[str]]]:
    try:
        lines = encoded.decode("latin-1").split("\r\n")
        method, target, version = lines[0].split(" ")
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise BillingMeteringTransportError(
            "billing_metering_request_invalid", "Billing Metering request is invalid"
        ) from exc
    if version != "HTTP/1.1":
        raise BillingMeteringTransportError(
            "billing_metering_request_invalid", "Billing Metering requires HTTP/1.1"
        )
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line or line[:1].isspace():
            raise BillingMeteringTransportError(
                "billing_metering_request_invalid", "Billing Metering headers are invalid"
            )
        name, value = line.split(":", 1)
        lowered = name.strip().lower()
        stripped = value.strip()
        if (
            not lowered
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in lowered
            )
            or "\r" in stripped
            or "\n" in stripped
        ):
            raise BillingMeteringTransportError(
                "billing_metering_request_invalid", "Billing Metering headers are invalid"
            )
        headers.setdefault(lowered, []).append(stripped)
    return method, target, headers


def _one_header(headers: Mapping[str, list[str]], name: str) -> str:
    values = headers.get(name, [])
    if len(values) != 1:
        raise BillingMeteringTransportError(
            "billing_metering_request_invalid",
            f"Billing Metering {name} header is invalid",
        )
    return values[0]


def _strict_json_document(encoded: bytes) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("duplicate JSON member")
            document[key] = value
        return document

    document = json.loads(encoded.decode("utf-8"), object_pairs_hook=unique_object)
    if not isinstance(document, dict):
        raise ValueError("JSON document must be an object")
    return document


def _canonical_uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise ValueError("UUID is invalid")
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("UUID is not canonical")
    return parsed


def _aware_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("datetime is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("datetime must include an offset")
    return parsed


def _bounded_text(value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("text is invalid")
    return value


def _request_document(body: bytes) -> _MeteringRequest:
    try:
        document = _strict_json_document(body)
        if set(document) != _REQUEST_FIELDS:
            raise ValueError("request fields are invalid")
        attributes = document["attributes"]
        if not isinstance(attributes, dict):
            raise ValueError("attributes are invalid")
        return {
            "attributes": attributes,
            "capability_token": _bounded_text(document["capability_token"], 512),
            "idempotency_key": _bounded_text(document["idempotency_key"], 128),
            "meter": _bounded_text(document["meter"], 128),
            "occurred_at": _aware_datetime(document["occurred_at"]),
            "provider": _bounded_text(document["provider"], 64),
            "provider_request_id": _bounded_text(document["provider_request_id"], 256),
            "quantity": _bounded_text(document["quantity"], 128),
            "run_id": _canonical_uuid(document["run_id"]),
            "unit": _bounded_text(document["unit"], 64),
        }
    except (UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
        raise BillingMeteringTransportError(
            "billing_metering_request_invalid", "Billing Metering request body is invalid"
        ) from exc


def _usage_document(usage: MeteredUsage) -> bytes:
    return json.dumps(
        {
            "currency": usage.currency,
            "customer_charge_minor": usage.customer_charge_minor,
            "meter": usage.meter,
            "occurred_at": usage.occurred_at.isoformat(),
            "pricing_snapshot_id": str(usage.pricing_snapshot_id),
            "project_id": str(usage.project_id),
            "quantity": str(usage.quantity),
            "receipt_id": str(usage.receipt_id),
            "recorded_at": usage.recorded_at.isoformat(),
            "replayed": usage.replayed,
            "run_id": str(usage.run_id),
            "runner_id": str(usage.runner_id),
            "space_id": str(usage.space_id),
            "tenant_id": str(usage.tenant_id),
            "unit": usage.unit,
            "usage_event_id": str(usage.usage_event_id),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _error_document(code: str) -> bytes:
    return json.dumps({"detail": {"code": code}}, sort_keys=True, separators=(",", ":")).encode()


async def _write_response(
    writer: asyncio.StreamWriter,
    *,
    status: int,
    body: bytes,
) -> None:
    reason = {
        200: "OK",
        400: "Bad Request",
        403: "Forbidden",
        409: "Conflict",
        500: "Internal Server Error",
    }[status]
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "content-type: application/json\r\n"
        "cache-control: no-store\r\n"
        "pragma: no-cache\r\n"
        "x-content-type-options: nosniff\r\n"
        f"content-length: {len(body)}\r\n"
        "connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(head + body)
    await writer.drain()


class MutualTlsBillingMeteringServer:
    """Bounded internal server deriving Runner and certificate identity from mTLS."""

    def __init__(
        self,
        authority: BillingMeteringRecorder,
        tls_context: ssl.SSLContext,
        certificate_authorizer: MeteringCertificateAuthorizer,
        *,
        expected_host: str = "billing-metering.internal",
        request_timeout_seconds: float = 5.0,
    ) -> None:
        _require_tls13(tls_context, server=True)
        if not _INTERNAL_HOST.fullmatch(expected_host.lower()) or request_timeout_seconds <= 0:
            raise ValueError("Billing Metering server configuration is invalid")
        self._authority = authority
        self._tls_context = tls_context
        self._certificate_authorizer = certificate_authorizer
        self._expected_host = expected_host
        self._request_timeout_seconds = request_timeout_seconds
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Billing Metering server is not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if self._server is not None:
            raise RuntimeError("Billing Metering server is already started")
        self._server = await asyncio.start_server(
            self._handle_connection,
            host,
            port,
            ssl=self._tls_context,
            ssl_handshake_timeout=self._request_timeout_seconds,
            start_serving=True,
        )

    async def aclose(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            runner_id, certificate_der = _runner_certificate(writer)
            certificate_authorized = await asyncio.to_thread(
                self._certificate_authorizer.is_runner_certificate_authorized,
                runner_id=runner_id,
                certificate_der=certificate_der,
                purpose="billing_metering",
            )
            if not certificate_authorized:
                raise BillingMeteringTransportError(
                    "billing_metering_runner_certificate_denied",
                    "Runner certificate is not active",
                )
            encoded_head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=self._request_timeout_seconds,
            )
            if len(encoded_head) > _MAX_REQUEST_HEAD_BYTES:
                raise BillingMeteringTransportError(
                    "billing_metering_request_invalid", "Billing Metering headers are oversized"
                )
            method, target, headers = _parse_headers(encoded_head[:-4])
            if method != "POST" or target != _RECORD_USAGE_PATH:
                raise BillingMeteringTransportError(
                    "billing_metering_request_invalid", "Billing Metering route is invalid"
                )
            if (
                "transfer-encoding" in headers
                or _one_header(headers, "content-type").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise BillingMeteringTransportError(
                    "billing_metering_request_invalid", "Billing Metering body framing is invalid"
                )
            if _one_header(headers, "host").lower() != self._expected_host.lower():
                raise BillingMeteringTransportError(
                    "billing_metering_request_invalid", "Billing Metering host is invalid"
                )
            encoded_content_length = _one_header(headers, "content-length")
            if not encoded_content_length.isascii() or not encoded_content_length.isdigit():
                raise BillingMeteringTransportError(
                    "billing_metering_request_invalid", "Billing Metering length is invalid"
                )
            content_length = int(encoded_content_length)
            if not 1 <= content_length <= _MAX_REQUEST_BODY_BYTES:
                raise BillingMeteringTransportError(
                    "billing_metering_request_invalid", "Billing Metering body is oversized"
                )
            body = await asyncio.wait_for(
                reader.readexactly(content_length),
                timeout=self._request_timeout_seconds,
            )
            request = _request_document(body)
            usage = await asyncio.to_thread(
                self._authority.record_usage,
                runner_id=runner_id,
                certificate_fingerprint_sha256=sha256(certificate_der).hexdigest(),
                **request,
            )
            await _write_response(writer, status=200, body=_usage_document(usage))
        except BillingMeteringTransportError as exc:
            status = (
                403
                if exc.code
                in {
                    "billing_metering_mtls_required",
                    "billing_metering_runner_certificate_denied",
                    "billing_metering_runner_identity_invalid",
                }
                else 400
            )
            await _write_response(writer, status=status, body=_error_document(exc.code))
        except BillingMeteringError as exc:
            if exc.code in {
                "metering_idempotency_conflict",
                "metering_provider_request_duplicate",
            }:
                status = 409
            elif exc.code in {
                "metering_attributes_invalid",
                "metering_attributes_sensitive",
                "metering_certificate_invalid",
                "metering_quantity_invalid",
                "metering_time_invalid",
                "metering_value_invalid",
            }:
                status = 400
            else:
                status = 403
            await _write_response(writer, status=status, body=_error_document(exc.code))
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            await _write_response(
                writer,
                status=400,
                body=_error_document("billing_metering_request_invalid"),
            )
        except Exception:  # noqa: BLE001 - fail closed without leaking authority internals
            await _write_response(
                writer,
                status=500,
                body=_error_document("billing_metering_internal_error"),
            )
        finally:
            writer.close()
            with suppress(ConnectionError, ssl.SSLError):
                await writer.wait_closed()


class MutualTlsBillingMeteringClient:
    """Runner-side client with caller-owned, stable idempotency and no hidden retry."""

    def __init__(
        self,
        *,
        base_url: str,
        runner_id: UUID,
        tls_context: ssl.SSLContext,
        expected_host: str = "billing-metering.internal",
        timeout_seconds: float = 5.0,
    ) -> None:
        _require_tls13(tls_context, server=False)
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or timeout_seconds <= 0
            or not _INTERNAL_HOST.fullmatch(expected_host.lower())
        ):
            raise ValueError("Billing Metering client endpoint is invalid")
        self._runner_id = runner_id
        self._expected_host = expected_host
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            verify=tls_context,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def record_usage(
        self,
        *,
        runner_id: UUID,
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
    ) -> MeteredUsage:
        if runner_id != self._runner_id:
            raise BillingMeteringTransportError(
                "billing_metering_runner_identity_mismatch",
                "Runner does not match the configured certificate identity",
            )
        payload = {
            "attributes": attributes or {},
            "capability_token": capability_token,
            "idempotency_key": idempotency_key,
            "meter": meter,
            "occurred_at": occurred_at.isoformat(),
            "provider": provider,
            "provider_request_id": provider_request_id,
            "quantity": str(quantity),
            "run_id": str(run_id),
            "unit": unit,
        }
        try:
            encoded_payload = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        except (TypeError, ValueError) as exc:
            raise BillingMeteringTransportError(
                "billing_metering_request_invalid", "Billing Metering request is invalid"
            ) from exc
        if not 1 <= len(encoded_payload) <= _MAX_REQUEST_BODY_BYTES:
            raise BillingMeteringTransportError(
                "billing_metering_request_invalid", "Billing Metering request is oversized"
            )
        try:
            with self._client.stream(
                "POST",
                _RECORD_USAGE_PATH,
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                    "host": self._expected_host,
                },
                content=encoded_payload,
            ) as response:
                response_body = bytearray()
                for chunk in response.iter_bytes():
                    if len(response_body) + len(chunk) > _MAX_RESPONSE_BODY_BYTES:
                        raise BillingMeteringTransportError(
                            "billing_metering_response_invalid",
                            "Billing Metering response is oversized",
                        )
                    response_body.extend(chunk)
                response_status = response.status_code
                response_content_type = response.headers.get("content-type", "")
        except httpx.TransportError as exc:
            raise BillingMeteringTransportError(
                "billing_metering_unavailable", "Billing Metering is unavailable"
            ) from exc
        content_type = response_content_type.split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise BillingMeteringTransportError(
                "billing_metering_response_invalid", "Billing Metering content type is invalid"
            )
        try:
            document = _strict_json_document(bytes(response_body))
        except (UnicodeDecodeError, ValueError) as exc:
            raise BillingMeteringTransportError(
                "billing_metering_response_invalid", "Billing Metering response is invalid"
            ) from exc
        if response_status != 200:
            code = "billing_metering_denied"
            detail = document.get("detail")
            if isinstance(detail, dict) and isinstance(detail.get("code"), str):
                candidate = detail["code"]
                if _ERROR_CODE.fullmatch(candidate):
                    code = candidate
            raise BillingMeteringTransportError(code, "Billing Metering request failed")
        return _parse_usage_document(document)


def _parse_usage_document(document: dict[str, object]) -> MeteredUsage:
    try:
        if set(document) != _RESPONSE_FIELDS:
            raise ValueError("response fields are invalid")
        quantity_value = document["quantity"]
        if not isinstance(quantity_value, str):
            raise ValueError("quantity is invalid")
        quantity = Decimal(quantity_value)
        charge = document["customer_charge_minor"]
        replayed = document["replayed"]
        if (
            not quantity.is_finite()
            or quantity <= 0
            or type(charge) is not int
            or charge <= 0
            or not isinstance(replayed, bool)
        ):
            raise ValueError("usage values are invalid")
        return MeteredUsage(
            receipt_id=_canonical_uuid(document["receipt_id"]),
            usage_event_id=_canonical_uuid(document["usage_event_id"]),
            tenant_id=_canonical_uuid(document["tenant_id"]),
            space_id=_canonical_uuid(document["space_id"]),
            project_id=_canonical_uuid(document["project_id"]),
            run_id=_canonical_uuid(document["run_id"]),
            runner_id=_canonical_uuid(document["runner_id"]),
            pricing_snapshot_id=_canonical_uuid(document["pricing_snapshot_id"]),
            meter=_bounded_text(document["meter"], 128),
            quantity=quantity,
            unit=_bounded_text(document["unit"], 64),
            currency=_bounded_text(document["currency"], 3),
            customer_charge_minor=charge,
            occurred_at=_aware_datetime(document["occurred_at"]),
            recorded_at=_aware_datetime(document["recorded_at"]),
            replayed=replayed,
        )
    except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
        raise BillingMeteringTransportError(
            "billing_metering_response_invalid", "Billing Metering usage response is invalid"
        ) from exc


__all__ = [
    "BillingMeteringRecorder",
    "BillingMeteringTransportError",
    "MeteringCertificateAuthorizer",
    "MutualTlsBillingMeteringClient",
    "MutualTlsBillingMeteringServer",
]
