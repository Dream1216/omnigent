"""mTLS workload transport for the managed Preview Gateway control-plane surface.

The Gateway process receives no PostgreSQL credential.  A separately provisioned
control identity is extracted from the real TLS peer certificate and bound to every
method and Gateway instance before a narrow authority call is made.  Relay leaves and
the platform-health probe identity are deliberately not valid control identities.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import math
import re
import ssl
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from saas.control_plane import (
    ActivatedPreviewGatewayCertificate,
    PreviewGatewayLifecycleError,
    RegisteredPreviewGateway,
)

_MAX_REQUEST_HEAD_BYTES = 8_192
_MAX_REQUEST_BODY_BYTES = 65_536
_MAX_RESPONSE_BODY_BYTES = 32_768
_CONTROL_IDENTITY = re.compile(
    r"^spiffe://omnigent/preview-gateway-control/"
    r"(?P<gateway>[A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
_GATEWAY_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_INTERNAL_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
_ACTION_PATHS = {
    "/internal/v1/preview-gateways/register": "register",
    "/internal/v1/preview-gateways/activate": "activate",
    "/internal/v1/preview-gateways/heartbeat": "heartbeat",
    "/internal/v1/preview-gateways/drain": "drain",
    "/internal/v1/preview-gateways/release": "release",
    "/internal/v1/preview-gateways/certificates/activate": "certificate_activate",
    "/internal/v1/preview-gateways/certificates/revoke": "certificate_revoke",
}
_ACTION_ROUTES = {action: path for path, action in _ACTION_PATHS.items()}


class PreviewGatewayControlTransportError(RuntimeError):
    """Stable control transport failure without credentials or topology details."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PreviewGatewayControlIdentityAuthorizer(Protocol):
    """Authorize one exact workload leaf and one fixed control method."""

    def is_preview_gateway_control_identity_authorized(
        self,
        *,
        gateway_instance_id: str,
        certificate_der: bytes,
        action: str,
    ) -> bool: ...


class PreviewGatewayDirectoryAuthority(Protocol):
    def register_gateway(
        self,
        *,
        gateway_instance_id: str,
        connect_host: str,
        connect_port: int,
        server_name: str,
        failure_domain: str,
        source_revision: str,
        adapter_contract_version: str,
        registration_token: str,
        lease_duration: timedelta = timedelta(seconds=45),
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway: ...

    def activate_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway: ...

    def heartbeat_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        lease_duration: timedelta = timedelta(seconds=45),
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway: ...

    def begin_draining(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> bool: ...

    def release_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        reason: str,
        now: datetime | None = None,
    ) -> bool: ...


class PreviewGatewayCertificateAuthority(Protocol):
    def activate_certificate(
        self,
        *,
        gateway_instance_id: str,
        purpose: str,
        certificate_der: bytes,
        trust_bundle_version: str,
        rotation_overlap: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> ActivatedPreviewGatewayCertificate: ...

    def revoke_certificate(
        self,
        *,
        fingerprint_sha256: str,
        reason: str,
        gateway_instance_id: str | None = None,
        now: datetime | None = None,
    ) -> bool: ...


def _require_tls13(context: ssl.SSLContext, *, server: bool) -> None:
    if (
        context.minimum_version != ssl.TLSVersion.TLSv1_3
        or context.maximum_version != ssl.TLSVersion.TLSv1_3
        or context.verify_mode != ssl.CERT_REQUIRED
    ):
        raise ValueError("Preview Gateway control transport must use only mutual TLS 1.3")
    if not server and not context.check_hostname:
        raise ValueError("Preview Gateway control client must verify the server hostname")


def _control_identity(writer: asyncio.StreamWriter) -> tuple[str, bytes]:
    ssl_object = writer.get_extra_info("ssl_object")
    certificate_der = (
        ssl_object.getpeercert(binary_form=True)
        if isinstance(ssl_object, ssl.SSLObject | ssl.SSLSocket)
        else None
    )
    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_mtls_required",
            "Preview Gateway control client certificate is required",
        )
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        names = list(
            certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        )
        uris = [name.value for name in names if isinstance(name, x509.UniformResourceIdentifier)]
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_identity_invalid",
            "Preview Gateway control identity is invalid",
        ) from exc
    match = _CONTROL_IDENTITY.fullmatch(uris[0]) if len(uris) == 1 else None
    if (
        match is None
        or len(names) != 1
        or basic.ca
        or not usage.digital_signature
        or usage.content_commitment
        or usage.key_encipherment
        or usage.data_encipherment
        or usage.key_agreement
        or usage.key_cert_sign
        or usage.crl_sign
        or frozenset(extended) != frozenset((ExtendedKeyUsageOID.CLIENT_AUTH,))
    ):
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_identity_invalid",
            "Preview Gateway control identity is invalid",
        )
    return match.group("gateway"), certificate_der


def _parse_headers(encoded: bytes) -> tuple[str, str, dict[str, list[str]]]:
    try:
        lines = encoded.decode("latin-1").split("\r\n")
        method, target, version = lines[0].split(" ")
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control request is invalid",
        ) from exc
    if version != "HTTP/1.1":
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control request requires HTTP/1.1",
        )
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line or line[:1].isspace():
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_request_invalid",
                "Preview Gateway control headers are invalid",
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
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_request_invalid",
                "Preview Gateway control headers are invalid",
            )
        headers.setdefault(lowered, []).append(stripped)
    return method, target, headers


def _one_header(headers: Mapping[str, list[str]], name: str) -> str:
    values = headers.get(name, [])
    if len(values) != 1:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control request headers are invalid",
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


def _exact(document: Mapping[str, object], fields: set[str]) -> None:
    if set(document) != fields:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control request fields are invalid",
        )


def _text(document: Mapping[str, object], name: str, *, maximum: int) -> str:
    value = document.get(name)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value.strip() != value
        or "\x00" in value
    ):
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control request value is invalid",
        )
    return value


def _gateway_identity(document: Mapping[str, object], expected: str) -> str:
    value = _text(document, "gateway_instance_id", maximum=128)
    if value != expected or _GATEWAY_INSTANCE.fullmatch(value) is None:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_identity_mismatch",
            "Preview Gateway control identity does not match the request",
        )
    return value


def _seconds(
    document: Mapping[str, object],
    name: str,
    *,
    maximum: float,
    allow_zero: bool = False,
) -> timedelta:
    value = document.get(name)
    numeric = (
        float(value) if isinstance(value, int | float) and not isinstance(value, bool) else -1
    )
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(numeric)
        or numeric > maximum
        or (numeric < 0 if allow_zero else numeric <= 0)
    ):
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control duration is invalid",
        )
    return timedelta(seconds=numeric)


def _response_exact(document: Mapping[str, object], fields: set[str]) -> None:
    if set(document) != fields:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_response_invalid",
            "Preview Gateway control response fields are invalid",
        )


def _certificate_der(document: Mapping[str, object]) -> bytes:
    encoded = _text(document, "certificate_der_base64", maximum=48_000)
    try:
        value = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control certificate is invalid",
        ) from exc
    if not 1 <= len(value) <= 32_768:
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control certificate is invalid",
        )
    return value


def _datetime_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("invalid datetime")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("datetime has no timezone")
    return parsed.astimezone(timezone.utc)


def _gateway_document(receipt: RegisteredPreviewGateway) -> dict[str, object]:
    return {
        "activated_at": _datetime_text(receipt.activated_at),
        "adapter_contract_version": receipt.adapter_contract_version,
        "connect_host": receipt.connect_host,
        "connect_port": receipt.connect_port,
        "failure_domain": receipt.failure_domain,
        "gateway_instance_id": receipt.gateway_instance_id,
        "last_heartbeat_at": _datetime_text(receipt.last_heartbeat_at),
        "lease_expires_at": _datetime_text(receipt.lease_expires_at),
        "registered_at": _datetime_text(receipt.registered_at),
        "server_name": receipt.server_name,
        "source_revision": receipt.source_revision,
        "status": receipt.status,
    }


def _certificate_document(
    receipt: ActivatedPreviewGatewayCertificate,
) -> dict[str, object]:
    return {
        "certificate_id": str(receipt.certificate_id),
        "certificate_not_after": _datetime_text(receipt.certificate_not_after),
        "fingerprint_sha256": receipt.fingerprint_sha256,
        "gateway_instance_id": receipt.gateway_instance_id,
        "purpose": receipt.purpose,
        "rotation_generation": receipt.rotation_generation,
        "trust_bundle_version": receipt.trust_bundle_version,
    }


def _error_document(code: str) -> bytes:
    return json.dumps({"detail": {"code": code}}, sort_keys=True, separators=(",", ":")).encode()


async def _write_response(writer: asyncio.StreamWriter, *, status: int, body: bytes) -> None:
    reason = {
        200: "OK",
        400: "Bad Request",
        403: "Forbidden",
        409: "Conflict",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }[status]
    writer.write(
        (
            f"HTTP/1.1 {status} {reason}\r\n"
            "content-type: application/json\r\n"
            "cache-control: no-store\r\n"
            "pragma: no-cache\r\n"
            "x-content-type-options: nosniff\r\n"
            f"content-length: {len(body)}\r\n"
            "connection: close\r\n\r\n"
        ).encode("ascii")
        + body
    )
    await writer.drain()


class MutualTlsPreviewGatewayControlServer:
    """Bounded TLS 1.3 method surface in front of privileged DB authorities."""

    def __init__(
        self,
        directory: PreviewGatewayDirectoryAuthority,
        certificate_authority: PreviewGatewayCertificateAuthority,
        tls_context: ssl.SSLContext,
        identity_authorizer: PreviewGatewayControlIdentityAuthorizer,
        *,
        expected_host: str = "preview-gateway-control.internal",
        request_timeout_seconds: float = 5.0,
    ) -> None:
        _require_tls13(tls_context, server=True)
        if _INTERNAL_HOST.fullmatch(expected_host.lower()) is None or request_timeout_seconds <= 0:
            raise ValueError("Preview Gateway control server configuration is invalid")
        self._directory = directory
        self._certificate_authority = certificate_authority
        self._tls_context = tls_context
        self._identity_authorizer = identity_authorizer
        self._expected_host = expected_host.lower()
        self._request_timeout_seconds = request_timeout_seconds
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Preview Gateway control server is not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if self._server is not None:
            raise RuntimeError("Preview Gateway control server is already started")
        self._server = await asyncio.start_server(
            self._handle_connection,
            host,
            port,
            ssl=self._tls_context,
            ssl_handshake_timeout=self._request_timeout_seconds,
            start_serving=True,
            limit=_MAX_REQUEST_HEAD_BYTES,
        )

    async def aclose(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _dispatch(
        self,
        *,
        action: str,
        gateway_instance_id: str,
        document: Mapping[str, object],
    ) -> dict[str, object]:
        _gateway_identity(document, gateway_instance_id)
        if action == "register":
            _exact(
                document,
                {
                    "adapter_contract_version",
                    "connect_host",
                    "connect_port",
                    "failure_domain",
                    "gateway_instance_id",
                    "lease_seconds",
                    "registration_token",
                    "server_name",
                    "source_revision",
                },
            )
            connect_port = document.get("connect_port")
            if isinstance(connect_port, bool) or not isinstance(connect_port, int):
                raise PreviewGatewayControlTransportError(
                    "preview_gateway_control_request_invalid",
                    "Preview Gateway control port is invalid",
                )
            receipt = await asyncio.to_thread(
                self._directory.register_gateway,
                gateway_instance_id=gateway_instance_id,
                connect_host=_text(document, "connect_host", maximum=253),
                connect_port=connect_port,
                server_name=_text(document, "server_name", maximum=253),
                failure_domain=_text(document, "failure_domain", maximum=128),
                source_revision=_text(document, "source_revision", maximum=64),
                adapter_contract_version=_text(document, "adapter_contract_version", maximum=32),
                registration_token=_text(document, "registration_token", maximum=512),
                lease_duration=_seconds(document, "lease_seconds", maximum=120),
            )
            return {"gateway": _gateway_document(receipt)}
        if action in {"activate", "heartbeat", "drain", "release"}:
            fields = {"gateway_instance_id", "registration_token"}
            if action == "heartbeat":
                fields.add("lease_seconds")
            if action == "release":
                fields.add("reason")
            _exact(document, fields)
            token = _text(document, "registration_token", maximum=512)
            if action == "activate":
                receipt = await asyncio.to_thread(
                    self._directory.activate_gateway,
                    gateway_instance_id=gateway_instance_id,
                    registration_token=token,
                )
                return {"gateway": _gateway_document(receipt)}
            if action == "heartbeat":
                receipt = await asyncio.to_thread(
                    self._directory.heartbeat_gateway,
                    gateway_instance_id=gateway_instance_id,
                    registration_token=token,
                    lease_duration=_seconds(document, "lease_seconds", maximum=120),
                )
                return {"gateway": _gateway_document(receipt)}
            if action == "drain":
                changed = await asyncio.to_thread(
                    self._directory.begin_draining,
                    gateway_instance_id=gateway_instance_id,
                    registration_token=token,
                )
                return {"changed": changed}
            changed = await asyncio.to_thread(
                self._directory.release_gateway,
                gateway_instance_id=gateway_instance_id,
                registration_token=token,
                reason=_text(document, "reason", maximum=256),
            )
            return {"changed": changed}
        if action == "certificate_activate":
            _exact(
                document,
                {
                    "certificate_der_base64",
                    "gateway_instance_id",
                    "purpose",
                    "rotation_overlap_seconds",
                    "trust_bundle_version",
                },
            )
            receipt = await asyncio.to_thread(
                self._certificate_authority.activate_certificate,
                gateway_instance_id=gateway_instance_id,
                purpose=_text(document, "purpose", maximum=64),
                certificate_der=_certificate_der(document),
                trust_bundle_version=_text(document, "trust_bundle_version", maximum=64),
                rotation_overlap=_seconds(
                    document,
                    "rotation_overlap_seconds",
                    maximum=900,
                    allow_zero=True,
                ),
            )
            return {"certificate": _certificate_document(receipt)}
        if action == "certificate_revoke":
            _exact(document, {"fingerprint_sha256", "gateway_instance_id", "reason"})
            changed = await asyncio.to_thread(
                self._certificate_authority.revoke_certificate,
                gateway_instance_id=gateway_instance_id,
                fingerprint_sha256=_text(document, "fingerprint_sha256", maximum=64),
                reason=_text(document, "reason", maximum=256),
            )
            return {"changed": changed}
        raise PreviewGatewayControlTransportError(
            "preview_gateway_control_request_invalid",
            "Preview Gateway control action is invalid",
        )

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        status = 500
        body = _error_document("preview_gateway_control_internal_error")
        try:
            gateway_instance_id, certificate_der = _control_identity(writer)
            encoded_head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=self._request_timeout_seconds
            )
            if len(encoded_head) > _MAX_REQUEST_HEAD_BYTES:
                raise PreviewGatewayControlTransportError(
                    "preview_gateway_control_request_invalid",
                    "Preview Gateway control headers are oversized",
                )
            method, target, headers = _parse_headers(encoded_head[:-4])
            action = _ACTION_PATHS.get(target)
            if method != "POST" or action is None:
                raise PreviewGatewayControlTransportError(
                    "preview_gateway_control_request_invalid",
                    "Preview Gateway control route is invalid",
                )
            authorized = await asyncio.to_thread(
                self._identity_authorizer.is_preview_gateway_control_identity_authorized,
                gateway_instance_id=gateway_instance_id,
                certificate_der=certificate_der,
                action=action,
            )
            if not authorized:
                raise PreviewGatewayControlTransportError(
                    "preview_gateway_control_identity_denied",
                    "Preview Gateway control identity is denied",
                )
            if (
                "transfer-encoding" in headers
                or _one_header(headers, "host").lower() != self._expected_host
                or _one_header(headers, "content-type").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise PreviewGatewayControlTransportError(
                    "preview_gateway_control_request_invalid",
                    "Preview Gateway control body framing is invalid",
                )
            length_text = _one_header(headers, "content-length")
            try:
                content_length = int(length_text)
            except ValueError as exc:
                raise PreviewGatewayControlTransportError(
                    "preview_gateway_control_request_invalid",
                    "Preview Gateway control length is invalid",
                ) from exc
            if (
                str(content_length) != length_text
                or not 1 <= content_length <= _MAX_REQUEST_BODY_BYTES
            ):
                raise PreviewGatewayControlTransportError(
                    "preview_gateway_control_request_invalid",
                    "Preview Gateway control body is oversized",
                )
            encoded_body = await asyncio.wait_for(
                reader.readexactly(content_length), timeout=self._request_timeout_seconds
            )
            try:
                document = _strict_json_document(encoded_body)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise PreviewGatewayControlTransportError(
                    "preview_gateway_control_request_invalid",
                    "Preview Gateway control body is invalid",
                ) from exc
            result = await self._dispatch(
                action=action,
                gateway_instance_id=gateway_instance_id,
                document=document,
            )
            body = json.dumps(
                result, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
            status = 200
        except PreviewGatewayControlTransportError as exc:
            status = (
                403
                if exc.code
                in {
                    "preview_gateway_control_identity_denied",
                    "preview_gateway_control_identity_invalid",
                    "preview_gateway_control_identity_mismatch",
                    "preview_gateway_control_mtls_required",
                }
                else 400
            )
            body = _error_document(exc.code)
        except PreviewGatewayLifecycleError as exc:
            status = 409
            body = _error_document(exc.code)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
            status = 400
            body = _error_document("preview_gateway_control_request_invalid")
        except Exception:  # noqa: BLE001 - fail closed without leaking service internals
            status = 500
            body = _error_document("preview_gateway_control_internal_error")
        try:
            await _write_response(writer, status=status, body=body)
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            writer.close()
            with suppress(ConnectionError, ssl.SSLError):
                await writer.wait_closed()


class MutualTlsPreviewGatewayControlClient:
    """Synchronous narrow client implementing the Gateway runtime authority protocols."""

    def __init__(
        self,
        *,
        base_url: str,
        gateway_instance_id: str,
        tls_context: ssl.SSLContext,
        expected_host: str = "preview-gateway-control.internal",
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
            or _GATEWAY_INSTANCE.fullmatch(gateway_instance_id) is None
            or _INTERNAL_HOST.fullmatch(expected_host.lower()) is None
            or timeout_seconds <= 0
        ):
            raise ValueError("Preview Gateway control client configuration is invalid")
        self._gateway_instance_id = gateway_instance_id
        self._expected_host = expected_host.lower()
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            verify=tls_context,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def _identity(self, gateway_instance_id: str) -> None:
        if gateway_instance_id != self._gateway_instance_id:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_identity_mismatch",
                "Preview Gateway control identity does not match the client",
            )

    @staticmethod
    def _server_time(now: datetime | None) -> None:
        if now is not None:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_client_time_forbidden",
                "Preview Gateway control time is selected by the server",
            )

    def _request(self, action: str, document: Mapping[str, object]) -> dict[str, object]:
        try:
            encoded = json.dumps(
                document, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        except (TypeError, ValueError) as exc:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_request_invalid",
                "Preview Gateway control request is invalid",
            ) from exc
        if not 1 <= len(encoded) <= _MAX_REQUEST_BODY_BYTES:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_request_invalid",
                "Preview Gateway control request is oversized",
            )
        try:
            with self._client.stream(
                "POST",
                _ACTION_ROUTES[action],
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                    "host": self._expected_host,
                },
                content=encoded,
            ) as response:
                lengths = response.headers.get_list("content-length")
                try:
                    declared_length = int(lengths[0]) if len(lengths) == 1 else -1
                except ValueError:
                    declared_length = -1
                if (
                    "transfer-encoding" in response.headers
                    or "content-encoding" in response.headers
                    or declared_length < 1
                    or declared_length > _MAX_RESPONSE_BODY_BYTES
                    or str(declared_length) != lengths[0]
                ):
                    raise PreviewGatewayControlTransportError(
                        "preview_gateway_control_response_invalid",
                        "Preview Gateway control response framing is invalid",
                    )
                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_raw():
                    received += len(chunk)
                    if received > declared_length:
                        raise PreviewGatewayControlTransportError(
                            "preview_gateway_control_response_invalid",
                            "Preview Gateway control response is oversized",
                        )
                    chunks.append(chunk)
                if received != declared_length:
                    raise PreviewGatewayControlTransportError(
                        "preview_gateway_control_response_invalid",
                        "Preview Gateway control response length is invalid",
                    )
                response_body = b"".join(chunks)
                response_status = response.status_code
                response_content_type = response.headers.get("content-type", "")
        except httpx.TransportError as exc:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_unavailable",
                "Preview Gateway control service is unavailable",
            ) from exc
        if response_content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_response_invalid",
                "Preview Gateway control response content type is invalid",
            )
        try:
            result = _strict_json_document(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_response_invalid",
                "Preview Gateway control response is invalid",
            ) from exc
        if response_status != 200:
            code = "preview_gateway_control_denied"
            detail = result.get("detail")
            if isinstance(detail, dict) and isinstance(detail.get("code"), str):
                candidate = detail["code"]
                if _ERROR_CODE.fullmatch(candidate):
                    code = candidate
            raise PreviewGatewayControlTransportError(
                code, "Preview Gateway control operation failed"
            )
        return result

    def _gateway_receipt(self, result: Mapping[str, object]) -> RegisteredPreviewGateway:
        _response_exact(result, {"gateway"})
        document = result["gateway"]
        if not isinstance(document, dict):
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_response_invalid",
                "Preview Gateway control receipt is invalid",
            )
        fields = {
            "activated_at",
            "adapter_contract_version",
            "connect_host",
            "connect_port",
            "failure_domain",
            "gateway_instance_id",
            "last_heartbeat_at",
            "lease_expires_at",
            "registered_at",
            "server_name",
            "source_revision",
            "status",
        }
        if set(document) != fields:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_response_invalid",
                "Preview Gateway control receipt fields are invalid",
            )
        try:
            activated_value = document["activated_at"]
            activated_at = None if activated_value is None else _parse_datetime(activated_value)
            connect_port = document["connect_port"]
            if isinstance(connect_port, bool) or not isinstance(connect_port, int):
                raise ValueError
            text_fields = {
                name: document[name]
                for name in (
                    "adapter_contract_version",
                    "connect_host",
                    "failure_domain",
                    "gateway_instance_id",
                    "server_name",
                    "source_revision",
                    "status",
                )
            }
            if not all(isinstance(value, str) and value for value in text_fields.values()):
                raise ValueError
            if text_fields["gateway_instance_id"] != self._gateway_instance_id:
                raise ValueError
            return RegisteredPreviewGateway(
                gateway_instance_id=str(text_fields["gateway_instance_id"]),
                connect_host=str(text_fields["connect_host"]),
                connect_port=connect_port,
                server_name=str(text_fields["server_name"]),
                failure_domain=str(text_fields["failure_domain"]),
                source_revision=str(text_fields["source_revision"]),
                adapter_contract_version=str(text_fields["adapter_contract_version"]),
                status=str(text_fields["status"]),
                registered_at=_parse_datetime(document["registered_at"]),
                activated_at=activated_at,
                last_heartbeat_at=_parse_datetime(document["last_heartbeat_at"]),
                lease_expires_at=_parse_datetime(document["lease_expires_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_response_invalid",
                "Preview Gateway control receipt is invalid",
            ) from exc

    def _certificate_receipt(
        self, result: Mapping[str, object]
    ) -> ActivatedPreviewGatewayCertificate:
        _response_exact(result, {"certificate"})
        document = result["certificate"]
        fields = {
            "certificate_id",
            "certificate_not_after",
            "fingerprint_sha256",
            "gateway_instance_id",
            "purpose",
            "rotation_generation",
            "trust_bundle_version",
        }
        if not isinstance(document, dict) or set(document) != fields:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_response_invalid",
                "Preview Gateway certificate receipt is invalid",
            )
        try:
            certificate_id_value = document["certificate_id"]
            rotation = document["rotation_generation"]
            string_fields = {
                name: document[name]
                for name in (
                    "fingerprint_sha256",
                    "gateway_instance_id",
                    "purpose",
                    "trust_bundle_version",
                )
            }
            if (
                not isinstance(certificate_id_value, str)
                or isinstance(rotation, bool)
                or not isinstance(rotation, int)
                or rotation <= 0
                or not all(isinstance(value, str) and value for value in string_fields.values())
            ):
                raise ValueError
            if string_fields["gateway_instance_id"] != self._gateway_instance_id:
                raise ValueError
            certificate_id = UUID(certificate_id_value)
            if str(certificate_id) != certificate_id_value:
                raise ValueError
            return ActivatedPreviewGatewayCertificate(
                certificate_id=certificate_id,
                gateway_instance_id=str(string_fields["gateway_instance_id"]),
                purpose=str(string_fields["purpose"]),
                fingerprint_sha256=str(string_fields["fingerprint_sha256"]),
                rotation_generation=rotation,
                certificate_not_after=_parse_datetime(document["certificate_not_after"]),
                trust_bundle_version=str(string_fields["trust_bundle_version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_response_invalid",
                "Preview Gateway certificate receipt is invalid",
            ) from exc

    @staticmethod
    def _changed(result: Mapping[str, object]) -> bool:
        _response_exact(result, {"changed"})
        changed = result["changed"]
        if not isinstance(changed, bool):
            raise PreviewGatewayControlTransportError(
                "preview_gateway_control_response_invalid",
                "Preview Gateway control result is invalid",
            )
        return changed

    def register_gateway(
        self,
        *,
        gateway_instance_id: str,
        connect_host: str,
        connect_port: int,
        server_name: str,
        failure_domain: str,
        source_revision: str,
        adapter_contract_version: str,
        registration_token: str,
        lease_duration: timedelta = timedelta(seconds=45),
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway:
        self._identity(gateway_instance_id)
        self._server_time(now)
        return self._gateway_receipt(
            self._request(
                "register",
                {
                    "adapter_contract_version": adapter_contract_version,
                    "connect_host": connect_host,
                    "connect_port": connect_port,
                    "failure_domain": failure_domain,
                    "gateway_instance_id": gateway_instance_id,
                    "lease_seconds": lease_duration.total_seconds(),
                    "registration_token": registration_token,
                    "server_name": server_name,
                    "source_revision": source_revision,
                },
            )
        )

    def activate_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway:
        self._identity(gateway_instance_id)
        self._server_time(now)
        return self._gateway_receipt(
            self._request(
                "activate",
                {
                    "gateway_instance_id": gateway_instance_id,
                    "registration_token": registration_token,
                },
            )
        )

    def heartbeat_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        lease_duration: timedelta = timedelta(seconds=45),
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway:
        self._identity(gateway_instance_id)
        self._server_time(now)
        return self._gateway_receipt(
            self._request(
                "heartbeat",
                {
                    "gateway_instance_id": gateway_instance_id,
                    "lease_seconds": lease_duration.total_seconds(),
                    "registration_token": registration_token,
                },
            )
        )

    def begin_draining(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> bool:
        self._identity(gateway_instance_id)
        self._server_time(now)
        return self._changed(
            self._request(
                "drain",
                {
                    "gateway_instance_id": gateway_instance_id,
                    "registration_token": registration_token,
                },
            )
        )

    def release_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        self._identity(gateway_instance_id)
        self._server_time(now)
        return self._changed(
            self._request(
                "release",
                {
                    "gateway_instance_id": gateway_instance_id,
                    "reason": reason,
                    "registration_token": registration_token,
                },
            )
        )

    def activate_certificate(
        self,
        *,
        gateway_instance_id: str,
        purpose: str,
        certificate_der: bytes,
        trust_bundle_version: str,
        rotation_overlap: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> ActivatedPreviewGatewayCertificate:
        self._identity(gateway_instance_id)
        self._server_time(now)
        return self._certificate_receipt(
            self._request(
                "certificate_activate",
                {
                    "certificate_der_base64": base64.b64encode(certificate_der).decode(),
                    "gateway_instance_id": gateway_instance_id,
                    "purpose": purpose,
                    "rotation_overlap_seconds": rotation_overlap.total_seconds(),
                    "trust_bundle_version": trust_bundle_version,
                },
            )
        )

    def revoke_certificate(
        self,
        *,
        fingerprint_sha256: str,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        self._server_time(now)
        return self._changed(
            self._request(
                "certificate_revoke",
                {
                    "fingerprint_sha256": fingerprint_sha256,
                    "gateway_instance_id": self._gateway_instance_id,
                    "reason": reason,
                },
            )
        )


__all__ = [
    "MutualTlsPreviewGatewayControlClient",
    "MutualTlsPreviewGatewayControlServer",
    "PreviewGatewayControlIdentityAuthorizer",
    "PreviewGatewayControlTransportError",
]
