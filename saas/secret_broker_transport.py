"""Mutually authenticated transport for one-time Secret Broker redemption."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx

from saas.control_plane.isolation import (
    IsolationControlPlaneError,
    SecretMaterial,
    SecretValueProvider,
)

_REDEEM_PATH = "/v1/secret-leases/redeem"
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
_MAX_REQUEST_BODY_BYTES = 2_048
_MAX_RESPONSE_BODY_BYTES = 70_000


class SecretRedemptionAuthority(Protocol):
    def redeem_secret(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
        provider: SecretValueProvider,
    ) -> SecretMaterial: ...


class RunnerCertificateAuthorizer(Protocol):
    """Replica-independent revocation and Runner-generation check for a TLS leaf."""

    def is_runner_certificate_authorized(
        self,
        *,
        runner_id: UUID,
        certificate_der: bytes,
        purpose: str,
    ) -> bool: ...


class SecretBrokerTransportError(RuntimeError):
    """Stable fail-closed transport error without certificate or token detail."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class _ReplayEntry:
    fingerprint: str
    task: asyncio.Task[SecretMaterial]
    expires_at: float


def _require_tls13(context: ssl.SSLContext, *, server: bool) -> None:
    if (
        context.minimum_version != ssl.TLSVersion.TLSv1_3
        or context.maximum_version != ssl.TLSVersion.TLSv1_3
    ):
        raise ValueError("Secret Broker TLS context must allow only TLS 1.3")
    if context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("Secret Broker TLS context must require peer certificates")
    if not server and not context.check_hostname:
        raise ValueError("Secret Broker client TLS context must verify the server hostname")


def _runner_certificate(writer: asyncio.StreamWriter) -> tuple[UUID, bytes]:
    ssl_object = writer.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject | ssl.SSLSocket):
        raise SecretBrokerTransportError(
            "secret_broker_mtls_required", "Secret Broker requires mutual TLS"
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
        raise SecretBrokerTransportError(
            "secret_broker_runner_identity_invalid",
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
        raise SecretBrokerTransportError(
            "secret_broker_request_invalid", "Secret Broker request is invalid"
        ) from exc
    if version != "HTTP/1.1":
        raise SecretBrokerTransportError(
            "secret_broker_request_invalid", "Secret Broker requires HTTP/1.1"
        )
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line or line[:1].isspace():
            raise SecretBrokerTransportError(
                "secret_broker_request_invalid", "Secret Broker headers are invalid"
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
            raise SecretBrokerTransportError(
                "secret_broker_request_invalid", "Secret Broker headers are invalid"
            )
        headers.setdefault(lowered, []).append(stripped)
    return method, target, headers


def _one_header(headers: Mapping[str, list[str]], name: str) -> str:
    values = headers.get(name, [])
    if len(values) != 1:
        raise SecretBrokerTransportError(
            "secret_broker_request_invalid", f"Secret Broker {name} header is invalid"
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

    document = json.loads(
        encoded.decode("utf-8"),
        object_pairs_hook=unique_object,
    )
    if not isinstance(document, dict):
        raise ValueError("JSON document must be an object")
    return document


def _request_document(body: bytes) -> tuple[UUID, UUID, str]:
    try:
        document = _strict_json_document(body)
        if set(document) != {
            "lease_token",
            "request_id",
            "run_id",
        }:
            raise ValueError
        request_id_value = document["request_id"]
        run_id_value = document["run_id"]
        if not isinstance(request_id_value, str) or not isinstance(run_id_value, str):
            raise ValueError
        request_id = UUID(request_id_value)
        run_id = UUID(run_id_value)
        lease_token = document["lease_token"]
    except (UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
        raise SecretBrokerTransportError(
            "secret_broker_request_invalid", "Secret Broker request body is invalid"
        ) from exc
    if (
        request_id.version != 4
        or str(request_id) != request_id_value
        or str(run_id) != run_id_value
        or not isinstance(lease_token, str)
        or not 1 <= len(lease_token) <= 512
    ):
        raise SecretBrokerTransportError(
            "secret_broker_request_invalid", "Secret lease token is invalid"
        )
    return request_id, run_id, lease_token


def _material_document(material: SecretMaterial) -> bytes:
    return json.dumps(
        {
            "binding_id": str(material.binding_id),
            "credential_scheme": material.credential_scheme,
            "host": material.host,
            "inject_env": list(material.inject_env),
            "name": material.name,
            "username": material.username,
            "value": material.value,
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
        503: "Service Unavailable",
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


class MutualTlsSecretBrokerServer:
    """Small bounded TLS 1.3 server that derives Runner identity from client SAN."""

    def __init__(
        self,
        authority: SecretRedemptionAuthority,
        provider: SecretValueProvider,
        tls_context: ssl.SSLContext,
        certificate_authorizer: RunnerCertificateAuthorizer,
        *,
        expected_host: str = "secret-broker.internal",
        request_timeout_seconds: float = 5.0,
        replay_ttl_seconds: float = 30.0,
        max_replay_entries: int = 4096,
    ) -> None:
        _require_tls13(tls_context, server=True)
        if (
            not _INTERNAL_HOST.fullmatch(expected_host.lower())
            or request_timeout_seconds <= 0
            or replay_ttl_seconds <= 0
            or max_replay_entries <= 0
        ):
            raise ValueError("Secret Broker server configuration is invalid")
        self._authority = authority
        self._provider = provider
        self._tls_context = tls_context
        self._certificate_authorizer = certificate_authorizer
        self._expected_host = expected_host
        self._request_timeout_seconds = request_timeout_seconds
        self._replay_ttl_seconds = replay_ttl_seconds
        self._max_replay_entries = max_replay_entries
        self._replays: dict[UUID, _ReplayEntry] = {}
        self._replay_lock = asyncio.Lock()
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Secret Broker server is not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if self._server is not None:
            raise RuntimeError("Secret Broker server is already started")
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
        async with self._replay_lock:
            entries = list(self._replays.values())
            self._replays.clear()
        for entry in entries:
            if not entry.task.done():
                entry.task.cancel()

    async def _redeem(
        self,
        *,
        request_id: UUID,
        runner_id: UUID,
        run_id: UUID,
        lease_token: str,
    ) -> SecretMaterial:
        fingerprint = hashlib.sha256(
            f"{runner_id}\x00{run_id}\x00{lease_token}".encode()
        ).hexdigest()
        now = time.monotonic()
        async with self._replay_lock:
            expired = [
                cached_id
                for cached_id, entry in self._replays.items()
                if entry.expires_at <= now and entry.task.done()
            ]
            for cached_id in expired:
                self._replays.pop(cached_id, None)
            entry = self._replays.get(request_id)
            if entry is not None and entry.fingerprint != fingerprint:
                raise SecretBrokerTransportError(
                    "secret_broker_request_replay_mismatch",
                    "Secret Broker request id was reused with different authority",
                )
            if entry is None:
                if len(self._replays) >= self._max_replay_entries:
                    raise SecretBrokerTransportError(
                        "secret_broker_busy", "Secret Broker replay capacity is exhausted"
                    )
                task = asyncio.create_task(
                    asyncio.to_thread(
                        self._authority.redeem_secret,
                        token=lease_token,
                        runner_id=runner_id,
                        run_id=run_id,
                        provider=self._provider,
                    )
                )
                entry = _ReplayEntry(
                    fingerprint=fingerprint,
                    task=task,
                    expires_at=now + self._replay_ttl_seconds,
                )
                self._replays[request_id] = entry
        try:
            return await entry.task
        except BaseException:
            async with self._replay_lock:
                if self._replays.get(request_id) == entry:
                    self._replays.pop(request_id, None)
            raise

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
                purpose="secret_broker",
            )
            if not certificate_authorized:
                raise SecretBrokerTransportError(
                    "secret_broker_runner_certificate_denied",
                    "Runner certificate is not active",
                )
            encoded_head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=self._request_timeout_seconds,
            )
            if len(encoded_head) > _MAX_REQUEST_HEAD_BYTES:
                raise SecretBrokerTransportError(
                    "secret_broker_request_invalid", "Secret Broker headers are oversized"
                )
            method, target, headers = _parse_headers(encoded_head[:-4])
            if method != "POST" or target != _REDEEM_PATH:
                raise SecretBrokerTransportError(
                    "secret_broker_request_invalid", "Secret Broker route is invalid"
                )
            if (
                "transfer-encoding" in headers
                or _one_header(headers, "content-type").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise SecretBrokerTransportError(
                    "secret_broker_request_invalid", "Secret Broker body framing is invalid"
                )
            if _one_header(headers, "host").lower() != self._expected_host.lower():
                raise SecretBrokerTransportError(
                    "secret_broker_request_invalid", "Secret Broker host is invalid"
                )
            try:
                content_length = int(_one_header(headers, "content-length"))
            except ValueError as exc:
                raise SecretBrokerTransportError(
                    "secret_broker_request_invalid", "Secret Broker length is invalid"
                ) from exc
            if not 1 <= content_length <= _MAX_REQUEST_BODY_BYTES:
                raise SecretBrokerTransportError(
                    "secret_broker_request_invalid", "Secret Broker body is oversized"
                )
            body = await asyncio.wait_for(
                reader.readexactly(content_length),
                timeout=self._request_timeout_seconds,
            )
            request_id, run_id, lease_token = _request_document(body)
            material = await self._redeem(
                request_id=request_id,
                runner_id=runner_id,
                run_id=run_id,
                lease_token=lease_token,
            )
            await _write_response(writer, status=200, body=_material_document(material))
        except SecretBrokerTransportError as exc:
            if exc.code == "secret_broker_request_replay_mismatch":
                status = 409
            elif exc.code == "secret_broker_busy":
                status = 503
            elif exc.code in {
                "secret_broker_mtls_required",
                "secret_broker_runner_certificate_denied",
                "secret_broker_runner_identity_invalid",
            }:
                status = 403
            else:
                status = 400
            await _write_response(writer, status=status, body=_error_document(exc.code))
        except IsolationControlPlaneError:
            await _write_response(
                writer,
                status=403,
                body=_error_document("secret_broker_redemption_denied"),
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            await _write_response(
                writer,
                status=400,
                body=_error_document("secret_broker_request_invalid"),
            )
        except Exception:  # noqa: BLE001 - fail closed without leaking broker internals
            await _write_response(
                writer,
                status=500,
                body=_error_document("secret_broker_internal_error"),
            )
        finally:
            writer.close()
            with suppress(ConnectionError, ssl.SSLError):
                await writer.wait_closed()


class MutualTlsSecretBrokerClient:
    """Synchronous Runner authority adapter with same-request retry semantics."""

    def __init__(
        self,
        *,
        base_url: str,
        runner_id: UUID,
        tls_context: ssl.SSLContext,
        expected_host: str = "secret-broker.internal",
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
            raise ValueError("Secret Broker client endpoint is invalid")
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

    def redeem_secret(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
        provider: SecretValueProvider,
        request_id: UUID | None = None,
    ) -> SecretMaterial:
        del provider
        if runner_id != self._runner_id:
            raise SecretBrokerTransportError(
                "secret_broker_runner_identity_mismatch",
                "Runner does not match the configured certificate identity",
            )
        stable_request_id = request_id or uuid4()
        payload = {
            "lease_token": token,
            "request_id": str(stable_request_id),
            "run_id": str(run_id),
        }
        response: httpx.Response | None = None
        failure: Exception | None = None
        for _ in range(2):
            try:
                response = self._client.post(
                    _REDEEM_PATH,
                    headers={
                        "accept": "application/json",
                        "content-type": "application/json",
                        "host": self._expected_host,
                    },
                    content=json.dumps(payload, sort_keys=True, separators=(",", ":")),
                )
                break
            except httpx.TransportError as exc:
                failure = exc
        if response is None:
            raise SecretBrokerTransportError(
                "secret_broker_unavailable", "Secret Broker is unavailable"
            ) from failure
        if len(response.content) > _MAX_RESPONSE_BODY_BYTES:
            raise SecretBrokerTransportError(
                "secret_broker_response_invalid", "Secret Broker response is oversized"
            )
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise SecretBrokerTransportError(
                "secret_broker_response_invalid", "Secret Broker content type is invalid"
            )
        try:
            document = _strict_json_document(response.content)
        except (UnicodeDecodeError, ValueError) as exc:
            raise SecretBrokerTransportError(
                "secret_broker_response_invalid", "Secret Broker response is invalid"
            ) from exc
        if response.status_code != 200:
            code = "secret_broker_redemption_denied"
            detail = document.get("detail")
            if isinstance(detail, dict) and isinstance(detail.get("code"), str):
                candidate = detail["code"]
                if _ERROR_CODE.fullmatch(candidate):
                    code = candidate
            raise SecretBrokerTransportError(code, "Secret Broker redemption failed")
        try:
            if set(document) != {
                "binding_id",
                "credential_scheme",
                "host",
                "inject_env",
                "name",
                "username",
                "value",
            }:
                raise ValueError
            binding_id_value = document["binding_id"]
            name = document["name"]
            host = document["host"]
            credential_scheme = document["credential_scheme"]
            username = document["username"]
            inject_env = document["inject_env"]
            value = document["value"]
            valid = (
                isinstance(binding_id_value, str)
                and isinstance(name, str)
                and isinstance(host, str)
                and isinstance(credential_scheme, str)
                and (username is None or isinstance(username, str))
                and isinstance(inject_env, list)
                and all(isinstance(item, str) for item in inject_env)
                and isinstance(value, str)
                and 1 <= len(value) <= 65_536
            )
            if not valid:
                raise ValueError
            binding_id = UUID(binding_id_value)
            if str(binding_id) != binding_id_value:
                raise ValueError
        except (ValueError, TypeError, KeyError) as exc:
            raise SecretBrokerTransportError(
                "secret_broker_response_invalid", "Secret Broker material is invalid"
            ) from exc
        return SecretMaterial(
            binding_id=binding_id,
            name=name,
            host=host,
            credential_scheme=credential_scheme,
            username=username,
            inject_env=tuple(inject_env),
            value=value,
        )


__all__ = [
    "MutualTlsSecretBrokerClient",
    "MutualTlsSecretBrokerServer",
    "RunnerCertificateAuthorizer",
    "SecretBrokerTransportError",
    "SecretRedemptionAuthority",
]
