"""Mutually authenticated cross-replica transport for Preview HTTP responses."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import ssl
import struct
from collections.abc import AsyncIterable, AsyncIterator, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID

from saas.control_plane import PreviewRouteGrant, RunnerTunnelPlacement
from saas.preview_gateway import PreviewTunnelRequest, PreviewTunnelResponse
from saas.preview_tunnel import PlacementRoutedPreviewTunnel, PreviewTunnelAdapterError

_PROTOCOL_VERSION = 1
_MAGIC = b"OMNIPVR1"
_REQUEST_PREFIX = struct.Struct("!8sIQ")
_RESPONSE_PREFIX = struct.Struct("!8sI")
_CHUNK_PREFIX = struct.Struct("!I")
_MAX_REQUEST_HEAD_BYTES = 65_536
_MAX_RESPONSE_HEAD_BYTES = 32_768
_MAX_CHUNK_BYTES = 65_536
_MAX_HEADER_COUNT = 32
_MAX_HEADER_VALUE_BYTES = 8_192
_MAX_INTEGER = (1 << 63) - 1
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_REQUEST_HEADERS = frozenset(
    {"accept", "accept-encoding", "accept-language", "content-type", "user-agent"}
)
_RESPONSE_HEADERS = frozenset(
    {"cache-control", "content-language", "content-type", "etag", "last-modified"}
)
_HEADER_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_GATEWAY_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_GATEWAY_SPIFFE_ID = re.compile(
    r"^spiffe://omnigent/preview-gateway/(?P<gateway>[A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
_RELAY_SUBJECT = re.compile(r"^rtp_[0-9a-f]{32}$")
_OPAQUE_PREVIEW_KEY = re.compile(r"^pvr_[0-9a-zA-Z_-]{1,92}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INTERNAL_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class PreviewGatewayCertificateAuthorizer(Protocol):
    """Replica-independent lifecycle check for a presented Gateway TLS leaf."""

    def is_preview_gateway_certificate_authorized(
        self,
        *,
        gateway_instance_id: str,
        certificate_der: bytes,
        purpose: str,
    ) -> bool: ...


class PreviewRelayEndpointResolver(Protocol):
    """Resolve a server-selected Placement owner to an internal TLS endpoint."""

    def resolve(self, placement: RunnerTunnelPlacement) -> PreviewRelayEndpoint: ...


class PreviewRelayTransportError(RuntimeError):
    """Stable fail-closed relay failure without certificate or topology detail."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PreviewRelayEndpoint:
    connect_host: str
    port: int
    server_name: str

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.connect_host)
            valid_connect_host = True
        except ValueError:
            valid_connect_host = bool(_INTERNAL_HOST.fullmatch(self.connect_host.lower()))
        try:
            ipaddress.ip_address(self.server_name)
            valid_server_name = True
        except ValueError:
            valid_server_name = bool(_INTERNAL_HOST.fullmatch(self.server_name.lower()))
        if (
            not valid_connect_host
            or not valid_server_name
            or isinstance(self.port, bool)
            or not 1 <= self.port <= 65_535
        ):
            raise ValueError("Preview Relay endpoint is invalid")


def _require_tls13(context: ssl.SSLContext, *, server: bool) -> None:
    if (
        context.minimum_version != ssl.TLSVersion.TLSv1_3
        or context.maximum_version != ssl.TLSVersion.TLSv1_3
    ):
        raise ValueError("Preview Relay TLS context must allow only TLS 1.3")
    if context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("Preview Relay TLS context must require peer certificates")
    if not server and not context.check_hostname:
        raise ValueError("Preview Relay client TLS context must verify the server hostname")


def _gateway_certificate(writer: asyncio.StreamWriter) -> tuple[str, bytes]:
    ssl_object = writer.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject | ssl.SSLSocket):
        raise PreviewRelayTransportError(
            "preview_relay_mtls_required", "Preview Relay requires mutual TLS"
        )
    certificate = ssl_object.getpeercert()
    certificate_der = ssl_object.getpeercert(binary_form=True)
    subject_alt_names = certificate.get("subjectAltName", ()) if certificate else ()
    uri_identities = [
        value for kind, value in subject_alt_names if kind == "URI" and isinstance(value, str)
    ]
    matched = _GATEWAY_SPIFFE_ID.fullmatch(uri_identities[0]) if len(uri_identities) == 1 else None
    if matched is None or not isinstance(certificate_der, bytes) or not certificate_der:
        raise PreviewRelayTransportError(
            "preview_relay_gateway_identity_invalid",
            "Preview Relay Gateway certificate identity is invalid",
        )
    return matched.group("gateway"), certificate_der


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


def _object(value: object, *, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("object fields are invalid")
    return value


def _uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise ValueError("UUID is invalid")
    parsed = UUID(value)
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError("UUID is not canonical")
    return parsed


def _positive_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_INTEGER:
        raise ValueError("integer is invalid")
    return value


def _utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is invalid")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    normalized = parsed.astimezone(timezone.utc)
    if value != normalized.isoformat():
        raise ValueError("timestamp is not canonical UTC")
    return normalized


def _headers(value: object, *, allowed: frozenset[str]) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > _MAX_HEADER_COUNT:
        raise ValueError("headers are invalid")
    result: dict[str, str] = {}
    total = 0
    for raw_name, raw_value in value.items():
        if (
            not isinstance(raw_name, str)
            or raw_name not in allowed
            or not _HEADER_NAME.fullmatch(raw_name)
            or not isinstance(raw_value, str)
            or "\r" in raw_value
            or "\n" in raw_value
            or "\x00" in raw_value
        ):
            raise ValueError("header is invalid")
        size = len(raw_name.encode("ascii")) + len(raw_value.encode("utf-8"))
        if size > _MAX_HEADER_VALUE_BYTES:
            raise ValueError("header is oversized")
        total += size
        result[raw_name] = raw_value
    if total > _MAX_REQUEST_HEAD_BYTES // 2:
        raise ValueError("headers are oversized")
    return result


def _request_document(
    encoded: bytes,
    body: bytes,
) -> tuple[RunnerTunnelPlacement, PreviewTunnelRequest]:
    try:
        document = _strict_json_document(encoded)
        if set(document) != {"placement", "request", "route", "version"}:
            raise ValueError
        if document["version"] != _PROTOCOL_VERSION:
            raise ValueError
        placement_document = _object(
            document["placement"],
            fields=frozenset(
                {
                    "gateway_instance_id",
                    "placement_id",
                    "relay_subject",
                    "routing_generation",
                    "runner_connection_generation",
                    "runner_id",
                }
            ),
        )
        route_document = _object(
            document["route"],
            fields=frozenset(
                {
                    "expires_at",
                    "opaque_preview_key",
                    "preview_id",
                    "preview_token_hash",
                    "project_id",
                    "run_fence_token",
                    "run_id",
                    "runner_connection_generation",
                    "runner_id",
                    "space_id",
                    "tenant_id",
                    "worktree_id",
                    "worktree_lease_generation",
                }
            ),
        )
        request_document = _object(
            document["request"],
            fields=frozenset({"headers", "method", "path", "query"}),
        )
        placement_id = _uuid(placement_document["placement_id"])
        runner_id = _uuid(placement_document["runner_id"])
        connection_generation = _positive_integer(
            placement_document["runner_connection_generation"]
        )
        routing_generation = _positive_integer(placement_document["routing_generation"])
        gateway_instance_id = placement_document["gateway_instance_id"]
        relay_subject = placement_document["relay_subject"]
        if (
            not isinstance(gateway_instance_id, str)
            or not _GATEWAY_INSTANCE.fullmatch(gateway_instance_id)
            or not isinstance(relay_subject, str)
            or not _RELAY_SUBJECT.fullmatch(relay_subject)
        ):
            raise ValueError

        route_runner_id = _uuid(route_document["runner_id"])
        route_connection_generation = _positive_integer(
            route_document["runner_connection_generation"]
        )
        opaque_key = route_document["opaque_preview_key"]
        preview_token_hash = route_document["preview_token_hash"]
        if (
            route_runner_id != runner_id
            or route_connection_generation != connection_generation
            or not isinstance(opaque_key, str)
            or not _OPAQUE_PREVIEW_KEY.fullmatch(opaque_key)
            or not isinstance(preview_token_hash, str)
            or not _HEX_SHA256.fullmatch(preview_token_hash)
        ):
            raise ValueError
        headers = _headers(request_document["headers"], allowed=_REQUEST_HEADERS)
        method = request_document["method"]
        path = request_document["path"]
        query = request_document["query"]
        if (
            not isinstance(method, str)
            or method not in _METHODS
            or not isinstance(path, str)
            or not path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(segment == ".." for segment in path.split("/"))
            or len(path) > 4096
            or not isinstance(query, str)
            or len(query) > 8192
            or "\r" in query
            or "\n" in query
            or "\x00" in query
        ):
            raise ValueError
        expires_at = _utc_timestamp(route_document["expires_at"])
        route = PreviewRouteGrant(
            preview_id=_uuid(route_document["preview_id"]),
            tenant_id=_uuid(route_document["tenant_id"]),
            space_id=_uuid(route_document["space_id"]),
            project_id=_uuid(route_document["project_id"]),
            runner_id=route_runner_id,
            runner_connection_generation=route_connection_generation,
            run_id=_uuid(route_document["run_id"]),
            run_fence_token=_positive_integer(route_document["run_fence_token"]),
            worktree_id=_uuid(route_document["worktree_id"]),
            worktree_lease_generation=_positive_integer(
                route_document["worktree_lease_generation"]
            ),
            opaque_preview_key=opaque_key,
            preview_token_hash=preview_token_hash,
            upstream_request_headers=headers,
            response_headers={},
            expires_at=expires_at,
        )
        placement = RunnerTunnelPlacement(
            placement_id=placement_id,
            runner_id=runner_id,
            runner_connection_generation=connection_generation,
            routing_generation=routing_generation,
            gateway_instance_id=gateway_instance_id,
            relay_subject=relay_subject,
            status="active",
            lease_expires_at=expires_at,
        )
    except (KeyError, TypeError, UnicodeError, ValueError) as exc:
        raise PreviewRelayTransportError(
            "preview_relay_request_invalid", "Preview Relay request is invalid"
        ) from exc
    return placement, PreviewTunnelRequest(route, method, path, query, headers, body)


def _encoded_request(
    placement: RunnerTunnelPlacement,
    request: PreviewTunnelRequest,
    *,
    maximum_request_bytes: int,
) -> bytes:
    route = request.route
    if (
        placement.status not in {"active", "draining"}
        or placement.lease_expires_at.tzinfo is None
        or placement.lease_expires_at <= datetime.now(timezone.utc)
        or route.expires_at.tzinfo is None
        or len(request.body) > maximum_request_bytes
        or request.headers != route.upstream_request_headers
    ):
        raise PreviewRelayTransportError(
            "preview_relay_request_invalid", "Preview Relay request is invalid"
        )
    document = {
        "placement": {
            "gateway_instance_id": placement.gateway_instance_id,
            "placement_id": str(placement.placement_id),
            "relay_subject": placement.relay_subject,
            "routing_generation": placement.routing_generation,
            "runner_connection_generation": placement.runner_connection_generation,
            "runner_id": str(placement.runner_id),
        },
        "request": {
            "headers": request.headers,
            "method": request.method,
            "path": request.path,
            "query": request.query,
        },
        "route": {
            "expires_at": route.expires_at.astimezone(timezone.utc).isoformat(),
            "opaque_preview_key": route.opaque_preview_key,
            "preview_id": str(route.preview_id),
            "preview_token_hash": route.preview_token_hash,
            "project_id": str(route.project_id),
            "run_fence_token": route.run_fence_token,
            "run_id": str(route.run_id),
            "runner_connection_generation": route.runner_connection_generation,
            "runner_id": str(route.runner_id),
            "space_id": str(route.space_id),
            "tenant_id": str(route.tenant_id),
            "worktree_id": str(route.worktree_id),
            "worktree_lease_generation": route.worktree_lease_generation,
        },
        "version": _PROTOCOL_VERSION,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > _MAX_REQUEST_HEAD_BYTES:
        raise PreviewRelayTransportError(
            "preview_relay_request_invalid", "Preview Relay request metadata is oversized"
        )
    _request_document(encoded, request.body)
    return _REQUEST_PREFIX.pack(_MAGIC, len(encoded), len(request.body)) + encoded + request.body


def _encoded_head(document: Mapping[str, object]) -> bytes:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > _MAX_RESPONSE_HEAD_BYTES:
        raise PreviewRelayTransportError(
            "preview_relay_response_invalid", "Preview Relay response metadata is oversized"
        )
    return _RESPONSE_PREFIX.pack(_MAGIC, len(encoded)) + encoded


async def _close_body(body: bytes | AsyncIterable[bytes] | None) -> None:
    if body is None or isinstance(body, bytes):
        return
    close = getattr(body, "aclose", None)
    if close is not None:
        await close()


class MutualTlsPreviewRelayServer:
    """One-request TLS 1.3 server that re-authorizes Placement on the owner."""

    def __init__(
        self,
        *,
        gateway_instance_id: str,
        router: PlacementRoutedPreviewTunnel,
        tls_context: ssl.SSLContext,
        certificate_authorizer: PreviewGatewayCertificateAuthorizer,
        request_timeout_seconds: float = 10.0,
        response_head_timeout_seconds: float = 30.0,
        response_idle_timeout_seconds: float = 30.0,
        maximum_request_bytes: int = 1_048_576,
        maximum_response_bytes: int = 10_485_760,
        maximum_concurrent_requests: int = 256,
    ) -> None:
        _require_tls13(tls_context, server=True)
        if (
            not _GATEWAY_INSTANCE.fullmatch(gateway_instance_id)
            or request_timeout_seconds <= 0
            or response_head_timeout_seconds <= 0
            or response_idle_timeout_seconds <= 0
            or maximum_request_bytes <= 0
            or maximum_response_bytes <= 0
            or maximum_concurrent_requests <= 0
        ):
            raise ValueError("Preview Relay server configuration is invalid")
        self._gateway_instance_id = gateway_instance_id
        self._router = router
        self._tls_context = tls_context
        self._certificate_authorizer = certificate_authorizer
        self._request_timeout_seconds = request_timeout_seconds
        self._response_head_timeout_seconds = response_head_timeout_seconds
        self._response_idle_timeout_seconds = response_idle_timeout_seconds
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes
        self._capacity = asyncio.Semaphore(maximum_concurrent_requests)
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Preview Relay server is not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        if self._server is not None:
            raise RuntimeError("Preview Relay server is already started")
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

    async def _write_error(self, writer: asyncio.StreamWriter, code: str) -> None:
        if not _ERROR_CODE.fullmatch(code):
            code = "preview_relay_internal_error"
        writer.write(_encoded_head({"code": code, "kind": "error", "version": _PROTOCOL_VERSION}))
        await asyncio.wait_for(writer.drain(), timeout=self._response_idle_timeout_seconds)

    async def _write_response(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        response: PreviewTunnelResponse,
    ) -> None:
        if not 200 <= response.status_code <= 599:
            raise PreviewRelayTransportError(
                "preview_relay_response_invalid", "Preview Relay status is invalid"
            )
        safe_headers = {
            name.lower(): value
            for name, value in response.headers.items()
            if name.lower() in _RESPONSE_HEADERS
            and isinstance(value, str)
            and "\r" not in value
            and "\n" not in value
            and "\x00" not in value
        }
        safe_headers = _headers(safe_headers, allowed=_RESPONSE_HEADERS)
        writer.write(
            _encoded_head(
                {
                    "headers": safe_headers,
                    "kind": "response",
                    "status_code": response.status_code,
                    "version": _PROTOCOL_VERSION,
                }
            )
        )
        await asyncio.wait_for(writer.drain(), timeout=self._response_idle_timeout_seconds)

        async def byte_body() -> AsyncIterator[bytes]:
            if isinstance(response.body, bytes):
                if response.body:
                    yield response.body
            else:
                async for item in response.body:
                    yield item

        iterator = byte_body().__aiter__()
        disconnect = asyncio.create_task(reader.read(1))
        total = 0

        async def next_body_chunk() -> bytes:
            return await anext(iterator)

        try:
            while True:
                next_chunk = asyncio.create_task(next_body_chunk())
                done, _ = await asyncio.wait(
                    {next_chunk, disconnect}, return_when=asyncio.FIRST_COMPLETED
                )
                if disconnect in done:
                    next_chunk.cancel()
                    with suppress(asyncio.CancelledError, StopAsyncIteration):
                        await next_chunk
                    raise PreviewRelayTransportError(
                        "preview_relay_client_disconnected", "Preview Relay client disconnected"
                    )
                try:
                    chunk = next_chunk.result()
                except StopAsyncIteration:
                    break
                if not isinstance(chunk, bytes):
                    raise PreviewRelayTransportError(
                        "preview_relay_response_invalid",
                        "Preview Relay response chunk is invalid",
                    )
                total += len(chunk)
                if total > self._maximum_response_bytes:
                    raise PreviewRelayTransportError(
                        "preview_relay_response_too_large",
                        "Preview Relay response is oversized",
                    )
                for offset in range(0, len(chunk), _MAX_CHUNK_BYTES):
                    part = chunk[offset : offset + _MAX_CHUNK_BYTES]
                    if not part:
                        continue
                    writer.write(_CHUNK_PREFIX.pack(len(part)) + part)
                    await asyncio.wait_for(
                        writer.drain(), timeout=self._response_idle_timeout_seconds
                    )
            writer.write(_CHUNK_PREFIX.pack(0))
            await asyncio.wait_for(writer.drain(), timeout=self._response_idle_timeout_seconds)
        finally:
            disconnect.cancel()
            with suppress(asyncio.CancelledError):
                await disconnect

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        response: PreviewTunnelResponse | None = None
        response_started = False
        acquired = False
        try:
            await asyncio.wait_for(self._capacity.acquire(), timeout=self._request_timeout_seconds)
            acquired = True
            peer_gateway_id, certificate_der = _gateway_certificate(writer)
            certificate_authorized = await asyncio.wait_for(
                asyncio.to_thread(
                    self._certificate_authorizer.is_preview_gateway_certificate_authorized,
                    gateway_instance_id=peer_gateway_id,
                    certificate_der=certificate_der,
                    purpose="preview_relay",
                ),
                timeout=self._request_timeout_seconds,
            )
            if not certificate_authorized:
                raise PreviewRelayTransportError(
                    "preview_relay_gateway_certificate_denied",
                    "Preview Relay Gateway certificate is not active",
                )
            prefix = await asyncio.wait_for(
                reader.readexactly(_REQUEST_PREFIX.size),
                timeout=self._request_timeout_seconds,
            )
            magic, head_length, body_length = _REQUEST_PREFIX.unpack(prefix)
            if (
                magic != _MAGIC
                or not 1 <= head_length <= _MAX_REQUEST_HEAD_BYTES
                or body_length > self._maximum_request_bytes
            ):
                raise PreviewRelayTransportError(
                    "preview_relay_request_invalid", "Preview Relay request framing is invalid"
                )
            encoded_head = await asyncio.wait_for(
                reader.readexactly(head_length), timeout=self._request_timeout_seconds
            )
            body = await asyncio.wait_for(
                reader.readexactly(body_length), timeout=self._request_timeout_seconds
            )
            placement, request = _request_document(encoded_head, body)
            if placement.gateway_instance_id != self._gateway_instance_id:
                raise PreviewRelayTransportError(
                    "preview_relay_destination_mismatch",
                    "Preview Relay destination does not own the Placement",
                )
            try:
                response = await asyncio.wait_for(
                    self._router.accept_relay(placement, request),
                    timeout=self._response_head_timeout_seconds,
                )
            except asyncio.TimeoutError as exc:
                raise PreviewRelayTransportError(
                    "preview_relay_owner_timeout",
                    "Preview Relay owner did not produce a response",
                ) from exc
            response_started = True
            await self._write_response(reader, writer, response)
        except PreviewTunnelAdapterError as exc:
            if not response_started:
                await self._write_error(writer, exc.code)
        except PreviewRelayTransportError as exc:
            if not response_started:
                await self._write_error(writer, exc.code)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            if not response_started:
                await self._write_error(writer, "preview_relay_request_invalid")
        except Exception:  # noqa: BLE001 - fail closed without peer or topology detail
            if not response_started:
                with suppress(Exception):
                    await self._write_error(writer, "preview_relay_internal_error")
        finally:
            with suppress(Exception):
                await _close_body(None if response is None else response.body)
            if acquired:
                self._capacity.release()
            writer.close()
            with suppress(ConnectionError, ssl.SSLError):
                await writer.wait_closed()


class _RelayResponseBody:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        idle_timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._idle_timeout_seconds = idle_timeout_seconds
        self._maximum_response_bytes = maximum_response_bytes
        self._started = False
        self._closed = False

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[bytes]:
        if self._started:
            raise PreviewRelayTransportError(
                "preview_relay_response_invalid", "Preview Relay body is single-use"
            )
        self._started = True
        total = 0
        try:
            while True:
                encoded_length = await asyncio.wait_for(
                    self._reader.readexactly(_CHUNK_PREFIX.size),
                    timeout=self._idle_timeout_seconds,
                )
                (length,) = _CHUNK_PREFIX.unpack(encoded_length)
                if length == 0:
                    break
                if length > _MAX_CHUNK_BYTES:
                    raise PreviewRelayTransportError(
                        "preview_relay_response_invalid",
                        "Preview Relay response framing is invalid",
                    )
                total += length
                if total > self._maximum_response_bytes:
                    raise PreviewRelayTransportError(
                        "preview_relay_response_too_large",
                        "Preview Relay response is oversized",
                    )
                yield await asyncio.wait_for(
                    self._reader.readexactly(length), timeout=self._idle_timeout_seconds
                )
        except (asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
            raise PreviewRelayTransportError(
                "preview_relay_response_invalid", "Preview Relay response ended unexpectedly"
            ) from exc
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._writer.close()
        with suppress(ConnectionError, ssl.SSLError):
            await self._writer.wait_closed()


class MutualTlsPreviewRelayClient:
    """Placement-bound relay client with no automatic request replay."""

    def __init__(
        self,
        *,
        gateway_instance_id: str,
        endpoint_resolver: PreviewRelayEndpointResolver,
        tls_context: ssl.SSLContext,
        certificate_authorizer: PreviewGatewayCertificateAuthorizer,
        connect_timeout_seconds: float = 10.0,
        response_head_timeout_seconds: float = 30.0,
        response_idle_timeout_seconds: float = 30.0,
        maximum_request_bytes: int = 1_048_576,
        maximum_response_bytes: int = 10_485_760,
    ) -> None:
        _require_tls13(tls_context, server=False)
        if (
            not _GATEWAY_INSTANCE.fullmatch(gateway_instance_id)
            or connect_timeout_seconds <= 0
            or response_head_timeout_seconds <= 0
            or response_idle_timeout_seconds <= 0
            or maximum_request_bytes <= 0
            or maximum_response_bytes <= 0
        ):
            raise ValueError("Preview Relay client configuration is invalid")
        self._gateway_instance_id = gateway_instance_id
        self._endpoint_resolver = endpoint_resolver
        self._tls_context = tls_context
        self._certificate_authorizer = certificate_authorizer
        self._connect_timeout_seconds = connect_timeout_seconds
        self._response_head_timeout_seconds = response_head_timeout_seconds
        self._response_idle_timeout_seconds = response_idle_timeout_seconds
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes

    async def forward(
        self,
        placement: RunnerTunnelPlacement,
        request: PreviewTunnelRequest,
    ) -> PreviewTunnelResponse:
        if placement.gateway_instance_id == self._gateway_instance_id:
            raise PreviewRelayTransportError(
                "preview_relay_loop", "Preview Relay cannot forward to the local Gateway"
            )
        encoded_request = _encoded_request(
            placement, request, maximum_request_bytes=self._maximum_request_bytes
        )
        endpoint = self._endpoint_resolver.resolve(placement)
        if not isinstance(endpoint, PreviewRelayEndpoint):
            raise PreviewRelayTransportError(
                "preview_relay_endpoint_invalid", "Preview Relay endpoint is invalid"
            )
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    endpoint.connect_host,
                    endpoint.port,
                    ssl=self._tls_context,
                    server_hostname=endpoint.server_name,
                    ssl_handshake_timeout=self._connect_timeout_seconds,
                ),
                timeout=self._connect_timeout_seconds,
            )
            peer_gateway_id, certificate_der = _gateway_certificate(writer)
            if peer_gateway_id != placement.gateway_instance_id:
                raise PreviewRelayTransportError(
                    "preview_relay_destination_identity_mismatch",
                    "Preview Relay peer does not match the Placement owner",
                )
            certificate_authorized = await asyncio.wait_for(
                asyncio.to_thread(
                    self._certificate_authorizer.is_preview_gateway_certificate_authorized,
                    gateway_instance_id=peer_gateway_id,
                    certificate_der=certificate_der,
                    purpose="preview_relay",
                ),
                timeout=self._connect_timeout_seconds,
            )
            if not certificate_authorized:
                raise PreviewRelayTransportError(
                    "preview_relay_gateway_certificate_denied",
                    "Preview Relay Gateway certificate is not active",
                )
            writer.write(encoded_request)
            await asyncio.wait_for(writer.drain(), timeout=self._connect_timeout_seconds)
            prefix = await asyncio.wait_for(
                reader.readexactly(_RESPONSE_PREFIX.size),
                timeout=self._response_head_timeout_seconds,
            )
            magic, head_length = _RESPONSE_PREFIX.unpack(prefix)
            if magic != _MAGIC or not 1 <= head_length <= _MAX_RESPONSE_HEAD_BYTES:
                raise PreviewRelayTransportError(
                    "preview_relay_response_invalid", "Preview Relay response framing is invalid"
                )
            encoded_head = await asyncio.wait_for(
                reader.readexactly(head_length), timeout=self._response_head_timeout_seconds
            )
            document = _strict_json_document(encoded_head)
            if document.get("kind") == "error":
                if set(document) != {"code", "kind", "version"}:
                    raise ValueError
                code = document["code"]
                if (
                    document["version"] != _PROTOCOL_VERSION
                    or not isinstance(code, str)
                    or not _ERROR_CODE.fullmatch(code)
                ):
                    raise ValueError
                raise PreviewRelayTransportError(code, "Preview Relay request was denied")
            if set(document) != {"headers", "kind", "status_code", "version"}:
                raise ValueError
            status_code = document["status_code"]
            if (
                document["kind"] != "response"
                or document["version"] != _PROTOCOL_VERSION
                or isinstance(status_code, bool)
                or not isinstance(status_code, int)
                or not 200 <= status_code <= 599
            ):
                raise ValueError
            headers = _headers(document["headers"], allowed=_RESPONSE_HEADERS)
            body = _RelayResponseBody(
                reader,
                writer,
                idle_timeout_seconds=self._response_idle_timeout_seconds,
                maximum_response_bytes=self._maximum_response_bytes,
            )
            writer = None
            return PreviewTunnelResponse(status_code=status_code, headers=headers, body=body)
        except PreviewRelayTransportError:
            raise
        except (OSError, ssl.SSLError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
            raise PreviewRelayTransportError(
                "preview_relay_unavailable", "Preview Relay is unavailable"
            ) from exc
        except (KeyError, TypeError, UnicodeError, ValueError) as exc:
            raise PreviewRelayTransportError(
                "preview_relay_response_invalid", "Preview Relay response is invalid"
            ) from exc
        finally:
            if writer is not None:
                writer.close()
                with suppress(ConnectionError, ssl.SSLError):
                    await writer.wait_closed()


__all__ = [
    "MutualTlsPreviewRelayClient",
    "MutualTlsPreviewRelayServer",
    "PreviewGatewayCertificateAuthorizer",
    "PreviewRelayEndpoint",
    "PreviewRelayEndpointResolver",
    "PreviewRelayTransportError",
]
