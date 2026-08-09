"""Generation-bound Preview HTTP over the official Runner WebSocket tunnel."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import re
import stat
import threading
import uuid
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from uuid import UUID

import httpx
from starlette.types import ASGIApp, Receive, Scope, Send

from omnigent.runner.transports.ws_tunnel.frames import (
    RequestCancelFrame,
    RequestFrame,
    ResponseBodyFrame,
    decode_body,
    encode_body,
    encode_frame,
)
from omnigent.runner.transports.ws_tunnel.registry import (
    RequestState,
    RunnerSession,
    TunnelRegistry,
)
from saas.control_plane import (
    PreviewRouteGrant,
    RunnerTunnelPlacement,
    RunnerTunnelPlacementError,
)
from saas.preview_gateway import PreviewTunnelRequest, PreviewTunnelResponse

_INTERNAL_PREFIX = "/__omnigent_saas/preview/"
_OPAQUE_KEY = re.compile(r"^pvr_[0-9a-zA-Z_-]{1,92}$")
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_UDS_PATH_MAX_BYTES = 100
_INTERNAL_HEADERS = {
    "x-omnigent-saas-preview-id": "preview_id",
    "x-omnigent-saas-tenant-id": "tenant_id",
    "x-omnigent-saas-space-id": "space_id",
    "x-omnigent-saas-project-id": "project_id",
    "x-omnigent-saas-runner-id": "runner_id",
    "x-omnigent-saas-runner-generation": "runner_connection_generation",
    "x-omnigent-saas-run-id": "run_id",
    "x-omnigent-saas-run-fence": "run_fence_token",
    "x-omnigent-saas-worktree-id": "worktree_id",
    "x-omnigent-saas-worktree-generation": "worktree_lease_generation",
}


class PreviewTunnelAdapterError(RuntimeError):
    """Stable fail-closed error returned without internal transport details."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RunnerTunnelBinding:
    """Exact SaaS Runner incarnation bound to one official live WS session."""

    runner_id: UUID
    connection_generation: int
    official_runner_id: str
    session: RunnerSession


class RunnerTunnelBindingResolver(Protocol):
    def resolve(self, route: PreviewRouteGrant) -> RunnerTunnelBinding: ...


class RunnerTunnelPlacementResolver(Protocol):
    def resolve_preview_route(
        self,
        *,
        runner_id: UUID,
        runner_connection_generation: int,
        preview_token_hash: str,
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement: ...

    def require_route_owner(
        self,
        *,
        placement: RunnerTunnelPlacement,
        runner_id: UUID,
        runner_connection_generation: int,
        preview_token_hash: str,
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement: ...


class PreviewReplicaRelay(Protocol):
    async def forward(
        self,
        placement: RunnerTunnelPlacement,
        request: PreviewTunnelRequest,
    ) -> PreviewTunnelResponse: ...


class LocalRunnerTunnelBindings:
    """Process-local binding seam for a co-located official TunnelRegistry.

    A production multi-process Preview gateway must replace this resolver with
    authenticated placement routing. This implementation deliberately binds
    the exact official ``RunnerSession`` object, not only a reusable runner id.
    """

    def __init__(self, registry: TunnelRegistry) -> None:
        self._registry = registry
        self._bindings: dict[UUID, RunnerTunnelBinding] = {}
        self._lock = threading.RLock()

    def bind(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        official_runner_id: str,
    ) -> RunnerTunnelBinding:
        if connection_generation <= 0:
            raise PreviewTunnelAdapterError(
                "preview_runner_generation_invalid", "Runner generation must be positive"
            )
        if not official_runner_id or len(official_runner_id) > 256:
            raise PreviewTunnelAdapterError(
                "preview_official_runner_id_invalid", "Official Runner id is invalid"
            )
        session = self._registry.get(official_runner_id)
        if session is None or session.runner_id != official_runner_id:
            raise PreviewTunnelAdapterError(
                "preview_runner_tunnel_offline", "Runner tunnel is unavailable"
            )
        binding = RunnerTunnelBinding(
            runner_id=runner_id,
            connection_generation=connection_generation,
            official_runner_id=official_runner_id,
            session=session,
        )
        with self._lock:
            current = self._bindings.get(runner_id)
            if current is not None:
                if current == binding:
                    return current
                if connection_generation <= current.connection_generation:
                    raise PreviewTunnelAdapterError(
                        "preview_runner_generation_not_monotonic",
                        "Runner tunnel generation must advance on replacement",
                    )
            self._bindings[runner_id] = binding
        return binding

    def unbind(self, binding: RunnerTunnelBinding) -> bool:
        with self._lock:
            if self._bindings.get(binding.runner_id) != binding:
                return False
            self._bindings.pop(binding.runner_id, None)
            return True

    def resolve(self, route: PreviewRouteGrant) -> RunnerTunnelBinding:
        with self._lock:
            binding = self._bindings.get(route.runner_id)
        if (
            binding is None
            or binding.connection_generation != route.runner_connection_generation
            or self._registry.get(binding.official_runner_id) is not binding.session
        ):
            raise PreviewTunnelAdapterError(
                "preview_runner_tunnel_stale", "Runner tunnel binding is stale"
            )
        return binding


def _route_headers(route: PreviewRouteGrant) -> dict[str, str]:
    return {
        "x-omnigent-saas-preview-id": str(route.preview_id),
        "x-omnigent-saas-tenant-id": str(route.tenant_id),
        "x-omnigent-saas-space-id": str(route.space_id),
        "x-omnigent-saas-project-id": str(route.project_id),
        "x-omnigent-saas-runner-id": str(route.runner_id),
        "x-omnigent-saas-runner-generation": str(route.runner_connection_generation),
        "x-omnigent-saas-run-id": str(route.run_id),
        "x-omnigent-saas-run-fence": str(route.run_fence_token),
        "x-omnigent-saas-worktree-id": str(route.worktree_id),
        "x-omnigent-saas-worktree-generation": str(route.worktree_lease_generation),
    }


class _OfficialPreviewBody:
    def __init__(
        self,
        registry: TunnelRegistry,
        binding: RunnerTunnelBinding,
        request_id: str,
        state: RequestState,
    ) -> None:
        self._registry = registry
        self._binding = binding
        self._request_id = request_id
        self._state = state
        self._complete = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            while True:
                item = await self._state.body_queue.get()
                if self._state.aborted_with is not None:
                    raise self._state.aborted_with
                if item is None:
                    self._complete = True
                    break
                if isinstance(item, ResponseBodyFrame):
                    yield decode_body(item.body, item.encoding)
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if self._registry.request_is_open(self._state.session, self._request_id):
            if not self._complete:
                with contextlib.suppress(Exception):
                    await self._registry.send_text(
                        self._state.session,
                        encode_frame(
                            RequestCancelFrame(
                                id=self._request_id,
                                reason="preview_client_disconnected",
                            )
                        ),
                    )
            self._registry.close_request(
                self._binding.official_runner_id,
                self._request_id,
                session=self._state.session,
            )


class OfficialRunnerPreviewTunnel:
    """Forward authorized Preview HTTP over an exact official Runner session."""

    def __init__(
        self,
        registry: TunnelRegistry,
        bindings: RunnerTunnelBindingResolver,
        *,
        response_head_timeout_seconds: float = 30.0,
    ) -> None:
        if response_head_timeout_seconds <= 0:
            raise ValueError("Preview response-head timeout must be positive")
        self._registry = registry
        self._bindings = bindings
        self._response_head_timeout_seconds = response_head_timeout_seconds

    async def forward(self, request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        route = request.route
        if route.expires_at <= datetime.now(timezone.utc):
            raise PreviewTunnelAdapterError("preview_route_expired", "Preview route expired")
        if not _OPAQUE_KEY.fullmatch(route.opaque_preview_key):
            raise PreviewTunnelAdapterError(
                "preview_route_key_invalid", "Preview route key is invalid"
            )
        binding = self._bindings.resolve(route)
        request_id = uuid.uuid4().hex
        try:
            state = self._registry.open_request(binding.official_runner_id, request_id)
        except KeyError as exc:
            raise PreviewTunnelAdapterError(
                "preview_runner_tunnel_offline", "Runner tunnel is unavailable"
            ) from exc
        if state.session is not binding.session:
            self._registry.close_request(
                binding.official_runner_id, request_id, session=state.session
            )
            raise PreviewTunnelAdapterError(
                "preview_runner_tunnel_stale", "Runner tunnel binding changed"
            )

        headers: dict[str, str] = {}
        for name, value in request.headers.items():
            lowered = name.lower()
            if (
                lowered in headers
                or lowered in _INTERNAL_HEADERS
                or "\r" in name
                or "\n" in name
                or "\r" in value
                or "\n" in value
            ):
                self._registry.close_request(
                    binding.official_runner_id, request_id, session=state.session
                )
                raise PreviewTunnelAdapterError(
                    "preview_internal_header_collision", "Preview headers are invalid"
                )
            headers[lowered] = value
        content_type = headers.get("content-type", "application/octet-stream")
        headers.update(_route_headers(route))
        body, encoding = (
            encode_body(request.body, content_type) if request.body else (None, "utf-8")
        )
        frame = RequestFrame(
            id=request_id,
            method=request.method,
            path=f"{_INTERNAL_PREFIX}{route.opaque_preview_key}{request.path}",
            query_string=request.query,
            headers=[[key, value] for key, value in headers.items()],
            body=body,
            encoding=encoding,
            stream=True,
        )
        try:
            await self._registry.send_text(state.session, encode_frame(frame))
            head = await asyncio.wait_for(
                state.head_future,
                timeout=self._response_head_timeout_seconds,
            )
        except BaseException as exc:
            with contextlib.suppress(Exception):
                await self._registry.send_text(
                    state.session,
                    encode_frame(RequestCancelFrame(id=request_id, reason="preview_head_failed")),
                )
            self._registry.close_request(
                binding.official_runner_id, request_id, session=state.session
            )
            if isinstance(exc, asyncio.TimeoutError):
                raise PreviewTunnelAdapterError(
                    "preview_response_timeout", "Preview Runner did not respond"
                ) from exc
            raise
        return PreviewTunnelResponse(
            status_code=head.status,
            headers={key.lower(): value for key, value in head.headers},
            body=_OfficialPreviewBody(
                self._registry,
                binding,
                request_id,
                state,
            ),
        )


class PlacementRoutedPreviewTunnel:
    """Route Preview traffic to the replica owning the exact Runner incarnation.

    PostgreSQL remains the ownership authority. The relay is intentionally an
    interface: production transport must authenticate gateway peers and bind
    each message to the opaque relay subject. Clients never select either.
    """

    def __init__(
        self,
        *,
        gateway_instance_id: str,
        placements: RunnerTunnelPlacementResolver,
        local_tunnel: OfficialRunnerPreviewTunnel,
        relay: PreviewReplicaRelay | None,
    ) -> None:
        if not gateway_instance_id or len(gateway_instance_id) > 128:
            raise ValueError("gateway_instance_id is invalid")
        self._gateway_instance_id = gateway_instance_id
        self._placements = placements
        self._local_tunnel = local_tunnel
        self._relay = relay

    async def forward(self, request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        """Resolve every request from durable state and select local or peer forwarding."""

        placement = await asyncio.to_thread(self._resolve, request.route)
        if placement.gateway_instance_id == self._gateway_instance_id:
            return await self._local_tunnel.forward(request)
        if self._relay is None:
            raise PreviewTunnelAdapterError(
                "preview_runner_relay_unavailable", "Runner tunnel relay is unavailable"
            )
        return await self._relay.forward(placement, request)

    async def accept_relay(
        self,
        placement: RunnerTunnelPlacement,
        request: PreviewTunnelRequest,
    ) -> PreviewTunnelResponse:
        """Re-authorize ownership on the receiver before touching its local session."""

        route = request.route
        try:
            await asyncio.to_thread(
                self._placements.require_route_owner,
                placement=placement,
                runner_id=route.runner_id,
                runner_connection_generation=route.runner_connection_generation,
                preview_token_hash=route.preview_token_hash,
            )
        except RunnerTunnelPlacementError as exc:
            raise PreviewTunnelAdapterError(
                "preview_runner_placement_stale", "Runner tunnel placement is stale"
            ) from exc
        return await self._local_tunnel.forward(request)

    def _resolve(self, route: PreviewRouteGrant) -> RunnerTunnelPlacement:
        try:
            return self._placements.resolve_preview_route(
                runner_id=route.runner_id,
                runner_connection_generation=route.runner_connection_generation,
                preview_token_hash=route.preview_token_hash,
            )
        except RunnerTunnelPlacementError as exc:
            raise PreviewTunnelAdapterError(
                "preview_runner_placement_unavailable",
                "Runner tunnel placement is unavailable",
            ) from exc


@dataclass(frozen=True, slots=True)
class PreviewTargetBinding:
    route: PreviewRouteGrant
    app: ASGIApp


class LocalPreviewTargetRegistry:
    """Runner-local exact Preview target registry; no host port is client-selected."""

    def __init__(self) -> None:
        self._targets: dict[str, PreviewTargetBinding] = {}
        self._lock = threading.RLock()

    def register(self, route: PreviewRouteGrant, app: ASGIApp) -> PreviewTargetBinding:
        if not _OPAQUE_KEY.fullmatch(route.opaque_preview_key):
            raise PreviewTunnelAdapterError(
                "preview_route_key_invalid", "Preview route key is invalid"
            )
        target = PreviewTargetBinding(route=route, app=app)
        with self._lock:
            current = self._targets.get(route.opaque_preview_key)
            if current is not None and current != target:
                raise PreviewTunnelAdapterError(
                    "preview_target_key_conflict", "Preview target key is already registered"
                )
            self._targets[route.opaque_preview_key] = target
        return target

    def revoke(self, target: PreviewTargetBinding) -> bool:
        with self._lock:
            if self._targets.get(target.route.opaque_preview_key) != target:
                return False
            self._targets.pop(target.route.opaque_preview_key, None)
            return True

    def resolve(self, opaque_key: str, metadata: Mapping[str, str]) -> PreviewTargetBinding | None:
        with self._lock:
            target = self._targets.get(opaque_key)
        if target is None or metadata != _route_headers(target.route):
            return None
        if target.route.expires_at <= datetime.now(timezone.utc):
            return None
        return target


@dataclass(frozen=True, slots=True)
class UnixSocketIdentity:
    """Exact filesystem identity of an activated Runner-local socket."""

    device: int
    inode: int
    owner_uid: int
    ctime_ns: int


class UnixSocketPreviewTarget:
    """Proxy one exact Preview route to a server-chosen Runner-local UDS.

    The socket path is derived from the complete route binding below a private
    Runner-owned root. Neither a Preview request nor control-plane metadata can
    select a TCP host, port, or host filesystem path. Activation pins the
    socket inode, device, and owner; replacement without a new target lifecycle
    fails closed even when the pathname is reused.
    """

    def __init__(
        self,
        route: PreviewRouteGrant,
        socket_root: Path,
        *,
        request_timeout_seconds: float = 30.0,
    ) -> None:
        if os.name != "posix":
            raise PreviewTunnelAdapterError(
                "preview_uds_unsupported", "Unix socket Preview targets require POSIX"
            )
        if request_timeout_seconds <= 0:
            raise ValueError("Preview UDS request timeout must be positive")
        if not _OPAQUE_KEY.fullmatch(route.opaque_preview_key):
            raise PreviewTunnelAdapterError(
                "preview_route_key_invalid", "Preview route key is invalid"
            )
        raw_root = Path(socket_root)
        if not raw_root.is_absolute():
            raise PreviewTunnelAdapterError(
                "preview_uds_root_invalid", "Preview socket root must be absolute"
            )
        try:
            root = raw_root.resolve(strict=True)
            root_stat = os.lstat(root)
            root_fd = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_root_stat = os.fstat(root_fd)
        except OSError as exc:
            raise PreviewTunnelAdapterError(
                "preview_uds_root_invalid", "Preview socket root is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) & 0o077
            or not stat.S_ISDIR(opened_root_stat.st_mode)
            or opened_root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(opened_root_stat.st_mode) & 0o077
            or (root_stat.st_dev, root_stat.st_ino)
            != (opened_root_stat.st_dev, opened_root_stat.st_ino)
        ):
            os.close(root_fd)
            raise PreviewTunnelAdapterError(
                "preview_uds_root_invalid",
                "Preview socket root must be a private Runner-owned directory",
            )
        route_material = "\x00".join(
            (
                str(route.preview_id),
                str(route.tenant_id),
                str(route.space_id),
                str(route.project_id),
                str(route.runner_id),
                str(route.runner_connection_generation),
                str(route.run_id),
                str(route.run_fence_token),
                str(route.worktree_id),
                str(route.worktree_lease_generation),
                route.opaque_preview_key,
            )
        )
        digest = hashlib.sha256(route_material.encode()).hexdigest()[:20]
        socket_path = root / f"preview-{digest}.sock"
        if len(os.fsencode(socket_path)) > _UDS_PATH_MAX_BYTES:
            os.close(root_fd)
            raise PreviewTunnelAdapterError(
                "preview_uds_path_too_long", "Preview socket path is too long"
            )
        if os.path.lexists(socket_path):
            os.close(root_fd)
            raise PreviewTunnelAdapterError(
                "preview_uds_path_occupied", "Preview socket path is already occupied"
            )

        timeout = httpx.Timeout(request_timeout_seconds)
        transport = httpx.AsyncHTTPTransport(
            uds=str(socket_path),
            trust_env=False,
            retries=0,
        )
        self.route = route
        self.socket_path = socket_path
        self._root_identity = (root_stat.st_dev, root_stat.st_ino, root_stat.st_uid)
        self._root_fd: int | None = root_fd
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )
        self._identity: UnixSocketIdentity | None = None
        self._lock = threading.RLock()

    def _socket_identity(self) -> UnixSocketIdentity:
        with self._lock:
            root_fd = self._root_fd
        if root_fd is None:
            raise PreviewTunnelAdapterError(
                "preview_uds_socket_unavailable", "Preview socket target is closed"
            )
        try:
            root_stat = os.lstat(self.socket_path.parent)
            opened_root_stat = os.fstat(root_fd)
            socket_stat = os.lstat(self.socket_path)
        except OSError as exc:
            raise PreviewTunnelAdapterError(
                "preview_uds_socket_unavailable", "Preview socket is unavailable"
            ) from exc
        if (
            (root_stat.st_dev, root_stat.st_ino, root_stat.st_uid) != self._root_identity
            or (opened_root_stat.st_dev, opened_root_stat.st_ino, opened_root_stat.st_uid)
            != self._root_identity
            or not stat.S_ISDIR(root_stat.st_mode)
            or stat.S_IMODE(root_stat.st_mode) & 0o077
            or not stat.S_ISSOCK(socket_stat.st_mode)
            or socket_stat.st_uid != os.geteuid()
            or stat.S_IMODE(socket_stat.st_mode) & 0o077
        ):
            raise PreviewTunnelAdapterError(
                "preview_uds_socket_invalid",
                "Preview socket must be an exact private Runner-owned socket",
            )
        return UnixSocketIdentity(
            device=socket_stat.st_dev,
            inode=socket_stat.st_ino,
            owner_uid=socket_stat.st_uid,
            ctime_ns=socket_stat.st_ctime_ns,
        )

    def activate(self) -> UnixSocketIdentity:
        """Pin the socket only after the supervised Preview process binds it."""

        identity = self._socket_identity()
        with self._lock:
            if self._identity is not None and self._identity != identity:
                raise PreviewTunnelAdapterError(
                    "preview_uds_socket_replaced",
                    "Preview socket identity changed during activation",
                )
            self._identity = identity
        return identity

    def deactivate(self) -> None:
        with self._lock:
            self._identity = None

    async def aclose(self) -> None:
        self.deactivate()
        await self._client.aclose()
        with self._lock:
            root_fd = self._root_fd
            self._root_fd = None
        if root_fd is not None:
            os.close(root_fd)

    def _verify_active(self) -> None:
        current = self._socket_identity()
        with self._lock:
            expected = self._identity
        if expected is None or current != expected:
            raise PreviewTunnelAdapterError(
                "preview_uds_socket_stale", "Preview socket identity is stale"
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        client = scope.get("client")
        if (
            scope.get("type") != "http"
            or not isinstance(client, tuple)
            or client != ("preview-tunnel", 0)
            or self.route.expires_at <= datetime.now(timezone.utc)
        ):
            await _asgi_error(send, status=404, code="preview_route_not_found")
            return
        try:
            self._verify_active()
        except PreviewTunnelAdapterError:
            await _asgi_error(send, status=502, code="preview_target_unavailable")
            return

        async def request_body() -> AsyncIterator[bytes]:
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    raise PreviewTunnelAdapterError(
                        "preview_client_disconnected", "Preview client disconnected"
                    )
                if message["type"] != "http.request":
                    raise PreviewTunnelAdapterError(
                        "preview_request_invalid", "Preview request stream is invalid"
                    )
                body = message.get("body", b"")
                if body:
                    yield body
                if not message.get("more_body", False):
                    break

        headers: list[tuple[bytes, bytes]] = []
        denied_headers = (
            _HOP_BY_HOP
            | frozenset(_INTERNAL_HEADERS)
            | {
                "host",
                "content-length",
            }
        )
        for raw_name, raw_value in scope.get("headers", []):
            name = raw_name.decode("latin-1").lower()
            if name in denied_headers:
                continue
            headers.append((raw_name, raw_value))
        raw_path = scope.get("raw_path", b"/")
        query_string = scope.get("query_string", b"")
        if not isinstance(raw_path, bytes) or not isinstance(query_string, bytes):
            await _asgi_error(send, status=400, code="preview_request_invalid")
            return
        target = raw_path + (b"?" + query_string if query_string else b"")
        request = self._client.build_request(
            str(scope.get("method", "GET")),
            httpx.URL(scheme="http", host="preview.invalid", raw_path=target),
            headers=headers,
            content=request_body(),
        )
        response: httpx.Response | None = None
        started = False
        try:
            response = await self._client.send(request, stream=True)
            response_headers = [
                (name, value)
                for name, value in response.headers.raw
                if name.decode("latin-1").lower() not in _HOP_BY_HOP
            ]
            await send(
                {
                    "type": "http.response.start",
                    "status": response.status_code,
                    "headers": response_headers,
                }
            )
            started = True
            async for chunk in response.aiter_raw():
                if chunk:
                    await send(
                        {
                            "type": "http.response.body",
                            "body": chunk,
                            "more_body": True,
                        }
                    )
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        except httpx.TimeoutException:
            if not started:
                await _asgi_error(send, status=504, code="preview_target_timeout")
            else:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        except (httpx.HTTPError, OSError, PreviewTunnelAdapterError):
            if not started:
                await _asgi_error(send, status=502, code="preview_target_unavailable")
            else:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            if response is not None:
                await response.aclose()


async def _asgi_error(send: Send, *, status: int, code: str) -> None:
    body = (f'{{"detail":{{"code":"{code}"}}}}').encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _internal_metadata(headers: list[tuple[bytes, bytes]]) -> dict[str, str] | None:
    values: dict[str, list[str]] = {name: [] for name in _INTERNAL_HEADERS}
    for raw_name, raw_value in headers:
        name = raw_name.decode("latin-1").lower()
        if name in values:
            values[name].append(raw_value.decode("latin-1"))
    if any(len(items) != 1 for items in values.values()):
        return None
    return {name: items[0] for name, items in values.items()}


class PreviewRunnerASGI:
    """Intercept internal Preview tunnel paths before the official Runner app."""

    def __init__(self, official_app: ASGIApp, targets: LocalPreviewTargetRegistry) -> None:
        self._official_app = official_app
        self._targets = targets

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        if scope.get("type") != "http" or not path.startswith(_INTERNAL_PREFIX):
            await self._official_app(scope, receive, send)
            return
        client = scope.get("client")
        if not isinstance(client, tuple) or not client or client[0] != "tunnel":
            await _asgi_error(send, status=404, code="preview_route_not_found")
            return
        suffix = path.removeprefix(_INTERNAL_PREFIX)
        opaque_key, separator, remainder = suffix.partition("/")
        if not _OPAQUE_KEY.fullmatch(opaque_key):
            await _asgi_error(send, status=404, code="preview_route_not_found")
            return
        headers = list(scope.get("headers", []))
        metadata = _internal_metadata(headers)
        target = None if metadata is None else self._targets.resolve(opaque_key, metadata)
        if target is None:
            await _asgi_error(send, status=404, code="preview_route_not_found")
            return
        target_scope = dict(scope)
        target_path = f"/{remainder}" if separator else "/"
        target_scope["path"] = target_path
        target_scope["raw_path"] = target_path.encode("utf-8")
        target_scope["root_path"] = ""
        target_scope["client"] = ("preview-tunnel", 0)
        target_scope["headers"] = [
            (name, value)
            for name, value in headers
            if name.decode("latin-1").lower() not in _INTERNAL_HEADERS
        ]
        await target.app(target_scope, receive, send)


__all__ = [
    "LocalPreviewTargetRegistry",
    "LocalRunnerTunnelBindings",
    "OfficialRunnerPreviewTunnel",
    "PlacementRoutedPreviewTunnel",
    "PreviewReplicaRelay",
    "PreviewRunnerASGI",
    "PreviewTargetBinding",
    "PreviewTunnelAdapterError",
    "RunnerTunnelBinding",
    "RunnerTunnelBindingResolver",
    "RunnerTunnelPlacementResolver",
    "UnixSocketIdentity",
    "UnixSocketPreviewTarget",
]
