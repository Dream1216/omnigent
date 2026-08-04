"""Generation-bound Preview HTTP over the official Runner WebSocket tunnel."""

from __future__ import annotations

import asyncio
import contextlib
import re
import threading
import uuid
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID

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
from saas.control_plane import PreviewRouteGrant
from saas.preview_gateway import PreviewTunnelRequest, PreviewTunnelResponse

_INTERNAL_PREFIX = "/__omnigent_saas/preview/"
_OPAQUE_KEY = re.compile(r"^pvr_[0-9a-zA-Z_-]{1,92}$")
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

    def resolve(
        self, opaque_key: str, metadata: Mapping[str, str]
    ) -> PreviewTargetBinding | None:
        with self._lock:
            target = self._targets.get(opaque_key)
        if target is None or metadata != _route_headers(target.route):
            return None
        if target.route.expires_at <= datetime.now(timezone.utc):
            return None
        return target


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
    "PreviewRunnerASGI",
    "PreviewTargetBinding",
    "PreviewTunnelAdapterError",
    "RunnerTunnelBinding",
    "RunnerTunnelBindingResolver",
]
