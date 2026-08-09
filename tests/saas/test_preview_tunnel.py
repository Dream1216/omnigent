from __future__ import annotations

import asyncio
import contextlib
import json
import multiprocessing
import os
import socket
import stat
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

import pytest
import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

from omnigent.runner.transports.ws_tunnel.frames import (
    HelloFrame,
    RequestCancelFrame,
    RequestFrame,
    ResponseBodyFrame,
    ResponseEndFrame,
    ResponseHeadFrame,
    decode_frame,
)
from omnigent.runner.transports.ws_tunnel.registry import RunnerSession, TunnelRegistry
from omnigent.runner.transports.ws_tunnel.serve import dispatch_via_asgi
from saas.control_plane import PreviewRouteGrant
from saas.preview_gateway import PreviewTunnelRequest
from saas.preview_tunnel import (
    LocalPreviewTargetRegistry,
    LocalRunnerTunnelBindings,
    OfficialRunnerPreviewTunnel,
    PreviewRunnerASGI,
    PreviewTunnelAdapterError,
    UnixSocketPreviewTarget,
)


class _NoopWebSocket:
    async def send_text(self, data: str) -> None:
        del data

    async def receive_text(self) -> str:
        return await asyncio.Future()


class _ClosableBody(Protocol):
    async def aclose(self) -> None: ...


def _hello() -> HelloFrame:
    return HelloFrame(
        runner_version="0.9.0.dev0",
        frame_protocol_version=1,
        harnesses=["codex"],
        envs=["local"],
    )


def _route(*, generation: int = 4, opaque_key: str = "pvr_abc123") -> PreviewRouteGrant:
    return PreviewRouteGrant(
        preview_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        runner_id=uuid4(),
        runner_connection_generation=generation,
        run_id=uuid4(),
        run_fence_token=9,
        worktree_id=uuid4(),
        worktree_lease_generation=6,
        opaque_preview_key=opaque_key,
        preview_token_hash="a" * 64,
        upstream_request_headers={
            "accept": "text/plain",
            "content-type": "application/json",
            "user-agent": "preview-contract-test",
        },
        response_headers={"Content-Security-Policy": "sandbox"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


async def _fallback(scope: Scope, receive: Receive, send: Send) -> None:
    del scope, receive
    await send({"type": "http.response.start", "status": 404, "headers": []})
    await send({"type": "http.response.body", "body": b"fallback"})


async def _uds_process_app(scope: Scope, receive: Receive, send: Send) -> None:
    body = bytearray()
    while True:
        event = await receive()
        if event["type"] == "http.disconnect":
            return
        assert event["type"] == "http.request"
        body.extend(event.get("body", b""))
        if not event.get("more_body", False):
            break
    if scope.get("path") == "/slow":
        await asyncio.sleep(0.25)
    headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in scope.get("headers", [])
    }
    payload = json.dumps(
        {
            "body": bytes(body).decode(),
            "host": headers.get("host"),
            "internal_headers": sorted(
                key for key in headers if key.startswith("x-omnigent-saas-")
            ),
            "method": scope.get("method"),
            "path": scope.get("path"),
            "query": scope.get("query_string", b"").decode(),
        },
        sort_keys=True,
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    midpoint = max(1, len(payload) // 2)
    await send(
        {
            "type": "http.response.body",
            "body": payload[:midpoint],
            "more_body": True,
        }
    )
    await send({"type": "http.response.body", "body": payload[midpoint:]})


def _serve_preview_uds(socket_path: str) -> None:
    os.umask(0o077)
    uvicorn.run(
        _uds_process_app,
        uds=socket_path,
        lifespan="off",
        access_log=False,
        log_level="critical",
    )


async def _start_preview_process(socket_path: Path) -> multiprocessing.Process:
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_serve_preview_uds, args=(str(socket_path),))
    process.start()
    # macOS spawn imports the complete test module in a fresh interpreter. Under
    # concurrent local Docker/PostgreSQL work that cold import can exceed the old
    # implicit five-second polling budget even though the child is healthy. Keep
    # the bound explicit and independent from the request-timeout contract being
    # tested below.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 30.0
    while loop.time() < deadline:
        if os.path.lexists(socket_path):
            socket_stat = os.lstat(socket_path)
            if stat.S_ISSOCK(socket_stat.st_mode):
                # Uvicorn binds first and then applies its 0666 default. The
                # Runner supervisor hardens the final ready socket to 0600.
                await asyncio.sleep(0.05)
                os.chmod(socket_path, 0o600)
                return process
        if not process.is_alive():
            process.join(timeout=1)
            raise RuntimeError("Preview UDS child exited before binding")
        await asyncio.sleep(0.01)
    process.terminate()
    process.join(timeout=5)
    raise TimeoutError("Preview UDS child did not bind in time")


def _stop_preview_process(process: multiprocessing.Process, socket_path: Path) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
    if process.is_alive():
        process.kill()
        process.join(timeout=5)
    with contextlib.suppress(FileNotFoundError):
        socket_path.unlink()


class _PreviewApp:
    def __init__(self) -> None:
        self.requests: list[tuple[str, bytes, dict[str, str], tuple[str, int] | None]] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = bytearray()
        while True:
            event = await receive()
            assert event["type"] == "http.request"
            body.extend(event.get("body", b""))
            if not event.get("more_body", False):
                break
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        self.requests.append((str(scope["path"]), bytes(body), headers, scope.get("client")))
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain"), (b"set-cookie", b"denied=1")],
            }
        )
        await send({"type": "http.response.body", "body": b"chunk-one", "more_body": True})
        await asyncio.sleep(0)
        await send({"type": "http.response.body", "body": b"chunk-two"})


async def _dispatch_one(
    registry: TunnelRegistry,
    session: RunnerSession,
    app: ASGIApp,
) -> RequestFrame:
    raw = await session.outbound_queue.get()
    assert raw is not None
    frame = decode_frame(raw)
    assert isinstance(frame, RequestFrame)

    async def send_back(payload: str) -> None:
        response = decode_frame(payload)
        assert isinstance(response, ResponseHeadFrame | ResponseBodyFrame | ResponseEndFrame)
        assert registry.route_response_frame(session.runner_id, response, session=session)

    await dispatch_via_asgi(app, frame, send_back)
    return frame


@pytest.mark.asyncio
async def test_preview_http_streams_over_exact_official_runner_session() -> None:
    registry = TunnelRegistry()
    session = registry.register("official-runner-a", _NoopWebSocket(), _hello())
    route = _route()
    bindings = LocalRunnerTunnelBindings(registry)
    bindings.bind(
        runner_id=route.runner_id,
        connection_generation=route.runner_connection_generation,
        official_runner_id=session.runner_id,
    )
    targets = LocalPreviewTargetRegistry()
    preview_app = _PreviewApp()
    targets.register(route, preview_app)
    runner_app = PreviewRunnerASGI(_fallback, targets)
    tunnel = OfficialRunnerPreviewTunnel(registry, bindings)

    dispatch = asyncio.create_task(_dispatch_one(registry, session, runner_app))
    response = await tunnel.forward(
        PreviewTunnelRequest(
            route=route,
            method="POST",
            path="/nested/api",
            query="mode=test",
            headers=route.upstream_request_headers,
            body=b'{"ok":true}',
        )
    )
    assert not isinstance(response.body, bytes)
    chunks = [chunk async for chunk in response.body]
    frame = await dispatch

    assert response.status_code == 200
    assert chunks == [b"chunk-one", b"chunk-two"]
    assert frame.path.startswith("/__omnigent_saas/preview/pvr_abc123/")
    assert frame.query_string == "mode=test"
    assert preview_app.requests == [
        (
            "/nested/api",
            b'{"ok":true}',
            {
                "accept": "text/plain",
                "content-type": "application/json",
                "user-agent": "preview-contract-test",
            },
            ("preview-tunnel", 0),
        )
    ]
    assert not session.in_flight


@pytest.mark.asyncio
async def test_preview_tunnel_rejects_stale_control_plane_or_official_session_generation() -> None:
    registry = TunnelRegistry()
    first = registry.register("official-runner-a", _NoopWebSocket(), _hello())
    route = _route(generation=2)
    bindings = LocalRunnerTunnelBindings(registry)
    binding = bindings.bind(
        runner_id=route.runner_id,
        connection_generation=route.runner_connection_generation,
        official_runner_id=first.runner_id,
    )
    tunnel = OfficialRunnerPreviewTunnel(registry, bindings)
    request = PreviewTunnelRequest(route, "GET", "/", "", {}, b"")

    registry.register("official-runner-a", _NoopWebSocket(), _hello())
    with pytest.raises(PreviewTunnelAdapterError) as replaced_session:
        await tunnel.forward(request)
    assert replaced_session.value.code == "preview_runner_tunnel_stale"
    assert not bindings.unbind(replace(binding, connection_generation=99))
    assert bindings.unbind(binding)

    second = registry.get("official-runner-a")
    assert second is not None
    bindings.bind(
        runner_id=route.runner_id,
        connection_generation=3,
        official_runner_id=second.runner_id,
    )
    with pytest.raises(PreviewTunnelAdapterError) as stale_control_plane:
        await tunnel.forward(request)
    assert stale_control_plane.value.code == "preview_runner_tunnel_stale"


@pytest.mark.asyncio
async def test_runner_preview_route_rejects_cross_scope_metadata_without_enumeration() -> None:
    registry = TunnelRegistry()
    session = registry.register("official-runner-a", _NoopWebSocket(), _hello())
    route = _route()
    bindings = LocalRunnerTunnelBindings(registry)
    bindings.bind(
        runner_id=route.runner_id,
        connection_generation=route.runner_connection_generation,
        official_runner_id=session.runner_id,
    )
    targets = LocalPreviewTargetRegistry()
    targets.register(route, _PreviewApp())
    runner_app = PreviewRunnerASGI(_fallback, targets)
    tunnel = OfficialRunnerPreviewTunnel(registry, bindings)
    forged = replace(route, run_id=uuid4())

    dispatch = asyncio.create_task(_dispatch_one(registry, session, runner_app))
    response = await tunnel.forward(PreviewTunnelRequest(forged, "GET", "/private", "", {}, b""))
    assert not isinstance(response.body, bytes)
    body = b"".join([chunk async for chunk in response.body])
    await dispatch

    assert response.status_code == 404
    assert body == b'{"detail":{"code":"preview_route_not_found"}}'


@pytest.mark.asyncio
async def test_preview_response_close_sends_cancel_and_releases_inflight_slot() -> None:
    registry = TunnelRegistry()
    session = registry.register("official-runner-a", _NoopWebSocket(), _hello())
    route = _route()
    bindings = LocalRunnerTunnelBindings(registry)
    bindings.bind(
        runner_id=route.runner_id,
        connection_generation=route.runner_connection_generation,
        official_runner_id=session.runner_id,
    )
    tunnel = OfficialRunnerPreviewTunnel(registry, bindings)

    forward = asyncio.create_task(
        tunnel.forward(PreviewTunnelRequest(route, "GET", "/stream", "", {}, b""))
    )
    raw = await session.outbound_queue.get()
    assert raw is not None
    request_frame = decode_frame(raw)
    assert isinstance(request_frame, RequestFrame)
    assert registry.route_response_frame(
        session.runner_id,
        ResponseHeadFrame(id=request_frame.id, status=200, headers=[]),
        session=session,
    )
    response = await forward
    assert not isinstance(response.body, bytes)
    await cast(_ClosableBody, response.body).aclose()

    cancel_raw = await session.outbound_queue.get()
    assert cancel_raw is not None
    cancel = decode_frame(cancel_raw)
    assert isinstance(cancel, RequestCancelFrame)
    assert cancel.id == request_frame.id
    assert not session.in_flight


@pytest.mark.asyncio
async def test_preview_response_head_timeout_fails_closed_and_cleans_request() -> None:
    registry = TunnelRegistry()
    session = registry.register("official-runner-a", _NoopWebSocket(), _hello())
    route = _route()
    bindings = LocalRunnerTunnelBindings(registry)
    bindings.bind(
        runner_id=route.runner_id,
        connection_generation=route.runner_connection_generation,
        official_runner_id=session.runner_id,
    )
    tunnel = OfficialRunnerPreviewTunnel(
        registry,
        bindings,
        response_head_timeout_seconds=0.01,
    )

    with pytest.raises(PreviewTunnelAdapterError) as timeout:
        await tunnel.forward(PreviewTunnelRequest(route, "GET", "/slow", "", {}, b""))
    assert timeout.value.code == "preview_response_timeout"
    assert not session.in_flight


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket target requires POSIX")
@pytest.mark.asyncio
async def test_preview_tunnel_reaches_real_runner_local_uds_process() -> None:
    route = _route(opaque_key="pvr_real_uds")
    with tempfile.TemporaryDirectory(prefix="omnigent-preview-", dir="/tmp") as root_text:
        root = Path(root_text).resolve()
        os.chmod(root, 0o700)
        target = UnixSocketPreviewTarget(route, root)
        process = await _start_preview_process(target.socket_path)
        try:
            identity = target.activate()
            assert identity.owner_uid == os.geteuid()

            registry = TunnelRegistry()
            session = registry.register("official-runner-uds", _NoopWebSocket(), _hello())
            bindings = LocalRunnerTunnelBindings(registry)
            bindings.bind(
                runner_id=route.runner_id,
                connection_generation=route.runner_connection_generation,
                official_runner_id=session.runner_id,
            )
            targets = LocalPreviewTargetRegistry()
            targets.register(route, target)
            runner_app = PreviewRunnerASGI(_fallback, targets)
            tunnel = OfficialRunnerPreviewTunnel(registry, bindings)

            dispatch = asyncio.create_task(_dispatch_one(registry, session, runner_app))
            response = await tunnel.forward(
                PreviewTunnelRequest(
                    route=route,
                    method="POST",
                    path="/nested/echo",
                    query="mode=uds",
                    headers=route.upstream_request_headers,
                    body=b'{"through":"uds"}',
                )
            )
            assert not isinstance(response.body, bytes)
            payload = json.loads(b"".join([chunk async for chunk in response.body]))
            await dispatch

            assert response.status_code == 200
            assert payload == {
                "body": '{"through":"uds"}',
                "host": "preview.invalid",
                "internal_headers": [],
                "method": "POST",
                "path": "/nested/echo",
                "query": "mode=uds",
            }
            assert not session.in_flight
        finally:
            await target.aclose()
            _stop_preview_process(process, target.socket_path)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket target requires POSIX")
@pytest.mark.asyncio
async def test_preview_uds_socket_replacement_without_lifecycle_fails_closed() -> None:
    route = _route(opaque_key="pvr_stale_uds")
    with tempfile.TemporaryDirectory(prefix="omnigent-preview-", dir="/tmp") as root_text:
        root = Path(root_text).resolve()
        os.chmod(root, 0o700)
        target = UnixSocketPreviewTarget(route, root)
        first_process = await _start_preview_process(target.socket_path)
        replacement_process: multiprocessing.Process | None = None
        try:
            first_identity = target.activate()
            _stop_preview_process(first_process, target.socket_path)
            replacement_process = await _start_preview_process(target.socket_path)
            with pytest.raises(PreviewTunnelAdapterError) as replacement:
                target.activate()
            assert replacement.value.code == "preview_uds_socket_replaced"
            assert first_identity.inode > 0

            registry = TunnelRegistry()
            session = registry.register("official-runner-stale-uds", _NoopWebSocket(), _hello())
            bindings = LocalRunnerTunnelBindings(registry)
            bindings.bind(
                runner_id=route.runner_id,
                connection_generation=route.runner_connection_generation,
                official_runner_id=session.runner_id,
            )
            targets = LocalPreviewTargetRegistry()
            targets.register(route, target)
            runner_app = PreviewRunnerASGI(_fallback, targets)
            tunnel = OfficialRunnerPreviewTunnel(registry, bindings)

            dispatch = asyncio.create_task(_dispatch_one(registry, session, runner_app))
            response = await tunnel.forward(
                PreviewTunnelRequest(route, "GET", "/private", "", {}, b"")
            )
            assert not isinstance(response.body, bytes)
            body = b"".join([chunk async for chunk in response.body])
            await dispatch

            assert response.status_code == 502
            assert body == b'{"detail":{"code":"preview_target_unavailable"}}'
            assert not session.in_flight
        finally:
            await target.aclose()
            if replacement_process is not None:
                _stop_preview_process(replacement_process, target.socket_path)
            else:
                _stop_preview_process(first_process, target.socket_path)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket target requires POSIX")
@pytest.mark.asyncio
async def test_preview_uds_response_head_timeout_is_bounded() -> None:
    route = _route(opaque_key="pvr_slow_uds")
    with tempfile.TemporaryDirectory(prefix="omnigent-preview-", dir="/tmp") as root_text:
        root = Path(root_text).resolve()
        os.chmod(root, 0o700)
        target = UnixSocketPreviewTarget(route, root, request_timeout_seconds=0.05)
        process = await _start_preview_process(target.socket_path)
        try:
            target.activate()
            registry = TunnelRegistry()
            session = registry.register("official-runner-slow-uds", _NoopWebSocket(), _hello())
            bindings = LocalRunnerTunnelBindings(registry)
            bindings.bind(
                runner_id=route.runner_id,
                connection_generation=route.runner_connection_generation,
                official_runner_id=session.runner_id,
            )
            targets = LocalPreviewTargetRegistry()
            targets.register(route, target)
            runner_app = PreviewRunnerASGI(_fallback, targets)
            tunnel = OfficialRunnerPreviewTunnel(registry, bindings)

            dispatch = asyncio.create_task(_dispatch_one(registry, session, runner_app))
            response = await tunnel.forward(
                PreviewTunnelRequest(route, "GET", "/slow", "", {}, b"")
            )
            assert not isinstance(response.body, bytes)
            body = b"".join([chunk async for chunk in response.body])
            await dispatch

            assert response.status_code == 504
            assert body == b'{"detail":{"code":"preview_target_timeout"}}'
            assert not session.in_flight
        finally:
            await target.aclose()
            _stop_preview_process(process, target.socket_path)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket target requires POSIX")
@pytest.mark.asyncio
async def test_preview_uds_activation_rejects_symlink_or_public_socket() -> None:
    route = _route(opaque_key="pvr_bad_uds")
    with tempfile.TemporaryDirectory(prefix="omnigent-preview-", dir="/tmp") as root_text:
        root = Path(root_text).resolve()
        os.chmod(root, 0o700)

        symlink_target = UnixSocketPreviewTarget(route, root)
        symlink_target.socket_path.symlink_to("/dev/null")
        with pytest.raises(PreviewTunnelAdapterError) as symlink_error:
            symlink_target.activate()
        assert symlink_error.value.code == "preview_uds_socket_invalid"
        symlink_target.socket_path.unlink()
        await symlink_target.aclose()

        public_target = UnixSocketPreviewTarget(route, root)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(public_target.socket_path))
            os.chmod(public_target.socket_path, 0o666)
            with pytest.raises(PreviewTunnelAdapterError) as public_error:
                public_target.activate()
            assert public_error.value.code == "preview_uds_socket_invalid"
        finally:
            listener.close()
            with contextlib.suppress(FileNotFoundError):
                public_target.socket_path.unlink()
            await public_target.aclose()


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket target requires POSIX")
def test_preview_uds_rejects_non_private_or_client_shaped_root() -> None:
    route = _route(opaque_key="pvr_bad_root")
    with tempfile.TemporaryDirectory(prefix="omnigent-preview-", dir="/tmp") as root_text:
        root = Path(root_text).resolve()
        os.chmod(root, 0o755)
        with pytest.raises(PreviewTunnelAdapterError) as public_root:
            UnixSocketPreviewTarget(route, root)
        assert public_root.value.code == "preview_uds_root_invalid"

        with pytest.raises(PreviewTunnelAdapterError) as relative_root:
            UnixSocketPreviewTarget(route, Path("client/selected/socket"))
        assert relative_root.value.code == "preview_uds_root_invalid"
