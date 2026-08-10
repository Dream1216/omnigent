from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from omnigent.runner.transports.ws_tunnel.registry import TunnelRegistry
from saas.control_plane import PreviewRouteGrant
from saas.preview_gateway import PreviewTunnelRequest
from saas.preview_tunnel import (
    LocalPreviewTargetRegistry,
    LocalRunnerTunnelBindings,
    OfficialRunnerPreviewTunnel,
    PreviewRunnerASGI,
)
from saas.runner_adapter.preview_supervisor import (
    PreviewProcessSpec,
    PreviewProcessSupervisorError,
    RunnerPreviewProcessSupervisor,
)
from tests.saas.test_preview_tunnel import (
    _dispatch_one,
    _fallback,
    _hello,
    _NoopWebSocket,
    _route,
)


def _spec(
    *,
    unhealthy: bool = False,
    ignore_term: bool = False,
    never_binds: bool = False,
    stubborn_child: bool = False,
    late_broaden_socket: bool = False,
) -> PreviewProcessSpec:
    environment = [("PYTHONUNBUFFERED", "1")]
    if unhealthy:
        environment.append(("PREVIEW_FIXTURE_UNHEALTHY", "1"))
    if ignore_term:
        environment.append(("PREVIEW_FIXTURE_IGNORE_TERM", "1"))
    if never_binds:
        environment.append(("PREVIEW_FIXTURE_NEVER_BINDS", "1"))
    if stubborn_child:
        environment.append(("PREVIEW_FIXTURE_STUBBORN_CHILD", "1"))
    if late_broaden_socket:
        environment.append(("PREVIEW_FIXTURE_LATE_BROADEN_SOCKET", "1"))
    return PreviewProcessSpec(
        argv=(sys.executable, "-m", "tests.saas.preview_supervisor_fixture"),
        working_directory=Path.cwd().resolve(),
        environment=tuple(environment),
        startup_timeout_seconds=0.2 if never_binds else 5,
        health_timeout_seconds=1,
        shutdown_timeout_seconds=0.1 if ignore_term else 2,
    )


def _metadata(route: PreviewRouteGrant) -> dict[str, str]:
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


async def _wait_for_exit(
    supervisor: RunnerPreviewProcessSupervisor,
    preview_id: UUID,
    *,
    timeout: float = 5,
):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        exit_state = await supervisor.last_exit(preview_id)
        if exit_state is not None:
            return exit_state
        await asyncio.sleep(0.02)
    raise AssertionError("Preview supervisor did not record process exit")


@pytest.mark.skipif(sys.platform == "win32", reason="Preview supervision requires POSIX")
@pytest.mark.asyncio
async def test_supervisor_publishes_only_healthy_uds_and_stops_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("API_TOKEN", "parent-secret-must-not-reach-preview")
    route = _route(opaque_key="pvr_supervised")
    with (
        tempfile.TemporaryDirectory(prefix="omnigent-preview-sockets-", dir="/tmp") as sockets,
        tempfile.TemporaryDirectory(prefix="omnigent-preview-logs-", dir="/tmp") as logs,
    ):
        socket_root = Path(sockets).resolve()
        log_root = Path(logs).resolve()
        os.chmod(socket_root, 0o700)
        os.chmod(log_root, 0o700)
        targets = LocalPreviewTargetRegistry()
        supervisor = RunnerPreviewProcessSupervisor(
            targets,
            socket_root,
            log_root,
            runner_id=route.runner_id,
            connection_generation=route.runner_connection_generation,
        )

        snapshot = await supervisor.start(route, _spec(late_broaden_socket=True))
        try:
            assert snapshot.pid > 0
            assert stat.S_ISSOCK(os.lstat(snapshot.socket_path).st_mode)
            assert stat.S_IMODE(os.lstat(snapshot.socket_path).st_mode) == 0o600
            assert stat.S_IMODE(os.lstat(snapshot.log_path).st_mode) == 0o600
            assert targets.resolve(route.opaque_preview_key, _metadata(route)) is not None

            registry = TunnelRegistry()
            session = registry.register("official-supervised", _NoopWebSocket(), _hello())
            bindings = LocalRunnerTunnelBindings(registry)
            bindings.bind(
                runner_id=route.runner_id,
                connection_generation=route.runner_connection_generation,
                official_runner_id=session.runner_id,
            )
            tunnel = OfficialRunnerPreviewTunnel(registry, bindings)
            runner_app = PreviewRunnerASGI(_fallback, targets)
            dispatch = asyncio.create_task(_dispatch_one(registry, session, runner_app))
            response = await tunnel.forward(
                PreviewTunnelRequest(route, "POST", "/supervised", "", {}, b"body")
            )
            assert not isinstance(response.body, bytes)
            payload = json.loads(b"".join([chunk async for chunk in response.body]))
            await dispatch
            assert payload == {
                "body": "body",
                "method": "POST",
                "parent_api_token_present": False,
                "path": "/supervised",
            }
            assert b"parent-secret-must-not-reach-preview" not in snapshot.log_path.read_bytes()

            exit_state = await supervisor.stop(route.preview_id)
            assert exit_state is not None
            assert exit_state.reason == "stopped"
            assert exit_state.cleanup_error_code is None
            assert await supervisor.snapshot(route.preview_id) is None
            assert targets.resolve(route.opaque_preview_key, _metadata(route)) is None
            assert not snapshot.socket_path.exists()
        finally:
            await supervisor.aclose()


@pytest.mark.skipif(sys.platform == "win32", reason="Preview supervision requires POSIX")
@pytest.mark.asyncio
async def test_supervisor_crash_watch_revokes_target_and_records_exit() -> None:
    route = _route(opaque_key="pvr_crash_watch")
    with (
        tempfile.TemporaryDirectory(prefix="omnigent-preview-sockets-", dir="/tmp") as sockets,
        tempfile.TemporaryDirectory(prefix="omnigent-preview-logs-", dir="/tmp") as logs,
    ):
        socket_root = Path(sockets).resolve()
        log_root = Path(logs).resolve()
        os.chmod(socket_root, 0o700)
        os.chmod(log_root, 0o700)
        targets = LocalPreviewTargetRegistry()
        supervisor = RunnerPreviewProcessSupervisor(
            targets,
            socket_root,
            log_root,
            runner_id=route.runner_id,
            connection_generation=route.runner_connection_generation,
        )
        snapshot = await supervisor.start(route, _spec())
        os.killpg(snapshot.pid, signal.SIGKILL)

        exit_state = await _wait_for_exit(supervisor, route.preview_id)
        assert exit_state.reason == "exited"
        assert exit_state.returncode == -signal.SIGKILL
        assert exit_state.cleanup_error_code is None
        assert await supervisor.snapshot(route.preview_id) is None
        assert targets.resolve(route.opaque_preview_key, _metadata(route)) is None
        assert not snapshot.socket_path.exists()
        await supervisor.aclose()


@pytest.mark.skipif(sys.platform == "win32", reason="Preview supervision requires POSIX")
@pytest.mark.asyncio
async def test_supervisor_expiry_revokes_and_terminates_process() -> None:
    lease_seconds = 8
    route = replace(
        _route(opaque_key="pvr_expiry_watch"),
        # Keep expiry beyond the five-second bounded startup contract. A
        # two-second lease made this acceptance depend on host load and could
        # expire before the fixture had bound its UDS in a full-suite run.
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=lease_seconds),
    )
    with (
        tempfile.TemporaryDirectory(prefix="omnigent-preview-sockets-", dir="/tmp") as sockets,
        tempfile.TemporaryDirectory(prefix="omnigent-preview-logs-", dir="/tmp") as logs,
    ):
        socket_root = Path(sockets).resolve()
        log_root = Path(logs).resolve()
        os.chmod(socket_root, 0o700)
        os.chmod(log_root, 0o700)
        targets = LocalPreviewTargetRegistry()
        supervisor = RunnerPreviewProcessSupervisor(
            targets,
            socket_root,
            log_root,
            runner_id=route.runner_id,
            connection_generation=route.runner_connection_generation,
        )
        snapshot = await supervisor.start(route, _spec())

        exit_state = await _wait_for_exit(
            supervisor,
            route.preview_id,
            timeout=lease_seconds + 2,
        )
        assert exit_state.reason == "expired"
        assert exit_state.returncode is not None
        assert await supervisor.snapshot(route.preview_id) is None
        assert targets.resolve(route.opaque_preview_key, _metadata(route)) is None
        assert not snapshot.socket_path.exists()
        await supervisor.aclose()


@pytest.mark.skipif(sys.platform == "win32", reason="Preview supervision requires POSIX")
@pytest.mark.asyncio
async def test_supervisor_health_failure_never_publishes_target() -> None:
    route = _route(opaque_key="pvr_bad_health")
    with (
        tempfile.TemporaryDirectory(prefix="omnigent-preview-sockets-", dir="/tmp") as sockets,
        tempfile.TemporaryDirectory(prefix="omnigent-preview-logs-", dir="/tmp") as logs,
    ):
        socket_root = Path(sockets).resolve()
        log_root = Path(logs).resolve()
        os.chmod(socket_root, 0o700)
        os.chmod(log_root, 0o700)
        targets = LocalPreviewTargetRegistry()
        supervisor = RunnerPreviewProcessSupervisor(
            targets,
            socket_root,
            log_root,
            runner_id=route.runner_id,
            connection_generation=route.runner_connection_generation,
        )

        with pytest.raises(PreviewProcessSupervisorError) as failure:
            await supervisor.start(route, _spec(unhealthy=True))
        assert failure.value.code == "preview_supervisor_health_failed"
        assert await supervisor.snapshot(route.preview_id) is None
        assert targets.resolve(route.opaque_preview_key, _metadata(route)) is None
        assert not any(socket_root.iterdir())
        await supervisor.aclose()


@pytest.mark.skipif(sys.platform == "win32", reason="Preview supervision requires POSIX")
@pytest.mark.asyncio
async def test_supervisor_does_not_unlink_replaced_socket_path() -> None:
    route = _route(opaque_key="pvr_cleanup_replacement")
    with (
        tempfile.TemporaryDirectory(prefix="omnigent-preview-sockets-", dir="/tmp") as sockets,
        tempfile.TemporaryDirectory(prefix="omnigent-preview-logs-", dir="/tmp") as logs,
    ):
        socket_root = Path(sockets).resolve()
        log_root = Path(logs).resolve()
        os.chmod(socket_root, 0o700)
        os.chmod(log_root, 0o700)
        targets = LocalPreviewTargetRegistry()
        supervisor = RunnerPreviewProcessSupervisor(
            targets,
            socket_root,
            log_root,
            runner_id=route.runner_id,
            connection_generation=route.runner_connection_generation,
        )
        snapshot = await supervisor.start(route, _spec())

        snapshot.socket_path.unlink()
        snapshot.socket_path.write_text("replacement", encoding="utf-8")
        os.chmod(snapshot.socket_path, 0o600)
        exit_state = await supervisor.stop(route.preview_id)

        assert exit_state is not None
        assert exit_state.cleanup_error_code == "preview_supervisor_socket_replaced"
        assert snapshot.socket_path.read_text(encoding="utf-8") == "replacement"
        assert targets.resolve(route.opaque_preview_key, _metadata(route)) is None
        snapshot.socket_path.unlink()
        await supervisor.aclose()


def test_process_spec_rejects_shell_lookup_and_secret_shaped_environment() -> None:
    with pytest.raises(PreviewProcessSupervisorError) as relative:
        PreviewProcessSpec(argv=("python", "-m", "app"), working_directory=Path.cwd())
    assert relative.value.code == "preview_process_executable_invalid"

    with pytest.raises(PreviewProcessSupervisorError) as credential:
        PreviewProcessSpec(
            argv=(sys.executable, "-m", "app"),
            working_directory=Path.cwd().resolve(),
            environment=(("API_TOKEN", "not-logged"),),
        )
    assert credential.value.code == "preview_process_environment_invalid"


@pytest.mark.skipif(sys.platform == "win32", reason="Preview supervision requires POSIX")
@pytest.mark.asyncio
async def test_supervisor_rejects_route_for_another_runner_incarnation() -> None:
    route = _route(opaque_key="pvr_wrong_runner")
    with (
        tempfile.TemporaryDirectory(prefix="omnigent-preview-sockets-", dir="/tmp") as sockets,
        tempfile.TemporaryDirectory(prefix="omnigent-preview-logs-", dir="/tmp") as logs,
    ):
        socket_root = Path(sockets).resolve()
        log_root = Path(logs).resolve()
        os.chmod(socket_root, 0o700)
        os.chmod(log_root, 0o700)
        supervisor = RunnerPreviewProcessSupervisor(
            LocalPreviewTargetRegistry(),
            socket_root,
            log_root,
            runner_id=uuid4(),
            connection_generation=route.runner_connection_generation,
        )
        with pytest.raises(PreviewProcessSupervisorError) as mismatch:
            await supervisor.start(route, _spec())
        assert mismatch.value.code == "preview_supervisor_runner_binding_mismatch"
        assert not any(socket_root.iterdir())
        assert not any(log_root.iterdir())


@pytest.mark.skipif(sys.platform == "win32", reason="Preview supervision requires POSIX")
@pytest.mark.asyncio
async def test_supervisor_bounds_startup_and_kills_term_resistant_process() -> None:
    route = _route(opaque_key="pvr_start_timeout")
    with (
        tempfile.TemporaryDirectory(prefix="omnigent-preview-sockets-", dir="/tmp") as sockets,
        tempfile.TemporaryDirectory(prefix="omnigent-preview-logs-", dir="/tmp") as logs,
    ):
        socket_root = Path(sockets).resolve()
        log_root = Path(logs).resolve()
        os.chmod(socket_root, 0o700)
        os.chmod(log_root, 0o700)
        supervisor = RunnerPreviewProcessSupervisor(
            LocalPreviewTargetRegistry(),
            socket_root,
            log_root,
            runner_id=route.runner_id,
            connection_generation=route.runner_connection_generation,
        )
        with pytest.raises(PreviewProcessSupervisorError) as timeout:
            await supervisor.start(route, _spec(never_binds=True))
        assert timeout.value.code == "preview_supervisor_start_timeout"
        assert not any(socket_root.iterdir())

        second_route = replace(
            route,
            preview_id=uuid4(),
            opaque_preview_key="pvr_force_kill",
        )
        snapshot = await supervisor.start(second_route, _spec(ignore_term=True))
        exit_state = await supervisor.stop(second_route.preview_id)
        assert exit_state is not None
        assert exit_state.returncode == -signal.SIGKILL
        assert not snapshot.socket_path.exists()


@pytest.mark.skipif(
    sys.platform in {"win32", "emscripten"}, reason="Process-group test requires POSIX fork"
)
@pytest.mark.asyncio
async def test_supervisor_reaps_process_group_after_main_process_crash() -> None:
    route = _route(opaque_key="pvr_crash_with_child")
    with (
        tempfile.TemporaryDirectory(prefix="omnigent-preview-sockets-", dir="/tmp") as sockets,
        tempfile.TemporaryDirectory(prefix="omnigent-preview-logs-", dir="/tmp") as logs,
    ):
        socket_root = Path(sockets).resolve()
        log_root = Path(logs).resolve()
        os.chmod(socket_root, 0o700)
        os.chmod(log_root, 0o700)
        supervisor = RunnerPreviewProcessSupervisor(
            LocalPreviewTargetRegistry(),
            socket_root,
            log_root,
            runner_id=route.runner_id,
            connection_generation=route.runner_connection_generation,
        )
        snapshot = await supervisor.start(route, _spec(stubborn_child=True))
        os.kill(snapshot.pid, signal.SIGKILL)

        exit_state = await _wait_for_exit(supervisor, route.preview_id)
        assert exit_state.reason == "exited"
        assert exit_state.returncode == -signal.SIGKILL
        assert exit_state.cleanup_error_code is None
        with pytest.raises(ProcessLookupError):
            os.killpg(snapshot.pid, 0)
