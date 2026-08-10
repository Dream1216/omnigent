"""Runner-local lifecycle supervisor for one Preview process per route grant.

The control plane selects a :class:`PreviewProcessSpec`; Preview requests never
select an executable, working directory, environment variable, TCP address, or
Unix socket path.  The child receives only an exact server-built environment
and a route-derived private UDS path.  Registration happens after the socket is
pinned and a direct UDS health probe succeeds.  Revocation always precedes
termination, and cleanup never unlinks a replacement filesystem object.

This is a process-lifecycle adapter, not a complete production placement
system.  Dedicated uid/mount/cgroup containment, cross-host placement, mTLS,
certificate rotation, and replica reconciliation remain separate gates.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import signal
import stat
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import httpx

from saas.control_plane import PreviewRouteGrant
from saas.preview_tunnel import (
    LocalPreviewTargetRegistry,
    PreviewTargetBinding,
    PreviewTunnelAdapterError,
    UnixSocketIdentity,
    UnixSocketPreviewTarget,
)

_ENVIRONMENT_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_FORBIDDEN_ENVIRONMENT_FRAGMENT = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY|API_KEY|AUTH|COOKIE|SESSION)"
)
_RESERVED_ENVIRONMENT_NAMES = frozenset(
    {
        "OMNIGENT_PREVIEW_SOCKET_PATH",
        "OMNIGENT_PREVIEW_HEALTH_PATH",
    }
)
_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_BYTES = 16_384
_MAX_ENVIRONMENT_BYTES = 65_536


class PreviewProcessSupervisorError(RuntimeError):
    """Stable fail-closed error for a Runner-local Preview lifecycle."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PreviewProcessSpec:
    """Immutable server-owned process input; never deserialize from a request."""

    argv: tuple[str, ...]
    working_directory: Path
    environment: tuple[tuple[str, str], ...] = ()
    health_path: str = "/__omnigent_preview_health"
    startup_timeout_seconds: float = 15.0
    health_timeout_seconds: float = 2.0
    shutdown_timeout_seconds: float = 5.0
    request_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not self.argv or len(self.argv) > _MAX_ARGUMENTS:
            raise PreviewProcessSupervisorError(
                "preview_process_argv_invalid", "Preview process argv is invalid"
            )
        total_bytes = 0
        for argument in self.argv:
            if not isinstance(argument, str) or not argument or "\x00" in argument:
                raise PreviewProcessSupervisorError(
                    "preview_process_argv_invalid", "Preview process argv is invalid"
                )
            total_bytes += len(os.fsencode(argument))
        if total_bytes > _MAX_ARGUMENT_BYTES:
            raise PreviewProcessSupervisorError(
                "preview_process_argv_invalid", "Preview process argv is too large"
            )
        executable = Path(self.argv[0])
        if not executable.is_absolute():
            raise PreviewProcessSupervisorError(
                "preview_process_executable_invalid",
                "Preview process executable must be an absolute server-owned path",
            )
        if (
            not self.health_path.startswith("/")
            or "?" in self.health_path
            or "#" in self.health_path
            or len(self.health_path) > 512
        ):
            raise PreviewProcessSupervisorError(
                "preview_process_health_path_invalid", "Preview health path is invalid"
            )
        for value, label in (
            (self.startup_timeout_seconds, "startup"),
            (self.health_timeout_seconds, "health"),
            (self.shutdown_timeout_seconds, "shutdown"),
            (self.request_timeout_seconds, "request"),
        ):
            if value <= 0 or value > 300:
                raise PreviewProcessSupervisorError(
                    "preview_process_timeout_invalid",
                    f"Preview {label} timeout is invalid",
                )
        seen: set[str] = set()
        environment_bytes = 0
        for name, value in self.environment:
            if (
                not isinstance(name, str)
                or not _ENVIRONMENT_NAME.fullmatch(name)
                or name in seen
                or name in _RESERVED_ENVIRONMENT_NAMES
                or _FORBIDDEN_ENVIRONMENT_FRAGMENT.search(name)
                or not isinstance(value, str)
                or "\x00" in value
            ):
                raise PreviewProcessSupervisorError(
                    "preview_process_environment_invalid",
                    "Preview process environment is invalid or contains a secret-shaped name",
                )
            seen.add(name)
            environment_bytes += len(name.encode()) + len(value.encode()) + 2
        if environment_bytes > _MAX_ENVIRONMENT_BYTES:
            raise PreviewProcessSupervisorError(
                "preview_process_environment_invalid",
                "Preview process environment is too large",
            )


@dataclass(frozen=True, slots=True)
class PreviewProcessSnapshot:
    preview_id: UUID
    pid: int
    socket_path: Path
    socket_identity: UnixSocketIdentity
    log_path: Path
    started_at: datetime


@dataclass(frozen=True, slots=True)
class PreviewProcessExit:
    preview_id: UUID
    pid: int
    reason: str
    returncode: int | None
    stopped_at: datetime
    cleanup_error_code: str | None = None


@dataclass(slots=True)
class _RunningPreview:
    route: PreviewRouteGrant
    process: asyncio.subprocess.Process
    target: UnixSocketPreviewTarget
    binding: PreviewTargetBinding
    snapshot: PreviewProcessSnapshot
    shutdown_timeout_seconds: float
    watcher: asyncio.Task[None] | None = None


class RunnerPreviewProcessSupervisor:
    """Own multiple route-bound Preview children on one official Runner."""

    def __init__(
        self,
        targets: LocalPreviewTargetRegistry,
        socket_root: Path,
        log_root: Path,
        *,
        runner_id: UUID,
        connection_generation: int,
    ) -> None:
        if os.name != "posix":
            raise PreviewProcessSupervisorError(
                "preview_supervisor_unsupported", "Preview supervision requires POSIX"
            )
        self._targets = targets
        if connection_generation <= 0:
            raise PreviewProcessSupervisorError(
                "preview_supervisor_runner_binding_invalid",
                "Preview supervisor Runner generation must be positive",
            )
        self._runner_id = runner_id
        self._connection_generation = connection_generation
        self._socket_root = _require_private_directory(socket_root, "socket")
        self._log_root = _require_private_directory(log_root, "log")
        self._running: dict[UUID, _RunningPreview] = {}
        self._starting: set[UUID] = set()
        self._last_exit: dict[UUID, PreviewProcessExit] = {}
        self._lock = asyncio.Lock()

    async def start(
        self,
        route: PreviewRouteGrant,
        spec: PreviewProcessSpec,
    ) -> PreviewProcessSnapshot:
        """Start, pin, health-check, then publish one exact Preview target."""

        now = datetime.now(timezone.utc)
        if (
            route.runner_id != self._runner_id
            or route.runner_connection_generation != self._connection_generation
        ):
            raise PreviewProcessSupervisorError(
                "preview_supervisor_runner_binding_mismatch",
                "Preview route does not belong to this Runner incarnation",
            )
        if route.expires_at <= now:
            raise PreviewProcessSupervisorError(
                "preview_supervisor_route_expired", "Preview route already expired"
            )
        executable, working_directory = _validate_process_paths(spec)
        async with self._lock:
            if route.preview_id in self._running or route.preview_id in self._starting:
                raise PreviewProcessSupervisorError(
                    "preview_supervisor_already_started", "Preview process is already starting"
                )
            self._starting.add(route.preview_id)

        target: UnixSocketPreviewTarget | None = None
        process: asyncio.subprocess.Process | None = None
        binding: PreviewTargetBinding | None = None
        identity: UnixSocketIdentity | None = None
        log_path: Path | None = None
        try:
            target = UnixSocketPreviewTarget(
                route,
                self._socket_root,
                request_timeout_seconds=spec.request_timeout_seconds,
            )
            log_path, log_fd = _open_private_log(self._log_root, route.preview_id)
            environment = dict(spec.environment)
            environment["OMNIGENT_PREVIEW_SOCKET_PATH"] = str(target.socket_path)
            environment["OMNIGENT_PREVIEW_HEALTH_PATH"] = spec.health_path
            try:
                process = await asyncio.create_subprocess_exec(
                    str(executable),
                    *spec.argv[1:],
                    cwd=str(working_directory),
                    env=environment,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=log_fd,
                    stderr=asyncio.subprocess.STDOUT,
                    close_fds=True,
                    start_new_session=True,
                )
            finally:
                os.close(log_fd)

            identity = await _wait_for_private_socket(
                process,
                target.socket_path,
                route.expires_at,
                timeout_seconds=spec.startup_timeout_seconds,
            )
            # Some ASGI servers create the UDS and then apply their configured
            # mode after the listener is already visible.  Under load that late
            # chmod can race our first hardening pass.  A private, unpublished
            # health request is therefore only a server-startup barrier; after
            # it returns, revalidate and harden the exact socket before pinning.
            try:
                await _require_healthy(
                    target.socket_path,
                    spec.health_path,
                    timeout_seconds=spec.health_timeout_seconds,
                )
            except PreviewProcessSupervisorError:
                # Preserve an exact cleanup identity even when the unpublished
                # health check fails after a server-side late chmod.
                with contextlib.suppress(PreviewProcessSupervisorError):
                    identity = await _wait_for_private_socket(
                        process,
                        target.socket_path,
                        route.expires_at,
                        timeout_seconds=spec.startup_timeout_seconds,
                        expected_identity=identity,
                    )
                raise
            identity = await _wait_for_private_socket(
                process,
                target.socket_path,
                route.expires_at,
                timeout_seconds=spec.startup_timeout_seconds,
                expected_identity=identity,
            )
            if target.activate() != identity:
                raise PreviewProcessSupervisorError(
                    "preview_supervisor_socket_replaced",
                    "Preview socket identity changed during activation",
                )
            await _require_healthy(
                target.socket_path,
                spec.health_path,
                timeout_seconds=spec.health_timeout_seconds,
            )
            # The final health request must not have replaced or mutated the
            # pinned socket before the route becomes visible.
            if target.activate() != identity:
                raise PreviewProcessSupervisorError(
                    "preview_supervisor_socket_replaced",
                    "Preview socket identity changed during final health validation",
                )
            if process.returncode is not None:
                raise PreviewProcessSupervisorError(
                    "preview_supervisor_process_exited",
                    "Preview process exited before publication",
                )
            binding = self._targets.register(route, target)
            snapshot = PreviewProcessSnapshot(
                preview_id=route.preview_id,
                pid=process.pid,
                socket_path=target.socket_path,
                socket_identity=identity,
                log_path=log_path,
                started_at=datetime.now(timezone.utc),
            )
            running = _RunningPreview(
                route=route,
                process=process,
                target=target,
                binding=binding,
                snapshot=snapshot,
                shutdown_timeout_seconds=spec.shutdown_timeout_seconds,
            )
            async with self._lock:
                if process.returncode is not None:
                    raise PreviewProcessSupervisorError(
                        "preview_supervisor_process_exited",
                        "Preview process exited before publication",
                    )
                self._running[route.preview_id] = running
                running.watcher = asyncio.create_task(
                    self._watch(running),
                    name=f"preview-supervisor-{route.preview_id}",
                )
            return snapshot
        except PreviewTunnelAdapterError as exc:
            raise PreviewProcessSupervisorError(exc.code, str(exc)) from exc
        finally:
            async with self._lock:
                self._starting.discard(route.preview_id)
                published = route.preview_id in self._running
            if not published and target is not None:
                if binding is not None:
                    self._targets.revoke(binding)
                target.deactivate()
                process_cleanup_error: str | None = None
                if process is not None:
                    _, process_cleanup_error = await _terminate_process(
                        process, spec.shutdown_timeout_seconds
                    )
                await _cleanup_target(target, identity)
                if process_cleanup_error is not None:
                    raise PreviewProcessSupervisorError(
                        process_cleanup_error,
                        "Preview process group could not be fully cleaned up",
                    )

    async def stop(self, preview_id: UUID) -> PreviewProcessExit | None:
        """Revoke first, then terminate the owned process group and clean UDS."""

        running = await self._detach(preview_id)
        if running is None:
            return None
        watcher = running.watcher
        if watcher is not None and watcher is not asyncio.current_task():
            watcher.cancel()
        returncode, process_cleanup_error = await _terminate_process(
            running.process, running.shutdown_timeout_seconds
        )
        socket_cleanup_error = await _cleanup_target(
            running.target, running.snapshot.socket_identity
        )
        exit_state = PreviewProcessExit(
            preview_id=preview_id,
            pid=running.snapshot.pid,
            reason="stopped",
            returncode=returncode,
            stopped_at=datetime.now(timezone.utc),
            cleanup_error_code=process_cleanup_error or socket_cleanup_error,
        )
        async with self._lock:
            self._last_exit[preview_id] = exit_state
        return exit_state

    async def snapshot(self, preview_id: UUID) -> PreviewProcessSnapshot | None:
        async with self._lock:
            running = self._running.get(preview_id)
            return None if running is None else running.snapshot

    async def last_exit(self, preview_id: UUID) -> PreviewProcessExit | None:
        async with self._lock:
            return self._last_exit.get(preview_id)

    async def aclose(self) -> None:
        async with self._lock:
            preview_ids = tuple(self._running)
        for preview_id in preview_ids:
            await self.stop(preview_id)

    async def _detach(self, preview_id: UUID) -> _RunningPreview | None:
        async with self._lock:
            running = self._running.pop(preview_id, None)
            if running is not None:
                # Stop accepting new tunnel requests before process signaling.
                self._targets.revoke(running.binding)
                running.target.deactivate()
            return running

    async def _watch(self, running: _RunningPreview) -> None:
        expires_in = max(
            0.0,
            (running.route.expires_at - datetime.now(timezone.utc)).total_seconds(),
        )
        reason = "exited"
        try:
            await asyncio.wait_for(asyncio.shield(running.process.wait()), expires_in)
        except TimeoutError:
            reason = "expired"
        except asyncio.CancelledError:
            return

        detached = await self._detach(running.route.preview_id)
        if detached is not running:
            return
        if reason == "expired":
            returncode, process_cleanup_error = await _terminate_process(
                running.process, running.shutdown_timeout_seconds
            )
        else:
            returncode, process_cleanup_error = await _terminate_process(
                running.process, running.shutdown_timeout_seconds
            )
        socket_cleanup_error = await _cleanup_target(
            running.target, running.snapshot.socket_identity
        )
        exit_state = PreviewProcessExit(
            preview_id=running.route.preview_id,
            pid=running.snapshot.pid,
            reason=reason,
            returncode=returncode,
            stopped_at=datetime.now(timezone.utc),
            cleanup_error_code=process_cleanup_error or socket_cleanup_error,
        )
        async with self._lock:
            self._last_exit[running.route.preview_id] = exit_state


def _require_private_directory(path: Path, label: str) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        raise PreviewProcessSupervisorError(
            f"preview_supervisor_{label}_root_invalid",
            f"Preview {label} root must be absolute",
        )
    try:
        resolved = raw.resolve(strict=True)
        path_stat = os.lstat(resolved)
    except OSError as exc:
        raise PreviewProcessSupervisorError(
            f"preview_supervisor_{label}_root_invalid",
            f"Preview {label} root is unavailable",
        ) from exc
    if (
        not stat.S_ISDIR(path_stat.st_mode)
        or path_stat.st_uid != os.geteuid()
        or stat.S_IMODE(path_stat.st_mode) & 0o077
    ):
        raise PreviewProcessSupervisorError(
            f"preview_supervisor_{label}_root_invalid",
            f"Preview {label} root must be a private Runner-owned directory",
        )
    return resolved


def _validate_process_paths(spec: PreviewProcessSpec) -> tuple[Path, Path]:
    try:
        # Validate the final target but execute the original absolute path.
        # Resolving a virtualenv/uv Python symlink changes ``sys.prefix`` and
        # silently drops the environment's installed dependencies.
        executable = Path(spec.argv[0])
        executable_stat = os.stat(executable.resolve(strict=True))
        working_directory = spec.working_directory.resolve(strict=True)
        working_stat = os.lstat(working_directory)
    except OSError as exc:
        raise PreviewProcessSupervisorError(
            "preview_process_path_invalid", "Preview process path is unavailable"
        ) from exc
    if not stat.S_ISREG(executable_stat.st_mode) or not os.access(executable, os.X_OK):
        raise PreviewProcessSupervisorError(
            "preview_process_executable_invalid", "Preview process executable is invalid"
        )
    if (
        not spec.working_directory.is_absolute()
        or not stat.S_ISDIR(working_stat.st_mode)
        or working_stat.st_uid != os.geteuid()
        or stat.S_IMODE(working_stat.st_mode) & 0o022
    ):
        raise PreviewProcessSupervisorError(
            "preview_process_working_directory_invalid",
            "Preview working directory must be an absolute, non-writable Runner-owned directory",
        )
    return executable, working_directory


def _open_private_log(log_root: Path, preview_id: UUID) -> tuple[Path, int]:
    filename = f"preview-{preview_id}-{uuid.uuid4().hex}.log"
    path = log_root / filename
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd: int | None = None
    fd: int | None = None
    try:
        path_stat = os.lstat(log_root)
        root_fd = os.open(
            log_root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_root_stat = os.fstat(root_fd)
        if (path_stat.st_dev, path_stat.st_ino, path_stat.st_uid) != (
            opened_root_stat.st_dev,
            opened_root_stat.st_ino,
            opened_root_stat.st_uid,
        ) or stat.S_IMODE(opened_root_stat.st_mode) & 0o077:
            raise OSError("Preview log root identity changed")
        fd = os.open(filename, flags, 0o600, dir_fd=root_fd)
        opened = os.fstat(fd)
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        raise PreviewProcessSupervisorError(
            "preview_supervisor_log_unavailable", "Preview process log is unavailable"
        ) from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)
    assert fd is not None
    if not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600:
        os.close(fd)
        raise PreviewProcessSupervisorError(
            "preview_supervisor_log_invalid", "Preview process log is not private"
        )
    return path, fd


async def _wait_for_private_socket(
    process: asyncio.subprocess.Process,
    socket_path: Path,
    expires_at: datetime,
    *,
    timeout_seconds: float,
    expected_identity: UnixSocketIdentity | None = None,
) -> UnixSocketIdentity:
    deadline = min(
        time.monotonic() + timeout_seconds,
        time.monotonic() + max(0.0, (expires_at - datetime.now(timezone.utc)).total_seconds()),
    )
    while time.monotonic() < deadline:
        if os.path.lexists(socket_path):
            try:
                socket_stat = os.lstat(socket_path)
            except OSError:
                await asyncio.sleep(0.01)
                continue
            if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != os.geteuid():
                raise PreviewProcessSupervisorError(
                    "preview_supervisor_socket_invalid",
                    "Preview process created an invalid socket object",
                )
            if expected_identity is not None and (
                socket_stat.st_dev,
                socket_stat.st_ino,
                socket_stat.st_uid,
            ) != (
                expected_identity.device,
                expected_identity.inode,
                expected_identity.owner_uid,
            ):
                raise PreviewProcessSupervisorError(
                    "preview_supervisor_socket_replaced",
                    "Preview socket identity changed during startup",
                )
            # Uvicorn binds with 0666 after umask on some versions. The
            # supervisor owns the private parent and hardens before publish.
            os.chmod(socket_path, 0o600, follow_symlinks=False)
            await asyncio.sleep(0.02)
            try:
                hardened = os.lstat(socket_path)
            except OSError:
                continue
            if (
                not stat.S_ISSOCK(hardened.st_mode)
                or hardened.st_uid != os.geteuid()
                or (hardened.st_dev, hardened.st_ino, hardened.st_uid)
                != (socket_stat.st_dev, socket_stat.st_ino, socket_stat.st_uid)
            ):
                raise PreviewProcessSupervisorError(
                    "preview_supervisor_socket_replaced",
                    "Preview socket identity changed during hardening",
                )
            if stat.S_IMODE(hardened.st_mode) & 0o077:
                # A server-side post-bind chmod raced this pass. Retry against
                # the same inode until the bounded startup deadline.
                continue
            return UnixSocketIdentity(
                device=hardened.st_dev,
                inode=hardened.st_ino,
                owner_uid=hardened.st_uid,
                ctime_ns=hardened.st_ctime_ns,
            )
        if process.returncode is not None:
            raise PreviewProcessSupervisorError(
                "preview_supervisor_process_exited",
                "Preview process exited before binding its socket",
            )
        await asyncio.sleep(0.01)
    raise PreviewProcessSupervisorError(
        "preview_supervisor_start_timeout", "Preview process did not become ready in time"
    )


async def _require_healthy(
    socket_path: Path,
    health_path: str,
    *,
    timeout_seconds: float,
) -> None:
    transport = httpx.AsyncHTTPTransport(uds=str(socket_path), trust_env=False, retries=0)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(f"http://preview.invalid{health_path}")
            await response.aread()
    except (httpx.HTTPError, OSError) as exc:
        raise PreviewProcessSupervisorError(
            "preview_supervisor_health_failed", "Preview process health probe failed"
        ) from exc
    if response.status_code != 200:
        raise PreviewProcessSupervisorError(
            "preview_supervisor_health_failed", "Preview process health probe failed"
        )


async def _terminate_process(
    process: asyncio.subprocess.Process, timeout_seconds: float
) -> tuple[int | None, str | None]:
    """Terminate the complete session process group, including survivors.

    A daemonized child can outlive an already reaped group leader. Therefore
    ``process.returncode`` is not sufficient lifecycle evidence: signal and
    observe the server-created process group even when the main process has
    already crashed.
    """

    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout_seconds
    if process.returncode is None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                asyncio.shield(process.wait()), max(0.01, deadline - time.monotonic())
            )
    while _process_group_exists(process.pid) and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    if _process_group_exists(process.pid):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        kill_deadline = time.monotonic() + min(max(timeout_seconds, 0.5), 5.0)
        if process.returncode is None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(process.wait()),
                    max(0.01, kill_deadline - time.monotonic()),
                )
        while _process_group_exists(process.pid) and time.monotonic() < kill_deadline:
            await asyncio.sleep(0.02)
    cleanup_error = (
        "preview_supervisor_process_group_cleanup_failed"
        if _process_group_exists(process.pid)
        else None
    )
    return process.returncode, cleanup_error


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    else:
        if sys.platform == "linux":
            live_members = _linux_process_group_has_live_members(process_group_id)
            if live_members is not None:
                return live_members
        return True


def _linux_process_group_has_live_members(
    process_group_id: int,
    proc_root: Path = Path("/proc"),
) -> bool | None:
    """Return whether a Linux process group has executable members.

    ``killpg(..., 0)`` also succeeds while a killed orphan is waiting to be
    reaped. A zombie cannot execute or retain Preview resources, so it must not
    turn successful SIGKILL cleanup into a false failure. Unknown procfs state
    remains fail-closed by returning ``None``.
    """

    try:
        entries = tuple(proc_root.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            encoded_stat = (entry / "stat").read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        command_end = encoded_stat.rfind(")")
        if command_end < 0:
            continue
        fields = encoded_stat[command_end + 1 :].split()
        if len(fields) < 3:
            continue
        try:
            member_group_id = int(fields[2])
        except ValueError:
            continue
        if member_group_id != process_group_id:
            continue
        if fields[0] not in {"X", "Z"}:
            return True
    return False


async def _cleanup_target(
    target: UnixSocketPreviewTarget,
    expected_identity: UnixSocketIdentity | None,
) -> str | None:
    cleanup_error: str | None = None
    try:
        if os.path.lexists(target.socket_path):
            socket_stat = os.lstat(target.socket_path)
            current = UnixSocketIdentity(
                device=socket_stat.st_dev,
                inode=socket_stat.st_ino,
                owner_uid=socket_stat.st_uid,
                ctime_ns=socket_stat.st_ctime_ns,
            )
            if (
                expected_identity is None
                or not stat.S_ISSOCK(socket_stat.st_mode)
                or current != expected_identity
            ):
                cleanup_error = "preview_supervisor_socket_replaced"
            else:
                os.unlink(target.socket_path)
    except OSError:
        cleanup_error = "preview_supervisor_socket_cleanup_failed"
    finally:
        await target.aclose()
    return cleanup_error


__all__ = [
    "PreviewProcessExit",
    "PreviewProcessSnapshot",
    "PreviewProcessSpec",
    "PreviewProcessSupervisorError",
    "RunnerPreviewProcessSupervisor",
]
