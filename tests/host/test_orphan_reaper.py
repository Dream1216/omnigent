"""Child-process ownership and runner reporting during orphan cleanup."""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from omnigent.host.connect import HostProcess, _RunnerHandle
from omnigent.host.identity import HostIdentity
from omnigent.host.runner_zygote import ZygoteManager, ZygoteRunnerProc

pytestmark = pytest.mark.posix_only


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> HostProcess:
    monkeypatch.setenv("OMNIGENT_RUNNER_ZYGOTE", "0")
    monkeypatch.setattr("omnigent.host.connect._RUNNER_WATCH_INTERVAL_S", 0.01)
    return HostProcess(
        identity=HostIdentity(host_id="host_reaper_test", name="reaper-test"),
        server_url="http://localhost:8000",
        interactive_shells=["bash"],
    )


@pytest.fixture
def zombie_child() -> Iterator[Callable[[], int]]:
    """Create only our own direct children, and collect them even on failure."""
    children: list[int] = []

    def spawn() -> int:
        pid = os.posix_spawn(
            sys.executable,
            [sys.executable, "-c", "import os; os._exit(0)"],
            os.environ,
        )
        children.append(pid)
        return pid

    try:
        yield spawn
    finally:
        for pid in children:
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)


@contextlib.contextmanager
def _exited_process(exit_code: int) -> Iterator[subprocess.Popen[bytes]]:
    """Leave an exited child waitable until its real owner collects its status."""
    proc = subprocess.Popen(
        [sys.executable, "-c", f"import os; os._exit({exit_code})"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.read() == b""
        if hasattr(os, "waitid"):
            deadline = time.monotonic() + 5.0
            while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                assert time.monotonic() < deadline, "child did not exit"
                time.sleep(0.01)
        yield proc
    finally:
        proc.wait(timeout=5.0)
        if proc.stdout is not None:
            proc.stdout.close()


def _reap(host: HostProcess, expected: int, child_pids: list[int]) -> None:
    deadline = time.monotonic() + 2.0
    reaped = 0
    while reaped < expected and time.monotonic() < deadline:
        reaped += host._reap_orphans_once(child_pids=child_pids)
        if reaped < expected:
            time.sleep(0.01)
    assert reaped == expected


def _assert_reaped(pid: int) -> None:
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_child_discovery_preserves_exit_status(host: HostProcess) -> None:
    with _exited_process(42) as proc:
        assert proc.pid in host._orphan_child_pids()

        assert proc.returncode is None
        assert proc.wait(timeout=5.0) == 42


@pytest.mark.asyncio
@pytest.mark.parametrize("exit_code", [0, 42])
async def test_watcher_releases_exited_runner_and_keeps_crash_report(
    host: HostProcess, tmp_path: Path, exit_code: int
) -> None:
    with _exited_process(exit_code) as proc:
        host._runners["runner_exited"] = _RunnerHandle(proc=proc, log_path=tmp_path / "runner.log")

        await asyncio.wait_for(host._watch_runner("runner_exited"), timeout=5.0)

        assert "runner_exited" not in host._runners
        assert proc.pid not in host._tracked_runner_pids()
        assert proc.returncode == exit_code
        if exit_code:
            assert set(host._unreported_exits) == {"runner_exited"}
            assert "code 42" in host._unreported_exits["runner_exited"]
        else:
            assert host._unreported_exits == {}


def test_completed_runner_handle_does_not_claim_reused_pid(
    host: HostProcess,
    tmp_path: Path,
    zombie_child: Callable[[], int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _exited_process(0) as proc:
        assert proc.wait(timeout=5.0) == 0
        reused_pid = zombie_child()
        monkeypatch.setattr(proc, "pid", reused_pid)
        host._runners["runner_completed"] = _RunnerHandle(
            proc=proc, log_path=tmp_path / "runner.log"
        )
        behind = zombie_child()

        _reap(host, expected=2, child_pids=[reused_pid, behind])

        _assert_reaped(reused_pid)
        _assert_reaped(behind)
        assert proc.returncode == 0


def test_exited_runner_without_watcher_does_not_block_orphans(
    host: HostProcess, tmp_path: Path, zombie_child: Callable[[], int]
) -> None:
    with _exited_process(42) as proc:
        host._runners["runner_unwatched"] = _RunnerHandle(
            proc=proc, log_path=tmp_path / "runner.log"
        )
        assert proc.returncode is None
        assert not host._watcher_tasks
        orphan = zombie_child()

        _reap(host, expected=1, child_pids=[proc.pid, orphan])

        _assert_reaped(orphan)
        assert proc.poll() == 42


def test_exited_zygote_does_not_block_orphans_or_lose_exit_status(
    host: HostProcess, zombie_child: Callable[[], int]
) -> None:
    with _exited_process(43) as proc:
        manager = ZygoteManager()
        manager._proc = proc
        host._zygote = manager
        orphan = zombie_child()

        _reap(host, expected=1, child_pids=[proc.pid, orphan])

        _assert_reaped(orphan)
        assert proc.poll() == 43
        assert not manager.is_running()


def test_busy_runner_owner_does_not_block_other_ready_children(
    host: HostProcess, tmp_path: Path, zombie_child: Callable[[], int]
) -> None:
    with _exited_process(42) as proc:
        host._runners["runner_busy"] = _RunnerHandle(proc=proc, log_path=tmp_path / "runner.log")
        orphan = zombie_child()

        with proc._waitpid_lock:  # type: ignore[attr-defined]
            _reap(host, expected=1, child_pids=[proc.pid, orphan])
            assert proc.returncode is None

        _assert_reaped(orphan)
        assert proc.poll() == 42


def test_zygote_runner_owner_needs_no_ipc_to_reap_other_children(
    host: HostProcess,
    tmp_path: Path,
    zombie_child: Callable[[], int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned_pid = zombie_child()
    orphan = zombie_child()
    manager = ZygoteManager()

    def unexpected_poll(pid: int) -> int | None:
        pytest.fail("orphan cleanup must not make a blocking zygote control request")

    monkeypatch.setattr(manager, "poll", unexpected_poll)
    proc = ZygoteRunnerProc(owned_pid, manager)
    host._runners["runner_zygote"] = _RunnerHandle(proc=proc, log_path=tmp_path / "runner.log")

    _reap(host, expected=1, child_pids=[owned_pid, orphan])

    _assert_reaped(orphan)
    assert proc.returncode is None
    assert os.waitpid(owned_pid, 0) == (owned_pid, 0)


def test_vanished_first_child_does_not_block_later_orphan(
    host: HostProcess, zombie_child: Callable[[], int]
) -> None:
    with _exited_process(42) as proc:
        orphan = zombie_child()
        snapshot = [proc.pid, orphan]
        assert proc.wait(timeout=5.0) == 42

        _reap(host, expected=1, child_pids=snapshot)

        _assert_reaped(orphan)
