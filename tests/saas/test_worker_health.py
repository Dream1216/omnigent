from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from uuid import UUID

import pytest

from saas.control_plane.outbox import DispatchResult
from saas.production.worker import (
    ProductionSchedulerWorker,
    ProductionWorkerAdapters,
    ProductionWorkerHealthError,
    ProductionWorkerHealthPolicy,
    ProductionWorkerHealthState,
    ProductionWorkerHealthStateWriter,
    assert_production_worker_health,
    load_production_worker_health_state,
)
from saas.scripts.check_worker_health import main

_START = 1_800_000_000_000_000_000


class _Ready:
    def assert_production_ready(self) -> None:
        pass


class _Recovery:
    def recover_expired_dispatches(
        self, *, max_fence_token: int = 3, limit: int = 100
    ) -> tuple[UUID, ...]:
        del max_fence_token, limit
        return ()


class _StopDispatcher:
    def __init__(self, stop: threading.Event, *, failure: Exception | None = None) -> None:
        self._stop = stop
        self._failure = failure

    def dispatch_once(self, *, batch_size: int = 100) -> DispatchResult:
        del batch_size
        self._stop.set()
        if self._failure is not None:
            raise self._failure
        return DispatchResult(claimed=0, published=0, failed=0, quarantined=0)


def _policy(path: Path) -> ProductionWorkerHealthPolicy:
    return ProductionWorkerHealthPolicy(
        state_path=path,
        readiness_max_age_seconds=60,
        liveness_max_age_seconds=120,
        max_consecutive_failures=3,
    )


def test_health_writer_is_exact_owner_only_canonical_and_probeable(tmp_path: Path) -> None:
    path = tmp_path / "worker-health.json"
    state = ProductionWorkerHealthState(
        startup_unix_ns=_START,
        last_loop_progress_unix_ns=_START + 2_000_000_000,
        last_full_successful_cycle_unix_ns=_START + 2_000_000_000,
        consecutive_failures=0,
        failure_codes=(),
    )

    ProductionWorkerHealthStateWriter(path).write(state)

    assert load_production_worker_health_state(path) == state
    assert path.stat().st_uid == os.geteuid()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == (
        json.dumps(state.document(), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    assert_production_worker_health(
        state,
        _policy(path),
        mode="startup",
        now_unix_ns=_START + 3_000_000_000,
    )
    assert_production_worker_health(
        state,
        _policy(path),
        mode="readiness",
        now_unix_ns=_START + 3_000_000_000,
    )
    assert_production_worker_health(
        state,
        _policy(path),
        mode="liveness",
        now_unix_ns=_START + 3_000_000_000,
    )


def test_readiness_fails_closed_but_liveness_only_requires_loop_progress(
    tmp_path: Path,
) -> None:
    path = tmp_path / "worker-health.json"
    no_success = ProductionWorkerHealthState(
        startup_unix_ns=_START,
        last_loop_progress_unix_ns=_START + 1,
        last_full_successful_cycle_unix_ns=None,
        consecutive_failures=1,
        failure_codes=("dispatch_failed",),
    )
    with pytest.raises(ProductionWorkerHealthError, match="successful cycle"):
        assert_production_worker_health(
            no_success,
            _policy(path),
            mode="startup",
            now_unix_ns=_START + 2,
        )

    state = ProductionWorkerHealthState(
        startup_unix_ns=_START,
        last_loop_progress_unix_ns=_START + 10_000_000_000,
        last_full_successful_cycle_unix_ns=_START + 1_000_000_000,
        consecutive_failures=3,
        failure_codes=("dispatch_failed",),
    )
    ProductionWorkerHealthStateWriter(path).write(state)

    assert_production_worker_health(
        state,
        _policy(path),
        mode="liveness",
        now_unix_ns=_START + 11_000_000_000,
    )
    with pytest.raises(ProductionWorkerHealthError, match="failure limit"):
        assert_production_worker_health(
            state,
            _policy(path),
            mode="readiness",
            now_unix_ns=_START + 11_000_000_000,
        )


def test_health_reader_rejects_links_modes_and_noncanonical_documents(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    state = ProductionWorkerHealthState(
        startup_unix_ns=_START,
        last_loop_progress_unix_ns=None,
        last_full_successful_cycle_unix_ns=None,
        consecutive_failures=0,
        failure_codes=(),
    )
    ProductionWorkerHealthStateWriter(real).write(state)
    link = tmp_path / "linked.json"
    link.symlink_to(real)

    with pytest.raises(ProductionWorkerHealthError, match="unavailable"):
        load_production_worker_health_state(link)
    real.chmod(0o640)
    with pytest.raises(ProductionWorkerHealthError, match="ownership"):
        load_production_worker_health_state(real)
    real.write_text(json.dumps(state.document(), indent=2), encoding="ascii")
    real.chmod(0o600)
    with pytest.raises(ProductionWorkerHealthError, match="canonical"):
        load_production_worker_health_state(real)


def test_health_boundary_rejects_writable_or_linked_parent_directory(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "worker-health.json"
    state = ProductionWorkerHealthState(
        startup_unix_ns=_START,
        last_loop_progress_unix_ns=None,
        last_full_successful_cycle_unix_ns=None,
        consecutive_failures=0,
        failure_codes=(),
    )
    writer = ProductionWorkerHealthStateWriter(path)
    writer.write(state)

    private.chmod(0o770)
    with pytest.raises(ProductionWorkerHealthError, match="directory is invalid"):
        writer.write(state)
    with pytest.raises(ProductionWorkerHealthError, match="directory is invalid"):
        load_production_worker_health_state(path)

    private.chmod(0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(private, target_is_directory=True)
    linked_path = linked / path.name
    with pytest.raises(ProductionWorkerHealthError, match="directory is unavailable"):
        ProductionWorkerHealthStateWriter(linked_path).write(state)
    with pytest.raises(ProductionWorkerHealthError, match="directory is unavailable"):
        load_production_worker_health_state(linked_path)


@pytest.mark.parametrize(
    ("failure", "expected_codes", "expected_failures", "successful"),
    [
        (None, (), 0, True),
        (RuntimeError("private database error"), ("dispatch_failed",), 1, False),
    ],
)
def test_worker_publishes_content_blind_cycle_health(
    tmp_path: Path,
    failure: Exception | None,
    expected_codes: tuple[str, ...],
    expected_failures: int,
    successful: bool,
) -> None:
    stop = threading.Event()
    path = tmp_path / "worker-health.json"
    times = iter((_START, _START + 1_000_000_000))
    worker = ProductionSchedulerWorker(
        _StopDispatcher(stop, failure=failure),
        _Recovery(),
        ProductionWorkerAdapters(runner=_Ready(), preview=_Ready()),
        idle_interval_seconds=0.01,
        error_backoff_seconds=0.01,
        max_error_backoff_seconds=0.01,
        recovery_interval_seconds=1,
        clock=lambda: 0.0,
        wall_clock_ns=lambda: next(times),
        health_writer=ProductionWorkerHealthStateWriter(path),
    )

    worker.run(stop)

    state = load_production_worker_health_state(path)
    assert state.failure_codes == expected_codes
    assert state.consecutive_failures == expected_failures
    assert (state.last_full_successful_cycle_unix_ns is not None) is successful
    assert b"private database error" not in path.read_bytes()


def test_health_cli_uses_only_probe_policy_and_returns_content_blind_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "worker-health.json"
    state = ProductionWorkerHealthState(
        startup_unix_ns=_START,
        last_loop_progress_unix_ns=_START + 1,
        last_full_successful_cycle_unix_ns=_START + 1,
        consecutive_failures=0,
        failure_codes=(),
    )
    ProductionWorkerHealthStateWriter(path).write(state)
    environ = {"OMNIGENT_SAAS_WORKER_HEALTH_STATE_FILE": str(path)}

    assert main(["--mode", "readiness"], environ=environ, now_unix_ns=_START + 2) == 0
    path.chmod(0o644)
    assert main(["--mode", "readiness"], environ=environ, now_unix_ns=_START + 2) == 1
    assert capsys.readouterr().err == "production worker health probe failed\n"
