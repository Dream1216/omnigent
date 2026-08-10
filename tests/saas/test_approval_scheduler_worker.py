from __future__ import annotations

import base64
import threading
from datetime import datetime

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.approval_scheduler_worker import (
    ApprovalSchedulerWorker,
    build_approval_scheduler,
    load_approval_scheduler_source_factory,
)
from saas.control_plane.approval_scheduler import ApprovalSchedulerRunResult
from saas.control_plane.db_models import SaasBase


class StopAfterScheduler:
    def __init__(
        self,
        stop: threading.Event,
        result: ApprovalSchedulerRunResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.stop = stop
        self.result = result
        self.error = error
        self.limits: list[int] = []

    def run_once(
        self, *, now: datetime | None = None, limit: int = 100
    ) -> ApprovalSchedulerRunResult:
        del now
        self.limits.append(limit)
        self.stop.set()
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def test_scheduler_worker_runs_one_bounded_cycle_and_reports_stats() -> None:
    stop = threading.Event()
    scheduler = StopAfterScheduler(
        stop,
        ApprovalSchedulerRunResult(
            reconciled_pending=2,
            reconciled_terminal=1,
            reminded=3,
            escalated=4,
            expired=5,
            failed=6,
        ),
    )
    worker = ApprovalSchedulerWorker(
        scheduler,  # type: ignore[arg-type]
        interval=0.001,
        error_backoff=0.001,
        max_error_backoff=0.002,
        limit=37,
    )

    stats = worker.run(stop)

    assert scheduler.limits == [37]
    assert stats.cycles == 1
    assert stats.reconciled_pending == 2
    assert stats.reconciled_terminal == 1
    assert stats.reminded == 3
    assert stats.escalated == 4
    assert stats.expired == 5
    assert stats.item_failures == 6
    assert stats.infrastructure_failures == 0


@pytest.mark.parametrize(
    "value",
    ("", "missing-separator", "bad-module!:factory", "module:bad-name!"),
)
def test_source_factory_path_is_fail_closed(value: str) -> None:
    with pytest.raises(RuntimeError):
        load_approval_scheduler_source_factory(value)


def test_built_in_production_source_factory_is_loadable() -> None:
    factory = load_approval_scheduler_source_factory(
        "saas.control_plane.approval_source_adapters:production_approval_scheduler_source_factory"
    )
    assert callable(factory)


def test_scheduler_build_rejects_incomplete_source_registry() -> None:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)

    with pytest.raises(RuntimeError, match="source registry is incomplete"):
        build_approval_scheduler(
            sessions=sessions,
            source_sessions={
                "enterprise": sessions,
                "privacy": sessions,
                "audit": sessions,
                "support.customer": sessions,
                "support.staff": sessions,
            },
            source_factory=lambda context: {},
            configuration={
                "hmac_key_id": "scheduler-key",
                "hmac_secret_b64": base64.b64encode(b"s" * 32).decode(),
            },
        )
