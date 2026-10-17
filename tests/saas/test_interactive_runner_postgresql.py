from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from types import SimpleNamespace

import pytest
import sqlalchemy as sa

from omnigent.server.schemas import SessionEventInput
from saas.compatibility import bind_runtime_context
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.runner_execution_spec import production_run_execution_spec
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.scheduling_models import RunnerPoolRecord, TenantQueueShareRecord
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_http import _message, _queued_worker, _scheduling
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_interactive_runner_lease import _claim, _register
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@pytest.mark.parametrize("generic_recovery", [False, True])
def test_actual_executor_logins_claim_one_session_without_replaying_expired_work(
    interactive_postgresql,
    generic_recovery,
):
    fixture = interactive_postgresql
    f, runtime = fixture.base, fixture.runtime
    _, pool = _scheduling(f.factory, runtime, runtime.project_id)
    with bind_runtime_context(runtime):
        for stable_id in ("a" * 32, "b" * 32):
            fixture.service.dispatch(
                runtime,
                fixture.conversation,
                SessionEventInput.model_validate(_message(stable_id=stable_id)),
                created_by=runtime.runtime_user_key,
            )
    with _worker_logins(f) as factories:
        assert (
            _queued_worker(factories["dispatcher"], factories["executor"])
            .dispatch_once()
            .published
            == 2
        )
        control = SchedulingControlPlane(factories["executor"])
        with f.factory() as db:
            pool_row = db.get(RunnerPoolRecord, pool)
            assert pool_row.capacity_slots == 2
            share = db.scalar(
                sa.select(TenantQueueShareRecord).where(
                    TenantQueueShareRecord.tenant_id == runtime.tenant_id,
                    TenantQueueShareRecord.pool_id == pool,
                )
            )
            assert share.max_concurrent == 2
            domain, schema = pool_row.failure_domain, pool_row.schema_revision
        scope = SimpleNamespace(factory=f.factory, runtime=runtime)
        connections = [
            _register(scope, control, pool, domain, schema, key=f"isolated-controller-{index}")
            for index in range(2)
        ]
        start = Barrier(2)
        now = datetime.now(timezone.utc)

        def claim(connection):
            start.wait(timeout=10)
            return _claim(control, connection, now=now)

        with ThreadPoolExecutor(max_workers=2) as threads:
            claimed = list(threads.map(claim, connections))
        leases = [lease for lease in claimed if lease is not None]
        assert len(leases) == 1
        lease = leases[0]
        assert lease.execution_envelope is not None
        assert lease.execution_envelope.change_set_id is None
        assert lease.execution_envelope.launch_argv == ()
        with f.factory() as db:
            run = db.get(RunRecord, lease.run_id)
            assert run.input["execution"]["runtime_session_id"] == fixture.conversation.id
            assert (
                lease.execution_envelope.execution_spec_hash
                == production_run_execution_spec(run.input).spec_hash
            )
        later = now + timedelta(seconds=6)
        if generic_recovery:
            recovered_runs = ExecutionControlPlane(factories["executor"]).recover_expired_runs(
                now=later
            )
            assert len(recovered_runs) == 1 and recovered_runs[0].status == "orphaned"
        recovered = control.recover_expired_dispatches(now=later)
        assert len(recovered) == 1
        for connection in connections:
            assert _claim(control, connection, now=later) is None
        with f.factory() as db:
            statuses = sorted(db.scalars(sa.select(RunRecord.status)))
            assert statuses == ["orphaned", "queued"]
        # The generic recovery path cannot resurrect the already orphaned Run.
        assert ExecutionControlPlane(factories["executor"]).recover_expired_runs(now=later) == ()
