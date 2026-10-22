from __future__ import annotations

from contextlib import contextmanager
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from omnigent.server.schemas import SessionEventInput
from saas.compatibility import bind_runtime_context
from saas.control_plane import RuntimePartitionRecord, RuntimeResourceBindingRecord
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.scheduling_models import CapabilityTokenRecord, RunDispatchRecord
from tests.saas.test_interactive_execution_http import _message, _queued_worker, _scheduling
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@contextmanager
def _worker_logins(fixture):
    roles, engines, factories = [], [], {}
    try:
        with fixture.engine.begin() as connection:
            for service in ("executor", "dispatcher"):
                role = f"interactive_{service}_{uuid4().hex[:16]}"
                password = "isolated-interactive-worker-only"
                connection.exec_driver_sql(
                    f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER "
                    "NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT"
                )
                roles.append(role)
                connection.exec_driver_sql(
                    f"GRANT saas_{service} TO {role} WITH INHERIT TRUE, SET FALSE"
                )
                connection.exec_driver_sql(
                    f'GRANT CONNECT ON DATABASE "{fixture.engine.url.database}" TO {role}'
                )
                engine = sa.create_engine(fixture.engine.url.set(username=role, password=password))
                engines.append(engine)
                factories[service] = sessionmaker(engine, expire_on_commit=False)
        for engine in engines:
            with engine.connect() as connection:
                assert connection.exec_driver_sql(
                    "SELECT current_user=session_user,rolsuper,rolbypassrls "
                    "FROM pg_roles WHERE rolname=current_user"
                ).one() == (True, False, False)
                assert not connection.exec_driver_sql(
                    "SELECT has_table_privilege(current_user,"
                    "'saas_runtime_resource_bindings','INSERT')"
                ).scalar_one()
        yield factories
    finally:
        for engine in engines:
            engine.dispose()
        with fixture.engine.begin() as connection:
            for role in reversed(roles):
                connection.exec_driver_sql(f"DROP OWNED BY {role}")
                connection.exec_driver_sql(f"DROP ROLE {role}")


@pytest.mark.parametrize("moved", [False, True])
def test_real_app_and_separate_worker_logins_route_or_reject_the_frozen_input(
    interactive_postgresql, moved
):
    fixture = interactive_postgresql
    f, runtime = fixture.base, fixture.runtime
    _scheduling(f.factory, runtime, runtime.project_id)
    with bind_runtime_context(runtime):
        admitted = fixture.service.dispatch(
            runtime,
            fixture.conversation,
            SessionEventInput.model_validate(_message()),
            created_by=runtime.runtime_user_key,
        )
    if moved:
        with f.factory.begin() as db:
            db.execute(sa.update(RuntimePartitionRecord).values(placement_generation=3))
            db.execute(sa.update(RuntimeResourceBindingRecord).values(partition_generation=3))
    with _worker_logins(f) as factories:
        worker = _queued_worker(factories["dispatcher"], factories["executor"])
        result = worker.dispatch_once()
        if moved:
            assert result.failed == result.quarantined == 1 and result.published == 0
        else:
            assert (result.claimed, result.published, result.failed) == (1, 1, 0)
            assert worker.dispatch_once().claimed == 0
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunDispatchRecord)) == (not moved)
        if not moved:
            dispatch = db.scalars(sa.select(RunDispatchRecord)).one()
            assert "runtime.interactive.v1" in dispatch.required_capabilities
        assert db.scalar(sa.select(sa.func.count()).select_from(CapabilityTokenRecord)) == 0
        run = db.scalars(sa.select(RunRecord)).one()
        assert str(run.id) == admitted["run_id"]
        assert run.status == "queued" and run.lease_token is None and run.fence_token == 0
