from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from omnigent.server.schemas import SessionEventInput
from saas.compatibility import bind_runtime_context
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.production.interactive_model_channel import ModelChannelScope
from saas.production.runner_control import (
    ProductionRunnerMachineAuthority,
    RunnerControlClientLease,
    RunnerControlError,
)
from saas.production.runner_executor import _runner_agent_database_login
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_http import _message, _queued_worker, _scheduling
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_interactive_runner_lease import _register
from tests.saas.test_interactive_runtime import _runtime_authority
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@contextmanager
def _machine_login(f, runner_id, generation):
    login = _runner_agent_database_login(runner_id, generation)
    password = "isolated-runtime-controller-only"
    engine = None
    with f.engine.begin() as connection:
        connection.exec_driver_sql(
            f"CREATE ROLE {login} LOGIN PASSWORD '{password}' NOSUPERUSER "
            "NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT"
        )
        connection.exec_driver_sql(
            f"GRANT saas_runner_agent TO {login} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
        )
        connection.exec_driver_sql(
            f'GRANT CONNECT ON DATABASE "{f.engine.url.database}" TO {login}'
        )
    try:
        engine = sa.create_engine(f.engine.url.set(username=login, password=password))
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT current_user=session_user,rolsuper,rolbypassrls "
                "FROM pg_roles WHERE rolname=current_user"
            ).one() == (True, False, False)
            assert not connection.exec_driver_sql(
                "SELECT has_table_privilege(current_user,'saas_runs','UPDATE')"
            ).scalar_one()
            assert not connection.exec_driver_sql(
                "SELECT has_table_privilege(current_user,'saas_customer_ledger_entries','INSERT')"
            ).scalar_one()
        yield sessionmaker(engine, expire_on_commit=False)
    finally:
        if engine is not None:
            engine.dispose()
        with f.engine.begin() as connection:
            connection.exec_driver_sql(f"DROP OWNED BY {login}")
            connection.exec_driver_sql(f"DROP ROLE {login}")


def test_runtime_reads_only_its_real_leased_run_then_uses_separate_app_authority(
    interactive_postgresql,
):
    fixture = interactive_postgresql
    f, runtime = fixture.base, fixture.runtime
    _, pool = _scheduling(f.factory, runtime, runtime.project_id)
    with bind_runtime_context(runtime):
        fixture.service.dispatch(
            runtime,
            fixture.conversation,
            SessionEventInput.model_validate(_message()),
            created_by=runtime.runtime_user_key,
        )
    with _worker_logins(f) as workers:
        assert (
            _queued_worker(workers["dispatcher"], workers["executor"]).dispatch_once().published
            == 1
        )
        scheduling = SchedulingControlPlane(workers["executor"])
        with f.factory() as db:
            from saas.control_plane.scheduling_models import RunnerPoolRecord

            pool_row = db.get(RunnerPoolRecord, pool)
            domain, schema = pool_row.failure_domain, pool_row.schema_revision
        scope = SimpleNamespace(factory=f.factory, runtime=runtime)
        connection = _register(scope, scheduling, pool, domain, schema, key="runtime-reader")
        control = ProductionRunnerMachineAuthority(
            scheduling,
            ExecutionControlPlane(workers["executor"]),
            product_revision="c" * 40,
            image_digest="sha256:" + "a" * 64,
        )
        credentials = {
            "runner_id": connection.runner_id,
            "connection_generation": connection.connection_generation,
            "connection_token": connection.connection_token,
        }
        claim = control.claim_run(**credentials)
        assert claim is not None
        for status in ("starting", "running"):
            control.transition_run(
                **credentials,
                run_id=claim.run_id,
                lease_token=claim.lease_token,
                fence_token=claim.fence_token,
                capability_token=claim.capability_token,
                target_status=status,
            )
        lease = RunnerControlClientLease(
            **{
                field.name: getattr(claim, field.name)
                for field in fields(RunnerControlClientLease)
            }
        )
        scope.delegate = scope.permissions = None
        with _machine_login(f, connection.runner_id, connection.connection_generation) as reader:
            authority = _runtime_authority(
                scope, connection, runner_sessions=reader, app_sessions=f.app_factory
            )
            run = authority._read_run(lease)
            assert run.id == lease.run_id
            assert run.input["execution"]["event"]["data"]["content"][0]["text"] == (
                "Build the requested page"
            )
            resolved = authority._resolve_runtime(run)
            assert resolved.actor_id == runtime.actor_id
            assert resolved.project_id == runtime.project_id
            assert resolved.runtime_partition_id == runtime.runtime_partition_id
            recovery = SimpleNamespace(
                run_id=lease.run_id,
                fence_token=lease.fence_token,
                connection_generation=connection.connection_generation,
                product_revision="c" * 40,
                image_digest="sha256:" + "a" * 64,
                grant=SimpleNamespace(runner_id=connection.runner_id),
                scope=ModelChannelScope(
                    runtime.tenant_id,
                    runtime.space_id,
                    runtime.project_id,
                    runtime.actor_id,
                    run.session_id,
                    runtime.runtime_partition_id,
                    fixture.conversation.id,
                    run.input["execution"]["model_publication"]["snapshot_sha256"],
                ),
            )
            authority.verify_recovery(recovery)
            control.transition_run(
                **credentials,
                run_id=lease.run_id,
                lease_token=lease.lease_token,
                fence_token=lease.fence_token,
                capability_token=lease.capability_token,
                target_status="succeeded",
            )
            control.release_run(
                **credentials,
                run_id=lease.run_id,
                fence_token=lease.fence_token,
            )
            authority.verify_recovery(recovery)
            recovery.fence_token += 1
            with pytest.raises(RunnerControlError):
                authority.verify_recovery(recovery)
            recovery.fence_token -= 1
            with _machine_login(f, uuid4(), 1) as unrelated:
                wrong = _runtime_authority(
                    scope, connection, runner_sessions=unrelated, app_sessions=f.app_factory
                )
                with pytest.raises(RunnerControlError, match="Runtime authority changed"):
                    wrong._read_run(lease)
                with pytest.raises(RunnerControlError):
                    wrong.verify_recovery(recovery)
