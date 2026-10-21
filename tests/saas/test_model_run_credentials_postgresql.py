from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from time import sleep
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from omnigent.server.schemas import SessionEventInput
from saas.compatibility import bind_runtime_context
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.model_routing_models import ModelRunTokenRecord
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.production.interactive_runtime import AuthorizedInteractiveInput
from saas.production.model_run_credentials import ModelRunCredentialService
from saas.production.runner_control import (
    ProductionRunnerMachineAuthority,
    RunnerControlClientLease,
)
from saas.runner_adapter.platform_model_gateway import (
    PlatformModelGatewayTokenError,
    PlatformModelGatewayTokenExpired,
)
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_http import _message, _queued_worker, _scheduling
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_interactive_runner_lease import _register
from tests.saas.test_interactive_runtime import _runtime_authority
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@contextmanager
def _authenticator_login(f):
    login = "model_auth_" + uuid4().hex[:16]
    password = "isolated-model-run-lookup-only"
    engine = None
    with f.engine.begin() as connection:
        connection.exec_driver_sql(
            f"CREATE ROLE {login} LOGIN PASSWORD '{password}' NOSUPERUSER "
            "NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT"
        )
        connection.exec_driver_sql(
            f"GRANT saas_authenticator TO {login} WITH INHERIT TRUE, SET FALSE"
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
        yield sessionmaker(engine, expire_on_commit=False)
    finally:
        if engine is not None:
            engine.dispose()
        with f.engine.begin() as connection:
            connection.exec_driver_sql(f"DROP OWNED BY {login}")
            connection.exec_driver_sql(f"DROP ROLE {login}")


def _claim(fixture, workers, *, include_controller=False):
    f, runtime = fixture.base, fixture.runtime
    _, pool = _scheduling(f.factory, runtime, runtime.project_id)
    with bind_runtime_context(runtime):
        fixture.service.dispatch(
            runtime,
            fixture.conversation,
            SessionEventInput.model_validate(_message()),
            created_by=runtime.runtime_user_key,
        )
    assert (
        _queued_worker(workers["dispatcher"], workers["executor"]).dispatch_once().published == 1
    )
    scheduling = SchedulingControlPlane(workers["executor"])
    from saas.control_plane.scheduling_models import RunnerPoolRecord

    with f.factory() as db:
        row = db.get(RunnerPoolRecord, pool)
        domain, schema = row.failure_domain, row.schema_revision
    scope = SimpleNamespace(factory=f.factory, runtime=runtime, delegate=None, permissions=None)
    connection = _register(scope, scheduling, pool, domain, schema, key="model-run-controller")
    control = ProductionRunnerMachineAuthority(
        scheduling,
        ExecutionControlPlane(workers["executor"]),
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
    )
    machine = {
        "runner_id": connection.runner_id,
        "connection_generation": connection.connection_generation,
        "connection_token": connection.connection_token,
    }
    claim = control.claim_run(**machine)
    assert claim is not None
    for status in ("starting", "running"):
        control.transition_run(
            **machine,
            run_id=claim.run_id,
            lease_token=claim.lease_token,
            fence_token=claim.fence_token,
            capability_token=claim.capability_token,
            target_status=status,
        )
    lease = RunnerControlClientLease(
        **{x.name: getattr(claim, x.name) for x in fields(RunnerControlClientLease)}
    )
    authority = _runtime_authority(scope, connection)
    run = authority._read_run(lease)
    runtime = authority._resolve_runtime(run)
    authorized = AuthorizedInteractiveInput(
        run_id=run.id,
        fence_token=run.fence_token,
        runtime=runtime,
        session_id=fixture.conversation.id,
        conversation=fixture.conversation,
        event=SessionEventInput.model_validate(run.input["execution"]["event"]),
        launch=run.input["execution"]["launch"],
        publication=run.input["execution"]["model_publication"],
    )
    if include_controller:
        return authority, authorized, lease, control, machine
    return authority, authorized, lease


@pytest.mark.parametrize("short_lived", [False, True])
def test_real_app_and_authenticator_logins_enforce_run_credential_boundaries(
    interactive_postgresql,
    short_lived,
):
    fixture = interactive_postgresql
    f = fixture.base
    with _worker_logins(f) as workers, _authenticator_login(f) as authentication:
        authority, authorized, lease = _claim(fixture, workers)
        service = ModelRunCredentialService(
            app_sessions=f.app_factory,
            authenticator_sessions=authentication,
            compatibility=authority._resolver._compatibility_policy,
            ttl=timedelta(seconds=15) if short_lived else timedelta(hours=8),
        )
        issued = service.issue(authorized, lease)
        assert issued == service.issue(authorized, lease)
        claims = service.authenticate(issued.value)
        assert service.authorize(claims).claims.run_id == lease.run_id
        if not short_lived:
            assert issued.expires_at - datetime.now(timezone.utc) > timedelta(hours=7, minutes=59)
            assert service.renew(issued.value) == issued
        if short_lived:
            sleep(max(0, (issued.expires_at - datetime.now(timezone.utc)).total_seconds()) + 0.1)
            with pytest.raises(PlatformModelGatewayTokenExpired):
                service.authenticate(issued.value)
            with ThreadPoolExecutor(max_workers=3) as pool:
                replies = list(pool.map(lambda _: service.renew(issued.value), range(3)))
            successor = replies[0]
            assert replies == [successor] * 3
            assert successor.generation == 1
            assert successor == service.renew(issued.value)
            assert service.authenticate(successor.value).run_id == lease.run_id
        for factory in (f.app_factory, authentication):
            with factory() as db:
                assert db.scalar(sa.select(sa.func.count()).select_from(ModelRunTokenRecord)) == 0
                assert not db.scalar(
                    sa.text(
                        "SELECT has_table_privilege(current_user,"
                        "'saas_customer_ledger_entries','INSERT')"
                    )
                )
                assert not db.scalar(
                    sa.text(
                        "SELECT has_table_privilege(current_user,'saas_model_run_tokens','UPDATE')"
                    )
                )
                assert not db.scalar(
                    sa.text(
                        "SELECT has_table_privilege(current_user,'saas_model_run_tokens','DELETE')"
                    )
                )
        with f.app_factory() as db:
            # Existing Run policy planning needs this ACL; no App row policy is added.
            assert db.execute(sa.text("SELECT token_hash FROM saas_capability_tokens")).all() == []
            service._context(db, claims)
            assert db.execute(sa.text("SELECT token_hash FROM saas_capability_tokens")).all() == []
            assert (
                db.execute(
                    sa.text("SELECT * FROM public.saas_model_run_capability_v1(:run,:cap)"),
                    {"run": lease.run_id, "cap": uuid4()},
                ).all()
                == []
            )
        with pytest.raises(DBAPIError) as denied, f.app_factory() as db:
            db.execute(sa.text("SELECT token_hash FROM saas_model_run_tokens"))
        assert denied.value.orig.sqlstate == "42501"
        for change in (
            {"expires_at": datetime.now(timezone.utc) + timedelta(hours=9)},
            {"fence_token": claims.fence_token + 1},
            {"capability_id": uuid4()},
        ):
            tampered = replace(claims, token_id=uuid4(), **change)
            with pytest.raises(DBAPIError) as rejected, f.app_factory.begin() as db:
                service._context(db, tampered)
                db.add(
                    service._new_row(
                        tampered,
                        "mrt_" + uuid4().hex * 2,
                        at=datetime.now(timezone.utc),
                        generation=0,
                        parent_id=None,
                    )
                )
            assert rejected.value.orig.sqlstate == "23514"
        with pytest.raises(PlatformModelGatewayTokenError):
            service.authenticate("mrt_" + "0" * 64)
        with f.engine.connect() as connection:
            config = Config(str(f.role_sql.parent / "alembic.ini"))
            config.attributes["connection"] = connection
            with pytest.raises(
                RuntimeError, match=r"^retained execution schema cannot be downgraded$"
            ):
                command.downgrade(config, "lm2e00000001")
        with f.factory() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(ModelRunTokenRecord)) == (
                2 if short_lived else 1
            )
