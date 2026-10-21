from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import sessionmaker

from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from tests.saas.test_execution_control_plane import _execution_fixture
from tests.saas.test_model_gateway_audit_postgresql import _assign_control_plane_owner
from tests.saas.test_run_customer_pricing import _admit, _plan


@pytest.fixture
def priced_execution(isolated_postgres_url):
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    suffix = uuid4().hex
    table_owner, app_login = "price_owner_" + suffix, "price_app_" + suffix
    password = "isolated-customer-price-test-only"
    app = None
    roles = []
    try:
        with engine.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
        factory, _, scope, context = _execution_fixture(engine)
        with engine.begin() as connection:
            for role, login in (
                (table_owner, "NOLOGIN"),
                (app_login, f"LOGIN PASSWORD '{password}'"),
            ):
                connection.exec_driver_sql(
                    f"CREATE ROLE {role} {login} NOSUPERUSER NOBYPASSRLS "
                    "NOCREATEDB NOCREATEROLE INHERIT"
                )
                roles.append(role)
            connection.exec_driver_sql(
                f"GRANT saas_app TO {app_login} WITH INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                f'GRANT CONNECT ON DATABASE "{sa.make_url(isolated_postgres_url).database}" '
                f"TO {app_login}"
            )
            connection.exec_driver_sql(f"GRANT USAGE,CREATE ON SCHEMA public TO {table_owner}")
            _assign_control_plane_owner(connection, "postgres", table_owner)
            connection.exec_driver_sql(f"REVOKE CREATE ON SCHEMA public FROM {table_owner}")
        app = sa.create_engine(
            sa.make_url(isolated_postgres_url).set(username=app_login, password=password)
        )
        app_factory = sessionmaker(app, expire_on_commit=False)
        yield SimpleNamespace(
            engine=engine,
            app=app,
            factory=factory,
            app_factory=app_factory,
            service=ExecutionControlPlane(app_factory),
            scope=scope,
            context=context,
            table_owner=table_owner,
            role_sql=root / "saas/control_plane/postgresql_roles.sql",
        )
    finally:
        if app is not None:
            app.dispose()
        with engine.begin() as connection:
            if table_owner in roles:
                _assign_control_plane_owner(connection, table_owner, "postgres")
            for role in reversed(roles):
                connection.exec_driver_sql(f"DROP OWNED BY {role}")
                connection.exec_driver_sql(f"DROP ROLE {role}")
        engine.dispose()


def test_real_postgresql_login_freezes_session_and_run_without_reading_billing(priced_execution):
    f = priced_execution
    original = _plan(f.factory, f.scope)
    session = f.service.create_session(f.context, project_id=f.scope.project_id)
    first = _admit(f.service, f.scope, f.context, session_id=session)
    changed = _plan(f.factory, f.scope, key="team-v2", version=1, rate=250)
    continued = _admit(f.service, f.scope, f.context, session_id=session)
    fresh_session = f.service.create_session(f.context, project_id=f.scope.project_id)
    fresh = _admit(f.service, f.scope, f.context, session_id=fresh_session)
    with f.factory() as db:
        assert db.get(ExecutionSessionRecord, session).customer_pricing_snapshot_id == original
        for identity, expected in ((first, original), (continued, original), (fresh, changed)):
            run = db.get(RunRecord, identity)
            assert run.customer_pricing_frozen and run.customer_pricing_snapshot_id == expected
    with f.app.connect() as connection:
        assert connection.exec_driver_sql(
            "SELECT current_user=session_user,"
            "has_table_privilege(current_user,'saas_pricing_snapshots','SELECT'),"
            "has_table_privilege(current_user,'saas_customer_ledger_entries','INSERT'),"
            "has_function_privilege(current_user,'public.saas_execution_customer_price_guard_v1()','EXECUTE')"
        ).one() == (True, False, False, False)
    with f.engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {f.table_owner}")
        connection.exec_driver_sql(f.role_sql.read_text())


def test_real_postgresql_pricing_reference_is_immutable_for_actual_app_login(priced_execution):
    f = priced_execution
    price = _plan(f.factory, f.scope)
    session = f.service.create_session(f.context, project_id=f.scope.project_id)
    run = _admit(f.service, f.scope, f.context, session_id=session)
    for table, identity in (("saas_execution_sessions", session), ("saas_runs", run)):
        with pytest.raises(sa.exc.DBAPIError, match="customer pricing is immutable"):
            with f.app_factory.begin() as db:
                apply_rls_context(
                    db,
                    RlsContext(
                        actor_id=f.scope.owner_id,
                        tenant_id=f.scope.tenant_id,
                        space_id=f.scope.space_id,
                    ),
                )
                db.execute(
                    sa.text(f"UPDATE {table} SET customer_pricing_snapshot_id=NULL WHERE id=:id"),
                    {"id": identity},
                )
    with f.factory() as db:
        assert db.get(RunRecord, run).customer_pricing_snapshot_id == price


def test_real_postgresql_missing_price_stays_unavailable_after_later_configuration(
    priced_execution,
):
    f = priced_execution
    _plan(f.factory, f.scope, priced=False)
    session = f.service.create_session(f.context, project_id=f.scope.project_id)
    _plan(f.factory, f.scope, version=1)
    run = _admit(f.service, f.scope, f.context, session_id=session)
    with f.factory() as db:
        row = db.get(RunRecord, run)
        assert row.customer_pricing_frozen and row.customer_pricing_snapshot_id is None


def test_real_postgresql_retained_customer_price_blocks_schema_downgrade(priced_execution):
    f = priced_execution
    _plan(f.factory, f.scope)
    f.service.create_session(f.context, project_id=f.scope.project_id)
    with pytest.raises(RuntimeError, match=r"^retained execution schema cannot be downgraded$"):
        with f.engine.begin() as connection:
            config = Config(Path(__file__).resolve().parents[2] / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.downgrade(config, "lm2c00000001")
