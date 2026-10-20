"""Exercise the schema delivery without importing unshipped model services."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
from saas.production import postgresql_migration as migration
from saas.production.service_bindings import (
    EXPECTED_MODEL_PROJECTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
    render_production_service_role_bindings,
)
from tests.saas import test_release_schema_replay
from tests.saas.test_execution_control_plane import _admitted_run, _execution_fixture
from tests.saas.test_production_migration_replay import production_replay as production_replay


@pytest.fixture
def standalone_replay(production_replay, tmp_path):
    known = production_replay.service_role_graph.by_service
    rows = tuple(
        known[service]
        if service in known
        else ProductionServiceRoleBinding(
            service=service, login="replay_model_projection", base_role=role
        )
        for service, role in sorted(EXPECTED_MODEL_PROJECTION_SERVICE_ROLES.items())
    )
    path = tmp_path / "model-projection-bindings.json"
    document = render_production_service_role_bindings(rows)
    path.write_text(document)
    path.chmod(0o400)
    profile = ProductionServiceRoleBindings(
        path, hashlib.sha256(document.encode()).hexdigest(), rows
    )
    admin = sa.create_engine(
        sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
            query=production_replay.saas_owner.url.query
        ),
        isolation_level="AUTOCOMMIT",
    )
    try:
        with admin.connect() as connection:
            connection.exec_driver_sql(
                "CREATE ROLE replay_model_projection LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "INHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'production-replay-test'"
            )
    finally:
        admin.dispose()
    plan = replace(production_replay, model_projection_service_role_bindings=profile)
    assert len(plan.service_role_graph.bindings) == 19
    return plan


def test_standalone_model_schema_replays_and_matches_the_pinned_r_catalog(
    standalone_replay, monkeypatch, record_property
):
    plan = standalone_replay
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: plan.product_revision)
    assert migration._expected_head("saas") == "lm2s00000001"
    receipt = migration.run_production_postgresql_migration(plan)
    assert receipt.saas_head == "lm2s00000001"
    assert receipt.runtime_rls_table_count == 19
    assert "saas.control_plane.model_routing_models" not in sys.modules
    engine = sa.create_engine(plan.saas_owner.url)
    try:
        with engine.connect() as connection:
            protected = (
                connection.execute(
                    sa.text(
                        "SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace "
                        "AND relname=ANY(:names) AND relrowsecurity AND relforcerowsecurity "
                        "LIMIT 132"
                    ),
                    {"names": sorted(CONTROL_PLANE_RLS_TABLES)},
                )
                .scalars()
                .all()
            )
            assert set(protected) == CONTROL_PLANE_RLS_TABLES
            assert len(protected) == 131
            foreign_keys = (
                connection.exec_driver_sql(
                    "SELECT conname FROM pg_constraint WHERE contype='f' "
                    "AND conname IN ('fk_session_customer_pricing','fk_run_customer_pricing') "
                    "ORDER BY conname LIMIT 3"
                )
                .scalars()
                .all()
            )
    finally:
        engine.dispose()
    record_property("new_customer_pricing_foreign_keys", ",".join(foreign_keys))
    # New schema must satisfy the repository's no-new-foreign-key contract.
    assert foreign_keys == []


def _produce_r_predecessor(plan):
    source, revision = test_release_schema_replay._producer_source()
    bindings = {}
    for prefix, value in (
        ("OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS", plan.service_role_bindings),
        (
            "OMNIGENT_SAAS_PLATFORM_MODEL_SERVICE_ROLE_BINDINGS",
            plan.platform_model_service_role_bindings,
        ),
        (
            "OMNIGENT_SAAS_PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS",
            plan.platform_admin_service_role_bindings,
        ),
        (
            "OMNIGENT_SAAS_MODEL_PROJECTION_SERVICE_ROLE_BINDINGS",
            plan.model_projection_service_role_bindings,
        ),
    ):
        assert value is not None
        bindings[prefix + "_FILE"] = str(value.path)
        bindings[prefix + "_SHA256"] = value.sha256
    document = {
        "source_root": str(source),
        "source_revision": revision,
        "bindings": bindings,
        "urls": {
            authority.kind + "_url": authority.url.render_as_string(hide_password=False)
            for authority in plan.authorities()
        },
    }
    environment = {name: os.environ[name] for name in ("PATH", "TMPDIR") if name in os.environ}
    environment.update(PYTHONPATH=str(source), OMNIGENT_SKIP_WEB_UI="true")
    result = subprocess.run(
        [sys.executable, str(Path(test_release_schema_replay.__file__).resolve()), "--produce"],
        input=json.dumps(document),
        env=environment,
        cwd=source,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    receipt = test_release_schema_replay._receipt_from_document(json.loads(result.stdout))
    assert receipt.status == "pass" and receipt.saas_head == "lm2r00000001"


def test_forward_price_reference_retirement_retains_old_app_execution(standalone_replay):
    plan = standalone_replay
    _produce_r_predecessor(plan)
    admin_url = sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"])
    admin = sa.create_engine(
        admin_url.set(database=plan.saas_owner.url.database, query=plan.saas_owner.url.query)
    )
    app_binding = plan.service_role_graph.by_service["app"]
    billing_binding = plan.service_role_graph.by_service["billing"]
    app = sa.create_engine(
        plan.saas_owner.url.set(username=app_binding.login, password="production-replay-test")
    )
    billing = sa.create_engine(
        plan.saas_owner.url.set(username=billing_binding.login, password="production-replay-test")
    )
    owner = sa.create_engine(plan.saas_owner.url)
    try:

        @sa.event.listens_for(admin, "before_cursor_execute")
        def refuse_schema_repair(_connection, _cursor, statement, _parameters, _context, _many):
            assert (
                not statement.lstrip()
                .upper()
                .startswith(("CREATE TABLE", "ALTER TABLE", "DROP TABLE"))
            )

        factory, _service, scope, request = _execution_fixture(admin)
        service = ExecutionControlPlane(sessionmaker(app, expire_on_commit=False))
        service.configure_quota(
            request, project_id=scope.project_id, resource="run_units", limit_units=4
        )
        run, task, session = _admitted_run(service, scope, request)
        with owner.connect() as connection:
            before = connection.exec_driver_sql(
                "SELECT prosrc FROM pg_proc WHERE oid="
                "'public.saas_execution_customer_price_guard_v1()'::regprocedure"
            ).scalar_one()
        migration._upgrade(owner, "saas")
        with owner.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar_one()
                == "lm2s00000001"
            )
            assert (
                connection.exec_driver_sql(
                    "SELECT conname FROM pg_constraint WHERE contype='f' AND "
                    "conname IN ('fk_session_customer_pricing','fk_run_customer_pricing') LIMIT 1"
                ).first()
                is None
            )
            assert (
                connection.exec_driver_sql(
                    "SELECT prosrc FROM pg_proc WHERE oid="
                    "'public.saas_execution_customer_price_guard_v1()'::regprocedure"
                ).scalar_one()
                == before
            )
        with billing.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT current_user=session_user,rolsuper,rolbypassrls "
                "FROM pg_roles WHERE rolname=current_user"
            ).one() == (True, False, False)
            assert connection.exec_driver_sql(
                "SELECT has_table_privilege(current_user,'saas_pricing_snapshots','SELECT'),"
                "has_table_privilege(current_user,'saas_pricing_snapshots','INSERT'),"
                "has_table_privilege(current_user,'saas_pricing_snapshots','UPDATE'),"
                "has_table_privilege(current_user,'saas_pricing_snapshots','DELETE')"
            ).one() == (True, True, False, False)
        assert service.task_state(request, project_id=scope.project_id, task_id=task) == "queued"
        assert service.replay_events(request, project_id=scope.project_id, run_id=run, limit=3)
        assert "saas.control_plane.model_routing_models" not in sys.modules
        with factory() as db:
            assert (
                db.scalar(sa.text("SELECT session_id FROM saas_runs WHERE id=:id"), {"id": run})
                == session
            )
    finally:
        for engine in (owner, billing, app, admin):
            engine.dispose()
