from __future__ import annotations

import sys
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from saas.control_plane.db_models import SaasBase
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord
from saas.control_plane.migrations.schema_metadata import (
    _MODEL_TABLES,
    control_plane_migration_metadata,
)
from tests.saas.test_control_plane_migration import _migration_config
from tests.saas.test_execution_control_plane import _admitted_run, _execution_fixture

_R = "lm2r00000001"
_T = "lm2t00000001"
_PRICE_KEYS = {"fk_session_customer_pricing", "fk_run_customer_pricing"}


@pytest.fixture
def schema_database(tmp_path):
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "schema.db"))

    @sa.event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        yield engine
    finally:
        engine.dispose()


def _upgrade(engine, head="head"):
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), head)


def _foreign_keys(engine):
    inspector = sa.inspect(engine)
    return {
        foreign["name"]
        for table in ("saas_execution_sessions", "saas_runs")
        for foreign in inspector.get_foreign_keys(table)
        if foreign["name"] in _PRICE_KEYS
    }


def _legacy_run(engine):
    factory, service, scope, request = _execution_fixture(engine)
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=4
    )
    run, _task, session = _admitted_run(service, scope, request)
    return factory, run, session


def test_schema_projection_does_not_import_or_mutate_runtime_model_records(schema_database):
    _upgrade(schema_database, "p0s000000015")
    legacy = sa.MetaData()
    legacy.reflect(schema_database)
    names = set(legacy.tables)
    legacy_columns = tuple(legacy.tables["saas_execution_sessions"].c.keys())
    runtime_names = set(SaasBase.metadata.tables)
    columns = tuple(ExecutionSessionRecord.__table__.c.keys())
    modules = set(sys.modules)
    projected = control_plane_migration_metadata(legacy)
    assert len(_MODEL_TABLES) == 15
    assert set(projected.tables) - names == _MODEL_TABLES
    assert set(legacy.tables) == names
    assert tuple(legacy.tables["saas_execution_sessions"].c.keys()) == legacy_columns
    assert set(SaasBase.metadata.tables) == runtime_names
    assert tuple(ExecutionSessionRecord.__table__.c.keys()) == columns
    assert "customer_pricing_frozen" not in legacy_columns
    assert set(sys.modules) == modules
    assert not any(projected.tables[name].foreign_key_constraints for name in _MODEL_TABLES)


def test_partial_application_model_metadata_is_rejected():
    partial = sa.MetaData()
    sa.Table(sorted(_MODEL_TABLES)[0], partial, sa.Column("id", sa.Integer, primary_key=True))
    with pytest.raises(ValueError, match="incomplete application"):
        control_plane_migration_metadata(partial)


def test_fresh_schema_matches_the_ordinary_unfiltered_alembic_check(schema_database):
    _upgrade(schema_database)
    with schema_database.begin() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        command.check(_migration_config(connection))
        assert (
            connection.exec_driver_sql("SELECT version_num FROM saas_alembic_version").scalar_one()
            == _T
        )
    assert _foreign_keys(schema_database) == set()


def test_complete_application_metadata_is_not_overridden_or_hidden(schema_database, monkeypatch):
    _upgrade(schema_database)
    application = control_plane_migration_metadata(SaasBase.metadata)
    assert control_plane_migration_metadata(application) is application
    column = application.tables["saas_model_connections"].c.display_name
    original_type = column.type
    with monkeypatch.context() as mutation:
        mutation.setattr(column, "type", sa.String(12))
        with schema_database.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"version_table": "saas_alembic_version", "compare_type": True}
            )
            assert compare_metadata(context, control_plane_migration_metadata(application))
    assert column.type is original_type


def test_nonempty_p0_execution_survives_schema_upgrade_with_foreign_keys_enabled(
    schema_database,
):
    _upgrade(schema_database, "p0s000000015")
    factory, _service, scope, _request = _execution_fixture(schema_database, create_schema=False)
    run, task, session = uuid4(), uuid4(), uuid4()
    legacy = sa.MetaData()
    legacy.reflect(schema_database)
    common = {
        "tenant_id": scope.tenant_id.hex,
        "space_id": scope.space_id.hex,
        "project_id": scope.project_id.hex,
        "created_by": scope.owner_id.hex,
        "version": 1,
    }
    with schema_database.begin() as connection:
        connection.execute(
            legacy.tables["saas_execution_sessions"].insert(),
            {**common, "id": session.hex, "status": "active"},
        )
        connection.execute(
            legacy.tables["saas_tasks"].insert(),
            {**common, "id": task.hex, "title": "Retained P0 execution"},
        )
        connection.execute(
            legacy.tables["saas_runs"].insert(),
            {
                **common,
                "id": run.hex,
                "task_id": task.hex,
                "session_id": session.hex,
                "status": "queued",
                "event_sequence": 0,
                "queue_class": "interactive",
                "priority": 0,
                "idempotency_key": "retained-p0-execution",
                "request_hash": "a" * 64,
                "input": {"prompt": "synthetic retention test"},
                "product_revision": "p0-product",
                "upstream_revision": "p0-upstream",
                "schema_revision": "p0s000000015",
                "adapter_contract_version": "0.2.0",
                "fence_token": 0,
            },
        )
    assert not (_MODEL_TABLES & set(sa.inspect(schema_database).get_table_names()))
    assert "customer_pricing_frozen" not in legacy.tables["saas_execution_sessions"].c
    _upgrade(schema_database)
    with factory() as db:
        retained = db.get(RunRecord, run)
        assert retained is not None and retained.session_id == session
        assert db.get(ExecutionSessionRecord, session) is not None
    with schema_database.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    assert _foreign_keys(schema_database) == set()


def test_schema_downgrade_refuses_retained_execution_without_erasing_data(schema_database):
    _upgrade(schema_database)
    factory, run, session = _legacy_run(schema_database)
    with pytest.raises(RuntimeError, match="retained execution"):
        with schema_database.begin() as connection:
            command.downgrade(_migration_config(connection), _R)
    with factory() as db:
        retained = db.get(RunRecord, run)
        assert retained is not None and retained.session_id == session
    assert _foreign_keys(schema_database) == set()
    with schema_database.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT version_num FROM saas_alembic_version").scalar_one()
            == _T
        )


def test_empty_schema_can_restore_original_constraints_then_upgrade_again(schema_database):
    _upgrade(schema_database)
    with schema_database.begin() as connection:
        command.downgrade(_migration_config(connection), _R)
    assert _foreign_keys(schema_database) == _PRICE_KEYS
    _upgrade(schema_database)
    assert _foreign_keys(schema_database) == set()


def test_migration_refuses_unresolved_foreign_keys_instead_of_clearing_them(schema_database):
    _upgrade(schema_database)
    factory, run, session = _legacy_run(schema_database)
    with pytest.raises(RuntimeError, match="retain invalid foreign keys"):
        with schema_database.begin() as connection:
            connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
            connection.execute(
                sa.text("UPDATE saas_runs SET session_id=:session WHERE id=:run"),
                {"session": uuid4().hex, "run": run.hex},
            )
            command.upgrade(_migration_config(connection), "head")
    with factory() as db:
        retained = db.get(RunRecord, run)
        assert retained is not None and retained.session_id == session
    with schema_database.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []


def test_migration_preserves_caller_defer_mode_and_later_commit_enforcement(schema_database):
    _upgrade(schema_database)
    _factory, run, _session = _legacy_run(schema_database)
    with pytest.raises(sa.exc.IntegrityError, match="FOREIGN KEY"):
        with schema_database.begin() as connection:
            connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
            command.upgrade(_migration_config(connection), "head")
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar_one() == 1
            connection.execute(
                sa.text("UPDATE saas_runs SET session_id=:session WHERE id=:run"),
                {"session": uuid4().hex, "run": run.hex},
            )
