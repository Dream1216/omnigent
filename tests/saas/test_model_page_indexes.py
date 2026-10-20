from __future__ import annotations

import pytest
import sqlalchemy as sa
from alembic import command

from saas.control_plane.migrations.versions import lm2r00000001_model_page_indexes as migration
from tests.saas.test_model_document_storage_migration import _populated_documents, _raw_documents
from tests.saas.test_model_secret_storage_migration import _config


@pytest.fixture(params=[False, True], ids=["standard-driver", "explicit-begin"])
def index_engine(request):
    engine = sa.create_engine("sqlite+pysqlite://")
    if request.param:

        @sa.event.listens_for(engine, "connect")
        def manual_transactions(dbapi, _record):
            dbapi.isolation_level = None

        @sa.event.listens_for(engine, "begin")
        def explicit_begin(connection):
            connection.exec_driver_sql("BEGIN")

    try:
        with engine.begin() as connection:
            command.upgrade(_config(connection), "lm2q00000001")
        yield engine
    finally:
        engine.dispose()


def _indexes(engine):
    with engine.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT name,tbl_name,sql FROM sqlite_master WHERE type='index' ORDER BY name"
        ).all()


def _head(engine):
    with engine.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT version_num FROM saas_alembic_version"
        ).scalar_one()


def test_index_upgrade_and_downgrade_preserve_the_original_schema(index_engine):
    before = _indexes(index_engine)
    for _repeat in range(2):
        with index_engine.begin() as connection:
            command.upgrade(_config(connection), "lm2r00000001")
        assert _head(index_engine) == "lm2r00000001"
        for name, table, columns in migration._INDEXES:
            observed = next(
                item
                for item in sa.inspect(index_engine).get_indexes(table)
                if item["name"] == name
            )
            assert observed["column_names"] == list(columns) and not observed["unique"]
        budget_indexes = {
            index["name"]: index
            for index in sa.inspect(index_engine).get_indexes(
                "saas_model_provider_budget_reservations"
            )
        }
        assert "ix_model_budget_test_day" not in budget_indexes
        admitted = budget_indexes["ix_model_budget_admitted_test_day"]
        assert admitted["column_names"] == ["provider_id", "purpose", "usage_date", "id"]
        assert not admitted["unique"]
        assert str(admitted["dialect_options"]["sqlite_where"]) == "admitted_microusd > 0"
        with index_engine.begin() as connection:
            command.downgrade(_config(connection), "lm2q00000001")
        assert _head(index_engine) == "lm2q00000001" and _indexes(index_engine) == before


def test_failed_index_upgrade_rolls_back_earlier_indexes(index_engine):
    name, table, _columns = migration._INDEXES[2]
    with index_engine.begin() as connection:
        connection.exec_driver_sql(f"CREATE INDEX {name} ON {table} (id)")
    before = _indexes(index_engine)
    with pytest.raises(sa.exc.OperationalError, match="already exists"):
        with index_engine.begin() as connection:
            command.upgrade(_config(connection), "lm2r00000001")
    assert _head(index_engine) == "lm2q00000001" and _indexes(index_engine) == before


def test_failed_index_downgrade_restores_earlier_drops(index_engine):
    with index_engine.begin() as connection:
        command.upgrade(_config(connection), "lm2r00000001")
    name, _table, _columns = migration._INDEXES[-3]
    with index_engine.begin() as connection:
        connection.exec_driver_sql(f"DROP INDEX {name}")
    before = _indexes(index_engine)
    with pytest.raises(sa.exc.OperationalError, match="no such index"):
        with index_engine.begin() as connection:
            command.downgrade(_config(connection), "lm2q00000001")
    assert _head(index_engine) == "lm2r00000001" and _indexes(index_engine) == before


def test_populated_index_roundtrip_keeps_documents_hashes_and_supplier_calls(monkeypatch):
    engine = sa.create_engine("sqlite+pysqlite://")
    try:
        before, _factory, calls, original_calls = _populated_documents(engine, monkeypatch)
        original_indexes = _indexes(engine)
        with engine.begin() as connection:
            command.upgrade(_config(connection), "lm2r00000001")
        assert _raw_documents(engine) == before and calls == original_calls
        with engine.begin() as connection:
            command.downgrade(_config(connection), "lm2q00000001")
        assert _raw_documents(engine) == before and calls == original_calls
        assert _indexes(engine) == original_indexes
    finally:
        engine.dispose()
