from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command

from saas.control_plane.migrations.versions import (
    lm2q00000001_bounded_model_documents as migration,
)
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_gateway_evidence import GatewayRequestEvidence
from saas.control_plane.model_pricing import PlatformModelPrice
from tests.saas import test_model_projection as projection_helpers
from tests.saas.test_model_connections import _fixture as connection_fixture
from tests.saas.test_model_publications import _envelope
from tests.saas.test_model_publications import _fixture as publication_fixture
from tests.saas.test_model_run_evidence import _enable_budget
from tests.saas.test_model_secret_storage_migration import _config


def _explicit_begin(connection):
    connection.exec_driver_sql("BEGIN")


@pytest.fixture(params=[False, True], ids=["standard-driver", "explicit-begin"])
def document_migration_engine(request):
    engine = sa.create_engine("sqlite+pysqlite://")
    if request.param:

        @sa.event.listens_for(engine, "connect")
        def manual_transactions(dbapi, _record):
            dbapi.isolation_level = None

        sa.event.listen(engine, "begin", _explicit_begin)

    try:
        yield engine
    finally:
        engine.dispose()


def _raw_documents(engine):
    with engine.connect() as connection:
        return {
            table: connection.exec_driver_sql(
                f"SELECT {pk},"
                + ",".join(name for name, _limit in columns)
                + f" FROM {table} ORDER BY {pk}"
            ).all()
            for table, pk, columns in migration._COLUMNS
        }


def _populated_documents(engine, monkeypatch):
    with engine.begin() as connection:
        command.upgrade(_config(connection), "lm2q00000001")
    # Managed application sessions install their own explicit BEGIN IMMEDIATE.
    if sa.event.contains(engine, "begin", _explicit_begin):
        sa.event.remove(engine, "begin", _explicit_begin)
    monkeypatch.setattr(
        projection_helpers,
        "_fixture",
        lambda **kwargs: connection_fixture(engine=engine, **kwargs),
    )
    service, publisher, factory, actor, request, calls = publication_fixture()
    operation = service.admit(actor, **request)
    publisher.publish(**_envelope(factory, operation.id))
    assert service.receipt(actor, operation.id)["operation"]["status"] == "applied"
    before = list(calls)
    _enable_budget(factory)
    price = PlatformModelPrice(sha256(b"deepseek-flash").hexdigest(), *(1 for _ in range(6)))
    ModelProviderBudgetAdmissionService(factory).reserve(
        tenant_id=request["tenant_id"],
        run_id=uuid4(),
        operation_key="migration-gateway-evidence",
        requested_tokens=64,
        requested_microusd=1,
        ttl=timedelta(minutes=2),
        gateway_request=GatewayRequestEvidence(
            "deepseek-flash",
            "openai_chat_completions",
            "migration-synthetic-price",
            price,
            32,
        ),
    )
    assert calls == before
    rows = _raw_documents(engine)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    assert all(records for records in rows.values())
    assert all(
        isinstance(value, bytes) and value.startswith(b"OGMD\x01\x00\x00")
        for records in rows.values()
        for row in records
        for value in row[1:]
    )
    return rows, factory, calls, before


def test_empty_schema_document_roundtrip_is_repeatable(document_migration_engine):
    engine = document_migration_engine
    for target in ("lm2p00000001", "lm2q00000001", "lm2q00000001", "lm2p00000001", "lm2q00000001"):
        with engine.begin() as connection:
            if target == "lm2p00000001" and connection.dialect.has_table(
                connection, "saas_alembic_version"
            ):
                head = connection.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar()
                if head == "lm2q00000001":
                    command.downgrade(_config(connection), target)
                else:
                    command.upgrade(_config(connection), target)
            else:
                command.upgrade(_config(connection), target)
        for table, _pk, columns in migration._COLUMNS:
            physical = {
                column["name"]: column["type"] for column in sa.inspect(engine).get_columns(table)
            }
            for name, _limit in columns:
                assert isinstance(
                    physical[name], sa.LargeBinary if target == "lm2q00000001" else sa.Text
                )
        constraints = {
            table: sa.inspect(engine).get_foreign_keys(table)
            for table in migration._RELATION_ORDER
        }
        assert sum(map(len, constraints.values())) == (0 if target == "lm2q00000001" else 37)
        assert all(
            not item["referred_table"].startswith("_alembic_tmp_")
            for definitions in constraints.values()
            for item in definitions
        )


def test_populated_roundtrip_preserves_all_six_documents_hashes_and_domain_state(
    document_migration_engine, monkeypatch
):
    engine = document_migration_engine
    before, factory, calls, supplier_calls = _populated_documents(engine, monkeypatch)
    with factory() as db:
        domain = tuple(
            db.execute(
                sa.text(
                    "SELECT id,status,version FROM saas_model_provider_budget_reservations "
                    "ORDER BY id"
                )
            )
        )
        outbox = tuple(
            db.execute(
                sa.text("SELECT id,request_hash FROM saas_control_plane_outbox ORDER BY id")
            )
        )
    with engine.begin() as connection:
        command.downgrade(_config(connection), "lm2p00000001")
    legacy = _raw_documents(engine)
    for table, rows in legacy.items():
        assert [(row[0], *(value.encode() for value in row[1:])) for row in rows] == [
            (row[0], *(value[7:] for value in row[1:])) for row in before[table]
        ]
    with engine.begin() as connection:
        command.upgrade(_config(connection), "lm2q00000001")
        command.upgrade(_config(connection), "lm2q00000001")
    assert _raw_documents(engine) == before
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    with factory() as db:
        assert (
            tuple(
                db.execute(
                    sa.text(
                        "SELECT id,status,version FROM saas_model_provider_budget_reservations "
                        "ORDER BY id"
                    )
                )
            )
            == domain
        )
        assert (
            tuple(
                db.execute(
                    sa.text("SELECT id,request_hash FROM saas_control_plane_outbox ORDER BY id")
                )
            )
            == outbox
        )
    assert calls == supplier_calls


def test_oversize_last_table_refuses_all_prior_conversions_atomically(
    document_migration_engine, monkeypatch
):
    engine = document_migration_engine
    _populated_documents(engine, monkeypatch)
    with engine.begin() as connection:
        command.downgrade(_config(connection), "lm2p00000001")
        connection.execute(
            sa.text("UPDATE saas_model_gateway_evidence SET canonical_evidence=:value"),
            {"value": '{"synthetic":"' + "密" * 6000 + '"}'},
        )
    before = _raw_documents(engine)
    tables = sa.inspect(engine).get_table_names()
    with pytest.raises(RuntimeError, match="model document exceeds byte cap"):
        with engine.begin() as connection:
            command.upgrade(_config(connection), "lm2q00000001")
    assert _raw_documents(engine) == before
    assert sa.inspect(engine).get_table_names() == tables
    with engine.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT version_num FROM saas_alembic_version").scalar()
            == "lm2p00000001"
        )
