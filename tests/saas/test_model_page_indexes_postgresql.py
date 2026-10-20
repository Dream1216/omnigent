from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command

from tests.saas.test_model_secret_storage_migration import _config


@pytest.fixture
def index_schema(isolated_postgres_url):
    engine = sa.create_engine(isolated_postgres_url)
    roles = (
        Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
    ).read_text()
    try:
        with engine.begin() as connection:
            command.upgrade(_config(connection), "lm2q00000001")
            connection.exec_driver_sql(roles)
        yield engine, roles
    finally:
        engine.dispose()


def _indexes(engine):
    with engine.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT relation.relname,pg_get_indexdef(relation.oid) FROM pg_class relation "
            "WHERE relation.relnamespace='public'::regnamespace AND relation.relkind='i' "
            "ORDER BY 1"
        ).all()


def _catalog_columns(engine):
    with engine.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT has_column_privilege('saas_app',"
            "'public.saas_model_publication_versions','id','SELECT'),"
            "has_column_privilege('saas_app','public.saas_model_publication_versions',"
            "'created_at','SELECT'),has_column_privilege('saas_app',"
            "'public.saas_model_publication_versions','canonical_readiness','SELECT')"
        ).one()


def test_real_postgresql_R_migration_and_roles_accept_only_the_indexed_customer_page(
    index_schema,
):
    engine, roles = index_schema
    original = _indexes(engine)
    assert _catalog_columns(engine) == (False, False, False)
    for _repeat in range(2):
        with engine.begin() as connection:
            command.upgrade(_config(connection), "lm2r00000001")
            connection.exec_driver_sql(roles)
        assert _catalog_columns(engine) == (True, True, False)
        with engine.begin() as connection:
            command.downgrade(_config(connection), "lm2q00000001")
            connection.exec_driver_sql(roles)
        assert _catalog_columns(engine) == (False, False, False)
        assert _indexes(engine) == original


@pytest.mark.parametrize(
    "drift",
    (
        "missing",
        "prefix",
        "descending",
        "unique",
        "include",
        "predicate",
        "opclass",
        "collation",
        "wrong_table",
        "expression",
        "retired",
        "spoofed_head",
    ),
)
def test_real_postgresql_R_role_projection_rejects_index_drift_before_granting(
    index_schema, drift
):
    engine, roles = index_schema
    with engine.begin() as connection:
        command.upgrade(_config(connection), "lm2r00000001")
        connection.exec_driver_sql(roles)
    original = _indexes(engine)
    index = "ix_model_connection_page"
    connection_index = "CREATE INDEX ix_model_connection_page ON saas_model_connections "
    budget_index = (
        "CREATE INDEX ix_model_budget_admitted_test_day "
        "ON saas_model_provider_budget_reservations "
    )
    definition = {
        "prefix": connection_index + "(created_at)",
        "descending": connection_index + "(created_at DESC,id)",
        "unique": connection_index.replace("CREATE INDEX", "CREATE UNIQUE INDEX")
        + "(created_at,id)",
        "include": connection_index + "(created_at,id) INCLUDE (version)",
        "wrong_table": connection_index.replace(
            "saas_model_connections", "saas_model_deployment_versions"
        )
        + "(created_at,id)",
        "expression": connection_index + "(created_at,(id::text))",
        "predicate": budget_index
        + "(provider_id,purpose,usage_date,id) WHERE admitted_microusd>=0",
        "opclass": budget_index
        + "(provider_id text_pattern_ops,purpose,usage_date,id) WHERE admitted_microusd>0",
        "collation": budget_index
        + '(provider_id COLLATE "C",purpose,usage_date,id) WHERE admitted_microusd>0',
    }
    with pytest.raises(sa.exc.DBAPIError, match="model page index object contract rejected"):
        with engine.begin() as connection:
            if drift == "spoofed_head":
                command.downgrade(_config(connection), "lm2q00000001")
                connection.exec_driver_sql(
                    "UPDATE saas_alembic_version SET version_num='lm2r00000001'"
                )
            elif drift == "retired":
                connection.exec_driver_sql(
                    "CREATE INDEX ix_model_projection_status "
                    "ON saas_model_projection_operations (status,created_at)"
                )
            else:
                if drift in {"predicate", "opclass", "collation"}:
                    index = "ix_model_budget_admitted_test_day"
                connection.exec_driver_sql(f"DROP INDEX {index}")
                if drift != "missing":
                    connection.exec_driver_sql(definition[drift])
            connection.exec_driver_sql(roles)
    assert _indexes(engine) == original
    assert _catalog_columns(engine) == (True, True, False)
