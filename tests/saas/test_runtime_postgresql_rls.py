from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError

from omnigent.db.utils import make_managed_session_maker, shared_read_scope
from saas.compatibility import OmnigentStoreAdapter, RuntimeContext
from saas.runtime_rls import (
    RUNTIME_RLS_POLICY_NAME,
    RuntimeRlsContractError,
    install_runtime_rls,
    load_runtime_rls_contract,
    remove_runtime_rls,
    verify_runtime_rls,
)

_TEST_ROLE = "omnigent_runtime_rls_test_principal"


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for real RLS acceptance")
    return url


def _migrate_official(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "omnigent/db/alembic.ini")
    config.set_main_option("script_location", str(root / "omnigent/db/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _runtime(workspace_id: int) -> RuntimeContext:
    return RuntimeContext(
        actor_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        runtime_partition_id=uuid4(),
        placement_id=uuid4(),
        placement_generation=1,
        binding_generation=1,
        data_region="test-region",
        physical_workspace_id=workspace_id,
        runtime_user_key=f"runtime-{workspace_id}",
        runtime_type="omnigent",
        source_revision="reviewed-revision",
        adapter_contract_version="0.2.0",
        trace_id=f"runtime-rls-{workspace_id}",
    )


def _set_test_role(session: sa.Connection | sa.orm.Session) -> None:
    session.execute(sa.text(f"SET LOCAL ROLE {_TEST_ROLE}"))


def test_runtime_rls_contract_covers_every_official_workspace_table() -> None:
    contracts = load_runtime_rls_contract()

    assert len(contracts) == 17
    assert all(contract.primary_key_columns[0] == "workspace_id" for contract in contracts)


def test_runtime_rls_rejects_non_postgresql_installation() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection, pytest.raises(RuntimeRlsContractError) as exc_info:
        install_runtime_rls(connection)
    assert exc_info.value.code == "runtime_rls_postgresql_required"
    engine.dispose()


def test_real_postgresql_runtime_rls_and_store_adapter_context() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=1, max_overflow=0)
    user_a = f"rls-a-{uuid4()}"
    user_b = f"rls-b-{uuid4()}"
    own_insert = f"rls-own-{uuid4()}"
    cross_insert = f"rls-cross-{uuid4()}"
    workspace_a = 1_000_000 + uuid4().int % 1_000_000_000
    workspace_b = workspace_a + 1

    # Official PostgreSQL migrations include concurrent index creation, so
    # Alembic must control its own transaction and autocommit boundary.
    with engine.connect() as connection:
        _migrate_official(connection, root)

    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO users (workspace_id, id) VALUES "
                "(:workspace_a, :user_a), (:workspace_b, :user_b)"
            ),
            {
                "workspace_a": workspace_a,
                "workspace_b": workspace_b,
                "user_a": user_a,
                "user_b": user_b,
            },
        )
        install_runtime_rls(connection)
        connection.exec_driver_sql(
            (root / "saas/runtime_rls/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{_TEST_ROLE}') THEN
                    CREATE ROLE {_TEST_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$;
            ALTER ROLE {_TEST_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT;
            GRANT omnigent_runtime_app TO {_TEST_ROLE};
            """
        )
        verify_runtime_rls(connection)

        role_flags = connection.execute(
            sa.text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :role_name"),
            {"role_name": _TEST_ROLE},
        ).one()
        assert role_flags == (False, False)

        protected = connection.execute(
            sa.text(
                """
                SELECT count(*)
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_policy AS p ON p.polrelid = c.oid
                WHERE n.nspname = 'public'
                  AND p.polname = :policy_name
                  AND c.relrowsecurity
                  AND c.relforcerowsecurity
                """
            ),
            {"policy_name": RUNTIME_RLS_POLICY_NAME},
        ).scalar_one()
        assert protected == len(load_runtime_rls_contract())

    with engine.begin() as connection:
        _set_test_role(connection)
        connection.execute(
            sa.text("SELECT set_config('app.runtime_workspace_id', :workspace_id, true)"),
            {"workspace_id": str(workspace_a)},
        )
        assert connection.execute(sa.text("SELECT id FROM users")).scalars().all() == [user_a]
        connection.execute(
            sa.text("INSERT INTO users (workspace_id, id) VALUES (:workspace_id, :user_id)"),
            {"workspace_id": workspace_a, "user_id": own_insert},
        )

    with engine.begin() as connection:
        _set_test_role(connection)
        assert connection.execute(sa.text("SELECT count(*) FROM users")).scalar_one() == 0

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            _set_test_role(connection)
            connection.execute(
                sa.text("SELECT set_config('app.runtime_workspace_id', :workspace_id, true)"),
                {"workspace_id": str(workspace_a)},
            )
            connection.execute(
                sa.text("INSERT INTO users (workspace_id, id) VALUES (:workspace_id, :user_id)"),
                {"workspace_id": workspace_b, "user_id": cross_insert},
            )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            _set_test_role(connection)
            connection.exec_driver_sql("SET LOCAL row_security = off")
            connection.execute(sa.text("SELECT count(*) FROM users")).scalar_one()

    managed_session = make_managed_session_maker(engine)
    adapter = OmnigentStoreAdapter("0.2.0")

    def _list_users() -> list[str]:
        with managed_session() as session:
            _set_test_role(session)
            return list(session.execute(sa.text("SELECT id FROM users ORDER BY id")).scalars())

    assert adapter.invoke(_runtime(workspace_a), _list_users) == sorted([own_insert, user_a])
    assert adapter.invoke(_runtime(workspace_b), _list_users) == [user_b]

    with shared_read_scope():
        assert adapter.invoke(_runtime(workspace_a), _list_users) == sorted([own_insert, user_a])
        assert adapter.invoke(_runtime(workspace_b), _list_users) == [user_b]

    class ExpectedFailure(RuntimeError):
        pass

    def _fail_after_query() -> None:
        with managed_session() as session:
            _set_test_role(session)
            assert session.execute(sa.text("SELECT count(*) FROM users")).scalar_one() == 2
            raise ExpectedFailure

    with pytest.raises(ExpectedFailure):
        adapter.invoke(_runtime(workspace_a), _fail_after_query)

    with managed_session() as session:
        _set_test_role(session)
        assert session.execute(sa.text("SELECT count(*) FROM users")).scalar_one() == 0

    with engine.begin() as connection:
        remove_runtime_rls(connection)
        disabled = connection.execute(
            sa.text(
                """
                SELECT count(*)
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relname = ANY(:table_names)
                  AND (c.relrowsecurity OR c.relforcerowsecurity)
                """
            ),
            {"table_names": [item.table_name for item in load_runtime_rls_contract()]},
        ).scalar_one()
        assert disabled == 0
        install_runtime_rls(connection)

    engine.dispose()
