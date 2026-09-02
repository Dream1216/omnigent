from __future__ import annotations

from collections.abc import Iterator
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


@pytest.fixture
def production_runtime_engines(
    isolated_postgres_url: str,
) -> Iterator[tuple[sa.Engine, sa.Engine]]:
    """Create direct official-owner and runtime-login engines for one database.

    The Runtime ACL script intentionally rejects superusers and assumed roles.
    This fixture therefore preserves the production authority boundary instead
    of using ``SET ROLE`` from the test administrator.
    """

    nonce = uuid4().hex[:16]
    official_owner = f"official_owner_{nonce}"
    runtime_login = f"runtime_login_{nonce}"
    password = f"test-{uuid4().hex}"
    admin = sa.create_engine(isolated_postgres_url, pool_size=1, max_overflow=0)
    base_url = sa.engine.make_url(isolated_postgres_url)
    quote = admin.dialect.identifier_preparer.quote
    with admin.begin() as connection:
        if int(connection.exec_driver_sql("SHOW server_version_num").scalar_one()) < 160000:
            pytest.skip("production runtime authority acceptance requires PostgreSQL 16+")
        connection.exec_driver_sql(
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'omnigent_runtime_app') "
            "THEN CREATE ROLE omnigent_runtime_app; END IF; END $$"
        )
        connection.exec_driver_sql(
            "ALTER ROLE omnigent_runtime_app NOLOGIN NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT -1"
        )
        connection.exec_driver_sql("ALTER ROLE omnigent_runtime_app RESET ALL")
        connection.exec_driver_sql(
            f"CREATE ROLE {quote(official_owner)} LOGIN NOSUPERUSER NOCREATEDB "
            f"NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT PASSWORD '{password}'"
        )
        connection.exec_driver_sql(
            f"CREATE ROLE {quote(runtime_login)} LOGIN NOSUPERUSER NOCREATEDB "
            f"NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT PASSWORD '{password}'"
        )
        connection.exec_driver_sql(
            f"GRANT USAGE, CREATE ON SCHEMA public TO {quote(official_owner)}"
        )
        connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO omnigent_runtime_app")
        database_name = connection.exec_driver_sql("SELECT current_database()").scalar_one()
        connection.exec_driver_sql(
            f"GRANT CONNECT ON DATABASE {quote(database_name)} TO "
            f"{quote(official_owner)}, omnigent_runtime_app"
        )
        connection.exec_driver_sql(
            f"GRANT CREATE ON DATABASE {quote(database_name)} TO {quote(official_owner)}"
        )
        connection.exec_driver_sql(
            f"GRANT omnigent_runtime_app TO {quote(runtime_login)} "
            "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
        )

    owner_engine = sa.create_engine(
        base_url.set(username=official_owner, password=password),
        pool_size=1,
        max_overflow=0,
    )
    runtime_engine = sa.create_engine(
        base_url.set(username=runtime_login, password=password),
        pool_size=1,
        max_overflow=0,
    )
    try:
        yield owner_engine, runtime_engine
    finally:
        runtime_engine.dispose()
        owner_engine.dispose()
        with admin.begin() as connection:
            administrator = connection.exec_driver_sql("SELECT current_user").scalar_one()
            connection.exec_driver_sql(
                f"REVOKE CONNECT ON DATABASE {quote(database_name)} FROM omnigent_runtime_app"
            )
            connection.exec_driver_sql(
                f"REASSIGN OWNED BY {quote(official_owner)} TO {quote(administrator)}"
            )
            connection.exec_driver_sql(f"DROP OWNED BY {quote(official_owner)}")
            connection.exec_driver_sql(f"REVOKE omnigent_runtime_app FROM {quote(runtime_login)}")
            connection.exec_driver_sql(f"DROP ROLE {quote(runtime_login)}")
            connection.exec_driver_sql(f"DROP ROLE {quote(official_owner)}")
        admin.dispose()


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


def test_real_postgresql_runtime_rls_and_store_adapter_context(
    production_runtime_engines: tuple[sa.Engine, sa.Engine],
) -> None:
    root = Path(__file__).resolve().parents[2]
    owner_engine, runtime_engine = production_runtime_engines
    user_a = f"rls-a-{uuid4()}"
    user_b = f"rls-b-{uuid4()}"
    own_insert = f"rls-own-{uuid4()}"
    cross_insert = f"rls-cross-{uuid4()}"
    workspace_a = 1_000_000 + uuid4().int % 1_000_000_000
    workspace_b = workspace_a + 1

    # Official PostgreSQL migrations include concurrent index creation, so
    # Alembic must control its own transaction and autocommit boundary.
    with owner_engine.connect() as connection:
        _migrate_official(connection, root)

    with owner_engine.begin() as connection:
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
        verify_runtime_rls(connection)

        with runtime_engine.connect() as runtime_connection:
            role_flags = runtime_connection.execute(
                sa.text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
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

    with runtime_engine.begin() as connection:
        connection.execute(
            sa.text("SELECT set_config('app.runtime_workspace_id', :workspace_id, true)"),
            {"workspace_id": str(workspace_a)},
        )
        assert connection.execute(sa.text("SELECT id FROM users")).scalars().all() == [user_a]
        connection.execute(
            sa.text("INSERT INTO users (workspace_id, id) VALUES (:workspace_id, :user_id)"),
            {"workspace_id": workspace_a, "user_id": own_insert},
        )

    with runtime_engine.begin() as connection:
        assert connection.execute(sa.text("SELECT count(*) FROM users")).scalar_one() == 0

    with pytest.raises(DBAPIError):
        with runtime_engine.begin() as connection:
            connection.execute(
                sa.text("SELECT set_config('app.runtime_workspace_id', :workspace_id, true)"),
                {"workspace_id": str(workspace_a)},
            )
            connection.execute(
                sa.text("INSERT INTO users (workspace_id, id) VALUES (:workspace_id, :user_id)"),
                {"workspace_id": workspace_b, "user_id": cross_insert},
            )

    with pytest.raises(DBAPIError):
        with runtime_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL row_security = off")
            connection.execute(sa.text("SELECT count(*) FROM users")).scalar_one()

    managed_session = make_managed_session_maker(runtime_engine)
    adapter = OmnigentStoreAdapter("0.2.0")

    def _list_users() -> list[str]:
        with managed_session() as session:
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
            assert session.execute(sa.text("SELECT count(*) FROM users")).scalar_one() == 2
            raise ExpectedFailure

    with pytest.raises(ExpectedFailure):
        adapter.invoke(_runtime(workspace_a), _fail_after_query)

    with managed_session() as session:
        assert session.execute(sa.text("SELECT count(*) FROM users")).scalar_one() == 0

    with owner_engine.begin() as connection:
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
