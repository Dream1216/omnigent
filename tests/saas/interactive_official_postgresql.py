"""Own an isolated official database without lending migration authority to serving code."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError

from omnigent.db.utils import get_or_create_engine
from saas.runtime_rls import install_runtime_rls, verify_runtime_rls
from tests.saas.test_production_runner_postgresql import _public_database_privileges
from tests.saas.test_runtime_postgresql_rls import _migrate_official


@contextmanager
def official_runtime_database(admin_engine, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    nonce = uuid4().hex
    database = f"litellm_runtime_{nonce}"
    owner, login = f"official_owner_{nonce}", f"runtime_login_{nonce}"
    password = uuid4().hex
    quote = admin_engine.dialect.identifier_preparer.quote
    created, roles, owner_engine, runtime_engine = False, [], None, None
    restore_public_connect = False
    try:
        with admin_engine.begin() as connection:
            restore_public_connect = "CONNECT" in _public_database_privileges(connection).get(
                admin_engine.url.database, frozenset()
            )
            connection.exec_driver_sql(
                f"REVOKE CONNECT ON DATABASE {quote(admin_engine.url.database)} FROM PUBLIC"
            )
            for name in (owner, login):
                connection.exec_driver_sql(
                    f"CREATE ROLE {quote(name)} LOGIN NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT "
                    f"CONNECTION LIMIT {8 if name == login else -1} PASSWORD '{password}'"
                )
                roles.append(name)
            connection.exec_driver_sql(
                f"GRANT omnigent_runtime_app TO {quote(login)} "
                "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            )
        with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            connection.exec_driver_sql(f"CREATE DATABASE {quote(database)} TEMPLATE template0")
            created = True
            connection.exec_driver_sql(
                f"REVOKE ALL PRIVILEGES ON DATABASE {quote(database)} FROM PUBLIC"
            )
            connection.exec_driver_sql(
                f"GRANT CONNECT, CREATE ON DATABASE {quote(database)} TO {quote(owner)}"
            )
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quote(database)} TO omnigent_runtime_app"
            )
        owner_engine = sa.create_engine(
            admin_engine.url.set(database=database, username=owner, password=password),
            pool_size=1,
            max_overflow=0,
            hide_parameters=True,
        )
        with sa.create_engine(
            admin_engine.url.set(database=database), poolclass=sa.pool.NullPool
        ).begin() as connection:
            connection.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            connection.exec_driver_sql(f"GRANT USAGE, CREATE ON SCHEMA public TO {quote(owner)}")
            connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO omnigent_runtime_app")
        with owner_engine.connect() as connection:
            _migrate_official(connection, root)
        with owner_engine.begin() as connection:
            install_runtime_rls(connection)
            connection.exec_driver_sql(
                (root / "saas/runtime_rls/postgresql_roles.sql").read_text()
            )
            verify_runtime_rls(connection)
        url = admin_engine.url.set(database=database, username=login, password=password)
        monkeypatch.setenv("OMNIGENT_DB_POOL_SIZE", "4")
        monkeypatch.setenv("OMNIGENT_DB_MAX_OVERFLOW", "4")
        runtime_engine = get_or_create_engine(url.render_as_string(hide_password=False))
        with runtime_engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT current_user=session_user,rolsuper,rolbypassrls,rolcreatedb,"
                "rolcreaterole,rolconnlimit FROM pg_roles WHERE rolname=current_user"
            ).one() == (True, False, False, False, False, 8)
            assert connection.exec_driver_sql(
                "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
            ).scalar_one()
            assert (
                connection.exec_driver_sql(
                    "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace "
                    "AND relrowsecurity AND relforcerowsecurity"
                ).scalar_one()
                == 19
            )
            assert (
                connection.execute(
                    sa.text("SELECT has_database_privilege(current_user,:name,'CONNECT')"),
                    {"name": admin_engine.url.database},
                ).scalar_one()
                is False
            )
            assert (
                connection.exec_driver_sql(
                    "SELECT has_schema_privilege(current_user,'public','CREATE')"
                ).scalar_one()
                is False
            )
        for statement in (
            "INSERT INTO users(workspace_id,id) VALUES (1,'missing-context')",
            "CREATE TABLE public.forbidden_runtime_ddl(id integer)",
            f"SET ROLE {quote(owner)}",
        ):
            try:
                with runtime_engine.begin() as connection:
                    connection.exec_driver_sql(statement)
            except DBAPIError as error:
                assert getattr(error.orig, "sqlstate", None) == "42501"
            else:
                raise AssertionError("official Runtime login authority widened")
        Path("/exchange/official-runtime-authority.json").write_text(
            json.dumps(
                {
                    "passed": True,
                    "backend": "postgresql",
                    "direct_runtime_login": True,
                    "tls_verified": True,
                    "force_rls_tables": 19,
                    "control_database_connect_denied": True,
                    "schema_create_denied": True,
                    "contextless_write_denied": True,
                    "owner_role_assumption_denied": True,
                }
            )
        )
        yield url.render_as_string(hide_password=False)
    finally:
        if runtime_engine is not None:
            runtime_engine.dispose()
        if owner_engine is not None:
            owner_engine.dispose()
        with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            if created:
                assert (
                    connection.execute(
                        sa.text(
                            "SELECT datname FROM pg_database WHERE datname=:name "
                            "AND datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)"
                        ),
                        {"name": database},
                    ).scalar_one()
                    == database
                )
                connection.exec_driver_sql(f"DROP DATABASE {quote(database)}")
            for role in reversed(roles):
                connection.exec_driver_sql(f"DROP ROLE {quote(role)}")
            if restore_public_connect:
                connection.exec_driver_sql(
                    f"GRANT CONNECT ON DATABASE {quote(admin_engine.url.database)} TO PUBLIC"
                )
