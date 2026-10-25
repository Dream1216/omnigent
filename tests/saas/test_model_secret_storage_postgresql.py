from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command

from tests.saas.test_model_secret_storage_migration import (
    _config,
    _legacy_credential,
    _old_database,
    _oversize_refusal,
    _raw,
    _roundtrip,
)


@pytest.mark.parametrize(
    "ciphertext", [None, "x" * 16376, "密" * 5458], ids=["opaque", "max-bytes", "utf8"]
)
def test_real_postgresql_ciphertext_roundtrip(isolated_postgres_url, ciphertext):
    engine = sa.create_engine(isolated_postgres_url)
    try:
        _roundtrip(engine, ciphertext)
    finally:
        engine.dispose()


def test_real_postgresql_oversized_secret_refuses_atomically(isolated_postgres_url):
    engine = sa.create_engine(isolated_postgres_url)
    try:
        _oversize_refusal(engine)
    finally:
        engine.dispose()


def _authority(connection):
    return (
        connection.exec_driver_sql(
            "SELECT relrowsecurity,relforcerowsecurity,relacl::text,relowner::bigint "
            "FROM pg_class WHERE oid='saas_model_credential_versions'::regclass"
        ).one(),
        connection.exec_driver_sql(
            "SELECT policyname,roles::text,cmd,qual,with_check FROM pg_policies "
            "WHERE schemaname='public' AND tablename='saas_model_credential_versions' "
            "ORDER BY policyname"
        ).all(),
    )


def test_real_postgresql_storage_change_preserves_rls_owner_and_grants(isolated_postgres_url):
    engine = sa.create_engine(isolated_postgres_url)
    try:
        _service, _factory, actor, cipher, _client, _headers = _old_database(engine)
        _legacy_credential(engine, actor, cipher)
        with engine.begin() as connection:
            before = _authority(connection)
            assert before[0].relrowsecurity and before[0].relforcerowsecurity
            command.upgrade(_config(connection), "lm2p00000001")
            assert _authority(connection) == before
            command.downgrade(_config(connection), "lm2o00000001")
            assert _authority(connection) == before
    finally:
        engine.dispose()


@pytest.mark.parametrize("drift", ["spoofed_head", "weakened_bound"])
def test_real_postgresql_role_projection_rejects_inexact_storage_contract(
    isolated_postgres_url, drift
):
    engine = sa.create_engine(isolated_postgres_url)
    try:
        _old_database(engine)
        with pytest.raises(
            sa.exc.DBAPIError, match="model secret storage object contract rejected"
        ):
            with engine.begin() as connection:
                if drift == "spoofed_head":
                    connection.exec_driver_sql(
                        "UPDATE saas_alembic_version SET version_num='lm2p00000001'"
                    )
                else:
                    command.upgrade(_config(connection), "lm2p00000001")
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_model_credential_versions "
                        "DROP CONSTRAINT ck_model_credential_ciphertext"
                    )
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_model_credential_versions "
                        "ADD CONSTRAINT ck_model_credential_ciphertext "
                        "CHECK (length(api_key_ciphertext) BETWEEN 8 AND 16384)"
                    )
                connection.exec_driver_sql(
                    (
                        Path(__file__).resolve().parents[2]
                        / "saas/control_plane/postgresql_roles.sql"
                    ).read_text()
                )
        with engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar_one()
                == "lm2o00000001"
            )
    finally:
        engine.dispose()


def test_real_postgresql_direct_nobypass_owner_migrates_without_reading_hidden_secrets(
    isolated_postgres_url,
):
    engine = sa.create_engine(isolated_postgres_url)
    owner = "secret_migration_owner_" + uuid4().hex[:12]
    restricted, created = None, False
    try:
        _service, _factory, actor, cipher, _client, _headers = _old_database(engine)
        _identifier, original = _legacy_credential(engine, actor, cipher)
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {owner} LOGIN PASSWORD 'isolated-migration-owner-only' "
                "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT"
            )
            created = True
            database = connection.exec_driver_sql("SELECT current_database()").scalar_one()
            assert database.startswith("omnigent_isolated_")
            quoted_database = connection.dialect.identifier_preparer.quote(database)
            connection.exec_driver_sql(f"GRANT CONNECT ON DATABASE {quoted_database} TO {owner}")
            connection.exec_driver_sql(f"GRANT USAGE,CREATE ON SCHEMA public TO {owner}")
            connection.exec_driver_sql(f"GRANT SELECT ON saas_alembic_version TO {owner}")
            connection.exec_driver_sql(
                f"GRANT UPDATE(version_num) ON saas_alembic_version TO {owner}"
            )
            connection.exec_driver_sql(
                f"ALTER TABLE saas_model_credential_versions OWNER TO {owner}"
            )
        restricted = sa.create_engine(
            engine.url.set(username=owner, password="isolated-migration-owner-only")
        )
        with restricted.begin() as connection:
            assert connection.exec_driver_sql("SELECT current_user=session_user").scalar_one()
            assert connection.exec_driver_sql(
                "SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole "
                "FROM pg_roles WHERE rolname=current_user"
            ).scalar_one()
            assert (
                connection.exec_driver_sql(
                    "SELECT count(*) FROM saas_model_credential_versions"
                ).scalar_one()
                == 0
            )
            before = _authority(connection)
            command.upgrade(_config(connection), "lm2p00000001")
            assert _authority(connection) == before
            assert (
                connection.exec_driver_sql(
                    "SELECT count(*) FROM saas_model_credential_versions"
                ).scalar_one()
                == 0
            )
        with engine.connect() as connection:
            assert _raw(connection) == b"OGSM\x01\x01\x01" + original.encode()
        with restricted.begin() as connection:
            command.downgrade(_config(connection), "lm2o00000001")
            assert _authority(connection) == before
        with engine.connect() as connection:
            assert _raw(connection) == original
    finally:
        if restricted is not None:
            restricted.dispose()
        if created:
            with engine.begin() as connection:
                connection.exec_driver_sql(f"REASSIGN OWNED BY {owner} TO postgres")
                connection.exec_driver_sql(f"DROP OWNED BY {owner}")
                connection.exec_driver_sql(f"DROP ROLE {owner}")
        engine.dispose()
