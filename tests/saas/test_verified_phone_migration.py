from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command

from tests.saas.test_casdoor_migration import _config
from tests.saas.test_credential_authority_migration import _historical_users


def test_phone_extension_matches_metadata_without_inferred_legacy_verification():
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, "cd4a00000001")
            _historical_users(connection, native=True)
            before = connection.execute(
                sa.text(
                    "SELECT id,user_id,issuer,subject,email_verified "
                    "FROM saas_identity_connections ORDER BY id"
                )
            ).all()
            command.upgrade(config, "head")
            command.check(config)
            assert (
                connection.execute(
                    sa.text(
                        "SELECT id,user_id,issuer,subject,email_verified "
                        "FROM saas_identity_connections ORDER BY id"
                    )
                ).all()
                == before
            )
            assert (
                connection.execute(
                    sa.text("SELECT phone_e164,phone_verified FROM saas_identity_connections")
                ).all()
                == [(None, False)] * 2
            )
            command.downgrade(config, "cd4a00000001")
            assert "phone_e164" not in {
                c["name"] for c in sa.inspect(connection).get_columns("saas_identity_connections")
            }
    finally:
        engine.dispose()


def test_retained_phone_proof_blocks_destructive_downgrade():
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, "head")
            _historical_users(connection, native=True)
            connection.execute(
                sa.text(
                    "UPDATE saas_identity_connections "
                    "SET phone_e164='+12025550100',phone_verified=true"
                )
            )
            with pytest.raises(RuntimeError, match="application-only rollback"):
                command.downgrade(config, "cd4a00000001")
            assert (
                connection.scalar(
                    sa.text("SELECT count(*) FROM saas_identity_connections WHERE phone_verified")
                )
                == 2
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize("retained", [False, True])
def test_non_bypass_owner_checks_phone_data_under_forced_rls_before_downgrade(
    isolated_postgres_url, retained
):
    engine = sa.create_engine(isolated_postgres_url)
    owner = "verified_phone_owner_" + uuid4().hex
    try:
        with engine.begin() as connection:
            command.upgrade(_config(connection), "cd4a00000001")
            _historical_users(connection, native=True)
            connection.exec_driver_sql(f'CREATE ROLE "{owner}" NOLOGIN NOSUPERUSER NOBYPASSRLS')
            connection.exec_driver_sql(f'GRANT USAGE,CREATE ON SCHEMA public TO "{owner}"')
            for table in connection.scalars(
                sa.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                    "AND tablename LIKE 'saas_%'"
                )
            ):
                connection.exec_driver_sql(f'ALTER TABLE public."{table}" OWNER TO "{owner}"')
            connection.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            assert not connection.scalar(
                sa.text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")
            )
            command.upgrade(_config(connection), "head")
            assert connection.execute(
                sa.text(
                    "SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                    "WHERE oid='public.saas_identity_connections'::regclass"
                )
            ).one() == (True, True)
        if retained:
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "UPDATE saas_identity_connections "
                    "SET phone_e164='+12025550100',phone_verified=true"
                )
        with engine.begin() as connection:
            connection.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            if retained:
                with pytest.raises(RuntimeError, match="application-only rollback"):
                    command.downgrade(_config(connection), "cd4a00000001")
                assert (
                    connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                    == "cd4b00000001"
                )
                assert not connection.scalar(
                    sa.text(
                        "SELECT 1 FROM pg_policies WHERE schemaname='public' "
                        "AND policyname='rls_phone_rollback_owner_read'"
                    )
                )
            else:
                command.downgrade(_config(connection), "cd4a00000001")
                assert "phone_e164" not in {
                    c["name"]
                    for c in sa.inspect(connection).get_columns("saas_identity_connections")
                }
    finally:
        with engine.begin() as connection:
            if connection.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": owner}
            ):
                connection.exec_driver_sql(f'DROP OWNED BY "{owner}" CASCADE')
                connection.exec_driver_sql(f'DROP ROLE "{owner}"')
        engine.dispose()


def test_phone_authority_preserves_narrow_legacy_registration_and_privacy_erasure(
    isolated_postgres_url,
):
    engine = sa.create_engine(isolated_postgres_url)
    try:
        with engine.begin() as connection:
            command.upgrade(_config(connection), "head")
            connection.exec_driver_sql(
                (
                    Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
                ).read_text()
            )
            _historical_users(connection, native=True)
            connection.exec_driver_sql(
                "UPDATE saas_identity_connections "
                "SET phone_e164='+12025550100',phone_verified=true"
            )
            for column in ("phone_e164", "phone_verified"):
                assert not connection.scalar(
                    sa.text(
                        "SELECT has_column_privilege('saas_registration', "
                        "'saas_identity_connections', :column, 'INSERT,SELECT,UPDATE')"
                    ),
                    {"column": column},
                )
                assert connection.scalar(
                    sa.text(
                        "SELECT has_column_privilege('saas_privacy_executor', "
                        "'saas_identity_connections', :column, 'UPDATE')"
                    ),
                    {"column": column},
                )
            # The restrictive erasure policy still applies when another permissive
            # policy authorizes an identity selected by the privacy workflow.
            connection.exec_driver_sql(
                "CREATE POLICY test_privacy_target ON saas_identity_connections "
                "TO saas_privacy_executor USING (true) WITH CHECK (true)"
            )
        for operation in (
            "UPDATE saas_identity_connections SET phone_e164='+12025550101'",
            "UPDATE saas_identity_connections SET phone_verified=false",
            "UPDATE saas_identity_connections SET phone_e164=NULL",
        ):
            with pytest.raises(sa.exc.DBAPIError):
                with engine.begin() as connection:
                    connection.exec_driver_sql("SET LOCAL ROLE saas_privacy_executor")
                    connection.exec_driver_sql(operation)
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_privacy_executor")
            result = connection.exec_driver_sql(
                "UPDATE saas_identity_connections SET phone_e164=NULL,phone_verified=false"
            )
            assert result.rowcount == 2
        with engine.connect() as connection:
            assert (
                connection.execute(
                    sa.text("SELECT phone_e164,phone_verified FROM saas_identity_connections")
                ).all()
                == [(None, False)] * 2
            )
    finally:
        engine.dispose()
