from __future__ import annotations

from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command

from tests.saas.test_casdoor_migration import _config
from tests.saas.test_credential_authority_migration import _historical_users

_HEAD = "cd3b00000001"
_PREDECESSOR = "cd3a00000001"
_FUNCTION = "public.saas_guard_credential_migration_receipt()"


def _receipt(connection, user_id, *, mode=None):
    identifier = uuid4()
    values = {
        "id": identifier if connection.dialect.name == "postgresql" else identifier.hex,
        "user_id": user_id if connection.dialect.name == "postgresql" else user_id.hex,
        "subject": str(user_id),
        "source_sha": sha256(b"retained-hash").hexdigest(),
    }
    extra_columns, extra_values = "", ""
    if mode is not None:
        values["mode"] = mode
        values["connection_id"] = connection.scalar(
            sa.text("SELECT id FROM saas_identity_connections WHERE user_id=:user_id"), values
        )
        extra_columns = ",mode,identity_connection_id,provider_snapshot_sha256"
        extra_values = ",:mode,:connection_id,'" + "f" * 64 + "'"
    connection.execute(
        sa.text(
            "INSERT INTO saas_credential_migration_receipts "
            "(id,user_id,batch_id,issuer,organization,provider_subject,provider_username,"
            "source_password_version,source_security_version,source_password_sha256,"
            "source_email_sha256,policy_sha256,idempotency_key,request_hash,status,"
            f"attempt_count,version{extra_columns}) "
            "VALUES (:id,:user_id,'historical-batch','https://auth.example.test','customers',"
            ":subject,'existing-customer',1,1,:source_sha,"
            "'" + "b" * 64 + "','" + "c" * 64 + "','" + "d" * 64 + "','" + "e" * 64 + "',"
            f"'pending',0,1{extra_values})"
        ),
        values,
    )
    return identifier


def test_historical_hash_receipt_survives_mode_expansion_and_downgrade():
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, _PREDECESSOR)
            user, _ = _historical_users(connection, native=False)
            receipt = _receipt(connection, user)
            before = dict(
                connection.execute(sa.text("SELECT * FROM saas_credential_migration_receipts"))
                .mappings()
                .one()
            )
            command.upgrade(config, _HEAD)
            assert (
                connection.scalar(sa.text("SELECT mode FROM saas_credential_migration_receipts"))
                == "hash_import"
            )
            command.upgrade(config, "head")
            command.check(config)
            command.downgrade(config, _HEAD)
            command.downgrade(config, _PREDECESSOR)
            after = dict(
                connection.execute(sa.text("SELECT * FROM saas_credential_migration_receipts"))
                .mappings()
                .one()
            )
            assert before == after and after["id"] == receipt.hex
    finally:
        engine.dispose()


def test_existing_link_evidence_prevents_mode_downgrade():
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, _HEAD)
            user, _ = _historical_users(connection, native=True)
            _receipt(connection, user, mode="existing_link")
            with pytest.raises(RuntimeError, match="existing identity cutover"):
                command.downgrade(config, _PREDECESSOR)
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version")) == _HEAD
            )
    finally:
        engine.dispose()


def test_non_bypass_owner_restores_exact_predecessor_guard_and_forced_rls(isolated_postgres_url):
    engine = sa.create_engine(isolated_postgres_url)
    owner = "linked_migration_" + uuid4().hex
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, _PREDECESSOR)
            user, _ = _historical_users(connection, native=False)
            _receipt(connection, user)
            original = connection.scalar(
                sa.text(f"SELECT prosrc FROM pg_proc WHERE oid='{_FUNCTION}'::regprocedure")
            )
            connection.exec_driver_sql(f'CREATE ROLE "{owner}" NOLOGIN NOSUPERUSER NOBYPASSRLS')
            connection.exec_driver_sql(f'GRANT USAGE,CREATE ON SCHEMA public TO "{owner}"')
            for table in connection.scalars(
                sa.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                    "AND tablename LIKE 'saas_%'"
                )
            ):
                connection.exec_driver_sql(f'ALTER TABLE public."{table}" OWNER TO "{owner}"')
            connection.exec_driver_sql(f'ALTER FUNCTION {_FUNCTION} OWNER TO "{owner}"')
            connection.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            assert not connection.scalar(
                sa.text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")
            )
            command.upgrade(config, _HEAD)
            changed = connection.scalar(
                sa.text(f"SELECT prosrc FROM pg_proc WHERE oid='{_FUNCTION}'::regprocedure")
            )
            assert changed != original and "NEW.mode" in changed
            from saas.production.postgresql_migration import (
                PostgreSqlMigrationError,
                _verify_credential_migration_guard,
            )

            _verify_credential_migration_guard(connection, saas_head=_HEAD, saas_owner=owner)
            definition = connection.scalar(
                sa.text(f"SELECT pg_get_functiondef('{_FUNCTION}'::regprocedure)")
            )
            connection.exec_driver_sql(
                "CREATE OR REPLACE FUNCTION public.saas_guard_credential_migration_receipt() "
                "RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog "
                "AS $tampered$ BEGIN RETURN NEW; END $tampered$"
            )
            with pytest.raises(PostgreSqlMigrationError, match="credential_receipt_guard_drifted"):
                _verify_credential_migration_guard(connection, saas_head=_HEAD, saas_owner=owner)
            connection.exec_driver_sql(definition)
            command.downgrade(config, _PREDECESSOR)
            _verify_credential_migration_guard(
                connection, saas_head=_PREDECESSOR, saas_owner=owner
            )
            assert (
                connection.scalar(
                    sa.text(f"SELECT prosrc FROM pg_proc WHERE oid='{_FUNCTION}'::regprocedure")
                )
                == original
            )
            assert tuple(
                connection.execute(
                    sa.text(
                        "SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                        "WHERE oid='saas_credential_migration_receipts'::regclass"
                    )
                ).one()
            ) == (True, True)
    finally:
        with engine.begin() as connection:
            if connection.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": owner}
            ):
                connection.exec_driver_sql(f'DROP OWNED BY "{owner}" CASCADE')
                connection.exec_driver_sql(f'DROP ROLE "{owner}"')
        engine.dispose()
