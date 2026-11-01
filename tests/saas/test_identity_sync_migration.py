from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command

from saas.control_plane import IdentityEventInboxRecord, IdentityProviderStateRecord
from tests.saas.test_casdoor_migration import _config
from tests.saas.test_credential_authority_migration import _historical_users

_HEAD = "cd4a00000001"
_PREDECESSOR = "cd3b00000001"
_TABLES = ("saas_identity_event_inbox", "saas_identity_provider_states")


def _seed(connection):
    users = _historical_users(connection, native=True)
    identity = connection.scalar(sa.text("SELECT id FROM saas_identity_connections LIMIT 1"))
    return users, identity


def _event():
    return {
        "id": uuid4(),
        "provider": "casdoor",
        "issuer": "https://auth.example.test",
        "organization": "customers",
        "event_id": "retained-source-record",
        "action": "set-password",
        "security_event": True,
        "username_locator_sha256": "a" * 64,
        "request_sha256": "b" * 64,
        "occurred_at": datetime(2026, 10, 13, tzinfo=timezone.utc),
    }


def test_empty_extension_preserves_existing_identities_and_matches_unfiltered_metadata():
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = _config(connection)
            command.upgrade(cfg, _PREDECESSOR)
            users, _identity = _seed(connection)
            before = connection.execute(
                sa.text("SELECT * FROM saas_identity_connections ORDER BY id")
            ).all()
            command.upgrade(cfg, _HEAD)
            command.check(cfg)
            assert (
                connection.execute(
                    sa.text("SELECT * FROM saas_identity_connections ORDER BY id")
                ).all()
                == before
            )
            assert all(
                connection.scalar(sa.text("SELECT count(*) FROM " + table)) == 0
                for table in _TABLES
            )
            command.downgrade(cfg, _PREDECESSOR)
            assert not set(_TABLES) & set(sa.inspect(connection).get_table_names())
            assert set(connection.scalars(sa.text("SELECT id FROM saas_global_users"))) == {
                u.hex for u in users
            }
    finally:
        engine.dispose()


@pytest.mark.parametrize("table", _TABLES)
def test_retained_inbox_or_provider_state_requires_application_rollback(table):
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            cfg = _config(connection)
            command.upgrade(cfg, _HEAD)
            _users, identity = _seed(connection)
            if table == _TABLES[0]:
                connection.execute(sa.insert(IdentityEventInboxRecord), _event())
            else:
                connection.execute(
                    sa.insert(IdentityProviderStateRecord),
                    {"connection_id": UUID(identity), "subject_locator_sha256": "c" * 64},
                )
            with pytest.raises(RuntimeError, match="application-only rollback"):
                command.downgrade(cfg, _PREDECESSOR)
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version")) == _HEAD
            )
            assert connection.scalar(sa.text("SELECT count(*) FROM " + table)) == 1
    finally:
        engine.dispose()


@pytest.mark.parametrize("retained", [False, True])
def test_non_bypass_owner_expands_forced_rls_and_reads_retained_state_before_rollback(
    isolated_postgres_url, retained
):
    engine = sa.create_engine(isolated_postgres_url)
    owner = "identity_sync_owner_" + uuid4().hex
    try:
        with engine.begin() as connection:
            cfg = _config(connection)
            command.upgrade(cfg, _PREDECESSOR)
            _users, identity = _seed(connection)
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
            command.upgrade(cfg, _HEAD)
            rows = connection.execute(
                sa.text(
                    "SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class "
                    "WHERE relname=ANY(:tables) ORDER BY relname"
                ),
                {"tables": list(_TABLES)},
            ).all()
            assert len(rows) == 2 and all(row[1:] == (True, True) for row in rows)
        if retained:
            with engine.begin() as connection:
                connection.execute(
                    sa.insert(IdentityProviderStateRecord),
                    {"connection_id": identity, "subject_locator_sha256": "c" * 64},
                )
        with engine.begin() as connection:
            connection.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            if retained:
                with pytest.raises(RuntimeError, match="application-only rollback"):
                    command.downgrade(_config(connection), _PREDECESSOR)
            else:
                command.downgrade(_config(connection), _PREDECESSOR)
    finally:
        with engine.begin() as connection:
            if connection.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": owner}
            ):
                connection.exec_driver_sql(f'DROP OWNED BY "{owner}" CASCADE')
                connection.exec_driver_sql(f'DROP ROLE "{owner}"')
        engine.dispose()


def test_authenticator_can_only_update_worker_fields_and_other_services_have_no_inbox_authority(
    isolated_postgres_url,
):
    from pathlib import Path

    engine = sa.create_engine(isolated_postgres_url)
    event = _event()
    try:
        with engine.begin() as connection:
            command.upgrade(_config(connection), _HEAD)
            connection.exec_driver_sql(
                (
                    Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
                ).read_text()
            )
            _users, identity = _seed(connection)
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_authenticator")
            assert not connection.scalar(
                sa.text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")
            )
            connection.execute(sa.insert(IdentityEventInboxRecord), event)
            connection.execute(
                sa.insert(IdentityProviderStateRecord),
                {"connection_id": identity, "subject_locator_sha256": "c" * 64},
            )
            connection.execute(
                sa.update(IdentityEventInboxRecord)
                .where(IdentityEventInboxRecord.id == event["id"])
                .values(status="retry", attempt_count=1)
            )
            assert (
                connection.scalar(
                    sa.select(IdentityEventInboxRecord.attempt_count).where(
                        IdentityEventInboxRecord.id == event["id"]
                    )
                )
                == 1
            )
        for operation in [
            "UPDATE saas_identity_event_inbox SET event_id='rewritten'",
            "UPDATE saas_identity_event_inbox SET request_sha256=repeat('e',64)",
            "UPDATE saas_identity_provider_states SET subject_locator_sha256=repeat('e',64)",
            "DELETE FROM saas_identity_event_inbox",
            "DELETE FROM saas_identity_provider_states",
        ]:
            with pytest.raises(sa.exc.ProgrammingError):
                with engine.begin() as connection:
                    connection.exec_driver_sql("SET LOCAL ROLE saas_authenticator")
                    connection.exec_driver_sql(operation)
        for role in ["saas_app", "saas_registration", "saas_governance"]:
            with pytest.raises(sa.exc.ProgrammingError):
                with engine.begin() as connection:
                    connection.exec_driver_sql("SET LOCAL ROLE " + role)
                    connection.exec_driver_sql("SELECT * FROM saas_identity_event_inbox")
    finally:
        engine.dispose()
