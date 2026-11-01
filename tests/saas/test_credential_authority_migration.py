from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command

from tests.saas.test_casdoor_migration import _config


def _historical_users(connection: sa.Connection, *, native: bool):
    legacy, external = uuid4(), uuid4()
    for user_id in (legacy, external):
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id,status,security_version) "
                "VALUES (:id,'active',1)"
            ),
            {"id": user_id if connection.dialect.name == "postgresql" else user_id.hex},
        )
    connection.execute(
        sa.text(
            "INSERT INTO saas_password_credentials "
            "(user_id,login_email_normalized,password_hash,password_version,failed_attempts) "
            "VALUES (:user,'legacy@example.test','retained-hash',1,0)"
        ),
        {"user": legacy if connection.dialect.name == "postgresql" else legacy.hex},
    )
    if native:
        for user_id in (legacy, external):
            connection.execute(
                sa.text(
                    "INSERT INTO saas_identity_connections "
                    "(id,user_id,provider,issuer,subject,email_verified,status) "
                    "VALUES (:id,:user,'casdoor','https://auth.example.test',:subject,true,'active')"
                ),
                {
                    "id": uuid4() if connection.dialect.name == "postgresql" else uuid4().hex,
                    "user": user_id if connection.dialect.name == "postgresql" else user_id.hex,
                    "subject": str(user_id),
                },
            )
    return legacy, external


def test_sqlite_credential_authority_backfill_preserves_legacy_and_native_accounts():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _config(connection)
        command.upgrade(config, "cd2a00000001")
        legacy, native = _historical_users(connection, native=True)
        command.upgrade(config, "head")
        rows = {
            str(row.id).replace("-", ""): (row.credential_owner, row.migration_state)
            for row in connection.execute(
                sa.text("SELECT id,credential_owner,migration_state FROM saas_global_users")
            )
        }
        assert rows == {legacy.hex: ("legacy", "legacy"), native.hex: ("casdoor", "native")}
        assert (
            connection.scalar(sa.text("SELECT password_hash FROM saas_password_credentials"))
            == "retained-hash"
        )
        command.check(config)
        with pytest.raises(RuntimeError, match="matched identity recovery set"):
            command.downgrade(config, "cd2a00000001")
    engine.dispose()


def test_legacy_only_expansion_can_be_rolled_back_without_changing_user_ids():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _config(connection)
        command.upgrade(config, "cd2a00000001")
        ids = _historical_users(connection, native=False)
        command.upgrade(config, "head")
        command.downgrade(config, "cd2a00000001")
        assert set(connection.scalars(sa.text("SELECT id FROM saas_global_users"))) == {
            user.hex for user in ids
        }
        assert not {"credential_owner", "migration_state"} & {
            column["name"] for column in sa.inspect(connection).get_columns("saas_global_users")
        }
    engine.dispose()


@pytest.mark.parametrize("native", [False, True], ids=["legacy-only", "native-authority"])
def test_non_bypass_owner_backfills_and_cannot_drop_retained_credential_authority(
    isolated_postgres_url: str,
    native: bool,
):
    engine = sa.create_engine(isolated_postgres_url)
    owner = "credential_owner_" + uuid4().hex
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, "cd2a00000001")
            rate_sources = dict(
                connection.execute(
                    sa.text(
                        "SELECT proname,prosrc FROM pg_proc "
                        "WHERE pronamespace='public'::regnamespace "
                        "AND proname IN ('saas_consume_registration_rate_limit',"
                        "'saas_prune_registration_rate_limits')"
                    )
                ).all()
            )
            assert rate_sources
            _historical_users(connection, native=native)
            connection.exec_driver_sql(f'CREATE ROLE "{owner}" NOLOGIN NOSUPERUSER NOBYPASSRLS')
            connection.exec_driver_sql(f'GRANT USAGE, CREATE ON SCHEMA public TO "{owner}"')
            tables = list(
                connection.scalars(
                    sa.text(
                        "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                        "AND tablename LIKE 'saas_%'"
                    )
                )
            )
            for table in tables:
                connection.exec_driver_sql(f'ALTER TABLE public."{table}" OWNER TO "{owner}"')
            connection.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            assert not connection.scalar(
                sa.text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")
            )
            command.upgrade(config, "head")
            assert (
                dict(
                    connection.execute(
                        sa.text(
                            "SELECT proname,prosrc FROM pg_proc "
                            "WHERE pronamespace='public'::regnamespace "
                            "AND proname IN ('saas_consume_registration_rate_limit',"
                            "'saas_prune_registration_rate_limits')"
                        )
                    ).all()
                )
                == rate_sources
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM pg_policy WHERE polname LIKE 'credential_backfill_%'"
                    )
                )
                == 0
            )
            if native:
                assert (
                    connection.scalar(
                        sa.text(
                            "SELECT count(*) FROM saas_global_users "
                            "WHERE credential_owner='casdoor'"
                        )
                    )
                    == 1
                )
                with pytest.raises(RuntimeError, match="matched identity recovery set"):
                    command.downgrade(config, "cd2a00000001")
                assert tuple(
                    connection.execute(
                        sa.text(
                            "SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                            "WHERE oid='saas_credential_migration_receipts'::regclass"
                        )
                    ).one()
                ) == (True, True)
            else:
                command.downgrade(config, "cd2a00000001")
                assert (
                    connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                    == "cd2a00000001"
                )
    finally:
        with engine.begin() as connection:
            if connection.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": owner}
            ):
                connection.exec_driver_sql(f'DROP OWNED BY "{owner}" CASCADE')
                connection.exec_driver_sql(f'DROP ROLE "{owner}"')
        engine.dispose()


def test_receipt_authority_has_no_principal_ddl():
    root = Path(__file__).resolve().parents[2]
    source = (
        root / "saas/control_plane/migrations/versions/cd3a00000001_credential_authority.py"
    ).read_text()
    assert "CREATE ROLE" not in source and "BYPASSRLS" not in source
    assert "NO FORCE ROW LEVEL SECURITY" not in source
