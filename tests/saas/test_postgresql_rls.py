from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for real RLS acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def test_real_postgresql_rls_denies_cross_tenant_and_missing_context() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    actor_a, actor_b, tenant_a, tenant_b, cross_tenant = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            "CREATE ROLE saas_rls_app_login NOLOGIN NOSUPERUSER NOBYPASSRLS"
        )
        connection.exec_driver_sql(
            "CREATE ROLE saas_rls_auth_login NOLOGIN NOSUPERUSER NOBYPASSRLS"
        )
        connection.exec_driver_sql(
            "CREATE ROLE saas_rls_dispatch_login NOLOGIN NOSUPERUSER NOBYPASSRLS"
        )
        connection.exec_driver_sql("GRANT saas_app TO saas_rls_app_login")
        connection.exec_driver_sql("GRANT saas_authenticator TO saas_rls_auth_login")
        connection.exec_driver_sql("GRANT saas_dispatcher TO saas_rls_dispatch_login")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:actor_a, 'active', 1), (:actor_b, 'active', 1)"
            ),
            {"actor_a": actor_a, "actor_b": actor_b},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:tenant_a, 'rls-a', 'RLS A', 'active', 'team', 'cn-east-1'), "
                "(:tenant_b, 'rls-b', 'RLS B', 'active', 'team', 'cn-east-1')"
            ),
            {"tenant_a": tenant_a, "tenant_b": tenant_b},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox "
                "(id, tenant_id, aggregate_type, aggregate_key, event_type, "
                "idempotency_key, request_hash, payload, attempt_count) VALUES "
                "(:id, :tenant_id, 'tenant', 'a', 'tenant.created', "
                "'rls-seed-event', :request_hash, CAST(:payload AS jsonb), 0)"
            ),
            {
                "id": uuid4(),
                "tenant_id": tenant_a,
                "request_hash": "a" * 64,
                "payload": "{}",
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_app_login")
        connection.execute(
            sa.text("SELECT set_config('app.actor_id', :value, true)"),
            {"value": str(actor_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        visible_tenants = set(connection.execute(sa.text("SELECT id FROM saas_tenants")).scalars())
        visible_users = set(
            connection.execute(sa.text("SELECT id FROM saas_global_users")).scalars()
        )
        assert visible_tenants == {tenant_a}
        assert visible_users == {actor_a}

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_app_login")
        assert connection.execute(sa.text("SELECT count(*) FROM saas_tenants")).scalar_one() == 0
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_global_users")).scalar_one() == 0
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET ROLE saas_rls_app_login")
            connection.execute(
                sa.text("SELECT set_config('app.actor_id', :value, true)"),
                {"value": str(actor_a)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.tenant_id', :value, true)"),
                {"value": str(tenant_a)},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenants "
                    "(id, slug, name, status, plan, home_region) VALUES "
                    "(:id, 'cross-tenant', 'Cross Tenant', 'active', 'team', 'cn-east-1')"
                ),
                {"id": cross_tenant},
            )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_auth_login")
        visible_user_count = connection.execute(
            sa.text("SELECT count(*) FROM saas_global_users")
        ).scalar_one()
        assert visible_user_count == 2

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_dispatch_login")
        event_id = connection.execute(
            sa.text("SELECT id FROM saas_control_plane_outbox")
        ).scalar_one()
        result = connection.execute(
            sa.text("UPDATE saas_control_plane_outbox SET published_at = now() WHERE id = :id"),
            {"id": event_id},
        )
        assert result.rowcount == 1

    engine.dispose()
