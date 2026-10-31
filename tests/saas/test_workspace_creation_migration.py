from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command

from saas.control_plane.db_models import GlobalUser
from saas.control_plane.onboarding import OnboardingPlan
from saas.control_plane.onboarding_models import SelfServiceRegistrationRecord
from tests.saas.test_casdoor_migration import _config


def _history(connection: sa.Connection, *, verified: bool = True) -> UUID:
    now = datetime.now(timezone.utc)
    user_id, registration_id = uuid4(), uuid4()
    if verified:
        connection.execute(
            sa.insert(GlobalUser).values(id=user_id, status="active", security_version=1)
        )
    plan = OnboardingPlan("starter", "workspace-migration-v1", 14)
    connection.execute(
        sa.insert(SelfServiceRegistrationRecord).values(
            id=registration_id,
            user_id=user_id,
            email_normalized=f"{registration_id}@example.test",
            email_hash=sha256(registration_id.bytes).hexdigest(),
            tenant_name="Retained tenant",
            tenant_slug=f"retained-{registration_id.hex}",
            default_space_name="Default",
            default_space_slug="default",
            plan_key=plan.key,
            plan_policy_revision=plan.policy_revision,
            home_region="cn-east-1",
            status="verified" if verified else "pending_verification",
            verified_at=now if verified else None,
            terminal_at=now if verified else None,
            expires_at=now + timedelta(hours=1),
            plan_snapshot=plan.snapshot(),
            plan_snapshot_hash=plan.snapshot_hash(),
            idempotency_key=sha256(b"key" + registration_id.bytes).hexdigest(),
            request_hash=sha256(b"request" + registration_id.bytes).hexdigest(),
            created_at=now,
            updated_at=now,
        )
    )
    return registration_id


def test_intent_expansion_backfills_only_authenticated_history_and_refuses_lossy_downgrade():
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, "cd1c00000001")
            verified = _history(connection)
            pending = _history(connection, verified=False)
            command.upgrade(config, "head")
            rows = (
                connection.execute(
                    sa.text(
                        "SELECT id, registration_id, source, status, user_id, tenant_id, "
                        "onboarding_id, "
                        "plan_snapshot_hash FROM saas_tenant_creation_intents"
                    )
                )
                .mappings()
                .all()
            )
            assert len(rows) == 1 and UUID(rows[0]["id"]) == verified
            assert rows[0]["source"] == "registration" and rows[0]["status"] == "ready"
            assert UUID(rows[0]["registration_id"]) != pending
            legacy = connection.execute(
                sa.text(
                    "SELECT user_id, tenant_id, onboarding_id, plan_snapshot_hash "
                    "FROM saas_self_service_registrations WHERE id=:id"
                ),
                {"id": verified.hex},
            ).one()
            assert tuple(
                rows[0][k] for k in ("user_id", "tenant_id", "onboarding_id", "plan_snapshot_hash")
            ) == tuple(legacy)
            assert not any(
                c.get("column_names") == ["user_id"]
                for c in sa.inspect(connection).get_unique_constraints(
                    "saas_tenant_creation_intents"
                )
            )
            with pytest.raises(RuntimeError, match="application-only rollback"):
                command.downgrade(config, "cd1c00000001")
    finally:
        engine.dispose()


def test_empty_intent_expansion_can_be_removed_without_legacy_schema_loss():
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, "head")
            command.downgrade(config, "cd1c00000001")
            assert "saas_tenant_creation_intents" not in sa.inspect(connection).get_table_names()
            columns = {
                c["name"]: c for c in sa.inspect(connection).get_columns("saas_tenant_onboardings")
            }
            assert "creation_intent_id" not in columns
            assert columns["registration_id"]["nullable"] is False
    finally:
        engine.dispose()


def test_postgresql_non_bypass_owner_backfills_intents_and_preserves_source_functions(
    isolated_postgres_url: str,
) -> None:
    engine = sa.create_engine(isolated_postgres_url)
    owner = f"workspace_migration_{uuid4().hex}"
    try:
        with engine.begin() as connection:
            config = _config(connection)
            command.upgrade(config, "cd1c00000001")
            _history(connection)
            connection.exec_driver_sql(f'CREATE ROLE "{owner}" NOLOGIN NOBYPASSRLS')
            connection.exec_driver_sql(f'GRANT USAGE, CREATE ON SCHEMA public TO "{owner}"')
            tables = connection.scalars(
                sa.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public' AND "
                    "tablename LIKE 'saas_%'"
                )
            ).all()
            for table in tables:
                connection.exec_driver_sql(f'ALTER TABLE public."{table}" OWNER TO "{owner}"')
            connection.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            assert (
                connection.scalar(
                    sa.text("SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user")
                )
                is False
            )
            command.upgrade(config, "head")
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_tenant_creation_intents"))
                == 1
            )
            assert tuple(
                connection.execute(
                    sa.text(
                        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                        "WHERE oid='saas_tenant_creation_intents'::regclass"
                    )
                ).one()
            ) == (True, True)
            with pytest.raises(RuntimeError, match="application-only rollback"):
                command.downgrade(config, "cd1c00000001")
            connection.exec_driver_sql("RESET ROLE")
            definitions = connection.execute(
                sa.text(
                    "SELECT proname, prosrc FROM pg_proc JOIN pg_namespace n ON "
                    "n.oid=pronamespace "
                    "WHERE n.nspname='public' AND proname IN "
                    "('saas_consume_registration_rate_limit', "
                    "'saas_prune_registration_rate_limits', 'saas_registration_rate_limit_status')"
                )
            ).all()
            receipt = {
                name: sha256(source.strip(" \n\r\t").encode()).hexdigest()
                for name, source in definitions
            }
            if location := os.environ.get("WORKSPACE_MIGRATION_SOURCE_RECEIPT"):
                Path(location).write_text(json.dumps(receipt, indent=2) + "\n")
            assert len(receipt) == 3
    finally:
        with engine.begin() as connection:
            if connection.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": owner}
            ):
                connection.exec_driver_sql(f'DROP OWNED BY "{owner}"')
                connection.exec_driver_sql(f'DROP ROLE "{owner}"')
        engine.dispose()
