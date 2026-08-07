from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_lifecycle import PlatformLifecycleService
from saas.control_plane.platform_security import ValidatedPlatformPrincipal


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for PC2 RLS acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


class _PlatformGovernanceSession(Session):
    pass


@sa.event.listens_for(_PlatformGovernanceSession, "after_begin")
def _set_platform_governance_role(
    session: Session,
    transaction: object,
    connection: sa.Connection,
) -> None:
    del session, transaction
    connection.exec_driver_sql("SET LOCAL ROLE pc2_platform_governance_login")


class _ConflictGovernanceSession(Session):
    pass


@sa.event.listens_for(_ConflictGovernanceSession, "after_begin")
def _set_conflict_governance_role(
    session: Session,
    transaction: object,
    connection: sa.Connection,
) -> None:
    del session, transaction
    connection.exec_driver_sql("SET LOCAL ROLE pc2_conflict_governance_login")


def test_real_postgresql_pc2_lifecycle_is_exact_target_operator_only_and_forced_rls() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    operator_id, roleless_id, user_id, tenant_id = uuid4(), uuid4(), uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = 'pc2_platform_governance_login'
                ) THEN
                    CREATE ROLE pc2_platform_governance_login
                    NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$
            """
        )
        for inherited in (
            "saas_app",
            "saas_governance",
            "saas_platform",
            "saas_platform_app",
            "saas_platform_authenticator",
            "saas_platform_governance",
            "saas_platform_projector",
        ):
            connection.exec_driver_sql(f"REVOKE {inherited} FROM pc2_platform_governance_login")
        connection.exec_driver_sql(
            "GRANT saas_platform_governance TO pc2_platform_governance_login"
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_staff_principals "
                "(id, identity_connection_ref, issuer, subject, status, security_version) VALUES "
                "(:operator, :operator_ref, :issuer, :operator_subject, 'active', 1), "
                "(:roleless, :roleless_ref, :issuer, :roleless_subject, 'active', 1)"
            ),
            {
                "operator": operator_id,
                "operator_ref": f"staff-idp:{operator_id}",
                "operator_subject": f"operator-{operator_id}",
                "roleless": roleless_id,
                "roleless_ref": f"staff-idp:{roleless_id}",
                "roleless_subject": f"roleless-{roleless_id}",
                "issuer": "https://staff-idp.example.test",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_role_assignments "
                "(id, principal_id, role, status, version, assigned_by_principal_id, "
                "approval_ref, reason) VALUES "
                "(:id, :principal, 'platform_operator', 'active', 1, :assigned_by, "
                "'pc2-postgresql-approval', 'PC2 PostgreSQL acceptance')"
            ),
            {"id": uuid4(), "principal": operator_id, "assigned_by": roleless_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users "
                "(id, status, security_version, created_at, updated_at) "
                "VALUES (:user_id, 'active', 1, :now, :now)"
            ),
            {"user_id": user_id, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, lifecycle_version, "
                "created_at, updated_at) VALUES "
                "(:tenant_id, :slug, 'PC2 PostgreSQL', 'active', 'enterprise', "
                "'cn-east-1', 1, :now, :now)"
            ),
            {"tenant_id": tenant_id, "slug": f"pc2-{tenant_id.hex}", "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version, joined_at) "
                "VALUES (:tenant_id, :user_id, 'owner', 'active', 1, :now)"
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_auth_sessions "
                "(id, user_id, token_hash, csrf_token_hash, security_version, authn_method, "
                "expires_at, created_at) VALUES "
                "(:id, :user_id, :token_hash, :csrf_hash, 1, 'password', :expires_at, :now)"
            ),
            {
                "id": uuid4(),
                "user_id": user_id,
                "token_hash": uuid4().hex * 2,
                "csrf_hash": uuid4().hex * 2,
                "expires_at": now + timedelta(hours=1),
                "now": now,
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc2_platform_governance_login")
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(operator_id)},
        )
        assert (
            connection.execute(sa.text("SELECT count(id) FROM saas_global_users")).scalar_one()
            == 0
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_target_user_id', :value, true)"),
            {"value": str(user_id)},
        )
        assert (
            connection.execute(sa.text("SELECT count(id) FROM saas_global_users")).scalar_one()
            == 1
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc2_platform_governance_login")
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(roleless_id)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_target_user_id', :value, true)"),
            {"value": str(user_id)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_id)},
        )
        assert (
            connection.execute(sa.text("SELECT count(id) FROM saas_global_users")).scalar_one()
            == 0
        )

    actor = ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=operator_id,
        security_version=1,
        authn_method="passkey",
        authenticated_at=now,
        expires_at=now + timedelta(hours=1),
        roles=frozenset({"platform_operator"}),
        permissions=PLATFORM_ROLE_PERMISSIONS["platform_operator"],
    )
    factory = sessionmaker(
        engine,
        class_=_PlatformGovernanceSession,
        expire_on_commit=False,
    )
    result = PlatformLifecycleService(factory).suspend_user(
        actor,
        user_id=user_id,
        expected_security_version=1,
        approval_ref="pc2-real-postgresql-user-suspend",
        reason="real PostgreSQL target-bound acceptance",
        idempotency_key=f"pc2-user-suspend-{user_id}",
        now=now + timedelta(seconds=1),
    )
    assert result.result["status"] == "suspended"
    assert result.result["revoked_session_count"] == 1

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        user = connection.execute(
            sa.text("SELECT status, security_version FROM saas_global_users WHERE id = :user_id"),
            {"user_id": user_id},
        ).one()
        assert user == ("suspended", 2)
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(*) FROM saas_platform_lifecycle_operations "
                    "WHERE target_id = :user_id"
                ),
                {"user_id": user_id},
            ).scalar_one()
            == 1
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE pc2_platform_governance_login")
            connection.execute(sa.text("SELECT * FROM saas_projects"))
    engine.dispose()


def test_real_postgresql_identity_conflict_review_is_content_blind_and_exact_target() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    operator_id, roleless_id = uuid4(), uuid4()
    candidate_id, conflict_id, other_conflict_id = uuid4(), uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = 'pc2_conflict_governance_login'
                ) THEN
                    CREATE ROLE pc2_conflict_governance_login
                    NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$
            """
        )
        for inherited in (
            "saas_app",
            "saas_authenticator",
            "saas_governance",
            "saas_platform",
            "saas_platform_app",
            "saas_platform_authenticator",
            "saas_platform_governance",
            "saas_platform_projector",
        ):
            connection.exec_driver_sql(f"REVOKE {inherited} FROM pc2_conflict_governance_login")
        connection.exec_driver_sql(
            "GRANT saas_platform_governance TO pc2_conflict_governance_login"
        )
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_staff_principals "
                "(id, identity_connection_ref, issuer, subject, status, security_version) "
                "VALUES (:operator, :operator_ref, :issuer, :operator_subject, 'active', 1), "
                "(:roleless, :roleless_ref, :issuer, :roleless_subject, 'active', 1)"
            ),
            {
                "operator": operator_id,
                "operator_ref": f"staff-idp:{operator_id}",
                "operator_subject": f"operator-{operator_id}",
                "roleless": roleless_id,
                "roleless_ref": f"staff-idp:{roleless_id}",
                "roleless_subject": f"roleless-{roleless_id}",
                "issuer": "https://staff-idp.example.test",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_role_assignments "
                "(id, principal_id, role, status, version, assigned_by_principal_id, "
                "approval_ref, reason) VALUES "
                "(:id, :principal, 'platform_operator', 'active', 1, :assigned_by, "
                "'pc2-conflict-approval', 'PC2 conflict PostgreSQL acceptance')"
            ),
            {"id": uuid4(), "principal": operator_id, "assigned_by": roleless_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users "
                "(id, status, security_version, created_at, updated_at) "
                "VALUES (:candidate, 'active', 1, :now, :now)"
            ),
            {"candidate": candidate_id, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_identity_conflicts "
                "(id, provider, issuer, subject, email_normalized, status, version, "
                "platform_review_status, created_at, updated_at) VALUES "
                "(:conflict, 'oidc', 'https://private-idp.example.test', "
                "'private-subject-a', 'private-a@example.test', 'pending', 1, "
                "'unreviewed', :now, :now), "
                "(:other, 'oidc', 'https://private-idp.example.test', "
                "'private-subject-b', 'private-b@example.test', 'pending', 1, "
                "'unreviewed', :now, :now)"
            ),
            {"conflict": conflict_id, "other": other_conflict_id, "now": now},
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc2_conflict_governance_login")
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(operator_id)},
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(id) FROM saas_identity_conflicts WHERE id IN (:conflict, :other)"
                ),
                {"conflict": conflict_id, "other": other_conflict_id},
            ).scalar_one()
            == 2
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE pc2_conflict_governance_login")
            connection.execute(
                sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
                {"value": str(operator_id)},
            )
            connection.execute(sa.text("SELECT issuer FROM saas_identity_conflicts"))

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc2_conflict_governance_login")
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(roleless_id)},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(id) FROM saas_identity_conflicts")
            ).scalar_one()
            == 0
        )

    actor = ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=operator_id,
        security_version=1,
        authn_method="passkey",
        authenticated_at=now,
        expires_at=now + timedelta(hours=1),
        roles=frozenset({"platform_operator"}),
        permissions=PLATFORM_ROLE_PERMISSIONS["platform_operator"],
    )
    factory = sessionmaker(
        engine,
        class_=_ConflictGovernanceSession,
        expire_on_commit=False,
    )
    result = PlatformLifecycleService(factory).review_identity_conflict(
        actor,
        conflict_id=conflict_id,
        decision="assign",
        candidate_user_id=candidate_id,
        expected_version=1,
        approval_ref="pc2-real-postgresql-conflict-review",
        reason="exact target enterprise ownership verified",
        idempotency_key=f"pc2-conflict-{conflict_id}",
        now=now + timedelta(seconds=1),
    )
    assert result.result["platform_review_status"] == "assigned"
    assert result.result["identity_connection_created"] is False

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        reviewed = connection.execute(
            sa.text(
                "SELECT candidate_user_id, version, platform_review_status, "
                "platform_reviewed_by_principal_id FROM saas_identity_conflicts "
                "WHERE id = :conflict"
            ),
            {"conflict": conflict_id},
        ).one()
        assert reviewed == (candidate_id, 2, "assigned", operator_id)
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(*) FROM saas_platform_lifecycle_operations "
                    "WHERE target_type = 'identity_conflict' AND target_id = :conflict"
                ),
                {"conflict": conflict_id},
            ).scalar_one()
            == 1
        )

    with engine.begin() as connection:
        config = Config(root / "saas/control_plane/alembic.ini")
        config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
        config.attributes["connection"] = connection
        with pytest.raises(RuntimeError, match="identity conflict review facts"):
            command.downgrade(config, "p6b000000001")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "DELETE FROM saas_control_plane_outbox "
                "WHERE aggregate_type = 'platform_identity_conflict' "
                "AND aggregate_key = :conflict"
            ),
            {"conflict": str(conflict_id)},
        )
        connection.execute(
            sa.text(
                "DELETE FROM saas_platform_lifecycle_operations "
                "WHERE target_type = 'identity_conflict' AND target_id = :conflict"
            ),
            {"conflict": conflict_id},
        )
        connection.execute(
            sa.text("DELETE FROM saas_identity_conflicts WHERE id IN (:conflict, :other)"),
            {"conflict": conflict_id, "other": other_conflict_id},
        )
    engine.dispose()
