from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_governed_access import (
    AuditSigningKey,
    PlatformGovernedAccessService,
    TenantSupportActor,
)
from saas.control_plane.platform_security import PlatformSecurityError, ValidatedPlatformPrincipal


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for PC3 RLS acceptance")
    return url


class _Pc3GovernanceSession(Session):
    pass


@sa.event.listens_for(_Pc3GovernanceSession, "after_begin")
def _set_governance_role(
    session: Session,
    transaction: object,
    connection: sa.Connection,
) -> None:
    del session, transaction
    connection.exec_driver_sql("SET LOCAL ROLE pc3_platform_governance_login")


class _Pc3SupportSession(Session):
    pass


@sa.event.listens_for(_Pc3SupportSession, "after_begin")
def _set_support_role(
    session: Session,
    transaction: object,
    connection: sa.Connection,
) -> None:
    del session, transaction
    connection.exec_driver_sql("SET LOCAL ROLE pc3_platform_support_login")


def _actor(principal_id: UUID, role: str, now: datetime) -> ValidatedPlatformPrincipal:
    return ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=principal_id,
        security_version=1,
        authn_method="passkey",
        authenticated_at=now,
        expires_at=now + timedelta(hours=1),
        roles=frozenset({role}),
        permissions=PLATFORM_ROLE_PERMISSIONS[role],
    )


def test_real_postgresql_pc3_support_is_exact_token_tenant_and_immutable() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    support_id, operator_id, customer_id = uuid4(), uuid4(), uuid4()
    tenant_id, other_tenant_id = uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        config = Config(root / "saas/control_plane/alembic.ini")
        config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        for login_role in ("pc3_platform_governance_login", "pc3_platform_support_login"):
            connection.exec_driver_sql(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{login_role}') THEN
                        CREATE ROLE {login_role} NOLOGIN NOSUPERUSER NOBYPASSRLS;
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
                "saas_platform_support",
            ):
                connection.exec_driver_sql(f"REVOKE {inherited} FROM {login_role}")
        connection.exec_driver_sql(
            "GRANT saas_platform_governance TO pc3_platform_governance_login"
        )
        connection.exec_driver_sql("GRANT saas_platform_support TO pc3_platform_support_login")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_staff_principals "
                "(id, identity_connection_ref, issuer, subject, status, security_version, "
                "created_at, updated_at) VALUES "
                "(:support, :support_ref, :issuer, :support_subject, 'active', 1, :now, :now), "
                "(:operator, :operator_ref, :issuer, :operator_subject, 'active', 1, :now, :now)"
            ),
            {
                "support": support_id,
                "support_ref": f"staff-idp:{support_id}",
                "support_subject": f"support-{support_id}",
                "operator": operator_id,
                "operator_ref": f"staff-idp:{operator_id}",
                "operator_subject": f"operator-{operator_id}",
                "issuer": "https://staff-idp.example.test",
                "now": now,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_role_assignments "
                "(id, principal_id, role, status, version, assigned_by_principal_id, "
                "approval_ref, reason, created_at, updated_at) VALUES "
                "(:support_assignment, :support, 'support_agent', 'active', 1, :operator, "
                "'pc3-support', 'PC3 support RLS acceptance', :now, :now), "
                "(:operator_assignment, :operator, 'platform_operator', 'active', 1, :support, "
                "'pc3-operator', 'PC3 operator RLS acceptance', :now, :now)"
            ),
            {
                "support_assignment": uuid4(),
                "support": support_id,
                "operator_assignment": uuid4(),
                "operator": operator_id,
                "now": now,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users "
                "(id, status, security_version, created_at, updated_at) "
                "VALUES (:customer, 'active', 1, :now, :now)"
            ),
            {"customer": customer_id, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, lifecycle_version, "
                "created_at, updated_at) VALUES "
                "(:tenant, :slug, 'PC3 PostgreSQL', 'active', 'enterprise', 'cn-east-1', "
                "1, :now, :now), "
                "(:other, :other_slug, 'Other PC3 PostgreSQL', 'active', 'enterprise', "
                "'cn-east-1', 1, :now, :now)"
            ),
            {
                "tenant": tenant_id,
                "slug": f"pc3-{tenant_id.hex}",
                "other": other_tenant_id,
                "other_slug": f"pc3-{other_tenant_id.hex}",
                "now": now,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version, joined_at) "
                "VALUES (:tenant, :customer, 'owner', 'active', 1, :now)"
            ),
            {"tenant": tenant_id, "customer": customer_id, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_tenant_projections "
                "(tenant_id, slug, name, status, plan, home_region, member_count, "
                "space_count, source_version, updated_at) VALUES "
                "(:tenant, :slug, 'PC3 PostgreSQL', 'active', 'enterprise', 'cn-east-1', "
                "1, 0, 1, :now)"
            ),
            {"tenant": tenant_id, "slug": f"pc3-{tenant_id.hex}", "now": now},
        )

    governance_factory = sessionmaker(
        engine,
        class_=_Pc3GovernanceSession,
        expire_on_commit=False,
    )
    support_factory = sessionmaker(
        engine,
        class_=_Pc3SupportSession,
        expire_on_commit=False,
    )
    service = PlatformGovernedAccessService(
        cast(sessionmaker[Session], governance_factory),
        tenant_factory=cast(sessionmaker[Session], governance_factory),
        support_factory=cast(sessionmaker[Session], support_factory),
        signing_key=AuditSigningKey(key_id="pc3-test-key-v1", secret=b"p" * 32),
    )
    support = _actor(support_id, "support_agent", now)
    operator = _actor(operator_id, "platform_operator", now)
    grant = service.request_support_grant(
        support,
        tenant_id=tenant_id,
        mode="standard",
        scopes=("runtime.diagnostics.read",),
        project_ids=(),
        reason="real PostgreSQL PC3 acceptance",
        incident_ref=None,
        expires_at=now + timedelta(minutes=30),
        idempotency_key=f"pc3-request-{tenant_id}",
        now=now + timedelta(seconds=1),
    )
    grant = service.decide_customer_approval(
        TenantSupportActor(
            actor_id=customer_id,
            tenant_id=tenant_id,
            security_version=1,
        ),
        grant_id=grant.grant_id,
        expected_version=1,
        decision="approve",
        reason="tenant owner exact grant approval",
        reauthenticated_at=now,
        idempotency_key=f"pc3-customer-{tenant_id}",
        now=now + timedelta(seconds=2),
    )
    grant = service.decide_staff_approval(
        operator,
        grant_id=grant.grant_id,
        expected_version=2,
        decision="approve",
        reason="independent Staff approval",
        idempotency_key=f"pc3-staff-{tenant_id}",
        now=now + timedelta(seconds=3),
    )
    issued = service.issue_support_session(
        support,
        grant_id=grant.grant_id,
        expected_version=3,
        idempotency_key=f"pc3-session-{tenant_id}",
        now=now + timedelta(seconds=4),
    )
    validated = service.validate_support_session(
        issued.token,
        tenant_id=tenant_id,
        required_scope="runtime.diagnostics.read",
        now=now + timedelta(seconds=5),
    )
    assert validated.grant_id == grant.grant_id
    with pytest.raises(PlatformSecurityError) as missing_auditor:
        service.verify_audit_chain()
    assert missing_auditor.value.code == "platform_audit_verification_context_required"

    with pytest.raises(PlatformSecurityError):
        service.validate_support_session(
            issued.token,
            tenant_id=other_tenant_id,
            required_scope="runtime.diagnostics.read",
            now=now + timedelta(seconds=6),
        )

    revoked = service.revoke_support_grant_by_customer(
        TenantSupportActor(
            actor_id=customer_id,
            tenant_id=tenant_id,
            security_version=1,
        ),
        grant_id=grant.grant_id,
        expected_version=3,
        reason="Tenant Owner immediately stops support access",
        reauthenticated_at=now,
        idempotency_key=f"pc3-customer-revoke-{tenant_id}",
        now=now + timedelta(seconds=7),
    )
    assert revoked.status == "revoked"
    with pytest.raises(PlatformSecurityError):
        service.validate_support_session(
            issued.token,
            tenant_id=tenant_id,
            required_scope="runtime.diagnostics.read",
            now=now + timedelta(seconds=8),
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc3_platform_support_login")
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_platform_support_sessions")
            ).scalar_one()
            == 0
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_support_session_token_hash', :hash, true)"),
            {"hash": sha256(issued.token.encode()).hexdigest()},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_platform_support_sessions")
            ).scalar_one()
            == 0
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_support_session_token_hash', :hash, true)"),
            {"hash": "0" * 64},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_platform_support_sessions")
            ).scalar_one()
            == 0
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_platform_audit_events SET event_type = 'tampered' "
                    "WHERE target_id = :grant"
                ),
                {"grant": grant.grant_id},
            )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "SET LOCAL SESSION AUTHORIZATION pc3_platform_support_login"
            )
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")

    # This acceptance suite intentionally shares one PostgreSQL database so
    # migration round-trip tests exercise the same role/policy composition as
    # CI. Return only this test's PC3-owned facts and schema to the predecessor
    # revision. TRUNCATE is executed by the fixture superuser because the
    # product contract correctly makes audit events immutable to every runtime
    # role; application code has no equivalent bypass.
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE TABLE "
            "saas_platform_audit_exports, "
            "saas_platform_audit_events, "
            "saas_platform_support_sessions, "
            "saas_platform_support_grants, "
            "saas_platform_admin_operations CASCADE"
        )
        connection.exec_driver_sql(
            "UPDATE saas_platform_audit_chain_heads "
            "SET last_sequence = 0, last_event_hash = repeat('0', 64), updated_at = now()"
        )
        config = Config(root / "saas/control_plane/alembic.ini")
        config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
        config.attributes["connection"] = connection
        command.downgrade(config, "pc2b00000001")
    engine.dispose()
