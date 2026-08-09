from __future__ import annotations

import os
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_security import ValidatedPlatformPrincipal
from saas.control_plane.privacy_lifecycle import (
    DeletionEvidenceKey,
    PrivacyLifecycleService,
    oidc_identity_locator_hash,
)


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for PC5 privacy acceptance")
    return value


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def test_real_postgresql_privacy_executor_is_exact_content_blind_and_redacts_once() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    suffix = uuid4().hex[:12]
    login_role = f"pc5_privacy_executor_{suffix}"
    operator_id, assigner_id, user_id, tenant_id, directory_id, scim_user_id, event_id = (
        uuid4() for _ in range(7)
    )
    assignment_id = uuid4()
    now = datetime.now(timezone.utc)
    issuer = "https://privacy-idp.example.test"
    subject = f"subject-{suffix}"
    external_id = f"external-{suffix}"

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"CREATE ROLE {login_role} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT"
        )
        connection.exec_driver_sql(f"GRANT saas_privacy_executor TO {login_role}")
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_staff_principals "
                "(id, identity_connection_ref, issuer, subject, status, security_version) VALUES "
                "(:operator, :operator_ref, :staff_issuer, :operator_subject, 'active', 1), "
                "(:assigner, :assigner_ref, :staff_issuer, :assigner_subject, 'active', 1)"
            ),
            {
                "operator": operator_id,
                "operator_ref": f"staff-idp:{operator_id}",
                "operator_subject": f"privacy-{suffix}",
                "assigner": assigner_id,
                "assigner_ref": f"staff-idp:{assigner_id}",
                "assigner_subject": f"assigner-{suffix}",
                "staff_issuer": "https://staff-idp.example.test",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_role_assignments "
                "(id, principal_id, role, status, version, assigned_by_principal_id, "
                "approval_ref, reason) VALUES "
                "(:id, :principal, 'compliance_operator', 'active', 1, :assigner, "
                "'pc5-postgresql-approval', 'PC5 privacy PostgreSQL acceptance')"
            ),
            {"id": assignment_id, "principal": operator_id, "assigner": assigner_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users "
                "(id, status, display_name, primary_email_normalized, security_version) "
                "VALUES (:user, 'active', 'Privacy Subject', :email, 1)"
            ),
            {"user": user_id, "email": f"subject-{suffix}@example.test"},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:tenant, :slug, 'Privacy PostgreSQL', 'active', 'enterprise', 'cn-east-1')"
            ),
            {"tenant": tenant_id, "slug": f"pc5-privacy-{suffix}"},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version) "
                "VALUES (:tenant, :user, 'admin', 'active', 1)"
            ),
            {"tenant": tenant_id, "user": user_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_membership_invitations "
                "(id, tenant_id, email_normalized, tenant_role, token_hash, status, "
                "expires_at, created_by, version) VALUES "
                "(:id, :tenant, :email, 'member', :token_hash, 'pending', "
                "now() + interval '7 days', :user, 1)"
            ),
            {
                "id": uuid4(),
                "tenant": tenant_id,
                "email": f"subject-{suffix}@example.test",
                "token_hash": sha256(f"invitation-{suffix}".encode()).hexdigest(),
                "user": user_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_identity_connections "
                "(id, user_id, provider, issuer, subject, email_normalized, email_verified, "
                "status) VALUES (:id, :user, 'oidc', :issuer, :subject, :email, true, 'active')"
            ),
            {
                "id": uuid4(),
                "user": user_id,
                "issuer": issuer,
                "subject": subject,
                "email": f"subject-{suffix}@example.test",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_password_credentials "
                "(user_id, login_email_normalized, password_hash, password_version, "
                "failed_attempts) VALUES (:user, :email, 'hash', 1, 0)"
            ),
            {"user": user_id, "email": f"subject-{suffix}@example.test"},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_enterprise_scim_directories "
                "(id, tenant_id, display_name, token_hash, token_prefix, status, version, "
                "configured_by) VALUES "
                "(:directory, :tenant, 'Privacy IdP', :token_hash, 'privacy', 'active', 1, :user)"
            ),
            {
                "directory": directory_id,
                "tenant": tenant_id,
                "token_hash": sha256(f"token-{suffix}".encode()).hexdigest(),
                "user": user_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_enterprise_scim_users "
                "(id, tenant_id, directory_id, external_id, user_id, user_name_normalized, "
                "display_name, active, version, source_version, source_state_hash) VALUES "
                "(:id, :tenant, :directory, :external, :user, :email, 'Privacy Subject', "
                "true, 1, 1, :state_hash)"
            ),
            {
                "id": scim_user_id,
                "tenant": tenant_id,
                "directory": directory_id,
                "external": external_id,
                "user": user_id,
                "email": f"subject-{suffix}@example.test",
                "state_hash": "a" * 64,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_enterprise_scim_events "
                "(id, tenant_id, directory_id, event_id, resource_type, resource_id, "
                "source_version, request_hash, disposition, result) VALUES "
                "(:id, :tenant, :directory, :event, 'User', :resource, 1, :request_hash, "
                "'applied', CAST(:result AS jsonb))"
            ),
            {
                "id": event_id,
                "tenant": tenant_id,
                "directory": directory_id,
                "event": f"provision-{suffix}",
                "resource": scim_user_id,
                "request_hash": "b" * 64,
                "result": ('{"external_id":"' + external_id + '","subject":"' + subject + '"}'),
            },
        )

    with engine.begin() as connection:
        assert (
            connection.execute(
                sa.text(
                    "SELECT has_table_privilege('saas_platform_governance', "
                    "'saas_global_users', 'SELECT')"
                )
            ).scalar_one()
            is False
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT has_table_privilege('saas_privacy_executor', "
                    "'saas_global_users', 'SELECT')"
                )
            ).scalar_one()
            is True
        )

    privacy_sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(privacy_sessions, "after_begin")
    def _use_privacy_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {login_role}")

    actor = ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=operator_id,
        security_version=1,
        authn_method="passkey",
        authenticated_at=now,
        expires_at=now.replace(year=now.year + 1),
        roles=frozenset({"compliance_operator"}),
        permissions=PLATFORM_ROLE_PERMISSIONS["compliance_operator"],
    )
    service = PrivacyLifecycleService(
        privacy_sessions,
        evidence_verifier=DeletionEvidenceKey("pc5-postgresql-key", b"p" * 32),
    )
    preview = service.preview_deletion(
        actor,
        target_type="global_user",
        target_id=user_id,
        now=now,
    )
    assert preview.blockers == ()
    manifest = service.start_deletion(
        actor,
        target_type="global_user",
        target_id=user_id,
        expected_target_version=preview.target_version,
        preview_hash=preview.preview_hash,
        approval_ref="pc5-postgresql-approval",
        reason="verified erasure request",
        idempotency_key=f"pc5-delete-{suffix}",
        now=now,
    )

    with engine.begin() as connection:
        user = connection.execute(
            sa.text(
                "SELECT status, display_name, primary_email_normalized "
                "FROM saas_global_users WHERE id = :id"
            ),
            {"id": user_id},
        ).one()
        assert user == ("suspended", None, None)
        receipt = connection.execute(
            sa.text(
                "SELECT result, redaction_manifest_id, original_result_hash "
                "FROM saas_enterprise_scim_events WHERE id = :id"
            ),
            {"id": event_id},
        ).one()
        assert receipt.result["redacted"] is True
        assert receipt.result["manifest_id"] == str(manifest.manifest_id)
        assert external_id not in str(receipt.result)
        assert subject not in str(receipt.result)
        assert receipt.redaction_manifest_id == manifest.manifest_id
        assert len(receipt.original_result_hash) == 64
        invitation = connection.execute(
            sa.text(
                "SELECT email_normalized, status, deletion_manifest_id "
                "FROM saas_membership_invitations "
                "WHERE tenant_id = :tenant"
            ),
            {"tenant": tenant_id},
        ).one()
        assert invitation.email_normalized.startswith("deleted-")
        assert invitation.status == "revoked"
        assert invitation.deletion_manifest_id == manifest.manifest_id
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(*) FROM saas_privacy_identity_tombstones "
                    "WHERE manifest_id = :manifest"
                ),
                {"manifest": manifest.manifest_id},
            ).scalar_one()
            == 2
        )

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {login_role}")
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(operator_id)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_target_user_id', :value, true)"),
            {"value": str(uuid4())},
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_privacy_manifest_id', :value, true)"),
            {"value": str(uuid4())},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_membership_invitations")
            ).scalar_one()
            == 0
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            # The executor loses visibility once the SCIM subject is detached;
            # use the emergency owner here so the immutable-receipt trigger,
            # rather than a zero-row RLS update, is what rejects tampering.
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
                {"value": str(operator_id)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.platform_target_user_id', :value, true)"),
                {"value": str(user_id)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.platform_privacy_manifest_id', :value, true)"),
                {"value": str(manifest.manifest_id)},
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_enterprise_scim_events SET result = CAST(:payload AS jsonb) "
                    "WHERE id = :id"
                ),
                {"id": event_id, "payload": '{"tampered":true}'},
            )

    locator = oidc_identity_locator_hash(issuer, subject)
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_authenticator")
        connection.execute(
            sa.text("SELECT set_config('app.privacy_locator_hash', :value, true)"),
            {"value": locator},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_privacy_identity_tombstones")
            ).scalar_one()
            == 1
        )

    # Leave the shared CI database downgrade-safe for tests that exercise the
    # PC5 predecessor. The superuser removes only this test's immutable facts.
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
        connection.execute(
            sa.text("DELETE FROM saas_enterprise_scim_events WHERE id = :id"),
            {"id": event_id},
        )
        connection.execute(
            sa.text("DELETE FROM saas_privacy_identity_tombstones WHERE manifest_id = :manifest"),
            {"manifest": manifest.manifest_id},
        )
        connection.execute(
            sa.text("DELETE FROM saas_privacy_deletion_manifests WHERE id = :manifest"),
            {"manifest": manifest.manifest_id},
        )
        connection.exec_driver_sql(f"DROP ROLE {login_role}")
    engine.dispose()
