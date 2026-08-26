from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_security import PlatformSecurityError, ValidatedPlatformPrincipal
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


def _registration_erasure_replacements(
    manifest_id: UUID,
    registration_id: UUID,
) -> dict[str, object]:
    locator = sha256(f"{manifest_id}|{registration_id}|locator".encode()).hexdigest()
    return {
        "email_normalized": f"deleted-{locator}@invalid",
        "email_hash": sha256(f"{locator}|email_hash".encode()).hexdigest(),
        "tenant_slug": f"deleted-{locator[:24]}",
        "default_space_slug": f"deleted-{locator[24:48]}",
        "user_id": UUID(
            hex=sha256(f"{manifest_id}|{registration_id}|user_id".encode()).hexdigest()[:32]
        ),
        "tenant_id": UUID(
            hex=sha256(f"{manifest_id}|{registration_id}|tenant_id".encode()).hexdigest()[:32]
        ),
        "idempotency_key": sha256(f"{locator}|idempotency_key".encode()).hexdigest(),
        "request_hash": sha256(f"{locator}|request_hash".encode()).hexdigest(),
    }


def _attempt_registration_erasure(
    connection: sa.Connection,
    *,
    registration_id: UUID,
    manifest_id: UUID,
    principal_id: UUID,
    target_user_id: UUID | None,
    target_tenant_id: UUID | None,
    replacement_user_id: UUID,
    replacement_tenant_id: UUID,
) -> int:
    replacements = _registration_erasure_replacements(manifest_id, registration_id)
    connection.execute(
        sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
        {"value": str(principal_id)},
    )
    connection.execute(
        sa.text("SELECT set_config('app.platform_target_user_id', :value, true)"),
        {"value": "" if target_user_id is None else str(target_user_id)},
    )
    connection.execute(
        sa.text("SELECT set_config('app.platform_target_tenant_id', :value, true)"),
        {"value": "" if target_tenant_id is None else str(target_tenant_id)},
    )
    connection.execute(
        sa.text("SELECT set_config('app.platform_privacy_manifest_id', :value, true)"),
        {"value": str(manifest_id)},
    )
    result = connection.execute(
        sa.text(
            "UPDATE saas_self_service_registrations SET "
            "email_normalized = :email_normalized, email_hash = :email_hash, "
            "display_name = NULL, tenant_name = 'Deleted Tenant', "
            "tenant_slug = :tenant_slug, default_space_name = 'Deleted Space', "
            "default_space_slug = :default_space_slug, status = 'revoked', "
            "verified_at = NULL, terminal_at = now(), user_id = :user_id, "
            "tenant_id = :tenant_id, idempotency_key = :idempotency_key, "
            "request_hash = :request_hash, deletion_manifest_id = :manifest_id, "
            "version = version + 1, updated_at = now() WHERE id = :registration_id"
        ),
        {
            **replacements,
            "user_id": replacement_user_id,
            "tenant_id": replacement_tenant_id,
            "manifest_id": manifest_id,
            "registration_id": registration_id,
        },
    )
    return int(result.rowcount or 0)


def _cleanup_postgresql_test_state(
    engine: sa.Engine,
    *,
    deletes: tuple[tuple[str, str, dict[str, object]], ...],
    role_names: tuple[str, ...] = (),
) -> None:
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
            for table, predicate, parameters in deletes:
                exists = connection.execute(
                    sa.text("SELECT to_regclass(:table_name) IS NOT NULL"),
                    {"table_name": f"public.{table}"},
                ).scalar_one()
                if exists:
                    connection.execute(
                        sa.text(f"DELETE FROM {table} WHERE {predicate}"),
                        parameters,
                    )
    finally:
        with engine.begin() as connection:
            for role_name in role_names:
                exists = connection.execute(
                    sa.text("SELECT 1 FROM pg_roles WHERE rolname = :role_name"),
                    {"role_name": role_name},
                ).first()
                if exists is not None:
                    connection.exec_driver_sql(f"DROP ROLE {role_name}")


def test_privacy_registration_sql_and_psql_authority_are_consistent() -> None:
    root = Path(__file__).resolve().parents[2]
    roles = (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
    wrapper = (root / "saas/control_plane/postgresql_roles.psql").read_text(encoding="utf-8")
    migration = (
        root / "saas/control_plane/migrations/versions/p0s000000005_registration_rate_limits.py"
    ).read_text(encoding="utf-8")

    assert wrapper.index("\\set ON_ERROR_STOP on") < wrapper.index("BEGIN;")
    assert wrapper.index("BEGIN;") < wrapper.index("\\ir postgresql_roles.sql")
    assert wrapper.index("\\ir postgresql_roles.sql") < wrapper.index("COMMIT;")
    assert "GRANT SELECT (id, user_id, tenant_id, deletion_manifest_id, version)" in roles
    assert "ON saas_self_service_registrations TO saas_privacy_executor" in roles
    assert "email_normalized, email_hash, display_name, tenant_name, tenant_slug" in roles
    assert "a0e09fe6eb825ad9bed3428d4bfc31e2fa6d6b1bc1324199a9fa5f7ccff375b1" in roles
    assert "d9cdb654555fb782037992891e66fac188c7260c404b36f0b10dcef0e0406605" in roles
    assert "retaining the full-table aggregate still rejects" in roles
    assert "659fd922560eea249898647400542e711de87d290327029d74325201d82b725a" in roles
    assert "89e8bd459b1aab4e24bf7655fc9b386a01243bcb071a9c9bdd1eb8e6f46de49a" in roles
    assert "a712a6bb5fa0f0b66ce8102486e8d51bcc11382fb5397ab5043b17e5689efda5" in roles
    assert "Keep the complete constraint" in roles
    assert "rls_self_service_registrations_privacy_anonymize" in migration
    assert "OLD.deletion_manifest_id IS NOT NULL" in migration
    assert "privacy_registration_manifest.status = 'executing'" in migration
    assert "{_PRIVACY_TARGET_TENANT} IS NULL" in migration
    assert "{_PRIVACY_TARGET_USER} IS NULL" in migration
    assert "OLD.user_id =" in migration
    assert "OLD.tenant_id =" in migration
    assert "NEW.deletion_manifest_id =" in migration
    assert "NEW.user_id = substr" in migration
    assert "NEW.tenant_id = substr" in migration
    assert "privacy_hash('user_id')" in migration
    assert "privacy_hash('tenant_id')" in migration
    assert "LOCK TABLE public.saas_registration_rate_limit_policies, " in migration
    assert "public.saas_registration_rate_limits, " in migration
    assert "public.saas_self_service_registrations IN ACCESS EXCLUSIVE MODE" in migration
    assert "NO FORCE ROW LEVEL SECURITY" in migration
    assert '"deletion_manifest_id",' in migration
    assert "cannot downgrade p0s000000005 with anonymized registration evidence" in migration


def test_real_postgresql_privacy_executor_is_exact_content_blind_and_redacts_once(
    request: pytest.FixtureRequest,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    suffix = uuid4().hex[:12]
    login_role = f"pc5_privacy_executor_{suffix}"
    (
        operator_id,
        auditor_id,
        assigner_id,
        user_id,
        other_user_id,
        tenant_id,
        directory_id,
        scim_user_id,
        event_id,
    ) = (uuid4() for _ in range(9))
    assignment_id, auditor_assignment_id = uuid4(), uuid4()
    registration_id = uuid4()
    invitation_id, identity_connection_id = uuid4(), uuid4()
    guard_user_manifest_id, guard_tenant_manifest_id = uuid4(), uuid4()
    registration_idempotency_key = sha256(
        f"registration-idempotency:{suffix}".encode()
    ).hexdigest()
    registration_request_hash = sha256(f"registration-request:{suffix}".encode()).hexdigest()
    now = datetime.now(timezone.utc)
    issuer = "https://privacy-idp.example.test"
    subject = f"subject-{suffix}"
    external_id = f"external-{suffix}"

    request.addfinalizer(
        lambda: _cleanup_postgresql_test_state(
            engine,
            role_names=(login_role,),
            deletes=(
                (
                    "saas_control_plane_outbox",
                    "aggregate_type = 'privacy_global_user' AND aggregate_key = :target",
                    {"target": str(user_id)},
                ),
                (
                    "saas_enterprise_scim_events",
                    "id = :id",
                    {"id": event_id},
                ),
                (
                    "saas_privacy_identity_tombstones",
                    "target_user_id = :user",
                    {"user": user_id},
                ),
                (
                    "saas_self_service_registrations",
                    "id = :id",
                    {"id": registration_id},
                ),
                (
                    "saas_membership_invitations",
                    "id = :id",
                    {"id": invitation_id},
                ),
                (
                    "saas_enterprise_scim_users",
                    "id = :id",
                    {"id": scim_user_id},
                ),
                (
                    "saas_enterprise_scim_directories",
                    "id = :id",
                    {"id": directory_id},
                ),
                (
                    "saas_identity_connections",
                    "id = :id",
                    {"id": identity_connection_id},
                ),
                (
                    "saas_password_credentials",
                    "user_id = :user",
                    {"user": user_id},
                ),
                (
                    "saas_tenant_memberships",
                    "tenant_id = :tenant AND user_id = :user",
                    {"tenant": tenant_id, "user": user_id},
                ),
                (
                    "saas_privacy_deletion_manifests",
                    "requested_by_principal_id = :principal",
                    {"principal": operator_id},
                ),
                (
                    "saas_platform_role_assignments",
                    "principal_id IN (:operator, :auditor, :assigner)",
                    {
                        "operator": operator_id,
                        "auditor": auditor_id,
                        "assigner": assigner_id,
                    },
                ),
                (
                    "saas_global_users",
                    "id IN (:user, :other_user)",
                    {"user": user_id, "other_user": other_user_id},
                ),
                ("saas_tenants", "id = :id", {"id": tenant_id}),
                (
                    "saas_platform_staff_principals",
                    "id IN (:operator, :auditor, :assigner)",
                    {
                        "operator": operator_id,
                        "auditor": auditor_id,
                        "assigner": assigner_id,
                    },
                ),
            ),
        )
    )

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
                "(:auditor, :auditor_ref, :staff_issuer, :auditor_subject, 'active', 1), "
                "(:assigner, :assigner_ref, :staff_issuer, :assigner_subject, 'active', 1)"
            ),
            {
                "operator": operator_id,
                "operator_ref": f"staff-idp:{operator_id}",
                "operator_subject": f"privacy-{suffix}",
                "auditor": auditor_id,
                "auditor_ref": f"staff-idp:{auditor_id}",
                "auditor_subject": f"privacy-auditor-{suffix}",
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
                "'pc5-postgresql-approval', 'PC5 privacy PostgreSQL acceptance'), "
                "(:auditor_assignment, :auditor, 'platform_security_auditor', 'active', 1, "
                ":assigner, 'p1-privacy-auditor-read', "
                "'P1 exact-target Privacy read acceptance')"
            ),
            {
                "id": assignment_id,
                "principal": operator_id,
                "auditor_assignment": auditor_assignment_id,
                "auditor": auditor_id,
                "assigner": assigner_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users "
                "(id, status, display_name, primary_email_normalized, security_version) "
                "VALUES (:user, 'active', 'Privacy Subject', :email, 1), "
                "(:other_user, 'active', 'Other Privacy Subject', :other_email, 1)"
            ),
            {
                "user": user_id,
                "email": f"subject-{suffix}@example.test",
                "other_user": other_user_id,
                "other_email": f"other-subject-{suffix}@example.test",
            },
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
                "INSERT INTO saas_self_service_registrations ("
                "id, email_normalized, email_hash, display_name, tenant_name, tenant_slug, "
                "default_space_name, default_space_slug, plan_key, plan_policy_revision, "
                "home_region, status, challenge_generation, expires_at, verified_at, "
                "terminal_at, user_id, tenant_id, space_id, subscription_id, "
                "pricing_snapshot_id, entitlement_id, runtime_partition_id, "
                "default_project_id, runtime_binding_id, plan_snapshot, "
                "plan_snapshot_hash, onboarding_id, idempotency_key, request_hash, version"
                ") VALUES ("
                ":id, :email, :email_hash, 'Privacy Subject', 'Privacy PostgreSQL', "
                ":tenant_slug, 'Main Space', 'main', 'enterprise', 'privacy-postgresql-v1', "
                "'cn-east-1', 'verified', 1, now() + interval '1 day', now(), now(), "
                ":user, :tenant, :space, :subscription, :pricing_snapshot, :entitlement, "
                ":runtime_partition, :project, :runtime_binding, "
                "CAST(:plan_snapshot AS jsonb), :plan_snapshot_hash, :onboarding, "
                ":idempotency_key, :request_hash, 2)"
            ),
            {
                "id": registration_id,
                "email": f"subject-{suffix}@example.test",
                "email_hash": sha256(f"subject-{suffix}@example.test".encode()).hexdigest(),
                "tenant_slug": f"pc5-privacy-{suffix}",
                "user": user_id,
                "tenant": tenant_id,
                "space": uuid4(),
                "subscription": uuid4(),
                "pricing_snapshot": uuid4(),
                "entitlement": uuid4(),
                "runtime_partition": uuid4(),
                "project": uuid4(),
                "runtime_binding": uuid4(),
                "plan_snapshot": '{"plan_key":"enterprise"}',
                "plan_snapshot_hash": "e" * 64,
                "onboarding": uuid4(),
                "idempotency_key": registration_idempotency_key,
                "request_hash": registration_request_hash,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_privacy_deletion_manifests "
                "(id, target_type, target_id, tenant_id, requested_by_principal_id, "
                "idempotency_key, request_hash, approval_ref, reason, "
                "expected_target_version, preview_hash, status, blockers, "
                "surface_outcomes, version, started_at) VALUES "
                "(:user_manifest, 'global_user', :user, NULL, :principal, :user_key, "
                ":user_hash, 'registration-erasure-guard-user', "
                "'Registration erasure negative user acceptance', 1, :user_preview, "
                "'executing', CAST('[]' AS jsonb), CAST('{}' AS jsonb), 1, :now), "
                "(:tenant_manifest, 'tenant', :tenant, :tenant, :principal, :tenant_key, "
                ":tenant_hash, 'registration-erasure-guard-tenant', "
                "'Registration erasure negative tenant acceptance', 1, :tenant_preview, "
                "'executing', CAST('[]' AS jsonb), CAST('{}' AS jsonb), 1, :now)"
            ),
            {
                "user_manifest": guard_user_manifest_id,
                "tenant_manifest": guard_tenant_manifest_id,
                "user": user_id,
                "tenant": tenant_id,
                "principal": operator_id,
                "user_key": f"registration-erasure-guard-user-{suffix}",
                "tenant_key": f"registration-erasure-guard-tenant-{suffix}",
                "user_hash": "1" * 64,
                "tenant_hash": "2" * 64,
                "user_preview": "3" * 64,
                "tenant_preview": "4" * 64,
                "now": now,
            },
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
                "id": invitation_id,
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
                "id": identity_connection_id,
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
        expected_auditor_policies = {
            "rls_privacy_holds_auditor_read",
            "rls_privacy_manifests_auditor_read",
            "rls_global_users_privacy_auditor_read",
            "rls_tenants_privacy_auditor_read",
            "rls_tenant_memberships_privacy_auditor_read",
            "rls_service_accounts_privacy_auditor_read",
            "rls_identity_connections_privacy_auditor_read",
            "rls_scim_users_privacy_auditor_read",
            "rls_scim_directories_privacy_auditor_read",
            "rls_runs_privacy_auditor_read",
            "rls_support_grants_privacy_auditor_read",
            "rls_saas_privacy_deletion_work_items_auditor_read",
            "rls_saas_privacy_deletion_attempts_auditor_read",
            "rls_saas_privacy_evidence_attestations_auditor_read",
            "rls_saas_privacy_backup_retention_items_auditor_read",
        }
        auditor_policies = list(
            connection.execute(
                sa.text(
                    "SELECT policyname, cmd FROM pg_policies "
                    "WHERE schemaname = 'public' AND policyname LIKE '%auditor_read'"
                )
            ).mappings()
        )
        assert {value["policyname"] for value in auditor_policies} == expected_auditor_policies
        assert {value["cmd"] for value in auditor_policies} == {"SELECT"}
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
        assert (
            connection.execute(
                sa.text(
                    "SELECT has_table_privilege('saas_privacy_executor', "
                    "'saas_self_service_registrations', 'SELECT')"
                )
            ).scalar_one()
            is False
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT has_column_privilege('saas_privacy_executor', "
                    "'saas_self_service_registrations', 'user_id', 'SELECT')"
                )
            ).scalar_one()
            is True
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT has_column_privilege('saas_privacy_executor', "
                    "'saas_self_service_registrations', 'email_normalized', 'SELECT')"
                )
            ).scalar_one()
            is False
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT has_column_privilege('saas_privacy_executor', "
                    "'saas_self_service_registrations', 'email_normalized', 'UPDATE')"
                )
            ).scalar_one()
            is True
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT has_column_privilege('saas_privacy_executor', "
                    "'saas_self_service_registrations', 'plan_snapshot', 'UPDATE')"
                )
            ).scalar_one()
            is False
        )

    for manifest_id, target_user_id, target_tenant_id in (
        (guard_user_manifest_id, user_id, None),
        (guard_tenant_manifest_id, None, tenant_id),
    ):
        exact = _registration_erasure_replacements(manifest_id, registration_id)
        malformed_associations = (
            (user_id, exact["tenant_id"]),
            (exact["user_id"], tenant_id),
            (uuid4(), uuid4()),
        )
        for replacement_user_id, replacement_tenant_id in malformed_associations:
            assert isinstance(replacement_user_id, UUID)
            assert isinstance(replacement_tenant_id, UUID)
            with pytest.raises(DBAPIError):
                with engine.begin() as connection:
                    connection.exec_driver_sql(f"SET LOCAL ROLE {login_role}")
                    _attempt_registration_erasure(
                        connection,
                        registration_id=registration_id,
                        manifest_id=manifest_id,
                        principal_id=operator_id,
                        target_user_id=target_user_id,
                        target_tenant_id=target_tenant_id,
                        replacement_user_id=replacement_user_id,
                        replacement_tenant_id=replacement_tenant_id,
                    )

    # A manifest, its original row, and both deterministic replacement IDs must
    # all be authorized by one exclusive target branch.  Supplying the opposite
    # target GUC must not splice the manifest branch for one target together with
    # row authority for another target.
    for manifest_id, target_user_id, target_tenant_id in (
        (guard_user_manifest_id, user_id, uuid4()),
        (guard_tenant_manifest_id, uuid4(), tenant_id),
    ):
        exact = _registration_erasure_replacements(manifest_id, registration_id)
        replacement_user_id = exact["user_id"]
        replacement_tenant_id = exact["tenant_id"]
        assert isinstance(replacement_user_id, UUID)
        assert isinstance(replacement_tenant_id, UUID)
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql(f"SET LOCAL ROLE {login_role}")
                affected = _attempt_registration_erasure(
                    connection,
                    registration_id=registration_id,
                    manifest_id=manifest_id,
                    principal_id=operator_id,
                    target_user_id=target_user_id,
                    target_tenant_id=target_tenant_id,
                    replacement_user_id=replacement_user_id,
                    replacement_tenant_id=replacement_tenant_id,
                )
        except DBAPIError:
            # A row-level rejection and an RLS-hidden zero-row update are both
            # acceptable as long as neither can mutate the protected record.
            pass
        else:
            assert affected == 0

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        original_registration = connection.execute(
            sa.text(
                "SELECT status, email_normalized, user_id, tenant_id, "
                "deletion_manifest_id FROM saas_self_service_registrations WHERE id = :id"
            ),
            {"id": registration_id},
        ).one()
        assert original_registration == (
            "verified",
            f"subject-{suffix}@example.test",
            user_id,
            tenant_id,
            None,
        )
        connection.execute(
            sa.text(
                "DELETE FROM saas_privacy_deletion_manifests "
                "WHERE id IN (:user_manifest, :tenant_manifest)"
            ),
            {
                "user_manifest": guard_user_manifest_id,
                "tenant_manifest": guard_tenant_manifest_id,
            },
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
    holds = service.list_legal_holds(
        actor,
        target_type="global_user",
        target_id=user_id,
        now=now,
    )
    assert holds.items == ()
    assert holds.next_cursor is None
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
    manifests = service.list_manifests(
        actor,
        target_type="global_user",
        target_id=user_id,
        now=now,
    )
    assert tuple(item.manifest_id for item in manifests.items) == (manifest.manifest_id,)
    assert manifests.next_cursor is None

    auditor = ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=auditor_id,
        security_version=1,
        authn_method="passkey",
        authenticated_at=now,
        expires_at=now.replace(year=now.year + 1),
        roles=frozenset({"platform_security_auditor"}),
        permissions=PLATFORM_ROLE_PERMISSIONS["platform_security_auditor"],
    )
    auditor_preview = service.preview_deletion(
        auditor,
        target_type="global_user",
        target_id=user_id,
        now=now,
    )
    assert auditor_preview.target_id == user_id
    assert auditor_preview.target_status == "suspended"
    assert auditor_preview.impact_counts["identity_connections"] == 1
    auditor_tenant_preview = service.preview_deletion(
        auditor,
        target_type="tenant",
        target_id=tenant_id,
        now=now,
    )
    assert auditor_tenant_preview.target_id == tenant_id
    assert auditor_tenant_preview.impact_counts["memberships"] == 1
    assert auditor_tenant_preview.impact_counts["scim_directories"] == 1
    auditor_holds = service.list_legal_holds(
        auditor,
        target_type="global_user",
        target_id=user_id,
        now=now,
    )
    assert auditor_holds.items == ()
    assert auditor_holds.next_cursor is None
    auditor_manifests = service.list_manifests(
        auditor,
        target_type="global_user",
        target_id=user_id,
        now=now,
    )
    assert tuple(item.manifest_id for item in auditor_manifests.items) == (manifest.manifest_id,)
    assert auditor_manifests.next_cursor is None
    with pytest.raises(PlatformSecurityError) as cross_target:
        service.get_manifest(
            auditor,
            target_type="global_user",
            target_id=other_user_id,
            manifest_id=manifest.manifest_id,
            now=now,
        )
    assert cross_target.value.code == "platform_privacy_manifest_not_found"
    with pytest.raises(PlatformSecurityError) as auditor_write:
        service.place_legal_hold(
            auditor,
            target_type="global_user",
            target_id=user_id,
            scope=("identity",),
            authority_ref=f"auditor-must-not-write-{suffix}",
            reason="read-only auditor write denial",
            review_due_at=now + timedelta(days=30),
            now=now,
        )
    assert auditor_write.value.code == "platform_permission_denied"

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {login_role}")
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(auditor_id)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_target_user_id', :value, true)"),
            {"value": str(user_id)},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_global_users WHERE id = :id"),
                {"id": user_id},
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_global_users WHERE id = :id"),
                {"id": other_user_id},
            ).scalar_one()
            == 0
        )
        denied_update = connection.execute(
            sa.text(
                "UPDATE saas_privacy_deletion_manifests SET version = version + 1 "
                "WHERE id = :manifest"
            ),
            {"manifest": manifest.manifest_id},
        )
        assert denied_update.rowcount == 0

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
        registration = connection.execute(
            sa.text(
                "SELECT email_normalized, email_hash, display_name, tenant_name, "
                "default_space_name, status, verified_at, terminal_at, user_id, tenant_id, "
                "idempotency_key, request_hash, deletion_manifest_id "
                "FROM saas_self_service_registrations WHERE id = :id"
            ),
            {"id": registration_id},
        ).one()
        assert registration.email_normalized.startswith("deleted-")
        assert registration.email_normalized.endswith("@invalid")
        assert registration.email_normalized != f"subject-{suffix}@example.test"
        assert (
            registration.email_hash
            != sha256(f"subject-{suffix}@example.test".encode()).hexdigest()
        )
        assert registration.display_name is None
        assert registration.tenant_name == "Deleted Tenant"
        assert registration.default_space_name == "Deleted Space"
        assert registration.status == "revoked"
        assert registration.verified_at is None
        assert registration.terminal_at is not None
        assert registration.user_id != user_id
        assert registration.tenant_id != tenant_id
        assert registration.idempotency_key != registration_idempotency_key
        assert registration.request_hash != registration_request_hash
        assert registration.deletion_manifest_id == manifest.manifest_id
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(*) FROM saas_privacy_identity_tombstones "
                    "WHERE manifest_id = :manifest"
                ),
                {"manifest": manifest.manifest_id},
            ).scalar_one()
            == 3
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_self_service_registrations "
                    "SET deletion_manifest_id = NULL WHERE id = :id"
                ),
                {"id": registration_id},
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
            sa.text("DELETE FROM saas_self_service_registrations WHERE id = :id"),
            {"id": registration_id},
        )
        connection.execute(
            sa.text("DELETE FROM saas_privacy_deletion_manifests WHERE id = :manifest"),
            {"manifest": manifest.manifest_id},
        )
        connection.exec_driver_sql(f"DROP ROLE {login_role}")
    engine.dispose()


def test_real_postgresql_registration_erasure_evidence_blocks_downgrade(
    request: pytest.FixtureRequest,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    suffix = uuid4().hex[:12]
    principal_id = uuid4()
    target_user_id = uuid4()
    target_tenant_id = uuid4()
    manifest_id = uuid4()
    registration_id = uuid4()
    registration_idempotency_key = sha256(
        f"registration-downgrade-idempotency:{suffix}".encode()
    ).hexdigest()
    registration_request_hash = sha256(
        f"registration-downgrade-request:{suffix}".encode()
    ).hexdigest()

    request.addfinalizer(
        lambda: _cleanup_postgresql_test_state(
            engine,
            deletes=(
                (
                    "saas_self_service_registrations",
                    "id = :id",
                    {"id": registration_id},
                ),
                (
                    "saas_privacy_deletion_manifests",
                    "id = :id",
                    {"id": manifest_id},
                ),
                (
                    "saas_platform_staff_principals",
                    "id = :id",
                    {"id": principal_id},
                ),
            ),
        )
    )

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_staff_principals "
                "(id, identity_connection_ref, issuer, subject, status, security_version) "
                "VALUES (:id, :identity_ref, 'https://staff-idp.example.test', "
                ":subject, 'active', 1)"
            ),
            {
                "id": principal_id,
                "identity_ref": f"registration-downgrade:{suffix}",
                "subject": f"registration-downgrade-{suffix}",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_privacy_deletion_manifests "
                "(id, target_type, target_id, tenant_id, requested_by_principal_id, "
                "idempotency_key, request_hash, approval_ref, reason, "
                "expected_target_version, preview_hash, status, blockers, "
                "surface_outcomes, version, started_at) VALUES "
                "(:manifest, 'global_user', :target, NULL, :principal, :key, :request_hash, "
                "'registration-downgrade-guard', 'Registration downgrade guard acceptance', "
                "1, :preview_hash, 'executing', CAST('[]' AS jsonb), "
                "CAST('{}' AS jsonb), 1, now())"
            ),
            {
                "manifest": manifest_id,
                "target": target_user_id,
                "principal": principal_id,
                "key": f"registration-downgrade-{suffix}",
                "request_hash": "5" * 64,
                "preview_hash": "6" * 64,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_self_service_registrations ("
                "id, email_normalized, email_hash, tenant_name, tenant_slug, "
                "default_space_name, default_space_slug, plan_key, plan_policy_revision, "
                "home_region, status, challenge_generation, expires_at, terminal_at, "
                "user_id, tenant_id, space_id, subscription_id, pricing_snapshot_id, "
                "entitlement_id, runtime_partition_id, default_project_id, "
                "runtime_binding_id, plan_snapshot, plan_snapshot_hash, onboarding_id, "
                "idempotency_key, request_hash, deletion_manifest_id, version) VALUES ("
                ":id, :email, :email_hash, 'Deleted Tenant', :tenant_slug, "
                "'Deleted Space', :space_slug, 'enterprise', 'privacy-downgrade-v1', "
                "'cn-east-1', 'revoked', 1, now() + interval '1 day', now(), "
                ":user, :tenant, :space, :subscription, :pricing_snapshot, :entitlement, "
                ":runtime_partition, :project, :runtime_binding, "
                "CAST(:snapshot AS jsonb), :snapshot_hash, :onboarding, :idempotency_key, "
                ":request_hash, :manifest, 2)"
            ),
            {
                "id": registration_id,
                "email": f"deleted-{suffix}@invalid",
                "email_hash": "7" * 64,
                "tenant_slug": f"deleted-{suffix}",
                "space_slug": f"deleted-space-{suffix}",
                "user": target_user_id,
                "tenant": target_tenant_id,
                "space": uuid4(),
                "subscription": uuid4(),
                "pricing_snapshot": uuid4(),
                "entitlement": uuid4(),
                "runtime_partition": uuid4(),
                "project": uuid4(),
                "runtime_binding": uuid4(),
                "snapshot": '{"plan_key":"enterprise"}',
                "snapshot_hash": "8" * 64,
                "onboarding": uuid4(),
                "idempotency_key": registration_idempotency_key,
                "request_hash": registration_request_hash,
                "manifest": manifest_id,
            },
        )

    with engine.begin() as connection:
        config = Config(root / "saas/control_plane/alembic.ini")
        config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
        config.attributes["connection"] = connection
        with pytest.raises(
            RuntimeError,
            match="cannot downgrade p0s000000005 with anonymized registration evidence",
        ):
            command.downgrade(config, "p0s000000004")
        assert connection.execute(
            sa.text(
                "SELECT relforcerowsecurity FROM pg_class "
                "WHERE oid = 'saas_self_service_registrations'::regclass"
            )
        ).scalar_one()
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(*) FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'saas_self_service_registrations' "
                    "AND column_name = 'deletion_manifest_id'"
                )
            ).scalar_one()
            == 1
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
        connection.execute(
            sa.text("DELETE FROM saas_self_service_registrations WHERE id = :id"),
            {"id": registration_id},
        )
        connection.execute(
            sa.text("DELETE FROM saas_privacy_deletion_manifests WHERE id = :id"),
            {"id": manifest_id},
        )
        connection.execute(
            sa.text("DELETE FROM saas_platform_staff_principals WHERE id = :id"),
            {"id": principal_id},
        )

    with engine.begin() as connection:
        config = Config(root / "saas/control_plane/alembic.ini")
        config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
        config.attributes["connection"] = connection
        command.downgrade(config, "p0s000000004")
        command.upgrade(config, "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )

    engine.dispose()
