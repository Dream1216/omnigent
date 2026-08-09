-- Run as the SaaS control-plane database owner after every schema migration.
-- Application login roles should inherit exactly one of these NOLOGIN roles.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_app') THEN
        CREATE ROLE saas_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_authenticator') THEN
        CREATE ROLE saas_authenticator NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_governance') THEN
        CREATE ROLE saas_governance NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_dispatcher') THEN
        CREATE ROLE saas_dispatcher NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_executor') THEN
        CREATE ROLE saas_executor NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_secret_broker') THEN
        CREATE ROLE saas_secret_broker NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_preview_gateway') THEN
        CREATE ROLE saas_preview_gateway NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_webhook_dispatcher') THEN
        CREATE ROLE saas_webhook_dispatcher NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_billing') THEN
        CREATE ROLE saas_billing NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_metering') THEN
        CREATE ROLE saas_metering NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_platform') THEN
        CREATE ROLE saas_platform NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_platform_authenticator') THEN
        CREATE ROLE saas_platform_authenticator NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_platform_app') THEN
        CREATE ROLE saas_platform_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_platform_governance') THEN
        CREATE ROLE saas_platform_governance NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_platform_projector') THEN
        CREATE ROLE saas_platform_projector NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_platform_support') THEN
        CREATE ROLE saas_platform_support NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_privacy_executor') THEN
        CREATE ROLE saas_privacy_executor NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_privacy_dispatcher') THEN
        CREATE ROLE saas_privacy_dispatcher NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_privacy_verifier') THEN
        CREATE ROLE saas_privacy_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

ALTER ROLE saas_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_authenticator NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_governance NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_dispatcher NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_executor NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_secret_broker NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_preview_gateway NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_webhook_dispatcher NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_billing NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_metering NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_platform NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_platform_authenticator NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_platform_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_platform_governance NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_platform_projector NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_platform_support NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_privacy_executor NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_privacy_dispatcher NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_privacy_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS;

-- The deletion worker is a one-purpose backend identity. It inherits the
-- content-blind governance policies, while its additional PII privileges are
-- never inherited by a browser/API Staff login.
GRANT saas_platform_governance TO saas_privacy_executor;
REVOKE saas_platform_governance, saas_privacy_executor, saas_privacy_verifier
FROM saas_privacy_dispatcher;
REVOKE saas_platform_governance, saas_privacy_executor, saas_privacy_dispatcher
FROM saas_privacy_verifier;

GRANT USAGE ON SCHEMA public TO
    saas_app, saas_authenticator, saas_governance, saas_dispatcher, saas_executor,
    saas_secret_broker, saas_preview_gateway, saas_webhook_dispatcher, saas_billing,
    saas_metering, saas_platform, saas_platform_authenticator, saas_platform_app,
    saas_platform_governance, saas_platform_projector, saas_platform_support,
    saas_privacy_executor, saas_privacy_dispatcher, saas_privacy_verifier;

-- Platform browser/API roles are independent from the emergency saas_platform
-- role. No GRANT connects them, so an application login cannot SET ROLE into
-- the recovery authority even when its Staff identity has every product role.
REVOKE ALL PRIVILEGES ON
    saas_platform_staff_principals,
    saas_platform_role_assignments,
    saas_platform_auth_sessions,
    saas_platform_tenant_projections,
    saas_platform_user_projections,
    saas_platform_lifecycle_operations,
    saas_platform_admin_operations,
    saas_platform_support_grants,
    saas_platform_support_sessions,
    saas_platform_audit_chain_heads,
    saas_platform_audit_events,
    saas_platform_audit_exports,
    saas_privacy_legal_holds,
    saas_privacy_deletion_manifests,
    saas_privacy_identity_tombstones,
    saas_privacy_approval_bindings,
    saas_privacy_deletion_work_items,
    saas_privacy_deletion_attempts,
    saas_privacy_evidence_attestations,
    saas_privacy_backup_retention_items
FROM PUBLIC, saas_app, saas_authenticator, saas_governance, saas_dispatcher,
    saas_executor, saas_secret_broker, saas_preview_gateway,
    saas_webhook_dispatcher, saas_billing, saas_metering,
    saas_platform_authenticator, saas_platform_app, saas_platform_governance,
    saas_platform_projector, saas_platform_support, saas_privacy_executor,
    saas_privacy_dispatcher, saas_privacy_verifier, saas_platform;

GRANT SELECT ON
    saas_platform_staff_principals,
    saas_platform_role_assignments,
    saas_platform_auth_sessions
TO saas_platform_authenticator;
-- PC3 adds an exact support-session policy to the Staff and assignment tables.
-- PostgreSQL validates referenced-table privileges before choosing another
-- permissive policy branch. These two columns are therefore required by the
-- existing authenticator/app readers; FORCE RLS still exposes zero support rows.
GRANT SELECT (principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions
TO saas_platform_authenticator;
GRANT INSERT ON saas_platform_auth_sessions TO saas_platform_authenticator;
GRANT UPDATE (revoked_at, last_seen_at) ON saas_platform_auth_sessions
TO saas_platform_authenticator;

GRANT SELECT ON
    saas_platform_staff_principals,
    saas_platform_role_assignments,
    saas_platform_tenant_projections,
    saas_platform_user_projections
TO saas_platform_app;
GRANT SELECT (principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions
TO saas_platform_app;

GRANT SELECT, INSERT, UPDATE ON
    saas_platform_staff_principals,
    saas_platform_role_assignments
TO saas_platform_governance;
GRANT SELECT, INSERT ON saas_platform_lifecycle_operations
TO saas_platform_governance;
GRANT SELECT, INSERT, UPDATE ON
    saas_platform_admin_operations,
    saas_platform_support_grants,
    saas_platform_support_sessions,
    saas_platform_audit_chain_heads
TO saas_platform_governance;
GRANT SELECT, INSERT ON
    saas_platform_audit_events,
    saas_platform_audit_exports
TO saas_platform_governance;
GRANT SELECT ON
    saas_platform_auth_sessions,
    saas_platform_tenant_projections,
    saas_platform_user_projections
TO saas_platform_governance;
GRANT UPDATE (revoked_at) ON saas_platform_auth_sessions TO saas_platform_governance;
GRANT SELECT ON saas_control_plane_outbox TO saas_platform_governance;

-- The support data-plane role validates one opaque, short-lived JIT session.
-- It cannot create Grants, mutate their scope, approve operations, or inherit
-- the platform emergency authority.
GRANT SELECT ON
    saas_platform_staff_principals,
    saas_platform_role_assignments,
    saas_platform_support_grants,
    saas_platform_support_sessions
TO saas_platform_support;
GRANT UPDATE (last_seen_at) ON saas_platform_support_sessions
TO saas_platform_support;
-- PostgreSQL validates every table referenced by a permissive RLS policy even
-- when another OR branch grants the row. Tenant RLS still returns no rows
-- because the Support Realm clears app.actor_id and app.tenant_id.
GRANT SELECT (tenant_id, user_id, role, status) ON saas_tenant_memberships
TO saas_platform_support;

GRANT SELECT, INSERT, UPDATE ON
    saas_platform_tenant_projections,
    saas_platform_user_projections
TO saas_platform_projector;

GRANT SELECT, INSERT, UPDATE, DELETE ON
    saas_platform_staff_principals,
    saas_platform_role_assignments,
    saas_platform_auth_sessions,
    saas_platform_tenant_projections,
    saas_platform_user_projections,
    saas_platform_lifecycle_operations,
    saas_platform_admin_operations,
    saas_platform_support_grants,
    saas_platform_support_sessions,
    saas_platform_audit_chain_heads,
    saas_platform_audit_events,
    saas_platform_audit_exports,
    saas_privacy_legal_holds,
    saas_privacy_deletion_manifests,
    saas_privacy_identity_tombstones,
    saas_privacy_approval_bindings,
    saas_privacy_deletion_work_items,
    saas_privacy_deletion_attempts,
    saas_privacy_evidence_attestations,
    saas_privacy_backup_retention_items
TO saas_platform;

-- PC2 platform lifecycle commands are target-bound by FORCE RLS. The Staff
-- governance login gets only the metadata and columns required by those commands.
-- The lifecycle policies authenticate the Staff assignment in the database. PostgreSQL
-- validates subquery privileges before evaluating an OR branch, so every role that can
-- touch a protected business table needs read access to these four assignment columns.
-- The assignment table's own FORCE RLS policy still returns no rows to tenant/runtime
-- roles; this grant cannot expose Staff assignment data.
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO
    saas_app, saas_authenticator, saas_governance, saas_dispatcher, saas_executor,
    saas_secret_broker, saas_preview_gateway, saas_webhook_dispatcher, saas_billing,
    saas_metering, saas_platform_projector, saas_privacy_dispatcher;
-- PC3 adds a Support-session branch to the Assignment policy. These roles can
-- already evaluate PC2 Assignment predicates, so PostgreSQL also needs planning
-- access to exactly the four Session columns used by that branch. The Session
-- table's FORCE RLS exposes zero rows unless the caller is the exact Support role
-- with an active token.
GRANT SELECT (principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions TO
    saas_app, saas_authenticator, saas_governance, saas_dispatcher, saas_executor,
    saas_secret_broker, saas_preview_gateway, saas_webhook_dispatcher, saas_billing,
    saas_metering, saas_platform_projector, saas_privacy_dispatcher;
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO saas_platform_support;
-- Reapplying this authority file must also remove grants from older PC5
-- candidates that briefly placed privacy execution on the browser governance
-- role. The narrower grants below are then rebuilt deterministically.
REVOKE ALL PRIVILEGES ON
    saas_global_users,
    saas_identity_connections,
    saas_auth_sessions,
    saas_password_credentials,
    saas_oidc_login_transactions,
    saas_identity_conflicts,
    saas_tenants,
    saas_tenant_memberships,
    saas_space_memberships,
    saas_membership_invitations,
    saas_project_memberships,
    saas_resource_grants,
    saas_service_accounts,
    saas_api_credentials,
    saas_enterprise_group_memberships,
    saas_enterprise_scim_directories,
    saas_enterprise_scim_users,
    saas_enterprise_scim_groups,
    saas_enterprise_scim_events,
    saas_runs,
    saas_privacy_legal_holds,
    saas_privacy_deletion_manifests,
    saas_privacy_identity_tombstones
FROM saas_platform_governance;
GRANT SELECT (id, status, security_version) ON saas_global_users
TO saas_platform_governance;
GRANT SELECT (id, user_id, revoked_at) ON saas_auth_sessions
TO saas_platform_governance;
GRANT SELECT (id, target_user_id, status) ON saas_oidc_login_transactions
TO saas_platform_governance;
GRANT SELECT (
    id, provider, candidate_user_id, status, version, platform_review_status,
    platform_reviewed_by_principal_id, platform_reviewed_at, created_at, updated_at
) ON saas_identity_conflicts TO saas_platform_governance;
GRANT SELECT ON
    saas_tenants,
    saas_tenant_memberships
TO saas_platform_governance;
GRANT SELECT (id, tenant_id, steward_user_id, status) ON saas_service_accounts
TO saas_platform_governance;
GRANT SELECT (id, tenant_id, service_account_id, status) ON saas_api_credentials
TO saas_platform_governance;
-- Ordinary lifecycle restore must fail closed once deletion governance owns a
-- target. FORCE RLS still limits these planning columns to the exact Staff and
-- target GUCs; no erased content or evidence payload is exposed.
GRANT SELECT (id, target_type, target_id, status)
ON saas_privacy_deletion_manifests TO saas_platform_governance;
GRANT SELECT (id, manifest_id, target_user_id, tenant_id)
ON saas_privacy_identity_tombstones TO saas_platform_governance;
GRANT SELECT (operation_id, phase, target_type, target_id)
ON saas_privacy_approval_bindings TO saas_platform_governance;
GRANT UPDATE (status, security_version, updated_at) ON saas_global_users
TO saas_platform_governance;
GRANT UPDATE (revoked_at) ON saas_auth_sessions TO saas_platform_governance;
GRANT UPDATE (status, consumed_at) ON saas_oidc_login_transactions
TO saas_platform_governance;
GRANT UPDATE (
    candidate_user_id, version, platform_review_status,
    platform_reviewed_by_principal_id, platform_review_approval_ref,
    platform_review_reason, platform_reviewed_at, updated_at
) ON saas_identity_conflicts TO saas_platform_governance;
GRANT UPDATE (status, lifecycle_version, updated_at) ON saas_tenants
TO saas_platform_governance;
GRANT UPDATE (role, version) ON saas_tenant_memberships
TO saas_platform_governance;
GRANT UPDATE (status, security_version, updated_at) ON saas_service_accounts
TO saas_platform_governance;
GRANT UPDATE (status, revoked_at) ON saas_api_credentials
TO saas_platform_governance;
GRANT INSERT ON saas_control_plane_outbox TO saas_platform_governance;

-- PC5 privacy execution is isolated from the normal Staff governance login.
-- FORCE RLS still binds every row to the exact Staff principal and deletion
-- target GUC; these grants only make the background command technically able
-- to hash and erase direct identifiers without exposing them through the UI.
GRANT SELECT ON
    saas_global_users,
    saas_identity_connections,
    saas_auth_sessions,
    saas_password_credentials,
    saas_tenants,
    saas_tenant_memberships,
    saas_space_memberships,
    saas_membership_invitations,
    saas_project_memberships,
    saas_resource_grants,
    saas_service_accounts,
    saas_api_credentials,
    saas_enterprise_group_memberships,
    saas_enterprise_scim_directories,
    saas_enterprise_scim_users,
    saas_enterprise_scim_groups,
    saas_enterprise_scim_events,
    saas_platform_user_projections,
    saas_runs,
    saas_platform_support_grants,
    saas_privacy_legal_holds,
    saas_privacy_deletion_manifests,
    saas_privacy_identity_tombstones
TO saas_privacy_executor;
GRANT INSERT, UPDATE ON
    saas_privacy_legal_holds,
    saas_privacy_deletion_manifests,
    saas_privacy_identity_tombstones
TO saas_privacy_executor;
GRANT UPDATE (
    status, display_name, primary_email_normalized, security_version, updated_at
) ON saas_global_users TO saas_privacy_executor;
GRANT UPDATE (
    provider, issuer, subject, email_normalized, email_verified, status, updated_at
) ON saas_identity_connections TO saas_privacy_executor;
GRANT UPDATE (revoked_at) ON saas_auth_sessions TO saas_privacy_executor;
GRANT DELETE ON saas_password_credentials TO saas_privacy_executor;
GRANT UPDATE (slug, name, status, lifecycle_version, updated_at)
ON saas_tenants TO saas_privacy_executor;
GRANT UPDATE (status, version) ON saas_tenant_memberships TO saas_privacy_executor;
GRANT UPDATE (status, version) ON saas_space_memberships TO saas_privacy_executor;
GRANT UPDATE (status, version, updated_at)
ON saas_project_memberships TO saas_privacy_executor;
GRANT UPDATE (status, version, updated_at)
ON saas_resource_grants TO saas_privacy_executor;
GRANT UPDATE (
    email_normalized, status, accepted_by, deletion_manifest_id, version, updated_at
)
ON saas_membership_invitations TO saas_privacy_executor;
GRANT UPDATE (name, description, status, security_version, updated_at)
ON saas_service_accounts TO saas_privacy_executor;
GRANT UPDATE (status, revoked_at) ON saas_api_credentials TO saas_privacy_executor;
GRANT UPDATE (status, version, updated_at)
ON saas_enterprise_group_memberships TO saas_privacy_executor;
GRANT UPDATE ON
    saas_enterprise_scim_directories,
    saas_enterprise_scim_users,
    saas_enterprise_scim_groups
TO saas_privacy_executor;
GRANT UPDATE (result, redacted_at, redaction_manifest_id, original_result_hash)
ON saas_enterprise_scim_events TO saas_privacy_executor;
GRANT UPDATE ON saas_platform_user_projections TO saas_privacy_executor;
GRANT INSERT ON saas_control_plane_outbox TO saas_privacy_executor;

-- Runtime deletion dispatch is a separate, content-blind workload identity.
GRANT SELECT ON
    saas_privacy_legal_holds,
    saas_privacy_deletion_manifests,
    saas_privacy_deletion_work_items,
    saas_privacy_deletion_attempts,
    saas_privacy_evidence_attestations,
    saas_privacy_backup_retention_items
TO saas_privacy_dispatcher;
GRANT UPDATE (
    status, blockers, surface_outcomes, version, retention_status,
    retention_completed_at, updated_at
) ON saas_privacy_deletion_manifests TO saas_privacy_dispatcher;
GRANT UPDATE (
    status, attempt_count, available_at, leased_at, lease_expires_at,
    lease_token_hash, executor_identity_sha256, lease_generation,
    last_error_code, last_error_sha256, outcome_content_sha256,
    evidence_attestation_id, version, updated_at
) ON saas_privacy_deletion_work_items TO saas_privacy_dispatcher;
GRANT UPDATE (
    status, attempt_count, available_at, leased_at, lease_expires_at,
    lease_token_hash, executor_identity_sha256, lease_generation,
    last_error_code, last_error_sha256, purge_evidence_sha256,
    evidence_attestation_id, purged_at, version, updated_at
) ON saas_privacy_backup_retention_items TO saas_privacy_dispatcher;
GRANT INSERT ON
    saas_privacy_deletion_attempts,
    saas_privacy_backup_retention_items,
    saas_control_plane_outbox
TO saas_privacy_dispatcher;

-- DSSE verification is a separate authority. Its login can inspect the exact
-- leased subject and append one immutable receipt, but cannot claim or complete work.
GRANT SELECT ON
    saas_privacy_deletion_manifests,
    saas_privacy_deletion_work_items,
    saas_privacy_backup_retention_items,
    saas_privacy_evidence_attestations,
    saas_runtime_partitions
TO saas_privacy_verifier;
-- The Staff/auditor policies on Privacy tables transitively evaluate PC3's
-- assignment and support-session policies. PostgreSQL validates those referenced
-- columns before selecting the verifier policy; FORCE RLS still exposes no rows.
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO saas_privacy_verifier;
GRANT SELECT (principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions TO saas_privacy_verifier;
GRANT INSERT ON saas_privacy_evidence_attestations TO saas_privacy_verifier;

-- Staff-approved Privacy commands create work; only the dispatcher appends attempts.
GRANT SELECT, INSERT ON saas_privacy_approval_bindings TO saas_privacy_executor;
GRANT SELECT, INSERT, UPDATE ON
    saas_privacy_deletion_work_items,
    saas_privacy_backup_retention_items
TO saas_privacy_executor;
GRANT SELECT ON
    saas_privacy_deletion_attempts,
    saas_privacy_evidence_attestations
TO saas_privacy_executor;

GRANT SELECT ON saas_webhook_endpoints TO saas_webhook_dispatcher;
GRANT SELECT, UPDATE ON saas_webhook_deliveries TO saas_webhook_dispatcher;
GRANT INSERT ON saas_control_plane_outbox TO saas_webhook_dispatcher;

GRANT SELECT, INSERT, UPDATE ON saas_webhook_endpoints TO saas_app;
GRANT SELECT, INSERT ON saas_webhook_deliveries TO saas_app;
GRANT SELECT, INSERT, UPDATE ON
    saas_webhook_endpoints,
    saas_webhook_deliveries
TO saas_platform;

GRANT SELECT, INSERT, UPDATE ON
    saas_global_users,
    saas_identity_connections,
    saas_identity_conflicts,
    saas_oidc_login_transactions,
    saas_auth_sessions,
    saas_password_credentials,
    saas_control_plane_outbox
TO saas_authenticator;

-- Machine-token authentication is constrained by the exact credential ID
-- derived from the opaque token. The authenticator may update only coalesced
-- usage metadata; it cannot create, rotate, revoke, or inspect other keys.
GRANT SELECT ON
    saas_api_credentials,
    saas_service_accounts,
    saas_tenants,
    saas_spaces,
    saas_projects,
    saas_tenant_memberships,
    saas_space_memberships
TO saas_authenticator;
GRANT UPDATE (last_used_at, last_used_ip) ON saas_api_credentials TO saas_authenticator;
GRANT SELECT ON saas_membership_invitations TO saas_authenticator;
GRANT SELECT ON saas_privacy_identity_tombstones TO saas_authenticator;
-- The invitation privacy policy verifies a transformed row against its exact
-- deletion Manifest. These planning-only columns remain row-empty under the
-- Manifest table's FORCE RLS for Customer authenticator/governance sessions.
GRANT SELECT (id, target_type, target_id)
ON saas_privacy_deletion_manifests TO saas_authenticator, saas_governance;
GRANT UPDATE (status, accepted_by, accepted_at, version, updated_at)
ON saas_membership_invitations TO saas_authenticator;
GRANT INSERT (tenant_id, user_id, role, status, version, joined_at)
ON saas_tenant_memberships TO saas_authenticator;
GRANT INSERT (tenant_id, space_id, user_id, role, status, version, joined_at)
ON saas_space_memberships TO saas_authenticator;

GRANT SELECT, INSERT, UPDATE ON
    saas_global_users,
    saas_identity_connections,
    saas_auth_sessions,
    saas_tenants,
    saas_spaces,
    saas_tenant_memberships,
    saas_space_memberships,
    saas_membership_invitations,
    saas_projects,
    saas_project_memberships,
    saas_resource_grants,
    saas_runtime_resource_bindings,
    saas_runtime_binding_sagas,
    saas_ownership_transfers,
    saas_member_removal_preflights,
    saas_service_accounts,
    saas_api_credentials,
    saas_enterprise_groups,
    saas_enterprise_group_memberships,
    saas_enterprise_custom_roles,
    saas_enterprise_group_role_assignments,
    saas_enterprise_access_preflights,
    saas_enterprise_scim_directories,
    saas_enterprise_scim_users,
    saas_enterprise_scim_groups,
    saas_control_plane_outbox
TO saas_governance;
GRANT SELECT, INSERT ON saas_enterprise_scim_events TO saas_governance;
GRANT SELECT ON saas_privacy_identity_tombstones TO saas_governance;
-- The Customer app can read SCIM projections and PostgreSQL validates every
-- table referenced by their privacy-policy predicate. Tombstone FORCE RLS
-- still exposes zero rows to this role; these columns only permit planning.
GRANT SELECT (manifest_id, target_user_id, tenant_id, locator_kind, locator_hash)
ON saas_privacy_identity_tombstones TO saas_app;

GRANT SELECT ON
    saas_runs,
    saas_repositories,
    saas_changeset_groups,
    saas_changesets,
    saas_worktree_instances
TO saas_governance;

-- Enterprise governance evaluates project permissions in the same transaction
-- and therefore appends the immutable authorization decision before mutation.
GRANT SELECT, INSERT ON saas_authorization_decisions TO saas_governance;

GRANT SELECT ON
    saas_global_users,
    saas_tenants,
    saas_spaces,
    saas_tenant_memberships,
    saas_space_memberships,
    saas_projects,
    saas_project_memberships,
    saas_resource_grants,
    saas_runtime_placements,
    saas_runtime_partitions,
    saas_runtime_identity_aliases,
    saas_runtime_resource_bindings,
    saas_runtime_binding_sagas,
    saas_enterprise_groups,
    saas_enterprise_group_memberships,
    saas_enterprise_custom_roles,
    saas_enterprise_group_role_assignments,
    saas_enterprise_access_preflights,
    saas_enterprise_scim_users,
    saas_enterprise_scim_groups,
    saas_repositories,
    saas_changeset_groups,
    saas_changesets,
    saas_worktree_quotas,
    saas_worktree_instances,
    saas_worktree_events,
    saas_egress_policies,
    saas_execution_profiles,
    saas_secret_bindings,
    saas_preview_leases
TO saas_app;

GRANT INSERT, UPDATE ON
    saas_enterprise_groups,
    saas_enterprise_group_memberships,
    saas_enterprise_custom_roles,
    saas_enterprise_group_role_assignments,
    saas_enterprise_access_preflights,
    saas_repositories,
    saas_changeset_groups,
    saas_changesets,
    saas_worktree_quotas
TO saas_app;

-- Tenant application readers never receive the SCIM bearer digest. Directory
-- authentication stays in the governance boundary and binds one exact token
-- before the Tenant RLS context is established.
GRANT SELECT (
    id, tenant_id, display_name, token_prefix, status, version, configured_by,
    created_at, updated_at, rotated_at, disabled_at, successor_token_prefix,
    rotation_activates_at, rotation_grace_expires_at
) ON saas_enterprise_scim_directories TO saas_app;

GRANT INSERT, UPDATE ON
    saas_egress_policies,
    saas_execution_profiles,
    saas_secret_bindings,
    saas_preview_leases
TO saas_app;

GRANT SELECT, INSERT ON saas_authorization_decisions TO saas_app;

GRANT SELECT, INSERT, UPDATE ON
    saas_tasks,
    saas_execution_sessions,
    saas_session_tasks,
    saas_runs,
    saas_run_events,
    saas_admission_quotas,
    saas_quota_reservations,
    saas_effect_calls
TO saas_app;

GRANT SELECT, INSERT ON saas_artifacts, saas_run_artifacts TO saas_app;
GRANT SELECT, INSERT ON saas_control_plane_outbox TO saas_app;

GRANT SELECT, INSERT, UPDATE ON
    saas_runs,
    saas_run_events,
    saas_admission_quotas,
    saas_quota_reservations,
    saas_effect_calls
TO saas_executor;

GRANT SELECT ON
    saas_tasks,
    saas_execution_sessions,
    saas_session_tasks
TO saas_executor;

GRANT SELECT, INSERT ON
    saas_artifacts,
    saas_run_artifacts,
    saas_control_plane_outbox
TO saas_executor;

GRANT SELECT ON saas_runner_pools TO saas_executor;
GRANT SELECT (
    id, connect_host, connect_port, server_name, failure_domain,
    source_revision, adapter_contract_version, status, registered_at,
    last_heartbeat_at, lease_expires_at, released_at, release_reason
) ON saas_preview_gateway_instances TO saas_executor;
GRANT SELECT, INSERT, UPDATE ON
    saas_runner_registrations,
    saas_runner_tunnel_placements,
    saas_tenant_queue_shares,
    saas_run_dispatches,
    saas_capability_tokens
TO saas_executor;

GRANT SELECT ON
    saas_repositories,
    saas_changeset_groups
TO saas_executor;

GRANT SELECT, UPDATE ON saas_worktree_quotas TO saas_executor;

GRANT SELECT, INSERT, UPDATE ON
    saas_changesets,
    saas_worktree_instances
TO saas_executor;

GRANT SELECT, INSERT ON saas_worktree_events TO saas_executor;

GRANT SELECT ON
    saas_egress_policies,
    saas_execution_profiles,
    saas_secret_bindings
TO saas_executor;

GRANT SELECT, INSERT, UPDATE ON
    saas_run_isolation_grants,
    saas_secret_access_leases
TO saas_executor;

-- Cross-table RLS policies are evaluated with the invoking role's table
-- privileges. These SELECT grants do not expose rows: every authority table
-- uses FORCE RLS and only an exact token/certificate policy can reveal
-- a row to its dedicated service role.
GRANT SELECT ON
    saas_secret_access_leases,
    saas_preview_leases,
    saas_runner_certificates
TO saas_app, saas_governance, saas_executor, saas_secret_broker, saas_preview_gateway,
    saas_metering;

-- The exact metering Run policy references the capability table. These roles
-- need planning privilege when they read Runs, but the capability table's own
-- FORCE RLS exposes rows only to executor/platform or one exact metering hash.
GRANT SELECT ON saas_capability_tokens
TO saas_app, saas_governance, saas_secret_broker, saas_preview_gateway;

-- Privacy previews read Runs through an exact target-scoped auditor policy.
-- PostgreSQL still plans every permissive Run policy, so the isolated privacy
-- executor needs SELECT privilege on the three authority tables referenced by
-- those policies. FORCE RLS on each table continues to hide all authority rows;
-- this grant neither adds an auditor row policy nor permits writes.
GRANT SELECT ON
    saas_secret_access_leases,
    saas_preview_leases,
    saas_capability_tokens
TO saas_privacy_executor;

GRANT SELECT ON
    saas_secret_bindings,
    saas_runs,
    saas_runner_certificates,
    saas_runner_registrations
TO saas_secret_broker;

GRANT SELECT, UPDATE ON saas_secret_access_leases TO saas_secret_broker;

GRANT SELECT ON
    saas_runs,
    saas_runner_certificates,
    saas_runner_registrations,
    saas_runner_tunnel_placements,
    saas_worktree_instances
TO saas_preview_gateway;

GRANT SELECT (
    id, connect_host, connect_port, server_name, failure_domain,
    source_revision, adapter_contract_version, status, registered_at,
    activated_at, last_heartbeat_at, lease_expires_at, released_at, release_reason
) ON saas_preview_gateway_instances TO saas_preview_gateway;
GRANT UPDATE (
    status, last_heartbeat_at, lease_expires_at, released_at, release_reason, updated_at
) ON saas_preview_gateway_instances TO saas_preview_gateway;
GRANT SELECT ON saas_preview_gateway_certificates TO saas_preview_gateway;
GRANT SELECT, INSERT ON saas_control_plane_outbox TO saas_preview_gateway;

GRANT SELECT, UPDATE ON saas_preview_leases TO saas_preview_gateway;

GRANT SELECT, UPDATE ON saas_control_plane_outbox TO saas_dispatcher;

-- Billing owns commercial state but never customer prompts, code, secrets, or
-- runtime workspace content. Immutable facts have INSERT and SELECT only.
-- Revoke first so reapplying this file also removes stale grants from an older
-- deployment rather than only adding the current posture.
REVOKE ALL PRIVILEGES ON
    saas_billing_subscriptions,
    saas_pricing_snapshots,
    saas_billing_entitlements,
    saas_usage_events,
    saas_billing_balances,
    saas_billing_reservations,
    saas_customer_ledger_entries,
    saas_provider_cost_entries,
    saas_billing_reconciliation_batches,
    saas_billing_reconciliation_mismatches,
    saas_billing_period_closes,
    saas_billing_metering_receipts
FROM PUBLIC, saas_app, saas_authenticator, saas_governance, saas_dispatcher,
    saas_executor, saas_secret_broker, saas_preview_gateway,
    saas_webhook_dispatcher, saas_billing, saas_metering, saas_platform;

GRANT SELECT, INSERT, UPDATE ON
    saas_billing_subscriptions,
    saas_billing_entitlements,
    saas_billing_balances,
    saas_billing_reservations,
    saas_billing_reconciliation_mismatches
TO saas_billing;

GRANT SELECT, INSERT ON
    saas_pricing_snapshots,
    saas_usage_events,
    saas_customer_ledger_entries,
    saas_provider_cost_entries,
    saas_billing_reconciliation_batches,
    saas_billing_period_closes,
    saas_control_plane_outbox
TO saas_billing;

GRANT SELECT ON saas_billing_metering_receipts TO saas_billing;

-- These dependency reads are still row-empty for saas_billing because the
-- referenced tables retain FORCE RLS with no billing policy. PostgreSQL needs
-- the grants only to plan the exact-capability metering policies that coexist
-- with the ordinary billing policies.
GRANT SELECT ON
    saas_capability_tokens,
    saas_runner_certificates
TO saas_billing;

-- Machine metering can see exactly the certificate and capability selected by
-- transaction-local hashes. Run columns deliberately exclude input content.
GRANT SELECT ON
    saas_runner_certificates,
    saas_runner_registrations,
    saas_capability_tokens,
    saas_run_dispatches,
    saas_billing_subscriptions,
    saas_pricing_snapshots
TO saas_metering;
GRANT SELECT (
    id, tenant_id, space_id, project_id, session_id, created_by, status,
    fence_token, lease_owner, lease_expires_at, created_at
) ON saas_runs TO saas_metering;
-- PostgreSQL requires UPDATE privilege on at least one column before a
-- SELECT ... FOR UPDATE lock can be taken. These grants exist only for the
-- lock/revalidation transaction: the metering policies are SELECT/INSERT-only,
-- so FORCE RLS still rejects every attempted UPDATE.
GRANT UPDATE (updated_at) ON
    saas_runner_certificates,
    saas_runner_registrations,
    saas_run_dispatches,
    saas_runs,
    saas_billing_subscriptions
TO saas_metering;
GRANT UPDATE (revocation_reason) ON saas_capability_tokens TO saas_metering;
GRANT SELECT, INSERT ON
    saas_usage_events,
    saas_billing_metering_receipts
TO saas_metering;
GRANT INSERT ON saas_control_plane_outbox TO saas_metering;

GRANT SELECT ON
    saas_global_users,
    saas_tenants,
    saas_tenant_memberships
TO saas_billing;

GRANT SELECT, INSERT, UPDATE, DELETE ON
    saas_global_users,
    saas_identity_connections,
    saas_identity_conflicts,
    saas_oidc_login_transactions,
    saas_auth_sessions,
    saas_password_credentials,
    saas_tenants,
    saas_spaces,
    saas_tenant_memberships,
    saas_space_memberships,
    saas_membership_invitations,
    saas_projects,
    saas_project_memberships,
    saas_resource_grants,
    saas_authorization_decisions,
    saas_runtime_placements,
    saas_runtime_partitions,
    saas_runtime_identity_aliases,
    saas_runtime_resource_bindings,
    saas_runtime_binding_sagas,
    saas_ownership_transfers,
    saas_member_removal_preflights,
    saas_enterprise_access_preflights,
    saas_enterprise_scim_directories,
    saas_enterprise_scim_users,
    saas_enterprise_scim_groups,
    saas_enterprise_scim_events,
    saas_service_accounts,
    saas_api_credentials,
    saas_tasks,
    saas_execution_sessions,
    saas_session_tasks,
    saas_runs,
    saas_run_events,
    saas_admission_quotas,
    saas_quota_reservations,
    saas_effect_calls,
    saas_artifacts,
    saas_run_artifacts,
    saas_runner_pools,
    saas_runner_certificates,
    saas_runner_registrations,
    saas_runner_tunnel_placements,
    saas_preview_gateway_instances,
    saas_preview_gateway_certificates,
    saas_tenant_queue_shares,
    saas_run_dispatches,
    saas_capability_tokens,
    saas_repositories,
    saas_changeset_groups,
    saas_changesets,
    saas_worktree_quotas,
    saas_worktree_instances,
    saas_worktree_events,
    saas_egress_policies,
    saas_execution_profiles,
    saas_secret_bindings,
    saas_run_isolation_grants,
    saas_secret_access_leases,
    saas_preview_leases,
    saas_billing_subscriptions,
    saas_pricing_snapshots,
    saas_billing_entitlements,
    saas_usage_events,
    saas_billing_balances,
    saas_billing_reservations,
    saas_customer_ledger_entries,
    saas_provider_cost_entries,
    saas_billing_reconciliation_batches,
    saas_billing_reconciliation_mismatches,
    saas_billing_period_closes,
    saas_billing_metering_receipts,
    saas_privacy_legal_holds,
    saas_privacy_deletion_manifests,
    saas_privacy_identity_tombstones,
    saas_control_plane_outbox
TO saas_platform;
