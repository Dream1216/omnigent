-- Transaction body: never invoke this file directly with plain `psql -f`.
-- psql operators must use postgresql_roles.psql, which enables ON_ERROR_STOP
-- and wraps this entire authority projection in one transaction. API callers
-- must execute this body inside an explicit transaction.
-- Run as the SaaS control-plane database owner after every schema migration.
-- Application login roles should inherit exactly one of these NOLOGIN roles.
-- Cluster principals and their fixed role graph are an operator-owned phase.
-- Database-level PUBLIC TEMPORARY revocation is a separate database-owner
-- phase in postgresql_database.psql and must already be complete.
-- This database-object authority projection is intentionally read-only over
-- pg_roles/pg_auth_members so a NOCREATEROLE schema owner can apply it.
DO $$
DECLARE
    named_principals constant text[] := ARRAY[
        'saas_app',
        'saas_authenticator',
        'saas_governance',
        'saas_dispatcher',
        'saas_dispatcher_n1_compat',
        'saas_executor',
        'saas_secret_broker',
        'saas_preview_gateway',
        'saas_webhook_dispatcher',
        'saas_billing',
        'saas_metering',
        'saas_public_api',
        'saas_platform',
        'saas_platform_authenticator',
        'saas_platform_app',
        'saas_platform_governance',
        'saas_platform_projector',
        'saas_platform_support',
        'saas_privacy_executor',
        'saas_privacy_dispatcher',
        'saas_privacy_verifier',
        'saas_notification_scheduler',
        'saas_notification_dispatcher',
        'saas_notification_directory',
        'saas_approval_scheduler_enterprise',
        'saas_approval_scheduler_privacy',
        'saas_approval_scheduler_audit',
        'saas_approval_scheduler_support_customer',
        'saas_approval_scheduler_support_staff',
        'saas_registration',
        'saas_onboarding',
        'saas_onboarding_status',
        'saas_runtime_provider_journal'
    ];
    unsafe_principals text[];
    outgoing_memberships integer;
    fixed_memberships integer;
    n1_incoming_memberships integer;
BEGIN
    SELECT array_agg(expected.role_name ORDER BY expected.role_name)
    INTO unsafe_principals
    FROM unnest(named_principals) AS expected(role_name)
    LEFT JOIN pg_roles AS principal ON principal.rolname = expected.role_name
    WHERE principal.oid IS NULL
       OR principal.rolcanlogin
       OR principal.rolsuper
       OR principal.rolcreatedb
       OR principal.rolcreaterole
       OR principal.rolreplication
       OR principal.rolbypassrls
       OR NOT principal.rolinherit
       OR principal.rolconnlimit <> -1
       OR principal.rolconfig IS NOT NULL;

    IF unsafe_principals IS NOT NULL THEN
        RAISE EXCEPTION
            'control-plane principal preflight rejected; run postgresql_principals.psql first';
    END IF;

    SELECT count(*) INTO outgoing_memberships
    FROM pg_auth_members AS membership
    JOIN pg_roles AS member ON member.oid = membership.member
    WHERE member.rolname = ANY(named_principals);

    SELECT count(*) INTO fixed_memberships
    FROM pg_auth_members AS membership
    JOIN pg_roles AS member ON member.oid = membership.member
    JOIN pg_roles AS granted ON granted.oid = membership.roleid
    WHERE NOT membership.admin_option
      AND (
          (
              member.rolname = 'saas_dispatcher_n1_compat'
              AND granted.rolname = 'saas_dispatcher'
              AND NOT COALESCE(
                  (to_jsonb(membership) ->> 'inherit_option')::boolean,
                  true
              )
              AND NOT COALESCE(
                  (to_jsonb(membership) ->> 'set_option')::boolean,
                  true
              )
          ) OR (
              member.rolname = 'saas_privacy_executor'
              AND granted.rolname = 'saas_platform_governance'
              AND COALESCE(
                  (to_jsonb(membership) ->> 'inherit_option')::boolean,
                  true
              )
              AND COALESCE(
                  (to_jsonb(membership) ->> 'set_option')::boolean,
                  true
              )
          )
      );

    SELECT count(*) INTO n1_incoming_memberships
    FROM pg_auth_members AS membership
    JOIN pg_roles AS granted ON granted.oid = membership.roleid
    WHERE granted.rolname = 'saas_dispatcher_n1_compat';

    IF n1_incoming_memberships <> 0 THEN
        RAISE EXCEPTION 'p0s3 N-1 Outbox compatibility login admission rejected';
    END IF;

    IF outgoing_memberships <> 2 OR fixed_memberships <> 2 THEN
        RAISE EXCEPTION
            'control-plane fixed principal membership preflight rejected';
    END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO
    saas_app, saas_authenticator, saas_governance, saas_dispatcher, saas_executor,
    saas_secret_broker, saas_preview_gateway, saas_webhook_dispatcher, saas_billing,
    saas_metering, saas_public_api, saas_platform, saas_platform_authenticator,
    saas_platform_app,
    saas_platform_governance, saas_platform_projector, saas_platform_support,
    saas_privacy_executor, saas_privacy_dispatcher, saas_privacy_verifier,
    saas_notification_scheduler, saas_notification_dispatcher,
    saas_notification_directory, saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy, saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff, saas_registration, saas_onboarding,
    saas_onboarding_status;

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
    saas_privacy_backup_retention_items,
    saas_approval_work_items,
    saas_approval_delegations,
    saas_notification_templates,
    saas_notification_preferences,
    saas_notification_deliveries,
    saas_notification_delivery_attempts,
    saas_operation_batches,
    saas_operation_batch_items,
    saas_self_service_registrations,
    saas_email_verification_challenges,
    saas_tenant_onboardings,
    saas_self_service_events
FROM PUBLIC, saas_app, saas_authenticator, saas_governance, saas_dispatcher,
    saas_executor, saas_secret_broker, saas_preview_gateway,
    saas_webhook_dispatcher, saas_billing, saas_metering,
    saas_platform_authenticator, saas_platform_app, saas_platform_governance,
    saas_platform_projector, saas_platform_support, saas_privacy_executor,
    saas_privacy_dispatcher, saas_privacy_verifier, saas_notification_scheduler,
    saas_notification_dispatcher, saas_notification_directory, saas_platform,
    saas_registration, saas_onboarding, saas_onboarding_status;

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
    saas_privacy_backup_retention_items,
    saas_approval_work_items,
    saas_approval_delegations,
    saas_notification_templates,
    saas_notification_preferences,
    saas_notification_deliveries,
    saas_notification_delivery_attempts,
    saas_operation_batches,
    saas_operation_batch_items,
    saas_self_service_registrations,
    saas_email_verification_challenges,
    saas_tenant_onboardings,
    saas_self_service_events
TO saas_platform;

-- Runtime Provider journal authority is intentionally independent from every
-- control-plane application/runtime role.  Converge all historical grants
-- before installing the fixed Fence-write and Receipt-write column sets.
DO $$
DECLARE
    privilege_name text;
    column_list text;
    target_table text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'saas_runtime_provider_journal'
          AND NOT rolcanlogin
          AND NOT rolsuper
          AND NOT rolcreatedb
          AND NOT rolcreaterole
          AND NOT rolreplication
          AND NOT rolbypassrls
          AND rolinherit
          AND rolconnlimit = -1
          AND rolconfig IS NULL
    ) OR EXISTS (
        SELECT 1
        FROM pg_auth_members AS membership
        JOIN pg_roles AS member ON member.oid = membership.member
        WHERE member.rolname = 'saas_runtime_provider_journal'
    ) THEN
        RAISE EXCEPTION
            'Runtime Provider journal principal bootstrap is absent or unsafe';
    END IF;
    IF to_regclass('public.saas_runtime_provider_operation_journal') IS NULL THEN
        RETURN;
    END IF;

    FOR target_table IN
        SELECT relation.relname
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relkind IN ('r', 'p')
          AND left(relation.relname, 5) = 'saas_'
        ORDER BY relation.relname
    LOOP
        EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
            quote_ident(target_table) || ' FROM saas_runtime_provider_journal';
        SELECT string_agg(quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum)
        INTO column_list
        FROM pg_attribute AS attribute
        WHERE attribute.attrelid =
            ('public.' || quote_ident(target_table))::regclass
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped;
        FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
        LOOP
            EXECUTE 'REVOKE ' || privilege_name || ' (' || column_list ||
                ') ON TABLE public.' || quote_ident(target_table) ||
                ' FROM saas_runtime_provider_journal';
        END LOOP;
    END LOOP;
END
$$;
DO $$
BEGIN
    IF to_regclass('public.saas_runtime_provider_operation_journal') IS NOT NULL THEN
        REVOKE ALL ON SCHEMA public FROM saas_runtime_provider_journal;
        GRANT USAGE ON SCHEMA public TO saas_runtime_provider_journal;
        GRANT SELECT ON saas_runtime_provider_operation_journal
        TO saas_runtime_provider_journal;
        GRANT INSERT (
            id, provider_type, operation_kind, placement_id, binding_revision,
            binding_hash, target_hash, idempotency_hash, request_hash
        ) ON saas_runtime_provider_operation_journal
        TO saas_runtime_provider_journal;
        GRANT UPDATE (
            receipt_hash, attributes_hash, response_hash, receipt_json, attributes_json
        ) ON saas_runtime_provider_operation_journal
        TO saas_runtime_provider_journal;
    END IF;
END
$$;

DO $$
DECLARE
    journal_oid oid;
BEGIN
    SELECT oid INTO STRICT journal_oid
    FROM pg_roles WHERE rolname = 'saas_runtime_provider_journal';
    IF to_regclass('public.saas_runtime_provider_operation_journal') IS NULL THEN
        RETURN;
    END IF;

    IF NOT has_schema_privilege(journal_oid, 'public', 'USAGE')
       OR has_schema_privilege(journal_oid, 'public', 'CREATE')
       OR NOT EXISTS (
            SELECT 1 FROM pg_class
            WHERE oid = 'public.saas_runtime_provider_operation_journal'::regclass
              AND relrowsecurity
              AND relforcerowsecurity
       ) OR (
            SELECT array_agg(privilege_type ORDER BY privilege_type)
            FROM information_schema.table_privileges
            WHERE table_schema = 'public'
              AND table_name = 'saas_runtime_provider_operation_journal'
              AND grantee = 'saas_runtime_provider_journal'
       ) IS DISTINCT FROM ARRAY['SELECT']::information_schema.character_data[]
       OR (
            SELECT count(DISTINCT column_name)
            FROM information_schema.column_privileges
            WHERE table_schema = 'public'
              AND table_name = 'saas_runtime_provider_operation_journal'
              AND grantee = 'saas_runtime_provider_journal'
              AND privilege_type = 'INSERT'
       ) <> 9 OR EXISTS (
            SELECT 1
            FROM information_schema.column_privileges
            WHERE table_schema = 'public'
              AND table_name = 'saas_runtime_provider_operation_journal'
              AND grantee = 'saas_runtime_provider_journal'
              AND privilege_type = 'INSERT'
              AND column_name NOT IN (
                  'id', 'provider_type', 'operation_kind', 'placement_id',
                  'binding_revision', 'binding_hash', 'target_hash',
                  'idempotency_hash', 'request_hash'
              )
       ) OR (
            SELECT count(DISTINCT column_name)
            FROM information_schema.column_privileges
            WHERE table_schema = 'public'
              AND table_name = 'saas_runtime_provider_operation_journal'
              AND grantee = 'saas_runtime_provider_journal'
              AND privilege_type = 'UPDATE'
       ) <> 5 OR EXISTS (
            SELECT 1
            FROM information_schema.column_privileges
            WHERE table_schema = 'public'
              AND table_name = 'saas_runtime_provider_operation_journal'
              AND grantee = 'saas_runtime_provider_journal'
              AND privilege_type = 'UPDATE'
              AND column_name NOT IN (
                  'receipt_hash', 'attributes_hash', 'response_hash',
                  'receipt_json', 'attributes_json'
              )
       ) OR has_table_privilege(
            journal_oid,
            'public.saas_runtime_provider_operation_journal',
            'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       ) OR has_any_column_privilege(
            journal_oid,
            'public.saas_runtime_provider_operation_journal',
            'REFERENCES'
       ) OR EXISTS (
            SELECT 1
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relkind IN ('r', 'p')
              AND left(relation.relname, 5) = 'saas_'
              AND relation.relname <> 'saas_runtime_provider_operation_journal'
              AND (
                  has_table_privilege(
                      journal_oid, relation.oid,
                      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
                  ) OR has_any_column_privilege(
                      journal_oid, relation.oid,
                      'SELECT,INSERT,UPDATE,REFERENCES'
                  )
              )
       ) OR (
            SELECT count(*)
            FROM pg_policy AS policy
            JOIN pg_roles AS target ON target.oid = ANY(policy.polroles)
            WHERE policy.polrelid =
                'public.saas_runtime_provider_operation_journal'::regclass
              AND target.rolname = 'saas_runtime_provider_journal'
              AND policy.polname IN (
                  'rls_runtime_provider_journal_select',
                  'rls_runtime_provider_journal_insert',
                  'rls_runtime_provider_journal_update'
              )
       ) <> 3
    THEN
        RAISE EXCEPTION 'Runtime Provider journal authority projection rejected';
    END IF;
END
$$;

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

-- Notification and approval operations keep rendered content, recipient
-- addresses, and raw reasons outside PostgreSQL. Browser services receive only
-- content-blind facts; isolated workers receive bounded state-machine columns.
GRANT SELECT, INSERT, UPDATE ON
    saas_approval_work_items,
    saas_approval_delegations,
    saas_notification_preferences,
    saas_operation_batches,
    saas_operation_batch_items
TO saas_governance, saas_platform_governance;
GRANT SELECT ON
    saas_notification_templates,
    saas_notification_deliveries,
    saas_notification_delivery_attempts
TO saas_governance, saas_platform_governance;
GRANT INSERT ON saas_notification_deliveries
TO saas_governance, saas_platform_governance;
GRANT UPDATE (
    recipient_read_at, acknowledged_at, read_idempotency_hmac,
    read_request_hmac, replay_generation, replay_receipt_generation, replay_idempotency_hmac,
    replay_request_hmac, status, attempt_count, available_at,
    last_error_code, last_error_hmac, version, updated_at
) ON saas_notification_deliveries
TO saas_governance, saas_platform_governance;
-- Tenant admins consume versioned templates but cannot author or retire them.
GRANT INSERT ON saas_notification_templates TO saas_platform_governance;
GRANT UPDATE (
    status, retired_at, retire_idempotency_hmac, retire_request_hmac
) ON saas_notification_templates
TO saas_platform_governance;
-- The Tenant-side Support approval transaction proves the exact Grant before
-- projecting the next Staff approval item.
GRANT SELECT (
    id, operation_id, tenant_id, requested_by_principal_id,
    customer_approved_by_user_id, status
) ON saas_platform_support_grants TO saas_governance;

-- PostgreSQL validates every relation referenced by every permissive policy
-- before choosing the caller's worker/realm branch. These planning-only grants
-- expose no rows without the referenced tables' own FORCE RLS policies.
GRANT SELECT (id, status) ON saas_global_users TO
    saas_notification_scheduler, saas_notification_dispatcher;
GRANT SELECT (tenant_id, user_id, status) ON saas_tenant_memberships TO
    saas_notification_scheduler, saas_notification_dispatcher;
GRANT SELECT (id, status) ON saas_platform_staff_principals TO
    saas_governance, saas_notification_scheduler, saas_notification_dispatcher;
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO
    saas_governance, saas_notification_scheduler, saas_notification_dispatcher;
GRANT SELECT ON saas_platform_support_sessions TO
    saas_governance, saas_notification_scheduler, saas_notification_dispatcher;
GRANT SELECT ON saas_approval_delegations TO saas_notification_dispatcher;

-- Recipient resolution runs on a distinct connection. It can read only one
-- active address selected by transaction-local directory GUCs. The same role
-- may enumerate only active Staff assignments that carry the notification-read
-- permission so the dead-letter sink can build its bounded audience.
REVOKE ALL PRIVILEGES ON
    saas_global_users,
    saas_platform_staff_principals,
    saas_platform_role_assignments
FROM saas_notification_directory;
GRANT SELECT (id, status, primary_email_normalized)
ON saas_global_users TO saas_notification_directory;
GRANT SELECT (id, status, email_normalized)
ON saas_platform_staff_principals TO saas_notification_directory;
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO saas_notification_directory;

-- Each approval source scheduler owns one source projection boundary. These
-- roles never inherit browser governance or the notification scheduler; FORCE
-- RLS below limits all common-table access to their exact source GUCs.
REVOKE ALL PRIVILEGES ON
    saas_enterprise_access_preflights,
    saas_platform_admin_operations,
    saas_platform_support_grants,
    saas_platform_support_sessions,
    saas_privacy_approval_bindings,
    saas_approval_work_items,
    saas_approval_delegations,
    saas_notification_templates,
    saas_notification_preferences,
    saas_notification_deliveries,
    saas_global_users,
    saas_tenants,
    saas_spaces,
    saas_tenant_memberships,
    saas_space_memberships,
    saas_projects,
    saas_project_memberships,
    saas_resource_grants,
    saas_enterprise_groups,
    saas_enterprise_group_memberships,
    saas_enterprise_custom_roles,
    saas_enterprise_group_role_assignments,
    saas_platform_staff_principals,
    saas_platform_role_assignments
FROM saas_approval_scheduler_enterprise, saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit, saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;

GRANT SELECT (
    id, tenant_id, space_id, project_id, operation_type, target_id,
    target_version, requested_by, snapshot_hash, status, approved_by,
    approved_at, executed_at, expires_at, created_at
) ON saas_enterprise_access_preflights TO saas_approval_scheduler_enterprise;
GRANT SELECT ON
    saas_tenants, saas_spaces, saas_projects, saas_project_memberships,
    saas_resource_grants, saas_enterprise_groups,
    saas_enterprise_group_memberships, saas_enterprise_custom_roles,
    saas_enterprise_group_role_assignments
TO saas_approval_scheduler_enterprise;
GRANT SELECT (id, status, security_version) ON saas_global_users TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_support_customer;
GRANT SELECT (tenant_id, user_id, role, status, version)
ON saas_tenant_memberships TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_support_customer;
GRANT SELECT (tenant_id, space_id, user_id, role, status, version)
ON saas_space_memberships TO saas_approval_scheduler_enterprise;

-- Planning closure for legacy permissive policies on Admin Operation,
-- Membership, Assignment, and Support Grant. FORCE RLS still returns zero
-- unless a pc5c2 source policy below admits the exact source/audience GUCs.
GRANT SELECT (id, status) ON saas_global_users TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT SELECT (tenant_id, user_id, role, status)
ON saas_tenant_memberships TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT SELECT (id, status) ON saas_platform_staff_principals TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT SELECT (
    id, operation_id, tenant_id, requested_by_principal_id, mode, status,
    customer_approved_by_user_id, expires_at
) ON saas_platform_support_grants TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;

GRANT SELECT (
    id, action, risk_level, tenant_id, target_type, target_id,
    requested_by_principal_id, approved_by_principal_id, request_hash,
    status, version, error_code, approved_at, completed_at, created_at, updated_at
) ON saas_platform_admin_operations TO
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT SELECT (
    operation_id, phase, target_type, target_id, tenant_id, manifest_id,
    subject_id, expected_target_version, expected_manifest_version,
    snapshot_hash, expires_at, created_at
) ON saas_privacy_approval_bindings TO saas_approval_scheduler_privacy;
GRANT SELECT (
    id, operation_id, tenant_id, requested_by_principal_id, mode,
    customer_approval_required, status, version, customer_approved_by_user_id,
    customer_approved_at, staff_approved_by_principal_id, staff_approved_at,
    requested_at, starts_at, expires_at, revoked_by_actor_type,
    revoked_by_actor_id, revoked_at, created_at, updated_at
) ON saas_platform_support_grants TO
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT SELECT (id, status, security_version) ON saas_platform_staff_principals TO
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_staff;
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_staff;
-- Planning-only: legacy Staff/Assignment FORCE-RLS policies reference these
-- four columns. No source-role policy exists on Support Session, so rows remain
-- invisible while PostgreSQL can plan the source-specific Staff audience path.
GRANT SELECT (grant_id, principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;

GRANT SELECT, INSERT ON saas_approval_work_items TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT SELECT ON saas_approval_delegations TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT UPDATE (
    status, decided_by_user_id, decided_by_principal_id, decision_code,
    decided_at, version, updated_at
) ON saas_approval_work_items TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT SELECT ON saas_notification_templates, saas_notification_preferences,
    saas_notification_deliveries TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;
GRANT INSERT ON saas_notification_deliveries TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;

GRANT SELECT ON
    saas_approval_work_items,
    saas_approval_delegations,
    saas_notification_templates,
    saas_notification_preferences,
    saas_notification_deliveries,
    saas_operation_batches,
    saas_operation_batch_items
TO saas_notification_scheduler;
GRANT INSERT ON saas_notification_deliveries TO saas_notification_scheduler;
GRANT UPDATE (
    status, priority, escalation_at, escalation_count, version, updated_at
) ON saas_approval_work_items TO saas_notification_scheduler;
GRANT UPDATE (
    status, success_count, failure_count, result_hmac, started_at, completed_at,
    leased_at, lease_expires_at, lease_token_hmac, executor_identity_sha256,
    lease_generation, version, updated_at
) ON saas_operation_batches TO saas_notification_scheduler;
GRANT UPDATE (
    operation_id, status, error_code, error_hmac, result_hmac, version, updated_at
) ON saas_operation_batch_items TO saas_notification_scheduler;

GRANT SELECT (id, status) ON saas_approval_work_items
TO saas_notification_dispatcher;
GRANT SELECT ON
    saas_notification_templates,
    saas_notification_preferences,
    saas_notification_deliveries,
    saas_notification_delivery_attempts
TO saas_notification_dispatcher;
GRANT UPDATE (
    status, attempt_count, available_at, leased_at, lease_expires_at,
    lease_token_hash, executor_identity_sha256, lease_generation,
    provider_message_hmac, delivered_at, suppression_code,
    inflight_boundary_code, last_error_code, last_error_hmac, version, updated_at
) ON saas_notification_deliveries TO saas_notification_dispatcher;
GRANT INSERT ON saas_notification_deliveries TO saas_notification_dispatcher;
GRANT INSERT ON saas_notification_delivery_attempts TO saas_notification_dispatcher;

-- Public registration and background Tenant onboarding are separate database
-- identities. FORCE RLS additionally binds every row to server-generated GUCs.
-- Revoke first so rerunning this file also removes any historical table-level
-- grants. Every write below is constrained to the columns emitted by the two
-- onboarding services; state transitions cannot rewrite identity or scope.
REVOKE ALL PRIVILEGES ON
    saas_self_service_registrations,
    saas_email_verification_challenges,
    saas_tenant_onboardings,
    saas_self_service_events,
    saas_global_users,
    saas_identity_connections,
    saas_password_credentials,
    saas_privacy_identity_tombstones,
    saas_tenants,
    saas_spaces,
    saas_tenant_memberships,
    saas_space_memberships,
    saas_billing_subscriptions,
    saas_pricing_snapshots,
    saas_billing_entitlements,
    saas_billing_balances,
    saas_runtime_placements,
    saas_runtime_partitions,
    saas_runtime_identity_aliases,
    saas_runtime_resource_bindings,
    saas_projects,
    saas_project_memberships,
    saas_admission_quotas,
    saas_control_plane_outbox
FROM saas_registration, saas_onboarding;

-- Existing Staff/Support policies contain subqueries against these two tables.
-- PostgreSQL validates their referenced columns even when a separate onboarding
-- policy admits the target row. These are planning-only grants: neither role is
-- a Platform role member, so FORCE RLS exposes zero Staff or Support rows.
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments
TO saas_registration, saas_onboarding;
GRANT SELECT (principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions
TO saas_registration, saas_onboarding;
-- Existing Global User and Tenant SELECT policies plan ownership subqueries
-- even when a dedicated onboarding policy admits the exact row. Cleared or
-- exact customer GUCs keep this planning grant row-invisible under FORCE RLS.
GRANT SELECT (tenant_id, user_id, status)
ON saas_tenant_memberships TO saas_registration;
GRANT SELECT (tenant_id, user_id, status)
ON saas_tenant_memberships TO saas_onboarding;
GRANT SELECT (tenant_id, space_id, user_id, status)
ON saas_space_memberships TO saas_onboarding;

GRANT SELECT ON
    saas_self_service_registrations,
    saas_email_verification_challenges
TO saas_registration;
GRANT INSERT (
    id, email_normalized, email_hash, display_name, tenant_name, tenant_slug,
    default_space_name, default_space_slug, plan_key, plan_policy_revision,
    home_region, status, challenge_generation, expires_at, verified_at,
    terminal_at, user_id, tenant_id, space_id, subscription_id,
    runtime_partition_id, default_project_id, pricing_snapshot_id,
    entitlement_id, runtime_binding_id, onboarding_id, plan_snapshot,
    plan_snapshot_hash, idempotency_key, request_hash, version, created_at,
    updated_at
) ON saas_self_service_registrations TO saas_registration;
GRANT UPDATE (
    status, challenge_generation, expires_at, verified_at, terminal_at,
    version, updated_at
) ON saas_self_service_registrations TO saas_registration;
GRANT INSERT (
    id, registration_id, generation, token_hash, status, delivery_status,
    delivery_attempts, delivery_idempotency_key, last_delivery_error_code,
    expires_at, delivered_at, consumed_at, expired_at, revoked_at, created_at,
    updated_at
) ON saas_email_verification_challenges TO saas_registration;
GRANT UPDATE (
    status, delivery_status, delivery_attempts, last_delivery_error_code,
    delivered_at, consumed_at, expired_at, revoked_at, updated_at
) ON saas_email_verification_challenges TO saas_registration;
GRANT SELECT ON saas_self_service_events TO saas_registration;
GRANT INSERT (
    id, aggregate_type, aggregate_id, tenant_id, user_id, sequence, event_type,
    from_status, to_status, facts, facts_hash, previous_hash, event_hash,
    occurred_at
) ON saas_self_service_events TO saas_registration;
GRANT SELECT (user_id, email_normalized, email_verified, status, created_at, updated_at)
ON saas_identity_connections TO saas_registration;
GRANT SELECT (user_id, login_email_normalized, updated_at)
ON saas_password_credentials TO saas_registration;
GRANT SELECT (id, locator_kind, locator_hash)
ON saas_privacy_identity_tombstones TO saas_registration;
GRANT INSERT (
    id, status, display_name, primary_email_normalized, security_version
) ON saas_global_users TO saas_registration;
GRANT SELECT (created_at, updated_at)
ON saas_global_users TO saas_registration;
GRANT INSERT (
    id, user_id, provider, issuer, subject, email_normalized, email_verified,
    status
) ON saas_identity_connections TO saas_registration;
GRANT INSERT (
    user_id, login_email_normalized, password_hash, password_version,
    failed_attempts, locked_until
) ON saas_password_credentials TO saas_registration;
GRANT INSERT (
    id, tenant_id, aggregate_type, aggregate_key, event_type, payload,
    idempotency_key, request_hash, attempt_count, available_at, claimed_at,
    claim_token, published_at
) ON saas_control_plane_outbox TO saas_registration;
GRANT SELECT (created_at)
ON saas_control_plane_outbox TO saas_registration;

GRANT SELECT ON
    saas_self_service_registrations,
    saas_global_users
TO saas_onboarding;
GRANT SELECT ON saas_tenant_onboardings TO saas_onboarding;
GRANT INSERT (
    id, registration_id, user_id, tenant_id, space_id, subscription_id,
    runtime_partition_id, runtime_placement_id, runtime_target_snapshot,
    runtime_request_hash, default_project_id, pricing_snapshot_id,
    entitlement_id, runtime_binding_id, plan_key, plan_policy_revision,
    plan_snapshot, plan_snapshot_hash, home_region, trial_days,
    trial_started_at, trial_ends_at, status, idempotency_key, request_hash,
    version, attempt_count, available_at, claimed_at, claim_token,
    lease_expires_at, last_error_code, last_error_detail, billing_ready_at,
    runtime_ready_at, project_ready_at, activated_at, first_run_id,
    completed_at, compensated_at, failure_stage, compensation_cursor,
    last_transition_at, created_at, updated_at
) ON saas_tenant_onboardings TO saas_onboarding;
GRANT UPDATE (
    trial_started_at, trial_ends_at, status, version, attempt_count,
    available_at, claimed_at, claim_token, lease_expires_at, last_error_code,
    last_error_detail, billing_ready_at, runtime_ready_at, project_ready_at,
    activated_at, first_run_id, completed_at, compensated_at, failure_stage,
    compensation_cursor, runtime_placement_id, runtime_target_snapshot,
    runtime_request_hash, last_transition_at, updated_at
) ON saas_tenant_onboardings TO saas_onboarding;
GRANT SELECT ON saas_self_service_events TO saas_onboarding;
GRANT INSERT (
    id, aggregate_type, aggregate_id, tenant_id, user_id, sequence, event_type,
    from_status, to_status, facts, facts_hash, previous_hash, event_hash,
    occurred_at
) ON saas_self_service_events TO saas_onboarding;
GRANT SELECT (
    id, slug, name, status, plan, home_region, lifecycle_version, created_at,
    updated_at
), INSERT (
    id, slug, name, status, plan, home_region, lifecycle_version
) ON saas_tenants TO saas_onboarding;
GRANT UPDATE (status, lifecycle_version, updated_at)
ON saas_tenants TO saas_onboarding;
GRANT SELECT (
    id, tenant_id, slug, name, status, created_at, updated_at
), INSERT (
    id, tenant_id, slug, name, status
) ON saas_spaces TO saas_onboarding;
GRANT UPDATE (status, updated_at)
ON saas_spaces TO saas_onboarding;
GRANT INSERT (
    tenant_id, user_id, role, status, version, joined_at
) ON saas_tenant_memberships TO saas_onboarding;
GRANT INSERT (
    tenant_id, space_id, user_id, role, status, version, joined_at
) ON saas_space_memberships TO saas_onboarding;
GRANT INSERT (
    id, tenant_id, aggregate_type, aggregate_key, event_type, payload,
    idempotency_key, request_hash, attempt_count, available_at, claimed_at,
    claim_token, published_at
) ON saas_control_plane_outbox TO saas_onboarding;
GRANT SELECT (created_at)
ON saas_control_plane_outbox TO saas_onboarding;

-- The onboarding worker can touch only the preallocated facts of its exact Saga.
-- FORCE RLS policies in p0s000000002 additionally bind every row to the trusted
-- registration/onboarding/actor/Tenant GUC tuple; Runtime Partition reads and
-- writes are also bound to the frozen Saga Placement. Run writes remain excluded.
GRANT SELECT (
    id, tenant_id, plan_key, provider, provider_customer_ref,
    provider_subscription_ref, status, current_period_start,
    current_period_end, trial_ends_at, cancel_at_period_end,
    provider_event_cursor, version, updated_by, created_at, updated_at
) ON saas_billing_subscriptions TO saas_onboarding;
GRANT INSERT (
    id, tenant_id, plan_key, provider, provider_customer_ref,
    provider_subscription_ref, status, current_period_start,
    current_period_end, trial_ends_at, cancel_at_period_end,
    provider_event_cursor, version, updated_by
) ON saas_billing_subscriptions TO saas_onboarding;
GRANT UPDATE (
    status, current_period_start, current_period_end, trial_ends_at,
    cancel_at_period_end, provider_event_cursor, version, updated_by, updated_at
) ON saas_billing_subscriptions TO saas_onboarding;

GRANT SELECT (
    id, tenant_id, plan_key, currency, rates, version, effective_from,
    effective_until, created_by, created_at
) ON saas_pricing_snapshots TO saas_onboarding;
GRANT INSERT (
    id, tenant_id, plan_key, currency, rates, version, effective_from,
    effective_until, created_by
) ON saas_pricing_snapshots TO saas_onboarding;

GRANT SELECT (
    id, tenant_id, subscription_id, scope_type, scope_key, space_id,
    project_id, user_id, model_key, meter, unit, limit_quantity,
    reserved_quantity, consumed_quantity, concurrency_limit,
    active_reservations, hard_limit, period, period_start, period_end,
    status, version, updated_by, created_at, updated_at
) ON saas_billing_entitlements TO saas_onboarding;
GRANT INSERT (
    id, tenant_id, subscription_id, scope_type, scope_key, space_id,
    project_id, user_id, model_key, meter, unit, limit_quantity,
    reserved_quantity, consumed_quantity, concurrency_limit,
    active_reservations, hard_limit, period, period_start, period_end,
    status, version, updated_by
) ON saas_billing_entitlements TO saas_onboarding;
GRANT UPDATE (status, period_start, period_end, version, updated_by, updated_at)
ON saas_billing_entitlements TO saas_onboarding;

GRANT SELECT (
    tenant_id, currency, available_minor, reserved_minor, consumed_minor,
    version, updated_at
) ON saas_billing_balances TO saas_onboarding;
GRANT INSERT (
    tenant_id, currency, available_minor, reserved_minor, consumed_minor, version
) ON saas_billing_balances TO saas_onboarding;

GRANT SELECT (
    id, runtime_type, data_region, failure_domain, official_schema_revision,
    capacity_class, status, created_at, updated_at
) ON saas_runtime_placements TO saas_onboarding;
GRANT SELECT (
    id, tenant_id, space_id, placement_id, runtime_type, runtime_version,
    physical_partition_key, placement_generation, source_revision,
    adapter_contract_version, status, created_at, updated_at
) ON saas_runtime_partitions TO saas_onboarding;
GRANT INSERT (
    id, tenant_id, space_id, placement_id, runtime_type, runtime_version,
    physical_partition_key, placement_generation, source_revision,
    adapter_contract_version, status
) ON saas_runtime_partitions TO saas_onboarding;
GRANT UPDATE (status, updated_at)
ON saas_runtime_partitions TO saas_onboarding;

GRANT SELECT (runtime_partition_id, user_id, runtime_user_key, status, created_at)
ON saas_runtime_identity_aliases TO saas_onboarding;
GRANT INSERT (runtime_partition_id, user_id, runtime_user_key, status)
ON saas_runtime_identity_aliases TO saas_onboarding;
GRANT UPDATE (status)
ON saas_runtime_identity_aliases TO saas_onboarding;

GRANT SELECT (
    id, tenant_id, space_id, name, visibility, created_by, status,
    authorization_version, created_at, updated_at
) ON saas_projects TO saas_onboarding;
GRANT INSERT (
    id, tenant_id, space_id, name, visibility, created_by, status,
    authorization_version
) ON saas_projects TO saas_onboarding;
GRANT UPDATE (status, authorization_version, updated_at)
ON saas_projects TO saas_onboarding;

GRANT SELECT (
    tenant_id, space_id, project_id, subject_type, subject_id, role, status,
    expires_at, created_by, version, created_at, updated_at
) ON saas_project_memberships TO saas_onboarding;
GRANT INSERT (
    tenant_id, space_id, project_id, subject_type, subject_id, role, status,
    expires_at, created_by, version
) ON saas_project_memberships TO saas_onboarding;
GRANT UPDATE (status, version, updated_at)
ON saas_project_memberships TO saas_onboarding;

GRANT SELECT (
    id, runtime_partition_id, tenant_id, space_id, project_id, resource_type,
    runtime_resource_id, saas_resource_id, partition_generation,
    binding_generation, status, created_at
) ON saas_runtime_resource_bindings TO saas_onboarding;
GRANT INSERT (
    id, runtime_partition_id, tenant_id, space_id, project_id, resource_type,
    runtime_resource_id, saas_resource_id, partition_generation,
    binding_generation, status
) ON saas_runtime_resource_bindings TO saas_onboarding;
GRANT UPDATE (status)
ON saas_runtime_resource_bindings TO saas_onboarding;

GRANT SELECT (
    id, tenant_id, space_id, project_id, resource, limit_units,
    reserved_units, consumed_units, version, created_at, updated_at
) ON saas_admission_quotas TO saas_onboarding;
GRANT INSERT (
    id, tenant_id, space_id, project_id, resource, limit_units,
    reserved_units, consumed_units, version
) ON saas_admission_quotas TO saas_onboarding;

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
-- The Runtime Partition verifier policy contains a content-blind Privacy impact
-- subquery. PostgreSQL plans every permissive SELECT policy before choosing the
-- tenant branch, so the customer app needs only the two join columns. FORCE RLS
-- still returns no Privacy work rows to saas_app.
GRANT SELECT (manifest_id, runtime_partition_id)
ON saas_privacy_deletion_work_items TO saas_app;

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
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = 'saas_enterprise_scim_directories'::regclass
          AND attname = 'provider_type'
          AND NOT attisdropped
    ) AND EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = 'saas_enterprise_scim_directories'::regclass
          AND attname = 'attribute_mapping'
          AND NOT attisdropped
    ) THEN
        EXECUTE 'GRANT SELECT (provider_type, attribute_mapping) '
            'ON saas_enterprise_scim_directories TO saas_app';
    END IF;
END
$$;

-- Exact SCIM bearer matching remains inside a content-blind SECURITY DEFINER
-- predicate. Application readers can execute the boolean check but never gain
-- SELECT on either current or successor bearer digests.
DO $$
BEGIN
    IF to_regprocedure('saas_scim_source_token_matches(uuid,uuid,text)') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON FUNCTION '
            'saas_scim_source_token_matches(uuid, uuid, text) FROM PUBLIC';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
            'saas_scim_source_token_matches(uuid, uuid, text) TO '
            'saas_app, saas_governance, saas_platform, saas_privacy_executor';
    END IF;
END
$$;

GRANT INSERT, UPDATE ON
    saas_egress_policies,
    saas_execution_profiles,
    saas_secret_bindings,
    saas_preview_leases
TO saas_app;

GRANT SELECT, INSERT ON saas_authorization_decisions TO saas_app;

-- The pc6 public API ACL is version-tolerant so the same authority file remains
-- safe during N-1 rollback. Existing-table grants are always revoked first;
-- they are installed only while both pc6 marker tables exist.
DO $$
BEGIN
    EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE '
        'saas_tenants, saas_spaces, saas_projects, saas_service_accounts, '
        'saas_api_credentials, saas_tenant_memberships, saas_space_memberships, '
        'saas_tasks, saas_execution_sessions, '
        'saas_session_tasks, saas_runs, saas_run_events, saas_admission_quotas, '
        'saas_quota_reservations, saas_control_plane_outbox, '
        'saas_platform_role_assignments, saas_platform_support_sessions, '
        'saas_secret_access_leases, saas_preview_leases, '
        'saas_runner_certificates, saas_capability_tokens FROM saas_public_api';
    IF to_regclass('public.saas_public_api_mutation_receipts') IS NOT NULL
       AND to_regclass('public.saas_public_api_rate_limits') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE '
            'saas_public_api_mutation_receipts, saas_public_api_rate_limits FROM '
            'PUBLIC, saas_app, saas_authenticator, saas_governance, saas_dispatcher, '
            'saas_executor, saas_secret_broker, saas_preview_gateway, '
            'saas_webhook_dispatcher, saas_billing, saas_metering, '
            'saas_platform_authenticator, saas_platform_app, '
            'saas_platform_governance, saas_platform_projector, '
            'saas_platform_support, saas_privacy_executor, '
            'saas_privacy_dispatcher, saas_privacy_verifier, '
            'saas_notification_scheduler, saas_notification_dispatcher, '
            'saas_notification_directory, saas_public_api';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE '
            'saas_public_api_mutation_receipts TO saas_public_api';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE '
            'saas_public_api_rate_limits TO saas_public_api';
        EXECUTE 'GRANT SELECT ON TABLE saas_tenants, saas_spaces, saas_projects, '
            'saas_service_accounts, saas_api_credentials, saas_execution_sessions, '
            'saas_platform_role_assignments, saas_platform_support_sessions, '
            'saas_secret_access_leases, saas_preview_leases, '
            'saas_runner_certificates, saas_capability_tokens TO saas_public_api';
        EXECUTE 'GRANT SELECT (tenant_id, user_id, status) ON TABLE '
            'saas_tenant_memberships TO saas_public_api';
        EXECUTE 'GRANT SELECT (tenant_id, space_id, user_id, status) ON TABLE '
            'saas_space_memberships TO saas_public_api';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE saas_tasks, saas_session_tasks, '
            'saas_run_events, saas_quota_reservations TO saas_public_api';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE saas_runs, '
            'saas_admission_quotas TO saas_public_api';
        EXECUTE 'GRANT INSERT ON TABLE saas_control_plane_outbox TO saas_public_api';
        EXECUTE 'GRANT SELECT (created_at) ON TABLE '
            'saas_control_plane_outbox TO saas_public_api';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE '
            'saas_public_api_mutation_receipts, saas_public_api_rate_limits '
            'TO saas_platform';
    END IF;
END
$$;

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
-- Customer onboarding status has a dedicated read-only database authority.
-- Table-level REVOKE does not clear column ACLs. Dynamically revoke every
-- current SELECT column from the status authority on its four dependency
-- tables, plus every customer-status column from the historical app role,
-- before restoring only the allowlisted projections below.
DO $$
DECLARE
    target_role text;
    target_table text;
    target_privilege text;
    column_list text;
BEGIN
    FOR target_role, target_table IN
        SELECT * FROM (VALUES
            ('saas_onboarding_status', 'saas_tenant_onboardings'),
            ('saas_onboarding_status', 'saas_tenant_memberships'),
            ('saas_onboarding_status', 'saas_platform_role_assignments'),
            ('saas_onboarding_status', 'saas_platform_support_sessions'),
            ('saas_app', 'saas_tenant_onboardings')
        ) AS targets(role_name, table_name)
    LOOP
        SELECT string_agg(quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum)
        INTO column_list
        FROM pg_attribute AS attribute
        WHERE attribute.attrelid =
            ('public.' || quote_ident(target_table))::regclass
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped;
        IF column_list IS NOT NULL THEN
            FOREACH target_privilege IN ARRAY
                ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
            LOOP
                EXECUTE 'REVOKE ' || target_privilege || ' (' || column_list ||
                    ') ON TABLE public.' || quote_ident(target_table) ||
                    ' FROM ' || quote_ident(target_role);
            END LOOP;
        END IF;
    END LOOP;
END
$$;
REVOKE ALL PRIVILEGES ON
    saas_tenant_onboardings,
    saas_tenant_memberships
FROM saas_onboarding_status;
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO saas_onboarding_status;
GRANT SELECT (principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions TO saas_onboarding_status;
GRANT SELECT (
    id, user_id, tenant_id, space_id, default_project_id, status, version,
    trial_ends_at, last_transition_at, created_at
) ON saas_tenant_onboardings TO saas_onboarding_status;
GRANT SELECT (tenant_id, user_id, status)
ON saas_tenant_memberships TO saas_onboarding_status;

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

GRANT SELECT ON saas_control_plane_outbox TO saas_dispatcher;
-- A column GRANT does not narrow a historical table-level UPDATE.  Revoke it
-- explicitly first so applying this file converges existing deployments.
REVOKE UPDATE ON saas_control_plane_outbox FROM saas_dispatcher;
GRANT UPDATE (
    attempt_count, available_at, claimed_at, claim_token, last_error_code,
    last_error_digest, published_at, quarantined_at
) ON saas_control_plane_outbox TO saas_dispatcher;
REVOKE ALL PRIVILEGES ON saas_outbox_quarantine_events FROM PUBLIC;
GRANT SELECT, INSERT ON saas_outbox_quarantine_events TO saas_dispatcher;

-- Schema-forward application rollback only: the p0s3 migration and this
-- p0s3 authority bootstrap stay at N while the pinned N-1 worker switches to
-- a login inheriting saas_dispatcher_n1_compat.  Never replay the 9451a64
-- migration/roles SQL over this schema.  Fail closed before restoring the
-- security-patched N-1 fixed column grants unless all three p0s3 guards are
-- present: raw-error NULL constraint, restrictive quarantine policy, and the
-- enabled BEFORE sanitizer/boundary trigger.  This SQL only installs the
-- dormant schema bridge and never creates a password.  Production admission
-- remains blocked by ``python -m saas.n1_outbox_admission`` until a signed
-- patched-worker artifact Receipt can be verified and credential-bound.
REVOKE ALL PRIVILEGES ON saas_control_plane_outbox
FROM saas_dispatcher_n1_compat;
-- Zero incoming members is the only currently admitted state.  Catalog checks
-- below diagnose an otherwise well-shaped provisional LOGIN without exposing
-- its name, but still reject it: 9451a64 can log raw SQL bind parameters before
-- the database sanitizer runs.  A later patched worker may be enabled only by
-- a separate workflow that verifies a trusted artifact Receipt and binds its
-- non-exportable credential; this generic bootstrap cannot self-attest that.
DO $$
DECLARE
    compat_oid oid;
    incoming_count integer;
    incoming_oid oid;
    incoming_is_safe boolean;
    incoming_direct_memberships integer;
    incoming_login_memberships integer;
    incoming_authority_dependencies integer;
    admission_role_settings integer;
BEGIN
    SELECT oid INTO STRICT compat_oid
    FROM pg_roles WHERE rolname = 'saas_dispatcher_n1_compat';

    SELECT count(*), min(membership.member)
    INTO incoming_count, incoming_oid
    FROM pg_auth_members AS membership
    WHERE membership.roleid = compat_oid;

    IF incoming_count > 1 THEN
        RAISE EXCEPTION 'p0s3 N-1 Outbox compatibility login admission rejected';
    END IF;

    IF incoming_count = 1 THEN
        SELECT
            member.rolcanlogin
            AND NOT member.rolsuper
            AND NOT member.rolcreatedb
            AND NOT member.rolcreaterole
            AND NOT member.rolreplication
            AND NOT member.rolbypassrls
            AND member.rolinherit
            AND NOT membership.admin_option
            AND COALESCE(
                (to_jsonb(membership) ->> 'inherit_option')::boolean,
                true
            )
            AND NOT COALESCE(
                (to_jsonb(membership) ->> 'set_option')::boolean,
                true
            )
        INTO incoming_is_safe
        FROM pg_auth_members AS membership
        JOIN pg_roles AS member ON member.oid = membership.member
        WHERE membership.roleid = compat_oid
          AND membership.member = incoming_oid;

        SELECT count(*) INTO incoming_direct_memberships
        FROM pg_auth_members WHERE member = incoming_oid;

        -- The rollback LOGIN is an endpoint identity, never a role that any
        -- LOGIN/NOLOGIN principal may inherit or SET ROLE into.
        SELECT count(*) INTO incoming_login_memberships
        FROM pg_auth_members WHERE roleid = incoming_oid;

        SELECT count(*) INTO incoming_authority_dependencies
        FROM pg_shdepend AS dependency
        WHERE dependency.refclassid = 'pg_authid'::regclass
          AND dependency.refobjid = incoming_oid
          AND dependency.deptype IN ('a', 'o');

        SELECT count(*) INTO admission_role_settings
        FROM pg_db_role_setting
        WHERE setrole IN (incoming_oid, compat_oid);

        IF NOT COALESCE(incoming_is_safe, false)
            OR incoming_direct_memberships <> 1
            OR incoming_login_memberships <> 0
            OR incoming_authority_dependencies <> 0
            OR admission_role_settings <> 0
        THEN
            RAISE EXCEPTION 'p0s3 N-1 Outbox compatibility login admission rejected';
        END IF;

        RAISE EXCEPTION 'p0s3 N-1 Outbox compatibility login admission rejected';
    END IF;
END
$$;
-- The legacy Outbox RLS predicate references these authority tables at plan
-- time.  Grant only the named columns below and force the compatibility role
-- to observe an empty relation even if another permissive policy is added.
DROP POLICY IF EXISTS rls_n1_compat_role_assignments_deny
ON saas_platform_role_assignments;
CREATE POLICY rls_n1_compat_role_assignments_deny
ON saas_platform_role_assignments AS RESTRICTIVE FOR SELECT
TO saas_dispatcher_n1_compat USING (false);
DROP POLICY IF EXISTS rls_n1_compat_support_sessions_deny
ON saas_platform_support_sessions;
CREATE POLICY rls_n1_compat_support_sessions_deny
ON saas_platform_support_sessions AS RESTRICTIVE FOR SELECT
TO saas_dispatcher_n1_compat USING (false);
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_class
        WHERE oid = 'public.saas_control_plane_outbox'::regclass
          AND relrowsecurity
          AND relforcerowsecurity
    ) OR (
        SELECT count(*)
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relname IN (
              'saas_platform_role_assignments',
              'saas_platform_support_sessions'
          )
          AND relation.relrowsecurity
          AND relation.relforcerowsecurity
    ) <> 2 OR EXISTS (
        SELECT 1
        FROM (
            VALUES
                (
                    'saas_platform_role_assignments',
                    'rls_n1_compat_role_assignments_deny'
                ),
                (
                    'saas_platform_support_sessions',
                    'rls_n1_compat_support_sessions_deny'
                )
        ) AS expected(table_name, policy_name)
        LEFT JOIN pg_class AS relation
          ON relation.relname = expected.table_name
         AND relation.relnamespace = 'public'::regnamespace
         AND relation.relkind IN ('r', 'p')
        LEFT JOIN pg_policy AS policy
          ON policy.polrelid = relation.oid
         AND policy.polname = expected.policy_name
        LEFT JOIN pg_roles AS compat
          ON compat.rolname = 'saas_dispatcher_n1_compat'
        WHERE relation.oid IS NULL
           OR policy.oid IS NULL
           OR policy.polpermissive
           OR policy.polcmd <> 'r'
           OR cardinality(policy.polroles) <> 1
           OR compat.oid IS NULL
           OR NOT (compat.oid = ANY(policy.polroles))
           OR regexp_replace(
                pg_get_expr(policy.polqual, policy.polrelid),
                '[[:space:]()]', '', 'g'
              ) <> 'false'
           OR policy.polwithcheck IS NOT NULL
    ) OR EXISTS (
        SELECT 1
        FROM pg_policy AS policy
        JOIN pg_class AS relation ON relation.oid = policy.polrelid
        JOIN pg_roles AS compat
          ON compat.rolname = 'saas_dispatcher_n1_compat'
        WHERE relation.relnamespace = 'public'::regnamespace
          AND relation.relname IN (
              'saas_platform_role_assignments',
              'saas_platform_support_sessions'
          )
          AND compat.oid = ANY(policy.polroles)
          AND NOT (
              (
                  relation.relname = 'saas_platform_role_assignments'
                  AND policy.polname = 'rls_n1_compat_role_assignments_deny'
              ) OR (
                  relation.relname = 'saas_platform_support_sessions'
                  AND policy.polname = 'rls_n1_compat_support_sessions_deny'
              )
          )
    ) OR EXISTS (
        SELECT 1
        FROM pg_rewrite
        WHERE ev_class = 'public.saas_control_plane_outbox'::regclass
          AND rulename <> '_RETURN'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.saas_control_plane_outbox'::regclass
          AND conname = 'ck_outbox_legacy_error_null'
          AND contype = 'c'
          AND convalidated
          AND regexp_replace(
              pg_get_constraintdef(oid), '[[:space:]()]', '', 'g'
          ) = 'CHECKlast_errorISNULL'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_policy
        WHERE polrelid = 'public.saas_control_plane_outbox'::regclass
          AND polname = 'rls_outbox_n1_compat_dispatchable'
          AND NOT polpermissive
          AND polcmd = '*'
          AND cardinality(polroles) = 1
          AND (
              SELECT oid FROM pg_roles
              WHERE rolname = 'saas_dispatcher_n1_compat'
          ) = ANY(polroles)
          AND regexp_replace(
              pg_get_expr(polqual, polrelid), '[[:space:]()]', '', 'g'
          ) = 'quarantined_atISNULL'
          AND regexp_replace(
              pg_get_expr(polwithcheck, polrelid), '[[:space:]()]', '', 'g'
          ) = 'quarantined_atISNULL'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_proc AS sanitizer
        JOIN pg_language AS language ON language.oid = sanitizer.prolang
        JOIN pg_class AS outbox
          ON outbox.oid = 'public.saas_control_plane_outbox'::regclass
        JOIN pg_roles AS compat
          ON compat.rolname = 'saas_dispatcher_n1_compat'
        WHERE sanitizer.oid =
            to_regprocedure('public.saas_bridge_n1_outbox_update()')
          AND sanitizer.proowner = outbox.relowner
          AND language.lanname = 'plpgsql'
          AND NOT sanitizer.prosecdef
          AND NOT sanitizer.proleakproof
          AND sanitizer.provolatile = 'v'
          AND sanitizer.proparallel = 'u'
          AND sanitizer.proconfig = ARRAY['search_path=pg_catalog']::text[]
          AND encode(sha256(convert_to(btrim(sanitizer.prosrc), 'UTF8')), 'hex') =
              '06622ed237a21880bf84846f082deb876c3935597cd692f283d6f505cb616e3a'
          AND NOT has_function_privilege(compat.oid, sanitizer.oid, 'EXECUTE')
          AND NOT EXISTS (
              SELECT 1 FROM aclexplode(sanitizer.proacl) AS acl
              WHERE acl.grantee <> sanitizer.proowner
          )
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgrelid = 'public.saas_control_plane_outbox'::regclass
          AND tgname = 'trg_outbox_n1_compatibility'
          AND NOT tgisinternal
          AND tgenabled = 'O'
          AND tgtype = 19
          AND tgfoid = to_regprocedure('public.saas_bridge_n1_outbox_update()')
    ) OR (
        SELECT count(*)
        FROM pg_trigger
        WHERE tgrelid = 'public.saas_control_plane_outbox'::regclass
          AND NOT tgisinternal
          AND (tgtype & 19) = 19
    ) <> 1
    THEN
        RAISE EXCEPTION
            'p0s3 N-1 Outbox compatibility guards are absent or disabled';
    END IF;
END
$$;
DO $$
DECLARE
    privilege_name text;
    column_list text;
    target_table text;
BEGIN
    FOR target_table IN
        SELECT relation.relname
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relkind IN ('r', 'p')
          AND left(relation.relname, 5) = 'saas_'
        ORDER BY relation.relname
    LOOP
        EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
            quote_ident(target_table) || ' FROM saas_dispatcher_n1_compat';
        SELECT string_agg(quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum)
        INTO column_list
        FROM pg_attribute AS attribute
        WHERE attribute.attrelid =
            ('public.' || quote_ident(target_table))::regclass
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped;
        FOREACH privilege_name IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
        LOOP
            EXECUTE 'REVOKE ' || privilege_name || ' (' || column_list ||
                ') ON TABLE public.' || quote_ident(target_table) ||
                ' FROM saas_dispatcher_n1_compat';
        END LOOP;
    END LOOP;
END
$$;
REVOKE ALL ON SCHEMA public FROM saas_dispatcher_n1_compat;
GRANT USAGE ON SCHEMA public TO saas_dispatcher_n1_compat;
-- Fixed 9451a64 query projection.  Never replace these with table privileges:
-- an Outbox schema migration must drain the compat worker, apply DDL, and pass
-- a fresh catalog admission before restart so new columns cannot be inherited.
GRANT SELECT (
    id, published_at, available_at, claimed_at, created_at, claim_token,
    event_type, aggregate_type, aggregate_key, payload, attempt_count
) ON saas_control_plane_outbox TO saas_dispatcher_n1_compat;
GRANT UPDATE (
    attempt_count, available_at, claimed_at, claim_token, last_error, published_at
) ON saas_control_plane_outbox TO saas_dispatcher_n1_compat;
-- Planning-only columns required by the pre-existing public Outbox RLS policy
-- branches.  The role-specific restrictive false policies above expose no
-- Staff/Support rows, and the pinned verifier checks table privileges (these
-- remain false).
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO saas_dispatcher_n1_compat;
GRANT SELECT (principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions TO saas_dispatcher_n1_compat;

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
    id, tenant_id, space_id, project_id, session_id, created_by,
    status, fence_token, lease_owner, lease_expires_at, created_at
) ON saas_runs TO saas_metering;
-- pc6a adds machine provenance to Runs. Keep this authority file safe to
-- reapply after an N-1 rollback, where the column deliberately no longer exists.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = 'saas_runs'::regclass
          AND attname = 'created_by_service_account_id'
          AND NOT attisdropped
    ) THEN
        GRANT SELECT (created_by_service_account_id) ON saas_runs TO saas_metering;
    END IF;
END
$$;
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
