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
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_platform') THEN
        CREATE ROLE saas_platform NOLOGIN NOSUPERUSER NOBYPASSRLS;
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
ALTER ROLE saas_platform NOLOGIN NOSUPERUSER NOBYPASSRLS;

GRANT USAGE ON SCHEMA public TO
    saas_app, saas_authenticator, saas_governance, saas_dispatcher, saas_executor,
    saas_secret_broker, saas_preview_gateway, saas_platform;

GRANT SELECT, INSERT, UPDATE ON
    saas_global_users,
    saas_identity_connections,
    saas_identity_conflicts,
    saas_oidc_login_transactions,
    saas_auth_sessions,
    saas_password_credentials,
    saas_control_plane_outbox
TO saas_authenticator;

GRANT SELECT, INSERT, UPDATE ON
    saas_global_users,
    saas_auth_sessions,
    saas_tenants,
    saas_spaces,
    saas_tenant_memberships,
    saas_space_memberships,
    saas_projects,
    saas_project_memberships,
    saas_resource_grants,
    saas_runtime_resource_bindings,
    saas_runtime_binding_sagas,
    saas_ownership_transfers,
    saas_member_removal_preflights,
    saas_control_plane_outbox
TO saas_governance;

GRANT SELECT ON
    saas_runs,
    saas_repositories,
    saas_changeset_groups,
    saas_changesets,
    saas_worktree_instances
TO saas_governance;

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
    saas_repositories,
    saas_changeset_groups,
    saas_changesets,
    saas_worktree_quotas
TO saas_app;

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
GRANT SELECT, INSERT, UPDATE ON
    saas_runner_registrations,
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
-- privileges. These SELECT grants do not expose rows: both token tables use
-- FORCE RLS and only the role-specific exact-token policy can reveal a row.
GRANT SELECT ON
    saas_secret_access_leases,
    saas_preview_leases
TO saas_app, saas_governance, saas_executor, saas_secret_broker, saas_preview_gateway;

GRANT SELECT ON
    saas_secret_bindings,
    saas_runs,
    saas_runner_registrations
TO saas_secret_broker;

GRANT SELECT, UPDATE ON saas_secret_access_leases TO saas_secret_broker;

GRANT SELECT ON
    saas_runs,
    saas_runner_registrations,
    saas_worktree_instances
TO saas_preview_gateway;

GRANT SELECT, UPDATE ON saas_preview_leases TO saas_preview_gateway;

GRANT SELECT, UPDATE ON saas_control_plane_outbox TO saas_dispatcher;

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
    saas_runner_registrations,
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
    saas_control_plane_outbox
TO saas_platform;
