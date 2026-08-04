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
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_platform') THEN
        CREATE ROLE saas_platform NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

ALTER ROLE saas_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_authenticator NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_governance NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_dispatcher NOLOGIN NOSUPERUSER NOBYPASSRLS;
ALTER ROLE saas_platform NOLOGIN NOSUPERUSER NOBYPASSRLS;

GRANT USAGE ON SCHEMA public TO
    saas_app, saas_authenticator, saas_governance, saas_dispatcher, saas_platform;

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
    saas_runtime_binding_sagas
TO saas_app;

GRANT SELECT, INSERT ON saas_authorization_decisions TO saas_app;

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
    saas_control_plane_outbox
TO saas_platform;
