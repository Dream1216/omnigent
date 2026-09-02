-- Database-level production authority transaction body. Never invoke this
-- file directly with plain `psql -f`; operators must use
-- postgresql_database.psql so a rejected mutation rolls the whole boundary
-- transaction back.
--
-- Run as the current database owner (or an explicitly audited superuser)
-- after cluster principals exist and before Alembic. PostgreSQL grants TEMP
-- to PUBLIC by default on many installations. A dedicated worker that can
-- create pg_temp relations can shadow an unqualified durable fence table, so
-- production admission requires this privilege to be absent globally.
DO $$
DECLARE
    database_owner name;
    caller_is_superuser boolean;
    public_has_connect boolean;
    public_has_temporary boolean;
    public_has_schema_create boolean;
    public_has_schema_usage boolean;
BEGIN
    SELECT pg_get_userbyid(database.datdba)
    INTO database_owner
    FROM pg_database AS database
    WHERE database.datname = current_database();

    SELECT role.rolsuper
    INTO caller_is_superuser
    FROM pg_roles AS role
    WHERE role.rolname = current_user;

    IF current_user <> database_owner AND NOT COALESCE(caller_is_superuser, false) THEN
        RAISE EXCEPTION
            'control-plane database authority rejected: caller is not the database owner';
    END IF;

    EXECUTE 'REVOKE CONNECT, TEMPORARY, CREATE ON DATABASE '
        || quote_ident(current_database()) || ' FROM PUBLIC';
    REVOKE USAGE, CREATE ON SCHEMA public FROM PUBLIC;

    -- Schema reachability is a database-owner authority, not an object-owner
    -- grant.  Keep this exact projection in the transaction body as well as in
    -- the higher-level four-authority converger so direct verification/replay
    -- of this documented phase cannot strand otherwise valid object ACLs.
    GRANT USAGE ON SCHEMA public TO
        omnigent_runtime_app,
        saas_app,
        saas_authenticator,
        saas_governance,
        saas_dispatcher,
        saas_dispatcher_n1_compat,
        saas_executor,
        saas_runner_agent,
        saas_secret_broker,
        saas_preview_gateway,
        saas_preview_edge,
        saas_preview_owner,
        saas_webhook_dispatcher,
        saas_billing,
        saas_metering,
        saas_public_api,
        saas_platform,
        saas_platform_authenticator,
        saas_platform_app,
        saas_platform_governance,
        saas_platform_projector,
        saas_platform_support,
        saas_privacy_executor,
        saas_privacy_dispatcher,
        saas_privacy_verifier,
        saas_notification_scheduler,
        saas_notification_dispatcher,
        saas_notification_directory,
        saas_approval_scheduler_enterprise,
        saas_approval_scheduler_privacy,
        saas_approval_scheduler_audit,
        saas_approval_scheduler_support_customer,
        saas_approval_scheduler_support_staff,
        saas_registration,
        saas_onboarding,
        saas_onboarding_status,
        saas_runtime_provider_journal;

    SELECT EXISTS (
        SELECT 1
        FROM pg_database AS database
        CROSS JOIN LATERAL aclexplode(
            COALESCE(database.datacl, acldefault('d', database.datdba))
        ) AS privilege
        WHERE database.datname = current_database()
          AND privilege.grantee = 0
          AND privilege.privilege_type = 'CONNECT'
    )
    INTO public_has_connect;

    IF public_has_connect THEN
        RAISE EXCEPTION
            'control-plane database authority rejected: PUBLIC CONNECT remains enabled';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pg_database AS database
        CROSS JOIN LATERAL aclexplode(
            COALESCE(database.datacl, acldefault('d', database.datdba))
        ) AS privilege
        WHERE database.datname = current_database()
          AND privilege.grantee = 0
          AND privilege.privilege_type = 'TEMPORARY'
    )
    INTO public_has_temporary;

    IF public_has_temporary THEN
        RAISE EXCEPTION
            'control-plane database authority rejected: PUBLIC TEMPORARY remains enabled';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pg_namespace AS namespace
        CROSS JOIN LATERAL aclexplode(
            COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))
        ) AS privilege
        WHERE namespace.nspname = 'public'
          AND privilege.grantee = 0
          AND privilege.privilege_type = 'CREATE'
    )
    INTO public_has_schema_create;

    IF public_has_schema_create THEN
        RAISE EXCEPTION
            'control-plane database authority rejected: PUBLIC schema CREATE remains enabled';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pg_namespace AS namespace
        CROSS JOIN LATERAL aclexplode(
            COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))
        ) AS privilege
        WHERE namespace.nspname = 'public'
          AND privilege.grantee = 0
          AND privilege.privilege_type = 'USAGE'
    )
    INTO public_has_schema_usage;

    IF public_has_schema_usage THEN
        RAISE EXCEPTION
            'control-plane database authority rejected: PUBLIC schema USAGE remains enabled';
    END IF;
END
$$;
