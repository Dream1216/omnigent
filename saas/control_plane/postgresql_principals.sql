-- Cluster-principal transaction body. Never invoke this file directly with
-- plain `psql -f`; operators must use postgresql_principals.psql so the first
-- rejected mutation rolls the whole bootstrap back.
--
-- This is the only control-plane installation step that requires authority to
-- create and alter PostgreSQL roles. It intentionally contains no schema,
-- table, sequence, function, or row data privilege. Run it before Alembic as a
-- cluster principal operator with CREATEROLE (and ADMIN OPTION on every
-- pre-existing named principal), then run Alembic as the NOCREATEROLE schema
-- owner only after the database owner has run postgresql_database.psql.
-- Database-object grants are installed afterwards by
-- postgresql_roles.psql.

-- A pinned N-1 login is an admitted runtime, not bootstrap state. Refuse to
-- mutate the shared role graph while any login or other role can inherit or
-- SET ROLE to the dormant compatibility principal. PostgreSQL 16+ records the
-- creator/operator's management-only edge as ADMIN TRUE, INHERIT FALSE,
-- SET FALSE; that edge has no runtime authority and is the sole exception.
-- PostgreSQL 15 lacks the latter two columns, so the COALESCE defaults keep
-- every incoming membership active and fail closed there.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_auth_members AS membership
        JOIN pg_roles AS granted ON granted.oid = membership.roleid
        WHERE granted.rolname = 'saas_dispatcher_n1_compat'
          AND (
              NOT membership.admin_option
              OR COALESCE(
                  (to_jsonb(membership) ->> 'inherit_option')::boolean,
                  true
              )
              OR COALESCE(
                  (to_jsonb(membership) ->> 'set_option')::boolean,
                  true
              )
          )
    ) THEN
        RAISE EXCEPTION
            'control-plane principal bootstrap rejected: N-1 compatibility principal has an incoming member';
    END IF;
END
$$;

DO $$
DECLARE
    principal_name text;
    membership_record record;
    named_principals constant text[] := ARRAY[
        'saas_app',
        'saas_authenticator',
        'saas_governance',
        'saas_dispatcher',
        'saas_dispatcher_n1_compat',
        'saas_executor',
        'saas_runner_agent',
        'saas_secret_broker',
        'saas_preview_gateway',
        'saas_preview_edge',
        'saas_preview_owner',
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
        'saas_runtime_provider_journal',
        'omnigent_runtime_app'
    ];
BEGIN
    -- PostgreSQL 16 correctly forbids a non-superuser CREATEROLE operator
    -- from spelling NOSUPERUSER, NOCREATEDB, NOREPLICATION, or NOBYPASSRLS,
    -- even when those flags are already false. Existing principals must
    -- therefore prove those immutable-to-this-operator flags before the first
    -- CREATE/ALTER. Newly created roles receive the same safe defaults and the
    -- final projection below rechecks them inside this transaction.
    IF EXISTS (
        SELECT 1
        FROM pg_roles AS role
        WHERE role.rolname = ANY(named_principals)
          AND (
              role.rolsuper
              OR role.rolcreatedb
              OR role.rolreplication
              OR role.rolbypassrls
          )
    ) THEN
        RAISE EXCEPTION
            'control-plane principal bootstrap rejected: immutable role flags are unsafe';
    END IF;

    FOREACH principal_name IN ARRAY named_principals
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = principal_name) THEN
            EXECUTE 'CREATE ROLE ' || quote_ident(principal_name);
        END IF;
        EXECUTE 'ALTER ROLE ' || quote_ident(principal_name) ||
            ' NOLOGIN NOCREATEROLE INHERIT CONNECTION LIMIT -1';
        EXECUTE 'ALTER ROLE ' || quote_ident(principal_name) || ' RESET ALL';
    END LOOP;

    IF EXISTS (
        SELECT 1
        FROM pg_roles AS role
        WHERE role.rolname = ANY(named_principals)
          AND (
              role.rolcanlogin
              OR role.rolsuper
              OR role.rolcreatedb
              OR role.rolcreaterole
              OR role.rolreplication
              OR role.rolbypassrls
              OR NOT role.rolinherit
              OR role.rolconnlimit <> -1
              OR role.rolconfig IS NOT NULL
          )
    ) THEN
        RAISE EXCEPTION
            'control-plane principal bootstrap rejected: role flag projection failed';
    END IF;

    -- Capability principals may not inherit arbitrary cluster roles. Incoming
    -- service-login memberships are deliberately untouched; only outgoing
    -- capability-to-capability edges are converged here.
    FOR membership_record IN
        SELECT granted.rolname AS granted_role, member.rolname AS member_role
        FROM pg_auth_members AS membership
        JOIN pg_roles AS granted ON granted.oid = membership.roleid
        JOIN pg_roles AS member ON member.oid = membership.member
        WHERE member.rolname = ANY(named_principals)
    LOOP
        EXECUTE 'REVOKE ' || quote_ident(membership_record.granted_role) ||
            ' FROM ' || quote_ident(membership_record.member_role);
    END LOOP;

    -- These are the only fixed capability-to-capability memberships.
    GRANT saas_dispatcher TO saas_dispatcher_n1_compat
        WITH INHERIT FALSE, SET FALSE;
    GRANT saas_platform_governance TO saas_privacy_executor;
END
$$;
