-- PostgreSQL 18 cluster admission for direct Runner database credentials.
--
-- This file mutates pg_catalog-owned routine ACLs and therefore MUST run as
-- the managed-cluster bootstrap superuser after Alembic and the object-role
-- projection.  Object/database/schema owners are intentionally insufficient.
-- Invoke only through postgresql_runner_agent_cluster.psql so every revoke,
-- support grant, and final assertion is one first-error-stopping transaction.

DO $$
DECLARE
    caller_is_superuser boolean;
    server_major integer := current_setting('server_version_num')::integer / 10000;
    schema_head text;
    runner_role record;
    schema_owner record;
    schema_owner_oid oid;
    api_oid oid;
    api_owner oid;
    signature text;
    api_signatures constant text[] := ARRAY[
        'saas_canonical_json_v1(jsonb)',
        'saas_canonical_json_sha256_v1(jsonb)',
        'saas_runner_worktree_authority_live_v1(text,uuid,uuid,uuid,text,bigint,boolean)',
        'saas_runner_agent_identity_v1(uuid,bigint)',
        'saas_runner_agent_registered_v1(uuid,bigint)',
        'saas_runner_allocate_worktree_v1(text,uuid,uuid,uuid,uuid,text,bigint,integer,text,text,uuid)',
        'saas_runner_append_worktree_event_v1(uuid,text,jsonb,text)',
        'saas_runner_materialization_grant_v1(uuid,uuid,bigint,bigint,text)',
        'saas_runner_transition_worktree_v1(text,uuid,uuid,bigint,bigint,text,bigint,boolean,integer,text,text,text,text,text)',
        'saas_runner_issue_isolation_grant_v1(text,uuid,uuid,uuid,bigint,bigint,uuid,text,integer)',
        'saas_runner_isolation_snapshot_v1(text,uuid,uuid)',
        'saas_runner_isolation_metadata_v1(text,uuid,uuid)',
        'saas_runner_redeem_isolation_grant_v1(text,uuid,uuid,jsonb)',
        'saas_runner_claim_secret_lease_v1(text,uuid,uuid)',
        'saas_runner_preview_authority_v1(text,uuid,uuid,uuid,bigint,bigint)',
        'saas_runner_claim_preview_start_v1(text,uuid,uuid,uuid,bigint,bigint,text)',
        'saas_runner_claim_preview_stop_v1(text,uuid,uuid,uuid,bigint,bigint,text)',
        'saas_runner_transition_preview_v1(text,text,uuid,uuid,uuid,bigint,bigint,uuid,text,uuid,bigint,boolean,boolean,text)'
    ];
BEGIN
    SELECT role.rolsuper INTO caller_is_superuser
    FROM pg_roles AS role WHERE role.rolname = current_user;

    IF server_major <> 18 OR NOT COALESCE(caller_is_superuser, false) THEN
        RAISE EXCEPTION
            'Runner cluster admission rejected: PostgreSQL 18 superuser required';
    END IF;
    IF to_regclass('public.saas_alembic_version') IS NULL
       OR to_regclass('public.saas_runner_registrations') IS NULL THEN
        RAISE EXCEPTION
            'Runner cluster admission rejected: P0S10 authority is unavailable';
    END IF;
    EXECUTE 'SELECT version_num FROM public.saas_alembic_version'
    INTO STRICT schema_head;
    IF schema_head <> 'p0s000000010' THEN
        RAISE EXCEPTION
            'Runner cluster admission rejected: P0S10 authority is unavailable';
    END IF;
    SELECT role.* INTO runner_role
    FROM pg_roles AS role WHERE role.rolname = 'saas_runner_agent';
    IF NOT FOUND OR runner_role.rolcanlogin OR runner_role.rolsuper
       OR runner_role.rolcreatedb OR runner_role.rolcreaterole
       OR runner_role.rolreplication OR runner_role.rolbypassrls
       OR NOT runner_role.rolinherit OR runner_role.rolconnlimit <> -1
       OR runner_role.rolconfig IS NOT NULL
       OR EXISTS (
            SELECT 1 FROM pg_auth_members AS membership
            WHERE membership.member = runner_role.oid
       ) THEN
        RAISE EXCEPTION
            'Runner cluster admission rejected: Runner base role is unsafe';
    END IF;
    SELECT relation.relowner INTO STRICT schema_owner_oid
    FROM pg_class AS relation
    WHERE relation.oid = 'public.saas_runner_registrations'::regclass;
    SELECT role.* INTO STRICT schema_owner
    FROM pg_roles AS role WHERE role.oid = schema_owner_oid;
    IF schema_owner.rolsuper OR schema_owner.rolcreatedb
       OR schema_owner.rolcreaterole OR schema_owner.rolreplication
       OR schema_owner.rolbypassrls OR schema_owner.rolconfig IS NOT NULL
       OR EXISTS (
            SELECT 1 FROM pg_auth_members AS membership
            WHERE membership.member = schema_owner_oid
               OR membership.roleid = schema_owner_oid
       ) THEN
        RAISE EXCEPTION
            'Runner cluster admission rejected: schema owner is unsafe';
    END IF;
    FOREACH signature IN ARRAY api_signatures LOOP
        api_oid := to_regprocedure('public.' || signature);
        IF api_oid IS NULL THEN
            RAISE EXCEPTION
                'Runner cluster admission rejected: Runner API is unavailable';
        END IF;
        SELECT procedure.proowner INTO STRICT api_owner
        FROM pg_proc AS procedure WHERE procedure.oid = api_oid;
        IF api_owner <> schema_owner_oid THEN
            RAISE EXCEPTION
                'Runner cluster admission rejected: Runner API owner drifted';
        END IF;
    END LOOP;
    IF (
        SELECT count(*)
        FROM pg_settings AS setting
        WHERE (
            setting.name = 'max_notify_queue_pages'
            AND setting.setting = '64'
            AND setting.context = 'postmaster'
            AND NOT setting.pending_restart
            AND setting.source = 'configuration file'
        ) OR (
            setting.name = 'max_prepared_transactions'
            AND setting.setting = '0'
            AND setting.context = 'postmaster'
            AND NOT setting.pending_restart
            AND setting.source = 'configuration file'
        )
    ) <> 2 OR EXISTS (SELECT 1 FROM pg_prepared_xacts) THEN
        RAISE EXCEPTION
            'Runner cluster admission rejected: PostgreSQL settings are unsafe';
    END IF;
END
$$;

-- Persistent database amplification and cross-session lock primitives are
-- never inherited through PUBLIC by an untrusted per-incarnation Runner.
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_creat(integer) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_create(oid) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_from_bytea(oid, bytea) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_put(oid, bigint, bytea) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lowrite(integer, bytea) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_truncate(integer, integer) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_truncate64(integer, bigint) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_unlink(oid) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_import(text) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_import(text, oid) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) FROM PUBLIC, saas_runner_agent;

REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(integer, integer)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock_shared(bigint)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock_shared(integer, integer)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(integer, integer)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock_shared(bigint)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock_shared(integer, integer)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock(bigint)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock(integer, integer)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock_shared(bigint)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock_shared(integer, integer)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_xact_lock(bigint)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_xact_lock(integer, integer)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_xact_lock_shared(bigint)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_xact_lock_shared(integer, integer)
    FROM PUBLIC, saas_runner_agent;

REVOKE EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text, boolean)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, bytea, boolean)
    FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_notify(text, text) FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_current_xact_id() FROM PUBLIC, saas_runner_agent;
REVOKE EXECUTE ON FUNCTION pg_catalog.txid_current() FROM PUBLIC, saas_runner_agent;

-- Audited central authorities retain only signatures used by the source tree.
-- The dynamic schema owner owns migration-created SECURITY DEFINER gates that
-- take the bigint transaction lock. The database owner runs
-- postgresql_migration.py's session-scoped try lock. Neither receives a
-- blocking session lock or any integer-pair/shared variant.
DO $$
DECLARE
    schema_owner name;
    database_owner name;
BEGIN
    SELECT pg_get_userbyid(relation.relowner) INTO schema_owner
    FROM pg_class AS relation
    WHERE relation.oid = 'public.saas_runner_registrations'::regclass;

    EXECUTE 'GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO '
        || quote_ident(schema_owner);
    SELECT pg_get_userbyid(database.datdba) INTO database_owner
    FROM pg_database AS database
    WHERE database.datname = current_database();
    EXECUTE 'GRANT EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock(bigint) TO '
        || quote_ident(database_owner);
    EXECUTE 'GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_unlock(bigint) TO '
        || quote_ident(database_owner);
END
$$;

-- Exact transaction-lock callers, mapped to their deployed authority:
--   saas_app: tenant-side governed Support decisions;
--   saas_governance: EnterpriseAccessService;
--   saas_public_api: public API rate/idempotency fencing;
--   saas_dispatcher/saas_executor/saas_platform: SchedulingControlPlane;
--   saas_platform_governance/saas_platform_support: platform lifecycle/support;
--   saas_privacy_executor/saas_privacy_dispatcher: privacy lifecycle/execution;
--   saas_registration/saas_onboarding: registration and onboarding event chains;
--   saas_billing: BillingControlPlane.
GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO
    saas_app,
    saas_governance,
    saas_public_api,
    saas_dispatcher,
    saas_executor,
    saas_platform,
    saas_platform_governance,
    saas_platform_support,
    saas_privacy_executor,
    saas_privacy_dispatcher,
    saas_registration,
    saas_onboarding,
    saas_billing,
    saas_metering;

-- EnterpriseScimService.bulk_request is the sole blocking session-lock caller.
GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) TO saas_governance;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_unlock(bigint) TO saas_governance;

DO $$
DECLARE
    denied_signatures constant text[] := ARRAY[
        'lo_creat(integer)',
        'lo_create(oid)',
        'lo_from_bytea(oid,bytea)',
        'lo_put(oid,bigint,bytea)',
        'lowrite(integer,bytea)',
        'lo_truncate(integer,integer)',
        'lo_truncate64(integer,bigint)',
        'lo_unlink(oid)',
        'lo_import(text)',
        'lo_import(text,oid)',
        'lo_export(oid,text)',
        'pg_advisory_lock(bigint)',
        'pg_advisory_lock(integer,integer)',
        'pg_advisory_lock_shared(bigint)',
        'pg_advisory_lock_shared(integer,integer)',
        'pg_advisory_xact_lock(bigint)',
        'pg_advisory_xact_lock(integer,integer)',
        'pg_advisory_xact_lock_shared(bigint)',
        'pg_advisory_xact_lock_shared(integer,integer)',
        'pg_try_advisory_lock(bigint)',
        'pg_try_advisory_lock(integer,integer)',
        'pg_try_advisory_lock_shared(bigint)',
        'pg_try_advisory_lock_shared(integer,integer)',
        'pg_try_advisory_xact_lock(bigint)',
        'pg_try_advisory_xact_lock(integer,integer)',
        'pg_try_advisory_xact_lock_shared(bigint)',
        'pg_try_advisory_xact_lock_shared(integer,integer)',
        'pg_logical_emit_message(boolean,text,text,boolean)',
        'pg_logical_emit_message(boolean,text,bytea,boolean)',
        'pg_notify(text,text)',
        'pg_current_xact_id()',
        'txid_current()'
    ];
    signature text;
BEGIN
    FOREACH signature IN ARRAY denied_signatures LOOP
        IF to_regprocedure('pg_catalog.' || signature) IS NULL
           OR has_function_privilege(
                'saas_runner_agent', 'pg_catalog.' || signature, 'EXECUTE'
           ) THEN
            RAISE EXCEPTION
                'Runner cluster admission rejected: unsafe routine authority remains';
        END IF;
    END LOOP;
END
$$;
