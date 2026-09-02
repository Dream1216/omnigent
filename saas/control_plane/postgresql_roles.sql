-- Transaction body: never invoke this file directly with plain `psql -f`.
-- psql operators must use postgresql_roles.psql, which enables ON_ERROR_STOP
-- and wraps this entire authority projection in one transaction. API callers
-- must execute this body inside an explicit transaction.
-- Run as the direct, narrow owner of the SaaS control-plane objects after
-- every schema migration. The database and official Runtime objects have
-- different owners and are deliberately outside this authority boundary.
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
      );

    IF n1_incoming_memberships <> 0 THEN
        RAISE EXCEPTION 'p0s3 N-1 Outbox compatibility login admission rejected';
    END IF;

    IF outgoing_memberships <> 2 OR fixed_memberships <> 2 THEN
        RAISE EXCEPTION
            'control-plane fixed principal membership preflight rejected';
    END IF;
END
$$;

-- This authority body is intentionally replayable at the two supported
-- schema-forward rollback points, p0s3 and p0s4.  Object-name probing alone is
-- not a version boundary: a partial restore or a manually-created marker could
-- otherwise make a newer grant execute over an older RLS/trigger contract.
-- Reject every mixed state before the first ACL mutation below.
DO $$
DECLARE
    schema_revision text;
    revision_rows integer;
    registration_table oid := to_regclass('public.saas_self_service_registrations');
    privacy_manifest_table oid := to_regclass('public.saas_privacy_deletion_manifests');
    rate_policy_table oid := to_regclass('public.saas_registration_rate_limit_policies');
    rate_counter_table oid := to_regclass('public.saas_registration_rate_limits');
    privacy_guard_function oid :=
        to_regprocedure('public.saas_guard_self_service_registration_privacy_erasure()');
    consume_function oid := to_regprocedure(
        'public.saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)'
    );
    prune_function oid := to_regprocedure(
        'public.saas_prune_registration_rate_limits(text,text,integer)'
    );
    status_function oid :=
        to_regprocedure('public.saas_registration_rate_limit_status()');
    privacy_column_present boolean;
    privacy_column_exact boolean;
    privacy_constraints integer;
    privacy_constraint_contract_hash text;
    privacy_policies integer;
    registration_policy_contract_hash text;
    privacy_triggers integer;
    privacy_trigger_contracts integer;
    privacy_function_contracts integer;
    rate_relations integer;
    rate_relation_owners integer;
    rate_policies integer;
    rate_policy_contract_hash text;
    rate_functions integer;
    rate_function_contracts integer;
    policy_columns text[];
    counter_columns text[];
    rate_column_contract_hash text;
    policy_constraints text[];
    counter_constraints text[];
    rate_constraint_contract_hash text;
    policy_indexes text[];
    counter_indexes text[];
    rate_index_contract_hash text;
    network_constraints integer;
    network_policy_actions text[];
    network_policy_contract text[];
    rotation_guard_present boolean;
BEGIN
    IF to_regclass('public.saas_alembic_version') IS NULL THEN
        RAISE EXCEPTION
            'control-plane schema revision/object contract rejected';
    END IF;
    SELECT count(*), min(version_num)::text
    INTO revision_rows, schema_revision
    FROM public.saas_alembic_version;
    IF revision_rows <> 1 OR schema_revision NOT IN (
        'p0s000000003',
        'p0s000000004',
        'p0s000000005',
        'p0s000000006',
        'p0s000000007',
        'p0s000000008',
        'p0s000000009',
        'p0s000000010',
        'p0s000000011'
    ) THEN
        RAISE EXCEPTION
            'control-plane schema revision/object contract rejected';
    END IF;

    SELECT count(*) > 0, count(*) = 1 AND bool_and(
        attribute.atttypid = 'uuid'::regtype
        AND NOT attribute.attnotnull
        AND NOT attribute.attisdropped
        AND attribute.attidentity = ''
        AND attribute.attgenerated = ''
        AND attribute_default.oid IS NULL
    )
    INTO privacy_column_present, privacy_column_exact
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS attribute_default
      ON attribute_default.adrelid = attribute.attrelid
     AND attribute_default.adnum = attribute.attnum
    WHERE attribute.attrelid = registration_table
      AND attribute.attname = 'deletion_manifest_id'
      AND NOT attribute.attisdropped;

    IF schema_revision IN ('p0s000000003', 'p0s000000004') THEN
        IF privacy_column_present
           OR privacy_guard_function IS NOT NULL
           OR rate_policy_table IS NOT NULL
           OR rate_counter_table IS NOT NULL
           OR consume_function IS NOT NULL
           OR prune_function IS NOT NULL
           OR status_function IS NOT NULL
           OR EXISTS (
                SELECT 1
                FROM pg_policy
                WHERE polrelid = registration_table
                  AND polname IN (
                      'rls_self_service_registrations_privacy_target',
                      'rls_self_service_registrations_privacy_anonymize'
                  )
           ) OR EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgrelid = registration_table
                  AND tgname = 'trg_self_service_registration_privacy_erasure'
                  AND NOT tgisinternal
           )
        THEN
            RAISE EXCEPTION
                'control-plane schema revision/object contract rejected';
        END IF;
        RETURN;
    END IF;

    IF registration_table IS NULL
       OR privacy_manifest_table IS NULL
       OR NOT privacy_column_exact
       OR privacy_guard_function IS NULL
       OR rate_policy_table IS NULL
       OR rate_counter_table IS NULL
       OR consume_function IS NULL
       OR prune_function IS NULL
       OR status_function IS NULL
    THEN
        RAISE EXCEPTION
            'control-plane schema revision/object contract rejected';
    END IF;

    SELECT count(*)
    INTO privacy_constraints
    FROM pg_constraint
    WHERE conrelid = registration_table
      AND (
          (
              conname = 'fk_self_service_registration_deletion_manifest'
              AND contype = 'f'
              AND confrelid = privacy_manifest_table
          ) OR (
              conname = 'ck_self_service_registration_deletion_manifest'
              AND contype = 'c'
              AND position('deletion_manifest_id' IN pg_get_constraintdef(oid)) > 0
              AND position('status' IN pg_get_constraintdef(oid)) > 0
              AND position('revoked' IN pg_get_constraintdef(oid)) > 0
          )
      );
    SELECT encode(sha256(convert_to(
        string_agg(
            concat_ws(
                '|', constraint_row.conname, constraint_row.contype::text,
                constraint_row.convalidated::text,
                constraint_row.condeferrable::text,
                constraint_row.condeferred::text,
                regexp_replace(
                    pg_get_constraintdef(constraint_row.oid),
                    '[[:space:]]+', '', 'g'
                )
            ),
            E'\n' ORDER BY constraint_row.conname
        ),
        'UTF8'
    )), 'hex')
    INTO privacy_constraint_contract_hash
    FROM pg_constraint AS constraint_row
    WHERE constraint_row.conrelid = registration_table
      AND constraint_row.conname IN (
          'fk_self_service_registration_deletion_manifest',
          'ck_self_service_registration_deletion_manifest'
      );
    SELECT count(*)
    INTO privacy_policies
    FROM pg_policy AS policy
    JOIN pg_roles AS target ON target.oid = ANY(policy.polroles)
    WHERE policy.polrelid = registration_table
      AND target.rolname = 'saas_privacy_executor'
      AND cardinality(policy.polroles) = 1
      AND policy.polpermissive
      AND policy.polname IN (
          'rls_self_service_registrations_privacy_target',
          'rls_self_service_registrations_privacy_anonymize'
      )
      AND policy.polcmd = CASE
          WHEN policy.polname = 'rls_self_service_registrations_privacy_target' THEN 'r'
          ELSE 'w'
      END;
    SELECT encode(sha256(convert_to(
        string_agg(
            concat_ws(
                '|', policy.polname, policy.polpermissive::text, policy.polcmd,
                ARRAY(
                    SELECT CASE
                        WHEN policy_role.role_oid = 0 THEN 'PUBLIC'
                        ELSE pg_get_userbyid(policy_role.role_oid)
                    END
                    FROM unnest(policy.polroles) AS policy_role(role_oid)
                    ORDER BY 1
                )::text,
                COALESCE(
                    regexp_replace(
                        pg_get_expr(policy.polqual, policy.polrelid),
                        '[[:space:]]+', '', 'g'
                    ),
                    '<null>'
                ),
                COALESCE(
                    regexp_replace(
                        pg_get_expr(policy.polwithcheck, policy.polrelid),
                        '[[:space:]]+', '', 'g'
                    ),
                    '<null>'
                )
            ),
            E'\n' ORDER BY policy.polname
        ),
        'UTF8'
    )), 'hex')
    INTO registration_policy_contract_hash
    FROM pg_policy AS policy
    WHERE policy.polrelid = registration_table;
    SELECT count(*)
    INTO privacy_triggers
    FROM pg_trigger
    WHERE tgrelid = registration_table
      AND tgname = 'trg_self_service_registration_privacy_erasure'
      AND tgfoid = privacy_guard_function
      AND tgtype = 19
      AND tgenabled = 'O'
      AND tgnargs = 0
      AND tgattr = ''::int2vector
      AND tgqual IS NULL
      AND NOT tgisinternal;
    SELECT count(*)
    INTO privacy_trigger_contracts
    FROM pg_trigger
    WHERE tgrelid = registration_table
      AND NOT tgisinternal;
    SELECT count(*)
    INTO privacy_function_contracts
    FROM pg_proc AS procedure
    JOIN pg_language AS language ON language.oid = procedure.prolang
    WHERE procedure.oid = privacy_guard_function
      AND procedure.proowner = (
          SELECT relowner FROM pg_class WHERE oid = registration_table
      )
      AND language.lanname = 'plpgsql'
      AND procedure.prokind = 'f'
      AND NOT procedure.prosecdef
      AND NOT procedure.proleakproof
      AND procedure.provolatile = 'v'
      AND procedure.proparallel = 'u'
      AND procedure.proconfig IS NULL
      AND pg_get_function_result(procedure.oid) = 'trigger'
      AND encode(sha256(convert_to(
          btrim(procedure.prosrc, E' \n\r\t'), 'UTF8'
      )), 'hex') =
          '504a18be57b9bed8c87d7b2c96c7c33764a335f8005ccf814a3845dfb058ef7b';
    IF privacy_constraints <> 2
       OR privacy_constraint_contract_hash IS DISTINCT FROM
          'f40979410766d2c6de7f7c96db487c7f47c7c016fc561deb6a3bf24e3fbf18f3'
       OR privacy_policies <> 2
       -- pg_dump/pg_restore preserves the seven-policy authority but PostgreSQL
       -- reparses three varchar-array predicates into an equivalent text-array
       -- AST.  Admit only the exact migrated or exact logical-roundtrip catalog
       -- hashes; retaining the full-table aggregate still rejects an added,
       -- removed, or widened policy.
       OR (
          registration_policy_contract_hash IS DISTINCT FROM
             'a0e09fe6eb825ad9bed3428d4bfc31e2fa6d6b1bc1324199a9fa5f7ccff375b1'
          AND registration_policy_contract_hash IS DISTINCT FROM
             'd9cdb654555fb782037992891e66fac188c7260c404b36f0b10dcef0e0406605'
       )
       OR privacy_triggers <> 1
       OR privacy_trigger_contracts <> 1
       OR privacy_function_contracts <> 1
    THEN
        RAISE EXCEPTION
            'control-plane schema revision/object contract rejected';
    END IF;

    SELECT count(*)
    INTO rate_relations
    FROM pg_class
    WHERE oid IN (rate_policy_table, rate_counter_table)
      AND relkind IN ('r', 'p')
      AND relrowsecurity
      AND relforcerowsecurity;
    SELECT count(DISTINCT relowner)
    INTO rate_relation_owners
    FROM pg_class
    WHERE oid IN (rate_policy_table, rate_counter_table);
    SELECT array_agg(attname::text ORDER BY attnum)
    INTO policy_columns
    FROM pg_attribute
    WHERE attrelid = rate_policy_table
      AND attnum > 0
      AND NOT attisdropped;
    SELECT array_agg(attname::text ORDER BY attnum)
    INTO counter_columns
    FROM pg_attribute
    WHERE attrelid = rate_counter_table
      AND attnum > 0
      AND NOT attisdropped;
    SELECT encode(sha256(convert_to(
        string_agg(
            concat_ws(
                '|', relation.relname, attribute.attnum::text,
                attribute.attname,
                format_type(attribute.atttypid, attribute.atttypmod),
                attribute.attnotnull::text,
                COALESCE(
                    pg_get_expr(attribute_default.adbin, attribute_default.adrelid),
                    '<null>'
                ),
                attribute.attidentity,
                attribute.attgenerated
            ),
            E'\n' ORDER BY relation.relname, attribute.attnum
        ),
        'UTF8'
    )), 'hex')
    INTO rate_column_contract_hash
    FROM pg_class AS relation
    JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
    LEFT JOIN pg_attrdef AS attribute_default
      ON attribute_default.adrelid = attribute.attrelid
     AND attribute_default.adnum = attribute.attnum
    WHERE relation.oid IN (rate_policy_table, rate_counter_table)
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped;
    SELECT array_agg(conname::text ORDER BY conname)
    INTO policy_constraints
    FROM pg_constraint
    WHERE conrelid = rate_policy_table
      AND contype <> 'n';
    SELECT array_agg(conname::text ORDER BY conname)
    INTO counter_constraints
    FROM pg_constraint
    WHERE conrelid = rate_counter_table
      AND contype <> 'n';
    SELECT encode(sha256(convert_to(
        string_agg(
            concat_ws(
                '|', relation.relname, constraint_row.conname,
                constraint_row.contype::text,
                constraint_row.convalidated::text,
                constraint_row.condeferrable::text,
                constraint_row.condeferred::text,
                regexp_replace(
                    pg_get_constraintdef(constraint_row.oid),
                    '[[:space:]]+', '', 'g'
                )
            ),
            E'\n' ORDER BY relation.relname, constraint_row.conname
        ),
        'UTF8'
    )), 'hex')
    INTO rate_constraint_contract_hash
    FROM pg_constraint AS constraint_row
    JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid
    WHERE constraint_row.conrelid IN (rate_policy_table, rate_counter_table)
      -- PostgreSQL 18 also exposes virtual NOT NULL constraints in pg_constraint.
      AND constraint_row.contype <> 'n';
    SELECT array_agg(indexname::text ORDER BY indexname)
    INTO policy_indexes
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'saas_registration_rate_limit_policies';
    SELECT array_agg(indexname::text ORDER BY indexname)
    INTO counter_indexes
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'saas_registration_rate_limits';
    SELECT encode(sha256(convert_to(
        string_agg(
            concat_ws(
                '|', index_row.indexrelid::regclass::text,
                index_row.indisunique::text,
                index_row.indisprimary::text,
                index_row.indisvalid::text,
                index_row.indisready::text,
                regexp_replace(
                    pg_get_indexdef(index_row.indexrelid),
                    '[[:space:]]+', '', 'g'
                )
            ),
            E'\n' ORDER BY index_row.indexrelid::regclass::text
        ),
        'UTF8'
    )), 'hex')
    INTO rate_index_contract_hash
    FROM pg_index AS index_row
    WHERE index_row.indrelid IN (rate_policy_table, rate_counter_table);
    SELECT count(*)
    INTO rate_policies
    FROM pg_policy
    WHERE (
        (
            polrelid = rate_policy_table
            AND polname = 'rls_registration_rate_limit_policies_owner'
        ) OR (
            polrelid = rate_counter_table
            AND polname = 'rls_registration_rate_limits_owner'
        )
    )
      AND polcmd = '*'
      AND polpermissive
      AND cardinality(polroles) = 1
      AND 0 = ANY(polroles);
    SELECT encode(sha256(convert_to(
        string_agg(
            concat_ws(
                '|', relation.relname, policy.polname,
                policy.polpermissive::text, policy.polcmd,
                ARRAY(
                    SELECT CASE
                        WHEN policy_role.role_oid = 0 THEN 'PUBLIC'
                        ELSE pg_get_userbyid(policy_role.role_oid)
                    END
                    FROM unnest(policy.polroles) AS policy_role(role_oid)
                    ORDER BY 1
                )::text,
                COALESCE(
                    regexp_replace(
                        pg_get_expr(policy.polqual, policy.polrelid),
                        '[[:space:]]+', '', 'g'
                    ),
                    '<null>'
                ),
                COALESCE(
                    regexp_replace(
                        pg_get_expr(policy.polwithcheck, policy.polrelid),
                        '[[:space:]]+', '', 'g'
                    ),
                    '<null>'
                )
            ),
            E'\n' ORDER BY relation.relname, policy.polname
        ),
        'UTF8'
    )), 'hex')
    INTO rate_policy_contract_hash
    FROM pg_policy AS policy
    JOIN pg_class AS relation ON relation.oid = policy.polrelid
    WHERE policy.polrelid IN (rate_policy_table, rate_counter_table);
    SELECT count(*)
    INTO rate_functions
    FROM pg_proc
    WHERE oid IN (consume_function, prune_function, status_function)
      AND prokind = 'f'
      AND prosecdef
      AND provolatile = 'v'
      AND 'search_path=pg_catalog' = ANY(proconfig)
      AND proowner = (SELECT relowner FROM pg_class WHERE oid = rate_policy_table);
    SELECT count(*)
    INTO rate_function_contracts
    FROM pg_proc AS procedure
    JOIN pg_language AS language ON language.oid = procedure.prolang
    WHERE procedure.oid IN (consume_function, prune_function, status_function)
      AND procedure.prokind = 'f'
      AND procedure.prosecdef
      AND NOT procedure.proleakproof
      AND procedure.provolatile = 'v'
      AND procedure.proparallel = 'u'
      AND procedure.proowner = (
          SELECT relowner FROM pg_class WHERE oid = rate_policy_table
      )
      AND (
          (
              procedure.oid = consume_function
              AND language.lanname = 'plpgsql'
              AND procedure.proconfig = ARRAY[
                  'search_path=pg_catalog', 'lock_timeout=250ms'
              ]::text[]
              AND pg_get_function_result(procedure.oid) =
                  'TABLE(allowed boolean, retry_after_seconds integer, '
                  'remaining integer, policy_revision text)'
              AND encode(sha256(convert_to(
                  btrim(procedure.prosrc, E' \n\r\t'), 'UTF8'
              )), 'hex') = CASE schema_revision
                  WHEN 'p0s000000005' THEN
                      '5e56381f6058e96322e5bf27cde7f5add1fdfb70415095f4f65a9c5f169243a6'
                  WHEN 'p0s000000006' THEN
                      '84edaf917bdde5521267880561cb83d9b6099530dc8d76b3d07d26eb32867a8b'
                  WHEN 'p0s000000007' THEN
                      '8c21f811324aa7ebceae27b159369502ad24ae6aa9cc1e12c6e38070a8119112'
                  WHEN 'p0s000000008' THEN
                      '8c21f811324aa7ebceae27b159369502ad24ae6aa9cc1e12c6e38070a8119112'
                  WHEN 'p0s000000009' THEN
                      '8c21f811324aa7ebceae27b159369502ad24ae6aa9cc1e12c6e38070a8119112'
                  WHEN 'p0s000000010' THEN
                      '8c21f811324aa7ebceae27b159369502ad24ae6aa9cc1e12c6e38070a8119112'
                  WHEN 'p0s000000011' THEN
                      '8c21f811324aa7ebceae27b159369502ad24ae6aa9cc1e12c6e38070a8119112'
              END
          ) OR (
              procedure.oid = prune_function
              AND language.lanname = 'plpgsql'
              AND procedure.proconfig = ARRAY[
                  'search_path=pg_catalog', 'lock_timeout=500ms'
              ]::text[]
              AND pg_get_function_result(procedure.oid) = 'integer'
              AND encode(sha256(convert_to(
                  btrim(procedure.prosrc, E' \n\r\t'), 'UTF8'
              )), 'hex') =
                  '6353a9f1722a6b9be68c753dba6031b8364246887eeedba68923a5f7f6257041'
          ) OR (
              procedure.oid = status_function
              AND language.lanname = 'sql'
              AND procedure.proconfig = ARRAY['search_path=pg_catalog']::text[]
              AND pg_get_function_result(procedure.oid) =
                  'TABLE(action text, subject_kind text, limit_count integer, '
                  'window_seconds integer, retention_seconds integer, max_rows integer, '
                  'current_rows integer, policy_revision text, expired_rows bigint)'
              AND encode(sha256(convert_to(
                  btrim(procedure.prosrc, E' \n\r\t'), 'UTF8'
              )), 'hex') =
                  '0459d679cf4e870d0725e2f93ee6f5a83548a9fcd65483a071dda61d76edcd73'
          )
      );

    IF rate_relations <> 2
       OR rate_relation_owners <> 1
       OR policy_columns IS DISTINCT FROM ARRAY[
            'action', 'subject_kind', 'limit_count', 'window_seconds',
            'retention_seconds', 'max_rows', 'current_rows', 'policy_revision',
            'created_at', 'updated_at'
       ]::text[]
       OR counter_columns IS DISTINCT FROM ARRAY[
            'action', 'subject_kind', 'key_id', 'subject_hmac',
            'window_started_at', 'request_count', 'expires_at',
            'policy_revision', 'version', 'created_at', 'updated_at'
       ]::text[]
       OR rate_column_contract_hash IS DISTINCT FROM
          'e5cffedb8c3546fb330bd1f885fa992d4d215ea88940429fdee07848ada2d59c'
       OR policy_constraints IS DISTINCT FROM ARRAY[
            'ck_registration_rate_limit_policy_action',
            'ck_registration_rate_limit_policy_current_rows',
            'ck_registration_rate_limit_policy_limit',
            'ck_registration_rate_limit_policy_max_rows',
            'ck_registration_rate_limit_policy_retention',
            'ck_registration_rate_limit_policy_revision',
            'ck_registration_rate_limit_policy_subject_kind',
            'ck_registration_rate_limit_policy_window',
            'saas_registration_rate_limit_policies_pkey'
       ]::text[]
       OR counter_constraints IS DISTINCT FROM ARRAY[
            'ck_registration_rate_limit_action',
            'ck_registration_rate_limit_count',
            'ck_registration_rate_limit_expiry',
            'ck_registration_rate_limit_key_id',
            'ck_registration_rate_limit_revision',
            'ck_registration_rate_limit_subject_hmac',
            'ck_registration_rate_limit_subject_kind',
            'ck_registration_rate_limit_version',
            'fk_registration_rate_limit_policy',
            'saas_registration_rate_limits_pkey'
       ]::text[]
       OR policy_indexes IS DISTINCT FROM ARRAY[
            'saas_registration_rate_limit_policies_pkey'
       ]::text[]
       OR counter_indexes IS DISTINCT FROM ARRAY[
            'ix_registration_rate_limit_expiry',
            'saas_registration_rate_limits_pkey'
       ]::text[]
       -- PostgreSQL's logical roundtrip reparses varchar-array CHECK predicates
       -- into equivalent per-element text casts.  Keep the complete constraint
       -- aggregate and admit only the exact migrated or exact roundtrip catalog
       -- hash for each supported revision.
       OR (
          schema_revision = 'p0s000000005'
          AND rate_constraint_contract_hash IS DISTINCT FROM
             '72a30643de641319a27cdc0ca7ba4d97b8dc2b6093c7089c802dc9e474276aa1'
          AND rate_constraint_contract_hash IS DISTINCT FROM
             'a712a6bb5fa0f0b66ce8102486e8d51bcc11382fb5397ab5043b17e5689efda5'
       )
       OR (
          schema_revision IN (
              'p0s000000006', 'p0s000000007', 'p0s000000008', 'p0s000000009',
              'p0s000000010', 'p0s000000011'
          )
          AND rate_constraint_contract_hash IS DISTINCT FROM
             '659fd922560eea249898647400542e711de87d290327029d74325201d82b725a'
          AND rate_constraint_contract_hash IS DISTINCT FROM
             '89e8bd459b1aab4e24bf7655fc9b386a01243bcb071a9c9bdd1eb8e6f46de49a'
       )
       OR rate_index_contract_hash IS DISTINCT FROM
          '17a36e093545fdbf51d1ca5da5682b2cff1273de9e82ff580a96e54212d46b5f'
       OR rate_policies <> 2
       OR rate_policy_contract_hash IS DISTINCT FROM
          'f056fa696bc9911c49b89d385197de29c5901b392fcb65069ec5d1334648d064'
       OR rate_functions <> 3
       OR rate_function_contracts <> 3
    THEN
        RAISE EXCEPTION
            'control-plane schema revision/object contract rejected';
    END IF;

    SELECT count(*)
    INTO network_constraints
    FROM pg_constraint
    WHERE (
        (
            conrelid = rate_policy_table
            AND conname = 'ck_registration_rate_limit_policy_subject_kind'
        ) OR (
            conrelid = rate_counter_table
            AND conname = 'ck_registration_rate_limit_subject_kind'
        )
    )
      AND position('network' IN pg_get_constraintdef(oid)) > 0;
    SELECT array_agg(action::text ORDER BY action)
    INTO network_policy_actions
    FROM public.saas_registration_rate_limit_policies
    WHERE subject_kind = 'network';
    SELECT array_agg(
        concat_ws(
            '|', action::text, subject_kind::text, limit_count::text,
            window_seconds::text, retention_seconds::text, max_rows::text,
            policy_revision::text
        )
        ORDER BY action
    )
    INTO network_policy_contract
    FROM public.saas_registration_rate_limit_policies
    WHERE subject_kind = 'network';
    SELECT position(
        'registration rate-limit rotation phase rejected'
        IN pg_get_functiondef(consume_function)
    ) > 0
    INTO rotation_guard_present;
    IF schema_revision = 'p0s000000005' THEN
        IF network_constraints <> 0
           OR network_policy_actions IS NOT NULL
           OR network_policy_contract IS NOT NULL
           OR rotation_guard_present
        THEN
            RAISE EXCEPTION
                'control-plane schema revision/object contract rejected';
        END IF;
    ELSIF network_constraints <> 2
       OR network_policy_actions IS DISTINCT FROM ARRAY[
            'registration.request',
            'registration.resend',
            'registration.verify'
       ]::text[]
       OR network_policy_contract IS DISTINCT FROM ARRAY[
            'registration.request|network|60|900|86400|1000000|registration-rate-limit-v1',
            'registration.resend|network|60|900|86400|1000000|registration-rate-limit-v1',
            'registration.verify|network|120|900|86400|1000000|registration-rate-limit-v1'
       ]::text[]
       OR NOT rotation_guard_present
    THEN
        RAISE EXCEPTION
            'control-plane schema revision/object contract rejected';
    END IF;
END
$$;

-- A replay can arrive after an older release, an operator, or a compromised
-- owner has granted rate-limit state to PUBLIC or another fixed principal.
-- Remove that drift immediately after the complete schema preflight and before
-- any per-principal projection verifier runs.  The exact three routine grants
-- and their terminal verifier remain in the onboarding authority section
-- below; this phase only removes authority and therefore cannot make a partial
-- projection usable.
DO $$
DECLARE
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
        'saas_runtime_provider_journal'
    ];
    rate_policy_table oid := to_regclass('public.saas_registration_rate_limit_policies');
    target_role text;
    target_table text;
    target_privilege text;
    target_signature text;
    column_list text;
BEGIN
    IF rate_policy_table IS NULL THEN
        RETURN;
    END IF;

    FOR target_table IN
        SELECT table_name
        FROM (VALUES
            ('saas_registration_rate_limit_policies'),
            ('saas_registration_rate_limits')
        ) AS rate_tables(table_name)
    LOOP
        EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
            quote_ident(target_table) || ' FROM PUBLIC';
        SELECT string_agg(quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum)
        INTO column_list
        FROM pg_attribute AS attribute
        WHERE attribute.attrelid = ('public.' || quote_ident(target_table))::regclass
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped;
        FOREACH target_role IN ARRAY named_principals
        LOOP
            EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
                quote_ident(target_table) || ' FROM ' || quote_ident(target_role);
            FOREACH target_privilege IN ARRAY
                ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
            LOOP
                EXECUTE 'REVOKE ' || target_privilege || ' (' || column_list ||
                    ') ON TABLE public.' || quote_ident(target_table) ||
                    ' FROM ' || quote_ident(target_role);
            END LOOP;
        END LOOP;
        FOREACH target_privilege IN ARRAY
            ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
        LOOP
            EXECUTE 'REVOKE ' || target_privilege || ' (' || column_list ||
                ') ON TABLE public.' || quote_ident(target_table) || ' FROM PUBLIC';
        END LOOP;
    END LOOP;

    FOREACH target_signature IN ARRAY ARRAY[
        'public.saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)',
        'public.saas_prune_registration_rate_limits(text,text,integer)',
        'public.saas_registration_rate_limit_status()'
    ]
    LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || target_signature || ' FROM PUBLIC';
        FOREACH target_role IN ARRAY named_principals
        LOOP
            EXECUTE 'REVOKE ALL ON FUNCTION ' || target_signature ||
                ' FROM ' || quote_ident(target_role);
        END LOOP;
    END LOOP;
END
$$;
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

-- P0S9 Preview is split into a browser Edge (content-blind token routines) and
-- a placement-bound Owner.  Keep this projection conditional so the same
-- authority body remains replayable at every supported schema-forward rollback
-- point while refusing a partial P0S9 object set.
DO $$
DECLARE
    schema_revision text;
    target_role text;
    target_table text;
    target_privilege text;
    target_signature text;
    column_list text;
    target_roles constant text[] := ARRAY[
        'saas_app', 'saas_authenticator', 'saas_governance', 'saas_dispatcher',
        'saas_dispatcher_n1_compat', 'saas_executor', 'saas_runner_agent',
        'saas_secret_broker',
        'saas_preview_gateway', 'saas_preview_edge', 'saas_preview_owner',
        'saas_webhook_dispatcher', 'saas_billing', 'saas_metering',
        'saas_public_api', 'saas_platform', 'saas_platform_authenticator',
        'saas_platform_app', 'saas_platform_governance',
        'saas_platform_projector', 'saas_platform_support',
        'saas_privacy_executor', 'saas_privacy_dispatcher',
        'saas_privacy_verifier', 'saas_notification_scheduler',
        'saas_notification_dispatcher', 'saas_notification_directory',
        'saas_approval_scheduler_enterprise', 'saas_approval_scheduler_privacy',
        'saas_approval_scheduler_audit', 'saas_approval_scheduler_support_customer',
        'saas_approval_scheduler_support_staff', 'saas_registration',
        'saas_onboarding', 'saas_onboarding_status',
        'saas_runtime_provider_journal'
    ];
    preview_tables constant text[] := ARRAY[
        'saas_preview_executions', 'saas_preview_commands',
        'saas_preview_sessions', 'saas_preview_tunnel_registrations'
    ];
    preview_functions constant text[] := ARRAY[
        'public.saas_preview_issue_tunnel_registration_v1(uuid,bigint,text,text,uuid,text,text,text,integer)',
        'public.saas_preview_revoke_tunnel_registration_v1(uuid,bigint,text,text,uuid,text)',
        'public.saas_preview_preauthorize_tunnel_v1(text,text,text,text,timestamptz)',
        'public.saas_preview_redeem_tunnel_v1(text,text,text,text,uuid,text,timestamptz)',
        'public.saas_preview_heartbeat_tunnel_v1(text,text,text,text,timestamptz)',
        'public.saas_preview_disconnect_tunnel_v1(text,text,text,text,timestamptz)',
        'public.saas_preview_issue_exchange_v1(uuid,text,timestamptz)',
        'public.saas_preview_create_command_v1(uuid,uuid,text,text,timestamptz)',
        'public.saas_preview_exchange_v1(text,uuid,text,timestamptz,timestamptz)',
        'public.saas_preview_authorize_session_v1(text,text,timestamptz)',
        'public.saas_preview_rotate_session_v1(text,text,text,timestamptz,timestamptz)',
        'public.saas_preview_revoke_session_v1(text,timestamptz)',
        'public.saas_preview_owner_route_match_v1(uuid,uuid,bigint,text,text,timestamptz)',
        'public.saas_preview_owner_heartbeat_gateway_v1(text,text)',
        'public.saas_preview_owner_release_gateway_v1(text,text)'
    ];
BEGIN
    SELECT version_num INTO STRICT schema_revision
    FROM public.saas_alembic_version;
    IF schema_revision NOT IN ('p0s000000009', 'p0s000000010', 'p0s000000011') THEN
        IF EXISTS (
            SELECT 1 FROM unnest(preview_tables) AS expected(table_name)
            WHERE to_regclass('public.' || expected.table_name) IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'P0S9 Preview authority found on an older schema revision';
        END IF;
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1 FROM unnest(preview_tables) AS expected(table_name)
        WHERE to_regclass('public.' || expected.table_name) IS NULL
    ) OR EXISTS (
        SELECT 1 FROM unnest(preview_functions) AS expected(signature)
        WHERE to_regprocedure(expected.signature) IS NULL
    ) THEN
        RAISE EXCEPTION 'P0S9 Preview authority object contract rejected';
    END IF;

    FOREACH target_table IN ARRAY preview_tables
    LOOP
        EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
            quote_ident(target_table) || ' FROM PUBLIC';
        SELECT string_agg(quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum)
        INTO column_list
        FROM pg_attribute AS attribute
        WHERE attribute.attrelid = ('public.' || quote_ident(target_table))::regclass
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped;
        FOREACH target_role IN ARRAY target_roles
        LOOP
            EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
                quote_ident(target_table) || ' FROM ' || quote_ident(target_role);
            FOREACH target_privilege IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
            LOOP
                EXECUTE 'REVOKE ' || target_privilege || ' (' || column_list ||
                    ') ON TABLE public.' || quote_ident(target_table) ||
                    ' FROM ' || quote_ident(target_role);
            END LOOP;
        END LOOP;
    END LOOP;
    FOREACH target_signature IN ARRAY preview_functions
    LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || target_signature || ' FROM PUBLIC';
        FOREACH target_role IN ARRAY target_roles
        LOOP
            EXECUTE 'REVOKE ALL ON FUNCTION ' || target_signature ||
                ' FROM ' || quote_ident(target_role);
        END LOOP;
    END LOOP;

    GRANT EXECUTE ON FUNCTION
        public.saas_preview_issue_exchange_v1(uuid,text,timestamptz),
        public.saas_preview_create_command_v1(uuid,uuid,text,text,timestamptz)
    TO saas_app;
    GRANT EXECUTE ON FUNCTION
        public.saas_preview_exchange_v1(text,uuid,text,timestamptz,timestamptz),
        public.saas_preview_authorize_session_v1(text,text,timestamptz),
        public.saas_preview_rotate_session_v1(text,text,text,timestamptz,timestamptz),
        public.saas_preview_revoke_session_v1(text,timestamptz)
    TO saas_preview_edge;
    GRANT EXECUTE ON FUNCTION
        public.saas_preview_issue_tunnel_registration_v1(
            uuid,bigint,text,text,uuid,text,text,text,integer
        ),
        public.saas_preview_revoke_tunnel_registration_v1(
            uuid,bigint,text,text,uuid,text
        )
    TO saas_executor;
    GRANT EXECUTE ON FUNCTION
        public.saas_preview_preauthorize_tunnel_v1(text,text,text,text,timestamptz),
        public.saas_preview_redeem_tunnel_v1(
            text,text,text,text,uuid,text,timestamptz
        ),
        public.saas_preview_heartbeat_tunnel_v1(text,text,text,text,timestamptz),
        public.saas_preview_disconnect_tunnel_v1(text,text,text,text,timestamptz),
        public.saas_preview_owner_route_match_v1(
            uuid,uuid,bigint,text,text,timestamptz
        ),
        public.saas_preview_authorize_session_v1(text,text,timestamptz),
        public.saas_preview_owner_heartbeat_gateway_v1(text,text),
        public.saas_preview_owner_release_gateway_v1(text,text)
    TO saas_preview_owner;

    GRANT SELECT (
        id, tenant_id, space_id, project_id, source_run_id, child_run_id,
        change_set_id, created_by, profile, opaque_preview_key, preview_host,
        status, command_generation, expires_at, ready_at, terminal_at,
        failure_code, version, created_at, updated_at, exchange_issued_at,
        exchange_consumed_at
    ) ON public.saas_preview_executions TO saas_app;
    GRANT INSERT (
        id, tenant_id, space_id, project_id, source_run_id, child_run_id,
        change_set_id, created_by, profile, idempotency_key_hash, request_hash,
        opaque_preview_key, preview_host, status, command_generation, expires_at,
        version, created_at, updated_at
    ) ON public.saas_preview_executions TO saas_app;

    GRANT SELECT ON public.saas_preview_executions,
        public.saas_preview_commands TO saas_executor;
    GRANT INSERT ON public.saas_preview_commands TO saas_executor;
    GRANT UPDATE (
        status, command_generation, runner_id, placement_id, worktree_id,
        run_fence_token, runner_connection_generation, worktree_lease_generation,
        expires_at, ready_at, terminal_at, failure_code, version, updated_at
    ) ON public.saas_preview_executions TO saas_executor;
    GRANT UPDATE (
        status, runner_id, placement_id, runner_connection_generation,
        claim_token_hash, claimed_by_gateway, attempt_count, available_at,
        claimed_at, completed_at, failure_code, updated_at
    ) ON public.saas_preview_commands TO saas_executor;
    GRANT SELECT (
        id, tenant_id, space_id, project_id, child_run_id, status,
        command_generation, runner_id, placement_id, worktree_id,
        run_fence_token, runner_connection_generation, worktree_lease_generation,
        expires_at, ready_at, terminal_at, failure_code, version
    ) ON public.saas_preview_executions TO saas_preview_owner;
    GRANT UPDATE (
        status, command_generation, runner_id, placement_id, worktree_id,
        run_fence_token, runner_connection_generation, worktree_lease_generation,
        ready_at, terminal_at, failure_code, version, updated_at
    ) ON public.saas_preview_executions TO saas_preview_owner;
    GRANT SELECT ON public.saas_preview_commands,
        public.saas_preview_tunnel_registrations TO saas_preview_owner;
    GRANT UPDATE (
        status, claim_token_hash, claimed_by_gateway, attempt_count, claimed_at,
        completed_at, failure_code, updated_at
    ) ON public.saas_preview_commands TO saas_preview_owner;
    GRANT UPDATE (
        status, official_runner_id, redeemed_at, disconnected_at, revoked_at,
        updated_at
    ) ON public.saas_preview_tunnel_registrations TO saas_preview_owner;
    GRANT SELECT (
        id, status, lease_expires_at
    ) ON public.saas_preview_gateway_instances TO saas_preview_owner;
    GRANT SELECT (
        id, runner_id, runner_connection_generation, routing_generation,
        gateway_instance_id, relay_subject, status, lease_expires_at
    ) ON public.saas_runner_tunnel_placements TO saas_preview_owner;
    GRANT SELECT (
        id, placement_id, status, connection_generation, protocol_version,
        source_revision, schema_revision, adapter_contract_version, capabilities,
        capabilities_hash
    ) ON public.saas_runner_registrations TO saas_preview_owner;

    GRANT SELECT, INSERT, UPDATE, DELETE ON
        public.saas_preview_executions,
        public.saas_preview_commands,
        public.saas_preview_sessions,
        public.saas_preview_tunnel_registrations
    TO saas_platform;
END
$$;

-- PostgreSQL grants new functions to PUBLIC by default.  The production owner
-- sanitizer removes that implicit authority from every SaaS-owned routine.
-- These two SECURITY INVOKER predicates are referenced by CHECK constraints,
-- so restore EXECUTE only to the exact writers whose GUC-bound source proofs
-- the function bodies recognize.
REVOKE EXECUTE ON FUNCTION public.approval_source_work_binding_is_valid(
    uuid, text, uuid, uuid, uuid, text, uuid, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.approval_source_work_binding_is_valid(
    uuid, text, uuid, uuid, uuid, text, uuid, text, text
) TO
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;

REVOKE EXECUTE ON FUNCTION public.approval_notification_binding_is_valid(
    text, uuid, uuid, uuid, text, uuid, uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.approval_notification_binding_is_valid(
    text, uuid, uuid, uuid, text, uuid, uuid
) TO
    saas_notification_scheduler,
    saas_governance,
    saas_platform_governance,
    saas_approval_scheduler_enterprise,
    saas_approval_scheduler_privacy,
    saas_approval_scheduler_audit,
    saas_approval_scheduler_support_customer,
    saas_approval_scheduler_support_staff;

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
-- p0s5 adds deletion_manifest_id to self-service registration.  Keep the
-- current Privacy projection exact without making a p0s3 N-1 replay resolve a
-- column that does not exist yet.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = 'public.saas_self_service_registrations'::regclass
          AND attname = 'deletion_manifest_id'
          AND NOT attisdropped
    ) THEN
        GRANT SELECT (id, user_id, tenant_id, deletion_manifest_id, version)
        ON saas_self_service_registrations TO saas_privacy_executor;
        GRANT UPDATE (
            email_normalized, email_hash, display_name, tenant_name, tenant_slug,
            default_space_name, default_space_slug, status, verified_at, terminal_at,
            user_id, tenant_id, idempotency_key, request_hash, deletion_manifest_id,
            version, updated_at
        )
        ON saas_self_service_registrations TO saas_privacy_executor;
    END IF;
END
$$;
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
-- Revoke first so rerunning this file also removes every historical table- or
-- column-level grant.  A table-level REVOKE is insufficient in PostgreSQL:
-- column ACLs survive it.  Converge all four onboarding authorities over every
-- current public relation before rebuilding the exact projections below.  The
-- sequence, routine, and default-ACL revocations keep an old release from
-- retaining an independent authority channel. Database/schema authority is
-- owned and verified by the preceding database-owner phase.
DO $$
DECLARE
    target_roles constant text[] := ARRAY[
        'saas_registration',
        'saas_onboarding',
        'saas_executor',
        'saas_runner_agent',
        'saas_onboarding_status'
    ];
    caller_role oid;
    target_role text;
    target_table text;
    target_sequence text;
    target_signature text;
    target_privilege text;
    column_list text;
    unmanaged_foreign_authority integer;
BEGIN
    SELECT role.oid
    INTO caller_role
    FROM pg_roles AS role
    WHERE role.rolname = current_user;

    -- A narrow SaaS owner cannot revoke ACLs granted by the official owner or
    -- any other authority. Reject such drift before the first mutation rather
    -- than crossing an ownership boundary or leaving a hidden authority path.
    SELECT count(*)
    INTO unmanaged_foreign_authority
    FROM (
        SELECT 1
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl
        JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE grantee.rolname = ANY(target_roles)
          AND (
              namespace.nspname <> 'public'
              OR relation.relowner <> caller_role
          )
        UNION ALL
        SELECT 1
        FROM pg_attribute AS attribute
        JOIN pg_class AS relation ON relation.oid = attribute.attrelid
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
        JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE grantee.rolname = ANY(target_roles)
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND (
              namespace.nspname <> 'public'
              OR relation.relowner <> caller_role
          )
        UNION ALL
        SELECT 1
        FROM pg_proc AS routine
        JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
        CROSS JOIN LATERAL aclexplode(routine.proacl) AS acl
        JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE grantee.rolname = ANY(target_roles)
          AND (
              namespace.nspname <> 'public'
              OR routine.proowner <> caller_role
          )
        UNION ALL
        SELECT 1
        FROM pg_type AS type
        CROSS JOIN LATERAL aclexplode(type.typacl) AS acl
        JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE grantee.rolname = ANY(target_roles)
        UNION ALL
        SELECT 1
        FROM pg_database AS database
        CROSS JOIN LATERAL aclexplode(database.datacl) AS acl
        JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE database.datname = current_database()
          AND grantee.rolname = ANY(target_roles)
          AND NOT (
              grantee.rolname IN ('saas_executor', 'saas_runner_agent')
              AND acl.grantor = database.datdba
              AND acl.privilege_type = 'CONNECT'
              AND NOT acl.is_grantable
          )
        UNION ALL
        SELECT 1
        FROM pg_default_acl AS defaults
        LEFT JOIN pg_namespace AS namespace
          ON namespace.oid = defaults.defaclnamespace
        CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl
        JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE grantee.rolname = ANY(target_roles)
          AND (
              defaults.defaclrole <> caller_role
              OR namespace.nspname IS DISTINCT FROM 'public'
              OR defaults.defaclobjtype NOT IN ('r', 'S', 'f')
          )
    ) AS foreign_authority;
    IF unmanaged_foreign_authority <> 0 THEN
        RAISE EXCEPTION
            'control-plane onboarding authority rejected: foreign owner ACL drifted';
    END IF;

    FOREACH target_role IN ARRAY target_roles
    LOOP
        FOR target_table IN
            SELECT relation.relname
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND relation.relowner = caller_role
            ORDER BY relation.relname
        LOOP
            EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
                quote_ident(target_table) || ' FROM ' || quote_ident(target_role);
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
        FOR target_sequence IN
            SELECT relation.relname
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relkind = 'S'
              AND relation.relowner = caller_role
            ORDER BY relation.relname
        LOOP
            EXECUTE 'REVOKE ALL PRIVILEGES ON SEQUENCE public.' ||
                quote_ident(target_sequence) || ' FROM ' || quote_ident(target_role);
        END LOOP;
        FOR target_signature IN
            SELECT 'public.' || quote_ident(routine.proname) || '(' ||
                pg_get_function_identity_arguments(routine.oid) || ')'
            FROM pg_proc AS routine
            JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
            WHERE namespace.nspname = 'public'
              AND routine.proowner = caller_role
            ORDER BY routine.oid
        LOOP
            EXECUTE 'REVOKE ALL PRIVILEGES ON FUNCTION ' || target_signature ||
                ' FROM ' || quote_ident(target_role);
        END LOOP;
    END LOOP;
END
$$;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES FROM
        saas_registration, saas_onboarding, saas_executor, saas_runner_agent,
        saas_onboarding_status;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM
        saas_registration, saas_onboarding, saas_executor, saas_runner_agent,
        saas_onboarding_status;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON FUNCTIONS FROM
        saas_registration, saas_onboarding, saas_executor, saas_runner_agent,
        saas_onboarding_status;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TYPES FROM
        saas_registration, saas_onboarding, saas_executor, saas_runner_agent,
        saas_onboarding_status;

-- Application-owned objects are default-deny to PUBLIC as well as to every
-- service capability.  Extension members are excluded from the existing
-- routine sweep: the separately pinned pg_trgm contract intentionally retains
-- its upstream PUBLIC EXECUTE/USAGE projection.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TYPES FROM PUBLIC;
DO $$
DECLARE
    target_signature text;
    target_type text;
BEGIN
    FOR target_signature IN
        SELECT 'public.' || quote_ident(routine.proname) || '(' ||
            pg_get_function_identity_arguments(routine.oid) || ')'
        FROM pg_proc AS routine
        JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname = 'public'
          AND routine.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend AS dependency
              WHERE dependency.classid = 'pg_proc'::regclass
                AND dependency.objid = routine.oid
                AND dependency.refclassid = 'pg_extension'::regclass
                AND dependency.deptype = 'e'
          )
        ORDER BY routine.oid
    LOOP
        EXECUTE 'REVOKE ALL PRIVILEGES ON FUNCTION ' || target_signature ||
            ' FROM PUBLIC';
    END LOOP;
    FOR target_type IN
        SELECT 'public.' || quote_ident(type.typname)
        FROM pg_type AS type
        JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace
        WHERE namespace.nspname = 'public'
          AND type.typowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          AND type.typelem = 0
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend AS dependency
              WHERE dependency.classid = 'pg_type'::regclass
                AND dependency.objid = type.oid
                AND dependency.refclassid = 'pg_extension'::regclass
                AND dependency.deptype = 'e'
          )
        ORDER BY type.oid
    LOOP
        EXECUTE 'REVOKE ALL PRIVILEGES ON TYPE ' || target_type || ' FROM PUBLIC';
    END LOOP;
END
$$;

-- Rate-limit state is reachable only through three content-blind routines.
-- Remove table-, column-, and routine-level ACL drift from every observed
-- non-owner grantee before restoring those three exact EXECUTE grants.  This
-- catalog-driven closure also revokes grants to principals created outside the
-- fixed SaaS role inventory.  The schema contract above proves that all objects
-- are absent at p0s3/p0s4 or complete at p0s5/p0s6; this block never guesses
-- from a partial object set.
DO $$
DECLARE
    rate_policy_table oid := to_regclass('public.saas_registration_rate_limit_policies');
    rate_counter_table oid := to_regclass('public.saas_registration_rate_limits');
    consume_function oid := to_regprocedure(
        'public.saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)'
    );
    prune_function oid := to_regprocedure(
        'public.saas_prune_registration_rate_limits(text,text,integer)'
    );
    status_function oid :=
        to_regprocedure('public.saas_registration_rate_limit_status()');
    target_role text;
    target_table text;
    target_privilege text;
    target_signature text;
    column_list text;
    target_relation oid;
    target_owner oid;
    unexpected_relation_acls integer;
    expected_function_acls integer;
    unexpected_function_acls integer;
BEGIN
    IF rate_policy_table IS NULL THEN
        RETURN;
    END IF;

    FOR target_table IN
        SELECT table_name
        FROM (VALUES
            ('saas_registration_rate_limit_policies'),
            ('saas_registration_rate_limits')
        ) AS rate_tables(table_name)
    LOOP
        target_relation := to_regclass('public.' || quote_ident(target_table));
        SELECT relowner
        INTO target_owner
        FROM pg_class
        WHERE oid = target_relation;
        EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
            quote_ident(target_table) || ' FROM PUBLIC';
        SELECT string_agg(quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum)
        INTO column_list
        FROM pg_attribute AS attribute
        WHERE attribute.attrelid = target_relation
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped;
        FOR target_role IN
            SELECT DISTINCT observed_role.rolname
            FROM (
                SELECT acl.grantee
                FROM pg_class AS relation
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(relation.relacl, acldefault('r', relation.relowner))
                ) AS acl
                WHERE relation.oid = target_relation
                UNION
                SELECT acl.grantee
                FROM pg_attribute AS attribute
                CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
                WHERE attribute.attrelid = target_relation
                  AND attribute.attnum > 0
                  AND NOT attribute.attisdropped
                  AND attribute.attacl IS NOT NULL
                  AND cardinality(attribute.attacl) > 0
            ) AS observed_acl
            JOIN pg_roles AS observed_role ON observed_role.oid = observed_acl.grantee
            WHERE observed_acl.grantee <> target_owner
        LOOP
            EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
                quote_ident(target_table) || ' FROM ' || quote_ident(target_role);
            FOREACH target_privilege IN ARRAY
                ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
            LOOP
                EXECUTE 'REVOKE ' || target_privilege || ' (' || column_list ||
                    ') ON TABLE public.' || quote_ident(target_table) ||
                    ' FROM ' || quote_ident(target_role);
            END LOOP;
        END LOOP;
        FOREACH target_privilege IN ARRAY
            ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
        LOOP
            EXECUTE 'REVOKE ' || target_privilege || ' (' || column_list ||
                ') ON TABLE public.' || quote_ident(target_table) || ' FROM PUBLIC';
        END LOOP;
    END LOOP;

    FOREACH target_signature IN ARRAY ARRAY[
        'public.saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)',
        'public.saas_prune_registration_rate_limits(text,text,integer)',
        'public.saas_registration_rate_limit_status()'
    ]
    LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || target_signature || ' FROM PUBLIC';
        SELECT procedure.proowner
        INTO target_owner
        FROM pg_proc AS procedure
        WHERE procedure.oid = to_regprocedure(target_signature);
        FOR target_role IN
            SELECT DISTINCT observed_role.rolname
            FROM pg_proc AS procedure
            CROSS JOIN LATERAL aclexplode(
                COALESCE(procedure.proacl, acldefault('f', procedure.proowner))
            ) AS acl
            JOIN pg_roles AS observed_role ON observed_role.oid = acl.grantee
            WHERE procedure.oid = to_regprocedure(target_signature)
              AND acl.grantee <> target_owner
        LOOP
            EXECUTE 'REVOKE ALL ON FUNCTION ' || target_signature ||
                ' FROM ' || quote_ident(target_role);
        END LOOP;
    END LOOP;
    GRANT EXECUTE ON FUNCTION public.saas_consume_registration_rate_limit(
        text, text, text, text, text, text, text, text
    ) TO saas_registration;
    GRANT EXECUTE ON FUNCTION public.saas_prune_registration_rate_limits(
        text, text, integer
    ) TO saas_platform;
    GRANT EXECUTE ON FUNCTION public.saas_registration_rate_limit_status()
    TO saas_platform;

    SELECT count(*)
    INTO unexpected_relation_acls
    FROM (
        SELECT acl.grantee, relation.relowner AS relation_owner
        FROM pg_class AS relation
        CROSS JOIN LATERAL aclexplode(
            COALESCE(relation.relacl, acldefault('r', relation.relowner))
        ) AS acl
        WHERE relation.oid IN (rate_policy_table, rate_counter_table)
        UNION ALL
        SELECT acl.grantee, relation.relowner AS relation_owner
        FROM pg_attribute AS attribute
        JOIN pg_class AS relation ON relation.oid = attribute.attrelid
        CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
        WHERE attribute.attrelid IN (rate_policy_table, rate_counter_table)
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND attribute.attacl IS NOT NULL
          AND cardinality(attribute.attacl) > 0
    ) AS relation_acl
    WHERE relation_acl.grantee <> relation_acl.relation_owner;
    SELECT count(*)
    INTO expected_function_acls
    FROM pg_proc AS procedure
    CROSS JOIN LATERAL aclexplode(
        COALESCE(procedure.proacl, acldefault('f', procedure.proowner))
    ) AS acl
    JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE NOT acl.is_grantable
      AND acl.privilege_type = 'EXECUTE'
      AND (
          (procedure.oid = consume_function AND grantee.rolname = 'saas_registration')
          OR (
              procedure.oid IN (prune_function, status_function)
              AND grantee.rolname = 'saas_platform'
          )
      );
    SELECT count(*)
    INTO unexpected_function_acls
    FROM pg_proc AS procedure
    CROSS JOIN LATERAL aclexplode(
        COALESCE(procedure.proacl, acldefault('f', procedure.proowner))
    ) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE procedure.oid IN (consume_function, prune_function, status_function)
      AND acl.grantee <> procedure.proowner
      AND NOT (
          NOT acl.is_grantable
          AND acl.privilege_type = 'EXECUTE'
          AND (
              (procedure.oid = consume_function AND grantee.rolname = 'saas_registration')
              OR (
                  procedure.oid IN (prune_function, status_function)
                  AND grantee.rolname = 'saas_platform'
              )
          )
      );
    IF unexpected_relation_acls <> 0
       OR expected_function_acls <> 3
       OR unexpected_function_acls <> 0
    THEN
        RAISE EXCEPTION 'registration rate-limit authority projection rejected';
    END IF;
END
$$;

-- Every write below is constrained to the columns emitted by the two
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
-- The global authority convergence above already clears this role.  Repeat its
-- four dependency tables here as a local fail-safe, and also clear the
-- historical app projection, before restoring only the customer-safe columns.
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

-- Executor planning dependencies were intentionally removed by the global
-- authority convergence.  Regrant only the columns used by the pre-existing
-- Staff/Support RLS predicates; FORCE RLS keeps their rows invisible here.
GRANT SELECT (principal_id, role, status, expires_at)
ON saas_platform_role_assignments TO saas_executor;
GRANT SELECT (principal_id, token_hash, revoked_at, expires_at)
ON saas_platform_support_sessions TO saas_executor;

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
GRANT SELECT ON
    saas_runtime_placements,
    saas_runtime_partitions,
    saas_runtime_resource_bindings
TO saas_executor;
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

-- The global executor authority convergence above deliberately revokes every
-- function ACL before reconstructing the final projection.  Restore only the
-- two P0S9 incarnation-bound registration CAS functions (when present); never
-- restore direct registration-table DML.
DO $$
BEGIN
    IF to_regprocedure(
        'public.saas_preview_issue_tunnel_registration_v1('
        'uuid,bigint,text,text,uuid,text,text,text,integer)'
    ) IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION
            public.saas_preview_issue_tunnel_registration_v1(
                uuid,bigint,text,text,uuid,text,text,text,integer
            ),
            public.saas_preview_revoke_tunnel_registration_v1(
                uuid,bigint,text,text,uuid,text
            )
        TO saas_executor;
    END IF;
END
$$;

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
-- PostgreSQL requires UPDATE privilege on at least one column before a
-- SELECT ... FOR SHARE lock can serialize profile retirement.  Only the
-- immutable primary-key column is granted.  The only executor UPDATE policy
-- has exact-scope USING and WITH CHECK (false), so FORCE RLS still rejects
-- every attempted write while permitting the row lock.
GRANT UPDATE (id) ON saas_egress_policies TO saas_executor;
GRANT UPDATE (id) ON saas_execution_profiles TO saas_executor;
-- The authoritative queue projector locks its exact active route and pool in
-- the same transaction as the selected profile. P0S8 supplies Project-scoped
-- UPDATE eligibility plus false-WITH-CHECK mutation policies, so these four
-- primary-key-only ACLs permit FOR SHARE but no real UPDATE or side channel.
-- Runner-pool ordinary SELECT remains fleet-global for content-blind readiness;
-- its FOR SHARE lock still intersects the Project-scoped UPDATE policy.
REVOKE UPDATE ON
    saas_runtime_placements,
    saas_runtime_partitions,
    saas_runtime_resource_bindings,
    saas_runner_pools
FROM saas_executor;
GRANT UPDATE (id) ON saas_runtime_placements TO saas_executor;
GRANT UPDATE (id) ON saas_runtime_partitions TO saas_executor;
GRANT UPDATE (id) ON saas_runtime_resource_bindings TO saas_executor;
GRANT UPDATE (id) ON saas_runner_pools TO saas_executor;

DO $$
DECLARE
    expected_lock_acls integer;
    unexpected_lock_acls integer;
BEGIN
    SELECT count(*)
    INTO expected_lock_acls
    FROM pg_attribute AS attribute
    JOIN pg_class AS relation ON relation.oid = attribute.attrelid
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
    JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname = 'public'
      AND relation.relname IN (
          'saas_egress_policies', 'saas_execution_profiles',
          'saas_runtime_placements', 'saas_runtime_partitions',
          'saas_runtime_resource_bindings', 'saas_runner_pools'
      )
      AND attribute.attname = 'id'
      AND grantee.rolname = 'saas_executor'
      AND acl.privilege_type = 'UPDATE'
      AND NOT acl.is_grantable;

    SELECT count(*)
    INTO unexpected_lock_acls
    FROM (
        SELECT relation.relname, NULL::text AS column_name, acl.privilege_type
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(
            COALESCE(relation.relacl, acldefault('r', relation.relowner))
        ) AS acl
        JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE namespace.nspname = 'public'
          AND relation.relname IN (
              'saas_egress_policies', 'saas_execution_profiles',
              'saas_runtime_placements', 'saas_runtime_partitions',
              'saas_runtime_resource_bindings', 'saas_runner_pools'
          )
          AND grantee.rolname = 'saas_executor'
          AND acl.privilege_type = 'UPDATE'
        UNION ALL
        SELECT relation.relname, attribute.attname, acl.privilege_type
        FROM pg_attribute AS attribute
        JOIN pg_class AS relation ON relation.oid = attribute.attrelid
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
        JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE namespace.nspname = 'public'
          AND relation.relname IN (
              'saas_egress_policies', 'saas_execution_profiles',
              'saas_runtime_placements', 'saas_runtime_partitions',
              'saas_runtime_resource_bindings', 'saas_runner_pools'
          )
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND grantee.rolname = 'saas_executor'
          AND acl.privilege_type = 'UPDATE'
          AND (attribute.attname <> 'id' OR acl.is_grantable)
    ) AS unexpected;
    IF expected_lock_acls <> 6 OR unexpected_lock_acls <> 0 THEN
        RAISE EXCEPTION 'dispatch profile lock authority projection rejected';
    END IF;
END
$$;

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
    WHERE membership.roleid = compat_oid
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
      );

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
-- A logical restore produced with --no-privileges recreates functions with
-- PostgreSQL's default PUBLIC EXECUTE. Normalize that default before the
-- fail-closed catalog verification; any other unexpected grantee still fails.
REVOKE EXECUTE ON FUNCTION public.saas_bridge_n1_outbox_update() FROM PUBLIC;
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

-- P0S10 replaces the fleet-wide executor DSN in Runner pods with one LOGIN per
-- immutable Runner incarnation.  The LOGIN inherits this NOLOGIN capability
-- directly, but every row policy also authenticates the unforgeable
-- session_user spelling runner_<uuidhex>_g<generation>.  No SET ROLE path can
-- satisfy that predicate and this role never inherits saas_executor.
DO $$
DECLARE
    schema_revision text;
    canonical_json_function oid;
    canonical_json_sha256_function oid;
    worktree_authority_function oid;
    identity_function oid;
    registered_function oid;
    allocate_worktree_function oid;
    append_worktree_event_function oid;
    materialization_grant_function oid;
    transition_worktree_function oid;
    issue_isolation_grant_function oid;
    isolation_snapshot_function oid;
    isolation_metadata_function oid;
    redeem_isolation_grant_function oid;
    claim_secret_lease_function oid;
    preview_authority_function oid;
    claim_preview_start_function oid;
    claim_preview_stop_function oid;
    transition_preview_function oid;
    observed_policy_count integer;
    observed_policy_relations integer;
    unsafe_policy_relations integer;
    policy_contract_hash text;
    support_policy_count integer;
    support_policy_relations integer;
    support_policy_contract_hash text;
    function_contract_hash text;
    safe_function_acls integer;
    observed_function_acls integer;
    unsafe_function_acl record;
BEGIN
    SELECT version_num INTO STRICT schema_revision
    FROM public.saas_alembic_version;
    identity_function := to_regprocedure(
        'public.saas_runner_agent_identity_v1(uuid,bigint)'
    );
    canonical_json_function := to_regprocedure(
        'public.saas_canonical_json_v1(jsonb)'
    );
    canonical_json_sha256_function := to_regprocedure(
        'public.saas_canonical_json_sha256_v1(jsonb)'
    );
    worktree_authority_function := to_regprocedure(
        'public.saas_runner_worktree_authority_live_v1('
        'text,uuid,uuid,uuid,text,bigint,boolean)'
    );
    registered_function := to_regprocedure(
        'public.saas_runner_agent_registered_v1(uuid,bigint)'
    );
    allocate_worktree_function := to_regprocedure(
        'public.saas_runner_allocate_worktree_v1('
        'text,uuid,uuid,uuid,uuid,text,bigint,integer,text,text,uuid)'
    );
    append_worktree_event_function := to_regprocedure(
        'public.saas_runner_append_worktree_event_v1(uuid,text,jsonb,text)'
    );
    materialization_grant_function := to_regprocedure(
        'public.saas_runner_materialization_grant_v1(uuid,uuid,bigint,bigint,text)'
    );
    transition_worktree_function := to_regprocedure(
        'public.saas_runner_transition_worktree_v1('
        'text,uuid,uuid,bigint,bigint,text,bigint,boolean,integer,'
        'text,text,text,text,text)'
    );
    issue_isolation_grant_function := to_regprocedure(
        'public.saas_runner_issue_isolation_grant_v1('
        'text,uuid,uuid,uuid,bigint,bigint,uuid,text,integer)'
    );
    isolation_snapshot_function := to_regprocedure(
        'public.saas_runner_isolation_snapshot_v1(text,uuid,uuid)'
    );
    isolation_metadata_function := to_regprocedure(
        'public.saas_runner_isolation_metadata_v1(text,uuid,uuid)'
    );
    redeem_isolation_grant_function := to_regprocedure(
        'public.saas_runner_redeem_isolation_grant_v1(text,uuid,uuid,jsonb)'
    );
    claim_secret_lease_function := to_regprocedure(
        'public.saas_runner_claim_secret_lease_v1(text,uuid,uuid)'
    );
    preview_authority_function := to_regprocedure(
        'public.saas_runner_preview_authority_v1('
        'text,uuid,uuid,uuid,bigint,bigint)'
    );
    claim_preview_start_function := to_regprocedure(
        'public.saas_runner_claim_preview_start_v1('
        'text,uuid,uuid,uuid,bigint,bigint,text)'
    );
    claim_preview_stop_function := to_regprocedure(
        'public.saas_runner_claim_preview_stop_v1('
        'text,uuid,uuid,uuid,bigint,bigint,text)'
    );
    transition_preview_function := to_regprocedure(
        'public.saas_runner_transition_preview_v1('
        'text,text,uuid,uuid,uuid,bigint,bigint,uuid,text,uuid,bigint,'
        'boolean,boolean,text)'
    );
    IF schema_revision NOT IN ('p0s000000010', 'p0s000000011') THEN
        IF canonical_json_function IS NOT NULL
           OR canonical_json_sha256_function IS NOT NULL
           OR worktree_authority_function IS NOT NULL
           OR identity_function IS NOT NULL OR registered_function IS NOT NULL
           OR allocate_worktree_function IS NOT NULL
           OR append_worktree_event_function IS NOT NULL
           OR materialization_grant_function IS NOT NULL
           OR transition_worktree_function IS NOT NULL
           OR issue_isolation_grant_function IS NOT NULL
           OR isolation_snapshot_function IS NOT NULL
           OR isolation_metadata_function IS NOT NULL
           OR redeem_isolation_grant_function IS NOT NULL
           OR claim_secret_lease_function IS NOT NULL
           OR preview_authority_function IS NOT NULL
           OR claim_preview_start_function IS NOT NULL
           OR claim_preview_stop_function IS NOT NULL
           OR transition_preview_function IS NOT NULL
           OR to_regclass('public.uq_worktree_runner_run_fence_v1') IS NOT NULL
           OR to_regclass(
                'public.uq_runner_isolation_grant_capability_worktree_v1'
           ) IS NOT NULL
           OR EXISTS (
            SELECT 1
            FROM pg_policy AS policy
            WHERE (SELECT oid FROM pg_roles WHERE rolname = 'saas_runner_agent') =
                  ANY(policy.polroles)
               OR policy.polname ~ '^rls_.*_runner_api_definer$'
        ) THEN
            RAISE EXCEPTION 'P0S10 Runner authority found on an older schema revision';
        END IF;
        RETURN;
    END IF;
    IF canonical_json_function IS NULL OR canonical_json_sha256_function IS NULL
       OR worktree_authority_function IS NULL
       OR identity_function IS NULL OR registered_function IS NULL
       OR allocate_worktree_function IS NULL
       OR append_worktree_event_function IS NULL
       OR materialization_grant_function IS NULL
       OR transition_worktree_function IS NULL
       OR issue_isolation_grant_function IS NULL
       OR isolation_snapshot_function IS NULL
       OR isolation_metadata_function IS NULL
       OR redeem_isolation_grant_function IS NULL
       OR claim_secret_lease_function IS NULL
       OR preview_authority_function IS NULL
       OR claim_preview_start_function IS NULL
       OR claim_preview_stop_function IS NULL
       OR transition_preview_function IS NULL THEN
        RAISE EXCEPTION 'P0S10 Runner authority object contract rejected';
    END IF;

    SELECT count(*), count(DISTINCT policy.polrelid)
    INTO observed_policy_count, observed_policy_relations
    FROM pg_policy AS policy
    JOIN pg_class AS relation ON relation.oid = policy.polrelid
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND (SELECT oid FROM pg_roles WHERE rolname = 'saas_runner_agent') =
          ANY(policy.polroles);
    SELECT count(*)
    INTO unsafe_policy_relations
    FROM (
        SELECT DISTINCT relation.oid
        FROM pg_policy AS policy
        JOIN pg_class AS relation ON relation.oid = policy.polrelid
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND (SELECT oid FROM pg_roles WHERE rolname = 'saas_runner_agent') =
              ANY(policy.polroles)
          AND (
              NOT relation.relrowsecurity
              OR NOT relation.relforcerowsecurity
              OR relation.relowner <> (
                  SELECT registration.relowner
                  FROM pg_class AS registration
                  WHERE registration.oid =
                        'public.saas_runner_registrations'::regclass
              )
          )
    ) AS unsafe_relation;
    IF observed_policy_count <> 36 OR observed_policy_relations <> 18
       OR unsafe_policy_relations <> 0
    THEN
        RAISE EXCEPTION 'P0S10 Runner RLS policy contract rejected';
    END IF;
    SELECT encode(sha256(convert_to(string_agg(
        relation.relname || '|' || policy.polname || '|' ||
        policy.polcmd::text || '|' || policy.polpermissive::text || '|' ||
        array_to_string(ARRAY(
            SELECT role.rolname
            FROM unnest(policy.polroles) AS role_oid
            JOIN pg_roles AS role ON role.oid = role_oid
            ORDER BY role.rolname
        ), ',') || '|' ||
        COALESCE(pg_get_expr(policy.polqual, policy.polrelid, false), '') || '|' ||
        COALESCE(pg_get_expr(policy.polwithcheck, policy.polrelid, false), '') || '|' ||
        relation.relrowsecurity::text || '|' ||
        relation.relforcerowsecurity::text || '|' ||
        (relation.relowner = (
            SELECT registration.relowner
            FROM pg_class AS registration
            WHERE registration.oid =
                  'public.saas_runner_registrations'::regclass
        ))::text,
        E'\n' ORDER BY relation.relname, policy.polname
    ), 'UTF8')), 'hex')
    INTO policy_contract_hash
    FROM pg_policy AS policy
    JOIN pg_class AS relation ON relation.oid = policy.polrelid
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND (SELECT oid FROM pg_roles WHERE rolname = 'saas_runner_agent') =
          ANY(policy.polroles);
    -- pg_dump/pg_restore reparses the three varchar-array predicates used by
    -- Runner registration and Worktree selection into an equivalent text-array
    -- AST.  Admit only the exact migrated or exact logical-roundtrip catalogs;
    -- counts, owners, FORCE RLS, roles, commands, and every other expression
    -- remain part of the digest above.
    IF policy_contract_hash IS DISTINCT FROM
       'd312cd026e9669e0fb5e723c390c8f0e93c5566ff691ad6d4a41870147d17f0a'
       AND policy_contract_hash IS DISTINCT FROM
       '3ef7ef89c9dc74b75a3a22d8c6e31ac48d48d38f15aae1c17a9a654db9b5d325'
    THEN
        RAISE EXCEPTION 'P0S10 Runner RLS policy contract rejected';
    END IF;
    SELECT count(*), count(DISTINCT policy.polrelid),
        encode(sha256(convert_to(string_agg(
            relation.relname || '|' || policy.polname || '|' ||
            policy.polcmd::text || '|' || policy.polpermissive::text || '|' ||
            array_to_string(ARRAY(
                SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' ELSE role.rolname END
                FROM unnest(policy.polroles) AS role_oid
                LEFT JOIN pg_roles AS role ON role.oid = role_oid
                ORDER BY 1
            ), ',') || '|' ||
            COALESCE(pg_get_expr(policy.polqual, policy.polrelid, false), '') || '|' ||
            COALESCE(pg_get_expr(policy.polwithcheck, policy.polrelid, false), '') || '|' ||
            relation.relrowsecurity::text || '|' ||
            relation.relforcerowsecurity::text || '|' ||
            (relation.relowner = (
                SELECT registration.relowner FROM pg_class AS registration
                WHERE registration.oid =
                      'public.saas_runner_registrations'::regclass
            ))::text,
            E'\n' ORDER BY relation.relname, policy.polname
        ), 'UTF8')), 'hex')
    INTO support_policy_count, support_policy_relations,
        support_policy_contract_hash
    FROM pg_policy AS policy
    JOIN pg_class AS relation ON relation.oid = policy.polrelid
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND policy.polname ~ '^rls_.*_runner_api_definer$';
    IF support_policy_count <> 19 OR support_policy_relations <> 19
       OR support_policy_contract_hash IS DISTINCT FROM
          'dc0b05ef2b6602113a0158cab27b3e787f39edd8b285ab40bc10aa5fd78bd65e'
    THEN
        RAISE EXCEPTION 'P0S10 Runner API support policy contract rejected';
    END IF;
    SELECT encode(sha256(convert_to(string_agg(
        procedure.proname || '|' || oidvectortypes(procedure.proargtypes) ||
        '|' || language.lanname || '|' || procedure.prokind::text || '|' ||
        procedure.prosecdef::text || '|' || procedure.proleakproof::text ||
        '|' || procedure.provolatile::text || '|' ||
        procedure.proparallel::text || '|' ||
        COALESCE(array_to_string(procedure.proconfig, E'\x1f'), '') || '|' ||
        pg_get_function_result(procedure.oid) || '|' || procedure.prosrc ||
        '|' || (procedure.proowner = (
            SELECT relation.relowner FROM pg_class AS relation
            WHERE relation.oid =
                  'public.saas_runner_registrations'::regclass
        ))::text,
        E'\n' ORDER BY procedure.proname
    ), 'UTF8')), 'hex')
    INTO function_contract_hash
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    JOIN pg_language AS language ON language.oid = procedure.prolang
    WHERE namespace.nspname = 'public'
      AND procedure.proname IN (
          'saas_canonical_json_v1',
          'saas_canonical_json_sha256_v1',
          'saas_runner_worktree_authority_live_v1',
          'saas_runner_agent_identity_v1',
          'saas_runner_agent_registered_v1',
          'saas_runner_allocate_worktree_v1',
          'saas_runner_append_worktree_event_v1',
          'saas_runner_materialization_grant_v1',
          'saas_runner_transition_worktree_v1',
          'saas_runner_issue_isolation_grant_v1',
          'saas_runner_isolation_snapshot_v1',
          'saas_runner_isolation_metadata_v1',
          'saas_runner_redeem_isolation_grant_v1',
          'saas_runner_claim_secret_lease_v1',
          'saas_runner_preview_authority_v1',
          'saas_runner_claim_preview_start_v1',
          'saas_runner_claim_preview_stop_v1',
          'saas_runner_transition_preview_v1'
      );
    IF function_contract_hash IS DISTINCT FROM
       '43423586ac39ca5a08a415b36f37e93d7409deb5f03050238b0b876c4d33ca02'
    THEN
        RAISE EXCEPTION 'P0S10 Runner function contract rejected';
    END IF;

    -- Remove PostgreSQL's implicit PUBLIC EXECUTE and any replay drift before
    -- restoring the sole invoker.  The owner sanitizer earlier in this file
    -- has already removed every stale table, column, sequence, and routine ACL
    -- from saas_runner_agent.
    REVOKE ALL ON FUNCTION
        public.saas_canonical_json_v1(jsonb),
        public.saas_canonical_json_sha256_v1(jsonb),
        public.saas_runner_worktree_authority_live_v1(
            text,uuid,uuid,uuid,text,bigint,boolean
        )
    FROM PUBLIC;
    REVOKE ALL ON FUNCTION
        public.saas_runner_agent_identity_v1(uuid,bigint)
    FROM PUBLIC;
    REVOKE ALL ON FUNCTION
        public.saas_runner_agent_registered_v1(uuid,bigint)
    FROM PUBLIC;
    REVOKE ALL ON FUNCTION
        public.saas_runner_allocate_worktree_v1(
            text,uuid,uuid,uuid,uuid,text,bigint,integer,text,text,uuid
        ),
        public.saas_runner_append_worktree_event_v1(uuid,text,jsonb,text),
        public.saas_runner_materialization_grant_v1(uuid,uuid,bigint,bigint,text),
        public.saas_runner_transition_worktree_v1(
            text,uuid,uuid,bigint,bigint,text,bigint,boolean,integer,
            text,text,text,text,text
        ),
        public.saas_runner_issue_isolation_grant_v1(
            text,uuid,uuid,uuid,bigint,bigint,uuid,text,integer
        ),
        public.saas_runner_isolation_snapshot_v1(text,uuid,uuid),
        public.saas_runner_isolation_metadata_v1(text,uuid,uuid),
        public.saas_runner_redeem_isolation_grant_v1(text,uuid,uuid,jsonb),
        public.saas_runner_claim_secret_lease_v1(text,uuid,uuid),
        public.saas_runner_preview_authority_v1(
            text,uuid,uuid,uuid,bigint,bigint
        ),
        public.saas_runner_claim_preview_start_v1(
            text,uuid,uuid,uuid,bigint,bigint,text
        ),
        public.saas_runner_claim_preview_stop_v1(
            text,uuid,uuid,uuid,bigint,bigint,text
        ),
        public.saas_runner_transition_preview_v1(
            text,text,uuid,uuid,uuid,bigint,bigint,uuid,text,uuid,bigint,
            boolean,boolean,text
        )
    FROM PUBLIC;
    FOR unsafe_function_acl IN
        SELECT DISTINCT
            'public.' || quote_ident(procedure.proname) || '(' ||
                pg_get_function_identity_arguments(procedure.oid) || ')' AS signature,
            pg_get_userbyid(acl.grantee) AS grantee_name
        FROM pg_proc AS procedure
        CROSS JOIN LATERAL aclexplode(
            COALESCE(procedure.proacl, acldefault('f', procedure.proowner))
        ) AS acl
        WHERE procedure.oid IN (
            canonical_json_function, canonical_json_sha256_function,
            worktree_authority_function,
            identity_function, registered_function, allocate_worktree_function,
            append_worktree_event_function, materialization_grant_function,
            transition_worktree_function, issue_isolation_grant_function,
            isolation_snapshot_function, isolation_metadata_function,
            redeem_isolation_grant_function, claim_secret_lease_function,
            preview_authority_function, claim_preview_start_function,
            claim_preview_stop_function, transition_preview_function
        )
          AND acl.grantee NOT IN (0, procedure.proowner)
          AND pg_get_userbyid(acl.grantee) <> 'saas_runner_agent'
    LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || unsafe_function_acl.signature ||
            ' FROM ' || quote_ident(unsafe_function_acl.grantee_name);
    END LOOP;
    GRANT EXECUTE ON FUNCTION
        public.saas_runner_agent_identity_v1(uuid,bigint)
    TO saas_runner_agent;
    GRANT EXECUTE ON FUNCTION
        public.saas_runner_agent_registered_v1(uuid,bigint)
    TO saas_runner_agent;
    GRANT EXECUTE ON FUNCTION
        public.saas_runner_allocate_worktree_v1(
            text,uuid,uuid,uuid,uuid,text,bigint,integer,text,text,uuid
        ),
        public.saas_runner_materialization_grant_v1(uuid,uuid,bigint,bigint,text),
        public.saas_runner_transition_worktree_v1(
            text,uuid,uuid,bigint,bigint,text,bigint,boolean,integer,
            text,text,text,text,text
        ),
        public.saas_runner_issue_isolation_grant_v1(
            text,uuid,uuid,uuid,bigint,bigint,uuid,text,integer
        ),
        public.saas_runner_isolation_metadata_v1(text,uuid,uuid),
        public.saas_runner_redeem_isolation_grant_v1(text,uuid,uuid,jsonb),
        public.saas_runner_claim_secret_lease_v1(text,uuid,uuid),
        public.saas_runner_claim_preview_start_v1(
            text,uuid,uuid,uuid,bigint,bigint,text
        ),
        public.saas_runner_claim_preview_stop_v1(
            text,uuid,uuid,uuid,bigint,bigint,text
        ),
        public.saas_runner_transition_preview_v1(
            text,text,uuid,uuid,uuid,bigint,bigint,uuid,text,uuid,bigint,
            boolean,boolean,text
        )
    TO saas_runner_agent;

    GRANT SELECT ON
        public.saas_alembic_version,
        public.saas_run_dispatches,
        public.saas_runs,
        public.saas_repositories,
        public.saas_changeset_groups,
        public.saas_changesets,
        public.saas_worktree_quotas,
        public.saas_worktree_events,
        public.saas_egress_policies,
        public.saas_execution_profiles,
        public.saas_secret_bindings,
        public.saas_preview_sessions
    TO saas_runner_agent;
    GRANT SELECT (
        id, pool_id, placement_id, instance_key, failure_domain, status,
        connection_generation, protocol_version, source_revision, schema_revision,
        adapter_contract_version, capabilities, capabilities_hash,
        max_concurrency, active_leases, last_heartbeat_at, registered_at, updated_at
    ) ON public.saas_runner_registrations TO saas_runner_agent;
    GRANT SELECT (
        id, tenant_id, space_id, project_id, run_id, runner_id,
        runner_connection_generation, dispatch_generation, fence_token,
        allowed_actions, resource_scope, issued_at, expires_at, revoked_at,
        revocation_reason
    ) ON public.saas_capability_tokens TO saas_runner_agent;
    GRANT SELECT (
        id, tenant_id, space_id, project_id, change_set_id, run_id, runner_id,
        created_by, created_by_service_account_id, opaque_runtime_key, access_mode,
        status, lease_generation, run_fence_token, runner_connection_generation,
        lease_expires_at, heartbeat_at, maximum_lifetime_at, reserved_bytes,
        actual_bytes, dirty, recovery_artifact_ref, environment_snapshot_ref,
        event_sequence, released_at, quarantine_reason, deleted_at, created_at,
        updated_at
    ) ON public.saas_worktree_instances TO saas_runner_agent;
    GRANT SELECT (
        id, tenant_id, space_id, project_id, run_id, runner_id, worktree_id,
        execution_profile_id, capability_id, run_fence_token,
        runner_connection_generation, worktree_lease_generation, grant_hash,
        status, expires_at, redeemed_at, revoked_at, created_at
    ) ON public.saas_run_isolation_grants TO saas_runner_agent;
    GRANT SELECT (
        id, tenant_id, space_id, project_id, isolation_grant_id,
        secret_binding_id, run_id, runner_id, run_fence_token,
        runner_connection_generation, status, expires_at, redeemed_at,
        revoked_at, created_at
    ) ON public.saas_secret_access_leases TO saas_runner_agent;
    GRANT SELECT (
        id, tenant_id, space_id, project_id, source_run_id, child_run_id,
        change_set_id, created_by, profile, idempotency_key_hash, request_hash,
        opaque_preview_key, preview_host, status, command_generation, runner_id,
        placement_id, worktree_id, run_fence_token, runner_connection_generation,
        worktree_lease_generation, exchange_issued_at, exchange_consumed_at,
        expires_at, ready_at, terminal_at, failure_code, version, created_at,
        updated_at
    ) ON public.saas_preview_executions TO saas_runner_agent;
    GRANT SELECT (
        id, tenant_id, space_id, project_id, preview_execution_id, command_type,
        generation, request_hash, status, runner_id, placement_id,
        runner_connection_generation, run_fence_token, claimed_by_gateway,
        attempt_count, available_at, claimed_at, completed_at, failure_code,
        created_at, updated_at
    ) ON public.saas_preview_commands TO saas_runner_agent;
    REVOKE SELECT ON public.saas_preview_sessions FROM saas_runner_agent;
    GRANT SELECT (
        id, tenant_id, space_id, project_id, preview_execution_id, generation,
        status, expires_at, last_authenticated_at, rotated_at, revoked_at,
        created_at, updated_at
    ) ON public.saas_preview_sessions TO saas_runner_agent;

    -- All business mutations below this boundary are owner-executed through
    -- exact SECURITY DEFINER APIs.  Runner logins receive no raw INSERT,
    -- DELETE, or mutable-column UPDATE authority on Worktree, evidence,
    -- isolation, secret, or Preview lifecycle tables.

    SELECT count(*), count(*) FILTER (
        WHERE (
            acl.grantee = procedure.proowner
            AND acl.grantor = procedure.proowner
            AND acl.privilege_type = 'EXECUTE'
            AND NOT acl.is_grantable
        ) OR (
            pg_get_userbyid(acl.grantee) = 'saas_runner_agent'
            AND acl.grantor = procedure.proowner
            AND acl.privilege_type = 'EXECUTE'
            AND NOT acl.is_grantable
        )
    )
    INTO observed_function_acls, safe_function_acls
    FROM pg_proc AS procedure
    CROSS JOIN LATERAL aclexplode(
        COALESCE(procedure.proacl, acldefault('f', procedure.proowner))
    ) AS acl
    WHERE procedure.oid IN (
        canonical_json_function, canonical_json_sha256_function,
        worktree_authority_function,
        identity_function, registered_function, allocate_worktree_function,
        append_worktree_event_function, materialization_grant_function,
        transition_worktree_function, issue_isolation_grant_function,
        isolation_snapshot_function, isolation_metadata_function,
        redeem_isolation_grant_function, claim_secret_lease_function,
        preview_authority_function, claim_preview_start_function,
        claim_preview_stop_function, transition_preview_function
    );
    IF observed_function_acls <> 30 OR safe_function_acls <> 30 OR NOT EXISTS (
        SELECT 1
        FROM pg_proc AS procedure
        JOIN pg_language AS language ON language.oid = procedure.prolang
        WHERE procedure.oid = identity_function
          AND language.lanname = 'sql'
          AND procedure.prokind = 'f'
          AND NOT procedure.prosecdef
          AND NOT procedure.proleakproof
          AND procedure.provolatile = 's'
          AND procedure.proparallel = 's'
          AND procedure.proconfig = ARRAY['search_path=pg_catalog']::text[]
          AND pg_get_function_result(procedure.oid) = 'boolean'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_proc AS procedure
        JOIN pg_language AS language ON language.oid = procedure.prolang
        WHERE procedure.oid = registered_function
          AND language.lanname = 'sql'
          AND procedure.prokind = 'f'
          AND NOT procedure.prosecdef
          AND NOT procedure.proleakproof
          AND procedure.provolatile = 's'
          AND procedure.proparallel = 's'
          AND procedure.proconfig = ARRAY['search_path=pg_catalog']::text[]
          AND pg_get_function_result(procedure.oid) = 'boolean'
          AND procedure.proowner = (
              SELECT relation.relowner
              FROM pg_class AS relation
              WHERE relation.oid =
                    'public.saas_runner_registrations'::regclass
          )
    ) OR has_function_privilege(
        'saas_runner_agent', canonical_json_function, 'EXECUTE'
    ) OR has_function_privilege(
        'saas_runner_agent', canonical_json_sha256_function, 'EXECUTE'
    ) OR has_function_privilege(
        'saas_runner_agent', worktree_authority_function, 'EXECUTE'
    ) OR has_function_privilege(
        'saas_runner_agent', append_worktree_event_function, 'EXECUTE'
    ) OR has_function_privilege(
        'saas_runner_agent', isolation_snapshot_function, 'EXECUTE'
    ) OR has_function_privilege(
        'saas_runner_agent', preview_authority_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', allocate_worktree_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', materialization_grant_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', transition_worktree_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', issue_isolation_grant_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', isolation_metadata_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', redeem_isolation_grant_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', claim_secret_lease_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', claim_preview_start_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', claim_preview_stop_function, 'EXECUTE'
    ) OR NOT has_function_privilege(
        'saas_runner_agent', transition_preview_function, 'EXECUTE'
    ) OR (
        SELECT count(*) <> 16
        FROM pg_proc AS procedure
        WHERE procedure.oid IN (
            canonical_json_function, canonical_json_sha256_function,
            worktree_authority_function,
            allocate_worktree_function, append_worktree_event_function,
            materialization_grant_function, transition_worktree_function,
            issue_isolation_grant_function, isolation_snapshot_function,
            isolation_metadata_function, redeem_isolation_grant_function,
            claim_secret_lease_function, preview_authority_function,
            claim_preview_start_function, claim_preview_stop_function,
            transition_preview_function
        )
          AND procedure.prosecdef
          AND NOT procedure.proleakproof
          AND procedure.proconfig =
              ARRAY['search_path=pg_catalog, pg_temp']::text[]
          AND procedure.proowner = (
              SELECT relation.relowner
              FROM pg_class AS relation
              WHERE relation.oid =
                    'public.saas_runner_registrations'::regclass
          )
    ) THEN
        RAISE EXCEPTION 'P0S10 Runner identity function authority rejected';
    END IF;
END
$$;
