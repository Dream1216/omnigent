-- Transaction body for the official Runtime database-object authority.
-- psql operators must use postgresql_roles.psql; API callers must execute this
-- file inside an explicit transaction. Cluster roles are created and hardened
-- only by saas/control_plane/postgresql_principals.psql.
--
-- Run as the direct, NOCREATEROLE owner of the official Runtime tables after
-- official Alembic and Runtime RLS installation. The preflight completes before
-- the first ACL mutation and the final projection is deliberately replayable.

DO $$
DECLARE
    runtime_role oid;
    caller_role oid;
    expected_tables constant text[] := ARRAY[
        'account_tokens',
        'agents',
        'comments',
        'conversation_items',
        'conversation_labels',
        'conversations',
        'device_grants',
        'files',
        'hosts',
        'omnigent_conversation_metadata',
        'policies',
        'projects',
        'scheduled_task_runs',
        'scheduled_tasks',
        'session_permissions',
        'user_daily_cost',
        'users'
    ];
    unsafe_unmanaged_authority integer;
    unsafe_ownership integer;
    unsafe_tables text[];
    unsafe_policies text[];
BEGIN
    IF current_user <> session_user THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: caller started under an assumed role';
    END IF;

    SELECT role.oid
    INTO caller_role
    FROM pg_roles AS role
    WHERE role.rolname = current_user
      AND role.rolcanlogin
      AND NOT role.rolsuper
      AND NOT role.rolcreatedb
      AND NOT role.rolcreaterole
      AND NOT role.rolreplication
      AND NOT role.rolbypassrls
      AND role.rolinherit
      AND role.rolconnlimit = -1
      AND role.rolconfig IS NULL;
    IF caller_role IS NULL THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: caller is not a narrow direct owner';
    END IF;

    SELECT role.oid
    INTO runtime_role
    FROM pg_roles AS role
    WHERE role.rolname = 'omnigent_runtime_app'
      AND NOT role.rolcanlogin
      AND NOT role.rolsuper
      AND NOT role.rolcreatedb
      AND NOT role.rolcreaterole
      AND NOT role.rolreplication
      AND NOT role.rolbypassrls
      AND role.rolinherit
      AND role.rolconnlimit = -1
      AND role.rolconfig IS NULL;
    IF runtime_role IS NULL THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: run postgresql_principals.psql first';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_auth_members AS membership
        WHERE membership.member = runtime_role
    ) OR EXISTS (
        SELECT 1 FROM pg_db_role_setting AS setting
        WHERE setting.setrole = runtime_role
    ) THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: Runtime principal has outgoing authority';
    END IF;

    SELECT array_agg(expected.table_name ORDER BY expected.table_name)
    INTO unsafe_tables
    FROM unnest(expected_tables) AS expected(table_name)
    LEFT JOIN pg_class AS relation
      ON relation.oid = to_regclass('public.' || quote_ident(expected.table_name))
    WHERE relation.oid IS NULL
       OR relation.relkind NOT IN ('r', 'p')
       OR relation.relowner <> caller_role;
    IF unsafe_tables IS NOT NULL THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: official table ownership drifted';
    END IF;

    SELECT count(*)
    INTO unsafe_ownership
    FROM (
        SELECT 1 FROM pg_database WHERE datdba = runtime_role
        UNION ALL
        SELECT 1 FROM pg_namespace WHERE nspowner = runtime_role
        UNION ALL
        SELECT 1 FROM pg_class WHERE relowner = runtime_role
        UNION ALL
        SELECT 1 FROM pg_proc WHERE proowner = runtime_role
        UNION ALL
        SELECT 1 FROM pg_type WHERE typowner = runtime_role
        UNION ALL
        SELECT 1 FROM pg_default_acl WHERE defaclrole = runtime_role
    ) AS owned;
    IF unsafe_ownership <> 0 THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: Runtime principal owns database objects';
    END IF;

    -- The official owner cannot revoke grants made on SaaS-owned or otherwise
    -- foreign objects. Reject every such edge before the first mutation; only
    -- this caller's grants on the exact official table set are converged below.
    SELECT count(*)
    INTO unsafe_unmanaged_authority
    FROM (
        SELECT 1
        FROM pg_namespace AS namespace
        CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl
        WHERE acl.grantee = runtime_role
          AND (
              namespace.nspname <> 'public'
              OR acl.grantor <> namespace.nspowner
              OR acl.privilege_type <> 'USAGE'
              OR acl.is_grantable
          )
        UNION ALL
        SELECT 1
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl
        WHERE acl.grantee = runtime_role
          AND (
              namespace.nspname <> 'public'
              OR relation.relname <> ALL(expected_tables)
              OR relation.relowner <> caller_role
              OR acl.grantor <> caller_role
          )
        UNION ALL
        SELECT 1
        FROM pg_attribute AS attribute
        JOIN pg_class AS relation ON relation.oid = attribute.attrelid
        CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
        WHERE acl.grantee = runtime_role
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
        UNION ALL
        SELECT 1
        FROM pg_proc AS routine
        JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
        CROSS JOIN LATERAL aclexplode(routine.proacl) AS acl
        WHERE acl.grantee = runtime_role
        UNION ALL
        SELECT 1
        FROM pg_type AS type
        JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace
        CROSS JOIN LATERAL aclexplode(type.typacl) AS acl
        WHERE acl.grantee = runtime_role
        UNION ALL
        SELECT 1
        FROM pg_database AS database
        CROSS JOIN LATERAL aclexplode(database.datacl) AS acl
        WHERE acl.grantee = runtime_role
          AND (
              database.datname <> current_database()
              OR acl.grantor <> database.datdba
              OR acl.privilege_type <> 'CONNECT'
              OR acl.is_grantable
          )
        UNION ALL
        SELECT 1
        FROM pg_default_acl AS defaults
        CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl
        WHERE acl.grantee = runtime_role
    ) AS unmanaged_authority;
    IF unsafe_unmanaged_authority <> 0 THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: Runtime principal has unmanaged authority';
    END IF;

    SELECT array_agg(expected.table_name ORDER BY expected.table_name)
    INTO unsafe_policies
    FROM unnest(expected_tables) AS expected(table_name)
    JOIN pg_class AS relation
      ON relation.oid = to_regclass('public.' || quote_ident(expected.table_name))
    WHERE NOT relation.relrowsecurity
       OR NOT relation.relforcerowsecurity
       OR (
            SELECT count(*)
            FROM pg_policy AS policy
            WHERE policy.polrelid = relation.oid
              AND policy.polname IN (
                  'omnigent_runtime_workspace_access',
                  'omnigent_runtime_workspace_isolation'
              )
              AND (
                  (
                      policy.polname = 'omnigent_runtime_workspace_access'
                      AND policy.polpermissive
                  ) OR (
                      policy.polname = 'omnigent_runtime_workspace_isolation'
                      AND NOT policy.polpermissive
                  )
              )
              AND policy.polcmd = '*'
              AND policy.polroles = ARRAY[0::oid]
              AND position(
                  'app.runtime_workspace_id'
                  IN pg_get_expr(policy.polqual, policy.polrelid)
              ) > 0
              AND position(
                  'workspace_id'
                  IN pg_get_expr(policy.polwithcheck, policy.polrelid)
              ) > 0
       ) <> 2
       OR EXISTS (
            SELECT 1
            FROM pg_policy AS policy
            WHERE policy.polrelid = relation.oid
              AND policy.polname NOT IN (
                  'omnigent_runtime_workspace_access',
                  'omnigent_runtime_workspace_isolation'
              )
       );
    IF unsafe_policies IS NOT NULL THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: Runtime RLS contract drifted';
    END IF;
END
$$;

-- Converge the complete official table/column ACL surface, not only the
-- intended Runtime principal.  A custom PostgreSQL GUC is not an
-- authentication boundary: any role with a stale table grant could otherwise
-- choose a workspace id and satisfy the public RLS predicate.  The direct
-- official owner can remove grants it issued, but PostgreSQL leaves a grant
-- made by another grantor in place even when a plain owner REVOKE reports
-- success.  Reject every such foreign-grantor edge before the first mutation.
DO $$
DECLARE
    caller_role oid := (
        SELECT oid FROM pg_roles WHERE rolname = current_user
    );
    official_tables constant text[] := ARRAY[
        'account_tokens', 'agents', 'alembic_version', 'comments',
        'conversation_items', 'conversation_labels', 'conversations',
        'device_grants', 'files', 'hosts', 'omnigent_conversation_metadata',
        'policies', 'projects', 'scheduled_task_runs', 'scheduled_tasks',
        'session_permissions', 'user_daily_cost', 'users'
    ];
    unmanaged_acl_count integer;
    target_table text;
    target_grantee_sql text;
    target_privilege text;
    column_list text;
BEGIN
    SELECT count(*)
    INTO unmanaged_acl_count
    FROM (
        SELECT acl.grantee, acl.grantor
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl
        LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE namespace.nspname = 'public'
          AND relation.relname = ANY(official_tables)
          AND acl.grantee <> relation.relowner
          AND (
              acl.grantor <> caller_role
              OR (acl.grantee <> 0 AND grantee.oid IS NULL)
          )
        UNION ALL
        SELECT acl.grantee, acl.grantor
        FROM pg_attribute AS attribute
        JOIN pg_class AS relation ON relation.oid = attribute.attrelid
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
        LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
        WHERE namespace.nspname = 'public'
          AND relation.relname = ANY(official_tables)
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND acl.grantee <> relation.relowner
          AND (
              acl.grantor <> caller_role
              OR (acl.grantee <> 0 AND grantee.oid IS NULL)
          )
    ) AS unmanaged_acl;
    IF unmanaged_acl_count <> 0 THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: official foreign-grantor ACL drifted';
    END IF;

    FOREACH target_table IN ARRAY official_tables
    LOOP
        FOR target_grantee_sql IN
            SELECT DISTINCT CASE
                WHEN observed.grantee = 0 THEN 'PUBLIC'
                ELSE quote_ident(grantee.rolname)
            END
            FROM (
                SELECT acl.grantee, acl.grantor
                FROM pg_class AS relation
                CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl
                WHERE relation.oid = ('public.' || quote_ident(target_table))::regclass
                UNION ALL
                SELECT acl.grantee, acl.grantor
                FROM pg_attribute AS attribute
                CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
                WHERE attribute.attrelid =
                    ('public.' || quote_ident(target_table))::regclass
                  AND attribute.attnum > 0
                  AND NOT attribute.attisdropped
            ) AS observed
            LEFT JOIN pg_roles AS grantee ON grantee.oid = observed.grantee
            WHERE observed.grantee <> caller_role
              AND observed.grantor = caller_role
            ORDER BY 1
        LOOP
            EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE public.' ||
                quote_ident(target_table) || ' FROM ' || target_grantee_sql;
            SELECT string_agg(
                quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum
            )
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
                        ' FROM ' || target_grantee_sql;
                END LOOP;
            END IF;
        END LOOP;
    END LOOP;
END
$$;

REVOKE ALL PRIVILEGES ON TABLE
    account_tokens,
    agents,
    comments,
    conversation_items,
    conversation_labels,
    conversations,
    device_grants,
    files,
    hosts,
    omnigent_conversation_metadata,
    policies,
    projects,
    scheduled_task_runs,
    scheduled_tasks,
    session_permissions,
    user_daily_cost,
    users
FROM omnigent_runtime_app;

REVOKE ALL PRIVILEGES ON TABLE
    account_tokens,
    agents,
    comments,
    conversation_items,
    conversation_labels,
    conversations,
    device_grants,
    files,
    hosts,
    omnigent_conversation_metadata,
    policies,
    projects,
    scheduled_task_runs,
    scheduled_tasks,
    session_permissions,
    user_daily_cost,
    users
FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    account_tokens,
    agents,
    comments,
    conversation_items,
    conversation_labels,
    conversations,
    device_grants,
    files,
    hosts,
    omnigent_conversation_metadata,
    policies,
    projects,
    scheduled_task_runs,
    scheduled_tasks,
    session_permissions,
    user_daily_cost,
    users
TO omnigent_runtime_app;

DO $$
DECLARE
    runtime_role oid := (
        SELECT oid FROM pg_roles WHERE rolname = 'omnigent_runtime_app'
    );
    caller_role oid := (
        SELECT oid FROM pg_roles WHERE rolname = current_user
    );
    expected_tables constant text[] := ARRAY[
        'account_tokens', 'agents', 'comments', 'conversation_items',
        'conversation_labels', 'conversations', 'device_grants', 'files',
        'hosts', 'omnigent_conversation_metadata', 'policies', 'projects',
        'scheduled_task_runs', 'scheduled_tasks', 'session_permissions',
        'user_daily_cost', 'users'
    ];
    official_tables constant text[] := ARRAY[
        'account_tokens', 'agents', 'alembic_version', 'comments',
        'conversation_items', 'conversation_labels', 'conversations',
        'device_grants', 'files', 'hosts', 'omnigent_conversation_metadata',
        'policies', 'projects', 'scheduled_task_runs', 'scheduled_tasks',
        'session_permissions', 'user_daily_cost', 'users'
    ];
    relation_acl_count integer;
    schema_acl_count integer;
    unexpected_acl_count integer;
BEGIN
    SELECT count(*)
    INTO relation_acl_count
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl
    WHERE namespace.nspname = 'public'
      AND relation.relname = ANY(expected_tables)
      AND acl.grantee = runtime_role
      AND acl.grantor = relation.relowner
      AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
      AND NOT acl.is_grantable;

    SELECT count(*)
    INTO schema_acl_count
    FROM pg_namespace AS namespace
    CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl
    WHERE namespace.nspname = 'public'
      AND acl.grantee = runtime_role
      AND acl.privilege_type = 'USAGE'
      AND NOT acl.is_grantable;

    SELECT count(*)
    INTO unexpected_acl_count
    FROM (
        SELECT 1
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl
        WHERE namespace.nspname = 'public'
          AND relation.relname = ANY(official_tables)
          AND acl.grantee <> relation.relowner
          AND NOT (
              relation.relname = ANY(expected_tables)
              AND acl.grantee = runtime_role
              AND acl.grantor = caller_role
              AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
              AND NOT acl.is_grantable
          )
        UNION ALL
        SELECT 1
        FROM pg_attribute AS attribute
        JOIN pg_class AS relation ON relation.oid = attribute.attrelid
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
        WHERE namespace.nspname = 'public'
          AND relation.relname = ANY(official_tables)
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND acl.grantee <> relation.relowner
        UNION ALL
        SELECT 1
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl
        WHERE namespace.nspname = 'public'
          AND acl.grantee = runtime_role
          AND (
              relation.relname <> ALL(expected_tables)
              OR acl.privilege_type NOT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
              OR acl.is_grantable
          )
        UNION ALL
        SELECT 1
        FROM pg_namespace AS namespace
        CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl
        WHERE namespace.nspname = 'public'
          AND acl.grantee = runtime_role
          AND (acl.privilege_type <> 'USAGE' OR acl.is_grantable)
        UNION ALL
        SELECT 1
        FROM pg_attribute AS attribute
        JOIN pg_class AS relation ON relation.oid = attribute.attrelid
        CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
        WHERE acl.grantee = runtime_role
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
        UNION ALL
        SELECT 1
        FROM pg_proc AS routine
        CROSS JOIN LATERAL aclexplode(routine.proacl) AS acl
        WHERE acl.grantee = runtime_role
        UNION ALL
        SELECT 1
        FROM pg_type AS type
        CROSS JOIN LATERAL aclexplode(type.typacl) AS acl
        WHERE acl.grantee = runtime_role
        UNION ALL
        SELECT 1
        FROM pg_default_acl AS defaults
        CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl
        WHERE acl.grantee = runtime_role
    ) AS unexpected_acl;

    IF relation_acl_count <> cardinality(expected_tables) * 4
       OR schema_acl_count <> 1
       OR unexpected_acl_count <> 0 THEN
        RAISE EXCEPTION
            'Runtime database authority rejected: exact ACL projection failed';
    END IF;
END
$$;
