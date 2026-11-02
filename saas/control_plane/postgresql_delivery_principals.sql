-- Additive upgrade phase: never resets any pre-existing SaaS/Runner role graph.
-- Invoke only through postgresql_delivery_principals.psql, as principal operator.
DO $phase$
DECLARE role_name text; existing record;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'saas_usage_consumer','saas_audit_delivery','saas_revocation_consumer'
    ] LOOP
        SELECT * INTO existing FROM pg_catalog.pg_roles WHERE rolname=role_name;
        IF NOT FOUND THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                'NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT -1',role_name);
        ELSIF existing.rolcanlogin OR existing.rolsuper OR existing.rolcreatedb
            OR existing.rolcreaterole OR existing.rolreplication OR existing.rolbypassrls
            OR NOT existing.rolinherit OR existing.rolconnlimit<>-1
            OR existing.rolconfig IS NOT NULL THEN
            RAISE EXCEPTION 'existing typed-delivery principal is unsafe';
        END IF;
        IF EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m
            JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=role_name) THEN
            RAISE EXCEPTION 'typed-delivery base role inherits another authority';
        END IF;
    END LOOP;
END $phase$;
