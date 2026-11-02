-- Additive database-owner phase; no PUBLIC/CREATE/TEMP/old-role grants.
DO $phase$
DECLARE db_owner name; caller_super boolean;
BEGIN
    SELECT pg_get_userbyid(datdba) INTO db_owner
    FROM pg_catalog.pg_database WHERE datname=current_database();
    SELECT rolsuper INTO caller_super FROM pg_catalog.pg_roles WHERE rolname=current_user;
    IF current_user<>db_owner AND NOT COALESCE(caller_super,false) THEN
        RAISE EXCEPTION 'typed-delivery schema reachability requires database owner';
    END IF;
    GRANT USAGE ON SCHEMA public
    TO saas_usage_consumer,saas_audit_delivery,saas_revocation_consumer;
END $phase$;
