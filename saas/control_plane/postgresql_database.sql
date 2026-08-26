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
    public_has_temporary boolean;
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

    EXECUTE 'REVOKE TEMPORARY ON DATABASE '
        || quote_ident(current_database()) || ' FROM PUBLIC';

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
END
$$;
