-- Run only with the existing cluster principal operator, never a serving identity.
DO $$
DECLARE role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['omnigent_litellm_attestation_read', 'omnigent_litellm_attestor'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('CREATE ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT', role_name);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name
                   AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
            RAISE EXCEPTION 'LiteLLM attestation role has unexpected authority';
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_auth_members membership JOIN pg_roles member ON member.oid = membership.member
               WHERE member.rolname IN ('omnigent_litellm_attestation_read', 'omnigent_litellm_attestor')
               AND NOT (member.rolname = 'omnigent_litellm_attestor'
                        AND membership.roleid = 'omnigent_litellm_attestation_read'::regrole
                        AND membership.inherit_option AND NOT membership.set_option
                        AND NOT membership.admin_option)) THEN
        RAISE EXCEPTION 'LiteLLM attestation membership drift';
    END IF;
END $$;
ALTER ROLE omnigent_litellm_attestation_read NOLOGIN;
ALTER ROLE omnigent_litellm_attestor LOGIN;
ALTER ROLE omnigent_litellm_attestor SET default_transaction_read_only = on;
GRANT omnigent_litellm_attestation_read TO omnigent_litellm_attestor WITH INHERIT TRUE, SET FALSE;
-- Issue its password through the deployment secret workflow; no password is stored here.
