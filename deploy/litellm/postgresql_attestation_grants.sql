-- Run as the dedicated LiteLLM database owner after the pinned vendor migration.
REVOKE TEMPORARY ON DATABASE :"litellm_database" FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO omnigent_litellm_attestation_read;
GRANT CONNECT ON DATABASE :"litellm_database" TO omnigent_litellm_attestor;
GRANT SELECT (model_id, model_name, litellm_params, model_info, blocked)
    ON public."LiteLLM_ProxyModelTable" TO omnigent_litellm_attestation_read;
GRANT SELECT (credential_id, credential_name, credential_values, credential_info)
    ON public."LiteLLM_CredentialsTable" TO omnigent_litellm_attestation_read;
GRANT SELECT (param_name, param_value)
    ON public."LiteLLM_Config" TO omnigent_litellm_attestation_read;
