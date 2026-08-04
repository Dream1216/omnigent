-- Runtime data-plane role. Run after official migrations and Runtime RLS install.
-- Service login roles inherit this role; they must never own protected tables.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'omnigent_runtime_app') THEN
        CREATE ROLE omnigent_runtime_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

ALTER ROLE omnigent_runtime_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO omnigent_runtime_app;
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
