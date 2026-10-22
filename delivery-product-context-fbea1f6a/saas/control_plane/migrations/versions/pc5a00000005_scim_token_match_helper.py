"""Encapsulate exact SCIM source-token matching behind a content-blind helper.

Revision ID: pc5a00000005
Revises: pc5a00000004
"""

from __future__ import annotations

from alembic import op

revision: str = "pc5a00000005"
down_revision: str | None = "pc5a00000004"
branch_labels: str | None = None
depends_on: str | None = None

_SOURCE_TABLES = (
    "saas_enterprise_scim_users",
    "saas_enterprise_scim_groups",
    "saas_enterprise_scim_events",
)


def _replace_source_policies(*, use_helper: bool) -> None:
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    token = "NULLIF(current_setting('app.scim_token_hash', true), '')"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    governance = "pg_has_role(current_user, 'saas_governance', 'member')"
    for table in _SOURCE_TABLES:
        if use_helper:
            source_scope = f"saas_scim_source_token_matches(tenant_id, directory_id, {token})"
        else:
            source_scope = (
                "EXISTS (SELECT 1 FROM saas_enterprise_scim_directories scim_source "
                f"WHERE scim_source.tenant_id = {table}.tenant_id "
                f"AND scim_source.id = {table}.directory_id "
                "AND scim_source.status = 'active' "
                f"AND (scim_source.token_hash = {token} "
                f"OR scim_source.successor_token_hash = {token}))"
            )
        scope = f"({platform} OR (tenant_id = {tenant} AND (NOT {governance} OR {source_scope})))"
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_select ON {table}")
        op.execute(f"CREATE POLICY rls_{table}_select ON {table} FOR SELECT USING ({scope})")
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_insert ON {table}")
        op.execute(f"CREATE POLICY rls_{table}_insert ON {table} FOR INSERT WITH CHECK ({scope})")
        if table != "saas_enterprise_scim_events":
            op.execute(f"DROP POLICY IF EXISTS rls_{table}_update ON {table}")
            op.execute(
                f"CREATE POLICY rls_{table}_update ON {table} FOR UPDATE "
                f"USING ({scope}) WITH CHECK ({scope})"
            )


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION saas_scim_source_token_matches(
            source_tenant_id uuid,
            source_directory_id uuid,
            presented_token_hash text
        ) RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $function$
            SELECT presented_token_hash IS NOT NULL
               AND presented_token_hash <> ''
               AND EXISTS (
                    SELECT 1
                    FROM public.saas_enterprise_scim_directories AS source
                    WHERE source.tenant_id = source_tenant_id
                      AND source.id = source_directory_id
                      AND source.status = 'active'
                      AND (
                          source.token_hash = presented_token_hash
                          OR source.successor_token_hash = presented_token_hash
                      )
               )
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION saas_scim_source_token_matches(uuid, uuid, text) FROM PUBLIC"
    )
    op.execute(
        """
        DO $$
        DECLARE role_name text;
        BEGIN
            FOREACH role_name IN ARRAY ARRAY[
                'saas_app', 'saas_governance', 'saas_platform', 'saas_privacy_executor'
            ] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
                    EXECUTE format(
                        'GRANT EXECUTE ON FUNCTION '
                        'saas_scim_source_token_matches(uuid, uuid, text) TO %I',
                        role_name
                    );
                END IF;
            END LOOP;
        END
        $$
        """
    )
    _replace_source_policies(use_helper=True)


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    _replace_source_policies(use_helper=False)
    op.execute("DROP FUNCTION IF EXISTS saas_scim_source_token_matches(uuid, uuid, text)")
