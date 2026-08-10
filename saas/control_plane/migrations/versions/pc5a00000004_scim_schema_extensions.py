"""Add SCIM discovery profile, IdP mapping and optional User attributes.

Revision ID: pc5a00000004
Revises: pc6a00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc5a00000004"
down_revision: str | None = "pc6a00000001"
branch_labels: str | None = None
depends_on: str | None = None


def _replace_postgresql_source_policies(*, exact_directory: bool) -> None:
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    token = "NULLIF(current_setting('app.scim_token_hash', true), '')"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    governance = "pg_has_role(current_user, 'saas_governance', 'member')"
    for table in (
        "saas_enterprise_scim_users",
        "saas_enterprise_scim_groups",
        "saas_enterprise_scim_events",
    ):
        tenant_scope = f"({platform} OR tenant_id = {tenant})"
        if exact_directory:
            source_scope = (
                "EXISTS (SELECT 1 FROM saas_enterprise_scim_directories scim_source "
                f"WHERE scim_source.tenant_id = {table}.tenant_id "
                f"AND scim_source.id = {table}.directory_id "
                "AND scim_source.status = 'active' "
                f"AND (scim_source.token_hash = {token} "
                f"OR scim_source.successor_token_hash = {token}))"
            )
            tenant_scope = (
                f"({platform} OR (tenant_id = {tenant} AND (NOT {governance} OR {source_scope})))"
            )
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_select ON {table}")
        op.execute(
            f"CREATE POLICY rls_{table}_select ON {table} FOR SELECT USING ({tenant_scope})"
        )
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_insert ON {table}")
        op.execute(
            f"CREATE POLICY rls_{table}_insert ON {table} FOR INSERT WITH CHECK ({tenant_scope})"
        )
        if table != "saas_enterprise_scim_events":
            op.execute(f"DROP POLICY IF EXISTS rls_{table}_update ON {table}")
            op.execute(
                f"CREATE POLICY rls_{table}_update ON {table} FOR UPDATE "
                f"USING ({tenant_scope}) WITH CHECK ({tenant_scope})"
            )


def upgrade() -> None:
    with op.batch_alter_table("saas_enterprise_scim_directories") as batch_op:
        batch_op.add_column(
            sa.Column(
                "provider_type",
                sa.String(32),
                nullable=False,
                server_default="generic",
            )
        )
        batch_op.add_column(
            sa.Column(
                "attribute_mapping",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.create_check_constraint(
            "ck_scim_directory_provider_type",
            "provider_type IN ('generic', 'microsoft_entra', 'okta', 'google_workspace')",
        )
    with op.batch_alter_table("saas_enterprise_scim_users") as batch_op:
        batch_op.add_column(
            sa.Column(
                "core_attributes",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.add_column(
            sa.Column(
                "enterprise_attributes",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
    if op.get_bind().dialect.name == "postgresql":
        _replace_postgresql_source_policies(exact_directory=True)


def downgrade() -> None:
    bind = op.get_bind()
    configured = any(
        provider_type != "generic" or bool(attribute_mapping)
        for provider_type, attribute_mapping in bind.execute(
            sa.text(
                "SELECT provider_type, attribute_mapping FROM saas_enterprise_scim_directories"
            )
        )
    )
    enriched = any(
        bool(core_attributes) or bool(enterprise_attributes)
        for core_attributes, enterprise_attributes in bind.execute(
            sa.text(
                "SELECT core_attributes, enterprise_attributes FROM saas_enterprise_scim_users"
            )
        )
    )
    if configured or enriched:
        raise RuntimeError(
            "cannot downgrade SCIM schema extensions while IdP configuration or "
            "extended User attributes exist"
        )
    if bind.dialect.name == "postgresql":
        _replace_postgresql_source_policies(exact_directory=False)
    with op.batch_alter_table("saas_enterprise_scim_users") as batch_op:
        batch_op.drop_column("enterprise_attributes")
        batch_op.drop_column("core_attributes")
    with op.batch_alter_table("saas_enterprise_scim_directories") as batch_op:
        batch_op.drop_constraint("ck_scim_directory_provider_type", type_="check")
        batch_op.drop_column("attribute_mapping")
        batch_op.drop_column("provider_type")
