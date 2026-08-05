"""Create Service Account and hashed API credential authority.

Revision ID: p6a000000001
Revises: p5a000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p6a000000001"
down_revision: str | None = "p5a000000001"
branch_labels: str | None = None
depends_on: str | None = None


def _enable_rls() -> None:
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    credential = "NULLIF(current_setting('app.api_credential_id', true), '')::uuid"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    authenticator = "pg_has_role(current_user, 'saas_authenticator', 'member')"
    tenant_scope = f"({platform} OR tenant_id = {tenant})"
    exact_credential = f"({authenticator} AND id = {credential})"
    for table in ("saas_service_accounts", "saas_api_credentials"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY rls_service_account_select ON saas_service_accounts "
        f"FOR SELECT USING ({tenant_scope})"
    )
    op.execute(
        "CREATE POLICY rls_service_account_insert ON saas_service_accounts "
        f"FOR INSERT WITH CHECK ({tenant_scope})"
    )
    op.execute(
        "CREATE POLICY rls_service_account_update ON saas_service_accounts "
        f"FOR UPDATE USING ({tenant_scope}) WITH CHECK ({tenant_scope})"
    )
    op.execute(
        "CREATE POLICY rls_api_credential_select ON saas_api_credentials "
        f"FOR SELECT USING ({tenant_scope} OR {exact_credential})"
    )
    op.execute(
        "CREATE POLICY rls_api_credential_insert ON saas_api_credentials "
        f"FOR INSERT WITH CHECK ({tenant_scope})"
    )
    op.execute(
        "CREATE POLICY rls_api_credential_update ON saas_api_credentials "
        f"FOR UPDATE USING ({tenant_scope} OR {exact_credential}) "
        f"WITH CHECK ({tenant_scope} OR {exact_credential})"
    )


def upgrade() -> None:
    op.create_table(
        "saas_service_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=True),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("steward_user_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "project_id IS NULL OR space_id IS NOT NULL",
            name="ck_service_account_project_requires_space",
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_service_account_name_nonempty"),
        sa.CheckConstraint("security_version > 0", name="ck_service_account_security_version"),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'deleted')",
            name="ck_service_account_status",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "steward_user_id"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_service_account_steward_tenant_member",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "steward_user_id"],
            [
                "saas_space_memberships.tenant_id",
                "saas_space_memberships.space_id",
                "saas_space_memberships.user_id",
            ],
            name="fk_service_account_steward_space_member",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id"],
            ["saas_spaces.tenant_id", "saas_spaces.id"],
            name="fk_service_account_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id"],
            ["saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"],
            name="fk_service_account_project",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_service_account_tenant_id"),
    )
    op.create_index(
        "ix_service_account_scope_status",
        "saas_service_accounts",
        ["tenant_id", "space_id", "project_id", "status"],
    )
    op.create_index(
        "ix_service_account_steward",
        "saas_service_accounts",
        ["tenant_id", "steward_user_id", "status"],
    )
    op.create_table(
        "saas_api_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("service_account_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("display_prefix", sa.String(length=64), nullable=False),
        sa.Column("permission_scopes", sa.JSON(), nullable=False),
        sa.Column("allowed_networks", sa.JSON(), nullable=False),
        sa.Column("account_security_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_ip", sa.String(length=64), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "account_security_version > 0", name="ck_api_credential_security_version"
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_api_credential_name_nonempty"),
        sa.CheckConstraint(
            "length(display_prefix) > 0", name="ck_api_credential_prefix_nonempty"
        ),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_api_credential_token_hash"),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL)",
            name="ck_api_credential_revocation",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_api_credential_status"
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_account_id"],
            ["saas_service_accounts.tenant_id", "saas_service_accounts.id"],
            name="fk_api_credential_service_account",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("display_prefix"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_api_credential_account_status",
        "saas_api_credentials",
        ["tenant_id", "service_account_id", "status", "expires_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        _enable_rls()


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for policy, table in (
            ("rls_api_credential_update", "saas_api_credentials"),
            ("rls_api_credential_insert", "saas_api_credentials"),
            ("rls_api_credential_select", "saas_api_credentials"),
            ("rls_service_account_update", "saas_service_accounts"),
            ("rls_service_account_insert", "saas_service_accounts"),
            ("rls_service_account_select", "saas_service_accounts"),
        ):
            op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
        op.execute("ALTER TABLE saas_api_credentials DISABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE saas_service_accounts DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_api_credential_account_status", table_name="saas_api_credentials")
    op.drop_table("saas_api_credentials")
    op.drop_index("ix_service_account_steward", table_name="saas_service_accounts")
    op.drop_index("ix_service_account_scope_status", table_name="saas_service_accounts")
    op.drop_table("saas_service_accounts")
