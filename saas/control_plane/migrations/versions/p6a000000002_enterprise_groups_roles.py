"""Create Tenant groups and project-scoped custom roles.

Revision ID: p6a000000002
Revises: p6a000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p6a000000002"
down_revision: str | None = "p6a000000001"
branch_labels: str | None = None
depends_on: str | None = None


def _enable_rls() -> None:
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    space = "NULLIF(current_setting('app.space_id', true), '')::uuid"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    tenant_scope = f"({platform} OR tenant_id = {tenant})"
    project_scope = f"({platform} OR (tenant_id = {tenant} AND space_id = {space}))"
    predicates = {
        "saas_enterprise_groups": tenant_scope,
        "saas_enterprise_group_memberships": tenant_scope,
        "saas_enterprise_custom_roles": project_scope,
        "saas_enterprise_group_role_assignments": project_scope,
    }
    for table, predicate in predicates.items():
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY rls_{table}_select ON {table} FOR SELECT USING ({predicate})")
        op.execute(
            f"CREATE POLICY rls_{table}_insert ON {table} FOR INSERT WITH CHECK ({predicate})"
        )
        op.execute(
            f"CREATE POLICY rls_{table}_update ON {table} FOR UPDATE "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def upgrade() -> None:
    op.create_table(
        "saas_enterprise_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_enterprise_group_name_nonempty"),
        sa.CheckConstraint("status IN ('active', 'archived')", name="ck_enterprise_group_status"),
        sa.CheckConstraint("version > 0", name="ck_enterprise_group_version"),
        sa.ForeignKeyConstraint(["created_by"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_enterprise_group_tenant_id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_enterprise_group_tenant_name"),
    )
    op.create_index(
        "ix_enterprise_group_scope_status",
        "saas_enterprise_groups",
        ["tenant_id", "status", "name"],
    )
    op.create_table(
        "saas_enterprise_group_memberships",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('active', 'removed')", name="ck_enterprise_group_membership_status"
        ),
        sa.CheckConstraint("version > 0", name="ck_enterprise_group_membership_version"),
        sa.ForeignKeyConstraint(["created_by"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "group_id"],
            ["saas_enterprise_groups.tenant_id", "saas_enterprise_groups.id"],
            name="fk_enterprise_group_membership_group",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_enterprise_group_membership_tenant_member",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("group_id", "user_id"),
    )
    op.create_index(
        "ix_enterprise_group_membership_user",
        "saas_enterprise_group_memberships",
        ["tenant_id", "user_id", "status", "expires_at"],
    )
    op.create_table(
        "saas_enterprise_custom_roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_enterprise_custom_role_name_nonempty"),
        sa.CheckConstraint(
            "status IN ('active', 'retired')", name="ck_enterprise_custom_role_status"
        ),
        sa.CheckConstraint("version > 0", name="ck_enterprise_custom_role_version"),
        sa.ForeignKeyConstraint(["created_by"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id"],
            ["saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"],
            name="fk_enterprise_custom_role_project",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "id",
            name="uq_enterprise_custom_role_scope_id",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "name",
            name="uq_enterprise_custom_role_scope_name",
        ),
    )
    op.create_index(
        "ix_enterprise_custom_role_scope_status",
        "saas_enterprise_custom_roles",
        ["tenant_id", "space_id", "project_id", "status", "name"],
    )
    op.create_table(
        "saas_enterprise_group_role_assignments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("custom_role_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')",
            name="ck_enterprise_group_role_assignment_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_enterprise_group_role_assignment_version"),
        sa.ForeignKeyConstraint(["created_by"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "group_id"],
            ["saas_enterprise_groups.tenant_id", "saas_enterprise_groups.id"],
            name="fk_enterprise_group_role_assignment_group",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id", "custom_role_id"],
            [
                "saas_enterprise_custom_roles.tenant_id",
                "saas_enterprise_custom_roles.space_id",
                "saas_enterprise_custom_roles.project_id",
                "saas_enterprise_custom_roles.id",
            ],
            name="fk_enterprise_group_role_assignment_role",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "group_id",
            "custom_role_id",
            name="uq_enterprise_group_role_assignment",
        ),
    )
    op.create_index(
        "ix_enterprise_group_role_assignment_scope",
        "saas_enterprise_group_role_assignments",
        ["tenant_id", "space_id", "project_id", "status", "expires_at"],
    )
    op.create_index(
        "ix_enterprise_group_role_assignment_group",
        "saas_enterprise_group_role_assignments",
        ["tenant_id", "group_id", "status", "expires_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        _enable_rls()


def downgrade() -> None:
    tables = (
        "saas_enterprise_group_role_assignments",
        "saas_enterprise_custom_roles",
        "saas_enterprise_group_memberships",
        "saas_enterprise_groups",
    )
    if op.get_bind().dialect.name == "postgresql":
        for table in tables:
            for suffix in ("update", "insert", "select"):
                op.execute(f"DROP POLICY IF EXISTS rls_{table}_{suffix} ON {table}")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_index(
        "ix_enterprise_group_role_assignment_group",
        table_name="saas_enterprise_group_role_assignments",
    )
    op.drop_index(
        "ix_enterprise_group_role_assignment_scope",
        table_name="saas_enterprise_group_role_assignments",
    )
    op.drop_table("saas_enterprise_group_role_assignments")
    op.drop_index(
        "ix_enterprise_custom_role_scope_status", table_name="saas_enterprise_custom_roles"
    )
    op.drop_table("saas_enterprise_custom_roles")
    op.drop_index(
        "ix_enterprise_group_membership_user",
        table_name="saas_enterprise_group_memberships",
    )
    op.drop_table("saas_enterprise_group_memberships")
    op.drop_index("ix_enterprise_group_scope_status", table_name="saas_enterprise_groups")
    op.drop_table("saas_enterprise_groups")
