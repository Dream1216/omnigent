"""Add hash-bound enterprise access preflights and two-person approvals.

Revision ID: p6a000000004
Revises: p6a000000003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p6a000000004"
down_revision: str | None = "p6a000000003"
branch_labels: str | None = None
depends_on: str | None = None


def _enable_rls() -> None:
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    predicate = f"({platform} OR tenant_id = {tenant})"
    table = "saas_enterprise_access_preflights"
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY rls_{table}_select ON {table} FOR SELECT USING ({predicate})")
    op.execute(f"CREATE POLICY rls_{table}_insert ON {table} FOR INSERT WITH CHECK ({predicate})")
    op.execute(
        f"CREATE POLICY rls_{table}_update ON {table} FOR UPDATE "
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


def upgrade() -> None:
    op.create_table(
        "saas_enterprise_access_preflights",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=True),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("operation_type", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("target_version", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("reason", sa.String(length=512), nullable=False),
        sa.Column("approval_policy", sa.String(length=32), nullable=False),
        sa.Column("impact_snapshot", sa.JSON(), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approval_reason", sa.String(length=512), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "operation_type IN ('group_archive', 'custom_role_retire')",
            name="ck_enterprise_access_preflight_operation",
        ),
        sa.CheckConstraint(
            "(operation_type = 'group_archive' AND space_id IS NULL AND project_id IS NULL) OR "
            "(operation_type = 'custom_role_retire' AND space_id IS NOT NULL AND "
            "project_id IS NOT NULL)",
            name="ck_enterprise_access_preflight_scope",
        ),
        sa.CheckConstraint(
            "status IN ('pending_approval', 'approved', 'rejected', 'executed')",
            name="ck_enterprise_access_preflight_status",
        ),
        sa.CheckConstraint(
            "approval_policy = 'different_principal'",
            name="ck_enterprise_access_preflight_policy",
        ),
        sa.CheckConstraint("target_version > 0", name="ck_enterprise_access_target_version"),
        sa.CheckConstraint("length(reason) > 0", name="ck_enterprise_access_reason_nonempty"),
        sa.CheckConstraint(
            "length(snapshot_hash) = 64", name="ck_enterprise_access_snapshot_hash"
        ),
        sa.CheckConstraint(
            "(status = 'pending_approval' AND approved_by IS NULL AND approved_at IS NULL "
            "AND approval_reason IS NULL AND executed_at IS NULL) OR "
            "(status = 'rejected' AND approved_by IS NOT NULL AND approved_at IS NOT NULL "
            "AND length(approval_reason) > 0 AND executed_at IS NULL) OR "
            "(status = 'approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL "
            "AND length(approval_reason) > 0 AND executed_at IS NULL) OR "
            "(status = 'executed' AND approved_by IS NOT NULL AND approved_at IS NOT NULL "
            "AND length(approval_reason) > 0 AND executed_at IS NOT NULL)",
            name="ck_enterprise_access_preflight_decision_state",
        ),
        sa.CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name="ck_enterprise_access_preflight_distinct_approver",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["requested_by"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id"],
            ["saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"],
            name="fk_enterprise_access_preflight_project",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_enterprise_access_preflight_scope",
        "saas_enterprise_access_preflights",
        ["tenant_id", "space_id", "project_id", "status", "expires_at"],
    )
    op.create_index(
        "ix_enterprise_access_preflight_target",
        "saas_enterprise_access_preflights",
        ["tenant_id", "operation_type", "target_id", "status"],
    )
    if op.get_bind().dialect.name == "postgresql":
        _enable_rls()


def downgrade() -> None:
    table = "saas_enterprise_access_preflights"
    if op.get_bind().dialect.name == "postgresql":
        for suffix in ("update", "insert", "select"):
            op.execute(f"DROP POLICY IF EXISTS rls_{table}_{suffix} ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_enterprise_access_preflight_target", table_name=table)
    op.drop_index("ix_enterprise_access_preflight_scope", table_name=table)
    op.drop_table(table)
