"""Add Staff-governed Identity Conflict review without direct identity linking.

Revision ID: pc2b00000001
Revises: p6b000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc2b00000001"
down_revision: str | None = "p6b000000001"
branch_labels: str | None = None
depends_on: str | None = None

_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_TARGET = "NULLIF(current_setting('app.platform_target_identity_conflict_id', true), '')::uuid"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _current_role(roles: str) -> str:
    return (
        f"({_GOVERNANCE} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} "
        f"AND assignment.role IN ({roles}) AND assignment.status = 'active' "
        "AND (assignment.expires_at IS NULL OR assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _alter_identity_conflicts() -> None:
    with op.batch_alter_table("saas_identity_conflicts") as batch_op:
        batch_op.add_column(
            sa.Column(
                "platform_review_status",
                sa.String(32),
                nullable=False,
                server_default="unreviewed",
            )
        )
        batch_op.add_column(sa.Column("platform_reviewed_by_principal_id", sa.Uuid()))
        batch_op.add_column(sa.Column("platform_review_approval_ref", sa.String(256)))
        batch_op.add_column(sa.Column("platform_review_reason", sa.String(1024)))
        batch_op.add_column(sa.Column("platform_reviewed_at", sa.DateTime(timezone=True)))
        batch_op.create_foreign_key(
            "fk_identity_conflict_platform_reviewer",
            "saas_platform_staff_principals",
            ["platform_reviewed_by_principal_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_check_constraint(
            "ck_identity_conflict_platform_review_status",
            "platform_review_status IN ('unreviewed', 'assigned', 'blocked')",
        )
        batch_op.create_check_constraint(
            "ck_identity_conflict_platform_review",
            "(platform_review_status = 'unreviewed' "
            "AND platform_reviewed_by_principal_id IS NULL "
            "AND platform_review_approval_ref IS NULL "
            "AND platform_review_reason IS NULL AND platform_reviewed_at IS NULL) OR "
            "(platform_review_status = 'assigned' AND candidate_user_id IS NOT NULL "
            "AND platform_reviewed_by_principal_id IS NOT NULL "
            "AND length(platform_review_approval_ref) > 0 "
            "AND length(platform_review_reason) > 0 AND platform_reviewed_at IS NOT NULL) OR "
            "(platform_review_status = 'blocked' AND candidate_user_id IS NULL "
            "AND platform_reviewed_by_principal_id IS NOT NULL "
            "AND length(platform_review_approval_ref) > 0 "
            "AND length(platform_review_reason) > 0 AND platform_reviewed_at IS NOT NULL)",
        )


def _extend_operation_contract() -> None:
    with op.batch_alter_table("saas_platform_lifecycle_operations") as batch_op:
        batch_op.drop_constraint("ck_platform_lifecycle_target_type", type_="check")
        batch_op.drop_constraint("ck_platform_lifecycle_action", type_="check")
        batch_op.drop_constraint("ck_platform_lifecycle_target_scope", type_="check")
        batch_op.create_check_constraint(
            "ck_platform_lifecycle_target_type",
            "target_type IN ('global_user', 'tenant', 'identity_conflict')",
        )
        batch_op.create_check_constraint(
            "ck_platform_lifecycle_action",
            "action IN ('user_suspend', 'user_restore', 'user_sessions_revoke', "
            "'tenant_suspend', 'tenant_restore', 'tenant_owner_recover', "
            "'identity_conflict_assign', 'identity_conflict_block')",
        )
        batch_op.create_check_constraint(
            "ck_platform_lifecycle_target_scope",
            "(target_type IN ('global_user', 'identity_conflict') AND tenant_id IS NULL) OR "
            "(target_type = 'tenant' AND tenant_id = target_id)",
        )


def upgrade() -> None:
    _alter_identity_conflicts()
    _extend_operation_contract()
    if op.get_bind().dialect.name != "postgresql":
        return
    reader = _current_role("'platform_operator', 'platform_security_auditor'")
    operator = _current_role("'platform_operator'")
    op.execute(
        'CREATE POLICY "rls_identity_conflicts_platform_read" ON saas_identity_conflicts '
        f"FOR SELECT USING ({_EMERGENCY} OR {reader})"
    )
    op.execute(
        'CREATE POLICY "rls_identity_conflicts_platform_review" ON saas_identity_conflicts '
        f"FOR UPDATE USING ({_EMERGENCY} OR ({operator} AND id = {_TARGET})) "
        f"WITH CHECK ({_EMERGENCY} OR ({operator} AND id = {_TARGET}))"
    )


def _require_no_pc2_review_facts() -> None:
    """Refuse a downgrade that would erase Staff review decisions or audit receipts."""
    bind = op.get_bind()
    reviewed = bind.execute(
        sa.text(
            "SELECT count(*) FROM saas_identity_conflicts "
            "WHERE platform_review_status <> 'unreviewed'"
        )
    ).scalar_one()
    operations = bind.execute(
        sa.text(
            "SELECT count(*) FROM saas_platform_lifecycle_operations "
            "WHERE target_type = 'identity_conflict' "
            "OR action IN ('identity_conflict_assign', 'identity_conflict_block')"
        )
    ).scalar_one()
    if reviewed or operations:
        raise RuntimeError(
            "pc2b00000001 downgrade refused: identity conflict review facts or audit "
            "receipts exist; retain this revision or perform an explicitly approved "
            "forward-compatible archival migration"
        )


def downgrade() -> None:
    _require_no_pc2_review_facts()
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            'DROP POLICY IF EXISTS "rls_identity_conflicts_platform_review" '
            "ON saas_identity_conflicts"
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_identity_conflicts_platform_read" '
            "ON saas_identity_conflicts"
        )
    with op.batch_alter_table("saas_platform_lifecycle_operations") as batch_op:
        batch_op.drop_constraint("ck_platform_lifecycle_target_type", type_="check")
        batch_op.drop_constraint("ck_platform_lifecycle_action", type_="check")
        batch_op.drop_constraint("ck_platform_lifecycle_target_scope", type_="check")
        batch_op.create_check_constraint(
            "ck_platform_lifecycle_target_type", "target_type IN ('global_user', 'tenant')"
        )
        batch_op.create_check_constraint(
            "ck_platform_lifecycle_action",
            "action IN ('user_suspend', 'user_restore', 'user_sessions_revoke', "
            "'tenant_suspend', 'tenant_restore', 'tenant_owner_recover')",
        )
        batch_op.create_check_constraint(
            "ck_platform_lifecycle_target_scope",
            "(target_type = 'global_user' AND tenant_id IS NULL) OR "
            "(target_type = 'tenant' AND tenant_id = target_id)",
        )
    with op.batch_alter_table("saas_identity_conflicts") as batch_op:
        batch_op.drop_constraint("ck_identity_conflict_platform_review", type_="check")
        batch_op.drop_constraint("ck_identity_conflict_platform_review_status", type_="check")
        batch_op.drop_constraint("fk_identity_conflict_platform_reviewer", type_="foreignkey")
        batch_op.drop_column("platform_reviewed_at")
        batch_op.drop_column("platform_review_reason")
        batch_op.drop_column("platform_review_approval_ref")
        batch_op.drop_column("platform_reviewed_by_principal_id")
        batch_op.drop_column("platform_review_status")
