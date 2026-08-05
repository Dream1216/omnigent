"""Add auditable enterprise group and custom-role lifecycle state.

Revision ID: p6a000000003
Revises: p6a000000002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p6a000000003"
down_revision: str | None = "p6a000000002"
branch_labels: str | None = None
depends_on: str | None = None


def _set_force_rls(table: str, *, enabled: bool) -> None:
    if op.get_bind().dialect.name == "postgresql":
        posture = "FORCE" if enabled else "NO FORCE"
        op.execute(f"ALTER TABLE {table} {posture} ROW LEVEL SECURITY")


def upgrade() -> None:
    # The preceding revision already uses FORCE RLS. Alembic must be the table
    # owner to alter these tables; temporarily exempt only that owner while the
    # same transactional DDL lock protects the legacy-state backfill. RLS stays
    # enabled for every non-owner and a failed migration restores FORCE on rollback.
    _set_force_rls("saas_enterprise_groups", enabled=False)
    with op.batch_alter_table("saas_enterprise_groups") as batch_op:
        batch_op.add_column(sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("archived_by", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("archive_reason", sa.String(512), nullable=True))
        batch_op.create_foreign_key(
            "fk_enterprise_group_archived_by",
            "saas_global_users",
            ["archived_by"],
            ["id"],
            ondelete="RESTRICT",
        )

    op.execute(
        sa.text(
            "UPDATE saas_enterprise_groups "
            "SET archived_at = updated_at, archived_by = created_by, "
            "archive_reason = 'legacy-state-backfill:p6a000000003' "
            "WHERE status = 'archived'"
        )
    )

    with op.batch_alter_table("saas_enterprise_groups") as batch_op:
        batch_op.create_check_constraint(
            "ck_enterprise_group_archive_state",
            "(status = 'active' AND archived_at IS NULL AND archived_by IS NULL AND "
            "archive_reason IS NULL) OR "
            "(status = 'archived' AND archived_at IS NOT NULL AND archived_by IS NOT NULL "
            "AND length(archive_reason) > 0)",
        )
    _set_force_rls("saas_enterprise_groups", enabled=True)

    _set_force_rls("saas_enterprise_custom_roles", enabled=False)
    with op.batch_alter_table("saas_enterprise_custom_roles") as batch_op:
        batch_op.add_column(sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("retired_by", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("retire_reason", sa.String(512), nullable=True))
        batch_op.create_foreign_key(
            "fk_enterprise_custom_role_retired_by",
            "saas_global_users",
            ["retired_by"],
            ["id"],
            ondelete="RESTRICT",
        )

    op.execute(
        sa.text(
            "UPDATE saas_enterprise_custom_roles "
            "SET retired_at = updated_at, retired_by = created_by, "
            "retire_reason = 'legacy-state-backfill:p6a000000003' "
            "WHERE status = 'retired'"
        )
    )

    with op.batch_alter_table("saas_enterprise_custom_roles") as batch_op:
        batch_op.create_check_constraint(
            "ck_enterprise_custom_role_retire_state",
            "(status = 'active' AND retired_at IS NULL AND retired_by IS NULL AND "
            "retire_reason IS NULL) OR "
            "(status = 'retired' AND retired_at IS NOT NULL AND retired_by IS NOT NULL "
            "AND length(retire_reason) > 0)",
        )
    _set_force_rls("saas_enterprise_custom_roles", enabled=True)


def downgrade() -> None:
    with op.batch_alter_table("saas_enterprise_custom_roles") as batch_op:
        batch_op.drop_constraint(
            "ck_enterprise_custom_role_retire_state", type_="check"
        )
        batch_op.drop_constraint(
            "fk_enterprise_custom_role_retired_by", type_="foreignkey"
        )
        batch_op.drop_column("retire_reason")
        batch_op.drop_column("retired_by")
        batch_op.drop_column("retired_at")

    with op.batch_alter_table("saas_enterprise_groups") as batch_op:
        batch_op.drop_constraint("ck_enterprise_group_archive_state", type_="check")
        batch_op.drop_constraint("fk_enterprise_group_archived_by", type_="foreignkey")
        batch_op.drop_column("archive_reason")
        batch_op.drop_column("archived_by")
        batch_op.drop_column("archived_at")
