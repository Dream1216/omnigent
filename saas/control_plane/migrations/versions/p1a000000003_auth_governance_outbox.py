"""Add password auth, outbox leases, and membership governance records."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p1a000000003"
down_revision: str | None = "p1a000000002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create authentication and high-risk membership-operation records."""

    with op.batch_alter_table("saas_auth_sessions") as batch_op:
        batch_op.add_column(sa.Column("csrf_token_hash", sa.String(64), nullable=True))
        batch_op.create_check_constraint(
            "ck_auth_session_csrf_hash",
            "csrf_token_hash IS NULL OR length(csrf_token_hash) = 64",
        )
    op.add_column(
        "saas_control_plane_outbox",
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "saas_control_plane_outbox",
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("saas_control_plane_outbox", sa.Column("claim_token", sa.Uuid(), nullable=True))
    op.add_column(
        "saas_control_plane_outbox", sa.Column("last_error", sa.String(2048), nullable=True)
    )
    op.create_index(
        "ix_outbox_dispatchable",
        "saas_control_plane_outbox",
        ["published_at", "available_at", "claimed_at"],
    )

    op.create_table(
        "saas_password_credentials",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("login_email_normalized", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("password_version", sa.Integer(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "length(login_email_normalized) > 0",
            name="ck_password_login_email_nonempty",
        ),
        sa.CheckConstraint("length(password_hash) > 0", name="ck_password_hash_nonempty"),
        sa.CheckConstraint("password_version > 0", name="ck_password_version"),
        sa.CheckConstraint("failed_attempts >= 0", name="ck_password_failed_attempts"),
        sa.ForeignKeyConstraint(("user_id",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("user_id"),
        sa.UniqueConstraint(
            "login_email_normalized", name="uq_saas_password_credentials_login_email_normalized"
        ),
    )

    op.create_table(
        "saas_ownership_transfers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=True),
        sa.Column("from_user_id", sa.Uuid(), nullable=False),
        sa.Column("to_user_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("source_version_before", sa.Integer(), nullable=False),
        sa.Column("target_version_before", sa.Integer(), nullable=False),
        sa.Column("source_version_after", sa.Integer(), nullable=False),
        sa.Column("target_version_after", sa.Integer(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('completed', 'cancelled')", name="ck_ownership_transfer_status"
        ),
        sa.CheckConstraint("from_user_id <> to_user_id", name="ck_owner_transfer_distinct_users"),
        sa.CheckConstraint("length(reason) > 0", name="ck_owner_transfer_reason_nonempty"),
        sa.CheckConstraint(
            "source_version_before > 0 AND target_version_before > 0 AND "
            "source_version_after > source_version_before AND "
            "target_version_after > target_version_before",
            name="ck_owner_transfer_versions",
        ),
        sa.ForeignKeyConstraint(("from_user_id",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(("requested_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            name="fk_ownership_transfer_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(("to_user_id",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_ownership_transfer_scope",
        "saas_ownership_transfers",
        ["tenant_id", "space_id", "created_at"],
    )

    op.create_table(
        "saas_member_removal_preflights",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("membership_version", sa.Integer(), nullable=False),
        sa.Column("impact_snapshot", sa.JSON(), nullable=False),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
        sa.Column("blocking_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('ready', 'blocked', 'executed', 'expired', 'cancelled')",
            name="ck_member_removal_preflight_status",
        ),
        sa.CheckConstraint("membership_version > 0", name="ck_removal_membership_version"),
        sa.CheckConstraint("length(snapshot_hash) = 64", name="ck_removal_snapshot_hash"),
        sa.CheckConstraint("blocking_count >= 0", name="ck_removal_blocking_count"),
        sa.ForeignKeyConstraint(("requested_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            name="fk_member_removal_preflight_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(("user_id",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_member_removal_scope",
        "saas_member_removal_preflights",
        ["tenant_id", "space_id", "user_id", "status"],
    )


def downgrade() -> None:
    """Remove authentication and high-risk membership-operation records."""

    op.drop_index("ix_member_removal_scope", table_name="saas_member_removal_preflights")
    op.drop_table("saas_member_removal_preflights")
    op.drop_index("ix_ownership_transfer_scope", table_name="saas_ownership_transfers")
    op.drop_table("saas_ownership_transfers")
    op.drop_table("saas_password_credentials")
    op.drop_index("ix_outbox_dispatchable", table_name="saas_control_plane_outbox")
    op.drop_column("saas_control_plane_outbox", "last_error")
    op.drop_column("saas_control_plane_outbox", "claim_token")
    op.drop_column("saas_control_plane_outbox", "claimed_at")
    op.drop_column("saas_control_plane_outbox", "available_at")
    with op.batch_alter_table("saas_auth_sessions") as batch_op:
        batch_op.drop_constraint("ck_auth_session_csrf_hash", type_="check")
        batch_op.drop_column("csrf_token_hash")
