"""Add identity connections, revocable sessions, invitations, and outbox."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p1a000000002"
down_revision: str | None = "p1a000000001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def upgrade() -> None:
    """Create the P1 identity and membership-lifecycle schema."""

    op.add_column("saas_global_users", sa.Column("display_name", sa.String(256), nullable=True))
    op.add_column(
        "saas_global_users",
        sa.Column("primary_email_normalized", sa.String(320), nullable=True),
    )

    op.create_table(
        "saas_identity_connections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("email_normalized", sa.String(320), nullable=True),
        sa.Column("email_verified", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_identity_connection_status"
        ),
        sa.CheckConstraint("length(provider) > 0", name="ck_identity_provider_nonempty"),
        sa.CheckConstraint("length(issuer) > 0", name="ck_identity_issuer_nonempty"),
        sa.CheckConstraint("length(subject) > 0", name="ck_identity_subject_nonempty"),
        sa.ForeignKeyConstraint(("user_id",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),
    )
    op.create_index("ix_identity_user_status", "saas_identity_connections", ["user_id", "status"])
    op.create_index(
        "ix_identity_verified_email",
        "saas_identity_connections",
        ["email_normalized", "email_verified"],
    )

    op.create_table(
        "saas_auth_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.Column("authn_method", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_auth_session_token_hash"),
        sa.CheckConstraint("security_version > 0", name="ck_auth_session_security_version"),
        sa.CheckConstraint("length(authn_method) > 0", name="ck_auth_session_method_nonempty"),
        sa.ForeignKeyConstraint(("user_id",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_auth_session_user_active",
        "saas_auth_sessions",
        ["user_id", "revoked_at", "expires_at"],
    )

    op.create_table(
        "saas_membership_invitations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=True),
        sa.Column("email_normalized", sa.String(320), nullable=False),
        sa.Column("tenant_role", sa.String(32), nullable=False),
        sa.Column("space_role", sa.String(32), nullable=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_by", sa.Uuid(), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('pending', 'accepted', 'revoked', 'expired')",
            name="ck_invitation_status",
        ),
        sa.CheckConstraint(
            "tenant_role IN ('owner', 'admin', 'member')",
            name="ck_invitation_tenant_role",
        ),
        sa.CheckConstraint(
            "space_role IS NULL OR space_role IN ('owner', 'admin', 'operator', 'member')",
            name="ck_invitation_space_role",
        ),
        sa.CheckConstraint(
            "(space_id IS NULL AND space_role IS NULL) OR "
            "(space_id IS NOT NULL AND space_role IS NOT NULL)",
            name="ck_invitation_space_role_pair",
        ),
        sa.CheckConstraint("length(email_normalized) > 0", name="ck_invitation_email_nonempty"),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_invitation_token_hash"),
        sa.CheckConstraint("version > 0", name="ck_invitation_version"),
        sa.ForeignKeyConstraint(("accepted_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            name="fk_invitation_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_invitation_scope_email_status",
        "saas_membership_invitations",
        ["tenant_id", "space_id", "email_normalized", "status"],
    )

    op.create_table(
        "saas_control_plane_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=True),
        sa.Column("aggregate_type", sa.String(64), nullable=False),
        sa.Column("aggregate_key", sa.String(256), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("length(aggregate_type) > 0", name="ck_outbox_aggregate_nonempty"),
        sa.CheckConstraint("length(aggregate_key) > 0", name="ck_outbox_key_nonempty"),
        sa.CheckConstraint("length(event_type) > 0", name="ck_outbox_event_nonempty"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_outbox_idempotency_nonempty"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_outbox_request_hash"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_outbox_attempt_count"),
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_index(
        "ix_outbox_tenant_event",
        "saas_control_plane_outbox",
        ["tenant_id", "event_type", "created_at"],
    )
    op.create_index(
        "ix_outbox_unpublished",
        "saas_control_plane_outbox",
        ["published_at", "created_at"],
    )


def downgrade() -> None:
    """Remove P1 identity and membership-lifecycle tables."""

    op.drop_index("ix_outbox_unpublished", table_name="saas_control_plane_outbox")
    op.drop_index("ix_outbox_tenant_event", table_name="saas_control_plane_outbox")
    op.drop_table("saas_control_plane_outbox")
    op.drop_index("ix_invitation_scope_email_status", table_name="saas_membership_invitations")
    op.drop_table("saas_membership_invitations")
    op.drop_index("ix_auth_session_user_active", table_name="saas_auth_sessions")
    op.drop_table("saas_auth_sessions")
    op.drop_index("ix_identity_verified_email", table_name="saas_identity_connections")
    op.drop_index("ix_identity_user_status", table_name="saas_identity_connections")
    op.drop_table("saas_identity_connections")
    op.drop_column("saas_global_users", "primary_email_normalized")
    op.drop_column("saas_global_users", "display_name")
