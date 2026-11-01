"""Persist identity event receipts and independent external provider state."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "cd4a00000001"
down_revision = "cd3b00000001"
branch_labels = None
depends_on = None

_TABLES = ("saas_identity_event_inbox", "saas_identity_provider_states")


def _hex64(column: str) -> str:
    """Return a SQLite/PostgreSQL portable lowercase SHA-256 check."""

    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {remainder} = ''"


def upgrade() -> None:
    op.create_table(
        "saas_identity_event_inbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("organization", sa.String(length=128), nullable=False),
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("security_event", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("subject_locator_sha256", sa.String(length=64), nullable=True),
        sa.Column("username_locator_sha256", sa.String(length=64), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), server_default="pending", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("claim_token", sa.Uuid(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("processed_connection_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.CheckConstraint(
            "(claim_token IS NULL AND lease_expires_at IS NULL AND status<>'processing') OR "
            "(claim_token IS NOT NULL AND lease_expires_at IS NOT NULL AND status='processing')",
            name="ck_identity_inbox_lease",
        ),
        sa.CheckConstraint(
            "(status IN ('completed','ignored','dead')) = (completed_at IS NOT NULL)",
            name="ck_identity_inbox_completion",
        ),
        sa.CheckConstraint(
            "action IN ('update-user','delete-user','set-password')",
            name="ck_identity_inbox_action",
        ),
        sa.CheckConstraint(_hex64("request_sha256"), name="ck_identity_inbox_request_sha256"),
        sa.CheckConstraint(
            _hex64("username_locator_sha256"), name="ck_identity_inbox_username_locator_sha256"
        ),
        sa.CheckConstraint(
            "provider='casdoor' AND length(issuer)>0 AND length(organization)>0 "
            "AND length(event_id)>0",
            name="ck_identity_inbox_source",
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','retry','completed','ignored','dead')",
            name="ck_identity_inbox_status",
        ),
        sa.CheckConstraint(
            "subject_locator_sha256 IS NULL OR (" + _hex64("subject_locator_sha256") + ")",
            name="ck_identity_inbox_subject",
        ),
        sa.CheckConstraint(
            "attempt_count>=0 AND version>0 AND processed_connection_count>=0",
            name="ck_identity_inbox_versions",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "issuer", "organization", "event_id", name="uq_identity_inbox_provider_event"
        ),
    )
    with op.batch_alter_table("saas_identity_event_inbox", schema=None) as batch_op:
        batch_op.create_index(
            "ix_identity_inbox_due", ["status", "available_at", "lease_expires_at"], unique=False
        )

    op.create_table(
        "saas_identity_provider_states",
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("subject_locator_sha256", sa.String(length=64), nullable=False),
        sa.Column("username_locator_sha256", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="active", nullable=False),
        sa.Column("snapshot_sha256", sa.String(length=64), nullable=True),
        sa.Column("password_revision_sha256", sa.String(length=64), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "next_check_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("claim_token", sa.Uuid(), nullable=True),
        sa.Column("claim_sha256", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            _hex64("subject_locator_sha256"), name="ck_identity_provider_state_subject"
        ),
        sa.CheckConstraint(
            "password_revision_sha256 IS NULL OR (" + _hex64("password_revision_sha256") + ")",
            name="ck_identity_provider_state_password_revision_sha256",
        ),
        sa.CheckConstraint(
            "snapshot_sha256 IS NULL OR (" + _hex64("snapshot_sha256") + ")",
            name="ck_identity_provider_state_snapshot_sha256",
        ),
        sa.CheckConstraint(
            "status IN ('active','disabled','deleted')", name="ck_identity_provider_state_status"
        ),
        sa.CheckConstraint(
            "username_locator_sha256 IS NULL OR (" + _hex64("username_locator_sha256") + ")",
            name="ck_identity_provider_state_username_locator_sha256",
        ),
        sa.CheckConstraint(
            "(claim_token IS NULL) = (lease_expires_at IS NULL) AND "
            "(claim_token IS NULL) = (claim_sha256 IS NULL)",
            name="ck_identity_provider_state_lease",
        ),
        sa.CheckConstraint(
            "claim_sha256 IS NULL OR (" + _hex64("claim_sha256") + ")",
            name="ck_identity_provider_state_claim_sha256",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND version > 0", name="ck_identity_provider_state_versions"
        ),
        sa.CheckConstraint(
            "checked_at IS NULL OR snapshot_sha256 IS NOT NULL",
            name="ck_identity_provider_state_snapshot",
        ),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["saas_identity_connections.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("connection_id"),
    )
    with op.batch_alter_table("saas_identity_provider_states", schema=None) as batch_op:
        batch_op.create_index(
            "ix_identity_provider_state_due", ["next_check_at", "lease_expires_at"], unique=False
        )
        batch_op.create_index(
            "ix_identity_provider_state_subject", ["subject_locator_sha256"], unique=False
        )
        batch_op.create_index(
            "ix_identity_provider_state_username", ["username_locator_sha256"], unique=False
        )

    if op.get_bind().dialect.name == "postgresql":
        for table in _TABLES:
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            authority = "pg_has_role(current_user, 'saas_authenticator', 'member')"
            op.execute(
                f"CREATE POLICY rls_identity_sync_authenticator ON {table} "
                f"FOR ALL USING ({authority}) WITH CHECK ({authority})"
            )
            owner = (
                "current_user=pg_catalog.pg_get_userbyid((SELECT relowner FROM "
                f"pg_catalog.pg_class WHERE oid='public.{table}'::regclass))"
            )
            op.execute(
                f"CREATE POLICY rls_identity_sync_owner_read ON {table} FOR SELECT USING ({owner})"
            )


def downgrade() -> None:
    for table in _TABLES:
        if op.get_bind().execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError(
                "retained identity sync evidence requires application-only rollback"
            )
    with op.batch_alter_table("saas_identity_provider_states", schema=None) as batch_op:
        batch_op.drop_index("ix_identity_provider_state_username")
        batch_op.drop_index("ix_identity_provider_state_subject")
        batch_op.drop_index("ix_identity_provider_state_due")

    op.drop_table("saas_identity_provider_states")
    with op.batch_alter_table("saas_identity_event_inbox", schema=None) as batch_op:
        batch_op.drop_index("ix_identity_inbox_due")

    op.drop_table("saas_identity_event_inbox")
