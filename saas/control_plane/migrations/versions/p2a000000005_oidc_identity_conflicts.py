"""Add replica-safe OIDC transactions and explicit identity conflicts."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p2a000000005"
down_revision: str | None = "p2a000000004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_AUTHENTICATOR = (
    "(pg_has_role(current_user, 'saas_authenticator', 'member') "
    "OR pg_has_role(current_user, 'saas_governance', 'member') "
    "OR pg_has_role(current_user, 'saas_platform', 'member'))"
)


def upgrade() -> None:
    """Create one-time OIDC state and explicit same-email conflict records."""

    op.create_table(
        "saas_oidc_login_transactions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("browser_binding_hash", sa.String(64), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("code_verifier_ciphertext", sa.String(1024), nullable=False),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("target_user_id", sa.Uuid(), nullable=True),
        sa.Column("target_security_version", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'consumed', 'failed')",
            name="ck_oidc_login_transaction_status",
        ),
        sa.CheckConstraint(
            "purpose IN ('login', 'link')", name="ck_oidc_login_transaction_purpose"
        ),
        sa.CheckConstraint("length(provider) > 0", name="ck_oidc_login_provider_nonempty"),
        sa.CheckConstraint("length(state_hash) = 64", name="ck_oidc_login_state_hash"),
        sa.CheckConstraint(
            "length(browser_binding_hash) = 64",
            name="ck_oidc_login_browser_binding_hash",
        ),
        sa.CheckConstraint("length(nonce_hash) = 64", name="ck_oidc_login_nonce_hash"),
        sa.CheckConstraint(
            "length(code_verifier_ciphertext) > 0",
            name="ck_oidc_login_verifier_nonempty",
        ),
        sa.CheckConstraint(
            "(purpose = 'login' AND target_user_id IS NULL "
            "AND target_security_version IS NULL) OR "
            "(purpose = 'link' AND target_user_id IS NOT NULL "
            "AND target_security_version > 0)",
            name="ck_oidc_login_target_by_purpose",
        ),
        sa.ForeignKeyConstraint(
            ("target_user_id",), ("saas_global_users.id",), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("state_hash"),
    )
    op.create_index(
        "ix_oidc_login_expiry",
        "saas_oidc_login_transactions",
        ["status", "expires_at"],
    )

    op.create_table(
        "saas_identity_conflicts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("email_normalized", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("candidate_user_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("resolved_by", sa.Uuid(), nullable=True),
        sa.Column("resolution_reason", sa.String(1024), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected')",
            name="ck_identity_conflict_status",
        ),
        sa.CheckConstraint("length(provider) > 0", name="ck_identity_conflict_provider"),
        sa.CheckConstraint("length(issuer) > 0", name="ck_identity_conflict_issuer"),
        sa.CheckConstraint("length(subject) > 0", name="ck_identity_conflict_subject"),
        sa.CheckConstraint("length(email_normalized) > 0", name="ck_identity_conflict_email"),
        sa.CheckConstraint("version > 0", name="ck_identity_conflict_version"),
        sa.CheckConstraint(
            "(status = 'pending' AND resolved_by IS NULL AND resolved_at IS NULL "
            "AND resolution_reason IS NULL) OR "
            "(status IN ('approved', 'rejected') AND resolved_by IS NOT NULL "
            "AND resolved_at IS NOT NULL AND length(resolution_reason) > 0)",
            name="ck_identity_conflict_resolution",
        ),
        sa.ForeignKeyConstraint(
            ("candidate_user_id",), ("saas_global_users.id",), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(("resolved_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_identity_conflict_issuer_subject"),
    )
    op.create_index(
        "ix_identity_conflict_candidate",
        "saas_identity_conflicts",
        ["candidate_user_id", "status"],
    )

    if op.get_bind().dialect.name == "postgresql":
        for table in ("saas_oidc_login_transactions", "saas_identity_conflicts"):
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(
                f'CREATE POLICY "rls_{table}_authenticator" ON "{table}" '
                f"FOR ALL USING ({_AUTHENTICATOR}) WITH CHECK ({_AUTHENTICATOR})"
            )


def downgrade() -> None:
    """Remove OIDC transaction and identity-conflict records."""

    if op.get_bind().dialect.name == "postgresql":
        for table in ("saas_identity_conflicts", "saas_oidc_login_transactions"):
            op.execute(f'DROP POLICY IF EXISTS "rls_{table}_authenticator" ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    op.drop_index("ix_identity_conflict_candidate", table_name="saas_identity_conflicts")
    op.drop_table("saas_identity_conflicts")
    op.drop_index("ix_oidc_login_expiry", table_name="saas_oidc_login_transactions")
    op.drop_table("saas_oidc_login_transactions")
