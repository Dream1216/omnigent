"""Persist revocable interactive development-preview handoffs.

Revision ID: dp1a00000001
Revises: lm2t00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "dp1a00000001"
down_revision = "lm2t00000001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saas_development_preview_grants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("actor_id", sa.Uuid(), sa.ForeignKey("saas_global_users.id"), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("saas_tenants.id"), nullable=False),
        sa.Column("space_id", sa.Uuid(), sa.ForeignKey("saas_spaces.id"), nullable=False),
        sa.Column("context_json", sa.Text(), nullable=False),
        sa.Column("launch_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("session_hash", sa.String(64), unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(launch_hash) = 64", name="ck_dev_preview_launch_hash"),
        sa.CheckConstraint(
            "session_hash IS NULL OR length(session_hash) = 64", name="ck_dev_preview_session_hash"
        ),
        sa.CheckConstraint(
            "(session_hash IS NULL) = (redeemed_at IS NULL)", name="ck_dev_preview_redemption"
        ),
        sa.CheckConstraint(
            "length(context_json) BETWEEN 1 AND 4096", name="ck_dev_preview_context_bound"
        ),
    )
    op.create_index(
        "ix_dev_preview_actor_expiry",
        "saas_development_preview_grants",
        ["actor_id", "expires_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE saas_development_preview_grants ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE saas_development_preview_grants FORCE ROW LEVEL SECURITY")
        scope = " AND ".join(
            f"{column} = NULLIF(current_setting('app.{setting}', true), '')::uuid"
            for column, setting in (
                ("actor_id", "actor_id"),
                ("tenant_id", "tenant_id"),
                ("space_id", "space_id"),
            )
        )
        op.execute(
            f"CREATE POLICY rls_development_preview_scope ON saas_development_preview_grants "
            f"USING ({scope}) WITH CHECK ({scope})"
        )
        op.execute("GRANT SELECT, INSERT ON saas_development_preview_grants TO saas_app")
        op.execute(
            "GRANT UPDATE (session_hash, redeemed_at, revoked_at) "
            "ON saas_development_preview_grants TO saas_app"
        )


def downgrade() -> None:
    if (
        op.get_bind().scalar(sa.text("SELECT 1 FROM saas_development_preview_grants LIMIT 1"))
        is not None
    ):
        raise RuntimeError("Development preview access history must be retained")
    op.drop_table("saas_development_preview_grants")
