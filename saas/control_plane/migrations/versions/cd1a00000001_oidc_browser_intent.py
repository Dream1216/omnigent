"""Persist OIDC signup intent and the validated browser completion target."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "cd1a00000001"
down_revision = "lm2t00000001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("saas_oidc_login_transactions") as batch:
        batch.add_column(
            sa.Column("return_to", sa.String(2048), nullable=False, server_default="/")
        )
        batch.add_column(
            sa.Column("ui_locale", sa.String(16), nullable=False, server_default="zh-CN")
        )
        batch.drop_constraint("ck_oidc_login_transaction_purpose", type_="check")
        batch.drop_constraint("ck_oidc_login_target_by_purpose", type_="check")
        batch.create_check_constraint(
            "ck_oidc_login_transaction_purpose", "purpose IN ('login', 'signup', 'link')"
        )
        batch.create_check_constraint(
            "ck_oidc_login_target_by_purpose",
            "(purpose IN ('login', 'signup') AND target_user_id IS NULL "
            "AND target_security_version IS NULL) OR "
            "(purpose = 'link' AND target_user_id IS NOT NULL AND target_security_version > 0)",
        )


def downgrade() -> None:
    table = sa.table("saas_oidc_login_transactions", sa.column("id"))
    if op.get_bind().execute(sa.select(table.c.id).limit(1)).first() is not None:
        raise RuntimeError("retained OIDC transactions require application-only rollback")
    with op.batch_alter_table("saas_oidc_login_transactions") as batch:
        batch.drop_constraint("ck_oidc_login_transaction_purpose", type_="check")
        batch.drop_constraint("ck_oidc_login_target_by_purpose", type_="check")
        batch.create_check_constraint(
            "ck_oidc_login_transaction_purpose", "purpose IN ('login', 'link')"
        )
        batch.create_check_constraint(
            "ck_oidc_login_target_by_purpose",
            "(purpose = 'login' AND target_user_id IS NULL "
            "AND target_security_version IS NULL) OR "
            "(purpose = 'link' AND target_user_id IS NOT NULL AND target_security_version > 0)",
        )
        batch.drop_column("ui_locale")
        batch.drop_column("return_to")
