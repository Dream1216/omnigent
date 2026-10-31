"""Persist explicit reauthentication and the local session authorizing a link."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "cd1c00000001"
down_revision = "cd1b00000001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("saas_oidc_login_transactions") as batch:
        batch.add_column(sa.Column("target_session_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            "fk_oidc_target_session",
            "saas_auth_sessions",
            ["target_session_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.drop_constraint("ck_oidc_login_transaction_purpose", type_="check")
        batch.drop_constraint("ck_oidc_login_target_by_purpose", type_="check")
        batch.create_check_constraint(
            "ck_oidc_login_transaction_purpose", "purpose IN ('login', 'signup', 'link', 'reauth')"
        )
        batch.create_check_constraint(
            "ck_oidc_login_target_by_purpose",
            "(purpose IN ('login', 'signup') AND target_user_id IS NULL "
            "AND target_security_version IS NULL AND target_session_id IS NULL) OR "
            "(purpose = 'link' AND target_user_id IS NOT NULL AND target_security_version > 0) OR "
            "(purpose = 'reauth' AND ((target_user_id IS NULL "
            "AND target_security_version IS NULL AND target_session_id IS NULL) OR "
            "(target_user_id IS NOT NULL AND target_security_version > 0 "
            "AND target_session_id IS NOT NULL)))",
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "CREATE POLICY rls_oidc_transaction_migration_read "
            "ON saas_oidc_login_transactions FOR SELECT USING "
            "(current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
            "WHERE oid = 'public.saas_oidc_login_transactions'::regclass)))"
        )


def downgrade() -> None:
    table = sa.table("saas_oidc_login_transactions", sa.column("id"))
    if op.get_bind().execute(sa.select(table.c.id).limit(1)).first() is not None:
        raise RuntimeError("retained OIDC transactions require application-only rollback")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP POLICY rls_oidc_transaction_migration_read ON saas_oidc_login_transactions"
        )
    with op.batch_alter_table("saas_oidc_login_transactions") as batch:
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
        batch.drop_constraint("fk_oidc_target_session", type_="foreignkey")
        batch.drop_column("target_session_id")
