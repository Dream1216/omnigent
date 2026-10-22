"""Add bounded scheduled and overlapping SCIM Directory credentials.

Revision ID: pc5a00000003
Revises: pc5a00000002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc5a00000003"
down_revision: str | None = "pc5a00000002"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "saas_enterprise_scim_directories"


def _replace_postgresql_select_policy(*, overlap: bool) -> None:
    token = "NULLIF(current_setting('app.scim_token_hash', true), '')"
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    tenant_scope = f"({platform} OR tenant_id = {tenant})"
    token_scope = f"token_hash = {token}"
    if overlap:
        token_scope = f"({token_scope} OR successor_token_hash = {token})"
    op.execute(f"DROP POLICY rls_{_TABLE}_select ON {_TABLE}")
    op.execute(
        f"CREATE POLICY rls_{_TABLE}_select ON {_TABLE} FOR SELECT "
        f"USING ({tenant_scope} OR {token_scope})"
    )


def upgrade() -> None:
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(sa.Column("successor_token_hash", sa.String(64)))
        batch.add_column(sa.Column("successor_token_prefix", sa.String(24)))
        batch.add_column(sa.Column("rotation_activates_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("rotation_grace_expires_at", sa.DateTime(timezone=True)))
        batch.create_unique_constraint(
            "uq_scim_directory_successor_hash",
            ["successor_token_hash"],
        )
        batch.create_check_constraint(
            "ck_scim_directory_successor_hash",
            "successor_token_hash IS NULL OR length(successor_token_hash) = 64",
        )
        batch.create_check_constraint(
            "ck_scim_directory_successor_prefix",
            "successor_token_prefix IS NULL OR length(successor_token_prefix) > 0",
        )
        batch.create_check_constraint(
            "ck_scim_directory_rotation_state",
            "(successor_token_hash IS NULL AND successor_token_prefix IS NULL "
            "AND rotation_activates_at IS NULL AND rotation_grace_expires_at IS NULL) OR "
            "(successor_token_hash IS NOT NULL AND successor_token_prefix IS NOT NULL "
            "AND rotation_activates_at IS NOT NULL AND rotation_grace_expires_at IS NOT NULL "
            "AND rotation_activates_at < rotation_grace_expires_at)",
        )
    if op.get_bind().dialect.name == "postgresql":
        _replace_postgresql_select_policy(overlap=True)
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_app') "
            "THEN EXECUTE 'GRANT SELECT (successor_token_prefix, rotation_activates_at, "
            "rotation_grace_expires_at) ON saas_enterprise_scim_directories TO saas_app'; "
            "END IF; END $$"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM saas_enterprise_scim_directories "
            "WHERE successor_token_hash IS NOT NULL LIMIT 1) THEN RAISE EXCEPTION "
            "'cannot downgrade with an active SCIM credential overlap'; END IF; END $$"
        )
        _replace_postgresql_select_policy(overlap=False)
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_constraint("ck_scim_directory_rotation_state", type_="check")
        batch.drop_constraint("ck_scim_directory_successor_prefix", type_="check")
        batch.drop_constraint("ck_scim_directory_successor_hash", type_="check")
        batch.drop_constraint("uq_scim_directory_successor_hash", type_="unique")
        batch.drop_column("rotation_grace_expires_at")
        batch.drop_column("rotation_activates_at")
        batch.drop_column("successor_token_prefix")
        batch.drop_column("successor_token_hash")
