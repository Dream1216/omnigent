"""Allow authenticator access to one exact invitation token under forced RLS.

Revision ID: p6a000000007
Revises: p6a000000006
"""

from __future__ import annotations

from alembic import op

revision: str = "p6a000000007"
down_revision: str | None = "p6a000000006"
branch_labels: str | None = None
depends_on: str | None = None

_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_TOKEN_HASH = "NULLIF(current_setting('app.invitation_token_hash', true), '')"
_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_AUTHENTICATOR = "pg_has_role(current_user, 'saas_authenticator', 'member')"
_POLICY = "rls_saas_membership_invitations_tenant"
_TABLE = "saas_membership_invitations"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    predicate = (
        f"({_PLATFORM} OR tenant_id = {_TENANT} OR "
        f"({_AUTHENTICATOR} AND token_hash = {_TOKEN_HASH} AND length({_TOKEN_HASH}) = 64))"
    )
    op.execute(f'DROP POLICY "{_POLICY}" ON "{_TABLE}"')
    op.execute(
        f'CREATE POLICY "{_POLICY}" ON "{_TABLE}" '
        f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    predicate = f"({_PLATFORM} OR tenant_id = {_TENANT})"
    op.execute(f'DROP POLICY "{_POLICY}" ON "{_TABLE}"')
    op.execute(
        f'CREATE POLICY "{_POLICY}" ON "{_TABLE}" '
        f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
    )
