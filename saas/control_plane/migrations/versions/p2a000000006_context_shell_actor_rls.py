"""Allow Context Shell to enumerate only the current actor's active scopes."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "p2a000000006"
down_revision: str | None = "p2a000000005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTOR = "NULLIF(current_setting('app.actor_id', true), '')::uuid"


def upgrade() -> None:
    """Add SELECT-only actor policies without broadening any mutation policy."""

    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        'CREATE POLICY "rls_tenant_memberships_actor_select" '
        'ON "saas_tenant_memberships" FOR SELECT '
        f"USING (user_id = {_ACTOR})"
    )
    op.execute(
        'CREATE POLICY "rls_space_memberships_actor_select" '
        'ON "saas_space_memberships" FOR SELECT '
        f"USING (user_id = {_ACTOR})"
    )
    op.execute(
        'CREATE POLICY "rls_tenants_actor_select" ON "saas_tenants" FOR SELECT USING ('
        "EXISTS (SELECT 1 FROM saas_tenant_memberships actor_membership "
        "WHERE actor_membership.tenant_id = saas_tenants.id "
        f"AND actor_membership.user_id = {_ACTOR} "
        "AND actor_membership.status = 'active'))"
    )
    op.execute(
        'CREATE POLICY "rls_spaces_actor_select" ON "saas_spaces" FOR SELECT USING ('
        "EXISTS (SELECT 1 FROM saas_space_memberships actor_space_membership "
        "JOIN saas_tenant_memberships actor_tenant_membership "
        "ON actor_tenant_membership.tenant_id = actor_space_membership.tenant_id "
        "AND actor_tenant_membership.user_id = actor_space_membership.user_id "
        "WHERE actor_space_membership.tenant_id = saas_spaces.tenant_id "
        "AND actor_space_membership.space_id = saas_spaces.id "
        f"AND actor_space_membership.user_id = {_ACTOR} "
        "AND actor_space_membership.status = 'active' "
        "AND actor_tenant_membership.status = 'active'))"
    )


def downgrade() -> None:
    """Remove only the Context Shell actor-enumeration policies."""

    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute('DROP POLICY IF EXISTS "rls_spaces_actor_select" ON "saas_spaces"')
    op.execute('DROP POLICY IF EXISTS "rls_tenants_actor_select" ON "saas_tenants"')
    op.execute(
        'DROP POLICY IF EXISTS "rls_space_memberships_actor_select" ON "saas_space_memberships"'
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_tenant_memberships_actor_select" ON "saas_tenant_memberships"'
    )
