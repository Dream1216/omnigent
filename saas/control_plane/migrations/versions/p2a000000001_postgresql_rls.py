"""Enable PostgreSQL row-level isolation for SaaS control-plane facts."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "p2a000000001"
down_revision: str | None = "p1a000000003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTOR = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_AUTHENTICATOR = (
    "(pg_has_role(current_user, 'saas_authenticator', 'member') "
    "OR pg_has_role(current_user, 'saas_governance', 'member') "
    f"OR {_PLATFORM})"
)
_DISPATCHER = f"(pg_has_role(current_user, 'saas_dispatcher', 'member') OR {_PLATFORM})"

_TENANT_TABLES = {
    "saas_tenants": "id",
    "saas_spaces": "tenant_id",
    "saas_tenant_memberships": "tenant_id",
    "saas_space_memberships": "tenant_id",
    "saas_runtime_partitions": "tenant_id",
    "saas_runtime_resource_bindings": "tenant_id",
    "saas_membership_invitations": "tenant_id",
    "saas_ownership_transfers": "tenant_id",
    "saas_member_removal_preflights": "tenant_id",
}

_USER_TABLES = {
    "saas_global_users": "id",
    "saas_identity_connections": "user_id",
    "saas_auth_sessions": "user_id",
    "saas_password_credentials": "user_id",
}


def _enable(table: str) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')


def _disable(table: str) -> None:
    op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


def upgrade() -> None:
    """Install fail-closed PostgreSQL policies; SQLite remains unaffected."""

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    for table, tenant_column in _TENANT_TABLES.items():
        _enable(table)
        predicate = f"({_PLATFORM} OR {tenant_column} = {_TENANT})"
        op.execute(
            f'CREATE POLICY "rls_{table}_tenant" ON "{table}" '
            f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
        )

    for table, user_column in _USER_TABLES.items():
        _enable(table)
        predicate = f"({_AUTHENTICATOR} OR {user_column} = {_ACTOR})"
        op.execute(
            f'CREATE POLICY "rls_{table}_actor" ON "{table}" '
            f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
        )

    _enable("saas_runtime_placements")
    placement_predicate = (
        f"({_PLATFORM} OR EXISTS ("
        "SELECT 1 FROM saas_runtime_partitions partition_scope "
        "WHERE partition_scope.placement_id = saas_runtime_placements.id "
        f"AND partition_scope.tenant_id = {_TENANT}))"
    )
    op.execute(
        'CREATE POLICY "rls_runtime_placements_scope" ON "saas_runtime_placements" '
        f"FOR SELECT USING ({placement_predicate})"
    )

    _enable("saas_runtime_identity_aliases")
    alias_predicate = (
        f"({_PLATFORM} OR (user_id = {_ACTOR} AND EXISTS ("
        "SELECT 1 FROM saas_runtime_partitions partition_scope "
        "WHERE partition_scope.id = saas_runtime_identity_aliases.runtime_partition_id "
        f"AND partition_scope.tenant_id = {_TENANT})))"
    )
    op.execute(
        'CREATE POLICY "rls_runtime_identity_aliases_scope" '
        'ON "saas_runtime_identity_aliases" '
        f"FOR ALL USING ({alias_predicate}) WITH CHECK ({alias_predicate})"
    )

    _enable("saas_control_plane_outbox")
    outbox_read = (
        f"({_DISPATCHER} OR tenant_id = {_TENANT} OR ({_AUTHENTICATOR} AND tenant_id IS NULL))"
    )
    outbox_write = outbox_read
    op.execute(
        'CREATE POLICY "rls_outbox_select" ON "saas_control_plane_outbox" '
        f"FOR SELECT USING ({outbox_read})"
    )
    op.execute(
        'CREATE POLICY "rls_outbox_insert" ON "saas_control_plane_outbox" '
        f"FOR INSERT WITH CHECK ({outbox_write})"
    )
    op.execute(
        'CREATE POLICY "rls_outbox_update" ON "saas_control_plane_outbox" '
        f"FOR UPDATE USING ({_DISPATCHER}) WITH CHECK ({_DISPATCHER})"
    )


def downgrade() -> None:
    """Remove PostgreSQL policies while retaining all application tables."""

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute('DROP POLICY IF EXISTS "rls_outbox_update" ON "saas_control_plane_outbox"')
    op.execute('DROP POLICY IF EXISTS "rls_outbox_insert" ON "saas_control_plane_outbox"')
    op.execute('DROP POLICY IF EXISTS "rls_outbox_select" ON "saas_control_plane_outbox"')
    _disable("saas_control_plane_outbox")
    op.execute(
        'DROP POLICY IF EXISTS "rls_runtime_identity_aliases_scope" '
        'ON "saas_runtime_identity_aliases"'
    )
    _disable("saas_runtime_identity_aliases")
    op.execute('DROP POLICY IF EXISTS "rls_runtime_placements_scope" ON "saas_runtime_placements"')
    _disable("saas_runtime_placements")
    for table in reversed(tuple(_USER_TABLES)):
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_actor" ON "{table}"')
        _disable(table)
    for table in reversed(tuple(_TENANT_TABLES)):
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_tenant" ON "{table}"')
        _disable(table)
