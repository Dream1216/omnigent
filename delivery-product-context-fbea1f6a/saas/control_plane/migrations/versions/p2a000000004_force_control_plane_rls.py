"""Force control-plane RLS for table owners as well as ordinary roles."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "p2a000000004"
down_revision: str | None = "p2a000000003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROTECTED_TABLES = (
    "saas_global_users",
    "saas_identity_connections",
    "saas_auth_sessions",
    "saas_password_credentials",
    "saas_tenants",
    "saas_spaces",
    "saas_tenant_memberships",
    "saas_space_memberships",
    "saas_membership_invitations",
    "saas_projects",
    "saas_project_memberships",
    "saas_resource_grants",
    "saas_authorization_decisions",
    "saas_runtime_placements",
    "saas_runtime_partitions",
    "saas_runtime_identity_aliases",
    "saas_runtime_resource_bindings",
    "saas_runtime_binding_sagas",
    "saas_ownership_transfers",
    "saas_member_removal_preflights",
    "saas_control_plane_outbox",
)


def upgrade() -> None:
    """Prevent table ownership from silently bypassing installed policies."""

    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _PROTECTED_TABLES:
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')


def downgrade() -> None:
    """Restore the earlier owner-bypass behavior without removing policies."""

    if op.get_bind().dialect.name != "postgresql":
        return
    for table in reversed(_PROTECTED_TABLES):
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
