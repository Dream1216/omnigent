"""Add exact-target Privacy read policies for Platform Security Auditors.

Revision ID: pc5b00000002
Revises: pc5b00000001
"""

from __future__ import annotations

from alembic import op

revision: str = "pc5b00000002"
down_revision: str | None = "pc5b00000001"
branch_labels: str | None = None
depends_on: str | None = None

_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_TARGET_TENANT = "NULLIF(current_setting('app.platform_target_tenant_id', true), '')::uuid"
_TARGET_USER = "NULLIF(current_setting('app.platform_target_user_id', true), '')::uuid"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"


def _auditor() -> str:
    return (
        f"({_GOVERNANCE} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} "
        "AND assignment.role = 'platform_security_auditor' "
        "AND assignment.status = 'active' "
        "AND (assignment.expires_at IS NULL OR assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


_READ_POLICIES = {
    "saas_privacy_legal_holds": (
        "rls_privacy_holds_auditor_read",
        f"((target_type = 'tenant' AND target_id = {_TARGET_TENANT}) OR "
        f"(target_type = 'global_user' AND target_id = {_TARGET_USER}))",
    ),
    "saas_privacy_deletion_manifests": (
        "rls_privacy_manifests_auditor_read",
        f"((target_type = 'tenant' AND target_id = {_TARGET_TENANT}) OR "
        f"(target_type = 'global_user' AND target_id = {_TARGET_USER}))",
    ),
    "saas_global_users": (
        "rls_global_users_privacy_auditor_read",
        f"id = {_TARGET_USER}",
    ),
    "saas_tenants": (
        "rls_tenants_privacy_auditor_read",
        f"id = {_TARGET_TENANT}",
    ),
    "saas_tenant_memberships": (
        "rls_tenant_memberships_privacy_auditor_read",
        f"tenant_id = {_TARGET_TENANT} OR user_id = {_TARGET_USER}",
    ),
    "saas_service_accounts": (
        "rls_service_accounts_privacy_auditor_read",
        f"steward_user_id = {_TARGET_USER}",
    ),
    "saas_identity_connections": (
        "rls_identity_connections_privacy_auditor_read",
        f"user_id = {_TARGET_USER}",
    ),
    "saas_enterprise_scim_users": (
        "rls_scim_users_privacy_auditor_read",
        f"user_id = {_TARGET_USER}",
    ),
    "saas_enterprise_scim_directories": (
        "rls_scim_directories_privacy_auditor_read",
        f"tenant_id = {_TARGET_TENANT}",
    ),
    "saas_runs": (
        "rls_runs_privacy_auditor_read",
        f"tenant_id = {_TARGET_TENANT}",
    ),
    "saas_platform_support_grants": (
        "rls_support_grants_privacy_auditor_read",
        f"tenant_id = {_TARGET_TENANT}",
    ),
}


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    auditor = _auditor()
    for table, (policy, target) in _READ_POLICIES.items():
        op.execute(
            f'CREATE POLICY "{policy}" ON {table} FOR SELECT USING ({auditor} AND ({target}))'
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, (policy, _target) in reversed(_READ_POLICIES.items()):
        op.execute(f'DROP POLICY IF EXISTS "{policy}" ON {table}')
