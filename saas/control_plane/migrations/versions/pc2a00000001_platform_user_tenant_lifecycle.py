"""Add PC2 platform user, Tenant lifecycle, and Owner Recovery authority.

Revision ID: pc2a00000001
Revises: pc1a00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc2a00000001"
down_revision: str | None = "pc1a00000001"
branch_labels: str | None = None
depends_on: str | None = None

_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_TARGET_TENANT = "NULLIF(current_setting('app.platform_target_tenant_id', true), '')::uuid"
_TARGET_USER = "NULLIF(current_setting('app.platform_target_user_id', true), '')::uuid"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _operator() -> str:
    return (
        f"({_GOVERNANCE} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} "
        "AND assignment.role = 'platform_operator' "
        "AND assignment.status = 'active' "
        "AND (assignment.expires_at IS NULL OR assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _create_table() -> None:
    op.create_table(
        "saas_platform_lifecycle_operations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("approval_ref", sa.String(256), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant')",
            name="ck_platform_lifecycle_target_type",
        ),
        sa.CheckConstraint(
            "action IN ('user_suspend', 'user_restore', 'user_sessions_revoke', "
            "'tenant_suspend', 'tenant_restore', 'tenant_owner_recover')",
            name="ck_platform_lifecycle_action",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) > 0", name="ck_platform_lifecycle_idempotency_nonempty"
        ),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_platform_lifecycle_request_hash"),
        sa.CheckConstraint(
            "length(approval_ref) > 0", name="ck_platform_lifecycle_approval_nonempty"
        ),
        sa.CheckConstraint("length(reason) > 0", name="ck_platform_lifecycle_reason_nonempty"),
        sa.CheckConstraint(
            "(target_type = 'global_user' AND tenant_id IS NULL) OR "
            "(target_type = 'tenant' AND tenant_id = target_id)",
            name="ck_platform_lifecycle_target_scope",
        ),
        sa.ForeignKeyConstraint(
            ["actor_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "actor_principal_id",
            "idempotency_key",
            name="uq_platform_lifecycle_actor_idempotency",
        ),
    )
    op.create_index(
        "ix_platform_lifecycle_target",
        "saas_platform_lifecycle_operations",
        ["target_type", "target_id", "occurred_at"],
    )


def _add_tenant_version() -> None:
    with op.batch_alter_table("saas_tenants") as batch_op:
        batch_op.add_column(
            sa.Column("lifecycle_version", sa.Integer(), nullable=False, server_default="1")
        )
        batch_op.create_check_constraint("ck_tenant_lifecycle_version", "lifecycle_version > 0")


def _install_postgresql_policies() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    operator = _operator()
    op.execute("ALTER TABLE saas_platform_lifecycle_operations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE saas_platform_lifecycle_operations FORCE ROW LEVEL SECURITY")
    op.execute(
        'CREATE POLICY "rls_platform_lifecycle_operations" '
        "ON saas_platform_lifecycle_operations FOR ALL "
        f"USING ({_EMERGENCY} OR ({operator} AND actor_principal_id = {_PRINCIPAL})) "
        f"WITH CHECK ({_EMERGENCY} OR ({operator} AND actor_principal_id = {_PRINCIPAL}))"
    )

    user_scope = (
        f"({_EMERGENCY} OR ({operator} AND (id = {_TARGET_USER} OR EXISTS ("
        "SELECT 1 FROM saas_tenant_memberships platform_member_scope "
        "WHERE platform_member_scope.user_id = saas_global_users.id "
        f"AND platform_member_scope.tenant_id = {_TARGET_TENANT}))))"
    )
    op.execute(
        'CREATE POLICY "rls_global_users_platform_target" ON saas_global_users '
        f"FOR ALL USING ({user_scope}) WITH CHECK ({user_scope})"
    )
    session_scope = (
        f"({_EMERGENCY} OR ({operator} AND (user_id = {_TARGET_USER} OR EXISTS ("
        "SELECT 1 FROM saas_tenant_memberships platform_member_scope "
        "WHERE platform_member_scope.user_id = saas_auth_sessions.user_id "
        f"AND platform_member_scope.tenant_id = {_TARGET_TENANT}))))"
    )
    op.execute(
        'CREATE POLICY "rls_auth_sessions_platform_target" ON saas_auth_sessions '
        f"FOR UPDATE USING ({session_scope}) WITH CHECK ({session_scope})"
    )
    oidc_scope = f"({_EMERGENCY} OR ({operator} AND target_user_id = {_TARGET_USER}))"
    op.execute(
        'CREATE POLICY "rls_oidc_transactions_platform_target" ON saas_oidc_login_transactions '
        f"FOR UPDATE USING ({oidc_scope}) WITH CHECK ({oidc_scope})"
    )
    tenant_scope = f"({_EMERGENCY} OR ({operator} AND id = {_TARGET_TENANT}))"
    op.execute(
        'CREATE POLICY "rls_tenants_platform_target" ON saas_tenants '
        f"FOR ALL USING ({tenant_scope}) WITH CHECK ({tenant_scope})"
    )
    membership_scope = f"({_EMERGENCY} OR ({operator} AND tenant_id = {_TARGET_TENANT}))"
    op.execute(
        'CREATE POLICY "rls_tenant_memberships_platform_target" ON saas_tenant_memberships '
        f"FOR ALL USING ({membership_scope}) WITH CHECK ({membership_scope})"
    )
    service_scope = (
        f"({_EMERGENCY} OR ({operator} AND (tenant_id = {_TARGET_TENANT} "
        f"OR steward_user_id = {_TARGET_USER})))"
    )
    op.execute(
        'CREATE POLICY "rls_service_accounts_platform_target" ON saas_service_accounts '
        f"FOR ALL USING ({service_scope}) WITH CHECK ({service_scope})"
    )
    credential_scope = (
        f"({_EMERGENCY} OR ({operator} AND EXISTS ("
        "SELECT 1 FROM saas_service_accounts platform_account_scope "
        "WHERE platform_account_scope.id = saas_api_credentials.service_account_id "
        "AND platform_account_scope.tenant_id = saas_api_credentials.tenant_id "
        f"AND (platform_account_scope.tenant_id = {_TARGET_TENANT} "
        f"OR platform_account_scope.steward_user_id = {_TARGET_USER}))))"
    )
    op.execute(
        'CREATE POLICY "rls_api_credentials_platform_target" ON saas_api_credentials '
        f"FOR UPDATE USING ({credential_scope}) WITH CHECK ({credential_scope})"
    )
    outbox_scope = f"({_EMERGENCY} OR {operator})"
    op.execute(
        'CREATE POLICY "rls_outbox_platform_insert" ON saas_control_plane_outbox '
        f"FOR INSERT WITH CHECK ({outbox_scope})"
    )


def upgrade() -> None:
    _add_tenant_version()
    _create_table()
    _install_postgresql_policies()


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            'DROP POLICY IF EXISTS "rls_outbox_platform_insert" ON saas_control_plane_outbox'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_api_credentials_platform_target" ON saas_api_credentials'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_service_accounts_platform_target" ON saas_service_accounts'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_tenant_memberships_platform_target" '
            "ON saas_tenant_memberships"
        )
        op.execute('DROP POLICY IF EXISTS "rls_tenants_platform_target" ON saas_tenants')
        op.execute(
            'DROP POLICY IF EXISTS "rls_oidc_transactions_platform_target" '
            "ON saas_oidc_login_transactions"
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_auth_sessions_platform_target" ON saas_auth_sessions'
        )
        op.execute('DROP POLICY IF EXISTS "rls_global_users_platform_target" ON saas_global_users')
    op.drop_table("saas_platform_lifecycle_operations")
    with op.batch_alter_table("saas_tenants") as batch_op:
        batch_op.drop_constraint("ck_tenant_lifecycle_version", type_="check")
        batch_op.drop_column("lifecycle_version")
