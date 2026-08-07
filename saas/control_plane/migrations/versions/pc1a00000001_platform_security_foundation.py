"""Create the PC1 Staff Realm and content-blind platform projections.

Revision ID: pc1a00000001
Revises: p6a000000009
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc1a00000001"
down_revision: str | None = "p6a000000009"
branch_labels: str | None = None
depends_on: str | None = None

_TABLES = (
    "saas_platform_staff_principals",
    "saas_platform_role_assignments",
    "saas_platform_auth_sessions",
    "saas_platform_tenant_projections",
    "saas_platform_user_projections",
)
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_TOKEN_HASH = "NULLIF(current_setting('app.platform_session_token_hash', true), '')"
_IDENTITY_ISSUER = "NULLIF(current_setting('app.platform_identity_issuer', true), '')"
_IDENTITY_SUBJECT = "NULLIF(current_setting('app.platform_identity_subject', true), '')"
_AUTHENTICATOR = "pg_has_role(current_user, 'saas_platform_authenticator', 'member')"
_APP = "pg_has_role(current_user, 'saas_platform_app', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_PROJECTOR = "pg_has_role(current_user, 'saas_platform_projector', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _create_tables() -> None:
    op.create_table(
        "saas_platform_staff_principals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("identity_connection_ref", sa.String(256), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("display_name", sa.String(256)),
        sa.Column("email_normalized", sa.String(320)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'deleted')", name="ck_platform_staff_status"
        ),
        sa.CheckConstraint("security_version > 0", name="ck_platform_staff_security_version"),
        sa.CheckConstraint(
            "length(identity_connection_ref) > 0",
            name="ck_platform_staff_identity_ref_nonempty",
        ),
        sa.CheckConstraint("length(issuer) > 0", name="ck_platform_staff_issuer_nonempty"),
        sa.CheckConstraint("length(subject) > 0", name="ck_platform_staff_subject_nonempty"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_platform_staff_subject"),
        sa.UniqueConstraint(
            "identity_connection_ref", name="uq_platform_staff_identity_connection_ref"
        ),
    )
    op.create_index(
        "ix_platform_staff_status",
        "saas_platform_staff_principals",
        ["status", "updated_at"],
    )
    op.create_table(
        "saas_platform_role_assignments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("assigned_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("approval_ref", sa.String(256), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by_principal_id", sa.Uuid()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "role IN ('platform_operator', 'platform_security_auditor', 'support_agent', "
            "'billing_operator', 'compliance_operator')",
            name="ck_platform_assignment_role",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked', 'expired')",
            name="ck_platform_assignment_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_platform_assignment_version"),
        sa.CheckConstraint(
            "length(approval_ref) > 0", name="ck_platform_assignment_approval_nonempty"
        ),
        sa.CheckConstraint("length(reason) > 0", name="ck_platform_assignment_reason_nonempty"),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL AND revoked_by_principal_id IS NULL) "
            "OR (status IN ('revoked', 'expired'))",
            name="ck_platform_assignment_revocation_state",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_platform_assignment_principal_status",
        "saas_platform_role_assignments",
        ["principal_id", "status", "expires_at"],
    )
    op.create_table(
        "saas_platform_auth_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(64), nullable=False),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.Column("audience", sa.String(256), nullable=False),
        sa.Column("origin", sa.String(512), nullable=False),
        sa.Column("authn_method", sa.String(128), nullable=False),
        sa.Column("mfa_strength", sa.String(64), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_platform_session_token_hash"),
        sa.CheckConstraint("length(csrf_token_hash) = 64", name="ck_platform_session_csrf_hash"),
        sa.CheckConstraint("security_version > 0", name="ck_platform_session_security_version"),
        sa.CheckConstraint("length(audience) > 0", name="ck_platform_session_audience_nonempty"),
        sa.CheckConstraint("length(origin) > 0", name="ck_platform_session_origin_nonempty"),
        sa.CheckConstraint(
            "length(authn_method) > 0", name="ck_platform_session_authn_method_nonempty"
        ),
        sa.CheckConstraint(
            "mfa_strength = 'phishing_resistant'", name="ck_platform_session_mfa_strength"
        ),
        sa.CheckConstraint(
            "authenticated_at < expires_at", name="ck_platform_session_expiry_order"
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_platform_session_token_hash"),
    )
    op.create_index(
        "ix_platform_session_principal_active",
        "saas_platform_auth_sessions",
        ["principal_id", "revoked_at", "expires_at"],
    )
    op.create_table(
        "saas_platform_tenant_projections",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(128), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("plan", sa.String(64), nullable=False),
        sa.Column("home_region", sa.String(64), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False),
        sa.Column("space_count", sa.Integer(), nullable=False),
        sa.Column("source_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("member_count >= 0", name="ck_platform_tenant_member_count"),
        sa.CheckConstraint("space_count >= 0", name="ck_platform_tenant_space_count"),
        sa.CheckConstraint("source_version > 0", name="ck_platform_tenant_source_version"),
        sa.PrimaryKeyConstraint("tenant_id"),
    )
    op.create_index(
        "ix_platform_tenant_projection_list",
        "saas_platform_tenant_projections",
        ["status", "tenant_id"],
    )
    op.create_table(
        "saas_platform_user_projections",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(256)),
        sa.Column("email_masked", sa.String(320)),
        sa.Column("membership_count", sa.Integer(), nullable=False),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.Column("source_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("membership_count >= 0", name="ck_platform_user_membership_count"),
        sa.CheckConstraint("security_version > 0", name="ck_platform_user_security_version"),
        sa.CheckConstraint("source_version > 0", name="ck_platform_user_source_version"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_index(
        "ix_platform_user_projection_list",
        "saas_platform_user_projections",
        ["status", "user_id"],
    )


def _active_assignment() -> str:
    return (
        "EXISTS (SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} "
        "AND assignment.status = 'active' "
        "AND (assignment.expires_at IS NULL OR assignment.expires_at > CURRENT_TIMESTAMP))"
    )


def _create_postgresql_policies() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    staff_read = (
        f"({_EMERGENCY} OR {_GOVERNANCE} OR "
        f"({_APP} AND id = {_PRINCIPAL}) OR "
        f"({_AUTHENTICATOR} AND (id = {_PRINCIPAL} OR "
        f"(issuer = {_IDENTITY_ISSUER} AND subject = {_IDENTITY_SUBJECT}))))"
    )
    assignment_read = (
        f"({_EMERGENCY} OR {_GOVERNANCE} OR "
        f"(({_APP} OR {_AUTHENTICATOR}) AND principal_id = {_PRINCIPAL}))"
    )
    session_read = (
        f"({_EMERGENCY} OR {_GOVERNANCE} OR ({_AUTHENTICATOR} AND token_hash = {_TOKEN_HASH}))"
    )
    projection_read = (
        f"({_EMERGENCY} OR {_GOVERNANCE} OR {_PROJECTOR} OR "
        f"({_APP} AND {_PRINCIPAL} IS NOT NULL AND {_active_assignment()}))"
    )
    governance_write = f"({_EMERGENCY} OR {_GOVERNANCE})"
    projector_write = f"({_EMERGENCY} OR {_PROJECTOR})"

    op.execute(
        'CREATE POLICY "rls_platform_staff_read" ON saas_platform_staff_principals '
        f"FOR SELECT USING ({staff_read})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_staff_write" ON saas_platform_staff_principals '
        f"FOR ALL USING ({governance_write}) WITH CHECK ({governance_write})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_assignments_read" ON saas_platform_role_assignments '
        f"FOR SELECT USING ({assignment_read})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_assignments_write" ON saas_platform_role_assignments '
        f"FOR ALL USING ({governance_write}) WITH CHECK ({governance_write})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_sessions_exact" ON saas_platform_auth_sessions '
        f"FOR SELECT USING ({session_read})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_sessions_insert" ON saas_platform_auth_sessions '
        f"FOR INSERT WITH CHECK ({_EMERGENCY} OR ({_AUTHENTICATOR} "
        f"AND principal_id = {_PRINCIPAL} AND token_hash = {_TOKEN_HASH}))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_sessions_update" ON saas_platform_auth_sessions '
        f"FOR UPDATE USING ({session_read}) WITH CHECK ({session_read})"
    )
    for table in ("saas_platform_tenant_projections", "saas_platform_user_projections"):
        op.execute(
            f'CREATE POLICY "rls_{table.removeprefix("saas_")}_read" ON {table} '
            f"FOR SELECT USING ({projection_read})"
        )
        op.execute(
            f'CREATE POLICY "rls_{table.removeprefix("saas_")}_write" ON {table} '
            f"FOR ALL USING ({projector_write}) WITH CHECK ({projector_write})"
        )


def upgrade() -> None:
    """Create independent platform security facts and forced-RLS policies."""

    _create_tables()
    _create_postgresql_policies()


def downgrade() -> None:
    """Remove the PC1 platform security foundation."""

    for table in reversed(_TABLES):
        op.drop_table(table)
