"""Add Project scopes, additive grants, decisions, and Space-aware RLS."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p2a000000002"
down_revision: str | None = "p2a000000001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTOR = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_SPACE = "NULLIF(current_setting('app.space_id', true), '')::uuid"
_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_governance', 'member')"

_SPACE_TABLES = {
    "saas_spaces": "id",
    "saas_space_memberships": "space_id",
    "saas_runtime_partitions": "space_id",
    "saas_runtime_resource_bindings": "space_id",
}
_PROJECT_TABLES = (
    "saas_projects",
    "saas_project_memberships",
    "saas_resource_grants",
    "saas_authorization_decisions",
)


def _replace_role_constraints() -> None:
    with op.batch_alter_table("saas_tenant_memberships") as batch_op:
        batch_op.drop_constraint("ck_tenant_membership_role", type_="check")
        batch_op.create_check_constraint(
            "ck_tenant_membership_role",
            "role IN ('owner', 'admin', 'billing_admin', 'security_auditor', "
            "'operator', 'member')",
        )
    with op.batch_alter_table("saas_membership_invitations") as batch_op:
        batch_op.drop_constraint("ck_invitation_tenant_role", type_="check")
        batch_op.create_check_constraint(
            "ck_invitation_tenant_role",
            "tenant_role IN ('owner', 'admin', 'billing_admin', 'security_auditor', "
            "'operator', 'member')",
        )
        batch_op.drop_constraint("ck_invitation_space_role", type_="check")
        batch_op.create_check_constraint(
            "ck_invitation_space_role",
            "space_role IS NULL OR space_role IN "
            "('owner', 'admin', 'operator', 'member', 'viewer')",
        )
    with op.batch_alter_table("saas_space_memberships") as batch_op:
        batch_op.drop_constraint("ck_space_membership_role", type_="check")
        batch_op.create_check_constraint(
            "ck_space_membership_role",
            "role IN ('owner', 'admin', 'operator', 'member', 'viewer')",
        )


def _restore_role_constraints() -> None:
    with op.batch_alter_table("saas_space_memberships") as batch_op:
        batch_op.drop_constraint("ck_space_membership_role", type_="check")
        batch_op.create_check_constraint(
            "ck_space_membership_role",
            "role IN ('owner', 'admin', 'operator', 'member')",
        )
    with op.batch_alter_table("saas_membership_invitations") as batch_op:
        batch_op.drop_constraint("ck_invitation_space_role", type_="check")
        batch_op.create_check_constraint(
            "ck_invitation_space_role",
            "space_role IS NULL OR space_role IN ('owner', 'admin', 'operator', 'member')",
        )
        batch_op.drop_constraint("ck_invitation_tenant_role", type_="check")
        batch_op.create_check_constraint(
            "ck_invitation_tenant_role", "tenant_role IN ('owner', 'admin', 'member')"
        )
    with op.batch_alter_table("saas_tenant_memberships") as batch_op:
        batch_op.drop_constraint("ck_tenant_membership_role", type_="check")
        batch_op.create_check_constraint(
            "ck_tenant_membership_role", "role IN ('owner', 'admin', 'member')"
        )


def _create_project_tables() -> None:
    op.create_table(
        "saas_projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("visibility", sa.String(32), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "visibility IN ('private', 'space', 'restricted')", name="ck_project_visibility"
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'archived')", name="ck_project_status"
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_project_name_nonempty"),
        sa.CheckConstraint("authorization_version > 0", name="ck_project_auth_version"),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            name="fk_project_space",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "space_id", "id", name="uq_project_scope"),
    )
    op.create_index(
        "ix_project_scope_status", "saas_projects", ["tenant_id", "space_id", "status"]
    )

    op.create_table(
        "saas_project_memberships",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "subject_type IN ('user', 'space')", name="ck_project_membership_subject_type"
        ),
        sa.CheckConstraint(
            "role IN ('owner', 'manage', 'operate', 'edit', 'read')",
            name="ck_project_membership_role",
        ),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="ck_project_membership_status"),
        sa.CheckConstraint(
            "subject_type <> 'space' OR subject_id = space_id",
            name="ck_project_membership_space_subject",
        ),
        sa.CheckConstraint("version > 0", name="ck_project_membership_version"),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_project_membership_project",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("project_id", "subject_type", "subject_id"),
    )
    op.create_index(
        "ix_project_membership_subject",
        "saas_project_memberships",
        ["tenant_id", "space_id", "subject_type", "subject_id", "status"],
    )

    op.create_table(
        "saas_resource_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "subject_type IN ('user', 'space')", name="ck_resource_grant_subject_type"
        ),
        sa.CheckConstraint(
            "role IN ('owner', 'manage', 'operate', 'edit', 'read')",
            name="ck_resource_grant_role",
        ),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="ck_resource_grant_status"),
        sa.CheckConstraint(
            "subject_type <> 'space' OR subject_id = space_id",
            name="ck_resource_grant_space_subject",
        ),
        sa.CheckConstraint("length(resource_type) > 0", name="ck_resource_grant_type_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_resource_grant_version"),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_resource_grant_project",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_active_resource_grant",
        "saas_resource_grants",
        [
            "tenant_id",
            "space_id",
            "project_id",
            "resource_type",
            "resource_id",
            "subject_type",
            "subject_id",
        ],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_resource_grant_subject",
        "saas_resource_grants",
        ["tenant_id", "space_id", "subject_type", "subject_id", "status"],
    )

    op.create_table(
        "saas_authorization_decisions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.Uuid(), nullable=True),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(128), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("trace_id", sa.String(128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("mode IN ('shadow', 'enforce')", name="ck_authorization_mode"),
        sa.CheckConstraint("length(action) > 0", name="ck_authorization_action_nonempty"),
        sa.CheckConstraint("length(reason) > 0", name="ck_authorization_reason_nonempty"),
        sa.CheckConstraint("length(trace_id) > 0", name="ck_authorization_trace_nonempty"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            name="fk_authorization_decision_space",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_authorization_decision_scope",
        "saas_authorization_decisions",
        ["tenant_id", "space_id", "project_id", "created_at"],
    )
    op.create_index(
        "ix_authorization_decision_actor",
        "saas_authorization_decisions",
        ["actor_id", "created_at"],
    )

    with op.batch_alter_table("saas_runtime_resource_bindings") as batch_op:
        batch_op.create_foreign_key(
            "fk_runtime_binding_project_scope",
            "saas_projects",
            ["tenant_id", "space_id", "project_id"],
            ["tenant_id", "space_id", "id"],
            ondelete="RESTRICT",
        )


def _install_postgresql_rls() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    for table, space_column in _SPACE_TABLES.items():
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_tenant" ON "{table}"')
        predicate = (
            f"({_PLATFORM} OR ({_GOVERNANCE} AND tenant_id = {_TENANT}) OR "
            f"(tenant_id = {_TENANT} AND {space_column} = {_SPACE}))"
        )
        op.execute(
            f'CREATE POLICY "rls_{table}_tenant_space" ON "{table}" '
            f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
        )

    for table in _PROJECT_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        predicate = (
            f"({_PLATFORM} OR ({_GOVERNANCE} AND tenant_id = {_TENANT}) OR "
            f"(tenant_id = {_TENANT} AND space_id = {_SPACE}))"
        )
        if table == "saas_authorization_decisions":
            op.execute(
                f'CREATE POLICY "rls_{table}_select" ON "{table}" FOR SELECT USING ({predicate})'
            )
            insert_predicate = (
                f"({_PLATFORM} OR ({_GOVERNANCE} AND tenant_id = {_TENANT}) OR "
                f"(tenant_id = {_TENANT} AND space_id = {_SPACE} "
                f"AND actor_id = {_ACTOR}))"
            )
            op.execute(
                f'CREATE POLICY "rls_{table}_insert" ON "{table}" '
                f"FOR INSERT WITH CHECK ({insert_predicate})"
            )
        else:
            op.execute(
                f'CREATE POLICY "rls_{table}_tenant_space" ON "{table}" '
                f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
            )


def _remove_postgresql_rls() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    for table in reversed(_PROJECT_TABLES):
        if table == "saas_authorization_decisions":
            op.execute(f'DROP POLICY IF EXISTS "rls_{table}_insert" ON "{table}"')
            op.execute(f'DROP POLICY IF EXISTS "rls_{table}_select" ON "{table}"')
        else:
            op.execute(f'DROP POLICY IF EXISTS "rls_{table}_tenant_space" ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')

    for table in reversed(tuple(_SPACE_TABLES)):
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_tenant_space" ON "{table}"')
        predicate = f"({_PLATFORM} OR tenant_id = {_TENANT})"
        op.execute(
            f'CREATE POLICY "rls_{table}_tenant" ON "{table}" '
            f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
        )


def upgrade() -> None:
    """Install Project authorization records and tighten mandatory Space scopes."""

    _replace_role_constraints()
    _create_project_tables()
    _install_postgresql_rls()


def downgrade() -> None:
    """Remove Project authorization records and restore the P1 role set."""

    _remove_postgresql_rls()
    with op.batch_alter_table("saas_runtime_resource_bindings") as batch_op:
        batch_op.drop_constraint("fk_runtime_binding_project_scope", type_="foreignkey")
    op.drop_index("ix_authorization_decision_actor", table_name="saas_authorization_decisions")
    op.drop_index("ix_authorization_decision_scope", table_name="saas_authorization_decisions")
    op.drop_table("saas_authorization_decisions")
    op.drop_index("ix_resource_grant_subject", table_name="saas_resource_grants")
    op.drop_index("uq_active_resource_grant", table_name="saas_resource_grants")
    op.drop_table("saas_resource_grants")
    op.drop_index("ix_project_membership_subject", table_name="saas_project_memberships")
    op.drop_table("saas_project_memberships")
    op.drop_index("ix_project_scope_status", table_name="saas_projects")
    op.drop_table("saas_projects")
    _restore_role_constraints()
