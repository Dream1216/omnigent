"""Persist immutable deployment drafts without enabling a runtime model.

Revision ID: lm1c00000001
Revises: lm1b00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64

revision: str = "lm1c00000001"
down_revision: str | None = "lm1b00000001"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "saas_model_deployment_versions"
_OPERATIONS = "saas_model_projection_operations"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"


def _assignment(*roles: str) -> str:
    values = ", ".join(f"'{role}'" for role in roles)
    return (
        "(pg_has_role(current_user, 'saas_platform_app', 'member') "
        f"AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} AND assignment.role IN ({values}) "
        "AND assignment.status = 'active' AND (assignment.expires_at IS NULL "
        "OR assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("public_model_id", sa.String(128), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("provider_model", sa.String(128), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("credential_version_id", sa.Uuid(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("deployment_alias", sa.String(128), nullable=False),
        sa.Column("wire_api", sa.String(32), nullable=False),
        sa.Column("max_output_tokens", sa.Integer(), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_configuration", sa.Text(), nullable=False),
        sa.Column("created_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["connection_id", "credential_version_id"],
            ["saas_model_credential_versions.connection_id", "saas_model_credential_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("deployment_alias"),
        sa.UniqueConstraint(
            "public_model_id", "generation", name="uq_model_deployment_generation"
        ),
        sa.UniqueConstraint(
            "connection_id", "credential_version_id", "id", name="uq_model_deployment_scope"
        ),
        sa.CheckConstraint(
            "public_model_id = provider_model AND public_model_id LIKE 'deepseek-%' "
            "AND length(public_model_id) BETWEEN 10 AND 128",
            name="ck_model_deployment_model",
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 128", name="ck_model_deployment_name"
        ),
        sa.CheckConstraint("generation > 0", name="ck_model_deployment_generation"),
        sa.CheckConstraint(
            "deployment_alias = 'platform-model-' || replace(CAST(id AS TEXT), '-', '')",
            name="ck_model_deployment_alias",
        ),
        sa.CheckConstraint(
            "wire_api IN ('openai_chat_completions', 'openai_responses')",
            name="ck_model_deployment_wire_api",
        ),
        sa.CheckConstraint(
            "max_output_tokens BETWEEN 1 AND 65536", name="ck_model_deployment_output_limit"
        ),
        sa.CheckConstraint(_hex64("configuration_sha256"), name="ck_model_deployment_hash"),
        sa.CheckConstraint(
            "length(canonical_configuration) BETWEEN 1 AND 16384",
            name="ck_model_deployment_configuration",
        ),
    )
    with op.batch_alter_table(_OPERATIONS) as batch:
        batch.add_column(sa.Column("deployment_version_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            "fk_model_projection_deployment_scope",
            _TABLE,
            ["connection_id", "credential_version_id", "deployment_version_id"],
            ["connection_id", "credential_version_id", "id"],
            ondelete="RESTRICT",
        )
        batch.drop_constraint("ck_model_projection_action", type_="check")
        batch.create_check_constraint(
            "ck_model_projection_action",
            "action IN ('create_connection', 'rotate_credential', 'create_deployment')",
        )
        batch.create_check_constraint(
            "ck_model_projection_deployment_scope",
            "(action IN ('create_connection', 'rotate_credential') "
            "AND deployment_version_id IS NULL) "
            "OR (action = 'create_deployment' AND deployment_version_id IS NOT NULL)",
        )
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY rls_model_deployment_read ON {_TABLE} FOR SELECT TO saas_platform_app "
        f"USING ({_assignment('platform_operator', 'platform_security_auditor')})"
    )
    op.execute(
        f"CREATE POLICY rls_model_deployment_insert ON {_TABLE} FOR INSERT TO saas_platform_app "
        f"WITH CHECK ({_assignment('platform_operator')} "
        f"AND created_by_principal_id = {_PRINCIPAL})"
    )
    op.execute(
        f"CREATE POLICY rls_model_deployment_projection_read ON {_TABLE} "
        "FOR SELECT TO saas_model_projection USING (EXISTS ("
        f"SELECT 1 FROM {_OPERATIONS} operation "
        f"WHERE operation.deployment_version_id = {_TABLE}.id "
        "AND operation.status IN ('requested', 'applying')))"
    )
    op.execute(
        f"CREATE POLICY rls_model_deployment_recovery_read ON {_TABLE} "
        "FOR SELECT TO saas_platform, saas_platform_governance USING (true)"
    )
    op.execute(
        "CREATE POLICY rls_model_connection_projection_read ON saas_model_connections "
        "FOR SELECT TO saas_model_projection USING (EXISTS ("
        f"SELECT 1 FROM {_OPERATIONS} operation "
        "WHERE operation.connection_id = saas_model_connections.id "
        "AND operation.status IN ('requested', 'applying')))"
    )
    op.execute(
        "GRANT SELECT (id, credential_generation) "
        "ON saas_model_connections TO saas_model_projection"
    )
    op.execute(f"GRANT SELECT, INSERT ON {_TABLE} TO saas_platform_app")
    op.execute(
        f"GRANT SELECT ON {_TABLE} "
        "TO saas_model_projection, saas_platform, saas_platform_governance"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"LOCK TABLE {_TABLE}, {_OPERATIONS} IN ACCESS EXCLUSIVE MODE")
        op.execute(f"ALTER TABLE {_TABLE} NO FORCE ROW LEVEL SECURITY")
    if bind.execute(sa.text(f"SELECT EXISTS (SELECT 1 FROM {_TABLE})")).scalar_one():
        raise RuntimeError("cannot remove model deployment schema with retained drafts")
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP POLICY rls_model_deployment_projection_read ON {_TABLE}")
        op.execute("DROP POLICY rls_model_connection_projection_read ON saas_model_connections")
        op.execute(
            "REVOKE SELECT (id, credential_generation) "
            "ON saas_model_connections FROM saas_model_projection"
        )
    with op.batch_alter_table(_OPERATIONS) as batch:
        batch.drop_constraint("fk_model_projection_deployment_scope", type_="foreignkey")
        batch.drop_constraint("ck_model_projection_deployment_scope", type_="check")
        batch.drop_constraint("ck_model_projection_action", type_="check")
        batch.create_check_constraint(
            "ck_model_projection_action", "action IN ('create_connection', 'rotate_credential')"
        )
        batch.drop_column("deployment_version_id")
    op.drop_table(_TABLE)
