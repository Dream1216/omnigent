"""Add Staff model connections and persist-first credential projections.

Revision ID: lm1a00000001
Revises: p0s000000015
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "lm1a00000001"
down_revision: str | None = "p0s000000015"
branch_labels: str | None = None
depends_on: str | None = None

_CONNECTIONS = "saas_model_connections"
_CREDENTIALS = "saas_model_credential_versions"
_OPERATIONS = "saas_model_projection_operations"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_APP = "pg_has_role(current_user, 'saas_platform_app', 'member')"
_BROKER = "pg_has_role(current_user, 'saas_secret_broker', 'member')"
_RECOVERY = (
    "(pg_has_role(current_user, 'saas_platform', 'member') OR "
    "pg_has_role(current_user, 'saas_platform_governance', 'member'))"
)


def _hex64(column: str) -> str:
    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {remainder} = ''"


def _assignment(*roles: str) -> str:
    allowed = ", ".join(f"'{role}'" for role in roles)
    return (
        f"({_APP} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} AND assignment.role IN ({allowed}) "
        "AND assignment.status = 'active' AND (assignment.expires_at IS NULL "
        "OR assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _create_tables() -> None:
    op.create_table(
        _CONNECTIONS,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("provider_id", sa.String(32), nullable=False),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("credential_generation", sa.Integer(), nullable=False),
        sa.Column("updated_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["updated_by_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint("provider_id = 'deepseek'", name="ck_model_connection_provider"),
        sa.CheckConstraint(
            "base_url = 'https://api.deepseek.com'", name="ck_model_connection_url"
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 128", name="ck_model_connection_name"
        ),
        sa.CheckConstraint(
            "version > 0 AND credential_generation > 0", name="ck_model_connection_version"
        ),
    )
    op.create_table(
        _CREDENTIALS,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("credential_name", sa.String(128), nullable=False),
        sa.Column("api_key_ciphertext", sa.Text(), nullable=False),
        sa.Column("created_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["connection_id"], [f"{_CONNECTIONS}.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["created_by_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("credential_name"),
        sa.UniqueConstraint("connection_id", "generation", name="uq_model_credential_generation"),
        sa.UniqueConstraint("connection_id", "id", name="uq_model_credential_connection"),
        sa.CheckConstraint("generation > 0", name="ck_model_credential_generation"),
        sa.CheckConstraint(
            "length(api_key_ciphertext) > 0", name="ck_model_credential_ciphertext"
        ),
        sa.CheckConstraint(
            "length(credential_name) BETWEEN 1 AND 128", name="ck_model_credential_name"
        ),
    )
    op.create_table(
        _OPERATIONS,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("credential_version_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(128)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["actor_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["connection_id", "credential_version_id"],
            [f"{_CREDENTIALS}.connection_id", f"{_CREDENTIALS}.id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "actor_principal_id", "idempotency_key", name="uq_model_projection_idempotency"
        ),
        sa.CheckConstraint(
            "action IN ('create_connection', 'rotate_credential')",
            name="ck_model_projection_action",
        ),
        sa.CheckConstraint(
            "status IN ('requested', 'applying', 'applied', 'verified', 'failed', 'uncertain')",
            name="ck_model_projection_status",
        ),
        sa.CheckConstraint(
            _hex64("request_hash"),
            name="ck_model_projection_request_hash",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 128", name="ck_model_projection_idempotency"
        ),
        sa.CheckConstraint("version > 0", name="ck_model_projection_version"),
    )
    op.create_index("ix_model_projection_status", _OPERATIONS, ["status", "created_at"])


def _postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    read = _assignment("platform_operator", "platform_security_auditor")
    write = _assignment("platform_operator")
    for table in (_CONNECTIONS, _CREDENTIALS, _OPERATIONS):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        app_read = write if table == _CREDENTIALS else read
        op.execute(
            f"CREATE POLICY rls_{table.removeprefix('saas_')}_read ON {table} "
            f"FOR SELECT TO saas_platform_app USING ({app_read})"
        )
        op.execute(
            f"CREATE POLICY rls_{table.removeprefix('saas_')}_broker ON {table} "
            f"FOR SELECT TO saas_secret_broker USING ({_BROKER})"
        )
        op.execute(
            f"CREATE POLICY rls_{table.removeprefix('saas_')}_recovery ON {table} "
            f"FOR SELECT TO saas_platform, saas_platform_governance USING ({_RECOVERY})"
        )
        op.execute(
            f"GRANT SELECT ON {table} TO saas_platform_app, saas_secret_broker, "
            "saas_platform, saas_platform_governance"
        )
        actor_column = (
            "updated_by_principal_id"
            if table == _CONNECTIONS
            else "created_by_principal_id"
            if table == _CREDENTIALS
            else "actor_principal_id"
        )
        initial = (
            " AND status = 'requested' AND version = 1 AND error_code IS NULL"
            if table == _OPERATIONS
            else ""
        )
        op.execute(
            f"CREATE POLICY rls_{table.removeprefix('saas_')}_insert ON {table} "
            "FOR INSERT TO saas_platform_app "
            f"WITH CHECK ({write} AND {actor_column} = {_PRINCIPAL}{initial})"
        )
        op.execute(f"GRANT INSERT ON {table} TO saas_platform_app")
    op.execute(
        f"CREATE POLICY rls_model_connection_update ON {_CONNECTIONS} "
        f"FOR UPDATE TO saas_platform_app USING ({write}) "
        f"WITH CHECK ({write} AND updated_by_principal_id = {_PRINCIPAL})"
    )
    op.execute(
        "GRANT UPDATE (version, credential_generation, updated_by_principal_id, updated_at) "
        f"ON {_CONNECTIONS} TO saas_platform_app"
    )
    envelope = (
        f"({write} AND tenant_id IS NULL AND aggregate_type = 'platform_model' "
        "AND event_type = 'platform.model_projection.requested' "
        "AND payload->>'event_type' = event_type "
        "AND (payload->'schema_version')::jsonb = '1'::jsonb "
        "AND payload::jsonb - ARRAY['event_type', 'operation_id', "
        "'credential_version_id', 'schema_version']::text[] = '{}'::jsonb "
        f"AND EXISTS (SELECT 1 FROM {_OPERATIONS} operation "
        "WHERE operation.id::text = aggregate_key "
        "AND operation.id::text = payload->>'operation_id' "
        "AND operation.credential_version_id::text = payload->>'credential_version_id' "
        f"AND operation.actor_principal_id = {_PRINCIPAL} AND operation.status = 'requested' "
        "AND operation.request_hash = saas_control_plane_outbox.request_hash))"
    )
    op.execute(
        "CREATE POLICY rls_outbox_model_projection_insert ON saas_control_plane_outbox "
        f"FOR INSERT TO saas_platform_app WITH CHECK ({envelope})"
    )
    op.execute(
        "GRANT INSERT (id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
        "idempotency_key, request_hash, attempt_count, available_at, claimed_at, claim_token, "
        "published_at, created_at) ON saas_control_plane_outbox TO saas_platform_app"
    )


def upgrade() -> None:
    _create_tables()
    _postgresql_authority()


def downgrade() -> None:
    bind = op.get_bind()
    tables = (_CONNECTIONS, _CREDENTIALS, _OPERATIONS)
    if bind.dialect.name == "postgresql":
        for table in tables:
            op.execute(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE")
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    if any(
        bind.execute(sa.text(f"SELECT EXISTS (SELECT 1 FROM {table})")).scalar_one()
        for table in tables
    ):
        raise RuntimeError(
            "cannot remove model routing schema with retained credentials or operations"
        )
    if bind.dialect.name == "postgresql":
        op.execute("DROP POLICY rls_outbox_model_projection_insert ON saas_control_plane_outbox")
    op.drop_table(_OPERATIONS)
    op.drop_table(_CREDENTIALS)
    op.drop_table(_CONNECTIONS)
