"""Separate credential projection authority and immutable transition receipts.

Revision ID: lm1b00000001
Revises: lm1a00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "lm1b00000001"
down_revision: str | None = "lm1a00000001"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "saas_model_projection_transitions"
_WORKER = "saas_model_projection"
_OPERATIONS = "saas_model_projection_operations"


def _postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY")
    # Existing readers already enforce the live Staff role or recovery authority.
    op.execute(
        f"CREATE POLICY rls_model_projection_transition_read ON {_TABLE} "
        "FOR SELECT TO saas_platform_app, saas_platform, saas_platform_governance "
        f"USING (EXISTS (SELECT 1 FROM {_OPERATIONS} operation "
        f"WHERE operation.id = {_TABLE}.operation_id))"
    )
    op.execute(
        f"CREATE POLICY rls_model_projection_worker_read ON {_OPERATIONS} "
        f"FOR SELECT TO {_WORKER} USING (true)"
    )
    op.execute(
        f"CREATE POLICY rls_model_projection_worker_update ON {_OPERATIONS} "
        # FOR UPDATE must see terminal rows on redelivery; the trigger freezes them.
        f"FOR UPDATE TO {_WORKER} USING (true) "
        "WITH CHECK (status IN ('applying', 'applied', 'failed', 'uncertain'))"
    )
    op.execute(
        "CREATE POLICY rls_model_credential_projection_read ON saas_model_credential_versions "
        f"FOR SELECT TO {_WORKER} USING (EXISTS (SELECT 1 FROM {_OPERATIONS} operation "
        "WHERE operation.credential_version_id = saas_model_credential_versions.id "
        "AND operation.status IN ('requested', 'applying')))"
    )
    for table, column in (
        ("saas_platform_staff_principals", "id"),
        ("saas_platform_role_assignments", "principal_id"),
    ):
        op.execute(
            f"CREATE POLICY rls_model_projection_actor_read ON {table} "
            f"FOR SELECT TO {_WORKER} USING (EXISTS (SELECT 1 FROM {_OPERATIONS} operation "
            f"WHERE operation.actor_principal_id = {table}.{column} "
            "AND operation.status IN ('requested', 'applying')))"
        )
    op.execute(
        "CREATE POLICY rls_outbox_model_projection_read ON saas_control_plane_outbox "
        f"FOR SELECT TO {_WORKER} USING (tenant_id IS NULL "
        "AND aggregate_type = 'platform_model' "
        "AND event_type = 'platform.model_projection.requested' "
        f"AND EXISTS (SELECT 1 FROM {_OPERATIONS} operation "
        "WHERE operation.id::text = aggregate_key "
        "AND operation.id::text = payload->>'operation_id' "
        "AND operation.credential_version_id::text = payload->>'credential_version_id' "
        "AND operation.request_hash = saas_control_plane_outbox.request_hash))"
    )
    op.execute(
        f"CREATE POLICY rls_model_projection_transition_worker_read ON {_TABLE} "
        f"FOR SELECT TO {_WORKER} USING (true)"
    )
    op.execute(
        f"CREATE POLICY rls_model_projection_transition_insert ON {_TABLE} "
        f"FOR INSERT TO {_WORKER} WITH CHECK (EXISTS ("
        f"SELECT 1 FROM {_OPERATIONS} operation "
        "JOIN saas_control_plane_outbox event ON event.aggregate_key = operation.id::text "
        f"WHERE operation.id = {_TABLE}.operation_id "
        f"AND operation.version = {_TABLE}.version "
        f"AND operation.actor_principal_id = {_TABLE}.actor_principal_id "
        f"AND operation.status = {_TABLE}.status "
        f"AND operation.error_code IS NOT DISTINCT FROM {_TABLE}.error_code "
        f"AND operation.updated_at = {_TABLE}.occurred_at "
        f"AND event.id = {_TABLE}.event_id))"
    )
    op.execute(
        "CREATE FUNCTION public.saas_model_projection_transition_guard() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ BEGIN "
        "IF NEW.version <> OLD.version + 1 OR NOT ("
        "(OLD.status = 'requested' AND NEW.status IN ('applying', 'failed')) OR "
        "(OLD.status = 'applying' AND NEW.status IN ('applied', 'failed', 'uncertain'))) "
        "OR (NEW.status IN ('applying', 'applied') AND NEW.error_code IS NOT NULL) "
        "OR (NEW.status IN ('failed', 'uncertain') AND "
        "(NEW.error_code IS NULL OR length(NEW.error_code) = 0)) THEN "
        "RAISE EXCEPTION 'model projection transition rejected' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_model_projection_transition_guard() FROM PUBLIC"
    )
    op.execute(
        f"CREATE TRIGGER model_projection_transition_guard BEFORE UPDATE ON {_OPERATIONS} "
        "FOR EACH ROW EXECUTE FUNCTION public.saas_model_projection_transition_guard()"
    )
    op.execute(f"GRANT SELECT ON {_OPERATIONS}, saas_model_credential_versions TO {_WORKER}")
    op.execute(
        f"GRANT UPDATE (status, error_code, version, updated_at) ON {_OPERATIONS} TO {_WORKER}"
    )
    op.execute(f"GRANT SELECT, INSERT ON {_TABLE} TO {_WORKER}")
    op.execute(
        f"GRANT SELECT ON {_TABLE} TO saas_platform_app, saas_platform, saas_platform_governance"
    )
    op.execute(f"GRANT SELECT (id, status) ON saas_platform_staff_principals TO {_WORKER}")
    op.execute(
        "GRANT SELECT (principal_id, role, status, expires_at) "
        f"ON saas_platform_role_assignments TO {_WORKER}"
    )
    # PUBLIC support policies need these columns, but expose no rows to this role.
    op.execute(
        "GRANT SELECT (principal_id, token_hash, revoked_at, expires_at) "
        f"ON saas_platform_support_sessions TO {_WORKER}"
    )
    op.execute(
        "GRANT SELECT (id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
        f"request_hash) ON saas_control_plane_outbox TO {_WORKER}"
    )


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(), nullable=False),
        sa.Column("previous_status", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(128)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("operation_id", "version"),
        sa.ForeignKeyConstraint(["operation_id"], [f"{_OPERATIONS}.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["event_id"], ["saas_control_plane_outbox.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["actor_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint("version > 1", name="ck_model_projection_transition_version"),
        sa.CheckConstraint(
            "(previous_status = 'requested' AND status IN ('applying', 'failed')) OR "
            "(previous_status = 'applying' AND status IN ('applied', 'failed', 'uncertain'))",
            name="ck_model_projection_transition_edge",
        ),
    )
    _postgresql_authority()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE")
        op.execute(f"ALTER TABLE {_TABLE} NO FORCE ROW LEVEL SECURITY")
    if bind.execute(sa.text(f"SELECT EXISTS (SELECT 1 FROM {_TABLE})")).scalar_one():
        raise RuntimeError("cannot remove model projection schema with retained receipts")
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP TRIGGER model_projection_transition_guard ON {_OPERATIONS}")
        op.execute("DROP FUNCTION public.saas_model_projection_transition_guard()")
        for policy, table in (
            ("rls_model_projection_worker_read", _OPERATIONS),
            ("rls_model_projection_worker_update", _OPERATIONS),
            ("rls_model_credential_projection_read", "saas_model_credential_versions"),
            ("rls_model_projection_actor_read", "saas_platform_staff_principals"),
            ("rls_model_projection_actor_read", "saas_platform_role_assignments"),
            ("rls_outbox_model_projection_read", "saas_control_plane_outbox"),
        ):
            op.execute(f"DROP POLICY {policy} ON {table}")
        for table in (
            _OPERATIONS,
            "saas_model_credential_versions",
            "saas_platform_staff_principals",
            "saas_platform_role_assignments",
            "saas_platform_support_sessions",
            "saas_control_plane_outbox",
        ):
            op.execute(f"REVOKE ALL ON {table} FROM {_WORKER}")
            columns = [column["name"] for column in sa.inspect(bind).get_columns(table)]
            quoted = ", ".join(bind.dialect.identifier_preparer.quote(c) for c in columns)
            for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
                op.execute(f"REVOKE {privilege} ({quoted}) ON {table} FROM {_WORKER}")
    op.drop_table(_TABLE)
