"""Retain priced verification commands, real budget bindings, and protocol receipts.

Revision ID: lm1f00000001
Revises: lm1e00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64

revision: str = "lm1f00000001"
down_revision: str | None = "lm1e00000001"
branch_labels: str | None = None
depends_on: str | None = None

_OPS = "saas_model_projection_operations"
_COMMANDS = "saas_model_verification_commands"
_BINDINGS = "saas_model_verification_budget_bindings"
_RECEIPTS = "saas_model_verification_receipts"
_BUDGETS = "saas_model_provider_budget_reservations"
_OUTBOX = "saas_control_plane_outbox"
_WORKER = "saas_model_projection"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_BUDGET_COLUMNS = (
    "id, purpose, test_operation_id, test_configuration_sha256, test_policy_version, "
    "status, outcome_evidence_sha256, settled_microusd, settled_tokens"
)


def _operation_constraints(*, verification: bool) -> None:
    actions = "'create_connection', 'rotate_credential', 'create_deployment'"
    deployments = "action = 'create_deployment'"
    terminal = "'applied', 'failed', 'uncertain'"
    if verification:
        actions += ", 'verify_deployment'"
        deployments = "action IN ('create_deployment', 'verify_deployment')"
        terminal = "'applied', 'verified', 'failed', 'uncertain'"
    with op.batch_alter_table(_OPS) as batch:
        batch.drop_constraint("ck_model_projection_action", type_="check")
        batch.create_check_constraint("ck_model_projection_action", f"action IN ({actions})")
        batch.drop_constraint("ck_model_projection_deployment_scope", type_="check")
        batch.create_check_constraint(
            "ck_model_projection_deployment_scope",
            "(action IN ('create_connection', 'rotate_credential') "
            "AND deployment_version_id IS NULL) OR "
            + f"({deployments} AND deployment_version_id IS NOT NULL)",
        )
    with op.batch_alter_table("saas_model_projection_transitions") as batch:
        batch.drop_constraint("ck_model_projection_transition_edge", type_="check")
        batch.create_check_constraint(
            "ck_model_projection_transition_edge",
            "(previous_status = 'requested' AND status IN ('applying', 'failed')) OR "
            + f"(previous_status = 'applying' AND status IN ({terminal}))",
        )


def _guard(*, verification: bool) -> None:
    terminal = (
        "'applied', 'verified', 'failed', 'uncertain'"
        if verification
        else "'applied', 'failed', 'uncertain'"
    )
    success = "'applying', 'applied', 'verified'" if verification else "'applying', 'applied'"
    financial = (
        "IF NEW.status = 'verified' AND (NEW.action <> 'verify_deployment' OR NOT EXISTS ("
        f"SELECT 1 FROM public.{_RECEIPTS} receipt "
        f"JOIN public.{_BUDGETS} budget ON budget.id = receipt.budget_reservation_id "
        "WHERE receipt.operation_id = NEW.id AND receipt.outcome = 'passed' "
        "AND budget.purpose = 'platform_test' AND budget.test_operation_id = NEW.id "
        "AND budget.status = 'settled' AND budget.settled_microusd = receipt.actual_microusd "
        "AND budget.settled_tokens = "
        "(receipt.canonical_evidence::jsonb->'usage'->>'total_tokens')::bigint "
        "AND budget.outcome_evidence_sha256 = receipt.evidence_sha256)) THEN "
        "RAISE EXCEPTION 'model verification settlement rejected' USING ERRCODE = '23514'; "
        "END IF; IF NEW.action = 'verify_deployment' AND NEW.status = 'applied' THEN "
        "RAISE EXCEPTION 'model verification transition rejected' USING ERRCODE = '23514'; "
        "END IF; "
        if verification
        else ""
    )
    op.execute(
        "CREATE OR REPLACE FUNCTION public.saas_model_projection_transition_guard() "
        "RETURNS trigger "
        "LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ BEGIN "
        "IF NEW.version <> OLD.version + 1 OR NOT ("
        "(OLD.status = 'requested' AND NEW.status IN ('applying', 'failed')) OR "
        f"(OLD.status = 'applying' AND NEW.status IN ({terminal}))) "
        f"OR (NEW.status IN ({success}) AND NEW.error_code IS NOT NULL) "
        "OR (NEW.status IN ('failed', 'uncertain') AND "
        "(NEW.error_code IS NULL OR length(NEW.error_code) = 0)) THEN "
        "RAISE EXCEPTION 'model projection transition rejected' USING ERRCODE = '23514'; "
        f"END IF; {financial}RETURN NEW; END $$"
    )


def _tables() -> None:
    op.create_table(
        _COMMANDS,
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_price", sa.Text(), nullable=False),
        sa.Column("price_sha256", sa.String(64), nullable=False),
        sa.Column("pricing_revision", sa.String(32), nullable=False),
        sa.Column("funding_policy_version", sa.Integer(), nullable=False),
        sa.Column("requested_microusd", sa.BigInteger(), nullable=False),
        sa.Column("requested_tokens", sa.Integer(), nullable=False),
        sa.Column("output_token_limit", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.ForeignKeyConstraint(["operation_id"], [f"{_OPS}.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["provider_id", "funding_policy_version"],
            [
                "saas_model_test_funding_policies.provider_id",
                "saas_model_test_funding_policies.version",
            ],
            name="fk_model_verification_funding",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "operation_id",
            "configuration_sha256",
            "funding_policy_version",
            name="uq_model_verification_command_scope",
        ),
        sa.CheckConstraint(
            "provider_id = 'deepseek' AND funding_policy_version > 0",
            name="ck_model_verification_funding",
        ),
        sa.CheckConstraint(
            _hex64("configuration_sha256") + " AND " + _hex64("price_sha256"),
            name="ck_model_verification_command_hashes",
        ),
        sa.CheckConstraint(
            "requested_microusd > 0 AND requested_tokens BETWEEN 1 AND 1056 "
            "AND output_token_limit BETWEEN 1 AND 32 "
            "AND length(canonical_price) BETWEEN 1 AND 8192 "
            "AND length(pricing_revision) BETWEEN 1 AND 32",
            name="ck_model_verification_command_bounds",
        ),
    )
    with op.batch_alter_table(_BUDGETS) as batch:
        batch.create_unique_constraint(
            "uq_model_budget_verification_binding",
            ["test_operation_id", "id", "test_configuration_sha256", "test_policy_version"],
        )
    op.create_table(
        _BINDINGS,
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("budget_reservation_id", sa.Uuid(), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("funding_policy_version", sa.Integer(), nullable=False),
        sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.UniqueConstraint("budget_reservation_id"),
        sa.ForeignKeyConstraint(
            ["operation_id", "configuration_sha256", "funding_policy_version"],
            [
                f"{_COMMANDS}.operation_id",
                f"{_COMMANDS}.configuration_sha256",
                f"{_COMMANDS}.funding_policy_version",
            ],
            name="fk_model_verification_binding_command",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            [
                "operation_id",
                "budget_reservation_id",
                "configuration_sha256",
                "funding_policy_version",
            ],
            [
                f"{_BUDGETS}.test_operation_id",
                f"{_BUDGETS}.id",
                f"{_BUDGETS}.test_configuration_sha256",
                f"{_BUDGETS}.test_policy_version",
            ],
            name="fk_model_verification_binding_budget",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "operation_id", "budget_reservation_id", name="uq_model_verification_budget_binding"
        ),
    )
    op.create_table(
        _RECEIPTS,
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("budget_reservation_id", sa.Uuid(), nullable=True),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("actual_microusd", sa.BigInteger(), nullable=True),
        sa.Column("request_attempts", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("canonical_evidence", sa.Text(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.UniqueConstraint("evidence_sha256"),
        sa.ForeignKeyConstraint(
            ["operation_id"], [f"{_COMMANDS}.operation_id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["operation_id", "budget_reservation_id"],
            [f"{_BINDINGS}.operation_id", f"{_BINDINGS}.budget_reservation_id"],
            name="fk_model_verification_receipt_budget",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "request_attempts IN (0, 1) "
            "AND (actual_microusd IS NULL OR actual_microusd >= 0) "
            "AND length(canonical_evidence) BETWEEN 1 AND 8192",
            name="ck_model_verification_receipt_bounds",
        ),
        sa.CheckConstraint(
            "(outcome = 'passed' AND error_code IS NULL AND request_attempts = 1 "
            "AND actual_microusd IS NOT NULL AND actual_microusd > 0 "
            "AND budget_reservation_id IS NOT NULL) OR "
            "(outcome IN ('failed', 'uncertain') AND error_code IS NOT NULL "
            "AND length(error_code) > 0)",
            name="ck_model_verification_receipt_outcome",
        ),
        sa.CheckConstraint(_hex64("evidence_sha256"), name="ck_model_verification_receipt_hash"),
    )


def _authority() -> None:
    for table in (_COMMANDS, _BINDINGS, _RECEIPTS):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY rls_model_verification_read ON {table} "
            "FOR SELECT TO saas_platform_app USING (EXISTS ("
            f"SELECT 1 FROM {_OPS} operation WHERE operation.id = {table}.operation_id))"
        )
        op.execute(
            f"CREATE POLICY rls_model_verification_worker_read ON {table} "
            f"FOR SELECT TO {_WORKER} USING (true)"
        )
        op.execute(
            f"CREATE POLICY rls_model_verification_recovery ON {table} "
            "FOR SELECT TO saas_platform, saas_platform_governance USING (true)"
        )
        status = (
            "operation.status = 'requested'"
            if table == _COMMANDS
            else "operation.status = 'applying'"
            if table == _BINDINGS
            else "operation.status IN ('applying', 'uncertain')"
        )
        role = "saas_platform_app" if table == _COMMANDS else _WORKER
        actor = f" AND operation.actor_principal_id = {_PRINCIPAL}" if table == _COMMANDS else ""
        expiry = (
            f" AND {table}.expires_at > operation.created_at "
            f"AND {table}.expires_at <= operation.created_at + interval '5 minutes'"
            if table == _COMMANDS
            else ""
        )
        op.execute(
            f"CREATE POLICY rls_model_verification_insert ON {table} "
            f"FOR INSERT TO {role} WITH CHECK (EXISTS (SELECT 1 FROM {_OPS} operation "
            f"WHERE operation.id = {table}.operation_id "
            f"AND operation.action = 'verify_deployment' AND {status}{actor}{expiry}))"
        )
        op.execute(
            f"GRANT SELECT ON {table} TO saas_platform_app, {_WORKER}, "
            "saas_platform, saas_platform_governance"
        )
        op.execute(f"GRANT INSERT ON {table} TO {role}")
    op.execute(
        f"CREATE POLICY rls_model_verification_budget_read ON {_BUDGETS} "
        f"FOR SELECT TO {_WORKER} USING (purpose = 'platform_test' "
        f"AND EXISTS (SELECT 1 FROM {_BINDINGS} binding "
        f"WHERE binding.operation_id = {_BUDGETS}.test_operation_id "
        f"AND binding.budget_reservation_id = {_BUDGETS}.id))"
    )
    op.execute(f"GRANT SELECT ({_BUDGET_COLUMNS}) ON {_BUDGETS} TO {_WORKER}")
    op.execute(
        "CREATE POLICY rls_model_verification_deployment_read "
        "ON saas_model_deployment_versions FOR SELECT TO saas_model_projection "
        f"USING (EXISTS (SELECT 1 FROM {_OPS} operation "
        "WHERE operation.deployment_version_id = saas_model_deployment_versions.id "
        "AND operation.action = 'verify_deployment'))"
    )
    op.execute(f"DROP POLICY rls_model_projection_worker_update ON {_OPS}")
    op.execute(
        f"CREATE POLICY rls_model_projection_worker_update ON {_OPS} "
        f"FOR UPDATE TO {_WORKER} USING (true) "
        "WITH CHECK (status IN ('applying', 'applied', 'verified', 'failed', 'uncertain'))"
    )
    envelope = (
        "tenant_id IS NULL AND aggregate_type = 'platform_model' "
        "AND event_type = 'platform.model_verification.requested' "
        "AND payload->>'event_type' = event_type "
        "AND (payload->'schema_version')::jsonb = '1'::jsonb "
        "AND payload::jsonb - ARRAY['event_type', 'operation_id', "
        "'credential_version_id', 'schema_version']::text[] = '{}'::jsonb "
        f"AND EXISTS (SELECT 1 FROM {_OPS} operation JOIN {_COMMANDS} command "
        "ON command.operation_id = operation.id WHERE operation.id::text = aggregate_key "
        "AND operation.id::text = payload->>'operation_id' "
        "AND operation.credential_version_id::text = payload->>'credential_version_id' "
        "AND operation.action = 'verify_deployment' "
        "AND operation.request_hash = saas_control_plane_outbox.request_hash"
    )
    op.execute(
        f"CREATE POLICY rls_outbox_model_verification_insert ON {_OUTBOX} "
        f"FOR INSERT TO saas_platform_app WITH CHECK ({envelope} "
        f"AND operation.actor_principal_id = {_PRINCIPAL} "
        "AND operation.status = 'requested'))"
    )
    op.execute(
        f"CREATE POLICY rls_outbox_model_verification_read ON {_OUTBOX} "
        f"FOR SELECT TO {_WORKER} USING ({envelope}))"
    )
    _guard(verification=True)


def upgrade() -> None:
    _tables()
    _operation_constraints(verification=True)
    if op.get_bind().dialect.name == "postgresql":
        _authority()


def downgrade() -> None:
    bind = op.get_bind()
    tables = (_RECEIPTS, _BINDINGS, _COMMANDS, _OPS)
    if bind.dialect.name == "postgresql":
        op.execute("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE")
        for table in tables:
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    if bind.execute(
        sa.text(
            f"SELECT EXISTS (SELECT 1 FROM {_OPS} WHERE action = 'verify_deployment') "
            f"OR EXISTS (SELECT 1 FROM {_COMMANDS})"
        )
    ).scalar_one():
        raise RuntimeError("cannot remove retained model verification evidence")
    if bind.dialect.name == "postgresql":
        for table in tables:
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY rls_outbox_model_verification_insert ON {_OUTBOX}")
        op.execute(f"DROP POLICY rls_outbox_model_verification_read ON {_OUTBOX}")
        op.execute(f"DROP POLICY rls_model_verification_budget_read ON {_BUDGETS}")
        op.execute(
            "DROP POLICY rls_model_verification_deployment_read ON saas_model_deployment_versions"
        )
        op.execute(f"REVOKE SELECT ({_BUDGET_COLUMNS}) ON {_BUDGETS} FROM {_WORKER}")
        op.execute(f"DROP POLICY rls_model_projection_worker_update ON {_OPS}")
        op.execute(
            f"CREATE POLICY rls_model_projection_worker_update ON {_OPS} "
            f"FOR UPDATE TO {_WORKER} USING (true) "
            "WITH CHECK (status IN ('applying', 'applied', 'failed', 'uncertain'))"
        )
        _guard(verification=False)
    for table in (_RECEIPTS, _BINDINGS, _COMMANDS):
        op.drop_table(table)
    with op.batch_alter_table(_BUDGETS) as batch:
        batch.drop_constraint("uq_model_budget_verification_binding", type_="unique")
    _operation_constraints(verification=False)
