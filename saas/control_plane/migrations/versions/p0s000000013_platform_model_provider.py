"""Add governed Platform model Provider configuration and receipts.

Revision ID: p0s000000013
Revises: p0s000000012
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000013"
down_revision: str | None = "p0s000000012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONFIGURATION = "saas_model_provider_configurations"
_RECEIPTS = "saas_model_provider_configuration_receipts"
_MONTHLY_BUDGETS = "saas_model_provider_monthly_budgets"
_TENANT_DAILY_USAGE = "saas_model_provider_tenant_daily_usage"
_BUDGET_RESERVATIONS = "saas_model_provider_budget_reservations"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_APP = "pg_has_role(current_user, 'saas_platform_app', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_SECRET_BROKER = "pg_has_role(current_user, 'saas_secret_broker', 'member')"
_BILLING = "pg_has_role(current_user, 'saas_billing', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _active_assignment(*roles: str) -> str:
    allowed = ", ".join(f"'{role}'" for role in roles)
    return (
        "EXISTS (SELECT 1 FROM saas_platform_role_assignments model_assignment "
        f"WHERE model_assignment.principal_id = {_PRINCIPAL} "
        f"AND model_assignment.role IN ({allowed}) "
        "AND model_assignment.status = 'active' "
        "AND (model_assignment.expires_at IS NULL "
        "OR model_assignment.expires_at > CURRENT_TIMESTAMP))"
    )


def _create_tables() -> None:
    op.create_table(
        _CONFIGURATION,
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("api_type", sa.String(64), nullable=False),
        sa.Column("api_key_ciphertext", sa.Text(), nullable=False),
        sa.Column("allowed_models", sa.JSON(), nullable=False),
        sa.Column("default_model", sa.String(128), nullable=False),
        sa.Column("monthly_budget_microusd", sa.BigInteger(), nullable=False),
        sa.Column("per_tenant_daily_token_limit", sa.BigInteger(), nullable=False),
        sa.Column("verification_status", sa.String(16), nullable=False),
        sa.Column("last_verified_model", sa.String(128)),
        sa.Column("last_verified_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_id IN ('deepseek')",
            name="ck_model_provider_configuration_provider",
        ),
        sa.CheckConstraint(
            "api_type IN ('openai_chat_completions')",
            name="ck_model_provider_configuration_api_type",
        ),
        sa.CheckConstraint(
            "verification_status IN ('never', 'verified', 'failed')",
            name="ck_model_provider_configuration_verification",
        ),
        sa.CheckConstraint(
            "length(base_url) > 0 AND length(api_key_ciphertext) > 0 "
            "AND length(default_model) > 0",
            name="ck_model_provider_configuration_required_values",
        ),
        sa.CheckConstraint(
            "monthly_budget_microusd > 0",
            name="ck_model_provider_configuration_monthly_budget",
        ),
        sa.CheckConstraint(
            "per_tenant_daily_token_limit > 0",
            name="ck_model_provider_configuration_tenant_tokens",
        ),
        sa.CheckConstraint(
            "version > 0",
            name="ck_model_provider_configuration_version",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("provider_id"),
    )
    op.create_table(
        _RECEIPTS,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("configuration_version", sa.Integer(), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("configuration_hash", sa.String(64), nullable=False),
        sa.Column("api_key_rotated", sa.Boolean(), nullable=False),
        sa.Column("model_id", sa.String(128)),
        sa.Column("provider_request_id_hash", sa.String(64)),
        sa.Column("latency_millis", sa.Integer()),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_id IN ('deepseek')",
            name="ck_model_provider_receipt_provider",
        ),
        sa.CheckConstraint(
            "action IN ('configured', 'disabled', 'verification_succeeded', "
            "'verification_failed')",
            name="ck_model_provider_receipt_action",
        ),
        sa.CheckConstraint(
            "configuration_version > 0",
            name="ck_model_provider_receipt_version",
        ),
        sa.CheckConstraint(
            "length(configuration_hash) = 64",
            name="ck_model_provider_receipt_hash",
        ),
        sa.CheckConstraint(
            "provider_request_id_hash IS NULL OR length(provider_request_id_hash) = 64",
            name="ck_model_provider_receipt_request_hash",
        ),
        sa.CheckConstraint(
            "latency_millis IS NULL OR latency_millis >= 0",
            name="ck_model_provider_receipt_latency",
        ),
        sa.ForeignKeyConstraint(
            ["actor_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_model_provider_receipt_provider_time",
        _RECEIPTS,
        ("provider_id", "occurred_at", "id"),
    )
    op.create_table(
        _MONTHLY_BUDGETS,
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("reserved_microusd", sa.BigInteger(), nullable=False),
        sa.Column("settled_microusd", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_id IN ('deepseek')",
            name="ck_model_provider_monthly_budget_provider",
        ),
        sa.CheckConstraint(
            "reserved_microusd >= 0 AND settled_microusd >= 0",
            name="ck_model_provider_monthly_budget_nonnegative",
        ),
        sa.CheckConstraint("version > 0", name="ck_model_provider_monthly_budget_version"),
        sa.PrimaryKeyConstraint("provider_id", "period_start"),
    )
    op.create_table(
        _TENANT_DAILY_USAGE,
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("usage_date", sa.Date(), nullable=False),
        sa.Column("reserved_tokens", sa.BigInteger(), nullable=False),
        sa.Column("settled_tokens", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_id IN ('deepseek')",
            name="ck_model_provider_tenant_usage_provider",
        ),
        sa.CheckConstraint(
            "reserved_tokens >= 0 AND settled_tokens >= 0",
            name="ck_model_provider_tenant_usage_nonnegative",
        ),
        sa.CheckConstraint("version > 0", name="ck_model_provider_tenant_usage_version"),
        sa.PrimaryKeyConstraint("tenant_id", "provider_id", "usage_date"),
    )
    op.create_index(
        "ix_model_provider_tenant_usage_date",
        _TENANT_DAILY_USAGE,
        ("provider_id", "usage_date", "tenant_id"),
    )
    op.create_table(
        _BUDGET_RESERVATIONS,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("operation_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("configuration_version", sa.Integer(), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("usage_date", sa.Date(), nullable=False),
        sa.Column("requested_microusd", sa.BigInteger(), nullable=False),
        sa.Column("requested_tokens", sa.BigInteger(), nullable=False),
        sa.Column("admitted_microusd", sa.BigInteger(), nullable=False),
        sa.Column("admitted_tokens", sa.BigInteger(), nullable=False),
        sa.Column("settled_microusd", sa.BigInteger(), nullable=False),
        sa.Column("settled_tokens", sa.BigInteger(), nullable=False),
        sa.Column("released_microusd", sa.BigInteger(), nullable=False),
        sa.Column("released_tokens", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("rejection_code", sa.String(64)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "provider_id IN ('deepseek')",
            name="ck_model_provider_budget_reservation_provider",
        ),
        sa.CheckConstraint(
            "status IN ('reserved', 'settled', 'released', 'rejected', 'expired')",
            name="ck_model_provider_budget_reservation_status",
        ),
        sa.CheckConstraint(
            "requested_microusd > 0 AND requested_tokens > 0",
            name="ck_model_provider_budget_reservation_request",
        ),
        sa.CheckConstraint(
            "admitted_microusd >= 0 AND admitted_microusd <= requested_microusd "
            "AND admitted_tokens >= 0 AND admitted_tokens <= requested_tokens",
            name="ck_model_provider_budget_reservation_admitted",
        ),
        sa.CheckConstraint(
            "settled_microusd >= 0 AND released_microusd >= 0 "
            "AND settled_tokens >= 0 AND released_tokens >= 0 "
            "AND ((status = 'reserved' AND released_microusd = 0 "
            "AND released_tokens = 0 AND settled_microusd <= admitted_microusd "
            "AND settled_tokens <= admitted_tokens) "
            "OR (status <> 'reserved' "
            "AND settled_microusd + released_microusd = admitted_microusd "
            "AND settled_tokens + released_tokens = admitted_tokens))",
            name="ck_model_provider_budget_reservation_conservation",
        ),
        sa.CheckConstraint(
            "(status = 'reserved' AND admitted_microusd = requested_microusd "
            "AND admitted_tokens = requested_tokens "
            "AND released_microusd = 0 AND released_tokens = 0 "
            "AND rejection_code IS NULL) OR "
            "(status = 'settled' AND settled_microusd > 0 AND settled_tokens > 0 "
            "AND rejection_code IS NULL) OR "
            "(status IN ('released', 'expired') AND admitted_microusd > 0 "
            "AND admitted_tokens > 0 "
            "AND rejection_code IS NULL) OR "
            "(status = 'rejected' AND admitted_microusd = 0 AND admitted_tokens = 0 "
            "AND rejection_code IS NOT NULL)",
            name="ck_model_provider_budget_reservation_state",
        ),
        sa.CheckConstraint(
            "length(operation_key) > 0 AND length(request_hash) = 64",
            name="ck_model_provider_budget_reservation_identity",
        ),
        sa.CheckConstraint(
            "configuration_version > 0 AND version > 0",
            name="ck_model_provider_budget_reservation_version",
        ),
        sa.CheckConstraint(
            "created_at <= updated_at AND created_at < expires_at",
            name="ck_model_provider_budget_reservation_time",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider_id",
            "operation_key",
            name="uq_model_provider_budget_reservation_operation",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_model_provider_budget_reservation_scope",
        ),
    )
    op.create_index(
        "ix_model_provider_budget_reservation_expiry",
        _BUDGET_RESERVATIONS,
        ("provider_id", "status", "expires_at", "id"),
    )
    op.create_index(
        "ix_model_provider_budget_reservation_run",
        _BUDGET_RESERVATIONS,
        ("tenant_id", "run_id", "id"),
    )
    with op.batch_alter_table("saas_billing_metering_receipts") as batch_op:
        batch_op.add_column(
            sa.Column("model_budget_reservation_id", sa.Uuid(), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_billing_metering_receipt_model_budget",
            _BUDGET_RESERVATIONS,
            ["tenant_id", "model_budget_reservation_id"],
            ["tenant_id", "id"],
            ondelete="RESTRICT",
        )


def _create_postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in (
        _CONFIGURATION,
        _RECEIPTS,
        _MONTHLY_BUDGETS,
        _TENANT_DAILY_USAGE,
        _BUDGET_RESERVATIONS,
    ):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    app_read = (
        f"({_APP} AND {_PRINCIPAL} IS NOT NULL AND "
        f"{_active_assignment('platform_operator', 'platform_security_auditor')})"
    )
    app_write = (
        f"({_APP} AND {_PRINCIPAL} IS NOT NULL AND {_active_assignment('platform_operator')})"
    )
    recovery = f"({_EMERGENCY} OR {_GOVERNANCE})"
    config_write = f"({app_write} AND updated_by_principal_id = {_PRINCIPAL})"
    receipt_insert = f"({app_write} AND actor_principal_id = {_PRINCIPAL})"
    op.execute(
        'CREATE POLICY "rls_model_provider_configuration_app_read" '
        f"ON {_CONFIGURATION} FOR SELECT TO saas_platform_app USING ({app_read})"
    )
    op.execute(
        'CREATE POLICY "rls_model_provider_configuration_runtime_read" '
        f"ON {_CONFIGURATION} FOR SELECT TO saas_secret_broker USING ({_SECRET_BROKER})"
    )
    op.execute(
        'CREATE POLICY "rls_model_provider_configuration_billing_read" '
        f"ON {_CONFIGURATION} FOR SELECT TO saas_billing USING ({_BILLING})"
    )
    op.execute(
        'CREATE POLICY "rls_model_provider_configuration_app_insert" '
        f"ON {_CONFIGURATION} FOR INSERT TO saas_platform_app WITH CHECK ({config_write})"
    )
    op.execute(
        'CREATE POLICY "rls_model_provider_configuration_app_update" '
        f"ON {_CONFIGURATION} FOR UPDATE TO saas_platform_app "
        f"USING ({app_write}) WITH CHECK ({config_write})"
    )
    op.execute(
        'CREATE POLICY "rls_model_provider_configuration_recovery" '
        f"ON {_CONFIGURATION} FOR ALL TO saas_platform, saas_platform_governance "
        f"USING ({recovery}) WITH CHECK ({recovery})"
    )
    op.execute(
        'CREATE POLICY "rls_model_provider_receipt_app_read" '
        f"ON {_RECEIPTS} FOR SELECT TO saas_platform_app USING ({app_read})"
    )
    op.execute(
        'CREATE POLICY "rls_model_provider_receipt_app_insert" '
        f"ON {_RECEIPTS} FOR INSERT TO saas_platform_app WITH CHECK ({receipt_insert})"
    )
    op.execute(
        'CREATE POLICY "rls_model_provider_receipt_recovery" '
        f"ON {_RECEIPTS} FOR ALL TO saas_platform, saas_platform_governance "
        f"USING ({recovery}) WITH CHECK ({recovery})"
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_CONFIGURATION} TO saas_platform_app")
    op.execute(f"GRANT SELECT, INSERT ON {_RECEIPTS} TO saas_platform_app")
    op.execute(f"GRANT SELECT ON {_CONFIGURATION} TO saas_secret_broker")
    op.execute(
        f"GRANT SELECT (provider_id, enabled, monthly_budget_microusd, "
        f"per_tenant_daily_token_limit, verification_status, version) "
        f"ON {_CONFIGURATION} TO saas_billing"
    )
    for table in (_MONTHLY_BUDGETS, _TENANT_DAILY_USAGE, _BUDGET_RESERVATIONS):
        op.execute(
            f'CREATE POLICY "rls_{table.removeprefix("saas_")}_billing" '
            f"ON {table} FOR ALL TO saas_billing USING ({_BILLING}) WITH CHECK ({_BILLING})"
        )
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON {table} TO saas_billing")
        op.execute(
            f'CREATE POLICY "rls_{table.removeprefix("saas_")}_recovery" '
            f"ON {table} FOR ALL TO saas_platform, saas_platform_governance "
            f"USING ({recovery}) WITH CHECK ({recovery})"
        )
    for role in ("saas_platform_governance", "saas_platform"):
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_CONFIGURATION} TO {role}")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_RECEIPTS} TO {role}")
        for table in (_MONTHLY_BUDGETS, _TENANT_DAILY_USAGE, _BUDGET_RESERVATIONS):
            op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {role}")
    op.execute(
        """
        CREATE FUNCTION saas_apply_model_provider_budget_usage(
            p_reservation_id uuid,
            p_tenant_id uuid,
            p_run_id uuid,
            p_actual_microusd bigint,
            p_actual_tokens bigint
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            changed integer;
        BEGIN
            IF p_actual_microusd <= 0 OR p_actual_tokens <= 0
               OR NULLIF(current_setting('app.model_budget_reservation_id', true), '')::uuid
                    IS DISTINCT FROM p_reservation_id
               OR NULLIF(current_setting('app.metering_tenant_id', true), '')::uuid
                    IS DISTINCT FROM p_tenant_id
               OR NULLIF(current_setting('app.metering_run_id', true), '')::uuid
                    IS DISTINCT FROM p_run_id THEN
                RAISE EXCEPTION 'model budget metering context is invalid'
                    USING ERRCODE = '42501';
            END IF;

            UPDATE public.saas_model_provider_budget_reservations
            SET settled_microusd = settled_microusd + p_actual_microusd,
                settled_tokens = settled_tokens + p_actual_tokens,
                updated_at = GREATEST(updated_at, CURRENT_TIMESTAMP),
                version = version + 1
            WHERE id = p_reservation_id
              AND provider_id = 'deepseek'
              AND tenant_id = p_tenant_id
              AND run_id = p_run_id
              AND status = 'reserved'
              AND expires_at > CURRENT_TIMESTAMP
              AND settled_microusd + p_actual_microusd <= admitted_microusd
              AND settled_tokens + p_actual_tokens <= admitted_tokens;
            GET DIAGNOSTICS changed = ROW_COUNT;
            IF changed <> 1 THEN
                RAISE EXCEPTION 'model budget reservation is unavailable or exhausted'
                    USING ERRCODE = '42501';
            END IF;
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "saas_apply_model_provider_budget_usage(uuid, uuid, uuid, bigint, bigint) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION "
        "saas_apply_model_provider_budget_usage(uuid, uuid, uuid, bigint, bigint) "
        "TO saas_metering"
    )


def upgrade() -> None:
    _create_tables()
    _create_postgresql_authority()


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP FUNCTION IF EXISTS "
            "saas_apply_model_provider_budget_usage(uuid, uuid, uuid, bigint, bigint)"
        )
    with op.batch_alter_table("saas_billing_metering_receipts") as batch_op:
        batch_op.drop_constraint(
            "fk_billing_metering_receipt_model_budget",
            type_="foreignkey",
        )
        batch_op.drop_column("model_budget_reservation_id")
    op.drop_table(_BUDGET_RESERVATIONS)
    op.drop_table(_TENANT_DAILY_USAGE)
    op.drop_table(_MONTHLY_BUDGETS)
    op.drop_table(_RECEIPTS)
    op.drop_table(_CONFIGURATION)
