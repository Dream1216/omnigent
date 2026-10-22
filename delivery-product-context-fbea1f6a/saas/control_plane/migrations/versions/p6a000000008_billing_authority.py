"""Create P6 metering, entitlement, ledger, and reconciliation authority.

Revision ID: p6a000000008
Revises: p6a000000007
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "p6a000000008"
down_revision: str | None = "p6a000000007"
branch_labels: str | None = None
depends_on: str | None = None

_TABLES = (
    "saas_billing_subscriptions",
    "saas_pricing_snapshots",
    "saas_billing_entitlements",
    "saas_usage_events",
    "saas_billing_balances",
    "saas_billing_reservations",
    "saas_customer_ledger_entries",
    "saas_provider_cost_entries",
    "saas_billing_reconciliation_batches",
    "saas_billing_reconciliation_mismatches",
)
_IMMUTABLE_TABLES = (
    "saas_pricing_snapshots",
    "saas_usage_events",
    "saas_customer_ledger_entries",
    "saas_provider_cost_entries",
    "saas_billing_reconciliation_batches",
)


def _timestamps(*, updated: bool = False) -> tuple[sa.Column[Any], ...]:
    columns: tuple[sa.Column[Any], ...] = (
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    if updated:
        columns += (
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
        )
    return columns


def _create_subscription() -> None:
    op.create_table(
        "saas_billing_subscriptions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("plan_key", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column("provider_customer_ref", sa.String(length=256), nullable=True),
        sa.Column("provider_subscription_ref", sa.String(length=256), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trial_ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False),
        sa.Column("provider_event_cursor", sa.String(length=256), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        *_timestamps(updated=True),
        sa.CheckConstraint("length(plan_key) > 0", name="ck_billing_subscription_plan"),
        sa.CheckConstraint(
            "status IN ('trialing', 'active', 'past_due', 'suspended', 'canceled')",
            name="ck_billing_subscription_status",
        ),
        sa.CheckConstraint(
            "current_period_end > current_period_start",
            name="ck_billing_subscription_period",
        ),
        sa.CheckConstraint("version > 0", name="ck_billing_subscription_version"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "updated_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_billing_subscription_actor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", name="uq_billing_subscription_tenant"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_subscription_scope"),
        sa.UniqueConstraint(
            "provider", "provider_subscription_ref", name="uq_billing_provider_subscription"
        ),
    )


def _create_pricing() -> None:
    op.create_table(
        "saas_pricing_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("plan_key", sa.String(length=128), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("rates", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint("length(plan_key) > 0", name="ck_pricing_snapshot_plan"),
        sa.CheckConstraint("length(currency) = 3", name="ck_pricing_snapshot_currency"),
        sa.CheckConstraint("version > 0", name="ck_pricing_snapshot_version"),
        sa.CheckConstraint(
            "effective_until IS NULL OR effective_until > effective_from",
            name="ck_pricing_snapshot_window",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "created_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_pricing_snapshot_actor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_pricing_snapshot_scope"),
        sa.UniqueConstraint("tenant_id", "version", name="uq_pricing_snapshot_version"),
    )
    op.create_index(
        "ix_pricing_snapshot_effective",
        "saas_pricing_snapshots",
        ["tenant_id", "plan_key", "effective_from", "effective_until"],
    )


def _create_entitlement() -> None:
    op.create_table(
        "saas_billing_entitlements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("subscription_id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.String(length=16), nullable=False),
        sa.Column("scope_key", sa.String(length=256), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=True),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("model_key", sa.String(length=256), nullable=True),
        sa.Column("meter", sa.String(length=128), nullable=False),
        sa.Column("unit", sa.String(length=64), nullable=False),
        sa.Column("limit_quantity", sa.Numeric(38, 12), nullable=True),
        sa.Column("reserved_quantity", sa.Numeric(38, 12), nullable=False),
        sa.Column("consumed_quantity", sa.Numeric(38, 12), nullable=False),
        sa.Column("concurrency_limit", sa.Integer(), nullable=True),
        sa.Column("active_reservations", sa.Integer(), nullable=False),
        sa.Column("hard_limit", sa.Boolean(), nullable=False),
        sa.Column("period", sa.String(length=16), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        *_timestamps(updated=True),
        sa.CheckConstraint(
            "scope_type IN ('tenant', 'space', 'project', 'user', 'model')",
            name="ck_billing_entitlement_scope_type",
        ),
        sa.CheckConstraint(
            "period IN ('none', 'day', 'month')", name="ck_billing_entitlement_period"
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'expired')",
            name="ck_billing_entitlement_status",
        ),
        sa.CheckConstraint("length(scope_key) > 0", name="ck_billing_entitlement_scope_key"),
        sa.CheckConstraint("length(meter) > 0", name="ck_billing_entitlement_meter"),
        sa.CheckConstraint("length(unit) > 0", name="ck_billing_entitlement_unit"),
        sa.CheckConstraint(
            "limit_quantity IS NULL OR limit_quantity > 0",
            name="ck_billing_entitlement_limit",
        ),
        sa.CheckConstraint(
            "reserved_quantity >= 0 AND consumed_quantity >= 0",
            name="ck_billing_entitlement_counters",
        ),
        sa.CheckConstraint(
            "concurrency_limit IS NULL OR concurrency_limit > 0",
            name="ck_billing_entitlement_concurrency",
        ),
        sa.CheckConstraint("active_reservations >= 0", name="ck_billing_entitlement_active"),
        sa.CheckConstraint("version > 0", name="ck_billing_entitlement_version"),
        sa.CheckConstraint(
            "period_end IS NULL OR period_end > period_start",
            name="ck_billing_entitlement_window",
        ),
        sa.CheckConstraint(
            "(scope_type = 'tenant' AND space_id IS NULL AND project_id IS NULL "
            "AND user_id IS NULL AND model_key IS NULL) OR "
            "(scope_type = 'space' AND space_id IS NOT NULL AND project_id IS NULL "
            "AND user_id IS NULL AND model_key IS NULL) OR "
            "(scope_type = 'project' AND space_id IS NOT NULL AND project_id IS NOT NULL "
            "AND user_id IS NULL AND model_key IS NULL) OR "
            "(scope_type = 'user' AND space_id IS NULL AND project_id IS NULL "
            "AND user_id IS NOT NULL AND model_key IS NULL) OR "
            "(scope_type = 'model' AND space_id IS NULL AND project_id IS NULL "
            "AND user_id IS NULL AND model_key IS NOT NULL)",
            name="ck_billing_entitlement_scope_shape",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "subscription_id"],
            ["saas_billing_subscriptions.tenant_id", "saas_billing_subscriptions.id"],
            name="fk_billing_entitlement_subscription",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id"],
            ["saas_spaces.tenant_id", "saas_spaces.id"],
            name="fk_billing_entitlement_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id"],
            ["saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"],
            name="fk_billing_entitlement_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_billing_entitlement_user",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "updated_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_billing_entitlement_actor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_entitlement_scope"),
        sa.UniqueConstraint(
            "tenant_id",
            "scope_type",
            "scope_key",
            "meter",
            name="uq_billing_entitlement_meter_scope",
        ),
    )
    op.create_index(
        "ix_billing_entitlement_status",
        "saas_billing_entitlements",
        ["tenant_id", "status", "period_end"],
    )


def _create_usage() -> None:
    op.create_table(
        "saas_usage_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=True),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("meter", sa.String(length=128), nullable=False),
        sa.Column("quantity", sa.Numeric(38, 12), nullable=False),
        sa.Column("unit", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("provider_request_id", sa.String(length=256), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("pricing_snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("customer_charge_minor", sa.BigInteger(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(meter) > 0", name="ck_usage_event_meter"),
        sa.CheckConstraint("quantity > 0", name="ck_usage_event_quantity"),
        sa.CheckConstraint("length(unit) > 0", name="ck_usage_event_unit"),
        sa.CheckConstraint("length(provider) > 0", name="ck_usage_event_provider"),
        sa.CheckConstraint(
            "length(provider_request_id) > 0", name="ck_usage_event_provider_request"
        ),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_usage_event_idempotency"),
        sa.CheckConstraint("length(currency) = 3", name="ck_usage_event_currency"),
        sa.CheckConstraint("customer_charge_minor >= 0", name="ck_usage_event_customer_charge"),
        sa.CheckConstraint(
            "project_id IS NULL OR space_id IS NOT NULL", name="ck_usage_event_project_space"
        ),
        sa.CheckConstraint(
            "run_id IS NULL OR project_id IS NOT NULL", name="ck_usage_event_run_project"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "pricing_snapshot_id"],
            ["saas_pricing_snapshots.tenant_id", "saas_pricing_snapshots.id"],
            name="fk_usage_event_pricing",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id"],
            ["saas_spaces.tenant_id", "saas_spaces.id"],
            name="fk_usage_event_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id"],
            ["saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"],
            name="fk_usage_event_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id", "run_id"],
            ["saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id", "saas_runs.id"],
            name="fk_usage_event_run",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_usage_event_user",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_usage_event_scope"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_usage_event_idempotency"),
        sa.UniqueConstraint(
            "tenant_id",
            "provider",
            "provider_request_id",
            "meter",
            name="uq_usage_event_provider_meter",
        ),
    )
    op.create_index(
        "ix_usage_event_period", "saas_usage_events", ["tenant_id", "occurred_at", "id"]
    )
    op.create_index(
        "ix_usage_event_project",
        "saas_usage_events",
        ["tenant_id", "space_id", "project_id", "occurred_at"],
    )


def _create_balance_and_reservation() -> None:
    op.create_table(
        "saas_billing_balances",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("available_minor", sa.BigInteger(), nullable=False),
        sa.Column("reserved_minor", sa.BigInteger(), nullable=False),
        sa.Column("consumed_minor", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(currency) = 3", name="ck_billing_balance_currency"),
        sa.CheckConstraint(
            "available_minor >= 0 AND reserved_minor >= 0 AND consumed_minor >= 0",
            name="ck_billing_balance_nonnegative",
        ),
        sa.CheckConstraint("version > 0", name="ck_billing_balance_version"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("tenant_id"),
    )
    op.create_table(
        "saas_billing_reservations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("entitlement_id", sa.Uuid(), nullable=False),
        sa.Column("usage_event_id", sa.Uuid(), nullable=True),
        sa.Column("operation_key", sa.String(length=128), nullable=False),
        sa.Column("meter", sa.String(length=128), nullable=False),
        sa.Column("unit", sa.String(length=64), nullable=False),
        sa.Column("reserved_quantity", sa.Numeric(38, 12), nullable=False),
        sa.Column("settled_quantity", sa.Numeric(38, 12), nullable=False),
        sa.Column("reserved_minor", sa.BigInteger(), nullable=False),
        sa.Column("settled_minor", sa.BigInteger(), nullable=False),
        sa.Column("released_minor", sa.BigInteger(), nullable=False),
        sa.Column("refunded_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('reserved', 'settled', 'released', 'refunded')",
            name="ck_billing_reservation_status",
        ),
        sa.CheckConstraint("length(operation_key) > 0", name="ck_billing_reservation_key"),
        sa.CheckConstraint("length(meter) > 0", name="ck_billing_reservation_meter"),
        sa.CheckConstraint("length(unit) > 0", name="ck_billing_reservation_unit"),
        sa.CheckConstraint("reserved_quantity > 0", name="ck_billing_reservation_quantity"),
        sa.CheckConstraint(
            "settled_quantity >= 0 AND settled_quantity <= reserved_quantity",
            name="ck_billing_reservation_settled_quantity",
        ),
        sa.CheckConstraint("reserved_minor > 0", name="ck_billing_reservation_amount"),
        sa.CheckConstraint(
            "settled_minor >= 0 AND released_minor >= 0 AND refunded_minor >= 0",
            name="ck_billing_reservation_amounts",
        ),
        sa.CheckConstraint(
            "(status = 'reserved' AND settled_minor = 0 AND released_minor = 0) OR "
            "(status <> 'reserved' AND settled_minor + released_minor = reserved_minor)",
            name="ck_billing_reservation_conservation",
        ),
        sa.CheckConstraint(
            "refunded_minor <= settled_minor", name="ck_billing_reservation_refund"
        ),
        sa.CheckConstraint("length(currency) = 3", name="ck_billing_reservation_currency"),
        sa.CheckConstraint("version > 0", name="ck_billing_reservation_version"),
        sa.CheckConstraint(
            "(status = 'reserved' AND settled_minor = 0 AND released_minor = 0 "
            "AND refunded_minor = 0 AND finalized_at IS NULL) OR "
            "(status = 'settled' AND settled_minor > 0 AND refunded_minor = 0 "
            "AND finalized_at IS NOT NULL) OR "
            "(status = 'released' AND settled_minor = 0 AND released_minor = reserved_minor "
            "AND refunded_minor = 0 AND finalized_at IS NOT NULL) OR "
            "(status = 'refunded' AND settled_minor > 0 AND refunded_minor = settled_minor "
            "AND finalized_at IS NOT NULL)",
            name="ck_billing_reservation_state",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "entitlement_id"],
            ["saas_billing_entitlements.tenant_id", "saas_billing_entitlements.id"],
            name="fk_billing_reservation_entitlement",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "usage_event_id"],
            ["saas_usage_events.tenant_id", "saas_usage_events.id"],
            name="fk_billing_reservation_usage",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "created_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_billing_reservation_actor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_reservation_scope"),
        sa.UniqueConstraint("tenant_id", "operation_key", name="uq_billing_reservation_key"),
    )
    op.create_index(
        "ix_billing_reservation_status",
        "saas_billing_reservations",
        ["tenant_id", "status", "created_at"],
    )


def _create_ledgers() -> None:
    op.create_table(
        "saas_customer_ledger_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("reservation_id", sa.Uuid(), nullable=True),
        sa.Column("usage_event_id", sa.Uuid(), nullable=True),
        sa.Column("operation_type", sa.String(length=32), nullable=False),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("delta_available_minor", sa.BigInteger(), nullable=False),
        sa.Column("delta_reserved_minor", sa.BigInteger(), nullable=False),
        sa.Column("delta_consumed_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "operation_type IN ('credit', 'reserve', 'settle', 'release', 'refund')",
            name="ck_customer_ledger_operation",
        ),
        sa.CheckConstraint("amount_minor > 0", name="ck_customer_ledger_amount"),
        sa.CheckConstraint("length(currency) = 3", name="ck_customer_ledger_currency"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_customer_ledger_idempotency"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_customer_ledger_hash"),
        sa.CheckConstraint(
            "(operation_type = 'credit' AND delta_available_minor = amount_minor "
            "AND delta_reserved_minor = 0 AND delta_consumed_minor = 0 "
            "AND reservation_id IS NULL) OR "
            "(operation_type = 'reserve' AND delta_available_minor = -amount_minor "
            "AND delta_reserved_minor = amount_minor AND delta_consumed_minor = 0 "
            "AND reservation_id IS NOT NULL) OR "
            "(operation_type = 'settle' AND delta_available_minor = 0 "
            "AND delta_reserved_minor = -amount_minor "
            "AND delta_consumed_minor = amount_minor AND reservation_id IS NOT NULL) OR "
            "(operation_type = 'release' AND delta_available_minor = amount_minor "
            "AND delta_reserved_minor = -amount_minor AND delta_consumed_minor = 0 "
            "AND reservation_id IS NOT NULL) OR "
            "(operation_type = 'refund' AND delta_available_minor = amount_minor "
            "AND delta_reserved_minor = 0 AND delta_consumed_minor = -amount_minor "
            "AND reservation_id IS NOT NULL)",
            name="ck_customer_ledger_conservation",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "reservation_id"],
            ["saas_billing_reservations.tenant_id", "saas_billing_reservations.id"],
            name="fk_customer_ledger_reservation",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "usage_event_id"],
            ["saas_usage_events.tenant_id", "saas_usage_events.id"],
            name="fk_customer_ledger_usage",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "created_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_customer_ledger_actor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_customer_ledger_scope"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_customer_ledger_idempotency"),
    )
    op.create_index(
        "ix_customer_ledger_period",
        "saas_customer_ledger_entries",
        ["tenant_id", "occurred_at", "id"],
    )
    op.create_table(
        "saas_provider_cost_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("usage_event_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("provider_receipt_id", sa.String(length=256), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("recorded_by", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "kind IN ('estimated', 'final', 'refund')", name="ck_provider_cost_kind"
        ),
        sa.CheckConstraint("amount_minor > 0", name="ck_provider_cost_amount"),
        sa.CheckConstraint("length(provider) > 0", name="ck_provider_cost_provider"),
        sa.CheckConstraint("length(provider_receipt_id) > 0", name="ck_provider_cost_receipt"),
        sa.CheckConstraint("length(currency) = 3", name="ck_provider_cost_currency"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_provider_cost_idempotency"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_provider_cost_hash"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "usage_event_id"],
            ["saas_usage_events.tenant_id", "saas_usage_events.id"],
            name="fk_provider_cost_usage",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "recorded_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_provider_cost_actor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_provider_cost_scope"),
        sa.UniqueConstraint(
            "tenant_id",
            "provider",
            "provider_receipt_id",
            "kind",
            name="uq_provider_cost_receipt",
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_provider_cost_idempotency"),
    )
    op.create_index(
        "ix_provider_cost_period",
        "saas_provider_cost_entries",
        ["tenant_id", "occurred_at", "id"],
    )


def _create_reconciliation() -> None:
    op.create_table(
        "saas_billing_reconciliation_batches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("usage_event_count", sa.Integer(), nullable=False),
        sa.Column("customer_settlement_count", sa.Integer(), nullable=False),
        sa.Column("provider_cost_count", sa.Integer(), nullable=False),
        sa.Column("customer_charge_minor", sa.BigInteger(), nullable=False),
        sa.Column("customer_settled_minor", sa.BigInteger(), nullable=False),
        sa.Column("provider_cost_minor", sa.BigInteger(), nullable=False),
        sa.Column("mismatch_count", sa.Integer(), nullable=False),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('completed', 'exception')", name="ck_billing_reconciliation_status"
        ),
        sa.CheckConstraint("period_end > period_start", name="ck_billing_reconciliation_period"),
        sa.CheckConstraint(
            "usage_event_count >= 0 AND customer_settlement_count >= 0 "
            "AND provider_cost_count >= 0 AND mismatch_count >= 0",
            name="ck_billing_reconciliation_counts",
        ),
        sa.CheckConstraint(
            "customer_charge_minor >= 0 AND customer_settled_minor >= 0 "
            "AND provider_cost_minor >= 0",
            name="ck_billing_reconciliation_amounts",
        ),
        sa.CheckConstraint(
            "length(evidence_sha256) = 64", name="ck_billing_reconciliation_evidence"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "created_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_billing_reconciliation_actor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_reconciliation_scope"),
        sa.UniqueConstraint(
            "tenant_id", "period_start", "period_end", name="uq_billing_reconciliation_period"
        ),
    )
    op.create_index(
        "ix_billing_reconciliation_status",
        "saas_billing_reconciliation_batches",
        ["tenant_id", "status", "period_end"],
    )
    op.create_table(
        "saas_billing_reconciliation_mismatches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("usage_event_id", sa.Uuid(), nullable=False),
        sa.Column("mismatch_type", sa.String(length=64), nullable=False),
        sa.Column("expected_minor", sa.BigInteger(), nullable=True),
        sa.Column("actual_minor", sa.BigInteger(), nullable=True),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("resolution", sa.String(length=1024), nullable=True),
        sa.Column("resolved_by", sa.Uuid(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "mismatch_type IN ('missing_provider_cost', 'missing_customer_settlement', "
            "'customer_amount_mismatch', 'currency_mismatch')",
            name="ck_billing_mismatch_type",
        ),
        sa.CheckConstraint("status IN ('open', 'resolved')", name="ck_billing_mismatch_status"),
        sa.CheckConstraint("length(currency) = 3", name="ck_billing_mismatch_currency"),
        sa.CheckConstraint(
            "(status = 'open' AND resolution IS NULL AND resolved_by IS NULL "
            "AND resolved_at IS NULL) OR "
            "(status = 'resolved' AND length(resolution) > 0 AND resolved_by IS NOT NULL "
            "AND resolved_at IS NOT NULL)",
            name="ck_billing_mismatch_resolution",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "batch_id"],
            [
                "saas_billing_reconciliation_batches.tenant_id",
                "saas_billing_reconciliation_batches.id",
            ],
            name="fk_billing_mismatch_batch",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "usage_event_id"],
            ["saas_usage_events.tenant_id", "saas_usage_events.id"],
            name="fk_billing_mismatch_usage",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "resolved_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            name="fk_billing_mismatch_resolver",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_mismatch_scope"),
        sa.UniqueConstraint(
            "tenant_id",
            "batch_id",
            "usage_event_id",
            "mismatch_type",
            name="uq_billing_mismatch_fact",
        ),
    )
    op.create_index(
        "ix_billing_mismatch_status",
        "saas_billing_reconciliation_mismatches",
        ["tenant_id", "status", "created_at"],
    )


def _enable_postgresql_guards_and_rls() -> None:
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    predicate = f"({platform} OR tenant_id = {tenant})"
    for table in _TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "rls_{table}_tenant" ON "{table}" '
            f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
        )
    op.execute(
        """
        CREATE FUNCTION saas_reject_billing_fact_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Billing fact is append-only';
        END
        $$
        """
    )
    for table in _IMMUTABLE_TABLES:
        op.execute(
            f'CREATE TRIGGER "trg_{table}_immutable" BEFORE UPDATE OR DELETE ON "{table}" '
            "FOR EACH ROW EXECUTE FUNCTION saas_reject_billing_fact_mutation()"
        )
    op.execute(
        """
        CREATE FUNCTION saas_guard_billing_mismatch_resolution()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(NEW.id, NEW.tenant_id, NEW.batch_id, NEW.usage_event_id,
                   NEW.mismatch_type, NEW.expected_minor, NEW.actual_minor,
                   NEW.currency, NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.tenant_id, OLD.batch_id, OLD.usage_event_id,
                   OLD.mismatch_type, OLD.expected_minor, OLD.actual_minor,
                   OLD.currency, OLD.created_at) THEN
                RAISE EXCEPTION 'Billing mismatch fact is immutable';
            END IF;
            IF NOT (OLD.status = 'open' AND NEW.status = 'resolved'
                    AND NEW.resolution IS NOT NULL AND NEW.resolved_by IS NOT NULL
                    AND NEW.resolved_at IS NOT NULL) THEN
                RAISE EXCEPTION 'Billing mismatch transition is invalid';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER trg_billing_mismatch_resolution BEFORE UPDATE ON "
        "saas_billing_reconciliation_mismatches FOR EACH ROW "
        "EXECUTE FUNCTION saas_guard_billing_mismatch_resolution()"
    )


def upgrade() -> None:
    _create_subscription()
    _create_pricing()
    _create_entitlement()
    _create_usage()
    _create_balance_and_reservation()
    _create_ledgers()
    _create_reconciliation()
    if op.get_bind().dialect.name == "postgresql":
        _enable_postgresql_guards_and_rls()


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_billing_mismatch_resolution ON "
            "saas_billing_reconciliation_mismatches"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_guard_billing_mismatch_resolution()")
        for table in reversed(_IMMUTABLE_TABLES):
            op.execute(f'DROP TRIGGER IF EXISTS "trg_{table}_immutable" ON "{table}"')
        op.execute("DROP FUNCTION IF EXISTS saas_reject_billing_fact_mutation()")
        for table in reversed(_TABLES):
            op.execute(f'DROP POLICY IF EXISTS "rls_{table}_tenant" ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    op.drop_index(
        "ix_billing_mismatch_status", table_name="saas_billing_reconciliation_mismatches"
    )
    op.drop_table("saas_billing_reconciliation_mismatches")
    op.drop_index(
        "ix_billing_reconciliation_status", table_name="saas_billing_reconciliation_batches"
    )
    op.drop_table("saas_billing_reconciliation_batches")
    op.drop_index("ix_provider_cost_period", table_name="saas_provider_cost_entries")
    op.drop_table("saas_provider_cost_entries")
    op.drop_index("ix_customer_ledger_period", table_name="saas_customer_ledger_entries")
    op.drop_table("saas_customer_ledger_entries")
    op.drop_index("ix_billing_reservation_status", table_name="saas_billing_reservations")
    op.drop_table("saas_billing_reservations")
    op.drop_table("saas_billing_balances")
    op.drop_index("ix_usage_event_project", table_name="saas_usage_events")
    op.drop_index("ix_usage_event_period", table_name="saas_usage_events")
    op.drop_table("saas_usage_events")
    op.drop_index("ix_billing_entitlement_status", table_name="saas_billing_entitlements")
    op.drop_table("saas_billing_entitlements")
    op.drop_index("ix_pricing_snapshot_effective", table_name="saas_pricing_snapshots")
    op.drop_table("saas_pricing_snapshots")
    op.drop_table("saas_billing_subscriptions")
