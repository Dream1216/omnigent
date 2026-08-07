"""Durable P6 metering, entitlement, subscription, and billing authority records."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase

SUBSCRIPTION_STATUSES = ("trialing", "active", "past_due", "suspended", "canceled")
ENTITLEMENT_STATUSES = ("active", "suspended", "expired")
ENTITLEMENT_SCOPE_TYPES = ("tenant", "space", "project", "user", "model")
ENTITLEMENT_PERIODS = ("none", "day", "month")
RESERVATION_STATUSES = ("reserved", "settled", "released", "refunded")
LEDGER_OPERATION_TYPES = ("credit", "reserve", "settle", "release", "refund")
PROVIDER_COST_KINDS = ("estimated", "final", "refund")
RECONCILIATION_STATUSES = ("completed", "exception")
MISMATCH_TYPES = (
    "missing_provider_cost",
    "missing_customer_settlement",
    "customer_amount_mismatch",
    "currency_mismatch",
)
MISMATCH_STATUSES = ("open", "resolved")
BILLING_PERIOD_CLOSE_STATUSES = ("closed", "closed_with_resolved_exceptions")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


class BillingSubscriptionRecord(SaasBase):
    """Tenant subscription state machine; provider callbacks never overwrite it blindly."""

    __tablename__ = "saas_billing_subscriptions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    plan_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    provider: Mapped[str | None] = mapped_column(sa.String(64))
    provider_customer_ref: Mapped[str | None] = mapped_column(sa.String(256))
    provider_subscription_ref: Mapped[str | None] = mapped_column(sa.String(256))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    current_period_start: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    current_period_end: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    trial_ends_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    cancel_at_period_end: Mapped[bool] = mapped_column(nullable=False, default=False)
    provider_event_cursor: Mapped[str | None] = mapped_column(sa.String(256))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    updated_by: Mapped[UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "updated_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_billing_subscription_actor",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(SUBSCRIPTION_STATUSES)})",
            name="ck_billing_subscription_status",
        ),
        sa.CheckConstraint("length(plan_key) > 0", name="ck_billing_subscription_plan"),
        sa.CheckConstraint(
            "current_period_end > current_period_start",
            name="ck_billing_subscription_period",
        ),
        sa.CheckConstraint("version > 0", name="ck_billing_subscription_version"),
        sa.UniqueConstraint("tenant_id", name="uq_billing_subscription_tenant"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_subscription_scope"),
        sa.UniqueConstraint(
            "provider", "provider_subscription_ref", name="uq_billing_provider_subscription"
        ),
    )


class PricingSnapshotRecord(SaasBase):
    """Immutable, tenant-specific fixed-point price schedule."""

    __tablename__ = "saas_pricing_snapshots"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    plan_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    currency: Mapped[str] = mapped_column(sa.String(3), nullable=False)
    rates: Mapped[dict[str, dict[str, object]]] = mapped_column(sa.JSON, nullable=False)
    version: Mapped[int] = mapped_column(nullable=False)
    effective_from: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    effective_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_by: Mapped[UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "created_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_pricing_snapshot_actor",
        ),
        sa.CheckConstraint("length(plan_key) > 0", name="ck_pricing_snapshot_plan"),
        sa.CheckConstraint("length(currency) = 3", name="ck_pricing_snapshot_currency"),
        sa.CheckConstraint("version > 0", name="ck_pricing_snapshot_version"),
        sa.CheckConstraint(
            "effective_until IS NULL OR effective_until > effective_from",
            name="ck_pricing_snapshot_window",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_pricing_snapshot_scope"),
        sa.UniqueConstraint("tenant_id", "version", name="uq_pricing_snapshot_version"),
        sa.Index(
            "ix_pricing_snapshot_effective",
            "tenant_id",
            "plan_key",
            "effective_from",
            "effective_until",
        ),
    )


class BillingEntitlementRecord(SaasBase):
    """Versioned quota bucket at Tenant, Space, Project, User, or Model scope."""

    __tablename__ = "saas_billing_entitlements"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    subscription_id: Mapped[UUID] = mapped_column(nullable=False)
    scope_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    scope_key: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    space_id: Mapped[UUID | None] = mapped_column()
    project_id: Mapped[UUID | None] = mapped_column()
    user_id: Mapped[UUID | None] = mapped_column()
    model_key: Mapped[str | None] = mapped_column(sa.String(256))
    meter: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    unit: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    limit_quantity: Mapped[Decimal | None] = mapped_column(sa.Numeric(38, 12))
    reserved_quantity: Mapped[Decimal] = mapped_column(
        sa.Numeric(38, 12), nullable=False, default=Decimal(0)
    )
    consumed_quantity: Mapped[Decimal] = mapped_column(
        sa.Numeric(38, 12), nullable=False, default=Decimal(0)
    )
    concurrency_limit: Mapped[int | None] = mapped_column()
    active_reservations: Mapped[int] = mapped_column(nullable=False, default=0)
    hard_limit: Mapped[bool] = mapped_column(nullable=False, default=True)
    period: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="month")
    period_start: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    updated_by: Mapped[UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "subscription_id"),
            ("saas_billing_subscriptions.tenant_id", "saas_billing_subscriptions.id"),
            ondelete="RESTRICT",
            name="fk_billing_entitlement_subscription",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_billing_entitlement_space",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            ondelete="RESTRICT",
            name="fk_billing_entitlement_project",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "user_id"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_billing_entitlement_user",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "updated_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_billing_entitlement_actor",
        ),
        sa.CheckConstraint(
            f"scope_type IN ({_values(ENTITLEMENT_SCOPE_TYPES)})",
            name="ck_billing_entitlement_scope_type",
        ),
        sa.CheckConstraint(
            f"period IN ({_values(ENTITLEMENT_PERIODS)})",
            name="ck_billing_entitlement_period",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(ENTITLEMENT_STATUSES)})",
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
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_entitlement_scope"),
        sa.UniqueConstraint(
            "tenant_id",
            "scope_type",
            "scope_key",
            "meter",
            name="uq_billing_entitlement_meter_scope",
        ),
        sa.Index(
            "ix_billing_entitlement_status",
            "tenant_id",
            "status",
            "period_end",
        ),
    )


class UsageEventRecord(SaasBase):
    """Immutable metering fact with an exact pricing snapshot and dedupe identity."""

    __tablename__ = "saas_usage_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID | None] = mapped_column()
    project_id: Mapped[UUID | None] = mapped_column()
    session_id: Mapped[UUID | None] = mapped_column()
    run_id: Mapped[UUID | None] = mapped_column()
    user_id: Mapped[UUID | None] = mapped_column()
    meter: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    quantity: Mapped[Decimal] = mapped_column(sa.Numeric(38, 12), nullable=False)
    unit: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    provider_request_id: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    pricing_snapshot_id: Mapped[UUID] = mapped_column(nullable=False)
    currency: Mapped[str] = mapped_column(sa.String(3), nullable=False)
    customer_charge_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    attributes: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "pricing_snapshot_id"),
            ("saas_pricing_snapshots.tenant_id", "saas_pricing_snapshots.id"),
            ondelete="RESTRICT",
            name="fk_usage_event_pricing",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_usage_event_space",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            ondelete="RESTRICT",
            name="fk_usage_event_project",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id", "run_id"),
            ("saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id", "saas_runs.id"),
            ondelete="RESTRICT",
            name="fk_usage_event_run",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "user_id"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_usage_event_user",
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
        sa.UniqueConstraint("tenant_id", "id", name="uq_usage_event_scope"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_usage_event_idempotency"),
        sa.UniqueConstraint(
            "tenant_id",
            "provider",
            "provider_request_id",
            "meter",
            name="uq_usage_event_provider_meter",
        ),
        sa.Index("ix_usage_event_period", "tenant_id", "occurred_at", "id"),
        sa.Index("ix_usage_event_project", "tenant_id", "space_id", "project_id", "occurred_at"),
    )


class BillingMeteringReceiptRecord(SaasBase):
    """Immutable machine identity and execution fence behind one Usage fact."""

    __tablename__ = "saas_billing_metering_receipts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    usage_event_id: Mapped[UUID] = mapped_column(nullable=False)
    runner_id: Mapped[UUID] = mapped_column(nullable=False)
    runner_connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    runner_certificate_id: Mapped[UUID] = mapped_column(nullable=False)
    certificate_fingerprint_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    capability_id: Mapped[UUID] = mapped_column(nullable=False)
    dispatch_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    fence_token: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id", "run_id"),
            ("saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id", "saas_runs.id"),
            ondelete="RESTRICT",
            name="fk_billing_metering_receipt_run",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "usage_event_id"),
            ("saas_usage_events.tenant_id", "saas_usage_events.id"),
            ondelete="RESTRICT",
            name="fk_billing_metering_receipt_usage",
        ),
        sa.ForeignKeyConstraint(
            ("runner_id",),
            ("saas_runner_registrations.id",),
            ondelete="RESTRICT",
            name="fk_billing_metering_receipt_runner",
        ),
        sa.ForeignKeyConstraint(
            ("runner_certificate_id",),
            ("saas_runner_certificates.id",),
            ondelete="RESTRICT",
            name="fk_billing_metering_receipt_certificate",
        ),
        sa.ForeignKeyConstraint(
            ("capability_id",),
            ("saas_capability_tokens.id",),
            ondelete="RESTRICT",
            name="fk_billing_metering_receipt_capability",
        ),
        sa.CheckConstraint(
            "runner_connection_generation > 0",
            name="ck_billing_metering_receipt_runner_generation",
        ),
        sa.CheckConstraint(
            "dispatch_generation > 0", name="ck_billing_metering_receipt_dispatch_generation"
        ),
        sa.CheckConstraint("fence_token > 0", name="ck_billing_metering_receipt_fence"),
        sa.CheckConstraint(
            "length(certificate_fingerprint_sha256) = 64",
            name="ck_billing_metering_receipt_fingerprint",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) > 0", name="ck_billing_metering_receipt_idempotency"
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64", name="ck_billing_metering_receipt_request_hash"
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_metering_receipt_scope"),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_billing_metering_receipt_idempotency",
        ),
        sa.UniqueConstraint("usage_event_id", name="uq_billing_metering_receipt_usage"),
        sa.Index(
            "ix_billing_metering_receipt_run",
            "tenant_id",
            "run_id",
            "recorded_at",
        ),
        sa.Index(
            "ix_billing_metering_receipt_runner",
            "runner_id",
            "runner_connection_generation",
            "recorded_at",
        ),
    )


class BillingBalanceRecord(SaasBase):
    """Rebuildable Tenant balance projection locked by every ledger mutation."""

    __tablename__ = "saas_billing_balances"

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    currency: Mapped[str] = mapped_column(sa.String(3), nullable=False)
    available_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    reserved_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    consumed_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.CheckConstraint("length(currency) = 3", name="ck_billing_balance_currency"),
        sa.CheckConstraint(
            "available_minor >= 0 AND reserved_minor >= 0 AND consumed_minor >= 0",
            name="ck_billing_balance_nonnegative",
        ),
        sa.CheckConstraint("version > 0", name="ck_billing_balance_version"),
    )


class BillingReservationRecord(SaasBase):
    """Quota and financial hold state; immutable money movements live in the ledger."""

    __tablename__ = "saas_billing_reservations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    entitlement_id: Mapped[UUID] = mapped_column(nullable=False)
    usage_event_id: Mapped[UUID | None] = mapped_column()
    operation_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    meter: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    unit: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    reserved_quantity: Mapped[Decimal] = mapped_column(sa.Numeric(38, 12), nullable=False)
    settled_quantity: Mapped[Decimal] = mapped_column(
        sa.Numeric(38, 12), nullable=False, default=Decimal(0)
    )
    reserved_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    settled_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    released_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    refunded_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(sa.String(3), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="reserved")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_by: Mapped[UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    finalized_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "entitlement_id"),
            ("saas_billing_entitlements.tenant_id", "saas_billing_entitlements.id"),
            ondelete="RESTRICT",
            name="fk_billing_reservation_entitlement",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "usage_event_id"),
            ("saas_usage_events.tenant_id", "saas_usage_events.id"),
            ondelete="RESTRICT",
            name="fk_billing_reservation_usage",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "created_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_billing_reservation_actor",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(RESERVATION_STATUSES)})",
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
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_reservation_scope"),
        sa.UniqueConstraint("tenant_id", "operation_key", name="uq_billing_reservation_key"),
        sa.Index("ix_billing_reservation_status", "tenant_id", "status", "created_at"),
    )


class CustomerLedgerEntryRecord(SaasBase):
    """Append-only customer credit movement with database-enforced conservation."""

    __tablename__ = "saas_customer_ledger_entries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    reservation_id: Mapped[UUID | None] = mapped_column()
    usage_event_id: Mapped[UUID | None] = mapped_column()
    operation_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    amount_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    delta_available_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    delta_reserved_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    delta_consumed_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(sa.String(3), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    created_by: Mapped[UUID] = mapped_column(nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "reservation_id"),
            ("saas_billing_reservations.tenant_id", "saas_billing_reservations.id"),
            ondelete="RESTRICT",
            name="fk_customer_ledger_reservation",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "usage_event_id"),
            ("saas_usage_events.tenant_id", "saas_usage_events.id"),
            ondelete="RESTRICT",
            name="fk_customer_ledger_usage",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "created_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_customer_ledger_actor",
        ),
        sa.CheckConstraint(
            f"operation_type IN ({_values(LEDGER_OPERATION_TYPES)})",
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
        sa.UniqueConstraint("tenant_id", "id", name="uq_customer_ledger_scope"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_customer_ledger_idempotency"),
        sa.Index("ix_customer_ledger_period", "tenant_id", "occurred_at", "id"),
    )


class ProviderCostEntryRecord(SaasBase):
    """Append-only provider receipt or estimate, separate from customer charges."""

    __tablename__ = "saas_provider_cost_entries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    usage_event_id: Mapped[UUID] = mapped_column(nullable=False)
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    provider_receipt_id: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    amount_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(sa.String(3), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    recorded_by: Mapped[UUID] = mapped_column(nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "usage_event_id"),
            ("saas_usage_events.tenant_id", "saas_usage_events.id"),
            ondelete="RESTRICT",
            name="fk_provider_cost_usage",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "recorded_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_provider_cost_actor",
        ),
        sa.CheckConstraint(
            f"kind IN ({_values(PROVIDER_COST_KINDS)})", name="ck_provider_cost_kind"
        ),
        sa.CheckConstraint("amount_minor > 0", name="ck_provider_cost_amount"),
        sa.CheckConstraint("length(provider) > 0", name="ck_provider_cost_provider"),
        sa.CheckConstraint("length(provider_receipt_id) > 0", name="ck_provider_cost_receipt"),
        sa.CheckConstraint("length(currency) = 3", name="ck_provider_cost_currency"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_provider_cost_idempotency"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_provider_cost_hash"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_provider_cost_scope"),
        sa.UniqueConstraint(
            "tenant_id",
            "provider",
            "provider_receipt_id",
            "kind",
            name="uq_provider_cost_receipt",
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_provider_cost_idempotency"),
        sa.Index("ix_provider_cost_period", "tenant_id", "occurred_at", "id"),
    )


class BillingReconciliationBatchRecord(SaasBase):
    """Immutable daily comparison summary across Usage and both ledgers."""

    __tablename__ = "saas_billing_reconciliation_batches"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    period_start: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    usage_event_count: Mapped[int] = mapped_column(nullable=False)
    customer_settlement_count: Mapped[int] = mapped_column(nullable=False)
    provider_cost_count: Mapped[int] = mapped_column(nullable=False)
    customer_charge_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    customer_settled_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    provider_cost_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    mismatch_count: Mapped[int] = mapped_column(nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    created_by: Mapped[UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "created_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_billing_reconciliation_actor",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(RECONCILIATION_STATUSES)})",
            name="ck_billing_reconciliation_status",
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
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_reconciliation_scope"),
        sa.UniqueConstraint(
            "tenant_id", "period_start", "period_end", name="uq_billing_reconciliation_period"
        ),
        sa.Index("ix_billing_reconciliation_status", "tenant_id", "status", "period_end"),
    )


class BillingPeriodCloseRecord(SaasBase):
    """Immutable period-close checkpoint after reconciliation and reservation drain."""

    __tablename__ = "saas_billing_period_closes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    reconciliation_batch_id: Mapped[UUID] = mapped_column(nullable=False)
    period_start: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    rolled_entitlement_count: Mapped[int] = mapped_column(nullable=False)
    usage_event_count: Mapped[int] = mapped_column(nullable=False)
    customer_charge_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    customer_settled_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    provider_cost_minor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    reconciliation_evidence_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    close_evidence_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    closed_by: Mapped[UUID] = mapped_column(nullable=False)
    closed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "reconciliation_batch_id"),
            (
                "saas_billing_reconciliation_batches.tenant_id",
                "saas_billing_reconciliation_batches.id",
            ),
            ondelete="RESTRICT",
            name="fk_billing_period_close_reconciliation",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "closed_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_billing_period_close_actor",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(BILLING_PERIOD_CLOSE_STATUSES)})",
            name="ck_billing_period_close_status",
        ),
        sa.CheckConstraint("period_end > period_start", name="ck_billing_period_close_period"),
        sa.CheckConstraint(
            "rolled_entitlement_count >= 0 AND usage_event_count >= 0",
            name="ck_billing_period_close_counts",
        ),
        sa.CheckConstraint(
            "customer_charge_minor >= 0 AND customer_settled_minor >= 0 "
            "AND provider_cost_minor >= 0",
            name="ck_billing_period_close_amounts",
        ),
        sa.CheckConstraint(
            "length(reconciliation_evidence_sha256) = 64",
            name="ck_billing_period_close_reconciliation_hash",
        ),
        sa.CheckConstraint(
            "length(close_evidence_sha256) = 64",
            name="ck_billing_period_close_evidence_hash",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_period_close_scope"),
        sa.UniqueConstraint(
            "tenant_id", "period_start", "period_end", name="uq_billing_period_close_period"
        ),
        sa.Index("ix_billing_period_close_list", "tenant_id", "period_end", "id"),
    )


class BillingReconciliationMismatchRecord(SaasBase):
    """Exception queue item; only one-way resolution metadata may change."""

    __tablename__ = "saas_billing_reconciliation_mismatches"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    batch_id: Mapped[UUID] = mapped_column(nullable=False)
    usage_event_id: Mapped[UUID] = mapped_column(nullable=False)
    mismatch_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    expected_minor: Mapped[int | None] = mapped_column(sa.BigInteger)
    actual_minor: Mapped[int | None] = mapped_column(sa.BigInteger)
    currency: Mapped[str] = mapped_column(sa.String(3), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="open")
    resolution: Mapped[str | None] = mapped_column(sa.String(1024))
    resolved_by: Mapped[UUID | None] = mapped_column()
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "batch_id"),
            (
                "saas_billing_reconciliation_batches.tenant_id",
                "saas_billing_reconciliation_batches.id",
            ),
            ondelete="RESTRICT",
            name="fk_billing_mismatch_batch",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "usage_event_id"),
            ("saas_usage_events.tenant_id", "saas_usage_events.id"),
            ondelete="RESTRICT",
            name="fk_billing_mismatch_usage",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "resolved_by"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_billing_mismatch_resolver",
        ),
        sa.CheckConstraint(
            f"mismatch_type IN ({_values(MISMATCH_TYPES)})",
            name="ck_billing_mismatch_type",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(MISMATCH_STATUSES)})", name="ck_billing_mismatch_status"
        ),
        sa.CheckConstraint("length(currency) = 3", name="ck_billing_mismatch_currency"),
        sa.CheckConstraint(
            "(status = 'open' AND resolution IS NULL AND resolved_by IS NULL "
            "AND resolved_at IS NULL) OR "
            "(status = 'resolved' AND length(resolution) > 0 AND resolved_by IS NOT NULL "
            "AND resolved_at IS NOT NULL)",
            name="ck_billing_mismatch_resolution",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_mismatch_scope"),
        sa.UniqueConstraint(
            "tenant_id",
            "batch_id",
            "usage_event_id",
            "mismatch_type",
            name="uq_billing_mismatch_fact",
        ),
        sa.Index("ix_billing_mismatch_status", "tenant_id", "status", "created_at"),
    )
