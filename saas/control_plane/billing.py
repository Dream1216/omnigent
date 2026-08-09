"""Transactional P6 metering, entitlement, ledger, and reconciliation authority."""

from __future__ import annotations

import json
from calendar import monthrange
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from hashlib import sha256
from typing import TypedDict, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.billing_models import (
    ENTITLEMENT_PERIODS,
    ENTITLEMENT_SCOPE_TYPES,
    ENTITLEMENT_STATUSES,
    MISMATCH_STATUSES,
    PROVIDER_COST_KINDS,
    SUBSCRIPTION_STATUSES,
    BillingBalanceRecord,
    BillingEntitlementRecord,
    BillingPeriodCloseRecord,
    BillingReconciliationBatchRecord,
    BillingReconciliationMismatchRecord,
    BillingReservationRecord,
    BillingSubscriptionRecord,
    CustomerLedgerEntryRecord,
    PricingSnapshotRecord,
    ProviderCostEntryRecord,
    UsageEventRecord,
)
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    Tenant,
    TenantMembership,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.permissions import TENANT_ROLE_PERMISSIONS
from saas.control_plane.rls import RlsContext, apply_rls_context

_SUBSCRIPTION_TRANSITIONS = {
    "trialing": frozenset({"trialing", "active", "past_due", "suspended", "canceled"}),
    "active": frozenset({"active", "past_due", "suspended", "canceled"}),
    "past_due": frozenset({"past_due", "active", "suspended", "canceled"}),
    "suspended": frozenset({"suspended", "active", "canceled"}),
    "canceled": frozenset({"canceled"}),
}
_SENSITIVE_ATTRIBUTE_TOKENS = frozenset(
    {"prompt", "code", "secret", "token", "password", "credential", "authorization"}
)
_USAGE_ATTRIBUTE_KEYS = frozenset(
    {
        "batch",
        "cache_hit",
        "model",
        "model_version",
        "operation",
        "provider_region",
        "request_class",
        "service_tier",
        "tool_kind",
    }
)


class BillingControlPlaneError(RuntimeError):
    """Stable, transport-neutral billing authority failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class SubscriptionView:
    id: UUID
    tenant_id: UUID
    plan_key: str
    status: str
    provider: str | None
    provider_customer_ref: str | None
    provider_subscription_ref: str | None
    current_period_start: datetime
    current_period_end: datetime
    trial_ends_at: datetime | None
    cancel_at_period_end: bool
    version: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class PricingSnapshotView:
    id: UUID
    tenant_id: UUID
    plan_key: str
    currency: str
    rates: dict[str, dict[str, object]]
    version: int
    effective_from: datetime
    effective_until: datetime | None
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class EntitlementView:
    id: UUID
    tenant_id: UUID
    subscription_id: UUID
    scope_type: str
    scope_key: str
    meter: str
    unit: str
    limit_quantity: Decimal | None
    reserved_quantity: Decimal
    consumed_quantity: Decimal
    concurrency_limit: int | None
    active_reservations: int
    hard_limit: bool
    period: str
    period_start: datetime
    period_end: datetime | None
    status: str
    version: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class UsageEventView:
    id: UUID
    tenant_id: UUID
    meter: str
    quantity: Decimal
    unit: str
    provider: str
    provider_request_id: str
    pricing_snapshot_id: UUID
    currency: str
    customer_charge_minor: int
    occurred_at: datetime
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class BalanceView:
    tenant_id: UUID
    currency: str
    available_minor: int
    reserved_minor: int
    consumed_minor: int
    version: int


@dataclass(frozen=True, slots=True)
class BalanceAuditView:
    """Comparison between the rebuildable projection and immutable ledger sums."""

    projection: BalanceView
    ledger_available_minor: int
    ledger_reserved_minor: int
    ledger_consumed_minor: int
    consistent: bool
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ReservationView:
    id: UUID
    tenant_id: UUID
    entitlement_id: UUID
    usage_event_id: UUID | None
    operation_key: str
    meter: str
    unit: str
    reserved_quantity: Decimal
    settled_quantity: Decimal
    reserved_minor: int
    settled_minor: int
    released_minor: int
    refunded_minor: int
    currency: str
    status: str
    version: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ReconciliationView:
    id: UUID
    tenant_id: UUID
    period_start: datetime
    period_end: datetime
    status: str
    usage_event_count: int
    customer_settlement_count: int
    provider_cost_count: int
    customer_charge_minor: int
    customer_settled_minor: int
    provider_cost_minor: int
    mismatch_count: int
    evidence_sha256: str
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class BillingPeriodCloseView:
    id: UUID
    tenant_id: UUID
    reconciliation_batch_id: UUID
    period_start: datetime
    period_end: datetime
    status: str
    rolled_entitlement_count: int
    usage_event_count: int
    customer_charge_minor: int
    customer_settled_minor: int
    provider_cost_minor: int
    reconciliation_evidence_sha256: str
    close_evidence_sha256: str
    closed_by: UUID
    closed_at: datetime
    replayed: bool = False


class BillingOverview(TypedDict):
    """Typed, content-blind snapshot returned to the Tenant Billing console."""

    subscription: SubscriptionView | None
    balance: BalanceView | None
    entitlements: tuple[EntitlementView, ...]
    latest_reconciliation: ReconciliationView | None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _time(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BillingControlPlaneError("billing_time_invalid", f"{field} must be timezone-aware")
    return value


def _stored_time(value: datetime) -> datetime:
    """Normalize SQLite's timezone-naive round trip to the PostgreSQL UTC contract."""

    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _text(value: str, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or cleaned != value or len(cleaned) > maximum:
        raise BillingControlPlaneError("billing_value_invalid", f"{field} is invalid")
    return cleaned


def _currency(value: str) -> str:
    cleaned = value.upper()
    if len(cleaned) != 3 or not cleaned.isalpha() or cleaned != value:
        raise BillingControlPlaneError("billing_currency_invalid", "currency is invalid")
    return cleaned


def _quantity(value: Decimal | str | int, field: str) -> Decimal:
    if isinstance(value, (float, bool)):
        raise BillingControlPlaneError("billing_quantity_invalid", f"{field} is invalid")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as error:
        raise BillingControlPlaneError(
            "billing_quantity_invalid", f"{field} is invalid"
        ) from error
    exponent = parsed.as_tuple().exponent
    if not parsed.is_finite() or parsed <= 0 or not isinstance(exponent, int) or exponent < -12:
        raise BillingControlPlaneError("billing_quantity_invalid", f"{field} is invalid")
    return parsed


def _idempotency_key(value: str) -> str:
    return _text(value, "idempotency_key", 128)


def _request_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode()).hexdigest()


def _derived_key(value: str, suffix: str) -> str:
    candidate = f"{value}.{suffix}"
    return candidate if len(candidate) <= 128 else sha256(candidate.encode()).hexdigest()


def _next_period_end(period: str, current_end: datetime) -> datetime:
    if period == "day":
        return current_end + timedelta(days=1)
    if period == "month":
        year = current_end.year + (1 if current_end.month == 12 else 0)
        month = 1 if current_end.month == 12 else current_end.month + 1
        day = min(current_end.day, monthrange(year, month)[1])
        return current_end.replace(year=year, month=month, day=day)
    raise BillingControlPlaneError(
        "billing_period_close_invalid", "only periodic entitlements can be rolled"
    )


class BillingControlPlane:
    """Own all commercial-state writes and keep customer/provider ledgers separate."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def configure_subscription(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        plan_key: str,
        status: str,
        current_period_start: datetime,
        current_period_end: datetime,
        expected_version: int | None,
        idempotency_key: str,
        provider: str | None = None,
        provider_customer_ref: str | None = None,
        provider_subscription_ref: str | None = None,
        provider_event_cursor: str | None = None,
        trial_ends_at: datetime | None = None,
        cancel_at_period_end: bool = False,
    ) -> SubscriptionView:
        key = _idempotency_key(idempotency_key)
        plan = _text(plan_key, "plan_key", 128)
        if status not in SUBSCRIPTION_STATUSES:
            raise BillingControlPlaneError("subscription_status_invalid", "status is invalid")
        start = _time(current_period_start, "current_period_start")
        end = _time(current_period_end, "current_period_end")
        if end <= start:
            raise BillingControlPlaneError("subscription_period_invalid", "period is invalid")
        trial = _time(trial_ends_at, "trial_ends_at") if trial_ends_at else None
        cleaned_provider = _text(provider, "provider", 64) if provider is not None else None
        customer_ref = (
            _text(provider_customer_ref, "provider_customer_ref", 256)
            if provider_customer_ref is not None
            else None
        )
        subscription_ref = (
            _text(provider_subscription_ref, "provider_subscription_ref", 256)
            if provider_subscription_ref is not None
            else None
        )
        event_cursor = (
            _text(provider_event_cursor, "provider_event_cursor", 256)
            if provider_event_cursor is not None
            else None
        )
        if any(value is not None for value in (customer_ref, subscription_ref, event_cursor)) and (
            cleaned_provider is None
        ):
            raise BillingControlPlaneError(
                "subscription_provider_invalid", "provider references require a provider"
            )
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "plan_key": plan,
            "status": status,
            "current_period_start": start.isoformat(),
            "current_period_end": end.isoformat(),
            "trial_ends_at": trial.isoformat() if trial else None,
            "cancel_at_period_end": cancel_at_period_end,
            "provider": cleaned_provider,
            "provider_customer_ref": customer_ref,
            "provider_subscription_ref": subscription_ref,
            "provider_event_cursor": event_cursor,
            "expected_version": expected_version,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                f"billing-subscription:{tenant_id}",
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.subscription.configured", digest)
            if replay is not None:
                record = self._subscription(db, tenant_id, lock=False)
                assert record is not None
                return self._subscription_view(record, replayed=True)
            record = self._subscription(db, tenant_id, lock=True, required=False)
            if record is None:
                if expected_version is not None or status not in {"trialing", "active"}:
                    raise BillingControlPlaneError(
                        "subscription_version_conflict", "subscription creation facts changed"
                    )
                record = BillingSubscriptionRecord(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    plan_key=plan,
                    provider=cleaned_provider,
                    provider_customer_ref=customer_ref,
                    provider_subscription_ref=subscription_ref,
                    status=status,
                    current_period_start=start,
                    current_period_end=end,
                    trial_ends_at=trial,
                    cancel_at_period_end=cancel_at_period_end,
                    provider_event_cursor=event_cursor,
                    version=1,
                    updated_by=actor_id,
                )
                db.add(record)
            else:
                if expected_version != record.version:
                    raise BillingControlPlaneError(
                        "subscription_version_conflict", "subscription changed concurrently"
                    )
                if status not in _SUBSCRIPTION_TRANSITIONS[record.status]:
                    raise BillingControlPlaneError(
                        "subscription_transition_invalid", "subscription transition is invalid"
                    )
                record.plan_key = plan
                if cleaned_provider is not None:
                    record.provider = cleaned_provider
                    record.provider_customer_ref = customer_ref
                    record.provider_subscription_ref = subscription_ref
                record.status = status
                record.current_period_start = start
                record.current_period_end = end
                record.trial_ends_at = trial
                record.cancel_at_period_end = cancel_at_period_end
                if event_cursor is not None:
                    record.provider_event_cursor = event_cursor
                record.version += 1
                record.updated_by = actor_id
            db.flush()
            result = self._subscription_view(record)
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.subscription.configured",
                idempotency_key=key,
                request_hash=digest,
                payload={**payload, "subscription_id": str(record.id), "version": record.version},
            )
            return result

    def create_pricing_snapshot(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        plan_key: str,
        currency: str,
        rates: dict[str, dict[str, object]],
        effective_from: datetime,
        effective_until: datetime | None,
        idempotency_key: str,
    ) -> PricingSnapshotView:
        key = _idempotency_key(idempotency_key)
        plan = _text(plan_key, "plan_key", 128)
        code = _currency(currency)
        normalized_rates = self._rates(rates)
        start = _time(effective_from, "effective_from")
        end = _time(effective_until, "effective_until") if effective_until else None
        if end is not None and end <= start:
            raise BillingControlPlaneError("pricing_window_invalid", "pricing window is invalid")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "plan_key": plan,
            "currency": code,
            "rates": normalized_rates,
            "effective_from": start.isoformat(),
            "effective_until": end.isoformat() if end else None,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                f"billing-pricing:{tenant_id}",
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.pricing.created", digest)
            if replay is not None:
                record = db.get(
                    PricingSnapshotRecord, UUID(cast(str, replay.payload["pricing_snapshot_id"]))
                )
                if record is None:
                    raise BillingControlPlaneError(
                        "billing_invariant_broken", "pricing receipt is orphaned"
                    )
                return self._pricing_view(record, replayed=True)
            subscription = self._subscription(db, tenant_id, lock=False)
            assert subscription is not None
            if subscription.plan_key != plan:
                raise BillingControlPlaneError(
                    "pricing_plan_mismatch", "pricing plan does not match subscription"
                )
            overlap_conditions: list[sa.ColumnElement[bool]] = [
                PricingSnapshotRecord.tenant_id == tenant_id,
                PricingSnapshotRecord.plan_key == plan,
                sa.or_(
                    PricingSnapshotRecord.effective_until.is_(None),
                    PricingSnapshotRecord.effective_until > start,
                ),
            ]
            if end is not None:
                overlap_conditions.append(PricingSnapshotRecord.effective_from < end)
            overlapping = db.scalar(
                sa.select(PricingSnapshotRecord.id).where(*overlap_conditions).limit(1)
            )
            if overlapping is not None:
                raise BillingControlPlaneError(
                    "pricing_window_overlap",
                    "pricing snapshot overlaps an existing plan window",
                )
            current_version = db.scalar(
                sa.select(sa.func.max(PricingSnapshotRecord.version)).where(
                    PricingSnapshotRecord.tenant_id == tenant_id
                )
            )
            record = PricingSnapshotRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                plan_key=plan,
                currency=code,
                rates=normalized_rates,
                version=int(current_version or 0) + 1,
                effective_from=start,
                effective_until=end,
                created_by=actor_id,
            )
            db.add(record)
            balance = db.get(BillingBalanceRecord, tenant_id)
            if balance is None:
                db.add(
                    BillingBalanceRecord(
                        tenant_id=tenant_id,
                        currency=code,
                        available_minor=0,
                        reserved_minor=0,
                        consumed_minor=0,
                        version=1,
                    )
                )
            elif balance.currency != code:
                raise BillingControlPlaneError(
                    "billing_currency_mismatch", "pricing currency differs from account"
                )
            db.flush()
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.pricing.created",
                idempotency_key=key,
                request_hash=digest,
                payload={
                    **payload,
                    "pricing_snapshot_id": str(record.id),
                    "version": record.version,
                },
            )
            return self._pricing_view(record)

    def set_entitlement(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        scope_type: str,
        meter: str,
        unit: str,
        limit_quantity: Decimal | str | int | None,
        concurrency_limit: int | None,
        hard_limit: bool,
        period: str,
        period_start: datetime,
        period_end: datetime | None,
        status: str,
        expected_version: int | None,
        idempotency_key: str,
        space_id: UUID | None = None,
        project_id: UUID | None = None,
        user_id: UUID | None = None,
        model_key: str | None = None,
    ) -> EntitlementView:
        key = _idempotency_key(idempotency_key)
        if scope_type not in ENTITLEMENT_SCOPE_TYPES:
            raise BillingControlPlaneError("entitlement_scope_invalid", "scope is invalid")
        scope_key = self._scope_key(
            tenant_id=tenant_id,
            scope_type=scope_type,
            space_id=space_id,
            project_id=project_id,
            user_id=user_id,
            model_key=model_key,
        )
        clean_meter = _text(meter, "meter", 128)
        clean_unit = _text(unit, "unit", 64)
        limit = _quantity(limit_quantity, "limit_quantity") if limit_quantity is not None else None
        if hard_limit and limit is None:
            raise BillingControlPlaneError(
                "entitlement_limit_invalid", "hard entitlement requires a limit"
            )
        if concurrency_limit is not None and (
            isinstance(concurrency_limit, bool) or concurrency_limit <= 0
        ):
            raise BillingControlPlaneError(
                "entitlement_concurrency_invalid", "concurrency limit is invalid"
            )
        if period not in ENTITLEMENT_PERIODS:
            raise BillingControlPlaneError("entitlement_period_invalid", "period is invalid")
        start = _time(period_start, "period_start")
        end = _time(period_end, "period_end") if period_end else None
        if (period == "none") != (end is None) or (end is not None and end <= start):
            raise BillingControlPlaneError("entitlement_period_invalid", "period is invalid")
        if status not in ENTITLEMENT_STATUSES:
            raise BillingControlPlaneError("entitlement_status_invalid", "status is invalid")
        cleaned_model = _text(model_key, "model_key", 256) if model_key else None
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "scope_type": scope_type,
            "scope_key": scope_key,
            "space_id": str(space_id) if space_id else None,
            "project_id": str(project_id) if project_id else None,
            "user_id": str(user_id) if user_id else None,
            "model_key": cleaned_model,
            "meter": clean_meter,
            "unit": clean_unit,
            "limit_quantity": str(limit) if limit is not None else None,
            "concurrency_limit": concurrency_limit,
            "hard_limit": hard_limit,
            "period": period,
            "period_start": start.isoformat(),
            "period_end": end.isoformat() if end else None,
            "status": status,
            "expected_version": expected_version,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                f"billing-entitlement:{tenant_id}:{scope_type}:{scope_key}:{clean_meter}",
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.entitlement.set", digest)
            if replay is not None:
                record = db.get(
                    BillingEntitlementRecord,
                    UUID(cast(str, replay.payload["entitlement_id"])),
                )
                if record is None:
                    raise BillingControlPlaneError(
                        "billing_invariant_broken", "entitlement receipt is orphaned"
                    )
                return self._entitlement_view(record, replayed=True)
            subscription = self._subscription(db, tenant_id, lock=False)
            assert subscription is not None
            if subscription.status == "canceled":
                raise BillingControlPlaneError(
                    "subscription_inactive", "canceled subscription cannot grant entitlement"
                )
            statement = sa.select(BillingEntitlementRecord).where(
                BillingEntitlementRecord.tenant_id == tenant_id,
                BillingEntitlementRecord.scope_type == scope_type,
                BillingEntitlementRecord.scope_key == scope_key,
                BillingEntitlementRecord.meter == clean_meter,
            )
            record = db.scalar(statement.with_for_update())
            if record is None:
                if expected_version is not None:
                    raise BillingControlPlaneError(
                        "entitlement_version_conflict", "entitlement creation facts changed"
                    )
                record = BillingEntitlementRecord(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    subscription_id=subscription.id,
                    scope_type=scope_type,
                    scope_key=scope_key,
                    space_id=space_id,
                    project_id=project_id,
                    user_id=user_id,
                    model_key=cleaned_model,
                    meter=clean_meter,
                    unit=clean_unit,
                    limit_quantity=limit,
                    reserved_quantity=Decimal(0),
                    consumed_quantity=Decimal(0),
                    concurrency_limit=concurrency_limit,
                    active_reservations=0,
                    hard_limit=hard_limit,
                    period=period,
                    period_start=start,
                    period_end=end,
                    status=status,
                    version=1,
                    updated_by=actor_id,
                )
                db.add(record)
            else:
                if expected_version != record.version:
                    raise BillingControlPlaneError(
                        "entitlement_version_conflict", "entitlement changed concurrently"
                    )
                if clean_unit != record.unit:
                    raise BillingControlPlaneError(
                        "entitlement_unit_immutable", "entitlement unit cannot change"
                    )
                if (
                    limit is not None
                    and limit < record.reserved_quantity + record.consumed_quantity
                ):
                    raise BillingControlPlaneError(
                        "entitlement_in_use", "limit is below reserved and consumed usage"
                    )
                if (
                    concurrency_limit is not None
                    and concurrency_limit < record.active_reservations
                ):
                    raise BillingControlPlaneError(
                        "entitlement_in_use", "concurrency is below active reservations"
                    )
                record.subscription_id = subscription.id
                record.limit_quantity = limit
                record.concurrency_limit = concurrency_limit
                record.hard_limit = hard_limit
                record.period = period
                record.period_start = start
                record.period_end = end
                record.status = status
                record.version += 1
                record.updated_by = actor_id
            db.flush()
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.entitlement.set",
                idempotency_key=key,
                request_hash=digest,
                payload={**payload, "entitlement_id": str(record.id), "version": record.version},
            )
            return self._entitlement_view(record)

    def grant_credit(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
        occurred_at: datetime | None = None,
    ) -> BalanceView:
        amount = self._amount(amount_minor)
        code = _currency(currency)
        key = _idempotency_key(idempotency_key)
        happened = _time(occurred_at or _utcnow(), "occurred_at")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "amount_minor": amount,
            "currency": code,
            "occurred_at": happened.isoformat(),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(db, f"billing-idempotency:{tenant_id}:{key}")
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.credit.granted", digest)
            balance = self._balance(db, tenant_id, code, lock=True)
            if replay is not None:
                return self._balance_view(balance)
            self._ledger(
                db,
                tenant_id=tenant_id,
                reservation_id=None,
                usage_event_id=None,
                operation_type="credit",
                amount_minor=amount,
                currency=code,
                idempotency_key=key,
                request_hash=digest,
                actor_id=actor_id,
                occurred_at=happened,
            )
            balance.available_minor += amount
            balance.version += 1
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(tenant_id),
                event_type="billing.credit.granted",
                idempotency_key=key,
                request_hash=digest,
                payload={**payload, "balance_version": balance.version},
            )
            return self._balance_view(balance)

    def reserve(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        entitlement_id: UUID,
        operation_key: str,
        quantity: Decimal | str | int,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ReservationView:
        key = _idempotency_key(idempotency_key)
        external_key = _text(operation_key, "operation_key", 128)
        units = _quantity(quantity, "quantity")
        amount = self._amount(amount_minor)
        code = _currency(currency)
        checked_at = _time(now or _utcnow(), "now")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "entitlement_id": str(entitlement_id),
            "operation_key": external_key,
            "quantity": str(units),
            "amount_minor": amount,
            "currency": code,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                f"billing-operation:{tenant_id}:{external_key}",
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.reservation.created", digest)
            if replay is not None:
                record = db.get(
                    BillingReservationRecord,
                    UUID(cast(str, replay.payload["reservation_id"])),
                )
                if record is None:
                    raise BillingControlPlaneError(
                        "billing_invariant_broken", "reservation receipt is orphaned"
                    )
                return self._reservation_view(record, replayed=True)
            subscription = self._subscription(db, tenant_id, lock=False)
            assert subscription is not None
            if subscription.status not in {"trialing", "active"}:
                raise BillingControlPlaneError(
                    "subscription_inactive", "subscription does not allow new reservations"
                )
            entitlement = db.scalar(
                sa.select(BillingEntitlementRecord)
                .where(
                    BillingEntitlementRecord.id == entitlement_id,
                    BillingEntitlementRecord.tenant_id == tenant_id,
                )
                .with_for_update()
            )
            if entitlement is None or entitlement.status != "active":
                raise BillingControlPlaneError(
                    "entitlement_unavailable", "entitlement is not active"
                )
            if checked_at < _stored_time(entitlement.period_start) or (
                entitlement.period_end is not None
                and checked_at >= _stored_time(entitlement.period_end)
            ):
                raise BillingControlPlaneError(
                    "entitlement_period_closed", "entitlement period is not active"
                )
            if entitlement.concurrency_limit is not None and (
                entitlement.active_reservations >= entitlement.concurrency_limit
            ):
                raise BillingControlPlaneError(
                    "entitlement_concurrency_exceeded", "concurrency entitlement is exhausted"
                )
            projected = entitlement.reserved_quantity + entitlement.consumed_quantity + units
            if entitlement.hard_limit and (
                entitlement.limit_quantity is None or projected > entitlement.limit_quantity
            ):
                raise BillingControlPlaneError(
                    "entitlement_limit_exceeded", "usage entitlement is exhausted"
                )
            balance = self._balance(db, tenant_id, code, lock=True)
            if balance.available_minor < amount:
                raise BillingControlPlaneError(
                    "billing_credit_exhausted", "available billing credit is exhausted"
                )
            existing = db.scalar(
                sa.select(BillingReservationRecord).where(
                    BillingReservationRecord.tenant_id == tenant_id,
                    BillingReservationRecord.operation_key == external_key,
                )
            )
            if existing is not None:
                raise BillingControlPlaneError(
                    "billing_operation_duplicate", "operation key already exists"
                )
            record = BillingReservationRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                entitlement_id=entitlement_id,
                usage_event_id=None,
                operation_key=external_key,
                meter=entitlement.meter,
                unit=entitlement.unit,
                reserved_quantity=units,
                settled_quantity=Decimal(0),
                reserved_minor=amount,
                settled_minor=0,
                released_minor=0,
                refunded_minor=0,
                currency=code,
                status="reserved",
                version=1,
                created_by=actor_id,
                finalized_at=None,
            )
            db.add(record)
            db.flush()
            self._ledger(
                db,
                tenant_id=tenant_id,
                reservation_id=record.id,
                usage_event_id=None,
                operation_type="reserve",
                amount_minor=amount,
                currency=code,
                idempotency_key=key,
                request_hash=digest,
                actor_id=actor_id,
                occurred_at=checked_at,
            )
            balance.available_minor -= amount
            balance.reserved_minor += amount
            balance.version += 1
            entitlement.reserved_quantity += units
            entitlement.active_reservations += 1
            entitlement.version += 1
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.reservation.created",
                idempotency_key=key,
                request_hash=digest,
                payload={**payload, "reservation_id": str(record.id), "version": 1},
            )
            return self._reservation_view(record)

    def record_usage(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        pricing_snapshot_id: UUID,
        meter: str,
        quantity: Decimal | str | int,
        unit: str,
        provider: str,
        provider_request_id: str,
        idempotency_key: str,
        occurred_at: datetime,
        space_id: UUID | None = None,
        project_id: UUID | None = None,
        session_id: UUID | None = None,
        run_id: UUID | None = None,
        user_id: UUID | None = None,
        attributes: dict[str, object] | None = None,
    ) -> UsageEventView:
        key = _idempotency_key(idempotency_key)
        clean_meter = _text(meter, "meter", 128)
        units = _quantity(quantity, "quantity")
        clean_unit = _text(unit, "unit", 64)
        clean_provider = _text(provider, "provider", 64)
        request_id = _text(provider_request_id, "provider_request_id", 256)
        happened = _time(occurred_at, "occurred_at")
        clean_attributes = self._attributes(attributes or {})
        if project_id is not None and space_id is None:
            raise BillingControlPlaneError("usage_scope_invalid", "Project requires Space")
        if run_id is not None and project_id is None:
            raise BillingControlPlaneError("usage_scope_invalid", "Run requires Project")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "space_id": str(space_id) if space_id else None,
            "project_id": str(project_id) if project_id else None,
            "session_id": str(session_id) if session_id else None,
            "run_id": str(run_id) if run_id else None,
            "user_id": str(user_id) if user_id else None,
            "pricing_snapshot_id": str(pricing_snapshot_id),
            "meter": clean_meter,
            "quantity": str(units),
            "unit": clean_unit,
            "provider": clean_provider,
            "provider_request_id": request_id,
            "occurred_at": happened.isoformat(),
            "attributes": clean_attributes,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                (
                    f"billing-provider-request:{tenant_id}:{clean_provider}:"
                    f"{request_id}:{clean_meter}"
                ),
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.usage.recorded", digest)
            if replay is not None:
                record = db.get(
                    UsageEventRecord, UUID(cast(str, replay.payload["usage_event_id"]))
                )
                if record is None:
                    raise BillingControlPlaneError(
                        "billing_invariant_broken", "usage receipt is orphaned"
                    )
                return self._usage_view(record, replayed=True)
            duplicate = db.scalar(
                sa.select(UsageEventRecord).where(
                    UsageEventRecord.tenant_id == tenant_id,
                    UsageEventRecord.provider == clean_provider,
                    UsageEventRecord.provider_request_id == request_id,
                    UsageEventRecord.meter == clean_meter,
                )
            )
            if duplicate is not None:
                raise BillingControlPlaneError(
                    "usage_provider_request_duplicate", "provider request and meter already exist"
                )
            pricing = db.scalar(
                sa.select(PricingSnapshotRecord).where(
                    PricingSnapshotRecord.id == pricing_snapshot_id,
                    PricingSnapshotRecord.tenant_id == tenant_id,
                )
            )
            if (
                pricing is None
                or happened < _stored_time(pricing.effective_from)
                or (
                    pricing.effective_until is not None
                    and happened >= _stored_time(pricing.effective_until)
                )
            ):
                raise BillingControlPlaneError(
                    "pricing_snapshot_unavailable", "pricing snapshot is not effective"
                )
            rate = pricing.rates.get(clean_meter)
            if rate is None or rate["unit"] != clean_unit:
                raise BillingControlPlaneError("pricing_rate_missing", "meter rate is unavailable")
            unit_size = Decimal(cast(str, rate["unit_size"]))
            minor_per_unit = cast(int, rate["minor_per_unit"])
            charge = int(
                (units / unit_size * minor_per_unit).to_integral_value(rounding=ROUND_CEILING)
            )
            if charge <= 0:
                raise BillingControlPlaneError(
                    "pricing_charge_invalid", "priced charge is invalid"
                )
            record = UsageEventRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                session_id=session_id,
                run_id=run_id,
                user_id=user_id,
                meter=clean_meter,
                quantity=units,
                unit=clean_unit,
                provider=clean_provider,
                provider_request_id=request_id,
                idempotency_key=key,
                pricing_snapshot_id=pricing_snapshot_id,
                currency=pricing.currency,
                customer_charge_minor=charge,
                attributes=clean_attributes,
                occurred_at=happened,
            )
            db.add(record)
            db.flush()
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.usage.recorded",
                idempotency_key=key,
                request_hash=digest,
                payload={
                    **payload,
                    "usage_event_id": str(record.id),
                    "currency": record.currency,
                    "customer_charge_minor": charge,
                },
            )
            return self._usage_view(record)

    def settle(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        reservation_id: UUID,
        usage_event_id: UUID,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ReservationView:
        key = _idempotency_key(idempotency_key)
        checked_at = _time(now or _utcnow(), "now")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "reservation_id": str(reservation_id),
            "usage_event_id": str(usage_event_id),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(db, f"billing-idempotency:{tenant_id}:{key}")
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.reservation.settled", digest)
            record = self._reservation(db, tenant_id, reservation_id, lock=True)
            if replay is not None:
                return self._reservation_view(record, replayed=True)
            if record.status != "reserved":
                raise BillingControlPlaneError(
                    "billing_reservation_finalized", "reservation is already final"
                )
            usage = db.scalar(
                sa.select(UsageEventRecord).where(
                    UsageEventRecord.id == usage_event_id,
                    UsageEventRecord.tenant_id == tenant_id,
                )
            )
            if usage is None:
                raise BillingControlPlaneError("usage_not_found", "usage event does not exist")
            if usage.meter != record.meter or usage.unit != record.unit:
                raise BillingControlPlaneError(
                    "billing_reservation_usage_mismatch", "usage does not match reservation"
                )
            if usage.quantity > record.reserved_quantity or (
                usage.customer_charge_minor > record.reserved_minor
            ):
                raise BillingControlPlaneError(
                    "billing_reservation_exceeded", "usage exceeds the reserved maximum"
                )
            entitlement = db.scalar(
                sa.select(BillingEntitlementRecord)
                .where(BillingEntitlementRecord.id == record.entitlement_id)
                .with_for_update()
            )
            if entitlement is None or entitlement.reserved_quantity < record.reserved_quantity:
                raise BillingControlPlaneError(
                    "billing_invariant_broken", "entitlement reservation is inconsistent"
                )
            balance = self._balance(db, tenant_id, record.currency, lock=True)
            if balance.reserved_minor < record.reserved_minor:
                raise BillingControlPlaneError(
                    "billing_invariant_broken", "billing reservation balance is inconsistent"
                )
            settled = usage.customer_charge_minor
            released = record.reserved_minor - settled
            record.usage_event_id = usage.id
            record.settled_quantity = usage.quantity
            record.settled_minor = settled
            record.released_minor = released
            record.status = "settled"
            record.version += 1
            record.finalized_at = checked_at
            self._ledger(
                db,
                tenant_id=tenant_id,
                reservation_id=record.id,
                usage_event_id=usage.id,
                operation_type="settle",
                amount_minor=settled,
                currency=record.currency,
                idempotency_key=_derived_key(key, "settle"),
                request_hash=digest,
                actor_id=actor_id,
                occurred_at=checked_at,
            )
            if released:
                self._ledger(
                    db,
                    tenant_id=tenant_id,
                    reservation_id=record.id,
                    usage_event_id=usage.id,
                    operation_type="release",
                    amount_minor=released,
                    currency=record.currency,
                    idempotency_key=_derived_key(key, "release"),
                    request_hash=digest,
                    actor_id=actor_id,
                    occurred_at=checked_at,
                )
            balance.reserved_minor -= record.reserved_minor
            balance.consumed_minor += settled
            balance.available_minor += released
            balance.version += 1
            entitlement.reserved_quantity -= record.reserved_quantity
            entitlement.consumed_quantity += usage.quantity
            entitlement.active_reservations -= 1
            entitlement.version += 1
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.reservation.settled",
                idempotency_key=key,
                request_hash=digest,
                payload={
                    **payload,
                    "settled_minor": settled,
                    "released_minor": released,
                    "version": record.version,
                },
            )
            return self._reservation_view(record)

    def release(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        reservation_id: UUID,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ReservationView:
        key = _idempotency_key(idempotency_key)
        checked_at = _time(now or _utcnow(), "now")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "reservation_id": str(reservation_id),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(db, f"billing-idempotency:{tenant_id}:{key}")
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.reservation.released", digest)
            record = self._reservation(db, tenant_id, reservation_id, lock=True)
            if replay is not None:
                return self._reservation_view(record, replayed=True)
            if record.status != "reserved":
                raise BillingControlPlaneError(
                    "billing_reservation_finalized", "reservation is already final"
                )
            entitlement = db.scalar(
                sa.select(BillingEntitlementRecord)
                .where(BillingEntitlementRecord.id == record.entitlement_id)
                .with_for_update()
            )
            if entitlement is None or entitlement.reserved_quantity < record.reserved_quantity:
                raise BillingControlPlaneError(
                    "billing_invariant_broken", "entitlement reservation is inconsistent"
                )
            balance = self._balance(db, tenant_id, record.currency, lock=True)
            if balance.reserved_minor < record.reserved_minor:
                raise BillingControlPlaneError(
                    "billing_invariant_broken", "billing reservation balance is inconsistent"
                )
            record.released_minor = record.reserved_minor
            record.status = "released"
            record.version += 1
            record.finalized_at = checked_at
            self._ledger(
                db,
                tenant_id=tenant_id,
                reservation_id=record.id,
                usage_event_id=None,
                operation_type="release",
                amount_minor=record.reserved_minor,
                currency=record.currency,
                idempotency_key=key,
                request_hash=digest,
                actor_id=actor_id,
                occurred_at=checked_at,
            )
            balance.reserved_minor -= record.reserved_minor
            balance.available_minor += record.reserved_minor
            balance.version += 1
            entitlement.reserved_quantity -= record.reserved_quantity
            entitlement.active_reservations -= 1
            entitlement.version += 1
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.reservation.released",
                idempotency_key=key,
                request_hash=digest,
                payload={
                    **payload,
                    "released_minor": record.released_minor,
                    "version": record.version,
                },
            )
            return self._reservation_view(record)

    def refund(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        reservation_id: UUID,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ReservationView:
        key = _idempotency_key(idempotency_key)
        checked_at = _time(now or _utcnow(), "now")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "reservation_id": str(reservation_id),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(db, f"billing-idempotency:{tenant_id}:{key}")
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.reservation.refunded", digest)
            record = self._reservation(db, tenant_id, reservation_id, lock=True)
            if replay is not None:
                return self._reservation_view(record, replayed=True)
            if record.status != "settled" or record.settled_minor <= 0:
                raise BillingControlPlaneError(
                    "billing_refund_invalid", "only an unrefunded settlement can be refunded"
                )
            balance = self._balance(db, tenant_id, record.currency, lock=True)
            if balance.consumed_minor < record.settled_minor:
                raise BillingControlPlaneError(
                    "billing_invariant_broken", "billing consumed balance is inconsistent"
                )
            record.refunded_minor = record.settled_minor
            record.status = "refunded"
            record.version += 1
            self._ledger(
                db,
                tenant_id=tenant_id,
                reservation_id=record.id,
                usage_event_id=record.usage_event_id,
                operation_type="refund",
                amount_minor=record.settled_minor,
                currency=record.currency,
                idempotency_key=key,
                request_hash=digest,
                actor_id=actor_id,
                occurred_at=checked_at,
            )
            balance.consumed_minor -= record.settled_minor
            balance.available_minor += record.settled_minor
            balance.version += 1
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.reservation.refunded",
                idempotency_key=key,
                request_hash=digest,
                payload={
                    **payload,
                    "refunded_minor": record.refunded_minor,
                    "version": record.version,
                },
            )
            return self._reservation_view(record)

    def record_provider_cost(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        usage_event_id: UUID,
        provider: str,
        provider_receipt_id: str,
        kind: str,
        amount_minor: int,
        currency: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> UUID:
        key = _idempotency_key(idempotency_key)
        clean_provider = _text(provider, "provider", 64)
        receipt_id = _text(provider_receipt_id, "provider_receipt_id", 256)
        if kind not in PROVIDER_COST_KINDS:
            raise BillingControlPlaneError("provider_cost_kind_invalid", "kind is invalid")
        amount = self._amount(amount_minor)
        code = _currency(currency)
        happened = _time(occurred_at, "occurred_at")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "usage_event_id": str(usage_event_id),
            "provider": clean_provider,
            "provider_receipt_id": receipt_id,
            "kind": kind,
            "amount_minor": amount,
            "currency": code,
            "occurred_at": happened.isoformat(),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                (f"billing-provider-cost:{tenant_id}:{clean_provider}:{receipt_id}:{kind}"),
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.provider_cost.recorded", digest)
            if replay is not None:
                return UUID(cast(str, replay.payload["provider_cost_id"]))
            usage = db.scalar(
                sa.select(UsageEventRecord).where(
                    UsageEventRecord.id == usage_event_id,
                    UsageEventRecord.tenant_id == tenant_id,
                )
            )
            if usage is None or usage.provider != clean_provider:
                raise BillingControlPlaneError(
                    "provider_cost_usage_mismatch", "provider cost does not match usage"
                )
            record = ProviderCostEntryRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                usage_event_id=usage_event_id,
                provider=clean_provider,
                provider_receipt_id=receipt_id,
                kind=kind,
                amount_minor=amount,
                currency=code,
                idempotency_key=key,
                request_hash=digest,
                recorded_by=actor_id,
                occurred_at=happened,
            )
            db.add(record)
            db.flush()
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.provider_cost.recorded",
                idempotency_key=key,
                request_hash=digest,
                payload={**payload, "provider_cost_id": str(record.id)},
            )
            return record.id

    def reconcile(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        period_start: datetime,
        period_end: datetime,
        idempotency_key: str,
    ) -> ReconciliationView:
        key = _idempotency_key(idempotency_key)
        start = _time(period_start, "period_start")
        end = _time(period_end, "period_end")
        if end <= start:
            raise BillingControlPlaneError(
                "reconciliation_period_invalid", "reconciliation period is invalid"
            )
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                f"billing-reconciliation:{tenant_id}:{start.isoformat()}:{end.isoformat()}",
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.reconciliation.completed", digest)
            if replay is not None:
                batch = db.get(
                    BillingReconciliationBatchRecord,
                    UUID(cast(str, replay.payload["batch_id"])),
                )
                if batch is None:
                    raise BillingControlPlaneError(
                        "billing_invariant_broken", "reconciliation receipt is orphaned"
                    )
                return self._reconciliation_view(batch, replayed=True)
            if (
                db.scalar(
                    sa.select(BillingReconciliationBatchRecord.id).where(
                        BillingReconciliationBatchRecord.tenant_id == tenant_id,
                        BillingReconciliationBatchRecord.period_start == start,
                        BillingReconciliationBatchRecord.period_end == end,
                    )
                )
                is not None
            ):
                raise BillingControlPlaneError(
                    "reconciliation_period_duplicate", "period was already reconciled"
                )
            usage_events = tuple(
                db.scalars(
                    sa.select(UsageEventRecord)
                    .where(
                        UsageEventRecord.tenant_id == tenant_id,
                        UsageEventRecord.occurred_at >= start,
                        UsageEventRecord.occurred_at < end,
                    )
                    .order_by(UsageEventRecord.id)
                )
            )
            usage_ids = tuple(event.id for event in usage_events)
            ledger_entries = (
                tuple(
                    db.scalars(
                        sa.select(CustomerLedgerEntryRecord).where(
                            CustomerLedgerEntryRecord.tenant_id == tenant_id,
                            CustomerLedgerEntryRecord.usage_event_id.in_(usage_ids),
                            CustomerLedgerEntryRecord.operation_type.in_(("settle", "refund")),
                        )
                    )
                )
                if usage_ids
                else ()
            )
            provider_entries = (
                tuple(
                    db.scalars(
                        sa.select(ProviderCostEntryRecord).where(
                            ProviderCostEntryRecord.tenant_id == tenant_id,
                            ProviderCostEntryRecord.usage_event_id.in_(usage_ids),
                            ProviderCostEntryRecord.kind.in_(("final", "refund")),
                        )
                    )
                )
                if usage_ids
                else ()
            )
            ledger_by_usage: dict[UUID, list[CustomerLedgerEntryRecord]] = {}
            for entry in ledger_entries:
                if entry.usage_event_id is not None:
                    ledger_by_usage.setdefault(entry.usage_event_id, []).append(entry)
            provider_by_usage: dict[UUID, list[ProviderCostEntryRecord]] = {}
            for entry in provider_entries:
                provider_by_usage.setdefault(entry.usage_event_id, []).append(entry)
            mismatch_facts: list[tuple[UsageEventRecord, str, int | None, int | None]] = []
            customer_settled = 0
            provider_cost = 0
            customer_settlement_count = 0
            provider_cost_count = 0
            for usage in usage_events:
                customer_entries = ledger_by_usage.get(usage.id, [])
                actual_customer = sum(
                    entry.amount_minor if entry.operation_type == "settle" else -entry.amount_minor
                    for entry in customer_entries
                )
                customer_settlement_count += sum(
                    entry.operation_type == "settle" for entry in customer_entries
                )
                customer_settled += actual_customer
                if not any(entry.operation_type == "settle" for entry in customer_entries):
                    mismatch_facts.append(
                        (usage, "missing_customer_settlement", usage.customer_charge_minor, None)
                    )
                elif actual_customer != usage.customer_charge_minor:
                    mismatch_facts.append(
                        (
                            usage,
                            "customer_amount_mismatch",
                            usage.customer_charge_minor,
                            actual_customer,
                        )
                    )
                costs = provider_by_usage.get(usage.id, [])
                actual_provider = sum(
                    entry.amount_minor if entry.kind == "final" else -entry.amount_minor
                    for entry in costs
                )
                provider_cost += actual_provider
                provider_cost_count += sum(entry.kind == "final" for entry in costs)
                if not any(entry.kind == "final" for entry in costs):
                    mismatch_facts.append((usage, "missing_provider_cost", None, None))
                if any(entry.currency != usage.currency for entry in (*customer_entries, *costs)):
                    mismatch_facts.append((usage, "currency_mismatch", None, None))
            charge_total = sum(event.customer_charge_minor for event in usage_events)
            evidence: dict[str, object] = {
                "tenant_id": str(tenant_id),
                "period_start": start.isoformat(),
                "period_end": end.isoformat(),
                "usage": [
                    {
                        "id": str(event.id),
                        "charge_minor": event.customer_charge_minor,
                        "currency": event.currency,
                    }
                    for event in usage_events
                ],
                "customer_ledger_entry_ids": sorted(str(entry.id) for entry in ledger_entries),
                "provider_cost_entry_ids": sorted(str(entry.id) for entry in provider_entries),
                "mismatches": [
                    {
                        "usage_event_id": str(usage.id),
                        "type": mismatch_type,
                        "expected_minor": expected,
                        "actual_minor": actual,
                    }
                    for usage, mismatch_type, expected, actual in mismatch_facts
                ],
            }
            evidence_digest = _request_hash(evidence)
            batch = BillingReconciliationBatchRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                period_start=start,
                period_end=end,
                status="exception" if mismatch_facts else "completed",
                usage_event_count=len(usage_events),
                customer_settlement_count=customer_settlement_count,
                provider_cost_count=provider_cost_count,
                customer_charge_minor=charge_total,
                customer_settled_minor=max(0, customer_settled),
                provider_cost_minor=max(0, provider_cost),
                mismatch_count=len(mismatch_facts),
                evidence_sha256=evidence_digest,
                created_by=actor_id,
            )
            db.add(batch)
            db.flush()
            for usage, mismatch_type, expected, actual in mismatch_facts:
                db.add(
                    BillingReconciliationMismatchRecord(
                        id=uuid4(),
                        tenant_id=tenant_id,
                        batch_id=batch.id,
                        usage_event_id=usage.id,
                        mismatch_type=mismatch_type,
                        expected_minor=expected,
                        actual_minor=actual,
                        currency=usage.currency,
                        status="open",
                    )
                )
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(batch.id),
                event_type="billing.reconciliation.completed",
                idempotency_key=key,
                request_hash=digest,
                payload={
                    **payload,
                    "batch_id": str(batch.id),
                    "status": batch.status,
                    "mismatch_count": batch.mismatch_count,
                    "evidence_sha256": evidence_digest,
                },
            )
            return self._reconciliation_view(batch)

    def close_period(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        period_start: datetime,
        period_end: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> BillingPeriodCloseView:
        """Close one reconciled period and atomically roll drained entitlements."""

        key = _idempotency_key(idempotency_key)
        start = _time(period_start, "period_start")
        end = _time(period_end, "period_end")
        closed_at = _time(now or _utcnow(), "now")
        if end <= start:
            raise BillingControlPlaneError(
                "billing_period_close_invalid", "billing period is invalid"
            )
        if closed_at < end:
            raise BillingControlPlaneError(
                "billing_period_not_ended", "billing period has not ended"
            )
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                f"billing-period-close:{tenant_id}:{start.isoformat()}:{end.isoformat()}",
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.period.closed", digest)
            if replay is not None:
                record = db.get(
                    BillingPeriodCloseRecord,
                    UUID(cast(str, replay.payload["period_close_id"])),
                )
                if record is None or record.tenant_id != tenant_id:
                    raise BillingControlPlaneError(
                        "billing_invariant_broken", "period-close receipt is orphaned"
                    )
                return self._period_close_view(record, replayed=True)
            if (
                db.scalar(
                    sa.select(BillingPeriodCloseRecord.id).where(
                        BillingPeriodCloseRecord.tenant_id == tenant_id,
                        BillingPeriodCloseRecord.period_start == start,
                        BillingPeriodCloseRecord.period_end == end,
                    )
                )
                is not None
            ):
                raise BillingControlPlaneError(
                    "billing_period_already_closed", "billing period is already closed"
                )
            # Reconciliation batches are append-only facts and the period advisory
            # lock above serializes close attempts. A row lock would require UPDATE
            # privilege on an immutable table and needlessly weaken the billing role.
            reconciliation = db.scalar(
                sa.select(BillingReconciliationBatchRecord).where(
                    BillingReconciliationBatchRecord.tenant_id == tenant_id,
                    BillingReconciliationBatchRecord.period_start == start,
                    BillingReconciliationBatchRecord.period_end == end,
                )
            )
            if reconciliation is None:
                raise BillingControlPlaneError(
                    "billing_reconciliation_missing",
                    "an exact reconciliation is required before period close",
                )
            open_mismatches = int(
                db.scalar(
                    sa.select(sa.func.count(BillingReconciliationMismatchRecord.id)).where(
                        BillingReconciliationMismatchRecord.tenant_id == tenant_id,
                        BillingReconciliationMismatchRecord.batch_id == reconciliation.id,
                        BillingReconciliationMismatchRecord.status == "open",
                    )
                )
                or 0
            )
            if open_mismatches:
                raise BillingControlPlaneError(
                    "billing_reconciliation_open_exceptions",
                    "all reconciliation exceptions must be resolved before period close",
                )
            entitlements = cast(
                tuple[BillingEntitlementRecord, ...],
                tuple(
                    db.scalars(
                        sa.select(BillingEntitlementRecord)
                        .where(
                            BillingEntitlementRecord.tenant_id == tenant_id,
                            BillingEntitlementRecord.status == "active",
                            BillingEntitlementRecord.period.in_(("day", "month")),
                            BillingEntitlementRecord.period_start == start,
                            BillingEntitlementRecord.period_end == end,
                        )
                        .order_by(BillingEntitlementRecord.id)
                        .with_for_update()
                    )
                ),
            )
            entitlement_ids = tuple(record.id for record in entitlements)
            if entitlement_ids:
                reserved_count = int(
                    db.scalar(
                        sa.select(sa.func.count(BillingReservationRecord.id)).where(
                            BillingReservationRecord.tenant_id == tenant_id,
                            BillingReservationRecord.entitlement_id.in_(entitlement_ids),
                            BillingReservationRecord.status == "reserved",
                        )
                    )
                    or 0
                )
                if reserved_count:
                    raise BillingControlPlaneError(
                        "billing_period_active_reservations",
                        "active reservations must be drained before period close",
                    )
            rollover_evidence: list[dict[str, object]] = []
            for entitlement in entitlements:
                active_reservations = entitlement.active_reservations
                reserved_quantity = entitlement.reserved_quantity
                if active_reservations != 0 or reserved_quantity != 0:
                    raise BillingControlPlaneError(
                        "billing_period_entitlement_not_drained",
                        "entitlement reservation counters must be drained before period close",
                    )
                rollover_evidence.append(self._roll_entitlement(entitlement, actor_id=actor_id))
            close_evidence = _request_hash(
                {
                    **payload,
                    "reconciliation_batch_id": str(reconciliation.id),
                    "reconciliation_evidence_sha256": reconciliation.evidence_sha256,
                    "rollovers": rollover_evidence,
                }
            )
            status = (
                "closed_with_resolved_exceptions"
                if reconciliation.status == "exception"
                else "closed"
            )
            record = BillingPeriodCloseRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                reconciliation_batch_id=reconciliation.id,
                period_start=start,
                period_end=end,
                status=status,
                rolled_entitlement_count=len(entitlements),
                usage_event_count=reconciliation.usage_event_count,
                customer_charge_minor=reconciliation.customer_charge_minor,
                customer_settled_minor=reconciliation.customer_settled_minor,
                provider_cost_minor=reconciliation.provider_cost_minor,
                reconciliation_evidence_sha256=reconciliation.evidence_sha256,
                close_evidence_sha256=close_evidence,
                closed_by=actor_id,
                closed_at=closed_at,
            )
            db.add(record)
            db.flush()
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.period.closed",
                idempotency_key=key,
                request_hash=digest,
                payload={
                    **payload,
                    "period_close_id": str(record.id),
                    "reconciliation_batch_id": str(reconciliation.id),
                    "status": status,
                    "rolled_entitlement_count": len(entitlements),
                    "close_evidence_sha256": close_evidence,
                },
            )
            return self._period_close_view(record)

    def resolve_mismatch(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        mismatch_id: UUID,
        resolution: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> UUID:
        key = _idempotency_key(idempotency_key)
        reason = _text(resolution, "resolution", 1024)
        checked_at = _time(now or _utcnow(), "now")
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "mismatch_id": str(mismatch_id),
            "resolution": reason,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(db, f"billing-idempotency:{tenant_id}:{key}")
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            replay = self._receipt(db, tenant_id, key, "billing.mismatch.resolved", digest)
            if replay is not None:
                return mismatch_id
            record = db.scalar(
                sa.select(BillingReconciliationMismatchRecord)
                .where(
                    BillingReconciliationMismatchRecord.id == mismatch_id,
                    BillingReconciliationMismatchRecord.tenant_id == tenant_id,
                )
                .with_for_update()
            )
            if record is None:
                raise BillingControlPlaneError(
                    "reconciliation_mismatch_not_found", "mismatch does not exist"
                )
            if record.status not in MISMATCH_STATUSES or record.status != "open":
                raise BillingControlPlaneError(
                    "reconciliation_mismatch_resolved", "mismatch is already resolved"
                )
            record.status = "resolved"
            record.resolution = reason
            record.resolved_by = actor_id
            record.resolved_at = checked_at
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(record.id),
                event_type="billing.mismatch.resolved",
                idempotency_key=key,
                request_hash=digest,
                payload={**payload, "resolved_at": checked_at.isoformat()},
            )
            return record.id

    def get_overview(self, *, actor_id: UUID, tenant_id: UUID) -> BillingOverview:
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._require_permission(db, actor_id, tenant_id, "billing.read")
            subscription = self._subscription(db, tenant_id, lock=False, required=False)
            balance = db.get(BillingBalanceRecord, tenant_id)
            entitlements = tuple(
                db.scalars(
                    sa.select(BillingEntitlementRecord)
                    .where(BillingEntitlementRecord.tenant_id == tenant_id)
                    .order_by(BillingEntitlementRecord.scope_type, BillingEntitlementRecord.meter)
                )
            )
            latest_reconciliation = db.scalar(
                sa.select(BillingReconciliationBatchRecord)
                .where(BillingReconciliationBatchRecord.tenant_id == tenant_id)
                .order_by(BillingReconciliationBatchRecord.period_end.desc())
                .limit(1)
            )
            return {
                "subscription": self._subscription_view(subscription) if subscription else None,
                "balance": self._balance_view(balance) if balance else None,
                "entitlements": tuple(self._entitlement_view(item) for item in entitlements),
                "latest_reconciliation": (
                    self._reconciliation_view(latest_reconciliation)
                    if latest_reconciliation
                    else None
                ),
            }

    def audit_balance(self, *, actor_id: UUID, tenant_id: UUID) -> BalanceAuditView:
        """Prove the mutable balance projection equals immutable ledger deltas."""

        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._require_permission(db, actor_id, tenant_id, "billing.read")
            balance = db.scalar(
                sa.select(BillingBalanceRecord)
                .where(BillingBalanceRecord.tenant_id == tenant_id)
                .with_for_update()
            )
            if balance is None:
                raise BillingControlPlaneError(
                    "billing_balance_missing", "billing account is not configured"
                )
            totals = self._ledger_totals(db, tenant_id, balance.currency)
            return self._balance_audit_view(balance, totals)

    def rebuild_balance(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        expected_version: int,
        reason: str,
        idempotency_key: str,
    ) -> BalanceAuditView:
        """Repair only the projection from immutable ledger facts under one lock."""

        key = _idempotency_key(idempotency_key)
        explanation = _text(reason, "reason", 1024)
        payload: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "expected_version": expected_version,
            "reason": explanation,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._transaction_locks(
                db,
                f"billing-idempotency:{tenant_id}:{key}",
                f"billing-balance:{tenant_id}",
            )
            self._require_permission(db, actor_id, tenant_id, "billing.manage")
            balance = db.scalar(
                sa.select(BillingBalanceRecord)
                .where(BillingBalanceRecord.tenant_id == tenant_id)
                .with_for_update()
            )
            if balance is None:
                raise BillingControlPlaneError(
                    "billing_balance_missing", "billing account is not configured"
                )
            replay = self._receipt(db, tenant_id, key, "billing.balance.rebuilt", digest)
            totals = self._ledger_totals(db, tenant_id, balance.currency)
            if replay is not None:
                return self._balance_audit_view(balance, totals, replayed=True)
            if expected_version != balance.version:
                raise BillingControlPlaneError(
                    "billing_balance_version_conflict", "billing balance changed concurrently"
                )
            before = {
                "available_minor": balance.available_minor,
                "reserved_minor": balance.reserved_minor,
                "consumed_minor": balance.consumed_minor,
                "version": balance.version,
            }
            balance.available_minor, balance.reserved_minor, balance.consumed_minor = totals
            balance.version += 1
            db.flush()
            self._event(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(tenant_id),
                event_type="billing.balance.rebuilt",
                idempotency_key=key,
                request_hash=digest,
                payload={
                    **payload,
                    "before": before,
                    "after": {
                        "available_minor": totals[0],
                        "reserved_minor": totals[1],
                        "consumed_minor": totals[2],
                        "version": balance.version,
                    },
                },
            )
            return self._balance_audit_view(balance, totals)

    def list_usage(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        period_start: datetime,
        period_end: datetime,
        limit: int = 100,
    ) -> tuple[UsageEventView, ...]:
        start = _time(period_start, "period_start")
        end = _time(period_end, "period_end")
        if end <= start or not 1 <= limit <= 1000:
            raise BillingControlPlaneError("billing_query_invalid", "usage query is invalid")
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._require_permission(db, actor_id, tenant_id, "billing.read")
            values = db.scalars(
                sa.select(UsageEventRecord)
                .where(
                    UsageEventRecord.tenant_id == tenant_id,
                    UsageEventRecord.occurred_at >= start,
                    UsageEventRecord.occurred_at < end,
                )
                .order_by(UsageEventRecord.occurred_at.desc(), UsageEventRecord.id.desc())
                .limit(limit)
            )
            return tuple(self._usage_view(value) for value in values)

    def list_ledger(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        period_start: datetime,
        period_end: datetime,
        limit: int = 100,
    ) -> tuple[dict[str, object], ...]:
        start = _time(period_start, "period_start")
        end = _time(period_end, "period_end")
        if end <= start or not 1 <= limit <= 1000:
            raise BillingControlPlaneError("billing_query_invalid", "ledger query is invalid")
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._require_permission(db, actor_id, tenant_id, "billing.read")
            values = db.scalars(
                sa.select(CustomerLedgerEntryRecord)
                .where(
                    CustomerLedgerEntryRecord.tenant_id == tenant_id,
                    CustomerLedgerEntryRecord.occurred_at >= start,
                    CustomerLedgerEntryRecord.occurred_at < end,
                )
                .order_by(
                    CustomerLedgerEntryRecord.occurred_at.desc(),
                    CustomerLedgerEntryRecord.id.desc(),
                )
                .limit(limit)
            )
            return tuple(
                {
                    "id": str(value.id),
                    "reservation_id": str(value.reservation_id) if value.reservation_id else None,
                    "usage_event_id": str(value.usage_event_id) if value.usage_event_id else None,
                    "operation_type": value.operation_type,
                    "amount_minor": value.amount_minor,
                    "delta_available_minor": value.delta_available_minor,
                    "delta_reserved_minor": value.delta_reserved_minor,
                    "delta_consumed_minor": value.delta_consumed_minor,
                    "currency": value.currency,
                    "occurred_at": _stored_time(value.occurred_at),
                }
                for value in values
            )

    def list_reconciliations(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        limit: int = 50,
    ) -> tuple[ReconciliationView, ...]:
        if not 1 <= limit <= 100:
            raise BillingControlPlaneError(
                "billing_query_invalid", "reconciliation query is invalid"
            )
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._require_permission(db, actor_id, tenant_id, "billing.read")
            values = db.scalars(
                sa.select(BillingReconciliationBatchRecord)
                .where(BillingReconciliationBatchRecord.tenant_id == tenant_id)
                .order_by(BillingReconciliationBatchRecord.period_end.desc())
                .limit(limit)
            )
            return tuple(self._reconciliation_view(value) for value in values)

    def list_period_closes(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        limit: int = 50,
    ) -> tuple[BillingPeriodCloseView, ...]:
        if not 1 <= limit <= 100:
            raise BillingControlPlaneError(
                "billing_query_invalid", "period-close query is invalid"
            )
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._require_permission(db, actor_id, tenant_id, "billing.read")
            values = db.scalars(
                sa.select(BillingPeriodCloseRecord)
                .where(BillingPeriodCloseRecord.tenant_id == tenant_id)
                .order_by(BillingPeriodCloseRecord.period_end.desc())
                .limit(limit)
            )
            return tuple(self._period_close_view(value) for value in values)

    def list_reconciliation_mismatches(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        batch_id: UUID,
        status: str | None = None,
        limit: int = 100,
    ) -> tuple[dict[str, object], ...]:
        if status is not None and status not in MISMATCH_STATUSES:
            raise BillingControlPlaneError("billing_query_invalid", "mismatch status is invalid")
        if not 1 <= limit <= 1000:
            raise BillingControlPlaneError("billing_query_invalid", "mismatch query is invalid")
        with self._session_factory.begin() as db:
            self._context(db, actor_id, tenant_id)
            self._require_permission(db, actor_id, tenant_id, "billing.read")
            query = sa.select(BillingReconciliationMismatchRecord).where(
                BillingReconciliationMismatchRecord.tenant_id == tenant_id,
                BillingReconciliationMismatchRecord.batch_id == batch_id,
            )
            if status is not None:
                query = query.where(BillingReconciliationMismatchRecord.status == status)
            values = db.scalars(
                query.order_by(BillingReconciliationMismatchRecord.created_at).limit(limit)
            )
            return tuple(
                {
                    "id": str(value.id),
                    "batch_id": str(value.batch_id),
                    "usage_event_id": str(value.usage_event_id),
                    "mismatch_type": value.mismatch_type,
                    "expected_minor": value.expected_minor,
                    "actual_minor": value.actual_minor,
                    "currency": value.currency,
                    "status": value.status,
                    "resolution": value.resolution,
                    "resolved_at": _stored_time(value.resolved_at) if value.resolved_at else None,
                }
                for value in values
            )

    @staticmethod
    def _context(db: Session, actor_id: UUID, tenant_id: UUID) -> None:
        apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))

    @staticmethod
    def _transaction_locks(db: Session, *keys: str) -> None:
        """Serialize exact write identities without granting UPDATE on Tenant metadata."""

        if db.get_bind().dialect.name != "postgresql":
            return
        lock_ids = sorted(
            {
                int.from_bytes(sha256(key.encode("utf-8")).digest()[:8], "big", signed=True)
                for key in keys
            }
        )
        for lock_id in lock_ids:
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": lock_id},
            )

    @staticmethod
    def _require_permission(
        db: Session, actor_id: UUID, tenant_id: UUID, permission: str
    ) -> TenantMembership:
        row = db.execute(
            sa.select(GlobalUser.status, Tenant.status, TenantMembership)
            .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
            .join(Tenant, Tenant.id == TenantMembership.tenant_id)
            .where(GlobalUser.id == actor_id, Tenant.id == tenant_id)
        ).one_or_none()
        if row is None:
            raise BillingControlPlaneError("billing_forbidden", "billing permission is required")
        user_status, tenant_status, membership = row
        if (
            user_status != "active"
            or tenant_status not in {"trial", "active", "suspended"}
            or membership.status != "active"
            or permission not in TENANT_ROLE_PERMISSIONS[membership.role]
        ):
            raise BillingControlPlaneError("billing_forbidden", "billing permission is required")
        return membership

    @staticmethod
    def _receipt(
        db: Session,
        tenant_id: UUID,
        idempotency_key: str,
        event_type: str,
        request_hash: str,
    ) -> ControlPlaneOutboxEvent | None:
        receipt = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key
                == scoped_idempotency_key("tenant", tenant_id, idempotency_key)
            )
        )
        if receipt is not None and (
            receipt.event_type != event_type or receipt.request_hash != request_hash
        ):
            raise BillingControlPlaneError(
                "billing_idempotency_conflict", "idempotency key was already used"
            )
        return receipt

    @staticmethod
    def _event(
        db: Session,
        *,
        tenant_id: UUID,
        aggregate_key: str,
        event_type: str,
        idempotency_key: str,
        request_hash: str,
        payload: dict[str, object],
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=tenant_id,
                aggregate_type="billing",
                aggregate_key=aggregate_key,
                event_type=event_type,
                payload=payload,
                idempotency_key=scoped_idempotency_key("tenant", tenant_id, idempotency_key),
                request_hash=request_hash,
                attempt_count=0,
            )
        )

    @staticmethod
    def _subscription(
        db: Session, tenant_id: UUID, *, lock: bool, required: bool = True
    ) -> BillingSubscriptionRecord | None:
        statement = sa.select(BillingSubscriptionRecord).where(
            BillingSubscriptionRecord.tenant_id == tenant_id
        )
        if lock:
            statement = statement.with_for_update()
        record = db.scalar(statement)
        if record is None and required:
            raise BillingControlPlaneError(
                "subscription_missing", "subscription is not configured"
            )
        return record

    @staticmethod
    def _balance(
        db: Session, tenant_id: UUID, currency: str, *, lock: bool
    ) -> BillingBalanceRecord:
        statement = sa.select(BillingBalanceRecord).where(
            BillingBalanceRecord.tenant_id == tenant_id
        )
        if lock:
            statement = statement.with_for_update()
        record = db.scalar(statement)
        if record is None:
            raise BillingControlPlaneError(
                "billing_balance_missing", "billing account is not configured"
            )
        if record.currency != currency:
            raise BillingControlPlaneError("billing_currency_mismatch", "billing currency differs")
        return record

    @staticmethod
    def _reservation(
        db: Session, tenant_id: UUID, reservation_id: UUID, *, lock: bool
    ) -> BillingReservationRecord:
        statement = sa.select(BillingReservationRecord).where(
            BillingReservationRecord.tenant_id == tenant_id,
            BillingReservationRecord.id == reservation_id,
        )
        if lock:
            statement = statement.with_for_update()
        record = db.scalar(statement)
        if record is None:
            raise BillingControlPlaneError(
                "billing_reservation_not_found", "reservation does not exist"
            )
        return record

    @staticmethod
    def _ledger(
        db: Session,
        *,
        tenant_id: UUID,
        reservation_id: UUID | None,
        usage_event_id: UUID | None,
        operation_type: str,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
        request_hash: str,
        actor_id: UUID,
        occurred_at: datetime,
    ) -> None:
        deltas = {
            "credit": (amount_minor, 0, 0),
            "reserve": (-amount_minor, amount_minor, 0),
            "settle": (0, -amount_minor, amount_minor),
            "release": (amount_minor, -amount_minor, 0),
            "refund": (amount_minor, 0, -amount_minor),
        }
        available, reserved, consumed = deltas[operation_type]
        db.add(
            CustomerLedgerEntryRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                reservation_id=reservation_id,
                usage_event_id=usage_event_id,
                operation_type=operation_type,
                amount_minor=amount_minor,
                delta_available_minor=available,
                delta_reserved_minor=reserved,
                delta_consumed_minor=consumed,
                currency=currency,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                created_by=actor_id,
                occurred_at=occurred_at,
            )
        )

    @staticmethod
    def _ledger_totals(db: Session, tenant_id: UUID, currency: str) -> tuple[int, int, int]:
        currencies = tuple(
            db.scalars(
                sa.select(CustomerLedgerEntryRecord.currency)
                .where(CustomerLedgerEntryRecord.tenant_id == tenant_id)
                .distinct()
            )
        )
        if any(value != currency for value in currencies):
            raise BillingControlPlaneError(
                "billing_currency_mismatch", "customer ledger contains another currency"
            )
        row = db.execute(
            sa.select(
                sa.func.coalesce(sa.func.sum(CustomerLedgerEntryRecord.delta_available_minor), 0),
                sa.func.coalesce(sa.func.sum(CustomerLedgerEntryRecord.delta_reserved_minor), 0),
                sa.func.coalesce(sa.func.sum(CustomerLedgerEntryRecord.delta_consumed_minor), 0),
            ).where(CustomerLedgerEntryRecord.tenant_id == tenant_id)
        ).one()
        totals = (int(row[0]), int(row[1]), int(row[2]))
        if any(value < 0 for value in totals):
            raise BillingControlPlaneError(
                "billing_ledger_invariant_broken", "customer ledger rebuild is negative"
            )
        return totals

    @classmethod
    def _balance_audit_view(
        cls,
        record: BillingBalanceRecord,
        totals: tuple[int, int, int],
        *,
        replayed: bool = False,
    ) -> BalanceAuditView:
        return BalanceAuditView(
            projection=cls._balance_view(record),
            ledger_available_minor=totals[0],
            ledger_reserved_minor=totals[1],
            ledger_consumed_minor=totals[2],
            consistent=(
                record.available_minor == totals[0]
                and record.reserved_minor == totals[1]
                and record.consumed_minor == totals[2]
            ),
            replayed=replayed,
        )

    @staticmethod
    def _rates(rates: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
        if not isinstance(rates, dict) or not rates or len(rates) > 128:
            raise BillingControlPlaneError("pricing_rates_invalid", "rates are invalid")
        normalized: dict[str, dict[str, object]] = {}
        for meter, raw in sorted(rates.items()):
            clean_meter = _text(meter, "meter", 128)
            if not isinstance(raw, dict) or set(raw) != {"unit", "unit_size", "minor_per_unit"}:
                raise BillingControlPlaneError("pricing_rates_invalid", "rate shape is invalid")
            unit = _text(cast(str, raw["unit"]), "unit", 64)
            unit_size = _quantity(cast(str | int, raw["unit_size"]), "unit_size")
            minor = raw["minor_per_unit"]
            if isinstance(minor, bool) or not isinstance(minor, int) or minor <= 0:
                raise BillingControlPlaneError("pricing_rates_invalid", "rate amount is invalid")
            normalized[clean_meter] = {
                "unit": unit,
                "unit_size": str(unit_size),
                "minor_per_unit": minor,
            }
        if len(json.dumps(normalized, separators=(",", ":"))) > 65536:
            raise BillingControlPlaneError("pricing_rates_invalid", "rates are oversized")
        return normalized

    @staticmethod
    def _attributes(attributes: dict[str, object]) -> dict[str, object]:
        if not isinstance(attributes, dict) or len(attributes) > 32:
            raise BillingControlPlaneError("usage_attributes_invalid", "attributes are invalid")
        for key, value in attributes.items():
            clean_key = _text(key, "attribute_key", 64)
            lowered = clean_key.lower()
            if any(token in lowered for token in _SENSITIVE_ATTRIBUTE_TOKENS):
                raise BillingControlPlaneError(
                    "usage_attributes_sensitive", "attributes cannot contain sensitive content"
                )
            if lowered not in _USAGE_ATTRIBUTE_KEYS:
                raise BillingControlPlaneError(
                    "usage_attributes_invalid", "attribute is not in the metering allowlist"
                )
            if not isinstance(value, (str, int, bool, type(None))) or (
                isinstance(value, str) and len(value) > 256
            ):
                raise BillingControlPlaneError(
                    "usage_attributes_invalid", "attributes are invalid"
                )
        if len(json.dumps(attributes, separators=(",", ":"))) > 4096:
            raise BillingControlPlaneError("usage_attributes_invalid", "attributes are oversized")
        return dict(attributes)

    @staticmethod
    def _scope_key(
        *,
        tenant_id: UUID,
        scope_type: str,
        space_id: UUID | None,
        project_id: UUID | None,
        user_id: UUID | None,
        model_key: str | None,
    ) -> str:
        shapes = {
            "tenant": space_id is None
            and project_id is None
            and user_id is None
            and model_key is None,
            "space": space_id is not None
            and project_id is None
            and user_id is None
            and model_key is None,
            "project": space_id is not None
            and project_id is not None
            and user_id is None
            and model_key is None,
            "user": space_id is None
            and project_id is None
            and user_id is not None
            and model_key is None,
            "model": space_id is None
            and project_id is None
            and user_id is None
            and model_key is not None,
        }
        if not shapes[scope_type]:
            raise BillingControlPlaneError("entitlement_scope_invalid", "scope shape is invalid")
        if scope_type == "tenant":
            return str(tenant_id)
        if scope_type == "space":
            return str(space_id)
        if scope_type == "project":
            return str(project_id)
        if scope_type == "user":
            return str(user_id)
        return _text(cast(str, model_key), "model_key", 256)

    @staticmethod
    def _amount(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 10**15:
            raise BillingControlPlaneError("billing_amount_invalid", "amount is invalid")
        return value

    @staticmethod
    def _subscription_view(
        record: BillingSubscriptionRecord, *, replayed: bool = False
    ) -> SubscriptionView:
        return SubscriptionView(
            id=record.id,
            tenant_id=record.tenant_id,
            plan_key=record.plan_key,
            status=record.status,
            provider=record.provider,
            provider_customer_ref=record.provider_customer_ref,
            provider_subscription_ref=record.provider_subscription_ref,
            current_period_start=record.current_period_start,
            current_period_end=record.current_period_end,
            trial_ends_at=record.trial_ends_at,
            cancel_at_period_end=record.cancel_at_period_end,
            version=record.version,
            replayed=replayed,
        )

    @staticmethod
    def _pricing_view(
        record: PricingSnapshotRecord, *, replayed: bool = False
    ) -> PricingSnapshotView:
        return PricingSnapshotView(
            id=record.id,
            tenant_id=record.tenant_id,
            plan_key=record.plan_key,
            currency=record.currency,
            rates=record.rates,
            version=record.version,
            effective_from=record.effective_from,
            effective_until=record.effective_until,
            replayed=replayed,
        )

    @staticmethod
    def _entitlement_view(
        record: BillingEntitlementRecord, *, replayed: bool = False
    ) -> EntitlementView:
        return EntitlementView(
            id=record.id,
            tenant_id=record.tenant_id,
            subscription_id=record.subscription_id,
            scope_type=record.scope_type,
            scope_key=record.scope_key,
            meter=record.meter,
            unit=record.unit,
            limit_quantity=record.limit_quantity,
            reserved_quantity=record.reserved_quantity,
            consumed_quantity=record.consumed_quantity,
            concurrency_limit=record.concurrency_limit,
            active_reservations=record.active_reservations,
            hard_limit=record.hard_limit,
            period=record.period,
            period_start=record.period_start,
            period_end=record.period_end,
            status=record.status,
            version=record.version,
            replayed=replayed,
        )

    @staticmethod
    def _usage_view(record: UsageEventRecord, *, replayed: bool = False) -> UsageEventView:
        return UsageEventView(
            id=record.id,
            tenant_id=record.tenant_id,
            meter=record.meter,
            quantity=record.quantity,
            unit=record.unit,
            provider=record.provider,
            provider_request_id=record.provider_request_id,
            pricing_snapshot_id=record.pricing_snapshot_id,
            currency=record.currency,
            customer_charge_minor=record.customer_charge_minor,
            occurred_at=record.occurred_at,
            replayed=replayed,
        )

    @staticmethod
    def _balance_view(record: BillingBalanceRecord) -> BalanceView:
        return BalanceView(
            tenant_id=record.tenant_id,
            currency=record.currency,
            available_minor=record.available_minor,
            reserved_minor=record.reserved_minor,
            consumed_minor=record.consumed_minor,
            version=record.version,
        )

    @staticmethod
    def _reservation_view(
        record: BillingReservationRecord, *, replayed: bool = False
    ) -> ReservationView:
        return ReservationView(
            id=record.id,
            tenant_id=record.tenant_id,
            entitlement_id=record.entitlement_id,
            usage_event_id=record.usage_event_id,
            operation_key=record.operation_key,
            meter=record.meter,
            unit=record.unit,
            reserved_quantity=record.reserved_quantity,
            settled_quantity=record.settled_quantity,
            reserved_minor=record.reserved_minor,
            settled_minor=record.settled_minor,
            released_minor=record.released_minor,
            refunded_minor=record.refunded_minor,
            currency=record.currency,
            status=record.status,
            version=record.version,
            replayed=replayed,
        )

    @staticmethod
    def _reconciliation_view(
        record: BillingReconciliationBatchRecord, *, replayed: bool = False
    ) -> ReconciliationView:
        return ReconciliationView(
            id=record.id,
            tenant_id=record.tenant_id,
            period_start=record.period_start,
            period_end=record.period_end,
            status=record.status,
            usage_event_count=record.usage_event_count,
            customer_settlement_count=record.customer_settlement_count,
            provider_cost_count=record.provider_cost_count,
            customer_charge_minor=record.customer_charge_minor,
            customer_settled_minor=record.customer_settled_minor,
            provider_cost_minor=record.provider_cost_minor,
            mismatch_count=record.mismatch_count,
            evidence_sha256=record.evidence_sha256,
            replayed=replayed,
        )

    @staticmethod
    def _period_close_view(
        record: BillingPeriodCloseRecord, *, replayed: bool = False
    ) -> BillingPeriodCloseView:
        return BillingPeriodCloseView(
            id=record.id,
            tenant_id=record.tenant_id,
            reconciliation_batch_id=record.reconciliation_batch_id,
            period_start=_stored_time(record.period_start),
            period_end=_stored_time(record.period_end),
            status=record.status,
            rolled_entitlement_count=record.rolled_entitlement_count,
            usage_event_count=record.usage_event_count,
            customer_charge_minor=record.customer_charge_minor,
            customer_settled_minor=record.customer_settled_minor,
            provider_cost_minor=record.provider_cost_minor,
            reconciliation_evidence_sha256=record.reconciliation_evidence_sha256,
            close_evidence_sha256=record.close_evidence_sha256,
            closed_by=record.closed_by,
            closed_at=_stored_time(record.closed_at),
            replayed=replayed,
        )

    @staticmethod
    def _roll_entitlement(
        entitlement: BillingEntitlementRecord, *, actor_id: UUID
    ) -> dict[str, object]:
        old_version = entitlement.version
        old_consumed = str(entitlement.consumed_quantity)
        if entitlement.period_end is None:
            raise BillingControlPlaneError(
                "billing_period_close_invalid", "periodic entitlement has no period end"
            )
        next_start = _stored_time(entitlement.period_end)
        next_end = _next_period_end(entitlement.period, next_start)
        entitlement.period_start = next_start
        entitlement.period_end = next_end
        entitlement.reserved_quantity = Decimal(0)
        entitlement.consumed_quantity = Decimal(0)
        entitlement.active_reservations = 0
        entitlement.updated_by = actor_id
        entitlement.version += 1
        return {
            "entitlement_id": str(entitlement.id),
            "old_version": old_version,
            "new_version": entitlement.version,
            "consumed_quantity": old_consumed,
            "next_period_start": next_start.isoformat(),
            "next_period_end": next_end.isoformat(),
        }
