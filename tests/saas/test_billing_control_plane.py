from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.billing import BillingControlPlane, BillingControlPlaneError
from saas.control_plane.billing_models import (
    BillingBalanceRecord,
    BillingEntitlementRecord,
    BillingReconciliationMismatchRecord,
    BillingReservationRecord,
    CustomerLedgerEntryRecord,
    PricingSnapshotRecord,
    ProviderCostEntryRecord,
    UsageEventRecord,
)
from saas.control_plane.db_models import GlobalUser, SaasBase, Tenant, TenantMembership

NOW = datetime(2026, 8, 6, 4, tzinfo=timezone.utc)


@pytest.fixture
def billing() -> tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID]:
    engine = sa.create_engine("sqlite://", connect_args={"check_same_thread": False})

    @sa.event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_connection: object, _record: object) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[attr-defined]

    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    owner_id = uuid4()
    billing_admin_id = uuid4()
    member_id = uuid4()
    tenant_id = uuid4()
    with factory.begin() as db:
        db.add_all(
            [
                GlobalUser(id=owner_id, status="active", security_version=1),
                GlobalUser(id=billing_admin_id, status="active", security_version=1),
                GlobalUser(id=member_id, status="active", security_version=1),
                Tenant(
                    id=tenant_id,
                    slug=f"billing-{tenant_id.hex}",
                    name="Billing",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=owner_id,
                    role="owner",
                    status="active",
                    version=1,
                ),
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=billing_admin_id,
                    role="billing_admin",
                    status="active",
                    version=1,
                ),
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=member_id,
                    role="member",
                    status="active",
                    version=1,
                ),
            ]
        )
    return BillingControlPlane(factory), factory, tenant_id, owner_id, member_id


def _bootstrap(control: BillingControlPlane, tenant_id: UUID, owner_id: UUID) -> tuple[UUID, UUID]:
    subscription = control.configure_subscription(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v1",
        status="active",
        current_period_start=NOW,
        current_period_end=NOW + timedelta(days=30),
        expected_version=None,
        idempotency_key="subscription-create",
    )
    pricing = control.create_pricing_snapshot(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v1",
        currency="USD",
        rates={
            "llm.input_tokens": {
                "unit": "tokens",
                "unit_size": "1000",
                "minor_per_unit": 25,
            }
        },
        effective_from=NOW,
        effective_until=NOW + timedelta(days=30),
        idempotency_key="pricing-create",
    )
    entitlement = control.set_entitlement(
        actor_id=owner_id,
        tenant_id=tenant_id,
        scope_type="tenant",
        meter="llm.input_tokens",
        unit="tokens",
        limit_quantity="100000",
        concurrency_limit=2,
        hard_limit=True,
        period="month",
        period_start=NOW,
        period_end=NOW + timedelta(days=30),
        status="active",
        expected_version=None,
        idempotency_key="entitlement-create",
    )
    assert entitlement.subscription_id == subscription.id
    return pricing.id, entitlement.id


def test_idempotency_replay_rechecks_current_billing_permission(
    billing: tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID],
) -> None:
    control, _factory, tenant_id, owner_id, member_id = billing
    _bootstrap(control, tenant_id, owner_id)

    with pytest.raises(BillingControlPlaneError) as error:
        control.configure_subscription(
            actor_id=member_id,
            tenant_id=tenant_id,
            plan_key="team-v1",
            status="active",
            current_period_start=NOW,
            current_period_end=NOW + timedelta(days=30),
            expected_version=None,
            idempotency_key="subscription-create",
        )

    assert error.value.code == "billing_forbidden"


def test_reserve_settle_refund_preserves_customer_ledger_and_quota(
    billing: tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID],
) -> None:
    control, factory, tenant_id, owner_id, _member_id = billing
    pricing_id, entitlement_id = _bootstrap(control, tenant_id, owner_id)
    credited = control.grant_credit(
        actor_id=owner_id,
        tenant_id=tenant_id,
        amount_minor=1000,
        currency="USD",
        idempotency_key="credit-1",
        occurred_at=NOW,
    )
    assert credited.available_minor == 1000
    reservation = control.reserve(
        actor_id=owner_id,
        tenant_id=tenant_id,
        entitlement_id=entitlement_id,
        operation_key="run-42-input",
        quantity="5000",
        amount_minor=200,
        currency="USD",
        idempotency_key="reserve-1",
        now=NOW + timedelta(minutes=1),
    )
    usage = control.record_usage(
        actor_id=owner_id,
        tenant_id=tenant_id,
        pricing_snapshot_id=pricing_id,
        meter="llm.input_tokens",
        quantity="2500",
        unit="tokens",
        provider="openai",
        provider_request_id="provider-request-42",
        idempotency_key="usage-1",
        occurred_at=NOW + timedelta(minutes=2),
        attributes={"model": "gpt-5"},
    )
    assert usage.customer_charge_minor == 63
    settled = control.settle(
        actor_id=owner_id,
        tenant_id=tenant_id,
        reservation_id=reservation.id,
        usage_event_id=usage.id,
        idempotency_key="settle-1",
        now=NOW + timedelta(minutes=3),
    )
    assert settled.status == "settled"
    assert settled.settled_minor == 63
    assert settled.released_minor == 137
    replay = control.settle(
        actor_id=owner_id,
        tenant_id=tenant_id,
        reservation_id=reservation.id,
        usage_event_id=usage.id,
        idempotency_key="settle-1",
        now=NOW + timedelta(minutes=4),
    )
    assert replay.replayed is True
    refunded = control.refund(
        actor_id=owner_id,
        tenant_id=tenant_id,
        reservation_id=reservation.id,
        idempotency_key="refund-1",
        now=NOW + timedelta(minutes=5),
    )
    assert refunded.status == "refunded"

    with factory.begin() as db:
        entries = tuple(
            db.scalars(
                sa.select(CustomerLedgerEntryRecord)
                .where(CustomerLedgerEntryRecord.tenant_id == tenant_id)
                .order_by(CustomerLedgerEntryRecord.occurred_at, CustomerLedgerEntryRecord.id)
            )
        )
        assert sorted(entry.operation_type for entry in entries) == [
            "credit",
            "refund",
            "release",
            "reserve",
            "settle",
        ]
        assert sum(entry.delta_reserved_minor for entry in entries) == 0
        assert sum(entry.delta_consumed_minor for entry in entries) == 0
        assert sum(entry.delta_available_minor for entry in entries) == 1000
        entitlement = db.get(BillingEntitlementRecord, entitlement_id)
        assert entitlement is not None
        assert entitlement.reserved_quantity == 0
        assert entitlement.consumed_quantity == Decimal("2500")
        assert entitlement.active_reservations == 0

    overview = control.get_overview(actor_id=owner_id, tenant_id=tenant_id)
    balance = overview["balance"]
    assert balance is not None
    assert balance.available_minor == 1000
    assert balance.reserved_minor == 0
    assert balance.consumed_minor == 0


def test_pricing_windows_are_non_overlapping_and_adjacent_versions_are_allowed(
    billing: tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID],
) -> None:
    control, _factory, tenant_id, owner_id, _member_id = billing
    first_id, _entitlement_id = _bootstrap(control, tenant_id, owner_id)
    with pytest.raises(BillingControlPlaneError) as overlap:
        control.create_pricing_snapshot(
            actor_id=owner_id,
            tenant_id=tenant_id,
            plan_key="team-v1",
            currency="USD",
            rates={
                "llm.input_tokens": {
                    "unit": "tokens",
                    "unit_size": "1000",
                    "minor_per_unit": 30,
                }
            },
            effective_from=NOW + timedelta(days=29),
            effective_until=NOW + timedelta(days=60),
            idempotency_key="pricing-overlap",
        )
    assert overlap.value.code == "pricing_window_overlap"

    second = control.create_pricing_snapshot(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v1",
        currency="USD",
        rates={
            "llm.input_tokens": {
                "unit": "tokens",
                "unit_size": "1000",
                "minor_per_unit": 30,
            }
        },
        effective_from=NOW + timedelta(days=30),
        effective_until=NOW + timedelta(days=60),
        idempotency_key="pricing-adjacent",
    )
    assert second.version == 2
    assert second.id != first_id


def test_balance_projection_is_auditable_and_rebuilds_only_from_ledger(
    billing: tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID],
) -> None:
    control, factory, tenant_id, owner_id, _member_id = billing
    _bootstrap(control, tenant_id, owner_id)
    credited = control.grant_credit(
        actor_id=owner_id,
        tenant_id=tenant_id,
        amount_minor=500,
        currency="USD",
        idempotency_key="projection-credit",
        occurred_at=NOW,
    )
    assert control.audit_balance(actor_id=owner_id, tenant_id=tenant_id).consistent is True

    with factory.begin() as db:
        projection = db.get(BillingBalanceRecord, tenant_id)
        assert projection is not None
        projection.available_minor = 7

    drifted = control.audit_balance(actor_id=owner_id, tenant_id=tenant_id)
    assert drifted.consistent is False
    assert drifted.projection.available_minor == 7
    assert drifted.ledger_available_minor == 500
    rebuilt = control.rebuild_balance(
        actor_id=owner_id,
        tenant_id=tenant_id,
        expected_version=credited.version,
        reason="Projection drift injected by the recovery acceptance fixture.",
        idempotency_key="projection-rebuild",
    )
    assert rebuilt.consistent is True
    assert rebuilt.projection.available_minor == 500
    assert rebuilt.projection.version == credited.version + 1
    replay = control.rebuild_balance(
        actor_id=owner_id,
        tenant_id=tenant_id,
        expected_version=credited.version,
        reason="Projection drift injected by the recovery acceptance fixture.",
        idempotency_key="projection-rebuild",
    )
    assert replay.replayed is True
    assert replay.consistent is True


def test_reconciliation_is_exception_until_provider_cost_is_present(
    billing: tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID],
) -> None:
    control, factory, tenant_id, owner_id, _member_id = billing
    pricing_id, entitlement_id = _bootstrap(control, tenant_id, owner_id)
    control.grant_credit(
        actor_id=owner_id,
        tenant_id=tenant_id,
        amount_minor=1000,
        currency="USD",
        idempotency_key="credit-reconcile",
        occurred_at=NOW,
    )
    reservation = control.reserve(
        actor_id=owner_id,
        tenant_id=tenant_id,
        entitlement_id=entitlement_id,
        operation_key="reconcile-run",
        quantity="1000",
        amount_minor=100,
        currency="USD",
        idempotency_key="reserve-reconcile",
        now=NOW,
    )
    usage = control.record_usage(
        actor_id=owner_id,
        tenant_id=tenant_id,
        pricing_snapshot_id=pricing_id,
        meter="llm.input_tokens",
        quantity="1000",
        unit="tokens",
        provider="openai",
        provider_request_id="reconcile-provider-request",
        idempotency_key="usage-reconcile",
        occurred_at=NOW + timedelta(minutes=1),
    )
    control.settle(
        actor_id=owner_id,
        tenant_id=tenant_id,
        reservation_id=reservation.id,
        usage_event_id=usage.id,
        idempotency_key="settle-reconcile",
        now=NOW + timedelta(minutes=2),
    )
    batch = control.reconcile(
        actor_id=owner_id,
        tenant_id=tenant_id,
        period_start=NOW,
        period_end=NOW + timedelta(days=1),
        idempotency_key="reconcile-day-1",
    )
    assert batch.status == "exception"
    assert batch.mismatch_count == 1
    with factory.begin() as db:
        mismatch = db.scalar(
            sa.select(BillingReconciliationMismatchRecord).where(
                BillingReconciliationMismatchRecord.batch_id == batch.id
            )
        )
        assert mismatch is not None
        assert mismatch.mismatch_type == "missing_provider_cost"
    control.resolve_mismatch(
        actor_id=owner_id,
        tenant_id=tenant_id,
        mismatch_id=mismatch.id,
        resolution="Provider invoice is pending; finance case FIN-42 owns closure.",
        idempotency_key="resolve-mismatch-1",
        now=NOW + timedelta(days=1, minutes=1),
    )


def test_complete_reconciliation_keeps_provider_and_customer_amounts_separate(
    billing: tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID],
) -> None:
    control, _factory, tenant_id, owner_id, _member_id = billing
    pricing_id, entitlement_id = _bootstrap(control, tenant_id, owner_id)
    control.grant_credit(
        actor_id=owner_id,
        tenant_id=tenant_id,
        amount_minor=1000,
        currency="USD",
        idempotency_key="credit-complete",
        occurred_at=NOW,
    )
    reservation = control.reserve(
        actor_id=owner_id,
        tenant_id=tenant_id,
        entitlement_id=entitlement_id,
        operation_key="complete-run",
        quantity="1000",
        amount_minor=100,
        currency="USD",
        idempotency_key="reserve-complete",
        now=NOW,
    )
    usage = control.record_usage(
        actor_id=owner_id,
        tenant_id=tenant_id,
        pricing_snapshot_id=pricing_id,
        meter="llm.input_tokens",
        quantity="1000",
        unit="tokens",
        provider="openai",
        provider_request_id="complete-provider-request",
        idempotency_key="usage-complete",
        occurred_at=NOW + timedelta(minutes=1),
    )
    control.settle(
        actor_id=owner_id,
        tenant_id=tenant_id,
        reservation_id=reservation.id,
        usage_event_id=usage.id,
        idempotency_key="settle-complete",
        now=NOW + timedelta(minutes=2),
    )
    control.record_provider_cost(
        actor_id=owner_id,
        tenant_id=tenant_id,
        usage_event_id=usage.id,
        provider="openai",
        provider_receipt_id="invoice-line-42",
        kind="final",
        amount_minor=9,
        currency="USD",
        occurred_at=NOW + timedelta(minutes=3),
        idempotency_key="provider-cost-complete",
    )
    batch = control.reconcile(
        actor_id=owner_id,
        tenant_id=tenant_id,
        period_start=NOW,
        period_end=NOW + timedelta(days=1),
        idempotency_key="reconcile-complete",
    )
    assert batch.status == "completed"
    assert batch.mismatch_count == 0
    assert batch.customer_charge_minor == 25
    assert batch.customer_settled_minor == 25
    assert batch.provider_cost_minor == 9


def test_member_cannot_read_or_mutate_billing(
    billing: tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID],
) -> None:
    control, _factory, tenant_id, owner_id, member_id = billing
    _bootstrap(control, tenant_id, owner_id)
    with pytest.raises(BillingControlPlaneError) as read_error:
        control.get_overview(actor_id=member_id, tenant_id=tenant_id)
    assert read_error.value.code == "billing_forbidden"
    with pytest.raises(BillingControlPlaneError) as write_error:
        control.grant_credit(
            actor_id=member_id,
            tenant_id=tenant_id,
            amount_minor=100,
            currency="USD",
            idempotency_key="member-credit",
            occurred_at=NOW,
        )
    assert write_error.value.code == "billing_forbidden"


def test_pricing_usage_and_ledgers_store_decimal_or_integer_not_float(
    billing: tuple[BillingControlPlane, sessionmaker[Session], UUID, UUID, UUID],
) -> None:
    control, factory, tenant_id, owner_id, _member_id = billing
    pricing_id, _entitlement_id = _bootstrap(control, tenant_id, owner_id)
    usage = control.record_usage(
        actor_id=owner_id,
        tenant_id=tenant_id,
        pricing_snapshot_id=pricing_id,
        meter="llm.input_tokens",
        quantity="1.250000000001",
        unit="tokens",
        provider="openai",
        provider_request_id="decimal-provider-request",
        idempotency_key="decimal-usage",
        occurred_at=NOW,
    )
    assert usage.quantity == Decimal("1.250000000001")
    with pytest.raises(BillingControlPlaneError):
        control.record_usage(
            actor_id=owner_id,
            tenant_id=tenant_id,
            pricing_snapshot_id=pricing_id,
            meter="llm.input_tokens",
            quantity=1.25,  # type: ignore[arg-type]
            unit="tokens",
            provider="openai",
            provider_request_id="float-provider-request",
            idempotency_key="float-usage",
            occurred_at=NOW,
        )
    with pytest.raises(BillingControlPlaneError) as content_error:
        control.record_usage(
            actor_id=owner_id,
            tenant_id=tenant_id,
            pricing_snapshot_id=pricing_id,
            meter="llm.input_tokens",
            quantity="1",
            unit="tokens",
            provider="openai",
            provider_request_id="content-bearing-provider-request",
            idempotency_key="content-bearing-usage",
            occurred_at=NOW,
            attributes={"input": "customer prompt material"},
        )
    assert content_error.value.code == "usage_attributes_invalid"
    with factory.begin() as db:
        pricing = db.get(PricingSnapshotRecord, pricing_id)
        stored = db.get(UsageEventRecord, usage.id)
        assert pricing is not None and pricing.rates["llm.input_tokens"]["unit_size"] == "1000"
        assert stored is not None and isinstance(stored.quantity, Decimal)
        assert db.scalar(sa.select(sa.func.count(ProviderCostEntryRecord.id))) == 0
        assert db.scalar(sa.select(sa.func.count(BillingReservationRecord.id))) == 0
