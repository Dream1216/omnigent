from __future__ import annotations

from datetime import timedelta

import pytest
import sqlalchemy as sa

from saas.control_plane.billing import BillingControlPlane, BillingControlPlaneError
from saas.control_plane.billing_models import (
    BillingReconciliationBatchRecord,
    CustomerLedgerEntryRecord,
    ProviderCostEntryRecord,
    UsageEventRecord,
)
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.outbox import OutboxDispatcher, OutboxPublishError
from saas.control_plane.outbox_delivery import UsageReconciliationConsumer
from saas.control_plane.outbox_delivery_models import UsageReconciliationIngressRecord
from saas.observability import SloMetrics
from tests.saas.test_billing_control_plane import NOW, _bootstrap
from tests.saas.test_billing_control_plane import billing as billing


def _usage(control, tenant, owner, pricing):
    return control.record_usage(
        actor_id=owner,
        tenant_id=tenant,
        pricing_snapshot_id=pricing,
        meter="llm.input_tokens",
        quantity="1000",
        unit="tokens",
        provider="openai",
        provider_request_id="consumer-native-request",
        idempotency_key="consumer-native-usage",
        occurred_at=NOW + timedelta(minutes=1),
    )


def _event(factory):
    with factory() as db:
        row = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_type == "billing",
                ControlPlaneOutboxEvent.event_type == "billing.usage.recorded",
            )
        )
        return {
            "event_id": row.id,
            "aggregate_type": row.aggregate_type,
            "event_type": row.event_type,
            "aggregate_key": row.aggregate_key,
            "payload": row.payload,
        }


def test_actual_usage_outbox_delivery_has_real_ingress_and_no_financial_side_effect(billing):
    control, factory, tenant, owner, _ = billing
    pricing, _ = _bootstrap(control, tenant, owner)
    usage = _usage(control, tenant, owner, pricing)
    strict = BillingControlPlane(factory, require_usage_ingress=True)
    kwargs = {
        "actor_id": owner,
        "tenant_id": tenant,
        "period_start": NOW,
        "period_end": NOW + timedelta(days=1),
        "idempotency_key": "real-ingress-reconcile",
    }
    with pytest.raises(BillingControlPlaneError) as pending:
        strict.reconcile(**kwargs)
    assert pending.value.code == "usage_ingress_pending"
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(BillingReconciliationBatchRecord))
            == 0
        )
    metrics = SloMetrics()
    consumer = UsageReconciliationConsumer(factory, product_revision="a" * 40, metrics=metrics)
    dispatcher = OutboxDispatcher(factory, consumer, claim_routes=consumer.claim_routes)
    actual = dispatcher.dispatch_once()
    assert (actual.claimed, actual.published, actual.failed) == (1, 1, 0)
    consumer.publish(**_event(factory))
    with factory() as db:
        receipt = db.scalar(sa.select(UsageReconciliationIngressRecord))
        assert receipt.usage_event_id == usage.id and receipt.pricing_snapshot_id == pricing
        assert receipt.facts["usage"]["customer_charge_minor"] == 25
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(UsageReconciliationIngressRecord))
            == 1
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(CustomerLedgerEntryRecord)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(ProviderCostEntryRecord)) == 0
    report = strict.reconcile(**kwargs)
    assert report.status == "exception" and report.provider_cost_count == 0
    assert report.customer_settlement_count == 0  # Real missing finance is not fabricated green.
    rendered = metrics.render().decode()
    assert 'stage="outbox_usage_delivery",outcome="success"' in rendered
    assert 'stage="outbox_usage_delivery",outcome="replayed"' in rendered
    assert str(tenant) not in rendered and "consumer-native-request" not in rendered


def test_committed_receiver_fact_recovers_after_actual_postcommit_ack_failure(billing):
    control, factory, tenant, owner, _ = billing
    pricing, _ = _bootstrap(control, tenant, owner)
    _usage(control, tenant, owner, pricing)
    consumer = UsageReconciliationConsumer(factory, product_revision="a" * 40)
    original = consumer._source
    calls = [0]

    def fail_readback_once(db, event_id, event):
        calls[0] += 1
        if calls[0] == 2:
            raise OutboxPublishError(
                "injected_readback_failure", retryable=True, pre_side_effect=False
            )
        return original(db, event_id, event)

    consumer._source = fail_readback_once
    with pytest.raises(OutboxPublishError):
        consumer.publish(**_event(factory))
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(UsageReconciliationIngressRecord))
            == 1
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(CustomerLedgerEntryRecord)) == 0
    consumer._source = original
    consumer.publish(**_event(factory))
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(UsageReconciliationIngressRecord))
            == 1
        )


def test_source_and_inbox_tamper_are_rejected_and_unknown_route_not_consumed(billing):
    control, factory, tenant, owner, _ = billing
    pricing, _ = _bootstrap(control, tenant, owner)
    _usage(control, tenant, owner, pricing)
    consumer = UsageReconciliationConsumer(factory, product_revision="a" * 40)
    event = _event(factory)
    forged = {**event, "payload": {**event["payload"], "customer_charge_minor": 0}}
    with pytest.raises(OutboxPublishError) as rejected:
        consumer.publish(**forged)
    assert rejected.value.code == "usage_source_mismatch"
    consumer.publish(**event)
    with factory.kw["bind"].begin() as connection:
        connection.execute(sa.update(UsageEventRecord).values(customer_charge_minor=999))
    with pytest.raises(OutboxPublishError) as changed:
        consumer.publish(**event)
    assert changed.value.code == "usage_payload_mismatch"
    with pytest.raises(OutboxPublishError):
        consumer.publish(**{**event, "event_type": "billing.reservation.settled"})
