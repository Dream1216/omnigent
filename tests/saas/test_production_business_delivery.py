from __future__ import annotations

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.outbox import OutboxClaimRoute, OutboxDispatcher, OutboxPublishError
from saas.control_plane.outbox_delivery import UsageReconciliationConsumer
from saas.control_plane.outbox_delivery_models import UsageReconciliationIngressRecord
from saas.control_plane.revocation import RevocationFanoutPublisher
from saas.production.business_delivery import BusinessDeliveryPublisher, _https
from tests.saas.test_billing_control_plane import _bootstrap
from tests.saas.test_billing_control_plane import billing as billing
from tests.saas.test_outbox_business_delivery import _usage


@pytest.mark.parametrize(
    "value",
    [
        False,
        None,
        "http://kms.example",
        "https://user:password@kms.example",
        "https://kms.example/path",
        "https://kms.example?redirect=other",
        "https://kms.example#other",
    ],
)
def test_native_business_endpoint_never_uses_default_tls_or_embedded_authority(value):
    with pytest.raises(ValueError, match="explicit HTTPS authority"):
        _https(value)


def test_actual_dispatcher_claims_usage_only_and_preserves_unsupported_original_event(billing):
    control, factory, tenant, owner, _ = billing
    pricing, _ = _bootstrap(control, tenant, owner)
    _usage(control, tenant, owner, pricing)
    with factory.begin() as db:
        unknown = ControlPlaneOutboxEvent(
            tenant_id=tenant,
            aggregate_type="platform_support",
            aggregate_key="unchanged",
            event_type="platform.support.grant.approved",
            payload={"original": "business-contract"},
            request_hash="a" * 64,
            idempotency_key="unsupported-typed-publisher",
        )
        db.add(unknown)
        db.flush()
        unknown_id = unknown.id

    class NeverCalled:
        def __init__(self, routes):
            self.claim_routes = routes

        def publish(self, **event):
            raise AssertionError("different typed consumer was invoked")

    publisher = BusinessDeliveryPublisher(
        UsageReconciliationConsumer(factory, product_revision="a" * 40),
        NeverCalled((OutboxClaimRoute("platform_audit", "platform.audit.persisted"),)),
        NeverCalled(RevocationFanoutPublisher.claim_routes),
        engines={},
        signer=None,
        storage_client=None,
    )
    result = OutboxDispatcher(
        factory, publisher, claim_routes=publisher.claim_routes
    ).dispatch_once()
    assert (result.claimed, result.published, result.failed) == (1, 1, 0)
    with factory() as db:
        original = db.get(ControlPlaneOutboxEvent, unknown_id)
        assert original.published_at is None and original.attempt_count == 0
        assert original.payload == {"original": "business-contract"}
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(UsageReconciliationIngressRecord))
            == 1
        )
    with pytest.raises(OutboxPublishError) as denied:
        publisher.publish(
            event_id=unknown_id,
            aggregate_type="platform_support",
            aggregate_key="unchanged",
            event_type="platform.support.grant.approved",
            payload={"original": "business-contract"},
        )
    assert denied.value.code == "unsupported_business_route"
