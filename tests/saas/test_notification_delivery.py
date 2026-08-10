from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase, Tenant
from saas.control_plane.notification_delivery import (
    DeliveryProviderReceipt,
    NotificationActor,
    NotificationDeliveryError,
    NotificationDeliveryService,
    NotificationDeliveryWorker,
    NotificationEnqueueCommand,
    NotificationErrorDigester,
    NotificationTemplate,
    NotificationWorkloadIdentity,
    ResolvedRecipient,
    ResolvedRenderContext,
)
from saas.control_plane.notification_models import (
    NotificationDeliveryAttemptRecord,
    NotificationDeliveryRecord,
)
from saas.control_plane.platform_models import PlatformStaffPrincipalRecord

NOW = datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc)
OLD = NotificationErrorDigester(key_id="notification-old", secret=b"o" * 32)
NEW = NotificationErrorDigester(key_id="notification-new", secret=b"n" * 32)


@dataclass(frozen=True, slots=True)
class DeliveryHarness:
    factory: sessionmaker[Session]
    tenant_id: UUID
    other_tenant_id: UUID
    user_id: UUID
    other_user_id: UUID
    staff_id: UUID
    tenant_actor: NotificationActor
    platform_actor: NotificationActor
    template_id: UUID
    service: NotificationDeliveryService


@pytest.fixture
def delivery() -> DeliveryHarness:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id, other_tenant_id, user_id, other_user_id, staff_id = (uuid4() for _ in range(5))
    with factory.begin() as db:
        db.add_all(
            (
                Tenant(
                    id=tenant_id,
                    slug=f"notify-{tenant_id.hex}",
                    name="Notification tenant",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    lifecycle_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                Tenant(
                    id=other_tenant_id,
                    slug=f"notify-{other_tenant_id.hex}",
                    name="Other tenant",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    lifecycle_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                GlobalUser(
                    id=user_id,
                    status="active",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                GlobalUser(
                    id=other_user_id,
                    status="active",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                PlatformStaffPrincipalRecord(
                    id=staff_id,
                    identity_connection_ref=f"notification:{staff_id}",
                    issuer="https://staff-idp.example.test",
                    subject="notification-operator",
                    status="active",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            )
        )
    tenant_actor = NotificationActor("tenant", user_id, tenant_id)
    platform_actor = NotificationActor(
        "staff",
        staff_id,
        None,
        frozenset(
            {
                "platform.notification.read",
                "platform.notification.replay",
                "platform.notification_template.manage",
            }
        ),
    )
    service = NotificationDeliveryService(factory, digester=OLD)
    template = service.create_template(
        platform_actor,
        tenant_id=None,
        template_key="approval.reminder",
        channel="email",
        locale="en-US",
        version=1,
        content_artifact_handle="artifact0123456789",
        content_sha256="1" * 64,
        variables_schema_sha256="2" * 64,
        idempotency_key="template-v1",
        now=NOW,
    )
    return DeliveryHarness(
        factory=factory,
        tenant_id=tenant_id,
        other_tenant_id=other_tenant_id,
        user_id=user_id,
        other_user_id=other_user_id,
        staff_id=staff_id,
        tenant_actor=tenant_actor,
        platform_actor=platform_actor,
        template_id=template.id,
        service=service,
    )


def _enqueue(
    harness: DeliveryHarness,
    *,
    token: str,
    recipient_id: UUID | None = None,
    tenant_id: UUID | None = None,
    template_id: UUID | None = None,
) -> UUID:
    with harness.factory.begin() as db:
        rows = harness.service.enqueue_in_transaction(
            db,
            NotificationEnqueueCommand(
                realm="tenant",
                tenant_id=tenant_id or harness.tenant_id,
                recipient_id=recipient_id or harness.user_id,
                event_type="approval.reminder",
                template_key="approval.reminder",
                channels=("email",),
                template_ids={"email": template_id or harness.template_id},
                deduplication_token=token,
                render_context_values=("work-1", "approve", "deadline", "1"),
            ),
            now=NOW,
        )
    return rows[0].id


def _identity(at: datetime) -> NotificationWorkloadIdentity:
    return NotificationWorkloadIdentity(
        subject="spiffe://prod/notification-dispatcher",
        audience="omnigent:notification-delivery",
        authenticated_at=at - timedelta(seconds=1),
        expires_at=at + timedelta(minutes=4),
    )


def test_retry_budget_dlq_replay_rotation_and_platform_visibility(
    delivery: DeliveryHarness,
) -> None:
    delivery_id = _enqueue(delivery, token="eight-attempts")
    at = NOW
    for attempt in range(1, 9):
        claim = delivery.service.claim(_identity(at), now=at)
        assert claim is not None and claim.delivery_id == delivery_id
        settled = delivery.service.fail(
            claim,
            error_code="notification_provider_unavailable",
            provider_status=503,
            retryable=True,
            now=at,
        )
        assert settled.status == ("dead_letter" if attempt == 8 else "retry")
        at = settled.available_at or at

    dlq = delivery.service.list_deliveries(delivery.platform_actor, status="dead_letter", now=at)
    assert [value.id for value in dlq.items] == [delivery_id]
    own_only = replace(
        delivery.platform_actor,
        permissions=frozenset(),
    )
    assert not delivery.service.list_deliveries(own_only, status="dead_letter", now=at).items

    rotated = NotificationDeliveryService(
        delivery.factory, digester=NEW, previous_digesters=(OLD,)
    )
    first = rotated.replay(
        delivery.platform_actor,
        delivery_id=delivery_id,
        expected_version=17,
        idempotency_key="replay-one",
        now=at,
    )
    assert first.replay_generation == 1
    claim = rotated.claim(_identity(at), now=at)
    assert claim is not None
    second_dlq = rotated.fail(
        claim,
        error_code="notification_provider_rejected",
        provider_status=400,
        retryable=False,
        now=at,
    )
    second = rotated.replay(
        delivery.platform_actor,
        delivery_id=delivery_id,
        expected_version=second_dlq.attempt_number + 19,
        idempotency_key="replay-two",
        now=at + timedelta(seconds=1),
    )
    assert second.replay_generation == 2

    with delivery.factory.begin() as db:
        replayed = rotated.enqueue_in_transaction(
            db,
            NotificationEnqueueCommand(
                realm="tenant",
                tenant_id=delivery.tenant_id,
                recipient_id=delivery.user_id,
                event_type="approval.reminder",
                template_key="approval.reminder",
                channels=("email",),
                template_ids={"email": delivery.template_id},
                deduplication_token="eight-attempts",
                render_context_values=("work-1", "approve", "deadline", "1"),
            ),
            now=at,
        )
    assert replayed[0].id == delivery_id
    with delivery.factory.begin() as db:
        row = db.get(NotificationDeliveryRecord, delivery_id)
        assert row is not None and row.hmac_key_id == OLD.key_id


def test_explicit_template_scope_and_template_idempotency(
    delivery: DeliveryHarness,
) -> None:
    replay = delivery.service.create_template(
        delivery.platform_actor,
        tenant_id=None,
        template_key="approval.reminder",
        channel="email",
        locale="en-US",
        version=1,
        content_artifact_handle="artifact0123456789",
        content_sha256="1" * 64,
        variables_schema_sha256="2" * 64,
        idempotency_key="template-v1",
        now=NOW,
    )
    assert replay.replayed and replay.id == delivery.template_id

    override = delivery.service.create_template(
        delivery.platform_actor,
        tenant_id=delivery.other_tenant_id,
        template_key="approval.reminder",
        channel="email",
        locale="en-US",
        version=2,
        content_artifact_handle="tenantoverride1234",
        content_sha256="3" * 64,
        variables_schema_sha256="4" * 64,
        idempotency_key="other-tenant-v2",
        now=NOW,
    )
    with pytest.raises(NotificationDeliveryError) as raised:
        _enqueue(delivery, token="cross-tenant-template", template_id=override.id)
    assert raised.value.code == "notification_template_not_found"


def test_claim_envelope_and_authority_inputs_are_revalidated(
    delivery: DeliveryHarness,
) -> None:
    delivery_id = _enqueue(delivery, token="authority-boundary")
    claim = delivery.service.claim(_identity(NOW), now=NOW)
    assert claim is not None and claim.delivery_id == delivery_id

    with pytest.raises(NotificationDeliveryError) as raised:
        delivery.service.ensure_sendable(
            replace(claim, recipient_id=delivery.other_user_id), now=NOW
        )
    assert raised.value.code == "notification_delivery_claim_invalid"

    with pytest.raises(NotificationDeliveryError) as raised:
        delivery.service.ensure_sendable(replace(claim, source_delivery_id=uuid4()), now=NOW)
    assert raised.value.code == "notification_delivery_claim_invalid"

    with pytest.raises(NotificationDeliveryError) as raised:
        delivery.service.complete(
            claim,
            receipt=DeliveryProviderReceipt(
                provider="smtp",
                provider_request_hmac="raw-request",
                provider_receipt_hmac="5" * 64,
                provider_message_hmac="6" * 64,
            ),
            now=NOW,
        )
    assert raised.value.code == "notification_provider_receipt_invalid"

    with pytest.raises(NotificationDeliveryError) as raised:
        delivery.service.fail(
            claim,
            error_code="smtp said user@example.test was rejected",
            provider_status=400,
            retryable=False,
            now=NOW,
        )
    assert raised.value.code == "notification_delivery_failure_invalid"
    with delivery.factory.begin() as db:
        row = db.get(NotificationDeliveryRecord, delivery_id)
        assert row is not None and row.status == "leased"
        assert not db.execute(sa.select(NotificationDeliveryAttemptRecord)).scalars().all()


def test_dead_letter_alert_requires_an_immutable_source_delivery(
    delivery: DeliveryHarness,
) -> None:
    with pytest.raises(NotificationDeliveryError) as raised:
        with delivery.factory.begin() as db:
            delivery.service.enqueue_in_transaction(
                db,
                NotificationEnqueueCommand(
                    realm="staff",
                    tenant_id=delivery.tenant_id,
                    recipient_id=delivery.staff_id,
                    event_type="notification.delivery_dead_letter",
                    template_key="notification.delivery_dead_letter",
                    channels=("email",),
                    template_ids={"email": delivery.template_id},
                    deduplication_token="missing-dead-letter-source",
                    render_context_values=("delivery", "0"),
                ),
                now=NOW,
            )
    assert raised.value.code == "notification_dead_letter_source_invalid"


def test_worker_uses_fresh_clock_after_provider_io(delivery: DeliveryHarness) -> None:
    delivery_id = _enqueue(delivery, token="slow-provider")
    times = iter((NOW, NOW, NOW, NOW + timedelta(seconds=31)))

    class IdentityProvider:
        def identity(self, *, now: datetime) -> NotificationWorkloadIdentity:
            return _identity(now)

    class ContextResolver:
        def resolve(self, **values: object) -> ResolvedRenderContext:
            at = values["now"]
            assert isinstance(at, datetime)
            return ResolvedRenderContext(
                variables={}, purpose="notification_render", expires_at=at + timedelta(minutes=1)
            )

    class AddressResolver:
        def resolve(self, **values: object) -> ResolvedRecipient:
            at = values["now"]
            assert isinstance(at, datetime)
            return ResolvedRecipient(
                address="recipient@example.test",
                purpose="notification_delivery",
                expires_at=at + timedelta(minutes=1),
            )

    class Catalog:
        def get(self, **values: object) -> NotificationTemplate:
            return NotificationTemplate(
                key="approval.reminder",
                locale="en-US",
                version=1,
                subject="Approval reminder",
                body="Open your approval inbox.",
                allowed_variables=frozenset(),
            )

    class Provider:
        sent = 0

        def send(self, **values: object) -> DeliveryProviderReceipt:
            self.sent += 1
            return DeliveryProviderReceipt("smtp", "7" * 64, "8" * 64, "9" * 64)

    provider = Provider()
    worker = NotificationDeliveryWorker(
        delivery.service,
        IdentityProvider(),
        AddressResolver(),
        ContextResolver(),
        Catalog(),
        provider,
        clock=lambda: next(times),
    )
    settled = worker.deliver_once(now=NOW)
    assert settled is not None and settled.status == "lease_lost"
    assert provider.sent == 1
    with delivery.factory.begin() as db:
        row = db.get(NotificationDeliveryRecord, delivery_id)
        assert row is not None and row.status == "leased"
        assert row.delivered_at is None


def test_secret_dataclass_repr_is_content_blind() -> None:
    rendered = NotificationTemplate(
        key="k",
        locale="en-US",
        version=1,
        subject="subject-secret",
        body="body-secret",
        allowed_variables=frozenset(),
    )
    identity = NotificationWorkloadIdentity(
        subject="spiffe-secret",
        audience="omnigent:notification-delivery",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    assert "subject-secret" not in repr(rendered)
    assert "body-secret" not in repr(rendered)
    assert "spiffe-secret" not in repr(identity)
