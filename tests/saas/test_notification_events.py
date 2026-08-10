from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.approval_operations import (
    ApprovalProjectionCommand,
    ApprovalProjectionService,
    ApprovalTerminalCommand,
    ApprovalWorkItemView,
)
from saas.control_plane.db_models import GlobalUser, SaasBase, Tenant
from saas.control_plane.notification_delivery import (
    NotificationActor,
    NotificationDeliveryError,
    NotificationDeliveryService,
    NotificationErrorDigester,
    NotificationWorkloadIdentity,
)
from saas.control_plane.notification_events import (
    DeadLetterNotificationSink,
    SourceApprovalNotificationService,
)
from saas.control_plane.notification_models import (
    ApprovalWorkItemRecord,
    NotificationDeliveryRecord,
)
from saas.control_plane.notification_templates import (
    NotificationTemplateBootstrap,
    PackagedNotificationTemplateCatalog,
)
from saas.control_plane.platform_models import PlatformStaffPrincipalRecord

NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


class Audience:
    def __init__(self, approver_id: object) -> None:
        self.approver_id = approver_id

    def eligible_actor_ids_in_transaction(
        self,
        db: object,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[object, ...]:
        del db, work_item, now, limit
        return (self.approver_id,)


class PlatformAudience:
    def __init__(self, operator_id: object) -> None:
        self.operator_id = operator_id

    def eligible_operator_ids(
        self,
        *,
        tenant_id: object,
        permission: str,
        now: datetime,
        limit: int,
    ) -> tuple[object, ...]:
        del tenant_id, now, limit
        assert permission == "platform.notification.read"
        return (self.operator_id,)


def test_default_bootstrap_catalog_and_transaction_local_source_events() -> None:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id, requester_id, approver_id, staff_id = (uuid4() for _ in range(4))
    with factory.begin() as db:
        db.add(
            Tenant(
                id=tenant_id,
                slug=f"events-{tenant_id.hex}",
                name="Notification events tenant",
                status="active",
                plan="enterprise",
                home_region="cn-east-1",
                lifecycle_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.add_all(
            GlobalUser(
                id=value,
                status="active",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
            for value in (requester_id, approver_id)
        )
        db.add(
            PlatformStaffPrincipalRecord(
                id=staff_id,
                identity_connection_ref=f"events:{staff_id}",
                issuer="https://staff-idp.example.test",
                subject="notification-bootstrap",
                status="active",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    delivery = NotificationDeliveryService(
        factory,
        digester=NotificationErrorDigester("events-key", b"e" * 32),
        dead_letter_sink=DeadLetterNotificationSink(
            PlatformAudience(staff_id)  # type: ignore[arg-type]
        ),
    )
    projection = ApprovalProjectionService()
    notifier = SourceApprovalNotificationService(
        delivery,
        Audience(approver_id),  # type: ignore[arg-type]
    )
    operation_id, work_item_id = uuid4(), uuid4()
    command = ApprovalProjectionCommand(
        work_item_id=work_item_id,
        source_authority="enterprise",
        source_subject_id=None,
        realm="tenant",
        tenant_id=tenant_id,
        hmac_key_id="events-key",
        requester_realm="tenant",
        requester_id=requester_id,
        assignee_id=approver_id,
        operation_kind="enterprise",
        operation_id=operation_id,
        action="custom_role_retire",
        target_type="custom_role",
        target_locator_hmac=operation_id.hex * 2,
        required_permission="tenant.enterprise.role.manage",
        risk_level="high",
        snapshot_hash="a" * 64,
        priority="high",
        due_at=NOW + timedelta(hours=1),
        escalation_at=NOW + timedelta(minutes=15),
    )

    with pytest.raises(NotificationDeliveryError) as raised:
        with factory.begin() as db:
            work = projection.project_in_transaction(db, command, now=NOW)
            notifier.enqueue_requested_in_transaction(db, work, now=NOW)
    assert raised.value.code == "notification_template_not_found"
    with factory.begin() as db:
        assert db.get(ApprovalWorkItemRecord, work_item_id) is None

    platform_actor = NotificationActor(
        "staff",
        staff_id,
        None,
        frozenset(
            {
                "platform.notification.read",
                "platform.notification_template.manage",
            }
        ),
    )
    seeded = NotificationTemplateBootstrap(delivery).seed(platform_actor, now=NOW)
    assert len(seeded) == 15
    assert all(
        value.replayed
        for value in NotificationTemplateBootstrap(delivery).seed(platform_actor, now=NOW)
    )
    catalog = PackagedNotificationTemplateCatalog()
    first = seeded[0]
    assert (
        catalog.get(
            key=first.template_key,
            locale=first.locale,
            version=first.version,
            artifact_handle=first.content_artifact_handle,
            expected_content_sha256=first.content_sha256,
            expected_variables_schema_sha256=first.variables_schema_sha256,
        )
        is not None
    )

    with factory.begin() as db:
        work = projection.project_in_transaction(db, command, now=NOW)
        notifier.enqueue_requested_in_transaction(db, work, now=NOW)
    with factory.begin() as db:
        terminal = projection.sync_terminal_in_transaction(
            db,
            ApprovalTerminalCommand(
                work_item_id=work.id,
                source_authority="enterprise",
                source_subject_id=None,
                realm="tenant",
                tenant_id=tenant_id,
                operation_kind="enterprise",
                operation_id=operation_id,
                required_permission=work.required_permission,
                expected_snapshot_hash=work.snapshot_hash,
                expected_projection_version=work.version,
                status="approved",
                decision_code="enterprise-approved",
                decided_by_id=approver_id,
                decided_at=NOW,
            ),
        )
        notifier.enqueue_terminal_in_transaction(db, terminal, now=NOW)
    with factory.begin() as db:
        events = tuple(
            db.execute(
                sa.select(NotificationDeliveryRecord.event_type).order_by(
                    NotificationDeliveryRecord.event_type,
                    NotificationDeliveryRecord.channel,
                )
            ).scalars()
        )
    assert events.count("approval.requested") == 2
    assert events.count("approval.decided") == 2

    identity = NotificationWorkloadIdentity(
        subject="spiffe://prod/notification-dispatcher",
        audience="omnigent:notification-delivery",
        authenticated_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
    )
    claim = delivery.claim(identity, now=NOW)
    assert claim is not None
    settled = delivery.fail(
        claim,
        error_code="notification_provider_rejected",
        provider_status=400,
        retryable=False,
        now=NOW,
    )
    assert settled.status == "dead_letter"
    with factory.begin() as db:
        alerts = tuple(
            db.execute(
                sa.select(NotificationDeliveryRecord).where(
                    NotificationDeliveryRecord.event_type == "notification.delivery_dead_letter"
                )
            ).scalars()
        )
    assert len(alerts) == 1
    assert alerts[0].realm == "staff"
    assert alerts[0].recipient_principal_id == staff_id
    assert alerts[0].channel == "in_app"
    assert alerts[0].source_delivery_id == claim.delivery_id
