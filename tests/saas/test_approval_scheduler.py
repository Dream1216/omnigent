from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.approval_operations import (
    ApprovalProjectionCommand,
    ApprovalProjectionService,
    ApprovalTerminalCommand,
    ApprovalWorkItemView,
)
from saas.control_plane.approval_scheduler import (
    ApprovalReconcileResult,
    ApprovalScheduler,
)
from saas.control_plane.db_models import GlobalUser, SaasBase, Tenant
from saas.control_plane.notification_delivery import (
    NotificationActor,
    NotificationDeliveryError,
    NotificationDeliveryService,
    NotificationDeliveryView,
    NotificationErrorDigester,
    NotificationEventCommand,
)
from saas.control_plane.notification_models import (
    ApprovalWorkItemRecord,
    NotificationDeliveryRecord,
)
from saas.control_plane.notification_templates import NotificationTemplateBootstrap
from saas.control_plane.platform_models import PlatformStaffPrincipalRecord

NOW = datetime(2026, 8, 10, 11, 0, tzinfo=timezone.utc)


class SchedulerSource:
    def __init__(
        self,
        factory: sessionmaker[Session],
        eligible: set[UUID],
    ) -> None:
        self.factory = factory
        self.eligible = eligible

    def reconcile(
        self,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
        limit: int,
    ) -> ApprovalReconcileResult:
        del projection, now, limit
        return ApprovalReconcileResult(0, 0)

    def expire(
        self,
        work_item: ApprovalWorkItemView,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
    ) -> None:
        with self.factory.begin() as db:
            projection.sync_terminal_in_transaction(
                db,
                ApprovalTerminalCommand(
                    work_item_id=work_item.id,
                    source_authority="enterprise",
                    source_subject_id=None,
                    realm="tenant",
                    tenant_id=work_item.tenant_id,
                    operation_kind="enterprise",
                    operation_id=work_item.operation_id,
                    required_permission=work_item.required_permission,
                    expected_snapshot_hash=work_item.snapshot_hash,
                    expected_projection_version=work_item.version,
                    status="expired",
                    decision_code="approval-timeout",
                    decided_by_id=None,
                    decided_at=now,
                ),
            )

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        del work_item, now
        return tuple(self.eligible)[:limit]


class BlockableNotificationDeliveryService(NotificationDeliveryService):
    def __init__(
        self,
        factory: sessionmaker[Session],
        *,
        digester: NotificationErrorDigester,
    ) -> None:
        super().__init__(factory, digester=digester)
        self.blocked_work_items: set[UUID] = set()

    def enqueue_event_in_transaction(
        self,
        db: Session,
        command: NotificationEventCommand,
        *,
        now: datetime | None = None,
    ) -> tuple[NotificationDeliveryView, ...]:
        if command.approval_work_item_id in self.blocked_work_items:
            raise NotificationDeliveryError("notification_test_blocked")
        return super().enqueue_event_in_transaction(db, command, now=now)


@dataclass(frozen=True, slots=True)
class SchedulerHarness:
    factory: sessionmaker[Session]
    projection: ApprovalProjectionService
    notifications: BlockableNotificationDeliveryService
    source: SchedulerSource
    tenant_id: UUID
    requester_id: UUID
    approver_id: UUID

    def project(
        self,
        *,
        due_at: datetime,
        escalation_at: datetime,
    ) -> ApprovalWorkItemView:
        operation_id = uuid4()
        command = ApprovalProjectionCommand(
            work_item_id=uuid4(),
            source_authority="enterprise",
            source_subject_id=None,
            realm="tenant",
            tenant_id=self.tenant_id,
            hmac_key_id="scheduler-hmac",
            requester_realm="tenant",
            requester_id=self.requester_id,
            assignee_id=self.approver_id,
            operation_kind="enterprise",
            operation_id=operation_id,
            action="custom_role_retire",
            target_type="custom_role",
            target_locator_hmac=operation_id.hex * 2,
            required_permission="tenant.enterprise.role.manage",
            risk_level="high",
            snapshot_hash="a" * 64,
            priority="normal",
            due_at=due_at,
            escalation_at=escalation_at,
        )
        with self.factory.begin() as db:
            return self.projection.project_in_transaction(db, command, now=NOW)


def _harness() -> SchedulerHarness:
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
                slug=f"scheduler-{tenant_id.hex}",
                name="Scheduler tenant",
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
                identity_connection_ref=f"scheduler:{staff_id}",
                issuer="https://staff-idp.example.test",
                subject="scheduler-template-operator",
                status="active",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    notifications = BlockableNotificationDeliveryService(
        factory,
        digester=NotificationErrorDigester("notification-key", b"n" * 32),
    )
    actor = NotificationActor(
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
    NotificationTemplateBootstrap(notifications).seed(actor, now=NOW)
    projection = ApprovalProjectionService()
    return SchedulerHarness(
        factory,
        projection,
        notifications,
        SchedulerSource(factory, {approver_id}),
        tenant_id,
        requester_id,
        approver_id,
    )


def test_scheduler_isolates_failures_and_atomically_retries_reminder() -> None:
    harness = _harness()
    successful = harness.project(
        due_at=NOW + timedelta(hours=1), escalation_at=NOW - timedelta(seconds=1)
    )
    failed = harness.project(
        due_at=NOW + timedelta(hours=1), escalation_at=NOW - timedelta(seconds=1)
    )
    scheduler = ApprovalScheduler(
        harness.factory,
        projection=harness.projection,
        sources={"enterprise": harness.source},
        notifications=harness.notifications,
    )
    harness.notifications.blocked_work_items.add(failed.id)
    result = scheduler.run_once(now=NOW)
    assert (result.reminded, result.failed) == (1, 1)
    with harness.factory.begin() as db:
        rows = {
            value.id: value
            for value in db.execute(
                sa.select(ApprovalWorkItemRecord).where(
                    ApprovalWorkItemRecord.id.in_((successful.id, failed.id))
                )
            ).scalars()
        }
        assert rows[successful.id].escalation_count == 1
        assert rows[failed.id].escalation_count == 0
        assert db.scalar(sa.select(sa.func.count(NotificationDeliveryRecord.id))) == 2

    harness.notifications.blocked_work_items.clear()
    retry = ApprovalScheduler(
        harness.factory,
        projection=harness.projection,
        sources={"enterprise": harness.source},
        notifications=harness.notifications,
    ).run_once(now=NOW)
    assert (retry.reminded, retry.failed) == (1, 0)


def test_scheduler_does_not_advance_when_dynamic_audience_is_revoked() -> None:
    harness = _harness()
    work = harness.project(
        due_at=NOW + timedelta(hours=1), escalation_at=NOW - timedelta(seconds=1)
    )
    harness.source.eligible.clear()
    result = ApprovalScheduler(
        harness.factory,
        projection=harness.projection,
        sources={"enterprise": harness.source},
        notifications=harness.notifications,
    ).run_once(now=NOW)
    assert (result.reminded, result.failed) == (0, 1)
    with harness.factory.begin() as db:
        row = db.get(ApprovalWorkItemRecord, work.id)
        assert row is not None and row.escalation_count == 0


def test_expiry_remains_committed_when_terminal_notification_fails() -> None:
    harness = _harness()
    work = harness.project(due_at=NOW + timedelta(minutes=1), escalation_at=NOW)
    harness.notifications.blocked_work_items.add(work.id)
    result = ApprovalScheduler(
        harness.factory,
        projection=harness.projection,
        sources={"enterprise": harness.source},
        notifications=harness.notifications,
    ).run_once(now=NOW + timedelta(minutes=2))
    assert (result.expired, result.failed) == (1, 1)
    with harness.factory.begin() as db:
        row = db.get(ApprovalWorkItemRecord, work.id)
        assert row is not None and row.status == "expired"
