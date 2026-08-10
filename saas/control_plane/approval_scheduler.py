"""Bounded reminder, escalation, timeout, and N-1 reconciliation scheduler."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.approval_operations import (
    ApprovalOperationsError,
    ApprovalProjectionService,
    ApprovalWorkItemView,
    _stored_utc,
    _work_view,
)
from saas.control_plane.notification_delivery import (
    NotificationDeliveryError,
    NotificationDeliveryService,
    NotificationEventCommand,
)
from saas.control_plane.notification_models import (
    ApprovalDelegationRecord,
    ApprovalWorkItemRecord,
)


@dataclass(frozen=True, slots=True)
class ApprovalReconcileResult:
    projected: int
    terminal_synced: int


class ApprovalSchedulerSource(Protocol):
    """Source-owned reconciliation and timeout transitions."""

    def reconcile(
        self,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
        limit: int,
    ) -> ApprovalReconcileResult: ...

    def expire(
        self,
        work_item: ApprovalWorkItemView,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
    ) -> None: ...

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]: ...


@dataclass(frozen=True, slots=True)
class ApprovalSchedulerRunResult:
    reconciled_pending: int
    reconciled_terminal: int
    reminded: int
    escalated: int
    expired: int
    failed: int


class ApprovalScheduler:
    """Run one bounded pass; source authorities remain the terminal deciders."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        projection: ApprovalProjectionService,
        sources: dict[str, ApprovalSchedulerSource],
        notifications: NotificationDeliveryService,
    ) -> None:
        self._sessions = session_factory
        self._projection = projection
        self._sources = dict(sources)
        self._notifications = notifications

    def run_once(
        self, *, now: datetime | None = None, limit: int = 100
    ) -> ApprovalSchedulerRunResult:
        at = _aware(now or datetime.now(timezone.utc))
        if not 1 <= limit <= 500:
            raise ValueError("approval scheduler limit must be between 1 and 500")
        projected = terminal = failed = 0
        for source in self._sources.values():
            try:
                result = source.reconcile(self._projection, now=at, limit=limit)
            except (ApprovalOperationsError, sa.exc.SQLAlchemyError):
                failed += 1
                continue
            projected += result.projected
            terminal += result.terminal_synced
        with self._sessions.begin() as db:
            _apply_scheduler_scan_rls(db)
            values = tuple(
                db.execute(
                    sa.select(ApprovalWorkItemRecord)
                    .where(
                        ApprovalWorkItemRecord.status == "pending",
                        ApprovalWorkItemRecord.escalation_at <= at,
                    )
                    .order_by(ApprovalWorkItemRecord.escalation_at, ApprovalWorkItemRecord.id)
                    .limit(limit)
                ).scalars()
            )
            work_items = tuple(_work_view(value) for value in values)
        reminded = escalated = expired = 0
        for work in work_items:
            source = self._sources.get(work.operation_kind)
            if source is None:
                failed += 1
                continue
            try:
                recipients = self._audience(source, work, at)
            except (ApprovalOperationsError, sa.exc.SQLAlchemyError):
                failed += 1
                continue
            if work.due_at <= at:
                try:
                    source.expire(work, self._projection, now=at)
                except (ApprovalOperationsError, sa.exc.SQLAlchemyError):
                    failed += 1
                    try:
                        self._notify(
                            work,
                            recipients,
                            event_type="approval.decision_failed",
                            generation=work.escalation_count,
                            at=at,
                        )
                    except (NotificationDeliveryError, sa.exc.SQLAlchemyError):
                        failed += 1
                else:
                    expired += 1
                    try:
                        self._notify(
                            work,
                            recipients,
                            event_type="approval.expired",
                            generation=work.escalation_count,
                            at=at,
                        )
                    except (NotificationDeliveryError, sa.exc.SQLAlchemyError):
                        # The source transition already committed. A delivery failure
                        # must never be reported as an expiry-authority failure.
                        failed += 1
                continue
            if not recipients:
                # Do not advance the reminder cursor when every dynamically
                # eligible approver was revoked; a later pass can recover.
                failed += 1
                continue
            try:
                generation = self._advance_escalation_and_notify(
                    work, recipients, at
                )
            except (
                ApprovalOperationsError,
                NotificationDeliveryError,
                sa.exc.SQLAlchemyError,
            ):
                # State advancement and all recipient enqueues share one
                # transaction, so a later pass can safely retry the work item.
                failed += 1
                continue
            if generation == 1:
                reminded += 1
            else:
                escalated += 1
        return ApprovalSchedulerRunResult(
            reconciled_pending=projected,
            reconciled_terminal=terminal,
            reminded=reminded,
            escalated=escalated,
            expired=expired,
            failed=failed,
        )

    def _advance_escalation_and_notify(
        self,
        work: ApprovalWorkItemView,
        recipients: tuple[UUID, ...],
        at: datetime,
    ) -> int:
        with self._sessions.begin() as db:
            _apply_scheduler_work_rls(db, work)
            record = db.execute(
                sa.select(ApprovalWorkItemRecord)
                .where(ApprovalWorkItemRecord.id == work.id)
                .with_for_update()
            ).scalar_one_or_none()
            if (
                record is None
                or record.status != "pending"
                or record.version != work.version
                or _stored_utc(record.escalation_at) > at
            ):
                raise ApprovalOperationsError("approval_scheduler_work_changed")
            record.escalation_count += 1
            record.priority = "critical" if record.escalation_count >= 2 else "high"
            record.escalation_at = min(_stored_utc(record.due_at), at + timedelta(minutes=15))
            record.version += 1
            record.updated_at = at
            event_type = (
                "approval.reminder"
                if record.escalation_count == 1
                else "approval.escalated"
            )
            self._enqueue_notifications(
                db,
                _work_view(record),
                recipients,
                event_type=event_type,
                generation=record.escalation_count,
                at=at,
            )
            db.flush()
            return record.escalation_count

    def _audience(
        self,
        source: ApprovalSchedulerSource,
        work: ApprovalWorkItemView,
        at: datetime,
    ) -> tuple[UUID, ...]:
        eligible = tuple(dict.fromkeys(source.eligible_actor_ids(work, now=at, limit=100)))
        if work.requester_realm == work.realm:
            eligible = tuple(value for value in eligible if value != work.requester_id)
        if work.assignee_id is None:
            return eligible[:100]
        routed = {work.assignee_id}
        with self._sessions.begin() as db:
            _apply_scheduler_work_rls(db, work)
            delegator = (
                ApprovalDelegationRecord.delegator_user_id
                if work.realm == "tenant"
                else ApprovalDelegationRecord.delegator_principal_id
            )
            delegate = (
                ApprovalDelegationRecord.delegate_user_id
                if work.realm == "tenant"
                else ApprovalDelegationRecord.delegate_principal_id
            )
            delegated = tuple(
                value
                for value in db.execute(
                    sa.select(delegate).where(
                        ApprovalDelegationRecord.realm == work.realm,
                        ApprovalDelegationRecord.tenant_id == work.tenant_id,
                        delegator == work.assignee_id,
                        ApprovalDelegationRecord.permission_code == work.required_permission,
                        ApprovalDelegationRecord.scope_id == work.operation_id,
                        ApprovalDelegationRecord.status == "active",
                        ApprovalDelegationRecord.starts_at <= at,
                        ApprovalDelegationRecord.expires_at > at,
                    )
                ).scalars()
                if value is not None
            )
            routed.update(delegated)
        return tuple(value for value in eligible if value in routed)

    def _notify(
        self,
        work: ApprovalWorkItemView,
        recipients: tuple[UUID, ...],
        *,
        event_type: str,
        generation: int,
        at: datetime,
    ) -> None:
        if not recipients:
            return
        with self._sessions.begin() as db:
            self._enqueue_notifications(
                db,
                work,
                recipients,
                event_type=event_type,
                generation=generation,
                at=at,
            )

    def _enqueue_notifications(
        self,
        db: Session,
        work: ApprovalWorkItemView,
        recipients: tuple[UUID, ...],
        *,
        event_type: str,
        generation: int,
        at: datetime,
    ) -> None:
        for recipient_id in recipients[:100]:
            self._notifications.enqueue_event_in_transaction(
                db,
                NotificationEventCommand(
                    realm=work.realm,  # type: ignore[arg-type]
                    tenant_id=work.tenant_id,
                    recipient_id=recipient_id,
                    event_type=event_type,
                    channels=("in_app", "email"),
                    deduplication_token=(
                        f"{work.id}:{event_type}:{generation}:{recipient_id}"
                    ),
                    render_context_values=(
                        str(work.id),
                        work.action,
                        work.due_at.isoformat(),
                        str(generation),
                    ),
                    approval_work_item_id=work.id,
                    forced=event_type
                    in {
                        "approval.escalated",
                        "approval.expired",
                        "approval.decision_failed",
                    },
                ),
                now=at,
            )


def _apply_scheduler_work_rls(db: Session, work: ApprovalWorkItemView) -> None:
    _apply_scheduler_rls(
        db,
        realm=work.realm,
        tenant_id=work.tenant_id,
        work_item_id=work.id,
        operation_id=work.operation_id,
        mutation="scheduler",
    )


def _apply_scheduler_scan_rls(db: Session) -> None:
    _apply_scheduler_rls(
        db,
        realm="",
        tenant_id=None,
        work_item_id=None,
        operation_id=None,
        mutation="scheduler_scan",
    )


def _apply_scheduler_rls(
    db: Session,
    *,
    realm: str,
    tenant_id: UUID | None,
    work_item_id: UUID | None,
    operation_id: UUID | None,
    mutation: str,
) -> None:
    """Bind scheduler-only claims without fabricating a human actor."""

    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    db.execute(
        sa.text(
            "SELECT "
            "set_config('app.notification_realm', :realm, true), "
            "set_config('app.notification_actor_realm', '', true), "
            "set_config('app.notification_tenant_id', :tenant_id, true), "
            "set_config('app.notification_recipient_user_id', '', true), "
            "set_config('app.notification_staff_principal_id', '', true), "
            "set_config('app.notification_work_item_id', :work_item_id, true), "
            "set_config('app.notification_source_operation_id', :operation_id, true), "
            "set_config('app.notification_source_authority', '', true), "
            "set_config('app.notification_source_support_grant_id', '', true), "
            "set_config('app.notification_mutation', :mutation, true)"
        ),
        {
            "realm": realm,
            "tenant_id": str(tenant_id) if tenant_id else "",
            "work_item_id": str(work_item_id) if work_item_id else "",
            "operation_id": str(operation_id) if operation_id else "",
            "mutation": mutation,
        },
    )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("approval scheduler time must include a timezone")
    return value.astimezone(timezone.utc)
