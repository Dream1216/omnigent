"""Transaction-local, content-blind notification event orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.approval_operations import ApprovalWorkItemView
from saas.control_plane.approval_source_projection import (
    SourceApprovalRlsContext,
    apply_source_approval_rls_context,
)
from saas.control_plane.notification_delivery import (
    NotificationChannel,
    NotificationDeliveryError,
    NotificationDeliveryService,
    NotificationEventCommand,
)
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)


class ApprovalNotificationAudience(Protocol):
    """Revalidate eligible approvers from the source authority."""

    def eligible_actor_ids_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]: ...


class PlatformNotificationAudience(Protocol):
    """Resolve active Staff operators from the platform permission authority."""

    def eligible_operator_ids(
        self,
        *,
        tenant_id: UUID | None,
        permission: str,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]: ...


@dataclass(frozen=True, slots=True)
class DatabasePlatformNotificationAudience:
    """Resolve active operators from the current platform role assignments."""

    sessions: sessionmaker[Session]

    def eligible_operator_ids(
        self,
        *,
        tenant_id: UUID | None,
        permission: str,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        del tenant_id
        if not 1 <= limit <= 100:
            raise NotificationDeliveryError("notification_operator_limit_invalid")
        roles = tuple(
            role
            for role, permissions in PLATFORM_ROLE_PERMISSIONS.items()
            if permission in permissions
        )
        if not roles:
            raise NotificationDeliveryError("notification_operator_permission_invalid")
        with self.sessions.begin() as db:
            _apply_dead_letter_audience_rls(db, permission=permission)
            values = db.execute(
                sa.select(PlatformRoleAssignmentRecord.principal_id)
                .join(
                    PlatformStaffPrincipalRecord,
                    PlatformStaffPrincipalRecord.id == PlatformRoleAssignmentRecord.principal_id,
                )
                .where(
                    PlatformRoleAssignmentRecord.role.in_(roles),
                    PlatformRoleAssignmentRecord.status == "active",
                    sa.or_(
                        PlatformRoleAssignmentRecord.expires_at.is_(None),
                        PlatformRoleAssignmentRecord.expires_at > now,
                    ),
                    PlatformStaffPrincipalRecord.status == "active",
                )
                .distinct()
                .order_by(PlatformRoleAssignmentRecord.principal_id)
                .limit(limit)
            ).scalars()
            return tuple(values)


@dataclass(frozen=True, slots=True)
class SourceApprovalNotificationService:
    """Concrete SourceApprovalNotifier used inside the source transaction."""

    deliveries: NotificationDeliveryService
    audience: ApprovalNotificationAudience
    channels: tuple[NotificationChannel, ...] = ("in_app", "email")
    locale: str = "en-US"

    def enqueue_requested_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None:
        if work_item.status != "pending":
            raise NotificationDeliveryError("notification_approval_state_invalid")
        eligible = tuple(
            dict.fromkeys(
                self.audience.eligible_actor_ids_in_transaction(db, work_item, now=now, limit=100)
            )
        )
        apply_source_approval_rls_context(
            db,
            SourceApprovalRlsContext(
                source_kind=work_item.operation_kind,
                mutation="project",
                realm=cast(Literal["tenant", "staff"], work_item.realm),
                tenant_id=work_item.tenant_id,
                operation_id=work_item.operation_id,
                subject_id=(
                    work_item.operation_id
                    if work_item.operation_kind.startswith("support.")
                    else None
                ),
                work_item_id=work_item.id,
            ),
        )
        if work_item.requester_realm == work_item.realm:
            eligible = tuple(value for value in eligible if value != work_item.requester_id)
        if work_item.assignee_id is not None:
            eligible = tuple(value for value in eligible if value == work_item.assignee_id)
        if not eligible:
            raise NotificationDeliveryError("notification_approval_audience_unavailable")
        for recipient_id in eligible:
            self.deliveries.enqueue_event_in_transaction(
                db,
                NotificationEventCommand(
                    realm=work_item.realm,  # type: ignore[arg-type]
                    tenant_id=work_item.tenant_id,
                    recipient_id=recipient_id,
                    event_type="approval.requested",
                    channels=self.channels,
                    deduplication_token=f"{work_item.id}:requested:{recipient_id}",
                    render_context_values=(
                        str(work_item.id),
                        work_item.action,
                        work_item.due_at.isoformat(),
                    ),
                    approval_work_item_id=work_item.id,
                    locale=self.locale,
                ),
                now=now,
            )

    def enqueue_terminal_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None:
        if work_item.status not in {
            "approved",
            "rejected",
            "expired",
            "cancelled",
        }:
            raise NotificationDeliveryError("notification_approval_state_invalid")
        event_type = "approval.expired" if work_item.status == "expired" else "approval.decided"
        self.deliveries.enqueue_event_in_transaction(
            db,
            NotificationEventCommand(
                realm=work_item.requester_realm,  # type: ignore[arg-type]
                tenant_id=work_item.tenant_id,
                recipient_id=work_item.requester_id,
                event_type=event_type,
                channels=self.channels,
                deduplication_token=f"{work_item.id}:terminal:{work_item.status}",
                render_context_values=(
                    str(work_item.id),
                    work_item.status,
                    work_item.decision_code or "system-terminal",
                ),
                approval_work_item_id=work_item.id,
                forced=True,
                locale=self.locale,
            ),
            now=now,
        )

    def enqueue_batch_completed_in_transaction(
        self,
        db: Session,
        *,
        realm: Literal["tenant", "staff"],
        tenant_id: UUID | None,
        requester_id: UUID,
        batch_id: UUID,
        status: str,
        now: datetime,
    ) -> None:
        self.deliveries.enqueue_event_in_transaction(
            db,
            NotificationEventCommand(
                realm=realm,
                tenant_id=tenant_id,
                recipient_id=requester_id,
                event_type="operation_batch.completed",
                channels=self.channels,
                deduplication_token=f"{batch_id}:completed:{status}",
                render_context_values=(str(batch_id), status),
                operation_batch_id=batch_id,
                forced=True,
                locale=self.locale,
            ),
            now=now,
        )


@dataclass(frozen=True, slots=True)
class DeadLetterNotificationSink:
    """Emit bounded, non-recursive in-app alerts to current platform operators."""

    audience: PlatformNotificationAudience
    locale: str = "en-US"

    def enqueue_dead_letter_in_transaction(
        self,
        deliveries: NotificationDeliveryService,
        db: Session,
        *,
        tenant_id: UUID | None,
        delivery_id: UUID,
        replay_generation: int,
        now: datetime,
    ) -> None:
        operator_ids = tuple(
            dict.fromkeys(
                self.audience.eligible_operator_ids(
                    tenant_id=tenant_id,
                    permission="platform.notification.read",
                    now=now,
                    limit=100,
                )
            )
        )
        if not operator_ids:
            raise NotificationDeliveryError("notification_dead_letter_audience_unavailable")
        for operator_id in operator_ids:
            deliveries.enqueue_event_in_transaction(
                db,
                NotificationEventCommand(
                    realm="staff",
                    tenant_id=tenant_id,
                    recipient_id=operator_id,
                    event_type="notification.delivery_dead_letter",
                    channels=("in_app",),
                    deduplication_token=(
                        f"{delivery_id}:dead-letter:{replay_generation}:{operator_id}"
                    ),
                    render_context_values=(
                        str(delivery_id),
                        str(replay_generation),
                    ),
                    source_delivery_id=delivery_id,
                    forced=True,
                    locale=self.locale,
                ),
                now=now,
            )


def _apply_dead_letter_audience_rls(db: Session, *, permission: str) -> None:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    db.execute(
        sa.text(
            "SELECT "
            "set_config('app.notification_directory_recipient_kind', '', true), "
            "set_config('app.notification_directory_recipient_id', '', true), "
            "set_config('app.notification_dead_letter_audience', :permission, true)"
        ),
        {"permission": permission},
    )


__all__ = [
    "ApprovalNotificationAudience",
    "DatabasePlatformNotificationAudience",
    "DeadLetterNotificationSink",
    "PlatformNotificationAudience",
    "SourceApprovalNotificationService",
]
