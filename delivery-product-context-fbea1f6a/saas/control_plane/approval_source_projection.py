"""Low-coupling bridge from source authorities to the approval operations index.

The source row is always authoritative.  Source services call this bridge with
their *existing* transaction so a projection or notification failure aborts the
source mutation as well.  The optional notifier is deliberately a Protocol: the
source layer never imports the delivery implementation or a provider SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

import sqlalchemy as sa
from sqlalchemy.orm import Session

from saas.control_plane.approval_operations import (
    ApprovalOperationsError,
    ApprovalProjectionCommand,
    ApprovalProjectionService,
    ApprovalSecretDigester,
    ApprovalTerminalCommand,
    ApprovalTerminalStatus,
    ApprovalWorkItemView,
)

SourceAuthority = Literal["support", "privacy", "enterprise", "audit"]
SourceRealm = Literal["tenant", "staff"]


@dataclass(frozen=True, slots=True)
class SourceApprovalRlsContext:
    source_kind: str
    mutation: Literal["scan", "read", "audience", "project", "terminal"]
    realm: Literal["tenant", "staff"]
    tenant_id: UUID | None = None
    operation_id: UUID | None = None
    subject_id: UUID | None = None
    work_item_id: UUID | None = None


def apply_source_approval_rls_context(
    db: Session,
    context: SourceApprovalRlsContext,
) -> None:
    """Bind server-derived source facts used by isolated source authorities."""

    if context.source_kind not in {
        "enterprise",
        "privacy",
        "audit",
        "support.customer",
        "support.staff",
    }:
        raise ApprovalOperationsError("approval_source_binding_conflict")
    if context.realm == "tenant" and context.tenant_id is None and context.mutation != "scan":
        raise ApprovalOperationsError("approval_source_binding_conflict")
    if db.get_bind().dialect.name != "postgresql":
        return
    values = {
        "app.approval_source_kind": context.source_kind,
        "app.approval_source_mutation": context.mutation,
        "app.approval_source_realm": context.realm,
        "app.approval_source_tenant_id": str(context.tenant_id) if context.tenant_id else "",
        "app.approval_source_operation_id": (
            str(context.operation_id) if context.operation_id else ""
        ),
        "app.approval_source_subject_id": str(context.subject_id) if context.subject_id else "",
        "app.approval_source_work_item_id": (
            str(context.work_item_id) if context.work_item_id else ""
        ),
    }
    db.execute(
        sa.text(
            "SELECT "
            + ", ".join(
                f"set_config('{name}', :value_{index}, true)" for index, name in enumerate(values)
            )
        ),
        {f"value_{index}": value for index, value in enumerate(values.values())},
    )


class SourceApprovalNotifier(Protocol):
    """Transaction-local notification boundary implemented by the delivery core."""

    def enqueue_requested_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None: ...

    def enqueue_terminal_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class SourceApprovalProjectionSpec:
    """Content-blind facts copied from one immutable source snapshot."""

    authority: SourceAuthority
    work_item_id: UUID
    source_subject_id: UUID | None
    realm: SourceRealm
    tenant_id: UUID | None
    requester_realm: SourceRealm
    requester_id: UUID
    operation_kind: str
    operation_id: UUID
    action: str
    target_type: str
    target_id: UUID
    required_permission: str
    risk_level: Literal["medium", "high", "critical"]
    snapshot_hash: str
    due_at: datetime
    escalation_at: datetime
    assignee_id: UUID | None = None
    priority: Literal["normal", "high", "critical"] = "normal"

    def __repr__(self) -> str:
        return (
            "SourceApprovalProjectionSpec("
            f"authority={self.authority!r}, work_item_id={self.work_item_id!r}, "
            f"operation_kind={self.operation_kind!r}, realm={self.realm!r})"
        )


@dataclass(frozen=True, slots=True)
class SourceApprovalProjectionBridge:
    """Project and settle source approvals without giving the index authority."""

    projection: ApprovalProjectionService
    digester: ApprovalSecretDigester = field(repr=False)
    notifier: SourceApprovalNotifier | None = field(default=None, repr=False)
    production_mode: bool = False

    def __post_init__(self) -> None:
        if self.production_mode and self.notifier is None:
            raise ValueError("production approval projection requires a real notifier")

    def project_in_transaction(
        self,
        db: Session,
        spec: SourceApprovalProjectionSpec,
        *,
        now: datetime,
        emit_notification: bool = True,
    ) -> ApprovalWorkItemView:
        at = _aware(now)
        apply_source_approval_rls_context(
            db,
            SourceApprovalRlsContext(
                source_kind=spec.operation_kind,
                mutation="project",
                realm=spec.realm,
                tenant_id=spec.tenant_id,
                operation_id=spec.operation_id,
                subject_id=spec.source_subject_id,
                work_item_id=spec.work_item_id,
            ),
        )
        work = self.projection.project_in_transaction(
            db,
            ApprovalProjectionCommand(
                work_item_id=spec.work_item_id,
                source_authority=spec.authority,
                source_subject_id=spec.source_subject_id,
                realm=spec.realm,
                tenant_id=spec.tenant_id,
                hmac_key_id=self.digester.key_id,
                requester_realm=spec.requester_realm,
                requester_id=spec.requester_id,
                assignee_id=spec.assignee_id,
                operation_kind=spec.operation_kind,
                operation_id=spec.operation_id,
                action=spec.action,
                target_type=spec.target_type,
                target_locator_hmac=self.digester.digest(
                    domain="approval-source-target-locator",
                    values=(spec.authority, spec.target_type, str(spec.target_id)),
                ),
                required_permission=spec.required_permission,
                risk_level=spec.risk_level,
                snapshot_hash=spec.snapshot_hash,
                priority=spec.priority,
                due_at=_aware(spec.due_at),
                escalation_at=_aware(spec.escalation_at),
            ),
            now=at,
        )
        if emit_notification and work.status == "pending" and self.notifier is not None:
            self.notifier.enqueue_requested_in_transaction(db, work, now=at)
        return work

    def terminal_in_transaction(
        self,
        db: Session,
        spec: SourceApprovalProjectionSpec,
        *,
        status: ApprovalTerminalStatus,
        decision_code: str,
        decided_by_id: UUID | None,
        decided_at: datetime,
        expected_projection_version: int | None = None,
    ) -> ApprovalWorkItemView:
        """Settle the projection after the source row has reached that state.

        Direct legacy source endpoints do not carry a projection version.  In
        that case the bridge locks the exact projection and uses its current
        version; unified approval operations pass an explicit version.
        """

        at = _aware(decided_at)
        apply_source_approval_rls_context(
            db,
            SourceApprovalRlsContext(
                source_kind=spec.operation_kind,
                mutation="terminal",
                realm=spec.realm,
                tenant_id=spec.tenant_id,
                operation_id=spec.operation_id,
                subject_id=spec.source_subject_id,
                work_item_id=spec.work_item_id,
            ),
        )
        try:
            current = self.projection.get_for_source_in_transaction(
                db,
                work_item_id=spec.work_item_id,
                source_authority=spec.authority,
                source_subject_id=spec.source_subject_id,
                realm=spec.realm,
                tenant_id=spec.tenant_id,
                operation_id=spec.operation_id,
                actor_realm=spec.realm,
                actor_id=decided_by_id,
                mutation="terminal_source_read",
            )
        except ApprovalOperationsError as error:
            if error.code != "approval_projection_not_found":
                raise
            # A source row may pre-date the projection migration. Repair it in
            # this same source transaction and emit only the truthful terminal
            # event, never a stale "requested" notification.
            current = self.project_in_transaction(
                db,
                spec,
                now=at,
                emit_notification=False,
            )
        version = (
            current.version if expected_projection_version is None else expected_projection_version
        )
        work = self.projection.sync_terminal_in_transaction(
            db,
            ApprovalTerminalCommand(
                work_item_id=spec.work_item_id,
                source_authority=spec.authority,
                source_subject_id=spec.source_subject_id,
                realm=spec.realm,
                tenant_id=spec.tenant_id,
                operation_kind=spec.operation_kind,
                operation_id=spec.operation_id,
                required_permission=spec.required_permission,
                expected_snapshot_hash=spec.snapshot_hash,
                expected_projection_version=version,
                status=status,
                decision_code=decision_code,
                decided_by_id=decided_by_id,
                decided_at=at,
            ),
        )
        if self.notifier is not None:
            self.notifier.enqueue_terminal_in_transaction(db, work, now=at)
        return work


def support_work_item_id(grant_id: UUID, stage: Literal["customer", "staff"]) -> UUID:
    """Stable IDs let reconciliation safely repair N-1 support approvals."""

    return uuid5(NAMESPACE_URL, f"omnigent:approval:support:{grant_id}:{stage}:v1")


def bounded_deadlines(
    *,
    now: datetime,
    source_expires_at: datetime | None,
    default_ttl: timedelta,
) -> tuple[datetime, datetime]:
    """Return a future due/reminder pair bounded by the source authority."""

    at = _aware(now)
    due = (
        min(_aware(source_expires_at), at + default_ttl) if source_expires_at else at + default_ttl
    )
    # Reconciliation may discover a row exactly at/after its source deadline.
    # Such rows are settled as expired before this helper is used.
    if due <= at:
        due = at + timedelta(microseconds=1)
    escalation = min(due, at + min(default_ttl / 2, timedelta(minutes=15)))
    return due, escalation


def _aware(value: datetime | None) -> datetime:
    if value is None or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("source approval time must include a timezone")
    return value.astimezone(timezone.utc)


__all__ = [
    "SourceApprovalNotifier",
    "SourceApprovalProjectionBridge",
    "SourceApprovalProjectionSpec",
    "bounded_deadlines",
    "support_work_item_id",
]
