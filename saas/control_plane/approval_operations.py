"""Content-blind approval projections, delegation, and bounded Operation Batches."""

from __future__ import annotations

import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal, Protocol
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.notification_models import (
    ApprovalDelegationRecord,
    ApprovalWorkItemRecord,
    OperationBatchItemRecord,
    OperationBatchRecord,
)

ApprovalRealm = Literal["tenant", "staff"]
ApprovalDecision = Literal["approve", "reject"]
ApprovalTerminalStatus = Literal["approved", "rejected", "expired", "cancelled"]

_BATCH_EXECUTION_WINDOW = timedelta(minutes=5)
_MAX_BATCH_ITEMS = 25


class ApprovalOperationsError(RuntimeError):
    """Stable approval error safe for API and batch feedback."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ApprovalActor:
    realm: ApprovalRealm
    actor_id: UUID
    tenant_id: UUID | None
    security_version: int
    authenticated_at: datetime
    expires_at: datetime
    permissions: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ApprovalProjectionCommand:
    work_item_id: UUID
    source_authority: Literal["support", "privacy", "enterprise", "audit"]
    source_subject_id: UUID | None
    realm: ApprovalRealm
    tenant_id: UUID | None
    hmac_key_id: str
    requester_realm: ApprovalRealm
    requester_id: UUID
    assignee_id: UUID | None
    operation_kind: str
    operation_id: UUID
    action: str
    target_type: str
    target_locator_hmac: str
    required_permission: str
    risk_level: Literal["medium", "high", "critical"]
    snapshot_hash: str
    priority: Literal["normal", "high", "critical"]
    due_at: datetime
    escalation_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalTerminalCommand:
    work_item_id: UUID
    source_authority: Literal["support", "privacy", "enterprise", "audit"]
    source_subject_id: UUID | None
    realm: ApprovalRealm
    tenant_id: UUID | None
    operation_kind: str
    operation_id: UUID
    required_permission: str
    expected_snapshot_hash: str
    expected_projection_version: int
    status: ApprovalTerminalStatus
    decision_code: str
    decided_by_id: UUID | None
    decided_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalWorkItemView:
    id: UUID
    realm: str
    tenant_id: UUID | None
    hmac_key_id: str
    requester_realm: str
    requester_id: UUID
    assignee_id: UUID | None
    operation_kind: str
    operation_id: UUID
    action: str
    target_type: str
    target_locator_hmac: str
    required_permission: str
    risk_level: str
    snapshot_hash: str
    status: str
    priority: str
    due_at: datetime
    escalation_at: datetime
    escalation_count: int
    decision_code: str | None
    decided_at: datetime | None
    version: int


@dataclass(frozen=True, slots=True)
class ApprovalWorkItemPage:
    items: tuple[ApprovalWorkItemView, ...]
    next_cursor: UUID | None


@dataclass(frozen=True, slots=True)
class ApprovalDelegationView:
    id: UUID
    realm: str
    tenant_id: UUID | None
    delegator_id: UUID
    delegate_id: UUID
    permission_code: str
    scope_type: str
    scope_id: UUID
    starts_at: datetime
    expires_at: datetime
    status: str
    version: int


@dataclass(frozen=True, slots=True)
class ApprovalDelegationPage:
    items: tuple[ApprovalDelegationView, ...]
    next_cursor: UUID | None


@dataclass(frozen=True, slots=True)
class BatchDecisionCommand:
    work_item_id: UUID
    expected_version: int


@dataclass(frozen=True, slots=True)
class OperationBatchItemView:
    id: UUID
    sequence: int
    work_item_id: UUID
    expected_work_item_version: int
    target_type: str
    target_locator_hmac: str
    operation_id: UUID | None
    status: str
    error_code: str | None
    result_hmac: str | None


@dataclass(frozen=True, slots=True)
class OperationBatchView:
    id: UUID
    realm: str
    tenant_id: UUID | None
    operation_kind: str
    action: str
    decision: str
    item_count: int
    status: str
    success_count: int
    failure_count: int
    version: int
    created_at: datetime
    items: tuple[OperationBatchItemView, ...]
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class AuthorityDecisionCommand:
    operation_id: UUID
    expected_snapshot_hash: str
    expected_projection_version: int
    decision: ApprovalDecision
    decision_code: str
    decision_reason: str = field(repr=False)
    idempotency_key: str


class ApprovalAuthorityAdapter(Protocol):
    """Adapter to one existing source authority; it remains the sole decider."""

    def authorize(
        self,
        actor: ApprovalActor,
        *,
        permission: str,
        tenant_id: UUID | None,
        now: datetime,
    ) -> None: ...

    def authorize_work_item(
        self,
        actor: ApprovalActor,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None:
        """Revalidate the exact source operation and current scope."""

    def authorize_identity(
        self,
        *,
        realm: ApprovalRealm,
        actor_id: UUID,
        permission: str,
        tenant_id: UUID | None,
        operation_id: UUID,
        now: datetime,
    ) -> None: ...

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]: ...

    def decide(
        self,
        actor: ApprovalActor,
        command: AuthorityDecisionCommand,
        *,
        projection: ApprovalProjectionService,
        now: datetime,
    ) -> None:
        """Decide in the source transaction and call projection terminal sync."""


class ApprovalBatchNotifier(Protocol):
    """Transaction-local terminal notification for Operation Batch requesters."""

    def enqueue_batch_completed_in_transaction(
        self,
        db: Session,
        *,
        realm: ApprovalRealm,
        tenant_id: UUID | None,
        requester_id: UUID,
        batch_id: UUID,
        status: str,
        now: datetime,
    ) -> None: ...


class ApprovalProjectionService:
    """Explicit hook called inside an existing authority's database transaction."""

    def get_for_source_in_transaction(
        self,
        db: Session,
        *,
        work_item_id: UUID,
        source_authority: Literal["support", "privacy", "enterprise", "audit"],
        source_subject_id: UUID | None,
        realm: ApprovalRealm,
        tenant_id: UUID | None,
        operation_id: UUID,
        actor_realm: ApprovalRealm,
        actor_id: UUID | None,
        mutation: str,
    ) -> ApprovalWorkItemView:
        """Lock one exact projection for a legacy source transition."""

        _validate_scope(realm, tenant_id)
        _code(mutation, "source_mutation", 64)
        _apply_notification_rls(
            db,
            realm=realm,
            tenant_id=tenant_id,
            actor_realm=actor_realm,
            actor_id=actor_id,
            work_item_id=work_item_id,
            operation_id=operation_id,
            source_authority=source_authority,
            source_subject_id=source_subject_id,
            mutation=mutation,
        )
        work = db.execute(
            sa.select(ApprovalWorkItemRecord)
            .where(ApprovalWorkItemRecord.id == work_item_id)
            .with_for_update()
        ).scalar_one_or_none()
        if work is None:
            raise ApprovalOperationsError("approval_projection_not_found")
        _validate_source_binding(
            source_authority=source_authority,
            source_subject_id=source_subject_id,
            operation_kind=work.operation_kind,
        )
        if work.realm != realm or work.tenant_id != tenant_id or work.operation_id != operation_id:
            raise ApprovalOperationsError("approval_projection_source_binding_conflict")
        return _work_view(work)

    def project_in_transaction(
        self,
        db: Session,
        command: ApprovalProjectionCommand,
        *,
        now: datetime | None = None,
    ) -> ApprovalWorkItemView:
        projected_at = _aware(now or datetime.now(timezone.utc))
        _validate_projection(command, projected_at)
        _apply_notification_rls(
            db,
            realm=command.realm,
            tenant_id=command.tenant_id,
            actor_realm=command.requester_realm,
            actor_id=command.requester_id,
            work_item_id=command.work_item_id,
            operation_id=command.operation_id,
            source_authority=command.source_authority,
            source_subject_id=command.source_subject_id,
            mutation="project",
        )
        existing = db.execute(
            sa.select(ApprovalWorkItemRecord).where(
                ApprovalWorkItemRecord.id == command.work_item_id,
            )
        ).scalar_one_or_none()
        if existing is None:
            existing = ApprovalWorkItemRecord(
                id=command.work_item_id,
                realm=command.realm,
                tenant_id=command.tenant_id,
                hmac_key_id=command.hmac_key_id,
                requester_realm=command.requester_realm,
                requested_by_user_id=(
                    command.requester_id if command.requester_realm == "tenant" else None
                ),
                requested_by_principal_id=(
                    command.requester_id if command.requester_realm == "staff" else None
                ),
                assignee_user_id=(command.assignee_id if command.realm == "tenant" else None),
                assignee_principal_id=(command.assignee_id if command.realm == "staff" else None),
                operation_kind=command.operation_kind,
                operation_id=command.operation_id,
                action=command.action,
                target_type=command.target_type,
                target_locator_hmac=command.target_locator_hmac,
                required_permission=command.required_permission,
                risk_level=command.risk_level,
                snapshot_hash=command.snapshot_hash,
                status="pending",
                priority=command.priority,
                due_at=command.due_at,
                escalation_at=command.escalation_at,
                escalation_count=0,
                version=1,
                created_at=projected_at,
                updated_at=projected_at,
            )
            db.add(existing)
            db.flush()
            return _work_view(existing)
        if existing.realm != command.realm or existing.tenant_id != command.tenant_id:
            raise ApprovalOperationsError("approval_projection_scope_conflict")
        if existing.hmac_key_id != command.hmac_key_id:
            raise ApprovalOperationsError("approval_projection_hmac_key_conflict")
        if _requester_id(existing) != command.requester_id:
            raise ApprovalOperationsError("approval_projection_requester_conflict")
        if existing.requester_realm != command.requester_realm:
            raise ApprovalOperationsError("approval_projection_requester_conflict")
        if any(
            (
                existing.snapshot_hash != command.snapshot_hash,
                existing.operation_kind != command.operation_kind,
                existing.operation_id != command.operation_id,
                existing.action != command.action,
                existing.target_type != command.target_type,
                existing.target_locator_hmac != command.target_locator_hmac,
                existing.required_permission != command.required_permission,
                existing.risk_level != command.risk_level,
            )
        ):
            raise ApprovalOperationsError("approval_projection_source_binding_conflict")
        if existing.status != "pending":
            return _work_view(existing)
        changed = any(
            (
                existing.assignee_user_id
                != (command.assignee_id if command.realm == "tenant" else None),
                existing.assignee_principal_id
                != (command.assignee_id if command.realm == "staff" else None),
                existing.due_at != command.due_at,
                existing.escalation_at != command.escalation_at,
                existing.priority != command.priority,
            )
        )
        existing.assignee_user_id = command.assignee_id if command.realm == "tenant" else None
        existing.assignee_principal_id = command.assignee_id if command.realm == "staff" else None
        existing.priority = command.priority
        existing.due_at = command.due_at
        existing.escalation_at = command.escalation_at
        if changed:
            existing.version += 1
            existing.updated_at = projected_at
        db.flush()
        return _work_view(existing)

    def sync_terminal_in_transaction(
        self,
        db: Session,
        command: ApprovalTerminalCommand,
    ) -> ApprovalWorkItemView:
        decided_at = _aware(command.decided_at)
        _validate_terminal(command)
        _apply_notification_rls(
            db,
            realm=command.realm,
            tenant_id=command.tenant_id,
            actor_realm=command.realm,
            actor_id=command.decided_by_id,
            work_item_id=command.work_item_id,
            operation_id=command.operation_id,
            source_authority=command.source_authority,
            source_subject_id=command.source_subject_id,
            mutation="terminal",
        )
        work = db.execute(
            sa.select(ApprovalWorkItemRecord)
            .where(
                ApprovalWorkItemRecord.id == command.work_item_id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if work is None:
            raise ApprovalOperationsError("approval_projection_not_found")
        if (
            work.realm != command.realm
            or work.tenant_id != command.tenant_id
            or work.operation_kind != command.operation_kind
            or work.operation_id != command.operation_id
            or work.required_permission != command.required_permission
        ):
            raise ApprovalOperationsError("approval_projection_source_binding_conflict")
        if work.snapshot_hash != command.expected_snapshot_hash:
            raise ApprovalOperationsError("approval_projection_snapshot_changed")
        if work.version != command.expected_projection_version:
            if work.status == command.status and work.decision_code == command.decision_code:
                return _work_view(work)
            raise ApprovalOperationsError("approval_projection_version_changed")
        if work.status != "pending":
            if work.status == command.status and work.decision_code == command.decision_code:
                return _work_view(work)
            raise ApprovalOperationsError("approval_projection_terminal_conflict")
        if command.status in {"approved", "rejected"} and command.decided_by_id is None:
            raise ApprovalOperationsError("approval_projection_decider_required")
        if command.status in {"expired", "cancelled"} and command.decided_by_id is not None:
            raise ApprovalOperationsError("approval_projection_system_terminal_invalid")
        work.status = command.status
        work.decision_code = _code(command.decision_code, "decision_code", 128)
        work.decided_at = decided_at
        work.decided_by_user_id = command.decided_by_id if work.realm == "tenant" else None
        work.decided_by_principal_id = command.decided_by_id if work.realm == "staff" else None
        work.version += 1
        work.updated_at = decided_at
        db.flush()
        return _work_view(work)


@dataclass(frozen=True, slots=True)
class ApprovalSecretDigester:
    """Keyed, domain-separated digest for reasons and error fingerprints."""

    key_id: str
    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not self.key_id.strip() or len(self.secret) < 32:
            raise ValueError("approval digester requires a 256-bit key")

    def digest(self, *, domain: str, values: tuple[str, ...]) -> str:
        material = "\x00".join((f"omnigent:{domain}:v1", *values))
        return hmac.new(self.secret, material.encode("utf-8"), sha256).hexdigest()


class ApprovalOperationsService:
    """Inbox orchestration that delegates every decision to its source authority."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        projection: ApprovalProjectionService,
        adapters: dict[str, ApprovalAuthorityAdapter],
        digester: ApprovalSecretDigester,
        previous_digesters: tuple[ApprovalSecretDigester, ...] = (),
        clock: Callable[[], datetime] | None = None,
        notifier: ApprovalBatchNotifier | None = None,
    ) -> None:
        self._sessions = session_factory
        self._projection = projection
        self._adapters = dict(adapters)
        self._digester = digester
        self._digesters = (digester, *previous_digesters)
        if len({value.key_id for value in self._digesters}) != len(self._digesters):
            raise ValueError("approval HMAC key IDs must be unique")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._notifier = notifier

    def list_work_items(
        self,
        actor: ApprovalActor,
        *,
        status: str | None = None,
        limit: int = 50,
        cursor: UUID | None = None,
        now: datetime | None = None,
    ) -> ApprovalWorkItemPage:
        at = _aware(now or datetime.now(timezone.utc))
        _validate_actor(actor, at)
        if not 1 <= limit <= 100:
            raise ApprovalOperationsError("approval_page_limit_invalid")
        if status is not None and status not in {
            "pending",
            "approved",
            "rejected",
            "expired",
            "cancelled",
        }:
            raise ApprovalOperationsError("approval_status_invalid")
        eligible: list[ApprovalWorkItemView] = []
        scan_cursor = cursor
        has_more = False
        scanned = 0
        while len(eligible) <= limit and scanned < 1000:
            with self._sessions.begin() as db:
                _apply_approval_actor_rls(db, actor, mutation="inbox_list")
                query = sa.select(ApprovalWorkItemRecord).where(
                    ApprovalWorkItemRecord.realm == actor.realm
                )
                if actor.realm == "tenant":
                    query = query.where(ApprovalWorkItemRecord.tenant_id == actor.tenant_id)
                if scan_cursor is not None:
                    query = query.where(ApprovalWorkItemRecord.id > scan_cursor)
                if status is not None:
                    query = query.where(ApprovalWorkItemRecord.status == status)
                values = tuple(
                    db.execute(query.order_by(ApprovalWorkItemRecord.id).limit(101)).scalars()
                )
                page_records = values[:100]
                candidates = tuple(
                    _work_view(value)
                    for value in page_records
                    if self._routing_allows(db, value, actor, at)
                )
            if not page_records:
                has_more = False
                break
            scanned += len(page_records)
            scan_cursor = page_records[-1].id
            has_more = len(values) > 100
            for value in candidates:
                if (
                    value.status == "pending"
                    and value.requester_realm == actor.realm
                    and value.requester_id == actor.actor_id
                ):
                    continue
                adapter = self._adapters.get(value.operation_kind)
                if adapter is None:
                    continue
                try:
                    adapter.authorize_work_item(actor, value, now=at)
                except ApprovalOperationsError:
                    continue
                eligible.append(value)
                if len(eligible) > limit:
                    break
            if not has_more:
                break
        items = tuple(eligible[:limit])
        next_cursor = None
        if len(eligible) > limit and items:
            next_cursor = items[-1].id
        elif has_more or scanned >= 1000:
            next_cursor = scan_cursor
        return ApprovalWorkItemPage(
            items=items,
            next_cursor=next_cursor,
        )

    def create_delegation(
        self,
        actor: ApprovalActor,
        *,
        work_item_id: UUID,
        expected_version: int,
        delegate_id: UUID,
        starts_at: datetime,
        expires_at: datetime,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ApprovalDelegationView:
        at = _aware(now or datetime.now(timezone.utc))
        _validate_actor(actor, at)
        start, expiry = _aware(starts_at), _aware(expires_at)
        cleaned_reason = _code(reason, "reason", 1024)
        key = _code(idempotency_key, "idempotency_key", 128)
        if delegate_id == actor.actor_id:
            raise ApprovalOperationsError("approval_delegation_self_forbidden")
        if (
            start > at + timedelta(minutes=5)
            or start >= expiry
            or expiry > at + timedelta(days=30)
        ):
            raise ApprovalOperationsError("approval_delegation_window_invalid")
        candidate_keys = {
            value.digest(
                domain="approval-delegation-create-idempotency",
                values=(actor.realm, str(actor.actor_id), key),
            ): value
            for value in self._digesters
        }
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(
                db, actor, mutation="delegation_replay", work_item_id=work_item_id
            )
            delegator_column, _ = _delegation_actor_columns(actor.realm)
            replay = db.execute(
                sa.select(ApprovalDelegationRecord).where(
                    ApprovalDelegationRecord.realm == actor.realm,
                    ApprovalDelegationRecord.tenant_id == actor.tenant_id,
                    getattr(ApprovalDelegationRecord, delegator_column) == actor.actor_id,
                    ApprovalDelegationRecord.create_idempotency_hmac.in_(tuple(candidate_keys)),
                )
            ).scalar_one_or_none()
            if replay is not None:
                replay_digester = candidate_keys.get(replay.create_idempotency_hmac)
                expected_request = (
                    replay_digester.digest(
                        domain="approval-delegation-create-request",
                        values=(
                            str(work_item_id),
                            str(expected_version),
                            str(delegate_id),
                            start.isoformat(),
                            expiry.isoformat(),
                            cleaned_reason,
                        ),
                    )
                    if replay_digester is not None
                    else ""
                )
                if (
                    replay_digester is None
                    or replay.hmac_key_id != replay_digester.key_id
                    or not hmac.compare_digest(replay.create_request_hmac, expected_request)
                ):
                    raise ApprovalOperationsError("approval_delegation_idempotency_conflict")
                return _delegation_view(replay)
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(
                db,
                actor,
                mutation="delegation_source_read",
                work_item_id=work_item_id,
            )
            work = db.get(ApprovalWorkItemRecord, work_item_id)
            if (
                work is None
                or work.realm != actor.realm
                or (actor.realm == "tenant" and work.tenant_id != actor.tenant_id)
                or work.status != "pending"
                or work.version != expected_version
            ):
                raise ApprovalOperationsError("approval_work_item_not_found")
            if _is_requester(work, actor):
                raise ApprovalOperationsError("approval_separation_of_duties")
            if _assignee_id(work) != actor.actor_id:
                if self._routing_allows(db, work, actor, at):
                    raise ApprovalOperationsError("approval_delegation_chain_forbidden")
                raise ApprovalOperationsError("approval_delegation_assignment_required")
            authority = self._adapters.get(work.operation_kind)
            if authority is None:
                raise ApprovalOperationsError("approval_authority_unavailable")
            permission = work.required_permission
            tenant_id = work.tenant_id
            scope_id = work.operation_id
            work_view = _work_view(work)
        authority.authorize_work_item(actor, work_view, now=at)
        authority.authorize_identity(
            realm=actor.realm,
            actor_id=delegate_id,
            permission=permission,
            tenant_id=tenant_id,
            operation_id=scope_id,
            now=at,
        )
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(
                db,
                actor,
                mutation="delegation_create",
                work_item_id=work_item_id,
                operation_id=scope_id,
            )
            locked_work = db.execute(
                sa.select(ApprovalWorkItemRecord)
                .where(ApprovalWorkItemRecord.id == work_item_id)
                .with_for_update()
            ).scalar_one_or_none()
            if (
                locked_work is None
                or locked_work.status != "pending"
                or locked_work.version != expected_version
                or locked_work.operation_id != scope_id
                or locked_work.required_permission != permission
                or locked_work.tenant_id != tenant_id
            ):
                raise ApprovalOperationsError("approval_delegation_source_changed")
            actor_delegator, actor_delegate = _delegation_actor_columns(actor.realm)
            chain = db.execute(
                sa.select(ApprovalDelegationRecord.id).where(
                    ApprovalDelegationRecord.realm == actor.realm,
                    ApprovalDelegationRecord.tenant_id == tenant_id,
                    ApprovalDelegationRecord.status == "active",
                    ApprovalDelegationRecord.starts_at <= at,
                    ApprovalDelegationRecord.expires_at > at,
                    sa.or_(
                        getattr(ApprovalDelegationRecord, actor_delegate) == actor.actor_id,
                        getattr(ApprovalDelegationRecord, actor_delegator) == delegate_id,
                        getattr(ApprovalDelegationRecord, actor_delegate) == delegate_id,
                    ),
                )
            ).scalar_one_or_none()
            if chain is not None:
                raise ApprovalOperationsError("approval_delegation_chain_forbidden")
            record = ApprovalDelegationRecord(
                id=uuid4(),
                realm=actor.realm,
                tenant_id=tenant_id,
                hmac_key_id=self._digester.key_id,
                delegator_user_id=(actor.actor_id if actor.realm == "tenant" else None),
                delegator_principal_id=(actor.actor_id if actor.realm == "staff" else None),
                delegate_user_id=(delegate_id if actor.realm == "tenant" else None),
                delegate_principal_id=(delegate_id if actor.realm == "staff" else None),
                permission_code=permission,
                scope_type="operation",
                scope_id=scope_id,
                starts_at=start,
                expires_at=expiry,
                status="active",
                reason_hmac=self._digester.digest(
                    domain="approval-delegation-reason",
                    values=(cleaned_reason,),
                ),
                create_idempotency_hmac=self._digester.digest(
                    domain="approval-delegation-create-idempotency",
                    values=(actor.realm, str(actor.actor_id), key),
                ),
                create_request_hmac=self._digester.digest(
                    domain="approval-delegation-create-request",
                    values=(
                        str(work_item_id),
                        str(expected_version),
                        str(delegate_id),
                        start.isoformat(),
                        expiry.isoformat(),
                        cleaned_reason,
                    ),
                ),
                version=1,
                created_at=at,
                updated_at=at,
            )
            db.add(record)
            db.flush()
            return _delegation_view(record)

    def list_delegations(
        self,
        actor: ApprovalActor,
        *,
        status: str | None = None,
        limit: int = 50,
        cursor: UUID | None = None,
        now: datetime | None = None,
    ) -> ApprovalDelegationPage:
        at = _aware(now or datetime.now(timezone.utc))
        _validate_actor(actor, at)
        if status is not None and status not in {"active", "revoked", "expired"}:
            raise ApprovalOperationsError("approval_delegation_status_invalid")
        if not 1 <= limit <= 100:
            raise ApprovalOperationsError("approval_page_limit_invalid")
        delegator_column, delegate_column = _delegation_actor_columns(actor.realm)
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(db, actor, mutation="delegation_list")
            query = sa.select(ApprovalDelegationRecord).where(
                ApprovalDelegationRecord.realm == actor.realm,
                sa.or_(
                    getattr(ApprovalDelegationRecord, delegator_column) == actor.actor_id,
                    getattr(ApprovalDelegationRecord, delegate_column) == actor.actor_id,
                ),
            )
            if actor.realm == "tenant" or actor.tenant_id is not None:
                query = query.where(ApprovalDelegationRecord.tenant_id == actor.tenant_id)
            if cursor is not None:
                query = query.where(ApprovalDelegationRecord.id > cursor)
            if status is not None:
                query = query.where(ApprovalDelegationRecord.status == status)
            values = tuple(
                db.execute(query.order_by(ApprovalDelegationRecord.id).limit(limit + 1)).scalars()
            )
            for value in values:
                if value.status == "active" and _stored_utc(value.expires_at) <= at:
                    value.status = "expired"
                    value.version += 1
                    value.updated_at = at
            db.flush()
            items = tuple(_delegation_view(value) for value in values[:limit])
        return ApprovalDelegationPage(
            items=items,
            next_cursor=(items[-1].id if len(values) > limit and items else None),
        )

    def revoke_delegation(
        self,
        actor: ApprovalActor,
        *,
        delegation_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ApprovalDelegationView:
        at = _aware(now or datetime.now(timezone.utc))
        _validate_actor(actor, at)
        key = _code(idempotency_key, "idempotency_key", 128)
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(db, actor, mutation="delegation_revoke")
            record = db.execute(
                sa.select(ApprovalDelegationRecord)
                .where(ApprovalDelegationRecord.id == delegation_id)
                .with_for_update()
            ).scalar_one_or_none()
            if record is None or not _delegation_visible(record, actor):
                raise ApprovalOperationsError("approval_delegation_not_found")
            if _delegator_id(record) != actor.actor_id:
                raise ApprovalOperationsError("approval_delegation_revoke_forbidden")
            digester = self._digester_for_key(record.hmac_key_id)
            key_hmac = digester.digest(
                domain="approval-delegation-revoke-idempotency",
                values=(str(record.id), key),
            )
            request_hmac = digester.digest(
                domain="approval-delegation-revoke-request",
                values=(str(record.id), str(expected_version)),
            )
            if record.status == "revoked":
                if not hmac.compare_digest(record.revoke_idempotency_hmac or "", key_hmac):
                    raise ApprovalOperationsError("approval_delegation_idempotency_conflict")
                if not hmac.compare_digest(record.revoke_request_hmac or "", request_hmac):
                    raise ApprovalOperationsError("approval_delegation_payload_conflict")
                return _delegation_view(record)
            if record.status != "active" or record.version != expected_version:
                raise ApprovalOperationsError("approval_delegation_conflict")
            record.status = "revoked"
            record.revoke_idempotency_hmac = key_hmac
            record.revoke_request_hmac = request_hmac
            record.revoked_at = at
            record.version += 1
            record.updated_at = at
            db.flush()
            return _delegation_view(record)

    def decide(
        self,
        actor: ApprovalActor,
        *,
        work_item_id: UUID,
        expected_version: int,
        decision: ApprovalDecision,
        decision_code: str,
        decision_reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ApprovalWorkItemView:
        at = _aware(now or datetime.now(timezone.utc))
        _validate_actor(actor, at)
        if decision not in {"approve", "reject"}:
            raise ApprovalOperationsError("approval_decision_invalid")
        code = _code(decision_code, "decision_code", 128)
        reason = _code(decision_reason, "decision_reason", 1024)
        key = _code(idempotency_key, "idempotency_key", 128)
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(db, actor, mutation="decision", work_item_id=work_item_id)
            work = db.execute(
                sa.select(ApprovalWorkItemRecord).where(ApprovalWorkItemRecord.id == work_item_id)
            ).scalar_one_or_none()
            if work is None or not self._can_act(db, work, actor, at):
                raise ApprovalOperationsError("approval_work_item_not_found")
            if _is_requester(work, actor):
                raise ApprovalOperationsError("approval_separation_of_duties")
            if work.status == "pending" and work.version != expected_version:
                raise ApprovalOperationsError("approval_work_item_conflict")
            adapter = self._adapters.get(work.operation_kind)
            if adapter is None:
                raise ApprovalOperationsError("approval_authority_unavailable")
            adapter.authorize_work_item(actor, _work_view(work), now=at)
            authority_command = AuthorityDecisionCommand(
                operation_id=work.operation_id,
                expected_snapshot_hash=work.snapshot_hash,
                expected_projection_version=expected_version,
                decision=decision,
                decision_code=code,
                decision_reason=reason,
                idempotency_key=key,
            )
            operation_kind = work.operation_kind
        adapter.decide(actor, authority_command, projection=self._projection, now=at)
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(
                db, actor, mutation="decision_read", work_item_id=work_item_id
            )
            terminal = db.get(ApprovalWorkItemRecord, work_item_id)
            expected_status = "approved" if decision == "approve" else "rejected"
            if terminal is None or terminal.operation_kind != operation_kind:
                raise ApprovalOperationsError("approval_projection_not_found")
            if terminal.status != expected_status or terminal.decision_code != code:
                raise ApprovalOperationsError("approval_authority_projection_unsynchronized")
            return _work_view(terminal)

    def preview_batch(
        self,
        actor: ApprovalActor,
        *,
        commands: tuple[BatchDecisionCommand, ...],
        decision: ApprovalDecision,
        decision_code: str,
        decision_reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> OperationBatchView:
        at = _aware(now or self._clock())
        _validate_actor(actor, at)
        if not 1 <= len(commands) <= _MAX_BATCH_ITEMS:
            raise ApprovalOperationsError("operation_batch_size_invalid")
        if len({value.work_item_id for value in commands}) != len(commands):
            raise ApprovalOperationsError("operation_batch_duplicate_item")
        key = _code(idempotency_key, "idempotency_key", 128)
        code = _code(decision_code, "decision_code", 128)
        reason = _code(decision_reason, "decision_reason", 1024)
        item_payload = json.dumps(
            [(str(v.work_item_id), v.expected_version) for v in commands],
            separators=(",", ":"),
        )

        def request_values_for(
            value: ApprovalSecretDigester,
        ) -> tuple[str, str, str, str]:
            return (
                item_payload,
                decision,
                code,
                value.digest(domain="operation-batch-decision-reason", values=(reason,)),
            )

        candidate_keys = {
            value.digest(
                domain="operation-batch-idempotency",
                values=(actor.realm, str(actor.actor_id), key),
            ): value
            for value in self._digesters
        }
        with self._sessions.begin() as db:
            existing = self._batch_replay(db, actor, tuple(candidate_keys))
            if existing is not None:
                replay_digester = candidate_keys.get(existing.idempotency_key_hmac)
                if replay_digester is None or replay_digester.key_id != existing.hmac_key_id:
                    raise ApprovalOperationsError("operation_batch_hmac_key_unavailable")
                if existing.request_hmac != replay_digester.digest(
                    domain="operation-batch-request",
                    values=request_values_for(replay_digester),
                ):
                    raise ApprovalOperationsError("operation_batch_idempotency_conflict")
                return self._batch_view(db, existing, replayed=True)
            request_hmac = self._digester.digest(
                domain="operation-batch-request",
                values=request_values_for(self._digester),
            )
            key_hmac = self._digester.digest(
                domain="operation-batch-idempotency",
                values=(actor.realm, str(actor.actor_id), key),
            )
            batch_id = UUID(hex=key_hmac[:32])
            _apply_approval_actor_rls(db, actor, mutation="batch_preview", batch_id=batch_id)
            works = tuple(
                db.execute(
                    sa.select(ApprovalWorkItemRecord).where(
                        ApprovalWorkItemRecord.id.in_(v.work_item_id for v in commands)
                    )
                ).scalars()
            )
            by_id = {value.id: value for value in works}
            if len(by_id) != len(commands):
                raise ApprovalOperationsError("operation_batch_item_not_found")
            first = by_id[commands[0].work_item_id]
            for command in commands:
                work = by_id[command.work_item_id]
                if not self._can_act(db, work, actor, at):
                    raise ApprovalOperationsError("operation_batch_item_not_found")
                if _is_requester(work, actor):
                    raise ApprovalOperationsError("approval_separation_of_duties")
                if work.status != "pending" or work.version != command.expected_version:
                    raise ApprovalOperationsError("operation_batch_preview_conflict")
                if (
                    work.realm != first.realm
                    or work.tenant_id != first.tenant_id
                    or work.operation_kind != first.operation_kind
                    or work.action != first.action
                ):
                    raise ApprovalOperationsError("operation_batch_scope_mixed")
            batch = OperationBatchRecord(
                id=batch_id,
                realm=actor.realm,
                tenant_id=first.tenant_id,
                requested_by_user_id=(actor.actor_id if actor.realm == "tenant" else None),
                requested_by_principal_id=(actor.actor_id if actor.realm == "staff" else None),
                operation_kind=first.operation_kind,
                action=first.action,
                decision_code=decision,
                authority_decision_code=code,
                decision_reason_hmac=request_values_for(self._digester)[3],
                hmac_key_id=self._digester.key_id,
                idempotency_key_hmac=key_hmac,
                request_hmac=request_hmac,
                item_count=len(commands),
                status="pending",
                success_count=0,
                failure_count=0,
                version=1,
                created_at=at,
                updated_at=at,
            )
            db.add(batch)
            db.flush()
            db.add_all(
                OperationBatchItemRecord(
                    id=uuid4(),
                    batch_id=batch.id,
                    realm=actor.realm,
                    tenant_id=first.tenant_id,
                    hmac_key_id=self._digester.key_id,
                    requested_by_user_id=(actor.actor_id if actor.realm == "tenant" else None),
                    requested_by_principal_id=(actor.actor_id if actor.realm == "staff" else None),
                    sequence=sequence,
                    target_type=by_id[command.work_item_id].target_type,
                    target_locator_hmac=by_id[command.work_item_id].target_locator_hmac,
                    operation_id=by_id[command.work_item_id].operation_id,
                    approval_work_item_id=command.work_item_id,
                    expected_work_item_version=command.expected_version,
                    status="pending",
                    version=1,
                    created_at=at,
                    updated_at=at,
                )
                for sequence, command in enumerate(commands, start=1)
            )
            db.flush()
            return self._batch_view(db, batch, replayed=False)

    def execute_batch(
        self,
        actor: ApprovalActor,
        *,
        batch_id: UUID,
        expected_version: int,
        decision_reason: str,
        now: datetime | None = None,
    ) -> OperationBatchView:
        at = _aware(now or self._clock())
        _validate_actor(actor, at)
        reason = _code(decision_reason, "decision_reason", 1024)
        lease_token = secrets.token_urlsafe(32)
        lease_token_hmac = ""
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(db, actor, mutation="batch_execute", batch_id=batch_id)
            batch = db.execute(
                sa.select(OperationBatchRecord)
                .where(OperationBatchRecord.id == batch_id)
                .with_for_update()
            ).scalar_one_or_none()
            if batch is None or not _batch_visible(batch, actor):
                raise ApprovalOperationsError("operation_batch_not_found")
            batch_digester = self._digester_for_key(batch.hmac_key_id)
            if not hmac.compare_digest(
                batch.decision_reason_hmac,
                batch_digester.digest(domain="operation-batch-decision-reason", values=(reason,)),
            ):
                raise ApprovalOperationsError("operation_batch_decision_reason_conflict")
            lease_token_hmac = batch_digester.digest(
                domain="operation-batch-lease", values=(str(batch_id), lease_token)
            )
            if batch.status in {"partial", "succeeded", "failed", "cancelled"}:
                return self._batch_view(db, batch, replayed=True)
            if batch.version != expected_version:
                raise ApprovalOperationsError("operation_batch_conflict")
            if batch.status == "running":
                if batch.lease_expires_at is None:
                    raise ApprovalOperationsError("operation_batch_lease_invalid")
                if _stored_utc(batch.lease_expires_at) > at:
                    raise ApprovalOperationsError("operation_batch_lease_active")
            if batch.status not in {"pending", "running"}:
                raise ApprovalOperationsError("operation_batch_conflict")
            if _stored_utc(batch.created_at) + _BATCH_EXECUTION_WINDOW < at:
                batch.status = "cancelled"
                batch.completed_at = at
                batch.leased_at = None
                batch.lease_expires_at = None
                batch.lease_token_hmac = None
                batch.executor_identity_sha256 = None
                batch.result_hmac = batch_digester.digest(
                    domain="operation-batch-result", values=(str(batch.id), "cancelled")
                )
                batch.version += 1
                batch.updated_at = at
                db.flush()
                self._notify_batch_completed(db, actor, batch, at)
                return self._batch_view(db, batch, replayed=False)
            batch.status = "running"
            batch.started_at = batch.started_at or at
            batch.leased_at = at
            batch.lease_expires_at = at + timedelta(minutes=2)
            batch.lease_token_hmac = lease_token_hmac
            batch.executor_identity_sha256 = sha256(
                f"{actor.realm}:{actor.actor_id}".encode()
            ).hexdigest()
            batch.lease_generation += 1
            batch.version += 1
            batch.updated_at = at
            items = tuple(
                db.execute(
                    sa.select(OperationBatchItemRecord)
                    .where(OperationBatchItemRecord.batch_id == batch.id)
                    .order_by(OperationBatchItemRecord.sequence)
                ).scalars()
            )
            decision = batch.decision_code
            decision_code = batch.authority_decision_code
        for item in items:
            if item.status in {"succeeded", "failed", "skipped"}:
                continue
            item_at = _aware(now or self._clock())
            if not self._refresh_batch_lease(actor, batch_id, lease_token_hmac, item_at):
                raise ApprovalOperationsError("operation_batch_lease_lost")
            if not self._claim_batch_item(actor, item.id, batch_id, lease_token_hmac, item_at):
                raise ApprovalOperationsError("operation_batch_lease_lost")
            try:
                result = self.decide(
                    actor,
                    work_item_id=item.approval_work_item_id,
                    expected_version=item.expected_work_item_version,
                    decision=decision,  # type: ignore[arg-type]
                    decision_code=decision_code,
                    decision_reason=reason,
                    idempotency_key=f"batch:{batch_id}:{item.id}",
                    now=item_at,
                )
            except ApprovalOperationsError as error:
                self._settle_batch_item(
                    actor,
                    item.id,
                    batch_id,
                    lease_token_hmac,
                    error.code,
                    None,
                    item_at,
                )
            else:
                self._settle_batch_item(
                    actor,
                    item.id,
                    batch_id,
                    lease_token_hmac,
                    None,
                    batch_digester.digest(
                        domain="operation-batch-item-result",
                        values=(json.dumps(_work_result(result), sort_keys=True),),
                    ),
                    item_at,
                )
        completed_at = _aware(now or self._clock())
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(db, actor, mutation="batch_complete", batch_id=batch_id)
            batch = db.execute(
                sa.select(OperationBatchRecord)
                .where(OperationBatchRecord.id == batch_id)
                .with_for_update()
            ).scalar_one()
            if batch.status != "running" or not hmac.compare_digest(
                batch.lease_token_hmac or "", lease_token_hmac
            ):
                raise ApprovalOperationsError("operation_batch_lease_lost")
            if (
                batch.lease_expires_at is None
                or _stored_utc(batch.lease_expires_at) <= completed_at
            ):
                raise ApprovalOperationsError("operation_batch_lease_lost")
            batch_digester = self._digester_for_key(batch.hmac_key_id)
            rows = tuple(
                db.execute(
                    sa.select(OperationBatchItemRecord).where(
                        OperationBatchItemRecord.batch_id == batch.id
                    )
                ).scalars()
            )
            success = sum(value.status == "succeeded" for value in rows)
            failure = sum(value.status == "failed" for value in rows)
            batch.success_count = success
            batch.failure_count = failure
            batch.status = "succeeded" if failure == 0 else "failed" if success == 0 else "partial"
            batch.completed_at = completed_at
            batch.leased_at = None
            batch.lease_expires_at = None
            batch.lease_token_hmac = None
            batch.executor_identity_sha256 = None
            batch.result_hmac = batch_digester.digest(
                domain="operation-batch-result",
                values=(
                    str(batch.id),
                    str(success),
                    str(failure),
                    json.dumps(
                        [(value.sequence, value.status) for value in rows],
                        separators=(",", ":"),
                    ),
                ),
            )
            batch.version += 1
            batch.updated_at = completed_at
            db.flush()
            self._notify_batch_completed(db, actor, batch, completed_at)
            return self._batch_view(db, batch, replayed=False)

    def _notify_batch_completed(
        self,
        db: Session,
        actor: ApprovalActor,
        batch: OperationBatchRecord,
        at: datetime,
    ) -> None:
        if self._notifier is None:
            return
        self._notifier.enqueue_batch_completed_in_transaction(
            db,
            realm=actor.realm,
            tenant_id=batch.tenant_id,
            requester_id=actor.actor_id,
            batch_id=batch.id,
            status=batch.status,
            now=at,
        )

    def _settle_batch_item(
        self,
        actor: ApprovalActor,
        item_id: UUID,
        batch_id: UUID,
        lease_token_hmac: str,
        error_code: str | None,
        result_hmac: str | None,
        at: datetime,
    ) -> None:
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(db, actor, mutation="batch_item_settle", batch_id=batch_id)
            batch = db.get(OperationBatchRecord, batch_id)
            if (
                batch is None
                or batch.status != "running"
                or batch.lease_expires_at is None
                or _stored_utc(batch.lease_expires_at) <= at
                or not hmac.compare_digest(batch.lease_token_hmac or "", lease_token_hmac)
            ):
                raise ApprovalOperationsError("operation_batch_lease_lost")
            batch_digester = self._digester_for_key(batch.hmac_key_id)
            item = db.execute(
                sa.select(OperationBatchItemRecord)
                .where(OperationBatchItemRecord.id == item_id)
                .with_for_update()
            ).scalar_one()
            if item.status in {"succeeded", "failed", "skipped"}:
                return
            item.status = "succeeded" if error_code is None else "failed"
            item.error_code = error_code
            item.error_hmac = (
                None
                if error_code is None
                else batch_digester.digest(domain="operation-batch-error", values=(error_code,))
            )
            item.result_hmac = result_hmac or batch_digester.digest(
                domain="operation-batch-item-result",
                values=(str(item.id), "failed", error_code or "unknown"),
            )
            item.version += 1
            item.updated_at = at

    def _refresh_batch_lease(
        self,
        actor: ApprovalActor,
        batch_id: UUID,
        lease_token_hmac: str,
        at: datetime,
    ) -> bool:
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(db, actor, mutation="batch_lease_refresh", batch_id=batch_id)
            batch = db.execute(
                sa.select(OperationBatchRecord)
                .where(OperationBatchRecord.id == batch_id)
                .with_for_update()
            ).scalar_one_or_none()
            if (
                batch is None
                or batch.status != "running"
                or batch.lease_expires_at is None
                or _stored_utc(batch.lease_expires_at) <= at
                or not hmac.compare_digest(batch.lease_token_hmac or "", lease_token_hmac)
            ):
                return False
            deadline = _stored_utc(batch.created_at) + _BATCH_EXECUTION_WINDOW
            if at >= deadline:
                return False
            if _stored_utc(batch.lease_expires_at) - at <= timedelta(seconds=30):
                batch.lease_expires_at = min(deadline, at + timedelta(minutes=2))
                batch.version += 1
                batch.updated_at = at
            return True

    def _claim_batch_item(
        self,
        actor: ApprovalActor,
        item_id: UUID,
        batch_id: UUID,
        lease_token_hmac: str,
        at: datetime,
    ) -> bool:
        with self._sessions.begin() as db:
            _apply_approval_actor_rls(db, actor, mutation="batch_item_claim", batch_id=batch_id)
            batch = db.get(OperationBatchRecord, batch_id)
            if (
                batch is None
                or batch.status != "running"
                or batch.lease_expires_at is None
                or _stored_utc(batch.lease_expires_at) <= at
                or not hmac.compare_digest(batch.lease_token_hmac or "", lease_token_hmac)
            ):
                return False
            item = db.execute(
                sa.select(OperationBatchItemRecord)
                .where(OperationBatchItemRecord.id == item_id)
                .with_for_update()
            ).scalar_one_or_none()
            if item is None or item.batch_id != batch_id:
                return False
            if item.status == "pending":
                item.status = "running"
                item.version += 1
                item.updated_at = at
            return item.status == "running"

    def _can_act(
        self,
        db: Session,
        work: ApprovalWorkItemRecord,
        actor: ApprovalActor,
        at: datetime,
    ) -> bool:
        if work.realm != actor.realm:
            return False
        if actor.realm == "tenant" and work.tenant_id != actor.tenant_id:
            return False
        if not self._routing_allows(db, work, actor, at):
            return False
        adapter = self._adapters.get(work.operation_kind)
        if adapter is None:
            return False
        try:
            adapter.authorize_work_item(actor, _work_view(work), now=at)
        except ApprovalOperationsError:
            return False
        return True

    @staticmethod
    def _routing_allows(
        db: Session,
        work: ApprovalWorkItemRecord,
        actor: ApprovalActor,
        at: datetime,
    ) -> bool:
        assignee_id = _assignee_id(work)
        if assignee_id is None or assignee_id == actor.actor_id:
            return True
        delegator_column, delegate_column = _delegation_actor_columns(actor.realm)
        delegated = db.execute(
            sa.select(ApprovalDelegationRecord.id).where(
                ApprovalDelegationRecord.realm == actor.realm,
                ApprovalDelegationRecord.tenant_id == work.tenant_id,
                getattr(ApprovalDelegationRecord, delegator_column) == assignee_id,
                getattr(ApprovalDelegationRecord, delegate_column) == actor.actor_id,
                ApprovalDelegationRecord.permission_code == work.required_permission,
                ApprovalDelegationRecord.scope_type == "operation",
                ApprovalDelegationRecord.scope_id == work.operation_id,
                ApprovalDelegationRecord.status == "active",
                ApprovalDelegationRecord.starts_at <= at,
                ApprovalDelegationRecord.expires_at > at,
            )
        ).scalar_one_or_none()
        return delegated is not None

    def _batch_replay(
        self, db: Session, actor: ApprovalActor, key_hmacs: tuple[str, ...]
    ) -> OperationBatchRecord | None:
        for key_hmac in key_hmacs:
            batch_id = UUID(hex=key_hmac[:32])
            _apply_approval_actor_rls(db, actor, mutation="batch_replay", batch_id=batch_id)
            value = db.get(OperationBatchRecord, batch_id)
            if value is not None:
                return value
        return None

    def _digester_for_key(self, key_id: str) -> ApprovalSecretDigester:
        for value in self._digesters:
            if hmac.compare_digest(value.key_id, key_id):
                return value
        raise ApprovalOperationsError("approval_hmac_key_unavailable")

    @staticmethod
    def _batch_view(
        db: Session, batch: OperationBatchRecord, *, replayed: bool
    ) -> OperationBatchView:
        items = tuple(
            db.execute(
                sa.select(OperationBatchItemRecord)
                .where(OperationBatchItemRecord.batch_id == batch.id)
                .order_by(OperationBatchItemRecord.sequence)
            ).scalars()
        )
        return OperationBatchView(
            id=batch.id,
            realm=batch.realm,
            tenant_id=batch.tenant_id,
            operation_kind=batch.operation_kind,
            action=batch.action,
            decision=batch.decision_code,
            item_count=batch.item_count,
            status=batch.status,
            success_count=batch.success_count,
            failure_count=batch.failure_count,
            version=batch.version,
            created_at=_stored_utc(batch.created_at),
            items=tuple(_batch_item_view(value) for value in items),
            replayed=replayed,
        )


def _validate_projection(command: ApprovalProjectionCommand, at: datetime) -> None:
    _validate_scope(command.realm, command.tenant_id)
    if command.requester_realm not in {"tenant", "staff"}:
        raise ApprovalOperationsError("approval_requester_realm_invalid")
    if command.source_authority not in {"support", "privacy", "enterprise", "audit"}:
        raise ApprovalOperationsError("approval_source_authority_invalid")
    _validate_source_binding(
        source_authority=command.source_authority,
        source_subject_id=command.source_subject_id,
        operation_kind=command.operation_kind,
    )
    _code(command.hmac_key_id, "hmac_key_id", 128)
    for value, field_name, maximum in (
        (command.operation_kind, "operation_kind", 64),
        (command.action, "action", 96),
        (command.target_type, "target_type", 64),
        (command.required_permission, "required_permission", 128),
    ):
        _code(value, field_name, maximum)
    _hash(command.target_locator_hmac, "target_locator_hmac")
    _hash(command.snapshot_hash, "snapshot_hash")
    due, escalation = _aware(command.due_at), _aware(command.escalation_at)
    if due <= at or escalation > due:
        raise ApprovalOperationsError("approval_projection_deadline_invalid")


def _validate_terminal(command: ApprovalTerminalCommand) -> None:
    _validate_scope(command.realm, command.tenant_id)
    _validate_source_binding(
        source_authority=command.source_authority,
        source_subject_id=command.source_subject_id,
        operation_kind=command.operation_kind,
    )
    _code(command.operation_kind, "operation_kind", 64)
    _code(command.required_permission, "required_permission", 128)
    _hash(command.expected_snapshot_hash, "snapshot_hash")


def _validate_source_binding(
    *, source_authority: str, source_subject_id: UUID | None, operation_kind: str
) -> None:
    prefixes = {
        "support": "support",
        "privacy": "privacy",
        "enterprise": "enterprise",
        "audit": "audit",
    }
    prefix = prefixes.get(source_authority)
    if prefix is None or not operation_kind.startswith(prefix):
        raise ApprovalOperationsError("approval_source_authority_invalid")
    if source_authority == "support" and source_subject_id is None:
        raise ApprovalOperationsError("approval_source_subject_required")
    if source_authority != "support" and source_subject_id is not None:
        raise ApprovalOperationsError("approval_source_subject_invalid")


def _validate_actor(actor: ApprovalActor, at: datetime) -> None:
    _validate_scope(actor.realm, actor.tenant_id)
    if _aware(actor.authenticated_at) > at or _aware(actor.expires_at) <= at:
        raise ApprovalOperationsError("approval_actor_session_invalid")
    if actor.security_version < 1:
        raise ApprovalOperationsError("approval_actor_security_version_invalid")


def _validate_scope(realm: str, tenant_id: UUID | None) -> None:
    if realm not in {"tenant", "staff"}:
        raise ApprovalOperationsError("approval_realm_invalid")
    if realm == "tenant" and tenant_id is None:
        raise ApprovalOperationsError("approval_tenant_scope_required")


def _code(value: str, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or "\x00" in cleaned:
        raise ApprovalOperationsError(f"approval_{field}_invalid")
    return cleaned


def _hash(value: str, field: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ApprovalOperationsError(f"approval_{field}_invalid")
    return value


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ApprovalOperationsError("approval_time_invalid")
    return value.astimezone(timezone.utc)


def _stored_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _work_view(value: ApprovalWorkItemRecord) -> ApprovalWorkItemView:
    return ApprovalWorkItemView(
        id=value.id,
        realm=value.realm,
        tenant_id=value.tenant_id,
        hmac_key_id=value.hmac_key_id,
        requester_realm=value.requester_realm,
        requester_id=_requester_id(value),
        assignee_id=_assignee_id(value),
        operation_kind=value.operation_kind,
        operation_id=value.operation_id,
        action=value.action,
        target_type=value.target_type,
        target_locator_hmac=value.target_locator_hmac,
        required_permission=value.required_permission,
        risk_level=value.risk_level,
        snapshot_hash=value.snapshot_hash,
        status=value.status,
        priority=value.priority,
        due_at=_stored_utc(value.due_at),
        escalation_at=_stored_utc(value.escalation_at),
        escalation_count=value.escalation_count,
        decision_code=value.decision_code,
        decided_at=_stored_utc(value.decided_at) if value.decided_at else None,
        version=value.version,
    )


def _assignee_id(value: ApprovalWorkItemRecord) -> UUID | None:
    return value.assignee_user_id or value.assignee_principal_id


def _requester_id(value: ApprovalWorkItemRecord) -> UUID:
    actor_id = value.requested_by_user_id or value.requested_by_principal_id
    if actor_id is None:
        raise ApprovalOperationsError("approval_projection_requester_invalid")
    return actor_id


def _is_requester(value: ApprovalWorkItemRecord, actor: ApprovalActor) -> bool:
    return value.requester_realm == actor.realm and _requester_id(value) == actor.actor_id


def _delegator_id(value: ApprovalDelegationRecord) -> UUID:
    actor_id = value.delegator_user_id or value.delegator_principal_id
    if actor_id is None:
        raise ApprovalOperationsError("approval_delegation_actor_invalid")
    return actor_id


def _delegate_id(value: ApprovalDelegationRecord) -> UUID:
    actor_id = value.delegate_user_id or value.delegate_principal_id
    if actor_id is None:
        raise ApprovalOperationsError("approval_delegation_actor_invalid")
    return actor_id


def _delegation_actor_columns(realm: str) -> tuple[str, str]:
    return (
        ("delegator_user_id", "delegate_user_id")
        if realm == "tenant"
        else ("delegator_principal_id", "delegate_principal_id")
    )


def _delegation_visible(value: ApprovalDelegationRecord, actor: ApprovalActor) -> bool:
    return value.realm == actor.realm and (
        actor.realm == "staff" or value.tenant_id == actor.tenant_id
    )


def _batch_visible(value: OperationBatchRecord, actor: ApprovalActor) -> bool:
    requester = value.requested_by_user_id or value.requested_by_principal_id
    return (
        value.realm == actor.realm
        and (actor.realm == "staff" or value.tenant_id == actor.tenant_id)
        and requester == actor.actor_id
    )


def _delegation_view(value: ApprovalDelegationRecord) -> ApprovalDelegationView:
    return ApprovalDelegationView(
        id=value.id,
        realm=value.realm,
        tenant_id=value.tenant_id,
        delegator_id=_delegator_id(value),
        delegate_id=_delegate_id(value),
        permission_code=value.permission_code,
        scope_type=value.scope_type,
        scope_id=value.scope_id,
        starts_at=_stored_utc(value.starts_at),
        expires_at=_stored_utc(value.expires_at),
        status=value.status,
        version=value.version,
    )


def _batch_item_view(value: OperationBatchItemRecord) -> OperationBatchItemView:
    return OperationBatchItemView(
        id=value.id,
        sequence=value.sequence,
        work_item_id=value.approval_work_item_id,
        expected_work_item_version=value.expected_work_item_version,
        target_type=value.target_type,
        target_locator_hmac=value.target_locator_hmac,
        operation_id=value.operation_id,
        status=value.status,
        error_code=value.error_code,
        result_hmac=value.result_hmac,
    )


def _work_result(value: ApprovalWorkItemView) -> dict[str, object]:
    return {
        "work_item_id": str(value.id),
        "status": value.status,
        "version": value.version,
        "decision_code": value.decision_code,
    }


def _apply_notification_rls(
    db: Session,
    *,
    realm: str,
    tenant_id: UUID | None,
    actor_realm: str,
    actor_id: UUID | None,
    work_item_id: UUID,
    operation_id: UUID,
    source_authority: str,
    source_subject_id: UUID | None,
    mutation: str,
) -> None:
    """Bind exact notification claims without changing the source authority GUCs."""

    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    if realm not in {"tenant", "staff"} or actor_realm not in {"tenant", "staff"}:
        raise ApprovalOperationsError("approval_rls_realm_invalid")
    if source_authority not in {"support", "privacy", "enterprise", "audit"}:
        raise ApprovalOperationsError("approval_source_authority_invalid")
    values = {
        "realm": realm,
        "actor_realm": actor_realm,
        "tenant_id": str(tenant_id) if tenant_id is not None else "",
        "user_id": str(actor_id) if actor_realm == "tenant" and actor_id else "",
        "principal_id": str(actor_id) if actor_realm == "staff" and actor_id else "",
        "work_item_id": str(work_item_id),
        "operation_id": str(operation_id),
        "source_authority": source_authority,
        "source_support_grant_id": (
            str(source_subject_id) if source_authority == "support" and source_subject_id else ""
        ),
        "mutation": mutation,
    }
    db.execute(
        sa.text(
            "SELECT "
            "set_config('app.notification_realm', :realm, true), "
            "set_config('app.notification_actor_realm', :actor_realm, true), "
            "set_config('app.notification_tenant_id', :tenant_id, true), "
            "set_config('app.notification_recipient_user_id', :user_id, true), "
            "set_config('app.notification_staff_principal_id', :principal_id, true), "
            "set_config('app.notification_work_item_id', :work_item_id, true), "
            "set_config('app.notification_source_operation_id', :operation_id, true), "
            "set_config('app.notification_source_authority', :source_authority, true), "
            "set_config('app.notification_source_support_grant_id', "
            ":source_support_grant_id, true), "
            "set_config('app.notification_mutation', :mutation, true)"
        ),
        values,
    )


def _apply_approval_actor_rls(
    db: Session,
    actor: ApprovalActor,
    *,
    mutation: str,
    work_item_id: UUID | None = None,
    operation_id: UUID | None = None,
    batch_id: UUID | None = None,
) -> None:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    db.execute(
        sa.text(
            "SELECT "
            "set_config('app.notification_realm', :realm, true), "
            "set_config('app.notification_actor_realm', :realm, true), "
            "set_config('app.notification_tenant_id', :tenant_id, true), "
            "set_config('app.notification_recipient_user_id', :user_id, true), "
            "set_config('app.notification_staff_principal_id', :principal_id, true), "
            "set_config('app.notification_work_item_id', :work_item_id, true), "
            "set_config('app.notification_source_operation_id', :operation_id, true), "
            "set_config('app.notification_batch_id', :batch_id, true), "
            "set_config('app.notification_source_authority', '', true), "
            "set_config('app.notification_mutation', :mutation, true)"
        ),
        {
            "realm": actor.realm,
            "tenant_id": str(actor.tenant_id) if actor.tenant_id else "",
            "user_id": str(actor.actor_id) if actor.realm == "tenant" else "",
            "principal_id": str(actor.actor_id) if actor.realm == "staff" else "",
            "work_item_id": str(work_item_id) if work_item_id else "",
            "operation_id": str(operation_id) if operation_id else "",
            "batch_id": str(batch_id) if batch_id else "",
            "mutation": mutation,
        },
    )
