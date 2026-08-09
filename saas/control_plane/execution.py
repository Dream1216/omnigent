"""Transactional P3 execution authority with durable queue and event replay."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution_models import (
    EFFECT_STATUSES,
    EFFECT_TYPES,
    RUN_STATUSES,
    TERMINAL_RUN_STATUSES,
    UNKNOWN_EFFECT_POLICIES,
    AdmissionQuotaRecord,
    ArtifactRecord,
    EffectCallRecord,
    ExecutionSessionRecord,
    QuotaReservationRecord,
    RunArtifactRecord,
    RunEventRecord,
    RunRecord,
    SessionTaskRecord,
    TaskRecord,
)
from saas.control_plane.rls import RlsContext, apply_rls_context

_LEASED_STATUSES = frozenset(
    {"leased", "starting", "running", "waiting_input", "waiting_approval", "cancelling"}
)
_ALLOWED_TRANSITIONS = {
    "created": frozenset({"queued", "cancelled"}),
    "queued": frozenset({"leased", "cancelled"}),
    "leased": frozenset({"starting", "cancelling", "failed", "orphaned"}),
    "starting": frozenset({"running", "cancelling", "failed", "timed_out", "orphaned"}),
    "running": frozenset(
        {
            "waiting_input",
            "waiting_approval",
            "cancelling",
            "succeeded",
            "failed",
            "timed_out",
            "orphaned",
        }
    ),
    "waiting_input": frozenset({"running", "cancelling", "timed_out", "orphaned"}),
    "waiting_approval": frozenset({"running", "cancelling", "timed_out", "orphaned"}),
    "cancelling": frozenset({"cancelled", "orphaned"}),
    "cancelled": frozenset(),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "timed_out": frozenset(),
    "orphaned": frozenset(),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _validate_time(value: datetime) -> None:
    if value.tzinfo is None:
        raise ExecutionControlPlaneError("time_timezone_required", "time must include a timezone")


def _canonical_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


def _validate_text(value: str, *, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise ExecutionControlPlaneError(f"{field}_invalid", f"{field} is invalid")
    return cleaned


class ExecutionControlPlaneError(RuntimeError):
    """Stable error surface for execution admission and worker operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ExecutionRevisionSet:
    """Immutable revisions attached to every admitted Run."""

    product_revision: str
    upstream_revision: str
    schema_revision: str
    adapter_contract_version: str

    def validate(self) -> None:
        for field, value, maximum in (
            ("product_revision", self.product_revision, 64),
            ("upstream_revision", self.upstream_revision, 64),
            ("schema_revision", self.schema_revision, 64),
            ("adapter_contract_version", self.adapter_contract_version, 32),
        ):
            _validate_text(value, field=field, maximum=maximum)


@dataclass(frozen=True, slots=True)
class RunAdmission:
    run_id: UUID
    task_id: UUID
    session_id: UUID | None
    status: str
    quota_reservation_id: UUID
    event_sequence: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class RunLease:
    run_id: UUID
    lease_token: UUID
    fence_token: int
    status: str
    expires_at: datetime
    version: int


@dataclass(frozen=True, slots=True)
class RunMutation:
    run_id: UUID
    status: str
    version: int
    event_sequence: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class PersistedRunEvent:
    id: UUID
    run_id: UUID
    sequence: int
    event_type: str
    payload: dict[str, object]
    trace_id: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class EffectCallState:
    effect_call_id: UUID
    status: str
    version: int
    replayed: bool
    retry_permitted: bool
    unknown_policy: str


@dataclass(frozen=True, slots=True)
class ArtifactRegistration:
    artifact_id: UUID
    run_id: UUID
    sha256: str
    replayed: bool


class ExecutionControlPlane:
    """Own durable execution state; push delivery is exclusively Outbox-driven."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        authorizer: ProjectAuthorizer | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._authorizer = authorizer or ProjectAuthorizer(session_factory)

    def create_task(self, request: RequestContext, *, project_id: UUID, title: str) -> UUID:
        """Create durable intent without persisting a second Task status authority."""

        self._authorizer.require(request, action="run.create", project_id=project_id)
        cleaned_title = _validate_text(title, field="task_title", maximum=256)
        task_id = uuid4()
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            db.add(
                TaskRecord(
                    id=task_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    created_by=request.actor_id,
                    title=cleaned_title,
                    version=1,
                )
            )
        return task_id

    def create_session(self, request: RequestContext, *, project_id: UUID) -> UUID:
        """Create an independent Session that may span zero or many Tasks."""

        self._authorizer.require(request, action="run.create", project_id=project_id)
        session_id = uuid4()
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            db.add(
                ExecutionSessionRecord(
                    id=session_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    created_by=request.actor_id,
                    status="active",
                    version=1,
                )
            )
        return session_id

    def attach_task(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        session_id: UUID,
        task_id: UUID,
    ) -> bool:
        """Idempotently associate Task and Session without coupling their lifecycles."""

        self._authorizer.require(request, action="run.create", project_id=project_id)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            execution_session = self._session(db, request, project_id, session_id, lock=True)
            if execution_session.status != "active":
                raise ExecutionControlPlaneError("session_closed", "Session is closed")
            self._task(db, request, project_id, task_id, lock=False)
            existing = db.scalar(
                sa.select(SessionTaskRecord.id).where(
                    SessionTaskRecord.session_id == session_id,
                    SessionTaskRecord.task_id == task_id,
                )
            )
            if existing is not None:
                return True
            db.add(
                SessionTaskRecord(
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    session_id=session_id,
                    task_id=task_id,
                    attached_by=request.actor_id,
                )
            )
            return False

    def close_session(
        self, request: RequestContext, *, project_id: UUID, session_id: UUID
    ) -> bool:
        """Close only the Session; existing Task and Run facts remain unchanged."""

        self._authorizer.require(request, action="run.create", project_id=project_id)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            execution_session = self._session(db, request, project_id, session_id, lock=True)
            if execution_session.status == "closed":
                return True
            execution_session.status = "closed"
            execution_session.closed_at = _utcnow()
            execution_session.version += 1
            return False

    def configure_quota(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        resource: str,
        limit_units: int,
    ) -> UUID:
        """Create or resize a project admission quota under optimistic safety."""

        self._authorizer.require(request, action="project.update", project_id=project_id)
        cleaned_resource = _validate_text(resource, field="quota_resource", maximum=64)
        if limit_units <= 0:
            raise ExecutionControlPlaneError("quota_limit_invalid", "quota limit must be positive")
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            quota = db.scalar(
                sa.select(AdmissionQuotaRecord)
                .where(
                    AdmissionQuotaRecord.tenant_id == request.tenant_id,
                    AdmissionQuotaRecord.space_id == request.space_id,
                    AdmissionQuotaRecord.project_id == project_id,
                    AdmissionQuotaRecord.resource == cleaned_resource,
                )
                .with_for_update()
            )
            if quota is None:
                quota = AdmissionQuotaRecord(
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    resource=cleaned_resource,
                    limit_units=limit_units,
                    reserved_units=0,
                    consumed_units=0,
                    version=1,
                )
                db.add(quota)
                db.flush()
                return quota.id
            if quota.reserved_units + quota.consumed_units > limit_units:
                raise ExecutionControlPlaneError(
                    "quota_below_allocated", "quota cannot be reduced below allocated units"
                )
            quota.limit_units = limit_units
            quota.version += 1
            return quota.id

    def admit_run(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        task_id: UUID,
        session_id: UUID | None,
        input_payload: dict[str, object],
        quota_resource: str,
        quota_units: int,
        idempotency_key: str,
        revisions: ExecutionRevisionSet,
        queue_class: str = "interactive",
        priority: int = 0,
    ) -> RunAdmission:
        """Atomically reserve quota, create/queue a Run, persist events, and enqueue pushes."""

        self._authorizer.require(request, action="run.create", project_id=project_id)
        revisions.validate()
        key = _validate_text(idempotency_key, field="idempotency_key", maximum=128)
        resource = _validate_text(quota_resource, field="quota_resource", maximum=64)
        queue = _validate_text(queue_class, field="queue_class", maximum=64)
        if quota_units <= 0:
            raise ExecutionControlPlaneError("quota_units_invalid", "quota units must be positive")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "task_id": str(task_id),
            "session_id": str(session_id) if session_id else None,
            "input": input_payload,
            "quota_resource": resource,
            "quota_units": quota_units,
            "queue_class": queue,
            "priority": priority,
            "product_revision": revisions.product_revision,
            "upstream_revision": revisions.upstream_revision,
            "schema_revision": revisions.schema_revision,
            "adapter_contract_version": revisions.adapter_contract_version,
        }
        digest = _canonical_hash(payload)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            existing = db.scalar(
                sa.select(RunRecord).where(
                    RunRecord.tenant_id == request.tenant_id,
                    RunRecord.idempotency_key == key,
                )
            )
            if existing is not None:
                if existing.request_hash != digest:
                    raise ExecutionControlPlaneError(
                        "idempotency_conflict", "idempotency key was used with another request"
                    )
                reservation_id = db.scalar(
                    sa.select(QuotaReservationRecord.id).where(
                        QuotaReservationRecord.run_id == existing.id
                    )
                )
                if reservation_id is None:
                    raise ExecutionControlPlaneError(
                        "admission_invariant_broken", "Run is missing its quota reservation"
                    )
                return RunAdmission(
                    existing.id,
                    existing.task_id,
                    existing.session_id,
                    existing.status,
                    reservation_id,
                    existing.event_sequence,
                    True,
                )

            self._task(db, request, project_id, task_id, lock=False)
            if session_id is not None:
                execution_session = self._session(db, request, project_id, session_id, lock=False)
                if execution_session.status != "active":
                    raise ExecutionControlPlaneError("session_closed", "Session is closed")
                link = db.scalar(
                    sa.select(SessionTaskRecord.id).where(
                        SessionTaskRecord.session_id == session_id,
                        SessionTaskRecord.task_id == task_id,
                    )
                )
                if link is None:
                    raise ExecutionControlPlaneError(
                        "session_task_unlinked", "Task is not attached to Session"
                    )

            quota = db.scalar(
                sa.select(AdmissionQuotaRecord)
                .where(
                    AdmissionQuotaRecord.tenant_id == request.tenant_id,
                    AdmissionQuotaRecord.space_id == request.space_id,
                    AdmissionQuotaRecord.project_id == project_id,
                    AdmissionQuotaRecord.resource == resource,
                )
                .with_for_update()
            )
            if quota is None:
                raise ExecutionControlPlaneError("quota_not_configured", "quota is not configured")
            if quota.reserved_units + quota.consumed_units + quota_units > quota.limit_units:
                raise ExecutionControlPlaneError("quota_exceeded", "admission quota is exhausted")

            run = RunRecord(
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=project_id,
                task_id=task_id,
                session_id=session_id,
                created_by=request.actor_id,
                status="created",
                version=1,
                event_sequence=0,
                queue_class=queue,
                priority=priority,
                idempotency_key=key,
                request_hash=digest,
                input=input_payload,
                product_revision=revisions.product_revision,
                upstream_revision=revisions.upstream_revision,
                schema_revision=revisions.schema_revision,
                adapter_contract_version=revisions.adapter_contract_version,
                fence_token=0,
            )
            db.add(run)
            db.flush()
            reservation_id = uuid4()
            reservation = QuotaReservationRecord(
                id=reservation_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=project_id,
                quota_id=quota.id,
                run_id=run.id,
                units=quota_units,
                status="reserved",
                version=1,
            )
            db.add(reservation)
            quota.reserved_units += quota_units
            quota.version += 1
            self._append_event(
                db,
                run,
                event_type="run.created",
                payload={
                    "status": "created",
                    "quota_reservation_id": str(reservation_id),
                    "quota_resource": resource,
                    "quota_units": quota_units,
                    "revisions": {
                        "product": revisions.product_revision,
                        "upstream": revisions.upstream_revision,
                        "schema": revisions.schema_revision,
                        "adapter": revisions.adapter_contract_version,
                    },
                },
                trace_id=request.trace_id,
            )
            run.status = "queued"
            run.version += 1
            self._append_event(
                db,
                run,
                event_type="run.queued",
                payload={"status": "queued", "queue_class": queue, "priority": priority},
                trace_id=request.trace_id,
            )
            return RunAdmission(
                run.id,
                task_id,
                session_id,
                run.status,
                reservation_id,
                run.event_sequence,
                False,
            )

    def claim_next_run(
        self,
        *,
        worker_id: str,
        lease_duration: timedelta,
        queue_class: str | None = None,
        now: datetime | None = None,
    ) -> RunLease | None:
        """Lease one queued Run using SKIP LOCKED and a monotonically increasing fence."""

        worker = _validate_text(worker_id, field="worker_id", maximum=256)
        if lease_duration <= timedelta(0):
            raise ExecutionControlPlaneError(
                "lease_duration_invalid", "lease duration must be positive"
            )
        claimed_at = now or _utcnow()
        _validate_time(claimed_at)
        with self._session_factory.begin() as db:
            query = sa.select(RunRecord).where(RunRecord.status == "queued")
            if queue_class is not None:
                query = query.where(
                    RunRecord.queue_class
                    == _validate_text(queue_class, field="queue_class", maximum=64)
                )
            query = query.order_by(
                RunRecord.priority.desc(), RunRecord.created_at, RunRecord.id
            ).limit(1)
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            run = db.scalar(query)
            if run is None:
                return None
            lease_token = uuid4()
            run.status = "leased"
            run.version += 1
            run.fence_token += 1
            run.lease_owner = worker
            run.lease_token = lease_token
            lease_expires_at = claimed_at + lease_duration
            run.lease_expires_at = lease_expires_at
            run.heartbeat_at = claimed_at
            self._append_event(
                db,
                run,
                event_type="run.leased",
                payload={
                    "status": "leased",
                    "worker_id": worker,
                    "fence_token": run.fence_token,
                    "lease_expires_at": lease_expires_at.isoformat(),
                },
                trace_id=f"worker:{worker}",
            )
            return RunLease(
                run.id,
                lease_token,
                run.fence_token,
                run.status,
                lease_expires_at,
                run.version,
            )

    def heartbeat(
        self,
        *,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        lease_duration: timedelta,
        now: datetime | None = None,
    ) -> RunLease:
        """Extend only the currently fenced lease; stale workers fail closed."""

        if lease_duration <= timedelta(0):
            raise ExecutionControlPlaneError(
                "lease_duration_invalid", "lease duration must be positive"
            )
        heartbeat_at = now or _utcnow()
        _validate_time(heartbeat_at)
        with self._session_factory.begin() as db:
            run = self._run(db, run_id, lock=True)
            self._require_lease(run, lease_token, fence_token, heartbeat_at)
            run.heartbeat_at = heartbeat_at
            run.lease_expires_at = heartbeat_at + lease_duration
            run.version += 1
            return RunLease(
                run.id,
                cast(UUID, run.lease_token),
                run.fence_token,
                run.status,
                cast(datetime, run.lease_expires_at),
                run.version,
            )

    def transition_run(
        self,
        *,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        target_status: str,
        payload: dict[str, object] | None = None,
        trace_id: str,
        now: datetime | None = None,
    ) -> RunMutation:
        """CAS-style state transition guarded by lease token, fence, and expiry."""

        if target_status not in RUN_STATUSES:
            raise ExecutionControlPlaneError("run_status_invalid", "Run status is invalid")
        changed_at = now or _utcnow()
        _validate_time(changed_at)
        trace = _validate_text(trace_id, field="trace_id", maximum=128)
        with self._session_factory.begin() as db:
            run = self._run(db, run_id, lock=True)
            self._require_lease(run, lease_token, fence_token, changed_at)
            if target_status not in _ALLOWED_TRANSITIONS[run.status]:
                raise ExecutionControlPlaneError(
                    "run_transition_invalid", f"cannot transition {run.status} to {target_status}"
                )
            run.status = target_status
            run.version += 1
            if target_status in TERMINAL_RUN_STATUSES:
                run.terminal_at = changed_at
                self._finalize_reservations(db, run, succeeded=target_status == "succeeded")
            self._append_event(
                db,
                run,
                event_type=f"run.{target_status}",
                payload={"status": target_status, **(payload or {})},
                trace_id=trace,
            )
            if target_status in TERMINAL_RUN_STATUSES:
                self._clear_lease(run)
            return RunMutation(run.id, run.status, run.version, run.event_sequence)

    def request_cancel(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        run_id: UUID,
        reason: str,
        now: datetime | None = None,
    ) -> RunMutation:
        """Persist cancellation intent; queued Runs terminate without worker coordination."""

        self._authorizer.require(request, action="run.cancel", project_id=project_id)
        requested_at = now or _utcnow()
        _validate_time(requested_at)
        cleaned_reason = _validate_text(reason, field="cancel_reason", maximum=1024)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            run = self._scoped_run(db, request, project_id, run_id, lock=True)
            if run.status in TERMINAL_RUN_STATUSES or run.status == "cancelling":
                return RunMutation(
                    run.id, run.status, run.version, run.event_sequence, replayed=True
                )
            run.cancel_requested_at = requested_at
            if run.status in {"created", "queued"}:
                run.status = "cancelled"
                run.terminal_at = requested_at
                self._finalize_reservations(db, run, succeeded=False)
                event_type = "run.cancelled"
            elif run.status in _LEASED_STATUSES:
                run.status = "cancelling"
                event_type = "run.cancelling"
            else:
                raise ExecutionControlPlaneError(
                    "run_cancel_invalid", f"Run in {run.status} cannot be cancelled"
                )
            run.version += 1
            self._append_event(
                db,
                run,
                event_type=event_type,
                payload={
                    "status": run.status,
                    "reason": cleaned_reason,
                    "requested_by": str(request.actor_id),
                },
                trace_id=request.trace_id,
            )
            if run.status == "cancelled":
                self._clear_lease(run)
            return RunMutation(run.id, run.status, run.version, run.event_sequence)

    def recover_expired_runs(
        self,
        *,
        max_fence_token: int = 3,
        batch_size: int = 100,
        now: datetime | None = None,
    ) -> tuple[RunMutation, ...]:
        """Requeue expired leases, or terminally orphan exhausted/cancelling Runs."""

        if max_fence_token <= 0 or not 1 <= batch_size <= 1000:
            raise ExecutionControlPlaneError(
                "recovery_policy_invalid", "recovery limits must be positive and bounded"
            )
        recovered_at = now or _utcnow()
        _validate_time(recovered_at)
        with self._session_factory.begin() as db:
            query = (
                sa.select(RunRecord)
                .where(
                    RunRecord.status.in_(_LEASED_STATUSES),
                    RunRecord.lease_expires_at < recovered_at,
                )
                .order_by(RunRecord.lease_expires_at, RunRecord.id)
                .limit(batch_size)
            )
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            runs = tuple(db.scalars(query))
            results: list[RunMutation] = []
            for run in runs:
                if run.status == "cancelling":
                    target = "cancelled"
                elif run.fence_token >= max_fence_token:
                    target = "orphaned"
                else:
                    target = "queued"
                run.status = target
                if target in TERMINAL_RUN_STATUSES:
                    run.terminal_at = recovered_at
                    self._finalize_reservations(db, run, succeeded=False)
                run.version += 1
                previous_fence = run.fence_token
                self._clear_lease(run)
                self._append_event(
                    db,
                    run,
                    event_type=f"run.{target}",
                    payload={
                        "status": target,
                        "reason": "lease_expired",
                        "expired_fence_token": previous_fence,
                    },
                    trace_id="recovery:lease-expired",
                )
                results.append(RunMutation(run.id, run.status, run.version, run.event_sequence))
            return tuple(results)

    def replay_events(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        run_id: UUID,
        after_sequence: int = 0,
        limit: int = 1000,
    ) -> tuple[PersistedRunEvent, ...]:
        """Replay persisted events only; no process-local stream is authoritative."""

        if after_sequence < 0 or not 1 <= limit <= 5000:
            raise ExecutionControlPlaneError("replay_cursor_invalid", "replay cursor is invalid")
        self._authorizer.require(request, action="run.read_metadata", project_id=project_id)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            self._scoped_run(db, request, project_id, run_id, lock=False)
            rows = db.scalars(
                sa.select(RunEventRecord)
                .where(
                    RunEventRecord.run_id == run_id,
                    RunEventRecord.sequence > after_sequence,
                )
                .order_by(RunEventRecord.sequence)
                .limit(limit)
            )
            return tuple(
                PersistedRunEvent(
                    row.id,
                    row.run_id,
                    row.sequence,
                    row.event_type,
                    row.payload,
                    row.trace_id,
                    row.created_at,
                )
                for row in rows
            )

    def task_state(self, request: RequestContext, *, project_id: UUID, task_id: UUID) -> str:
        """Derive Task state from authoritative Runs instead of storing a duplicate field."""

        self._authorizer.require(request, action="run.read_metadata", project_id=project_id)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            self._task(db, request, project_id, task_id, lock=False)
            statuses = tuple(
                db.execute(
                    sa.select(RunRecord.status)
                    .where(RunRecord.task_id == task_id)
                    .order_by(RunRecord.created_at.desc(), RunRecord.id.desc())
                ).scalars()
            )
        if not statuses:
            return "ready"
        active = next((status for status in statuses if status not in TERMINAL_RUN_STATUSES), None)
        if active is not None:
            return active
        return statuses[0]

    def begin_effect(
        self,
        *,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        effect_type: str,
        effect_name: str,
        idempotency_key: str,
        request_payload: dict[str, object],
        unknown_policy: str,
        trace_id: str,
        now: datetime | None = None,
    ) -> EffectCallState:
        """Reserve one side effect key before I/O and replay the existing authority on retry."""

        if effect_type not in EFFECT_TYPES or unknown_policy not in UNKNOWN_EFFECT_POLICIES:
            raise ExecutionControlPlaneError("effect_policy_invalid", "effect policy is invalid")
        name = _validate_text(effect_name, field="effect_name", maximum=256)
        key = _validate_text(idempotency_key, field="idempotency_key", maximum=128)
        trace = _validate_text(trace_id, field="trace_id", maximum=128)
        started_at = now or _utcnow()
        _validate_time(started_at)
        digest = _canonical_hash(
            {"effect_type": effect_type, "effect_name": name, "request": request_payload}
        )
        with self._session_factory.begin() as db:
            run = self._run(db, run_id, lock=True)
            self._require_lease(run, lease_token, fence_token, started_at)
            existing = db.scalar(
                sa.select(EffectCallRecord).where(
                    EffectCallRecord.run_id == run.id,
                    EffectCallRecord.idempotency_key == key,
                )
            )
            if existing is not None:
                if existing.request_hash != digest:
                    raise ExecutionControlPlaneError(
                        "idempotency_conflict", "effect key was used with another request"
                    )
                return self._effect_state(existing, replayed=True)
            effect = EffectCallRecord(
                tenant_id=run.tenant_id,
                space_id=run.space_id,
                project_id=run.project_id,
                run_id=run.id,
                effect_type=effect_type,
                effect_name=name,
                idempotency_key=key,
                request_hash=digest,
                request=request_payload,
                status="pending",
                unknown_policy=unknown_policy,
                version=1,
            )
            db.add(effect)
            db.flush()
            self._append_event(
                db,
                run,
                event_type="run.effect.started",
                payload={
                    "effect_call_id": str(effect.id),
                    "effect_type": effect_type,
                    "effect_name": name,
                    "unknown_policy": unknown_policy,
                },
                trace_id=trace,
            )
            return self._effect_state(effect, replayed=False)

    def resolve_effect(
        self,
        *,
        run_id: UUID,
        effect_call_id: UUID,
        lease_token: UUID,
        fence_token: int,
        status: str,
        response: dict[str, object] | None,
        error_code: str | None,
        trace_id: str,
        now: datetime | None = None,
    ) -> EffectCallState:
        """Persist a definite or explicitly unknown provider result before continuing."""

        if status not in set(EFFECT_STATUSES) - {"pending"}:
            raise ExecutionControlPlaneError("effect_status_invalid", "effect status is invalid")
        trace = _validate_text(trace_id, field="trace_id", maximum=128)
        resolved_at = now or _utcnow()
        _validate_time(resolved_at)
        with self._session_factory.begin() as db:
            run = self._run(db, run_id, lock=True)
            self._require_lease(run, lease_token, fence_token, resolved_at)
            effect = db.scalar(
                sa.select(EffectCallRecord)
                .where(EffectCallRecord.id == effect_call_id, EffectCallRecord.run_id == run_id)
                .with_for_update()
            )
            if effect is None:
                raise ExecutionControlPlaneError("effect_not_found", "effect call was not found")
            if effect.status != "pending":
                if (
                    effect.status == status
                    and effect.response == response
                    and effect.error_code == error_code
                ):
                    return self._effect_state(effect, replayed=True)
                raise ExecutionControlPlaneError(
                    "effect_already_resolved", "effect call already has an authoritative result"
                )
            effect.status = status
            effect.response = response
            effect.error_code = error_code
            effect.version += 1
            self._append_event(
                db,
                run,
                event_type=f"run.effect.{status}",
                payload={
                    "effect_call_id": str(effect.id),
                    "effect_type": effect.effect_type,
                    "effect_name": effect.effect_name,
                    "status": status,
                    "error_code": error_code,
                },
                trace_id=trace,
            )
            return self._effect_state(effect, replayed=False)

    def resolve_unknown_effect(
        self,
        *,
        run_id: UUID,
        effect_call_id: UUID,
        lease_token: UUID,
        fence_token: int,
        resolution: str,
        approval_or_compensation_ref: str,
        trace_id: str,
        now: datetime | None = None,
    ) -> EffectCallState:
        """Require durable approval/compensation evidence before retrying unknown effects."""

        if resolution not in {"retry", "failed"}:
            raise ExecutionControlPlaneError(
                "unknown_resolution_invalid", "unknown resolution is invalid"
            )
        evidence_ref = _validate_text(
            approval_or_compensation_ref, field="resolution_reference", maximum=512
        )
        trace = _validate_text(trace_id, field="trace_id", maximum=128)
        resolved_at = now or _utcnow()
        _validate_time(resolved_at)
        with self._session_factory.begin() as db:
            run = self._run(db, run_id, lock=True)
            self._require_lease(run, lease_token, fence_token, resolved_at)
            effect = db.scalar(
                sa.select(EffectCallRecord)
                .where(EffectCallRecord.id == effect_call_id, EffectCallRecord.run_id == run_id)
                .with_for_update()
            )
            if effect is None or effect.status != "unknown":
                raise ExecutionControlPlaneError(
                    "effect_not_unknown", "effect call is not awaiting unknown-result resolution"
                )
            effect.status = "pending" if resolution == "retry" else "failed"
            effect.response = {
                "unknown_resolution": resolution,
                "evidence_ref": evidence_ref,
            }
            effect.error_code = None if resolution == "retry" else "unknown_result_resolved_failed"
            effect.version += 1
            self._append_event(
                db,
                run,
                event_type=f"run.effect.unknown.{resolution}",
                payload={
                    "effect_call_id": str(effect.id),
                    "resolution": resolution,
                    "evidence_ref": evidence_ref,
                },
                trace_id=trace,
            )
            return self._effect_state(effect, replayed=False)

    def register_artifact(
        self,
        *,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        content_sha256: str,
        size_bytes: int,
        media_type: str,
        object_uri: str,
        source_revision: str,
        metadata: dict[str, object],
        role: str,
        trace_id: str,
        now: datetime | None = None,
    ) -> ArtifactRegistration:
        """Register immutable, content-addressed metadata and its Run link before push."""

        digest = content_sha256.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ExecutionControlPlaneError(
                "artifact_digest_invalid", "artifact digest is invalid"
            )
        if size_bytes < 0:
            raise ExecutionControlPlaneError("artifact_size_invalid", "artifact size is invalid")
        cleaned_media_type = _validate_text(media_type, field="media_type", maximum=256)
        cleaned_uri = _validate_text(object_uri, field="object_uri", maximum=2048)
        cleaned_revision = _validate_text(source_revision, field="source_revision", maximum=64)
        cleaned_role = _validate_text(role, field="artifact_role", maximum=64)
        trace = _validate_text(trace_id, field="trace_id", maximum=128)
        registered_at = now or _utcnow()
        _validate_time(registered_at)
        with self._session_factory.begin() as db:
            run = self._run(db, run_id, lock=True)
            self._require_lease(run, lease_token, fence_token, registered_at)
            artifact = db.scalar(
                sa.select(ArtifactRecord).where(
                    ArtifactRecord.tenant_id == run.tenant_id,
                    ArtifactRecord.space_id == run.space_id,
                    ArtifactRecord.project_id == run.project_id,
                    ArtifactRecord.sha256 == digest,
                )
            )
            replayed = artifact is not None
            if artifact is None:
                artifact = ArtifactRecord(
                    tenant_id=run.tenant_id,
                    space_id=run.space_id,
                    project_id=run.project_id,
                    sha256=digest,
                    size_bytes=size_bytes,
                    media_type=cleaned_media_type,
                    object_uri=cleaned_uri,
                    source_revision=cleaned_revision,
                    created_by=run.created_by,
                    metadata_json=metadata,
                )
                db.add(artifact)
                db.flush()
            elif (
                artifact.size_bytes != size_bytes
                or artifact.media_type != cleaned_media_type
                or artifact.object_uri != cleaned_uri
                or artifact.source_revision != cleaned_revision
                or artifact.metadata_json != metadata
            ):
                raise ExecutionControlPlaneError(
                    "artifact_metadata_conflict",
                    "artifact digest has different immutable metadata",
                )
            link = db.get(RunArtifactRecord, (run.id, artifact.id))
            if link is None:
                db.add(
                    RunArtifactRecord(
                        tenant_id=run.tenant_id,
                        space_id=run.space_id,
                        project_id=run.project_id,
                        run_id=run.id,
                        artifact_id=artifact.id,
                        role=cleaned_role,
                    )
                )
                self._append_event(
                    db,
                    run,
                    event_type="run.artifact.registered",
                    payload={
                        "artifact_id": str(artifact.id),
                        "sha256": digest,
                        "size_bytes": size_bytes,
                        "media_type": cleaned_media_type,
                        "source_revision": cleaned_revision,
                        "role": cleaned_role,
                    },
                    trace_id=trace,
                )
            elif link.role != cleaned_role:
                raise ExecutionControlPlaneError(
                    "artifact_link_conflict", "artifact is already linked with another role"
                )
            return ArtifactRegistration(artifact.id, run.id, digest, replayed and link is not None)

    @staticmethod
    def _apply_request_context(db: Session, request: RequestContext) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
            ),
        )

    @staticmethod
    def _task(
        db: Session,
        request: RequestContext,
        project_id: UUID,
        task_id: UUID,
        *,
        lock: bool,
    ) -> TaskRecord:
        query = sa.select(TaskRecord).where(
            TaskRecord.id == task_id,
            TaskRecord.tenant_id == request.tenant_id,
            TaskRecord.space_id == request.space_id,
            TaskRecord.project_id == project_id,
        )
        if lock:
            query = query.with_for_update()
        task = db.scalar(query)
        if task is None:
            raise ExecutionControlPlaneError("task_not_found", "Task was not found in scope")
        return task

    @staticmethod
    def _session(
        db: Session,
        request: RequestContext,
        project_id: UUID,
        session_id: UUID,
        *,
        lock: bool,
    ) -> ExecutionSessionRecord:
        query = sa.select(ExecutionSessionRecord).where(
            ExecutionSessionRecord.id == session_id,
            ExecutionSessionRecord.tenant_id == request.tenant_id,
            ExecutionSessionRecord.space_id == request.space_id,
            ExecutionSessionRecord.project_id == project_id,
        )
        if lock:
            query = query.with_for_update()
        execution_session = db.scalar(query)
        if execution_session is None:
            raise ExecutionControlPlaneError("session_not_found", "Session was not found in scope")
        return execution_session

    @staticmethod
    def _run(db: Session, run_id: UUID, *, lock: bool) -> RunRecord:
        query = sa.select(RunRecord).where(RunRecord.id == run_id)
        if lock:
            query = query.with_for_update()
        run = db.scalar(query)
        if run is None:
            raise ExecutionControlPlaneError("run_not_found", "Run was not found")
        return run

    @staticmethod
    def _scoped_run(
        db: Session,
        request: RequestContext,
        project_id: UUID,
        run_id: UUID,
        *,
        lock: bool,
    ) -> RunRecord:
        query = sa.select(RunRecord).where(
            RunRecord.id == run_id,
            RunRecord.tenant_id == request.tenant_id,
            RunRecord.space_id == request.space_id,
            RunRecord.project_id == project_id,
        )
        if lock:
            query = query.with_for_update()
        run = db.scalar(query)
        if run is None:
            raise ExecutionControlPlaneError("run_not_found", "Run was not found in scope")
        return run

    @staticmethod
    def _require_lease(
        run: RunRecord, lease_token: UUID, fence_token: int, checked_at: datetime
    ) -> None:
        if run.status not in _LEASED_STATUSES:
            raise ExecutionControlPlaneError("run_not_leased", "Run has no active worker lease")
        if run.lease_token != lease_token or run.fence_token != fence_token:
            raise ExecutionControlPlaneError("stale_fence", "worker lease or fence is stale")
        lease_expires_at = run.lease_expires_at
        if lease_expires_at is not None and lease_expires_at.tzinfo is None:
            lease_expires_at = lease_expires_at.replace(tzinfo=timezone.utc)
        if lease_expires_at is None or lease_expires_at <= checked_at:
            raise ExecutionControlPlaneError("lease_expired", "worker lease has expired")

    @staticmethod
    def _clear_lease(run: RunRecord) -> None:
        run.lease_owner = None
        run.lease_token = None
        run.lease_expires_at = None
        run.heartbeat_at = None

    @staticmethod
    def _append_event(
        db: Session,
        run: RunRecord,
        *,
        event_type: str,
        payload: dict[str, object],
        trace_id: str,
    ) -> RunEventRecord:
        """Persist RunEvent and its push intent in the caller's transaction."""

        run.event_sequence += 1
        event = RunEventRecord(
            tenant_id=run.tenant_id,
            space_id=run.space_id,
            project_id=run.project_id,
            run_id=run.id,
            sequence=run.event_sequence,
            event_type=event_type,
            payload=payload,
            trace_id=trace_id,
        )
        db.add(event)
        db.flush()
        outbox_payload: dict[str, object] = {
            "event_id": str(event.id),
            "run_id": str(run.id),
            "tenant_id": str(run.tenant_id),
            "space_id": str(run.space_id),
            "project_id": str(run.project_id),
            "sequence": event.sequence,
            "event_type": event_type,
            "payload": payload,
            "trace_id": trace_id,
        }
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=run.tenant_id,
                aggregate_type="run",
                aggregate_key=str(run.id),
                event_type="run.event.persisted",
                payload=outbox_payload,
                idempotency_key=f"run-event:{run.id}:{event.sequence}",
                request_hash=_canonical_hash(outbox_payload),
            )
        )
        return event

    @staticmethod
    def _finalize_reservations(db: Session, run: RunRecord, *, succeeded: bool) -> None:
        reservations = tuple(
            db.scalars(
                sa.select(QuotaReservationRecord)
                .where(
                    QuotaReservationRecord.run_id == run.id,
                    QuotaReservationRecord.status == "reserved",
                )
                .with_for_update()
            )
        )
        for reservation in reservations:
            quota = db.scalar(
                sa.select(AdmissionQuotaRecord)
                .where(AdmissionQuotaRecord.id == reservation.quota_id)
                .with_for_update()
            )
            if quota is None or quota.reserved_units < reservation.units:
                raise ExecutionControlPlaneError(
                    "quota_invariant_broken", "quota reservation counters are inconsistent"
                )
            quota.reserved_units -= reservation.units
            if succeeded:
                quota.consumed_units += reservation.units
            quota.version += 1
            reservation.status = "consumed" if succeeded else "released"
            reservation.finalized_at = run.terminal_at
            reservation.version += 1

    @staticmethod
    def _effect_state(effect: EffectCallRecord, *, replayed: bool) -> EffectCallState:
        retry_permitted = effect.status == "pending" or (
            effect.status == "unknown" and effect.unknown_policy == "retry_safe"
        )
        return EffectCallState(
            effect.id,
            effect.status,
            effect.version,
            replayed,
            retry_permitted,
            effect.unknown_policy,
        )
