"""P4 durable Repository, ChangeSet, and fenced Worktree lifecycle authority."""

from __future__ import annotations

import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution_models import TERMINAL_RUN_STATUSES, RunRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scheduling import SchedulingControlPlane, SchedulingError
from saas.control_plane.scheduling_models import (
    CapabilityTokenRecord,
    RunDispatchRecord,
    RunnerRegistrationRecord,
)
from saas.control_plane.worktree_models import (
    ACTIVE_WORKTREE_STATUSES,
    CHANGE_SET_STATUSES,
    ChangeSetGroupRecord,
    ChangeSetRecord,
    RepositoryRecord,
    WorktreeEventRecord,
    WorktreeInstanceRecord,
    WorktreeQuotaRecord,
)

_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_RUN_WORKTREE_STATUSES = frozenset(
    {"leased", "starting", "running", "waiting_input", "waiting_approval", "cancelling"}
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _validate_time(value: datetime) -> None:
    if value.tzinfo is None:
        raise WorktreeControlPlaneError("time_timezone_required", "time must include a timezone")


def _text(value: str, *, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise WorktreeControlPlaneError(f"{field}_invalid", f"{field} is invalid")
    return cleaned


def _opaque_ref(value: str, *, field: str) -> str:
    cleaned = value.strip()
    if not _OPAQUE_REF.fullmatch(cleaned) or ".." in cleaned:
        raise WorktreeControlPlaneError(
            f"{field}_invalid",
            f"{field} must be an opaque control-plane reference, not a path or URL",
        )
    return cleaned


def _token_hash(token: str) -> str:
    return sha256(token.encode()).hexdigest()


def _canonical_hash(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


class WorktreeControlPlaneError(RuntimeError):
    """Stable fail-closed error surface for Worktree lifecycle operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ChangeSetSpec:
    repository_id: UUID
    base_revision: str
    branch_ref: str


@dataclass(frozen=True, slots=True)
class CreatedChangeSetGroup:
    group_id: UUID
    change_set_ids: tuple[UUID, ...]


@dataclass(frozen=True, slots=True)
class WorktreeLease:
    worktree_id: UUID
    change_set_id: UUID
    run_id: UUID
    runner_id: UUID
    opaque_runtime_key: str
    access_mode: str
    lease_generation: int
    run_fence_token: int
    lease_token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class WorktreeMutation:
    worktree_id: UUID
    status: str
    lease_generation: int
    event_sequence: int


@dataclass(frozen=True, slots=True)
class WorktreeMaterializationGrant:
    """Trusted logical checkout inputs resolved from one active fenced lease."""

    worktree_id: UUID
    change_set_id: UUID
    run_id: UUID
    runner_id: UUID
    opaque_runtime_key: str
    access_mode: str
    lease_generation: int
    run_fence_token: int
    runner_connection_generation: int
    reserved_bytes: int
    repository_source_binding_key: str
    base_revision: str
    head_revision: str | None
    branch_ref: str
    recovery_artifact_ref: str | None
    environment_snapshot_ref: str | None


@dataclass(frozen=True, slots=True)
class WorktreeDeletionGrant:
    """Exact GC fence and credential-free Repository binding for physical deletion."""

    worktree_id: UUID
    runner_id: UUID
    opaque_runtime_key: str
    lease_generation: int
    repository_source_binding_key: str


class WorktreeControlPlane:
    """Own Worktree facts while a downstream Runner Adapter owns physical Git I/O."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        authorizer: ProjectAuthorizer | None = None,
        scheduler: SchedulingControlPlane | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._authorizer = authorizer or ProjectAuthorizer(session_factory)
        self._scheduler = scheduler or SchedulingControlPlane(session_factory)

    def register_repository(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        provider: str,
        source_binding_key: str,
        display_name: str,
        default_branch: str,
    ) -> UUID:
        """Register a credential-free provider binding; URLs and host paths are rejected."""

        self._authorizer.require(request, action="project.content.edit", project_id=project_id)
        repository_id = uuid4()
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            db.add(
                RepositoryRecord(
                    id=repository_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    created_by=request.actor_id,
                    provider=_text(provider, field="repository_provider", maximum=64),
                    source_binding_key=_opaque_ref(source_binding_key, field="source_binding_key"),
                    display_name=_text(display_name, field="repository_name", maximum=256),
                    default_branch=_text(default_branch, field="default_branch", maximum=256),
                    status="active",
                    version=1,
                )
            )
        return repository_id

    def create_change_set_group(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        title: str,
        specs: tuple[ChangeSetSpec, ...],
    ) -> CreatedChangeSetGroup:
        """Atomically create one ChangeSet per Repository for multi-repo work."""

        self._authorizer.require(request, action="project.content.edit", project_id=project_id)
        if not specs or len({spec.repository_id for spec in specs}) != len(specs):
            raise WorktreeControlPlaneError(
                "changeset_group_invalid",
                "ChangeSet group repositories must be non-empty and unique",
            )
        group_id = uuid4()
        change_set_ids: list[UUID] = []
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            repositories = tuple(
                db.scalars(
                    sa.select(RepositoryRecord).where(
                        RepositoryRecord.id.in_([spec.repository_id for spec in specs]),
                        RepositoryRecord.tenant_id == request.tenant_id,
                        RepositoryRecord.space_id == request.space_id,
                        RepositoryRecord.project_id == project_id,
                        RepositoryRecord.status == "active",
                    )
                )
            )
            if {record.id for record in repositories} != {spec.repository_id for spec in specs}:
                raise WorktreeControlPlaneError(
                    "repository_unavailable", "A ChangeSet Repository is unavailable"
                )
            db.add(
                ChangeSetGroupRecord(
                    id=group_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    created_by=request.actor_id,
                    title=_text(title, field="changeset_group_title", maximum=256),
                    status="open",
                    version=1,
                )
            )
            db.flush()
            for spec in specs:
                change_set_id = uuid4()
                change_set_ids.append(change_set_id)
                db.add(
                    ChangeSetRecord(
                        id=change_set_id,
                        tenant_id=request.tenant_id,
                        space_id=request.space_id,
                        project_id=project_id,
                        group_id=group_id,
                        repository_id=spec.repository_id,
                        created_by=request.actor_id,
                        base_revision=_text(
                            spec.base_revision, field="base_revision", maximum=128
                        ),
                        branch_ref=_text(spec.branch_ref, field="branch_ref", maximum=256),
                        status="open",
                        version=1,
                    )
                )
            self._append_outbox(
                db,
                tenant_id=request.tenant_id,
                aggregate_type="ChangeSetGroup",
                aggregate_key=str(group_id),
                event_type="changeset.group.created",
                payload={
                    "group_id": str(group_id),
                    "project_id": str(project_id),
                    "change_set_ids": [str(value) for value in change_set_ids],
                    "repository_count": len(change_set_ids),
                },
                idempotency_key=f"changeset-group:{group_id}:created",
            )
        return CreatedChangeSetGroup(group_id, tuple(change_set_ids))

    def configure_quota(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        max_active_instances: int,
        max_active_writers: int,
        max_reserved_bytes: int,
        max_lease_seconds: int,
        max_lifetime_seconds: int,
        gc_grace_seconds: int,
    ) -> UUID:
        """Create or tighten a Project Worktree quota without undercutting live usage."""

        self._authorizer.require(request, action="project.update", project_id=project_id)
        if (
            max_active_instances <= 0
            or max_active_writers <= 0
            or max_active_writers > max_active_instances
            or max_reserved_bytes <= 0
            or max_lease_seconds <= 0
            or max_lifetime_seconds < max_lease_seconds
            or gc_grace_seconds < 0
        ):
            raise WorktreeControlPlaneError("worktree_quota_invalid", "Worktree quota is invalid")
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            quota = db.scalar(
                sa.select(WorktreeQuotaRecord)
                .where(
                    WorktreeQuotaRecord.tenant_id == request.tenant_id,
                    WorktreeQuotaRecord.space_id == request.space_id,
                    WorktreeQuotaRecord.project_id == project_id,
                )
                .with_for_update()
            )
            if quota is None:
                quota = WorktreeQuotaRecord(
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    max_active_instances=max_active_instances,
                    max_active_writers=max_active_writers,
                    max_reserved_bytes=max_reserved_bytes,
                    max_lease_seconds=max_lease_seconds,
                    max_lifetime_seconds=max_lifetime_seconds,
                    gc_grace_seconds=gc_grace_seconds,
                    active_instances=0,
                    active_writers=0,
                    reserved_bytes=0,
                    version=1,
                )
                db.add(quota)
                db.flush()
            else:
                if (
                    quota.active_instances > max_active_instances
                    or quota.active_writers > max_active_writers
                    or quota.reserved_bytes > max_reserved_bytes
                ):
                    raise WorktreeControlPlaneError(
                        "worktree_quota_in_use", "Worktree quota is below active reservations"
                    )
                quota.max_active_instances = max_active_instances
                quota.max_active_writers = max_active_writers
                quota.max_reserved_bytes = max_reserved_bytes
                quota.max_lease_seconds = max_lease_seconds
                quota.max_lifetime_seconds = max_lifetime_seconds
                quota.gc_grace_seconds = gc_grace_seconds
                quota.version += 1
            return quota.id

    def allocate_worktree(
        self,
        *,
        capability_token: str,
        runner_id: UUID,
        run_id: UUID,
        change_set_id: UUID,
        access_mode: str,
        reserved_bytes: int,
        lease_duration: timedelta,
        trace_id: str,
        rebuild_from_id: UUID | None = None,
        now: datetime | None = None,
    ) -> WorktreeLease:
        """Reserve a server-keyed Worktree from a live scoped scheduling capability."""

        allocated_at = now or _utcnow()
        _validate_time(allocated_at)
        if access_mode not in {"writer", "readonly"}:
            raise WorktreeControlPlaneError("worktree_access_invalid", "Access mode is invalid")
        if reserved_bytes <= 0 or lease_duration <= timedelta(0):
            raise WorktreeControlPlaneError(
                "worktree_reservation_invalid", "Worktree reservation is invalid"
            )
        trace = _text(trace_id, field="trace_id", maximum=128)
        action = "worktree.write" if access_mode == "writer" else "worktree.read"
        try:
            capability = self._scheduler.verify_capability(
                capability_token=capability_token,
                runner_id=runner_id,
                run_id=run_id,
                action=action,
                required_resource_scope={"change_set_id": str(change_set_id)},
                now=allocated_at,
            )
        except SchedulingError as exc:
            raise WorktreeControlPlaneError(exc.code, str(exc)) from exc
        raw_token = secrets.token_urlsafe(32)
        worktree_id = uuid4()
        runtime_key = f"wti_{secrets.token_hex(24)}"
        try:
            with self._session_factory.begin() as db:
                self._apply_scope(
                    db,
                    actor_id=None,
                    tenant_id=capability.tenant_id,
                    space_id=capability.space_id,
                )
                change_set = db.scalar(
                    sa.select(ChangeSetRecord)
                    .where(ChangeSetRecord.id == change_set_id)
                    .with_for_update()
                )
                if (
                    change_set is None
                    or change_set.tenant_id != capability.tenant_id
                    or change_set.space_id != capability.space_id
                    or change_set.project_id != capability.project_id
                    or change_set.status not in {"open", "checkpointed"}
                ):
                    raise WorktreeControlPlaneError(
                        "changeset_unavailable", "ChangeSet is unavailable for allocation"
                    )
                run = db.scalar(
                    sa.select(RunRecord).where(RunRecord.id == run_id).with_for_update()
                )
                if (
                    run is None
                    or run.tenant_id != change_set.tenant_id
                    or run.space_id != change_set.space_id
                    or run.project_id != change_set.project_id
                    or run.status not in _RUN_WORKTREE_STATUSES
                    or run.fence_token != capability.fence_token
                ):
                    raise WorktreeControlPlaneError(
                        "worktree_run_stale", "Run is not an active ChangeSet lease authority"
                    )
                capability_record = db.scalar(
                    sa.select(CapabilityTokenRecord)
                    .where(CapabilityTokenRecord.id == capability.capability_id)
                    .with_for_update()
                )
                dispatch = db.get(RunDispatchRecord, run_id)
                if (
                    capability_record is None
                    or not hmac.compare_digest(
                        capability_record.token_hash, _token_hash(capability_token)
                    )
                    or capability_record.revoked_at is not None
                    or _aware(capability_record.expires_at) <= allocated_at
                    or capability_record.run_id != run.id
                    or capability_record.runner_id != runner_id
                    or capability_record.fence_token != run.fence_token
                    or action not in capability_record.allowed_actions
                    or capability_record.resource_scope.get("change_set_id") != str(change_set.id)
                    or dispatch is None
                    or dispatch.status != "leased"
                    or dispatch.selected_runner_id != runner_id
                    or dispatch.dispatch_generation != capability_record.dispatch_generation
                ):
                    raise WorktreeControlPlaneError(
                        "worktree_capability_stale",
                        "Scheduling capability changed before Worktree allocation",
                    )
                runner = db.scalar(
                    sa.select(RunnerRegistrationRecord)
                    .where(RunnerRegistrationRecord.id == runner_id)
                    .with_for_update()
                )
                if runner is None or runner.status not in {"online", "draining"}:
                    raise WorktreeControlPlaneError(
                        "worktree_runner_unavailable", "Runner is unavailable"
                    )
                if runner.connection_generation != capability_record.runner_connection_generation:
                    raise WorktreeControlPlaneError(
                        "worktree_runner_stale", "Runner incarnation changed before allocation"
                    )
                quota = db.scalar(
                    sa.select(WorktreeQuotaRecord)
                    .where(
                        WorktreeQuotaRecord.tenant_id == change_set.tenant_id,
                        WorktreeQuotaRecord.space_id == change_set.space_id,
                        WorktreeQuotaRecord.project_id == change_set.project_id,
                    )
                    .with_for_update()
                )
                if quota is None:
                    raise WorktreeControlPlaneError(
                        "worktree_quota_missing", "Project Worktree quota is not configured"
                    )
                if lease_duration > timedelta(seconds=quota.max_lease_seconds):
                    raise WorktreeControlPlaneError(
                        "worktree_lease_too_long", "Worktree lease exceeds Project policy"
                    )
                expires_at = min(
                    allocated_at + lease_duration,
                    _aware(capability_record.expires_at),
                )
                if expires_at <= allocated_at:
                    raise WorktreeControlPlaneError(
                        "worktree_capability_expired", "Scheduling capability has expired"
                    )
                if quota.active_instances >= quota.max_active_instances:
                    raise WorktreeControlPlaneError(
                        "worktree_instance_quota_exceeded", "Active Worktree quota is exhausted"
                    )
                if access_mode == "writer" and quota.active_writers >= quota.max_active_writers:
                    raise WorktreeControlPlaneError(
                        "worktree_writer_quota_exceeded", "Active writer quota is exhausted"
                    )
                if quota.reserved_bytes + reserved_bytes > quota.max_reserved_bytes:
                    raise WorktreeControlPlaneError(
                        "worktree_storage_quota_exceeded", "Reserved Worktree storage is exhausted"
                    )
                if access_mode == "writer":
                    rebuild_pending = db.scalar(
                        sa.select(WorktreeInstanceRecord.id).where(
                            WorktreeInstanceRecord.change_set_id == change_set_id,
                            WorktreeInstanceRecord.access_mode == "writer",
                            WorktreeInstanceRecord.status == "rebuild_pending",
                        )
                    )
                    if rebuild_pending is not None and rebuild_from_id is None:
                        raise WorktreeControlPlaneError(
                            "worktree_rebuild_source_required",
                            "Checkpointed recovery must be consumed by an explicit rebuild",
                        )
                    active_writer = db.scalar(
                        sa.select(WorktreeInstanceRecord.id).where(
                            WorktreeInstanceRecord.change_set_id == change_set_id,
                            WorktreeInstanceRecord.access_mode == "writer",
                            WorktreeInstanceRecord.status.in_(ACTIVE_WORKTREE_STATUSES),
                        )
                    )
                    if active_writer is not None:
                        raise WorktreeControlPlaneError(
                            "changeset_writer_conflict", "ChangeSet already has an active writer"
                        )
                recovery_ref = (
                    change_set.recovery_artifact_ref
                    if change_set.status == "checkpointed"
                    else None
                )
                environment_ref: str | None = None
                event_type = "worktree.created"
                if rebuild_from_id is not None:
                    source = db.scalar(
                        sa.select(WorktreeInstanceRecord)
                        .where(WorktreeInstanceRecord.id == rebuild_from_id)
                        .with_for_update()
                    )
                    if (
                        source is None
                        or source.change_set_id != change_set_id
                        or source.status != "rebuild_pending"
                        or source.recovery_artifact_ref is None
                    ):
                        raise WorktreeControlPlaneError(
                            "worktree_rebuild_source_invalid", "Rebuild source is unavailable"
                        )
                    recovery_ref = source.recovery_artifact_ref
                    environment_ref = source.environment_snapshot_ref
                    source.status = "released"
                    source.released_at = allocated_at
                    self._append_worktree_event(
                        db,
                        source,
                        event_type="worktree.rebuild.source_consumed",
                        payload={"replacement_worktree_id": str(worktree_id)},
                        trace_id=trace,
                    )
                    event_type = "worktree.rebuilt"
                quota.active_instances += 1
                quota.active_writers += int(access_mode == "writer")
                quota.reserved_bytes += reserved_bytes
                quota.version += 1
                record = WorktreeInstanceRecord(
                    id=worktree_id,
                    tenant_id=change_set.tenant_id,
                    space_id=change_set.space_id,
                    project_id=change_set.project_id,
                    change_set_id=change_set.id,
                    run_id=run.id,
                    runner_id=runner.id,
                    created_by=run.created_by,
                    opaque_runtime_key=runtime_key,
                    access_mode=access_mode,
                    status="reserved",
                    lease_generation=1,
                    run_fence_token=run.fence_token,
                    runner_connection_generation=runner.connection_generation,
                    lease_token_hash=_token_hash(raw_token),
                    lease_expires_at=expires_at,
                    heartbeat_at=allocated_at,
                    maximum_lifetime_at=allocated_at
                    + timedelta(seconds=quota.max_lifetime_seconds),
                    reserved_bytes=reserved_bytes,
                    actual_bytes=0,
                    dirty=False,
                    recovery_artifact_ref=recovery_ref,
                    environment_snapshot_ref=environment_ref,
                    event_sequence=0,
                )
                db.add(record)
                db.flush()
                self._append_worktree_event(
                    db,
                    record,
                    event_type=event_type,
                    payload={
                        "change_set_id": str(change_set.id),
                        "run_id": str(run.id),
                        "runner_id": str(runner.id),
                        "access_mode": access_mode,
                        "lease_generation": 1,
                        "run_fence_token": run.fence_token,
                        "rebuild_from_id": str(rebuild_from_id) if rebuild_from_id else None,
                    },
                    trace_id=trace,
                )
                return WorktreeLease(
                    record.id,
                    record.change_set_id,
                    record.run_id,
                    record.runner_id,
                    record.opaque_runtime_key,
                    record.access_mode,
                    record.lease_generation,
                    record.run_fence_token,
                    raw_token,
                    expires_at,
                )
        except IntegrityError as exc:
            raise WorktreeControlPlaneError(
                "changeset_writer_conflict", "Concurrent ChangeSet writer allocation lost"
            ) from exc

    def begin_materialization(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        trace_id: str,
        now: datetime | None = None,
    ) -> WorktreeMutation:
        """Acknowledge that the adapter is creating the checkout for this exact fence."""

        changed_at = now or _utcnow()
        with self._session_factory.begin() as db:
            record = self._require_active_lease(
                db,
                worktree_id=worktree_id,
                runner_id=runner_id,
                lease_generation=lease_generation,
                run_fence_token=run_fence_token,
                lease_token=lease_token,
                now=changed_at,
            )
            if record.status in {"materializing", "ready"}:
                return self._mutation(record)
            if record.status != "reserved":
                raise WorktreeControlPlaneError(
                    "worktree_transition_invalid", "Worktree is not reserved"
                )
            record.status = "materializing"
            self._append_worktree_event(
                db,
                record,
                event_type="worktree.materializing",
                payload={"lease_generation": record.lease_generation},
                trace_id=_text(trace_id, field="trace_id", maximum=128),
            )
            return self._mutation(record)

    def acknowledge_ready(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        actual_bytes: int,
        trace_id: str,
        now: datetime | None = None,
    ) -> WorktreeMutation:
        """Record a mounted checkout without accepting any Runner-supplied host path."""

        changed_at = now or _utcnow()
        if actual_bytes < 0:
            raise WorktreeControlPlaneError("worktree_size_invalid", "Worktree size is invalid")
        with self._session_factory.begin() as db:
            record = self._require_active_lease(
                db,
                worktree_id=worktree_id,
                runner_id=runner_id,
                lease_generation=lease_generation,
                run_fence_token=run_fence_token,
                lease_token=lease_token,
                now=changed_at,
            )
            if record.status == "ready":
                return self._mutation(record)
            if record.status not in {"materializing", "ready"}:
                raise WorktreeControlPlaneError(
                    "worktree_transition_invalid", "Worktree is not materializing"
                )
            if actual_bytes > record.reserved_bytes:
                raise WorktreeControlPlaneError(
                    "worktree_reservation_exceeded", "Worktree exceeds its storage reservation"
                )
            record.status = "ready"
            record.actual_bytes = actual_bytes
            record.heartbeat_at = changed_at
            self._append_worktree_event(
                db,
                record,
                event_type="worktree.mounted",
                payload={"actual_bytes": actual_bytes},
                trace_id=_text(trace_id, field="trace_id", maximum=128),
            )
            return self._mutation(record)

    def materialization_grant(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        now: datetime | None = None,
    ) -> WorktreeMaterializationGrant:
        """Resolve credential-free Git inputs only after materialization is fenced."""

        resolved_at = now or _utcnow()
        with self._session_factory.begin() as db:
            record = self._require_active_lease(
                db,
                worktree_id=worktree_id,
                runner_id=runner_id,
                lease_generation=lease_generation,
                run_fence_token=run_fence_token,
                lease_token=lease_token,
                now=resolved_at,
            )
            if record.status not in {"materializing", "ready"}:
                raise WorktreeControlPlaneError(
                    "worktree_materialization_not_started",
                    "Worktree materialization must be fenced before resolving Git inputs",
                )
            change_set = db.get(ChangeSetRecord, record.change_set_id)
            repository = (
                db.get(RepositoryRecord, change_set.repository_id)
                if change_set is not None
                else None
            )
            if (
                change_set is None
                or repository is None
                or change_set.tenant_id != record.tenant_id
                or change_set.space_id != record.space_id
                or change_set.project_id != record.project_id
                or repository.tenant_id != record.tenant_id
                or repository.space_id != record.space_id
                or repository.project_id != record.project_id
            ):
                raise WorktreeControlPlaneError(
                    "worktree_materialization_scope_invalid",
                    "Worktree Repository or ChangeSet scope is invalid",
                )
            return WorktreeMaterializationGrant(
                worktree_id=record.id,
                change_set_id=record.change_set_id,
                run_id=record.run_id,
                runner_id=record.runner_id,
                opaque_runtime_key=record.opaque_runtime_key,
                access_mode=record.access_mode,
                lease_generation=record.lease_generation,
                run_fence_token=record.run_fence_token,
                runner_connection_generation=record.runner_connection_generation,
                reserved_bytes=record.reserved_bytes,
                repository_source_binding_key=repository.source_binding_key,
                base_revision=change_set.base_revision,
                head_revision=change_set.head_revision,
                branch_ref=change_set.branch_ref,
                recovery_artifact_ref=record.recovery_artifact_ref,
                environment_snapshot_ref=record.environment_snapshot_ref,
            )

    def heartbeat(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        actual_bytes: int,
        dirty: bool,
        now: datetime | None = None,
    ) -> WorktreeMutation:
        """Refresh liveness and usage for a ready checkout; readonly instances stay clean."""

        heartbeat_at = now or _utcnow()
        if actual_bytes < 0:
            raise WorktreeControlPlaneError("worktree_size_invalid", "Worktree size is invalid")
        with self._session_factory.begin() as db:
            record = self._require_active_lease(
                db,
                worktree_id=worktree_id,
                runner_id=runner_id,
                lease_generation=lease_generation,
                run_fence_token=run_fence_token,
                lease_token=lease_token,
                now=heartbeat_at,
            )
            if record.status != "ready":
                raise WorktreeControlPlaneError("worktree_not_ready", "Worktree is not ready")
            if dirty and record.access_mode != "writer":
                raise WorktreeControlPlaneError(
                    "worktree_readonly_write_denied", "Readonly Worktree cannot become dirty"
                )
            if actual_bytes > record.reserved_bytes:
                raise WorktreeControlPlaneError(
                    "worktree_reservation_exceeded", "Worktree exceeds its storage reservation"
                )
            record.actual_bytes = actual_bytes
            record.dirty = dirty
            record.heartbeat_at = heartbeat_at
            return self._mutation(record)

    def checkpoint(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        head_revision: str,
        recovery_artifact_ref: str,
        environment_snapshot_ref: str,
        dirty_after: bool,
        trace_id: str,
        now: datetime | None = None,
    ) -> WorktreeMutation:
        """Persist recovery material before a dirty writer may be released or rebuilt."""

        checkpointed_at = now or _utcnow()
        head = _text(head_revision, field="head_revision", maximum=128)
        recovery = _opaque_ref(recovery_artifact_ref, field="recovery_artifact_ref")
        environment = _opaque_ref(environment_snapshot_ref, field="environment_snapshot_ref")
        with self._session_factory.begin() as db:
            record = self._require_active_lease(
                db,
                worktree_id=worktree_id,
                runner_id=runner_id,
                lease_generation=lease_generation,
                run_fence_token=run_fence_token,
                lease_token=lease_token,
                now=checkpointed_at,
            )
            if record.status != "ready" or record.access_mode != "writer":
                raise WorktreeControlPlaneError(
                    "worktree_checkpoint_denied", "Only a ready writer can checkpoint"
                )
            change_set = db.scalar(
                sa.select(ChangeSetRecord)
                .where(ChangeSetRecord.id == record.change_set_id)
                .with_for_update()
            )
            if change_set is None or change_set.status not in {"open", "checkpointed"}:
                raise WorktreeControlPlaneError(
                    "changeset_unavailable", "ChangeSet is unavailable for checkpoint"
                )
            if (
                change_set.head_revision == head
                and change_set.recovery_artifact_ref == recovery
                and change_set.status == "checkpointed"
                and record.recovery_artifact_ref == recovery
                and record.environment_snapshot_ref == environment
                and record.dirty == dirty_after
            ):
                record.heartbeat_at = checkpointed_at
                return self._mutation(record)
            change_set.head_revision = head
            change_set.recovery_artifact_ref = recovery
            change_set.status = "checkpointed"
            change_set.version += 1
            record.recovery_artifact_ref = recovery
            record.environment_snapshot_ref = environment
            record.dirty = dirty_after
            record.heartbeat_at = checkpointed_at
            self._append_worktree_event(
                db,
                record,
                event_type="worktree.checkpointed",
                payload={
                    "head_revision": head,
                    "recovery_artifact_ref": recovery,
                    "environment_snapshot_ref": environment,
                    "dirty_after": dirty_after,
                },
                trace_id=_text(trace_id, field="trace_id", maximum=128),
            )
            return self._mutation(record)

    def release(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        final_change_set_status: str | None,
        trace_id: str,
        now: datetime | None = None,
    ) -> WorktreeMutation:
        """Release after terminal completion or requeue; dirty state requires a checkpoint."""

        released_at = now or _utcnow()
        if final_change_set_status is not None and final_change_set_status not in {
            "checkpointed",
            "committed",
            "abandoned",
        }:
            raise WorktreeControlPlaneError(
                "changeset_status_invalid", "Final ChangeSet status is invalid"
            )
        with self._session_factory.begin() as db:
            record = self._require_active_lease(
                db,
                worktree_id=worktree_id,
                runner_id=runner_id,
                lease_generation=lease_generation,
                run_fence_token=run_fence_token,
                lease_token=lease_token,
                now=released_at,
                require_run_active=False,
            )
            run = db.get(RunRecord, record.run_id)
            if run is None or run.status not in TERMINAL_RUN_STATUSES | {"queued"}:
                raise WorktreeControlPlaneError(
                    "worktree_release_invalid", "Run must be terminal or recovered to queued"
                )
            if record.dirty and record.recovery_artifact_ref is None:
                raise WorktreeControlPlaneError(
                    "worktree_checkpoint_required", "Dirty Worktree must checkpoint before release"
                )
            if final_change_set_status is not None and run.status not in TERMINAL_RUN_STATUSES:
                raise WorktreeControlPlaneError(
                    "changeset_finalization_invalid", "Only a terminal Run can finalize ChangeSet"
                )
            if final_change_set_status is not None:
                change_set = db.scalar(
                    sa.select(ChangeSetRecord)
                    .where(ChangeSetRecord.id == record.change_set_id)
                    .with_for_update()
                )
                if change_set is None:
                    raise WorktreeControlPlaneError(
                        "changeset_unavailable", "ChangeSet is unavailable"
                    )
                change_set.status = final_change_set_status
                change_set.version += 1
                self._refresh_group_status(db, change_set.group_id)
            self._release_quota(db, record)
            record.status = "released"
            record.released_at = released_at
            record.lease_generation += 1
            record.lease_token_hash = None
            record.lease_expires_at = None
            self._append_worktree_event(
                db,
                record,
                event_type="worktree.released",
                payload={
                    "run_status": run.status,
                    "dirty": record.dirty,
                    "checkpointed": record.recovery_artifact_ref is not None,
                    "final_change_set_status": final_change_set_status,
                },
                trace_id=_text(trace_id, field="trace_id", maximum=128),
            )
            return self._mutation(record)

    def expire_stale_leases(
        self,
        *,
        now: datetime | None = None,
        limit: int = 100,
    ) -> tuple[WorktreeMutation, ...]:
        """Fence expired instances into released, rebuild-pending, or quarantine states."""

        expired_at = now or _utcnow()
        _validate_time(expired_at)
        if not 1 <= limit <= 1000:
            raise WorktreeControlPlaneError("worktree_sweep_invalid", "Sweep limit is invalid")
        with self._session_factory.begin() as db:
            query = (
                sa.select(WorktreeInstanceRecord)
                .where(
                    WorktreeInstanceRecord.status.in_(ACTIVE_WORKTREE_STATUSES),
                    sa.or_(
                        WorktreeInstanceRecord.lease_expires_at <= expired_at,
                        WorktreeInstanceRecord.maximum_lifetime_at <= expired_at,
                    ),
                )
                .order_by(WorktreeInstanceRecord.lease_expires_at, WorktreeInstanceRecord.id)
                .limit(limit)
            )
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            records = tuple(db.scalars(query))
            results: list[WorktreeMutation] = []
            for record in records:
                self._apply_scope(
                    db,
                    actor_id=None,
                    tenant_id=record.tenant_id,
                    space_id=record.space_id,
                )
                self._release_quota(db, record)
                if record.dirty and record.recovery_artifact_ref is not None:
                    record.status = "rebuild_pending"
                    event_type = "worktree.rebuild_pending"
                elif record.dirty:
                    record.status = "quarantined"
                    record.quarantine_reason = "expired_without_recovery_artifact"
                    self._quarantine_change_set(db, record.change_set_id)
                    event_type = "worktree.quarantined"
                else:
                    record.status = "released"
                    record.released_at = expired_at
                    event_type = "worktree.released"
                record.lease_generation += 1
                record.lease_token_hash = None
                record.lease_expires_at = None
                self._append_worktree_event(
                    db,
                    record,
                    event_type=event_type,
                    payload={
                        "reason": "lease_or_lifetime_expired",
                        "dirty": record.dirty,
                        "recovery_available": record.recovery_artifact_ref is not None,
                    },
                    trace_id="recovery:worktree-expired",
                )
                results.append(self._mutation(record))
            return tuple(results)

    def mark_gc_eligible(
        self,
        *,
        now: datetime | None = None,
        limit: int = 100,
    ) -> tuple[WorktreeMutation, ...]:
        """Mark safely released instances after their Project grace period; no physical I/O."""

        checked_at = now or _utcnow()
        _validate_time(checked_at)
        if not 1 <= limit <= 1000:
            raise WorktreeControlPlaneError("worktree_gc_invalid", "GC limit is invalid")
        with self._session_factory.begin() as db:
            query = (
                sa.select(WorktreeInstanceRecord, WorktreeQuotaRecord.gc_grace_seconds)
                .join(
                    WorktreeQuotaRecord,
                    sa.and_(
                        WorktreeQuotaRecord.tenant_id == WorktreeInstanceRecord.tenant_id,
                        WorktreeQuotaRecord.space_id == WorktreeInstanceRecord.space_id,
                        WorktreeQuotaRecord.project_id == WorktreeInstanceRecord.project_id,
                    ),
                )
                .where(
                    WorktreeInstanceRecord.status == "released",
                    WorktreeInstanceRecord.released_at.is_not(None),
                )
                .order_by(WorktreeInstanceRecord.released_at, WorktreeInstanceRecord.id)
                .limit(limit)
            )
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                query = query.with_for_update(
                    of=WorktreeInstanceRecord,
                    skip_locked=True,
                )
            rows = tuple(db.execute(query))
            results: list[WorktreeMutation] = []
            for record, grace_seconds in rows:
                released_at = record.released_at
                if (
                    released_at is None
                    or _aware(released_at) + timedelta(seconds=grace_seconds) > checked_at
                ):
                    continue
                if record.dirty and record.recovery_artifact_ref is None:
                    record.status = "quarantined"
                    record.quarantine_reason = "gc_dirty_without_recovery_artifact"
                    self._quarantine_change_set(db, record.change_set_id)
                    event_type = "worktree.quarantined"
                else:
                    record.status = "gc_eligible"
                    event_type = "worktree.gc_eligible"
                self._apply_scope(
                    db,
                    actor_id=None,
                    tenant_id=record.tenant_id,
                    space_id=record.space_id,
                )
                self._append_worktree_event(
                    db,
                    record,
                    event_type=event_type,
                    payload={"released_at": _aware(released_at).isoformat()},
                    trace_id="gc:worktree-eligible",
                )
                results.append(self._mutation(record))
            return tuple(results)

    def confirm_deleted(
        self,
        *,
        worktree_id: UUID,
        expected_lease_generation: int,
        opaque_runtime_key: str,
        trace_id: str,
        now: datetime | None = None,
    ) -> WorktreeMutation:
        """Persist adapter-confirmed deletion for one exact opaque key and fenced generation."""

        deleted_at = now or _utcnow()
        _validate_time(deleted_at)
        with self._session_factory.begin() as db:
            record = db.scalar(
                sa.select(WorktreeInstanceRecord)
                .where(WorktreeInstanceRecord.id == worktree_id)
                .with_for_update()
            )
            if (
                record is None
                or record.status not in {"gc_eligible", "deleted"}
                or record.lease_generation != expected_lease_generation
                or not hmac.compare_digest(record.opaque_runtime_key, opaque_runtime_key)
            ):
                raise WorktreeControlPlaneError(
                    "worktree_delete_fence_stale", "Worktree delete confirmation is stale"
                )
            if record.status == "deleted":
                return self._mutation(record)
            self._apply_scope(
                db,
                actor_id=None,
                tenant_id=record.tenant_id,
                space_id=record.space_id,
            )
            record.status = "deleted"
            record.deleted_at = deleted_at
            self._append_worktree_event(
                db,
                record,
                event_type="worktree.deleted",
                payload={"lease_generation": expected_lease_generation},
                trace_id=_text(trace_id, field="trace_id", maximum=128),
            )
            return self._mutation(record)

    def deletion_grant(
        self,
        *,
        worktree_id: UUID,
        expected_lease_generation: int,
        opaque_runtime_key: str,
    ) -> WorktreeDeletionGrant:
        """Validate an exact GC candidate before the Runner performs physical deletion."""

        with self._session_factory.begin() as db:
            record = db.scalar(
                sa.select(WorktreeInstanceRecord)
                .where(WorktreeInstanceRecord.id == worktree_id)
                .with_for_update()
            )
            if (
                record is None
                or record.status not in {"gc_eligible", "deleted"}
                or record.lease_generation != expected_lease_generation
                or not hmac.compare_digest(record.opaque_runtime_key, opaque_runtime_key)
            ):
                raise WorktreeControlPlaneError(
                    "worktree_delete_fence_stale", "Worktree delete grant is stale"
                )
            change_set = db.get(ChangeSetRecord, record.change_set_id)
            repository = (
                db.get(RepositoryRecord, change_set.repository_id)
                if change_set is not None
                else None
            )
            if (
                change_set is None
                or repository is None
                or change_set.tenant_id != record.tenant_id
                or change_set.space_id != record.space_id
                or change_set.project_id != record.project_id
                or repository.tenant_id != record.tenant_id
                or repository.space_id != record.space_id
                or repository.project_id != record.project_id
            ):
                raise WorktreeControlPlaneError(
                    "worktree_delete_scope_invalid",
                    "Worktree Repository scope is invalid for deletion",
                )
            return WorktreeDeletionGrant(
                worktree_id=record.id,
                runner_id=record.runner_id,
                opaque_runtime_key=record.opaque_runtime_key,
                lease_generation=record.lease_generation,
                repository_source_binding_key=repository.source_binding_key,
            )

    def replay_events(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        worktree_id: UUID,
        after_sequence: int = 0,
        limit: int = 1000,
    ) -> tuple[WorktreeEventRecord, ...]:
        """Replay persisted lifecycle events in strict per-Worktree order."""

        if after_sequence < 0 or not 1 <= limit <= 5000:
            raise WorktreeControlPlaneError("worktree_replay_invalid", "Replay cursor is invalid")
        self._authorizer.require(request, action="run.read_metadata", project_id=project_id)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            exists = db.scalar(
                sa.select(WorktreeInstanceRecord.id).where(
                    WorktreeInstanceRecord.id == worktree_id,
                    WorktreeInstanceRecord.tenant_id == request.tenant_id,
                    WorktreeInstanceRecord.space_id == request.space_id,
                    WorktreeInstanceRecord.project_id == project_id,
                )
            )
            if exists is None:
                raise WorktreeControlPlaneError("worktree_not_found", "Worktree is not accessible")
            return tuple(
                db.scalars(
                    sa.select(WorktreeEventRecord)
                    .where(
                        WorktreeEventRecord.worktree_id == worktree_id,
                        WorktreeEventRecord.sequence > after_sequence,
                    )
                    .order_by(WorktreeEventRecord.sequence)
                    .limit(limit)
                )
            )

    def _require_active_lease(
        self,
        db: Session,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        now: datetime,
        require_run_active: bool = True,
    ) -> WorktreeInstanceRecord:
        _validate_time(now)
        record = db.scalar(
            sa.select(WorktreeInstanceRecord)
            .where(WorktreeInstanceRecord.id == worktree_id)
            .with_for_update()
        )
        if record is None:
            raise WorktreeControlPlaneError("worktree_not_found", "Worktree is not accessible")
        self._apply_scope(
            db,
            actor_id=None,
            tenant_id=record.tenant_id,
            space_id=record.space_id,
        )
        digest = _token_hash(_text(lease_token, field="worktree_lease_token", maximum=512))
        if (
            record.status not in ACTIVE_WORKTREE_STATUSES
            or record.runner_id != runner_id
            or record.lease_generation != lease_generation
            or record.run_fence_token != run_fence_token
            or record.lease_token_hash is None
            or not hmac.compare_digest(record.lease_token_hash, digest)
            or record.lease_expires_at is None
            or _aware(record.lease_expires_at) <= now
            or _aware(record.maximum_lifetime_at) <= now
        ):
            raise WorktreeControlPlaneError("worktree_lease_stale", "Worktree lease is stale")
        run = db.get(RunRecord, record.run_id)
        runner = db.get(RunnerRegistrationRecord, record.runner_id)
        if (
            run is None
            or run.fence_token != record.run_fence_token
            or (require_run_active and run.status not in _RUN_WORKTREE_STATUSES)
            or runner is None
            or runner.connection_generation != record.runner_connection_generation
            or runner.status not in {"online", "draining"}
        ):
            raise WorktreeControlPlaneError(
                "worktree_authority_stale", "Run or Runner authority is stale"
            )
        return record

    @staticmethod
    def _release_quota(db: Session, record: WorktreeInstanceRecord) -> None:
        quota = db.scalar(
            sa.select(WorktreeQuotaRecord)
            .where(
                WorktreeQuotaRecord.tenant_id == record.tenant_id,
                WorktreeQuotaRecord.space_id == record.space_id,
                WorktreeQuotaRecord.project_id == record.project_id,
            )
            .with_for_update()
        )
        if (
            quota is None
            or quota.active_instances <= 0
            or quota.reserved_bytes < record.reserved_bytes
            or (record.access_mode == "writer" and quota.active_writers <= 0)
        ):
            raise WorktreeControlPlaneError(
                "worktree_quota_inconsistent", "Worktree quota counters are inconsistent"
            )
        quota.active_instances -= 1
        quota.active_writers -= int(record.access_mode == "writer")
        quota.reserved_bytes -= record.reserved_bytes
        quota.version += 1

    @staticmethod
    def _quarantine_change_set(db: Session, change_set_id: UUID) -> None:
        change_set = db.scalar(
            sa.select(ChangeSetRecord).where(ChangeSetRecord.id == change_set_id).with_for_update()
        )
        if change_set is not None and change_set.status != "quarantined":
            change_set.status = "quarantined"
            change_set.version += 1

    @staticmethod
    def _refresh_group_status(db: Session, group_id: UUID) -> None:
        group = db.scalar(
            sa.select(ChangeSetGroupRecord)
            .where(ChangeSetGroupRecord.id == group_id)
            .with_for_update()
        )
        if group is None:
            raise WorktreeControlPlaneError(
                "changeset_group_unavailable", "ChangeSet group is unavailable"
            )
        statuses = frozenset(
            db.scalars(
                sa.select(ChangeSetRecord.status).where(ChangeSetRecord.group_id == group_id)
            )
        )
        if statuses and statuses <= {"committed"}:
            target = "completed"
        elif statuses and statuses <= {"committed", "abandoned"}:
            target = "abandoned"
        else:
            target = "open"
        if group.status != target:
            group.status = target
            group.version += 1

    @classmethod
    def _append_worktree_event(
        cls,
        db: Session,
        record: WorktreeInstanceRecord,
        *,
        event_type: str,
        payload: dict[str, object],
        trace_id: str,
    ) -> None:
        record.event_sequence += 1
        event = WorktreeEventRecord(
            tenant_id=record.tenant_id,
            space_id=record.space_id,
            project_id=record.project_id,
            worktree_id=record.id,
            sequence=record.event_sequence,
            event_type=event_type,
            payload=payload,
            trace_id=trace_id,
        )
        db.add(event)
        cls._append_outbox(
            db,
            tenant_id=record.tenant_id,
            aggregate_type="WorktreeInstance",
            aggregate_key=str(record.id),
            event_type=event_type,
            payload={
                "worktree_id": str(record.id),
                "sequence": record.event_sequence,
                "status": record.status,
                **payload,
            },
            idempotency_key=f"worktree:{record.id}:{record.event_sequence}",
        )

    @staticmethod
    def _append_outbox(
        db: Session,
        *,
        tenant_id: UUID,
        aggregate_type: str,
        aggregate_key: str,
        event_type: str,
        payload: dict[str, object],
        idempotency_key: str,
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=tenant_id,
                aggregate_type=aggregate_type,
                aggregate_key=aggregate_key,
                event_type=event_type,
                payload=payload,
                idempotency_key=idempotency_key,
                request_hash=_canonical_hash(payload),
                attempt_count=0,
                available_at=_utcnow(),
            )
        )

    @staticmethod
    def _apply_request_context(db: Session, request: RequestContext) -> None:
        WorktreeControlPlane._apply_scope(
            db,
            actor_id=request.actor_id,
            tenant_id=request.tenant_id,
            space_id=request.space_id,
        )

    @staticmethod
    def _apply_scope(
        db: Session,
        *,
        actor_id: UUID | None,
        tenant_id: UUID,
        space_id: UUID,
    ) -> None:
        apply_rls_context(
            db,
            RlsContext(actor_id=actor_id, tenant_id=tenant_id, space_id=space_id),
        )

    @staticmethod
    def _mutation(record: WorktreeInstanceRecord) -> WorktreeMutation:
        return WorktreeMutation(
            record.id, record.status, record.lease_generation, record.event_sequence
        )


def validate_change_set_status(value: str) -> str:
    """Validate public/admin status inputs against the durable model contract."""

    if value not in CHANGE_SET_STATUSES:
        raise WorktreeControlPlaneError("changeset_status_invalid", "ChangeSet status is invalid")
    return value
