"""Transactional projection from authoritative ``run.queued`` events to dispatches."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import NoReturn, cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.dispatch_binding import dispatch_requirements_hash
from saas.control_plane.execution_models import TERMINAL_RUN_STATUSES, RunEventRecord, RunRecord
from saas.control_plane.isolation_models import EgressPolicyRecord, ExecutionProfileRecord
from saas.control_plane.outbox import OutboxPublishError
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scheduling_models import (
    RunDispatchRecord,
    RunnerPoolRecord,
    TenantQueueShareRecord,
)

_OUTBOX_KEYS = frozenset(
    {
        "event_id",
        "run_id",
        "tenant_id",
        "space_id",
        "project_id",
        "sequence",
        "event_type",
        "payload",
        "trace_id",
    }
)
_QUEUED_KEYS = frozenset({"status", "queue_class", "priority"})
_REQUIRED_CAPABILITIES = frozenset(
    {
        "sandbox.readonly_root",
        "sandbox.nonroot",
        "sandbox.no_new_privileges",
        "sandbox.no_host_socket",
        "sandbox.resource_limits",
        "egress.proxy",
        "secret.broker",
    }
)


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _reject(code: str, *, retryable: bool = False) -> NoReturn:
    raise OutboxPublishError(code, retryable=retryable, pre_side_effect=True)


def _uuid(value: object, *, code: str) -> UUID:
    if not isinstance(value, str):
        _reject(code)
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        _reject(code)
    if str(parsed) != value:
        _reject(code)
    return parsed


def _nonempty_text(value: object, *, maximum: int, code: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        _reject(code)
    if len(value) > maximum:
        _reject(code)
    return value


@dataclass(frozen=True, slots=True)
class RunQueuedEvent:
    event_id: UUID
    run_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    sequence: int
    queue_class: str
    priority: int
    queued_payload: dict[str, object]
    trace_id: str


@dataclass(frozen=True, slots=True)
class RunDispatchProjectionResult:
    run_id: UUID
    pool_id: UUID | None
    execution_profile_id: UUID | None
    projected: bool
    replayed: bool
    stale: bool


class RunQueuedDispatchProjection:
    """Idempotently create scheduling requirements from a persisted queue event.

    The projector accepts no caller-selected pool, Placement, or sandbox profile.
    It resolves each fact from active server-owned rows while holding the Run lock,
    and the dispatch row is committed in that same database transaction.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        maximum_wait: timedelta = timedelta(hours=1),
        cost_units: int = 1,
    ) -> None:
        if not timedelta(0) < maximum_wait <= timedelta(hours=24):
            raise ValueError("maximum_wait must be positive and no greater than 24 hours")
        if not 1 <= cost_units <= 1_000_000:
            raise ValueError("cost_units must be between 1 and 1000000")
        self._session_factory = session_factory
        self._maximum_wait = maximum_wait
        self._cost_units = cost_units

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        """Implement the Outbox publisher protocol for a queue-event route."""

        self.project(
            event_id=event_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_key=aggregate_key,
            payload=payload,
        )

    def project(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> RunDispatchProjectionResult:
        """Validate event provenance and atomically materialize one dispatch row."""

        event = self._parse(
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_key=aggregate_key,
            payload=payload,
        )
        with self._session_factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(
                    tenant_id=event.tenant_id,
                    space_id=event.space_id,
                    project_id=event.project_id,
                ),
            )
            self._require_outbox_authority(
                db,
                outbox_event_id=event_id,
                aggregate_key=aggregate_key,
                payload=payload,
                event=event,
            )
            run_event = self._require_run_event(db, event)
            run = db.scalar(
                sa.select(RunRecord).where(RunRecord.id == event.run_id).with_for_update()
            )
            if run is None:
                _reject("run_dispatch_run_missing")
            self._require_run_scope(run, event)

            existing = db.get(RunDispatchRecord, run.id)
            if existing is not None:
                self._require_replay_integrity(db, existing, run, run_event)
                return RunDispatchProjectionResult(
                    run.id,
                    existing.pool_id,
                    existing.execution_profile_id,
                    projected=False,
                    replayed=True,
                    stale=False,
                )

            # A cancellation may legitimately overtake an at-least-once queue
            # delivery. Never resurrect it and never fabricate a dispatch row.
            if run.status in TERMINAL_RUN_STATUSES:
                return RunDispatchProjectionResult(
                    run.id,
                    None,
                    None,
                    projected=False,
                    replayed=False,
                    stale=True,
                )
            if run.status != "queued":
                _reject("run_dispatch_run_not_queued")

            placement, partition = self._resolve_runtime(db, run)
            profile, egress_policy = self._resolve_profile_binding(db, run)
            pool = self._resolve_pool(db, run, placement, partition)
            capabilities = tuple(
                sorted(
                    {
                        *_REQUIRED_CAPABILITIES,
                        f"sandbox.{profile.sandbox_backend}",
                        f"syscall.{profile.syscall_profile_ref}",
                    }
                )
            )
            ready_at = _aware(run_event.created_at)
            max_wait_at = ready_at + self._maximum_wait
            request_hash = dispatch_requirements_hash(
                tenant_id=run.tenant_id,
                space_id=run.space_id,
                project_id=run.project_id,
                pool_id=pool.id,
                execution_profile_id=profile.id,
                execution_profile_hash=profile.config_hash,
                egress_policy_id=egress_policy.id,
                egress_policy_hash=egress_policy.rules_hash,
                queue_class=run.queue_class,
                required_capabilities=list(capabilities),
                cost_units=self._cost_units,
                eligible_at=ready_at,
                max_wait_at=max_wait_at,
            )
            db.add(
                RunDispatchRecord(
                    run_id=run.id,
                    tenant_id=run.tenant_id,
                    space_id=run.space_id,
                    project_id=run.project_id,
                    pool_id=pool.id,
                    execution_profile_id=profile.id,
                    execution_profile_hash=profile.config_hash,
                    egress_policy_id=egress_policy.id,
                    egress_policy_hash=egress_policy.rules_hash,
                    queue_class=run.queue_class,
                    required_capabilities=list(capabilities),
                    requirements_hash=request_hash,
                    cost_units=self._cost_units,
                    eligible_at=ready_at,
                    max_wait_at=max_wait_at,
                    status="pending",
                    dispatch_generation=0,
                )
            )
            db.flush()
            return RunDispatchProjectionResult(
                run.id,
                pool.id,
                profile.id,
                projected=True,
                replayed=False,
                stale=False,
            )

    @staticmethod
    def _parse(
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> RunQueuedEvent:
        if event_type != "run.event.persisted" or aggregate_type != "run":
            _reject("run_dispatch_envelope_unsupported")
        if not isinstance(payload, dict) or set(payload) != _OUTBOX_KEYS:
            _reject("run_dispatch_payload_malformed")

        run_id = _uuid(payload.get("run_id"), code="run_dispatch_payload_malformed")
        if aggregate_key != str(run_id):
            _reject("run_dispatch_aggregate_mismatch")
        nested_event_type = payload.get("event_type")
        if nested_event_type != "run.queued":
            _reject("run_dispatch_event_unsupported")
        queued_payload = payload.get("payload")
        if not isinstance(queued_payload, dict) or set(queued_payload) != _QUEUED_KEYS:
            _reject("run_dispatch_queue_payload_malformed")
        if queued_payload.get("status") != "queued":
            _reject("run_dispatch_queue_payload_malformed")
        queue_class = _nonempty_text(
            queued_payload.get("queue_class"),
            maximum=64,
            code="run_dispatch_queue_payload_malformed",
        )
        priority = queued_payload.get("priority")
        sequence = payload.get("sequence")
        if isinstance(priority, bool) or not isinstance(priority, int):
            _reject("run_dispatch_queue_payload_malformed")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            _reject("run_dispatch_payload_malformed")
        return RunQueuedEvent(
            event_id=_uuid(payload.get("event_id"), code="run_dispatch_payload_malformed"),
            run_id=run_id,
            tenant_id=_uuid(payload.get("tenant_id"), code="run_dispatch_payload_malformed"),
            space_id=_uuid(payload.get("space_id"), code="run_dispatch_payload_malformed"),
            project_id=_uuid(payload.get("project_id"), code="run_dispatch_payload_malformed"),
            sequence=sequence,
            queue_class=queue_class,
            priority=priority,
            queued_payload=cast(dict[str, object], queued_payload),
            trace_id=_nonempty_text(
                payload.get("trace_id"), maximum=128, code="run_dispatch_payload_malformed"
            ),
        )

    @staticmethod
    def _require_outbox_authority(
        db: Session,
        *,
        outbox_event_id: UUID,
        aggregate_key: str,
        payload: dict[str, object],
        event: RunQueuedEvent,
    ) -> None:
        # The dispatcher has already committed its narrow operational claim.
        # Its role cannot mutate envelope/provenance columns, and the executor
        # has SELECT/INSERT only, so a second cross-authority row lock would add
        # no integrity and would incorrectly require an UPDATE capability.
        outbox = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(ControlPlaneOutboxEvent.id == outbox_event_id)
        )
        if outbox is None:
            _reject("run_dispatch_outbox_missing", retryable=True)
        if (
            outbox.tenant_id != event.tenant_id
            or outbox.aggregate_type != "run"
            or outbox.aggregate_key != aggregate_key
            or outbox.event_type != "run.event.persisted"
            or outbox.payload != payload
            or outbox.request_hash != _canonical_hash(payload)
            or outbox.idempotency_key != f"run-event:{event.run_id}:{event.sequence}"
        ):
            _reject("run_dispatch_outbox_mismatch")

    @staticmethod
    def _require_run_event(db: Session, event: RunQueuedEvent) -> RunEventRecord:
        row = db.get(RunEventRecord, event.event_id)
        if row is None:
            _reject("run_dispatch_event_missing", retryable=True)
        if (
            row.run_id != event.run_id
            or row.tenant_id != event.tenant_id
            or row.space_id != event.space_id
            or row.project_id != event.project_id
            or row.sequence != event.sequence
            or row.event_type != "run.queued"
            or row.payload != event.queued_payload
            or row.trace_id != event.trace_id
        ):
            _reject("run_dispatch_event_mismatch")
        return row

    @staticmethod
    def _require_run_scope(run: RunRecord, event: RunQueuedEvent) -> None:
        if (
            run.tenant_id != event.tenant_id
            or run.space_id != event.space_id
            or run.project_id != event.project_id
            or run.id != event.run_id
            or run.queue_class != event.queue_class
            or run.priority != event.priority
            or run.event_sequence < event.sequence
        ):
            _reject("run_dispatch_scope_mismatch")

    @staticmethod
    def _require_replay_integrity(
        db: Session,
        dispatch: RunDispatchRecord,
        run: RunRecord,
        event: RunEventRecord,
    ) -> None:
        binding = db.execute(
            sa.select(ExecutionProfileRecord, EgressPolicyRecord)
            .join(
                EgressPolicyRecord,
                sa.and_(
                    EgressPolicyRecord.id == ExecutionProfileRecord.egress_policy_id,
                    EgressPolicyRecord.tenant_id == ExecutionProfileRecord.tenant_id,
                    EgressPolicyRecord.space_id == ExecutionProfileRecord.space_id,
                    EgressPolicyRecord.project_id == ExecutionProfileRecord.project_id,
                ),
            )
            .where(
                ExecutionProfileRecord.id == dispatch.execution_profile_id,
                EgressPolicyRecord.id == dispatch.egress_policy_id,
            )
            .where(EgressPolicyRecord.allow_private_destinations.is_(False))
            .with_for_update(read=True)
        ).one_or_none()
        profile: ExecutionProfileRecord | None = None
        egress_policy: EgressPolicyRecord | None = None
        if binding is not None:
            profile, egress_policy = binding
        capabilities = dispatch.required_capabilities
        if (
            dispatch.tenant_id != run.tenant_id
            or dispatch.space_id != run.space_id
            or dispatch.project_id != run.project_id
            or dispatch.queue_class != run.queue_class
            or dispatch.execution_profile_id is None
            or dispatch.execution_profile_hash is None
            or len(dispatch.execution_profile_hash) != 64
            or dispatch.egress_policy_id is None
            or dispatch.egress_policy_hash is None
            or len(dispatch.egress_policy_hash) != 64
            or profile is None
            or egress_policy is None
            or profile.status not in {"active", "retired"}
            or egress_policy.status not in {"active", "retired"}
            or egress_policy.allow_private_destinations
            or profile.egress_policy_id != egress_policy.id
            or profile.tenant_id != run.tenant_id
            or profile.space_id != run.space_id
            or profile.project_id != run.project_id
            or profile.config_hash != dispatch.execution_profile_hash
            or egress_policy.tenant_id != run.tenant_id
            or egress_policy.space_id != run.space_id
            or egress_policy.project_id != run.project_id
            or egress_policy.rules_hash != dispatch.egress_policy_hash
            or _aware(dispatch.eligible_at) != _aware(event.created_at)
            or dispatch.max_wait_at <= dispatch.eligible_at
            or dispatch.cost_units <= 0
            or not isinstance(capabilities, list)
            or not capabilities
            or any(not isinstance(value, str) or not value for value in capabilities)
            or capabilities != sorted(set(capabilities))
        ):
            _reject("run_dispatch_replay_conflict")
        expected_hash = dispatch_requirements_hash(
            tenant_id=dispatch.tenant_id,
            space_id=dispatch.space_id,
            project_id=dispatch.project_id,
            pool_id=dispatch.pool_id,
            execution_profile_id=dispatch.execution_profile_id,
            execution_profile_hash=dispatch.execution_profile_hash,
            egress_policy_id=dispatch.egress_policy_id,
            egress_policy_hash=dispatch.egress_policy_hash,
            queue_class=dispatch.queue_class,
            required_capabilities=capabilities,
            cost_units=dispatch.cost_units,
            eligible_at=dispatch.eligible_at,
            max_wait_at=dispatch.max_wait_at,
        )
        if dispatch.requirements_hash != expected_hash:
            _reject("run_dispatch_replay_conflict")

    @staticmethod
    def _resolve_runtime(
        db: Session, run: RunRecord
    ) -> tuple[RuntimePlacementRecord, RuntimePartitionRecord]:
        rows = tuple(
            db.execute(
                sa.select(RuntimePlacementRecord, RuntimePartitionRecord)
                .select_from(RuntimeResourceBindingRecord)
                .join(
                    RuntimePartitionRecord,
                    sa.and_(
                        RuntimePartitionRecord.id
                        == RuntimeResourceBindingRecord.runtime_partition_id,
                        RuntimePartitionRecord.tenant_id == RuntimeResourceBindingRecord.tenant_id,
                        RuntimePartitionRecord.space_id == RuntimeResourceBindingRecord.space_id,
                    ),
                )
                .join(
                    RuntimePlacementRecord,
                    RuntimePlacementRecord.id == RuntimePartitionRecord.placement_id,
                )
                .where(
                    RuntimeResourceBindingRecord.tenant_id == run.tenant_id,
                    RuntimeResourceBindingRecord.space_id == run.space_id,
                    RuntimeResourceBindingRecord.project_id == run.project_id,
                    RuntimeResourceBindingRecord.resource_type == "project",
                    RuntimeResourceBindingRecord.saas_resource_id == run.project_id,
                    RuntimeResourceBindingRecord.status == "active",
                    RuntimeResourceBindingRecord.partition_generation
                    == RuntimePartitionRecord.placement_generation,
                    RuntimePartitionRecord.status == "active",
                    RuntimePartitionRecord.runtime_type == "omnigent",
                    RuntimePartitionRecord.source_revision == run.upstream_revision,
                    RuntimePartitionRecord.adapter_contract_version
                    == run.adapter_contract_version,
                    RuntimePlacementRecord.status == "active",
                    RuntimePlacementRecord.runtime_type == RuntimePartitionRecord.runtime_type,
                    RuntimePlacementRecord.official_schema_revision == run.schema_revision,
                )
                .limit(2)
                .with_for_update(read=True)
            )
        )
        if len(rows) != 1:
            _reject("run_dispatch_runtime_route_ambiguous")
        placement, partition = rows[0]
        return placement, partition

    @staticmethod
    def _resolve_profile_binding(
        db: Session,
        run: RunRecord,
    ) -> tuple[ExecutionProfileRecord, EgressPolicyRecord]:
        profiles = tuple(
            db.execute(
                sa.select(ExecutionProfileRecord, EgressPolicyRecord)
                .join(
                    EgressPolicyRecord,
                    sa.and_(
                        EgressPolicyRecord.id == ExecutionProfileRecord.egress_policy_id,
                        EgressPolicyRecord.tenant_id == ExecutionProfileRecord.tenant_id,
                        EgressPolicyRecord.space_id == ExecutionProfileRecord.space_id,
                        EgressPolicyRecord.project_id == ExecutionProfileRecord.project_id,
                    ),
                )
                .where(
                    ExecutionProfileRecord.tenant_id == run.tenant_id,
                    ExecutionProfileRecord.space_id == run.space_id,
                    ExecutionProfileRecord.project_id == run.project_id,
                    ExecutionProfileRecord.status == "active",
                    EgressPolicyRecord.status == "active",
                    EgressPolicyRecord.allow_private_destinations.is_(False),
                )
                .limit(2)
                .with_for_update(read=True)
            )
        )
        if len(profiles) != 1:
            _reject("run_dispatch_execution_profile_ambiguous")
        profile, egress_policy = profiles[0]
        if (
            profile.network_mode != "proxy_only"
            or not profile.root_read_only
            or profile.run_as_uid <= 0
            or profile.run_as_gid <= 0
            or not profile.no_new_privileges
            or profile.host_socket_access
        ):
            _reject("run_dispatch_execution_profile_unsafe")
        return profile, egress_policy

    @staticmethod
    def _resolve_pool(
        db: Session,
        run: RunRecord,
        placement: RuntimePlacementRecord,
        partition: RuntimePartitionRecord,
    ) -> RunnerPoolRecord:
        pools = tuple(
            db.scalars(
                sa.select(RunnerPoolRecord)
                .join(
                    TenantQueueShareRecord,
                    sa.and_(
                        TenantQueueShareRecord.pool_id == RunnerPoolRecord.id,
                        TenantQueueShareRecord.tenant_id == run.tenant_id,
                        TenantQueueShareRecord.queue_class == RunnerPoolRecord.queue_class,
                    ),
                )
                .where(
                    RunnerPoolRecord.placement_id == placement.id,
                    RunnerPoolRecord.failure_domain == placement.failure_domain,
                    RunnerPoolRecord.queue_class == run.queue_class,
                    RunnerPoolRecord.status == "active",
                    RunnerPoolRecord.source_revision == partition.source_revision,
                    RunnerPoolRecord.schema_revision == placement.official_schema_revision,
                    RunnerPoolRecord.adapter_contract_version
                    == partition.adapter_contract_version,
                )
                .limit(2)
                .with_for_update(read=True)
            )
        )
        if len(pools) != 1:
            _reject("run_dispatch_runner_pool_ambiguous")
        return pools[0]
