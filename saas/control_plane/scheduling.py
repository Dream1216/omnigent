"""P4 durable weighted-fair scheduling, Runner registry, and capabilities."""

from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import RuntimePlacementRecord
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import TERMINAL_RUN_STATUSES, RunRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scheduling_models import (
    CapabilityTokenRecord,
    RunDispatchRecord,
    RunnerPoolRecord,
    RunnerRegistrationRecord,
    TenantQueueShareRecord,
)

_ACTIVE_RUN_STATUSES = frozenset(
    {"leased", "starting", "running", "waiting_input", "waiting_approval", "cancelling"}
)
_VIRTUAL_RUNTIME_SCALE = 1_000_000


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _validate_time(value: datetime) -> None:
    if value.tzinfo is None:
        raise SchedulingError("time_timezone_required", "time must include a timezone")


def _text(value: str, *, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise SchedulingError(f"{field}_invalid", f"{field} is invalid")
    return cleaned


def _normalized_values(values: tuple[str, ...] | list[str], *, field: str) -> list[str]:
    normalized = sorted({_text(value, field=field, maximum=128) for value in values})
    if not normalized:
        raise SchedulingError(f"{field}_invalid", f"{field} must not be empty")
    return normalized


def _canonical_hash(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


def _token_hash(token: str) -> str:
    return sha256(token.encode()).hexdigest()


class SchedulingError(RuntimeError):
    """Stable fail-closed error surface for distributed scheduling."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RunnerConnection:
    runner_id: UUID
    connection_generation: int
    connection_token: str
    status: str


@dataclass(frozen=True, slots=True)
class FairRunLease:
    run_id: UUID
    runner_id: UUID
    lease_token: UUID
    fence_token: int
    dispatch_generation: int
    failure_domain: str
    expires_at: datetime
    capability_id: UUID
    capability_token: str


@dataclass(frozen=True, slots=True)
class VerifiedCapability:
    capability_id: UUID
    run_id: UUID
    runner_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    fence_token: int
    allowed_actions: tuple[str, ...]
    resource_scope: dict[str, str]
    expires_at: datetime


class SchedulingControlPlane:
    """Own cross-replica scheduling facts outside official Runner hot paths."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create_pool(
        self,
        *,
        placement_id: UUID,
        name: str,
        queue_class: str,
        capacity_slots: int,
        reserved_slots: int,
        protocol_version: int,
        source_revision: str,
        schema_revision: str,
        adapter_contract_version: str,
    ) -> UUID:
        """Create a pool pinned to an active reviewed Runtime Placement."""

        if capacity_slots <= 0 or reserved_slots < 0 or reserved_slots > capacity_slots:
            raise SchedulingError("pool_capacity_invalid", "Runner pool capacity is invalid")
        if protocol_version <= 0:
            raise SchedulingError("runner_protocol_invalid", "Runner protocol must be positive")
        pool_id = uuid4()
        with self._session_factory.begin() as db:
            placement = db.get(RuntimePlacementRecord, placement_id)
            if placement is None or placement.status != "active":
                raise SchedulingError(
                    "placement_unavailable", "Runner pool placement is not active"
                )
            expected_schema = _text(schema_revision, field="schema_revision", maximum=64)
            if placement.official_schema_revision != expected_schema:
                raise SchedulingError(
                    "placement_schema_mismatch", "Runner pool schema is not placement-approved"
                )
            db.add(
                RunnerPoolRecord(
                    id=pool_id,
                    placement_id=placement_id,
                    failure_domain=placement.failure_domain,
                    name=_text(name, field="pool_name", maximum=128),
                    queue_class=_text(queue_class, field="queue_class", maximum=64),
                    capacity_slots=capacity_slots,
                    reserved_slots=reserved_slots,
                    status="active",
                    protocol_version=protocol_version,
                    source_revision=_text(source_revision, field="source_revision", maximum=64),
                    schema_revision=expected_schema,
                    adapter_contract_version=_text(
                        adapter_contract_version,
                        field="adapter_contract_version",
                        maximum=32,
                    ),
                )
            )
        return pool_id

    def register_runner(
        self,
        *,
        pool_id: UUID,
        instance_key: str,
        failure_domain: str,
        protocol_version: int,
        source_revision: str,
        schema_revision: str,
        adapter_contract_version: str,
        capabilities: tuple[str, ...] | list[str],
        max_concurrency: int,
        now: datetime | None = None,
    ) -> RunnerConnection:
        """Register or fence-reconnect one Runner and return its one-time raw token."""

        registered_at = now or _utcnow()
        _validate_time(registered_at)
        if max_concurrency <= 0:
            raise SchedulingError("runner_capacity_invalid", "Runner concurrency must be positive")
        instance = _text(instance_key, field="runner_instance", maximum=256)
        domain = _text(failure_domain, field="failure_domain", maximum=128)
        normalized_capabilities = _normalized_values(capabilities, field="runner_capability")
        raw_token = secrets.token_urlsafe(32)
        digest = _token_hash(raw_token)
        with self._session_factory.begin() as db:
            pool = self._pool(db, pool_id, lock=True)
            self._require_pool_compatibility(
                pool,
                protocol_version=protocol_version,
                source_revision=source_revision,
                schema_revision=schema_revision,
                adapter_contract_version=adapter_contract_version,
            )
            if domain != pool.failure_domain:
                raise SchedulingError(
                    "runner_failure_domain_mismatch",
                    "Runner failure domain does not match its reviewed Placement",
                )
            existing = db.scalar(
                sa.select(RunnerRegistrationRecord)
                .where(
                    RunnerRegistrationRecord.pool_id == pool_id,
                    RunnerRegistrationRecord.instance_key == instance,
                )
                .with_for_update()
            )
            if existing is None:
                runner = RunnerRegistrationRecord(
                    pool_id=pool.id,
                    placement_id=pool.placement_id,
                    instance_key=instance,
                    failure_domain=domain,
                    status="online",
                    connection_generation=1,
                    connection_token_hash=digest,
                    protocol_version=protocol_version,
                    source_revision=pool.source_revision,
                    schema_revision=pool.schema_revision,
                    adapter_contract_version=pool.adapter_contract_version,
                    capabilities=normalized_capabilities,
                    capabilities_hash=_canonical_hash(normalized_capabilities),
                    max_concurrency=max_concurrency,
                    active_leases=0,
                    last_heartbeat_at=registered_at,
                    registered_at=registered_at,
                )
                db.add(runner)
                db.flush()
            else:
                runner = existing
                runner.connection_generation += 1
                runner.connection_token_hash = digest
                runner.failure_domain = domain
                runner.status = "online"
                runner.protocol_version = protocol_version
                runner.source_revision = pool.source_revision
                runner.schema_revision = pool.schema_revision
                runner.adapter_contract_version = pool.adapter_contract_version
                runner.capabilities = normalized_capabilities
                runner.capabilities_hash = _canonical_hash(normalized_capabilities)
                runner.max_concurrency = max(max_concurrency, runner.active_leases)
                runner.last_heartbeat_at = registered_at
                self._revoke_runner_capabilities(
                    db,
                    runner.id,
                    revoked_at=registered_at,
                    reason="runner_reconnected",
                )
            return RunnerConnection(
                runner.id,
                runner.connection_generation,
                raw_token,
                runner.status,
            )

    def heartbeat_runner(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        now: datetime | None = None,
    ) -> str:
        """Refresh only the latest Runner incarnation; stale replicas fail closed."""

        heartbeat_at = now or _utcnow()
        _validate_time(heartbeat_at)
        with self._session_factory.begin() as db:
            runner = self._runner(db, runner_id, lock=True)
            self._require_runner_connection(
                runner,
                connection_generation=connection_generation,
                connection_token=connection_token,
            )
            if runner.status not in {"online", "draining"}:
                raise SchedulingError("runner_unavailable", "Runner is not heartbeat-eligible")
            runner.last_heartbeat_at = heartbeat_at
            return runner.status

    def configure_tenant_share(
        self,
        *,
        tenant_id: UUID,
        pool_id: UUID,
        weight: int,
        max_concurrent: int,
        burst_limit: int,
    ) -> UUID:
        """Create or update a tenant's durable weighted-fair share."""

        if weight <= 0 or max_concurrent <= 0 or burst_limit < max_concurrent:
            raise SchedulingError("queue_share_invalid", "Tenant queue share is invalid")
        with self._session_factory.begin() as db:
            pool = self._pool(db, pool_id, lock=False)
            share = db.scalar(
                sa.select(TenantQueueShareRecord)
                .where(
                    TenantQueueShareRecord.tenant_id == tenant_id,
                    TenantQueueShareRecord.pool_id == pool_id,
                    TenantQueueShareRecord.queue_class == pool.queue_class,
                )
                .with_for_update()
            )
            if share is None:
                share = TenantQueueShareRecord(
                    tenant_id=tenant_id,
                    pool_id=pool_id,
                    queue_class=pool.queue_class,
                    weight=weight,
                    max_concurrent=max_concurrent,
                    burst_limit=burst_limit,
                    active_leases=0,
                    virtual_runtime=0,
                    version=1,
                )
                db.add(share)
                db.flush()
            else:
                if burst_limit < share.active_leases:
                    raise SchedulingError(
                        "queue_share_in_use", "Burst limit is below active leases"
                    )
                share.weight = weight
                share.max_concurrent = max(max_concurrent, share.active_leases)
                share.burst_limit = burst_limit
                share.version += 1
            return share.id

    def prepare_dispatch(
        self,
        *,
        run_id: UUID,
        pool_id: UUID,
        required_capabilities: tuple[str, ...] | list[str],
        cost_units: int = 1,
        eligible_at: datetime | None = None,
        maximum_wait: timedelta = timedelta(hours=1),
    ) -> bool:
        """Attach immutable dispatch requirements to a queued Run; return replay status."""

        ready_at = eligible_at or _utcnow()
        _validate_time(ready_at)
        if cost_units <= 0 or maximum_wait <= timedelta(0):
            raise SchedulingError("dispatch_window_invalid", "Dispatch cost or wait is invalid")
        capabilities = _normalized_values(required_capabilities, field="required_capability")
        wait_until = ready_at + maximum_wait
        with self._session_factory.begin() as db:
            run = self._run(db, run_id, lock=True)
            if run.status != "queued":
                raise SchedulingError("run_not_queued", "Only queued Runs can be dispatched")
            pool = self._pool(db, pool_id, lock=False)
            if pool.status != "active" or pool.queue_class != run.queue_class:
                raise SchedulingError(
                    "runner_pool_unavailable", "Runner pool cannot accept this queue class"
                )
            share = self._queue_share(db, run.tenant_id, pool, lock=False)
            if share is None:
                raise SchedulingError(
                    "tenant_queue_share_missing", "Tenant has no configured fair-queue share"
                )
            request_hash = _canonical_hash(
                {
                    "pool_id": str(pool_id),
                    "queue_class": run.queue_class,
                    "required_capabilities": capabilities,
                    "cost_units": cost_units,
                    "eligible_at": ready_at.isoformat(),
                    "max_wait_at": wait_until.isoformat(),
                }
            )
            existing = db.get(RunDispatchRecord, run_id)
            if existing is not None:
                if existing.requirements_hash != request_hash:
                    raise SchedulingError(
                        "dispatch_idempotency_conflict",
                        "Run dispatch requirements changed on replay",
                    )
                return True
            db.add(
                RunDispatchRecord(
                    run_id=run.id,
                    tenant_id=run.tenant_id,
                    space_id=run.space_id,
                    project_id=run.project_id,
                    pool_id=pool.id,
                    queue_class=run.queue_class,
                    required_capabilities=capabilities,
                    requirements_hash=request_hash,
                    cost_units=cost_units,
                    eligible_at=ready_at,
                    max_wait_at=wait_until,
                    status="pending",
                    dispatch_generation=0,
                )
            )
            return False

    def claim_fair_run(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        lease_duration: timedelta,
        capability_actions: tuple[str, ...] | list[str],
        capability_resource_scope: dict[str, str],
        heartbeat_timeout: timedelta = timedelta(seconds=30),
        now: datetime | None = None,
    ) -> FairRunLease | None:
        """Atomically choose a tenant by weighted virtual runtime and lease one Run."""

        claimed_at = now or _utcnow()
        _validate_time(claimed_at)
        if lease_duration <= timedelta(0) or heartbeat_timeout <= timedelta(0):
            raise SchedulingError("lease_duration_invalid", "Lease durations must be positive")
        actions = _normalized_values(capability_actions, field="capability_action")
        resource_scope = self._resource_scope(capability_resource_scope)
        raw_capability = secrets.token_urlsafe(32)
        with self._session_factory.begin() as db:
            runner = self._runner(db, runner_id, lock=True)
            self._require_runner_connection(
                runner,
                connection_generation=connection_generation,
                connection_token=connection_token,
            )
            if runner.status != "online":
                raise SchedulingError("runner_unavailable", "Runner does not accept new work")
            if _aware(runner.last_heartbeat_at) + heartbeat_timeout <= claimed_at:
                runner.status = "offline"
                raise SchedulingError("runner_heartbeat_stale", "Runner heartbeat is stale")
            if runner.active_leases >= runner.max_concurrency:
                return None
            pool = self._pool(db, runner.pool_id, lock=True)
            if pool.status != "active":
                raise SchedulingError("runner_pool_unavailable", "Runner pool is not active")
            active_pool_leases = cast(
                int,
                db.scalar(
                    sa.select(
                        sa.func.coalesce(sa.func.sum(RunnerRegistrationRecord.active_leases), 0)
                    ).where(RunnerRegistrationRecord.pool_id == pool.id)
                ),
            )
            if active_pool_leases >= pool.capacity_slots:
                return None
            selected = self._select_fair_dispatch(
                db,
                pool=pool,
                runner_capabilities=frozenset(runner.capabilities),
                claimed_at=claimed_at,
            )
            if selected is None:
                return None
            share, dispatch, run = selected
            authoritative_scope = {
                "tenant_id": str(run.tenant_id),
                "space_id": str(run.space_id),
                "project_id": str(run.project_id),
                "run_id": str(run.id),
                "runner_id": str(runner.id),
            }
            for key, value in authoritative_scope.items():
                supplied = resource_scope.get(key)
                if supplied is not None and supplied != value:
                    raise SchedulingError(
                        "capability_scope_conflict",
                        "Caller capability scope conflicts with authoritative dispatch scope",
                    )
            resource_scope = {**resource_scope, **authoritative_scope}
            lease_token = uuid4()
            expires_at = claimed_at + lease_duration
            run.status = "leased"
            run.version += 1
            run.fence_token += 1
            run.lease_owner = str(runner.id)
            run.lease_token = lease_token
            run.lease_expires_at = expires_at
            run.heartbeat_at = claimed_at
            dispatch.status = "leased"
            dispatch.selected_runner_id = runner.id
            dispatch.selected_failure_domain = runner.failure_domain
            dispatch.dispatch_generation += 1
            share.active_leases += 1
            share.virtual_runtime += (
                dispatch.cost_units * _VIRTUAL_RUNTIME_SCALE + share.weight - 1
            ) // share.weight
            share.last_dispatched_at = claimed_at
            share.version += 1
            runner.active_leases += 1
            capability = CapabilityTokenRecord(
                token_hash=_token_hash(raw_capability),
                tenant_id=run.tenant_id,
                space_id=run.space_id,
                project_id=run.project_id,
                run_id=run.id,
                runner_id=runner.id,
                runner_connection_generation=runner.connection_generation,
                dispatch_generation=dispatch.dispatch_generation,
                fence_token=run.fence_token,
                allowed_actions=actions,
                resource_scope=resource_scope,
                issued_at=claimed_at,
                expires_at=expires_at,
            )
            db.add(capability)
            db.flush()
            self._apply_run_context(db, run)
            ExecutionControlPlane._append_event(
                db,
                run,
                event_type="run.leased",
                payload={
                    "status": "leased",
                    "runner_id": str(runner.id),
                    "runner_pool_id": str(pool.id),
                    "failure_domain": runner.failure_domain,
                    "fence_token": run.fence_token,
                    "dispatch_generation": dispatch.dispatch_generation,
                    "lease_expires_at": expires_at.isoformat(),
                },
                trace_id=f"runner:{runner.id}",
            )
            return FairRunLease(
                run.id,
                runner.id,
                lease_token,
                run.fence_token,
                dispatch.dispatch_generation,
                runner.failure_domain,
                expires_at,
                capability.id,
                raw_capability,
            )

    def verify_capability(
        self,
        *,
        capability_token: str,
        runner_id: UUID,
        run_id: UUID,
        action: str,
        required_resource_scope: dict[str, str],
        now: datetime | None = None,
    ) -> VerifiedCapability:
        """Verify a hashed capability against Runner incarnation, Run fence, and scope."""

        checked_at = now or _utcnow()
        _validate_time(checked_at)
        digest = _token_hash(_text(capability_token, field="capability_token", maximum=512))
        requested_action = _text(action, field="capability_action", maximum=128)
        required_scope = self._resource_scope(required_resource_scope)
        with self._session_factory() as db:
            capability = db.scalar(
                sa.select(CapabilityTokenRecord).where(CapabilityTokenRecord.token_hash == digest)
            )
            if capability is None:
                raise SchedulingError("capability_invalid", "Capability is invalid")
            if capability.revoked_at is not None or _aware(capability.expires_at) <= checked_at:
                raise SchedulingError("capability_expired", "Capability is expired or revoked")
            if capability.runner_id != runner_id or capability.run_id != run_id:
                raise SchedulingError(
                    "capability_binding_invalid", "Capability binding is invalid"
                )
            if requested_action not in capability.allowed_actions:
                raise SchedulingError("capability_action_denied", "Capability action is denied")
            for key, value in required_scope.items():
                if capability.resource_scope.get(key) != value:
                    raise SchedulingError(
                        "capability_scope_denied", "Capability resource scope is denied"
                    )
            runner = self._runner(db, runner_id, lock=False)
            run = self._run(db, run_id, lock=False)
            dispatch = db.get(RunDispatchRecord, run_id)
            if dispatch is None or dispatch.status != "leased":
                raise SchedulingError("capability_dispatch_stale", "Dispatch is not leased")
            if runner.status not in {"online", "draining"}:
                raise SchedulingError("capability_runner_unavailable", "Runner is unavailable")
            if runner.connection_generation != capability.runner_connection_generation:
                raise SchedulingError("capability_runner_stale", "Runner incarnation is stale")
            if (
                dispatch.selected_runner_id != runner.id
                or dispatch.dispatch_generation != capability.dispatch_generation
                or run.fence_token != capability.fence_token
                or run.status not in _ACTIVE_RUN_STATUSES
                or run.lease_expires_at is None
                or _aware(run.lease_expires_at) <= checked_at
            ):
                raise SchedulingError("capability_fence_stale", "Capability fence is stale")
            return VerifiedCapability(
                capability.id,
                capability.run_id,
                capability.runner_id,
                capability.tenant_id,
                capability.space_id,
                capability.project_id,
                capability.fence_token,
                tuple(capability.allowed_actions),
                dict(capability.resource_scope),
                _aware(capability.expires_at),
            )

    def release_dispatch(
        self,
        *,
        run_id: UUID,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        fence_token: int,
        requeue: bool,
        now: datetime | None = None,
    ) -> bool:
        """Release capacity once; optionally make a recovered queued Run dispatchable again."""

        released_at = now or _utcnow()
        _validate_time(released_at)
        with self._session_factory.begin() as db:
            runner = self._runner(db, runner_id, lock=True)
            self._require_runner_connection(
                runner,
                connection_generation=connection_generation,
                connection_token=connection_token,
            )
            dispatch = db.scalar(
                sa.select(RunDispatchRecord)
                .where(RunDispatchRecord.run_id == run_id)
                .with_for_update()
            )
            if dispatch is None:
                raise SchedulingError("dispatch_not_found", "Run dispatch was not found")
            if dispatch.status == "released" and not requeue:
                return True
            if dispatch.status == "pending" and requeue:
                return True
            if dispatch.status == "pending":
                raise SchedulingError("dispatch_not_leased", "Run dispatch is not leased")
            if dispatch.status != "leased" or dispatch.selected_runner_id != runner_id:
                raise SchedulingError("dispatch_binding_stale", "Dispatch Runner is stale")
            run = self._run(db, run_id, lock=True)
            if run.fence_token != fence_token:
                raise SchedulingError("dispatch_fence_stale", "Dispatch fence is stale")
            if requeue:
                if run.status != "queued":
                    raise SchedulingError(
                        "dispatch_requeue_invalid", "Run must be recovered to queued first"
                    )
            elif run.status not in TERMINAL_RUN_STATUSES:
                raise SchedulingError(
                    "dispatch_release_invalid", "Run must be terminal before final release"
                )
            share = self._queue_share(
                db,
                run.tenant_id,
                self._pool(db, dispatch.pool_id),
                lock=True,
            )
            if share is None or share.active_leases <= 0 or runner.active_leases <= 0:
                raise SchedulingError(
                    "dispatch_counter_inconsistent", "Dispatch capacity counters are inconsistent"
                )
            share.active_leases -= 1
            share.version += 1
            runner.active_leases -= 1
            self._revoke_run_capabilities(
                db,
                run_id,
                revoked_at=released_at,
                reason="run_requeued" if requeue else "run_terminal",
            )
            if requeue:
                dispatch.status = "pending"
                dispatch.selected_runner_id = None
                dispatch.selected_failure_domain = None
                dispatch.released_at = None
            else:
                dispatch.status = "released"
                dispatch.released_at = released_at
            return False

    def set_runner_status(
        self,
        *,
        runner_id: UUID,
        target_status: str,
        reason: str,
        now: datetime | None = None,
    ) -> str:
        """Drain, quarantine, or stop a Runner with fail-closed revocation."""

        if target_status not in {"draining", "offline", "quarantined"}:
            raise SchedulingError("runner_status_invalid", "Runner status is invalid")
        changed_at = now or _utcnow()
        _validate_time(changed_at)
        cleaned_reason = _text(reason, field="runner_status_reason", maximum=256)
        with self._session_factory.begin() as db:
            runner = self._runner(db, runner_id, lock=True)
            runner.status = target_status
            if target_status in {"offline", "quarantined"}:
                self._revoke_runner_capabilities(
                    db,
                    runner_id,
                    revoked_at=changed_at,
                    reason=cleaned_reason,
                )
            return runner.status

    def expire_stale_runners(
        self,
        *,
        heartbeat_timeout: timedelta,
        now: datetime | None = None,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        """Fence stale Runner connections and revoke their short-lived capabilities."""

        checked_at = now or _utcnow()
        _validate_time(checked_at)
        if heartbeat_timeout <= timedelta(0) or limit <= 0:
            raise SchedulingError("runner_sweep_invalid", "Runner sweep settings are invalid")
        threshold = checked_at - heartbeat_timeout
        with self._session_factory.begin() as db:
            query = (
                sa.select(RunnerRegistrationRecord)
                .where(
                    RunnerRegistrationRecord.status == "online",
                    RunnerRegistrationRecord.last_heartbeat_at <= threshold,
                )
                .order_by(RunnerRegistrationRecord.last_heartbeat_at, RunnerRegistrationRecord.id)
                .limit(limit)
            )
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            runners = tuple(db.scalars(query))
            for runner in runners:
                runner.status = "offline"
                self._revoke_runner_capabilities(
                    db,
                    runner.id,
                    revoked_at=checked_at,
                    reason="heartbeat_expired",
                )
            return tuple(runner.id for runner in runners)

    def dead_letter_expired_dispatches(
        self,
        *,
        now: datetime | None = None,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        """Move over-wait queued Runs to durable DLQ without mutating their original input."""

        checked_at = now or _utcnow()
        _validate_time(checked_at)
        if limit <= 0:
            raise SchedulingError("dispatch_sweep_invalid", "Dispatch sweep limit is invalid")
        with self._session_factory.begin() as db:
            query = (
                sa.select(RunDispatchRecord)
                .join(RunRecord, RunRecord.id == RunDispatchRecord.run_id)
                .where(
                    RunDispatchRecord.status == "pending",
                    RunDispatchRecord.max_wait_at <= checked_at,
                    RunRecord.status == "queued",
                )
                .order_by(RunDispatchRecord.max_wait_at, RunDispatchRecord.run_id)
                .limit(limit)
            )
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            dispatches = tuple(db.scalars(query))
            for dispatch in dispatches:
                run = self._run(db, dispatch.run_id, lock=True)
                dispatch.status = "dead_letter"
                dispatch.released_at = checked_at
                dispatch.dead_letter_reason = "maximum_wait_exceeded"
                run.status = "orphaned"
                run.version += 1
                run.terminal_at = checked_at
                ExecutionControlPlane._finalize_reservations(db, run, succeeded=False)
                self._apply_run_context(db, run)
                ExecutionControlPlane._append_event(
                    db,
                    run,
                    event_type="run.orphaned",
                    payload={"status": "orphaned", "reason": "maximum_wait_exceeded"},
                    trace_id="scheduler:dead-letter",
                )
            return tuple(dispatch.run_id for dispatch in dispatches)

    def _select_fair_dispatch(
        self,
        db: Session,
        *,
        pool: RunnerPoolRecord,
        runner_capabilities: frozenset[str],
        claimed_at: datetime,
    ) -> tuple[TenantQueueShareRecord, RunDispatchRecord, RunRecord] | None:
        pending_exists = sa.exists(
            sa.select(1)
            .select_from(RunDispatchRecord)
            .join(RunRecord, RunRecord.id == RunDispatchRecord.run_id)
            .where(
                RunDispatchRecord.tenant_id == TenantQueueShareRecord.tenant_id,
                RunDispatchRecord.pool_id == pool.id,
                RunDispatchRecord.queue_class == pool.queue_class,
                RunDispatchRecord.status == "pending",
                RunDispatchRecord.eligible_at <= claimed_at,
                RunDispatchRecord.max_wait_at > claimed_at,
                RunRecord.status == "queued",
            )
        )
        share_query = (
            sa.select(TenantQueueShareRecord)
            .where(
                TenantQueueShareRecord.pool_id == pool.id,
                TenantQueueShareRecord.queue_class == pool.queue_class,
                TenantQueueShareRecord.active_leases < TenantQueueShareRecord.max_concurrent,
                pending_exists,
            )
            .order_by(
                TenantQueueShareRecord.virtual_runtime,
                TenantQueueShareRecord.last_dispatched_at,
                TenantQueueShareRecord.tenant_id,
            )
            .limit(64)
        )
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            share_query = share_query.with_for_update(skip_locked=True)
        for share in db.scalars(share_query):
            dispatch_query = (
                sa.select(RunDispatchRecord)
                .join(RunRecord, RunRecord.id == RunDispatchRecord.run_id)
                .where(
                    RunDispatchRecord.tenant_id == share.tenant_id,
                    RunDispatchRecord.pool_id == pool.id,
                    RunDispatchRecord.queue_class == pool.queue_class,
                    RunDispatchRecord.status == "pending",
                    RunDispatchRecord.eligible_at <= claimed_at,
                    RunDispatchRecord.max_wait_at > claimed_at,
                    RunRecord.status == "queued",
                )
                .order_by(RunRecord.priority.desc(), RunRecord.created_at, RunRecord.id)
                .limit(64)
            )
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                dispatch_query = dispatch_query.with_for_update(skip_locked=True)
            for dispatch in db.scalars(dispatch_query):
                if not set(dispatch.required_capabilities).issubset(runner_capabilities):
                    continue
                run = self._run(db, dispatch.run_id, lock=True)
                if run.status == "queued":
                    return share, dispatch, run
        return None

    @staticmethod
    def _apply_run_context(db: Session, run: RunRecord) -> None:
        apply_rls_context(
            db,
            RlsContext(tenant_id=run.tenant_id, space_id=run.space_id),
        )

    @staticmethod
    def _resource_scope(values: dict[str, str]) -> dict[str, str]:
        if not values:
            raise SchedulingError(
                "capability_scope_invalid", "Capability resource scope must not be empty"
            )
        return {
            _text(key, field="capability_scope_key", maximum=128): _text(
                value, field="capability_scope_value", maximum=512
            )
            for key, value in sorted(values.items())
        }

    @staticmethod
    def _require_pool_compatibility(
        pool: RunnerPoolRecord,
        *,
        protocol_version: int,
        source_revision: str,
        schema_revision: str,
        adapter_contract_version: str,
    ) -> None:
        if pool.status != "active":
            raise SchedulingError("runner_pool_unavailable", "Runner pool is not active")
        supplied = (
            protocol_version,
            source_revision.strip(),
            schema_revision.strip(),
            adapter_contract_version.strip(),
        )
        expected = (
            pool.protocol_version,
            pool.source_revision,
            pool.schema_revision,
            pool.adapter_contract_version,
        )
        if supplied != expected:
            raise SchedulingError(
                "runner_compatibility_rejected", "Runner revision or protocol is not approved"
            )

    @staticmethod
    def _require_runner_connection(
        runner: RunnerRegistrationRecord,
        *,
        connection_generation: int,
        connection_token: str,
    ) -> None:
        supplied_hash = _token_hash(
            _text(connection_token, field="runner_connection_token", maximum=512)
        )
        if runner.connection_generation != connection_generation or not hmac.compare_digest(
            runner.connection_token_hash, supplied_hash
        ):
            raise SchedulingError(
                "runner_connection_stale", "Runner connection generation or token is stale"
            )

    @staticmethod
    def _revoke_runner_capabilities(
        db: Session,
        runner_id: UUID,
        *,
        revoked_at: datetime,
        reason: str,
    ) -> None:
        for capability in db.scalars(
            sa.select(CapabilityTokenRecord)
            .where(
                CapabilityTokenRecord.runner_id == runner_id,
                CapabilityTokenRecord.revoked_at.is_(None),
            )
            .with_for_update()
        ):
            capability.revoked_at = revoked_at
            capability.revocation_reason = reason

    @staticmethod
    def _revoke_run_capabilities(
        db: Session,
        run_id: UUID,
        *,
        revoked_at: datetime,
        reason: str,
    ) -> None:
        for capability in db.scalars(
            sa.select(CapabilityTokenRecord)
            .where(
                CapabilityTokenRecord.run_id == run_id,
                CapabilityTokenRecord.revoked_at.is_(None),
            )
            .with_for_update()
        ):
            capability.revoked_at = revoked_at
            capability.revocation_reason = reason

    @staticmethod
    def _pool(db: Session, pool_id: UUID, *, lock: bool = False) -> RunnerPoolRecord:
        if lock and db.bind is not None and db.bind.dialect.name == "postgresql":
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
                {"lock_key": f"saas_runner_pool:{pool_id}"},
            )
        query = sa.select(RunnerPoolRecord).where(RunnerPoolRecord.id == pool_id)
        if lock and (db.bind is None or db.bind.dialect.name != "postgresql"):
            query = query.with_for_update()
        pool = db.scalar(query)
        if pool is None:
            raise SchedulingError("runner_pool_not_found", "Runner pool was not found")
        return pool

    @staticmethod
    def _runner(db: Session, runner_id: UUID, *, lock: bool = False) -> RunnerRegistrationRecord:
        query = sa.select(RunnerRegistrationRecord).where(RunnerRegistrationRecord.id == runner_id)
        if lock:
            query = query.with_for_update()
        runner = db.scalar(query)
        if runner is None:
            raise SchedulingError("runner_not_found", "Runner was not found")
        return runner

    @staticmethod
    def _run(db: Session, run_id: UUID, *, lock: bool = False) -> RunRecord:
        query = sa.select(RunRecord).where(RunRecord.id == run_id)
        if lock:
            query = query.with_for_update()
        run = db.scalar(query)
        if run is None:
            raise SchedulingError("run_not_found", "Run was not found")
        return run

    @staticmethod
    def _queue_share(
        db: Session,
        tenant_id: UUID,
        pool: RunnerPoolRecord,
        *,
        lock: bool = False,
    ) -> TenantQueueShareRecord | None:
        query = sa.select(TenantQueueShareRecord).where(
            TenantQueueShareRecord.tenant_id == tenant_id,
            TenantQueueShareRecord.pool_id == pool.id,
            TenantQueueShareRecord.queue_class == pool.queue_class,
        )
        if lock:
            query = query.with_for_update()
        return db.scalar(query)
