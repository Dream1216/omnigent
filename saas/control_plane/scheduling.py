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

from saas.control_plane.db_models import ControlPlaneOutboxEvent, RuntimePlacementRecord
from saas.control_plane.dispatch_binding import (
    dispatch_requirements_hash as _canonical_dispatch_requirements_hash,
)
from saas.control_plane.execution import ExecutionControlPlane, RunLease, RunMutation
from saas.control_plane.execution_models import TERMINAL_RUN_STATUSES, RunRecord
from saas.control_plane.isolation_models import EgressPolicyRecord, ExecutionProfileRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.runner_execution_spec import (
    ManagedRunExecutionSpecError,
    production_run_execution_spec,
)
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
_HASH_ALPHABET = frozenset("0123456789abcdef")
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


def _hash64(value: str, *, field: str) -> str:
    normalized = _text(value, field=field, maximum=64)
    if len(normalized) != 64 or any(character not in _HASH_ALPHABET for character in normalized):
        raise SchedulingError(f"{field}_invalid", f"{field} is invalid")
    return normalized


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
class RunnerExecutionEnvelope:
    """Server-derived immutable facts consumed by one managed Runner launch."""

    change_set_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    run_id: UUID
    runner_id: UUID
    fence_token: int
    execution_profile_id: UUID
    execution_profile_hash: str
    egress_policy_id: UUID
    egress_policy_hash: str
    product_revision: str
    image_digest: str
    execution_spec_hash: str
    launch_argv: tuple[str, ...]
    execution_kind: str = "omnigent.agent.v1"
    preview_execution_id: UUID | None = None
    checkpoint_revision: str | None = None


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
    execution_envelope: RunnerExecutionEnvelope | None = None


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
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                db.execute(
                    sa.text("LOCK TABLE public.saas_runner_registrations IN ROW EXCLUSIVE MODE")
                )
            pool = self._pool(db, pool_id, lock=True)
            promoted_fleet = db.scalar(
                sa.select(ControlPlaneOutboxEvent.id)
                .where(
                    ControlPlaneOutboxEvent.aggregate_type == "runner_fleet",
                    ControlPlaneOutboxEvent.event_type == "runner.fleet.promoted",
                )
                .limit(1)
            )
            if promoted_fleet is not None:
                raise SchedulingError(
                    "runner_fleet_stage_required",
                    "A promoted production fleet can only rotate through owner staging",
                )
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
        execution_profile_id: UUID | None = None,
        execution_profile_hash: str | None = None,
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
            self._apply_run_context(db, run)
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
            profile, egress_policy = self._resolve_dispatch_profile_binding(db, run)
            if execution_profile_id is not None and execution_profile_id != profile.id:
                raise SchedulingError(
                    "dispatch_execution_profile_invalid",
                    "Caller-selected profile differs from server authority",
                )
            profile_hash = _hash64(
                profile.config_hash,
                field="dispatch_execution_profile_hash",
            )
            if execution_profile_hash is not None and (
                _hash64(
                    execution_profile_hash,
                    field="dispatch_execution_profile_hash",
                )
                != profile_hash
            ):
                raise SchedulingError(
                    "dispatch_execution_profile_hash_mismatch",
                    "Dispatch execution profile hash is not current",
                )
            egress_policy_hash = _hash64(
                egress_policy.rules_hash,
                field="dispatch_egress_policy_hash",
            )
            request_hash = self._dispatch_requirements_hash(
                tenant_id=run.tenant_id,
                space_id=run.space_id,
                project_id=run.project_id,
                pool_id=pool_id,
                execution_profile_id=profile.id,
                execution_profile_hash=profile_hash,
                egress_policy_id=egress_policy.id,
                egress_policy_hash=egress_policy_hash,
                queue_class=run.queue_class,
                required_capabilities=capabilities,
                cost_units=cost_units,
                eligible_at=ready_at,
                max_wait_at=wait_until,
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
                    execution_profile_id=profile.id,
                    execution_profile_hash=profile_hash,
                    egress_policy_id=egress_policy.id,
                    egress_policy_hash=egress_policy_hash,
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
        expected_product_revision: str | None = None,
        product_image_digest: str | None = None,
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
            pool, runner = self._lock_pool_then_runner(db, runner_id)
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
            self._apply_run_context(db, run)
            profile = self._require_dispatch_profile_binding(db, dispatch=dispatch, run=run)
            raw_change_set_id = run.input.get("change_set_id")
            try:
                change_set_id = (
                    UUID(raw_change_set_id) if isinstance(raw_change_set_id, str) else None
                )
            except ValueError:
                change_set_id = None
            if expected_product_revision is not None or product_image_digest is not None:
                try:
                    execution_spec = production_run_execution_spec(run.input)
                except ManagedRunExecutionSpecError as exc:
                    raise SchedulingError(
                        "run_execution_envelope_invalid",
                        "Run does not have a valid managed execution specification",
                    ) from exc
                if (
                    change_set_id is None
                    or change_set_id.int == 0
                    or expected_product_revision is None
                    or product_image_digest is None
                    or run.product_revision != expected_product_revision
                ):
                    raise SchedulingError(
                        "run_execution_envelope_invalid",
                        "Run does not have an exact production execution envelope",
                    )
                if (
                    not product_image_digest.startswith("sha256:")
                    or len(product_image_digest) != 71
                ):
                    raise SchedulingError(
                        "run_execution_envelope_invalid", "Runner image digest is invalid"
                    )
                required_actions = (
                    {"preview.serve", "run.execute", "worktree.read"}
                    if execution_spec.kind == "omnigent.preview.v1"
                    else {"run.execute", "sandbox.launch", "worktree.write"}
                )
                if not required_actions.issubset(actions):
                    raise SchedulingError(
                        "run_execution_capability_invalid",
                        "Production Runner capability actions are incomplete",
                    )
            else:
                execution_spec = None
            authoritative_scope = {
                "tenant_id": str(run.tenant_id),
                "space_id": str(run.space_id),
                "project_id": str(run.project_id),
                "run_id": str(run.id),
                "runner_id": str(runner.id),
            }
            if change_set_id is not None:
                authoritative_scope["change_set_id"] = str(change_set_id)
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
            envelope = None
            if (
                change_set_id is not None
                and product_image_digest is not None
                and execution_spec is not None
            ):
                envelope = RunnerExecutionEnvelope(
                    change_set_id=change_set_id,
                    tenant_id=run.tenant_id,
                    space_id=run.space_id,
                    project_id=run.project_id,
                    run_id=run.id,
                    runner_id=runner.id,
                    fence_token=run.fence_token,
                    execution_profile_id=profile.id,
                    execution_profile_hash=profile.config_hash,
                    egress_policy_id=dispatch.egress_policy_id,
                    egress_policy_hash=dispatch.egress_policy_hash,
                    product_revision=run.product_revision,
                    image_digest=product_image_digest,
                    execution_spec_hash=execution_spec.spec_hash,
                    launch_argv=execution_spec.launch_argv,
                    execution_kind=execution_spec.kind,
                    preview_execution_id=execution_spec.preview_execution_id,
                    checkpoint_revision=execution_spec.checkpoint_revision,
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
                envelope,
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
            runner = self._runner(db, runner_id, lock=False)
            return self._verify_capability_in_transaction(
                db,
                digest=digest,
                runner=runner,
                run_id=run_id,
                requested_action=requested_action,
                required_scope=required_scope,
                checked_at=checked_at,
                lock=False,
            )

    def authenticated_run_heartbeat(
        self,
        execution: ExecutionControlPlane,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        capability_token: str,
        lease_duration: timedelta,
        now: datetime | None = None,
    ) -> RunLease:
        """Authenticate Runner incarnation and extend one Run in one lock domain."""

        checked_at = now or _utcnow()
        _validate_time(checked_at)
        with self._session_factory.begin() as db:
            _pool, runner = self._lock_pool_then_runner(db, runner_id)
            self._require_authenticated_run(
                db,
                runner=runner,
                connection_generation=connection_generation,
                connection_token=connection_token,
                run_id=run_id,
                capability_token=capability_token,
                checked_at=checked_at,
            )
            return execution.heartbeat_in_transaction(
                db,
                run_id=run_id,
                lease_token=lease_token,
                fence_token=fence_token,
                lease_duration=lease_duration,
                now=checked_at,
            )

    def authenticated_run_transition(
        self,
        execution: ExecutionControlPlane,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        lease_token: UUID,
        fence_token: int,
        capability_token: str,
        target_status: str,
        trace_id: str,
        now: datetime | None = None,
    ) -> RunMutation:
        """Authenticate Runner incarnation and mutate one Run in one transaction."""

        checked_at = now or _utcnow()
        _validate_time(checked_at)
        with self._session_factory.begin() as db:
            _pool, runner = self._lock_pool_then_runner(db, runner_id)
            self._require_authenticated_run(
                db,
                runner=runner,
                connection_generation=connection_generation,
                connection_token=connection_token,
                run_id=run_id,
                capability_token=capability_token,
                checked_at=checked_at,
            )
            return execution.transition_run_in_transaction(
                db,
                run_id=run_id,
                lease_token=lease_token,
                fence_token=fence_token,
                target_status=target_status,
                payload=None,
                trace_id=trace_id,
                now=checked_at,
            )

    def _require_authenticated_run(
        self,
        db: Session,
        *,
        runner: RunnerRegistrationRecord,
        connection_generation: int,
        connection_token: str,
        run_id: UUID,
        capability_token: str,
        checked_at: datetime,
    ) -> VerifiedCapability:
        self._require_runner_connection(
            runner,
            connection_generation=connection_generation,
            connection_token=connection_token,
        )
        if runner.status not in {"online", "draining"}:
            raise SchedulingError("runner_unavailable", "Runner is not heartbeat-eligible")
        runner.last_heartbeat_at = checked_at
        digest = _token_hash(_text(capability_token, field="capability_token", maximum=512))
        return self._verify_capability_in_transaction(
            db,
            digest=digest,
            runner=runner,
            run_id=run_id,
            requested_action="run.execute",
            required_scope={"run_id": str(run_id)},
            checked_at=checked_at,
            lock=True,
        )

    def _verify_capability_in_transaction(
        self,
        db: Session,
        *,
        digest: str,
        runner: RunnerRegistrationRecord,
        run_id: UUID,
        requested_action: str,
        required_scope: dict[str, str],
        checked_at: datetime,
        lock: bool,
    ) -> VerifiedCapability:
        query = sa.select(CapabilityTokenRecord).where(CapabilityTokenRecord.token_hash == digest)
        if lock:
            query = query.with_for_update()
        capability = db.scalar(query)
        if capability is None:
            raise SchedulingError("capability_invalid", "Capability is invalid")
        if capability.revoked_at is not None or _aware(capability.expires_at) <= checked_at:
            raise SchedulingError("capability_expired", "Capability is expired or revoked")
        if capability.runner_id != runner.id or capability.run_id != run_id:
            raise SchedulingError("capability_binding_invalid", "Capability binding is invalid")
        if requested_action not in capability.allowed_actions:
            raise SchedulingError("capability_action_denied", "Capability action is denied")
        for key, value in required_scope.items():
            if capability.resource_scope.get(key) != value:
                raise SchedulingError(
                    "capability_scope_denied", "Capability resource scope is denied"
                )
        run = self._run(db, run_id, lock=lock)
        dispatch_query = sa.select(RunDispatchRecord).where(RunDispatchRecord.run_id == run_id)
        if lock:
            dispatch_query = dispatch_query.with_for_update()
        dispatch = db.scalar(dispatch_query)
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
            pool, runner = self._lock_pool_then_runner(db, runner_id)
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
            if (
                dispatch.status != "leased"
                or dispatch.selected_runner_id != runner_id
                or dispatch.pool_id != pool.id
            ):
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
                pool,
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

    def recover_expired_dispatches(
        self,
        *,
        max_fence_token: int = 3,
        limit: int = 100,
        now: datetime | None = None,
    ) -> tuple[UUID, ...]:
        """Atomically recover expired Run leases and their scheduling capacity.

        This is scheduler-authority recovery, not a Runner-authenticated release.
        It deliberately does not accept a raw Runner connection token: that secret
        can disappear with the failed process whose lease is being recovered.  The
        persisted capability row instead binds the exact Runner incarnation,
        dispatch generation, and Run fence that acquired the capacity.

        A normally expired Run is requeued until ``max_fence_token`` is reached;
        cancelling or exhausted Runs become terminal.  The method also reconciles
        the narrow half-recovered state produced by the older execution-only
        sweeper, and releases capacity for a terminal Run whose worker died before
        calling :meth:`release_dispatch`.
        """

        recovered_at = now or _utcnow()
        _validate_time(recovered_at)
        if max_fence_token <= 0 or not 1 <= limit <= 1000:
            raise SchedulingError(
                "dispatch_recovery_policy_invalid",
                "Dispatch recovery limits must be positive and bounded",
            )

        with self._session_factory.begin() as db:
            candidate_query = (
                sa.select(
                    RunDispatchRecord.run_id,
                    RunDispatchRecord.selected_runner_id,
                    RunDispatchRecord.pool_id,
                    RunRecord.tenant_id,
                    RunRecord.space_id,
                    RunRecord.project_id,
                )
                .join(RunRecord, RunRecord.id == RunDispatchRecord.run_id)
                .where(
                    RunDispatchRecord.status == "leased",
                    RunDispatchRecord.recovery_quarantined_at.is_(None),
                    sa.or_(
                        sa.and_(
                            RunRecord.status.in_(tuple(_ACTIVE_RUN_STATUSES)),
                            RunRecord.lease_expires_at.is_not(None),
                            RunRecord.lease_expires_at <= recovered_at,
                        ),
                        sa.and_(
                            RunRecord.status == "queued",
                            RunRecord.lease_token.is_(None),
                            RunRecord.lease_expires_at.is_(None),
                            RunRecord.heartbeat_at.is_(None),
                        ),
                        RunRecord.status.in_(tuple(TERMINAL_RUN_STATUSES)),
                    ),
                )
                .order_by(RunDispatchRecord.run_id)
                .limit(limit)
            )
            candidates = tuple(db.execute(candidate_query))
            recovered: list[UUID] = []
            for (
                run_id,
                selected_runner_id,
                pool_id,
                tenant_id,
                space_id,
                project_id,
            ) in candidates:
                recovered_id: UUID | None = None
                try:
                    with db.begin_nested():
                        recovered_id = self._recover_one_expired_dispatch(
                            db,
                            run_id=run_id,
                            selected_runner_id=selected_runner_id,
                            pool_id=pool_id,
                            max_fence_token=max_fence_token,
                            recovered_at=recovered_at,
                        )
                except SchedulingError as exc:
                    self._quarantine_dispatch_recovery(
                        db,
                        run_id=run_id,
                        tenant_id=tenant_id,
                        space_id=space_id,
                        project_id=project_id,
                        recovered_at=recovered_at,
                        reason=exc.code,
                    )
                    continue
                if recovered_id is not None:
                    recovered.append(recovered_id)
            return tuple(recovered)

    def _recover_one_expired_dispatch(
        self,
        db: Session,
        *,
        run_id: UUID,
        selected_runner_id: UUID | None,
        pool_id: UUID,
        max_fence_token: int,
        recovered_at: datetime,
    ) -> UUID | None:
        # Pool advisory lock is the global leading scheduler lock. Reconnect,
        # claim, release, and recovery all take pool -> Runner -> Dispatch -> Run.
        pool = self._pool(db, pool_id, lock=True)
        if selected_runner_id is None:
            raise SchedulingError(
                "dispatch_recovery_binding_invalid",
                "Leased dispatch is missing its selected Runner",
            )
        runner = self._runner(db, selected_runner_id, lock=True)
        dispatch = db.scalar(
            sa.select(RunDispatchRecord)
            .where(RunDispatchRecord.run_id == run_id)
            .with_for_update()
        )
        if dispatch is None:
            raise SchedulingError("dispatch_not_found", "Run dispatch was not found")
        if dispatch.status != "leased" or dispatch.recovery_quarantined_at is not None:
            return None
        if (
            dispatch.selected_runner_id != runner.id
            or dispatch.pool_id != pool.id
            or dispatch.selected_failure_domain != pool.failure_domain
            or runner.pool_id != pool.id
            or runner.placement_id != pool.placement_id
        ):
            raise SchedulingError(
                "dispatch_recovery_binding_invalid",
                "Dispatch Runner no longer matches its reviewed pool",
            )

        run = self._run(db, run_id, lock=True)
        self._apply_run_context(db, run)
        self._require_dispatch_profile_binding(db, dispatch=dispatch, run=run)
        active_expired = (
            run.status in _ACTIVE_RUN_STATUSES
            and run.lease_expires_at is not None
            and _aware(run.lease_expires_at) <= recovered_at
        )
        legacy_requeued = (
            run.status == "queued"
            and run.lease_token is None
            and run.lease_expires_at is None
            and run.heartbeat_at is None
        )
        terminal = run.status in TERMINAL_RUN_STATUSES
        if not (active_expired or legacy_requeued or terminal):
            return None

        capabilities = tuple(
            db.scalars(
                sa.select(CapabilityTokenRecord)
                .where(
                    CapabilityTokenRecord.run_id == run.id,
                    CapabilityTokenRecord.runner_id == runner.id,
                    CapabilityTokenRecord.dispatch_generation == dispatch.dispatch_generation,
                    CapabilityTokenRecord.fence_token == run.fence_token,
                )
                .with_for_update()
            )
        )
        if len(capabilities) != 1:
            raise SchedulingError(
                "dispatch_recovery_binding_invalid",
                "Dispatch recovery requires one exact persisted capability",
            )
        capability = capabilities[0]
        if capability.runner_connection_generation > runner.connection_generation:
            raise SchedulingError(
                "dispatch_recovery_generation_invalid",
                "Capability Runner generation is newer than the Runner authority",
            )
        if active_expired and _aware(capability.expires_at) != _aware(
            cast(datetime, run.lease_expires_at)
        ):
            raise SchedulingError(
                "dispatch_recovery_lease_invalid",
                "Capability and Run lease expiry do not match",
            )
        if legacy_requeued and _aware(capability.expires_at) > recovered_at:
            raise SchedulingError(
                "dispatch_recovery_lease_invalid",
                "Half-recovered dispatch capability has not expired",
            )

        share = self._queue_share(db, run.tenant_id, pool, lock=True)
        if share is None or share.active_leases <= 0 or runner.active_leases <= 0:
            raise SchedulingError(
                "dispatch_counter_inconsistent",
                "Dispatch capacity counters are inconsistent",
            )

        if active_expired:
            if run.status == "cancelling":
                target_status = "cancelled"
            elif run.fence_token >= max_fence_token:
                target_status = "orphaned"
            else:
                target_status = "queued"
            run.status = target_status
            run.version += 1
            if target_status in TERMINAL_RUN_STATUSES:
                run.terminal_at = recovered_at
                ExecutionControlPlane._finalize_reservations(db, run, succeeded=False)
            ExecutionControlPlane._clear_lease(run)
            ExecutionControlPlane._append_event(
                db,
                run,
                event_type=f"run.{target_status}",
                payload={
                    "status": target_status,
                    "reason": "lease_expired",
                    "expired_fence_token": run.fence_token,
                    "dispatch_generation": dispatch.dispatch_generation,
                    "runner_connection_generation": capability.runner_connection_generation,
                },
                trace_id="scheduler:lease-expired",
            )

        share.active_leases -= 1
        share.version += 1
        runner.active_leases -= 1
        terminal = run.status in TERMINAL_RUN_STATUSES
        self._revoke_run_capabilities(
            db,
            run.id,
            revoked_at=recovered_at,
            reason="run_terminal" if terminal else "run_requeued",
        )
        if terminal:
            dispatch.status = "released"
            dispatch.released_at = recovered_at
        else:
            dispatch.status = "pending"
            dispatch.selected_runner_id = None
            dispatch.selected_failure_domain = None
            dispatch.released_at = None
            dispatch.dead_letter_reason = None
        return run.id

    @classmethod
    def _quarantine_dispatch_recovery(
        cls,
        db: Session,
        *,
        run_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        recovered_at: datetime,
        reason: str,
    ) -> None:
        apply_rls_context(
            db,
            RlsContext(tenant_id=tenant_id, space_id=space_id, project_id=project_id),
        )
        dispatch = db.scalar(
            sa.select(RunDispatchRecord)
            .where(RunDispatchRecord.run_id == run_id)
            .with_for_update()
        )
        if (
            dispatch is not None
            and dispatch.status == "leased"
            and dispatch.recovery_quarantined_at is None
        ):
            run = db.get(RunRecord, run_id)
            cls._record_dispatch_quarantine(
                db,
                dispatch=dispatch,
                run=run,
                quarantined_at=recovered_at,
                reason=reason,
                source="recovery",
            )

    @staticmethod
    def _record_dispatch_quarantine(
        db: Session,
        *,
        dispatch: RunDispatchRecord,
        run: RunRecord | None,
        quarantined_at: datetime,
        reason: str,
        source: str,
    ) -> None:
        if dispatch.recovery_quarantined_at is not None:
            return
        safe_reason = _text(reason, field="dispatch_quarantine_reason", maximum=128)
        safe_source = _text(source, field="dispatch_quarantine_source", maximum=32)
        forensic_context: dict[str, object] = {
            "tenant_id": str(dispatch.tenant_id),
            "space_id": str(dispatch.space_id),
            "project_id": str(dispatch.project_id),
            "run_id": str(dispatch.run_id),
            "pool_id": str(dispatch.pool_id),
            "execution_profile_id": str(dispatch.execution_profile_id),
            "execution_profile_hash": dispatch.execution_profile_hash,
            "egress_policy_id": str(dispatch.egress_policy_id),
            "egress_policy_hash": dispatch.egress_policy_hash,
            "requirements_hash": dispatch.requirements_hash,
            "dispatch_generation": dispatch.dispatch_generation,
            "dispatch_status": dispatch.status,
            "selected_runner_id": (
                str(dispatch.selected_runner_id)
                if dispatch.selected_runner_id is not None
                else None
            ),
            "run_fence_token": run.fence_token if run is not None else None,
            "capacity_policy": (
                "retained_until_reconciliation" if dispatch.status == "leased" else "not_acquired"
            ),
            "reason": safe_reason,
            "source": safe_source,
        }
        payload = {
            **forensic_context,
            "forensic_hash": _canonical_hash(forensic_context),
            "quarantined_at": _aware(quarantined_at).isoformat(),
        }
        dispatch.recovery_quarantined_at = quarantined_at
        dispatch.recovery_quarantine_reason = safe_reason
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=dispatch.tenant_id,
                aggregate_type="run_dispatch",
                aggregate_key=str(dispatch.run_id),
                event_type="run.dispatch.quarantined",
                payload=payload,
                idempotency_key=(
                    f"run-dispatch-quarantine:{dispatch.run_id}:"
                    f"{dispatch.dispatch_generation}:{safe_source}"
                ),
                request_hash=_canonical_hash(payload),
                attempt_count=0,
                available_at=quarantined_at,
            )
        )
        # The scheduler may continue into a different tenant scope in this
        # transaction; persist this exact-scope quarantine before changing GUCs.
        db.flush()

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
                RunDispatchRecord.recovery_quarantined_at.is_(None),
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
                    RunDispatchRecord.recovery_quarantined_at.is_(None),
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
                    self._apply_run_context(db, run)
                    try:
                        self._require_dispatch_profile_binding(
                            db,
                            dispatch=dispatch,
                            run=run,
                        )
                    except SchedulingError as exc:
                        self._record_dispatch_quarantine(
                            db,
                            dispatch=dispatch,
                            run=run,
                            quarantined_at=claimed_at,
                            reason=exc.code,
                            source="claim",
                        )
                        continue
                    return share, dispatch, run
        return None

    @staticmethod
    def _dispatch_requirements_hash(
        *,
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        pool_id: UUID,
        execution_profile_id: UUID,
        execution_profile_hash: str,
        egress_policy_id: UUID,
        egress_policy_hash: str,
        queue_class: str,
        required_capabilities: list[str],
        cost_units: int,
        eligible_at: datetime,
        max_wait_at: datetime,
    ) -> str:
        return _canonical_dispatch_requirements_hash(
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            pool_id=pool_id,
            execution_profile_id=execution_profile_id,
            execution_profile_hash=execution_profile_hash,
            egress_policy_id=egress_policy_id,
            egress_policy_hash=egress_policy_hash,
            queue_class=queue_class,
            required_capabilities=required_capabilities,
            cost_units=cost_units,
            eligible_at=eligible_at,
            max_wait_at=max_wait_at,
        )

    @classmethod
    def _require_dispatch_profile_binding(
        cls,
        db: Session,
        *,
        dispatch: RunDispatchRecord,
        run: RunRecord,
    ) -> ExecutionProfileRecord:
        """Revalidate the immutable server-selected profile before side effects."""

        try:
            profile_hash = _hash64(
                dispatch.execution_profile_hash,
                field="dispatch_execution_profile_hash",
            )
            egress_policy_hash = _hash64(
                dispatch.egress_policy_hash,
                field="dispatch_egress_policy_hash",
            )
        except (AttributeError, TypeError, SchedulingError) as exc:
            raise SchedulingError(
                "dispatch_execution_profile_binding_invalid",
                "Dispatch execution profile binding is malformed",
            ) from exc
        query = cls._dispatch_profile_query(
            dispatch.execution_profile_id,
            dispatch.egress_policy_id,
        ).with_for_update(read=True)
        binding = db.execute(query).one_or_none()
        if binding is None:
            raise SchedulingError(
                "dispatch_execution_profile_invalid",
                "Dispatch execution profile is unavailable or outside the Run scope",
            )
        profile, egress_policy = binding
        if (
            profile.status not in {"active", "retired"}
            or egress_policy.status not in {"active", "retired"}
            or egress_policy.allow_private_destinations
            or profile.egress_policy_id != egress_policy.id
            or profile.tenant_id != run.tenant_id
            or profile.space_id != run.space_id
            or profile.project_id != run.project_id
            or egress_policy.tenant_id != run.tenant_id
            or egress_policy.space_id != run.space_id
            or egress_policy.project_id != run.project_id
            or dispatch.tenant_id != run.tenant_id
            or dispatch.space_id != run.space_id
            or dispatch.project_id != run.project_id
        ):
            raise SchedulingError(
                "dispatch_execution_profile_invalid",
                "Dispatch execution profile is unavailable or outside the Run scope",
            )
        if profile.config_hash != profile_hash:
            raise SchedulingError(
                "dispatch_execution_profile_hash_mismatch",
                "Dispatch execution profile hash is not current",
            )
        if egress_policy.rules_hash != egress_policy_hash:
            raise SchedulingError(
                "dispatch_egress_policy_hash_mismatch",
                "Dispatch egress policy hash is not current",
            )
        expected_hash = cls._dispatch_requirements_hash(
            tenant_id=dispatch.tenant_id,
            space_id=dispatch.space_id,
            project_id=dispatch.project_id,
            pool_id=dispatch.pool_id,
            execution_profile_id=profile.id,
            execution_profile_hash=profile_hash,
            egress_policy_id=egress_policy.id,
            egress_policy_hash=egress_policy_hash,
            queue_class=dispatch.queue_class,
            required_capabilities=dispatch.required_capabilities,
            cost_units=dispatch.cost_units,
            eligible_at=dispatch.eligible_at,
            max_wait_at=dispatch.max_wait_at,
        )
        if dispatch.requirements_hash != expected_hash:
            raise SchedulingError(
                "dispatch_requirements_hash_mismatch",
                "Dispatch requirements are not bound to the selected execution profile",
            )
        return profile

    @staticmethod
    def _dispatch_profile_query(
        execution_profile_id: UUID,
        egress_policy_id: UUID,
    ) -> sa.Select[tuple[ExecutionProfileRecord, EgressPolicyRecord]]:
        """Select one exact persisted profile and egress policy as a lockable unit."""

        return (
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
                ExecutionProfileRecord.id == execution_profile_id,
                EgressPolicyRecord.id == egress_policy_id,
                EgressPolicyRecord.allow_private_destinations.is_(False),
            )
        )

    @classmethod
    def _resolve_dispatch_profile_binding(
        cls,
        db: Session,
        run: RunRecord,
    ) -> tuple[ExecutionProfileRecord, EgressPolicyRecord]:
        query = (
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
        bindings = tuple(db.execute(query))
        if not bindings:
            raise SchedulingError(
                "dispatch_execution_profile_invalid",
                "Run scope has no active execution profile",
            )
        if len(bindings) != 1:
            raise SchedulingError(
                "dispatch_execution_profile_ambiguous",
                "Run scope must have exactly one active execution profile",
            )
        profile, egress_policy = bindings[0]
        if (
            profile.network_mode != "proxy_only"
            or not profile.root_read_only
            or profile.run_as_uid <= 0
            or profile.run_as_gid <= 0
            or not profile.no_new_privileges
            or profile.host_socket_access
        ):
            raise SchedulingError(
                "dispatch_execution_profile_unsafe",
                "Run execution profile does not satisfy the managed safety contract",
            )
        return profile, egress_policy

    @staticmethod
    def _apply_run_context(db: Session, run: RunRecord) -> None:
        apply_rls_context(
            db,
            RlsContext(
                tenant_id=run.tenant_id,
                space_id=run.space_id,
                project_id=run.project_id,
            ),
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

    @classmethod
    def _lock_pool_then_runner(
        cls,
        db: Session,
        runner_id: UUID,
    ) -> tuple[RunnerPoolRecord, RunnerRegistrationRecord]:
        """Take every pool/Runner mutation lock in one global order.

        ``pool_id`` is immutable for a Runner registration. The leading read is
        deliberately unlocked; both rows are re-read and the binding is checked
        after the pool advisory lock has serialized reconnect, claim, release,
        and scheduler recovery.
        """

        pool_id = db.scalar(
            sa.select(RunnerRegistrationRecord.pool_id).where(
                RunnerRegistrationRecord.id == runner_id
            )
        )
        if pool_id is None:
            raise SchedulingError("runner_not_found", "Runner was not found")
        pool = cls._pool(db, pool_id, lock=True)
        runner = cls._runner(db, runner_id, lock=True)
        if runner.pool_id != pool.id:
            raise SchedulingError(
                "runner_pool_binding_invalid",
                "Runner pool binding changed while acquiring scheduler locks",
            )
        return pool, runner

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
