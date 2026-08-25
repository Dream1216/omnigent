"""Durable vertical Tenant-onboarding Saga and compensation authority.

The workflow advances one short, idempotent stage per Outbox wake-up.  It never
temporarily activates a Tenant in order to reuse customer-facing APIs, and all
official-runtime effects are delegated to an idempotent deployment adapter.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
from typing import Protocol, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.billing_models import (
    BillingBalanceRecord,
    BillingEntitlementRecord,
    BillingSubscriptionRecord,
    PricingSnapshotRecord,
)
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    ProjectMembershipRecord,
    ProjectRecord,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
    Space,
    Tenant,
)
from saas.control_plane.execution_models import (
    AdmissionQuotaRecord,
    QuotaReservationRecord,
    RunEventRecord,
    RunRecord,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.onboarding_models import (
    SelfServiceEventRecord,
    TenantOnboardingRecord,
)
from saas.control_plane.rls import (
    OnboardingRlsContext,
    RlsContext,
    apply_onboarding_rls_context,
    apply_rls_context,
)

_ZERO_HASH = "0" * 64
_REQUESTED_EVENT_BY_STATUS = {
    "billing_ready": "onboarding.runtime.requested",
    "runtime_ready": "onboarding.project.requested",
    "project_ready": "onboarding.activation.requested",
    "compensating": "onboarding.compensation.requested",
}
_WORKFLOW_EVENT_TYPES = frozenset(
    {
        "onboarding.billing.requested",
        "onboarding.runtime.requested",
        "onboarding.project.requested",
        "onboarding.activation.requested",
        "onboarding.compensation.requested",
    }
)
_EXPECTED_STATUS_BY_EVENT = {
    "onboarding.billing.requested": "tenant_created",
    "onboarding.runtime.requested": "billing_ready",
    "onboarding.project.requested": "runtime_ready",
    "onboarding.activation.requested": "project_ready",
    "onboarding.compensation.requested": "compensating",
}
_STATUS_ORDER = {
    "tenant_created": 0,
    "billing_ready": 1,
    "runtime_ready": 2,
    "project_ready": 3,
    "active": 4,
    "completed": 5,
}
_TERMINAL_STATUSES = frozenset({"completed", "compensated", "manual_review"})
_WAITING_STATUSES = frozenset({"active"})
_SAFE_ERROR_DETAILS = {
    "billing_bootstrap_failed": "billing bootstrap did not complete",
    "runtime_allocation_failed": "runtime allocation did not complete",
    "runtime_partition_conflict": "runtime partition evidence is inconsistent",
    "runtime_project_failed": "runtime project provisioning did not complete",
    "activation_precondition_failed": "activation preconditions are incomplete",
    "compensation_failed": "compensation did not complete",
    "onboarding_internal_error": "onboarding stage did not complete",
}


class OnboardingWorkflowError(RuntimeError):
    """Stable workflow failure without provider payloads or customer secrets."""

    def __init__(self, code: str, message: str, *, retryable: bool = True) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class OnboardingScope:
    """Exact server-derived Saga identity used to bind PostgreSQL RLS GUCs."""

    onboarding_id: UUID
    registration_id: UUID
    actor_id: UUID
    tenant_id: UUID


@dataclass(frozen=True, slots=True)
class RuntimeProviderBindingSnapshot:
    """Non-secret Provider identity frozen before the first external effect."""

    provider_type: str
    binding_revision: str
    binding_hash: str

    def __post_init__(self) -> None:
        if not self.provider_type.strip() or len(self.provider_type) > 128:
            raise ValueError("Runtime Provider type is invalid")
        if not self.binding_revision.strip() or len(self.binding_revision) > 128:
            raise ValueError("Runtime Provider binding revision is invalid")
        if len(self.binding_hash) != 64 or any(
            character not in "0123456789abcdef" for character in self.binding_hash
        ):
            raise ValueError("Runtime Provider binding hash is invalid")


@dataclass(frozen=True, slots=True)
class RuntimePartitionTarget:
    """Server-selected Placement facts passed to the official-runtime adapter."""

    onboarding_id: UUID
    tenant_id: UUID
    space_id: UUID
    user_id: UUID
    runtime_partition_id: UUID
    placement_id: UUID
    runtime_type: str
    data_region: str
    failure_domain: str
    official_schema_revision: str
    capacity_class: str
    provider_binding: RuntimeProviderBindingSnapshot


@dataclass(frozen=True, slots=True)
class RuntimePartitionAllocation:
    """Non-secret receipt returned by an idempotent Runtime allocation."""

    runtime_version: str
    physical_partition_key: str
    placement_generation: int
    source_revision: str
    adapter_contract_version: str
    runtime_user_key: str
    receipt_hash: str


@dataclass(frozen=True, slots=True)
class RuntimeProjectTarget:
    """Trusted default-Project facts passed to the official Runtime."""

    partition: RuntimePartitionTarget
    project_id: UUID
    project_name: str


@dataclass(frozen=True, slots=True)
class RuntimeProjectAllocation:
    """Official Project identity and hash-only provisioning receipt."""

    runtime_resource_id: str
    receipt_hash: str


class RuntimePartitionProvisioner(Protocol):
    """Placement adapter; every method must deduplicate by ``idempotency_key``."""

    def binding_snapshot(self, placement_id: UUID) -> RuntimeProviderBindingSnapshot: ...

    def allocate_partition(
        self, *, target: RuntimePartitionTarget, idempotency_key: str
    ) -> RuntimePartitionAllocation: ...

    def provision_default_project(
        self, *, target: RuntimeProjectTarget, idempotency_key: str
    ) -> RuntimeProjectAllocation: ...

    def compensate_default_project(
        self, *, target: RuntimeProjectTarget, idempotency_key: str
    ) -> None: ...

    def compensate_partition(
        self, *, target: RuntimePartitionTarget, idempotency_key: str
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class OnboardingWorkflowResult:
    onboarding_id: UUID
    status: str
    project_id: UUID
    first_run_id: UUID | None
    version: int
    attempt_count: int
    available_at: datetime
    replayed: bool


@dataclass(frozen=True, slots=True)
class _Claim:
    scope: OnboardingScope
    token: UUID
    status: str
    version: int
    attempt_count: int
    space_id: UUID
    user_id: UUID
    project_id: UUID
    runtime_partition_id: UUID
    runtime_placement_id: UUID | None
    runtime_target_snapshot: dict[str, object] | None
    runtime_request_hash: str | None
    plan_snapshot: dict[str, object]


@dataclass(frozen=True, slots=True)
class _PlanTerms:
    trial_days: int
    currency: str
    trial_run_limit: int
    trial_concurrency_limit: int
    runtime_type: str
    capacity_class: str
    default_project_name: str
    default_project_visibility: str
    quota_resource: str
    quota_limit: int

    @classmethod
    def load(cls, saga: TenantOnboardingRecord) -> _PlanTerms:
        payload = saga.plan_snapshot
        if not isinstance(payload, dict):
            raise OnboardingWorkflowError(
                "plan_snapshot_invalid", "plan snapshot is invalid", retryable=False
            )
        if not hmac.compare_digest(_digest(payload), saga.plan_snapshot_hash):
            raise OnboardingWorkflowError(
                "plan_snapshot_invalid", "plan snapshot hash is invalid", retryable=False
            )
        try:
            terms = cls(
                trial_days=int(payload.get("trial_days", saga.trial_days)),
                currency=str(payload.get("currency", "USD")).upper(),
                trial_run_limit=int(payload.get("trial_run_limit", 100)),
                trial_concurrency_limit=int(payload.get("trial_concurrency_limit", 2)),
                runtime_type=str(payload.get("runtime_type", "omnigent")),
                capacity_class=str(payload.get("capacity_class", "starter")),
                default_project_name=str(payload.get("default_project_name", "Getting Started")),
                default_project_visibility=str(
                    payload.get("default_project_visibility", "private")
                ),
                quota_resource=str(payload.get("quota_resource", "interactive_runs")),
                quota_limit=int(payload.get("quota_limit", 100)),
            )
        except (TypeError, ValueError) as error:
            raise OnboardingWorkflowError(
                "plan_snapshot_invalid", "plan snapshot values are invalid", retryable=False
            ) from error
        terms.validate()
        return terms

    def validate(self) -> None:
        if not 1 <= self.trial_days <= 90 or len(self.currency) != 3:
            raise OnboardingWorkflowError(
                "plan_snapshot_invalid", "plan trial terms are invalid", retryable=False
            )
        if self.trial_run_limit < 1 or self.trial_concurrency_limit < 1:
            raise OnboardingWorkflowError(
                "plan_snapshot_invalid", "plan entitlement terms are invalid", retryable=False
            )
        if self.quota_limit < 1:
            raise OnboardingWorkflowError(
                "plan_snapshot_invalid", "plan quota is invalid", retryable=False
            )
        bounded = (
            (self.runtime_type, 64),
            (self.capacity_class, 64),
            (self.default_project_name, 256),
            (self.quota_resource, 64),
        )
        if any(not value.strip() or len(value) > maximum for value, maximum in bounded):
            raise OnboardingWorkflowError(
                "plan_snapshot_invalid", "plan text is invalid", retryable=False
            )
        if self.default_project_visibility not in {"private", "space", "restricted"}:
            raise OnboardingWorkflowError(
                "plan_snapshot_invalid", "plan visibility is invalid", retryable=False
            )


class TenantOnboardingWorkflow:
    """Advance one fenced Saga stage and schedule the next durable wake-up."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        runtime: RuntimePartitionProvisioner,
        execution_session_factory: sessionmaker[Session],
        lease_duration: timedelta = timedelta(minutes=2),
        max_attempts: int = 3,
        retry_base: timedelta = timedelta(seconds=5),
    ) -> None:
        if lease_duration <= timedelta(0):
            raise ValueError("onboarding lease duration must be positive")
        if max_attempts < 1:
            raise ValueError("onboarding max attempts must be positive")
        if retry_base <= timedelta(0):
            raise ValueError("onboarding retry base must be positive")
        self._sessions = session_factory
        self._execution_sessions = execution_session_factory
        self._runtime = runtime
        self._lease_duration = lease_duration
        self._max_attempts = max_attempts
        self._retry_base = retry_base

    def handle_event(
        self,
        *,
        event_type: str,
        payload: dict[str, object],
    ) -> OnboardingWorkflowResult:
        """Consume one server-authored Outbox wake-up and reject route confusion."""

        if event_type not in _WORKFLOW_EVENT_TYPES:
            raise OnboardingWorkflowError(
                "onboarding_event_invalid", "onboarding event is invalid", retryable=False
            )
        scope = onboarding_scope_from_payload(payload)
        expected_status = _EXPECTED_STATUS_BY_EVENT[event_type]
        payload_status = payload.get("expected_status")
        if not isinstance(payload_status, str) or payload_status != expected_status:
            raise OnboardingWorkflowError(
                "onboarding_event_invalid", "onboarding event is invalid", retryable=False
            )
        payload_version = payload.get("version")
        if (
            not isinstance(payload_version, int)
            or isinstance(payload_version, bool)
            or payload_version < 1
        ):
            raise OnboardingWorkflowError(
                "onboarding_event_invalid", "onboarding event is invalid", retryable=False
            )
        return self.advance(
            scope,
            expected_status=expected_status,
            expected_version=payload_version,
        )

    def status(self, scope: OnboardingScope) -> OnboardingWorkflowResult:
        """Return the owner-scoped, secret-free durable journey state."""

        with self._sessions() as db:
            self._apply_scope(db, scope)
            return self._result(self._saga(db, scope, lock=False), replayed=True)

    def advance(
        self,
        scope: OnboardingScope,
        *,
        now: datetime | None = None,
        expected_status: str | None = None,
        expected_version: int | None = None,
    ) -> OnboardingWorkflowResult:
        """Claim and execute at most one stage; terminal/waiting stages replay safely."""

        effective_now = _stored_time(now or datetime.now(timezone.utc))
        claim, replay = self._claim(
            scope,
            effective_now,
            expected_status=expected_status,
            expected_version=expected_version,
        )
        if claim is None:
            return replay
        try:
            if claim.status == "tenant_created":
                return self._bootstrap_billing(claim, effective_now)
            if claim.status == "billing_ready":
                return self._allocate_runtime(claim, effective_now)
            if claim.status == "runtime_ready":
                return self._bootstrap_project(claim, effective_now)
            if claim.status == "project_ready":
                return self._activate(claim, effective_now)
            if claim.status == "compensating":
                return self._compensate(claim, effective_now)
            raise OnboardingWorkflowError(
                "onboarding_state_invalid", "onboarding state is invalid", retryable=False
            )
        except OnboardingWorkflowError as error:
            return self._record_failure(claim, error, effective_now)
        except Exception:  # noqa: BLE001 - convert unknown provider/DB failures to stable evidence
            return self._record_failure(
                claim,
                OnboardingWorkflowError(
                    "onboarding_internal_error",
                    _SAFE_ERROR_DETAILS["onboarding_internal_error"],
                ),
                effective_now,
            )

    def record_first_run(
        self,
        scope: OnboardingScope,
        *,
        run_id: UUID,
        now: datetime | None = None,
    ) -> OnboardingWorkflowResult:
        """Close the customer journey only after a real, normally admitted user Run."""

        occurred_at = _stored_time(now or datetime.now(timezone.utc))
        with self._sessions() as db:
            self._apply_scope(db, scope)
            saga = self._saga(db, scope, lock=False)
            if saga.status == "completed":
                if saga.first_run_id != run_id:
                    raise OnboardingWorkflowError(
                        "first_run_conflict",
                        "another first Run is already recorded",
                        retryable=False,
                    )
                return self._result(saga, replayed=True)
            if saga.status != "active":
                raise OnboardingWorkflowError(
                    "onboarding_not_active", "Tenant onboarding is not active", retryable=False
                )
            project_id = saga.default_project_id
            actor_id = saga.user_id
            tenant_id = saga.tenant_id
            space_id = saga.space_id
            activated_at = cast(datetime, saga.activated_at)
        with self._execution_sessions.begin() as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=actor_id,
                    tenant_id=tenant_id,
                    space_id=space_id,
                    project_id=project_id,
                ),
            )
            run = db.scalar(
                sa.select(RunRecord).where(
                    RunRecord.id == run_id,
                    RunRecord.tenant_id == tenant_id,
                    RunRecord.space_id == space_id,
                    RunRecord.project_id == project_id,
                    RunRecord.created_by == actor_id,
                )
            )
            reservation_id = db.scalar(
                sa.select(QuotaReservationRecord.id).where(
                    QuotaReservationRecord.run_id == run_id,
                    QuotaReservationRecord.tenant_id == tenant_id,
                    QuotaReservationRecord.space_id == space_id,
                    QuotaReservationRecord.project_id == project_id,
                )
            )
            queued_event_id = db.scalar(
                sa.select(RunEventRecord.id).where(
                    RunEventRecord.run_id == run_id,
                    RunEventRecord.tenant_id == tenant_id,
                    RunEventRecord.space_id == space_id,
                    RunEventRecord.project_id == project_id,
                    RunEventRecord.event_type == "run.queued",
                )
            )
            if (
                run is None
                or run.status == "created"
                # PostgreSQL server timestamps and the application clock can
                # differ slightly.  Project suspension before activation and
                # the normal admission evidence provide the causal boundary;
                # this tolerance only absorbs bounded clock skew.
                or _stored_time(run.created_at) + timedelta(seconds=5) < _stored_time(activated_at)
                or reservation_id is None
                or queued_event_id is None
            ):
                raise OnboardingWorkflowError(
                    "first_run_not_admitted",
                    "first Run admission evidence is not accessible",
                    retryable=False,
                )
        with self._sessions.begin() as db:
            self._apply_scope(db, scope)
            saga = self._saga(db, scope, lock=True)
            if saga.status == "completed":
                if saga.first_run_id != run_id:
                    raise OnboardingWorkflowError(
                        "first_run_conflict",
                        "another first Run is already recorded",
                        retryable=False,
                    )
                return self._result(saga, replayed=True)
            if saga.status != "active":
                raise OnboardingWorkflowError(
                    "onboarding_not_active", "Tenant onboarding is not active", retryable=False
                )
            previous = saga.status
            saga.status = "completed"
            saga.first_run_id = run_id
            saga.completed_at = occurred_at
            saga.last_transition_at = occurred_at
            saga.version += 1
            self._append_event(
                db,
                saga=saga,
                event_type="tenant_onboarding.first_run_admitted",
                from_status=previous,
                to_status="completed",
                facts={"project_id": str(saga.default_project_id), "run_id": str(run_id)},
                occurred_at=occurred_at,
            )
            db.flush()
            return self._result(saga, replayed=False)

    def _claim(
        self,
        scope: OnboardingScope,
        now: datetime,
        *,
        expected_status: str | None = None,
        expected_version: int | None = None,
    ) -> tuple[_Claim | None, OnboardingWorkflowResult]:
        with self._sessions.begin() as db:
            self._apply_scope(db, scope)
            saga = self._saga(db, scope, lock=True)
            if expected_status is not None and saga.status != expected_status:
                current_order = _STATUS_ORDER.get(saga.status)
                expected_order = _STATUS_ORDER.get(expected_status)
                if (
                    saga.status in _TERMINAL_STATUSES | _WAITING_STATUSES
                    or (saga.status == "compensating" and expected_status != "compensating")
                    or (
                        current_order is not None
                        and expected_order is not None
                        and current_order > expected_order
                    )
                ):
                    return None, self._result(saga, replayed=True)
                raise OnboardingWorkflowError(
                    "onboarding_event_stale",
                    "onboarding event does not match the durable Saga state",
                    retryable=False,
                )
            if expected_version is not None and saga.version != expected_version:
                if saga.version > expected_version:
                    return None, self._result(saga, replayed=True)
                raise OnboardingWorkflowError(
                    "onboarding_event_stale",
                    "onboarding event version is ahead of the durable Saga state",
                    retryable=False,
                )
            if saga.status in _TERMINAL_STATUSES | _WAITING_STATUSES:
                return None, self._result(saga, replayed=True)
            available_at = _stored_time(saga.available_at)
            if available_at > now:
                if expected_status is not None:
                    raise OnboardingWorkflowError(
                        "onboarding_not_due",
                        "onboarding stage is not due",
                        retryable=True,
                    )
                return None, self._result(saga, replayed=True)
            if saga.claim_token is not None:
                lease_expires_at = _stored_time(cast(datetime, saga.lease_expires_at))
                if lease_expires_at > now:
                    if expected_status is not None:
                        raise OnboardingWorkflowError(
                            "onboarding_claim_active",
                            "onboarding stage is already claimed",
                            retryable=True,
                        )
                    return None, self._result(saga, replayed=True)
                saga.claim_token = None
                saga.claimed_at = None
                saga.lease_expires_at = None
            token = uuid4()
            saga.claim_token = token
            saga.claimed_at = now
            saga.lease_expires_at = now + self._lease_duration
            saga.attempt_count += 1
            saga.version += 1
            # The source Outbox message can be acknowledged after this claim
            # commits.  Persist a second wake-up at the Saga lease boundary so
            # a worker crash can never strand the journey.
            self._enqueue(
                db,
                saga,
                self._requested_event_for(saga.status),
                cast(datetime, saga.lease_expires_at),
            )
            claim = _Claim(
                scope=scope,
                token=token,
                status=saga.status,
                version=saga.version,
                attempt_count=saga.attempt_count,
                space_id=saga.space_id,
                user_id=saga.user_id,
                project_id=saga.default_project_id,
                runtime_partition_id=saga.runtime_partition_id,
                runtime_placement_id=saga.runtime_placement_id,
                runtime_target_snapshot=(
                    dict(saga.runtime_target_snapshot)
                    if saga.runtime_target_snapshot is not None
                    else None
                ),
                runtime_request_hash=saga.runtime_request_hash,
                plan_snapshot=dict(saga.plan_snapshot),
            )
            db.flush()
            return claim, self._result(saga, replayed=False)

    def _bootstrap_billing(self, claim: _Claim, now: datetime) -> OnboardingWorkflowResult:
        with self._sessions.begin() as db:
            saga = self._claimed_saga(db, claim, now)
            terms = _PlanTerms.load(saga)
            subscription = db.get(BillingSubscriptionRecord, saga.subscription_id)
            if subscription is not None:
                self._require_exact(subscription.tenant_id == saga.tenant_id)
            else:
                provisional_end = now + timedelta(days=terms.trial_days)
                db.add(
                    BillingSubscriptionRecord(
                        id=saga.subscription_id,
                        tenant_id=saga.tenant_id,
                        plan_key=saga.plan_key,
                        status="trialing",
                        current_period_start=now,
                        current_period_end=provisional_end,
                        trial_ends_at=provisional_end,
                        cancel_at_period_end=False,
                        version=1,
                        updated_by=saga.user_id,
                    )
                )
                # The entitlement has a composite FK to the preallocated
                # subscription.  Flush the parent explicitly because these
                # independently owned models intentionally define no ORM
                # relationship that would otherwise order the unit of work.
                db.flush()
                db.add(
                    PricingSnapshotRecord(
                        id=saga.pricing_snapshot_id,
                        tenant_id=saga.tenant_id,
                        plan_key=saga.plan_key,
                        currency=terms.currency,
                        rates={
                            terms.quota_resource: {
                                "unit": "run",
                                "price_minor": 0,
                            }
                        },
                        version=1,
                        effective_from=now,
                        effective_until=None,
                        created_by=saga.user_id,
                    )
                )
                db.add(
                    BillingEntitlementRecord(
                        id=saga.entitlement_id,
                        tenant_id=saga.tenant_id,
                        subscription_id=saga.subscription_id,
                        scope_type="tenant",
                        scope_key=str(saga.tenant_id),
                        meter=terms.quota_resource,
                        unit="run",
                        limit_quantity=Decimal(terms.trial_run_limit),
                        reserved_quantity=Decimal(0),
                        consumed_quantity=Decimal(0),
                        concurrency_limit=terms.trial_concurrency_limit,
                        active_reservations=0,
                        hard_limit=True,
                        period="none",
                        period_start=now,
                        period_end=provisional_end,
                        status="active",
                        version=1,
                        updated_by=saga.user_id,
                    )
                )
                db.add(
                    BillingBalanceRecord(
                        tenant_id=saga.tenant_id,
                        currency=terms.currency,
                        available_minor=0,
                        reserved_minor=0,
                        consumed_minor=0,
                        version=1,
                    )
                )
            saga.billing_ready_at = now
            return self._transition(
                db,
                saga,
                to_status="billing_ready",
                event_type="tenant_onboarding.billing_ready",
                facts={
                    "subscription_id": str(saga.subscription_id),
                    "pricing_snapshot_id": str(saga.pricing_snapshot_id),
                    "entitlement_id": str(saga.entitlement_id),
                    "plan_snapshot_hash": saga.plan_snapshot_hash,
                },
                now=now,
            )

    def _allocate_runtime(self, claim: _Claim, now: datetime) -> OnboardingWorkflowResult:
        claim, target = self._freeze_partition_target(claim, now)
        try:
            allocation = self._runtime.allocate_partition(
                target=target,
                idempotency_key=f"onboarding:{claim.scope.onboarding_id}:runtime",
            )
        except Exception as error:
            raise OnboardingWorkflowError(
                "runtime_allocation_failed",
                _SAFE_ERROR_DETAILS["runtime_allocation_failed"],
            ) from error
        self._validate_partition_allocation(allocation)
        with self._sessions.begin() as db:
            saga = self._claimed_saga(db, claim, now)
            placement_status = db.scalar(
                sa.select(RuntimePlacementRecord.status).where(
                    RuntimePlacementRecord.id == target.placement_id
                )
            )
            if placement_status not in {"active", "draining"}:
                raise OnboardingWorkflowError(
                    "runtime_allocation_failed",
                    _SAFE_ERROR_DETAILS["runtime_allocation_failed"],
                )
            partition = db.get(RuntimePartitionRecord, saga.runtime_partition_id)
            alias = db.get(
                RuntimeIdentityAliasRecord,
                (saga.runtime_partition_id, saga.user_id),
            )
            if partition is None:
                if alias is not None:
                    raise OnboardingWorkflowError(
                        "runtime_partition_conflict",
                        _SAFE_ERROR_DETAILS["runtime_partition_conflict"],
                        retryable=False,
                    )
                db.add(
                    RuntimePartitionRecord(
                        id=saga.runtime_partition_id,
                        tenant_id=saga.tenant_id,
                        space_id=saga.space_id,
                        placement_id=target.placement_id,
                        runtime_type=target.runtime_type,
                        runtime_version=allocation.runtime_version,
                        physical_partition_key=allocation.physical_partition_key,
                        placement_generation=allocation.placement_generation,
                        source_revision=allocation.source_revision,
                        adapter_contract_version=allocation.adapter_contract_version,
                        status="active",
                    )
                )
                db.flush()
                db.add(
                    RuntimeIdentityAliasRecord(
                        runtime_partition_id=saga.runtime_partition_id,
                        user_id=saga.user_id,
                        runtime_user_key=allocation.runtime_user_key,
                        status="active",
                    )
                )
            elif not self._runtime_partition_matches_allocation(
                partition=partition,
                target=target,
                allocation=allocation,
            ) or not self._runtime_alias_matches_allocation(
                alias=alias,
                target=target,
                allocation=allocation,
            ):
                raise OnboardingWorkflowError(
                    "runtime_partition_conflict",
                    _SAFE_ERROR_DETAILS["runtime_partition_conflict"],
                    retryable=False,
                )
            saga.runtime_ready_at = now
            return self._transition(
                db,
                saga,
                to_status="runtime_ready",
                event_type="tenant_onboarding.runtime_ready",
                facts={
                    "runtime_partition_id": str(saga.runtime_partition_id),
                    "placement_id": str(target.placement_id),
                    "external_receipt_hash": allocation.receipt_hash,
                },
                now=now,
            )

    def _bootstrap_project(self, claim: _Claim, now: datetime) -> OnboardingWorkflowResult:
        partition_target = self._partition_target(claim, require_partition=True)
        terms = self._terms_from_claim(claim)
        target = RuntimeProjectTarget(
            partition=partition_target,
            project_id=claim.project_id,
            project_name=terms.default_project_name,
        )
        try:
            allocation = self._runtime.provision_default_project(
                target=target,
                idempotency_key=f"onboarding:{claim.scope.onboarding_id}:project",
            )
        except Exception as error:
            raise OnboardingWorkflowError(
                "runtime_project_failed",
                _SAFE_ERROR_DETAILS["runtime_project_failed"],
            ) from error
        self._validate_project_allocation(allocation)
        with self._sessions.begin() as db:
            saga = self._claimed_saga(db, claim, now)
            terms = _PlanTerms.load(saga)
            partition = db.get(RuntimePartitionRecord, saga.runtime_partition_id)
            if partition is None or partition.status != "active":
                raise OnboardingWorkflowError(
                    "runtime_project_failed",
                    _SAFE_ERROR_DETAILS["runtime_project_failed"],
                )
            project = db.get(ProjectRecord, saga.default_project_id)
            if project is None:
                db.add(
                    ProjectRecord(
                        id=saga.default_project_id,
                        tenant_id=saga.tenant_id,
                        space_id=saga.space_id,
                        name=terms.default_project_name,
                        visibility=terms.default_project_visibility,
                        created_by=saga.user_id,
                        status="suspended",
                        authorization_version=1,
                    )
                )
                db.flush()
                db.add(
                    ProjectMembershipRecord(
                        tenant_id=saga.tenant_id,
                        space_id=saga.space_id,
                        project_id=saga.default_project_id,
                        subject_type="user",
                        subject_id=saga.user_id,
                        role="owner",
                        status="active",
                        created_by=saga.user_id,
                        version=1,
                    )
                )
                db.add(
                    AdmissionQuotaRecord(
                        tenant_id=saga.tenant_id,
                        space_id=saga.space_id,
                        project_id=saga.default_project_id,
                        resource=terms.quota_resource,
                        limit_units=terms.quota_limit,
                        reserved_units=0,
                        consumed_units=0,
                        version=1,
                    )
                )
                db.add(
                    RuntimeResourceBindingRecord(
                        id=saga.runtime_binding_id,
                        runtime_partition_id=saga.runtime_partition_id,
                        tenant_id=saga.tenant_id,
                        space_id=saga.space_id,
                        project_id=saga.default_project_id,
                        resource_type="project",
                        runtime_resource_id=allocation.runtime_resource_id,
                        saas_resource_id=saga.default_project_id,
                        partition_generation=partition.placement_generation,
                        binding_generation=1,
                        status="active",
                    )
                )
            saga.project_ready_at = now
            return self._transition(
                db,
                saga,
                to_status="project_ready",
                event_type="tenant_onboarding.project_ready",
                facts={
                    "project_id": str(saga.default_project_id),
                    "runtime_binding_id": str(saga.runtime_binding_id),
                    "external_receipt_hash": allocation.receipt_hash,
                },
                now=now,
            )

    def _activate(self, claim: _Claim, now: datetime) -> OnboardingWorkflowResult:
        with self._sessions.begin() as db:
            saga = self._claimed_saga(db, claim, now)
            terms = _PlanTerms.load(saga)
            tenant_state = db.execute(
                sa.select(Tenant.status, Tenant.lifecycle_version).where(
                    Tenant.id == saga.tenant_id
                )
            ).one_or_none()
            space_status = db.scalar(
                sa.select(Space.status).where(
                    Space.id == saga.space_id,
                    Space.tenant_id == saga.tenant_id,
                )
            )
            subscription = db.get(BillingSubscriptionRecord, saga.subscription_id)
            entitlement = db.get(BillingEntitlementRecord, saga.entitlement_id)
            partition = db.get(RuntimePartitionRecord, saga.runtime_partition_id)
            placement_status = (
                None
                if partition is None
                else db.scalar(
                    sa.select(RuntimePlacementRecord.status).where(
                        RuntimePlacementRecord.id == partition.placement_id
                    )
                )
            )
            alias = db.get(RuntimeIdentityAliasRecord, (saga.runtime_partition_id, saga.user_id))
            project = db.get(ProjectRecord, saga.default_project_id)
            membership = db.get(
                ProjectMembershipRecord, (saga.default_project_id, "user", saga.user_id)
            )
            binding = db.get(RuntimeResourceBindingRecord, saga.runtime_binding_id)
            quota = db.scalar(
                sa.select(AdmissionQuotaRecord).where(
                    AdmissionQuotaRecord.tenant_id == saga.tenant_id,
                    AdmissionQuotaRecord.space_id == saga.space_id,
                    AdmissionQuotaRecord.project_id == saga.default_project_id,
                    AdmissionQuotaRecord.resource == terms.quota_resource,
                )
            )
            valid = (
                tenant_state is not None
                and tenant_state.status == "provisioning"
                and tenant_state.lifecycle_version == 1
                and space_status == "suspended"
                and subscription is not None
                and subscription.status == "trialing"
                and entitlement is not None
                and entitlement.status == "active"
                and partition is not None
                and partition.status == "active"
                and placement_status in {"active", "draining"}
                and alias is not None
                and alias.status == "active"
                and project is not None
                and project.status == "suspended"
                and membership is not None
                and membership.status == "active"
                and membership.role == "owner"
                and binding is not None
                and binding.status == "active"
                and quota is not None
            )
            if not valid:
                raise OnboardingWorkflowError(
                    "activation_precondition_failed",
                    _SAFE_ERROR_DETAILS["activation_precondition_failed"],
                )
            trial_ends_at = now + timedelta(days=terms.trial_days)
            subscription.current_period_start = now
            subscription.current_period_end = trial_ends_at
            subscription.trial_ends_at = trial_ends_at
            subscription.version += 1
            entitlement.period_start = now
            entitlement.period_end = trial_ends_at
            entitlement.version += 1
            tenant_updated = db.execute(
                sa.update(Tenant)
                .where(
                    Tenant.id == saga.tenant_id,
                    Tenant.status == "provisioning",
                    Tenant.lifecycle_version == 1,
                )
                .values(status="trial", lifecycle_version=2)
            ).rowcount
            space_updated = db.execute(
                sa.update(Space)
                .where(
                    Space.id == saga.space_id,
                    Space.tenant_id == saga.tenant_id,
                    Space.status == "suspended",
                )
                .values(status="active")
            ).rowcount
            self._require_exact(tenant_updated == 1 and space_updated == 1)
            project.status = "active"
            project.authorization_version += 1
            saga.trial_started_at = now
            saga.trial_ends_at = trial_ends_at
            saga.activated_at = now
            return self._transition(
                db,
                saga,
                to_status="active",
                event_type="tenant_onboarding.activated",
                facts={
                    "project_id": str(saga.default_project_id),
                    "trial_ends_at": trial_ends_at.isoformat(),
                },
                now=now,
            )

    def _compensate(self, claim: _Claim, now: datetime) -> OnboardingWorkflowResult:
        with self._sessions() as db:
            self._apply_scope(db, claim.scope)
            saga = self._saga(db, claim.scope, lock=False)
            cursor = saga.compensation_cursor
        if cursor is None:
            raise OnboardingWorkflowError(
                "compensation_failed", _SAFE_ERROR_DETAILS["compensation_failed"], retryable=False
            )
        if cursor == "project":
            partition_target = self._partition_target(claim, allow_missing=True)
            terms = self._terms_from_claim(claim)
            target = RuntimeProjectTarget(
                partition=partition_target,
                project_id=claim.project_id,
                project_name=terms.default_project_name,
            )
            try:
                self._runtime.compensate_default_project(
                    target=target,
                    idempotency_key=f"onboarding:{claim.scope.onboarding_id}:project:compensate",
                )
            except Exception as error:
                raise OnboardingWorkflowError(
                    "compensation_failed", _SAFE_ERROR_DETAILS["compensation_failed"]
                ) from error
            with self._sessions.begin() as db:
                saga = self._claimed_saga(db, claim, now)
                binding = db.get(RuntimeResourceBindingRecord, saga.runtime_binding_id)
                if binding is not None:
                    binding.status = "retired"
                project = db.get(ProjectRecord, saga.default_project_id)
                if project is not None:
                    project.status = "archived"
                    project.authorization_version += 1
                saga.compensation_cursor = "runtime"
                return self._continue_compensation(db, saga, "project", now)
        if cursor == "runtime":
            partition_target = self._partition_target(claim, allow_missing=True)
            try:
                self._runtime.compensate_partition(
                    target=partition_target,
                    idempotency_key=f"onboarding:{claim.scope.onboarding_id}:runtime:compensate",
                )
            except Exception as error:
                raise OnboardingWorkflowError(
                    "compensation_failed", _SAFE_ERROR_DETAILS["compensation_failed"]
                ) from error
            with self._sessions.begin() as db:
                saga = self._claimed_saga(db, claim, now)
                alias = db.get(
                    RuntimeIdentityAliasRecord, (saga.runtime_partition_id, saga.user_id)
                )
                if alias is not None:
                    alias.status = "retired"
                partition = db.get(RuntimePartitionRecord, saga.runtime_partition_id)
                if partition is not None:
                    partition.status = "retired"
                saga.compensation_cursor = "billing"
                return self._continue_compensation(db, saga, "runtime", now)
        if cursor != "billing":
            raise OnboardingWorkflowError(
                "compensation_failed", _SAFE_ERROR_DETAILS["compensation_failed"], retryable=False
            )
        with self._sessions.begin() as db:
            saga = self._claimed_saga(db, claim, now)
            entitlement = db.get(BillingEntitlementRecord, saga.entitlement_id)
            if entitlement is not None:
                entitlement.status = "suspended"
                entitlement.version += 1
            subscription = db.get(BillingSubscriptionRecord, saga.subscription_id)
            if subscription is not None:
                subscription.status = "canceled"
                subscription.version += 1
            project = db.get(ProjectRecord, saga.default_project_id)
            if project is not None and project.status != "archived":
                project.status = "archived"
                project.authorization_version += 1
            # Compensation is intentionally one-way and exact: only this
            # Saga's still-provisioning Tenant can be suspended.  Replays over
            # an already suspended scope are harmless.
            db.execute(
                sa.update(Tenant)
                .where(
                    Tenant.id == saga.tenant_id,
                    Tenant.status == "provisioning",
                    Tenant.lifecycle_version == 1,
                )
                .values(status="suspended", lifecycle_version=2)
            )
            db.execute(
                sa.update(Space)
                .where(
                    Space.id == saga.space_id,
                    Space.tenant_id == saga.tenant_id,
                    Space.status != "suspended",
                )
                .values(status="suspended")
            )
            previous = saga.status
            saga.status = "compensated"
            saga.compensation_cursor = None
            saga.compensated_at = now
            saga.claim_token = None
            saga.claimed_at = None
            saga.lease_expires_at = None
            saga.available_at = now
            saga.attempt_count = 0
            saga.last_transition_at = now
            saga.version += 1
            self._append_event(
                db,
                saga=saga,
                event_type="tenant_onboarding.compensated",
                from_status=previous,
                to_status="compensated",
                facts={"failure_stage": saga.failure_stage or "unknown"},
                occurred_at=now,
            )
            db.flush()
            return self._result(saga, replayed=False)

    def _continue_compensation(
        self, db: Session, saga: TenantOnboardingRecord, completed_cursor: str, now: datetime
    ) -> OnboardingWorkflowResult:
        saga.claim_token = None
        saga.claimed_at = None
        saga.lease_expires_at = None
        saga.available_at = now
        saga.attempt_count = 0
        saga.last_transition_at = now
        saga.version += 1
        self._append_event(
            db,
            saga=saga,
            event_type="tenant_onboarding.compensation_step_completed",
            from_status="compensating",
            to_status="compensating",
            facts={
                "completed_cursor": completed_cursor,
                "next_cursor": saga.compensation_cursor or "billing",
            },
            occurred_at=now,
        )
        self._enqueue(db, saga, "onboarding.compensation.requested", now)
        db.flush()
        return self._result(saga, replayed=False)

    def _record_failure(
        self, claim: _Claim, error: OnboardingWorkflowError, now: datetime
    ) -> OnboardingWorkflowResult:
        with self._sessions.begin() as db:
            try:
                saga = self._claimed_saga(db, claim, now, allow_expired=True)
            except OnboardingWorkflowError:
                self._apply_scope(db, claim.scope)
                saga = self._saga(db, claim.scope, lock=True)
                return self._result(saga, replayed=True)
            detail = _SAFE_ERROR_DETAILS.get(error.code, "onboarding stage did not complete")
            saga.last_error_code = error.code[:128]
            saga.last_error_detail = detail
            saga.claim_token = None
            saga.claimed_at = None
            saga.lease_expires_at = None
            previous = saga.status
            if error.retryable and saga.attempt_count < self._max_attempts:
                delay = self._retry_base * (2 ** (saga.attempt_count - 1))
                saga.available_at = now + delay
                saga.version += 1
                self._append_event(
                    db,
                    saga=saga,
                    event_type="tenant_onboarding.retry_scheduled",
                    from_status=previous,
                    to_status=previous,
                    facts={
                        "error_code": saga.last_error_code,
                        "attempt_count": saga.attempt_count,
                        "available_at": saga.available_at.isoformat(),
                    },
                    occurred_at=now,
                )
                event_type = self._requested_event_for(previous)
                self._enqueue(db, saga, event_type, saga.available_at)
            elif previous == "compensating":
                saga.status = "manual_review"
                saga.available_at = now
                saga.last_transition_at = now
                saga.version += 1
                self._append_event(
                    db,
                    saga=saga,
                    event_type="tenant_onboarding.manual_review_required",
                    from_status=previous,
                    to_status="manual_review",
                    facts={"error_code": saga.last_error_code},
                    occurred_at=now,
                )
            else:
                saga.failure_stage = previous
                saga.compensation_cursor = self._cursor_for_failure(previous, error.code)
                saga.status = "compensating"
                saga.available_at = now
                saga.attempt_count = 0
                saga.last_transition_at = now
                saga.version += 1
                self._append_event(
                    db,
                    saga=saga,
                    event_type="tenant_onboarding.compensation_started",
                    from_status=previous,
                    to_status="compensating",
                    facts={
                        "error_code": saga.last_error_code,
                        "failure_stage": previous,
                        "compensation_cursor": saga.compensation_cursor,
                    },
                    occurred_at=now,
                )
                self._enqueue(db, saga, "onboarding.compensation.requested", now)
            db.flush()
            return self._result(saga, replayed=False)

    def _freeze_partition_target(
        self, claim: _Claim, now: datetime
    ) -> tuple[_Claim, RuntimePartitionTarget]:
        """Persist one immutable Placement request before any external effect."""

        if claim.runtime_target_snapshot is not None:
            return claim, self._target_from_claim(claim)
        with self._sessions.begin() as db:
            saga = self._claimed_saga(db, claim, now)
            terms = _PlanTerms.load(saga)
            placement = db.execute(
                sa.select(
                    RuntimePlacementRecord.id,
                    RuntimePlacementRecord.runtime_type,
                    RuntimePlacementRecord.data_region,
                    RuntimePlacementRecord.failure_domain,
                    RuntimePlacementRecord.official_schema_revision,
                    RuntimePlacementRecord.capacity_class,
                )
                .where(
                    RuntimePlacementRecord.status == "active",
                    RuntimePlacementRecord.runtime_type == terms.runtime_type,
                    RuntimePlacementRecord.data_region == saga.home_region,
                    RuntimePlacementRecord.capacity_class == terms.capacity_class,
                )
                .order_by(RuntimePlacementRecord.id)
                .limit(1)
            ).one_or_none()
            if placement is None:
                raise OnboardingWorkflowError(
                    "runtime_placement_unavailable",
                    "runtime Placement is unavailable",
                )
            try:
                provider_binding = self._runtime.binding_snapshot(placement.id)
            except Exception as error:
                raise OnboardingWorkflowError(
                    "runtime_placement_unavailable",
                    "runtime Provider binding is unavailable",
                ) from error
            snapshot: dict[str, object] = {
                "schema_version": 2,
                "placement_id": str(placement.id),
                "runtime_type": placement.runtime_type,
                "data_region": placement.data_region,
                "failure_domain": placement.failure_domain,
                "official_schema_revision": placement.official_schema_revision,
                "capacity_class": placement.capacity_class,
                "provider_binding": {
                    "provider_type": provider_binding.provider_type,
                    "binding_revision": provider_binding.binding_revision,
                    "binding_hash": provider_binding.binding_hash,
                },
            }
            request_hash = _digest(snapshot)
            saga.runtime_placement_id = placement.id
            saga.runtime_target_snapshot = snapshot
            saga.runtime_request_hash = request_hash
            self._append_event(
                db,
                saga=saga,
                event_type="tenant_onboarding.runtime_target_frozen",
                from_status=saga.status,
                to_status=saga.status,
                facts={
                    "placement_id": str(placement.id),
                    "runtime_request_hash": request_hash,
                },
                occurred_at=now,
            )
            db.flush()
            frozen = replace(
                claim,
                runtime_placement_id=placement.id,
                runtime_target_snapshot=snapshot,
                runtime_request_hash=request_hash,
            )
            return frozen, self._target_from_claim(frozen)

    def _partition_target(
        self,
        claim: _Claim,
        *,
        require_partition: bool = False,
        allow_missing: bool = False,
    ) -> RuntimePartitionTarget:
        with self._sessions.begin() as db:
            self._apply_scope(db, claim.scope)
            saga = self._saga(db, claim.scope, lock=False)
            current = replace(
                claim,
                runtime_placement_id=saga.runtime_placement_id,
                runtime_target_snapshot=(
                    dict(saga.runtime_target_snapshot)
                    if saga.runtime_target_snapshot is not None
                    else None
                ),
                runtime_request_hash=saga.runtime_request_hash,
            )
            target = self._target_from_claim(current)
            partition = db.get(RuntimePartitionRecord, saga.runtime_partition_id)
            if require_partition and (
                partition is None
                or partition.status != "active"
                or partition.placement_id != target.placement_id
            ):
                raise OnboardingWorkflowError(
                    "runtime_allocation_failed",
                    _SAFE_ERROR_DETAILS["runtime_allocation_failed"],
                )
            if not allow_missing:
                placement_status = db.scalar(
                    sa.select(RuntimePlacementRecord.status).where(
                        RuntimePlacementRecord.id == target.placement_id
                    )
                )
                if placement_status not in {"active", "draining"}:
                    raise OnboardingWorkflowError(
                        "runtime_placement_unavailable",
                        "runtime Placement is unavailable",
                    )
            return target

    @staticmethod
    def _target_from_claim(claim: _Claim) -> RuntimePartitionTarget:
        snapshot = claim.runtime_target_snapshot
        if (
            snapshot is None
            or snapshot.get("schema_version") != 2
            or claim.runtime_placement_id is None
            or claim.runtime_request_hash is None
            or not hmac.compare_digest(_digest(snapshot), claim.runtime_request_hash)
        ):
            raise OnboardingWorkflowError(
                "runtime_target_invalid", "runtime target evidence is invalid", retryable=False
            )
        try:
            placement_id = UUID(str(snapshot["placement_id"]))
            provider_binding_document = cast(dict[str, object], snapshot["provider_binding"])
            target = RuntimePartitionTarget(
                onboarding_id=claim.scope.onboarding_id,
                tenant_id=claim.scope.tenant_id,
                space_id=claim.space_id,
                user_id=claim.user_id,
                runtime_partition_id=claim.runtime_partition_id,
                placement_id=placement_id,
                runtime_type=str(snapshot["runtime_type"]),
                data_region=str(snapshot["data_region"]),
                failure_domain=str(snapshot["failure_domain"]),
                official_schema_revision=str(snapshot["official_schema_revision"]),
                capacity_class=str(snapshot["capacity_class"]),
                provider_binding=RuntimeProviderBindingSnapshot(
                    provider_type=str(provider_binding_document["provider_type"]),
                    binding_revision=str(provider_binding_document["binding_revision"]),
                    binding_hash=str(provider_binding_document["binding_hash"]),
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise OnboardingWorkflowError(
                "runtime_target_invalid", "runtime target evidence is invalid", retryable=False
            ) from error
        if placement_id != claim.runtime_placement_id:
            raise OnboardingWorkflowError(
                "runtime_target_invalid", "runtime target evidence is invalid", retryable=False
            )
        return target

    def _terms_from_claim(self, claim: _Claim) -> _PlanTerms:
        with self._sessions.begin() as db:
            self._apply_scope(db, claim.scope)
            return _PlanTerms.load(self._saga(db, claim.scope, lock=False))

    def _claimed_saga(
        self,
        db: Session,
        claim: _Claim,
        now: datetime,
        *,
        allow_expired: bool = False,
    ) -> TenantOnboardingRecord:
        self._apply_scope(db, claim.scope)
        saga = self._saga(db, claim.scope, lock=True)
        if (
            saga.claim_token != claim.token
            or saga.status != claim.status
            or saga.version != claim.version
        ):
            raise OnboardingWorkflowError(
                "onboarding_claim_stale", "onboarding claim is stale", retryable=False
            )
        # Never validate a slow provider call against the timestamp captured at
        # claim start.  The database clock is authoritative at commit time, so
        # a claimant cannot write after its lease merely because no successor
        # has changed the token yet.
        database_now = db.scalar(sa.select(sa.func.current_timestamp()))
        checked_at = (
            _stored_time(cast(datetime, database_now))
            if isinstance(database_now, datetime)
            else _stored_time(datetime.now(timezone.utc))
        )
        if not allow_expired and _stored_time(cast(datetime, saga.lease_expires_at)) <= checked_at:
            raise OnboardingWorkflowError(
                "onboarding_claim_expired", "onboarding claim expired", retryable=True
            )
        del now
        return saga

    def _transition(
        self,
        db: Session,
        saga: TenantOnboardingRecord,
        *,
        to_status: str,
        event_type: str,
        facts: dict[str, object],
        now: datetime,
    ) -> OnboardingWorkflowResult:
        previous = saga.status
        saga.status = to_status
        saga.claim_token = None
        saga.claimed_at = None
        saga.lease_expires_at = None
        saga.available_at = now
        saga.attempt_count = 0
        saga.last_error_code = None
        saga.last_error_detail = None
        saga.last_transition_at = now
        saga.version += 1
        self._append_event(
            db,
            saga=saga,
            event_type=event_type,
            from_status=previous,
            to_status=to_status,
            facts=facts,
            occurred_at=now,
        )
        requested = _REQUESTED_EVENT_BY_STATUS.get(to_status)
        if requested is not None:
            self._enqueue(db, saga, requested, now)
        db.flush()
        return self._result(saga, replayed=False)

    @staticmethod
    def _requested_event_for(status: str) -> str:
        if status == "tenant_created":
            return "onboarding.billing.requested"
        event_type = _REQUESTED_EVENT_BY_STATUS.get(status)
        if event_type is None:
            raise OnboardingWorkflowError(
                "onboarding_state_invalid", "onboarding state is invalid", retryable=False
            )
        return event_type

    @staticmethod
    def _cursor_for_failure(status: str, error_code: str) -> str:
        if status == "billing_ready" and error_code == "runtime_placement_unavailable":
            return "billing"
        return {
            "tenant_created": "billing",
            "billing_ready": "runtime",
            "runtime_ready": "project",
            "project_ready": "project",
        }.get(status, "billing")

    @staticmethod
    def _validate_partition_allocation(allocation: RuntimePartitionAllocation) -> None:
        values = (
            (allocation.runtime_version, 64),
            (allocation.physical_partition_key, 128),
            (allocation.source_revision, 64),
            (allocation.adapter_contract_version, 32),
            (allocation.runtime_user_key, 128),
        )
        if any(not value.strip() or len(value) > maximum for value, maximum in values):
            raise OnboardingWorkflowError(
                "runtime_receipt_invalid", "runtime receipt is invalid", retryable=False
            )
        if allocation.physical_partition_key == "0" or allocation.placement_generation < 1:
            raise OnboardingWorkflowError(
                "runtime_receipt_invalid", "runtime receipt is invalid", retryable=False
            )
        if len(allocation.receipt_hash) != 64:
            raise OnboardingWorkflowError(
                "runtime_receipt_invalid", "runtime receipt hash is invalid", retryable=False
            )

    @staticmethod
    def _runtime_partition_matches_allocation(
        *,
        partition: RuntimePartitionRecord,
        target: RuntimePartitionTarget,
        allocation: RuntimePartitionAllocation,
    ) -> bool:
        return (
            partition.tenant_id == target.tenant_id
            and partition.space_id == target.space_id
            and partition.placement_id == target.placement_id
            and partition.runtime_type == target.runtime_type
            and partition.status == "active"
            and partition.runtime_version == allocation.runtime_version
            and partition.physical_partition_key == allocation.physical_partition_key
            and partition.placement_generation == allocation.placement_generation
            and partition.source_revision == allocation.source_revision
            and partition.adapter_contract_version == allocation.adapter_contract_version
        )

    @staticmethod
    def _runtime_alias_matches_allocation(
        *,
        alias: RuntimeIdentityAliasRecord | None,
        target: RuntimePartitionTarget,
        allocation: RuntimePartitionAllocation,
    ) -> bool:
        return (
            alias is not None
            and alias.runtime_partition_id == target.runtime_partition_id
            and alias.user_id == target.user_id
            and alias.runtime_user_key == allocation.runtime_user_key
            and alias.status == "active"
        )

    @staticmethod
    def _validate_project_allocation(allocation: RuntimeProjectAllocation) -> None:
        if (
            not allocation.runtime_resource_id.strip()
            or len(allocation.runtime_resource_id) > 256
            or len(allocation.receipt_hash) != 64
        ):
            raise OnboardingWorkflowError(
                "runtime_receipt_invalid", "runtime Project receipt is invalid", retryable=False
            )

    @staticmethod
    def _require_exact(condition: bool) -> None:
        if not condition:
            raise OnboardingWorkflowError(
                "onboarding_invariant_broken",
                "onboarding evidence is inconsistent",
                retryable=False,
            )

    @staticmethod
    def _apply_scope(db: Session, scope: OnboardingScope) -> None:
        apply_onboarding_rls_context(
            db,
            OnboardingRlsContext(
                onboarding_id=scope.onboarding_id,
                registration_id=scope.registration_id,
                actor_id=scope.actor_id,
                tenant_id=scope.tenant_id,
            ),
        )

    @staticmethod
    def _saga(db: Session, scope: OnboardingScope, *, lock: bool) -> TenantOnboardingRecord:
        statement = sa.select(TenantOnboardingRecord).where(
            TenantOnboardingRecord.id == scope.onboarding_id,
            TenantOnboardingRecord.registration_id == scope.registration_id,
            TenantOnboardingRecord.user_id == scope.actor_id,
            TenantOnboardingRecord.tenant_id == scope.tenant_id,
        )
        if lock:
            statement = statement.with_for_update()
        saga = db.scalar(statement)
        if saga is None:
            raise OnboardingWorkflowError(
                "onboarding_not_found", "Tenant onboarding is not accessible", retryable=False
            )
        return saga

    @staticmethod
    def _enqueue(
        db: Session,
        saga: TenantOnboardingRecord,
        event_type: str,
        available_at: datetime,
    ) -> None:
        payload: dict[str, object] = {
            "onboarding_id": str(saga.id),
            "registration_id": str(saga.registration_id),
            "user_id": str(saga.user_id),
            "tenant_id": str(saga.tenant_id),
            "expected_status": saga.status,
            "version": saga.version,
        }
        key = scoped_idempotency_key(
            "tenant-onboarding",
            saga.id,
            f"{event_type}:{saga.version}:{saga.attempt_count}",
        )
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=saga.tenant_id,
                aggregate_type="tenant_onboarding",
                aggregate_key=str(saga.id),
                event_type=event_type,
                payload=payload,
                idempotency_key=key,
                request_hash=_digest(payload),
                attempt_count=0,
                available_at=available_at,
            )
        )

    @staticmethod
    def _append_event(
        db: Session,
        *,
        saga: TenantOnboardingRecord,
        event_type: str,
        from_status: str,
        to_status: str,
        facts: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        statement = (
            sa.select(SelfServiceEventRecord)
            .where(
                SelfServiceEventRecord.aggregate_type == "tenant_onboarding",
                SelfServiceEventRecord.aggregate_id == saga.id,
            )
            .order_by(SelfServiceEventRecord.sequence.desc())
            .limit(1)
        )
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"self-service-event:tenant_onboarding:{saga.id}"},
            )
        else:
            statement = statement.with_for_update()
        previous = db.scalar(statement)
        sequence = 1 if previous is None else previous.sequence + 1
        previous_hash = _ZERO_HASH if previous is None else previous.event_hash
        facts_hash = _digest(facts)
        event_hash = _digest(
            {
                "aggregate_type": "tenant_onboarding",
                "aggregate_id": str(saga.id),
                "sequence": sequence,
                "event_type": event_type,
                "from_status": from_status,
                "to_status": to_status,
                "facts_hash": facts_hash,
                "previous_hash": previous_hash,
                "occurred_at": occurred_at.isoformat(),
            }
        )
        db.add(
            SelfServiceEventRecord(
                id=uuid4(),
                aggregate_type="tenant_onboarding",
                aggregate_id=saga.id,
                tenant_id=saga.tenant_id,
                user_id=saga.user_id,
                sequence=sequence,
                event_type=event_type,
                from_status=from_status,
                to_status=to_status,
                facts=facts,
                facts_hash=facts_hash,
                previous_hash=previous_hash,
                event_hash=event_hash,
                occurred_at=occurred_at,
            )
        )

    @staticmethod
    def _result(saga: TenantOnboardingRecord, *, replayed: bool) -> OnboardingWorkflowResult:
        return OnboardingWorkflowResult(
            onboarding_id=saga.id,
            status=saga.status,
            project_id=saga.default_project_id,
            first_run_id=saga.first_run_id,
            version=saga.version,
            attempt_count=saga.attempt_count,
            available_at=_stored_time(saga.available_at),
            replayed=replayed,
        )


def onboarding_scope_from_payload(payload: dict[str, object]) -> OnboardingScope:
    """Parse only server-authored Outbox facts; callers must not pass HTTP bodies."""

    try:
        return OnboardingScope(
            onboarding_id=UUID(str(payload["onboarding_id"])),
            registration_id=UUID(str(payload["registration_id"])),
            actor_id=UUID(str(payload["user_id"])),
            tenant_id=UUID(str(payload["tenant_id"])),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise OnboardingWorkflowError(
            "onboarding_event_invalid", "onboarding event is invalid", retryable=False
        ) from error


def _stored_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode()).hexdigest()
