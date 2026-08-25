from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    AdmissionQuotaRecord,
    BillingEntitlementRecord,
    BillingSubscriptionRecord,
    ControlPlaneOutboxEvent,
    ExecutionControlPlane,
    ExecutionRevisionSet,
    GlobalUser,
    OnboardingPlan,
    OnboardingPolicy,
    OnboardingScope,
    OnboardingWorkflowError,
    OutboxDispatcher,
    PasswordCredential,
    ProjectMembershipRecord,
    ProjectRecord,
    RunAdmission,
    RuntimeCompatibilityPolicy,
    RuntimeIdentityAliasRecord,
    RuntimePartitionAllocation,
    RuntimePartitionRecord,
    RuntimePartitionTarget,
    RuntimePlacementRecord,
    RuntimeProjectAllocation,
    RuntimeProjectTarget,
    RuntimeProviderBindingSnapshot,
    RuntimeResourceBindingRecord,
    SaasBase,
    SelfServiceOnboardingService,
    SelfServiceRegistrationRecord,
    Space,
    SqlAlchemyContextResolver,
    Tenant,
    TenantOnboardingRecord,
    TenantOnboardingWorkflow,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.onboarding import EmailVerificationMessage
from saas.control_plane.outbox import DispatchResult
from saas.onboarding_composition import (
    TenantOnboardingComposition,
    TenantOnboardingDependencies,
    TenantOnboardingWorkflowConfig,
    create_tenant_onboarding_composition,
)

_EMAIL_EVENT = "onboarding.email_verification.requested"
_TENANT_EVENT = "onboarding.tenant.requested"
_BILLING_EVENT = "onboarding.billing.requested"
_RUNTIME_EVENT = "onboarding.runtime.requested"
_PASSWORD = "correct-horse-battery-staple"
_RUNTIME_VERSION = "0.11.0.dev0"
_SOURCE_REVISION = "14df304a8e958da36b8a606a2c825e3a6642247e"
_SCHEMA_REVISION = "e5d9bc8ac650"
_ADAPTER_VERSION = "0.2.0"


def _hash(value: str) -> str:
    return sha256(value.encode()).hexdigest()


class _AllowAllRateLimiter:
    def require(self, *, action: str, subject_hash: str, now: datetime) -> None:
        del action, subject_hash, now


class _RecordingEmailSender:
    def __init__(self) -> None:
        self.deliveries: list[tuple[UUID, EmailVerificationMessage]] = []

    def send_verification(self, *, event_id: UUID, message: EmailVerificationMessage) -> None:
        self.deliveries.append((event_id, message))


@dataclass(slots=True)
class _FakeRuntimePartitionProvisioner:
    """Idempotent fake with independently injectable provision/compensation failures."""

    allocation_failures_remaining: int = 0
    project_failures_remaining: int = 0
    partition_compensation_failures_remaining: int = 0
    project_compensation_failures_remaining: int = 0
    binding_revision: str = "test-binding-v1"
    allocation_attempts: list[str] = field(default_factory=list)
    project_attempts: list[str] = field(default_factory=list)
    partition_compensation_attempts: list[str] = field(default_factory=list)
    project_compensation_attempts: list[str] = field(default_factory=list)
    partition_targets: list[RuntimePartitionTarget] = field(default_factory=list)
    allocations: dict[str, RuntimePartitionAllocation] = field(default_factory=dict)
    projects: dict[str, RuntimeProjectAllocation] = field(default_factory=dict)
    compensated_partitions: set[str] = field(default_factory=set)
    compensated_projects: set[str] = field(default_factory=set)

    def binding_snapshot(self, placement_id: UUID) -> RuntimeProviderBindingSnapshot:
        return RuntimeProviderBindingSnapshot(
            provider_type="test-runtime",
            binding_revision=self.binding_revision,
            binding_hash=_hash(f"{self.binding_revision}:{placement_id}"),
        )

    def allocate_partition(
        self, *, target: RuntimePartitionTarget, idempotency_key: str
    ) -> RuntimePartitionAllocation:
        self.allocation_attempts.append(idempotency_key)
        self.partition_targets.append(target)
        if self.allocation_failures_remaining:
            self.allocation_failures_remaining -= 1
            raise RuntimeError("injected runtime allocation failure")
        allocation = self.allocations.get(idempotency_key)
        if allocation is None:
            physical_key = str(int(target.runtime_partition_id.hex[:12], 16) or 1)
            allocation = RuntimePartitionAllocation(
                runtime_version=_RUNTIME_VERSION,
                physical_partition_key=physical_key,
                placement_generation=1,
                source_revision=_SOURCE_REVISION,
                adapter_contract_version=_ADAPTER_VERSION,
                runtime_user_key=f"user-{target.user_id.hex}",
                receipt_hash=_hash(f"partition:{idempotency_key}:{physical_key}"),
            )
            self.allocations[idempotency_key] = allocation
        return allocation

    def provision_default_project(
        self, *, target: RuntimeProjectTarget, idempotency_key: str
    ) -> RuntimeProjectAllocation:
        self.project_attempts.append(idempotency_key)
        if self.project_failures_remaining:
            self.project_failures_remaining -= 1
            raise RuntimeError("injected runtime Project failure")
        allocation = self.projects.get(idempotency_key)
        if allocation is None:
            runtime_resource_id = f"project-{target.project_id}"
            allocation = RuntimeProjectAllocation(
                runtime_resource_id=runtime_resource_id,
                receipt_hash=_hash(f"project:{idempotency_key}:{runtime_resource_id}"),
            )
            self.projects[idempotency_key] = allocation
        return allocation

    def compensate_default_project(
        self, *, target: RuntimeProjectTarget, idempotency_key: str
    ) -> None:
        del target
        self.project_compensation_attempts.append(idempotency_key)
        if self.project_compensation_failures_remaining:
            self.project_compensation_failures_remaining -= 1
            raise RuntimeError("injected runtime Project compensation failure")
        self.compensated_projects.add(idempotency_key)

    def compensate_partition(
        self, *, target: RuntimePartitionTarget, idempotency_key: str
    ) -> None:
        del target
        self.partition_compensation_attempts.append(idempotency_key)
        if self.partition_compensation_failures_remaining:
            self.partition_compensation_failures_remaining -= 1
            raise RuntimeError("injected runtime partition compensation failure")
        self.compensated_partitions.add(idempotency_key)


@dataclass(frozen=True, slots=True)
class _Harness:
    sessions: sessionmaker[Session]
    registrations: SelfServiceOnboardingService
    runtime: _FakeRuntimePartitionProvisioner
    workflow: TenantOnboardingWorkflow
    composition: TenantOnboardingComposition
    sender: _RecordingEmailSender
    dispatcher: OutboxDispatcher
    now: datetime
    placement_id: UUID


@pytest.fixture
def onboarding_workflow() -> Iterator[_Harness]:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    policy = OnboardingPolicy(
        plans=(
            OnboardingPlan(
                key="starter",
                policy_revision="starter-workflow-v1",
                trial_days=14,
                currency="USD",
                trial_run_limit=25,
                trial_concurrency_limit=2,
                runtime_type="omnigent",
                capacity_class="starter",
                default_project_name="Getting Started",
                default_project_visibility="private",
                quota_resource="interactive_runs",
                quota_limit=25,
            ),
        ),
        home_regions=frozenset({"cn-east-1"}),
        verification_ttl=timedelta(minutes=30),
    )
    envelopes = VerificationEnvelopeKeyring(
        active_key_id="test-v1",
        keys={"test-v1": b"onboarding-workflow-envelope-key"},
    )
    runtime = _FakeRuntimePartitionProvisioner()
    sender = _RecordingEmailSender()
    composition = create_tenant_onboarding_composition(
        TenantOnboardingDependencies(
            registration_sessions=sessions,
            onboarding_sessions=sessions,
            execution_sessions=sessions,
            policy=policy,
            envelopes=envelopes,
            rate_limiter=_AllowAllRateLimiter(),
            email_sender=sender,
            runtime=runtime,
        ),
        config=TenantOnboardingWorkflowConfig(
            lease_duration=timedelta(seconds=30),
            max_attempts=3,
            retry_base=timedelta(seconds=5),
        ),
    )
    harness = _Harness(
        sessions=sessions,
        registrations=composition.registrations,
        runtime=runtime,
        workflow=composition.workflow,
        composition=composition,
        sender=sender,
        dispatcher=OutboxDispatcher(sessions, composition),
        now=datetime.now(timezone.utc).replace(microsecond=0),
        placement_id=uuid4(),
    )
    yield harness
    SaasBase.metadata.drop_all(engine)
    engine.dispose()


def _dispatch_one(harness: _Harness) -> DispatchResult:
    result = harness.dispatcher.dispatch_once(
        batch_size=1,
        now=datetime.now(timezone.utc) + timedelta(seconds=1),
    )
    assert (result.claimed, result.published, result.failed) == (1, 1, 0)
    return result


def _registration_to_tenant_created(harness: _Harness, *, suffix: str) -> OnboardingScope:
    accepted = harness.registrations.request_registration(
        email=f"owner-{suffix}@example.com",
        display_name="Workflow Owner",
        tenant_name=f"Workflow Tenant {suffix}",
        tenant_slug=f"workflow-{suffix}",
        default_space_name="Default Space",
        default_space_slug="default",
        plan_key="starter",
        home_region="cn-east-1",
        idempotency_key=f"registration-{suffix}",
        now=harness.now,
    )
    with harness.sessions() as db:
        email_event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(accepted.registration_id),
                ControlPlaneOutboxEvent.event_type == _EMAIL_EVENT,
            )
        )
        assert email_event is not None

    _dispatch_one(harness)
    assert len(harness.sender.deliveries) == 1
    _event_id, message = harness.sender.deliveries[0]
    assert message.registration_id == accepted.registration_id

    requested = harness.registrations.verify_and_request_onboarding(
        registration_id=accepted.registration_id,
        verification_token=message.verification_token,
        password=_PASSWORD,
        idempotency_key=f"verify-{suffix}",
        now=harness.now + timedelta(minutes=1),
    )
    assert requested.registration_id == accepted.registration_id
    with harness.sessions() as db:
        tenant_event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(requested.onboarding_id),
                ControlPlaneOutboxEvent.event_type == _TENANT_EVENT,
            )
        )
        assert tenant_event is not None

    _dispatch_one(harness)
    with harness.sessions() as db:
        registration = db.get(SelfServiceRegistrationRecord, accepted.registration_id)
        assert registration is not None
        saga = db.get(TenantOnboardingRecord, registration.onboarding_id)
        assert saga is not None
        assert saga.status == "tenant_created"
        assert saga.trial_started_at is None
        assert saga.trial_ends_at is None
        return OnboardingScope(
            onboarding_id=saga.id,
            registration_id=saga.registration_id,
            actor_id=saga.user_id,
            tenant_id=saga.tenant_id,
        )


def _seed_active_placement(harness: _Harness) -> None:
    with harness.sessions.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=harness.placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="runtime-db-a",
                object_store_ref="runtime-objects-a",
                kms_key_ref="runtime-kms-a",
                official_schema_revision=_SCHEMA_REVISION,
                capacity_class="starter",
                status="active",
            )
        )


def _saga(harness: _Harness, scope: OnboardingScope) -> TenantOnboardingRecord:
    with harness.sessions() as db:
        saga = db.get(TenantOnboardingRecord, scope.onboarding_id)
        assert saga is not None
        db.expunge(saga)
        return saga


def _activate(harness: _Harness, *, suffix: str) -> OnboardingScope:
    scope = _registration_to_tenant_created(harness, suffix=suffix)
    _seed_active_placement(harness)
    for expected_status in ("billing_ready", "runtime_ready", "project_ready", "active"):
        _dispatch_one(harness)
        assert _saga(harness, scope).status == expected_status
    return scope


def _compatibility_policy() -> RuntimeCompatibilityPolicy:
    return RuntimeCompatibilityPolicy(
        runtime_type="omnigent",
        allowed_runtime_versions=frozenset({_RUNTIME_VERSION}),
        allowed_source_revisions=frozenset({_SOURCE_REVISION}),
        allowed_schema_revisions=frozenset({_SCHEMA_REVISION}),
        adapter_contract_version=_ADAPTER_VERSION,
    )


def _failure_times() -> tuple[datetime, datetime, datetime]:
    start = datetime.now(timezone.utc) + timedelta(minutes=1)
    return start, start + timedelta(seconds=6), start + timedelta(seconds=17)


def test_composition_configuration_fails_before_worker_startup_when_unbound() -> None:
    policy = OnboardingPolicy(
        plans=(OnboardingPlan("starter", "unbound-v1", 14),),
        home_regions=frozenset({"cn-east-1"}),
    )
    envelopes = VerificationEnvelopeKeyring(
        active_key_id="test-v1",
        keys={"test-v1": b"onboarding-workflow-envelope-key"},
    )

    with pytest.raises(RuntimeError, match="Session factories must be bound"):
        TenantOnboardingDependencies(
            registration_sessions=sessionmaker(),
            onboarding_sessions=sessionmaker(),
            execution_sessions=sessionmaker(),
            policy=policy,
            envelopes=envelopes,
            rate_limiter=_AllowAllRateLimiter(),
            email_sender=_RecordingEmailSender(),
            runtime=_FakeRuntimePartitionProvisioner(),
        )
    with pytest.raises(ValueError, match="max attempts"):
        TenantOnboardingWorkflowConfig(max_attempts=0)


def test_outbox_advances_vertical_chain_and_activation_starts_trial(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix="happy")
    _seed_active_placement(harness)

    _dispatch_one(harness)
    billing_ready = _saga(harness, scope)
    assert billing_ready.status == "billing_ready"
    assert billing_ready.trial_started_at is None
    assert billing_ready.trial_ends_at is None

    _dispatch_one(harness)
    runtime_ready = _saga(harness, scope)
    assert runtime_ready.status == "runtime_ready"
    assert runtime_ready.trial_started_at is None
    assert runtime_ready.trial_ends_at is None

    _dispatch_one(harness)
    project_ready = _saga(harness, scope)
    assert project_ready.status == "project_ready"
    assert project_ready.trial_started_at is None
    assert project_ready.trial_ends_at is None

    _dispatch_one(harness)
    saga = _saga(harness, scope)
    assert saga.status == "active"
    assert saga.trial_started_at == saga.activated_at
    assert saga.trial_ends_at == saga.trial_started_at + timedelta(days=14)

    with harness.sessions() as db:
        tenant = db.get(Tenant, saga.tenant_id)
        space = db.get(Space, saga.space_id)
        project = db.get(ProjectRecord, saga.default_project_id)
        membership = db.get(
            ProjectMembershipRecord,
            (saga.default_project_id, "user", saga.user_id),
        )
        subscription = db.get(BillingSubscriptionRecord, saga.subscription_id)
        entitlement = db.get(BillingEntitlementRecord, saga.entitlement_id)
        partition = db.get(RuntimePartitionRecord, saga.runtime_partition_id)
        alias = db.get(RuntimeIdentityAliasRecord, (saga.runtime_partition_id, saga.user_id))
        binding = db.get(RuntimeResourceBindingRecord, saga.runtime_binding_id)
        quota = db.scalar(
            sa.select(AdmissionQuotaRecord).where(
                AdmissionQuotaRecord.tenant_id == saga.tenant_id,
                AdmissionQuotaRecord.space_id == saga.space_id,
                AdmissionQuotaRecord.project_id == saga.default_project_id,
                AdmissionQuotaRecord.resource == "interactive_runs",
            )
        )

        assert tenant is not None and tenant.status == "trial"
        assert space is not None and space.status == "active"
        assert project is not None and project.status == "active"
        assert membership is not None and membership.status == "active"
        assert membership.role == "owner"
        assert subscription is not None and subscription.status == "trialing"
        assert subscription.current_period_start == saga.trial_started_at
        assert subscription.trial_ends_at == saga.trial_ends_at
        assert entitlement is not None and entitlement.status == "active"
        assert entitlement.limit_quantity == 25
        assert entitlement.concurrency_limit == 2
        assert entitlement.period_start == saga.trial_started_at
        assert entitlement.period_end == saga.trial_ends_at
        assert partition is not None and partition.status == "active"
        assert partition.placement_id == harness.placement_id
        assert alias is not None and alias.status == "active"
        assert binding is not None and binding.status == "active"
        assert binding.project_id == saga.default_project_id
        assert quota is not None and quota.limit_units == 25
        assert quota.reserved_units == 0
        assert quota.consumed_units == 0

    assert len(harness.runtime.allocations) == 1
    assert len(harness.runtime.projects) == 1
    assert harness.runtime.compensated_partitions == set()
    assert harness.runtime.compensated_projects == set()


@pytest.mark.parametrize("terminal_status", ["cancelled", "failed"])
def test_first_real_run_completes_onboarding_and_terminal_run_does_not_compensate(
    onboarding_workflow: _Harness,
    terminal_status: str,
) -> None:
    harness = onboarding_workflow
    scope = _activate(harness, suffix=f"run-{terminal_status}")
    saga = _saga(harness, scope)
    resolver = SqlAlchemyContextResolver(harness.sessions, _compatibility_policy())
    request = resolver.resolve_request_context(
        actor_id=saga.user_id,
        tenant_id=saga.tenant_id,
        space_id=saga.space_id,
        trace_id=f"onboarding-first-run-{terminal_status}",
    )
    execution = ExecutionControlPlane(harness.sessions)
    task_id = execution.create_task(
        request,
        project_id=saga.default_project_id,
        title="First onboarding Run",
    )
    observed = harness.composition.execution_adapter(execution).admit_first_run(
        scope,
        request,
        project_id=saga.default_project_id,
        task_id=task_id,
        session_id=None,
        input_payload={"prompt": "Create a starter workflow"},
        quota_resource="interactive_runs",
        quota_units=1,
        idempotency_key=f"first-run-{terminal_status}",
        revisions=ExecutionRevisionSet(
            product_revision="wave1-product",
            upstream_revision=_SOURCE_REVISION,
            schema_revision=_SCHEMA_REVISION,
            adapter_contract_version=_ADAPTER_VERSION,
        ),
    )
    admitted = observed.admission
    assert admitted.status == "queued"
    completed = observed.onboarding
    assert completed.status == "completed"
    assert completed.first_run_id == admitted.run_id
    assert not completed.replayed

    if terminal_status == "cancelled":
        mutation = execution.request_cancel(
            request,
            project_id=saga.default_project_id,
            run_id=admitted.run_id,
            reason="test cancellation after admission",
        )
    else:
        lease = execution.claim_next_run(
            worker_id="onboarding-test-worker",
            lease_duration=timedelta(minutes=1),
        )
        assert lease is not None and lease.run_id == admitted.run_id
        mutation = execution.transition_run(
            run_id=admitted.run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            target_status="failed",
            payload={"reason": "injected worker failure"},
            trace_id="onboarding-test-worker",
        )
    assert mutation.status == terminal_status

    replay = harness.workflow.advance(scope)
    assert replay.status == "completed"
    assert replay.first_run_id == admitted.run_id
    assert replay.replayed
    with harness.sessions() as db:
        stored = db.get(TenantOnboardingRecord, scope.onboarding_id)
        assert stored is not None and stored.status == "completed"
        assert stored.failure_stage is None
        assert stored.compensation_cursor is None
    assert harness.runtime.compensated_partitions == set()
    assert harness.runtime.compensated_projects == set()


def test_first_run_observer_rejects_an_invented_uncommitted_admission(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _activate(harness, suffix="invented-run")
    saga = _saga(harness, scope)
    request = SqlAlchemyContextResolver(
        harness.sessions, _compatibility_policy()
    ).resolve_request_context(
        actor_id=saga.user_id,
        tenant_id=saga.tenant_id,
        space_id=saga.space_id,
        trace_id="invented-first-run",
    )
    invented = RunAdmission(
        run_id=uuid4(),
        task_id=uuid4(),
        session_id=None,
        status="queued",
        quota_reservation_id=uuid4(),
        event_sequence=2,
        replayed=False,
    )

    with pytest.raises(OnboardingWorkflowError) as raised:
        harness.composition.first_run_observer.record_committed_admission(
            scope=scope,
            request=request,
            project_id=saga.default_project_id,
            admission=invented,
        )

    assert raised.value.code == "first_run_not_admitted"
    assert _saga(harness, scope).status == "active"


def test_first_run_adapter_replays_committed_run_when_observation_is_retried(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _activate(harness, suffix="observation-retry")
    saga = _saga(harness, scope)
    request = SqlAlchemyContextResolver(
        harness.sessions, _compatibility_policy()
    ).resolve_request_context(
        actor_id=saga.user_id,
        tenant_id=saga.tenant_id,
        space_id=saga.space_id,
        trace_id="first-run-observation-retry",
    )
    execution = ExecutionControlPlane(harness.sessions)
    task_id = execution.create_task(
        request,
        project_id=saga.default_project_id,
        title="Committed before observation",
    )
    adapter = harness.composition.execution_adapter(execution)
    wrong_scope = OnboardingScope(
        onboarding_id=scope.onboarding_id,
        registration_id=scope.registration_id,
        actor_id=uuid4(),
        tenant_id=scope.tenant_id,
    )
    revisions = ExecutionRevisionSet(
        product_revision="wave1-product",
        upstream_revision=_SOURCE_REVISION,
        schema_revision=_SCHEMA_REVISION,
        adapter_contract_version=_ADAPTER_VERSION,
    )

    def admit(admission_scope: OnboardingScope):
        return adapter.admit_first_run(
            admission_scope,
            request,
            project_id=saga.default_project_id,
            task_id=task_id,
            session_id=None,
            input_payload={"prompt": "Verify post-commit observation"},
            quota_resource="interactive_runs",
            quota_units=1,
            idempotency_key="first-run-observation-retry",
            revisions=revisions,
        )

    with pytest.raises(OnboardingWorkflowError) as raised:
        admit(wrong_scope)
    assert raised.value.code == "first_run_scope_mismatch"
    assert _saga(harness, scope).status == "active"

    observed = admit(scope)
    assert observed.admission.replayed
    assert observed.onboarding.status == "completed"
    assert observed.onboarding.first_run_id == observed.admission.run_id


def test_runtime_retries_exhaust_to_compensation_without_deleting_identity(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix="runtime-failure")
    _seed_active_placement(harness)
    _dispatch_one(harness)
    assert _saga(harness, scope).status == "billing_ready"
    harness.runtime.allocation_failures_remaining = 3

    first, second, third = _failure_times()
    assert harness.workflow.advance(scope, now=first).status == "billing_ready"
    assert harness.workflow.advance(scope, now=second).status == "billing_ready"
    exhausted = harness.workflow.advance(scope, now=third)
    assert exhausted.status == "compensating"
    assert exhausted.attempt_count == 0
    assert len(harness.runtime.allocation_attempts) == 3

    runtime_compensated = harness.workflow.advance(scope, now=third + timedelta(seconds=1))
    assert runtime_compensated.status == "compensating"
    fully_compensated = harness.workflow.advance(scope, now=third + timedelta(seconds=2))
    assert fully_compensated.status == "compensated"

    saga = _saga(harness, scope)
    with harness.sessions() as db:
        tenant = db.get(Tenant, saga.tenant_id)
        space = db.get(Space, saga.space_id)
        subscription = db.get(BillingSubscriptionRecord, saga.subscription_id)
        entitlement = db.get(BillingEntitlementRecord, saga.entitlement_id)
        assert db.get(GlobalUser, saga.user_id) is not None
        assert db.get(PasswordCredential, saga.user_id) is not None
        assert tenant is not None and tenant.status == "suspended"
        assert space is not None and space.status == "suspended"
        assert subscription is not None and subscription.status == "canceled"
        assert entitlement is not None and entitlement.status == "suspended"
        assert db.get(RuntimePartitionRecord, saga.runtime_partition_id) is None
    assert saga.failure_stage == "billing_ready"
    assert saga.compensated_at is not None
    assert len(harness.runtime.partition_compensation_attempts) == 1
    assert len(harness.runtime.compensated_partitions) == 1


def test_compensation_retry_exhaustion_requires_manual_review(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix="manual-review")
    _seed_active_placement(harness)
    _dispatch_one(harness)
    harness.runtime.allocation_failures_remaining = 3
    harness.runtime.partition_compensation_failures_remaining = 3

    first, second, third = _failure_times()
    harness.workflow.advance(scope, now=first)
    harness.workflow.advance(scope, now=second)
    assert harness.workflow.advance(scope, now=third).status == "compensating"

    compensation_first = third + timedelta(seconds=1)
    compensation_second = compensation_first + timedelta(seconds=6)
    compensation_third = compensation_second + timedelta(seconds=11)
    assert harness.workflow.advance(scope, now=compensation_first).status == "compensating"
    assert harness.workflow.advance(scope, now=compensation_second).status == "compensating"
    reviewed = harness.workflow.advance(scope, now=compensation_third)
    assert reviewed.status == "manual_review"

    saga = _saga(harness, scope)
    with harness.sessions() as db:
        tenant = db.get(Tenant, saga.tenant_id)
        space = db.get(Space, saga.space_id)
        assert db.get(GlobalUser, saga.user_id) is not None
        assert db.get(PasswordCredential, saga.user_id) is not None
        assert tenant is not None and tenant.status == "provisioning"
        assert space is not None and space.status == "suspended"
    assert saga.failure_stage == "billing_ready"
    assert saga.last_error_code == "compensation_failed"
    assert saga.compensated_at is None
    assert len(harness.runtime.partition_compensation_attempts) == 3
    assert harness.runtime.compensated_partitions == set()


def test_replay_is_idempotent_and_live_claim_lease_fences_work(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix="lease")
    _seed_active_placement(harness)
    with harness.sessions() as db:
        billing_event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(scope.onboarding_id),
                ControlPlaneOutboxEvent.event_type == _BILLING_EVENT,
            )
        )
        assert billing_event is not None
        replay_payload = dict(billing_event.payload)

    claimed_at = datetime.now(timezone.utc) + timedelta(minutes=1)
    claim_token = uuid4()
    with harness.sessions.begin() as db:
        saga = db.get(TenantOnboardingRecord, scope.onboarding_id)
        assert saga is not None
        saga.claim_token = claim_token
        saga.claimed_at = claimed_at
        saga.lease_expires_at = claimed_at + timedelta(seconds=30)

    fenced = harness.workflow.advance(scope, now=claimed_at + timedelta(seconds=1))
    assert fenced.status == "tenant_created"
    assert fenced.replayed
    assert fenced.attempt_count == 0
    with harness.sessions() as db:
        saga = db.get(TenantOnboardingRecord, scope.onboarding_id)
        assert saga is not None and saga.claim_token == claim_token

    billing = harness.workflow.advance(scope, now=claimed_at + timedelta(seconds=31))
    assert billing.status == "billing_ready"
    runtime = harness.workflow.advance(scope, now=claimed_at + timedelta(seconds=32))
    assert runtime.status == "runtime_ready"
    project = harness.workflow.advance(scope, now=claimed_at + timedelta(seconds=33))
    assert project.status == "project_ready"
    active = harness.workflow.advance(scope, now=claimed_at + timedelta(seconds=34))
    assert active.status == "active"
    calls_before_replay = (
        tuple(harness.runtime.allocation_attempts),
        tuple(harness.runtime.project_attempts),
    )

    replay = harness.workflow.handle_event(
        event_type=_BILLING_EVENT,
        payload=replay_payload,
    )
    assert replay.status == "active"
    assert replay.replayed
    assert (
        tuple(harness.runtime.allocation_attempts),
        tuple(harness.runtime.project_attempts),
    ) == calls_before_replay
    assert len(harness.runtime.allocations) == 1
    assert len(harness.runtime.projects) == 1


def test_claim_persists_lease_recovery_wakeup_and_expired_claim_is_reclaimed(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix="claim-recovery")
    claimed_at = datetime.now(timezone.utc)

    claim, _result = harness.workflow._claim(scope, claimed_at)
    assert claim is not None
    saga = _saga(harness, scope)
    assert saga.claim_token == claim.token
    assert saga.lease_expires_at is not None

    with harness.sessions() as db:
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_key == str(scope.onboarding_id),
                    ControlPlaneOutboxEvent.event_type == _BILLING_EVENT,
                    ControlPlaneOutboxEvent.published_at.is_(None),
                )
            )
        )
        recovery = next(
            event
            for event in events
            if event.payload.get("version") == claim.version
            and event.payload.get("expected_status") == "tenant_created"
        )
        assert recovery.available_at == saga.lease_expires_at

    recovered = harness.workflow.advance(
        scope,
        now=saga.lease_expires_at + timedelta(seconds=1),
        expected_status="tenant_created",
        expected_version=claim.version,
    )
    assert recovered.status == "billing_ready"
    assert not recovered.replayed
    assert _saga(harness, scope).claim_token is None

    stale_recovery = harness.workflow.handle_event(
        event_type=_BILLING_EVENT,
        payload=dict(recovery.payload),
    )
    assert stale_recovery.status == "billing_ready"
    assert stale_recovery.replayed


def test_slow_claimant_cannot_commit_after_database_lease_expiry(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix="expired-commit")
    started_at = datetime.now(timezone.utc)
    claim, _result = harness.workflow._claim(scope, started_at)
    assert claim is not None

    with harness.sessions.begin() as db:
        saga = db.get(TenantOnboardingRecord, scope.onboarding_id)
        assert saga is not None
        saga.claimed_at = started_at - timedelta(minutes=2)
        saga.lease_expires_at = started_at - timedelta(minutes=1)

    with pytest.raises(OnboardingWorkflowError) as raised:
        harness.workflow._bootstrap_billing(claim, started_at)
    assert raised.value.code == "onboarding_claim_expired"
    with harness.sessions() as db:
        saga = db.get(TenantOnboardingRecord, scope.onboarding_id)
        assert saga is not None and saga.status == "tenant_created"
        assert db.get(BillingSubscriptionRecord, saga.subscription_id) is None


def test_frozen_runtime_target_survives_retry_and_placement_drain(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix="frozen-placement")
    _seed_active_placement(harness)
    _dispatch_one(harness)
    harness.runtime.allocation_failures_remaining = 1

    first_attempt = datetime.now(timezone.utc) + timedelta(minutes=1)
    failed = harness.workflow.advance(scope, now=first_attempt)
    assert failed.status == "billing_ready"
    frozen = _saga(harness, scope)
    assert frozen.runtime_placement_id == harness.placement_id
    assert frozen.runtime_target_snapshot is not None
    assert frozen.runtime_target_snapshot["schema_version"] == 2
    assert frozen.runtime_target_snapshot["provider_binding"] == {
        "provider_type": "test-runtime",
        "binding_revision": "test-binding-v1",
        "binding_hash": _hash(f"test-binding-v1:{harness.placement_id}"),
    }
    assert frozen.runtime_request_hash is not None

    # A deployment rotation after the Saga freeze must not retarget retries.
    harness.runtime.binding_revision = "test-binding-v2"

    replacement_id = uuid4()
    with harness.sessions.begin() as db:
        placement = db.get(RuntimePlacementRecord, harness.placement_id)
        assert placement is not None
        placement.status = "draining"
        db.add(
            RuntimePlacementRecord(
                id=replacement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1b",
                database_cluster_ref="runtime-db-b",
                object_store_ref="runtime-objects-b",
                kms_key_ref="runtime-kms-b",
                official_schema_revision=_SCHEMA_REVISION,
                capacity_class="starter",
                status="active",
            )
        )

    runtime_ready = harness.workflow.advance(
        scope,
        now=first_attempt + timedelta(seconds=6),
    )
    assert runtime_ready.status == "runtime_ready"
    assert [target.placement_id for target in harness.runtime.partition_targets] == [
        harness.placement_id,
        harness.placement_id,
    ]
    assert [
        target.provider_binding.binding_revision for target in harness.runtime.partition_targets
    ] == ["test-binding-v1", "test-binding-v1"]
    with harness.sessions() as db:
        partition = db.get(RuntimePartitionRecord, frozen.runtime_partition_id)
        assert partition is not None and partition.placement_id == harness.placement_id

    assert (
        harness.workflow.advance(scope, now=first_attempt + timedelta(seconds=7)).status
        == "project_ready"
    )
    assert (
        harness.workflow.advance(scope, now=first_attempt + timedelta(seconds=8)).status
        == "active"
    )


@pytest.mark.parametrize(
    ("record_name", "field_name", "invalid_value"),
    (
        ("partition", "tenant_id", uuid4()),
        ("partition", "space_id", uuid4()),
        ("partition", "placement_id", uuid4()),
        ("partition", "runtime_type", "other-runtime"),
        ("partition", "status", "provisioning"),
        ("partition", "runtime_version", "0.10.0"),
        ("partition", "physical_partition_key", "different-partition"),
        ("partition", "placement_generation", 2),
        ("partition", "source_revision", "f" * 40),
        ("partition", "adapter_contract_version", "0.1.0"),
        ("alias", "runtime_partition_id", uuid4()),
        ("alias", "user_id", uuid4()),
        ("alias", "runtime_user_key", "different-user"),
        ("alias", "status", "retired"),
    ),
)
def test_runtime_partition_replay_match_requires_every_authoritative_field(
    record_name: str,
    field_name: str,
    invalid_value: object,
) -> None:
    tenant_id, space_id, user_id = uuid4(), uuid4(), uuid4()
    partition_id, placement_id = uuid4(), uuid4()
    target = RuntimePartitionTarget(
        onboarding_id=uuid4(),
        tenant_id=tenant_id,
        space_id=space_id,
        user_id=user_id,
        runtime_partition_id=partition_id,
        placement_id=placement_id,
        runtime_type="omnigent",
        data_region="cn-east-1",
        failure_domain="cn-east-1a",
        official_schema_revision=_SCHEMA_REVISION,
        capacity_class="starter",
        provider_binding=RuntimeProviderBindingSnapshot(
            provider_type="signed-http",
            binding_revision="runtime-binding-v1",
            binding_hash="b" * 64,
        ),
    )
    allocation = RuntimePartitionAllocation(
        runtime_version=_RUNTIME_VERSION,
        physical_partition_key="partition-1",
        placement_generation=1,
        source_revision=_SOURCE_REVISION,
        adapter_contract_version=_ADAPTER_VERSION,
        runtime_user_key=f"user-{user_id.hex}",
        receipt_hash="a" * 64,
    )
    partition = RuntimePartitionRecord(
        id=partition_id,
        tenant_id=tenant_id,
        space_id=space_id,
        placement_id=placement_id,
        runtime_type="omnigent",
        runtime_version=_RUNTIME_VERSION,
        physical_partition_key="partition-1",
        placement_generation=1,
        source_revision=_SOURCE_REVISION,
        adapter_contract_version=_ADAPTER_VERSION,
        status="active",
    )
    alias = RuntimeIdentityAliasRecord(
        runtime_partition_id=partition_id,
        user_id=user_id,
        runtime_user_key=f"user-{user_id.hex}",
        status="active",
    )
    assert TenantOnboardingWorkflow._runtime_partition_matches_allocation(
        partition=partition,
        target=target,
        allocation=allocation,
    )
    assert TenantOnboardingWorkflow._runtime_alias_matches_allocation(
        alias=alias,
        target=target,
        allocation=allocation,
    )

    record = partition if record_name == "partition" else alias
    setattr(record, field_name, invalid_value)

    matches = TenantOnboardingWorkflow._runtime_partition_matches_allocation(
        partition=partition,
        target=target,
        allocation=allocation,
    ) and TenantOnboardingWorkflow._runtime_alias_matches_allocation(
        alias=alias,
        target=target,
        allocation=allocation,
    )
    assert not matches


@pytest.mark.parametrize("conflict", ("placement", "alias"))
def test_preexisting_runtime_partition_conflict_never_reaches_runtime_ready(
    onboarding_workflow: _Harness,
    conflict: str,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix=f"partition-conflict-{conflict}")
    _seed_active_placement(harness)
    _dispatch_one(harness)
    saga = _saga(harness, scope)
    assert saga.status == "billing_ready"

    partition_placement_id = harness.placement_id
    with harness.sessions.begin() as db:
        if conflict == "placement":
            partition_placement_id = uuid4()
            db.add(
                RuntimePlacementRecord(
                    id=partition_placement_id,
                    runtime_type="omnigent",
                    data_region="other-region",
                    failure_domain="other-region-a",
                    database_cluster_ref="wrong-runtime-db",
                    object_store_ref="wrong-runtime-objects",
                    kms_key_ref="wrong-runtime-kms",
                    official_schema_revision=_SCHEMA_REVISION,
                    capacity_class="starter",
                    status="active",
                )
            )
            db.flush()
        physical_key = str(int(saga.runtime_partition_id.hex[:12], 16) or 1)
        db.add(
            RuntimePartitionRecord(
                id=saga.runtime_partition_id,
                tenant_id=saga.tenant_id,
                space_id=saga.space_id,
                placement_id=partition_placement_id,
                runtime_type="omnigent",
                runtime_version=_RUNTIME_VERSION,
                physical_partition_key=physical_key,
                placement_generation=1,
                source_revision=_SOURCE_REVISION,
                adapter_contract_version=_ADAPTER_VERSION,
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimeIdentityAliasRecord(
                runtime_partition_id=saga.runtime_partition_id,
                user_id=saga.user_id,
                runtime_user_key=(
                    "wrong-runtime-user" if conflict == "alias" else f"user-{saga.user_id.hex}"
                ),
                status="active",
            )
        )

    failed = harness.workflow.advance(
        scope,
        now=datetime.now(timezone.utc) + timedelta(minutes=1),
    )

    assert failed.status == "compensating"
    stored = _saga(harness, scope)
    assert stored.runtime_ready_at is None
    assert stored.failure_stage == "billing_ready"
    assert stored.last_error_code == "runtime_partition_conflict"


def test_workflow_event_requires_exact_integer_fence_and_rejects_future_version(
    onboarding_workflow: _Harness,
) -> None:
    harness = onboarding_workflow
    scope = _registration_to_tenant_created(harness, suffix="event-fence")
    with harness.sessions() as db:
        billing_event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(scope.onboarding_id),
                ControlPlaneOutboxEvent.event_type == _BILLING_EVENT,
            )
        )
        assert billing_event is not None
        valid_payload = dict(billing_event.payload)

    for invalid_version in (None, True, 1.5, "1"):
        invalid_payload = {**valid_payload, "version": invalid_version}
        with pytest.raises(OnboardingWorkflowError) as raised:
            harness.workflow.handle_event(
                event_type=_BILLING_EVENT,
                payload=invalid_payload,
            )
        assert raised.value.code == "onboarding_event_invalid"
    assert _saga(harness, scope).status == "tenant_created"

    billing_ready = harness.workflow.handle_event(
        event_type=_BILLING_EVENT,
        payload=valid_payload,
    )
    assert billing_ready.status == "billing_ready"
    with harness.sessions() as db:
        runtime_event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(scope.onboarding_id),
                ControlPlaneOutboxEvent.event_type == _RUNTIME_EVENT,
            )
        )
        assert runtime_event is not None
        future_payload = dict(runtime_event.payload)
        future_payload["version"] = int(future_payload["version"]) + 100

    with pytest.raises(OnboardingWorkflowError) as raised:
        harness.workflow.handle_event(
            event_type=_RUNTIME_EVENT,
            payload=future_payload,
        )
    assert raised.value.code == "onboarding_event_stale"
    assert _saga(harness, scope).status == "billing_ready"
    assert harness.runtime.allocation_attempts == []
