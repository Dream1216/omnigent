from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane import (
    CapabilityTokenRecord,
    ExecutionControlPlane,
    ExecutionRevisionSet,
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    QuotaReservationRecord,
    RunDispatchRecord,
    RunnerRegistrationRecord,
    RunRecord,
    RuntimePlacementRecord,
    SaasBase,
    SchedulingControlPlane,
    SchedulingError,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
    TenantQueueShareRecord,
)


@dataclass(frozen=True, slots=True)
class SchedulingScope:
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    owner_id: UUID
    request: RequestContext


@dataclass(frozen=True, slots=True)
class SchedulingFixture:
    factory: sessionmaker[Session]
    execution: ExecutionControlPlane
    scheduling: SchedulingControlPlane
    placement_id: UUID
    scopes: tuple[SchedulingScope, SchedulingScope]


def _scope(index: int) -> SchedulingScope:
    owner_id = uuid4()
    tenant_id = uuid4()
    space_id = uuid4()
    project_id = uuid4()
    return SchedulingScope(
        tenant_id,
        space_id,
        project_id,
        owner_id,
        RequestContext(
            actor_id=owner_id,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            user_security_version=1,
            tenant_membership_version=1,
            space_membership_version=1,
            trace_id=f"scheduling-{index}",
        ),
    )


@pytest.fixture
def scheduling_fixture() -> Iterator[SchedulingFixture]:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    placement_id = uuid4()
    scopes = (_scope(1), _scope(2))
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="db-a",
                object_store_ref="objects-a",
                kms_key_ref="kms-a",
                official_schema_revision="runtime-schema-v1",
                capacity_class="shared-medium",
                status="active",
            )
        )
        for index, scope in enumerate(scopes, start=1):
            db.add(GlobalUser(id=scope.owner_id, status="active", security_version=1))
            db.add(
                Tenant(
                    id=scope.tenant_id,
                    slug=f"scheduler-{index}-{scope.tenant_id.hex}",
                    name=f"Scheduler tenant {index}",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                )
            )
            db.flush()
            db.add(
                Space(
                    id=scope.space_id,
                    tenant_id=scope.tenant_id,
                    slug="engineering",
                    name="Engineering",
                    status="active",
                )
            )
            db.flush()
            db.add(
                TenantMembership(
                    tenant_id=scope.tenant_id,
                    user_id=scope.owner_id,
                    role="owner",
                    status="active",
                    version=1,
                )
            )
            db.flush()
            db.add(
                SpaceMembership(
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    user_id=scope.owner_id,
                    role="owner",
                    status="active",
                    version=1,
                )
            )
            db.flush()
            db.add(
                ProjectRecord(
                    id=scope.project_id,
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    name="Scheduling project",
                    visibility="restricted",
                    created_by=scope.owner_id,
                    status="active",
                    authorization_version=1,
                )
            )
            db.flush()
            db.add(
                ProjectMembershipRecord(
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    project_id=scope.project_id,
                    subject_type="user",
                    subject_id=scope.owner_id,
                    role="owner",
                    status="active",
                    created_by=scope.owner_id,
                    version=1,
                )
            )
    yield SchedulingFixture(
        factory,
        ExecutionControlPlane(factory),
        SchedulingControlPlane(factory),
        placement_id,
        scopes,
    )
    engine.dispose()


def _revisions() -> ExecutionRevisionSet:
    return ExecutionRevisionSet(
        product_revision="product-revision",
        upstream_revision="upstream-revision",
        schema_revision="p4a000000001",
        adapter_contract_version="0.2.0",
    )


def _admit(fixture: SchedulingFixture, scope: SchedulingScope, *, key: str) -> UUID:
    fixture.execution.configure_quota(
        scope.request,
        project_id=scope.project_id,
        resource="run_units",
        limit_units=10,
    )
    task_id = fixture.execution.create_task(
        scope.request,
        project_id=scope.project_id,
        title=f"Scheduled task {key}",
    )
    admitted = fixture.execution.admit_run(
        scope.request,
        project_id=scope.project_id,
        task_id=task_id,
        session_id=None,
        input_payload={"key": key},
        quota_resource="run_units",
        quota_units=1,
        idempotency_key=key,
        revisions=_revisions(),
    )
    return admitted.run_id


def _pool(fixture: SchedulingFixture) -> UUID:
    return fixture.scheduling.create_pool(
        placement_id=fixture.placement_id,
        name="shared-interactive",
        queue_class="interactive",
        capacity_slots=4,
        reserved_slots=1,
        protocol_version=2,
        source_revision="upstream-revision",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )


def _finish_run(
    fixture: SchedulingFixture,
    *,
    run_id: UUID,
    lease_token: UUID,
    fence_token: int,
    now: datetime,
) -> None:
    fixture.execution.transition_run(
        run_id=run_id,
        lease_token=lease_token,
        fence_token=fence_token,
        target_status="starting",
        trace_id="runner-starting",
        now=now,
    )
    fixture.execution.transition_run(
        run_id=run_id,
        lease_token=lease_token,
        fence_token=fence_token,
        target_status="running",
        trace_id="runner-running",
        now=now + timedelta(seconds=1),
    )
    fixture.execution.transition_run(
        run_id=run_id,
        lease_token=lease_token,
        fence_token=fence_token,
        target_status="succeeded",
        trace_id="runner-succeeded",
        now=now + timedelta(seconds=2),
    )


def test_weighted_fair_claim_prevents_hot_tenant_starvation_and_scopes_capability(
    scheduling_fixture: SchedulingFixture,
) -> None:
    fixture = scheduling_fixture
    now = datetime(2026, 8, 4, 10, 0, tzinfo=timezone.utc)
    pool_id = _pool(fixture)
    for scope in fixture.scopes:
        fixture.scheduling.configure_tenant_share(
            tenant_id=scope.tenant_id,
            pool_id=pool_id,
            weight=1,
            max_concurrent=1,
            burst_limit=2,
        )
    hot_runs = tuple(_admit(fixture, fixture.scopes[0], key=f"hot-{index}") for index in range(3))
    quiet_run = _admit(fixture, fixture.scopes[1], key="quiet-1")
    for run_id in (*hot_runs, quiet_run):
        assert not fixture.scheduling.prepare_dispatch(
            run_id=run_id,
            pool_id=pool_id,
            required_capabilities=["shell"],
            eligible_at=now,
            maximum_wait=timedelta(hours=1),
        )
    assert fixture.scheduling.prepare_dispatch(
        run_id=hot_runs[0],
        pool_id=pool_id,
        required_capabilities=["shell"],
        eligible_at=now,
        maximum_wait=timedelta(hours=1),
    )
    connection = fixture.scheduling.register_runner(
        pool_id=pool_id,
        instance_key="runner-a",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream-revision",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["git", "shell"],
        max_concurrency=1,
        now=now,
    )

    first = fixture.scheduling.claim_fair_run(
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        lease_duration=timedelta(minutes=5),
        capability_actions=["worktree.read", "worktree.write"],
        capability_resource_scope={"worktree_id": "wt-a"},
        now=now + timedelta(seconds=1),
    )
    assert first is not None
    with fixture.factory() as db:
        first_run = db.get(RunRecord, first.run_id)
        assert first_run is not None
        first_tenant = first_run.tenant_id
    verified = fixture.scheduling.verify_capability(
        capability_token=first.capability_token,
        runner_id=first.runner_id,
        run_id=first.run_id,
        action="worktree.write",
        required_resource_scope={
            "tenant_id": str(first_tenant),
            "worktree_id": "wt-a",
        },
        now=now + timedelta(seconds=2),
    )
    assert verified.tenant_id == first_tenant
    other_tenant = next(
        scope.tenant_id for scope in fixture.scopes if scope.tenant_id != first_tenant
    )
    with pytest.raises(SchedulingError) as cross_scope:
        fixture.scheduling.verify_capability(
            capability_token=first.capability_token,
            runner_id=first.runner_id,
            run_id=first.run_id,
            action="worktree.write",
            required_resource_scope={"tenant_id": str(other_tenant)},
            now=now + timedelta(seconds=2),
        )
    assert cross_scope.value.code == "capability_scope_denied"
    _finish_run(
        fixture,
        run_id=first.run_id,
        lease_token=first.lease_token,
        fence_token=first.fence_token,
        now=now + timedelta(seconds=3),
    )
    assert not fixture.scheduling.release_dispatch(
        run_id=first.run_id,
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        fence_token=first.fence_token,
        requeue=False,
        now=now + timedelta(seconds=6),
    )

    second = fixture.scheduling.claim_fair_run(
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        lease_duration=timedelta(minutes=5),
        capability_actions=["worktree.read"],
        capability_resource_scope={"worktree_id": "wt-b"},
        now=now + timedelta(seconds=7),
    )
    assert second is not None
    with fixture.factory() as db:
        second_run = db.get(RunRecord, second.run_id)
        assert second_run is not None
        second_tenant = second_run.tenant_id
    assert first_tenant != second_tenant
    assert {first_tenant, second_tenant} == {
        fixture.scopes[0].tenant_id,
        fixture.scopes[1].tenant_id,
    }

    replacement = fixture.scheduling.register_runner(
        pool_id=pool_id,
        instance_key="runner-a",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream-revision",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["git", "shell"],
        max_concurrency=1,
        now=now + timedelta(seconds=8),
    )
    assert replacement.runner_id == connection.runner_id
    assert replacement.connection_generation == connection.connection_generation + 1
    with pytest.raises(SchedulingError) as stale_connection:
        fixture.scheduling.heartbeat_runner(
            runner_id=connection.runner_id,
            connection_generation=connection.connection_generation,
            connection_token=connection.connection_token,
            now=now + timedelta(seconds=9),
        )
    assert stale_connection.value.code == "runner_connection_stale"
    with pytest.raises(SchedulingError) as revoked_capability:
        fixture.scheduling.verify_capability(
            capability_token=second.capability_token,
            runner_id=second.runner_id,
            run_id=second.run_id,
            action="worktree.read",
            required_resource_scope={"worktree_id": "wt-b"},
            now=now + timedelta(seconds=9),
        )
    assert revoked_capability.value.code == "capability_expired"


def test_runner_compatibility_stale_heartbeat_and_dispatch_dead_letter(
    scheduling_fixture: SchedulingFixture,
) -> None:
    fixture = scheduling_fixture
    now = datetime(2026, 8, 4, 11, 0, tzinfo=timezone.utc)
    pool_id = _pool(fixture)
    scope = fixture.scopes[0]
    fixture.scheduling.configure_tenant_share(
        tenant_id=scope.tenant_id,
        pool_id=pool_id,
        weight=2,
        max_concurrent=1,
        burst_limit=1,
    )
    with pytest.raises(SchedulingError) as incompatible:
        fixture.scheduling.register_runner(
            pool_id=pool_id,
            instance_key="runner-invalid",
            failure_domain="cn-east-1b",
            protocol_version=2,
            source_revision="unapproved",
            schema_revision="runtime-schema-v1",
            adapter_contract_version="0.2.0",
            capabilities=["shell"],
            max_concurrency=1,
            now=now,
        )
    assert incompatible.value.code == "runner_compatibility_rejected"
    with pytest.raises(SchedulingError) as spoofed_domain:
        fixture.scheduling.register_runner(
            pool_id=pool_id,
            instance_key="runner-spoofed-domain",
            failure_domain="cn-east-1b",
            protocol_version=2,
            source_revision="upstream-revision",
            schema_revision="runtime-schema-v1",
            adapter_contract_version="0.2.0",
            capabilities=["shell"],
            max_concurrency=1,
            now=now,
        )
    assert spoofed_domain.value.code == "runner_failure_domain_mismatch"
    connection = fixture.scheduling.register_runner(
        pool_id=pool_id,
        instance_key="runner-stale",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream-revision",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["shell"],
        max_concurrency=1,
        now=now,
    )
    assert fixture.scheduling.expire_stale_runners(
        heartbeat_timeout=timedelta(seconds=30),
        now=now + timedelta(seconds=31),
    ) == (connection.runner_id,)
    with pytest.raises(SchedulingError) as unavailable:
        fixture.scheduling.heartbeat_runner(
            runner_id=connection.runner_id,
            connection_generation=connection.connection_generation,
            connection_token=connection.connection_token,
            now=now + timedelta(seconds=32),
        )
    assert unavailable.value.code == "runner_unavailable"

    run_id = _admit(fixture, scope, key="deadline")
    assert not fixture.scheduling.prepare_dispatch(
        run_id=run_id,
        pool_id=pool_id,
        required_capabilities=["shell"],
        eligible_at=now,
        maximum_wait=timedelta(minutes=1),
    )
    assert fixture.scheduling.dead_letter_expired_dispatches(now=now + timedelta(minutes=2)) == (
        run_id,
    )
    with fixture.factory() as db:
        run = db.get(RunRecord, run_id)
        dispatch = db.get(RunDispatchRecord, run_id)
        reservation = db.scalar(
            sa.select(QuotaReservationRecord).where(QuotaReservationRecord.run_id == run_id)
        )
        share = db.scalar(
            sa.select(TenantQueueShareRecord).where(
                TenantQueueShareRecord.tenant_id == scope.tenant_id
            )
        )
        runner = db.get(RunnerRegistrationRecord, connection.runner_id)
        assert run is not None and run.status == "orphaned"
        assert dispatch is not None and dispatch.status == "dead_letter"
        assert dispatch.dead_letter_reason == "maximum_wait_exceeded"
        assert reservation is not None and reservation.status == "released"
        assert share is not None and share.virtual_runtime == 0 and share.active_leases == 0
        assert runner is not None and runner.status == "offline"
        assert db.scalar(sa.select(sa.func.count()).select_from(CapabilityTokenRecord)) == 0
