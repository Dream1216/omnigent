from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane import (
    ChangeSetGroupRecord,
    ChangeSetRecord,
    ChangeSetSpec,
    CompositeRemovalImpactProvider,
    ControlPlaneOutboxEvent,
    EgressPolicyRecord,
    ExecutionControlPlane,
    ExecutionProfileRecord,
    ExecutionRevisionSet,
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    ProjectRemovalImpactProvider,
    RunnerRegistrationRecord,
    RunRecord,
    RuntimePlacementRecord,
    SaasBase,
    SchedulingControlPlane,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
    WorktreeControlPlane,
    WorktreeControlPlaneError,
    WorktreeEventRecord,
    WorktreeInstanceRecord,
    WorktreeQuotaRecord,
    WorktreeRemovalImpactProvider,
)
from saas.control_plane.preview_execution import (
    PreviewExecutionControlPlane,
    PreviewExecutionControlPlaneError,
    PreviewExecutionPolicy,
    PreviewRunnerExecutionAuthority,
)
from saas.control_plane.preview_models import PreviewCommandRecord, PreviewExecutionRecord
from saas.runner_adapter import (
    CheckpointArtifact,
    FilesystemRecoveryArtifactStore,
    RunnerWorktreeAdapter,
    RunnerWorktreeAdapterError,
    StaticRepositoryMirrorResolver,
)
from saas.runner_adapter.worktrees import ObjectRecoveryArtifactStore


class _FakeArtifactStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, key: str, data: bytes) -> None:
        self.objects[key] = data

    def get(self, key: str) -> bytes:
        try:
            return self.objects[key]
        except KeyError:
            raise KeyError(key) from None

    def exists(self, key: str) -> bool:
        return key in self.objects


@dataclass(frozen=True, slots=True)
class WorktreeFixture:
    factory: sessionmaker[Session]
    request: RequestContext
    project_id: UUID
    placement_id: UUID
    execution_profile_id: UUID
    execution_profile_hash: str
    execution: ExecutionControlPlane
    scheduling: SchedulingControlPlane
    worktrees: WorktreeControlPlane


@dataclass(frozen=True, slots=True)
class LeasedRun:
    run_id: UUID
    pool_id: UUID
    runner_id: UUID
    runner_generation: int
    runner_token: str
    run_lease_token: UUID
    run_fence_token: int
    capability_token: str


@pytest.fixture
def worktree_fixture(tmp_path: Path) -> Iterator[WorktreeFixture]:
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'worktree-control-plane.sqlite3'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    actor_id = uuid4()
    tenant_id = uuid4()
    space_id = uuid4()
    project_id = uuid4()
    placement_id = uuid4()
    execution_profile_id = uuid4()
    execution_profile_hash = "3" * 64
    request = RequestContext(
        actor_id=actor_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="worktree-fixture",
    )
    with factory.begin() as db:
        db.add(GlobalUser(id=actor_id, status="active", security_version=1))
        db.add(
            Tenant(
                id=tenant_id,
                slug=f"worktree-{tenant_id.hex}",
                name="Worktree tenant",
                status="active",
                plan="team",
                home_region="cn-east-1",
            )
        )
        db.flush()
        db.add(
            Space(
                id=space_id,
                tenant_id=tenant_id,
                slug="engineering",
                name="Engineering",
                status="active",
            )
        )
        db.flush()
        db.add(
            TenantMembership(
                tenant_id=tenant_id,
                user_id=actor_id,
                role="owner",
                status="active",
                version=1,
            )
        )
        db.flush()
        db.add(
            SpaceMembership(
                tenant_id=tenant_id,
                space_id=space_id,
                user_id=actor_id,
                role="owner",
                status="active",
                version=1,
            )
        )
        db.flush()
        db.add(
            ProjectRecord(
                id=project_id,
                tenant_id=tenant_id,
                space_id=space_id,
                name="Worktree project",
                visibility="restricted",
                created_by=actor_id,
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                subject_type="user",
                subject_id=actor_id,
                role="owner",
                status="active",
                created_by=actor_id,
                version=1,
            )
        )
        egress_policy_id = uuid4()
        db.add(
            EgressPolicyRecord(
                id=egress_policy_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                created_by=actor_id,
                name="worktree-default-deny",
                rules=[],
                rules_hash="0" * 64,
                allow_private_destinations=False,
                status="active",
                version=1,
            )
        )
        db.flush()
        db.add(
            ExecutionProfileRecord(
                id=execution_profile_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                egress_policy_id=egress_policy_id,
                created_by=actor_id,
                name="worktree-managed-default",
                sandbox_backend="linux_bwrap",
                network_mode="proxy_only",
                root_read_only=True,
                run_as_uid=65532,
                run_as_gid=65532,
                no_new_privileges=True,
                host_socket_access=False,
                syscall_profile_ref="oci-default-v1",
                cpu_millis=1000,
                memory_bytes=512 * 1024 * 1024,
                pids_limit=128,
                allowed_tools=["git", "shell"],
                approval_required_tools=[],
                denied_tools=[],
                config_hash=execution_profile_hash,
                status="active",
                version=1,
            )
        )
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="db-worktree",
                object_store_ref="objects-worktree",
                kms_key_ref="kms-worktree",
                official_schema_revision="runtime-schema-v1",
                capacity_class="shared-medium",
                status="active",
            )
        )
    execution = ExecutionControlPlane(factory)
    scheduling = SchedulingControlPlane(factory)
    yield WorktreeFixture(
        factory,
        request,
        project_id,
        placement_id,
        execution_profile_id,
        execution_profile_hash,
        execution,
        scheduling,
        WorktreeControlPlane(factory, scheduler=scheduling),
    )
    engine.dispose()


def _revisions() -> ExecutionRevisionSet:
    return ExecutionRevisionSet(
        product_revision="product",
        upstream_revision="upstream",
        schema_revision="p4b000000001",
        adapter_contract_version="0.2.0",
    )


def _repository_and_change_set(
    fixture: WorktreeFixture, *, suffix: str = "main"
) -> tuple[UUID, UUID]:
    request = fixture.request
    repository_id = fixture.worktrees.register_repository(
        request,
        project_id=fixture.project_id,
        provider="github-app",
        source_binding_key=f"repo_{suffix}_{uuid4().hex}",
        display_name=f"Repository {suffix}",
        default_branch="main",
    )
    created = fixture.worktrees.create_change_set_group(
        request,
        project_id=fixture.project_id,
        title=f"Change {suffix}",
        specs=(
            ChangeSetSpec(
                repository_id=repository_id,
                base_revision="a" * 40,
                branch_ref=f"refs/heads/codex/{suffix}",
            ),
        ),
    )
    return repository_id, created.change_set_ids[0]


def _configure_worktree_quota(fixture: WorktreeFixture) -> None:
    fixture.worktrees.configure_quota(
        fixture.request,
        project_id=fixture.project_id,
        max_active_instances=4,
        max_active_writers=2,
        max_reserved_bytes=4_000_000,
        max_lease_seconds=300,
        max_lifetime_seconds=3600,
        gc_grace_seconds=10,
    )


def _lease_run(
    fixture: WorktreeFixture,
    *,
    change_set_id: UUID,
    key: str,
    now: datetime,
    pool_id: UUID | None = None,
) -> LeasedRun:
    request = fixture.request
    fixture.execution.configure_quota(
        request,
        project_id=fixture.project_id,
        resource="run_units",
        limit_units=20,
    )
    task_id = fixture.execution.create_task(
        request,
        project_id=fixture.project_id,
        title=f"Worktree task {key}",
    )
    admitted = fixture.execution.admit_run(
        request,
        project_id=fixture.project_id,
        task_id=task_id,
        session_id=None,
        input_payload={"change_set_id": str(change_set_id)},
        quota_resource="run_units",
        quota_units=1,
        idempotency_key=key,
        revisions=_revisions(),
    )
    if pool_id is None:
        pool_id = fixture.scheduling.create_pool(
            placement_id=fixture.placement_id,
            name=f"worktree-{key}",
            queue_class="interactive",
            capacity_slots=2,
            reserved_slots=0,
            protocol_version=2,
            source_revision="upstream",
            schema_revision="runtime-schema-v1",
            adapter_contract_version="0.2.0",
        )
        fixture.scheduling.configure_tenant_share(
            tenant_id=request.tenant_id,
            pool_id=pool_id,
            weight=1,
            max_concurrent=2,
            burst_limit=2,
        )
    fixture.scheduling.prepare_dispatch(
        run_id=admitted.run_id,
        pool_id=pool_id,
        required_capabilities=["git", "shell"],
        execution_profile_id=fixture.execution_profile_id,
        execution_profile_hash=fixture.execution_profile_hash,
        eligible_at=now,
        maximum_wait=timedelta(hours=1),
    )
    connection = fixture.scheduling.register_runner(
        pool_id=pool_id,
        instance_key=f"runner-{key}",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["git", "shell"],
        max_concurrency=1,
        now=now,
    )
    lease = fixture.scheduling.claim_fair_run(
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        lease_duration=timedelta(seconds=120),
        capability_actions=["worktree.read", "worktree.write"],
        capability_resource_scope={"change_set_id": str(change_set_id)},
        now=now + timedelta(seconds=1),
    )
    assert lease is not None
    return LeasedRun(
        lease.run_id,
        pool_id,
        connection.runner_id,
        connection.connection_generation,
        connection.connection_token,
        lease.lease_token,
        lease.fence_token,
        lease.capability_token,
    )


def _allocate(
    fixture: WorktreeFixture,
    leased: LeasedRun,
    change_set_id: UUID,
    *,
    now: datetime,
    access_mode: str = "writer",
    rebuild_from_id: UUID | None = None,
):
    return fixture.worktrees.allocate_worktree(
        capability_token=leased.capability_token,
        runner_id=leased.runner_id,
        run_id=leased.run_id,
        change_set_id=change_set_id,
        access_mode=access_mode,
        reserved_bytes=1_000_000,
        lease_duration=timedelta(seconds=90),
        trace_id="runner:allocate",
        rebuild_from_id=rebuild_from_id,
        now=now,
    )


def _ready(
    fixture: WorktreeFixture,
    lease,
    *,
    now: datetime,
) -> None:
    fixture.worktrees.begin_materialization(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        trace_id="runner:materialize",
        now=now,
    )
    fixture.worktrees.acknowledge_ready(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        actual_bytes=100_000,
        trace_id="runner:mounted",
        now=now + timedelta(seconds=1),
    )


def test_worktree_heartbeat_renews_only_within_run_and_lifetime_fences(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, change_set_id = _repository_and_change_set(fixture, suffix="heartbeat-renew")
    fixture.worktrees.configure_quota(
        fixture.request,
        project_id=fixture.project_id,
        max_active_instances=4,
        max_active_writers=2,
        max_reserved_bytes=4_000_000,
        max_lease_seconds=90,
        max_lifetime_seconds=180,
        gc_grace_seconds=10,
    )
    leased = _lease_run(fixture, change_set_id=change_set_id, key="heartbeat-renew", now=now)
    lease = _allocate(fixture, leased, change_set_id, now=now + timedelta(seconds=2))
    _ready(fixture, lease, now=now + timedelta(seconds=3))
    assert lease.expires_at == now + timedelta(seconds=92)

    # A legacy usage-only heartbeat preserves the original TTL.
    unchanged = fixture.worktrees.heartbeat(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        actual_bytes=100_000,
        dirty=False,
        now=now + timedelta(seconds=10),
    )
    assert unchanged.lease_expires_at == lease.expires_at

    run_capped = fixture.worktrees.heartbeat(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        actual_bytes=105_000,
        dirty=True,
        lease_duration=timedelta(seconds=90),
        now=now + timedelta(seconds=80),
    )
    # now + TTL would be +170s, but the current Run lease ends at +121s.
    assert run_capped.lease_expires_at == now + timedelta(seconds=121)

    fixture.execution.heartbeat(
        run_id=leased.run_id,
        lease_token=leased.run_lease_token,
        fence_token=leased.run_fence_token,
        lease_duration=timedelta(seconds=300),
        now=now + timedelta(seconds=90),
    )
    renewed = fixture.worktrees.heartbeat(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        actual_bytes=110_000,
        dirty=True,
        lease_duration=timedelta(seconds=90),
        now=now + timedelta(seconds=100),
    )
    # now + TTL would be +190s and the Run lease is +390s, but lifetime is +182s.
    assert renewed.lease_expires_at == now + timedelta(seconds=182)
    assert fixture.worktrees.expire_stale_leases(now=now + timedelta(seconds=181)) == ()
    expired = fixture.worktrees.expire_stale_leases(now=now + timedelta(seconds=183))
    assert len(expired) == 1 and expired[0].status == "quarantined"


def test_worktree_heartbeat_stale_cas_and_authority_do_not_extend_expiry(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, change_set_id = _repository_and_change_set(fixture, suffix="heartbeat-cas")
    _configure_worktree_quota(fixture)
    leased = _lease_run(fixture, change_set_id=change_set_id, key="heartbeat-cas", now=now)
    lease = _allocate(fixture, leased, change_set_id, now=now + timedelta(seconds=2))
    _ready(fixture, lease, now=now + timedelta(seconds=3))

    exact_fence = {
        "runner_id": lease.runner_id,
        "lease_generation": lease.lease_generation,
        "run_fence_token": lease.run_fence_token,
        "lease_token": lease.lease_token,
    }
    stale_values = (
        (
            uuid4(),
            lease.lease_generation,
            lease.run_fence_token,
            lease.lease_token,
        ),
        (
            lease.runner_id,
            lease.lease_generation + 1,
            lease.run_fence_token,
            lease.lease_token,
        ),
        (
            lease.runner_id,
            lease.lease_generation,
            lease.run_fence_token + 1,
            lease.lease_token,
        ),
        (
            lease.runner_id,
            lease.lease_generation,
            lease.run_fence_token,
            "unknown-worktree-lease-token",
        ),
    )
    for stale_runner, stale_generation, stale_fence, stale_token in stale_values:
        with pytest.raises(WorktreeControlPlaneError) as stale_cas:
            fixture.worktrees.heartbeat(
                worktree_id=lease.worktree_id,
                runner_id=stale_runner,
                lease_generation=stale_generation,
                run_fence_token=stale_fence,
                lease_token=stale_token,
                actual_bytes=100_000,
                dirty=False,
                lease_duration=timedelta(seconds=90),
                now=now + timedelta(seconds=10),
            )
        assert stale_cas.value.code == "worktree_lease_stale"

    with fixture.factory.begin() as db:
        run = db.get(RunRecord, leased.run_id)
        assert run is not None and run.lease_expires_at is not None
        original_run_expiry = run.lease_expires_at
        run.lease_expires_at = now - timedelta(seconds=1)
    with pytest.raises(WorktreeControlPlaneError) as inactive_run:
        fixture.worktrees.heartbeat(
            worktree_id=lease.worktree_id,
            **exact_fence,
            actual_bytes=100_000,
            dirty=False,
            lease_duration=timedelta(seconds=90),
            now=now + timedelta(seconds=10),
        )
    assert inactive_run.value.code == "worktree_authority_stale"
    with fixture.factory.begin() as db:
        run = db.get(RunRecord, leased.run_id)
        assert run is not None
        run.lease_expires_at = original_run_expiry

    with fixture.factory.begin() as db:
        runner = db.get(RunnerRegistrationRecord, leased.runner_id)
        assert runner is not None
        runner.connection_generation += 1
    with pytest.raises(WorktreeControlPlaneError) as stale_runner:
        fixture.worktrees.heartbeat(
            worktree_id=lease.worktree_id,
            runner_id=lease.runner_id,
            lease_generation=lease.lease_generation,
            run_fence_token=lease.run_fence_token,
            lease_token=lease.lease_token,
            actual_bytes=100_000,
            dirty=False,
            lease_duration=timedelta(seconds=90),
            now=now + timedelta(seconds=11),
        )
    assert stale_runner.value.code == "worktree_authority_stale"
    with fixture.factory() as db:
        record = db.get(WorktreeInstanceRecord, lease.worktree_id)
        assert record is not None
        assert record.lease_expires_at == lease.expires_at.replace(tzinfo=None)


def test_postgresql_allocation_and_heartbeats_share_bounded_lock_order() -> None:
    postgres_url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not postgres_url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for lock-order acceptance")

    from tests.saas.test_worktree_postgresql import (
        _migrate,
        _role_factory,
        _seed_scope,
    )

    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(postgres_url, pool_size=6, max_overflow=0)
    placement_id = uuid4()
    scope = {
        "actor": uuid4(),
        "tenant": uuid4(),
        "space": uuid4(),
        "project": uuid4(),
        "task": uuid4(),
        "run": uuid4(),
        "profile": uuid4(),
        "profile_hash": "7" * 64,
        "repository": uuid4(),
        "group": uuid4(),
        "change_set": uuid4(),
        "quota": uuid4(),
    }
    try:
        with engine.begin() as connection:
            _migrate(connection, root)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runtime_placements "
                    "(id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                    "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
                    "status) VALUES (:id, 'omnigent', 'cn-east-1', 'cn-east-1a', "
                    "'db-heartbeat-lock', 'objects-heartbeat-lock', 'kms-heartbeat-lock', "
                    "'runtime-schema-v1', 'shared-medium', 'active')"
                ),
                {"id": placement_id},
            )
            _seed_scope(
                connection,
                actor_id=scope["actor"],
                tenant_id=scope["tenant"],
                space_id=scope["space"],
                project_id=scope["project"],
                task_id=scope["task"],
                run_id=scope["run"],
                execution_profile_id=scope["profile"],
                execution_profile_hash=scope["profile_hash"],
                repository_id=scope["repository"],
                group_id=scope["group"],
                change_set_id=scope["change_set"],
                quota_id=scope["quota"],
                suffix="heartbeat-lock",
            )

        platform = SchedulingControlPlane(_role_factory(engine, "saas_platform"))
        executor_factory = _role_factory(engine, "saas_executor")

        @sa.event.listens_for(executor_factory, "after_begin")
        def _bound_lock_wait(
            _session: Session,
            _transaction: object,
            connection: sa.Connection,
        ) -> None:
            connection.exec_driver_sql("SET LOCAL lock_timeout = '2s'")
            connection.exec_driver_sql("SET LOCAL statement_timeout = '4s'")

        scheduler = SchedulingControlPlane(executor_factory)
        execution = ExecutionControlPlane(executor_factory)
        worktrees = WorktreeControlPlane(executor_factory, scheduler=scheduler)
        pool_id = platform.create_pool(
            placement_id=placement_id,
            name=f"heartbeat-lock-{uuid4().hex}",
            queue_class="interactive",
            capacity_slots=1,
            reserved_slots=0,
            protocol_version=2,
            source_revision="upstream",
            schema_revision="runtime-schema-v1",
            adapter_contract_version="0.2.0",
        )
        scheduler.configure_tenant_share(
            tenant_id=scope["tenant"],
            pool_id=pool_id,
            weight=1,
            max_concurrent=1,
            burst_limit=1,
        )
        now = datetime.now(timezone.utc).replace(microsecond=0)
        scheduler.prepare_dispatch(
            run_id=scope["run"],
            pool_id=pool_id,
            required_capabilities=["git", "shell"],
            execution_profile_id=scope["profile"],
            execution_profile_hash=scope["profile_hash"],
            eligible_at=now,
            maximum_wait=timedelta(hours=1),
        )
        runner = scheduler.register_runner(
            pool_id=pool_id,
            instance_key=f"heartbeat-lock-{uuid4().hex}",
            failure_domain="cn-east-1a",
            protocol_version=2,
            source_revision="upstream",
            schema_revision="runtime-schema-v1",
            adapter_contract_version="0.2.0",
            capabilities=["git", "shell"],
            max_concurrency=1,
            now=now,
        )
        run_lease = scheduler.claim_fair_run(
            runner_id=runner.runner_id,
            connection_generation=runner.connection_generation,
            connection_token=runner.connection_token,
            lease_duration=timedelta(seconds=120),
            capability_actions=["worktree.read", "worktree.write", "run.execute"],
            capability_resource_scope={"change_set_id": str(scope["change_set"])},
            now=now + timedelta(seconds=1),
        )
        assert run_lease is not None
        lease = worktrees.allocate_worktree(
            capability_token=run_lease.capability_token,
            runner_id=runner.runner_id,
            run_id=run_lease.run_id,
            change_set_id=scope["change_set"],
            access_mode="writer",
            reserved_bytes=1_000_000,
            lease_duration=timedelta(seconds=90),
            trace_id="postgresql:heartbeat-lock",
            now=now + timedelta(seconds=2),
        )
        _ready(
            WorktreeFixture(
                executor_factory,
                RequestContext(
                    actor_id=scope["actor"],
                    tenant_id=scope["tenant"],
                    space_id=scope["space"],
                    project_id=scope["project"],
                    user_security_version=1,
                    tenant_membership_version=1,
                    space_membership_version=1,
                    trace_id="postgresql-heartbeat-lock",
                ),
                scope["project"],
                placement_id,
                scope["profile"],
                scope["profile_hash"],
                execution,
                scheduler,
                worktrees,
            ),
            lease,
            now=now + timedelta(seconds=3),
        )

        for iteration in range(8):
            participant_count = 3 if iteration == 0 else 2
            barrier = Barrier(participant_count)
            checked_at = now + timedelta(seconds=10 + iteration)

            def heartbeat_run(sync: Barrier = barrier, at: datetime = checked_at) -> object:
                sync.wait()
                return scheduler.authenticated_run_heartbeat(
                    execution,
                    runner_id=runner.runner_id,
                    connection_generation=runner.connection_generation,
                    connection_token=runner.connection_token,
                    run_id=run_lease.run_id,
                    lease_token=run_lease.lease_token,
                    fence_token=run_lease.fence_token,
                    capability_token=run_lease.capability_token,
                    lease_duration=timedelta(seconds=120),
                    now=at,
                )

            def heartbeat_worktree(sync: Barrier = barrier, at: datetime = checked_at) -> object:
                sync.wait()
                return worktrees.heartbeat(
                    worktree_id=lease.worktree_id,
                    runner_id=lease.runner_id,
                    lease_generation=lease.lease_generation,
                    run_fence_token=lease.run_fence_token,
                    lease_token=lease.lease_token,
                    actual_bytes=100_000,
                    dirty=False,
                    lease_duration=timedelta(seconds=90),
                    now=at,
                )

            def allocate_readonly(sync: Barrier = barrier, at: datetime = checked_at) -> object:
                sync.wait()
                return worktrees.allocate_worktree(
                    capability_token=run_lease.capability_token,
                    runner_id=runner.runner_id,
                    run_id=run_lease.run_id,
                    change_set_id=scope["change_set"],
                    access_mode="readonly",
                    reserved_bytes=100_000,
                    lease_duration=timedelta(seconds=90),
                    trace_id="postgresql:allocation-lock",
                    now=at,
                )

            with ThreadPoolExecutor(max_workers=participant_count) as workers:
                run_future = workers.submit(heartbeat_run)
                worktree_future = workers.submit(heartbeat_worktree)
                allocation_future = workers.submit(allocate_readonly) if iteration == 0 else None
                assert run_future.result(timeout=5) is not None
                assert worktree_future.result(timeout=5) is not None
                if allocation_future is not None:
                    assert allocation_future.result(timeout=5) is not None

        # Exercise the recovery/GC chains against live lifecycle calls, not only
        # allocation and the two heartbeat paths above. Any PostgreSQL deadlock,
        # lock timeout, or statement timeout escapes and fails this bounded test.
        with executor_factory() as database:
            writer = database.get(WorktreeInstanceRecord, lease.worktree_id)
            assert writer is not None and writer.lease_expires_at is not None
            writer_expiry = writer.lease_expires_at
            if writer_expiry.tzinfo is None:
                writer_expiry = writer_expiry.replace(tzinfo=timezone.utc)
        sweep_barrier = Barrier(3)

        def race_heartbeat() -> object:
            sweep_barrier.wait()
            try:
                return worktrees.heartbeat(
                    worktree_id=lease.worktree_id,
                    runner_id=lease.runner_id,
                    lease_generation=lease.lease_generation,
                    run_fence_token=lease.run_fence_token,
                    lease_token=lease.lease_token,
                    actual_bytes=100_000,
                    dirty=False,
                    lease_duration=timedelta(seconds=90),
                    now=writer_expiry - timedelta(seconds=1),
                )
            except WorktreeControlPlaneError as exc:
                return exc

        def race_checkpoint() -> object:
            sweep_barrier.wait()
            try:
                return worktrees.checkpoint(
                    worktree_id=lease.worktree_id,
                    runner_id=lease.runner_id,
                    lease_generation=lease.lease_generation,
                    run_fence_token=lease.run_fence_token,
                    lease_token=lease.lease_token,
                    head_revision="f" * 40,
                    recovery_artifact_ref=f"artifact:{uuid4()}",
                    environment_snapshot_ref=f"environment:{uuid4()}",
                    dirty_after=False,
                    trace_id="postgresql:checkpoint-lock-race",
                    now=writer_expiry - timedelta(seconds=1),
                )
            except WorktreeControlPlaneError as exc:
                return exc

        def race_sweep() -> object:
            sweep_barrier.wait()
            return worktrees.expire_stale_leases(now=writer_expiry)

        with ThreadPoolExecutor(max_workers=3) as workers:
            heartbeat_future = workers.submit(race_heartbeat)
            checkpoint_future = workers.submit(race_checkpoint)
            sweep_future = workers.submit(race_sweep)
            assert heartbeat_future.result(timeout=5) is not None
            assert checkpoint_future.result(timeout=5) is not None
            assert sweep_future.result(timeout=5) is not None

        # Whichever live operation won first, a later recovery pass converges the
        # writer to released state before GC races a stale release attempt.
        worktrees.expire_stale_leases(now=now + timedelta(seconds=300))
        with executor_factory() as database:
            released_writer = database.get(WorktreeInstanceRecord, lease.worktree_id)
            assert released_writer is not None and released_writer.status == "released"
        gc_barrier = Barrier(2)

        def race_gc() -> object:
            gc_barrier.wait()
            return worktrees.mark_gc_eligible(now=now + timedelta(seconds=320))

        def race_stale_release() -> object:
            gc_barrier.wait()
            try:
                return worktrees.release(
                    worktree_id=lease.worktree_id,
                    runner_id=lease.runner_id,
                    lease_generation=lease.lease_generation,
                    run_fence_token=lease.run_fence_token,
                    lease_token=lease.lease_token,
                    final_change_set_status=None,
                    trace_id="postgresql:release-lock-race",
                    now=now + timedelta(seconds=319),
                )
            except WorktreeControlPlaneError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as workers:
            gc_future = workers.submit(race_gc)
            release_future = workers.submit(race_stale_release)
            assert gc_future.result(timeout=5) is not None
            release_result = release_future.result(timeout=5)
            assert isinstance(release_result, WorktreeControlPlaneError)
            assert release_result.code == "worktree_lease_stale"
    finally:
        engine.dispose()


def _finish_run(
    fixture: WorktreeFixture,
    leased: LeasedRun,
    *,
    now: datetime,
) -> None:
    for offset, status in enumerate(("starting", "running", "succeeded"), start=1):
        fixture.execution.transition_run(
            run_id=leased.run_id,
            lease_token=leased.run_lease_token,
            fence_token=leased.run_fence_token,
            target_status=status,
            trace_id=f"runner:{status}",
            now=now + timedelta(seconds=offset),
        )


def test_recovery_and_gc_use_the_live_lifecycle_lock_order(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, expired_change_set_id = _repository_and_change_set(fixture, suffix="lock-trace-expire")
    _configure_worktree_quota(fixture)
    expired_run = _lease_run(
        fixture,
        change_set_id=expired_change_set_id,
        key="lock-trace-expire",
        now=now,
    )
    expired_lease = _allocate(
        fixture,
        expired_run,
        expired_change_set_id,
        now=now + timedelta(seconds=2),
    )
    _ready(fixture, expired_lease, now=now + timedelta(seconds=3))
    fixture.worktrees.heartbeat(
        worktree_id=expired_lease.worktree_id,
        runner_id=expired_lease.runner_id,
        lease_generation=expired_lease.lease_generation,
        run_fence_token=expired_lease.run_fence_token,
        lease_token=expired_lease.lease_token,
        actual_bytes=100_000,
        dirty=True,
        now=now + timedelta(seconds=5),
    )

    bind = fixture.factory.kw["bind"]
    statements: list[str] = []

    def capture_sql(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalized = " ".join(statement.lower().split())
        if normalized.startswith("select"):
            statements.append(normalized)

    def assert_chain(trace: list[str]) -> None:
        expected = (
            "saas_runner_registrations",
            "saas_capability_tokens",
            "saas_runs",
            "saas_changesets",
            "saas_worktree_instances",
            "saas_worktree_quotas",
        )
        position = -1
        for table in expected:
            position = next(
                index
                for index in range(position + 1, len(trace))
                if f"from {table}" in trace[index]
            )

    sa.event.listen(bind, "before_cursor_execute", capture_sql)
    try:
        expired = fixture.worktrees.expire_stale_leases(now=now + timedelta(seconds=93))
    finally:
        sa.event.remove(bind, "before_cursor_execute", capture_sql)
    assert len(expired) == 1 and expired[0].status == "quarantined"
    assert_chain(statements)

    _, released_change_set_id = _repository_and_change_set(fixture, suffix="lock-trace-gc")
    released_run = _lease_run(
        fixture,
        change_set_id=released_change_set_id,
        key="lock-trace-gc",
        now=now + timedelta(seconds=100),
    )
    released_lease = _allocate(
        fixture,
        released_run,
        released_change_set_id,
        now=now + timedelta(seconds=102),
    )
    _ready(fixture, released_lease, now=now + timedelta(seconds=103))
    _finish_run(fixture, released_run, now=now + timedelta(seconds=104))
    fixture.worktrees.release(
        worktree_id=released_lease.worktree_id,
        runner_id=released_lease.runner_id,
        lease_generation=released_lease.lease_generation,
        run_fence_token=released_lease.run_fence_token,
        lease_token=released_lease.lease_token,
        final_change_set_status=None,
        trace_id="lock-trace:release",
        now=now + timedelta(seconds=108),
    )
    with fixture.factory.begin() as database:
        released_record = database.get(WorktreeInstanceRecord, released_lease.worktree_id)
        assert released_record is not None
        released_record.dirty = True

    statements.clear()
    sa.event.listen(bind, "before_cursor_execute", capture_sql)
    try:
        eligible = fixture.worktrees.mark_gc_eligible(now=now + timedelta(seconds=120))
    finally:
        sa.event.remove(bind, "before_cursor_execute", capture_sql)
    assert len(eligible) == 1 and eligible[0].status == "quarantined"
    assert_chain(statements)


def _git_fixture(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        check=True,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        },
    )
    return result.stdout.strip()


def _create_git_fixture(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    _git_fixture(source, "init", "--initial-branch=main")
    _git_fixture(source, "config", "user.name", "Runner test")
    _git_fixture(source, "config", "user.email", "runner-test@invalid")
    (source / "README.md").write_text("base\n", encoding="utf-8")
    _git_fixture(source, "add", "README.md")
    _git_fixture(source, "commit", "-m", "base")
    return source, _git_fixture(source, "rev-parse", "HEAD")


def _create_bare_mirror(source: Path, mirror_root: Path, name: str) -> Path:
    mirror = mirror_root / name
    _git_fixture(mirror_root, "clone", "--bare", str(source), str(mirror))
    return mirror


def test_changeset_writer_checkpoint_release_gc_and_opaque_storage(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with pytest.raises(WorktreeControlPlaneError) as url_binding:
        fixture.worktrees.register_repository(
            fixture.request,
            project_id=fixture.project_id,
            provider="github-app",
            source_binding_key="https://token@example.test/repo.git",
            display_name="Unsafe",
            default_branch="main",
        )
    assert url_binding.value.code == "source_binding_key_invalid"

    first_repository, change_set_id = _repository_and_change_set(fixture)
    second_repository = fixture.worktrees.register_repository(
        fixture.request,
        project_id=fixture.project_id,
        provider="github-app",
        source_binding_key=f"repo_second_{uuid4().hex}",
        display_name="Second repository",
        default_branch="main",
    )
    multi = fixture.worktrees.create_change_set_group(
        fixture.request,
        project_id=fixture.project_id,
        title="Multi repository change",
        specs=(
            ChangeSetSpec(first_repository, "b" * 40, "refs/heads/codex/multi-a"),
            ChangeSetSpec(second_repository, "c" * 40, "refs/heads/codex/multi-b"),
        ),
    )
    assert len(multi.change_set_ids) == 2
    _configure_worktree_quota(fixture)
    leased = _lease_run(fixture, change_set_id=change_set_id, key="lifecycle", now=now)
    lease = _allocate(fixture, leased, change_set_id, now=now + timedelta(seconds=2))
    assert lease.opaque_runtime_key.startswith("wti_")
    assert "/" not in lease.opaque_runtime_key and "\\" not in lease.opaque_runtime_key
    with fixture.factory() as db:
        stored = db.get(WorktreeInstanceRecord, lease.worktree_id)
        assert stored is not None
        assert stored.lease_token_hash != lease.lease_token
        serialized = json_safe = str(stored.__dict__)
        assert lease.lease_token not in serialized
        assert "https://" not in json_safe

    with pytest.raises(WorktreeControlPlaneError) as writer_conflict:
        _allocate(fixture, leased, change_set_id, now=now + timedelta(seconds=3))
    assert writer_conflict.value.code == "changeset_writer_conflict"

    _ready(fixture, lease, now=now + timedelta(seconds=3))
    fixture.worktrees.heartbeat(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        actual_bytes=120_000,
        dirty=True,
        now=now + timedelta(seconds=5),
    )
    checkpointed = fixture.worktrees.checkpoint(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        head_revision="d" * 40,
        recovery_artifact_ref=f"artifact:{uuid4()}",
        environment_snapshot_ref=f"environment:{uuid4()}",
        dirty_after=False,
        trace_id="runner:checkpoint",
        now=now + timedelta(seconds=6),
    )
    assert checkpointed.status == "ready"
    _finish_run(fixture, leased, now=now + timedelta(seconds=7))
    released = fixture.worktrees.release(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        final_change_set_status="committed",
        trace_id="runner:release",
        now=now + timedelta(seconds=11),
    )
    assert released.status == "released" and released.lease_generation == 2
    with pytest.raises(WorktreeControlPlaneError) as stale_write:
        fixture.worktrees.heartbeat(
            worktree_id=lease.worktree_id,
            runner_id=lease.runner_id,
            lease_generation=lease.lease_generation,
            run_fence_token=lease.run_fence_token,
            lease_token=lease.lease_token,
            actual_bytes=120_000,
            dirty=False,
            now=now + timedelta(seconds=12),
        )
    assert stale_write.value.code == "worktree_lease_stale"

    eligible = fixture.worktrees.mark_gc_eligible(now=now + timedelta(seconds=22))
    assert [item.status for item in eligible] == ["gc_eligible"]
    with pytest.raises(WorktreeControlPlaneError) as stale_delete:
        fixture.worktrees.confirm_deleted(
            worktree_id=lease.worktree_id,
            expected_lease_generation=1,
            opaque_runtime_key=lease.opaque_runtime_key,
            trace_id="runner:deleted",
            now=now + timedelta(seconds=23),
        )
    assert stale_delete.value.code == "worktree_delete_fence_stale"
    deleted = fixture.worktrees.confirm_deleted(
        worktree_id=lease.worktree_id,
        expected_lease_generation=2,
        opaque_runtime_key=lease.opaque_runtime_key,
        trace_id="runner:deleted",
        now=now + timedelta(seconds=23),
    )
    assert deleted.status == "deleted"

    events = fixture.worktrees.replay_events(
        fixture.request,
        project_id=fixture.project_id,
        worktree_id=lease.worktree_id,
    )
    assert [event.sequence for event in events] == list(range(1, len(events) + 1))
    assert [event.event_type for event in events] == [
        "worktree.created",
        "worktree.materializing",
        "worktree.mounted",
        "worktree.checkpointed",
        "worktree.released",
        "worktree.gc_eligible",
        "worktree.deleted",
    ]
    with fixture.factory() as db:
        quota = db.scalar(sa.select(WorktreeQuotaRecord))
        change_set = db.get(ChangeSetRecord, change_set_id)
        group = db.get(ChangeSetGroupRecord, change_set.group_id) if change_set else None
        outbox = tuple(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        assert quota is not None and (quota.active_instances, quota.active_writers) == (0, 0)
        assert quota.reserved_bytes == 0
        assert change_set is not None and change_set.status == "committed"
        assert group is not None and group.status == "completed"
        assert all(lease.lease_token not in str(event.payload) for event in outbox)


def test_committed_checkpoint_allows_only_new_readonly_worktree(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, change_set_id = _repository_and_change_set(fixture, suffix="preview-readonly")
    _configure_worktree_quota(fixture)
    source_run = _lease_run(
        fixture,
        change_set_id=change_set_id,
        key="preview-source",
        now=now,
    )
    source = _allocate(
        fixture,
        source_run,
        change_set_id,
        now=now + timedelta(seconds=2),
    )
    _ready(fixture, source, now=now + timedelta(seconds=3))
    recovery_ref = f"artifact:{uuid4()}"
    fixture.worktrees.checkpoint(
        worktree_id=source.worktree_id,
        runner_id=source.runner_id,
        lease_generation=source.lease_generation,
        run_fence_token=source.run_fence_token,
        lease_token=source.lease_token,
        head_revision="f" * 40,
        recovery_artifact_ref=recovery_ref,
        environment_snapshot_ref=f"environment:{uuid4()}",
        dirty_after=False,
        trace_id="runner:preview-checkpoint",
        now=now + timedelta(seconds=4),
    )
    _finish_run(fixture, source_run, now=now + timedelta(seconds=5))
    fixture.worktrees.release(
        worktree_id=source.worktree_id,
        runner_id=source.runner_id,
        lease_generation=source.lease_generation,
        run_fence_token=source.run_fence_token,
        lease_token=source.lease_token,
        final_change_set_status="committed",
        trace_id="runner:source-release",
        now=now + timedelta(seconds=6),
    )

    preview_run = _lease_run(
        fixture,
        change_set_id=change_set_id,
        key="preview-child",
        now=now + timedelta(seconds=7),
    )
    readonly = _allocate(
        fixture,
        preview_run,
        change_set_id,
        access_mode="readonly",
        now=now + timedelta(seconds=9),
    )
    with fixture.factory() as db:
        readonly_record = db.get(WorktreeInstanceRecord, readonly.worktree_id)
        assert readonly_record is not None
        assert readonly_record.recovery_artifact_ref == recovery_ref
    with pytest.raises(WorktreeControlPlaneError) as writer:
        _allocate(
            fixture,
            preview_run,
            change_set_id,
            access_mode="writer",
            now=now + timedelta(seconds=10),
        )
    assert writer.value.code == "changeset_unavailable"


def test_preview_child_run_saga_derives_committed_checkpoint_and_replays(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, change_set_id = _repository_and_change_set(fixture, suffix="preview-saga")
    _configure_worktree_quota(fixture)
    source_run = _lease_run(
        fixture,
        change_set_id=change_set_id,
        key="preview-saga-source",
        now=now,
    )
    source = _allocate(
        fixture,
        source_run,
        change_set_id,
        now=now + timedelta(seconds=2),
    )
    _ready(fixture, source, now=now + timedelta(seconds=3))
    recovery_ref = f"artifact:{uuid4()}"
    fixture.worktrees.checkpoint(
        worktree_id=source.worktree_id,
        runner_id=source.runner_id,
        lease_generation=source.lease_generation,
        run_fence_token=source.run_fence_token,
        lease_token=source.lease_token,
        head_revision="a" * 40,
        recovery_artifact_ref=recovery_ref,
        environment_snapshot_ref=f"environment:{uuid4()}",
        dirty_after=False,
        trace_id="runner:preview-saga-checkpoint",
        now=now + timedelta(seconds=4),
    )
    _finish_run(fixture, source_run, now=now + timedelta(seconds=5))
    fixture.worktrees.release(
        worktree_id=source.worktree_id,
        runner_id=source.runner_id,
        lease_generation=source.lease_generation,
        run_fence_token=source.run_fence_token,
        lease_token=source.lease_token,
        final_change_set_status="committed",
        trace_id="runner:preview-saga-release",
        now=now + timedelta(seconds=6),
    )
    fixture.execution.configure_quota(
        fixture.request,
        project_id=fixture.project_id,
        resource="preview_runs",
        limit_units=2,
    )
    previews = PreviewExecutionControlPlane(
        fixture.factory,
        policy=PreviewExecutionPolicy(
            preview_root_domain="preview.example.test",
            exchange_hmac_key=b"p" * 32,
        ),
    )
    created = previews.request_preview(
        fixture.request,
        project_id=fixture.project_id,
        source_run_id=source_run.run_id,
        preview_kind="static_web_v1",
        idempotency_key="preview-saga-idempotency-0001",
        now=now + timedelta(seconds=7),
    )
    replayed = previews.request_preview(
        fixture.request,
        project_id=fixture.project_id,
        source_run_id=source_run.run_id,
        preview_kind="static_web_v1",
        idempotency_key="preview-saga-idempotency-0001",
        now=now + timedelta(seconds=8),
    )
    assert created.status == "queued" and created.replayed is False
    assert replayed.preview_execution_id == created.preview_execution_id
    assert replayed.child_run_id == created.child_run_id and replayed.replayed is True
    with fixture.factory() as db:
        child = db.get(RunRecord, created.child_run_id)
        execution = db.get(PreviewExecutionRecord, created.preview_execution_id)
        command = db.scalar(
            sa.select(PreviewCommandRecord).where(
                PreviewCommandRecord.preview_execution_id == created.preview_execution_id
            )
        )
        events = tuple(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_key == str(created.preview_execution_id)
                )
            )
        )
        assert child is not None and child.parent_run_id == source_run.run_id
        assert child.queue_class == "preview" and child.status == "queued"
        assert child.input["execution"] == {
            "checkpoint_revision": "a" * 40,
            "kind": "omnigent.preview.v1",
            "preview_execution_id": str(created.preview_execution_id),
            "profile": "static_web_v1",
        }
        assert execution is not None and execution.change_set_id == change_set_id
        assert command is not None and command.command_type == "start"
        assert command.generation == 1 and command.status == "pending"
        assert [event.event_type for event in events] == ["preview.command.available"]

    with fixture.factory.begin() as db:
        child = db.get(RunRecord, created.child_run_id)
        runner = db.get(RunnerRegistrationRecord, source_run.runner_id)
        assert child is not None and runner is not None
        child.status = "running"
        child.lease_owner = str(runner.id)
        child.lease_token = uuid4()
        child.lease_expires_at = now + timedelta(minutes=5)
        child.heartbeat_at = now + timedelta(seconds=9)
        child.fence_token = 11
    runner_commands = PreviewRunnerExecutionAuthority(fixture.factory)
    first_claim = runner_commands.claim_start(
        tenant_id=fixture.request.tenant_id,
        space_id=fixture.request.space_id,
        project_id=fixture.project_id,
        child_run_id=created.child_run_id,
        runner_id=source_run.runner_id,
        connection_generation=source_run.runner_generation,
        run_fence_token=11,
        now=now + timedelta(seconds=10),
    )
    assert first_claim.preview_execution_id == created.preview_execution_id
    assert first_claim.checkpoint_revision == "a" * 40
    with pytest.raises(PreviewExecutionControlPlaneError) as duplicate_claim:
        runner_commands.claim_start(
            tenant_id=fixture.request.tenant_id,
            space_id=fixture.request.space_id,
            project_id=fixture.project_id,
            child_run_id=created.child_run_id,
            runner_id=source_run.runner_id,
            connection_generation=source_run.runner_generation,
            run_fence_token=11,
            now=now + timedelta(seconds=11),
        )
    assert duplicate_claim.value.code == "preview_start_command_stale"

    with fixture.factory.begin() as db:
        child = db.get(RunRecord, created.child_run_id)
        assert child is not None
        child.fence_token = 12
    recovered_claim = runner_commands.claim_start(
        tenant_id=fixture.request.tenant_id,
        space_id=fixture.request.space_id,
        project_id=fixture.project_id,
        child_run_id=created.child_run_id,
        runner_id=source_run.runner_id,
        connection_generation=source_run.runner_generation,
        run_fence_token=12,
        now=now + timedelta(seconds=12),
    )
    assert recovered_claim.claim_token != first_claim.claim_token
    runner_commands.mark_starting(
        recovered_claim,
        runner_id=source_run.runner_id,
        connection_generation=source_run.runner_generation,
        run_fence_token=12,
        now=now + timedelta(seconds=13),
    )
    with fixture.factory() as db:
        execution = db.get(PreviewExecutionRecord, created.preview_execution_id)
        command = db.get(PreviewCommandRecord, recovered_claim.command_id)
        assert execution is not None and execution.status == "starting"
        assert command is not None and command.attempt_count == 2
        assert command.run_fence_token == 12


def test_expired_dirty_checkpoint_rebuilds_on_new_run_fence(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, change_set_id = _repository_and_change_set(fixture, suffix="rebuild")
    _configure_worktree_quota(fixture)
    first = _lease_run(fixture, change_set_id=change_set_id, key="rebuild", now=now)
    source = _allocate(fixture, first, change_set_id, now=now + timedelta(seconds=2))
    _ready(fixture, source, now=now + timedelta(seconds=3))
    fixture.worktrees.heartbeat(
        worktree_id=source.worktree_id,
        runner_id=source.runner_id,
        lease_generation=source.lease_generation,
        run_fence_token=source.run_fence_token,
        lease_token=source.lease_token,
        actual_bytes=150_000,
        dirty=True,
        now=now + timedelta(seconds=5),
    )
    recovery_ref = f"artifact:{uuid4()}"
    environment_ref = f"environment:{uuid4()}"
    fixture.worktrees.checkpoint(
        worktree_id=source.worktree_id,
        runner_id=source.runner_id,
        lease_generation=source.lease_generation,
        run_fence_token=source.run_fence_token,
        lease_token=source.lease_token,
        head_revision="e" * 40,
        recovery_artifact_ref=recovery_ref,
        environment_snapshot_ref=environment_ref,
        dirty_after=True,
        trace_id="runner:checkpoint",
        now=now + timedelta(seconds=6),
    )
    expired = fixture.worktrees.expire_stale_leases(now=now + timedelta(seconds=93))
    assert len(expired) == 1 and expired[0].status == "rebuild_pending"
    with pytest.raises(WorktreeControlPlaneError) as implicit_replacement:
        _allocate(
            fixture,
            first,
            change_set_id,
            now=now + timedelta(seconds=94),
        )
    assert implicit_replacement.value.code == "worktree_rebuild_source_required"

    recovered = fixture.execution.recover_expired_runs(now=now + timedelta(seconds=122))
    assert len(recovered) == 1 and recovered[0].status == "queued"
    fixture.scheduling.release_dispatch(
        run_id=first.run_id,
        runner_id=first.runner_id,
        connection_generation=first.runner_generation,
        connection_token=first.runner_token,
        fence_token=first.run_fence_token,
        requeue=True,
        now=now + timedelta(seconds=123),
    )
    second_runner = fixture.scheduling.register_runner(
        pool_id=first.pool_id,
        instance_key="runner-rebuild-second",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["git", "shell"],
        max_concurrency=1,
        now=now + timedelta(seconds=123),
    )
    second_lease = fixture.scheduling.claim_fair_run(
        runner_id=second_runner.runner_id,
        connection_generation=second_runner.connection_generation,
        connection_token=second_runner.connection_token,
        lease_duration=timedelta(seconds=120),
        capability_actions=["worktree.read", "worktree.write"],
        capability_resource_scope={"change_set_id": str(change_set_id)},
        now=now + timedelta(seconds=124),
    )
    assert second_lease is not None and second_lease.fence_token == 2
    second = LeasedRun(
        second_lease.run_id,
        first.pool_id,
        second_runner.runner_id,
        second_runner.connection_generation,
        second_runner.connection_token,
        second_lease.lease_token,
        second_lease.fence_token,
        second_lease.capability_token,
    )
    replacement = _allocate(
        fixture,
        second,
        change_set_id,
        now=now + timedelta(seconds=125),
        rebuild_from_id=source.worktree_id,
    )
    assert replacement.run_fence_token == 2
    assert replacement.runner_id != source.runner_id
    with fixture.factory() as db:
        old = db.get(WorktreeInstanceRecord, source.worktree_id)
        new = db.get(WorktreeInstanceRecord, replacement.worktree_id)
        assert old is not None and old.status == "released"
        assert new is not None
        assert new.recovery_artifact_ref == recovery_ref
        assert new.environment_snapshot_ref == environment_ref


def test_readonly_worktree_and_member_removal_preflight_fail_closed(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, change_set_id = _repository_and_change_set(fixture, suffix="readonly")
    _configure_worktree_quota(fixture)
    leased = _lease_run(fixture, change_set_id=change_set_id, key="readonly", now=now)
    lease = _allocate(
        fixture,
        leased,
        change_set_id,
        access_mode="readonly",
        now=now + timedelta(seconds=2),
    )
    _ready(fixture, lease, now=now + timedelta(seconds=3))
    with pytest.raises(WorktreeControlPlaneError) as readonly_dirty:
        fixture.worktrees.heartbeat(
            worktree_id=lease.worktree_id,
            runner_id=lease.runner_id,
            lease_generation=lease.lease_generation,
            run_fence_token=lease.run_fence_token,
            lease_token=lease.lease_token,
            actual_bytes=100_000,
            dirty=True,
            now=now + timedelta(seconds=5),
        )
    assert readonly_dirty.value.code == "worktree_readonly_write_denied"
    with pytest.raises(WorktreeControlPlaneError) as readonly_checkpoint:
        fixture.worktrees.checkpoint(
            worktree_id=lease.worktree_id,
            runner_id=lease.runner_id,
            lease_generation=lease.lease_generation,
            run_fence_token=lease.run_fence_token,
            lease_token=lease.lease_token,
            head_revision="f" * 40,
            recovery_artifact_ref=f"artifact:{uuid4()}",
            environment_snapshot_ref=f"environment:{uuid4()}",
            dirty_after=False,
            trace_id="runner:checkpoint",
            now=now + timedelta(seconds=6),
        )
    assert readonly_checkpoint.value.code == "worktree_checkpoint_denied"

    provider = WorktreeRemovalImpactProvider(fixture.factory)
    impact = provider.collect(
        tenant_id=fixture.request.tenant_id,
        space_id=fixture.request.space_id,
        user_id=fixture.request.actor_id,
    )
    assert impact.blocking_count == 2
    open_changes = cast(list[dict[str, object]], impact.facts["open_change_sets"])
    retained = cast(list[dict[str, object]], impact.facts["retained_worktrees"])
    assert open_changes[0]["change_set_id"] == str(change_set_id)
    assert retained[0]["worktree_id"] == str(lease.worktree_id)
    composed = CompositeRemovalImpactProvider(
        {
            "projects": ProjectRemovalImpactProvider(fixture.factory),
            "worktrees": provider,
        },
        required_domains=frozenset({"projects", "worktrees"}),
    ).collect(
        tenant_id=fixture.request.tenant_id,
        space_id=fixture.request.space_id,
        user_id=fixture.request.actor_id,
    )
    assert composed.blocking_count == 3
    assert set(composed.facts) == {"projects", "worktrees"}


def test_dirty_expiry_without_recovery_material_is_quarantined(
    worktree_fixture: WorktreeFixture,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, change_set_id = _repository_and_change_set(fixture, suffix="quarantine")
    _configure_worktree_quota(fixture)
    leased = _lease_run(fixture, change_set_id=change_set_id, key="quarantine", now=now)
    lease = _allocate(fixture, leased, change_set_id, now=now + timedelta(seconds=2))
    _ready(fixture, lease, now=now + timedelta(seconds=3))
    fixture.worktrees.heartbeat(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        actual_bytes=100_000,
        dirty=True,
        now=now + timedelta(seconds=5),
    )
    swept = fixture.worktrees.expire_stale_leases(now=now + timedelta(seconds=93))
    assert len(swept) == 1 and swept[0].status == "quarantined"
    with fixture.factory() as db:
        record = db.get(WorktreeInstanceRecord, lease.worktree_id)
        quota = db.scalar(sa.select(WorktreeQuotaRecord))
        assert record is not None
        assert record.quarantine_reason == "expired_without_recovery_artifact"
        assert record.lease_token_hash is None
        change_set = db.get(ChangeSetRecord, change_set_id)
        assert change_set is not None and change_set.status == "quarantined"
        assert quota is not None and quota.active_instances == 0


def test_physical_runner_materializes_checkpoints_recovers_and_fenced_deletes(
    worktree_fixture: WorktreeFixture,
    tmp_path: Path,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    source, base_revision = _create_git_fixture(tmp_path)
    binding = f"repo_physical_{uuid4().hex}"
    repository_id = fixture.worktrees.register_repository(
        fixture.request,
        project_id=fixture.project_id,
        provider="github-app",
        source_binding_key=binding,
        display_name="Physical Repository",
        default_branch="main",
    )
    created = fixture.worktrees.create_change_set_group(
        fixture.request,
        project_id=fixture.project_id,
        title="Physical Worktree",
        specs=(
            ChangeSetSpec(
                repository_id=repository_id,
                base_revision=base_revision,
                branch_ref="refs/heads/codex/physical",
            ),
        ),
    )
    change_set_id = created.change_set_ids[0]
    _configure_worktree_quota(fixture)

    first = _lease_run(fixture, change_set_id=change_set_id, key="physical-one", now=now)
    first_lease = _allocate(
        fixture,
        first,
        change_set_id,
        now=now + timedelta(seconds=2),
    )
    with pytest.raises(WorktreeControlPlaneError) as unfenced_grant:
        fixture.worktrees.materialization_grant(
            worktree_id=first_lease.worktree_id,
            runner_id=first_lease.runner_id,
            lease_generation=first_lease.lease_generation,
            run_fence_token=first_lease.run_fence_token,
            lease_token=first_lease.lease_token,
        )
    assert unfenced_grant.value.code == "worktree_materialization_not_started"

    artifact_store = FilesystemRecoveryArtifactStore(tmp_path / "recovery-artifacts")
    first_mirror_root = tmp_path / "runner-one-mirrors"
    first_mirror_root.mkdir(mode=0o700)
    first_mirror = _create_bare_mirror(source, first_mirror_root, "repository.git")
    first_adapter = RunnerWorktreeAdapter(
        managed_root=tmp_path / "runner-one-worktrees",
        mirror_root=first_mirror_root,
        state_root=tmp_path / "runner-one-state",
        authority=fixture.worktrees,
        mirrors=StaticRepositoryMirrorResolver({binding: first_mirror}),
        recovery_artifacts=artifact_store,
        runner_id=first_lease.runner_id,
    )
    _git_fixture(first_mirror, "config", "core.sshCommand", "/bin/false")
    with pytest.raises(RunnerWorktreeAdapterError) as executable_config:
        first_adapter.materialize(first_lease, trace_id="runner:unsafe-config")
    assert executable_config.value.code == "repository_mirror_config_unsafe"
    _git_fixture(first_mirror, "config", "--unset", "core.sshCommand")
    _git_fixture(
        first_mirror,
        "config",
        "remote.origin.url",
        "https://runner:secret@example.test/repository.git",
    )
    with pytest.raises(RunnerWorktreeAdapterError) as embedded_credential:
        first_adapter.materialize(first_lease, trace_id="runner:unsafe-credential")
    assert embedded_credential.value.code == "repository_mirror_credentials_exposed"
    _git_fixture(first_mirror, "config", "remote.origin.url", str(source))
    first_physical = first_adapter.materialize(first_lease, trace_id="runner:physical-one")
    assert first_physical.head_revision == base_revision
    assert _git_fixture(first_physical.worktree_path, "rev-parse", "HEAD") == base_revision
    assert first_lease.opaque_runtime_key not in str(first_physical.worktree_path)
    assert binding not in str(first_physical.worktree_path)
    retried_physical = first_adapter.materialize(
        first_lease,
        trace_id="runner:physical-one-retry",
    )
    assert retried_physical == first_physical

    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    escape = first_physical.worktree_path / "escape"
    escape.symlink_to(outside)
    with pytest.raises(RunnerWorktreeAdapterError) as symlink_escape:
        first_adapter.checkpoint(
            first_lease,
            environment_snapshot_ref="environment:physical-one",
            trace_id="runner:unsafe-checkpoint",
        )
    assert symlink_escape.value.code == "worktree_symlink_escape"
    escape.unlink()

    changed_content = "base\ncheckpoint from runner one\n"
    (first_physical.worktree_path / "README.md").write_text(
        changed_content,
        encoding="utf-8",
    )
    checkpoint = first_adapter.checkpoint(
        first_lease,
        environment_snapshot_ref="environment:physical-one",
        trace_id="runner:checkpoint-one",
    )
    assert checkpoint.head_revision != base_revision
    assert checkpoint.recovery_artifact_ref.startswith("wta_sha256_")
    recovered_artifact = artifact_store.get(checkpoint.recovery_artifact_ref)
    assert recovered_artifact.base_revision == base_revision
    assert recovered_artifact.head_revision == checkpoint.head_revision
    assert recovered_artifact.bundle
    checkpoint_retry = first_adapter.checkpoint(
        first_lease,
        environment_snapshot_ref="environment:physical-one",
        trace_id="runner:checkpoint-one-retry",
    )
    assert checkpoint_retry.recovery_artifact_ref == checkpoint.recovery_artifact_ref
    first_events = fixture.worktrees.replay_events(
        fixture.request,
        project_id=fixture.project_id,
        worktree_id=first_lease.worktree_id,
    )
    assert sum(event.event_type == "worktree.checkpointed" for event in first_events) == 1

    state_payload = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "runner-one-state").rglob("*.json")
    )
    assert first_lease.lease_token not in state_payload
    assert first_lease.opaque_runtime_key not in state_payload
    assert binding not in state_payload
    with fixture.factory() as db:
        stored = db.get(WorktreeInstanceRecord, first_lease.worktree_id)
        assert stored is not None
        assert str(first_physical.worktree_path) not in str(stored.__dict__)
        assert first_lease.lease_token not in str(stored.__dict__)

    _finish_run(fixture, first, now=now + timedelta(seconds=3))
    first_release = fixture.worktrees.release(
        worktree_id=first_lease.worktree_id,
        runner_id=first_lease.runner_id,
        lease_generation=first_lease.lease_generation,
        run_fence_token=first_lease.run_fence_token,
        lease_token=first_lease.lease_token,
        final_change_set_status="checkpointed",
        trace_id="runner:release-one",
        now=now + timedelta(seconds=7),
    )
    assert first_release.lease_generation == first_lease.lease_generation + 1

    second = _lease_run(
        fixture,
        change_set_id=change_set_id,
        key="physical-two",
        now=now + timedelta(seconds=8),
    )
    second_lease = _allocate(
        fixture,
        second,
        change_set_id,
        now=now + timedelta(seconds=10),
    )
    second_mirror_root = tmp_path / "runner-two-mirrors"
    second_mirror_root.mkdir(mode=0o700)
    second_mirror = _create_bare_mirror(source, second_mirror_root, "repository.git")
    assert _git_fixture(second_mirror, "cat-file", "-t", base_revision) == "commit"
    missing_head = subprocess.run(
        ["git", "cat-file", "-e", f"{checkpoint.head_revision}^{{commit}}"],
        cwd=second_mirror,
        capture_output=True,
        check=False,
        text=True,
    )
    assert missing_head.returncode != 0
    second_adapter = RunnerWorktreeAdapter(
        managed_root=tmp_path / "runner-two-worktrees",
        mirror_root=second_mirror_root,
        state_root=tmp_path / "runner-two-state",
        authority=fixture.worktrees,
        mirrors=StaticRepositoryMirrorResolver({binding: second_mirror}),
        recovery_artifacts=artifact_store,
        runner_id=second_lease.runner_id,
    )
    second_physical = second_adapter.materialize(second_lease, trace_id="runner:physical-two")
    assert second_physical.head_revision == checkpoint.head_revision
    assert (second_physical.worktree_path / "README.md").read_text(
        encoding="utf-8"
    ) == changed_content

    _finish_run(fixture, second, now=now + timedelta(seconds=11))
    second_release = fixture.worktrees.release(
        worktree_id=second_lease.worktree_id,
        runner_id=second_lease.runner_id,
        lease_generation=second_lease.lease_generation,
        run_fence_token=second_lease.run_fence_token,
        lease_token=second_lease.lease_token,
        final_change_set_status="committed",
        trace_id="runner:release-two",
        now=now + timedelta(seconds=15),
    )
    deletion_escape = second_physical.worktree_path / "delete-escape"
    deletion_escape.symlink_to(outside)
    eligible = fixture.worktrees.mark_gc_eligible(now=now + timedelta(seconds=26))
    assert {item.worktree_id for item in eligible} == {
        first_lease.worktree_id,
        second_lease.worktree_id,
    }

    with pytest.raises(RunnerWorktreeAdapterError) as cross_runner_delete:
        second_adapter.delete(
            worktree_id=first_lease.worktree_id,
            expected_lease_generation=first_release.lease_generation,
            opaque_runtime_key=first_lease.opaque_runtime_key,
            trace_id="runner:cross-runner-delete",
        )
    assert cross_runner_delete.value.code == "worktree_delete_grant_mismatch"

    first_deleted = first_adapter.delete(
        worktree_id=first_lease.worktree_id,
        expected_lease_generation=first_release.lease_generation,
        opaque_runtime_key=first_lease.opaque_runtime_key,
        trace_id="runner:delete-one",
    )
    second_deleted = second_adapter.delete(
        worktree_id=second_lease.worktree_id,
        expected_lease_generation=second_release.lease_generation,
        opaque_runtime_key=second_lease.opaque_runtime_key,
        trace_id="runner:delete-two",
    )
    assert first_deleted.status == second_deleted.status == "deleted"
    assert not first_physical.worktree_path.exists()
    assert not second_physical.worktree_path.exists()
    first_delete_retry = first_adapter.delete(
        worktree_id=first_lease.worktree_id,
        expected_lease_generation=first_release.lease_generation,
        opaque_runtime_key=first_lease.opaque_runtime_key,
        trace_id="runner:delete-one-retry",
    )
    assert first_delete_retry.event_sequence == first_deleted.event_sequence


def test_filesystem_recovery_artifact_store_rejects_tampering(tmp_path: Path) -> None:
    store = FilesystemRecoveryArtifactStore(tmp_path / "artifacts")
    artifact = CheckpointArtifact(
        repository_binding_digest="a" * 64,
        base_revision="b" * 40,
        head_revision="c" * 40,
        bundle=b"test bundle bytes",
    )
    artifact_ref = store.put(artifact)
    digest = artifact_ref.removeprefix("wta_sha256_")
    bundle_path = tmp_path / "artifacts" / digest[:2] / f"{digest}.bundle"
    bundle_path.write_bytes(b"tampered bundle bytes")
    bundle_path.chmod(0o600)
    with pytest.raises(RunnerWorktreeAdapterError) as tampered:
        store.get(artifact_ref)
    assert tampered.value.code == "artifact_integrity_failed"


def test_failed_materialization_is_recoverable_after_partial_state_loss(
    worktree_fixture: WorktreeFixture,
    tmp_path: Path,
) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    source, _ = _create_git_fixture(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (source / "unsafe-link").symlink_to(outside)
    _git_fixture(source, "add", "unsafe-link")
    _git_fixture(source, "commit", "-m", "add unsafe symlink")
    unsafe_revision = _git_fixture(source, "rev-parse", "HEAD")
    binding = f"repo_unsafe_{uuid4().hex}"
    repository_id = fixture.worktrees.register_repository(
        fixture.request,
        project_id=fixture.project_id,
        provider="github-app",
        source_binding_key=binding,
        display_name="Unsafe materialization fixture",
        default_branch="main",
    )
    created = fixture.worktrees.create_change_set_group(
        fixture.request,
        project_id=fixture.project_id,
        title="Unsafe physical tree",
        specs=(
            ChangeSetSpec(
                repository_id=repository_id,
                base_revision=unsafe_revision,
                branch_ref="refs/heads/codex/unsafe-physical",
            ),
        ),
    )
    change_set_id = created.change_set_ids[0]
    _configure_worktree_quota(fixture)
    leased = _lease_run(fixture, change_set_id=change_set_id, key="unsafe-tree", now=now)
    lease = _allocate(
        fixture,
        leased,
        change_set_id,
        now=now + timedelta(seconds=2),
    )
    mirror_root = tmp_path / "unsafe-runner-mirrors"
    mirror_root.mkdir(mode=0o700)
    mirror = _create_bare_mirror(source, mirror_root, "repository.git")
    managed_root = tmp_path / "unsafe-runner-worktrees"
    state_root = tmp_path / "unsafe-runner-state"
    adapter = RunnerWorktreeAdapter(
        managed_root=managed_root,
        mirror_root=mirror_root,
        state_root=state_root,
        authority=fixture.worktrees,
        mirrors=StaticRepositoryMirrorResolver({binding: mirror}),
        recovery_artifacts=FilesystemRecoveryArtifactStore(tmp_path / "unsafe-artifacts"),
    )
    with pytest.raises(RunnerWorktreeAdapterError) as unsafe_tree:
        adapter.materialize(lease, trace_id="runner:unsafe-tree")
    assert unsafe_tree.value.code == "worktree_symlink_escape"
    physical_paths = [
        path for path in managed_root.glob("*/*") if path.is_dir() and (path / ".git").is_file()
    ]
    assert len(physical_paths) == 1

    state_paths = list(state_root.glob("*/*.json"))
    assert len(state_paths) == 1
    partial_state = json.loads(state_paths[0].read_text(encoding="utf-8"))
    partial_state["phase"] = "materializing"
    partial_state["device"] = None
    partial_state["inode"] = None
    state_paths[0].write_text(
        json.dumps(partial_state, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    state_paths[0].chmod(0o600)

    _finish_run(fixture, leased, now=now + timedelta(seconds=3))
    released = fixture.worktrees.release(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        final_change_set_status="abandoned",
        trace_id="runner:release-unsafe-tree",
        now=now + timedelta(seconds=7),
    )
    eligible = fixture.worktrees.mark_gc_eligible(now=now + timedelta(seconds=18))
    assert [item.worktree_id for item in eligible] == [lease.worktree_id]
    deleted = adapter.delete(
        worktree_id=lease.worktree_id,
        expected_lease_generation=released.lease_generation,
        opaque_runtime_key=lease.opaque_runtime_key,
        trace_id="runner:delete-unsafe-tree",
    )
    assert deleted.status == "deleted"
    assert not physical_paths[0].exists()


def test_worktree_event_scope_is_database_enforced(worktree_fixture: WorktreeFixture) -> None:
    fixture = worktree_fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _, change_set_id = _repository_and_change_set(fixture, suffix="event-scope")
    _configure_worktree_quota(fixture)
    leased = _lease_run(fixture, change_set_id=change_set_id, key="event-scope", now=now)
    lease = _allocate(fixture, leased, change_set_id, now=now + timedelta(seconds=2))
    with pytest.raises(IntegrityError):
        with fixture.factory.begin() as db:
            db.add(
                WorktreeEventRecord(
                    tenant_id=uuid4(),
                    space_id=fixture.request.space_id,
                    project_id=fixture.request.project_id,
                    worktree_id=lease.worktree_id,
                    sequence=99,
                    event_type="worktree.scope.attack",
                    payload={},
                    trace_id="attack",
                )
            )


def test_object_recovery_store_is_content_addressed_idempotent_and_tamper_evident() -> None:
    backend = _FakeArtifactStore()
    store = ObjectRecoveryArtifactStore(backend, maximum_bundle_bytes=1024)
    artifact = CheckpointArtifact(
        repository_binding_digest="a" * 64,
        base_revision="b" * 40,
        head_revision="c" * 40,
        bundle=b"exact recovery bundle",
    )

    reference = store.put(artifact)
    assert store.put(artifact) == reference
    assert store.get(reference) == artifact
    assert len(backend.objects) == 2

    bundle_key = next(key for key in backend.objects if key.endswith(".bundle"))
    backend.objects[bundle_key] = b"tampered"
    with pytest.raises(RunnerWorktreeAdapterError) as tampered:
        store.get(reference)
    assert tampered.value.code == "artifact_integrity_failed"
    with pytest.raises(RunnerWorktreeAdapterError) as conflict:
        store.put(artifact)
    assert conflict.value.code == "artifact_digest_collision"
