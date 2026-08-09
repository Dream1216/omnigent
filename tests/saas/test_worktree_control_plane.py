from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane import (
    ChangeSetGroupRecord,
    ChangeSetRecord,
    ChangeSetSpec,
    CompositeRemovalImpactProvider,
    ControlPlaneOutboxEvent,
    ExecutionControlPlane,
    ExecutionRevisionSet,
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    ProjectRemovalImpactProvider,
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
from saas.runner_adapter import (
    CheckpointArtifact,
    FilesystemRecoveryArtifactStore,
    RunnerWorktreeAdapter,
    RunnerWorktreeAdapterError,
    StaticRepositoryMirrorResolver,
)


@dataclass(frozen=True, slots=True)
class WorktreeFixture:
    factory: sessionmaker[Session]
    request: RequestContext
    project_id: UUID
    placement_id: UUID
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
def worktree_fixture() -> Iterator[WorktreeFixture]:
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
    actor_id = uuid4()
    tenant_id = uuid4()
    space_id = uuid4()
    project_id = uuid4()
    placement_id = uuid4()
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
