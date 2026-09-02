from __future__ import annotations

from collections.abc import Iterator
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
    SaasBase,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.dispatch_binding import dispatch_requirements_hash
from saas.control_plane.execution import (
    ExecutionControlPlane,
    ExecutionControlPlaneError,
    ExecutionRevisionSet,
)
from saas.control_plane.execution_models import (
    QuotaReservationRecord,
    RunEventRecord,
    RunRecord,
)
from saas.control_plane.isolation_models import EgressPolicyRecord, ExecutionProfileRecord
from saas.control_plane.outbox import OutboxPublishError
from saas.control_plane.run_dispatch_projection import RunQueuedDispatchProjection
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.scheduling_models import (
    CapabilityTokenRecord,
    RunDispatchRecord,
    RunnerRegistrationRecord,
    TenantQueueShareRecord,
)


@dataclass(frozen=True, slots=True)
class RuntimeDispatchFixture:
    factory: sessionmaker[Session]
    execution: ExecutionControlPlane
    scheduling: SchedulingControlPlane
    projection: RunQueuedDispatchProjection
    request: RequestContext
    placement_id: UUID
    partition_id: UUID
    pool_id: UUID
    egress_policy_id: UUID
    profile_id: UUID


def test_dispatch_requirements_hash_is_timezone_stable() -> None:
    tenant_id, space_id, project_id, pool_id, profile_id, policy_id = (uuid4() for _ in range(6))
    common = {
        "tenant_id": tenant_id,
        "space_id": space_id,
        "project_id": project_id,
        "pool_id": pool_id,
        "execution_profile_id": profile_id,
        "execution_profile_hash": "a" * 64,
        "egress_policy_id": policy_id,
        "egress_policy_hash": "b" * 64,
        "queue_class": "interactive",
        "required_capabilities": ["shell"],
        "cost_units": 1,
    }
    utc_start = datetime(2026, 8, 4, 10, 30, tzinfo=timezone.utc)
    shanghai_start = utc_start.astimezone(ZoneInfo("Asia/Shanghai"))

    assert dispatch_requirements_hash(
        **common,
        eligible_at=utc_start,
        max_wait_at=utc_start + timedelta(hours=1),
    ) == dispatch_requirements_hash(
        **common,
        eligible_at=shanghai_start,
        max_wait_at=shanghai_start + timedelta(hours=1),
    )


@pytest.fixture
def runtime_dispatch_fixture() -> Iterator[RuntimeDispatchFixture]:
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
    user_id = uuid4()
    tenant_id = uuid4()
    space_id = uuid4()
    project_id = uuid4()
    placement_id = uuid4()
    partition_id = uuid4()
    egress_policy_id = uuid4()
    profile_id = uuid4()
    request = RequestContext(
        actor_id=user_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="runtime-dispatch-projection",
    )
    with factory.begin() as db:
        db.add(GlobalUser(id=user_id, status="active", security_version=1))
        db.add(
            Tenant(
                id=tenant_id,
                slug=f"runtime-dispatch-{tenant_id.hex}",
                name="Runtime dispatch tenant",
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
                user_id=user_id,
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
                user_id=user_id,
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
                name="Runtime dispatch project",
                visibility="restricted",
                created_by=user_id,
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
                subject_id=user_id,
                role="owner",
                status="active",
                created_by=user_id,
                version=1,
            )
        )
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="db-runtime-a",
                object_store_ref="objects-runtime-a",
                kms_key_ref="kms-runtime-a",
                official_schema_revision="runtime-schema-v1",
                capacity_class="shared-medium",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=tenant_id,
                space_id=space_id,
                placement_id=placement_id,
                runtime_type="omnigent",
                runtime_version="1.0.0",
                physical_partition_key="workspace-42",
                placement_generation=1,
                source_revision="upstream-revision",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimeResourceBindingRecord(
                runtime_partition_id=partition_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                resource_type="project",
                runtime_resource_id="42",
                saas_resource_id=project_id,
                partition_generation=1,
                binding_generation=1,
                status="active",
            )
        )
        db.add(
            EgressPolicyRecord(
                id=egress_policy_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                created_by=user_id,
                name="default-deny",
                rules=["GET api.example.test/v1/*"],
                rules_hash="1" * 64,
                allow_private_destinations=False,
                status="active",
                version=1,
            )
        )
        db.flush()
        db.add(
            ExecutionProfileRecord(
                id=profile_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                egress_policy_id=egress_policy_id,
                created_by=user_id,
                name="managed-default",
                sandbox_backend="linux_bwrap",
                network_mode="proxy_only",
                root_read_only=True,
                run_as_uid=10001,
                run_as_gid=10001,
                no_new_privileges=True,
                host_socket_access=False,
                syscall_profile_ref="default-v1",
                cpu_millis=1000,
                memory_bytes=512 * 1024 * 1024,
                pids_limit=128,
                allowed_tools=["shell"],
                approval_required_tools=[],
                denied_tools=[],
                config_hash="2" * 64,
                status="active",
                version=1,
            )
        )

    execution = ExecutionControlPlane(factory)
    scheduling = SchedulingControlPlane(factory)
    pool_id = scheduling.create_pool(
        placement_id=placement_id,
        name="runtime-interactive",
        queue_class="interactive",
        capacity_slots=4,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream-revision",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    scheduling.configure_tenant_share(
        tenant_id=tenant_id,
        pool_id=pool_id,
        weight=1,
        max_concurrent=2,
        burst_limit=2,
    )
    yield RuntimeDispatchFixture(
        factory,
        execution,
        scheduling,
        RunQueuedDispatchProjection(factory),
        request,
        placement_id,
        partition_id,
        pool_id,
        egress_policy_id,
        profile_id,
    )
    engine.dispose()


def _admit(fixture: RuntimeDispatchFixture, *, key: str) -> UUID:
    fixture.execution.configure_quota(
        fixture.request,
        project_id=fixture.request.project_id,
        resource="run_units",
        limit_units=20,
    )
    task_id = fixture.execution.create_task(
        fixture.request,
        project_id=fixture.request.project_id,
        title=f"Runtime dispatch {key}",
    )
    admission = fixture.execution.admit_run(
        fixture.request,
        project_id=fixture.request.project_id,
        task_id=task_id,
        session_id=None,
        input_payload={"key": key},
        quota_resource="run_units",
        quota_units=1,
        idempotency_key=key,
        revisions=ExecutionRevisionSet(
            product_revision="product-revision",
            upstream_revision="upstream-revision",
            schema_revision="runtime-schema-v1",
            adapter_contract_version="0.2.0",
        ),
    )
    return admission.run_id


def _delivery(
    fixture: RuntimeDispatchFixture, run_id: UUID
) -> tuple[dict[str, object], dict[str, object], datetime]:
    with fixture.factory() as db:
        rows = tuple(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_key == str(run_id)
                )
            )
        )
        outbox = next(row for row in rows if row.payload["event_type"] == "run.queued")
        event = db.get(RunEventRecord, UUID(str(outbox.payload["event_id"])))
        assert event is not None
        kwargs: dict[str, object] = {
            "event_id": outbox.id,
            "event_type": outbox.event_type,
            "aggregate_type": outbox.aggregate_type,
            "aggregate_key": outbox.aggregate_key,
            "payload": deepcopy(outbox.payload),
        }
        return kwargs, deepcopy(outbox.payload), _aware(event.created_at)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _project(fixture: RuntimeDispatchFixture, run_id: UUID):
    kwargs, _, _ = _delivery(fixture, run_id)
    return fixture.projection.project(**kwargs)


def _claim(
    fixture: RuntimeDispatchFixture,
    run_id: UUID,
    *,
    instance_key: str,
):
    _, _, queued_at = _delivery(fixture, run_id)
    with fixture.factory() as db:
        dispatch = db.get(RunDispatchRecord, run_id)
        assert dispatch is not None
        capabilities = list(dispatch.required_capabilities)
    registered_at = queued_at + timedelta(seconds=1)
    connection = fixture.scheduling.register_runner(
        pool_id=fixture.pool_id,
        instance_key=instance_key,
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream-revision",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=capabilities,
        max_concurrency=2,
        now=registered_at,
    )
    lease = fixture.scheduling.claim_fair_run(
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        lease_duration=timedelta(seconds=10),
        capability_actions=["run.execute"],
        capability_resource_scope={"runtime_partition_id": str(fixture.partition_id)},
        now=registered_at + timedelta(seconds=1),
    )
    assert lease is not None and lease.run_id == run_id
    return connection, lease, registered_at


def test_projects_authoritative_queue_event_once(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key="project-once")
    kwargs, _, queued_at = _delivery(fixture, run_id)

    projected = fixture.projection.project(**kwargs)
    replayed = fixture.projection.project(**kwargs)

    assert projected.projected and not projected.replayed and not projected.stale
    assert projected.pool_id == fixture.pool_id
    assert projected.execution_profile_id == fixture.profile_id
    assert replayed.replayed and not replayed.projected
    assert replayed.execution_profile_id == fixture.profile_id
    with fixture.factory() as db:
        dispatches = tuple(
            db.scalars(sa.select(RunDispatchRecord).where(RunDispatchRecord.run_id == run_id))
        )
        assert len(dispatches) == 1
        dispatch = dispatches[0]
        assert dispatch.execution_profile_id == fixture.profile_id
        assert dispatch.execution_profile_hash == "2" * 64
        assert dispatch.egress_policy_id == fixture.egress_policy_id
        assert dispatch.egress_policy_hash == "1" * 64
        assert _aware(dispatch.eligible_at) == queued_at
        assert dispatch.status == "pending"
        assert dispatch.required_capabilities == sorted(
            {
                "egress.proxy",
                "sandbox.linux_bwrap",
                "sandbox.no_host_socket",
                "sandbox.no_new_privileges",
                "sandbox.nonroot",
                "sandbox.readonly_root",
                "sandbox.resource_limits",
                "secret.broker",
                "syscall.default-v1",
            }
        )


@pytest.mark.parametrize(
    "drift",
    ["hash", "egress_hash"],
)
def test_replay_revalidates_persisted_execution_profile(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
    drift: str,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key=f"replay-profile-{drift}")
    kwargs, _, _ = _delivery(fixture, run_id)
    assert fixture.projection.project(**kwargs).projected
    with fixture.factory.begin() as db:
        profile = db.get(ExecutionProfileRecord, fixture.profile_id)
        assert profile is not None
        if drift == "hash":
            profile.config_hash = "f" * 64
        else:
            policy = db.get(EgressPolicyRecord, profile.egress_policy_id)
            assert policy is not None
            policy.rules_hash = "e" * 64

    with pytest.raises(OutboxPublishError) as rejected:
        fixture.projection.project(**kwargs)
    assert rejected.value.code == "run_dispatch_replay_conflict"


def test_pending_dispatch_survives_bound_profile_and_egress_retirement(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key="profile-replacement")
    kwargs, _, _ = _delivery(fixture, run_id)
    assert fixture.projection.project(**kwargs).projected
    with fixture.factory.begin() as db:
        bound = db.get(ExecutionProfileRecord, fixture.profile_id)
        assert bound is not None
        bound.status = "retired"
        bound.version += 1
        db.flush()
        db.add(
            ExecutionProfileRecord(
                id=uuid4(),
                tenant_id=bound.tenant_id,
                space_id=bound.space_id,
                project_id=bound.project_id,
                egress_policy_id=bound.egress_policy_id,
                created_by=bound.created_by,
                name="managed-replacement",
                sandbox_backend=bound.sandbox_backend,
                network_mode=bound.network_mode,
                root_read_only=bound.root_read_only,
                run_as_uid=bound.run_as_uid,
                run_as_gid=bound.run_as_gid,
                no_new_privileges=bound.no_new_privileges,
                host_socket_access=bound.host_socket_access,
                syscall_profile_ref=bound.syscall_profile_ref,
                cpu_millis=bound.cpu_millis,
                memory_bytes=bound.memory_bytes,
                pids_limit=bound.pids_limit,
                allowed_tools=list(bound.allowed_tools),
                approval_required_tools=list(bound.approval_required_tools),
                denied_tools=list(bound.denied_tools),
                config_hash="3" * 64,
                status="active",
                version=1,
            )
        )
        policy = db.get(EgressPolicyRecord, bound.egress_policy_id)
        assert policy is not None
        policy.status = "retired"

    replayed = fixture.projection.project(**kwargs)
    assert replayed.replayed and replayed.execution_profile_id == fixture.profile_id
    _, lease, _ = _claim(fixture, run_id, instance_key="profile-replacement")
    assert lease.run_id == run_id
    with fixture.factory() as db:
        dispatch = db.get(RunDispatchRecord, run_id)
        policy = db.get(EgressPolicyRecord, fixture.egress_policy_id)
        assert dispatch is not None
        assert policy is not None and policy.status == "retired"
        assert dispatch.execution_profile_id == fixture.profile_id


def test_rejects_malformed_and_cross_tenant_delivery(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key="reject-envelope")
    kwargs, _, _ = _delivery(fixture, run_id)

    malformed = deepcopy(kwargs)
    malformed_payload = deepcopy(kwargs["payload"])
    assert isinstance(malformed_payload, dict)
    malformed_payload["unexpected"] = True
    malformed["payload"] = malformed_payload
    with pytest.raises(OutboxPublishError) as malformed_error:
        fixture.projection.project(**malformed)
    assert malformed_error.value.code == "run_dispatch_payload_malformed"

    cross_tenant = deepcopy(kwargs)
    cross_payload = deepcopy(kwargs["payload"])
    assert isinstance(cross_payload, dict)
    cross_payload["tenant_id"] = str(uuid4())
    cross_tenant["payload"] = cross_payload
    with pytest.raises(OutboxPublishError) as scope_error:
        fixture.projection.project(**cross_tenant)
    assert scope_error.value.code == "run_dispatch_outbox_mismatch"
    with fixture.factory() as db:
        assert db.get(RunDispatchRecord, run_id) is None


def test_active_profile_is_unique_per_scope(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    with pytest.raises(sa.exc.IntegrityError):
        with fixture.factory.begin() as db:
            profile = db.get(ExecutionProfileRecord, fixture.profile_id)
            assert profile is not None
            db.add(
                ExecutionProfileRecord(
                    tenant_id=profile.tenant_id,
                    space_id=profile.space_id,
                    project_id=profile.project_id,
                    egress_policy_id=profile.egress_policy_id,
                    created_by=profile.created_by,
                    name="managed-second",
                    sandbox_backend=profile.sandbox_backend,
                    network_mode=profile.network_mode,
                    root_read_only=profile.root_read_only,
                    run_as_uid=profile.run_as_uid,
                    run_as_gid=profile.run_as_gid,
                    no_new_privileges=profile.no_new_privileges,
                    host_socket_access=profile.host_socket_access,
                    syscall_profile_ref=profile.syscall_profile_ref,
                    cpu_millis=profile.cpu_millis,
                    memory_bytes=profile.memory_bytes,
                    pids_limit=profile.pids_limit,
                    allowed_tools=profile.allowed_tools,
                    approval_required_tools=profile.approval_required_tools,
                    denied_tools=profile.denied_tools,
                    config_hash="3" * 64,
                    status="active",
                    version=1,
                )
            )


def test_rejects_multiple_active_pools(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key="ambiguous-pool")
    pool_id = fixture.scheduling.create_pool(
        placement_id=fixture.placement_id,
        name="runtime-interactive-second",
        queue_class="interactive",
        capacity_slots=2,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream-revision",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    fixture.scheduling.configure_tenant_share(
        tenant_id=fixture.request.tenant_id,
        pool_id=pool_id,
        weight=1,
        max_concurrent=1,
        burst_limit=1,
    )

    kwargs, _, _ = _delivery(fixture, run_id)
    with pytest.raises(OutboxPublishError) as error:
        fixture.projection.project(**kwargs)
    assert error.value.code == "run_dispatch_runner_pool_ambiguous"


@pytest.mark.parametrize("missing_kind", ["profile", "egress", "pool"])
def test_rejects_missing_active_profile_or_pool(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
    missing_kind: str,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key=f"missing-{missing_kind}")
    with fixture.factory.begin() as db:
        if missing_kind in {"profile", "egress"}:
            profile = db.get(ExecutionProfileRecord, fixture.profile_id)
            assert profile is not None
            if missing_kind == "profile":
                profile.status = "retired"
            else:
                policy = db.get(EgressPolicyRecord, profile.egress_policy_id)
                assert policy is not None
                policy.status = "retired"
            expected = "run_dispatch_execution_profile_ambiguous"
        else:
            pool = db.get(RunDispatchRecord, run_id)
            assert pool is None
            share = db.scalar(
                sa.select(TenantQueueShareRecord).where(
                    TenantQueueShareRecord.pool_id == fixture.pool_id
                )
            )
            assert share is not None
            db.delete(share)
            expected = "run_dispatch_runner_pool_ambiguous"

    kwargs, _, _ = _delivery(fixture, run_id)
    with pytest.raises(OutboxPublishError) as error:
        fixture.projection.project(**kwargs)
    assert error.value.code == expected


def test_scheduler_recovers_reconnected_runner_without_old_raw_token(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key="recover-reconnected")
    _project(fixture, run_id)
    connection, lease, registered_at = _claim(fixture, run_id, instance_key="recover-reconnected")
    reconnected = fixture.scheduling.register_runner(
        pool_id=fixture.pool_id,
        instance_key="recover-reconnected",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream-revision",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=list(_dispatch_capabilities(fixture, run_id)),
        max_concurrency=2,
        now=registered_at + timedelta(seconds=3),
    )
    assert reconnected.runner_id == connection.runner_id
    assert reconnected.connection_generation == connection.connection_generation + 1

    recovered_at = lease.expires_at + timedelta(seconds=1)
    assert fixture.scheduling.recover_expired_dispatches(now=recovered_at) == (run_id,)
    assert fixture.scheduling.recover_expired_dispatches(now=recovered_at) == ()

    with fixture.factory() as db:
        run = db.get(RunRecord, run_id)
        dispatch = db.get(RunDispatchRecord, run_id)
        runner = db.get(RunnerRegistrationRecord, connection.runner_id)
        share = db.scalar(
            sa.select(TenantQueueShareRecord).where(
                TenantQueueShareRecord.pool_id == fixture.pool_id,
                TenantQueueShareRecord.tenant_id == fixture.request.tenant_id,
            )
        )
        capability = db.get(CapabilityTokenRecord, lease.capability_id)
        assert run is not None and run.status == "queued"
        assert run.lease_token is None and run.lease_expires_at is None
        assert dispatch is not None and dispatch.status == "pending"
        assert dispatch.selected_runner_id is None
        assert dispatch.dispatch_generation == lease.dispatch_generation
        assert runner is not None and runner.active_leases == 0
        assert share is not None and share.active_leases == 0
        assert capability is not None and capability.revoked_at is not None
        assert capability.runner_connection_generation == connection.connection_generation
        latest = db.scalar(
            sa.select(RunEventRecord)
            .where(RunEventRecord.run_id == run_id)
            .order_by(RunEventRecord.sequence.desc())
            .limit(1)
        )
        assert latest is not None and latest.event_type == "run.queued"
        assert latest.payload["dispatch_generation"] == lease.dispatch_generation


def test_scheduled_heartbeat_atomically_renews_capability_and_recovery_deadline(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key="heartbeat-capability")
    _project(fixture, run_id)
    _, lease, registered_at = _claim(fixture, run_id, instance_key="heartbeat-capability")

    heartbeat_at = registered_at + timedelta(seconds=5)
    renewed = fixture.execution.heartbeat(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        lease_duration=timedelta(seconds=20),
        now=heartbeat_at,
    )
    expected_expiry = heartbeat_at + timedelta(seconds=20)
    assert _aware(renewed.expires_at) == expected_expiry
    with fixture.factory() as db:
        capability = db.get(CapabilityTokenRecord, lease.capability_id)
        run = db.get(RunRecord, run_id)
        assert capability is not None and run is not None
        assert _aware(capability.expires_at) == expected_expiry
        assert _aware(run.lease_expires_at) == expected_expiry

    assert (
        fixture.scheduling.recover_expired_dispatches(now=lease.expires_at + timedelta(seconds=1))
        == ()
    )
    assert fixture.scheduling.recover_expired_dispatches(
        now=expected_expiry + timedelta(seconds=1)
    ) == (run_id,)


def test_scheduled_heartbeat_fails_closed_without_exact_capability(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key="heartbeat-missing-capability")
    _project(fixture, run_id)
    _, lease, registered_at = _claim(
        fixture,
        run_id,
        instance_key="heartbeat-missing-capability",
    )
    with fixture.factory.begin() as db:
        capability = db.get(CapabilityTokenRecord, lease.capability_id)
        assert capability is not None
        capability.revoked_at = registered_at + timedelta(seconds=2)
        capability.revocation_reason = "mutation"

    with pytest.raises(ExecutionControlPlaneError) as error:
        fixture.execution.heartbeat(
            run_id=run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            lease_duration=timedelta(seconds=20),
            now=registered_at + timedelta(seconds=5),
        )
    assert getattr(error.value, "code", None) == "lease_capability_binding_invalid"
    with fixture.factory() as db:
        run = db.get(RunRecord, run_id)
        assert run is not None
        assert _aware(run.lease_expires_at) == lease.expires_at


def _dispatch_capabilities(fixture: RuntimeDispatchFixture, run_id: UUID) -> tuple[str, ...]:
    with fixture.factory() as db:
        dispatch = db.get(RunDispatchRecord, run_id)
        assert dispatch is not None
        return tuple(dispatch.required_capabilities)


def test_scheduler_recovery_fails_closed_on_future_runner_generation(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    poisoned_run_id = _admit(fixture, key="recover-generation-poisoned")
    _project(fixture, poisoned_run_id)
    connection, poisoned_lease, _ = _claim(
        fixture,
        poisoned_run_id,
        instance_key="recover-generation-poisoned",
    )
    healthy_run_id = _admit(fixture, key="recover-generation-healthy")
    _project(fixture, healthy_run_id)
    _, healthy_lease, _ = _claim(
        fixture,
        healthy_run_id,
        instance_key="recover-generation-healthy",
    )
    with fixture.factory.begin() as db:
        capability = db.get(CapabilityTokenRecord, poisoned_lease.capability_id)
        assert capability is not None
        capability.runner_connection_generation = connection.connection_generation + 1

    recovered_at = max(poisoned_lease.expires_at, healthy_lease.expires_at) + timedelta(seconds=1)
    assert fixture.scheduling.recover_expired_dispatches(now=recovered_at) == (healthy_run_id,)
    assert fixture.scheduling.recover_expired_dispatches(now=recovered_at) == ()
    with fixture.factory() as db:
        run = db.get(RunRecord, poisoned_run_id)
        dispatch = db.get(RunDispatchRecord, poisoned_run_id)
        runner = db.get(RunnerRegistrationRecord, connection.runner_id)
        healthy_run = db.get(RunRecord, healthy_run_id)
        healthy_dispatch = db.get(RunDispatchRecord, healthy_run_id)
        share = db.scalar(
            sa.select(TenantQueueShareRecord).where(
                TenantQueueShareRecord.pool_id == fixture.pool_id,
                TenantQueueShareRecord.tenant_id == fixture.request.tenant_id,
            )
        )
        assert run is not None and run.status == "leased"
        assert dispatch is not None and dispatch.status == "leased"
        assert dispatch.recovery_quarantined_at is not None
        assert dispatch.recovery_quarantine_reason == "dispatch_recovery_generation_invalid"
        assert runner is not None and runner.active_leases == 1
        assert share is not None and share.active_leases == 1
        assert healthy_run is not None and healthy_run.status == "queued"
        assert healthy_dispatch is not None and healthy_dispatch.status == "pending"
        assert healthy_dispatch.recovery_quarantined_at is None


def test_scheduler_exhausted_fence_atomically_orphans_and_finalizes_quota(
    runtime_dispatch_fixture: RuntimeDispatchFixture,
) -> None:
    fixture = runtime_dispatch_fixture
    run_id = _admit(fixture, key="recover-exhausted")
    _project(fixture, run_id)
    connection, lease, _ = _claim(fixture, run_id, instance_key="recover-exhausted")

    assert fixture.scheduling.recover_expired_dispatches(
        max_fence_token=1,
        now=lease.expires_at + timedelta(seconds=1),
    ) == (run_id,)
    with fixture.factory() as db:
        run = db.get(RunRecord, run_id)
        dispatch = db.get(RunDispatchRecord, run_id)
        runner = db.get(RunnerRegistrationRecord, connection.runner_id)
        reservation = db.scalar(
            sa.select(QuotaReservationRecord).where(QuotaReservationRecord.run_id == run_id)
        )
        capability = db.get(CapabilityTokenRecord, lease.capability_id)
        assert run is not None and run.status == "orphaned"
        assert _aware(run.terminal_at) == lease.expires_at + timedelta(seconds=1)
        assert run.lease_token is None
        assert dispatch is not None and dispatch.status == "released"
        assert dispatch.released_at is not None
        assert runner is not None and runner.active_leases == 0
        assert reservation is not None and reservation.status == "released"
        assert capability is not None and capability.revocation_reason == "run_terminal"
