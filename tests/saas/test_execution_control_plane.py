from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane import (
    AdmissionQuotaRecord,
    ArtifactRecord,
    ControlPlaneOutboxEvent,
    EffectCallRecord,
    ExecutionControlPlane,
    ExecutionControlPlaneError,
    ExecutionRevisionSet,
    ExecutionSessionRecord,
    GlobalUser,
    ProjectAuthorizationError,
    ProjectMembershipRecord,
    ProjectRecord,
    QuotaReservationRecord,
    RunArtifactRecord,
    RunEventRecord,
    RunRecord,
    SaasBase,
    SessionTaskRecord,
    Space,
    SpaceMembership,
    TaskRecord,
    Tenant,
    TenantMembership,
)


@dataclass(frozen=True, slots=True)
class ExecutionScope:
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    owner_id: UUID


@pytest.fixture
def execution_control_plane() -> Iterator[
    tuple[sessionmaker[Session], ExecutionControlPlane, ExecutionScope, RequestContext]
]:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    try:
        yield _execution_fixture(engine)
    finally:
        engine.dispose()


def _execution_fixture(engine: sa.Engine, *, create_schema: bool = True):

    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    if engine.dialect.name == "sqlite":
        sa.event.listen(engine, "connect", _enable_foreign_keys)
    if create_schema:
        SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    scope = ExecutionScope(uuid4(), uuid4(), uuid4(), uuid4())
    with factory.begin() as db:
        db.add(GlobalUser(id=scope.owner_id, status="active", security_version=1))
        db.add(
            Tenant(
                id=scope.tenant_id,
                slug=f"execution-{scope.tenant_id.hex}",
                name="Execution tenant",
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
        db.add(
            ProjectRecord(
                id=scope.project_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                name="Execution project",
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
    request = RequestContext(
        actor_id=scope.owner_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        project_id=scope.project_id,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="execution-test",
    )
    return factory, ExecutionControlPlane(factory), scope, request


def _revisions() -> ExecutionRevisionSet:
    return ExecutionRevisionSet(
        product_revision="product-revision",
        upstream_revision="upstream-revision",
        schema_revision="p3a000000001",
        adapter_contract_version="0.2.0",
    )


def _admitted_run(
    service: ExecutionControlPlane,
    scope: ExecutionScope,
    request: RequestContext,
    *,
    idempotency_key: str = "run-admission",
    units: int = 1,
) -> tuple[UUID, UUID, UUID]:
    task_id = service.create_task(request, project_id=scope.project_id, title="Ship P3")
    session_id = service.create_session(request, project_id=scope.project_id)
    assert not service.attach_task(
        request,
        project_id=scope.project_id,
        session_id=session_id,
        task_id=task_id,
    )
    admitted = service.admit_run(
        request,
        project_id=scope.project_id,
        task_id=task_id,
        session_id=session_id,
        input_payload={"prompt": "implement"},
        quota_resource="run_units",
        quota_units=units,
        idempotency_key=idempotency_key,
        revisions=_revisions(),
    )
    return admitted.run_id, task_id, session_id


def _task_admission(service, scope, request, session_id, **changes):
    command = {
        "project_id": scope.project_id,
        "session_id": session_id,
        "title": "Build the requested page",
        "input_payload": {"message": {"stable_id": "a" * 32, "text": "Build a page"}},
        "quota_resource": "run_units",
        "quota_units": 1,
        "idempotency_key": "interactive-message-a",
        "revisions": _revisions(),
    }
    command.update(changes)
    return service.admit_task_run(request, **command)


def _admission_counts(factory):
    with factory() as db:
        return {
            model.__tablename__: db.scalar(sa.select(sa.func.count()).select_from(model))
            for model in (
                TaskRecord,
                SessionTaskRecord,
                RunRecord,
                QuotaReservationRecord,
                RunEventRecord,
                ControlPlaneOutboxEvent,
            )
        }


def test_task_run_admission_is_atomic_and_replays_without_creating_another_task(
    execution_control_plane,
) -> None:
    factory, service, scope, request = execution_control_plane
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=1
    )
    session_id = service.create_session(request, project_id=scope.project_id)
    admitted = _task_admission(service, scope, request, session_id)
    assert admitted.session_id == session_id
    assert admitted.status == "queued" and not admitted.replayed
    assert admitted.event_sequence == 2
    counts = _admission_counts(factory)
    assert counts == {
        "saas_tasks": 1,
        "saas_session_tasks": 1,
        "saas_runs": 1,
        "saas_quota_reservations": 1,
        "saas_run_events": 2,
        "saas_control_plane_outbox": 2,
    }
    replay = _task_admission(service, scope, request, session_id)
    assert replay == replace(admitted, replayed=True)
    assert _admission_counts(factory) == counts
    with factory() as db:
        run = db.get(RunRecord, admitted.run_id)
        task = db.get(TaskRecord, admitted.task_id)
        assert run is not None and task is not None
        assert task.created_by == request.actor_id
        assert task.title == "Build the requested page"
        assert run.input == {"message": {"stable_id": "a" * 32, "text": "Build a page"}}
        assert run.lease_token is None and run.lease_owner is None and run.fence_token == 0


@pytest.mark.parametrize(
    "change",
    [
        {"title": "Another task"},
        {"input_payload": {"message": "A different input"}},
        {"quota_units": 2},
        {"queue_class": "batch"},
        {"priority": 3},
        {"revisions": ExecutionRevisionSet("new-product", "upstream", "schema", "adapter")},
    ],
)
def test_task_run_admission_rejects_changed_idempotency_facts(
    execution_control_plane,
    change,
) -> None:
    factory, service, scope, request = execution_control_plane
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=10
    )
    session_id = service.create_session(request, project_id=scope.project_id)
    _task_admission(service, scope, request, session_id)
    counts = _admission_counts(factory)
    with pytest.raises(ExecutionControlPlaneError, match="another request") as error:
        _task_admission(service, scope, request, session_id, **change)
    assert error.value.code == "idempotency_conflict"
    assert _admission_counts(factory) == counts


@pytest.mark.parametrize(
    "failure", ["missing_quota", "exhausted_quota", "closed_session", "foreign_session"]
)
def test_task_run_rejection_leaves_no_orphan_task_link_or_run(
    execution_control_plane,
    failure,
) -> None:
    factory, service, scope, request = execution_control_plane
    session_id = service.create_session(request, project_id=scope.project_id)
    if failure != "missing_quota":
        service.configure_quota(
            request, project_id=scope.project_id, resource="run_units", limit_units=1
        )
    if failure == "exhausted_quota":
        _task_admission(service, scope, request, session_id)
    elif failure == "closed_session":
        service.close_session(request, project_id=scope.project_id, session_id=session_id)
    elif failure == "foreign_session":
        session_id = uuid4()
    counts = _admission_counts(factory)
    with pytest.raises(ExecutionControlPlaneError) as error:
        _task_admission(
            service, scope, request, session_id, idempotency_key="new-interactive-message"
        )
    assert (
        error.value.code
        == {
            "missing_quota": "quota_not_configured",
            "exhausted_quota": "quota_exceeded",
            "closed_session": "session_closed",
            "foreign_session": "session_not_found",
        }[failure]
    )
    assert _admission_counts(factory) == counts


@pytest.mark.parametrize("payload", [{}, {"message": float("nan")}, {"message": object()}])
def test_task_run_rejects_empty_or_non_json_input(execution_control_plane, payload) -> None:
    factory, service, scope, request = execution_control_plane
    session_id = service.create_session(request, project_id=scope.project_id)
    with pytest.raises(ExecutionControlPlaneError) as error:
        _task_admission(service, scope, request, session_id, input_payload=payload)
    assert error.value.code == "run_input_invalid"
    assert all(count == 0 for count in _admission_counts(factory).values())


def test_task_run_replay_after_session_close_does_not_reopen_execution(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=1
    )
    session_id = service.create_session(request, project_id=scope.project_id)
    admitted = _task_admission(service, scope, request, session_id)
    counts = _admission_counts(factory)
    service.close_session(request, project_id=scope.project_id, session_id=session_id)
    assert _task_admission(service, scope, request, session_id) == replace(admitted, replayed=True)
    assert _admission_counts(factory) == counts
    with factory() as db:
        execution_session = db.get(ExecutionSessionRecord, session_id)
        assert execution_session is not None and execution_session.status == "closed"


@pytest.mark.parametrize("membership_model", [TenantMembership, SpaceMembership])
def test_task_run_replay_requires_current_authorization(execution_control_plane, membership_model):
    factory, service, scope, request = execution_control_plane
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=1
    )
    session_id = service.create_session(request, project_id=scope.project_id)
    _task_admission(service, scope, request, session_id)
    counts = _admission_counts(factory)
    with factory.begin() as db:
        membership = db.scalar(sa.select(membership_model))
        membership.status = "suspended"
        membership.version += 1
    with pytest.raises(ProjectAuthorizationError):
        _task_admission(service, scope, request, session_id)
    assert _admission_counts(factory) == counts


def test_task_run_cannot_attach_a_session_from_another_project(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    session_id = service.create_session(request, project_id=scope.project_id)
    other_project = uuid4()
    with factory.begin() as db:
        db.add(
            ProjectRecord(
                id=other_project,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                name="Another project",
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
                project_id=other_project,
                subject_type="user",
                subject_id=scope.owner_id,
                role="owner",
                status="active",
                created_by=scope.owner_id,
                version=1,
            )
        )
    with pytest.raises(ExecutionControlPlaneError) as denied:
        _task_admission(
            service,
            replace(scope, project_id=other_project),
            replace(request, project_id=other_project),
            session_id,
        )
    assert denied.value.code == "session_not_found"
    assert all(count == 0 for count in _admission_counts(factory).values())


def test_task_session_and_run_admission_are_durable_atomic_and_idempotent(
    execution_control_plane: tuple[
        sessionmaker[Session], ExecutionControlPlane, ExecutionScope, RequestContext
    ],
) -> None:
    factory, service, scope, request = execution_control_plane
    quota_id = service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=2
    )
    task_id = service.create_task(request, project_id=scope.project_id, title="Durable task")
    session_id = service.create_session(request, project_id=scope.project_id)
    assert not service.attach_task(
        request,
        project_id=scope.project_id,
        session_id=session_id,
        task_id=task_id,
    )
    assert service.attach_task(
        request,
        project_id=scope.project_id,
        session_id=session_id,
        task_id=task_id,
    )

    admitted = service.admit_run(
        request,
        project_id=scope.project_id,
        task_id=task_id,
        session_id=session_id,
        input_payload={"prompt": "hello"},
        quota_resource="run_units",
        quota_units=2,
        idempotency_key="atomic-admission",
        revisions=_revisions(),
    )
    replayed = service.admit_run(
        request,
        project_id=scope.project_id,
        task_id=task_id,
        session_id=session_id,
        input_payload={"prompt": "hello"},
        quota_resource="run_units",
        quota_units=2,
        idempotency_key="atomic-admission",
        revisions=_revisions(),
    )
    assert admitted.status == "queued"
    assert admitted.event_sequence == 2
    assert replayed.run_id == admitted.run_id
    assert replayed.replayed

    with pytest.raises(ExecutionControlPlaneError) as conflict:
        service.admit_run(
            request,
            project_id=scope.project_id,
            task_id=task_id,
            session_id=session_id,
            input_payload={"prompt": "different"},
            quota_resource="run_units",
            quota_units=2,
            idempotency_key="atomic-admission",
            revisions=_revisions(),
        )
    assert conflict.value.code == "idempotency_conflict"

    with pytest.raises(ExecutionControlPlaneError) as exhausted:
        service.admit_run(
            request,
            project_id=scope.project_id,
            task_id=task_id,
            session_id=session_id,
            input_payload={"prompt": "second"},
            quota_resource="run_units",
            quota_units=1,
            idempotency_key="quota-exhausted",
            revisions=_revisions(),
        )
    assert exhausted.value.code == "quota_exceeded"

    assert not service.close_session(request, project_id=scope.project_id, session_id=session_id)
    assert service.close_session(request, project_id=scope.project_id, session_id=session_id)
    assert service.task_state(request, project_id=scope.project_id, task_id=task_id) == "queued"

    with factory() as db:
        task = db.get(TaskRecord, task_id)
        execution_session = db.get(ExecutionSessionRecord, session_id)
        quota = db.get(AdmissionQuotaRecord, quota_id)
        assert task is not None and not hasattr(task, "status")
        assert execution_session is not None and execution_session.status == "closed"
        assert quota is not None and quota.reserved_units == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(QuotaReservationRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(SessionTaskRecord)) == 1


def test_lease_fencing_effect_unknown_artifact_and_event_replay(
    execution_control_plane: tuple[
        sessionmaker[Session], ExecutionControlPlane, ExecutionScope, RequestContext
    ],
) -> None:
    factory, service, scope, request = execution_control_plane
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=4
    )
    run_id, task_id, _session_id = _admitted_run(service, scope, request)
    now = datetime(2026, 8, 4, 9, 0, tzinfo=timezone.utc)
    lease = service.claim_next_run(
        worker_id="worker-a", lease_duration=timedelta(minutes=5), now=now
    )
    assert lease is not None and lease.run_id == run_id and lease.fence_token == 1
    service.transition_run(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        target_status="starting",
        trace_id="worker-starting",
        now=now + timedelta(seconds=1),
    )
    service.transition_run(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        target_status="running",
        trace_id="worker-running",
        now=now + timedelta(seconds=2),
    )

    effect = service.begin_effect(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        effect_type="external",
        effect_name="deploy",
        idempotency_key="deploy-once",
        request_payload={"target": "test"},
        unknown_policy="approval_required",
        trace_id="effect-start",
        now=now + timedelta(seconds=3),
    )
    replayed_effect = service.begin_effect(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        effect_type="external",
        effect_name="deploy",
        idempotency_key="deploy-once",
        request_payload={"target": "test"},
        unknown_policy="approval_required",
        trace_id="effect-replay",
        now=now + timedelta(seconds=4),
    )
    assert replayed_effect.effect_call_id == effect.effect_call_id
    assert replayed_effect.replayed and replayed_effect.retry_permitted
    unknown = service.resolve_effect(
        run_id=run_id,
        effect_call_id=effect.effect_call_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        status="unknown",
        response=None,
        error_code="provider_timeout",
        trace_id="effect-unknown",
        now=now + timedelta(seconds=5),
    )
    assert unknown.status == "unknown" and not unknown.retry_permitted
    unknown_replay = service.begin_effect(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        effect_type="external",
        effect_name="deploy",
        idempotency_key="deploy-once",
        request_payload={"target": "test"},
        unknown_policy="approval_required",
        trace_id="effect-unknown-replay",
        now=now + timedelta(seconds=6),
    )
    assert unknown_replay.status == "unknown" and not unknown_replay.retry_permitted
    retry = service.resolve_unknown_effect(
        run_id=run_id,
        effect_call_id=effect.effect_call_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        resolution="retry",
        approval_or_compensation_ref="approval:security-123",
        trace_id="effect-approved",
        now=now + timedelta(seconds=7),
    )
    assert retry.status == "pending" and retry.retry_permitted
    completed = service.resolve_effect(
        run_id=run_id,
        effect_call_id=effect.effect_call_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        status="succeeded",
        response={"deployment_id": "dep-1"},
        error_code=None,
        trace_id="effect-complete",
        now=now + timedelta(seconds=8),
    )
    assert completed.status == "succeeded"

    artifact = service.register_artifact(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        content_sha256="a" * 64,
        size_bytes=12,
        media_type="text/plain",
        object_uri="s3://artifacts/a",
        source_revision="product-revision",
        metadata={"name": "result.txt"},
        role="output",
        trace_id="artifact",
        now=now + timedelta(seconds=9),
    )
    replayed_artifact = service.register_artifact(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        content_sha256="a" * 64,
        size_bytes=12,
        media_type="text/plain",
        object_uri="s3://artifacts/a",
        source_revision="product-revision",
        metadata={"name": "result.txt"},
        role="output",
        trace_id="artifact-replay",
        now=now + timedelta(seconds=10),
    )
    assert replayed_artifact.artifact_id == artifact.artifact_id
    assert replayed_artifact.replayed
    finished = service.transition_run(
        run_id=run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        target_status="succeeded",
        payload={"result": "ok"},
        trace_id="worker-success",
        now=now + timedelta(seconds=11),
    )
    assert finished.status == "succeeded"
    assert service.task_state(request, project_id=scope.project_id, task_id=task_id) == "succeeded"

    events = service.replay_events(
        request, project_id=scope.project_id, run_id=run_id, after_sequence=2
    )
    assert events
    assert [event.sequence for event in events] == list(
        range(events[0].sequence, events[-1].sequence + 1)
    )
    with factory() as db:
        run = db.get(RunRecord, run_id)
        quota = db.scalar(sa.select(AdmissionQuotaRecord))
        reservation = db.scalar(sa.select(QuotaReservationRecord))
        assert run is not None and run.lease_token is None
        assert run.event_sequence == db.scalar(
            sa.select(sa.func.count())
            .select_from(RunEventRecord)
            .where(RunEventRecord.run_id == run_id)
        )
        assert run.event_sequence == db.scalar(
            sa.select(sa.func.count())
            .select_from(ControlPlaneOutboxEvent)
            .where(ControlPlaneOutboxEvent.aggregate_key == str(run_id))
        )
        assert quota is not None and (quota.reserved_units, quota.consumed_units) == (0, 1)
        assert reservation is not None and reservation.status == "consumed"
        assert db.scalar(sa.select(sa.func.count()).select_from(EffectCallRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(ArtifactRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(RunArtifactRecord)) == 1


def test_cancel_recover_and_stale_worker_are_durable(
    execution_control_plane: tuple[
        sessionmaker[Session], ExecutionControlPlane, ExecutionScope, RequestContext
    ],
) -> None:
    factory, service, scope, request = execution_control_plane
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=4
    )
    cancelled_run, _, _ = _admitted_run(service, scope, request, idempotency_key="cancel-run")
    cancelled = service.request_cancel(
        request,
        project_id=scope.project_id,
        run_id=cancelled_run,
        reason="user requested",
    )
    assert cancelled.status == "cancelled"
    assert service.request_cancel(
        request,
        project_id=scope.project_id,
        run_id=cancelled_run,
        reason="repeat",
    ).replayed

    recover_run, _, _ = _admitted_run(service, scope, request, idempotency_key="recover-run")
    now = datetime(2026, 8, 4, 10, 0, tzinfo=timezone.utc)
    first = service.claim_next_run(
        worker_id="worker-old", lease_duration=timedelta(seconds=10), now=now
    )
    assert first is not None and first.run_id == recover_run
    recovered = service.recover_expired_runs(max_fence_token=2, now=now + timedelta(seconds=11))
    assert len(recovered) == 1 and recovered[0].status == "queued"
    second = service.claim_next_run(
        worker_id="worker-new",
        lease_duration=timedelta(seconds=10),
        now=now + timedelta(seconds=12),
    )
    assert second is not None and second.fence_token == 2
    with pytest.raises(ExecutionControlPlaneError) as stale:
        service.heartbeat(
            run_id=recover_run,
            lease_token=first.lease_token,
            fence_token=first.fence_token,
            lease_duration=timedelta(seconds=10),
            now=now + timedelta(seconds=13),
        )
    assert stale.value.code == "stale_fence"
    orphaned = service.recover_expired_runs(max_fence_token=2, now=now + timedelta(seconds=23))
    assert len(orphaned) == 1 and orphaned[0].status == "orphaned"

    with factory() as db:
        statuses: dict[UUID, str] = {}
        for stored_run_id, status in db.execute(sa.select(RunRecord.id, RunRecord.status)):
            statuses[stored_run_id] = status
        assert statuses[cancelled_run] == "cancelled"
        assert statuses[recover_run] == "orphaned"
        reservations = tuple(db.scalars(sa.select(QuotaReservationRecord)))
        assert {reservation.status for reservation in reservations} == {"released"}
        quota = db.scalar(sa.select(AdmissionQuotaRecord))
        assert quota is not None and quota.reserved_units == 0
