from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from omnigent.errors import OmnigentError
from omnigent.host.frames import HostHelloFrame, HostStatFrame, decode_host_frame
from omnigent.server.app import create_app
from omnigent.server.auth import LEVEL_OWNER
from omnigent.server.managed_hosts import ManagedSandboxConfig, ManagedSandboxDeployment
from omnigent.server.schemas import SessionEventInput
from omnigent.stores.host_store import HostStore
from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore
from omnigent.stores.project_store.sqlalchemy_store import SqlAlchemyProjectStore
from saas.compatibility import bind_runtime_context
from saas.control_plane import (
    AdmissionQuotaRecord,
    ExecutionRevisionSet,
    ProjectMembershipRecord,
    ProjectRecord,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.execution_models import (
    ExecutionSessionRecord,
    QuotaReservationRecord,
    RunRecord,
    TaskRecord,
)
from saas.control_plane.interactive_execution import RuntimeSessionRunAdmission
from saas.control_plane.isolation_models import EgressPolicyRecord, ExecutionProfileRecord
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord
from saas.control_plane.outbox import OutboxClaimRoute, OutboxDispatcher
from saas.control_plane.run_dispatch_projection import RunQueuedDispatchProjection
from saas.control_plane.scheduling import SchedulingControlPlane, SchedulingError
from saas.control_plane.scheduling_models import CapabilityTokenRecord, RunDispatchRecord
from saas.control_plane.tenant_model_catalog import TenantModelCatalog
from saas.production.interactive_execution import InteractiveConversationStore
from saas.production.tenant_model_catalog import create_tenant_model_catalog_router
from tests.saas import test_model_projection
from tests.saas.test_agent_catalog import _runtime
from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login
from tests.saas.test_model_connections import _fixture as _connections_fixture
from tests.saas.test_model_publications import _envelope
from tests.saas.test_model_publications import _fixture as _publication_fixture
from tests.saas.test_official_http_integration import _official_dependencies
from tests.saas.test_run_customer_pricing import _plan
from tests.server.helpers import build_agent_bundle


@pytest.fixture
def interactive_http(db_uri, tmp_path, monkeypatch, request):
    monkeypatch.setenv("OMNIGENT_WS_ALLOWED_ORIGINS", "http://testserver")
    base, scope = _build_fastapi_app()
    engine = base.state.saas_test_engine
    factory = base.state.saas_test_sessions
    monkeypatch.setattr(
        test_model_projection, "_fixture", lambda: _connections_fixture(engine=engine)
    )
    case = getattr(request, "param", False)
    options = case if isinstance(case, dict) else {"responses": case}
    service, worker, _, actor, command, calls = _publication_fixture(
        responses=options.get("responses", False)
    )
    command["tenant_id"] = UUID(scope["tenant_id"])
    operation = service.admit(actor, **command)
    worker.publish(**_envelope(factory, operation.id))
    project_id, runtime_project_id = uuid4(), uuid4().hex
    with factory.begin() as db:
        partition = db.get(RuntimePartitionRecord, UUID(scope["partition_id"]))
        publication = db.scalar(sa.select(ModelPublicationVersionRecord))
        marker = {
            "schema_version": 1,
            "public_model_id": publication.public_model_id,
            "wire_api": publication.wire_api,
            "generation": publication.generation,
            "snapshot_sha256": publication.snapshot_sha256,
        }
        runtime = replace(
            _runtime(),
            actor_id=UUID(scope["user_id"]),
            tenant_id=UUID(scope["tenant_id"]),
            space_id=UUID(scope["space_id"]),
            project_id=None,
            runtime_partition_id=partition.id,
            placement_id=partition.placement_id,
            placement_generation=partition.placement_generation,
            binding_generation=3,
            source_revision=partition.source_revision,
            physical_workspace_id=41,
            runtime_user_key="runtime_http_user",
        )
        db.add(
            ProjectRecord(
                id=project_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                name="Interactive project",
                visibility="restricted",
                created_by=runtime.actor_id,
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=project_id,
                subject_type="user",
                subject_id=runtime.actor_id,
                role="owner",
                status="active",
                created_by=runtime.actor_id,
                version=1,
            )
        )
        db.add(
            RuntimeResourceBindingRecord(
                runtime_partition_id=runtime.runtime_partition_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=project_id,
                resource_type="project",
                runtime_resource_id=runtime_project_id,
                saas_resource_id=project_id,
                partition_generation=runtime.placement_generation,
                binding_generation=1,
                status="active",
            )
        )
        db.add(
            AdmissionQuotaRecord(
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=project_id,
                resource="run",
                limit_units=100,
                reserved_units=0,
                consumed_units=0,
                version=1,
            )
        )
    _plan(factory, SimpleNamespace(owner_id=runtime.actor_id, tenant_id=runtime.tenant_id))
    dependencies = _official_dependencies(db_uri, tmp_path)
    dependencies["host_store"] = HostStore(db_uri)
    permissions = SqlAlchemyPermissionStore(db_uri)
    projects = SqlAlchemyProjectStore(db_uri)
    admission = RuntimeSessionRunAdmission(
        factory,
        revisions=ExecutionRevisionSet("c" * 40, runtime.source_revision, "c4d5e6f7a8b9", "0.2.0"),
    )
    delegate = dependencies["conversation_store"]
    store = InteractiveConversationStore(
        delegate,
        admission,
        permission_store=permissions,
        agent_cache=dependencies["agent_cache"],
        runtime_enabled=True,
    )
    with bind_runtime_context(runtime):
        projects.create(runtime_project_id, "Interactive project", runtime.runtime_user_key)
        conversation = delegate.create_conversation(
            agent_id="b" * 32,
            host_id="c" * 32,
            workspace="/workspace",
            project_id=runtime_project_id,
            model_override=marker["public_model_id"],
            inference_snapshot={
                "runtime_config": {},
                "harness": "codex",
                "managed_execution": marker,
                "managed_launch": _launch(),
            },
        )
        permissions.grant(runtime.runtime_user_key, conversation.id, LEVEL_OWNER)
    dependencies["conversation_store"] = store
    base.include_router(
        create_tenant_model_catalog_router(
            auth_provider=base.state.saas_test_auth,
            catalog=TenantModelCatalog(engine),
            billing_sessions=factory if options.get("catalog_billing", True) else None,
        ),
        prefix="/v1",
    )
    app = create_app(
        **dependencies,
        auth_provider=base.state.saas_test_auth,
        permission_store=permissions,
        project_store=projects,
        extra_routers=[(base.router, "", ["saas-test"])],
    )
    for middleware in base.user_middleware:
        app.add_middleware(middleware.cls, **middleware.kwargs)
    client = TestClient(app)
    csrf = _login(client)
    yield SimpleNamespace(
        app=app,
        client=client,
        factory=factory,
        runtime=runtime,
        store=store,
        delegate=delegate,
        conversation=conversation,
        marker=marker,
        project_id=project_id,
        runtime_project_id=runtime_project_id,
        permissions=permissions,
        dependencies=dependencies,
        calls=calls,
        publication_service=service,
        publication_worker=worker,
        publication_actor=actor,
        publication_command=command,
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    client.close()
    engine.dispose()


def _message(stable_id="a" * 32, text="Build the requested page"):
    return {
        "type": "message",
        "data": {
            "role": "user",
            "stable_id": stable_id,
            "content": [{"type": "input_text", "text": text}],
        },
    }


def _launch():
    return {
        "schema_version": 1,
        "host_type": "external",
        "host_id": "c" * 32,
        "sandbox_provider": None,
        "workspaces": [],
        "workspace": "/workspace",
        "git_branch": None,
        "agent_id": "b" * 32,
        "harness": "codex",
        "reasoning_effort": None,
        "terminal_launch_args": None,
    }


def _post(f, body):
    return f.client.post(f"/v1/sessions/{f.conversation.id}/events", json=body, headers=f.headers)


@pytest.mark.parametrize("entry", ["new_session", "message"])
def test_default_disabled_runtime_rejects_managed_input_without_persistent_admission(
    interactive_http, entry
):
    f = interactive_http
    f.store.__init__(f.delegate, f.store._admission, permission_store=f.permissions)
    before_calls = list(f.calls)
    if entry == "new_session":
        body = _managed_create(f)
        response = f.client.post("/v1/sessions", json=body, headers=f.headers)
        with bind_runtime_context(f.runtime):
            assert (
                f.delegate.get_conversation(body["labels"]["omnigent.client_create_token"]) is None
            )
    else:
        response = _post(f, _message())
    assert response.status_code == 503, response.text
    assert "interactive_runtime_disabled" in response.text
    with f.factory() as db:
        for record in (TaskRecord, RunRecord, ExecutionSessionRecord):
            assert db.scalar(sa.select(sa.func.count()).select_from(record)) == 0
        assert db.scalar(sa.select(AdmissionQuotaRecord.reserved_units)) == 0
    assert f.calls == before_calls


def test_disabling_runtime_preserves_interrupt_of_already_admitted_input(interactive_http):
    f = interactive_http
    admitted = _post(f, _message())
    assert admitted.status_code == 202, admitted.text
    f.store.__init__(f.delegate, f.store._admission, permission_store=f.permissions)
    stopped = _post(f, {"type": "interrupt", "data": {}})
    assert stopped.status_code == 202, stopped.text
    assert stopped.json()["queued"] is False
    with f.factory() as db:
        assert db.scalar(sa.select(RunRecord.status)) == "cancelled"
        assert db.scalar(sa.select(AdmissionQuotaRecord.reserved_units)) == 0


@pytest.mark.asyncio
async def test_disabled_runtime_does_not_intercept_an_ordinary_session_creation():
    store = InteractiveConversationStore(object(), object(), permission_store=None)
    assert (
        await store.prepare_session_inference(
            None,
            SimpleNamespace(inference_configuration_revision=None),
            None,
            None,
            harness_override=None,
            model_override=None,
        )
        is None
    )


def _scheduling(factory, runtime, project_id, *, pool_id=None):
    policy_id, profile_id = uuid4(), uuid4()
    with factory.begin() as db:
        placement = db.get(RuntimePlacementRecord, runtime.placement_id)
        schema_revision = placement.official_schema_revision
        db.add(
            EgressPolicyRecord(
                id=policy_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=project_id,
                created_by=runtime.actor_id,
                name="default-deny",
                rules=[],
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
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=project_id,
                egress_policy_id=policy_id,
                created_by=runtime.actor_id,
                name="interactive-isolated",
                sandbox_backend="linux_bwrap",
                network_mode="proxy_only",
                root_read_only=True,
                run_as_uid=10001,
                run_as_gid=10001,
                no_new_privileges=True,
                host_socket_access=False,
                syscall_profile_ref="default-v1",
                cpu_millis=1000,
                memory_bytes=536870912,
                pids_limit=128,
                allowed_tools=["shell"],
                approval_required_tools=[],
                denied_tools=[],
                config_hash="2" * 64,
                status="active",
                version=1,
            )
        )
    scheduling = SchedulingControlPlane(factory)
    if pool_id is None:
        pool_id = scheduling.create_pool(
            placement_id=runtime.placement_id,
            name="managed-interactive",
            queue_class="managed_interactive",
            capacity_slots=2,
            reserved_slots=0,
            protocol_version=2,
            source_revision="c" * 40,
            schema_revision=schema_revision,
            adapter_contract_version=runtime.adapter_contract_version,
        )
    scheduling.configure_tenant_share(
        tenant_id=runtime.tenant_id,
        pool_id=pool_id,
        weight=1,
        max_concurrent=2,
        burst_limit=2,
    )
    return scheduling, pool_id


def _queued_worker(dispatcher_factory, executor_factory):
    return OutboxDispatcher(
        dispatcher_factory,
        RunQueuedDispatchProjection(executor_factory),
        claim_routes=(OutboxClaimRoute("run", "run.event.persisted", "run.queued"),),
    )


def test_actual_message_advances_through_existing_outbox_to_one_dispatch(interactive_http):
    f = interactive_http
    scheduling, pool_id = _scheduling(f.factory, f.runtime, f.project_id)
    before = list(f.calls)
    admitted = _post(f, _message())
    assert admitted.status_code == 202, admitted.text
    worker = _queued_worker(f.factory, f.factory)
    result = worker.dispatch_once()
    assert (result.claimed, result.published, result.failed) == (1, 1, 0)
    assert worker.dispatch_once().claimed == 0
    with f.factory() as db:
        dispatch = db.scalars(sa.select(RunDispatchRecord)).one()
        run = db.get(RunRecord, dispatch.run_id)
        assert str(dispatch.run_id) == admitted.json()["run_id"]
        assert run.status == "queued" and run.fence_token == 0 and run.lease_token is None
        assert (
            run.input["execution"]["runtime_partition_generation"]
            == f.runtime.placement_generation
        )
        assert run.input["execution"]["runtime_project_id"] == f.runtime_project_id
        required = dispatch.required_capabilities
        placement = db.get(RuntimePlacementRecord, f.runtime.placement_id)
        failure_domain, schema_revision = (
            placement.failure_domain,
            placement.official_schema_revision,
        )
    for claims_interactive in (False, True):
        connection = scheduling.register_runner(
            pool_id=pool_id,
            instance_key=f"runtime-support-{claims_interactive}",
            failure_domain=failure_domain,
            protocol_version=2,
            source_revision="c" * 40,
            schema_revision=schema_revision,
            adapter_contract_version=f.runtime.adapter_contract_version,
            capabilities=required
            if claims_interactive
            else [value for value in required if value != "runtime.interactive.v1"],
            max_concurrency=1,
        )

        def claim(connection=connection):
            return scheduling.claim_fair_run(
                runner_id=connection.runner_id,
                connection_generation=connection.connection_generation,
                connection_token=connection.connection_token,
                lease_duration=timedelta(seconds=30),
                capability_actions=["run.execute", "sandbox.launch", "worktree.write"],
                capability_resource_scope={
                    "runtime_partition_id": str(f.runtime.runtime_partition_id)
                },
                expected_product_revision="c" * 40,
                product_image_digest="sha256:" + "a" * 64,
            )

        if claims_interactive:
            with pytest.raises(SchedulingError) as rejected:
                claim()
            assert rejected.value.code == "interactive_executor_required"
        else:
            assert claim() is None
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(CapabilityTokenRecord)) == 0
        run = db.get(RunRecord, UUID(admitted.json()["run_id"]))
        assert run.status == "queued" and run.lease_token is None
    assert f.calls == before


@pytest.mark.parametrize(
    "drift", ["generation", "runtime_project", "runtime_session", "partition", "saas_session"]
)
def test_queued_interactive_input_cannot_be_silently_retargeted(interactive_http, drift):
    f = interactive_http
    _scheduling(f.factory, f.runtime, f.project_id)
    admitted = _post(f, _message())
    assert admitted.status_code == 202, admitted.text
    with f.factory.begin() as db:
        if drift == "generation":
            db.execute(sa.update(RuntimePartitionRecord).values(placement_generation=4))
            db.execute(sa.update(RuntimeResourceBindingRecord).values(partition_generation=4))
        elif drift == "runtime_project":
            db.execute(
                sa.update(RuntimeResourceBindingRecord).values(runtime_resource_id=uuid4().hex)
            )
        elif drift in {"runtime_session", "saas_session"}:
            run = db.get(RunRecord, UUID(admitted.json()["run_id"]))
            if drift == "saas_session":
                run.session_id = None
            else:
                run.input = {
                    "execution": {**run.input["execution"], "runtime_session_id": uuid4().hex}
                }
        else:
            original = db.get(RuntimePartitionRecord, f.runtime.runtime_partition_id)
            replacement = uuid4()
            db.add(
                RuntimePartitionRecord(
                    id=replacement,
                    tenant_id=original.tenant_id,
                    space_id=original.space_id,
                    placement_id=original.placement_id,
                    runtime_type=original.runtime_type,
                    runtime_version=original.runtime_version,
                    physical_partition_key="42",
                    placement_generation=original.placement_generation,
                    source_revision=original.source_revision,
                    adapter_contract_version=original.adapter_contract_version,
                    status="active",
                )
            )
            db.flush()
            db.execute(
                sa.update(RuntimeResourceBindingRecord).values(runtime_partition_id=replacement)
            )
    result = _queued_worker(f.factory, f.factory).dispatch_once()
    assert result.failed == result.quarantined == 1 and result.published == 0
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunDispatchRecord)) == 0
        run = db.get(RunRecord, UUID(admitted.json()["run_id"]))
        assert run.status == "queued" and run.lease_token is None and run.fence_token == 0


def test_actual_message_route_queues_one_real_run_without_a_runner_or_provider_call(
    interactive_http,
):
    f = interactive_http
    before_calls = list(f.calls)
    result = _post(f, _message())
    assert result.status_code == 202, result.text
    replay = _post(f, _message())
    assert replay.status_code == 202, replay.text
    assert replay.json() == result.json()
    with f.factory() as db:
        runs = list(db.scalars(sa.select(RunRecord)))
        assert len(runs) == 1
        run = runs[0]
        assert str(run.id) == result.json()["run_id"]
        assert run.session_id != UUID(f.conversation.id)
        assert run.status == "queued" and run.fence_token == 0 and run.lease_token is None
        assert run.input["execution"]["event"] == {
            **_message(),
            "model_override": None,
            "tools": None,
            "created_by": None,
        }
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(ExecutionSessionRecord)) == 1
    with bind_runtime_context(f.runtime):
        assert f.delegate.get_conversation(f.conversation.id).runner_id is None
        assert f.delegate.list_items(f.conversation.id).data == []
    assert f.calls == before_calls


def test_retry_reads_the_original_run_and_interrupt_cancels_all_queued_inputs(interactive_http):
    f = interactive_http
    first = _post(f, _message())
    second = _post(f, _message("b" * 32, "Continue the task"))
    assert first.status_code == second.status_code == 202
    retry = _post(f, {"type": "retry_session", "data": {}})
    assert retry.status_code == 202, retry.text
    assert retry.json()["queued"] is False
    assert retry.json()["run_id"] in {first.json()["run_id"], second.json()["run_id"]}
    with bind_runtime_context(f.runtime):
        f.delegate.update_conversation(f.conversation.id, model_override="retired-model")
    stopped = _post(f, {"type": "interrupt", "data": {}})
    assert stopped.status_code == 202, stopped.text
    again = _post(f, {"type": "interrupt", "data": {}})
    assert again.status_code == 202
    with f.factory() as db:
        assert set(db.scalars(sa.select(RunRecord.status))) == {"cancelled"}
        assert set(db.scalars(sa.select(QuotaReservationRecord.status))) == {"released"}
        assert db.scalar(sa.select(AdmissionQuotaRecord.reserved_units)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 2


def test_cancelled_message_replay_does_not_revive_execution(interactive_http):
    f = interactive_http
    first = _post(f, _message())
    assert first.status_code == 202, first.text
    assert _post(f, {"type": "interrupt", "data": {}}).status_code == 202
    replay = _post(f, _message())
    assert replay.status_code == 202, replay.text
    assert replay.json()["run_id"] == first.json()["run_id"]
    assert replay.json()["queued"] is False
    assert replay.json()["run_status"] == "cancelled"
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 1
        assert db.scalar(sa.select(AdmissionQuotaRecord.reserved_units)) == 0


@pytest.mark.parametrize("owner", [False, True])
def test_public_stop_requires_owner_before_cancelling_inputs(interactive_http, owner):
    from omnigent.server.auth import LEVEL_EDIT

    f = interactive_http
    assert _post(f, _message()).status_code == 202
    calls = []

    async def stop(conversation, runtime, cancel_inputs):
        calls.append((conversation.id, runtime.actor_id))
        return await cancel_inputs()

    f.store.session_stop_handler = stop
    if not owner:
        with bind_runtime_context(f.runtime):
            f.permissions.grant(f.runtime.runtime_user_key, f.conversation.id, LEVEL_EDIT)
    response = _post(f, {"type": "stop_session", "data": {}})
    assert response.status_code == (202 if owner else 403), response.text
    assert len(calls) == int(owner)
    with f.factory() as db:
        assert db.scalar(sa.select(RunRecord.status)) == ("cancelled" if owner else "queued")


def test_public_stop_without_a_trusted_controller_fails_closed(interactive_http):
    f = interactive_http
    assert _post(f, _message()).status_code == 202
    response = _post(f, {"type": "stop_session", "data": {}})
    assert response.status_code == 503, response.text
    with f.factory() as db:
        assert db.scalar(sa.select(RunRecord.status)) == "queued"


def test_interrupt_uses_cancel_receipt_when_queued_input_is_claimed_concurrently(
    interactive_http, monkeypatch
):
    from tests.saas.test_interactive_runtime import _running_lease

    f = interactive_http
    first = _post(f, _message())
    assert first.status_code == 202
    execution = f.store._admission._execution
    cancel = execution.request_cancel
    claimed = []

    def claim_before_cancel(*args, **kwargs):
        lease, _ = _running_lease(f)
        claimed.append(lease.run_id)
        return cancel(*args, **kwargs)

    monkeypatch.setattr(execution, "request_cancel", claim_before_cancel)
    response = _post(f, {"type": "interrupt", "data": {}})
    assert response.status_code == 202, response.text
    assert response.json()["physical_run_id"] == first.json()["run_id"] == str(claimed[0])
    with f.factory() as db:
        assert db.scalar(sa.select(RunRecord.status)) == "cancelling"


@pytest.mark.asyncio
@pytest.mark.parametrize("undone", [False, True])
async def test_managed_archive_honors_persisted_undo_before_controller_stop(
    interactive_http, monkeypatch, undone
):
    from omnigent.server.routes import sessions
    from omnigent.server.routes._sessions.orchestration import _archive_stop

    f = interactive_http
    contexts = []
    dispatch = f.store._admission.dispatch

    def capture(runtime, *args, **kwargs):
        contexts.append(runtime)
        return dispatch(runtime, *args, **kwargs)

    monkeypatch.setattr(f.store._admission, "dispatch", capture)
    assert _post(f, _message()).status_code == 202
    calls = []

    async def stop(conversation, runtime, cancel_inputs):
        calls.append(conversation.id)
        return await cancel_inputs()

    async def unexpected(*args, **kwargs):
        pytest.fail("Managed archive must not bypass the controller")

    f.store.session_stop_handler = stop
    monkeypatch.setattr(sessions, "_best_effort_stop", unexpected)
    with bind_runtime_context(contexts[0]):
        f.delegate.update_conversation(f.conversation.id, archived=True)
        if undone:
            f.delegate.update_conversation(f.conversation.id, archived=False)
        await _archive_stop(f.conversation.id, f.store, None, None)
    assert len(calls) == int(not undone)
    with f.factory() as db:
        assert db.scalar(sa.select(RunRecord.status)) == ("queued" if undone else "cancelled")


@pytest.mark.parametrize("revoked", ["project", "alias", "partition", "quota"])
def test_message_admission_rechecks_live_scope_and_quota(interactive_http, revoked):
    f = interactive_http
    with f.factory.begin() as db:
        if revoked == "project":
            db.execute(sa.update(ProjectMembershipRecord).values(status="revoked", version=2))
        elif revoked == "alias":
            db.execute(sa.update(RuntimeIdentityAliasRecord).values(status="suspended"))
        elif revoked == "partition":
            db.execute(sa.update(RuntimePartitionRecord).values(status="draining"))
        else:
            db.execute(sa.update(AdmissionQuotaRecord).values(limit_units=1, consumed_units=1))
    response = _post(f, _message())
    assert response.status_code in {400, 403}, response.text
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0
        assert db.scalar(sa.select(AdmissionQuotaRecord.reserved_units)) == 0


@pytest.mark.asyncio
async def test_marked_background_input_cannot_bypass_policy_or_actor_admission(interactive_http):
    f = interactive_http
    event = SessionEventInput.model_validate(_message())
    for checked, actor in ((False, f.runtime.runtime_user_key), (True, None)):
        with bind_runtime_context(f.runtime), pytest.raises(OmnigentError):
            await f.store.dispatch_session_input(
                f.conversation.id,
                f.conversation,
                event,
                created_by=actor,
                input_policy_checked=checked,
            )
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0


def _managed_create(f):
    agent_id = uuid4().hex
    bundle_path = f"{agent_id}/bundle"
    with bind_runtime_context(f.runtime):
        f.dependencies["agent_store"].create(agent_id, "interactive-agent", bundle_path)
    f.dependencies["artifact_store"].put(
        bundle_path,
        build_agent_bundle(
            name="interactive-agent",
            executor={"type": "omnigent", "config": {"harness": "openai-agents"}},
            include_llm=False,
        ),
    )

    def unused_launcher():
        pytest.fail("admission must not launch a legacy Sandbox")

    f.app.state.sandbox_config = ManagedSandboxDeployment.single(
        ManagedSandboxConfig(
            server_url="http://isolated.invalid",
            token_ttl_s=3600,
            provider="kubernetes",
            launcher_factory=unused_launcher,
        )
    )
    return {
        "agent_id": agent_id,
        "project_id": f.runtime_project_id,
        "host_type": "managed",
        "model_override": f.marker["public_model_id"],
        "inference_configuration_revision": (
            f"managed-model:{f.marker['wire_api']}:{f.marker['generation']}:"
            f"{f.marker['snapshot_sha256']}"
        ),
        "workspaces": ["https://github.com/example/synthetic.git#feature"],
        "initial_items": [_message()],
        "labels": {"omnigent.client_create_token": uuid4().hex},
    }


@pytest.mark.parametrize("recover_failed_admission", [None, "quota", "actor"])
def test_new_session_initial_items_uses_the_same_admission_contract(
    interactive_http, recover_failed_admission
):
    f = interactive_http
    body = _managed_create(f)
    agent_id = body["agent_id"]
    before_calls = list(f.calls)
    if recover_failed_admission == "quota":
        with f.factory.begin() as db:
            db.execute(sa.update(AdmissionQuotaRecord).values(limit_units=1, consumed_units=1))
        failed = f.client.post("/v1/sessions", json=body, headers=f.headers)
        assert failed.status_code == 400, failed.text
        with f.factory.begin() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0
            db.execute(sa.update(AdmissionQuotaRecord).values(limit_units=100, consumed_units=0))
    elif recover_failed_admission == "actor":
        forged = {**body, "initial_items": [{**_message(), "created_by": "someone-else"}]}
        failed = f.client.post("/v1/sessions", json=forged, headers=f.headers)
        assert failed.status_code == 400, failed.text
        with f.factory() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0
    response = f.client.post("/v1/sessions", json=body, headers=f.headers)
    assert response.status_code == 201, response.text
    session_id = response.json()["id"]
    assert session_id != f.conversation.id
    replay = f.client.post("/v1/sessions", json=body, headers=f.headers)
    assert replay.status_code == 201, replay.text
    assert replay.json()["id"] == session_id
    with f.factory() as db:
        run = db.scalars(sa.select(RunRecord)).one()
        assert run.status == "queued" and run.queue_class == "managed_interactive"
        assert run.input["execution"]["runtime_session_id"] == session_id
        assert run.input["execution"]["event"]["data"] == _message()["data"]
        target = run.input["execution"]["launch"]
        assert target["host_type"] == "managed" and target["sandbox_provider"] == "kubernetes"
        assert target["workspaces"] == body["workspaces"]
        assert target["agent_id"] == agent_id and target["harness"] == "openai-agents"
        assert run.input["execution"]["model_publication"] == f.marker
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 1
    with bind_runtime_context(f.runtime):
        stored = f.delegate.get_conversation(session_id)
        assert stored.runner_id is None
        assert stored.inference_snapshot["managed_launch"] == target
        assert f.delegate.list_items(session_id).data == []
    assert f.calls == before_calls


def test_managed_create_rejects_wrong_publication_project_and_target_before_persistence(
    interactive_http,
):
    f = interactive_http
    body = _managed_create(f)
    before_calls = list(f.calls)
    with bind_runtime_context(f.runtime):
        before_sessions = len(f.delegate.list_conversations().data)
    for changed in (
        {"inference_configuration_revision": body["inference_configuration_revision"] + ":extra"},
        {
            "inference_configuration_revision": body["inference_configuration_revision"][:-64]
            + "0" * 64
        },
        {"project_id": uuid4().hex},
        {"model_override": "unpublished"},
        {"sandbox_provider": "not-configured"},
        {"host_type": "external", "workspace": None, "workspaces": None},
    ):
        response = f.client.post("/v1/sessions", json={**body, **changed}, headers=f.headers)
        assert response.status_code in {400, 404}, response.text
    with bind_runtime_context(f.runtime):
        assert len(f.delegate.list_conversations().data) == before_sessions
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 0
    assert f.calls == before_calls


def test_managed_create_token_cannot_retarget_an_admitted_session(interactive_http):
    f = interactive_http
    body = _managed_create(f)
    first = f.client.post("/v1/sessions", json=body, headers=f.headers)
    assert first.status_code == 201, first.text
    changed = {**body, "workspaces": ["https://github.com/example/other.git"]}
    conflict = f.client.post("/v1/sessions", json=changed, headers=f.headers)
    assert conflict.status_code == 409, conflict.text
    with f.factory() as db:
        run = db.scalars(sa.select(RunRecord)).one()
        assert run.input["execution"]["launch"]["workspaces"] == body["workspaces"]


def test_managed_fork_cannot_fall_back_to_legacy_launch_or_create_an_orphan(interactive_http):
    f = interactive_http
    body = _managed_create(f)
    created = f.client.post("/v1/sessions", json=body, headers=f.headers)
    assert created.status_code == 201, created.text
    client = TestClient(f.app, raise_server_exceptions=False)
    client.cookies.update(f.client.cookies)
    try:
        response = client.post(
            f"/v1/sessions/{created.json()['id']}/fork", json={}, headers=f.headers
        )
    finally:
        client.close()
    assert response.status_code == 400, response.text
    assert "interactive_fork_requires_managed_lifecycle" in response.text
    with bind_runtime_context(f.runtime):
        assert len(f.delegate.list_conversations().data) == 2
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1


def test_create_recovery_pins_publication_and_provider_across_configuration_changes(
    interactive_http,
):
    f = interactive_http
    body = _managed_create(f)
    with f.factory.begin() as db:
        db.execute(sa.update(AdmissionQuotaRecord).values(limit_units=1, consumed_units=1))
    failed = f.client.post("/v1/sessions", json=body, headers=f.headers)
    assert failed.status_code == 400, failed.text
    publication = f.publication_service.admit(
        f.publication_actor,
        **{
            **f.publication_command,
            "expected_generation": 1,
            "idempotency_key": "next-interactive-publication",
        },
    )
    f.publication_worker.publish(**_envelope(f.factory, publication.id))
    original = f.app.state.sandbox_config.default
    f.app.state.sandbox_config = ManagedSandboxDeployment(
        configs=(
            replace(original, provider="agent_sandbox"),
            original,
        )
    )
    with f.factory.begin() as db:
        db.execute(sa.update(AdmissionQuotaRecord).values(limit_units=100, consumed_units=0))
    before_calls = list(f.calls)
    recovered = f.client.post("/v1/sessions", json=body, headers=f.headers)
    assert recovered.status_code == 201, recovered.text
    assert recovered.json()["id"] == body["labels"]["omnigent.client_create_token"]
    with f.factory() as db:
        run = db.scalars(sa.select(RunRecord)).one()
        assert run.input["execution"]["model_publication"] == f.marker
        assert run.input["execution"]["launch"]["sandbox_provider"] == "kubernetes"
    fresh = {**body, "labels": {"omnigent.client_create_token": uuid4().hex}}
    stale = f.client.post("/v1/sessions", json=fresh, headers=f.headers)
    assert stale.status_code == 400, stale.text
    selected = TenantModelCatalog(f.factory.kw["bind"]).list(f.runtime)[0]
    fresh["inference_configuration_revision"] = selected["configuration_revision"]
    created = f.client.post("/v1/sessions", json=fresh, headers=f.headers)
    assert created.status_code == 201, created.text
    with f.factory() as db:
        runs = list(db.scalars(sa.select(RunRecord)))
        assert len(runs) == 2
        new_run = next(
            run
            for run in runs
            if run.input["execution"]["runtime_session_id"] == created.json()["id"]
        )
        assert new_run.input["execution"]["model_publication"]["generation"] == 2
        assert new_run.input["execution"]["launch"]["sandbox_provider"] == "agent_sandbox"
    assert f.calls == before_calls


@pytest.mark.parametrize("owned", [False, True])
def test_fixed_host_creation_freezes_canonical_workspace_after_real_owner_validation(
    interactive_http, monkeypatch, owned
):
    f = interactive_http
    body = _managed_create(f)
    host_id = uuid4().hex
    owner = f.runtime.runtime_user_key if owned else "other-runtime-user"
    host_store = f.dependencies["host_store"]
    registry = f.app.state.host_registry
    with bind_runtime_context(f.runtime):
        host_store.upsert_on_connect(
            host_id, "isolated-host", owner, configured_harnesses={"openai-agents": True}
        )
        registry.register(
            host_id=host_id,
            ws=SimpleNamespace(),
            owner=owner,
            hello=HostHelloFrame(
                version="isolated", frame_protocol_version=1, name="isolated-host"
            ),
        )
    frames = []

    def stat_reply(connection, raw):
        frame = decode_host_frame(raw)
        assert isinstance(frame, HostStatFrame), "admission must not launch a Runner"
        frames.append(frame)
        connection.pending_stats.pop(frame.request_id).set_result(
            {
                "status": "ok",
                "exists": True,
                "type": "directory",
                "canonical_path": "/canonical/workspace",
                "error": None,
            }
        )

    monkeypatch.setattr(registry, "send_text", stat_reply)
    body.update(
        host_type="external", host_id=host_id, workspace="/selected/workspace", workspaces=None
    )
    response = f.client.post("/v1/sessions", json=body, headers=f.headers)
    if not owned:
        assert response.status_code == 403, response.text
        assert frames == []
        with f.factory() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0
        return
    assert response.status_code == 201, response.text
    with f.factory() as db:
        run = db.scalars(sa.select(RunRecord)).one()
        target = run.input["execution"]["launch"]
        assert target["host_id"] == host_id and target["sandbox_provider"] is None
        assert target["workspace"] == "/canonical/workspace" and frames


@pytest.mark.parametrize(
    "change",
    [
        "host_id",
        "workspace",
        "agent_id",
        "reasoning_effort",
        "terminal_launch_args",
        "harness_override",
    ],
)
def test_message_cannot_retarget_the_accepted_launch(interactive_http, change):
    f = interactive_http
    updated = {
        "host_id": uuid4().hex,
        "agent_id": uuid4().hex,
        "workspace": "/changed",
        "reasoning_effort": "high",
        "terminal_launch_args": ["--yolo"],
        "harness_override": "openai-agents",
    }[change]
    with bind_runtime_context(f.runtime):
        if change in {"host_id", "workspace"}:
            f.delegate.set_host_id(
                f.conversation.id,
                updated if change == "host_id" else f.conversation.host_id,
                workspace=updated if change == "workspace" else f.conversation.workspace,
            )
        elif change == "agent_id":
            f.conversation = f.delegate.create_conversation(
                agent_id=updated,
                project_id=f.runtime_project_id,
                host_id=f.conversation.host_id,
                workspace=f.conversation.workspace,
                model_override=f.conversation.model_override,
                inference_snapshot=f.conversation.inference_snapshot,
            )
            f.permissions.grant(f.runtime.runtime_user_key, f.conversation.id, LEVEL_OWNER)
        else:
            f.delegate.update_conversation(f.conversation.id, **{change: updated})
    rejected = _post(f, _message())
    assert rejected.status_code == 400, rejected.text
    assert "interactive_launch_changed" in rejected.text
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0


@pytest.mark.parametrize(
    "change", ["missing_stable_id", "conflicting_model", "unpublished", "csrf", "forged_actor"]
)
def test_message_route_rejects_invalid_or_unauthorized_intent_without_a_task(
    interactive_http, change
):
    f = interactive_http
    body = _message()
    if change == "missing_stable_id":
        body["data"].pop("stable_id")
    elif change == "conflicting_model":
        body["model_override"] = "unapproved-model"
    elif change == "unpublished":
        with bind_runtime_context(f.runtime):
            snapshot = {
                **f.conversation.inference_snapshot,
                "managed_execution": {
                    **f.marker,
                    "snapshot_sha256": "0" * 64,
                },
            }
            f.conversation = f.delegate.create_conversation(
                project_id=f.runtime_project_id,
                model_override=f.marker["public_model_id"],
                inference_snapshot=snapshot,
            )
            f.permissions.grant(f.runtime.runtime_user_key, f.conversation.id, LEVEL_OWNER)
    elif change == "csrf":
        f.headers.pop("X-CSRF-Token")
    else:
        body["created_by"] = "someone-else"
    response = _post(f, body)
    if change == "csrf":
        assert response.status_code == 401, response.text
        assert response.json()["error"]["code"] == "csrf_invalid"
    else:
        assert response.status_code in {400, 403}, response.text
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0
