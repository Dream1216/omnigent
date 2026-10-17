from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from omnigent.errors import OmnigentError
from omnigent.server.app import create_app
from omnigent.server.auth import LEVEL_OWNER
from omnigent.server.schemas import SessionEventInput
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
    RuntimeResourceBindingRecord,
)
from saas.control_plane.execution_models import (
    ExecutionSessionRecord,
    QuotaReservationRecord,
    RunRecord,
    TaskRecord,
)
from saas.control_plane.interactive_execution import RuntimeSessionRunAdmission
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord
from saas.production.interactive_execution import InteractiveConversationStore
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
def interactive_http(db_uri, tmp_path, monkeypatch):
    monkeypatch.setenv("OMNIGENT_WS_ALLOWED_ORIGINS", "http://testserver")
    base, scope = _build_fastapi_app()
    engine = base.state.saas_test_engine
    factory = base.state.saas_test_sessions
    monkeypatch.setattr(
        test_model_projection, "_fixture", lambda: _connections_fixture(engine=engine)
    )
    service, worker, _, actor, command, calls = _publication_fixture()
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
    permissions = SqlAlchemyPermissionStore(db_uri)
    projects = SqlAlchemyProjectStore(db_uri)
    admission = RuntimeSessionRunAdmission(
        factory, revisions=ExecutionRevisionSet("candidate", "upstream", "c4d5e6f7a8b9", "0.2.0")
    )
    delegate = dependencies["conversation_store"]
    store = InteractiveConversationStore(delegate, admission)
    with bind_runtime_context(runtime):
        projects.create(runtime_project_id, "Interactive project", runtime.runtime_user_key)
        conversation = delegate.create_conversation(
            project_id=runtime_project_id,
            model_override=marker["public_model_id"],
            inference_snapshot={
                "runtime_config": {},
                "harness": "codex",
                "managed_execution": marker,
            },
        )
        permissions.grant(runtime.runtime_user_key, conversation.id, LEVEL_OWNER)
    dependencies["conversation_store"] = store
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


def _post(f, body):
    return f.client.post(f"/v1/sessions/{f.conversation.id}/events", json=body, headers=f.headers)


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


@pytest.mark.parametrize("recover_failed_admission", [None, "quota", "actor"])
def test_new_session_initial_items_uses_the_same_admission_contract(
    interactive_http, monkeypatch, recover_failed_admission
):
    f = interactive_http
    agent_id = uuid4().hex
    bundle_path = f"{agent_id}/bundle"
    with bind_runtime_context(f.runtime):
        f.dependencies["agent_store"].create(agent_id, "interactive-agent", bundle_path)
    f.dependencies["artifact_store"].put(
        bundle_path,
        build_agent_bundle(
            name="interactive-agent",
            executor={"type": "omnigent", "config": {"harness": "codex"}},
            include_llm=False,
        ),
    )
    original_create = f.delegate.create_conversation

    def seed_marked_session(**kwargs):
        # Seed trusted server configuration; production model selection is not enabled.
        kwargs["inference_snapshot"] = f.conversation.inference_snapshot
        kwargs["model_override"] = f.marker["public_model_id"]
        return original_create(**kwargs)

    monkeypatch.setattr(f.delegate, "create_conversation", seed_marked_session)
    before_calls = list(f.calls)
    body = {
        "agent_id": agent_id,
        "project_id": f.runtime_project_id,
        "initial_items": [_message()],
        "labels": {"omnigent.client_create_token": uuid4().hex},
    }
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
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 1
    with bind_runtime_context(f.runtime):
        assert f.delegate.get_conversation(session_id).runner_id is None
        assert f.delegate.list_items(session_id).data == []
    assert f.calls == before_calls


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
