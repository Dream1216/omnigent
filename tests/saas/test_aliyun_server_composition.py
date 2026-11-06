from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import click
import httpx
import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from omnigent.debug_logging import runner_log_scope
from saas.compatibility.runtime_partition import bind_runtime_context
from saas.control_plane.db_models import ProjectMembershipRecord, ProjectRecord
from saas.control_plane.http_auth import SaasAuthContextMiddleware
from saas.production import server as server_module
from saas.production.server import (
    ProductionServerCompositionError,
    RoleSessionFactories,
    build_production_server,
)
from saas.production.tenant_sandbox import parse_tenant_sandbox_config
from tests.saas.test_aliyun_model_broker import broker_case as broker_case
from tests.saas.test_aliyun_sandbox import cloud as cloud
from tests.saas.test_aliyun_server_profile import _enable_artifacts, _enable_storage
from tests.saas.test_aliyun_server_profile import profile_case as profile_case
from tests.saas.test_aliyun_storage_admission import _binding, _project
from tests.saas.test_control_plane_resolver import COMPATIBILITY_POLICY
from tests.saas.test_control_plane_resolver import control_plane as control_plane
from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login
from tests.saas.test_production_server import (
    _config,
    _fake_official_app,
    _official,
    _reviewed_production_sandbox_config,
)


def _sessions(app=None):
    engines = tuple(
        sa.create_engine(
            "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
        )
        for _ in range(5)
    )
    return RoleSessionFactories(
        runtime_engine=engines[0],
        authenticator=sessionmaker(engines[1], expire_on_commit=False),
        app=app if app is not None else sessionmaker(engines[2], expire_on_commit=False),
        governance=sessionmaker(engines[3], expire_on_commit=False),
        public_api=sessionmaker(engines[4], expire_on_commit=False),
        _engines=engines,
    )


@pytest.fixture
def composition_case(broker_case, profile_case, tmp_path, monkeypatch, request):
    c, p = broker_case, profile_case
    p.document["tenants"][0].update(
        {
            "tenant_id": str(c.runtime.tenant_id),
            "workspace_id": c.runtime.physical_workspace_id,
        }
    )
    c.model_requests = []
    c.volume_requests = []
    c.volumes = {}
    if getattr(request, "param", None) in {"storage", "artifacts"}:
        from saas.production import aliyun_volume_control as control_module

        _enable_storage(p)
        if getattr(request, "param", None) == "artifacts":
            _enable_artifacts(p)
        original_control = control_module.AliyunVolumeControlClient

        def volume_api(api_request):
            c.volume_requests.append(api_request)
            if api_request.method == "POST":
                volume = {
                    **json.loads(api_request.content),
                    "volumeID": str(uuid4()),
                    "storageClass": "OSS",
                    "status": "AVAILABLE",
                }
                c.volumes[volume["volumeName"]] = volume
                return httpx.Response(200, json={"volume": volume})
            name = api_request.url.params["volumeName"]
            return httpx.Response(
                200, json={"volumes": [c.volumes[name]] if name in c.volumes else []}
            )

        monkeypatch.setattr(
            control_module,
            "AliyunVolumeControlClient",
            lambda **kwargs: original_control(
                **kwargs,
                client_factory=lambda: httpx.Client(transport=httpx.MockTransport(volume_api)),
            ),
        )
    if getattr(request, "param", None) == "ingress":
        from saas.production import aliyun_model_ingress as ingress_module

        p.document["model_gateway_url"] = f"{p.document['server_origin']}/saas/models/v1"
        original = ingress_module.AliyunModelIngress

        def upstream(model_request):
            c.model_requests.append(model_request)
            return httpx.Response(
                200,
                headers={"Content-Type": "text/event-stream"},
                stream=httpx.ByteStream(b"data: complete\n\n"),
            )

        monkeypatch.setattr(
            ingress_module,
            "AliyunModelIngress",
            lambda authorities: original(
                authorities,
                client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
            ),
        )
    p.save()
    profile = p.load()
    assert profile is not None
    config = replace(
        _config(tmp_path),
        runtime_version=next(iter(COMPATIBILITY_POLICY.allowed_runtime_versions)),
        upstream_revision=next(iter(COMPATIBILITY_POLICY.allowed_source_revisions)),
        official_schema_revision=next(iter(COMPATIBILITY_POLICY.allowed_schema_revisions)),
        aliyun_profile=profile,
    )
    official = replace(
        _official(),
        host_store=c.hosts,
        conversation_store=c.conversations,
        permission_store=c.permissions,
        sandbox_config=parse_tenant_sandbox_config(
            _reviewed_production_sandbox_config(), aliyun=profile.managed
        ),
    )
    monkeypatch.setattr(server_module, "create_omnigent_saas_app", _fake_official_app)
    sessions = _sessions(c.factory)
    built = build_production_server(config, sessions, official=official)
    c.built, c.config, c.profile, c.official = built, config, profile, official
    c.path = f"/v1/hosts/{c.host_id}/sessions/{c.session_id}/model-token"
    c.headers = {
        "X-Omnigent-Host-Token": c.token,
        "X-Omnigent-Model-Lease": c.lease,
        "X-Omnigent-Workspace-Id": str(c.runtime.physical_workspace_id),
    }
    yield c
    built.close()


def test_server_composition_mounts_scoped_broker_and_preserves_authentication(composition_case):
    c = composition_case
    middleware = next(m for m in c.built.app.user_middleware if m.cls is SaasAuthContextMiddleware)
    assert middleware.kwargs["host_model_broker_enabled"] is True
    assert middleware.kwargs["aliyun_model_ingress_enabled"] is False
    with TestClient(c.built.app, base_url=c.config.public_origin) as client:
        result = client.post(c.path, headers=c.headers)
        assert result.status_code == 200
        assert result.headers["cache-control"] == "no-store"
        assert c.authority.validate(result.json()["token"]).session_id == c.session_id
        assert client.post(c.path).status_code == 401
        assert client.get(c.path, headers=c.headers).status_code == 403
        assert (
            client.post(c.path, headers={**c.headers, "Authorization": "Bearer mixed"}).status_code
            == 403
        )
        denied = client.post(c.path, headers={**c.headers, "X-Omnigent-Workspace-Id": "92"})
        assert denied.status_code == 403


@pytest.mark.parametrize("composition_case", ["artifacts"], indirect=True)
def test_actual_server_mounts_output_routes_only_with_explicit_reader_authority(composition_case):
    c = composition_case
    path = f"/v1/sessions/{c.session_id.hex}/artifacts"
    routes = {getattr(route, "path", "") for route in c.built.app.routes}
    assert "/v1/sessions/{session_id}/artifacts/content" in routes
    assert "/v1/sessions/{session_id}/artifacts/availability" in routes
    with TestClient(c.built.app, base_url=c.config.public_origin) as client:
        assert client.get(path + "/availability").status_code == 401
        assert client.get(path, headers=c.headers).status_code == 403
    assert c.volume_requests == []


def test_older_profile_does_not_mount_output_reader_routes(composition_case):
    routes = {getattr(route, "path", "") for route in composition_case.built.app.routes}
    assert "/v1/sessions/{session_id}/artifacts/content" not in routes


@pytest.mark.parametrize("composition_case", ["artifacts"], indirect=True)
def test_storage_is_wired_into_the_actual_server_managed_launcher(composition_case, monkeypatch):
    c = composition_case
    sdk = Mock()
    sdk.create.return_value.sandbox_id = "sbx-composed-storage"
    monkeypatch.setattr("e2b.Sandbox", sdk)
    entry = next(e for e in c.built.official.sandbox_config.configs if e.provider == "e2b")
    with bind_runtime_context(c.runtime), runner_log_scope(c.session_id.hex, None):
        first = entry.launcher_factory()
        assert first.provision("managed-storage") == "sbx-composed-storage"
        values = sdk.create.call_args.kwargs
        assert values["metadata"]["omnigent-storage-session"] == str(c.session_id)
        assert set(values["volume_mounts"]) == {
            "/home/user/workspace/inputs",
            "/home/user/workspace/artifacts",
        }
        assert len(c.volumes) == 2
        assert all(len(v["ossVolumeConfig"]["bucketPath"]) <= 128 for v in c.volumes.values())
        assert sorted(v["ossVolumeConfig"]["readOnly"] for v in c.volumes.values()) == [
            False,
            True,
        ]
        assert entry.launcher_factory().provision("managed-rebuild") == "sbx-composed-storage"
        assert sum(r.method == "POST" for r in c.volume_requests) == 2
        c.permissions.revoke(c.runtime.runtime_user_key, c.session_id.hex)
        with pytest.raises(ValueError):
            entry.launcher_factory().provision("managed-after-revoke")
    assert sdk.create.call_count == 2


@pytest.mark.parametrize("composition_case", ["storage"], indirect=True)
def test_composed_storage_requires_session_admission_before_any_cloud_call(
    composition_case, monkeypatch
):
    c = composition_case
    sdk = Mock()
    monkeypatch.setattr("e2b.Sandbox", sdk)
    entry = next(e for e in c.built.official.sandbox_config.configs if e.provider == "e2b")
    with bind_runtime_context(c.runtime), pytest.raises(ValueError):
        entry.launcher_factory().provision("managed-no-session")
    assert c.volume_requests == []
    sdk.create.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("composition_case", ["artifacts"], indirect=True)
async def test_real_managed_launch_failure_recycles_vm_and_host_but_retains_volumes(
    composition_case, monkeypatch
):
    from omnigent.server.managed_hosts import launch_managed_host
    from saas.production.aliyun_sandbox import AliyunSandboxLauncher

    c = composition_case
    sdk = Mock()
    sdk.create.return_value.sandbox_id = "sbx-failed-storage-start"
    monkeypatch.setattr("e2b.Sandbox", sdk)

    def fail_start(self, sandbox_id, **kwargs):
        raise click.ClickException("forced storage Host startup failure")

    cleanup = Mock()
    monkeypatch.setattr(AliyunSandboxLauncher, "start_host", fail_start)
    monkeypatch.setattr(AliyunSandboxLauncher, "terminate", cleanup)
    with bind_runtime_context(c.runtime), runner_log_scope(c.session_id.hex, None):
        before = {h.host_id for h in c.hosts.list_hosts(c.runtime.runtime_user_key)}
        with pytest.raises(HTTPException) as raised:
            await launch_managed_host(
                config=c.built.official.sandbox_config,
                owner=c.runtime.runtime_user_key,
                host_store=c.hosts,
                provider="e2b",
            )
        assert raised.value.status_code == 502
        assert {h.host_id for h in c.hosts.list_hosts(c.runtime.runtime_user_key)} == before
    cleanup.assert_called_once_with("sbx-failed-storage-start")
    assert len(c.volumes) == 2
    assert {request.method for request in c.volume_requests} == {"GET", "POST"}


@pytest.mark.parametrize("revocation", ["project", "membership"])
def test_project_rights_are_rechecked_by_the_production_composed_broker(
    composition_case, revocation
):
    c = composition_case
    project, native = _project(c), uuid4()
    _binding(
        c,
        resource_type="project",
        runtime_resource_id=native.hex,
        saas_resource_id=project,
        project_id=project,
    )
    with bind_runtime_context(c.runtime):
        c.conversations.set_conversation_project(c.session_id.hex, native.hex)
    with TestClient(c.built.app, base_url=c.config.public_origin) as client:
        assert client.post(c.path, headers=c.headers).status_code == 200
        with c.factory.begin() as db:
            if revocation == "project":
                row = db.get(ProjectRecord, project)
                assert row is not None
                row.status = "suspended"
            else:
                membership = db.get(ProjectMembershipRecord, (project, "user", c.runtime.actor_id))
                assert membership is not None
                membership.status = "revoked"
        assert client.post(c.path, headers=c.headers).status_code == 403


@pytest.mark.parametrize("composition_case", [None, "artifacts"], indirect=True)
@pytest.mark.parametrize("revocation", ["membership", "binding", "unmapped"])
def test_composed_launch_resolves_native_project_before_cloud_creation(
    composition_case, monkeypatch, revocation
):
    from saas.control_plane.db_models import RuntimeResourceBindingRecord

    c = composition_case
    project, native = _project(c), uuid4()
    binding = _binding(
        c,
        resource_type="project",
        runtime_resource_id=native.hex,
        saas_resource_id=project,
        project_id=project,
    )
    sdk = Mock()
    sdk.create.return_value.sandbox_id = "sbx-project-admitted"
    monkeypatch.setattr("e2b.Sandbox", sdk)
    entry = c.built.official.sandbox_config.for_provider("e2b")
    with bind_runtime_context(c.runtime), runner_log_scope(c.session_id.hex, None):
        c.conversations.set_conversation_project(c.session_id.hex, native.hex)
        launcher = entry.launcher_factory()
        assert launcher.provision("managed-project") == "sbx-project-admitted"
        assert launcher._execution_runtime().project_id == project
        before = len(c.volume_requests)
        with c.factory.begin() as db:
            if revocation == "membership":
                row = db.get(ProjectMembershipRecord, (project, "user", c.runtime.actor_id))
                row.status = "revoked"
            else:
                row = db.get(RuntimeResourceBindingRecord, binding)
                if revocation == "binding":
                    row.status = "retired"
                else:
                    db.delete(row)
        with pytest.raises(ValueError):
            launcher.provision("managed-project-revoked")
    assert sdk.create.call_count == 1
    assert len(c.volume_requests) == before


def test_cookie_native_session_create_carries_trusted_project_into_host_lease(
    cloud, db_uri, tmp_path, monkeypatch
):
    import asyncio
    import threading
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from uuid import UUID

    from omnigent.db.db_models import workspace_scope
    from omnigent.db.utils import make_named_managed_session_maker
    from omnigent.onboarding.sandboxes.base import RemoteCommandResult
    from omnigent.runtime.agent_cache import AgentCache
    from omnigent.server import managed_hosts
    from omnigent.server.routes import sessions as native_sessions
    from omnigent.server.routes._sessions import orchestration
    from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
    from omnigent.stores.artifact_store.local import LocalArtifactStore
    from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
    from omnigent.stores.host_store import HostStore
    from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore
    from omnigent.stores.project_store.sqlalchemy_store import SqlAlchemyProjectStore
    from saas.production.aliyun_model_lease import HostModelLeaseAuthority
    from saas.production.aliyun_sandbox import AliyunSandboxLauncher, AliyunSandboxScope
    from saas.production.aliyun_storage_admission import AliyunStorageSessionAuthorizer
    from saas.production.aliyun_tenant_sandbox import (
        AliyunManagedSandbox,
        build_aliyun_managed_config,
    )
    from tests.server.helpers import build_agent_bundle

    app, ids = _build_fastapi_app(trusted_origin="http://localhost")
    integration = app.state.saas_test_integration
    resolver = integration.context_resolver
    runtime = resolver.resolve_space_allocation(
        resolver.resolve_request_context(
            actor_id=UUID(ids["user_id"]),
            tenant_id=UUID(ids["tenant_id"]),
            space_id=UUID(ids["space_id"]),
            trace_id="cookie-managed-test",
        )
    )
    conversations = SqlAlchemyConversationStore(db_uri)
    permissions, projects = SqlAlchemyPermissionStore(db_uri), SqlAlchemyProjectStore(db_uri)
    agents, hosts = SqlAlchemyAgentStore(db_uri), HostStore(db_uri)
    artifacts = LocalArtifactStore(str(tmp_path / "artifacts"))
    cache = AgentCache(artifact_store=artifacts, cache_dir=tmp_path / "cache")
    native, agent = uuid4().hex, uuid4().hex
    with workspace_scope(runtime.physical_workspace_id):
        permissions.ensure_user(runtime.runtime_user_key)
        projects.create(native, "Native managed Project", runtime.runtime_user_key)
        agents.create(agent, "cookie-managed-agent", agent + "/bundle")
        artifacts.put(agent + "/bundle", build_agent_bundle(name="cookie-managed-agent"))
    c = SimpleNamespace(factory=app.state.saas_test_sessions, runtime=runtime, session_id=uuid4())
    logical = _project(c)
    _binding(
        c,
        resource_type="project",
        runtime_resource_id=native,
        saas_resource_id=logical,
        project_id=logical,
    )
    authorizer = AliyunStorageSessionAuthorizer(
        sessions=make_named_managed_session_maker(
            c.factory.kw["bind"], query_name_prefix="test.cookie_managed"
        ),
        resolver=resolver,
        conversations=conversations,
        permissions=permissions,
    )
    leases = HostModelLeaseAuthority(b"l" * 32)
    scope = AliyunSandboxScope(runtime.tenant_id, runtime.physical_workspace_id)
    cloud.info.metadata.update(scope.metadata())
    config = build_aliyun_managed_config(
        AliyunManagedSandbox(
            "host-template",
            cloud.key,
            "https://control.invalid",
            "https://control.invalid/platform-model/v1",
            (scope,),
            leases,
        ),
        host_config=None,
        authorize_execution=authorizer.current_execution,
    )
    app.state.sandbox_config = managed_hosts.ManagedSandboxDeployment(configs=(config,))
    app.state.host_store = hosts
    app.state.managed_launches = managed_hosts.ManagedLaunchTracker()
    app.include_router(
        native_sessions.create_sessions_router(
            conversation_store=conversations,
            agent_store=agents,
            auth_provider=integration.auth_provider,
            permission_store=permissions,
            project_store=projects,
            agent_cache=cache,
            artifact_store=artifacts,
        ),
        prefix="/v1",
    )
    monkeypatch.setattr(
        AliyunSandboxLauncher,
        "run",
        lambda self, sandbox_id, command, **kwargs: RemoteCommandResult(
            0, "/home/user" if "$HOME" in command else "", ""
        ),
    )
    monkeypatch.setattr(AliyunSandboxLauncher, "run_background", Mock())
    monkeypatch.setattr(managed_hosts, "_wait_for_host_online", AsyncMock())
    completed = threading.Event()

    async def finish(**kwargs):
        kwargs["tracker"].finish(kwargs["session_id"])
        completed.set()

    monkeypatch.setattr(orchestration, "_bind_and_launch_managed_runner", finish)
    with TestClient(app, base_url="http://localhost") as client:
        csrf = _login(client)
        response = client.post(
            "/v1/sessions",
            json={
                "agent_id": agent,
                "project_id": native,
                "host_type": "managed",
                "sandbox_provider": "e2b",
            },
            headers={"Origin": "http://localhost", "X-CSRF-Token": csrf},
        )
        assert response.status_code == 201, response.text
        assert completed.wait(10)
        with c.factory.begin() as db:
            db.get(ProjectRecord, logical).status = "suspended"
        revoked = client.post(
            "/v1/sessions",
            json={
                "agent_id": agent,
                "project_id": native,
                "host_type": "managed",
                "sandbox_provider": "e2b",
            },
            headers={"Origin": "http://localhost", "X-CSRF-Token": csrf},
        )
        assert revoked.status_code == 201, revoked.text

        async def wait_for_denial():
            launch = app.state.managed_launches.get(revoked.json()["id"])
            assert launch is not None
            await asyncio.wait_for(launch.settled.wait(), timeout=10)
            return launch.error

        assert client.portal.call(wait_for_denial)
    writes = cloud.handle.files.write.call_args_list
    assert len(writes) == 2
    with workspace_scope(runtime.physical_workspace_id):
        host = hosts.list_hosts(runtime.runtime_user_key)[0]
        conversation = conversations.get_conversation(response.json()["id"])
    admitted = leases.verify(
        writes[1].args[1],
        host_id=host.host_id,
        launch_token=writes[0].args[1],
        now=int(cloud.clock.now.timestamp()),
    )
    assert runtime.project_id is None
    assert admitted.runtime.project_id == logical
    assert conversation.project_id == native and logical.hex != native
    assert cloud.sdk.create.call_count == 1


def test_fresh_server_composition_accepts_existing_lease_and_current_revocation(composition_case):
    c = composition_case
    sessions = _sessions(c.factory)
    restarted = build_production_server(c.config, sessions, official=c.official)
    try:
        with TestClient(restarted.app, base_url=c.config.public_origin) as client:
            assert client.post(c.path, headers=c.headers).status_code == 200
            from omnigent.db.db_models import workspace_scope

            with workspace_scope(c.runtime.physical_workspace_id):
                c.hosts.revoke_launch_token(c.host_id)
            assert client.post(c.path, headers=c.headers).status_code == 403
    finally:
        restarted.close()


def test_profile_cannot_enable_broker_without_its_managed_provider(composition_case):
    c = composition_case
    sessions = _sessions(c.factory)
    try:
        with pytest.raises(
            ProductionServerCompositionError, match="requires its managed provider"
        ):
            build_production_server(
                c.config, sessions, official=replace(c.official, sandbox_config=None)
            )
    finally:
        sessions.close()


def test_default_server_keeps_broker_and_aliyun_provider_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(server_module, "create_omnigent_saas_app", _fake_official_app)
    built = build_production_server(_config(tmp_path), _sessions(), official=_official())
    try:
        middleware = next(
            m for m in built.app.user_middleware if m.cls is SaasAuthContextMiddleware
        )
        assert middleware.kwargs["host_model_broker_enabled"] is False
        assert middleware.kwargs["aliyun_model_ingress_enabled"] is False
        assert not any("model-token" in getattr(route, "path", "") for route in built.app.routes)
        assert not any("/models/v1/" in getattr(route, "path", "") for route in built.app.routes)
    finally:
        built.close()


@pytest.mark.parametrize("composition_case", ["ingress"], indirect=True)
def test_same_origin_ingress_uses_model_auth_and_rejects_mixed_credentials(composition_case):
    c = composition_case
    middleware = next(m for m in c.built.app.user_middleware if m.cls is SaasAuthContextMiddleware)
    assert middleware.kwargs["aliyun_model_ingress_enabled"] is True
    path = "/saas/models/v1/responses"
    with TestClient(c.built.app, base_url=c.config.public_origin) as client:
        issued = client.post(c.path, headers=c.headers)
        assert issued.status_code == 200
        authorization = {"Authorization": f"Bearer {issued.json()['token']}"}
        result = client.post(path, headers=authorization, json={"model": "allowed"})
        assert result.status_code == 200
        assert result.content == b"data: complete\n\n"
        assert len(c.model_requests) == 1
        assert client.post(path, json={}).status_code == 401
        assert (
            client.post(path, headers={**authorization, "Cookie": "bad=user"}, json={}).status_code
            == 401
        )
        assert (
            client.post(path, headers={**authorization, **c.headers}, json={}).status_code == 403
        )
        assert client.get(path, headers=authorization).status_code != 200
        assert (
            client.post("/saas/models/v1/files", headers=authorization, json={}).status_code != 200
        )
        assert len(c.model_requests) == 1
