from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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
from tests.saas.test_aliyun_server_profile import profile_case as profile_case
from tests.saas.test_control_plane_resolver import COMPATIBILITY_POLICY
from tests.saas.test_control_plane_resolver import control_plane as control_plane
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


@pytest.mark.parametrize("revocation", ["project", "membership"])
def test_project_rights_are_rechecked_by_the_production_composed_broker(
    composition_case, revocation
):
    c = composition_case
    project = uuid4()
    with c.factory.begin() as db:
        db.add(
            ProjectRecord(
                id=project,
                tenant_id=c.runtime.tenant_id,
                space_id=c.runtime.space_id,
                name="Model admission",
                visibility="restricted",
                created_by=c.runtime.actor_id,
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=c.runtime.tenant_id,
                space_id=c.runtime.space_id,
                project_id=project,
                subject_type="user",
                subject_id=c.runtime.actor_id,
                role="edit",
                status="active",
                created_by=c.runtime.actor_id,
                version=1,
            )
        )
    lease = c.profile.managed.model_leases.issue(
        host_id=c.host_id,
        launch_token=c.token,
        runtime=replace(c.runtime, project_id=project),
        ttl_seconds=5400,
    )
    headers = {**c.headers, "X-Omnigent-Model-Lease": lease}
    with TestClient(c.built.app, base_url=c.config.public_origin) as client:
        assert client.post(c.path, headers=headers).status_code == 200
        with c.factory.begin() as db:
            if revocation == "project":
                row = db.get(ProjectRecord, project)
                assert row is not None
                row.status = "suspended"
            else:
                membership = db.get(ProjectMembershipRecord, (project, "user", c.runtime.actor_id))
                assert membership is not None
                membership.status = "revoked"
        assert client.post(c.path, headers=headers).status_code == 403


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
