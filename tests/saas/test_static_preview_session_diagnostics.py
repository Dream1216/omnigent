"""Real Cookie/project authority behind the static preview recovery messages."""

from contextlib import contextmanager
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from saas.control_plane import (
    ProjectAdministrationService,
    ProjectAuthorizer,
    RuntimeCompatibilityPolicy,
    SqlAlchemyContextResolver,
)
from saas.control_plane.execution_models import ExecutionSessionRecord
from saas.delivery.client import DeliveryClient, DeliveryConfig, DeliveryProject
from saas.delivery.http import create_delivery_router
from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login


@contextmanager
def session_fixture(*, configured=True):
    app, scope = _build_fastapi_app()
    sessions = app.state.saas_test_sessions
    resolver = SqlAlchemyContextResolver(
        sessions,
        RuntimeCompatibilityPolicy(
            runtime_type="omnigent",
            allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
            allowed_source_revisions=frozenset({"15dd7becff2bda8ee2b9afd5d16abc4feafb9552"}),
            allowed_schema_revisions=frozenset({"c4d5e6f7a8b9"}),
            adapter_contract_version="0.2.0",
        ),
    )
    current = resolver.resolve_request_context(
        actor_id=UUID(scope["user_id"]),
        tenant_id=UUID(scope["tenant_id"]),
        space_id=UUID(scope["space_id"]),
        trace_id="static-preview-diagnostics",
    )
    project = ProjectAdministrationService(sessions, ProjectAuthorizer(sessions)).create_project(
        current,
        name="Private preview project",
        visibility="private",
        idempotency_key="static-preview-diagnostics-project",
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    delivery = DeliveryClient(
        DeliveryConfig(
            endpoint="https://dcp.test",
            issuer="https://app.test/saas/delivery",
            key_id="fixture",
            private_key=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            projects=(
                DeliveryProject(
                    current.tenant_id,
                    current.space_id,
                    project.project_id,
                    "Private preview project",
                    "preview",
                    "production",
                ),
            ),
        )
    )
    app.include_router(
        create_delivery_router(
            auth=app.state.saas_test_auth,
            resolver=resolver,
            sessions=sessions,
            client=delivery if configured else None,
            preview_enabled=True,
        ),
        prefix="/saas",
    )
    with TestClient(app) as client:
        _login(client)
        try:
            yield client, app, sessions, current, project
        finally:
            app.state.saas_test_engine.dispose()


def test_missing_binding_no_completed_run_and_permission_denial_have_distinct_hints():
    with session_fixture() as (client, app, sessions, current, project):
        session_id = uuid4()
        path = f"/saas/delivery/sessions/{session_id}"
        missing = client.get(path)
        assert missing.status_code == 200 and missing.json()["runs"] == []
        assert missing.json()["diagnostic_code"] == "preview_project_binding_missing"
        assert "完成绑定" in missing.json()["diagnostic_message"]
        with sessions.begin() as db:
            db.add(
                ExecutionSessionRecord(
                    id=session_id,
                    tenant_id=current.tenant_id,
                    space_id=current.space_id,
                    project_id=project.project_id,
                    created_by=current.actor_id,
                )
            )
        pending = client.get(path)
        assert pending.status_code == 200 and pending.json()["runs"] == []
        assert pending.json()["diagnostic_code"] == "preview_source_unavailable"
        assert "生成构建产物" in pending.json()["diagnostic_message"]
        with TestClient(app) as member:
            login = member.post(
                "/saas/auth/login",
                json={
                    "email": "member@example.com",
                    "password": "initial-member-password",
                },
            )
            assert login.status_code == 200
            denied = member.get(path)
            assert denied.status_code == 200 and denied.json()["runs"] == []
            assert denied.json()["diagnostic_code"] == "preview_scope_unavailable"
            assert "项目管理员" in denied.json()["diagnostic_message"]
            assert str(project.project_id) not in denied.text
        with TestClient(app) as anonymous:
            assert anonymous.get(path).status_code == 401


def test_unconfigured_delivery_has_an_operator_action():
    with session_fixture(configured=False) as (client, *_):
        response = client.get(f"/saas/delivery/sessions/{uuid4()}")
        assert response.json()["diagnostic_code"] == "delivery_not_configured"
        assert "发布服务尚未配置" in response.json()["diagnostic_message"]


def test_required_static_browser_cannot_be_marked_skipped(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from tests.saas import conftest

    monkeypatch.setenv("OMNIGENT_SAAS_REQUIRE_STATIC_PREVIEW_BROWSER", "1")
    monkeypatch.setattr(conftest, "_chromium_is_installed", lambda: False)
    item = SimpleNamespace(path=tmp_path / "test_static_preview_control_browser.py")
    with pytest.raises(pytest.UsageError, match="required static preview Chromium"):
        conftest.pytest_collection_modifyitems([item])
