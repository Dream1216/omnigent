from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import HTTPConnection

from saas.compatibility import RequestContext
from saas.control_plane import PreviewRouteGrant
from saas.control_plane.http_auth import SaasPrincipal
from saas.control_plane.lifecycle import ValidatedAuthSession
from saas.control_plane.preview_execution import PreviewExecutionState
from saas.control_plane.preview_sessions import PreviewBrowserSessionGrant
from saas.control_plane.resolver import ControlPlaneResolutionError
from saas.preview_gateway import (
    PREVIEW_COOKIE_NAME,
    PreviewTunnelRequest,
    PreviewTunnelResponse,
    create_preview_session_gateway_app,
)
from saas.production.preview_control import (
    ProductionPreviewControlPolicy,
    create_production_preview_control_router,
)

ACTOR_ID = UUID("10000000-0000-4000-8000-000000000001")
TENANT_ID = UUID("20000000-0000-4000-8000-000000000002")
SPACE_ID = UUID("30000000-0000-4000-8000-000000000003")
PROJECT_ID = UUID("40000000-0000-4000-8000-000000000004")
RUN_ID = UUID("60000000-0000-4000-8000-000000000006")
CHILD_RUN_ID = UUID("70000000-0000-4000-8000-000000000007")
PREVIEW_ID = UUID("90000000-0000-4000-8000-000000000009")
NOW = datetime.now(timezone.utc).replace(microsecond=0)
IDEMPOTENCY = "preview-api-idempotency-0001"


class _Auth:
    def get_principal(self, connection: HTTPConnection) -> SaasPrincipal | None:
        del connection
        return SaasPrincipal(
            session=ValidatedAuthSession(
                session_id=UUID("a0000000-0000-4000-8000-00000000000a"),
                user_id=ACTOR_ID,
                security_version=7,
                authn_method="password",
                authenticated_at=NOW,
                expires_at=NOW + timedelta(hours=1),
            ),
            runtime_context=None,
        )


class _Resolver:
    def resolve_request_context(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        trace_id: str,
    ) -> RequestContext:
        if tenant_id != TENANT_ID or space_id != SPACE_ID:
            raise ControlPlaneResolutionError("scope_not_found", "scope is unavailable")
        return RequestContext(actor_id, tenant_id, space_id, None, 7, 3, 5, trace_id)


class _Authorizer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, UUID]] = []

    def bind_project_context(
        self,
        request: RequestContext,
        *,
        action: str,
        project_id: UUID,
    ) -> RequestContext:
        self.calls.append((action, project_id))
        if project_id != PROJECT_ID:
            raise AssertionError("unexpected project")
        return replace(request, project_id=project_id)


class _Previews:
    def __init__(self) -> None:
        self.create_calls: list[dict[str, object]] = []
        self.get_calls: list[dict[str, object]] = []
        self.stop_calls: list[dict[str, object]] = []

    @staticmethod
    def _state(*, status: str, replayed: bool, url: str | None = None) -> PreviewExecutionState:
        return PreviewExecutionState(
            preview_execution_id=PREVIEW_ID,
            source_run_id=RUN_ID,
            child_run_id=CHILD_RUN_ID,
            status=status,
            preview_host="opaque.preview.example.net",
            expires_at=NOW + timedelta(hours=1),
            replayed=replayed,
            exchange_url=url,
        )

    def request_preview(self, request: RequestContext, **values) -> PreviewExecutionState:
        self.create_calls.append({"request": request, **values})
        return self._state(status="queued", replayed=False)

    def get_preview(self, request: RequestContext, **values) -> PreviewExecutionState:
        self.get_calls.append({"request": request, **values})
        return self._state(
            status="ready",
            replayed=False,
            url=(
                "https://opaque.preview.example.net/__omnigent/bootstrap"
                "#token=server-generated-one-use-token-000000000000"
            ),
        )

    def stop_preview(self, request: RequestContext, **values) -> PreviewExecutionState:
        self.stop_calls.append({"request": request, **values})
        return self._state(status="stopping", replayed=len(self.stop_calls) > 1)


def _client() -> tuple[TestClient, FastAPI, _Authorizer, _Previews]:
    authorizer = _Authorizer()
    previews = _Previews()
    app = FastAPI()
    app.include_router(
        create_production_preview_control_router(
            auth_provider=_Auth(),
            resolver=_Resolver(),
            authorizer=authorizer,
            previews=previews,
        )
    )
    return TestClient(app), app, authorizer, previews


def _path(*, tenant_id: UUID = TENANT_ID) -> str:
    return f"/tenants/{tenant_id}/spaces/{SPACE_ID}/projects/{PROJECT_ID}/previews"


def test_browser_body_is_closed_non_secret_and_ready_url_is_one_use_exchange() -> None:
    client, app, authorizer, previews = _client()
    queued = client.post(
        _path(),
        headers={"Idempotency-Key": IDEMPOTENCY},
        json={"run_id": str(RUN_ID), "preview_kind": "static_web_v1"},
    )
    assert queued.status_code == 202
    assert queued.headers["cache-control"] == "no-store"
    assert queued.headers["referrer-policy"] == "no-referrer"
    assert "url" not in queued.json()
    assert queued.json()["status"] == "queued"
    assert previews.create_calls[0]["source_run_id"] == RUN_ID
    assert previews.create_calls[0]["idempotency_key"] == IDEMPOTENCY

    ready = client.get(f"{_path()}/{PREVIEW_ID}")
    assert ready.status_code == 200
    parsed = urlsplit(ready.json()["url"])
    assert parsed.path == "/__omnigent/bootstrap"
    assert parsed.query == ""
    assert parsed.fragment == "token=server-generated-one-use-token-000000000000"
    assert "access_token" not in ready.json()
    assert authorizer.calls == [
        ("preview.open", PROJECT_ID),
        ("preview.open", PROJECT_ID),
    ]

    schema = app.openapi()
    request_schema = schema["components"]["schemas"]["PreviewOpenBody"]
    assert request_schema["additionalProperties"] is False
    assert set(request_schema["properties"]) == {"run_id", "preview_kind"}


class _BootstrapAuthority:
    def __init__(self, route: PreviewRouteGrant, token: str) -> None:
        self.route = route
        self.token = token
        self.exchange_calls: list[tuple[str, str]] = []

    def exchange(
        self,
        *,
        host: str,
        exchange_token: str,
        now: datetime | None = None,
    ) -> PreviewBrowserSessionGrant:
        del now
        self.exchange_calls.append((host, exchange_token))
        if host != self.route.preview_host or exchange_token != self.token:
            raise AssertionError("unexpected bootstrap exchange")
        return PreviewBrowserSessionGrant(
            self.route,
            "session_" + "s" * 48,
        )

    def authorize_and_rotate(
        self,
        *,
        host: str,
        session_token: str,
        incoming_headers: dict[str, str],
        now: datetime | None = None,
    ) -> PreviewBrowserSessionGrant:
        del host, session_token, incoming_headers, now
        raise AssertionError("bootstrap test must not proxy Preview content")


class _BootstrapTunnel:
    async def forward(self, request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        del request
        raise AssertionError("bootstrap test must not reach the tunnel")


def test_control_ready_fragment_bootstraps_edge_cookie_without_query_bearer() -> None:
    control, _app, _authorizer, _previews = _client()
    ready = control.get(f"{_path()}/{PREVIEW_ID}")
    location = urlsplit(ready.json()["url"])
    assert location.scheme == "https"
    assert location.query == ""
    assert location.fragment.startswith("token=")
    token = location.fragment.removeprefix("token=")
    host = location.hostname
    assert host is not None
    route = PreviewRouteGrant(
        preview_id=PREVIEW_ID,
        tenant_id=TENANT_ID,
        space_id=SPACE_ID,
        project_id=PROJECT_ID,
        runner_id=UUID("50000000-0000-4000-8000-000000000005"),
        runner_connection_generation=3,
        run_id=CHILD_RUN_ID,
        run_fence_token=7,
        worktree_id=UUID("80000000-0000-4000-8000-000000000008"),
        worktree_lease_generation=2,
        opaque_preview_key="pvr_bootstrap_test",
        preview_token_hash="a" * 64,
        upstream_request_headers={},
        response_headers={},
        expires_at=NOW + timedelta(minutes=15),
        preview_host=host,
    )
    authority = _BootstrapAuthority(route, token)
    edge = create_preview_session_gateway_app(
        authority=authority,
        tunnel=_BootstrapTunnel(),
    )
    with TestClient(
        edge,
        base_url=f"https://{host}",
        follow_redirects=False,
    ) as browser:
        bootstrap = browser.get(location.path)
        assert bootstrap.status_code == 200
        assert token not in str(bootstrap.request.url)
        assert token not in bootstrap.text
        exchange = browser.post("/__omnigent/authorize", data={"token": token})
        assert exchange.status_code == 303
        cookie = exchange.headers["set-cookie"]
        assert cookie.startswith(f"{PREVIEW_COOKIE_NAME}=session_")
        assert token not in cookie
    assert authority.exchange_calls == [(host, token)]


@pytest.mark.parametrize(
    "secret_field,secret_value",
    (
        ("runner_id", "50000000-0000-4000-8000-000000000005"),
        ("worktree_id", "70000000-0000-4000-8000-000000000007"),
        ("run_fence_token", 4),
        ("runner_connection_generation", 3),
        ("capability_token", "cap_" + "c" * 60),
        ("worktree_lease_token", "wti_" + "w" * 60),
    ),
)
def test_browser_cannot_submit_runner_or_lease_secret_fields(
    secret_field: str,
    secret_value: object,
) -> None:
    client, _app, _authorizer, previews = _client()
    body: dict[str, object] = {
        "run_id": str(RUN_ID),
        "preview_kind": "static_web_v1",
        secret_field: secret_value,
    }
    response = client.post(_path(), headers={"Idempotency-Key": IDEMPOTENCY}, json=body)
    assert response.status_code == 422
    assert previews.create_calls == []


def test_cross_tenant_is_non_disclosing_and_stop_is_idempotency_keyed() -> None:
    client, _app, authorizer, previews = _client()
    other_tenant = UUID("b0000000-0000-4000-8000-00000000000b")
    denied = client.post(
        _path(tenant_id=other_tenant),
        headers={"Idempotency-Key": IDEMPOTENCY},
        json={"run_id": str(RUN_ID)},
    )
    assert denied.status_code == 404
    assert denied.json()["detail"]["code"] == "preview_scope_unavailable"
    assert authorizer.calls == [] and previews.create_calls == []

    path = f"{_path()}/{PREVIEW_ID}"
    first = client.delete(path, headers={"Idempotency-Key": IDEMPOTENCY})
    replay = client.delete(path, headers={"Idempotency-Key": IDEMPOTENCY})
    assert first.status_code == 202 and first.json()["status"] == "stopping"
    assert replay.status_code == 202 and replay.json()["replayed"] is True
    assert all(call["idempotency_key"] == IDEMPOTENCY for call in previews.stop_calls)


def test_policy_requires_isolated_https_domain_and_explicit_exchange_key() -> None:
    with pytest.raises(ValueError, match="cookie-isolated"):
        ProductionPreviewControlPolicy.from_origins(
            primary_origin="https://next.example.test",
            preview_root_domain="preview.next.example.test",
            lease_seconds=300,
            exchange_hmac_key=b"x" * 32,
        )
    with pytest.raises(ValueError, match="HMAC key"):
        ProductionPreviewControlPolicy.from_origins(
            primary_origin="https://next.example.test",
            preview_root_domain="preview.example.net",
            lease_seconds=300,
            exchange_hmac_key=b"short",
        )
