from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.db_models import (
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    Space,
    SpaceMembership,
)
from saas.control_plane.lifecycle import MembershipLifecycleService
from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login


def _two_scopes():
    app, scope = _build_fastapi_app()
    sessions = app.state.saas_test_sessions
    space_id, partition_id = uuid4(), uuid4()
    with sessions.begin() as db:
        original = db.get(RuntimePartitionRecord, UUID(scope["partition_id"]))
        assert original is not None
        db.add(
            Space(
                id=space_id,
                tenant_id=UUID(scope["tenant_id"]),
                name="Second workspace",
                slug="second",
                status="active",
            )
        )
        db.flush()
        db.add(
            SpaceMembership(
                tenant_id=UUID(scope["tenant_id"]),
                space_id=space_id,
                user_id=UUID(scope["user_id"]),
                role="owner",
                status="active",
                version=1,
            )
        )
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=original.tenant_id,
                space_id=space_id,
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
        db.add(
            RuntimeIdentityAliasRecord(
                runtime_partition_id=partition_id,
                user_id=UUID(scope["user_id"]),
                runtime_user_key="selected-workspace-user",
                status="active",
            )
        )
    return app, scope, space_id


def test_cookie_workspace_choice_routes_http_websocket_and_rechecks_live_membership():
    app, scope, second = _two_scopes()
    with TestClient(app) as client:
        csrf = _login(client)
        assert client.get("/saas/auth/bootstrap").json()["next"] == "/setup"
        assert client.get("/v1/protected").status_code == 403
        selected = client.post(
            "/saas/auth/active-scope",
            json={
                "tenant_id": scope["tenant_id"],
                "space_id": str(second),
            },
            headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        )
        assert selected.status_code == 204
        assert selected.headers["cache-control"] == "private, no-store"
        assert client.get("/saas/auth/bootstrap").json()["next"] == "/"
        assert client.get("/v1/protected").json()["workspace_id"] == 42
        with client.websocket_connect("/v1/ws", headers={"Origin": "http://testserver"}) as ws:
            assert ws.receive_json()["workspace_id"] == 42
        explicit = client.get(
            "/v1/protected",
            headers={
                "X-SaaS-Tenant-Id": scope["tenant_id"],
                "X-SaaS-Space-Id": scope["space_id"],
            },
        )
        assert explicit.json()["workspace_id"] == 41
        assert client.get("/v1/protected").json()["workspace_id"] == 42
        with app.state.saas_test_sessions.begin() as db:
            db.execute(
                sa.update(SpaceMembership)
                .where(
                    SpaceMembership.space_id == second,
                    SpaceMembership.user_id == UUID(scope["user_id"]),
                )
                .values(status="removed", version=2)
            )
        assert client.get("/v1/protected").status_code == 403
        assert client.get("/saas/auth/bootstrap").json()["next"] == "/setup"
        recovered = client.post(
            "/saas/auth/active-scope",
            json={
                "tenant_id": scope["tenant_id"],
                "space_id": scope["space_id"],
            },
            headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        )
        assert recovered.status_code == 204
        assert client.get("/v1/protected").json()["workspace_id"] == 41


def test_workspace_choice_rejects_missing_csrf_forged_scope_and_client_actor():
    app, scope, second = _two_scopes()
    with TestClient(app) as client:
        csrf = _login(client)
        body = {"tenant_id": scope["tenant_id"], "space_id": str(second)}
        assert (
            client.post(
                "/saas/auth/active-scope", json=body, headers={"Origin": "http://testserver"}
            ).status_code
            == 401
        )
        headers = {"Origin": "http://testserver", "X-CSRF-Token": csrf}
        assert (
            client.post(
                "/saas/auth/active-scope", json={**body, "space_id": str(uuid4())}, headers=headers
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/saas/auth/active-scope",
                json={**body, "actor_id": scope["member_id"]},
                headers=headers,
            ).status_code
            == 422
        )
        assert client.get("/saas/auth/bootstrap").json()["next"] == "/setup"


def test_parent_bound_reauthentication_preserves_workspace_preference():
    app, scope, second = _two_scopes()
    with TestClient(app) as client:
        csrf = _login(client)
        response = client.post(
            "/saas/auth/active-scope",
            json={
                "tenant_id": scope["tenant_id"],
                "space_id": str(second),
            },
            headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
        )
        assert response.status_code == 204
        lifecycle = MembershipLifecycleService(app.state.saas_test_sessions)
        parent = lifecycle.validate_auth_session(client.cookies.get("saas_session"))
        issued = lifecycle.issue_auth_session(
            user_id=parent.user_id,
            authn_method="password",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            required_parent_session_id=parent.session_id,
        )
        child = lifecycle.validate_auth_session(issued.token)
        assert child.active_tenant_id == UUID(scope["tenant_id"])
        assert child.active_space_id == second
