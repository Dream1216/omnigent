from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane.db_models import (
    GlobalUser,
    SaasBase,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.enterprise_identity import EnterpriseScimService
from saas.control_plane.enterprise_scim_http import create_enterprise_scim_router

_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def _app() -> tuple[TestClient, str, UUID, UUID]:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @sa.event.listens_for(engine, "connect")
    def _foreign_keys(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    owner_id, tenant_id, space_id = uuid4(), uuid4(), uuid4()
    with sessions.begin() as db:
        db.add_all(
            [
                GlobalUser(id=owner_id, status="active", security_version=1),
                Tenant(
                    id=tenant_id,
                    slug="scim-http",
                    name="SCIM HTTP",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=owner_id,
                    role="owner",
                    status="active",
                    version=1,
                ),
                Space(
                    id=space_id,
                    tenant_id=tenant_id,
                    slug="main",
                    name="Main",
                    status="active",
                ),
            ]
        )
        db.flush()
        db.add(
            SpaceMembership(
                tenant_id=tenant_id,
                space_id=space_id,
                user_id=owner_id,
                role="owner",
                status="active",
                version=1,
            )
        )
    service = EnterpriseScimService(cast(sessionmaker[Session], sessions))
    issued = service.issue_directory(
        RequestContext(
            actor_id=owner_id,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=None,
            user_security_version=1,
            tenant_membership_version=1,
            space_membership_version=1,
            trace_id="scim-http",
        ),
        display_name="HTTP Directory",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="http-directory",
    )
    assert issued.bearer_token is not None

    class _Auth:
        @staticmethod
        def get_principal(_request: object) -> object:
            return SimpleNamespace(
                session=SimpleNamespace(
                    user_id=owner_id,
                    security_version=1,
                    authenticated_at=datetime.now(timezone.utc),
                )
            )

    class _Resolver:
        @staticmethod
        def list_available_scopes(*, actor_id: UUID) -> tuple[object, ...]:
            assert actor_id == owner_id
            return (SimpleNamespace(tenant_id=tenant_id, space_id=space_id),)

        @staticmethod
        def resolve_request_context(
            *, actor_id: UUID, tenant_id: UUID, space_id: UUID, trace_id: str
        ) -> RequestContext:
            return RequestContext(
                actor_id=actor_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=None,
                user_security_version=1,
                tenant_membership_version=1,
                space_membership_version=1,
                trace_id=trace_id,
            )

    app = FastAPI()
    app.include_router(
        create_enterprise_scim_router(
            auth_provider=cast(Any, _Auth()),
            resolver=cast(Any, _Resolver()),
            service=service,
        ),
        prefix="/saas",
    )
    return TestClient(app), issued.bearer_token, tenant_id, issued.id


def test_scim_http_etag_deprovision_and_late_group_convergence() -> None:
    client, token, _, _ = _app()
    headers = {"Authorization": f"Bearer {token}"}

    config = client.get("/saas/scim/v2/ServiceProviderConfig")
    assert config.status_code == 200
    assert config.json()["etag"]["supported"] is True

    invalid = client.post(
        "/saas/scim/v2/Users",
        headers={"Authorization": "Bearer invalid", "Idempotency-Key": "invalid-user"},
        json={
            "schemas": [_USER_SCHEMA],
            "externalId": "invalid",
            "userName": "invalid@example.test",
            "active": True,
        },
    )
    assert invalid.status_code == 401
    assert invalid.headers["content-type"].startswith("application/scim+json")
    assert invalid.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert invalid.json()["scimType"] == "scim_authentication_failed"

    user = client.post(
        "/saas/scim/v2/Users",
        headers={**headers, "Idempotency-Key": "http-user-1"},
        json={
            "schemas": [_USER_SCHEMA],
            "externalId": "employee-http",
            "userName": "Employee.HTTP@example.test",
            "displayName": "HTTP Employee",
            "active": True,
        },
    )
    assert user.status_code == 201
    assert user.headers["etag"] == 'W/"1"'
    user_id = user.json()["id"]

    group = client.post(
        "/saas/scim/v2/Groups",
        headers={**headers, "Idempotency-Key": "http-group-1"},
        json={
            "schemas": [_GROUP_SCHEMA],
            "externalId": "engineering-http",
            "displayName": "Engineering HTTP",
            "members": [{"value": user_id}],
        },
    )
    assert group.status_code == 201
    assert group.headers["etag"] == 'W/"1"'
    group_id = group.json()["id"]
    assert group.json()["members"][0]["value"] == user_id

    deprovision = client.patch(
        f"/saas/scim/v2/Users/{user_id}",
        headers={
            **headers,
            "If-Match": 'W/"1"',
            "Idempotency-Key": "http-user-2",
        },
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert deprovision.status_code == 200
    assert deprovision.headers["etag"] == 'W/"2"'
    assert deprovision.json()["active"] is False

    stale = client.patch(
        f"/saas/scim/v2/Users/{user_id}",
        headers={
            **headers,
            "If-Match": 'W/"1"',
            "Idempotency-Key": "http-user-stale",
        },
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": True}],
        },
    )
    assert stale.status_code == 412

    late_group = client.patch(
        f"/saas/scim/v2/Groups/{group_id}",
        headers={
            **headers,
            "If-Match": 'W/"1"',
            "Idempotency-Key": "http-group-2",
        },
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "members", "value": [{"value": user_id}]}],
        },
    )
    assert late_group.status_code == 200
    payload = late_group.json()
    governance = payload["urn:omnigent:params:scim:schemas:extension:governance:1.0:Group"]
    assert governance["disposition"] == "blocked"
    assert governance["blockedExternalIds"] == ["employee-http"]
    assert payload["members"] == []


def test_scim_directory_http_rotation_and_disable_destroy_old_authority() -> None:
    client, old_token, tenant_id, directory_id = _app()
    rotate_path = f"/saas/tenants/{tenant_id}/enterprise/scim-directories/{directory_id}/rotate"
    rotated = client.post(
        rotate_path,
        headers={"Idempotency-Key": "http-directory-rotate"},
        json={"expected_version": 1},
    )
    assert rotated.status_code == 201
    assert rotated.headers["cache-control"] == "no-store"
    assert rotated.json()["version"] == 2
    new_token = rotated.json()["bearer_token"]
    assert isinstance(new_token, str)
    assert new_token != old_token

    replay = client.post(
        rotate_path,
        headers={"Idempotency-Key": "http-directory-rotate"},
        json={"expected_version": 1},
    )
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True
    assert replay.json()["bearer_token"] is None

    old_denied = client.post(
        "/saas/scim/v2/Users",
        headers={
            "Authorization": f"Bearer {old_token}",
            "Idempotency-Key": "old-http-token",
        },
        json={
            "schemas": [_USER_SCHEMA],
            "externalId": "old-token-user",
            "userName": "old-token@example.test",
            "active": True,
        },
    )
    assert old_denied.status_code == 401

    disable_path = f"/saas/tenants/{tenant_id}/enterprise/scim-directories/{directory_id}/disable"
    disabled = client.post(
        disable_path,
        headers={"Idempotency-Key": "http-directory-disable"},
        json={"expected_version": 2},
    )
    assert disabled.status_code == 200
    assert disabled.headers["cache-control"] == "no-store"
    assert disabled.json()["status"] == "disabled"
    assert disabled.json()["version"] == 3

    new_denied = client.post(
        "/saas/scim/v2/Users",
        headers={
            "Authorization": f"Bearer {new_token}",
            "Idempotency-Key": "disabled-http-token",
        },
        json={
            "schemas": [_USER_SCHEMA],
            "externalId": "disabled-token-user",
            "userName": "disabled-token@example.test",
            "active": True,
        },
    )
    assert new_denied.status_code == 401
