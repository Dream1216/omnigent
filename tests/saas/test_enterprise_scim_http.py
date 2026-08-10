from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
_ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
_BULK_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
_BULK_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"


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
    assert config.json()["filter"] == {"supported": True, "maxResults": 100}
    assert config.json()["sort"] == {"supported": True}

    resource_types = client.get("/saas/scim/v2/ResourceTypes")
    assert resource_types.status_code == 200
    assert resource_types.headers["content-type"].startswith("application/scim+json")
    assert [resource["id"] for resource in resource_types.json()["Resources"]] == [
        "User",
        "Group",
    ]
    user_resource = client.get("/saas/scim/v2/ResourceTypes/User")
    assert user_resource.status_code == 200
    assert user_resource.json()["schema"] == _USER_SCHEMA
    assert user_resource.json()["schemaExtensions"][0] == {
        "schema": _ENTERPRISE_USER_SCHEMA,
        "required": False,
    }

    schemas = client.get("/saas/scim/v2/Schemas")
    assert schemas.status_code == 200
    assert schemas.json()["totalResults"] == 5
    enterprise_schema = client.get(f"/saas/scim/v2/Schemas/{_ENTERPRISE_USER_SCHEMA}")
    assert enterprise_schema.status_code == 200
    assert [attribute["name"] for attribute in enterprise_schema.json()["attributes"]] == [
        "employeeNumber",
        "costCenter",
        "organization",
        "division",
        "department",
        "manager",
    ]
    assert client.get("/saas/scim/v2/ResourceTypes/Device").status_code == 404
    assert client.get("/saas/scim/v2/Schemas/urn:example:missing").status_code == 404

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
    projected_group = client.get(
        f"/saas/scim/v2/Groups/{group_id}",
        headers=headers,
        params={"attributes": "displayName,members.value"},
    )
    assert projected_group.status_code == 200
    assert set(projected_group.json()) == {
        "schemas",
        "id",
        "meta",
        "displayName",
        "members",
    }
    assert projected_group.json()["members"] == [{"value": user_id}]

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


def test_scim_directory_http_schedules_one_time_overlap_credential() -> None:
    client, old_token, tenant_id, directory_id = _app()
    path = f"/saas/tenants/{tenant_id}/enterprise/scim-directories/{directory_id}/rotate-overlap"
    activation = datetime.now(timezone.utc) + timedelta(minutes=2)
    body = {
        "expected_version": 1,
        "activates_at": activation.isoformat(),
        "grace_period_seconds": 300,
    }
    naive = client.post(
        path,
        headers={"Idempotency-Key": "http-directory-overlap-naive"},
        json={**body, "activates_at": activation.replace(tzinfo=None).isoformat()},
    )
    assert naive.status_code == 400
    assert naive.json()["detail"]["code"] == "scim_directory_rotation_time_invalid"

    unbounded = client.post(
        path,
        headers={"Idempotency-Key": "http-directory-overlap-unbounded"},
        json={**body, "activates_at": (activation + timedelta(days=31)).isoformat()},
    )
    assert unbounded.status_code == 400
    assert unbounded.json()["detail"]["code"] == "scim_directory_rotation_time_invalid"

    invalid_grace = client.post(
        path,
        headers={"Idempotency-Key": "http-directory-overlap-grace"},
        json={**body, "grace_period_seconds": 59},
    )
    assert invalid_grace.status_code == 422

    scheduled = client.post(
        path,
        headers={"Idempotency-Key": "http-directory-overlap"},
        json=body,
    )
    assert scheduled.status_code == 201
    assert scheduled.headers["cache-control"] == "no-store"
    payload = scheduled.json()
    assert payload["version"] == 2
    successor_token = payload["bearer_token"]
    assert isinstance(successor_token, str)
    assert payload["successor_token_prefix"] == successor_token[:24]
    assert payload["rotation_activates_at"] == activation.isoformat()

    replay = client.post(
        path,
        headers={"Idempotency-Key": "http-directory-overlap"},
        json=body,
    )
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True
    assert replay.json()["bearer_token"] is None

    changed = client.post(
        path,
        headers={"Idempotency-Key": "http-directory-overlap"},
        json={**body, "grace_period_seconds": 301},
    )
    assert changed.status_code == 409
    assert changed.json()["detail"]["code"] == "idempotency_conflict"

    old_allowed = client.get(
        "/saas/scim/v2/Users?count=0",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert old_allowed.status_code == 200
    successor_early = client.get(
        "/saas/scim/v2/Users?count=0",
        headers={"Authorization": f"Bearer {successor_token}"},
    )
    assert successor_early.status_code == 401


def test_scim_collection_list_filter_and_bounded_pagination() -> None:
    client, token, _, _ = _app()
    headers = {"Authorization": f"Bearer {token}"}
    created_users: dict[str, str] = {}
    for index, external_id in enumerate(("employee-alpha", "employee-beta"), start=1):
        response = client.post(
            "/saas/scim/v2/Users",
            headers={**headers, "Idempotency-Key": f"list-user-{index}"},
            json={
                "schemas": [_USER_SCHEMA],
                "externalId": external_id,
                "userName": f"{external_id}@example.test",
                "displayName": f"Employee {index}",
                "active": index == 1,
            },
        )
        assert response.status_code == 201
        created_users[external_id] = response.json()["id"]

    first = client.get(
        "/saas/scim/v2/Users?startIndex=1&count=1",
        headers=headers,
    )
    second = client.get(
        "/saas/scim/v2/Users?startIndex=2&count=1",
        headers=headers,
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert first.json()["totalResults"] == second.json()["totalResults"] == 2
    assert first.json()["itemsPerPage"] == second.json()["itemsPerPage"] == 1
    listed_ids = {
        first.json()["Resources"][0]["id"],
        second.json()["Resources"][0]["id"],
    }
    assert listed_ids == set(created_users.values())

    filtered_user = client.get(
        '/saas/scim/v2/Users?filter=userName%20eq%20"EMPLOYEE-ALPHA@example.test"',
        headers=headers,
    )
    assert filtered_user.status_code == 200
    assert filtered_user.json()["totalResults"] == 1
    assert filtered_user.json()["Resources"][0]["externalId"] == "employee-alpha"

    ordered_user = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'displayName gt "Employee 1"'},
    )
    assert ordered_user.status_code == 200
    assert [item["externalId"] for item in ordered_user.json()["Resources"]] == ["employee-beta"]
    schema_qualified = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={
            "filter": (
                "urn:ietf:params:scim:schemas:core:2.0:User:userName "
                'le "employee-alpha@example.test"'
            )
        },
    )
    assert schema_qualified.status_code == 200
    assert [item["externalId"] for item in schema_qualified.json()["Resources"]] == [
        "employee-alpha"
    ]
    greater_or_equal = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'externalId ge "employee-beta"'},
    )
    less_than = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'externalId lt "employee-beta"'},
    )
    assert [item["externalId"] for item in greater_or_equal.json()["Resources"]] == [
        "employee-beta"
    ]
    assert [item["externalId"] for item in less_than.json()["Resources"]] == ["employee-alpha"]

    inactive = client.get(
        "/saas/scim/v2/Users?filter=active%20eq%20false&count=0",
        headers=headers,
    )
    assert inactive.status_code == 200
    assert inactive.json()["totalResults"] == 1
    assert inactive.json()["itemsPerPage"] == 0
    assert inactive.json()["Resources"] == []

    created_groups: dict[str, str] = {}
    for index, external_id in enumerate(("group-alpha", "group-beta"), start=1):
        response = client.post(
            "/saas/scim/v2/Groups",
            headers={**headers, "Idempotency-Key": f"list-group-{index}"},
            json={
                "schemas": [_GROUP_SCHEMA],
                "externalId": external_id,
                "displayName": f"Group {index}",
                "members": ([{"value": created_users["employee-alpha"]}] if index == 1 else []),
            },
        )
        assert response.status_code == 201
        created_groups[external_id] = response.json()["id"]

    groups = client.get("/saas/scim/v2/Groups?startIndex=1&count=100", headers=headers)
    assert groups.status_code == 200
    assert groups.json()["totalResults"] == 2
    assert {item["id"] for item in groups.json()["Resources"]} == set(created_groups.values())

    filtered_group = client.get(
        '/saas/scim/v2/Groups?filter=displayName%20eq%20"GROUP%202"',
        headers=headers,
    )
    assert filtered_group.status_code == 200
    assert filtered_group.json()["totalResults"] == 1
    assert filtered_group.json()["Resources"][0]["externalId"] == "group-beta"

    member_value_path = client.get(
        "/saas/scim/v2/Groups",
        headers=headers,
        params={
            "filter": (f'members[(value eq "{created_users["employee-alpha"]}") and value pr]')
        },
    )
    assert member_value_path.status_code == 200
    assert [item["externalId"] for item in member_value_path.json()["Resources"]] == [
        "group-alpha"
    ]
    direct_member_sub_attribute = client.get(
        "/saas/scim/v2/Groups",
        headers=headers,
        params={"filter": f'members.value eq "{created_users["employee-alpha"]}"'},
    )
    assert direct_member_sub_attribute.status_code == 200
    assert direct_member_sub_attribute.json()["totalResults"] == 1

    compound_users = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={
            "filter": '(active eq true and displayName sw "employee") '
            'or externalId eq "employee-beta"',
            "sortBy": "displayName",
            "sortOrder": "descending",
        },
    )
    assert compound_users.status_code == 200
    assert [item["externalId"] for item in compound_users.json()["Resources"]] == [
        "employee-beta",
        "employee-alpha",
    ]

    inactive_not = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": "not active eq true"},
    )
    assert inactive_not.status_code == 200
    assert inactive_not.json()["totalResults"] == 1
    assert inactive_not.json()["Resources"][0]["externalId"] == "employee-beta"

    contains_and_presence = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": '(displayName co "PLOYEE") and displayName pr'},
    )
    assert contains_and_presence.status_code == 200
    assert contains_and_presence.json()["totalResults"] == 2

    escaped_like_wildcard = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'displayName co "%"'},
    )
    assert escaped_like_wildcard.status_code == 200
    assert escaped_like_wildcard.json()["totalResults"] == 0

    compound_groups = client.get(
        "/saas/scim/v2/Groups",
        headers=headers,
        params={
            "filter": '(displayName sw "group") and active eq true',
            "sortBy": "externalId",
            "sortOrder": "ascending",
        },
    )
    assert compound_groups.status_code == 200
    assert [item["externalId"] for item in compound_groups.json()["Resources"]] == [
        "group-alpha",
        "group-beta",
    ]

    missing_display_name = client.post(
        "/saas/scim/v2/Users",
        headers={**headers, "Idempotency-Key": "list-user-without-display-name"},
        json={
            "schemas": [_USER_SCHEMA],
            "externalId": "employee-no-display",
            "userName": "employee-no-display@example.test",
            "active": True,
        },
    )
    assert missing_display_name.status_code == 201
    missing_presence = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": "not displayName pr"},
    )
    assert missing_presence.status_code == 200
    assert missing_presence.json()["totalResults"] == 1
    assert missing_presence.json()["Resources"][0]["externalId"] == "employee-no-display"
    null_comparison = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": "displayName eq null"},
    )
    assert null_comparison.status_code == 200
    assert null_comparison.json()["Resources"][0]["externalId"] == "employee-no-display"
    two_valued_not = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'not displayName eq "Employee 1"'},
    )
    assert two_valued_not.status_code == 200
    assert {item["externalId"] for item in two_valued_not.json()["Resources"]} == {
        "employee-beta",
        "employee-no-display",
    }
    absent_comparison = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'displayName ne "Employee 1"'},
    )
    assert absent_comparison.status_code == 200
    assert [item["externalId"] for item in absent_comparison.json()["Resources"]] == [
        "employee-beta"
    ]
    descending_missing_first = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"sortBy": "displayName", "sortOrder": "descending"},
    )
    assert descending_missing_first.status_code == 200
    assert [item["externalId"] for item in descending_missing_first.json()["Resources"]] == [
        "employee-no-display",
        "employee-beta",
        "employee-alpha",
    ]
    ascending_missing_last = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"sortBy": "displayName", "sortOrder": "ascending"},
    )
    assert ascending_missing_last.status_code == 200
    assert [item["externalId"] for item in ascending_missing_last.json()["Resources"]] == [
        "employee-alpha",
        "employee-beta",
        "employee-no-display",
    ]

    unsupported = client.get(
        '/saas/scim/v2/Groups?filter=userName%20eq%20"nobody@example.test"',
        headers=headers,
    )
    assert unsupported.status_code == 400
    assert unsupported.json()["scimType"] == "invalidFilter"

    compound = client.get(
        '/saas/scim/v2/Users?filter=active%20eq%20"true"%20and%20userName%20eq%20"x"',
        headers=headers,
    )
    assert compound.status_code == 400
    assert compound.json()["scimType"] == "invalidFilter"

    boolean_ordering = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": "active gt false"},
    )
    assert boolean_ordering.status_code == 400
    assert boolean_ordering.json()["scimType"] == "invalidFilter"

    numeric_string_comparison = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": "displayName ge 2"},
    )
    assert numeric_string_comparison.status_code == 400
    assert numeric_string_comparison.json()["scimType"] == "invalidFilter"

    wrong_schema = client.get(
        "/saas/scim/v2/Groups",
        headers=headers,
        params={"filter": ('urn:ietf:params:scim:schemas:core:2.0:User:displayName eq "Group 1"')},
    )
    assert wrong_schema.status_code == 400
    assert wrong_schema.json()["scimType"] == "invalidFilter"

    group_sort_unsupported = client.get(
        "/saas/scim/v2/Groups?sortBy=userName",
        headers=headers,
    )
    assert group_sort_unsupported.status_code == 400
    assert group_sort_unsupported.json()["scimType"] == "invalidValue"

    missing_sort_attribute = client.get(
        "/saas/scim/v2/Users?sortOrder=descending",
        headers=headers,
    )
    assert missing_sort_attribute.status_code == 400
    assert missing_sort_attribute.json()["scimType"] == "invalidValue"

    too_many_terms = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": " or ".join(f'externalId eq "missing-{index}"' for index in range(17))},
    )
    assert too_many_terms.status_code == 400
    assert too_many_terms.json()["scimType"] == "invalidFilter"

    too_deep = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": "(((((active eq true)))))"},
    )
    assert too_deep.status_code == 400
    assert too_deep.json()["scimType"] == "invalidFilter"

    too_many = client.get("/saas/scim/v2/Users?count=101", headers=headers)
    assert too_many.status_code == 400
    assert too_many.json()["scimType"] == "invalidValue"


def test_scim_resource_lifecycle_put_patch_delete_and_lost_response_replay() -> None:
    client, token, _, _ = _app()
    headers = {"Authorization": f"Bearer {token}"}

    def create_user(external_id: str) -> dict[str, object]:
        response = client.post(
            "/saas/scim/v2/Users",
            headers={**headers, "Idempotency-Key": f"create-{external_id}"},
            json={
                "schemas": [_USER_SCHEMA],
                "externalId": external_id,
                "userName": f"{external_id}@example.test",
                "displayName": external_id,
                "active": True,
            },
        )
        assert response.status_code == 201
        return cast(dict[str, object], response.json())

    first = create_user("lifecycle-first")
    second = create_user("lifecycle-second")
    first_id, second_id = str(first["id"]), str(second["id"])
    replace_body = {
        "schemas": [_USER_SCHEMA],
        "externalId": "lifecycle-first",
        "userName": "lifecycle-first@example.test",
        "displayName": "First Replaced",
        "active": True,
    }
    replaced = client.put(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"1"', "Idempotency-Key": "replace-first"},
        json=replace_body,
    )
    assert replaced.status_code == 200
    assert replaced.headers["etag"] == 'W/"2"'
    assert replaced.json()["displayName"] == "First Replaced"

    lost_response_retry = client.put(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"1"', "Idempotency-Key": "replace-first"},
        json=replace_body,
    )
    assert lost_response_retry.status_code == 200
    assert lost_response_retry.headers["etag"] == 'W/"2"'
    conflicting_retry = client.put(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"1"', "Idempotency-Key": "replace-first"},
        json={**replace_body, "displayName": "Conflicting Retry"},
    )
    assert conflicting_retry.status_code == 409
    assert conflicting_retry.json()["scimType"] == "scim_event_conflict"

    removed_name = client.patch(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"2"', "Idempotency-Key": "remove-name"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "remove", "path": "displayName"}],
        },
    )
    assert removed_name.status_code == 200
    assert removed_name.headers["etag"] == 'W/"3"'
    assert removed_name.json()["displayName"] is None
    invalid_boolean = client.patch(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "invalid-active"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": "false"}],
        },
    )
    assert invalid_boolean.status_code == 400
    assert invalid_boolean.json()["scimType"] == "scim_active_invalid"
    immutable_external = client.put(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "immutable-user"},
        json={**replace_body, "externalId": "changed-external"},
    )
    assert immutable_external.status_code == 409
    assert immutable_external.json()["scimType"] == "scim_external_id_immutable"

    group = client.post(
        "/saas/scim/v2/Groups",
        headers={**headers, "Idempotency-Key": "lifecycle-group-create"},
        json={
            "schemas": [_GROUP_SCHEMA],
            "externalId": "lifecycle-group",
            "displayName": "Lifecycle Group",
            "members": [{"value": first_id}],
        },
    )
    assert group.status_code == 201
    group_id = group.json()["id"]
    added = client.patch(
        f"/saas/scim/v2/Groups/{group_id}",
        headers={**headers, "If-Match": 'W/"1"', "Idempotency-Key": "group-add"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": {"value": second_id}}],
        },
    )
    assert added.status_code == 200
    assert added.headers["etag"] == 'W/"2"'
    assert {member["value"] for member in added.json()["members"]} == {first_id, second_id}
    added_replay = client.patch(
        f"/saas/scim/v2/Groups/{group_id}",
        headers={**headers, "If-Match": 'W/"1"', "Idempotency-Key": "group-add"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": {"value": second_id}}],
        },
    )
    assert added_replay.status_code == 200
    assert added_replay.headers["etag"] == 'W/"2"'

    removed_member = client.patch(
        f"/saas/scim/v2/Groups/{group_id}",
        headers={**headers, "If-Match": 'W/"2"', "Idempotency-Key": "group-remove"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "remove", "path": f'members[value eq "{first_id}"]'}],
        },
    )
    assert removed_member.status_code == 200
    assert [member["value"] for member in removed_member.json()["members"]] == [second_id]
    group_replace_body = {
        "schemas": [_GROUP_SCHEMA],
        "externalId": "lifecycle-group",
        "displayName": "Lifecycle Replaced",
        "members": [{"value": second_id}],
    }
    group_replaced = client.put(
        f"/saas/scim/v2/Groups/{group_id}",
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "group-replace"},
        json=group_replace_body,
    )
    assert group_replaced.status_code == 200
    assert group_replaced.headers["etag"] == 'W/"4"'

    group_deleted = client.delete(
        f"/saas/scim/v2/Groups/{group_id}",
        headers={**headers, "If-Match": 'W/"4"', "Idempotency-Key": "group-delete"},
    )
    assert group_deleted.status_code == 204
    group_delete_replay = client.delete(
        f"/saas/scim/v2/Groups/{group_id}",
        headers={**headers, "If-Match": 'W/"4"', "Idempotency-Key": "group-delete"},
    )
    assert group_delete_replay.status_code == 204
    group_tombstone = client.get(f"/saas/scim/v2/Groups/{group_id}", headers=headers)
    assert group_tombstone.status_code == 200
    assert group_tombstone.headers["etag"] == 'W/"5"'
    assert group_tombstone.json()["members"] == []
    assert (
        group_tombstone.json()["urn:omnigent:params:scim:schemas:extension:governance:1.0:Group"][
            "active"
        ]
        is False
    )

    user_deleted = client.delete(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "user-delete"},
    )
    assert user_deleted.status_code == 204
    user_delete_replay = client.delete(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "user-delete"},
    )
    assert user_delete_replay.status_code == 204
    user_tombstone = client.get(f"/saas/scim/v2/Users/{first_id}", headers=headers)
    assert user_tombstone.status_code == 200
    assert user_tombstone.headers["etag"] == 'W/"4"'
    assert user_tombstone.json()["active"] is False
    stale_delete = client.delete(
        f"/saas/scim/v2/Users/{first_id}",
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "stale-delete"},
    )
    assert stale_delete.status_code == 412


def test_scim_patch_value_path_mutability_no_target_and_atomic_noops() -> None:
    client, token, _, _ = _app()
    headers = {"Authorization": f"Bearer {token}"}

    def create_user(name: str) -> str:
        response = client.post(
            "/saas/scim/v2/Users",
            headers={**headers, "Idempotency-Key": f"value-path-user-{name}"},
            json={
                "schemas": [_USER_SCHEMA],
                "externalId": name,
                "userName": f"{name}@example.test",
                "displayName": name,
                "active": True,
            },
        )
        assert response.status_code == 201
        return cast(str, response.json()["id"])

    first_id = create_user("value-path-first")
    second_id = create_user("value-path-second")
    group = client.post(
        "/saas/scim/v2/Groups",
        headers={**headers, "Idempotency-Key": "value-path-group-create"},
        json={
            "schemas": [_GROUP_SCHEMA],
            "externalId": "value-path-group",
            "displayName": "Value Path Group",
            "members": [{"value": first_id}, {"value": second_id}],
        },
    )
    assert group.status_code == 201
    group_path = f"/saas/scim/v2/Groups/{group.json()['id']}"

    removed = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"1"', "Idempotency-Key": "compound-remove"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "remove",
                    "path": f'members[(value eq "{first_id}") or value eq "{uuid4()}"]',
                }
            ],
        },
    )
    assert removed.status_code == 200
    assert removed.headers["etag"] == 'W/"2"'
    assert [member["value"] for member in removed.json()["members"]] == [second_id]

    absent_remove = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"2"', "Idempotency-Key": "absent-remove"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "remove", "path": f'members[value eq "{uuid4()}"]'}],
        },
    )
    assert absent_remove.status_code == 200
    assert absent_remove.headers["etag"] == 'W/"2"'

    duplicate_add = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"2"', "Idempotency-Key": "duplicate-add"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": {"value": second_id}}],
        },
    )
    assert duplicate_add.status_code == 200
    assert duplicate_add.headers["etag"] == 'W/"2"'
    duplicate_add_replay = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"2"', "Idempotency-Key": "duplicate-add"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": {"value": second_id}}],
        },
    )
    assert duplicate_add_replay.status_code == 200
    assert duplicate_add_replay.headers["etag"] == 'W/"2"'

    qualified_pathless = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"2"', "Idempotency-Key": "qualified-pathless"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "value": {
                        "urn:ietf:params:scim:schemas:core:2.0:Group:displayName": (
                            "Qualified Group"
                        )
                    },
                }
            ],
        },
    )
    assert qualified_pathless.status_code == 200
    assert qualified_pathless.headers["etag"] == 'W/"3"'
    assert qualified_pathless.json()["displayName"] == "Qualified Group"

    atomic_failure = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "atomic-failure"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "displayName", "value": "Must Roll Back"},
                {"op": "remove"},
            ],
        },
    )
    assert atomic_failure.status_code == 400
    assert atomic_failure.json()["scimType"] == "noTarget"
    unchanged = client.get(group_path, headers=headers)
    assert unchanged.headers["etag"] == 'W/"3"'
    assert unchanged.json()["displayName"] == "Qualified Group"

    selected_replace = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "immutable-replace"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": f'members[value eq "{second_id}"]',
                    "value": {"value": first_id},
                }
            ],
        },
    )
    assert selected_replace.status_code == 400
    assert selected_replace.json()["scimType"] == "mutability"

    missing_replace = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "missing-replace"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": f'members[value eq "{uuid4()}"]',
                    "value": {"value": first_id},
                }
            ],
        },
    )
    assert missing_replace.status_code == 400
    assert missing_replace.json()["scimType"] == "noTarget"

    immutable_sub_attribute = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "immutable-sub"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "remove", "path": f'members[value eq "{second_id}"].value'}],
        },
    )
    assert immutable_sub_attribute.status_code == 400
    assert immutable_sub_attribute.json()["scimType"] == "mutability"

    wrong_schema = client.patch(
        group_path,
        headers={**headers, "If-Match": 'W/"3"', "Idempotency-Key": "wrong-schema"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": "urn:ietf:params:scim:schemas:core:2.0:User:displayName",
                    "value": "Wrong",
                }
            ],
        },
    )
    assert wrong_schema.status_code == 400
    assert wrong_schema.json()["scimType"] == "invalidPath"

    user_path = f"/saas/scim/v2/Users/{first_id}"
    user_pathless = client.patch(
        user_path,
        headers={**headers, "If-Match": 'W/"1"', "Idempotency-Key": "user-pathless"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "add", "value": {"DisplayName": "Pathless User"}}],
        },
    )
    assert user_pathless.status_code == 200
    assert user_pathless.headers["etag"] == 'W/"2"'
    assert user_pathless.json()["displayName"] == "Pathless User"

    immutable_user = client.patch(
        user_path,
        headers={**headers, "If-Match": 'W/"2"', "Idempotency-Key": "immutable-user-patch"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "externalId", "value": "changed"}],
        },
    )
    assert immutable_user.status_code == 400
    assert immutable_user.json()["scimType"] == "mutability"

    missing_value = client.patch(
        user_path,
        headers={**headers, "If-Match": 'W/"2"', "Idempotency-Key": "missing-value"},
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "displayName"}],
        },
    )
    assert missing_value.status_code == 400
    assert missing_value.json()["scimType"] == "invalidValue"


def test_scim_bulk_back_references_replay_conflict_limits_and_fail_on_errors() -> None:
    client, token, _, _ = _app()
    headers = {
        "Authorization": f"Bearer {token}",
        "Idempotency-Key": "bulk-create-and-disable",
    }
    config = client.get("/saas/scim/v2/ServiceProviderConfig")
    assert config.json()["bulk"] == {
        "supported": True,
        "maxOperations": 32,
        "maxPayloadSize": 1_048_576,
    }
    body = {
        "schemas": [_BULK_REQUEST_SCHEMA],
        "Operations": [
            {
                "method": "POST",
                "bulkId": "employee",
                "path": "/Users",
                "data": {
                    "schemas": [_USER_SCHEMA],
                    "externalId": "bulk-employee",
                    "userName": "bulk.employee@example.test",
                    "displayName": "Bulk Employee",
                    "active": True,
                },
            },
            {
                "method": "POST",
                "bulkId": "team",
                "path": "/Groups",
                "data": {
                    "schemas": [_GROUP_SCHEMA],
                    "externalId": "bulk-team",
                    "displayName": "Bulk Team",
                    "members": [{"value": "bulkId:employee"}],
                },
            },
            {
                "method": "PATCH",
                "version": 'W/"1"',
                "path": "/Users/bulkId:employee",
                "data": {
                    "schemas": [_PATCH_SCHEMA],
                    "Operations": [{"op": "replace", "path": "active", "value": False}],
                },
            },
        ],
    }
    created = client.post("/saas/scim/v2/Bulk", headers=headers, json=body)
    assert created.status_code == 200
    assert created.json()["schemas"] == [_BULK_RESPONSE_SCHEMA]
    operations = created.json()["Operations"]
    assert [item["status"] for item in operations] == ["201", "201", "200"]
    user_id = operations[0]["response"]["id"]
    assert operations[1]["response"]["members"] == [
        {
            "value": user_id,
            "$ref": f"http://testserver/saas/scim/v2/Users/{user_id}",
        }
    ]
    assert operations[2]["response"]["active"] is False

    replay = client.post("/saas/scim/v2/Bulk", headers=headers, json=body)
    assert replay.status_code == 200
    assert replay.json() == created.json()
    conflict_body = cast(dict[str, object], {**body})
    conflict_operations = [
        dict(item) for item in cast(list[dict[str, object]], body["Operations"])
    ]
    conflict_user = dict(cast(dict[str, object], conflict_operations[0]["data"]))
    conflict_user["displayName"] = "Changed Bulk Employee"
    conflict_operations[0]["data"] = conflict_user
    conflict_body["Operations"] = conflict_operations
    conflict = client.post("/saas/scim/v2/Bulk", headers=headers, json=conflict_body)
    assert conflict.status_code == 409
    assert conflict.json()["scimType"] == "scim_event_conflict"

    forward = client.post(
        "/saas/scim/v2/Bulk",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "bulk-forward-reference",
        },
        json={
            "schemas": [_BULK_REQUEST_SCHEMA],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "forward-group",
                    "path": "/Groups",
                    "data": {
                        "schemas": [_GROUP_SCHEMA],
                        "externalId": "forward-group",
                        "displayName": "Forward Group",
                        "members": [{"value": "bulkId:forward-user"}],
                    },
                },
                {
                    "method": "POST",
                    "bulkId": "forward-user",
                    "path": "/Users",
                    "data": {
                        "schemas": [_USER_SCHEMA],
                        "externalId": "forward-user",
                        "userName": "forward-user@example.test",
                        "active": True,
                    },
                },
            ],
        },
    )
    assert forward.status_code == 200
    forward_operations = forward.json()["Operations"]
    assert [item["status"] for item in forward_operations] == ["201", "201"]
    assert (
        forward_operations[0]["response"]["members"][0]["value"]
        == (forward_operations[1]["response"]["id"])
    )

    stopped = client.post(
        "/saas/scim/v2/Bulk",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "bulk-stop-on-first-error",
        },
        json={
            "schemas": [_BULK_REQUEST_SCHEMA],
            "failOnErrors": 1,
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "failed-group",
                    "path": "/Groups",
                    "data": {
                        "schemas": [_GROUP_SCHEMA],
                        "externalId": "forward-reference-group",
                        "displayName": "Forward Reference",
                        "members": [{"value": "bulkId:missing-user"}],
                    },
                },
                {
                    "method": "POST",
                    "bulkId": "later-user",
                    "path": "/Users",
                    "data": {
                        "schemas": [_USER_SCHEMA],
                        "externalId": "must-not-run",
                        "userName": "must-not-run@example.test",
                        "active": True,
                    },
                },
            ],
        },
    )
    assert stopped.status_code == 200
    assert len(stopped.json()["Operations"]) == 1
    assert stopped.json()["Operations"][0]["status"] == "409"
    absent = client.get(
        '/saas/scim/v2/Users?filter=externalId%20eq%20"must-not-run"',
        headers={"Authorization": f"Bearer {token}"},
    )
    assert absent.json()["totalResults"] == 0

    invalid_syntax = client.post(
        "/saas/scim/v2/Bulk",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "bulk-invalid-syntax",
        },
        json={
            "schemas": [_BULK_REQUEST_SCHEMA],
            "Operations": [{"method": "post", "bulkId": "bad", "path": "/Users"}],
        },
    )
    assert invalid_syntax.status_code == 400
    assert invalid_syntax.json()["scimType"] == "invalidSyntax"
    missing_bulk_id = client.post(
        "/saas/scim/v2/Bulk",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "bulk-missing-id",
        },
        json={
            "schemas": [_BULK_REQUEST_SCHEMA],
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "data": {
                        "schemas": [_USER_SCHEMA],
                        "externalId": "missing-id",
                        "userName": "missing-id@example.test",
                    },
                }
            ],
        },
    )
    assert missing_bulk_id.status_code == 400
    assert missing_bulk_id.json()["scimType"] == "invalidValue"

    oversized = client.post(
        "/saas/scim/v2/Bulk",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "bulk-too-large",
            "Content-Type": "application/json",
        },
        content=b"{}" + b" " * 1_048_575,
    )
    assert oversized.status_code == 413
    assert "maxPayloadSize (1048576)" in oversized.json()["detail"]
    assert "scimType" not in oversized.json()

    too_many = client.post(
        "/saas/scim/v2/Bulk",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "bulk-too-many",
        },
        json={
            "schemas": [_BULK_REQUEST_SCHEMA],
            "Operations": [
                {"method": "DELETE", "path": f"/Users/{uuid4()}", "version": 'W/"1"'}
                for _ in range(33)
            ],
        },
    )
    assert too_many.status_code == 413
    assert "maxOperations (32)" in too_many.json()["detail"]
    assert "scimType" not in too_many.json()


def test_scim_idp_configuration_profile_list_get_update_and_replay() -> None:
    client, _, tenant_id, directory_id = _app()
    collection = f"/saas/tenants/{tenant_id}/enterprise/scim-directories"

    listed = client.get(collection)
    assert listed.status_code == 200
    assert listed.headers["cache-control"] == "no-store"
    assert listed.json()["total"] == 1
    original = listed.json()["items"][0]
    assert original["provider_type"] == "generic"
    assert original["bearer_token"] is None
    assert original["endpoints"]["schemas"].endswith("/saas/scim/v2/Schemas")

    item_path = f"{collection}/{directory_id}"
    fetched = client.get(item_path)
    assert fetched.status_code == 200
    assert fetched.json()["token_prefix"].startswith("omniscim_")
    assert "token_hash" not in fetched.json()

    configuration_path = f"{item_path}/configuration"
    body = {
        "expected_version": 1,
        "providerType": "microsoft_entra",
        "attributeMapping": {"extensionAttribute1": f"{_ENTERPRISE_USER_SCHEMA}:costCenter"},
    }
    configured = client.put(
        configuration_path,
        headers={"Idempotency-Key": "configure-entra"},
        json=body,
    )
    assert configured.status_code == 200
    assert configured.json()["version"] == 2
    assert configured.json()["provider_type"] == "microsoft_entra"
    assert (
        configured.json()["idp_profile"]["attributeMappings"]["extensionAttribute1"]
        == f"{_ENTERPRISE_USER_SCHEMA}:costCenter"
    )

    replay = client.put(
        configuration_path,
        headers={"Idempotency-Key": "configure-entra"},
        json=body,
    )
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["bearer_token"] is None

    conflict = client.put(
        configuration_path,
        headers={"Idempotency-Key": "configure-entra"},
        json={**body, "providerType": "okta"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "idempotency_conflict"

    duplicate_targets = client.put(
        configuration_path,
        headers={"Idempotency-Key": "configure-duplicate-targets"},
        json={
            "expected_version": 2,
            "providerType": "okta",
            "attributeMapping": {
                "department": f"{_ENTERPRISE_USER_SCHEMA}:department",
                "division": f"{_ENTERPRISE_USER_SCHEMA}:department",
            },
        },
    )
    assert duplicate_targets.status_code == 400
    assert duplicate_targets.json()["detail"]["code"] == "scim_idp_mapping_invalid"


def test_scim_enterprise_user_optional_attributes_filters_patch_and_replace() -> None:
    client, token, _, _ = _app()
    headers = {"Authorization": f"Bearer {token}"}
    enterprise = {
        "employeeNumber": "E-1001",
        "costCenter": "CC-42",
        "organization": "Omnigent",
        "division": "Product",
        "department": "Engineering",
        "manager": {"value": str(uuid4()), "$ref": "/Users/manager"},
    }
    created = client.post(
        "/saas/scim/v2/Users",
        headers={**headers, "Idempotency-Key": "enterprise-user-create"},
        json={
            "schemas": [_USER_SCHEMA, _ENTERPRISE_USER_SCHEMA],
            "externalId": "enterprise-user",
            "userName": "enterprise.user@example.test",
            "displayName": "Enterprise User",
            "name": {"givenName": "Ada", "familyName": "Lovelace"},
            "title": "Staff Engineer",
            "preferredLanguage": "en-US",
            "emails": [
                {"value": "enterprise.user@example.test", "type": "work", "primary": True},
                {"value": "ada@example.test", "type": "home"},
            ],
            "phoneNumbers": [{"value": "+1-555-0100", "type": "work"}],
            "addresses": [
                {
                    "streetAddress": "1 Computing Lane",
                    "locality": "London",
                    "country": "GB",
                    "type": "work",
                    "primary": True,
                }
            ],
            _ENTERPRISE_USER_SCHEMA: enterprise,
            "active": True,
        },
    )
    assert created.status_code == 201
    payload = created.json()
    user_id = payload["id"]
    assert payload["name"]["givenName"] == "Ada"
    assert payload["emails"][0]["primary"] is True
    assert payload[_ENTERPRISE_USER_SCHEMA]["department"] == "Engineering"
    assert _ENTERPRISE_USER_SCHEMA in payload["schemas"]

    by_name = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'name.givenName eq "ada"'},
    )
    assert by_name.status_code == 200
    assert by_name.json()["totalResults"] == 1
    by_department = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": (f'{_ENTERPRISE_USER_SCHEMA}:department eq "engineering"')},
    )
    assert by_department.status_code == 200
    assert by_department.json()["totalResults"] == 1

    by_work_email = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": ('emails[type eq "work" and value co "enterprise.user"]')},
    )
    assert by_work_email.status_code == 200
    assert by_work_email.json()["totalResults"] == 1
    by_phone = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'phoneNumbers[value sw "+1-555"]'},
    )
    assert by_phone.status_code == 200
    assert by_phone.json()["totalResults"] == 1
    by_address = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'addresses[country eq "gb" and primary eq true]'},
    )
    assert by_address.status_code == 200
    assert by_address.json()["totalResults"] == 1
    by_direct_value = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'emails.value eq "enterprise.user@example.test"'},
    )
    assert by_direct_value.status_code == 200
    assert by_direct_value.json()["totalResults"] == 1

    projected = client.get(
        f"/saas/scim/v2/Users/{user_id}",
        headers=headers,
        params={
            "attributes": (
                f"userName,name.givenName,emails.value,{_ENTERPRISE_USER_SCHEMA}:department"
            )
        },
    )
    assert projected.status_code == 200
    projected_payload = projected.json()
    assert set(projected_payload) == {
        "schemas",
        "id",
        "meta",
        "userName",
        "name",
        "emails",
        _ENTERPRISE_USER_SCHEMA,
    }
    assert projected_payload["name"] == {"givenName": "Ada"}
    assert projected_payload["emails"] == [
        {"value": "enterprise.user@example.test"},
        {"value": "ada@example.test"},
    ]
    assert projected_payload[_ENTERPRISE_USER_SCHEMA] == {"department": "Engineering"}

    excluded = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={
            "excludedAttributes": (f"displayName,emails.type,{_ENTERPRISE_USER_SCHEMA}:manager")
        },
    )
    assert excluded.status_code == 200
    excluded_user = excluded.json()["Resources"][0]
    assert "displayName" not in excluded_user
    assert all("type" not in email for email in excluded_user["emails"])
    assert "manager" not in excluded_user[_ENTERPRISE_USER_SCHEMA]
    ambiguous_projection = client.get(
        f"/saas/scim/v2/Users/{user_id}",
        headers=headers,
        params={"attributes": "userName", "excludedAttributes": "displayName"},
    )
    assert ambiguous_projection.status_code == 400
    assert ambiguous_projection.json()["scimType"] == "invalidValue"

    invalid_multivalue_filter = client.get(
        "/saas/scim/v2/Users",
        headers=headers,
        params={"filter": 'emails[primary eq "true"]'},
    )
    assert invalid_multivalue_filter.status_code == 400
    assert invalid_multivalue_filter.json()["scimType"] == "invalidFilter"

    patched = client.patch(
        f"/saas/scim/v2/Users/{user_id}",
        headers={
            **headers,
            "If-Match": 'W/"1"',
            "Idempotency-Key": "enterprise-user-patch",
        },
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "name.givenName", "value": "Grace"},
                {
                    "op": "replace",
                    "path": f"{_ENTERPRISE_USER_SCHEMA}:department",
                    "value": "Research",
                },
                {
                    "op": "replace",
                    "path": 'emails[type eq "work"].value',
                    "value": "grace@example.test",
                },
            ],
        },
    )
    assert patched.status_code == 200
    assert patched.headers["etag"] == 'W/"2"'
    assert patched.json()["name"]["givenName"] == "Grace"
    assert patched.json()[_ENTERPRISE_USER_SCHEMA]["department"] == "Research"
    assert patched.json()["emails"][0]["value"] == "grace@example.test"

    immutable_manager_display = client.patch(
        f"/saas/scim/v2/Users/{user_id}",
        headers={
            **headers,
            "If-Match": 'W/"2"',
            "Idempotency-Key": "enterprise-manager-display",
        },
        json={
            "schemas": [_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": f"{_ENTERPRISE_USER_SCHEMA}:manager.displayName",
                    "value": "Read Only",
                }
            ],
        },
    )
    assert immutable_manager_display.status_code == 400
    assert immutable_manager_display.json()["scimType"] == "mutability"

    replaced = client.put(
        f"/saas/scim/v2/Users/{user_id}",
        headers={
            **headers,
            "If-Match": 'W/"2"',
            "Idempotency-Key": "enterprise-user-replace",
        },
        json={
            "schemas": [_USER_SCHEMA],
            "externalId": "enterprise-user",
            "userName": "enterprise.user@example.test",
            "displayName": "Minimal User",
            "active": True,
        },
    )
    assert replaced.status_code == 200
    assert replaced.headers["etag"] == 'W/"3"'
    assert "name" not in replaced.json()
    assert "emails" not in replaced.json()
    assert _ENTERPRISE_USER_SCHEMA not in replaced.json()

    duplicate_primary = client.post(
        "/saas/scim/v2/Users",
        headers={**headers, "Idempotency-Key": "duplicate-primary"},
        json={
            "schemas": [_USER_SCHEMA],
            "externalId": "duplicate-primary",
            "userName": "duplicate.primary@example.test",
            "emails": [
                {"value": "one@example.test", "primary": True},
                {"value": "two@example.test", "primary": True},
            ],
        },
    )
    assert duplicate_primary.status_code == 400
    assert duplicate_primary.json()["scimType"] == "invalidSyntax"
