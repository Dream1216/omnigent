from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    EnterpriseAccessService,
    GlobalUser,
    IdentityManagementService,
    MembershipLifecycleService,
    PasswordCredentialService,
    ProjectAdministrationService,
    ProjectAuthorizer,
    ProjectMembershipRecord,
    ProjectRecord,
    RuntimeCompatibilityPolicy,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    SaasBase,
    SaasCookieConfig,
    Space,
    SpaceMembership,
    SqlAlchemyContextResolver,
    Tenant,
    TenantMembership,
    create_saas_http_integration,
)


def _http_fixture() -> tuple[sessionmaker[Session], dict[str, UUID]]:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    ids = {
        name: uuid4()
        for name in ("owner", "member", "tenant", "space", "project", "placement", "partition")
    }
    with sessions.begin() as db:
        db.add_all(
            GlobalUser(id=ids[name], status="active", security_version=1)
            for name in ("owner", "member")
        )
        db.add(
            Tenant(
                id=ids["tenant"],
                slug="enterprise-http",
                name="Enterprise HTTP",
                status="active",
                plan="enterprise",
                home_region="cn-east-1",
            )
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=ids["tenant"],
                    user_id=ids["owner"],
                    role="owner",
                    status="active",
                    version=1,
                ),
                TenantMembership(
                    tenant_id=ids["tenant"],
                    user_id=ids["member"],
                    role="member",
                    status="active",
                    version=1,
                ),
            ]
        )
        db.add(
            Space(
                id=ids["space"],
                tenant_id=ids["tenant"],
                slug="engineering",
                name="Engineering",
                status="active",
            )
        )
        db.flush()
        db.add_all(
            [
                SpaceMembership(
                    tenant_id=ids["tenant"],
                    space_id=ids["space"],
                    user_id=ids["owner"],
                    role="owner",
                    status="active",
                    version=1,
                ),
                SpaceMembership(
                    tenant_id=ids["tenant"],
                    space_id=ids["space"],
                    user_id=ids["member"],
                    role="member",
                    status="active",
                    version=1,
                ),
            ]
        )
        db.add(
            ProjectRecord(
                id=ids["project"],
                tenant_id=ids["tenant"],
                space_id=ids["space"],
                name="HTTP Project",
                visibility="restricted",
                created_by=ids["owner"],
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=ids["tenant"],
                space_id=ids["space"],
                project_id=ids["project"],
                subject_type="user",
                subject_id=ids["owner"],
                role="owner",
                status="active",
                created_by=ids["owner"],
                version=1,
            )
        )
        db.add(
            RuntimePlacementRecord(
                id=ids["placement"],
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="enterprise-http-db",
                object_store_ref="enterprise-http-object",
                kms_key_ref="enterprise-http-kms",
                official_schema_revision="test-schema",
                capacity_class="shared",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=ids["partition"],
                tenant_id=ids["tenant"],
                space_id=ids["space"],
                placement_id=ids["placement"],
                runtime_type="omnigent",
                runtime_version="test-runtime",
                physical_partition_key="701",
                placement_generation=1,
                source_revision="test-source",
                adapter_contract_version="test-adapter",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimeIdentityAliasRecord(
                runtime_partition_id=ids["partition"],
                user_id=ids["owner"],
                runtime_user_key="enterprise-http-owner",
                status="active",
            )
        )
    return sessions, ids


def test_enterprise_admin_http_is_cookie_csrf_bound_paginated_and_action_scoped() -> None:
    sessions, ids = _http_fixture()
    lifecycle = MembershipLifecycleService(sessions)
    resolver = SqlAlchemyContextResolver(
        sessions,
        RuntimeCompatibilityPolicy(
            runtime_type="omnigent",
            allowed_runtime_versions=frozenset({"test-runtime"}),
            allowed_source_revisions=frozenset({"test-source"}),
            allowed_schema_revisions=frozenset({"test-schema"}),
            adapter_contract_version="test-adapter",
        ),
    )
    authorizer = ProjectAuthorizer(sessions)
    integration = create_saas_http_integration(
        lifecycle=lifecycle,
        identities=IdentityManagementService(sessions),
        passwords=PasswordCredentialService(sessions),
        context_resolver=resolver,
        cookie_config=SaasCookieConfig(
            name="saas_session",
            secure=False,
            trusted_origins=frozenset({"http://testserver"}),
        ),
        project_admin=ProjectAdministrationService(sessions, authorizer),
        project_authorizer=authorizer,
        enterprise_access=EnterpriseAccessService(sessions, authorizer),
    )
    app = FastAPI()
    for router, prefix, tags in integration.extra_routers:
        app.include_router(router, prefix=prefix, tags=tags)
    integration.install_middleware(app)
    client = TestClient(app)
    now = datetime.now(timezone.utc)
    issued = lifecycle.issue_auth_session(
        user_id=ids["owner"],
        authn_method="password",
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    client.cookies.set("saas_session", issued.token)
    mutation_headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": issued.csrf_token,
    }

    missing_csrf = client.post(
        f"/saas/tenants/{ids['tenant']}/groups",
        headers={"Idempotency-Key": "missing-csrf", "Origin": "http://testserver"},
        json={"name": "Denied"},
    )
    assert missing_csrf.status_code == 401
    assert missing_csrf.json()["error"]["code"] == "csrf_invalid"

    group_ids: list[str] = []
    for index in range(2):
        created = client.post(
            f"/saas/tenants/{ids['tenant']}/groups",
            headers={**mutation_headers, "Idempotency-Key": f"group-{index}"},
            json={"name": f"Group {index}"},
        )
        assert created.status_code == 201, created.text
        group_ids.append(created.json()["id"])
    first_page = client.get(f"/saas/tenants/{ids['tenant']}/groups?limit=1")
    assert first_page.status_code == 200
    assert len(first_page.json()["items"]) == 1
    assert first_page.json()["next_cursor"]
    second_page = client.get(
        f"/saas/tenants/{ids['tenant']}/groups",
        params={"limit": 1, "cursor": first_page.json()["next_cursor"]},
    )
    assert second_page.status_code == 200
    assert len(second_page.json()["items"]) == 1
    assert second_page.json()["items"][0]["id"] != first_page.json()["items"][0]["id"]
    invalid_cursor = client.get(
        f"/saas/tenants/{ids['tenant']}/groups", params={"cursor": "invalid"}
    )
    assert invalid_cursor.status_code == 400
    assert invalid_cursor.json()["detail"]["code"] == "cursor_invalid"

    member = client.put(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[0]}/members/{ids['member']}",
        headers={**mutation_headers, "Idempotency-Key": "add-member"},
        json={},
    )
    assert member.status_code == 200, member.text
    role = client.post(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/custom-roles",
        headers={**mutation_headers, "Idempotency-Key": "create-role"},
        json={
            "name": "HTTP Runner",
            "permissions": ["run.create", "project.read_metadata"],
        },
    )
    assert role.status_code == 201, role.text
    assignment = client.post(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/group-role-assignments",
        headers={**mutation_headers, "Idempotency-Key": "assign-role"},
        json={"group_id": group_ids[0], "custom_role_id": role.json()["id"]},
    )
    assert assignment.status_code == 201, assignment.text
    assert assignment.json()["status"] == "active"

    permissions = client.get("/saas/admin/permissions")
    assert permissions.status_code == 200
    assert permissions.json()["policy_version"] == "2026-08-05.p6-groups"
    catalog = {value["name"] for value in permissions.json()["permissions"]}
    assert {"group.manage", "custom_role.manage"} <= catalog

    duplicate_batch = client.post(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[0]}/membership-batches",
        headers={**mutation_headers, "Idempotency-Key": "duplicate-batch-members"},
        json={
            "mutations": [
                {"user_id": str(ids["member"]), "action": "add"},
                {"user_id": str(ids["member"]), "action": "add"},
            ]
        },
    )
    assert duplicate_batch.status_code == 422
    assert duplicate_batch.json()["detail"]["code"] == "group_membership_batch_duplicate"

    batch = client.post(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[0]}/membership-batches",
        headers={**mutation_headers, "Idempotency-Key": "batch-members"},
        json={
            "mutations": [
                {
                    "user_id": str(ids["member"]),
                    "action": "remove",
                    "expected_version": 1,
                },
                {"user_id": str(ids["owner"]), "action": "add"},
            ]
        },
    )
    assert batch.status_code == 200, batch.text
    assert [item["status"] for item in batch.json()["memberships"]] == [
        "removed",
        "active",
    ]

    retired = client.post(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/custom-roles/{role.json()['id']}/retire",
        headers={**mutation_headers, "Idempotency-Key": "retire-role"},
        json={"expected_version": 1, "reason": "replaced by managed directory role"},
    )
    assert retired.status_code == 200, retired.text
    assert retired.json()["status"] == "retired"
    assert retired.json()["revoked_assignment_count"] == 1

    archived = client.post(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[0]}/archive",
        headers={**mutation_headers, "Idempotency-Key": "archive-group"},
        json={"expected_version": 1, "reason": "replaced by managed directory group"},
    )
    assert archived.status_code == 200, archived.text
    assert archived.json()["status"] == "archived"
    assert archived.json()["removed_membership_count"] == 1
