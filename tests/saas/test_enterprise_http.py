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
                    role="admin",
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
        db.add_all(
            [
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
                ),
                ProjectMembershipRecord(
                    tenant_id=ids["tenant"],
                    space_id=ids["space"],
                    project_id=ids["project"],
                    subject_type="user",
                    subject_id=ids["member"],
                    role="manage",
                    status="active",
                    created_by=ids["owner"],
                    version=1,
                ),
            ]
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
        db.add_all(
            [
                RuntimeIdentityAliasRecord(
                    runtime_partition_id=ids["partition"],
                    user_id=ids["owner"],
                    runtime_user_key="enterprise-http-owner",
                    status="active",
                ),
                RuntimeIdentityAliasRecord(
                    runtime_partition_id=ids["partition"],
                    user_id=ids["member"],
                    runtime_user_key="enterprise-http-member",
                    status="active",
                ),
            ]
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
    assert permissions.json()["policy_version"] == "2026-08-06.p6-members"
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

    retire_preflight = client.post(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/custom-roles/{role.json()['id']}/retire-preflights",
        headers={**mutation_headers, "Idempotency-Key": "retire-role-preflight"},
        json={"expected_version": 1, "reason": "replaced by managed directory role"},
    )
    assert retire_preflight.status_code == 201, retire_preflight.text
    assert retire_preflight.json()["status"] == "pending_approval"
    assert retire_preflight.json()["tenant_id"] == str(ids["tenant"])
    assert retire_preflight.json()["space_id"] == str(ids["space"])
    assert retire_preflight.json()["project_id"] == str(ids["project"])
    assert retire_preflight.json()["reason"] == "replaced by managed directory role"
    assert retire_preflight.json()["created_at"].endswith("+00:00")
    assert retire_preflight.json()["expires_at"].endswith("+00:00")
    assert retire_preflight.json()["impact_summary"]["target_name"] == "HTTP Runner"
    assert retire_preflight.json()["impact_summary"]["permission_count"] == 2
    assert "impact_snapshot" not in retire_preflight.json()

    mine = client.get(
        f"/saas/tenants/{ids['tenant']}/enterprise-access-preflights/mine",
        params={"status": "pending_approval"},
    )
    assert mine.status_code == 200, mine.text
    assert [item["preflight_id"] for item in mine.json()["items"]] == [
        retire_preflight.json()["preflight_id"]
    ]
    own_project_inbox = client.get(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/enterprise-access-preflights/custom-role-retire-inbox"
    )
    assert own_project_inbox.status_code == 200, own_project_inbox.text
    assert own_project_inbox.json()["items"] == []
    invalid_status = client.get(
        f"/saas/tenants/{ids['tenant']}/enterprise-access-preflights/mine",
        params={"status": "expired"},
    )
    assert invalid_status.status_code == 422
    self_approval = client.post(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/custom-roles/{role.json()['id']}/retire-preflights/"
        f"{retire_preflight.json()['preflight_id']}/decisions",
        headers={**mutation_headers, "Idempotency-Key": "self-approve-role"},
        json={"decision": "approve", "reason": "reviewed"},
    )
    assert self_approval.status_code == 409
    assert self_approval.json()["detail"]["code"] == "approval_separation_required"

    approver_issued = lifecycle.issue_auth_session(
        user_id=ids["member"],
        authn_method="password",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    client.cookies.set("saas_session", approver_issued.token)
    approver_headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": approver_issued.csrf_token,
    }
    project_inbox = client.get(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/enterprise-access-preflights/custom-role-retire-inbox"
    )
    assert project_inbox.status_code == 200, project_inbox.text
    assert [item["preflight_id"] for item in project_inbox.json()["items"]] == [
        retire_preflight.json()["preflight_id"]
    ]
    approved_role = client.post(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/custom-roles/{role.json()['id']}/retire-preflights/"
        f"{retire_preflight.json()['preflight_id']}/decisions",
        headers={**approver_headers, "Idempotency-Key": "approve-retire-role"},
        json={"decision": "approve", "reason": "replacement is active"},
    )
    assert approved_role.status_code == 200, approved_role.text
    assert approved_role.json()["status"] == "approved"
    assert approved_role.json()["approval_reason"] == "replacement is active"
    assert approved_role.json()["approved_at"]
    assert (
        client.get(
            f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
            f"{ids['project']}/enterprise-access-preflights/custom-role-retire-inbox"
        ).json()["items"]
        == []
    )

    client.cookies.set("saas_session", issued.token)
    retired = client.post(
        f"/saas/tenants/{ids['tenant']}/spaces/{ids['space']}/projects/"
        f"{ids['project']}/custom-roles/{role.json()['id']}/retire",
        headers={**mutation_headers, "Idempotency-Key": "retire-role"},
        json={
            "approval_preflight_id": retire_preflight.json()["preflight_id"],
            "expected_version": 1,
            "reason": "replaced by managed directory role",
        },
    )
    assert retired.status_code == 200, retired.text
    assert retired.json()["status"] == "retired"
    assert retired.json()["revoked_assignment_count"] == 1

    archive_preflight = client.post(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[0]}/archive-preflights",
        headers={**mutation_headers, "Idempotency-Key": "archive-group-preflight"},
        json={"expected_version": 1, "reason": "replaced by managed directory group"},
    )
    assert archive_preflight.status_code == 201, archive_preflight.text
    rejected_preflight = client.post(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[1]}/archive-preflights",
        headers={**mutation_headers, "Idempotency-Key": "reject-group-preflight"},
        json={"expected_version": 1, "reason": "group should remain available"},
    )
    assert rejected_preflight.status_code == 201, rejected_preflight.text
    assert archive_preflight.json()["impact_summary"]["target_name"] == "Group 0"
    assert (
        client.get(
            f"/saas/tenants/{ids['tenant']}/enterprise-access-preflights/group-archive-inbox"
        ).json()["items"]
        == []
    )
    client.cookies.set("saas_session", approver_issued.token)
    first_inbox_page = client.get(
        f"/saas/tenants/{ids['tenant']}/enterprise-access-preflights/group-archive-inbox",
        params={"limit": 1},
    )
    assert first_inbox_page.status_code == 200, first_inbox_page.text
    assert len(first_inbox_page.json()["items"]) == 1
    assert first_inbox_page.json()["next_cursor"]
    second_inbox_page = client.get(
        f"/saas/tenants/{ids['tenant']}/enterprise-access-preflights/group-archive-inbox",
        params={"limit": 1, "cursor": first_inbox_page.json()["next_cursor"]},
    )
    assert second_inbox_page.status_code == 200, second_inbox_page.text
    assert len(second_inbox_page.json()["items"]) == 1
    assert {
        first_inbox_page.json()["items"][0]["preflight_id"],
        second_inbox_page.json()["items"][0]["preflight_id"],
    } == {
        archive_preflight.json()["preflight_id"],
        rejected_preflight.json()["preflight_id"],
    }
    approved_group = client.post(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[0]}/archive-preflights/"
        f"{archive_preflight.json()['preflight_id']}/decisions",
        headers={**approver_headers, "Idempotency-Key": "approve-archive-group"},
        json={"decision": "approve", "reason": "directory group is ready"},
    )
    assert approved_group.status_code == 200, approved_group.text
    assert approved_group.json()["status"] == "approved"
    rejected_group = client.post(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[1]}/archive-preflights/"
        f"{rejected_preflight.json()['preflight_id']}/decisions",
        headers={**approver_headers, "Idempotency-Key": "reject-archive-group"},
        json={"decision": "reject", "reason": "active integration still depends on it"},
    )
    assert rejected_group.status_code == 200, rejected_group.text
    assert rejected_group.json()["status"] == "rejected"

    client.cookies.set("saas_session", issued.token)
    archived = client.post(
        f"/saas/tenants/{ids['tenant']}/groups/{group_ids[0]}/archive",
        headers={**mutation_headers, "Idempotency-Key": "archive-group"},
        json={
            "approval_preflight_id": archive_preflight.json()["preflight_id"],
            "expected_version": 1,
            "reason": "replaced by managed directory group",
        },
    )
    assert archived.status_code == 200, archived.text
    assert archived.json()["status"] == "archived"
    assert archived.json()["removed_membership_count"] == 1
    assert (
        client.get(f"/saas/tenants/{ids['tenant']}/enterprise-access-preflights/mine").status_code
        == 401
    )
    refreshed_owner = lifecycle.issue_auth_session(
        user_id=ids["owner"],
        authn_method="password",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    client.cookies.set("saas_session", refreshed_owner.token)
    requested = client.get(f"/saas/tenants/{ids['tenant']}/enterprise-access-preflights/mine")
    assert requested.status_code == 200, requested.text
    statuses = {item["preflight_id"]: item["status"] for item in requested.json()["items"]}
    assert statuses[retire_preflight.json()["preflight_id"]] == "executed"
    assert statuses[archive_preflight.json()["preflight_id"]] == "executed"
    assert statuses[rejected_preflight.json()["preflight_id"]] == "rejected"
