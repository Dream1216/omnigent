from __future__ import annotations

from uuid import uuid4

import sqlalchemy as sa
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import current_runtime_context
from saas.control_plane import (
    MEMBER_ADMIN_ROUTE_PERMISSIONS,
    PERMISSION_CATALOG,
    PROJECT_ADMIN_ROUTE_PERMISSIONS,
    ContextSnapshotPolicy,
    ContextSnapshotService,
    EnterpriseAccessService,
    IdentityManagementService,
    MembershipGovernanceService,
    MembershipLifecycleService,
    PasswordCredentialService,
    ProjectAdministrationService,
    ProjectAuthorizer,
    RemovalImpact,
    RuntimeBindingService,
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
    TenantMemberAdministrationService,
    TenantMembership,
    VerifiedIdentityAssertion,
    create_saas_http_integration,
)


class _NoRemovalImpact:
    def collect(self, **_scope: object) -> RemovalImpact:
        return RemovalImpact(facts={"owned_resources": []}, blocking_count=0)


def _build_fastapi_app(
    trusted_origin: str = "http://testserver",
) -> tuple[FastAPI, dict[str, str]]:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    lifecycle = MembershipLifecycleService(sessions)
    identities = IdentityManagementService(sessions)
    passwords = PasswordCredentialService(sessions)
    user_id = identities.provision_identity(
        VerifiedIdentityAssertion(
            provider="oidc",
            issuer="https://idp.example.com",
            subject="http-user",
            email="http@example.com",
            email_verified=True,
        )
    )
    member_id = identities.provision_identity(
        VerifiedIdentityAssertion(
            provider="oidc",
            issuer="https://idp.example.com",
            subject="http-member",
            email="member@example.com",
            email_verified=True,
        )
    )
    viewer_id = identities.provision_identity(
        VerifiedIdentityAssertion(
            provider="oidc",
            issuer="https://idp.example.com",
            subject="http-viewer",
            email="viewer@example.com",
            email_verified=True,
        )
    )
    invitee_id = identities.provision_identity(
        VerifiedIdentityAssertion(
            provider="oidc",
            issuer="https://idp.example.com",
            subject="http-invitee",
            email="invitee@example.com",
            email_verified=True,
        )
    )
    passwords.set_password(
        user_id=user_id,
        new_password="initial-http-password",
        expected_version=None,
        idempotency_key="http-initial-password",
    )
    passwords.set_password(
        user_id=member_id,
        new_password="initial-member-password",
        expected_version=None,
        idempotency_key="http-member-initial-password",
    )
    passwords.set_password(
        user_id=viewer_id,
        new_password="initial-viewer-password",
        expected_version=None,
        idempotency_key="http-viewer-initial-password",
    )
    passwords.set_password(
        user_id=invitee_id,
        new_password="initial-invitee-password",
        expected_version=None,
        idempotency_key="http-invitee-initial-password",
    )

    tenant_id, space_id, placement_id, partition_id = uuid4(), uuid4(), uuid4(), uuid4()
    with sessions.begin() as db:
        db.add_all(
            [
                Tenant(
                    id=tenant_id,
                    slug="http-tenant",
                    name="HTTP Tenant",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
                Space(
                    id=space_id,
                    tenant_id=tenant_id,
                    slug="engineering",
                    name="Engineering",
                    status="active",
                ),
            ]
        )
        db.flush()
        db.add(
            TenantMembership(
                tenant_id=tenant_id,
                user_id=user_id,
                role="owner",
                status="active",
                version=1,
            )
        )
        db.add(
            TenantMembership(
                tenant_id=tenant_id,
                user_id=viewer_id,
                role="member",
                status="active",
                version=1,
            )
        )
        db.add(
            TenantMembership(
                tenant_id=tenant_id,
                user_id=member_id,
                role="admin",
                status="active",
                version=1,
            )
        )
        db.flush()
        db.add_all(
            [
                SpaceMembership(
                    tenant_id=tenant_id,
                    space_id=space_id,
                    user_id=user_id,
                    role="owner",
                    status="active",
                    version=1,
                ),
                SpaceMembership(
                    tenant_id=tenant_id,
                    space_id=space_id,
                    user_id=viewer_id,
                    role="viewer",
                    status="active",
                    version=1,
                ),
                SpaceMembership(
                    tenant_id=tenant_id,
                    space_id=space_id,
                    user_id=member_id,
                    role="member",
                    status="active",
                    version=1,
                ),
            ]
        )
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="db-a",
                object_store_ref="objects-a",
                kms_key_ref="kms-a",
                official_schema_revision="c4d5e6f7a8b9",
                capacity_class="shared-medium",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=tenant_id,
                space_id=space_id,
                placement_id=placement_id,
                runtime_type="omnigent",
                runtime_version="0.9.0.dev0",
                physical_partition_key="41",
                placement_generation=3,
                source_revision="15dd7becff2bda8ee2b9afd5d16abc4feafb9552",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
        db.flush()
        db.add_all(
            [
                RuntimeIdentityAliasRecord(
                    runtime_partition_id=partition_id,
                    user_id=user_id,
                    runtime_user_key="runtime_http_user",
                    status="active",
                ),
                RuntimeIdentityAliasRecord(
                    runtime_partition_id=partition_id,
                    user_id=viewer_id,
                    runtime_user_key="runtime_http_viewer",
                    status="active",
                ),
                RuntimeIdentityAliasRecord(
                    runtime_partition_id=partition_id,
                    user_id=member_id,
                    runtime_user_key="runtime_http_member",
                    status="active",
                ),
            ]
        )

    policy = RuntimeCompatibilityPolicy(
        runtime_type="omnigent",
        allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
        allowed_source_revisions=frozenset({"15dd7becff2bda8ee2b9afd5d16abc4feafb9552"}),
        allowed_schema_revisions=frozenset({"c4d5e6f7a8b9"}),
        adapter_contract_version="0.2.0",
    )
    project_authorizer = ProjectAuthorizer(sessions)
    resolver = SqlAlchemyContextResolver(sessions, policy, project_authorizer=project_authorizer)
    project_admin = ProjectAdministrationService(sessions, project_authorizer)
    runtime_bindings = RuntimeBindingService(sessions, project_authorizer, policy)
    cookie = SaasCookieConfig(
        name="saas_session",
        secure=False,
        trusted_origins=frozenset({trusted_origin}),
    )
    integration = create_saas_http_integration(
        lifecycle=lifecycle,
        identities=identities,
        passwords=passwords,
        context_resolver=resolver,
        cookie_config=cookie,
        governance=MembershipGovernanceService(sessions, _NoRemovalImpact()),
        project_admin=project_admin,
        project_authorizer=project_authorizer,
        runtime_bindings=runtime_bindings,
        enterprise_access=EnterpriseAccessService(sessions, project_authorizer),
        member_admin=TenantMemberAdministrationService(sessions),
        member_lifecycle=lifecycle,
        context_snapshots=ContextSnapshotService(
            ContextSnapshotPolicy(
                active_key_id="fixture-v1",
                keys={"fixture-v1": b"context-shell-fixture-key-material-v1"},
                issuer="omnigent-saas-browser-fixture",
                audience="omnigent-api",
            )
        ),
        degraded_read_paths=frozenset({"/v1/protected"}),
    )
    auth = integration.auth_provider
    app = FastAPI()
    router, prefix, tags = integration.extra_router
    app.include_router(router, prefix=prefix, tags=tags)

    @app.api_route("/v1/protected", methods=["GET", "POST"])
    def protected(request: Request) -> dict[str, object]:
        runtime = current_runtime_context()
        return {
            "user_id": auth.get_user_id(request),
            "workspace_id": runtime.physical_workspace_id,
            "tenant_id": str(runtime.tenant_id),
        }

    integration.install_middleware(app)
    return app, {
        "tenant_id": str(tenant_id),
        "space_id": str(space_id),
        "user_id": str(user_id),
        "member_id": str(member_id),
        "viewer_id": str(viewer_id),
        "invitee_id": str(invitee_id),
        "partition_id": str(partition_id),
    }


def _build_app() -> tuple[TestClient, dict[str, str]]:
    app, scope = _build_fastapi_app()
    return TestClient(app), scope


def _login(client: TestClient) -> str:
    response = client.post(
        "/saas/auth/login",
        json={"email": "HTTP@example.com", "password": "initial-http-password"},
    )
    assert response.status_code == 200
    assert "HttpOnly" in response.headers["set-cookie"]
    return response.json()["csrf_token"]


def test_cookie_auth_binds_runtime_alias_and_enforces_origin_csrf() -> None:
    client, scope = _build_app()
    cross_site_login = client.post(
        "/saas/auth/login",
        json={"email": "HTTP@example.com", "password": "initial-http-password"},
        headers={"Origin": "https://attacker.example"},
    )
    assert cross_site_login.status_code == 403
    assert cross_site_login.json()["error"]["code"] == "origin_forbidden"
    assert client.get("/saas/auth/status").json() == {
        "authenticated": False,
        "user_id": None,
    }
    csrf = _login(client)
    assert client.get("/saas/auth/status").json() == {
        "authenticated": True,
        "user_id": scope["user_id"],
    }
    assert client.get("/saas/auth/me").json()["user_id"] == scope["user_id"]
    available_scopes = client.get("/saas/context/scopes")
    assert available_scopes.status_code == 200
    assert available_scopes.json() == [
        {
            "tenant_id": scope["tenant_id"],
            "tenant_slug": "http-tenant",
            "tenant_name": "HTTP Tenant",
            "tenant_role": "owner",
            "tenant_membership_version": 1,
            "space_id": scope["space_id"],
            "space_slug": "engineering",
            "space_name": "Engineering",
            "space_role": "owner",
            "space_membership_version": 1,
            "user_security_version": 2,
        }
    ]
    snapshot_response = client.post(
        "/saas/context/snapshots",
        json={"tenant_id": scope["tenant_id"], "space_id": scope["space_id"]},
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert snapshot_response.status_code == 201
    assert snapshot_response.json()["max_age_seconds"] <= 60
    assert snapshot_response.json()["context_snapshot"].count(".") == 2
    assert "placement_id" not in snapshot_response.json()
    assert "physical_workspace_id" not in snapshot_response.json()

    snapshot_bound = client.get(
        "/v1/protected",
        headers={"X-SaaS-Context-Snapshot": snapshot_response.json()["context_snapshot"]},
    )
    assert snapshot_bound.status_code == 200
    assert snapshot_bound.json()["workspace_id"] == 41

    missing_scope = client.get("/v1/protected")
    assert missing_scope.status_code == 403
    missing_csrf = client.post(
        "/v1/protected",
        headers={
            "Origin": "http://testserver",
            "X-SaaS-Tenant-Id": scope["tenant_id"],
            "X-SaaS-Space-Id": scope["space_id"],
        },
    )
    assert missing_csrf.status_code == 401

    response = client.post(
        "/v1/protected",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf,
            "X-SaaS-Tenant-Id": scope["tenant_id"],
            "X-SaaS-Space-Id": scope["space_id"],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "user_id": "runtime_http_user",
        "workspace_id": 41,
        "tenant_id": scope["tenant_id"],
    }


def test_identity_revoke_and_password_rotation_clear_revoked_cookie() -> None:
    client, _scope = _build_app()
    csrf = _login(client)
    identities = client.get("/saas/identities").json()
    revoked = client.delete(
        f"/saas/identities/{identities[0]['id']}",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "http-revoke-identity",
        },
    )
    assert revoked.status_code == 204
    assert "Max-Age=0" in revoked.headers["set-cookie"]
    assert client.get("/saas/auth/me").status_code == 401


def test_governance_http_routes_bind_fresh_session_and_impact_preflight() -> None:
    client, scope = _build_app()
    csrf = _login(client)
    headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": csrf,
        "Idempotency-Key": "http-removal-preflight",
    }
    preflight = client.post(
        f"/saas/tenants/{scope['tenant_id']}/members/{scope['member_id']}/removal-preflights",
        json={},
        headers=headers,
    )
    assert preflight.status_code == 201
    assert preflight.json()["status"] == "ready"
    executed = client.post(
        f"/saas/tenants/{scope['tenant_id']}/member-removal-preflights/"
        f"{preflight.json()['preflight_id']}/execute",
        json={"reason": "member access is no longer required"},
        headers={**headers, "Idempotency-Key": "http-removal-execute"},
    )
    assert executed.status_code == 200
    assert executed.json()["removed_space_memberships"] == 1

    client, scope = _build_app()
    csrf = _login(client)
    transferred = client.post(
        f"/saas/tenants/{scope['tenant_id']}/ownership-transfers",
        json={
            "to_user_id": scope["member_id"],
            "source_expected_version": 1,
            "target_expected_version": 1,
            "reason": "planned ownership handover",
        },
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "http-owner-transfer",
        },
    )
    assert transferred.status_code == 201
    assert transferred.json()["target_version"] == 2
    assert "Max-Age=0" in transferred.headers["set-cookie"]

    csrf = _login(client)
    rotated = client.put(
        "/saas/password",
        json={
            "new_password": "rotated-http-password",
            "current_password": "initial-http-password",
            "expected_version": 1,
        },
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "http-rotate-password",
        },
    )
    assert rotated.status_code == 200
    assert rotated.json()["reauthentication_required"] is True
    assert "Max-Age=0" in rotated.headers["set-cookie"]
    assert client.get("/saas/auth/me").status_code == 401


def test_project_admin_http_permission_and_binding_matrix() -> None:
    client, scope = _build_app()
    admin_page = client.get("/saas/admin/projects")
    assert admin_page.status_code == 200
    assert "SAAS CONTROL PLANE" in admin_page.text
    assert "script-src 'self'" in admin_page.headers["content-security-policy"]
    assert (
        client.get("/saas/admin/assets/project-admin.css")
        .headers["content-type"]
        .startswith("text/css")
    )
    assert (
        client.get("/saas/admin/assets/project-admin.js")
        .headers["content-type"]
        .startswith("text/javascript")
    )
    csrf = _login(client)
    base = f"/saas/tenants/{scope['tenant_id']}/spaces/{scope['space_id']}"
    headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": csrf,
    }
    catalog = client.get("/saas/admin/permissions")
    assert catalog.status_code == 200
    catalog_names = {item["name"] for item in catalog.json()["permissions"]}
    assert catalog_names == set(PERMISSION_CATALOG)
    assert set(PROJECT_ADMIN_ROUTE_PERMISSIONS.values()) <= catalog_names

    created = client.post(
        f"{base}/projects",
        json={"name": "HTTP restricted", "visibility": "restricted"},
        headers={**headers, "Idempotency-Key": "http-project-create"},
    )
    assert created.status_code == 201
    project_id = created.json()["project_id"]
    assert created.json()["authorization_version"] == 1
    listed = client.get(f"{base}/projects")
    assert listed.status_code == 200
    assert [project["project_id"] for project in listed.json()] == [project_id]

    denied = client.post(
        f"{base}/projects/{project_id}/access/decisions",
        json={
            "action": "project.content.read",
            "subject_user_id": scope["member_id"],
        },
        headers=headers,
    )
    assert denied.status_code == 200
    assert denied.json()["allowed"] is False
    assert denied.json()["mode"] == "shadow"
    granted = client.put(
        f"{base}/projects/{project_id}/members/user/{scope['member_id']}",
        json={"role": "read"},
        headers={**headers, "Idempotency-Key": "http-project-reader"},
    )
    assert granted.status_code == 200
    assert granted.json()["status"] == "active"
    allowed = client.post(
        f"{base}/projects/{project_id}/access/decisions",
        json={
            "action": "project.content.read",
            "subject_user_id": scope["member_id"],
        },
        headers=headers,
    )
    assert allowed.status_code == 200
    assert allowed.json()["allowed"] is True
    assert any(
        source["source_type"] == "project_membership" for source in allowed.json()["sources"]
    )

    membership_revoked = client.delete(
        f"{base}/projects/{project_id}/members/user/{scope['member_id']}",
        headers={**headers, "Idempotency-Key": "http-project-reader-revoke"},
    )
    assert membership_revoked.status_code == 200
    assert membership_revoked.json()["status"] == "revoked"

    resource_id = str(uuid4())
    resource_grant = client.put(
        f"{base}/projects/{project_id}/resource-grants",
        json={
            "resource_type": "conversation",
            "resource_id": resource_id,
            "subject_type": "user",
            "subject_id": scope["member_id"],
            "role": "read",
        },
        headers={**headers, "Idempotency-Key": "http-resource-reader"},
    )
    assert resource_grant.status_code == 200
    assert resource_grant.json()["grant_id"] is not None
    exact_allowed = client.post(
        f"{base}/projects/{project_id}/access/decisions",
        json={
            "action": "project.content.read",
            "subject_user_id": scope["member_id"],
            "resource_type": "conversation",
            "resource_id": resource_id,
        },
        headers=headers,
    )
    assert exact_allowed.status_code == 200
    assert exact_allowed.json()["allowed"] is True
    resource_revoked = client.delete(
        f"{base}/projects/{project_id}/resource-grants/{resource_grant.json()['grant_id']}",
        headers={**headers, "Idempotency-Key": "http-resource-reader-revoke"},
    )
    assert resource_revoked.status_code == 200
    assert resource_revoked.json()["status"] == "revoked"
    exact_denied = client.post(
        f"{base}/projects/{project_id}/access/decisions",
        json={
            "action": "project.content.read",
            "subject_user_id": scope["member_id"],
            "resource_type": "conversation",
            "resource_id": resource_id,
        },
        headers=headers,
    )
    assert exact_denied.status_code == 200
    assert exact_denied.json()["allowed"] is False

    bound = client.post(
        f"{base}/projects/{project_id}/bindings",
        json={
            "runtime_partition_id": scope["partition_id"],
            "resource_type": "conversation",
            "runtime_resource_id": "http-project-runtime-resource",
            "saas_resource_id": resource_id,
            "expected_partition_generation": 3,
        },
        headers={**headers, "Idempotency-Key": "http-project-binding"},
    )
    assert bound.status_code == 201
    assert bound.json()["status"] == "active"
    retired = client.post(
        f"{base}/bindings/{bound.json()['binding_id']}/retire",
        json={"expected_binding_generation": 1},
        headers={**headers, "Idempotency-Key": "http-project-binding-retire"},
    )
    assert retired.status_code == 200
    assert retired.json()["status"] == "retired"


def test_tenant_member_admin_http_is_private_scoped_and_lifecycle_complete() -> None:
    client, scope = _build_app()
    csrf = _login(client)
    tenant_base = f"/saas/tenants/{scope['tenant_id']}"
    headers = {"Origin": "http://testserver", "X-CSRF-Token": csrf}

    catalog = client.get("/saas/admin/permissions").json()
    catalog_names = {item["name"] for item in catalog["permissions"]}
    assert set(MEMBER_ADMIN_ROUTE_PERMISSIONS.values()) <= catalog_names

    listed = client.get(f"{tenant_base}/members?limit=100")
    assert listed.status_code == 200
    assert listed.headers["cache-control"] == "private, no-store"
    assert {item["user_id"] for item in listed.json()["items"]} == {
        scope["user_id"],
        scope["member_id"],
        scope["viewer_id"],
    }
    serialized = listed.text
    for secret_field in ("subject", "issuer", "token_hash", "security_version"):
        assert secret_field not in serialized

    viewer = TestClient(client.app)
    viewer_login = viewer.post(
        "/saas/auth/login",
        json={"email": "viewer@example.com", "password": "initial-viewer-password"},
    )
    assert viewer_login.status_code == 200
    denied = viewer.get(f"{tenant_base}/members")
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "forbidden"
    assert "http@example.com" not in denied.text

    invitation = client.post(
        f"{tenant_base}/membership-invitations",
        json={
            "email": "invitee@example.com",
            "tenant_role": "member",
            "space_id": scope["space_id"],
            "space_role": "viewer",
            "ttl_hours": 24,
        },
        headers={**headers, "Idempotency-Key": "http-member-invite-create"},
    )
    assert invitation.status_code == 201
    assert invitation.headers["cache-control"] == "private, no-store"
    first_token = invitation.json()["one_time_token"]
    invitation_id = invitation.json()["invitation_id"]

    invitation_list = client.get(f"{tenant_base}/membership-invitations?status=pending")
    assert invitation_list.status_code == 200
    assert invitation_list.headers["cache-control"] == "private, no-store"
    assert invitation_list.json()["items"][0]["email_normalized"] == "invitee@example.com"
    assert "one_time_token" not in invitation_list.text

    reissued = client.post(
        f"{tenant_base}/membership-invitations/{invitation_id}/reissue",
        json={
            "expected_version": 1,
            "ttl_hours": 48,
            "reason": "rotate token after delivery channel changed",
        },
        headers={**headers, "Idempotency-Key": "http-member-invite-reissue"},
    )
    assert reissued.status_code == 200
    second_token = reissued.json()["one_time_token"]
    assert second_token and second_token != first_token
    assert reissued.json()["version"] == 2

    invitee = TestClient(client.app)
    invitee_login = invitee.post(
        "/saas/auth/login",
        json={"email": "invitee@example.com", "password": "initial-invitee-password"},
    )
    invitee_csrf = invitee_login.json()["csrf_token"]
    old_token = invitee.post(
        "/saas/membership-invitations/accept",
        json={"token": first_token},
        headers={"Origin": "http://testserver", "X-CSRF-Token": invitee_csrf},
    )
    assert old_token.status_code == 409
    assert old_token.json()["detail"]["code"] == "invalid_invitation"
    accepted = invitee.post(
        "/saas/membership-invitations/accept",
        json={"token": second_token},
        headers={"Origin": "http://testserver", "X-CSRF-Token": invitee_csrf},
    )
    assert accepted.status_code == 200
    assert accepted.json()["tenant_id"] == scope["tenant_id"]
    assert accepted.json()["space_id"] == scope["space_id"]

    revocable = client.post(
        f"{tenant_base}/membership-invitations",
        json={"email": "revocable@example.com", "tenant_role": "member"},
        headers={**headers, "Idempotency-Key": "http-member-invite-revocable"},
    )
    revoked = client.post(
        f"{tenant_base}/membership-invitations/{revocable.json()['invitation_id']}/revoke",
        json={"expected_version": 1, "reason": "requester changed teams"},
        headers={**headers, "Idempotency-Key": "http-member-invite-revoke"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["version"] == 2

    viewer_id = scope["viewer_id"]
    promoted = client.put(
        f"{tenant_base}/members/{viewer_id}/role",
        json={
            "role": "admin",
            "expected_version": 1,
            "reason": "on-call Tenant administration rotation",
        },
        headers={**headers, "Idempotency-Key": "http-member-promote-admin"},
    )
    assert promoted.status_code == 200
    assert promoted.json()["membership_version"] == 2

    demoted = client.put(
        f"{tenant_base}/members/{viewer_id}/role",
        json={
            "role": "member",
            "expected_version": 2,
            "reason": "on-call rotation ended",
        },
        headers={**headers, "Idempotency-Key": "http-member-demote-admin"},
    )
    assert demoted.status_code == 200

    space_role = client.put(
        f"{tenant_base}/spaces/{scope['space_id']}/members/{viewer_id}/role",
        json={
            "role": "operator",
            "expected_version": 1,
            "reason": "grant deployment operations access",
        },
        headers={**headers, "Idempotency-Key": "http-member-space-operator"},
    )
    assert space_role.status_code == 200

    suspended = client.post(
        f"{tenant_base}/members/{viewer_id}/suspend",
        json={"expected_version": 3, "reason": "temporary access hold"},
        headers={**headers, "Idempotency-Key": "http-member-suspend"},
    )
    assert suspended.status_code == 200
    resumed = client.post(
        f"{tenant_base}/members/{viewer_id}/resume",
        json={"expected_version": 4, "reason": "access review completed"},
        headers={**headers, "Idempotency-Key": "http-member-resume"},
    )
    assert resumed.status_code == 200

    filtered = client.get(f"{tenant_base}/members?query=viewer%40example.com")
    assert filtered.status_code == 200
    assert [item["user_id"] for item in filtered.json()["items"]] == [viewer_id]
    assert filtered.json()["items"][0]["tenant_status"] == "active"
    assert filtered.json()["items"][0]["space_access"][0]["role"] == "operator"
