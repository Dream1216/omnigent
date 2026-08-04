from __future__ import annotations

from uuid import uuid4

import sqlalchemy as sa
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import current_runtime_context
from saas.control_plane import (
    IdentityManagementService,
    MembershipGovernanceService,
    MembershipLifecycleService,
    PasswordCredentialService,
    RemovalImpact,
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
    VerifiedIdentityAssertion,
    create_saas_http_integration,
)


class _NoRemovalImpact:
    def collect(self, **_scope: object) -> RemovalImpact:
        return RemovalImpact(facts={"owned_resources": []}, blocking_count=0)


def _build_app() -> tuple[TestClient, dict[str, str]]:
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
    passwords.set_password(
        user_id=user_id,
        new_password="initial-http-password",
        expected_version=None,
        idempotency_key="http-initial-password",
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
                user_id=member_id,
                role="member",
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
                source_revision="2ce9c60bf57e168bdd4d7e6236e68e18ebb4bb9f",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimeIdentityAliasRecord(
                runtime_partition_id=partition_id,
                user_id=user_id,
                runtime_user_key="runtime_http_user",
                status="active",
            )
        )

    policy = RuntimeCompatibilityPolicy(
        runtime_type="omnigent",
        allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
        allowed_source_revisions=frozenset({"2ce9c60bf57e168bdd4d7e6236e68e18ebb4bb9f"}),
        allowed_schema_revisions=frozenset({"c4d5e6f7a8b9"}),
        adapter_contract_version="0.2.0",
    )
    resolver = SqlAlchemyContextResolver(sessions, policy)
    cookie = SaasCookieConfig(
        name="saas_session",
        secure=False,
        trusted_origins=frozenset({"http://testserver"}),
    )
    integration = create_saas_http_integration(
        lifecycle=lifecycle,
        identities=identities,
        passwords=passwords,
        context_resolver=resolver,
        cookie_config=cookie,
        governance=MembershipGovernanceService(sessions, _NoRemovalImpact()),
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
    return TestClient(app), {
        "tenant_id": str(tenant_id),
        "space_id": str(space_id),
        "user_id": str(user_id),
        "member_id": str(member_id),
    }


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
    csrf = _login(client)
    assert client.get("/saas/auth/me").json()["user_id"] == scope["user_id"]

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
