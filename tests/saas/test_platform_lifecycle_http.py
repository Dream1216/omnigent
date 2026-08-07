from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import (
    GlobalUser,
    IdentityConflict,
    SaasBase,
    Tenant,
    TenantMembership,
)
from saas.control_plane.platform_governed_access import (
    AuditSigningKey,
    PlatformGovernedAccessService,
    TenantSupportActor,
)
from saas.control_plane.platform_http import PlatformHttpConfig, create_platform_admin_app
from saas.control_plane.platform_lifecycle import PlatformLifecycleService
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformTenantProjectionRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSessionService,
    StaffIdentityAssertion,
)

ORIGIN = "https://platform-admin.example.test"
AUDIENCE = "omnigent-platform-admin"


def test_platform_governed_support_http_runs_staff_request_approval_session_and_revoke() -> None:
    now = datetime.now(timezone.utc)
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=ORIGIN, audience=AUDIENCE)
    support_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:http-support",
        issuer="https://staff-idp.example.test",
        subject="http-support",
        now=now,
    )
    operator_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:http-support-operator",
        issuer="https://staff-idp.example.test",
        subject="http-support-operator",
        now=now,
    )
    customer_id, tenant_id = uuid4(), uuid4()
    with factory.begin() as db:
        db.add_all(
            [
                GlobalUser(
                    id=customer_id,
                    status="active",
                    security_version=1,
                    created_at=now,
                    updated_at=now,
                ),
                Tenant(
                    id=tenant_id,
                    slug=f"pc3-http-{tenant_id.hex}",
                    name="PC3 HTTP Tenant",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    lifecycle_version=1,
                    created_at=now,
                    updated_at=now,
                ),
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=customer_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=now,
                ),
                PlatformTenantProjectionRecord(
                    tenant_id=tenant_id,
                    slug=f"pc3-http-{tenant_id.hex}",
                    name="PC3 HTTP Tenant",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    member_count=1,
                    space_count=0,
                    source_version=1,
                    updated_at=now,
                ),
                PlatformRoleAssignmentRecord(
                    principal_id=support_id,
                    role="support_agent",
                    status="active",
                    version=1,
                    assigned_by_principal_id=operator_id,
                    approval_ref="bootstrap-http-support",
                    reason="PC3 HTTP support acceptance",
                    created_at=now,
                    updated_at=now,
                ),
                PlatformRoleAssignmentRecord(
                    principal_id=operator_id,
                    role="platform_operator",
                    status="active",
                    version=1,
                    assigned_by_principal_id=support_id,
                    approval_ref="bootstrap-http-support-operator",
                    reason="PC3 HTTP approval acceptance",
                    created_at=now,
                    updated_at=now,
                ),
            ]
        )
    support_session = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="http-support",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    operator_session = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="http-support-operator",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    governed = PlatformGovernedAccessService(
        factory,
        signing_key=AuditSigningKey(key_id="http-test-v1", secret=b"h" * 32),
    )
    config = PlatformHttpConfig(enabled=True, origin=ORIGIN, audience=AUDIENCE)
    client = TestClient(
        create_platform_admin_app(
            config=config,
            sessions=sessions,
            authorization=authorization,
            projections=PlatformProjectionService(factory),
            governed_access=governed,
        ),
        base_url=ORIGIN,
    )
    client.cookies.set(config.cookie_name, support_session.token)
    support_headers = {
        "Origin": ORIGIN,
        "X-CSRF-Token": support_session.csrf_token,
        "Idempotency-Key": "pc3-http-request",
    }
    requested = client.post(
        "/v2/platform-admin/support-access-grants",
        headers=support_headers,
        json={
            "tenant_id": str(tenant_id),
            "mode": "standard",
            "scopes": ["runtime.diagnostics.read"],
            "project_ids": [],
            "reason": "tenant-authorized HTTP diagnostics",
            "incident_ref": None,
            "expires_at": (now + timedelta(minutes=30)).isoformat(),
        },
    )
    assert requested.status_code == 201
    grant_id = requested.json()["grant_id"]
    assert requested.json()["status"] == "pending_customer_approval"

    governed.decide_customer_approval(
        TenantSupportActor(
            actor_id=customer_id,
            tenant_id=tenant_id,
            security_version=1,
        ),
        grant_id=UUID(grant_id),
        expected_version=1,
        decision="approve",
        reason="Tenant Owner confirms diagnostics",
        reauthenticated_at=now,
        idempotency_key="pc3-http-customer-approve",
        now=now + timedelta(seconds=1),
    )

    client.cookies.clear()
    client.cookies.set(config.cookie_name, operator_session.token)
    operator_headers = {
        "Origin": ORIGIN,
        "X-CSRF-Token": operator_session.csrf_token,
        "Idempotency-Key": "pc3-http-staff-approve",
    }
    approved = client.post(
        f"/v2/platform-admin/support-access-grants/{grant_id}/approve",
        headers=operator_headers,
        json={"expected_version": 2, "reason": "independent Staff approval"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "active"

    client.cookies.clear()
    client.cookies.set(config.cookie_name, support_session.token)
    issued = client.post(
        f"/v2/platform-admin/support-access-grants/{grant_id}/sessions",
        headers={**support_headers, "Idempotency-Key": "pc3-http-session"},
        json={"expected_version": 3},
    )
    assert issued.status_code == 201
    assert issued.json()["one_time_disclosure"] is True
    assert issued.json()["token"]

    client.cookies.clear()
    client.cookies.set(config.cookie_name, operator_session.token)
    revoked = client.post(
        f"/v2/platform-admin/support-access-grants/{grant_id}/revoke",
        headers={**operator_headers, "Idempotency-Key": "pc3-http-revoke"},
        json={"expected_version": 3, "reason": "support task complete"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"


def test_platform_user_lifecycle_http_requires_staff_cookie_csrf_permission_and_idempotency() -> (
    None
):
    now = datetime.now(timezone.utc)
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=ORIGIN, audience=AUDIENCE)
    operator_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:http-operator",
        issuer="https://staff-idp.example.test",
        subject="http-operator",
        now=now,
    )
    roleless_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:http-roleless",
        issuer="https://staff-idp.example.test",
        subject="http-roleless",
        now=now,
    )
    user_id = uuid4()
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                principal_id=operator_id,
                role="platform_operator",
                status="active",
                version=1,
                assigned_by_principal_id=roleless_id,
                approval_ref="bootstrap-http-operator",
                reason="PC2 HTTP acceptance",
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            GlobalUser(
                id=user_id,
                status="active",
                security_version=1,
                created_at=now,
                updated_at=now,
            )
        )
    operator = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="http-operator",
            authn_method="webauthn",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    roleless = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="http-roleless",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    config = PlatformHttpConfig(enabled=True, origin=ORIGIN, audience=AUDIENCE)
    app = create_platform_admin_app(
        config=config,
        sessions=sessions,
        authorization=authorization,
        projections=PlatformProjectionService(factory),
        lifecycle=PlatformLifecycleService(factory),
    )
    client = TestClient(app, base_url=ORIGIN)
    body = {
        "expected_version": 1,
        "approval_ref": "approval-http-user-suspend",
        "reason": "verified account compromise",
    }
    client.cookies.set(config.cookie_name, operator.token)
    no_csrf = client.post(
        f"/v2/platform-admin/users/{user_id}/suspend",
        json=body,
        headers={"Origin": ORIGIN, "Idempotency-Key": "http-user-suspend"},
    )
    assert no_csrf.status_code == 403
    assert no_csrf.json()["error"]["code"] == "platform_csrf_invalid"

    client.cookies.clear()
    client.cookies.set(config.cookie_name, roleless.token)
    denied = client.post(
        f"/v2/platform-admin/users/{user_id}/suspend",
        json=body,
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": roleless.csrf_token,
            "Idempotency-Key": "http-user-suspend-roleless",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "platform_permission_denied"

    client.cookies.clear()
    client.cookies.set(config.cookie_name, operator.token)
    headers = {
        "Origin": ORIGIN,
        "X-CSRF-Token": operator.csrf_token,
        "Idempotency-Key": "http-user-suspend",
        "X-Request-ID": "pc2-http-request",
    }
    suspended = client.post(
        f"/v2/platform-admin/users/{user_id}/suspend",
        json=body,
        headers=headers,
    )
    assert suspended.status_code == 200
    assert suspended.json()["request_id"] == "pc2-http-request"
    assert suspended.json()["result"]["status"] == "suspended"
    assert suspended.json()["result"]["security_version"] == 2
    assert suspended.json()["replayed"] is False

    replayed = client.post(
        f"/v2/platform-admin/users/{user_id}/suspend",
        json=body,
        headers=headers,
    )
    assert replayed.status_code == 200
    assert replayed.json()["operation_id"] == suspended.json()["operation_id"]
    assert replayed.json()["replayed"] is True


def test_platform_identity_conflict_http_is_content_blind_and_two_stage() -> None:
    now = datetime.now(timezone.utc)
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=ORIGIN, audience=AUDIENCE)
    operator_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:conflict-operator",
        issuer="https://staff-idp.example.test",
        subject="conflict-operator",
        now=now,
    )
    approver_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:conflict-approver",
        issuer="https://staff-idp.example.test",
        subject="conflict-approver",
        now=now,
    )
    candidate_id, conflict_id = uuid4(), uuid4()
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                principal_id=operator_id,
                role="platform_operator",
                status="active",
                version=1,
                assigned_by_principal_id=approver_id,
                approval_ref="bootstrap-conflict-operator",
                reason="PC2 conflict HTTP acceptance",
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            GlobalUser(
                id=candidate_id,
                status="active",
                security_version=1,
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            IdentityConflict(
                id=conflict_id,
                provider="oidc",
                issuer="https://private-idp.example.test",
                subject="private-subject",
                email_normalized="private@example.test",
                status="pending",
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
    issued = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="conflict-operator",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    config = PlatformHttpConfig(enabled=True, origin=ORIGIN, audience=AUDIENCE)
    client = TestClient(
        create_platform_admin_app(
            config=config,
            sessions=sessions,
            authorization=authorization,
            projections=PlatformProjectionService(factory),
            lifecycle=PlatformLifecycleService(factory),
        ),
        base_url=ORIGIN,
    )
    client.cookies.set(config.cookie_name, issued.token)
    listed = client.get("/v2/platform-admin/identity-conflicts")
    assert listed.status_code == 200
    assert listed.json()["content_access"] == "none"
    assert listed.json()["items"][0]["conflict_id"] == str(conflict_id)
    encoded = listed.text
    assert "private@example.test" not in encoded
    assert "private-subject" not in encoded
    assert "private-idp.example.test" not in encoded

    assigned = client.post(
        f"/v2/platform-admin/identity-conflicts/{conflict_id}/assign",
        json={
            "candidate_user_id": str(candidate_id),
            "expected_version": 1,
            "approval_ref": "approval-conflict-http",
            "reason": "enterprise directory ownership verified",
        },
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": issued.csrf_token,
            "Idempotency-Key": "identity-conflict-http-assign",
        },
    )
    assert assigned.status_code == 200
    assert assigned.json()["result"]["platform_review_status"] == "assigned"
    assert assigned.json()["result"]["identity_connection_created"] is False
