from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    PlatformAuthorizationService,
    PlatformHttpConfig,
    PlatformProjectionService,
    PlatformRoleAssignmentRecord,
    PlatformSessionService,
    SaasBase,
    StaffIdentityAssertion,
    TenantProjectionInput,
    UserProjectionInput,
    create_platform_admin_app,
)

ORIGIN = "https://platform-admin.example.test"
AUDIENCE = "omnigent-platform-admin"
NOW = datetime(2026, 8, 7, 13, 0, tzinfo=timezone.utc)


def _app(*, enabled: bool = True):
    session_now = datetime.now(timezone.utc)
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=ORIGIN, audience=AUDIENCE)
    projections = PlatformProjectionService(factory)
    operator_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:operator",
        issuer="https://staff-idp.example.test",
        subject="operator",
        now=NOW,
    )
    roleless_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:roleless",
        issuer="https://staff-idp.example.test",
        subject="roleless",
        now=NOW,
    )
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                principal_id=operator_id,
                role="platform_security_auditor",
                status="active",
                version=1,
                assigned_by_principal_id=roleless_id,
                approval_ref="bootstrap-approval",
                reason="bootstrap",
                created_at=NOW,
                updated_at=NOW,
            )
        )
    issued = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="operator",
            authn_method="webauthn",
            mfa_strength="phishing_resistant",
            authenticated_at=session_now,
        ),
        expires_at=session_now + timedelta(hours=1),
        now=session_now,
    )
    roleless = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="roleless",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=session_now,
        ),
        expires_at=session_now + timedelta(hours=1),
        now=session_now,
    )
    projections.upsert_tenant(
        TenantProjectionInput(
            tenant_id=uuid4(),
            slug="customer-a",
            name="Customer A",
            status="active",
            plan="team",
            home_region="cn-east-1",
            member_count=3,
            space_count=1,
            source_version=1,
            updated_at=NOW,
        )
    )
    projections.upsert_user(
        UserProjectionInput(
            user_id=uuid4(),
            status="active",
            display_name="Customer User",
            email_masked="c***@example.test",
            membership_count=1,
            security_version=7,
            source_version=1,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    config = PlatformHttpConfig(enabled=enabled, origin=ORIGIN, audience=AUDIENCE)
    app = create_platform_admin_app(
        config=config,
        sessions=sessions,
        authorization=authorization,
        projections=projections,
    )
    return config, sessions, TestClient(app, base_url=ORIGIN), issued, roleless


def test_platform_http_is_independent_origin_cookie_audience_and_content_blind() -> None:
    config, _sessions, client, issued, _roleless = _app()
    client.cookies.set(config.cookie_name, issued.token)

    context = client.get("/v2/platform-admin/context")
    assert context.status_code == 200
    assert context.json()["realm"] == "staff"
    assert context.json()["audience"] == AUDIENCE
    assert context.json()["content_access"] == "none"
    assert context.headers["cache-control"] == "private, no-store"
    assert (
        context.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    )

    permissions = client.get("/v2/platform-admin/permissions")
    assert permissions.status_code == 200
    assert permissions.json()["roles"]["platform"]
    assert all(
        not item["reads_content"]
        for item in permissions.json()["permissions"]
        if item["scope"] == "platform"
    )

    tenants = client.get("/v2/platform-admin/tenants")
    assert tenants.status_code == 200
    assert tenants.json()["items"][0]["slug"] == "customer-a"
    assert not {"prompt", "message", "artifact", "secret"} & set(tenants.json()["items"][0])

    users = client.get("/v2/platform-admin/users")
    assert users.status_code == 200
    assert users.json()["items"][0]["email_masked"] == "c***@example.test"
    assert users.json()["items"][0]["security_version"] == 7
    assert "primary_email" not in users.json()["items"][0]


def test_platform_console_shell_and_assets_require_staff_realm_session() -> None:
    config, _sessions, client, issued, roleless = _app()

    unauthenticated = client.get("/platform-admin")
    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["error"]["code"] == "platform_authentication_required"

    client.cookies.set(config.cookie_name, issued.token)
    page = client.get("/platform-admin")
    assert page.status_code == 200
    assert 'data-testid="view-overview"' in page.text
    assert 'data-testid="view-users"' in page.text
    assert 'data-testid="view-tenants"' in page.text
    assert 'data-testid="view-support"' in page.text
    assert 'data-testid="view-privacy"' in page.text
    assert 'data-testid="view-audit"' in page.text
    assert 'data-testid="operations-drawer"' in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert "'unsafe-inline'" not in page.headers["content-security-policy"]

    css = client.get("/platform-admin/assets/platform-admin.css")
    javascript = client.get("/platform-admin/assets/platform-admin.js")
    privacy_css = client.get("/platform-admin/assets/platform-privacy.css")
    privacy_javascript = client.get("/platform-admin/assets/platform-privacy.js")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert javascript.status_code == 200
    assert javascript.headers["content-type"].startswith("text/javascript")
    assert privacy_css.status_code == 200
    assert privacy_css.headers["content-type"].startswith("text/css")
    assert privacy_javascript.status_code == 200
    assert privacy_javascript.headers["content-type"].startswith("text/javascript")
    assert "innerHTML" not in javascript.text
    assert "innerHTML" not in privacy_javascript.text
    assert "platform.privacy.read" in privacy_javascript.text
    assert "principalId" in privacy_javascript.text
    assert "CONTROL-PLANE MANIFEST" in page.text

    client.cookies.clear()
    client.cookies.set(config.cookie_name, roleless.token)
    assert client.get("/platform-admin").status_code == 200
    client.cookies.set("__Host-omnigent_saas_session", "tenant-session")
    mixed_realm_asset = client.get("/platform-admin/assets/platform-admin.js")
    assert mixed_realm_asset.status_code == 401
    assert mixed_realm_asset.json()["error"]["code"] == "platform_realm_mismatch"


def test_platform_http_rejects_tenant_cookie_bearer_wrong_origin_and_roleless_actions() -> None:
    config, _sessions, client, issued, roleless = _app()
    client.cookies.set(config.cookie_name, issued.token)
    client.cookies.set("__Host-omnigent_saas_session", "tenant-token")
    mixed = client.get("/v2/platform-admin/context")
    assert mixed.status_code == 401
    assert mixed.json()["error"]["code"] == "platform_realm_mismatch"

    client.cookies.clear()
    client.cookies.set(config.cookie_name, issued.token)
    bearer = client.get(
        "/v2/platform-admin/context", headers={"Authorization": "Bearer machine-token"}
    )
    assert bearer.status_code == 401
    assert bearer.json()["error"]["code"] == "platform_realm_mismatch"

    wrong_origin = client.get(
        "/v2/platform-admin/context", headers={"Origin": "https://tenant.example.test"}
    )
    assert wrong_origin.status_code == 401
    assert wrong_origin.json()["error"]["code"] == "platform_realm_mismatch"

    client.cookies.clear()
    client.cookies.set(config.cookie_name, roleless.token)
    roleless_context = client.get("/v2/platform-admin/context")
    assert roleless_context.status_code == 200
    assert roleless_context.json()["roles"] == []
    denied = client.get("/v2/platform-admin/permissions")
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "platform_permission_denied"


def test_platform_logout_requires_exact_origin_and_csrf_then_revokes() -> None:
    config, _sessions, client, issued, _roleless = _app()
    client.cookies.set(config.cookie_name, issued.token)

    no_origin = client.post(
        "/v2/platform-admin/session/logout",
        headers={"X-CSRF-Token": issued.csrf_token},
    )
    assert no_origin.status_code == 401
    assert no_origin.json()["error"]["code"] == "platform_realm_mismatch"

    no_csrf = client.post(
        "/v2/platform-admin/session/logout",
        headers={"Origin": ORIGIN},
    )
    assert no_csrf.status_code == 403
    assert no_csrf.json()["error"]["code"] == "platform_csrf_invalid"

    logged_out = client.post(
        "/v2/platform-admin/session/logout",
        headers={"Origin": ORIGIN, "X-CSRF-Token": issued.csrf_token},
    )
    assert logged_out.status_code == 204
    assert client.get("/v2/platform-admin/context").status_code == 401


def test_platform_feature_flag_fails_closed() -> None:
    config, _sessions, client, issued, _roleless = _app(enabled=False)
    client.cookies.set(config.cookie_name, issued.token)
    disabled = client.get("/v2/platform-admin/context")
    assert disabled.status_code == 404
    assert disabled.json()["error"]["code"] == "platform_feature_disabled"
