from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase
from saas.control_plane.platform_http import PlatformHttpConfig, create_platform_admin_app
from saas.control_plane.platform_lifecycle import PlatformLifecycleService
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSessionService,
    StaffIdentityAssertion,
)

ORIGIN = "https://platform-admin.example.test"
AUDIENCE = "omnigent-platform-admin"


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
