from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase
from saas.control_plane.platform_http import PlatformHttpConfig, create_platform_admin_app
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSessionService,
    StaffIdentityAssertion,
)
from saas.control_plane.privacy_lifecycle import DeletionEvidenceKey, PrivacyLifecycleService

ORIGIN = "https://platform-admin.example.test"
AUDIENCE = "omnigent-platform-admin"


def test_privacy_http_requires_staff_cookie_permission_csrf_and_exact_manifest() -> None:
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
        identity_connection_ref="staff-idp:privacy-http",
        issuer="https://staff-idp.example.test",
        subject="privacy-http",
        now=now,
    )
    roleless_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:privacy-http-roleless",
        issuer="https://staff-idp.example.test",
        subject="privacy-http-roleless",
        now=now,
    )
    user_id = uuid4()
    with factory.begin() as db:
        db.add_all(
            [
                GlobalUser(
                    id=user_id,
                    status="active",
                    display_name="HTTP Privacy Subject",
                    primary_email_normalized="privacy-http@example.test",
                    security_version=1,
                    created_at=now,
                    updated_at=now,
                ),
                PlatformRoleAssignmentRecord(
                    principal_id=operator_id,
                    role="compliance_operator",
                    status="active",
                    version=1,
                    assigned_by_principal_id=roleless_id,
                    approval_ref="bootstrap-privacy-http",
                    reason="PC5 privacy HTTP acceptance",
                    created_at=now,
                    updated_at=now,
                ),
            ]
        )
    operator_session = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="privacy-http",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    roleless_session = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="privacy-http-roleless",
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
            privacy=PrivacyLifecycleService(
                factory,
                evidence_verifier=DeletionEvidenceKey("privacy-http-key", b"h" * 32),
            ),
        ),
        base_url=ORIGIN,
    )
    path = f"/v2/platform-admin/privacy/global_user/{user_id}"

    assert client.get(f"{path}/deletion-preview").status_code == 401
    client.cookies.set(config.cookie_name, roleless_session.token)
    assert client.get(f"{path}/deletion-preview").status_code == 403

    client.cookies.clear()
    client.cookies.set(config.cookie_name, operator_session.token)
    preview = client.get(f"{path}/deletion-preview")
    assert preview.status_code == 200
    assert preview.json()["content_access"] == "none"
    assert preview.json()["blockers"] == []

    hold_command = {
        "scope": ["identity", "audit"],
        "authority_ref": "case-http-100",
        "reason": "verified preservation order",
        "review_due_at": (now + timedelta(days=30)).isoformat(),
    }
    assert (
        client.post(
            f"{path}/legal-holds", headers={"Origin": ORIGIN}, json=hold_command
        ).status_code
        == 403
    )
    headers = {
        "Origin": ORIGIN,
        "X-CSRF-Token": operator_session.csrf_token,
    }
    hold = client.post(f"{path}/legal-holds", headers=headers, json=hold_command)
    assert hold.status_code == 201
    assert hold.json()["status"] == "active"
    assert hold.json()["review_due_at"] == (now + timedelta(days=30)).isoformat()
    blocked = client.get(f"{path}/deletion-preview")
    assert blocked.json()["blockers"] == ["active_legal_hold"]

    released = client.post(
        f"{path}/legal-holds/{hold.json()['hold_id']}/release",
        headers=headers,
        json={"expected_version": 1, "reason": "preservation order released"},
    )
    assert released.status_code == 200
    assert released.json()["status"] == "released"

    ready = client.get(f"{path}/deletion-preview").json()
    started = client.post(
        f"{path}/deletions",
        headers={**headers, "Idempotency-Key": "privacy-http-delete-1"},
        json={
            "expected_target_version": ready["target_version"],
            "preview_hash": ready["preview_hash"],
            "approval_ref": "privacy-http-approval",
            "reason": "verified erasure request",
        },
    )
    assert started.status_code == 202
    assert started.json()["status"] == "executing"
    assert len(started.json()["surface_outcomes"]) == 15
    manifest = client.get(f"{path}/deletions/{started.json()['manifest_id']}")
    assert manifest.status_code == 200
    assert manifest.json()["manifest_id"] == started.json()["manifest_id"]
