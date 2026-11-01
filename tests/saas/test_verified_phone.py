from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import GlobalUser, IdentityConnection, PasswordCredential
from saas.control_plane.identity import IdentityManagementService, VerifiedIdentityAssertion
from saas.control_plane.identity_events import IdentitySyncError, ProviderIdentityState
from saas.control_plane.identity_inbox import IdentitySyncPolicy
from saas.control_plane.identity_sync import IdentityStateSyncService
from saas.control_plane.lifecycle import LifecycleError, MembershipLifecycleService
from tests.saas.test_identity_sync import ISSUER, NOW, SUBJECT, Provider
from tests.saas.test_identity_sync import source as source
from tests.saas.test_onboarding_http import TRUSTED_ORIGIN
from tests.saas.test_workspace_creation import workspace_http as workspace_http

PHONE = "+12025550100"


@pytest.mark.parametrize(
    "phone,verified",
    [
        (None, True),
        ("2025550100", True),
        ("+1 2025550100", True),
        ("+01234", True),
        ("+1234567890123456", True),
        (PHONE, "true"),
        (123, False),
    ],
)
def test_phone_proof_requires_canonical_number_and_exact_boolean(phone, verified):
    assertion = VerifiedIdentityAssertion(
        "casdoor",
        ISSUER,
        "new-phone",
        None,
        False,
        phone_number=phone,
        phone_number_verified=verified,
    )
    with pytest.raises(LifecycleError, match="phone ownership assertion"):
        assertion.validate()


def test_same_phone_does_not_merge_subjects_or_create_email_password(source):
    identities = IdentityManagementService(source.sessions)
    first = VerifiedIdentityAssertion(
        "casdoor",
        ISSUER,
        "phone-first",
        None,
        False,
        phone_number=PHONE,
        phone_number_verified=True,
    )
    one = identities.resolve_verified_login(first)
    two = identities.resolve_verified_login(replace(first, subject="phone-second"))
    assert one.user_id != two.user_id and one.conflict_id is two.conflict_id is None
    assert identities.resolve_verified_login(first).user_id == one.user_id
    with source.sessions() as db:
        user = db.get(GlobalUser, one.user_id)
        connection = db.scalar(
            sa.select(IdentityConnection).where(IdentityConnection.user_id == one.user_id)
        )
        assert user.primary_email_normalized is None and user.credential_owner == "casdoor"
        assert connection.phone_e164 == PHONE and connection.phone_verified is True
        assert connection.email_normalized is None and connection.email_verified is False
        assert db.get(PasswordCredential, one.user_id) is None


def test_unverified_phone_claim_is_not_stored_as_ownership(source):
    identities = IdentityManagementService(source.sessions)
    key = identities.provision_identity(
        VerifiedIdentityAssertion(
            "casdoor", ISSUER, "unverified-phone", None, False, phone_number=PHONE
        )
    )
    with source.sessions() as db:
        row = db.scalar(sa.select(IdentityConnection).where(IdentityConnection.user_id == key))
        assert row.phone_e164 is None and row.phone_verified is False


def test_phone_change_or_removed_proof_invalidates_sessions_without_changing_user(source):
    source.sync(phone_e164=PHONE, phone_verified=True)
    issued = source.session(at=NOW + timedelta(seconds=1), issued_at=NOW + timedelta(seconds=1))
    result = source.sync(
        at=NOW + timedelta(seconds=2), phone_e164="+12025550101", phone_verified=True
    )
    assert result.revoked_session_count == 1
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(issued.token, now=NOW + timedelta(seconds=3))
    with source.sessions() as db:
        row = db.get(IdentityConnection, source.connection_id)
        assert row.user_id == source.user_id and row.subject == SUBJECT
        assert row.phone_e164 == "+12025550101" and row.phone_verified
    source.sync(at=NOW + timedelta(seconds=4), phone_verified=False)
    with source.sessions() as db:
        row = db.get(IdentityConnection, source.connection_id)
        assert row.phone_e164 is None and not row.phone_verified


def test_phone_snapshot_is_fenced_even_if_timestamp_is_unchanged(source):
    claim = source.service.claim(source.connection_id, force=True, now=NOW)
    with source.sessions.begin() as db:
        db.execute(
            sa.text(
                "UPDATE saas_identity_connections "
                "SET phone_e164=:phone,phone_verified=true WHERE id=:id"
            ),
            {"phone": PHONE, "id": source.connection_id.hex},
        )
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        source.service.process(claim, now=NOW)


def test_phone_workspace_requires_authoritative_current_proof_and_no_email(workspace_http):
    harness = workspace_http
    subject = str(uuid4())
    identities = IdentityManagementService(harness.sessions)
    actor = identities.provision_identity(
        VerifiedIdentityAssertion(
            "casdoor", ISSUER, subject, None, False, phone_number=PHONE, phone_number_verified=True
        )
    )
    now = datetime.now(timezone.utc)
    issued = MembershipLifecycleService(harness.sessions).issue_auth_session(
        user_id=actor, authn_method="oidc:casdoor", expires_at=now + timedelta(hours=1)
    )
    harness.client.cookies.set("saas_session", issued.token)
    headers = {
        "Origin": TRUSTED_ORIGIN,
        "X-CSRF-Token": issued.csrf_token,
        "Idempotency-Key": "phone-workspace",
    }
    endpoint = "/saas/onboarding/workspaces"
    missing = harness.client.post(endpoint, headers=headers, json={"tenant_name": "手机工作空间"})
    assert (
        missing.status_code == 503
        and missing.json()["detail"]["code"] == "identity_verification_pending"
    )
    assert missing.headers["retry-after"] == "5"
    provider = Provider()
    provider.state = ProviderIdentityState(
        ISSUER,
        "customers",
        subject,
        True,
        username="phone-user",
        password_configured=True,
        password_revision_sha256="a" * 64,
        phone_e164=PHONE,
        phone_verified=True,
    )
    sync = IdentityStateSyncService(
        harness.sessions,
        provider=provider,
        policy=IdentitySyncPolicy(issuer=ISSUER, organization="customers"),
    )
    with harness.sessions() as db:
        connection_id = db.scalar(
            sa.select(IdentityConnection.id).where(IdentityConnection.user_id == actor)
        )
    claim = sync.claim(connection_id, force=True, now=now)
    result = sync.process(claim, now=now)
    assert result.revoked_session_count == 0
    accepted = harness.client.post(endpoint, headers=headers, json={"tenant_name": "手机工作空间"})
    assert accepted.status_code == 202
    replay = harness.client.post(endpoint, headers=headers, json={"tenant_name": "手机工作空间"})
    assert replay.status_code == 202 and replay.json()["id"] == accepted.json()["id"]
    with harness.sessions() as db:
        user = db.get(GlobalUser, actor)
        row = db.get(IdentityConnection, connection_id)
        assert (
            user.primary_email_normalized is None
            and row.email_normalized is None
            and not row.email_verified
        )
