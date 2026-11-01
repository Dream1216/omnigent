from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import GlobalUser, IdentityManagementService, SaasBase
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    IdentityConnection,
    PasswordCredential,
    Tenant,
)
from saas.control_plane.federated_sessions import ExternalSessionIdentity
from saas.control_plane.identity import VerifiedIdentityAssertion
from saas.control_plane.identity_event_models import IdentityProviderStateRecord
from saas.control_plane.identity_events import (
    IdentityNotification,
    IdentitySyncError,
    ProviderIdentityState,
)
from saas.control_plane.identity_inbox import IdentitySyncPolicy
from saas.control_plane.identity_sync import IdentityStateSyncService
from saas.control_plane.lifecycle import LifecycleError, MembershipLifecycleService

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)
ISSUER = "https://auth.example.test"
SUBJECT = "stable-customer-uuid"


class Provider:
    def __init__(self):
        self.state = ProviderIdentityState(
            ISSUER,
            "customers",
            SUBJECT,
            True,
            "customer-login",
            "owner@example.test",
            True,
            password_configured=True,
            password_revision_sha256="a" * 64,
            password_changed_at=NOW - timedelta(days=1),
        )
        self.error = None
        self.calls = []
        self.before_read = lambda: None

    def read_identity(self, subject):
        self.before_read()
        self.calls.append(subject)
        if self.error:
            raise self.error
        return self.state


@dataclass
class Source:
    sessions: sessionmaker[Session]
    service: IdentityStateSyncService
    provider: Provider
    user_id: UUID
    connection_id: UUID
    lifecycle: MembershipLifecycleService

    def sync(self, *, at=NOW, **changes):
        self.provider.state = replace(self.provider.state, **changes)
        claim = self.service.claim(self.connection_id, force=True, now=at)
        assert claim is not None
        return self.service.process(claim, now=at)

    def session(self, *, at=NOW, issued_at=None):
        return self.lifecycle.issue_auth_session(
            user_id=self.user_id,
            authn_method="oidc:casdoor",
            now=at,
            expires_at=at + timedelta(hours=1),
            external_identity=ExternalSessionIdentity(
                "casdoor", ISSUER, SUBJECT, issued_at or at - timedelta(seconds=1)
            ),
        )


@pytest.fixture
def source():
    engine = sa.create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    identities = IdentityManagementService(sessions)
    user_id = identities.provision_identity(
        VerifiedIdentityAssertion("casdoor", ISSUER, SUBJECT, "owner@example.test", True)
    )
    with sessions() as db:
        connection_id = db.scalar(sa.select(IdentityConnection.id))
    provider = Provider()
    service = IdentityStateSyncService(
        sessions,
        provider=provider,
        policy=IdentitySyncPolicy(issuer=ISSUER, organization="customers"),
    )
    try:
        yield Source(
            sessions,
            service,
            provider,
            user_id,
            connection_id,
            MembershipLifecycleService(sessions),
        )
    finally:
        engine.dispose()


def test_first_baseline_preserves_fresh_session_and_does_not_write_password_or_tenant(source):
    issued = source.session()
    result = source.sync()
    assert result.revoked_session_count == 0 and result.security_version == 1
    assert source.lifecycle.validate_auth_session(issued.token, now=NOW).user_id == source.user_id
    with source.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(PasswordCredential)) == 0
        row = db.get(IdentityProviderStateRecord, source.connection_id)
        assert row.claim_token is row.claim_sha256 is row.lease_expires_at is None
        data = dict(db.execute(sa.select(IdentityProviderStateRecord.__table__)).mappings().one())
        serialized = json.dumps(data, default=str)
        assert SUBJECT not in serialized and "customer-login" not in serialized
        assert "owner@example.test" not in serialized
        assert (db.get(GlobalUser, source.user_id).credential_owner) == "casdoor"


@pytest.mark.parametrize(
    "change",
    [{"disabled": True}, {"deleted": True}, {"exists": False}, {"normal_customer": False}],
)
def test_observed_unusable_identity_revokes_sessions_and_blocks_even_fresh_login(source, change):
    source.sync()
    old = source.session(at=NOW + timedelta(seconds=1))
    result = source.sync(at=NOW + timedelta(seconds=2), **change)
    assert result.security_version == 2 and result.revoked_session_count == 1
    with pytest.raises(LifecycleError, match="session is invalid"):
        source.lifecycle.validate_auth_session(old.token, now=NOW + timedelta(seconds=3))
    with pytest.raises(LifecycleError, match="connection is unavailable"):
        source.session(at=NOW + timedelta(seconds=3))
    with source.sessions() as db:
        assert db.get(IdentityConnection, source.connection_id).status == "active"
        assert db.get(GlobalUser, source.user_id).status == "active"


def test_same_second_password_revision_change_revokes_once_and_fences_old_callback(source):
    source.sync()
    old = source.session(at=NOW + timedelta(seconds=1))
    changed = NOW + timedelta(seconds=2)
    result = source.sync(at=changed, password_revision_sha256="b" * 64)
    assert result.security_version == 2 and result.revoked_session_count == 1
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(old.token, now=changed)
    with pytest.raises(LifecycleError, match="identity session ended"):
        source.session(at=changed + timedelta(seconds=1), issued_at=changed)
    fresh = source.session(at=changed + timedelta(seconds=2))
    repeated = source.sync(at=changed + timedelta(seconds=3))
    assert repeated.security_version == 2 and repeated.revoked_session_count == 0
    assert source.lifecycle.validate_auth_session(fresh.token, now=changed + timedelta(seconds=4))


def test_reset_before_first_baseline_revokes_preexisting_session_and_blocks_inflight_token(source):
    old = source.session(at=NOW, issued_at=NOW - timedelta(seconds=3))
    result = source.sync(password_changed_at=NOW - timedelta(seconds=2))
    assert result.security_version == 2 and result.revoked_session_count == 1
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(old.token, now=NOW)
    with pytest.raises(LifecycleError, match="identity session ended"):
        source.session(issued_at=NOW - timedelta(seconds=2))


def test_verified_contact_change_does_not_merge_users_and_unverified_contact_is_not_persisted(
    source,
):
    other = IdentityManagementService(source.sessions).provision_identity(
        VerifiedIdentityAssertion("other", "urn:other", "other-user", "other@example.test", True)
    )
    source.sync()
    result = source.sync(at=NOW + timedelta(seconds=1), email="other@example.test")
    assert result.security_version == 2
    with source.sessions() as db:
        assert db.get(IdentityConnection, source.connection_id).user_id == source.user_id != other
        assert db.get(GlobalUser, source.user_id).primary_email_normalized == "other@example.test"
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 2
    result = source.sync(
        at=NOW + timedelta(seconds=2), email="unverified@example.test", email_verified=False
    )
    assert result.security_version == 3
    with source.sessions() as db:
        assert db.get(IdentityConnection, source.connection_id).email_normalized is None
        assert db.get(GlobalUser, source.user_id).primary_email_normalized is None
        payloads = json.dumps(list(db.scalars(sa.select(ControlPlaneOutboxEvent.payload))))
        applied = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent.payload).where(
                    ControlPlaneOutboxEvent.event_type == "identity.provider_state.applied"
                )
            )
        )
        assert "unverified@example.test" not in payloads
        assert "other@example.test" not in json.dumps(applied)


def test_disabled_may_reenable_but_deleted_identity_never_automatically_reactivates(source):
    source.sync(disabled=True)
    result = source.sync(at=NOW + timedelta(seconds=1), disabled=False)
    assert result.status == "active" and result.security_version == 3
    assert source.session(at=NOW + timedelta(seconds=3))
    source.sync(at=NOW + timedelta(seconds=4), deleted=True)
    source.provider.state = replace(source.provider.state, deleted=False)
    assert (
        source.service.claim(source.connection_id, force=True, now=NOW + timedelta(hours=1))
        is None
    )
    assert source.service.claim_due(now=NOW + timedelta(hours=1)) is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"subject": "forged"},
        {"user_id": uuid4()},
        {"security_version": 2},
        {"email_verified": False},
        {"lease_expires_at": NOW + timedelta(hours=1)},
    ],
)
def test_durable_claim_descriptor_cannot_be_forged_with_original_token(source, mutation):
    claim = source.service.claim(source.connection_id, now=NOW)
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        source.service.apply(replace(claim, **mutation), source.provider.state, now=NOW)
    assert source.service.apply(claim, source.provider.state, now=NOW)


@pytest.mark.parametrize("mutation", ["security_version", "revoked", "suspended", "contact"])
def test_account_or_connection_change_during_network_read_rejects_stale_result(source, mutation):
    claim = source.service.claim(source.connection_id, now=NOW)
    with source.sessions.begin() as db:
        if mutation == "security_version":
            db.get(GlobalUser, source.user_id).security_version += 1
        elif mutation == "suspended":
            db.get(GlobalUser, source.user_id).status = "suspended"
        elif mutation == "contact":
            db.get(IdentityConnection, source.connection_id).email_normalized = "new@example.test"
        else:
            db.get(IdentityConnection, source.connection_id).status = "revoked"
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        source.service.apply(claim, replace(source.provider.state, disabled=True), now=NOW)
    with source.sessions() as db:
        assert db.get(IdentityProviderStateRecord, source.connection_id).checked_at is None


def test_expired_lease_cannot_commit_and_replacement_worker_converges(source):
    first = source.service.claim_due(now=NOW)
    assert first is not None and source.service.claim_due(now=NOW) is None
    later = NOW + source.service.policy.provider_lease
    second = source.service.claim_due(now=later)
    assert second is not None and second.token != first.token
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        source.service.apply(first, source.provider.state, now=later)
    assert source.service.process(second, now=later)
    assert source.service.claim_due(now=later + timedelta(seconds=59)) is None
    assert source.service.claim_due(now=later + timedelta(seconds=60)) is not None


@pytest.mark.parametrize(
    "mutation",
    [
        {"subject": "different-user"},
        {"organization": "another"},
        {"issuer": "https://other.test"},
        {"password_revision_sha256": None},
        {"password_changed_at": NOW + timedelta(minutes=2)},
        {"email": "malformed"},
    ],
)
def test_invalid_readback_is_operational_failure_and_does_not_invent_deletion(source, mutation):
    old = source.session()
    source.provider.state = replace(source.provider.state, **mutation)
    claim = source.service.claim_due(now=NOW)
    with pytest.raises(IdentitySyncError, match="response_invalid"):
        source.service.process(claim, now=NOW)
    with source.sessions() as db:
        row = db.get(IdentityProviderStateRecord, source.connection_id)
        assert row.status == "active" and row.snapshot_sha256 is None
        assert row.last_error_code == "identity_provider_response_invalid"
        assert row.claim_token is row.claim_sha256 is row.lease_expires_at is None
    assert source.lifecycle.validate_auth_session(old.token, now=NOW)


def test_provider_outage_preserves_sessions_retries_and_network_runs_outside_transaction(source):
    old = source.session()
    claim = source.service.claim_due(now=NOW)
    source.provider.error = IdentitySyncError("secret provider response", retryable=True)
    with pytest.raises(IdentitySyncError):
        source.service.process(claim, now=NOW)
    assert source.lifecycle.validate_auth_session(old.token, now=NOW)
    assert source.service.claim_due(now=NOW + timedelta(seconds=1)) is None
    with source.sessions() as db:
        row = db.get(IdentityProviderStateRecord, source.connection_id)
        assert row.last_error_code == "identity_sync_failed"
    source.provider.error = None
    source.provider.before_read = lambda: source.lifecycle.validate_auth_session(
        old.token, now=NOW
    )
    assert source.service.process(
        source.service.claim_due(now=NOW + timedelta(seconds=2)), now=NOW + timedelta(seconds=2)
    )


def test_late_duplicate_security_event_does_not_revoke_new_session(source):
    source.sync()
    old = source.session(at=NOW + timedelta(seconds=1))
    event = IdentityNotification(
        "reset-1",
        "set-password",
        "customers",
        SUBJECT,
        "customer-login",
        NOW + timedelta(seconds=2),
        True,
    )
    source.service.inbox.ingest(event, now=NOW + timedelta(seconds=3))
    assert source.service.process_next_event(now=NOW + timedelta(seconds=3))
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(old.token, now=NOW + timedelta(seconds=3))
    fresh = source.session(at=NOW + timedelta(seconds=5))
    source.service.inbox.ingest(
        replace(event, event_id="reset-duplicate"), now=NOW + timedelta(seconds=6)
    )
    assert source.service.process_next_event(now=NOW + timedelta(seconds=6))
    assert source.lifecycle.validate_auth_session(fresh.token, now=NOW + timedelta(seconds=7))
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).security_version == 2


def test_subject_event_never_falls_back_to_username_of_another_subject(source):
    source.sync()
    event = IdentityNotification(
        "wrong-target",
        "delete-user",
        "customers",
        "unrelated-subject",
        "customer-login",
        NOW,
        True,
    )
    source.service.inbox.ingest(event, now=NOW)
    with pytest.raises(IdentitySyncError, match="mapping_unavailable"):
        source.service.process_next_event(now=NOW)
    assert len(source.provider.calls) == 1
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).security_version == 1


def test_security_event_waits_for_first_mapping_instead_of_losing_transient_disable(source):
    old = source.session()
    event = IdentityNotification(
        "initial-disable",
        "update-user",
        "customers",
        SUBJECT,
        "customer-login",
        NOW + timedelta(seconds=1),
        True,
    )
    source.service.inbox.ingest(event, now=NOW + timedelta(seconds=2))
    with pytest.raises(IdentitySyncError, match="mapping_unavailable"):
        source.service.process_next_event(now=NOW + timedelta(seconds=2))
    source.sync(at=NOW + timedelta(seconds=3))
    assert source.lifecycle.validate_auth_session(old.token, now=NOW + timedelta(seconds=3))
    assert source.service.process_next_event(now=NOW + timedelta(seconds=4))
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(old.token, now=NOW + timedelta(seconds=4))


def test_event_username_lookup_always_reads_current_stored_subject(source):
    source.sync()
    event = IdentityNotification(
        "username-reset", "set-password", "customers", None, "customer-login", NOW, True
    )
    source.service.inbox.ingest(event, now=NOW)
    assert source.service.process_next_event(now=NOW)
    assert source.provider.calls == [SUBJECT, SUBJECT]


@pytest.mark.parametrize("action", ["provision", "login", "link", "reauth"])
def test_observed_disabled_identity_cannot_bypass_cached_state_through_identity_operations(
    source, action
):
    source.sync(disabled=True)
    identities = IdentityManagementService(source.sessions)
    assertion = VerifiedIdentityAssertion("casdoor", ISSUER, SUBJECT, "owner@example.test", True)
    with pytest.raises(LifecycleError):
        if action == "provision":
            identities.provision_identity(assertion)
        elif action == "login":
            identities.resolve_verified_login(assertion)
        elif action == "reauth":
            identities.require_reauthentication_identity(
                user_id=source.user_id, assertion=assertion
            )
        else:
            identities.link_identity(
                user_id=source.user_id, assertion=assertion, idempotency_key="link-disabled"
            )


def test_disabled_provider_cannot_count_as_backup_for_last_login_method(source):
    identities = IdentityManagementService(source.sessions)
    backup = identities.link_identity(
        user_id=source.user_id,
        assertion=VerifiedIdentityAssertion("other", "urn:other", "backup-user", None, False),
        idempotency_key="backup",
    )
    source.sync(disabled=True)
    with pytest.raises(LifecycleError, match="last login method"):
        identities.revoke_identity(
            user_id=source.user_id, connection_id=backup, idempotency_key="revoke-backup"
        )
