from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.customer_auth_restore import (
    CustomerAuthRestoreError,
    CustomerAuthRestoreService,
    restore_review_sha256,
)
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    OidcLoginTransaction,
    TenantMembership,
)
from saas.control_plane.identity_event_models import (
    IdentityEventInboxRecord,
    IdentityProviderStateRecord,
)
from saas.control_plane.identity_events import IdentityNotification, IdentitySyncError
from saas.control_plane.lifecycle import LifecycleError
from tests.saas.test_identity_sync import NOW, SUBJECT
from tests.saas.test_identity_sync import source as source

REVISION = "9" * 40


def pending_oidc(source):
    identifier = uuid4()
    with source.sessions.begin() as db:
        db.add(
            OidcLoginTransaction(
                id=identifier,
                provider="casdoor",
                state_hash="a" * 64,
                browser_binding_hash="b" * 64,
                nonce_hash="c" * 64,
                code_verifier_ciphertext="owned-unit-encrypted-verifier",
                purpose="login",
                status="pending",
                expires_at=NOW + timedelta(minutes=5),
            )
        )
    return identifier


def reviewed(source):
    service = CustomerAuthRestoreService(source.sessions, product_revision=REVISION)
    review = service.review(restore_id=uuid4(), backup_set_sha256="b" * 64, now=NOW)
    return service, review, restore_review_sha256(review)


def test_restored_sessions_transactions_and_worker_leases_fail_without_changing_authority(source):
    source.sync()
    old = source.session()
    transaction = pending_oidc(source)
    provider_claim = source.service.claim(source.connection_id, force=True, now=NOW)
    event = source.service.inbox.ingest(
        IdentityNotification(
            "restore-inflight", "update-user", "customers", SUBJECT, "customer-login", NOW
        ),
        now=NOW,
    )
    event_claim = source.service.inbox.claim_next(now=NOW)
    assert event_claim is not None
    service, review, digest = reviewed(source)
    result = service.apply(
        review, expected_sha256=digest, review_reference="owned/RESTORE-123", now=NOW
    )
    assert result["counts"] == {
        "users": 1,
        "sessions": 1,
        "oidc_transactions": 1,
        "provider_claims": 1,
        "inbox_claims": 1,
        "migration_claims": 0,
    }
    with pytest.raises(LifecycleError):
        source.lifecycle.validate_auth_session(old.token, now=NOW + timedelta(seconds=1))
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        source.service.apply(provider_claim, source.provider.state, now=NOW)
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        source.service.inbox.finish(event_claim, processed_connections=1, now=NOW)
    with source.sessions() as db:
        user = db.get(GlobalUser, source.user_id)
        assert (
            user.security_version == 2
            and user.credential_owner == "casdoor"
            and user.status == "active"
        )
        assert db.get(IdentityConnection, source.connection_id).status == "active"
        assert db.get(OidcLoginTransaction, transaction).status == "failed"
        assert db.get(IdentityProviderStateRecord, source.connection_id).claim_token is None
        inbox = db.get(IdentityEventInboxRecord, event.id)
        assert inbox.status == "retry" and inbox.attempt_count == 1 and inbox.claim_token is None
        assert db.scalar(sa.select(sa.func.count()).select_from(TenantMembership)) == 0
    with pytest.raises(LifecycleError) as ended:
        source.session(at=NOW + timedelta(seconds=1), issued_at=NOW)
    assert ended.value.code == "oidc_session_ended"
    fresh = source.session(at=NOW + timedelta(seconds=1), issued_at=NOW + timedelta(seconds=1))
    assert source.lifecycle.validate_auth_session(fresh.token, now=NOW + timedelta(seconds=1))


def test_repeat_restore_receipt_does_not_revoke_sessions_created_after_recovery(source):
    source.sync()
    service, review, digest = reviewed(source)
    first = service.apply(
        review, expected_sha256=digest, review_reference="owned/RESTORE-123", now=NOW
    )
    fresh = source.session(at=NOW + timedelta(seconds=1), issued_at=NOW + timedelta(seconds=1))
    second = service.apply(
        review,
        expected_sha256=digest,
        review_reference="owned/RESTORE-123",
        now=NOW + timedelta(seconds=2),
    )
    assert second["duplicate"] and first["audit_id"] == second["audit_id"]
    assert source.lifecycle.validate_auth_session(fresh.token, now=NOW + timedelta(seconds=2))
    with source.sessions() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.event_type == "identity.customer_restore.invalidated"
                )
            )
            == 1
        )


def test_live_state_change_after_review_cannot_be_hidden_by_recomputing_no_digest(source):
    source.sync()
    service, review, digest = reviewed(source)
    session = source.session()
    with pytest.raises(CustomerAuthRestoreError, match="review_stale"):
        service.apply(
            review, expected_sha256=digest, review_reference="owned/RESTORE-123", now=NOW
        )
    assert source.lifecycle.validate_auth_session(session.token, now=NOW)
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).security_version == 1


@pytest.mark.parametrize(
    "change",
    [
        {"product_revision": "8" * 40},
        {"operation": "unreviewed"},
        {"schema_version": True},
        {"expires_at": NOW.isoformat()},
        {"expires_at": (NOW + timedelta(minutes=6)).isoformat()},
        {"secret": "never-accepted"},
    ],
)
def test_restore_requires_exact_bounded_review(source, change):
    service, review, _ = reviewed(source)
    review |= change
    with pytest.raises(CustomerAuthRestoreError, match="review_invalid"):
        service.apply(
            review,
            expected_sha256=restore_review_sha256(review),
            review_reference="owned/RESTORE-123",
            now=NOW,
        )


def test_review_target_and_audit_failure_both_preserve_old_state(source):
    source.sync()
    service, review, digest = reviewed(source)
    changed = review | {"target_binding_sha256": "0" * 64}
    with pytest.raises(CustomerAuthRestoreError, match="target_mismatch"):
        service.apply(
            changed,
            expected_sha256=restore_review_sha256(changed),
            review_reference="owned/RESTORE-123",
            now=NOW,
        )

    def fail(_session, _context, _instances):
        raise RuntimeError("private audit write failure")

    sa.event.listen(source.sessions, "before_flush", fail)
    try:
        with pytest.raises(RuntimeError):
            service.apply(
                review, expected_sha256=digest, review_reference="owned/RESTORE-123", now=NOW
            )
    finally:
        sa.event.remove(source.sessions, "before_flush", fail)
    assert (
        service.review(restore_id=uuid4(), backup_set_sha256="b" * 64, now=NOW)["tables"]
        == review["tables"]
    )


@pytest.mark.parametrize(
    "value",
    [
        {"row_count": True, "sha256": "a" * 64},
        {"row_count": -1, "sha256": "a" * 64},
        {"row_count": 0, "sha256": "invalid"},
        {"row_count": 0, "sha256": "a" * 64, "unreviewed": True},
    ],
)
def test_restore_rejects_malformed_nested_review_even_with_matching_digest(source, value):
    service, review, _ = reviewed(source)
    review["tables"][GlobalUser.__tablename__] = value
    with pytest.raises(CustomerAuthRestoreError, match="review_invalid"):
        service.apply(
            review,
            expected_sha256=restore_review_sha256(review),
            review_reference="owned/RESTORE-123",
            now=NOW,
        )


@pytest.mark.parametrize("terminal", ["completed", "ignored", "dead"])
def test_restore_preserves_terminal_notifications_and_disabled_identity(source, terminal):
    source.sync()
    event = source.service.inbox.ingest(
        IdentityNotification(
            "restore-terminal", "update-user", "customers", SUBJECT, "customer-login", NOW
        ),
        now=NOW,
    )
    with source.sessions.begin() as db:
        row = db.get(IdentityEventInboxRecord, event.id)
        row.status, row.completed_at = terminal, NOW
        row.attempt_count, row.last_error_code = 10, "identity_mapping_unknown"
        state = db.get(IdentityProviderStateRecord, source.connection_id)
        state.status = "disabled"
        user = db.get(GlobalUser, source.user_id)
        user.status = "suspended"
    service, review, digest = reviewed(source)
    service.apply(review, expected_sha256=digest, review_reference="owned/RESTORE-123", now=NOW)
    with source.sessions() as db:
        row = db.get(IdentityEventInboxRecord, event.id)
        assert row.status == terminal and row.attempt_count == 10 and row.version == 1
        assert row.last_error_code == "identity_mapping_unknown" and row.claim_token is None
        assert db.get(IdentityProviderStateRecord, source.connection_id).status == "disabled"
        user = db.get(GlobalUser, source.user_id)
        assert user.status == "suspended" and user.credential_owner == "casdoor"
