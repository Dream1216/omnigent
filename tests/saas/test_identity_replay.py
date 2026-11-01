from __future__ import annotations

import base64
import json
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saas.control_plane.db_models import ControlPlaneOutboxEvent, GlobalUser, TenantMembership
from saas.control_plane.identity_event_models import IdentityEventInboxRecord
from saas.control_plane.identity_events import IdentityNotification, IdentitySyncError
from saas.control_plane.identity_replay import (
    IdentityDeadLetterService,
    IdentityReplayError,
    IdentityReplayKeyring,
    replay_payload,
    replay_signature_input,
)
from tests.saas.test_identity_sync import ISSUER, NOW, SUBJECT
from tests.saas.test_identity_sync import source as source

REVISION = "7" * 40


def sign(key, document, *, key_id="offline-review"):
    payload = replay_payload(document)
    return ".".join(
        (
            "v1",
            key_id,
            *(
                base64.urlsafe_b64encode(value).decode().rstrip("=")
                for value in (
                    payload,
                    key.sign(replay_signature_input(key_id, payload)),
                )
            ),
        )
    )


def make_dead(source, *, at=NOW):
    event = source.service.inbox.ingest(
        IdentityNotification(
            "review-" + uuid4().hex,
            "set-password",
            "customers",
            SUBJECT,
            "customer-login",
            at,
            True,
        ),
        now=at,
    )
    claim = source.service.inbox.claim_next(now=at)
    assert claim is not None
    source.service.inbox.fail(claim, IdentitySyncError("identity_provider_unavailable"), now=at)
    return event.id


def reviewed(source, *, at=NOW):
    key = Ed25519PrivateKey.generate()
    keys = IdentityReplayKeyring({"offline-review": key.public_key().public_bytes_raw()})
    service = IdentityDeadLetterService(
        source.sessions,
        policy=source.service.policy,
        product_revision=REVISION,
        verification_keys=keys,
    )
    inbox_id = make_dead(source, at=at)
    review = service.review(inbox_id)
    document = {
        "schema_version": 1,
        "grant_id": str(uuid4()),
        "inbox_id": str(inbox_id),
        "product_revision": REVISION,
        "issuer": ISSUER,
        "organization": "customers",
        "review_sha256": review["review_sha256"],
        "review_reference": "synthetic-review/OPS-123",
        "reason_code": "provider_restored",
        "issued_at": at.isoformat(),
        "expires_at": (at + timedelta(minutes=5)).isoformat(),
    }
    return service, key, document, inbox_id


def test_replay_only_reschedules_original_event_and_audits_once_before_real_readback(source):
    source.sync()
    session = source.session()
    service, key, document, inbox_id = reviewed(source)
    before = service.review(inbox_id)["review"]
    token = sign(key, document)
    result = service.replay(token, now=NOW)
    assert not result["duplicate"]
    assert service.replay(token, now=NOW)["duplicate"]
    assert source.lifecycle.validate_auth_session(session.token, now=NOW)
    with source.sessions() as db:
        record = db.get(IdentityEventInboxRecord, inbox_id)
        assert record.status == "pending" and record.attempt_count == 0
        assert record.version == before["version"] + 1
        assert record.request_sha256 == before["request_sha256"]
        assert record.event_id == before["event_id"]
        assert record.completed_at is record.last_error_code is None
        assert db.get(GlobalUser, source.user_id).security_version == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(TenantMembership)) == 0
        audit = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.event_type == "identity.notification.replayed"
            )
        )
        assert audit.payload["reviewer_key_id"] == "offline-review"
        assert audit.payload["previous_attempt_count"] == 1
        assert audit.request_hash == sha256(token.encode()).hexdigest()
        assert token not in json.dumps(audit.payload)
    calls = len(source.provider.calls)
    assert source.service.process_next_event(now=NOW + timedelta(seconds=1))
    assert len(source.provider.calls) == calls + 1
    with source.sessions() as db:
        assert db.get(IdentityEventInboxRecord, inbox_id).status == "completed"
        assert db.get(GlobalUser, source.user_id).security_version == 2


@pytest.mark.parametrize(
    "change",
    [
        {"product_revision": "8" * 40},
        {"issuer": "https://other.example.test"},
        {"organization": "other"},
        {"review_sha256": "0" * 64},
        {"expires_at": NOW.isoformat()},
        {"expires_at": (NOW + timedelta(minutes=6)).isoformat()},
        {"issued_at": (NOW + timedelta(seconds=1)).isoformat()},
        {"schema_version": True},
        {"reason_code": "unreviewed"},
        {"password": "private"},
    ],
)
def test_grants_reject_wrong_scope_stale_review_expiry_and_extensions(source, change):
    service, key, document, inbox_id = reviewed(source)
    with pytest.raises(IdentityReplayError):
        service.replay(sign(key, document | change), now=NOW)
    with source.sessions() as db:
        assert db.get(IdentityEventInboxRecord, inbox_id).status == "dead"
        assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == 1


def test_renaming_a_trusted_alias_cannot_forge_reviewer_identity(source):
    service, key, document, _ = reviewed(source)
    service._keys = IdentityReplayKeyring(
        {
            "offline-review": key.public_key().public_bytes_raw(),
            "alias": key.public_key().public_bytes_raw(),
        }
    )
    token = sign(key, document).replace("v1.offline-review.", "v1.alias.")
    with pytest.raises(IdentityReplayError, match="grant_invalid"):
        service.replay(token, now=NOW)


def test_old_grant_cannot_reset_a_new_dead_cycle_and_new_grant_needs_fresh_review(source):
    service, key, document, inbox_id = reviewed(source)
    token = sign(key, document)
    service.replay(token, now=NOW)
    claim = source.service.inbox.claim_next(now=NOW)
    assert claim is not None
    source.service.inbox.fail(claim, IdentitySyncError("identity_provider_unavailable"), now=NOW)
    before = service.review(inbox_id)
    assert service.replay(token, now=NOW)["duplicate"]
    assert service.review(inbox_id) == before
    with pytest.raises(IdentityReplayError, match="review_stale"):
        service.replay(sign(key, document | {"grant_id": str(uuid4())}), now=NOW)
    with source.sessions() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == "identity.notification.replayed")
            )
            == 1
        )


def test_audit_failure_rolls_back_rescheduling(source):
    service, key, document, inbox_id = reviewed(source)
    before = service.review(inbox_id)

    def fail(_session, _context, _instances):
        raise RuntimeError("private audit failure")

    sa.event.listen(source.sessions, "before_flush", fail)
    try:
        with pytest.raises(RuntimeError):
            service.replay(sign(key, document), now=NOW)
    finally:
        sa.event.remove(source.sessions, "before_flush", fail)
    assert service.review(inbox_id) == before


def test_review_and_listing_are_scoped_and_contain_no_raw_identity_or_credential(source):
    service, _key, _document, inbox_id = reviewed(source)
    results = service.list_dead(limit=1)
    assert results == [service.review(inbox_id)]
    data = json.dumps(results)
    assert (
        SUBJECT not in data and "customer-login" not in data and "owner@example.test" not in data
    )
    foreign = IdentityDeadLetterService(
        source.sessions,
        policy=type(source.service.policy)(issuer=ISSUER, organization="other"),
        product_revision=REVISION,
        verification_keys=service._keys,
    )
    assert foreign.list_dead() == []
    with pytest.raises(IdentityReplayError, match="not_found"):
        foreign.review(inbox_id)
    for limit in (True, 0, 101):
        with pytest.raises(ValueError):
            service.list_dead(limit=limit)
