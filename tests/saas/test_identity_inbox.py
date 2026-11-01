from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from saas.control_plane import GlobalUser, IdentityEventInboxRecord, SaasBase, Tenant
from saas.control_plane.identity_events import IdentitySyncError, parse_casdoor_notification
from saas.control_plane.identity_inbox import IdentityEventInboxService, IdentitySyncPolicy
from tests.saas.test_casdoor_identity_events import NOW, notification


@pytest.fixture
def inbox():
    engine = sa.create_engine("sqlite://")
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    service = IdentityEventInboxService(
        sessions,
        policy=IdentitySyncPolicy(
            issuer="https://auth.example.test",
            organization="customers",
            max_attempts=2,
        ),
    )
    try:
        yield service, sessions
    finally:
        engine.dispose()


def event():
    return parse_casdoor_notification(notification(), organization="customers", now=NOW)


def test_ingest_is_persistent_deduplicated_and_contains_no_raw_target_or_credentials(inbox):
    service, sessions = inbox
    original = event()
    receipt = service.ingest(original, now=NOW)
    assert receipt.status == "pending" and not receipt.duplicate
    repeated = service.ingest(original, now=NOW + timedelta(seconds=1))
    assert repeated.id == receipt.id and repeated.duplicate
    with sessions() as db:
        data = dict(db.execute(sa.select(IdentityEventInboxRecord.__table__)).mappings().one())
        assert all(
            value not in json.dumps(data, default=str)
            for value in (
                "target-user",
                "stable-customer-uuid",
                "never-store",
                "administrator",
            )
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 0
    with pytest.raises(IdentitySyncError, match="idempotency_conflict"):
        service.ingest(replace(original, username="retargeted-account"), now=NOW)
    with sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(IdentityEventInboxRecord)) == 1


def test_expired_worker_cannot_complete_after_lease_takeover(inbox):
    service, _sessions = inbox
    service.ingest(event(), now=NOW)
    first = service.claim_next(now=NOW)
    assert first is not None
    assert service.claim_next(now=NOW + timedelta(seconds=1)) is None
    later = NOW + service.policy.event_lease + timedelta(seconds=1)
    second = service.claim_next(now=later)
    assert second is not None and second.token != first.token
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        service.finish(first, processed_connections=1, now=later)
    result = service.finish(second, processed_connections=1, now=later)
    assert result.status == "completed" and result.attempt_count == 2
    assert service.claim_next(now=later + timedelta(hours=1)) is None


def test_claim_cannot_retarget_a_stored_event_even_with_original_token(inbox):
    service, _sessions = inbox
    service.ingest(event(), now=NOW)
    claim = service.claim_next(now=NOW)
    with pytest.raises(IdentitySyncError, match="claim_stale"):
        service.finish(
            replace(claim, username_locator_sha256="f" * 64), processed_connections=1, now=NOW
        )
    assert service.finish(claim, processed_connections=0, now=NOW).status == "ignored"


def test_retry_is_bounded_content_free_and_nonretryable_failure_becomes_dead(inbox):
    service, sessions = inbox
    service.ingest(event(), now=NOW)
    first = service.claim_next(now=NOW)
    result = service.fail(
        first, IdentitySyncError("raw provider failure with secret", retryable=True), now=NOW
    )
    assert result.status == "retry"
    assert service.claim_next(now=NOW) is None
    with sessions() as db:
        assert db.get(IdentityEventInboxRecord, first.id).last_error_code == "identity_sync_failed"
    later = NOW + timedelta(seconds=2)
    second = service.claim_next(now=later)
    assert second is not None
    result = service.fail(
        second, IdentitySyncError("identity_provider_response_invalid"), now=later
    )
    assert result.status == "dead"
    assert service.claim_next(now=later + timedelta(days=1)) is None


def test_repeated_worker_crashes_exhaust_attempts_and_leave_terminal_evidence(inbox):
    service, sessions = inbox
    receipt = service.ingest(event(), now=NOW)
    assert service.claim_next(now=NOW) is not None
    assert service.claim_next(now=NOW + service.policy.event_lease) is not None
    assert service.claim_next(now=NOW + service.policy.event_lease * 2) is None
    with sessions() as db:
        row = db.get(IdentityEventInboxRecord, receipt.id)
        assert (row.status, row.attempt_count, row.claim_token, row.lease_expires_at) == (
            "dead",
            2,
            None,
            None,
        )
        assert row.completed_at is not None


def test_foreign_scope_is_rejected_before_any_record_is_written(inbox):
    service, sessions = inbox
    with pytest.raises(IdentitySyncError, match="scope_mismatch"):
        service.ingest(replace(event(), organization="foreign"), now=NOW)
    with sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(IdentityEventInboxRecord)) == 0
