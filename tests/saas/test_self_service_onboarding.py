from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    ControlPlaneOutboxEvent,
    EmailVerificationChallengeRecord,
    EmailVerificationMessage,
    GlobalUser,
    IdentityConnection,
    OnboardingError,
    OnboardingOutboxPublisher,
    OnboardingPlan,
    OnboardingPolicy,
    OutboxDispatcher,
    PasswordCredential,
    PasswordCredentialService,
    RegistrationRateLimitDecision,
    SaasBase,
    SelfServiceEventRecord,
    SelfServiceOnboardingService,
    SelfServiceRegistrationRecord,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
    TenantOnboardingCoordinator,
    TenantOnboardingRecord,
    VerificationEnvelopeKeyring,
)

EMAIL_EVENT = "onboarding.email_verification.requested"
TENANT_EVENT = "onboarding.tenant.requested"
BILLING_EVENT = "onboarding.billing.requested"
PASSWORD = "correct-horse-battery-staple"
ZERO_HASH = "0" * 64


class _AllowAllRateLimiter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.denied: set[tuple[str, str]] = set()

    def require(self, *, action: str, subject_kind: str, subject: str) -> None:
        self.calls.append((action, subject_kind, subject))

    def consume(
        self,
        db: Session,
        *,
        action: str,
        subject_kind: str,
        subject: str,
    ) -> RegistrationRateLimitDecision:
        del db
        self.calls.append((action, subject_kind, subject))
        if (action, subject_kind) in self.denied:
            return RegistrationRateLimitDecision(False, 37, 0, "test-deny")
        return RegistrationRateLimitDecision(True, 0, 1, "test-allow-all")


class _RecordingEmailSender:
    def __init__(self) -> None:
        self.deliveries: list[tuple[UUID, EmailVerificationMessage]] = []

    def send_verification(self, *, event_id: UUID, message: EmailVerificationMessage) -> None:
        self.deliveries.append((event_id, message))


@dataclass(frozen=True, slots=True)
class _OnboardingHarness:
    sessions: sessionmaker[Session]
    service: SelfServiceOnboardingService
    coordinator: TenantOnboardingCoordinator
    envelopes: VerificationEnvelopeKeyring
    sender: _RecordingEmailSender
    dispatcher: OutboxDispatcher
    limiter: _AllowAllRateLimiter
    now: datetime


@pytest.fixture
def onboarding() -> Iterator[_OnboardingHarness]:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    policy = OnboardingPolicy(
        plans=(
            OnboardingPlan(
                key="starter",
                policy_revision="starter-2026-08-10",
                trial_days=14,
            ),
        ),
        home_regions=frozenset({"cn-east-1"}),
        reserved_slugs=frozenset({"admin", "platform"}),
        verification_ttl=timedelta(minutes=30),
    )
    envelopes = VerificationEnvelopeKeyring(
        active_key_id="test-v1",
        keys={"test-v1": b"onboarding-test-envelope-key-001"},
    )
    limiter = _AllowAllRateLimiter()
    service = SelfServiceOnboardingService(
        sessions,
        policy=policy,
        envelope_keyring=envelopes,
        rate_limiter=limiter,
    )
    coordinator = TenantOnboardingCoordinator(sessions, policy=policy)
    sender = _RecordingEmailSender()
    publisher = OnboardingOutboxPublisher(
        registrations=service,
        coordinator=coordinator,
        envelopes=envelopes,
        email_sender=sender,
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    harness = _OnboardingHarness(
        sessions=sessions,
        service=service,
        coordinator=coordinator,
        envelopes=envelopes,
        sender=sender,
        dispatcher=OutboxDispatcher(sessions, publisher),
        limiter=limiter,
        now=now,
    )
    yield harness
    SaasBase.metadata.drop_all(engine)
    engine.dispose()


def _request(
    onboarding: _OnboardingHarness,
    *,
    suffix: str = "one",
    email: str | None = None,
    idempotency_key: str | None = None,
) -> UUID:
    accepted = onboarding.service.request_registration(
        email=email or f"owner-{suffix}@example.com",
        display_name="Example Owner",
        tenant_name=f"Example Tenant {suffix}",
        tenant_slug=f"example-{suffix}",
        default_space_name="Default Space",
        default_space_slug="default",
        plan_key="starter",
        home_region="cn-east-1",
        idempotency_key=idempotency_key or f"registration-{suffix}",
        now=onboarding.now,
    )
    assert not accepted.replayed
    return accepted.registration_id


def _email_event(
    onboarding: _OnboardingHarness, registration_id: UUID, *, newest: bool = True
) -> ControlPlaneOutboxEvent:
    with onboarding.sessions() as db:
        ordering = (
            ControlPlaneOutboxEvent.created_at.desc()
            if newest
            else ControlPlaneOutboxEvent.created_at.asc()
        )
        event = db.scalars(
            sa.select(ControlPlaneOutboxEvent)
            .where(
                ControlPlaneOutboxEvent.event_type == EMAIL_EVENT,
                ControlPlaneOutboxEvent.aggregate_key == str(registration_id),
            )
            .order_by(ordering, ControlPlaneOutboxEvent.id.desc())
        ).first()
        assert event is not None
        db.expunge(event)
        return event


def _message_for_challenge(
    onboarding: _OnboardingHarness, registration_id: UUID, challenge_id: UUID
) -> EmailVerificationMessage:
    with onboarding.sessions() as db:
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type == EMAIL_EVENT,
                    ControlPlaneOutboxEvent.aggregate_key == str(registration_id),
                )
            )
        )
        for event in events:
            message = onboarding.envelopes.open(event_id=event.id, payload=event.payload)
            if message.challenge_id == challenge_id:
                return message
    raise AssertionError(f"no email envelope exists for challenge {challenge_id}")


def _verify(
    onboarding: _OnboardingHarness,
    registration_id: UUID,
    message: EmailVerificationMessage,
    *,
    idempotency_key: str = "verify-once",
) -> None:
    result = onboarding.service.verify_and_request_onboarding(
        registration_id=registration_id,
        verification_token=message.verification_token,
        password=PASSWORD,
        idempotency_key=idempotency_key,
        now=onboarding.now + timedelta(minutes=1),
    )
    assert result.registration_id == registration_id
    assert not result.replayed


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode()).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _rate_calls(onboarding: _OnboardingHarness, action: str) -> list[tuple[str, str, str]]:
    return [call for call in onboarding.limiter.calls if call[0] == action]


def test_registration_stores_only_token_hash_and_dispatch_records_delivery(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding)
    event = _email_event(onboarding, registration_id)
    message = onboarding.envelopes.open(event_id=event.id, payload=event.payload)
    serialized_envelope = json.dumps(event.payload, sort_keys=True)

    assert message.email == "owner-one@example.com"
    assert message.verification_token not in serialized_envelope
    assert message.email not in serialized_envelope
    assert set(event.payload) == {"schema_version", "key_id", "ciphertext", "expires_at"}

    with onboarding.sessions() as db:
        challenge = db.scalar(
            sa.select(EmailVerificationChallengeRecord).where(
                EmailVerificationChallengeRecord.registration_id == registration_id
            )
        )
        assert challenge is not None
        assert challenge.token_hash == sha256(message.verification_token.encode()).hexdigest()
        assert challenge.token_hash != message.verification_token
        assert not hasattr(challenge, "token")
        assert not hasattr(challenge, "verification_token")

    replay = onboarding.service.request_registration(
        email="OWNER-ONE@example.com",
        display_name="Example Owner",
        tenant_name="Example Tenant one",
        tenant_slug="example-one",
        default_space_name="Default Space",
        default_space_slug="default",
        plan_key="starter",
        home_region="cn-east-1",
        idempotency_key="registration-one",
        now=onboarding.now,
    )
    assert replay.registration_id == registration_id
    assert replay.replayed
    assert _rate_calls(onboarding, "registration.request") == [
        ("registration.request", "email", "owner-one@example.com")
    ]

    dispatched = onboarding.dispatcher.dispatch_once(now=onboarding.now + timedelta(seconds=1))
    assert (dispatched.claimed, dispatched.published, dispatched.failed) == (1, 1, 0)
    assert onboarding.sender.deliveries == [(event.id, message)]
    with onboarding.sessions() as db:
        stored_event = db.get(ControlPlaneOutboxEvent, event.id)
        stored_challenge = db.get(EmailVerificationChallengeRecord, message.challenge_id)
        assert stored_event is not None and stored_event.published_at is not None
        assert stored_event.attempt_count == 1
        assert stored_challenge is not None
        assert stored_challenge.delivery_status == "sent"
        assert stored_challenge.delivery_attempts == 1
        assert stored_challenge.delivered_at is not None
        assert stored_challenge.last_delivery_error_code is None


def test_registration_returns_id_with_expire_on_commit_enabled() -> None:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=True)
    policy = OnboardingPolicy(
        plans=(OnboardingPlan("starter", "starter-expiring-session-v1", 14),),
        home_regions=frozenset({"cn-east-1"}),
    )
    envelopes = VerificationEnvelopeKeyring(
        active_key_id="test-v1",
        keys={"test-v1": b"onboarding-test-envelope-key-001"},
    )
    service = SelfServiceOnboardingService(
        sessions,
        policy=policy,
        envelope_keyring=envelopes,
        rate_limiter=_AllowAllRateLimiter(),
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)

    try:
        accepted = service.request_registration(
            email="expiring-session@example.com",
            display_name="Expiring Session Owner",
            tenant_name="Expiring Session Tenant",
            tenant_slug="expiring-session",
            default_space_name="Default Space",
            default_space_slug="default",
            plan_key="starter",
            home_region="cn-east-1",
            idempotency_key="expire-on-commit-registration",
            now=now,
        )

        assert isinstance(accepted.registration_id, UUID)
        assert not accepted.replayed
        with sessions() as db:
            registration = db.get(SelfServiceRegistrationRecord, accepted.registration_id)
            assert registration is not None
            assert registration.id == accepted.registration_id
            assert registration.status == "pending_verification"
    finally:
        SaasBase.metadata.drop_all(engine)
        engine.dispose()


def test_pending_email_collision_is_non_enumerating_and_does_not_duplicate_authority(
    onboarding: _OnboardingHarness,
) -> None:
    original_id = _request(onboarding, suffix="pending-email")

    accepted = onboarding.service.request_registration(
        email="OWNER-PENDING-EMAIL@example.com",
        display_name="Another Display Name",
        tenant_name="Another Tenant",
        tenant_slug="another-tenant",
        default_space_name="Another Space",
        default_space_slug="another-space",
        plan_key="starter",
        home_region="cn-east-1",
        idempotency_key="different-request-for-pending-email",
        now=onboarding.now + timedelta(seconds=1),
    )

    assert accepted.registration_id != original_id
    assert not accepted.replayed
    with onboarding.sessions() as db:
        registrations = list(db.scalars(sa.select(SelfServiceRegistrationRecord)))
        email_events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type == EMAIL_EVENT
                )
            )
        )
    assert [record.id for record in registrations] == [original_id]
    assert len(email_events) == 1


def test_invalid_registration_is_rejected_before_identity_rate_limit(
    onboarding: _OnboardingHarness,
) -> None:
    with pytest.raises(OnboardingError) as error:
        onboarding.service.request_registration(
            email="invalid-before-limit@example.com",
            display_name="Invalid",
            tenant_name="Invalid Tenant",
            tenant_slug="admin",
            default_space_name="Default Space",
            default_space_slug="default",
            plan_key="starter",
            home_region="cn-east-1",
            idempotency_key="invalid-before-limit",
            now=onboarding.now,
        )

    assert error.value.code == "registration_invalid"
    assert _rate_calls(onboarding, "registration.request") == []


def test_identity_limited_registration_is_non_enumerating_and_has_no_domain_writes(
    onboarding: _OnboardingHarness,
) -> None:
    onboarding.limiter.denied.add(("registration.request", "email"))

    accepted = onboarding.service.request_registration(
        email="identity-limited@example.com",
        display_name="Identity Limited",
        tenant_name="Identity Limited Tenant",
        tenant_slug="identity-limited",
        default_space_name="Default Space",
        default_space_slug="default",
        plan_key="starter",
        home_region="cn-east-1",
        idempotency_key="identity-limited",
        now=onboarding.now,
    )

    assert not accepted.replayed
    assert _rate_calls(onboarding, "registration.request") == [
        ("registration.request", "email", "identity-limited@example.com")
    ]
    with onboarding.sessions() as db:
        assert db.get(SelfServiceRegistrationRecord, accepted.registration_id) is None
        assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == 0


def test_unknown_resend_target_does_not_consume_identity_bucket(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="resend-target")
    with onboarding.sessions() as db:
        original_challenges = db.scalar(
            sa.select(sa.func.count()).select_from(EmailVerificationChallengeRecord)
        )
        original_events = db.scalar(
            sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)
        )

    for target_id, email in (
        (registration_id, "wrong-resend-target@example.com"),
        (uuid4(), "owner-resend-target@example.com"),
    ):
        accepted = onboarding.service.resend_verification(
            registration_id=target_id,
            email=email,
            idempotency_key=f"unknown-{target_id}",
            now=onboarding.now + timedelta(minutes=1),
        )
        assert not accepted.replayed

    assert _rate_calls(onboarding, "registration.resend") == []
    with onboarding.sessions() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(EmailVerificationChallengeRecord))
            == original_challenges
        )
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent))
            == original_events
        )


def test_identity_limited_resend_is_non_enumerating_and_preserves_challenge(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="resend-limited")
    original_event = _email_event(onboarding, registration_id)
    original_message = onboarding.envelopes.open(
        event_id=original_event.id, payload=original_event.payload
    )
    onboarding.limiter.denied.add(("registration.resend", "email"))

    accepted = onboarding.service.resend_verification(
        registration_id=registration_id,
        email="OWNER-RESEND-LIMITED@example.com",
        idempotency_key="resend-limited",
        now=onboarding.now + timedelta(minutes=1),
    )

    assert not accepted.replayed
    assert _rate_calls(onboarding, "registration.resend") == [
        ("registration.resend", "email", "owner-resend-limited@example.com")
    ]
    with onboarding.sessions() as db:
        registration = db.get(SelfServiceRegistrationRecord, registration_id)
        challenge = db.get(EmailVerificationChallengeRecord, original_message.challenge_id)
        assert registration is not None and registration.challenge_generation == 1
        assert challenge is not None and challenge.status == "pending"
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.aggregate_key == str(registration_id))
            )
            == 1
        )


def test_resend_revokes_old_token_and_replays_idempotently(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="resend")
    old_event = _email_event(onboarding, registration_id)
    old_message = onboarding.envelopes.open(event_id=old_event.id, payload=old_event.payload)

    resent = onboarding.service.resend_verification(
        registration_id=registration_id,
        email="OWNER-RESEND@example.com",
        idempotency_key="resend-once",
        now=onboarding.now + timedelta(minutes=2),
    )
    assert not resent.replayed
    replay = onboarding.service.resend_verification(
        registration_id=registration_id,
        email="owner-resend@example.com",
        idempotency_key="resend-once",
        now=onboarding.now + timedelta(minutes=3),
    )
    assert replay.replayed
    assert _rate_calls(onboarding, "registration.resend") == [
        ("registration.resend", "email", "owner-resend@example.com")
    ]

    with onboarding.sessions() as db:
        challenges = list(
            db.scalars(
                sa.select(EmailVerificationChallengeRecord)
                .where(EmailVerificationChallengeRecord.registration_id == registration_id)
                .order_by(EmailVerificationChallengeRecord.generation)
            )
        )
        assert [(item.generation, item.status) for item in challenges] == [
            (1, "revoked"),
            (2, "pending"),
        ]
        new_challenge_id = challenges[1].id

    with pytest.raises(OnboardingError) as error:
        onboarding.service.verify_and_request_onboarding(
            registration_id=registration_id,
            verification_token=old_message.verification_token,
            password=PASSWORD,
            idempotency_key="verify-revoked",
            now=onboarding.now + timedelta(minutes=4),
        )
    assert error.value.code == "verification_invalid"
    assert _rate_calls(onboarding, "registration.verify") == []

    new_message = _message_for_challenge(onboarding, registration_id, new_challenge_id)
    _verify(onboarding, registration_id, new_message, idempotency_key="verify-new-token")


def test_dispatch_suppresses_an_envelope_after_its_challenge_is_revoked(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="stale-delivery")
    old_event = _email_event(onboarding, registration_id)
    old_message = onboarding.envelopes.open(event_id=old_event.id, payload=old_event.payload)

    onboarding.service.resend_verification(
        registration_id=registration_id,
        email="owner-stale-delivery@example.com",
        idempotency_key="replace-before-dispatch",
        now=onboarding.now + timedelta(minutes=1),
    )
    with onboarding.sessions() as db:
        new_event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.event_type == EMAIL_EVENT,
                ControlPlaneOutboxEvent.aggregate_key == str(registration_id),
                ControlPlaneOutboxEvent.id != old_event.id,
            )
        )
        assert new_event is not None
        db.expunge(new_event)
    new_message = onboarding.envelopes.open(event_id=new_event.id, payload=new_event.payload)

    dispatched = onboarding.dispatcher.dispatch_once(
        now=onboarding.now + timedelta(minutes=1, seconds=1), batch_size=10
    )

    assert (dispatched.claimed, dispatched.published, dispatched.failed) == (2, 2, 0)
    assert onboarding.sender.deliveries == [(new_event.id, new_message)]
    with onboarding.sessions() as db:
        old_challenge = db.get(EmailVerificationChallengeRecord, old_message.challenge_id)
        assert old_challenge is not None
        assert old_challenge.status == "revoked"
        assert old_challenge.delivery_status == "failed"
        assert old_challenge.last_delivery_error_code == "challenge_inactive"


def test_invalid_verification_does_not_run_the_password_kdf(
    onboarding: _OnboardingHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration_id = _request(onboarding, suffix="kdf-guard")

    def _unexpected_hash(_password: str) -> str:
        raise AssertionError("password KDF ran before challenge authentication")

    monkeypatch.setattr("saas.control_plane.onboarding.hash_password", _unexpected_hash)
    with pytest.raises(OnboardingError) as error:
        onboarding.service.verify_and_request_onboarding(
            registration_id=registration_id,
            verification_token="not-the-issued-token",
            password=PASSWORD,
            idempotency_key="invalid-token-must-not-hash",
            now=onboarding.now + timedelta(minutes=1),
        )
    assert error.value.code == "verification_invalid"


def test_weak_password_is_rejected_before_verification_rate_limit(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="weak-password")
    event = _email_event(onboarding, registration_id)
    message = onboarding.envelopes.open(event_id=event.id, payload=event.payload)

    with pytest.raises(OnboardingError) as error:
        onboarding.service.verify_and_request_onboarding(
            registration_id=registration_id,
            verification_token=message.verification_token,
            password="too-short",
            idempotency_key="weak-password",
            now=onboarding.now + timedelta(minutes=1),
        )

    assert error.value.code == "password_policy"
    assert _rate_calls(onboarding, "registration.verify") == []
    with onboarding.sessions() as db:
        registration = db.get(SelfServiceRegistrationRecord, registration_id)
        challenge = db.get(EmailVerificationChallengeRecord, message.challenge_id)
        assert registration is not None and registration.status == "pending_verification"
        assert challenge is not None and challenge.status == "pending"


def test_verification_rate_denial_commits_before_429_and_preserves_domain_state(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="verify-limited")
    event = _email_event(onboarding, registration_id)
    message = onboarding.envelopes.open(event_id=event.id, payload=event.payload)
    onboarding.limiter.denied.add(("registration.verify", "registration"))

    with pytest.raises(OnboardingError) as error:
        onboarding.service.verify_and_request_onboarding(
            registration_id=registration_id,
            verification_token=message.verification_token,
            password=PASSWORD,
            idempotency_key="verify-limited",
            now=onboarding.now + timedelta(minutes=1),
        )

    assert error.value.code == "registration_rate_limited"
    assert error.value.retry_after_seconds == 37
    assert _rate_calls(onboarding, "registration.verify") == [
        ("registration.verify", "registration", str(registration_id))
    ]
    with onboarding.sessions() as db:
        registration = db.get(SelfServiceRegistrationRecord, registration_id)
        challenge = db.get(EmailVerificationChallengeRecord, message.challenge_id)
        assert registration is not None and registration.status == "pending_verification"
        assert challenge is not None and challenge.status == "pending"
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(PasswordCredential)) == 0
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == TENANT_EVENT)
            )
            == 0
        )


def test_verification_creates_login_then_outbox_starts_fail_closed_tenant_saga(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="provision")
    email_event = _email_event(onboarding, registration_id)
    message = onboarding.envelopes.open(event_id=email_event.id, payload=email_event.payload)
    assert (
        onboarding.dispatcher.dispatch_once(now=onboarding.now + timedelta(seconds=1)).published
        == 1
    )

    _verify(onboarding, registration_id, message)
    replay = onboarding.service.verify_and_request_onboarding(
        registration_id=registration_id,
        verification_token=message.verification_token,
        password=PASSWORD,
        idempotency_key="verify-once",
        now=onboarding.now + timedelta(minutes=1),
    )
    assert replay.replayed
    with pytest.raises(OnboardingError) as receipt_conflict:
        onboarding.service.verify_and_request_onboarding(
            registration_id=registration_id,
            verification_token=message.verification_token,
            password=PASSWORD,
            idempotency_key="different-consumed-token-replay",
            now=onboarding.now + timedelta(minutes=1),
        )
    assert receipt_conflict.value.code == "idempotency_conflict"
    assert _rate_calls(onboarding, "registration.verify") == [
        ("registration.verify", "registration", str(registration_id))
    ]

    with onboarding.sessions() as db:
        registration = db.get(SelfServiceRegistrationRecord, registration_id)
        assert registration is not None
        tenant_id = registration.tenant_id
        space_id = registration.space_id
        user_id = registration.user_id
        assert registration.status == "verified"
        assert db.get(GlobalUser, user_id) is not None
        assert db.get(PasswordCredential, user_id) is not None
        assert db.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 0
        tenant_event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.event_type == TENANT_EVENT,
                ControlPlaneOutboxEvent.aggregate_key == str(registration.onboarding_id),
            )
        )
        assert tenant_event is not None
        tenant_event_id = tenant_event.id

    assert (
        PasswordCredentialService(onboarding.sessions).authenticate(
            "OWNER-PROVISION@example.com",
            PASSWORD,
            now=onboarding.now + timedelta(minutes=2),
        )
        == user_id
    )

    dispatched = onboarding.dispatcher.dispatch_once(now=onboarding.now + timedelta(minutes=2))
    assert (dispatched.claimed, dispatched.published, dispatched.failed) == (1, 1, 0)
    with onboarding.sessions() as db:
        tenant = db.get(Tenant, tenant_id)
        space = db.get(Space, space_id)
        saga = db.scalar(
            sa.select(TenantOnboardingRecord).where(
                TenantOnboardingRecord.registration_id == registration_id
            )
        )
        tenant_membership = db.get(TenantMembership, (tenant_id, user_id))
        space_membership = db.get(SpaceMembership, (tenant_id, space_id, user_id))
        assert tenant is not None and tenant.status == "provisioning"
        assert space is not None and space.status == "suspended"
        assert tenant_membership is not None and tenant_membership.role == "owner"
        assert space_membership is not None and space_membership.role == "owner"
        assert saga is not None and saga.status == "tenant_created"
        assert saga.trial_started_at is None
        assert saga.trial_ends_at is None
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == BILLING_EVENT)
            )
            == 1
        )

    coordinator_replay = onboarding.coordinator.start(
        registration_id=registration_id,
        idempotency_key=str(tenant_event_id),
        now=onboarding.now + timedelta(minutes=3),
    )
    assert coordinator_replay.replayed
    with onboarding.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(TenantOnboardingRecord)) == 1


def test_onboarding_rejects_a_self_consistent_plan_snapshot_outside_reviewed_policy(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="plan-drift")
    email_event = _email_event(onboarding, registration_id)
    message = onboarding.envelopes.open(event_id=email_event.id, payload=email_event.payload)
    _verify(onboarding, registration_id, message)

    with onboarding.sessions.begin() as db:
        registration = db.get(SelfServiceRegistrationRecord, registration_id)
        assert registration is not None
        forged_snapshot = dict(registration.plan_snapshot)
        forged_snapshot["quota_limit"] = 1_000_000
        registration.plan_snapshot = forged_snapshot
        registration.plan_snapshot_hash = _digest(forged_snapshot)
        tenant_event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.event_type == TENANT_EVENT,
                ControlPlaneOutboxEvent.aggregate_key == str(registration.onboarding_id),
            )
        )
        assert tenant_event is not None
        tenant_event_id = tenant_event.id

    with pytest.raises(OnboardingError) as error:
        onboarding.coordinator.start(
            registration_id=registration_id,
            idempotency_key=str(tenant_event_id),
            now=onboarding.now + timedelta(minutes=2),
        )

    assert error.value.code == "onboarding_plan_snapshot_invalid"
    with onboarding.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(TenantOnboardingRecord)) == 0


def test_existing_verified_email_is_suppressed_without_challenge_or_email_event(
    onboarding: _OnboardingHarness,
) -> None:
    existing_user_id = uuid4()
    with onboarding.sessions.begin() as db:
        db.add(GlobalUser(id=existing_user_id, status="active", security_version=1))
        db.add(
            IdentityConnection(
                user_id=existing_user_id,
                provider="oidc",
                issuer="https://idp.example.com",
                subject="existing-owner",
                email_normalized="existing@example.com",
                email_verified=True,
                status="active",
            )
        )

    registration_id = _request(
        onboarding,
        suffix="suppressed",
        email="EXISTING@example.com",
    )
    synthetic_id = _request(
        onboarding,
        suffix="suppressed-again",
        email="existing@example.com",
    )
    assert synthetic_id != registration_id
    with onboarding.sessions() as db:
        registration = db.get(SelfServiceRegistrationRecord, registration_id)
        assert registration is not None and registration.status == "suppressed"
        assert registration.terminal_at is not None
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(EmailVerificationChallengeRecord)
                .where(EmailVerificationChallengeRecord.registration_id == registration_id)
            )
            == 0
        )
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(SelfServiceRegistrationRecord)) == 1
        )
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.aggregate_key == str(registration_id))
            )
            == 0
        )


def test_invalid_and_expired_verification_tokens_fail_closed(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="expiry")
    event = _email_event(onboarding, registration_id)
    message = onboarding.envelopes.open(event_id=event.id, payload=event.payload)

    with pytest.raises(OnboardingError) as invalid:
        onboarding.service.verify_and_request_onboarding(
            registration_id=registration_id,
            verification_token="not-the-issued-verification-token",
            password=PASSWORD,
            idempotency_key="invalid-token",
            now=onboarding.now + timedelta(minutes=1),
        )
    assert invalid.value.code == "verification_invalid"
    assert _rate_calls(onboarding, "registration.verify") == []
    with onboarding.sessions() as db:
        registration = db.get(SelfServiceRegistrationRecord, registration_id)
        challenge = db.get(EmailVerificationChallengeRecord, message.challenge_id)
        assert registration is not None and registration.status == "pending_verification"
        assert challenge is not None and challenge.status == "pending"

    with pytest.raises(OnboardingError) as expired:
        onboarding.service.verify_and_request_onboarding(
            registration_id=registration_id,
            verification_token=message.verification_token,
            password=PASSWORD,
            idempotency_key="expired-token",
            now=onboarding.now + timedelta(minutes=31),
        )
    assert expired.value.code == "verification_invalid"
    with onboarding.sessions() as db:
        registration = db.get(SelfServiceRegistrationRecord, registration_id)
        challenge = db.get(EmailVerificationChallengeRecord, message.challenge_id)
        assert registration is not None and registration.status == "expired"
        assert challenge is not None and challenge.status == "expired"
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 0


def test_events_are_hash_linked_pii_free_and_reject_sensitive_fact_keys(
    onboarding: _OnboardingHarness,
) -> None:
    registration_id = _request(onboarding, suffix="events")
    first_event = _email_event(onboarding, registration_id)
    first_message = onboarding.envelopes.open(event_id=first_event.id, payload=first_event.payload)
    onboarding.service.resend_verification(
        registration_id=registration_id,
        email=first_message.email,
        idempotency_key="events-resend",
        now=onboarding.now + timedelta(minutes=1),
    )

    with onboarding.sessions() as db:
        events = list(
            db.scalars(
                sa.select(SelfServiceEventRecord)
                .where(
                    SelfServiceEventRecord.aggregate_type == "registration",
                    SelfServiceEventRecord.aggregate_id == registration_id,
                )
                .order_by(SelfServiceEventRecord.sequence)
            )
        )
        assert [event.sequence for event in events] == [1, 2]
        previous_hash = ZERO_HASH
        for event in events:
            assert event.previous_hash == previous_hash
            assert event.facts_hash == _digest(event.facts)
            expected_hash = _digest(
                {
                    "aggregate_type": event.aggregate_type,
                    "aggregate_id": str(event.aggregate_id),
                    "sequence": event.sequence,
                    "event_type": event.event_type,
                    "from_status": event.from_status,
                    "to_status": event.to_status,
                    "facts_hash": event.facts_hash,
                    "previous_hash": event.previous_hash,
                    "occurred_at": _utc(event.occurred_at).isoformat(),
                }
            )
            assert event.event_hash == expected_hash
            previous_hash = event.event_hash

        serialized_facts = json.dumps([event.facts for event in events], sort_keys=True)
        assert first_message.email not in serialized_facts
        assert first_message.verification_token not in serialized_facts
        assert PASSWORD not in serialized_facts

        with pytest.raises(ValueError, match="sensitive key"):
            SelfServiceOnboardingService._append_event(
                db,
                aggregate_type="registration",
                aggregate_id=registration_id,
                tenant_id=None,
                user_id=None,
                event_type="registration.invalid_fact",
                from_status=None,
                to_status=None,
                facts={"verification_token": "must-never-be-recorded"},
                occurred_at=onboarding.now + timedelta(minutes=2),
            )
