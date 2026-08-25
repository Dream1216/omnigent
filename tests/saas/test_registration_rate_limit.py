from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from inspect import signature

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    OnboardingError,
    OnboardingPlan,
    OnboardingPolicy,
    RegistrationRateLimitPolicyRecord,
    RegistrationRateLimitRecord,
    RegistrationRateLimitSubjectKeyring,
    SaasBase,
    SelfServiceOnboardingService,
    SelfServiceRegistrationRecord,
    SharedRegistrationRateLimitJanitor,
    SharedRegistrationRateLimiter,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.onboarding_http import _http_error


@dataclass(slots=True)
class _Clock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory: sessionmaker[Session] = sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        SaasBase.metadata.drop_all(engine)
        engine.dispose()


def _keyring(
    *,
    active: str = "rate-v1",
    previous: str | None = None,
    anchor: str | None = None,
    write: str | None = None,
) -> RegistrationRateLimitSubjectKeyring:
    keys = {active: (active.encode() + b"-") * 8}
    if previous is not None:
        keys[previous] = (previous.encode() + b"-") * 8
    return RegistrationRateLimitSubjectKeyring(
        keys=keys,
        active_key_id=active,
        previous_key_id=previous,
        anchor_key_id=anchor,
        write_key_id=write,
    )


def _set_policy(
    sessions: sessionmaker[Session],
    *,
    action: str,
    subject_kind: str,
    limit: int,
    window: int = 60,
    retention: int = 60,
    max_rows: int = 100,
) -> None:
    with sessions.begin() as db:
        policy = db.get(RegistrationRateLimitPolicyRecord, (action, subject_kind))
        assert policy is not None
        policy.limit_count = limit
        policy.window_seconds = window
        policy.retention_seconds = retention
        policy.max_rows = max_rows


@pytest.mark.parametrize(
    ("action", "subject_kind", "subject"),
    [
        ("registration.request", "email", "request@example.test"),
        ("registration.resend", "email", "resend@example.test"),
        ("registration.verify", "registration", "018f7c54-1500-7000-8000-000000000001"),
    ],
)
def test_database_policy_blocks_each_action_across_replicas_and_commits_denial(
    sessions: sessionmaker[Session],
    action: str,
    subject_kind: str,
    subject: str,
) -> None:
    clock = _Clock(datetime(2026, 8, 26, 2, 0, tzinfo=timezone.utc))
    keyring = _keyring()
    first = SharedRegistrationRateLimiter(
        sessions, subject_keyring=keyring, development_clock=clock
    )
    second = SharedRegistrationRateLimiter(
        sessions, subject_keyring=keyring, development_clock=clock
    )
    _set_policy(sessions, action=action, subject_kind=subject_kind, limit=1)

    first.require(action=action, subject_kind=subject_kind, subject=subject)
    with pytest.raises(OnboardingError) as denied:
        second.require(action=action, subject_kind=subject_kind, subject=subject)

    assert denied.value.code == "registration_rate_limited"
    assert _http_error(denied.value).status_code == 429
    alias = keyring.aliases(action=action, subject_kind=subject_kind, subject=subject)
    with sessions() as db:
        counter = db.get(
            RegistrationRateLimitRecord,
            (action, subject_kind, alias.write_key_id, alias.active_subject_hmac),
        )
        assert counter is not None
        assert (counter.request_count, counter.version) == (1, 2)
        assert subject not in counter.subject_hmac


def test_expired_rows_release_bounded_capacity(
    sessions: sessionmaker[Session],
) -> None:
    clock = _Clock(datetime(2026, 8, 26, 3, 0, tzinfo=timezone.utc))
    limiter = SharedRegistrationRateLimiter(
        sessions, subject_keyring=_keyring(), development_clock=clock
    )
    _set_policy(
        sessions,
        action="registration.request",
        subject_kind="email",
        limit=1,
        max_rows=1,
    )

    limiter.require(
        action="registration.request", subject_kind="email", subject="first@example.test"
    )
    with pytest.raises(OnboardingError) as full:
        limiter.require(
            action="registration.request", subject_kind="email", subject="second@example.test"
        )
    assert full.value.code == "registration_rate_limit_unavailable"

    clock.value += timedelta(seconds=60)
    limiter.require(
        action="registration.request", subject_kind="email", subject="second@example.test"
    )
    with sessions() as db:
        policy = db.get(RegistrationRateLimitPolicyRecord, ("registration.request", "email"))
        counters = list(db.scalars(sa.select(RegistrationRateLimitRecord)))
        assert policy is not None and policy.current_rows == 1
        assert len(counters) == 1 and counters[0].request_count == 1


def test_rotation_overlap_keeps_anchor_writes_until_old_replicas_drain(
    sessions: sessionmaker[Session],
) -> None:
    clock = _Clock(datetime(2026, 8, 26, 3, 30, tzinfo=timezone.utc))
    old = SharedRegistrationRateLimiter(
        sessions, subject_keyring=_keyring(active="old"), development_clock=clock
    )
    overlap = SharedRegistrationRateLimiter(
        sessions,
        subject_keyring=_keyring(active="new", previous="old"),
        development_clock=clock,
    )
    _set_policy(sessions, action="registration.request", subject_kind="email", limit=2)

    for limiter in (old, overlap):
        limiter.require(
            action="registration.request", subject_kind="email", subject="rotate@example.test"
        )
    with pytest.raises(OnboardingError, match="rate limit exceeded"):
        old.require(
            action="registration.request", subject_kind="email", subject="rotate@example.test"
        )

    promoted = SharedRegistrationRateLimiter(
        sessions,
        subject_keyring=_keyring(active="new", previous="old", anchor="old", write="new"),
        development_clock=clock,
    )
    with pytest.raises(OnboardingError, match="rate limit exceeded"):
        promoted.require(
            action="registration.request", subject_kind="email", subject="rotate@example.test"
        )
    with sessions() as db:
        counters = list(db.scalars(sa.select(RegistrationRateLimitRecord)))
        assert len(counters) == 1
        assert (counters[0].key_id, counters[0].request_count) == ("new", 2)


def test_storage_failure_denies_before_domain_work(
    sessions: sessionmaker[Session],
) -> None:
    limiter = SharedRegistrationRateLimiter(sessions, subject_keyring=_keyring())
    service = SelfServiceOnboardingService(
        sessions,
        policy=OnboardingPolicy(
            plans=(OnboardingPlan("starter", "rate-limit-storage-v1", 14),),
            home_regions=frozenset({"cn-east-1"}),
        ),
        envelope_keyring=VerificationEnvelopeKeyring(
            active_key_id="rate-limit-test-v1", keys={"rate-limit-test-v1": b"r" * 32}
        ),
        rate_limiter=limiter,
    )
    RegistrationRateLimitRecord.__table__.drop(sessions.kw["bind"])

    with pytest.raises(OnboardingError) as denied:
        service.request_registration(
            email="storage-failure@example.test",
            display_name="Storage Failure",
            tenant_name="Storage Failure Tenant",
            tenant_slug="storage-failure",
            default_space_name="Default Space",
            default_space_slug="default",
            plan_key="starter",
            home_region="cn-east-1",
            idempotency_key="storage-failure",
            now=datetime(2026, 8, 26, 4, 0, tzinfo=timezone.utc),
        )
    assert denied.value.code == "registration_rate_limit_unavailable"
    assert _http_error(denied.value).status_code == 503
    with sessions() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(SelfServiceRegistrationRecord)) == 0
        )


@pytest.mark.parametrize(
    ("action", "subject_kind", "subject"),
    [
        ("registration.unknown", "email", "unknown@example.test"),
        ("registration.request", "email", ""),
        ("registration.request", "email", "contains\x00nul"),
    ],
)
def test_unknown_policy_and_untrusted_subject_fail_closed(
    sessions: sessionmaker[Session], action: str, subject_kind: str, subject: str
) -> None:
    limiter = SharedRegistrationRateLimiter(sessions, subject_keyring=_keyring())
    with pytest.raises(OnboardingError) as denied:
        limiter.require(action=action, subject_kind=subject_kind, subject=subject)
    assert denied.value.code == "registration_rate_limit_unavailable"


def test_keyring_requires_strong_exact_keys_and_domain_separates_aliases() -> None:
    with pytest.raises(ValueError, match="keyring is invalid"):
        RegistrationRateLimitSubjectKeyring(keys={"weak": b"short"}, active_key_id="weak")
    with pytest.raises(ValueError, match="keyring is invalid"):
        RegistrationRateLimitSubjectKeyring(
            keys={"active": b"a" * 32, "unused": b"b" * 32}, active_key_id="active"
        )
    keyring = _keyring()
    request = keyring.aliases(
        action="registration.request", subject_kind="email", subject="same@example.test"
    )
    resend = keyring.aliases(
        action="registration.resend", subject_kind="email", subject="same@example.test"
    )
    assert request.active_subject_hmac != resend.active_subject_hmac
    assert len(request.active_subject_hmac) == 64
    assert "same@example.test" not in request.active_subject_hmac


def test_consume_contract_has_no_caller_clock_or_policy_parameters() -> None:
    assert tuple(signature(SharedRegistrationRateLimiter.require).parameters) == (
        "self",
        "action",
        "subject_kind",
        "subject",
    )
    assert tuple(signature(SharedRegistrationRateLimitJanitor.prune).parameters) == (
        "self",
        "action",
        "subject_kind",
        "batch_size",
    )


def test_sqlite_counter_rejects_non_hex_hmac_like_production(
    sessions: sessionmaker[Session],
) -> None:
    now = datetime(2026, 8, 26, 8, 0, tzinfo=timezone.utc)
    with pytest.raises(sa.exc.IntegrityError):
        with sessions.begin() as db:
            db.add(
                RegistrationRateLimitRecord(
                    action="registration.request",
                    subject_kind="email",
                    key_id="test-v1",
                    subject_hmac="g" * 64,
                    window_started_at=now,
                    request_count=1,
                    expires_at=now + timedelta(minutes=1),
                    policy_revision="registration-rate-limit-v1",
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
