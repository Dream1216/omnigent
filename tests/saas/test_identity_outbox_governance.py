from __future__ import annotations

import json
import traceback
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityManagementService,
    LifecycleError,
    MembershipGovernanceService,
    MembershipLifecycleService,
    OutboxDispatcher,
    PasswordCredentialService,
    RemovalImpact,
    SaasBase,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
    VerifiedIdentityAssertion,
)
from saas.control_plane.db_models import ControlPlaneOutboxQuarantineEvent
from saas.control_plane.onboarding import (
    EmailVerificationMessage,
    OnboardingOutboxPublisher,
)
from saas.control_plane.outbox import (
    OutboxClaimRoute,
    OutboxPublishError,
    _quarantine_event_hash,
)

NOW = datetime(2026, 8, 4, 4, 0, tzinfo=timezone.utc)


@pytest.fixture
def sessions() -> sessionmaker[Session]:
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
    factory = sessionmaker(engine, expire_on_commit=True)
    yield factory
    SaasBase.metadata.drop_all(engine)
    engine.dispose()


def _assertion(subject: str, email: str = "same@example.com") -> VerifiedIdentityAssertion:
    return VerifiedIdentityAssertion(
        provider="oidc",
        issuer="https://idp.example.com",
        subject=subject,
        email=email,
        email_verified=True,
    )


def test_identity_email_never_auto_merges_and_last_login_method_is_preserved(
    sessions: sessionmaker[Session],
) -> None:
    identities = IdentityManagementService(sessions)
    first = identities.provision_identity(_assertion("subject-a"))
    second = identities.provision_identity(_assertion("subject-b"))

    assert first != second
    with pytest.raises(LifecycleError) as error:
        identities.revoke_identity(
            user_id=first,
            connection_id=identities.list_identities(first)[0].id,
            idempotency_key="remove-last-method",
            now=NOW,
        )
    assert error.value.code == "last_login_method"


def test_password_credentials_lock_rotate_and_revoke_sessions(
    sessions: sessionmaker[Session],
) -> None:
    identities = IdentityManagementService(sessions)
    lifecycle = MembershipLifecycleService(sessions)
    passwords = PasswordCredentialService(sessions)
    user_id = identities.provision_identity(_assertion("password-user", "user@example.com"))

    changed = passwords.set_password(
        user_id=user_id,
        new_password="initial-password-value",
        expected_version=None,
        idempotency_key="password-initial",
        now=NOW,
    )
    assert changed.password_version == 1
    assert passwords.authenticate("USER@example.com", "initial-password-value", now=NOW) == user_id

    issued = lifecycle.issue_auth_session(
        user_id=user_id,
        authn_method="password",
        expires_at=NOW + timedelta(hours=8),
        now=NOW,
    )
    rotated = passwords.set_password(
        user_id=user_id,
        new_password="rotated-password-value",
        current_password="initial-password-value",
        expected_version=1,
        idempotency_key="password-rotate",
        now=NOW + timedelta(minutes=1),
    )
    assert rotated.password_version == 2
    assert rotated.revoked_session_count == 1
    replayed = passwords.set_password(
        user_id=user_id,
        new_password="rotated-password-value",
        current_password="initial-password-value",
        expected_version=1,
        idempotency_key="password-rotate",
        now=NOW + timedelta(minutes=1),
    )
    assert replayed.replayed
    with pytest.raises(LifecycleError):
        lifecycle.validate_auth_session(issued.token, now=NOW + timedelta(minutes=2))

    for _ in range(5):
        with pytest.raises(LifecycleError):
            passwords.authenticate("user@example.com", "wrong-password", now=NOW)
    with pytest.raises(LifecycleError):
        passwords.authenticate("user@example.com", "rotated-password-value", now=NOW)
    assert (
        passwords.authenticate(
            "user@example.com",
            "rotated-password-value",
            now=NOW + timedelta(minutes=16),
        )
        == user_id
    )


def test_password_idempotency_keys_are_isolated_per_global_user(
    sessions: sessionmaker[Session],
) -> None:
    identities = IdentityManagementService(sessions)
    passwords = PasswordCredentialService(sessions)
    first_id = identities.provision_identity(_assertion("password-scope-a", "scope-a@example.com"))
    second_id = identities.provision_identity(
        _assertion("password-scope-b", "scope-b@example.com")
    )

    first = passwords.set_password(
        user_id=first_id,
        new_password="scope-a-password-value",
        expected_version=None,
        idempotency_key="shared-password-key",
        now=NOW,
    )
    second = passwords.set_password(
        user_id=second_id,
        new_password="scope-b-password-value",
        expected_version=None,
        idempotency_key="shared-password-key",
        now=NOW,
    )

    assert first.password_version == second.password_version == 1
    with sessions() as db:
        stored_keys = list(
            db.execute(
                sa.select(ControlPlaneOutboxEvent.idempotency_key).where(
                    ControlPlaneOutboxEvent.event_type == "identity.password.changed"
                )
            ).scalars()
        )
    assert len(stored_keys) == len(set(stored_keys)) == 2


class _RecordingPublisher:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.ids: list[UUID] = []

    def publish(self, *, event_id: UUID, **_event: object) -> None:
        self.ids.append(event_id)
        if self.fail:
            raise RuntimeError("broker unavailable")


def _add_outbox_event(sessions: sessionmaker[Session], event_id: UUID) -> None:
    with sessions.begin() as db:
        db.add(
            ControlPlaneOutboxEvent(
                id=event_id,
                tenant_id=None,
                aggregate_type="global_user",
                aggregate_key="user-1",
                event_type="test.created",
                idempotency_key=f"event-{event_id}",
                request_hash="a" * 64,
                payload={"value": 1},
                attempt_count=0,
            )
        )


def test_outbox_dispatcher_is_detached_safe_and_retries_with_backoff(
    sessions: sessionmaker[Session],
) -> None:
    first_id = uuid4()
    _add_outbox_event(sessions, first_id)
    publisher = _RecordingPublisher()
    dispatcher = OutboxDispatcher(sessions, publisher)

    first = dispatcher.dispatch_once(now=NOW)
    assert (first.claimed, first.published, first.failed) == (1, 1, 0)
    assert publisher.ids == [first_id]
    assert dispatcher.dispatch_once(now=NOW).claimed == 0

    second_id = uuid4()
    _add_outbox_event(sessions, second_id)
    publisher.fail = True
    failed = dispatcher.dispatch_once(now=NOW)
    assert (failed.claimed, failed.published, failed.failed) == (1, 0, 1)
    assert dispatcher.dispatch_once(now=NOW).claimed == 0
    publisher.fail = False
    retried = dispatcher.dispatch_once(now=NOW + timedelta(seconds=2))
    assert (retried.claimed, retried.published, retried.failed) == (1, 1, 0)
    with sessions() as db:
        stored = db.get(ControlPlaneOutboxEvent, second_id)
        assert stored is not None
        assert stored.attempt_count == 2
        assert stored.published_at is not None


def test_outbox_dispatcher_claim_route_leaves_unowned_events_unmodified(
    sessions: sessionmaker[Session],
) -> None:
    unrelated_id = uuid4()
    queued_id = uuid4()
    _add_outbox_event(sessions, unrelated_id)
    with sessions.begin() as db:
        db.add(
            ControlPlaneOutboxEvent(
                id=queued_id,
                tenant_id=None,
                aggregate_type="run",
                aggregate_key="run-1",
                event_type="run.event.persisted",
                idempotency_key=f"event-{queued_id}",
                request_hash="b" * 64,
                payload={"event_type": "run.queued"},
                attempt_count=0,
            )
        )
    publisher = _RecordingPublisher()
    dispatcher = OutboxDispatcher(
        sessions,
        publisher,
        claim_routes=(OutboxClaimRoute("run", "run.event.persisted", "run.queued"),),
    )

    result = dispatcher.dispatch_once(batch_size=1, now=NOW)

    assert (result.claimed, result.published, result.failed) == (1, 1, 0)
    assert publisher.ids == [queued_id]
    with sessions() as db:
        unrelated = db.get(ControlPlaneOutboxEvent, unrelated_id)
        queued = db.get(ControlPlaneOutboxEvent, queued_id)
        assert unrelated is not None and queued is not None
        assert unrelated.attempt_count == 0
        assert unrelated.claimed_at is None
        assert unrelated.claim_token is None
        assert unrelated.published_at is None
        assert queued.published_at is not None


def test_outbox_dispatcher_rejects_empty_duplicate_or_invalid_claim_routes(
    sessions: sessionmaker[Session],
) -> None:
    publisher = _RecordingPublisher()
    route = OutboxClaimRoute("run", "run.event.persisted", "run.queued")

    with pytest.raises(ValueError, match="non-empty"):
        OutboxDispatcher(sessions, publisher, claim_routes=())
    with pytest.raises(ValueError, match="unique"):
        OutboxDispatcher(sessions, publisher, claim_routes=(route, route))
    with pytest.raises(ValueError, match="route is invalid"):
        OutboxClaimRoute("run", "run.event.persisted", "Run Queued")


def test_nonretryable_pre_side_effect_error_is_quarantined_once_without_secret(
    sessions: sessionmaker[Session],
) -> None:
    event_id = uuid4()
    _add_outbox_event(sessions, event_id)

    class PoisonPublisher:
        def publish(self, **_event: object) -> None:
            raise OutboxPublishError(
                "onboarding_event_invalid",
                retryable=False,
                pre_side_effect=True,
            )

    dispatcher = OutboxDispatcher(sessions, PoisonPublisher())
    result = dispatcher.dispatch_once(now=NOW)

    assert (result.claimed, result.published, result.failed, result.quarantined) == (1, 0, 1, 1)
    assert dispatcher.dispatch_once(now=NOW + timedelta(days=1)).claimed == 0
    with sessions() as db:
        source = db.get(ControlPlaneOutboxEvent, event_id)
        receipt = db.scalar(
            sa.select(ControlPlaneOutboxQuarantineEvent).where(
                ControlPlaneOutboxQuarantineEvent.source_event_id == event_id
            )
        )
        assert source is not None and receipt is not None
        assert source.published_at is None
        assert source.quarantined_at is not None
        assert source.available_at is None
        assert source.claimed_at is None
        assert source.claim_token is None
        assert source.last_error is None
        assert source.last_error_code == "onboarding_event_invalid"
        assert receipt.sequence == 1
        assert receipt.previous_hash == "0" * 64
        assert receipt.event_hash == _quarantine_event_hash(
            source_event_id=receipt.source_event_id,
            tenant_id=receipt.tenant_id,
            source_request_hash=receipt.source_request_hash,
            source_attempt_count=receipt.source_attempt_count,
            action=receipt.action,
            error_code=receipt.error_code,
            error_digest=receipt.error_digest,
            sequence=receipt.sequence,
            previous_hash=receipt.previous_hash,
            created_at=receipt.created_at,
        )
        serialized = json.dumps(
            {
                "last_error": source.last_error,
                "last_error_code": source.last_error_code,
                "last_error_digest": source.last_error_digest,
                "receipt_error_code": receipt.error_code,
                "receipt_error_digest": receipt.error_digest,
            },
            sort_keys=True,
        )
        assert "customer-secret" not in serialized


@pytest.mark.parametrize("code", ("", "UPPERCASE", "line\nbreak", "../escape", "x" * 129))
def test_outbox_publish_error_rejects_unsafe_persisted_codes(code: str) -> None:
    with pytest.raises(ValueError, match="code is invalid"):
        OutboxPublishError(code, retryable=False, pre_side_effect=True)


def test_unknown_failure_retries_then_quarantines_at_budget_without_raw_error(
    sessions: sessionmaker[Session],
) -> None:
    event_id = uuid4()
    _add_outbox_event(sessions, event_id)

    class UnknownFailurePublisher:
        def publish(self, **_event: object) -> None:
            raise RuntimeError("provider rejected customer-secret")

    dispatcher = OutboxDispatcher(sessions, UnknownFailurePublisher(), max_attempts=2)
    first = dispatcher.dispatch_once(now=NOW)
    assert (first.failed, first.quarantined) == (1, 0)
    with sessions() as db:
        source = db.get(ControlPlaneOutboxEvent, event_id)
        assert source is not None
        assert source.last_error is None
        assert source.last_error_code == "outbox_publish_failed"
        assert source.quarantined_at is None

    terminal = dispatcher.dispatch_once(now=NOW + timedelta(seconds=1))
    assert (terminal.failed, terminal.quarantined) == (1, 1)
    with sessions() as db:
        source = db.get(ControlPlaneOutboxEvent, event_id)
        receipt = db.scalar(
            sa.select(ControlPlaneOutboxQuarantineEvent).where(
                ControlPlaneOutboxQuarantineEvent.source_event_id == event_id
            )
        )
        assert source is not None and receipt is not None
        assert source.attempt_count == 2
        assert source.last_error is None
        assert source.last_error_code == "outbox_retry_exhausted"
        assert receipt.error_code == "outbox_retry_exhausted"
        assert receipt.error_digest == source.last_error_digest
        assert "customer-secret" not in json.dumps(
            {
                "code": receipt.error_code,
                "digest": receipt.error_digest,
                "legacy": source.last_error,
            }
        )


def test_failure_state_database_error_suppresses_provider_exception_chain(
    sessions: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = uuid4()
    _add_outbox_event(sessions, event_id)

    class SecretFailurePublisher:
        def publish(self, **_event: object) -> None:
            raise RuntimeError("provider-secret-value")

    dispatcher = OutboxDispatcher(sessions, SecretFailurePublisher())

    def fail_release(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("database-secret-value")

    monkeypatch.setattr(dispatcher, "_release_failure", fail_release)
    with pytest.raises(RuntimeError) as raised:
        dispatcher.dispatch_once(now=NOW)

    rendered = "".join(
        traceback.format_exception(type(raised.value), raised.value, raised.value.__traceback__)
    )
    assert str(raised.value) == "Outbox failure-state persistence failed"
    assert raised.value.__suppress_context__
    assert "provider-secret-value" not in rendered
    assert "database-secret-value" not in rendered


def test_poison_event_does_not_block_the_rest_of_a_claimed_batch(
    sessions: sessionmaker[Session],
) -> None:
    first_id, second_id = uuid4(), uuid4()
    with sessions.begin() as db:
        for index, event_id in enumerate((first_id, second_id)):
            db.add(
                ControlPlaneOutboxEvent(
                    id=event_id,
                    tenant_id=None,
                    aggregate_type="global_user",
                    aggregate_key=str(event_id),
                    event_type=f"test.batch.{index}",
                    idempotency_key=f"event-{event_id}",
                    request_hash="d" * 64,
                    payload={"value": index},
                    attempt_count=0,
                    created_at=NOW + timedelta(microseconds=index),
                )
            )

    class PartialPoisonPublisher:
        def publish(self, *, event_id: UUID, **_event: object) -> None:
            if event_id == first_id:
                raise OutboxPublishError(
                    "onboarding_event_invalid",
                    retryable=False,
                    pre_side_effect=True,
                )

    result = OutboxDispatcher(sessions, PartialPoisonPublisher()).dispatch_once(
        batch_size=2, now=NOW
    )
    assert (result.claimed, result.published, result.failed, result.quarantined) == (2, 1, 1, 1)
    with sessions() as db:
        assert db.get(ControlPlaneOutboxEvent, first_id).quarantined_at is not None
        assert db.get(ControlPlaneOutboxEvent, second_id).published_at is not None


def test_stale_claim_cannot_quarantine_or_append_evidence(
    sessions: sessionmaker[Session],
) -> None:
    event_id = uuid4()
    takeover_token = uuid4()
    takeover_at = NOW + timedelta(seconds=31)
    _add_outbox_event(sessions, event_id)

    class LeaseTakingPoisonPublisher:
        def publish(self, **_event: object) -> None:
            with sessions.begin() as db:
                result = db.execute(
                    sa.update(ControlPlaneOutboxEvent)
                    .where(ControlPlaneOutboxEvent.id == event_id)
                    .values(
                        claimed_at=takeover_at,
                        claim_token=takeover_token,
                        attempt_count=ControlPlaneOutboxEvent.attempt_count + 1,
                    )
                )
                assert result.rowcount == 1
            raise OutboxPublishError(
                "onboarding_event_invalid",
                retryable=False,
                pre_side_effect=True,
            )

    result = OutboxDispatcher(sessions, LeaseTakingPoisonPublisher()).dispatch_once(now=NOW)
    assert (result.failed, result.quarantined) == (1, 0)
    with sessions() as db:
        source = db.get(ControlPlaneOutboxEvent, event_id)
        assert source is not None
        assert source.claim_token == takeover_token
        assert source.quarantined_at is None
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxQuarantineEvent)
                .where(ControlPlaneOutboxQuarantineEvent.source_event_id == event_id)
            )
            == 0
        )


def test_onboarding_publisher_classifies_malformed_scope_and_provider_failure() -> None:
    verification_message = EmailVerificationMessage(
        registration_id=uuid4(),
        challenge_id=uuid4(),
        email="redacted@example.test",
        verification_token="one-time",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    class Registrations:
        def email_delivery_is_current(self, *, message: object) -> bool:
            del message
            return True

        def record_email_delivery(self, **_values: object) -> None:
            return None

    class Envelopes:
        def open(self, **_values: object) -> EmailVerificationMessage:
            return verification_message

    class Sender:
        def send_verification(self, **_values: object) -> None:
            raise RuntimeError("provider customer-secret")

    publisher = OnboardingOutboxPublisher(
        registrations=Registrations(),  # type: ignore[arg-type]
        coordinator=object(),  # type: ignore[arg-type]
        envelopes=Envelopes(),  # type: ignore[arg-type]
        email_sender=Sender(),  # type: ignore[arg-type]
    )
    with pytest.raises(OutboxPublishError) as malformed:
        publisher.publish(
            event_id=uuid4(),
            event_type="onboarding.tenant.requested",
            aggregate_type="tenant_onboarding",
            aggregate_key="wrong",
            payload={"registration_id": str(uuid4()), "onboarding_id": str(uuid4())},
        )
    assert (malformed.value.retryable, malformed.value.pre_side_effect) == (False, True)

    with pytest.raises(OutboxPublishError) as provider:
        publisher.publish(
            event_id=uuid4(),
            event_type="onboarding.email_verification.requested",
            aggregate_type="self_service_registration",
            aggregate_key=str(verification_message.registration_id),
            payload={},
        )
    assert provider.value.code == "email_verification_delivery_failed"
    assert (provider.value.retryable, provider.value.pre_side_effect) == (True, False)


def test_outbox_lost_ack_is_an_event_failure_and_preserves_new_owner_claim(
    sessions: sessionmaker[Session],
) -> None:
    first_id, second_id = uuid4(), uuid4()
    takeover_token = uuid4()
    takeover_at = NOW + timedelta(seconds=31)
    with sessions.begin() as db:
        db.add_all(
            (
                ControlPlaneOutboxEvent(
                    id=first_id,
                    tenant_id=None,
                    aggregate_type="global_user",
                    aggregate_key="user-1",
                    event_type="test.first",
                    idempotency_key=f"event-{first_id}",
                    request_hash="b" * 64,
                    payload={"value": 1},
                    attempt_count=0,
                    created_at=NOW,
                ),
                ControlPlaneOutboxEvent(
                    id=second_id,
                    tenant_id=None,
                    aggregate_type="global_user",
                    aggregate_key="user-2",
                    event_type="test.second",
                    idempotency_key=f"event-{second_id}",
                    request_hash="c" * 64,
                    payload={"value": 2},
                    attempt_count=0,
                    created_at=NOW + timedelta(microseconds=1),
                ),
            )
        )

    class LeaseTakingPublisher:
        def __init__(self) -> None:
            self.ids: list[UUID] = []

        def publish(self, *, event_id: UUID, **_event: object) -> None:
            self.ids.append(event_id)
            if event_id != first_id:
                return
            # Model another worker taking over the first event after the old
            # lease expired but before this publisher returned to acknowledge.
            with sessions.begin() as db:
                result = db.execute(
                    sa.update(ControlPlaneOutboxEvent)
                    .where(
                        ControlPlaneOutboxEvent.id == first_id,
                        ControlPlaneOutboxEvent.published_at.is_(None),
                        ControlPlaneOutboxEvent.claimed_at < takeover_at - timedelta(seconds=30),
                    )
                    .values(
                        claimed_at=takeover_at,
                        claim_token=takeover_token,
                        attempt_count=ControlPlaneOutboxEvent.attempt_count + 1,
                        last_error=None,
                    )
                )
                assert result.rowcount == 1

    publisher = LeaseTakingPublisher()
    dispatcher = OutboxDispatcher(
        sessions,
        publisher,
        lease_duration=timedelta(seconds=30),
    )

    result = dispatcher.dispatch_once(batch_size=2, now=NOW)

    assert (result.claimed, result.published, result.failed) == (2, 1, 1)
    assert publisher.ids == [first_id, second_id]
    with sessions() as db:
        first = db.get(ControlPlaneOutboxEvent, first_id)
        second = db.get(ControlPlaneOutboxEvent, second_id)
        assert first is not None and second is not None
        assert first.claim_token == takeover_token
        assert first.claimed_at is not None
        assert first.published_at is None
        assert first.attempt_count == 2
        assert second.claim_token is None
        assert second.published_at is not None


class _ImpactProvider:
    def __init__(self) -> None:
        self.impact = RemovalImpact(facts={"owned_resources": []}, blocking_count=0)

    def collect(self, **_scope: object) -> RemovalImpact:
        return self.impact


def _seed_governance(sessions: sessionmaker[Session]) -> tuple[UUID, UUID, UUID, UUID]:
    owner_id, member_id, tenant_id, space_id = uuid4(), uuid4(), uuid4(), uuid4()
    with sessions.begin() as db:
        db.add_all(
            [
                GlobalUser(id=owner_id, status="active", security_version=1),
                GlobalUser(id=member_id, status="active", security_version=1),
                Tenant(
                    id=tenant_id,
                    slug=f"governance-{tenant_id.hex}",
                    name="Governance",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
            ]
        )
        db.flush()
        db.add(
            Space(
                id=space_id,
                tenant_id=tenant_id,
                slug=f"engineering-{space_id.hex}",
                name="Engineering",
                status="active",
            )
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=owner_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=member_id,
                    role="member",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                SpaceMembership(
                    tenant_id=tenant_id,
                    space_id=space_id,
                    user_id=owner_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
                SpaceMembership(
                    tenant_id=tenant_id,
                    space_id=space_id,
                    user_id=member_id,
                    role="member",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
            ]
        )
    return owner_id, member_id, tenant_id, space_id


def test_owner_transfer_is_atomic_idempotent_and_revokes_both_users(
    sessions: sessionmaker[Session],
) -> None:
    owner_id, member_id, tenant_id, _space_id = _seed_governance(sessions)
    lifecycle = MembershipLifecycleService(sessions)
    owner_session = lifecycle.issue_auth_session(
        user_id=owner_id,
        authn_method="password",
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )
    member_session = lifecycle.issue_auth_session(
        user_id=member_id,
        authn_method="password",
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )
    service = MembershipGovernanceService(sessions, _ImpactProvider())
    result = service.transfer_ownership(
        actor_id=owner_id,
        tenant_id=tenant_id,
        from_user_id=owner_id,
        to_user_id=member_id,
        source_expected_version=1,
        target_expected_version=1,
        reason="handover to the new team owner",
        reauthenticated_at=NOW,
        idempotency_key="transfer-owner",
        now=NOW,
    )
    assert (result.source_version, result.target_version, result.replayed) == (2, 2, False)
    replay = service.transfer_ownership(
        actor_id=owner_id,
        tenant_id=tenant_id,
        from_user_id=owner_id,
        to_user_id=member_id,
        source_expected_version=1,
        target_expected_version=1,
        reason="handover to the new team owner",
        reauthenticated_at=NOW,
        idempotency_key="transfer-owner",
        now=NOW,
    )
    assert replay.replayed
    with sessions() as db:
        assert db.get(TenantMembership, (tenant_id, owner_id)).role == "admin"  # type: ignore[union-attr]
        assert db.get(TenantMembership, (tenant_id, member_id)).role == "owner"  # type: ignore[union-attr]
    with pytest.raises(LifecycleError):
        lifecycle.validate_auth_session(owner_session.token, now=NOW)
    with pytest.raises(LifecycleError):
        lifecycle.validate_auth_session(member_session.token, now=NOW)


def test_owner_transfer_idempotency_keys_are_isolated_per_tenant(
    sessions: sessionmaker[Session],
) -> None:
    first_owner, first_target, first_tenant, _ = _seed_governance(sessions)
    second_owner, second_target, second_tenant, _ = _seed_governance(sessions)
    service = MembershipGovernanceService(sessions, _ImpactProvider())

    for owner_id, target_id, tenant_id in (
        (first_owner, first_target, first_tenant),
        (second_owner, second_target, second_tenant),
    ):
        transferred = service.transfer_ownership(
            actor_id=owner_id,
            tenant_id=tenant_id,
            from_user_id=owner_id,
            to_user_id=target_id,
            source_expected_version=1,
            target_expected_version=1,
            reason="same public key in an isolated tenant",
            reauthenticated_at=NOW,
            idempotency_key="shared-owner-transfer-key",
            now=NOW,
        )
        assert transferred.replayed is False


def test_member_removal_revalidates_impact_and_cascades_space_memberships(
    sessions: sessionmaker[Session],
) -> None:
    owner_id, member_id, tenant_id, space_id = _seed_governance(sessions)
    impact = _ImpactProvider()
    service = MembershipGovernanceService(sessions, impact)
    preflight = service.create_removal_preflight(
        actor_id=owner_id,
        tenant_id=tenant_id,
        user_id=member_id,
        idempotency_key="preflight-member",
        now=NOW,
    )
    assert preflight.status == "ready"

    impact.impact = RemovalImpact(facts={"owned_resources": ["project-1"]}, blocking_count=1)
    with pytest.raises(LifecycleError) as stale:
        service.execute_member_removal(
            actor_id=owner_id,
            tenant_id=tenant_id,
            preflight_id=preflight.preflight_id,
            reason="member left the company",
            reauthenticated_at=NOW,
            idempotency_key="remove-member",
            now=NOW,
        )
    assert stale.value.code == "preflight_stale"

    impact.impact = RemovalImpact(facts={"owned_resources": []}, blocking_count=0)
    removed = service.execute_member_removal(
        actor_id=owner_id,
        tenant_id=tenant_id,
        preflight_id=preflight.preflight_id,
        reason="member left the company",
        reauthenticated_at=NOW,
        idempotency_key="remove-member",
        now=NOW,
    )
    assert removed.removed_space_memberships == 1
    impact.impact = RemovalImpact(facts={"owned_resources": ["changed"]}, blocking_count=1)
    assert service.create_removal_preflight(
        actor_id=owner_id,
        tenant_id=tenant_id,
        user_id=member_id,
        idempotency_key="preflight-member",
        now=NOW,
    ).replayed
    assert service.execute_member_removal(
        actor_id=owner_id,
        tenant_id=tenant_id,
        preflight_id=preflight.preflight_id,
        reason="member left the company",
        reauthenticated_at=NOW,
        idempotency_key="remove-member",
        now=NOW,
    ).replayed
    with sessions() as db:
        tenant_member = db.get(TenantMembership, (tenant_id, member_id))
        space_member = db.get(SpaceMembership, (tenant_id, space_id, member_id))
        assert tenant_member is not None and tenant_member.status == "removed"
        assert space_member is not None and space_member.status == "removed"


def test_removal_fails_closed_without_resource_impact_provider(
    sessions: sessionmaker[Session],
) -> None:
    owner_id, member_id, tenant_id, _space_id = _seed_governance(sessions)
    service = MembershipGovernanceService(sessions)
    with pytest.raises(LifecycleError) as error:
        service.create_removal_preflight(
            actor_id=owner_id,
            tenant_id=tenant_id,
            user_id=member_id,
            idempotency_key="no-impact-provider",
            now=NOW,
        )
    assert error.value.code == "removal_impact_provider_unavailable"
