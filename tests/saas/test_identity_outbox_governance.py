from __future__ import annotations

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
                    slug="governance",
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
                slug="engineering",
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
