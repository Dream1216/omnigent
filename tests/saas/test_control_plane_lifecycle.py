from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    LifecycleError,
    MembershipInvitation,
    MembershipLifecycleService,
    SaasBase,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
    normalize_email,
)
from saas.control_plane.idempotency import scoped_idempotency_key

NOW = datetime(2026, 8, 4, 3, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class LifecycleFixture:
    service: MembershipLifecycleService
    sessions: sessionmaker[Session]
    actor_id: UUID
    target_id: UUID
    invitee_id: UUID
    outsider_id: UUID
    tenant_id: UUID
    other_tenant_id: UUID
    space_id: UUID
    other_space_id: UUID


@pytest.fixture
def lifecycle() -> LifecycleFixture:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)

    actor_id = uuid4()
    target_id = uuid4()
    invitee_id = uuid4()
    outsider_id = uuid4()
    tenant_id = uuid4()
    other_tenant_id = uuid4()
    space_id = uuid4()
    other_space_id = uuid4()
    with sessions.begin() as db:
        db.add_all(
            [
                GlobalUser(id=actor_id, status="active", security_version=1),
                GlobalUser(id=target_id, status="active", security_version=1),
                GlobalUser(id=invitee_id, status="active", security_version=1),
                GlobalUser(id=outsider_id, status="active", security_version=1),
                Tenant(
                    id=tenant_id,
                    slug="tenant-one",
                    name="Tenant One",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
                Tenant(
                    id=other_tenant_id,
                    slug="tenant-two",
                    name="Tenant Two",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                Space(
                    id=space_id,
                    tenant_id=tenant_id,
                    slug="engineering",
                    name="Engineering",
                    status="active",
                ),
                Space(
                    id=other_space_id,
                    tenant_id=other_tenant_id,
                    slug="other",
                    name="Other",
                    status="active",
                ),
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=actor_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=target_id,
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
                    user_id=actor_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
                SpaceMembership(
                    tenant_id=tenant_id,
                    space_id=space_id,
                    user_id=target_id,
                    role="member",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
                IdentityConnection(
                    user_id=invitee_id,
                    provider="oidc",
                    issuer="https://idp.example.com",
                    subject="invitee-subject",
                    email_normalized="invitee@example.com",
                    email_verified=True,
                    status="active",
                ),
                IdentityConnection(
                    user_id=outsider_id,
                    provider="oidc",
                    issuer="https://idp.example.com",
                    subject="outsider-subject",
                    email_normalized="outsider@example.com",
                    email_verified=True,
                    status="active",
                ),
            ]
        )

    yield LifecycleFixture(
        service=MembershipLifecycleService(sessions),
        sessions=sessions,
        actor_id=actor_id,
        target_id=target_id,
        invitee_id=invitee_id,
        outsider_id=outsider_id,
        tenant_id=tenant_id,
        other_tenant_id=other_tenant_id,
        space_id=space_id,
        other_space_id=other_space_id,
    )
    SaasBase.metadata.drop_all(engine)
    engine.dispose()


def test_auth_session_stores_digest_and_rechecks_security_version(
    lifecycle: LifecycleFixture,
) -> None:
    issued = lifecycle.service.issue_auth_session(
        user_id=lifecycle.target_id,
        authn_method="oidc",
        expires_at=NOW + timedelta(hours=8),
        now=NOW,
    )

    with lifecycle.sessions() as db:
        stored = db.get(AuthSessionRecord, issued.session_id)
        assert stored is not None
        assert stored.token_hash != issued.token
        assert len(stored.token_hash) == 64

    validated = lifecycle.service.validate_auth_session(
        issued.token, now=NOW + timedelta(minutes=1)
    )
    assert validated.user_id == lifecycle.target_id
    assert validated.security_version == 1

    with lifecycle.sessions.begin() as db:
        user = db.get(GlobalUser, lifecycle.target_id)
        assert user is not None
        user.security_version += 1

    with pytest.raises(LifecycleError, match="invalid") as stale:
        lifecycle.service.validate_auth_session(issued.token, now=NOW + timedelta(minutes=2))
    assert stale.value.code == "invalid_session"


def test_invitation_is_email_bound_single_use_and_persist_first(
    lifecycle: LifecycleFixture,
) -> None:
    created = lifecycle.service.create_invitation(
        actor_id=lifecycle.actor_id,
        tenant_id=lifecycle.tenant_id,
        space_id=lifecycle.space_id,
        email=" Invitee@Example.COM ",
        tenant_role="member",
        space_role="operator",
        expires_at=NOW + timedelta(days=2),
        idempotency_key="invite-engineering-1",
        now=NOW,
    )
    assert created.token is not None
    assert not created.replayed

    replay = lifecycle.service.create_invitation(
        actor_id=lifecycle.actor_id,
        tenant_id=lifecycle.tenant_id,
        space_id=lifecycle.space_id,
        email="invitee@example.com",
        tenant_role="member",
        space_role="operator",
        expires_at=NOW + timedelta(days=2),
        idempotency_key="invite-engineering-1",
        now=NOW,
    )
    assert replay.invitation_id == created.invitation_id
    assert replay.token is None
    assert replay.replayed

    with lifecycle.sessions.begin() as db:
        db.add(
            IdentityConnection(
                user_id=lifecycle.invitee_id,
                provider="passkey",
                issuer="https://passkeys.example.com",
                subject="invitee-passkey",
                email_normalized="invitee@example.com",
                email_verified=True,
                status="active",
            )
        )

    with pytest.raises(LifecycleError) as wrong_identity:
        lifecycle.service.accept_invitation(
            actor_id=lifecycle.outsider_id, token=created.token, now=NOW + timedelta(minutes=1)
        )
    assert wrong_identity.value.code == "invitation_identity_mismatch"

    accepted = lifecycle.service.accept_invitation(
        actor_id=lifecycle.invitee_id, token=created.token, now=NOW + timedelta(minutes=2)
    )
    assert accepted.tenant_membership_version == 1
    assert accepted.space_membership_version == 1
    assert not accepted.replayed

    accepted_replay = lifecycle.service.accept_invitation(
        actor_id=lifecycle.invitee_id, token=created.token, now=NOW + timedelta(minutes=3)
    )
    assert accepted_replay == type(accepted)(
        tenant_id=accepted.tenant_id,
        space_id=accepted.space_id,
        tenant_membership_version=1,
        space_membership_version=1,
        replayed=True,
    )

    with lifecycle.sessions() as db:
        invitation = db.get(MembershipInvitation, created.invitation_id)
        assert invitation is not None
        assert invitation.token_hash != created.token
        assert invitation.email_normalized == "invitee@example.com"
        assert invitation.status == "accepted"
        tenant_member = db.get(TenantMembership, (lifecycle.tenant_id, lifecycle.invitee_id))
        space_member = db.get(
            SpaceMembership,
            (lifecycle.tenant_id, lifecycle.space_id, lifecycle.invitee_id),
        )
        assert tenant_member is not None and tenant_member.role == "member"
        assert space_member is not None and space_member.role == "operator"
        events = db.execute(
            sa.select(ControlPlaneOutboxEvent).order_by(ControlPlaneOutboxEvent.created_at)
        ).scalars()
        assert [event.event_type for event in events] == [
            "membership.invitation.created",
            "membership.invitation.accepted",
        ]


def test_invitation_rejects_cross_tenant_space_and_owner_grants(
    lifecycle: LifecycleFixture,
) -> None:
    with pytest.raises(LifecycleError) as cross_tenant:
        lifecycle.service.create_invitation(
            actor_id=lifecycle.actor_id,
            tenant_id=lifecycle.tenant_id,
            space_id=lifecycle.other_space_id,
            email="invitee@example.com",
            tenant_role="member",
            space_role="member",
            expires_at=NOW + timedelta(days=1),
            idempotency_key="cross-tenant-space",
            now=NOW,
        )
    assert cross_tenant.value.code == "space_inactive"

    with pytest.raises(LifecycleError) as owner_grant:
        lifecycle.service.create_invitation(
            actor_id=lifecycle.actor_id,
            tenant_id=lifecycle.tenant_id,
            email="invitee@example.com",
            tenant_role="owner",
            expires_at=NOW + timedelta(days=1),
            idempotency_key="owner-invite",
            now=NOW,
        )
    assert owner_grant.value.code == "ownership_transfer_required"


def test_expired_invitation_cannot_create_memberships(lifecycle: LifecycleFixture) -> None:
    created = lifecycle.service.create_invitation(
        actor_id=lifecycle.actor_id,
        tenant_id=lifecycle.tenant_id,
        email="invitee@example.com",
        tenant_role="member",
        expires_at=NOW + timedelta(minutes=5),
        idempotency_key="short-invite",
        now=NOW,
    )
    assert created.token is not None

    with pytest.raises(LifecycleError) as expired:
        lifecycle.service.accept_invitation(
            actor_id=lifecycle.invitee_id,
            token=created.token,
            now=NOW + timedelta(minutes=6),
        )
    assert expired.value.code == "invalid_invitation"
    with lifecycle.sessions() as db:
        assert db.get(TenantMembership, (lifecycle.tenant_id, lifecycle.invitee_id)) is None


def test_ambiguous_verified_email_fails_closed(lifecycle: LifecycleFixture) -> None:
    created = lifecycle.service.create_invitation(
        actor_id=lifecycle.actor_id,
        tenant_id=lifecycle.tenant_id,
        email="invitee@example.com",
        tenant_role="member",
        expires_at=NOW + timedelta(hours=1),
        idempotency_key="ambiguous-email",
        now=NOW,
    )
    assert created.token is not None
    with lifecycle.sessions.begin() as db:
        db.add(
            IdentityConnection(
                user_id=lifecycle.outsider_id,
                provider="accounts",
                issuer="urn:omnigent:accounts",
                subject="duplicate-email-user",
                email_normalized="invitee@example.com",
                email_verified=True,
                status="active",
            )
        )

    with pytest.raises(LifecycleError) as ambiguous:
        lifecycle.service.accept_invitation(
            actor_id=lifecycle.invitee_id,
            token=created.token,
            now=NOW + timedelta(minutes=1),
        )
    assert ambiguous.value.code == "invitation_identity_ambiguous"


def test_tenant_membership_change_is_cas_idempotent_and_revokes_sessions(
    lifecycle: LifecycleFixture,
) -> None:
    first_session = lifecycle.service.issue_auth_session(
        user_id=lifecycle.target_id,
        authn_method="oidc",
        expires_at=NOW + timedelta(hours=8),
        now=NOW,
    )
    second_session = lifecycle.service.issue_auth_session(
        user_id=lifecycle.target_id,
        authn_method="passkey",
        expires_at=NOW + timedelta(hours=8),
        now=NOW,
    )

    changed = lifecycle.service.update_tenant_membership(
        actor_id=lifecycle.actor_id,
        tenant_id=lifecycle.tenant_id,
        user_id=lifecycle.target_id,
        role="member",
        status="suspended",
        expected_version=1,
        idempotency_key="suspend-target-1",
        now=NOW + timedelta(minutes=1),
    )
    assert changed.membership_version == 2
    assert changed.security_version == 2
    assert changed.revoked_session_count == 2
    assert not changed.replayed

    replay = lifecycle.service.update_tenant_membership(
        actor_id=lifecycle.actor_id,
        tenant_id=lifecycle.tenant_id,
        user_id=lifecycle.target_id,
        role="member",
        status="suspended",
        expected_version=1,
        idempotency_key="suspend-target-1",
        now=NOW + timedelta(minutes=2),
    )
    assert replay.replayed
    assert replay.membership_version == 2
    assert replay.security_version == 2

    for token in (first_session.token, second_session.token):
        with pytest.raises(LifecycleError) as invalid:
            lifecycle.service.validate_auth_session(token, now=NOW + timedelta(minutes=3))
        assert invalid.value.code == "invalid_session"

    with lifecycle.sessions() as db:
        membership = db.get(TenantMembership, (lifecycle.tenant_id, lifecycle.target_id))
        assert membership is not None
        assert (membership.status, membership.version) == ("suspended", 2)
        events = db.execute(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.event_type == "tenant.membership.updated"
            )
        ).scalars()
        assert len(list(events)) == 1


def test_membership_version_conflict_rolls_back_security_invalidation(
    lifecycle: LifecycleFixture,
) -> None:
    issued = lifecycle.service.issue_auth_session(
        user_id=lifecycle.target_id,
        authn_method="oidc",
        expires_at=NOW + timedelta(hours=8),
        now=NOW,
    )

    with pytest.raises(LifecycleError) as conflict:
        lifecycle.service.update_tenant_membership(
            actor_id=lifecycle.actor_id,
            tenant_id=lifecycle.tenant_id,
            user_id=lifecycle.target_id,
            role="member",
            status="suspended",
            expected_version=7,
            idempotency_key="stale-role-change",
            now=NOW + timedelta(minutes=1),
        )
    assert conflict.value.code == "membership_version_conflict"

    validated = lifecycle.service.validate_auth_session(
        issued.token, now=NOW + timedelta(minutes=2)
    )
    assert validated.security_version == 1
    with lifecycle.sessions() as db:
        assert (
            db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key
                    == scoped_idempotency_key("tenant", lifecycle.tenant_id, "stale-role-change")
                )
            ).scalar_one_or_none()
            is None
        )


def test_high_risk_membership_changes_require_dedicated_operations(
    lifecycle: LifecycleFixture,
) -> None:
    with pytest.raises(LifecycleError) as elevation:
        lifecycle.service.update_tenant_membership(
            actor_id=lifecycle.actor_id,
            tenant_id=lifecycle.tenant_id,
            user_id=lifecycle.target_id,
            role="admin",
            status="active",
            expected_version=1,
            idempotency_key="admin-elevation",
            now=NOW,
        )
    assert elevation.value.code == "privileged_role_operation_required"

    with pytest.raises(LifecycleError) as removal:
        lifecycle.service.update_space_membership(
            actor_id=lifecycle.actor_id,
            tenant_id=lifecycle.tenant_id,
            space_id=lifecycle.space_id,
            user_id=lifecycle.target_id,
            role="member",
            status="removed",
            expected_version=1,
            idempotency_key="remove-member",
            now=NOW,
        )
    assert removal.value.code == "membership_removal_preflight_required"


def test_idempotency_key_cannot_be_reused_for_different_mutation(
    lifecycle: LifecycleFixture,
) -> None:
    lifecycle.service.update_space_membership(
        actor_id=lifecycle.actor_id,
        tenant_id=lifecycle.tenant_id,
        space_id=lifecycle.space_id,
        user_id=lifecycle.target_id,
        role="operator",
        status="active",
        expected_version=1,
        idempotency_key="space-role-change",
        now=NOW,
    )

    with pytest.raises(LifecycleError) as reused:
        lifecycle.service.update_space_membership(
            actor_id=lifecycle.actor_id,
            tenant_id=lifecycle.tenant_id,
            space_id=lifecycle.space_id,
            user_id=lifecycle.target_id,
            role="admin",
            status="active",
            expected_version=1,
            idempotency_key="space-role-change",
            now=NOW + timedelta(minutes=1),
        )
    assert reused.value.code == "idempotency_conflict"


def test_identity_subject_is_unique_and_email_is_not_identity_authority(
    lifecycle: LifecycleFixture,
) -> None:
    assert normalize_email(" Shared@Example.com ") == "shared@example.com"
    with pytest.raises(IntegrityError):
        with lifecycle.sessions.begin() as db:
            db.add(
                IdentityConnection(
                    user_id=lifecycle.target_id,
                    provider="oidc",
                    issuer="https://idp.example.com",
                    subject="invitee-subject",
                    email_normalized="shared@example.com",
                    email_verified=True,
                    status="active",
                )
            )
