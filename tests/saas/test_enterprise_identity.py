from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    SaasBase,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.enterprise_identity import EnterpriseScimService
from saas.control_plane.enterprise_identity_models import (
    EnterpriseScimDirectoryRecord,
    EnterpriseScimEventRecord,
    EnterpriseScimUserRecord,
)
from saas.control_plane.enterprise_models import EnterpriseGroupMembershipRecord
from saas.control_plane.lifecycle import LifecycleError


@dataclass(frozen=True, slots=True)
class _Ids:
    tenant: UUID
    space: UUID
    owner: UUID
    member: UUID


@pytest.fixture
def scim_fixture() -> tuple[sessionmaker[Session], _Ids]:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @sa.event.listens_for(engine, "connect")
    def _foreign_keys(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    ids = _Ids(*(uuid4() for _ in range(4)))
    with sessions.begin() as db:
        db.add_all(
            [
                GlobalUser(id=ids.owner, status="active", security_version=1),
                GlobalUser(id=ids.member, status="active", security_version=1),
                Tenant(
                    id=ids.tenant,
                    slug="scim-enterprise",
                    name="SCIM Enterprise",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=ids.tenant,
                    user_id=ids.owner,
                    role="owner",
                    status="active",
                    version=1,
                ),
                TenantMembership(
                    tenant_id=ids.tenant,
                    user_id=ids.member,
                    role="member",
                    status="active",
                    version=1,
                ),
                Space(
                    id=ids.space,
                    tenant_id=ids.tenant,
                    slug="main",
                    name="Main",
                    status="active",
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                SpaceMembership(
                    tenant_id=ids.tenant,
                    space_id=ids.space,
                    user_id=ids.owner,
                    role="owner",
                    status="active",
                    version=1,
                ),
                SpaceMembership(
                    tenant_id=ids.tenant,
                    space_id=ids.space,
                    user_id=ids.member,
                    role="member",
                    status="active",
                    version=1,
                ),
            ]
        )
    return sessions, ids


def _context(ids: _Ids, actor_id: UUID) -> RequestContext:
    return RequestContext(
        actor_id=actor_id,
        tenant_id=ids.tenant,
        space_id=ids.space,
        project_id=None,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="pc5-scim",
    )


def _directory(service: EnterpriseScimService, ids: _Ids) -> str:
    issued = service.issue_directory(
        _context(ids, ids.owner),
        display_name="Corporate IdP",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="directory-1",
    )
    assert issued.bearer_token is not None
    return issued.bearer_token


def test_directory_token_is_one_time_hash_stored_and_permission_guarded(scim_fixture) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)

    with pytest.raises(LifecycleError, match="enterprise identity management") as denied:
        service.issue_directory(
            _context(ids, ids.member),
            display_name="Unauthorized",
            reauthenticated_at=datetime.now(timezone.utc),
            idempotency_key="denied-directory",
        )
    assert denied.value.code == "enterprise_identity_manage_forbidden"

    issued = service.issue_directory(
        _context(ids, ids.owner),
        display_name="Corporate IdP",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="directory-1",
    )
    assert issued.bearer_token is not None
    replay = service.issue_directory(
        _context(ids, ids.owner),
        display_name="Corporate IdP",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="directory-1",
    )
    assert replay.id == issued.id
    assert replay.replayed is True
    assert replay.bearer_token is None

    with sessions() as db:
        stored = db.get(EnterpriseScimDirectoryRecord, issued.id)
        assert stored is not None
        assert stored.token_hash == sha256(issued.bearer_token.encode()).hexdigest()
        assert issued.bearer_token not in str(db.scalars(sa.select(ControlPlaneOutboxEvent)).all())

    with pytest.raises(LifecycleError, match="recent authentication") as stale:
        service.issue_directory(
            _context(ids, ids.owner),
            display_name="Stale authentication",
            reauthenticated_at=datetime.now(timezone.utc) - timedelta(minutes=6),
            idempotency_key="stale-auth-directory",
        )
    assert stale.value.code == "fresh_auth_required"


def test_deprovision_wins_over_late_group_update_and_replay_is_idempotent(scim_fixture) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    token = _directory(service, ids)

    created = service.upsert_user(
        token,
        event_id="user-create-1",
        external_id="employee-42",
        user_name="Employee42@Example.com",
        display_name="Employee 42",
        active=True,
        source_version=1,
    )
    assert created.active is True
    assert created.user_id is not None
    with sessions.begin() as db:
        db.add(
            AuthSessionRecord(
                id=uuid4(),
                user_id=created.user_id,
                token_hash=sha256(b"scim-session").hexdigest(),
                security_version=1,
                authn_method="oidc",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )

    initial_group = service.sync_group(
        token,
        event_id="group-sync-1",
        external_id="engineering",
        display_name="Engineering",
        member_external_ids=["employee-42"],
        active=True,
        source_version=1,
    )
    assert initial_group.active_member_count == 1

    deprovisioned = service.upsert_user(
        token,
        event_id="user-deprovision-2",
        external_id="employee-42",
        user_name="employee42@example.com",
        display_name="Employee 42",
        active=False,
        source_version=2,
    )
    assert deprovisioned.active is False
    assert deprovisioned.membership_status == "removed"
    assert deprovisioned.revoked_session_count == 1

    late_group = service.sync_group(
        token,
        event_id="group-sync-2",
        external_id="engineering",
        display_name="Engineering",
        member_external_ids=["employee-42"],
        active=True,
        source_version=2,
    )
    assert late_group.disposition == "blocked"
    assert late_group.blocked_external_ids == ("employee-42",)
    assert late_group.active_member_count == 0

    replay = service.sync_group(
        token,
        event_id="group-sync-2",
        external_id="engineering",
        display_name="Engineering",
        member_external_ids=["employee-42"],
        active=True,
        source_version=2,
    )
    assert replay.replayed is True
    assert replay.active_member_count == 0

    stale_user = service.upsert_user(
        token,
        event_id="late-user-active-1",
        external_id="employee-42",
        user_name="employee42@example.com",
        display_name="Employee 42",
        active=True,
        source_version=1,
    )
    assert stale_user.disposition == "stale"
    assert stale_user.active is False

    with sessions() as db:
        membership = db.get(TenantMembership, (ids.tenant, created.user_id))
        assert membership is not None and membership.status == "removed"
        group_membership = db.get(
            EnterpriseGroupMembershipRecord,
            (initial_group.enterprise_group_id, created.user_id),
        )
        assert group_membership is not None and group_membership.status == "removed"
        assert db.scalar(sa.select(sa.func.count()).select_from(EnterpriseScimEventRecord)) == 5


def test_only_newer_explicit_user_event_reactivates_and_email_never_merges(scim_fixture) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    token = _directory(service, ids)

    first = service.upsert_user(
        token,
        event_id="user-a-1",
        external_id="employee-a",
        user_name="shared@example.com",
        display_name="Employee A",
        active=True,
        source_version=1,
    )
    second = service.upsert_user(
        token,
        event_id="user-b-1",
        external_id="employee-b",
        user_name="shared@example.com",
        display_name="Employee B",
        active=True,
        source_version=1,
    )
    assert first.user_id is not None and second.user_id is not None
    assert first.user_id != second.user_id

    service.upsert_user(
        token,
        event_id="user-a-2",
        external_id="employee-a",
        user_name="shared@example.com",
        display_name="Employee A",
        active=False,
        source_version=2,
    )
    reactivated = service.upsert_user(
        token,
        event_id="user-a-3",
        external_id="employee-a",
        user_name="shared@example.com",
        display_name="Employee A",
        active=True,
        source_version=3,
    )
    assert reactivated.active is True
    assert reactivated.membership_status == "active"

    with pytest.raises(LifecycleError) as conflict:
        service.upsert_user(
            token,
            event_id="user-a-3",
            external_id="employee-a",
            user_name="other@example.com",
            display_name="Employee A",
            active=True,
            source_version=3,
        )
    assert conflict.value.code == "scim_event_conflict"

    with sessions() as db:
        records = db.scalars(
            sa.select(EnterpriseScimUserRecord).order_by(EnterpriseScimUserRecord.external_id)
        ).all()
        assert len(records) == 2
        assert {record.user_id for record in records} == {first.user_id, second.user_id}


def test_owner_deprovision_suspends_access_and_requires_recovery(scim_fixture) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    token = _directory(service, ids)
    created = service.upsert_user(
        token,
        event_id="owner-create-1",
        external_id="managed-owner",
        user_name="owner@example.com",
        display_name="Managed Owner",
        active=True,
        source_version=1,
    )
    assert created.user_id is not None
    with sessions.begin() as db:
        original = db.get(TenantMembership, (ids.tenant, ids.owner))
        managed = db.get(TenantMembership, (ids.tenant, created.user_id))
        assert original is not None and managed is not None
        original.role = "admin"
        original.version += 1
        managed.role = "owner"
        managed.version += 1

    result = service.upsert_user(
        token,
        event_id="owner-deprovision-2",
        external_id="managed-owner",
        user_name="owner@example.com",
        display_name="Managed Owner",
        active=False,
        source_version=2,
    )
    assert result.disposition == "blocked"
    assert result.requires_owner_recovery is True
    assert result.membership_status == "suspended"
