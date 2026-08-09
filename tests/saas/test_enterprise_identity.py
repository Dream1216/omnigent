from __future__ import annotations

import json
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
from saas.control_plane.enterprise_identity import EnterpriseScimService, ScimFilterExpression
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


def test_directory_credential_rotation_and_disable_are_cas_and_idempotent(scim_fixture) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    issued = service.issue_directory(
        _context(ids, ids.owner),
        display_name="Rotating IdP",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="rotation-directory",
    )
    assert issued.bearer_token is not None
    old_token = issued.bearer_token

    rotated = service.rotate_directory_credential(
        _context(ids, ids.owner),
        directory_id=issued.id,
        expected_version=1,
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="rotate-1",
    )
    assert rotated.version == 2
    assert rotated.bearer_token is not None
    assert rotated.bearer_token != old_token
    assert rotated.token_prefix == rotated.bearer_token[:24]

    replay = service.rotate_directory_credential(
        _context(ids, ids.owner),
        directory_id=issued.id,
        expected_version=1,
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="rotate-1",
    )
    assert replay.replayed is True
    assert replay.version == 2
    assert replay.bearer_token is None

    with pytest.raises(LifecycleError) as old_denied:
        service.upsert_user(
            old_token,
            event_id="old-token-user",
            external_id="old-token-user",
            user_name="old-token@example.test",
            display_name=None,
            active=True,
            source_version=1,
        )
    assert old_denied.value.code == "scim_authentication_failed"

    with pytest.raises(LifecycleError) as stale:
        service.rotate_directory_credential(
            _context(ids, ids.owner),
            directory_id=issued.id,
            expected_version=1,
            reauthenticated_at=datetime.now(timezone.utc),
            idempotency_key="rotate-stale",
        )
    assert stale.value.code == "scim_directory_version_conflict"

    with pytest.raises(LifecycleError) as forbidden:
        service.disable_directory(
            _context(ids, ids.member),
            directory_id=issued.id,
            expected_version=2,
            reauthenticated_at=datetime.now(timezone.utc),
            idempotency_key="disable-forbidden",
        )
    assert forbidden.value.code == "enterprise_identity_manage_forbidden"

    disabled = service.disable_directory(
        _context(ids, ids.owner),
        directory_id=issued.id,
        expected_version=2,
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="disable-1",
    )
    assert disabled.status == "disabled"
    assert disabled.version == 3
    assert disabled.token_prefix == "disabled"
    assert disabled.bearer_token is None

    disabled_replay = service.disable_directory(
        _context(ids, ids.owner),
        directory_id=issued.id,
        expected_version=2,
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="disable-1",
    )
    assert disabled_replay.replayed is True
    assert disabled_replay.version == 3

    with pytest.raises(LifecycleError) as rotated_denied:
        service.get_user(rotated.bearer_token, scim_user_id=uuid4())
    assert rotated_denied.value.code == "scim_authentication_failed"

    with sessions() as db:
        stored = db.get(EnterpriseScimDirectoryRecord, issued.id)
        assert stored is not None
        assert stored.status == "disabled"
        assert stored.disabled_at is not None
        assert stored.token_hash not in {
            sha256(old_token.encode()).hexdigest(),
            sha256(rotated.bearer_token.encode()).hexdigest(),
        }
        outbox = list(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        serialized_outbox = json.dumps([event.payload for event in outbox], sort_keys=True)
        assert old_token not in serialized_outbox
        assert rotated.bearer_token not in serialized_outbox


def test_directory_scheduled_rotation_enforces_activation_grace_and_compaction(
    scim_fixture,
) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    issued = service.issue_directory(
        _context(ids, ids.owner),
        display_name="Overlapping IdP",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="overlap-directory",
    )
    assert issued.bearer_token is not None
    old_token = issued.bearer_token
    scheduled_at = datetime.now(timezone.utc)
    activation = scheduled_at + timedelta(minutes=2)
    scheduled = service.schedule_directory_credential_rotation(
        _context(ids, ids.owner),
        directory_id=issued.id,
        expected_version=1,
        activates_at=activation,
        grace_period_seconds=300,
        reauthenticated_at=scheduled_at,
        idempotency_key="overlap-1",
        now=scheduled_at,
    )
    assert scheduled.version == 2
    assert scheduled.bearer_token is not None
    successor_token = scheduled.bearer_token
    assert scheduled.successor_token_prefix == successor_token[:24]
    assert scheduled.rotation_activates_at == activation
    assert scheduled.rotation_grace_expires_at == activation + timedelta(minutes=5)

    replay_at = scheduled_at + timedelta(days=2)
    replay = service.schedule_directory_credential_rotation(
        _context(ids, ids.owner),
        directory_id=issued.id,
        expected_version=1,
        activates_at=activation,
        grace_period_seconds=300,
        reauthenticated_at=replay_at,
        idempotency_key="overlap-1",
        now=replay_at,
    )
    assert replay.replayed is True
    assert replay.bearer_token is None
    assert replay.rotation_activates_at == activation

    assert service.list_users(old_token).total_results == 0
    with pytest.raises(LifecycleError) as successor_early:
        service.list_users(successor_token)
    assert successor_early.value.code == "scim_authentication_failed"

    now = datetime.now(timezone.utc)
    with sessions.begin() as db:
        stored = db.get(EnterpriseScimDirectoryRecord, issued.id)
        assert stored is not None
        stored.rotation_activates_at = now - timedelta(minutes=1)
        stored.rotation_grace_expires_at = now + timedelta(minutes=1)

    assert service.list_users(old_token).total_results == 0
    assert service.list_users(successor_token).total_results == 0
    with pytest.raises(LifecycleError) as in_progress:
        service.schedule_directory_credential_rotation(
            _context(ids, ids.owner),
            directory_id=issued.id,
            expected_version=2,
            activates_at=now,
            grace_period_seconds=60,
            reauthenticated_at=now,
            idempotency_key="overlap-in-progress",
            now=now,
        )
    assert in_progress.value.code == "scim_directory_rotation_in_progress"

    with sessions.begin() as db:
        stored = db.get(EnterpriseScimDirectoryRecord, issued.id)
        assert stored is not None
        stored.rotation_grace_expires_at = now - timedelta(seconds=1)

    with pytest.raises(LifecycleError) as old_expired:
        service.list_users(old_token)
    assert old_expired.value.code == "scim_authentication_failed"
    assert service.list_users(successor_token).total_results == 0

    second = service.schedule_directory_credential_rotation(
        _context(ids, ids.owner),
        directory_id=issued.id,
        expected_version=2,
        activates_at=now + timedelta(minutes=1),
        grace_period_seconds=120,
        reauthenticated_at=now,
        idempotency_key="overlap-2",
        now=now,
    )
    assert second.version == 3
    assert second.bearer_token is not None
    with sessions() as db:
        stored = db.get(EnterpriseScimDirectoryRecord, issued.id)
        assert stored is not None
        assert stored.token_hash == sha256(successor_token.encode()).hexdigest()
        assert stored.successor_token_hash == sha256(second.bearer_token.encode()).hexdigest()
        serialized_outbox = json.dumps(
            [event.payload for event in db.scalars(sa.select(ControlPlaneOutboxEvent))],
            sort_keys=True,
        )
        assert old_token not in serialized_outbox
        assert successor_token not in serialized_outbox
        assert second.bearer_token not in serialized_outbox


def test_directory_scheduled_rotation_rejects_unbounded_or_ambiguous_windows(
    scim_fixture,
) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    issued = service.issue_directory(
        _context(ids, ids.owner),
        display_name="Bounded IdP",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="bounded-directory",
    )
    now = datetime.now(timezone.utc)

    cases = (
        (now.replace(tzinfo=None), 300, "scim_directory_rotation_time_invalid"),
        (now - timedelta(minutes=2), 300, "scim_directory_rotation_time_invalid"),
        (now + timedelta(days=31), 300, "scim_directory_rotation_time_invalid"),
        (datetime.max.replace(tzinfo=timezone.utc), 300, "scim_directory_rotation_time_invalid"),
        (now + timedelta(minutes=1), 59, "scim_directory_rotation_grace_invalid"),
        (now + timedelta(minutes=1), 86_401, "scim_directory_rotation_grace_invalid"),
    )
    for index, (activation, grace, expected_code) in enumerate(cases):
        with pytest.raises(LifecycleError) as rejected:
            service.schedule_directory_credential_rotation(
                _context(ids, ids.owner),
                directory_id=issued.id,
                expected_version=1,
                activates_at=activation,
                grace_period_seconds=grace,
                reauthenticated_at=now,
                idempotency_key=f"bounded-{index}",
                now=now,
            )
        assert rejected.value.code == expected_code


def test_directory_collection_queries_are_scoped_filtered_and_bounded(scim_fixture) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    first_token = _directory(service, ids)
    second_directory = service.issue_directory(
        _context(ids, ids.owner),
        display_name="Second IdP",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key="directory-2",
    )
    assert second_directory.bearer_token is not None

    first_user = service.upsert_user(
        first_token,
        event_id="first-directory-user",
        external_id="first-user",
        user_name="First.User@example.test",
        display_name="First User",
        active=True,
        source_version=1,
    )
    service.upsert_user(
        first_token,
        event_id="another-first-directory-user",
        external_id="another-user",
        user_name="another.user@example.test",
        display_name="Another User",
        active=False,
        source_version=1,
    )
    service.upsert_user(
        second_directory.bearer_token,
        event_id="second-directory-user",
        external_id="second-user",
        user_name="second.user@example.test",
        display_name="Second User",
        active=True,
        source_version=1,
    )

    first_page = service.list_users(first_token, start_index=1, count=1)
    assert first_page.total_results == 2
    assert first_page.items_per_page == 1
    filtered = service.list_users(
        first_token,
        filter_attribute="userName",
        filter_value="FIRST.USER@example.test",
    )
    assert filtered.total_results == 1
    assert filtered.resources[0].external_id == "first-user"
    compound = service.list_users(
        first_token,
        filter_expression=ScimFilterExpression(
            operator="and",
            operands=(
                ScimFilterExpression(
                    operator="co",
                    attribute="displayName",
                    value="USER",
                ),
                ScimFilterExpression(
                    operator="not",
                    operands=(
                        ScimFilterExpression(
                            operator="eq",
                            attribute="active",
                            value=True,
                        ),
                    ),
                ),
            ),
        ),
    )
    assert compound.total_results == 1
    assert compound.resources[0].external_id == "another-user"
    sorted_users = service.list_users(
        first_token,
        sort_by="displayName",
        sort_order="descending",
    )
    assert [value.display_name for value in sorted_users.resources] == [
        "First User",
        "Another User",
    ]
    assert (
        service.list_users(
            first_token,
            filter_attribute="externalId",
            filter_value="second-user",
        ).total_results
        == 0
    )

    group = service.sync_group(
        first_token,
        event_id="first-directory-group",
        external_id="first-group",
        display_name="First Group",
        member_external_ids=["first-user"],
        active=True,
        source_version=1,
    )
    group_page = service.list_groups(
        first_token,
        filter_attribute="id",
        filter_value=str(group.id),
    )
    assert group_page.total_results == 1
    assert group_page.resources[0].member_scim_user_ids == (first_user.id,)

    with pytest.raises(LifecycleError) as unsupported:
        service.list_groups(
            first_token,
            filter_attribute="userName",
            filter_value="first.user@example.test",
        )
    assert unsupported.value.code == "invalidFilter"
    with pytest.raises(LifecycleError) as unbounded:
        service.list_users(first_token, count=101)
    assert unbounded.value.code == "invalidValue"
    with pytest.raises(LifecycleError) as invalid_user_name:
        service.list_users(
            first_token,
            filter_attribute="userName",
            filter_value="   ",
        )
    assert invalid_user_name.value.code == "invalidFilter"


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


def test_guarded_resource_mutations_replay_before_etag_cas(scim_fixture) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    token = _directory(service, ids)
    created = service.upsert_user(
        token,
        event_id="guarded-user-create",
        external_id="guarded-user",
        user_name="guarded@example.test",
        display_name="Guarded User",
        active=True,
        source_version=1,
    )

    replaced = service.upsert_user(
        token,
        event_id="guarded-user-replace",
        external_id=created.external_id,
        user_name=created.user_name,
        display_name="Replaced User",
        active=True,
        source_version=None,
        scim_user_id=created.id,
        expected_version=1,
        operation="replace",
    )
    assert replaced.version == replaced.source_version == 2
    replay = service.upsert_user(
        token,
        event_id="guarded-user-replace",
        external_id=created.external_id,
        user_name=created.user_name,
        display_name="Replaced User",
        active=True,
        source_version=None,
        scim_user_id=created.id,
        expected_version=1,
        operation="replace",
    )
    assert replay.replayed is True
    assert replay.version == 2

    with pytest.raises(LifecycleError) as changed_replay:
        service.upsert_user(
            token,
            event_id="guarded-user-replace",
            external_id=created.external_id,
            user_name=created.user_name,
            display_name="Different Replay",
            active=True,
            source_version=None,
            scim_user_id=created.id,
            expected_version=1,
            operation="replace",
        )
    assert changed_replay.value.code == "scim_event_conflict"
    with pytest.raises(LifecycleError) as stale_etag:
        service.upsert_user(
            token,
            event_id="guarded-user-stale",
            external_id=created.external_id,
            user_name=created.user_name,
            display_name="Stale",
            active=True,
            source_version=None,
            scim_user_id=created.id,
            expected_version=1,
            operation="replace",
        )
    assert stale_etag.value.code == "scim_etag_mismatch"
    with pytest.raises(LifecycleError) as changed_external_id:
        service.upsert_user(
            token,
            event_id="guarded-user-external",
            external_id="changed-external-id",
            user_name=created.user_name,
            display_name="Replaced User",
            active=True,
            source_version=None,
            scim_user_id=created.id,
            expected_version=2,
            operation="replace",
        )
    assert changed_external_id.value.code == "scim_external_id_immutable"

    group = service.sync_group(
        token,
        event_id="guarded-group-create",
        external_id="guarded-group",
        display_name="Guarded Group",
        member_external_ids=[created.external_id],
        active=True,
        source_version=1,
    )
    deleted = service.sync_group(
        token,
        event_id="guarded-group-delete",
        external_id=group.external_id,
        display_name=group.display_name,
        member_external_ids=[],
        active=False,
        source_version=None,
        scim_group_id=group.id,
        expected_version=1,
        operation="delete",
    )
    assert deleted.active is False
    assert deleted.active_member_count == 0
    deleted_replay = service.sync_group(
        token,
        event_id="guarded-group-delete",
        external_id=group.external_id,
        display_name=group.display_name,
        member_external_ids=[],
        active=False,
        source_version=None,
        scim_group_id=group.id,
        expected_version=1,
        operation="delete",
    )
    assert deleted_replay.replayed is True
    assert deleted_replay.version == 2

    with sessions() as db:
        events = list(
            db.scalars(
                sa.select(EnterpriseScimEventRecord).order_by(EnterpriseScimEventRecord.event_id)
            )
        )
        assert len(events) == 4
        assert {event.event_id for event in events} == {
            "guarded-group-create",
            "guarded-group-delete",
            "guarded-user-create",
            "guarded-user-replace",
        }


def test_bulk_request_receipts_replay_conflict_and_resume_incomplete_work(scim_fixture) -> None:
    sessions, ids = scim_fixture
    service = EnterpriseScimService(sessions)
    token = _directory(service, ids)
    request = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations": [{"method": "POST", "path": "/Users"}],
    }
    response = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
        "Operations": [{"method": "POST", "status": "201"}],
    }
    with service.bulk_request(
        token,
        event_id="bulk-receipt",
        request_payload=request,
        operation_count=1,
    ) as execution:
        assert execution.replay_result is None
        execution.complete(response)

    with service.bulk_request(
        token,
        event_id="bulk-receipt",
        request_payload=request,
        operation_count=1,
    ) as replay:
        assert replay.replay_result == response

    with pytest.raises(LifecycleError) as conflict:
        with service.bulk_request(
            token,
            event_id="bulk-receipt",
            request_payload={**request, "failOnErrors": 1},
            operation_count=1,
        ):
            pass
    assert conflict.value.code == "scim_event_conflict"

    with pytest.raises(LifecycleError) as interrupted:
        with service.bulk_request(
            token,
            event_id="bulk-interrupted",
            request_payload=request,
            operation_count=1,
        ):
            pass
    assert interrupted.value.code == "scim_bulk_incomplete"
    with service.bulk_request(
        token,
        event_id="bulk-interrupted",
        request_payload=request,
        operation_count=1,
    ) as resumed:
        assert resumed.replay_result is None
        resumed.complete(response)

    with sessions() as db:
        bulk_events = tuple(
            db.scalars(
                sa.select(EnterpriseScimEventRecord)
                .where(EnterpriseScimEventRecord.resource_type == "Bulk")
                .order_by(EnterpriseScimEventRecord.event_id)
            )
        )
        assert len(bulk_events) == 4
        assert {event.disposition for event in bulk_events} == {"applied"}
