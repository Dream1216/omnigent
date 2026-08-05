from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane import (
    AuthSessionRecord,
    CompositeRemovalImpactProvider,
    ControlPlaneOutboxEvent,
    EnterpriseAccessPreflightRecord,
    EnterpriseAccessRemovalImpactProvider,
    EnterpriseAccessService,
    EnterpriseCustomRoleRecord,
    EnterpriseGroupMembershipMutation,
    EnterpriseGroupMembershipRecord,
    EnterpriseGroupRecord,
    EnterpriseGroupRoleAssignmentRecord,
    GlobalUser,
    LifecycleError,
    MembershipGovernanceService,
    MembershipLifecycleService,
    ProjectAuthorizer,
    ProjectMembershipRecord,
    ProjectRecord,
    SaasBase,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)

_NOW = datetime(2026, 8, 5, 13, 0, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class _Ids:
    tenant: UUID
    space: UUID
    project: UUID
    owner: UUID
    manager: UUID
    member: UUID
    outsider: UUID
    other_tenant: UUID


@pytest.fixture
def enterprise_fixture() -> tuple[sessionmaker[Session], _Ids]:
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
    ids = _Ids(*(uuid4() for _ in range(8)))
    with sessions.begin() as db:
        db.add_all(
            GlobalUser(id=value, status="active", security_version=1)
            for value in (ids.owner, ids.manager, ids.member, ids.outsider)
        )
        db.add_all(
            [
                Tenant(
                    id=ids.tenant,
                    slug="enterprise",
                    name="Enterprise",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                ),
                Tenant(
                    id=ids.other_tenant,
                    slug="other-enterprise",
                    name="Other Enterprise",
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
                    user_id=ids.manager,
                    role="admin",
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
                TenantMembership(
                    tenant_id=ids.other_tenant,
                    user_id=ids.outsider,
                    role="owner",
                    status="active",
                    version=1,
                ),
            ]
        )
        db.add(
            Space(
                id=ids.space,
                tenant_id=ids.tenant,
                slug="engineering",
                name="Engineering",
                status="active",
            )
        )
        db.flush()
        db.add_all(
            SpaceMembership(
                tenant_id=ids.tenant,
                space_id=ids.space,
                user_id=user_id,
                role="owner" if user_id == ids.owner else "member",
                status="active",
                version=1,
            )
            for user_id in (ids.owner, ids.manager, ids.member)
        )
        db.add(
            ProjectRecord(
                id=ids.project,
                tenant_id=ids.tenant,
                space_id=ids.space,
                name="Restricted",
                visibility="restricted",
                created_by=ids.owner,
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add_all(
            [
                ProjectMembershipRecord(
                    tenant_id=ids.tenant,
                    space_id=ids.space,
                    project_id=ids.project,
                    subject_type="user",
                    subject_id=ids.owner,
                    role="owner",
                    status="active",
                    created_by=ids.owner,
                    version=1,
                ),
                ProjectMembershipRecord(
                    tenant_id=ids.tenant,
                    space_id=ids.space,
                    project_id=ids.project,
                    subject_type="user",
                    subject_id=ids.manager,
                    role="manage",
                    status="active",
                    created_by=ids.owner,
                    version=1,
                ),
            ]
        )
    return sessions, ids


def _context(ids: _Ids, actor: UUID, trace: str) -> RequestContext:
    return RequestContext(
        actor_id=actor,
        tenant_id=ids.tenant,
        space_id=ids.space,
        project_id=None,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id=trace,
    )


def _grant_group_role(
    sessions: sessionmaker[Session], ids: _Ids
) -> tuple[EnterpriseAccessService, UUID, UUID, UUID]:
    service = EnterpriseAccessService(sessions)
    owner = _context(ids, ids.owner, "enterprise-owner")
    group = service.create_group(
        owner,
        name="Release Engineers",
        description="Can execute release workflows",
        idempotency_key="create-release-group",
    )
    service.add_group_member(
        owner,
        group_id=group.id,
        user_id=ids.member,
        expires_at=None,
        idempotency_key="add-release-member",
        now=_NOW,
    )
    role = service.create_custom_role(
        owner,
        project_id=ids.project,
        name="Release Runner",
        description="Run without repository administration",
        permissions=["run.create", "run.read_metadata", "project.read_metadata"],
        idempotency_key="create-release-role",
    )
    assignment = service.assign_group_role(
        owner,
        project_id=ids.project,
        group_id=group.id,
        custom_role_id=role.id,
        expires_at=None,
        idempotency_key="assign-release-role",
        now=_NOW,
    )
    return service, group.id, role.id, assignment.id


def test_group_custom_role_is_additive_explained_versioned_and_immediately_revoked(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service, group_id, role_id, _assignment_id = _grant_group_role(sessions, ids)
    authorizer = ProjectAuthorizer(sessions)
    member = _context(ids, ids.member, "member-group-decision")

    allowed = authorizer.evaluate(
        member,
        action="run.create",
        project_id=ids.project,
        now=_NOW,
    )
    assert allowed.allowed is True
    group_source = next(
        source
        for source in allowed.sources
        if source.source_type == "enterprise_group_custom_role"
    )
    assert group_source.subject_type == "group"
    assert group_source.subject_id == group_id
    assert group_source.role_id == role_id
    assert group_source.role_version == 1

    updated = service.update_custom_role(
        _context(ids, ids.owner, "role-update"),
        project_id=ids.project,
        custom_role_id=role_id,
        name="Release Observer",
        description=None,
        permissions=["run.read_metadata", "project.read_metadata"],
        expected_version=1,
        idempotency_key="remove-run-create",
    )
    assert updated.version == 2
    denied = authorizer.evaluate(
        member,
        action="run.create",
        project_id=ids.project,
        now=_NOW,
    )
    assert denied.allowed is False
    assert denied.reason == "permission_not_granted"
    assert any(source.role_version == 2 for source in denied.sources)


def test_enterprise_destructive_preflights_require_fresh_separated_approval_and_exact_impact(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service, group_id, role_id, _assignment_id = _grant_group_role(sessions, ids)
    owner = _context(ids, ids.owner, "preflight-requester")
    approver = _context(ids, ids.manager, "preflight-approver")

    with pytest.raises(LifecycleError) as stale_auth:
        service.create_group_archive_preflight(
            owner,
            group_id=group_id,
            expected_version=1,
            reason="replace directory group",
            reauthenticated_at=_NOW - timedelta(minutes=6),
            idempotency_key="stale-auth-group-preflight",
            now=_NOW,
        )
    assert stale_auth.value.code == "fresh_auth_required"

    group_preflight = service.create_group_archive_preflight(
        owner,
        group_id=group_id,
        expected_version=1,
        reason="replace directory group",
        reauthenticated_at=_NOW,
        idempotency_key="group-archive-preflight",
        now=_NOW,
    )
    assert group_preflight.status == "pending_approval"
    assert group_preflight.approval_policy == "different_principal"
    assert group_preflight.impact_summary["removed_membership_count"] == 1
    assert group_preflight.impact_summary["revoked_assignment_count"] == 1
    assert service.create_group_archive_preflight(
        owner,
        group_id=group_id,
        expected_version=1,
        reason="replace directory group",
        reauthenticated_at=_NOW,
        idempotency_key="group-archive-preflight",
        now=_NOW,
    ).replayed
    with pytest.raises(LifecycleError) as self_approval:
        service.decide_enterprise_access_preflight(
            owner,
            preflight_id=group_preflight.preflight_id,
            operation_type="group_archive",
            target_id=group_id,
            decision="approve",
            reason="self approval must fail",
            reauthenticated_at=_NOW,
            idempotency_key="self-approve-group",
            now=_NOW,
        )
    assert self_approval.value.code == "approval_separation_required"

    approved = service.decide_enterprise_access_preflight(
        approver,
        preflight_id=group_preflight.preflight_id,
        operation_type="group_archive",
        target_id=group_id,
        decision="approve",
        reason="replacement checked",
        reauthenticated_at=_NOW,
        idempotency_key="approve-group-archive",
        now=_NOW,
    )
    assert approved.status == "approved"
    assert service.decide_enterprise_access_preflight(
        approver,
        preflight_id=group_preflight.preflight_id,
        operation_type="group_archive",
        target_id=group_id,
        decision="approve",
        reason="replacement checked",
        reauthenticated_at=_NOW,
        idempotency_key="approve-group-archive",
        now=_NOW,
    ).replayed
    service.add_group_member(
        owner,
        group_id=group_id,
        user_id=ids.owner,
        expires_at=None,
        idempotency_key="change-impact-after-approval",
        now=_NOW,
    )
    with pytest.raises(LifecycleError) as stale_impact:
        service.archive_group(
            owner,
            group_id=group_id,
            expected_version=1,
            reason="replace directory group",
            approval_preflight_id=group_preflight.preflight_id,
            reauthenticated_at=_NOW,
            idempotency_key="execute-stale-group-archive",
            now=_NOW,
        )
    assert stale_impact.value.code == "enterprise_preflight_stale"

    role_preflight = service.create_custom_role_retire_preflight(
        owner,
        project_id=ids.project,
        custom_role_id=role_id,
        expected_version=1,
        reason="replace custom role",
        reauthenticated_at=_NOW,
        idempotency_key="role-retire-preflight",
        now=_NOW,
    )
    approved_role = service.decide_enterprise_access_preflight(
        approver,
        preflight_id=role_preflight.preflight_id,
        operation_type="custom_role_retire",
        target_id=role_id,
        project_id=ids.project,
        decision="approve",
        reason="replacement role checked",
        reauthenticated_at=_NOW,
        idempotency_key="approve-role-retire",
        now=_NOW,
    )
    assert approved_role.impact_summary["affected_user_count"] == 2
    with pytest.raises(LifecycleError) as changed_reason:
        service.retire_custom_role(
            owner,
            project_id=ids.project,
            custom_role_id=role_id,
            expected_version=1,
            reason="different reason",
            approval_preflight_id=role_preflight.preflight_id,
            reauthenticated_at=_NOW,
            idempotency_key="execute-role-wrong-reason",
            now=_NOW,
        )
    assert changed_reason.value.code == "enterprise_preflight_mismatch"
    retired = service.retire_custom_role(
        owner,
        project_id=ids.project,
        custom_role_id=role_id,
        expected_version=1,
        reason="replace custom role",
        approval_preflight_id=role_preflight.preflight_id,
        reauthenticated_at=_NOW,
        idempotency_key="execute-approved-role",
        now=_NOW,
    )
    assert retired.status == "retired"
    with sessions() as db:
        persisted = db.get(EnterpriseAccessPreflightRecord, role_preflight.preflight_id)
        assert persisted is not None
        assert persisted.status == "executed"
        assert persisted.executed_at.replace(tzinfo=timezone.utc) == _NOW


def test_enterprise_preflight_approval_is_invalidated_when_approver_loses_permission(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service = EnterpriseAccessService(sessions)
    owner = _context(ids, ids.owner, "approval-invalidation-requester")
    approver = _context(ids, ids.manager, "approval-invalidation-approver")
    group = service.create_group(
        owner,
        name="Approval Invalidated",
        description=None,
        idempotency_key="create-approval-invalidation-group",
    )
    preflight = service.create_group_archive_preflight(
        owner,
        group_id=group.id,
        expected_version=1,
        reason="replace invalidated group",
        reauthenticated_at=_NOW,
        idempotency_key="approval-invalidation-preflight",
        now=_NOW,
    )
    service.decide_enterprise_access_preflight(
        approver,
        preflight_id=preflight.preflight_id,
        operation_type="group_archive",
        target_id=group.id,
        decision="approve",
        reason="initially authorized",
        reauthenticated_at=_NOW,
        idempotency_key="approval-before-role-revocation",
        now=_NOW,
    )
    with sessions.begin() as db:
        membership = db.get(TenantMembership, (ids.tenant, ids.manager))
        assert membership is not None
        membership.role = "member"
        membership.version += 1
    with pytest.raises(LifecycleError) as invalidated:
        service.archive_group(
            owner,
            group_id=group.id,
            expected_version=1,
            reason="replace invalidated group",
            approval_preflight_id=preflight.preflight_id,
            reauthenticated_at=_NOW,
            idempotency_key="execute-invalidated-approval",
            now=_NOW,
        )
    assert invalidated.value.code == "approval_invalidated"


def test_enterprise_preflight_rejection_and_expiry_cannot_execute(enterprise_fixture) -> None:
    sessions, ids = enterprise_fixture
    service = EnterpriseAccessService(sessions)
    owner = _context(ids, ids.owner, "approval-terminal-requester")
    approver = _context(ids, ids.manager, "approval-terminal-approver")

    rejected_group = service.create_group(
        owner,
        name="Rejected Archive",
        description=None,
        idempotency_key="create-rejected-archive-group",
    )
    rejected = service.create_group_archive_preflight(
        owner,
        group_id=rejected_group.id,
        expected_version=1,
        reason="replace rejected group",
        reauthenticated_at=_NOW,
        idempotency_key="rejected-archive-preflight",
        now=_NOW,
    )
    decision = service.decide_enterprise_access_preflight(
        approver,
        preflight_id=rejected.preflight_id,
        operation_type="group_archive",
        target_id=rejected_group.id,
        decision="reject",
        reason="replacement is incomplete",
        reauthenticated_at=_NOW,
        idempotency_key="reject-archive-preflight",
        now=_NOW,
    )
    assert decision.status == "rejected"
    with pytest.raises(LifecycleError) as rejected_execution:
        service.archive_group(
            owner,
            group_id=rejected_group.id,
            expected_version=1,
            reason="replace rejected group",
            approval_preflight_id=rejected.preflight_id,
            reauthenticated_at=_NOW,
            idempotency_key="execute-rejected-preflight",
            now=_NOW,
        )
    assert rejected_execution.value.code == "enterprise_preflight_not_approved"

    expired_group = service.create_group(
        owner,
        name="Expired Archive",
        description=None,
        idempotency_key="create-expired-archive-group",
    )
    expiring = service.create_group_archive_preflight(
        owner,
        group_id=expired_group.id,
        expected_version=1,
        reason="replace expired group",
        reauthenticated_at=_NOW,
        idempotency_key="expired-archive-preflight",
        now=_NOW,
    )
    service.decide_enterprise_access_preflight(
        approver,
        preflight_id=expiring.preflight_id,
        operation_type="group_archive",
        target_id=expired_group.id,
        decision="approve",
        reason="replacement initially ready",
        reauthenticated_at=_NOW,
        idempotency_key="approve-expiring-preflight",
        now=_NOW,
    )
    expired_at = _NOW + timedelta(minutes=16)
    with pytest.raises(LifecycleError) as expired_execution:
        service.archive_group(
            owner,
            group_id=expired_group.id,
            expected_version=1,
            reason="replace expired group",
            approval_preflight_id=expiring.preflight_id,
            reauthenticated_at=expired_at,
            idempotency_key="execute-expired-preflight",
            now=expired_at,
        )
    assert expired_execution.value.code == "enterprise_preflight_expired"


def test_group_member_removal_revokes_sessions_and_all_assigned_project_access(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service, group_id, _role_id, _assignment_id = _grant_group_role(sessions, ids)
    lifecycle = MembershipLifecycleService(sessions)
    issued = lifecycle.issue_auth_session(
        user_id=ids.member,
        authn_method="password",
        expires_at=_NOW + timedelta(hours=1),
        now=_NOW,
    )
    with sessions() as db:
        project_before = db.get(ProjectRecord, ids.project)
        assert project_before is not None
        version_before = project_before.authorization_version

    removed = service.remove_group_member(
        _context(ids, ids.owner, "remove-group-member"),
        group_id=group_id,
        user_id=ids.member,
        expected_version=1,
        idempotency_key="remove-release-member",
        now=_NOW + timedelta(minutes=1),
    )
    assert removed.status == "removed"
    assert removed.version == 2
    assert removed.security_version == 2
    assert removed.revoked_session_count == 1
    with sessions() as db:
        session = db.get(AuthSessionRecord, issued.session_id)
        project_after = db.get(ProjectRecord, ids.project)
        assert session is not None and session.revoked_at is not None
        assert project_after is not None
        assert project_after.authorization_version == version_before + 1

    stale = ProjectAuthorizer(sessions).evaluate(
        _context(ids, ids.member, "stale-after-group-removal"),
        action="run.create",
        project_id=ids.project,
        now=_NOW + timedelta(minutes=1),
    )
    assert stale.allowed is False
    assert stale.reason == "authorization_snapshot_stale"


def test_group_archive_revokes_all_access_sessions_and_records_reason(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service, group_id, _role_id, assignment_id = _grant_group_role(sessions, ids)
    lifecycle = MembershipLifecycleService(sessions)
    issued = lifecycle.issue_auth_session(
        user_id=ids.member,
        authn_method="password",
        expires_at=_NOW + timedelta(hours=1),
        now=_NOW,
    )
    with sessions.begin() as db:
        member = db.get(GlobalUser, ids.member)
        assert member is not None
        member.status = "suspended"
    archived = service.archive_group(
        _context(ids, ids.owner, "archive-release-group"),
        group_id=group_id,
        expected_version=1,
        reason="release function moved to a managed directory group",
        idempotency_key="archive-release-group",
        now=_NOW + timedelta(minutes=1),
    )
    assert archived.status == "archived"
    assert archived.version == 2
    assert archived.removed_membership_count == 1
    assert archived.revoked_assignment_count == 1
    assert archived.invalidated_user_count == 1
    assert archived.revoked_session_count == 1
    assert archived.affected_project_ids == (ids.project,)
    replay = service.archive_group(
        _context(ids, ids.owner, "archive-release-group-replay"),
        group_id=group_id,
        expected_version=1,
        reason="release function moved to a managed directory group",
        idempotency_key="archive-release-group",
        now=_NOW + timedelta(minutes=2),
    )
    assert replay.replayed is True
    assert replay.archived_at == archived.archived_at

    with sessions() as db:
        group = db.get(EnterpriseGroupRecord, group_id)
        membership = db.get(EnterpriseGroupMembershipRecord, (group_id, ids.member))
        assignment = db.get(EnterpriseGroupRoleAssignmentRecord, assignment_id)
        session = db.get(AuthSessionRecord, issued.session_id)
        user = db.get(GlobalUser, ids.member)
        project = db.get(ProjectRecord, ids.project)
        assert group is not None and group.status == "archived"
        assert group.archived_by == ids.owner
        assert group.archive_reason == archived.archive_reason
        assert membership is not None and membership.status == "removed"
        assert assignment is not None and assignment.status == "revoked"
        assert session is not None and session.revoked_at is not None
        assert user is not None and user.security_version == 2
        assert project is not None and project.authorization_version == 4


def test_custom_role_retirement_revokes_assignments_and_is_idempotent(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service, _group_id, role_id, assignment_id = _grant_group_role(sessions, ids)
    retired = service.retire_custom_role(
        _context(ids, ids.owner, "retire-release-role"),
        project_id=ids.project,
        custom_role_id=role_id,
        expected_version=1,
        reason="role replaced by the audited deployment role",
        idempotency_key="retire-release-role",
        now=_NOW + timedelta(minutes=1),
    )
    assert retired.status == "retired"
    assert retired.version == 2
    assert retired.revoked_assignment_count == 1
    replay = service.retire_custom_role(
        _context(ids, ids.owner, "retire-release-role-replay"),
        project_id=ids.project,
        custom_role_id=role_id,
        expected_version=1,
        reason="role replaced by the audited deployment role",
        idempotency_key="retire-release-role",
        now=_NOW + timedelta(minutes=2),
    )
    assert replay.replayed is True
    assert replay.authorization_version == retired.authorization_version
    assert (
        not ProjectAuthorizer(sessions)
        .evaluate(
            _context(ids, ids.member, "after-role-retirement"),
            action="run.create",
            project_id=ids.project,
            now=_NOW + timedelta(minutes=2),
        )
        .allowed
    )
    with sessions() as db:
        role = db.get(EnterpriseCustomRoleRecord, role_id)
        assignment = db.get(EnterpriseGroupRoleAssignmentRecord, assignment_id)
        assert role is not None and role.status == "retired"
        assert role.retired_by == ids.owner
        assert role.retire_reason == retired.retire_reason
        assert assignment is not None and assignment.status == "revoked"


def test_group_membership_batch_is_atomic_bounded_and_revokes_removed_users(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service, group_id, _role_id, _assignment_id = _grant_group_role(sessions, ids)
    lifecycle = MembershipLifecycleService(sessions)
    issued = lifecycle.issue_auth_session(
        user_id=ids.member,
        authn_method="password",
        expires_at=_NOW + timedelta(hours=1),
        now=_NOW,
    )
    changed = service.change_group_members(
        _context(ids, ids.owner, "batch-members"),
        group_id=group_id,
        mutations=(
            EnterpriseGroupMembershipMutation(
                user_id=ids.member,
                action="remove",
                expected_version=1,
            ),
            EnterpriseGroupMembershipMutation(
                user_id=ids.manager,
                action="add",
                expires_at=_NOW + timedelta(days=1),
            ),
        ),
        idempotency_key="batch-swap-release-member",
        now=_NOW + timedelta(minutes=1),
    )
    assert changed.affected_project_ids == (ids.project,)
    assert [value.status for value in changed.memberships] == ["removed", "active"]
    assert changed.memberships[0].security_version == 2
    replay = service.change_group_members(
        _context(ids, ids.owner, "batch-members-replay"),
        group_id=group_id,
        mutations=(
            EnterpriseGroupMembershipMutation(
                user_id=ids.member,
                action="remove",
                expected_version=1,
            ),
            EnterpriseGroupMembershipMutation(
                user_id=ids.manager,
                action="add",
                expires_at=_NOW + timedelta(days=1),
            ),
        ),
        idempotency_key="batch-swap-release-member",
        now=_NOW + timedelta(minutes=2),
    )
    assert replay.replayed is True
    with sessions() as db:
        session = db.get(AuthSessionRecord, issued.session_id)
        manager = db.get(EnterpriseGroupMembershipRecord, (group_id, ids.manager))
        assert session is not None and session.revoked_at is not None
        assert manager is not None and manager.status == "active"

    second = service.create_group(
        _context(ids, ids.owner, "atomic-batch-group"),
        name="Atomic batch",
        description=None,
        idempotency_key="create-atomic-batch-group",
    )
    with pytest.raises(LifecycleError) as invalid:
        service.change_group_members(
            _context(ids, ids.owner, "invalid-atomic-batch"),
            group_id=second.id,
            mutations=(
                EnterpriseGroupMembershipMutation(user_id=ids.manager, action="add"),
                EnterpriseGroupMembershipMutation(user_id=ids.outsider, action="add"),
            ),
            idempotency_key="invalid-atomic-batch",
            now=_NOW,
        )
    assert invalid.value.code == "group_member_invalid"
    with sessions() as db:
        assert db.get(EnterpriseGroupMembershipRecord, (second.id, ids.manager)) is None


def test_custom_roles_reject_privilege_escalation_and_cross_tenant_members(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service = EnterpriseAccessService(sessions)
    owner = _context(ids, ids.owner, "owner-negative")
    group = service.create_group(
        owner,
        name="Boundary",
        description=None,
        idempotency_key="create-boundary-group",
    )
    with pytest.raises(LifecycleError) as unreadable:
        service.list_groups(_context(ids, ids.member, "member-cannot-list-groups"))
    assert unreadable.value.code == "group_read_forbidden"
    with pytest.raises(LifecycleError) as outsider:
        service.add_group_member(
            owner,
            group_id=group.id,
            user_id=ids.outsider,
            expires_at=None,
            idempotency_key="cross-tenant-member",
        )
    assert outsider.value.code == "group_member_invalid"

    for permission in ("grant.manage", "secret.manage", "tenant.update"):
        with pytest.raises(LifecycleError) as forbidden:
            service.create_custom_role(
                owner,
                project_id=ids.project,
                name=f"Forbidden {permission}",
                description=None,
                permissions=[permission],
                idempotency_key=f"forbidden-{permission}",
            )
        assert forbidden.value.code == "custom_role_permission_not_allowed"

    with pytest.raises(LifecycleError) as escalation:
        service.create_custom_role(
            _context(ids, ids.manager, "content-blind-manager"),
            project_id=ids.project,
            name="Content Editor",
            description=None,
            permissions=["project.content.edit"],
            idempotency_key="manager-cannot-delegate-content",
        )
    assert escalation.value.code == "permission_not_granted"


def test_enterprise_mutations_are_idempotent_and_outbox_is_scope_safe(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    service = EnterpriseAccessService(sessions)
    owner = _context(ids, ids.owner, "idempotent-group")
    first = service.create_group(
        owner,
        name="Idempotent",
        description="No duplicate facts",
        idempotency_key="same-group-request",
    )
    replay = service.create_group(
        owner,
        name="Idempotent",
        description="No duplicate facts",
        idempotency_key="same-group-request",
    )
    assert replay.id == first.id and replay.replayed is True
    with pytest.raises(LifecycleError) as conflict:
        service.create_group(
            owner,
            name="Different",
            description=None,
            idempotency_key="same-group-request",
        )
    assert conflict.value.code == "idempotency_conflict"

    with sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(EnterpriseGroupRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == 1
        event = db.scalar(sa.select(ControlPlaneOutboxEvent))
        assert event is not None
        assert event.tenant_id == ids.tenant
        assert set(event.payload) == {
            "actor_id",
            "tenant_id",
            "name",
            "description",
            "group_id",
            "status",
            "version",
        }


def test_expired_group_membership_and_assignment_do_not_authorize(enterprise_fixture) -> None:
    sessions, ids = enterprise_fixture
    service = EnterpriseAccessService(sessions)
    owner = _context(ids, ids.owner, "expiry-owner")
    group = service.create_group(
        owner,
        name="Temporary",
        description=None,
        idempotency_key="temporary-group",
    )
    service.add_group_member(
        owner,
        group_id=group.id,
        user_id=ids.member,
        expires_at=_NOW + timedelta(minutes=10),
        idempotency_key="temporary-member",
        now=_NOW,
    )
    role = service.create_custom_role(
        owner,
        project_id=ids.project,
        name="Temporary Runner",
        description=None,
        permissions=["run.create"],
        idempotency_key="temporary-role",
    )
    assignment = service.assign_group_role(
        owner,
        project_id=ids.project,
        group_id=group.id,
        custom_role_id=role.id,
        expires_at=_NOW + timedelta(minutes=5),
        idempotency_key="temporary-assignment",
        now=_NOW,
    )
    authorizer = ProjectAuthorizer(sessions)
    assert authorizer.evaluate(
        _context(ids, ids.member, "before-expiry"),
        action="run.create",
        project_id=ids.project,
        now=_NOW + timedelta(minutes=1),
    ).allowed
    assert not authorizer.evaluate(
        _context(ids, ids.member, "after-expiry"),
        action="run.create",
        project_id=ids.project,
        now=_NOW + timedelta(minutes=6),
    ).allowed
    with sessions() as db:
        assert db.get(EnterpriseGroupMembershipRecord, (group.id, ids.member)) is not None
        assert db.get(EnterpriseCustomRoleRecord, role.id) is not None
        assert db.get(EnterpriseGroupRoleAssignmentRecord, assignment.id) is not None


def test_tenant_member_removal_previews_and_revokes_group_access_atomically(
    enterprise_fixture,
) -> None:
    sessions, ids = enterprise_fixture
    _service, group_id, _role_id, _assignment_id = _grant_group_role(sessions, ids)
    provider = CompositeRemovalImpactProvider(
        {"enterprise_access": EnterpriseAccessRemovalImpactProvider(sessions)},
        required_domains=frozenset({"enterprise_access"}),
    )
    governance = MembershipGovernanceService(sessions, provider)
    preflight = governance.create_removal_preflight(
        actor_id=ids.owner,
        tenant_id=ids.tenant,
        user_id=ids.member,
        idempotency_key="enterprise-removal-preflight",
        now=_NOW,
    )
    assert preflight.status == "ready"
    removed = governance.execute_member_removal(
        actor_id=ids.owner,
        tenant_id=ids.tenant,
        preflight_id=preflight.preflight_id,
        reason="member left the enterprise",
        reauthenticated_at=_NOW,
        idempotency_key="enterprise-removal-execute",
        now=_NOW,
    )
    assert removed.revoked_group_memberships == 1
    assert removed.changed_group_project_authorizations == 1
    with sessions() as db:
        membership = db.get(EnterpriseGroupMembershipRecord, (group_id, ids.member))
        tenant_membership = db.get(TenantMembership, (ids.tenant, ids.member))
        assert membership is not None and membership.status == "removed"
        assert tenant_membership is not None and tenant_membership.status == "removed"
