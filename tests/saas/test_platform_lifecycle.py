from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.api_credential_models import ApiCredentialRecord, ServiceAccountRecord
from saas.control_plane.db_models import (
    AuthSessionRecord,
    GlobalUser,
    IdentityConflict,
    IdentityConnection,
    SaasBase,
    Tenant,
    TenantMembership,
)
from saas.control_plane.identity import IdentityManagementService, VerifiedIdentityAssertion
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.platform_lifecycle import PlatformLifecycleService
from saas.control_plane.platform_models import (
    PlatformLifecycleOperationRecord,
    PlatformRoleAssignmentRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    PlatformSessionService,
    StaffIdentityAssertion,
)

ORIGIN = "https://platform-admin.example.test"
AUDIENCE = "omnigent-platform-admin"
NOW = datetime(2026, 8, 8, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def pc2() -> tuple[
    sessionmaker[Session],
    PlatformLifecycleService,
    PlatformSessionService,
    UUID,
]:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=ORIGIN, audience=AUDIENCE)
    operator_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:operator",
        issuer="https://staff-idp.example.test",
        subject="operator",
        now=NOW,
    )
    approver_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:approver",
        issuer="https://staff-idp.example.test",
        subject="approver",
        now=NOW,
    )
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                principal_id=operator_id,
                role="platform_operator",
                status="active",
                version=1,
                assigned_by_principal_id=approver_id,
                approval_ref="bootstrap-platform-operator",
                reason="PC2 acceptance",
                created_at=NOW,
                updated_at=NOW,
            )
        )
    return factory, PlatformLifecycleService(factory), sessions, operator_id


def _actor(sessions: PlatformSessionService):
    issued = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="operator",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=NOW,
        ),
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )
    return sessions.validate_session(
        issued.token,
        origin=ORIGIN,
        audience=AUDIENCE,
        now=NOW + timedelta(seconds=1),
    )


def _seed_tenant(
    factory: sessionmaker[Session],
    *,
    owner_status: str = "active",
) -> tuple[UUID, UUID, UUID]:
    tenant_id = uuid4()
    owner_id = uuid4()
    target_id = uuid4()
    with factory.begin() as db:
        db.add_all(
            [
                GlobalUser(
                    id=owner_id,
                    status=owner_status,
                    display_name="Owner",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                GlobalUser(
                    id=target_id,
                    status="active",
                    display_name="Recovery Target",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                Tenant(
                    id=tenant_id,
                    slug=f"tenant-{tenant_id.hex[:8]}",
                    name="PC2 Tenant",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    lifecycle_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            ]
        )
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
                    user_id=target_id,
                    role="admin",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
            ]
        )
    return tenant_id, owner_id, target_id


def _seed_session(db: Session, user_id: UUID, suffix: str) -> None:
    db.add(
        AuthSessionRecord(
            id=uuid4(),
            user_id=user_id,
            token_hash=(suffix * 64)[:64],
            csrf_token_hash=(suffix.upper() * 64)[:64],
            security_version=1,
            authn_method="password",
            expires_at=NOW + timedelta(days=1),
            created_at=NOW,
        )
    )


def test_user_suspend_revokes_sessions_and_stewarded_api_credentials_then_restores(
    pc2,
) -> None:
    factory, lifecycle, sessions, _operator_id = pc2
    tenant_id, _owner_id, target_id = _seed_tenant(factory)
    account_id = uuid4()
    credential_id = uuid4()
    with factory.begin() as db:
        _seed_session(db, target_id, "a")
        db.add(
            ServiceAccountRecord(
                id=account_id,
                tenant_id=tenant_id,
                name="target-automation",
                steward_user_id=target_id,
                created_by=target_id,
                status="active",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.add(
            ApiCredentialRecord(
                id=credential_id,
                tenant_id=tenant_id,
                service_account_id=account_id,
                name="target-key",
                token_hash="b" * 64,
                display_prefix="ogt_target",
                permission_scopes=["project.read_metadata"],
                allowed_networks=[],
                account_security_version=1,
                status="active",
                expires_at=NOW + timedelta(days=30),
                created_by=target_id,
                created_at=NOW,
            )
        )
    actor = _actor(sessions)
    suspended = lifecycle.suspend_user(
        actor,
        user_id=target_id,
        expected_security_version=1,
        approval_ref="approval-user-suspend",
        reason="confirmed account compromise",
        idempotency_key="user-suspend-1",
        now=NOW + timedelta(seconds=2),
    )
    assert suspended.result == {
        "status": "suspended",
        "security_version": 2,
        "revoked_session_count": 1,
        "suspended_service_account_count": 1,
        "revoked_api_credential_count": 1,
    }
    replay = lifecycle.suspend_user(
        actor,
        user_id=target_id,
        expected_security_version=1,
        approval_ref="approval-user-suspend",
        reason="confirmed account compromise",
        idempotency_key="user-suspend-1",
        now=NOW + timedelta(seconds=3),
    )
    assert replay.operation_id == suspended.operation_id
    assert replay.replayed is True

    restored = lifecycle.restore_user(
        actor,
        user_id=target_id,
        expected_security_version=2,
        approval_ref="approval-user-restore",
        reason="identity recovery completed",
        idempotency_key="user-restore-1",
        now=NOW + timedelta(seconds=4),
    )
    assert restored.result["status"] == "active"
    assert restored.result["security_version"] == 3
    with factory() as db:
        assert db.get(ServiceAccountRecord, account_id).status == "suspended"
        assert db.get(ApiCredentialRecord, credential_id).status == "revoked"
        assert db.query(PlatformLifecycleOperationRecord).count() == 2


def test_tenant_suspend_is_versioned_and_revokes_member_sessions_without_reactivating_keys(
    pc2,
) -> None:
    factory, lifecycle, sessions, _operator_id = pc2
    tenant_id, owner_id, target_id = _seed_tenant(factory)
    with factory.begin() as db:
        _seed_session(db, owner_id, "c")
        _seed_session(db, target_id, "d")
    actor = _actor(sessions)
    suspended = lifecycle.suspend_tenant(
        actor,
        tenant_id=tenant_id,
        expected_lifecycle_version=1,
        approval_ref="approval-tenant-suspend",
        reason="tenant security incident",
        idempotency_key="tenant-suspend-1",
        now=NOW + timedelta(seconds=2),
    )
    assert suspended.result["status"] == "suspended"
    assert suspended.result["lifecycle_version"] == 2
    assert suspended.result["revoked_session_count"] == 2

    with pytest.raises(PlatformSecurityError) as stale:
        lifecycle.suspend_tenant(
            actor,
            tenant_id=tenant_id,
            expected_lifecycle_version=1,
            approval_ref="approval-tenant-suspend-2",
            reason="stale concurrent command",
            idempotency_key="tenant-suspend-stale",
            now=NOW + timedelta(seconds=3),
        )
    assert stale.value.code == "platform_tenant_conflict"

    restored = lifecycle.restore_tenant(
        actor,
        tenant_id=tenant_id,
        expected_lifecycle_version=2,
        approval_ref="approval-tenant-restore",
        reason="incident containment verified",
        idempotency_key="tenant-restore-1",
        now=NOW + timedelta(seconds=4),
    )
    assert restored.result["status"] == "active"
    assert restored.result["lifecycle_version"] == 3


def test_owner_recovery_requires_inactive_owner_and_hash_bound_current_preflight(pc2) -> None:
    factory, lifecycle, sessions, _operator_id = pc2
    tenant_id, owner_id, target_id = _seed_tenant(factory, owner_status="suspended")
    actor = _actor(sessions)
    preview = lifecycle.preview_owner_recovery(
        actor,
        tenant_id=tenant_id,
        target_user_id=target_id,
        now=NOW + timedelta(seconds=2),
    )
    assert preview.blockers == ()
    assert preview.source_owner_id == owner_id
    recovered = lifecycle.recover_tenant_owner(
        actor,
        tenant_id=tenant_id,
        target_user_id=target_id,
        expected_tenant_version=preview.tenant_version,
        expected_source_membership_version=cast_int(preview.source_membership_version),
        expected_target_membership_version=cast_int(preview.target_membership_version),
        preview_hash=preview.preview_hash,
        approval_ref="approval-owner-recovery",
        reason="verified abandoned Owner account",
        idempotency_key="owner-recovery-1",
        now=NOW + timedelta(seconds=3),
    )
    assert recovered.result["source_owner_id"] == str(owner_id)
    assert recovered.result["target_owner_id"] == str(target_id)
    with factory() as db:
        assert db.get(TenantMembership, (tenant_id, owner_id)).role == "admin"
        assert db.get(TenantMembership, (tenant_id, target_id)).role == "owner"
        assert db.get(Tenant, tenant_id).lifecycle_version == 2

    with pytest.raises(PlatformSecurityError) as stale:
        lifecycle.recover_tenant_owner(
            actor,
            tenant_id=tenant_id,
            target_user_id=target_id,
            expected_tenant_version=preview.tenant_version,
            expected_source_membership_version=cast_int(preview.source_membership_version),
            expected_target_membership_version=cast_int(preview.target_membership_version),
            preview_hash=preview.preview_hash,
            approval_ref="approval-owner-recovery-stale",
            reason="stale second recovery",
            idempotency_key="owner-recovery-stale",
            now=NOW + timedelta(seconds=4),
        )
    assert stale.value.code in {
        "platform_owner_recovery_blocked",
        "platform_owner_recovery_conflict",
    }


def test_owner_recovery_preflight_blocks_when_current_owner_is_still_active(pc2) -> None:
    factory, lifecycle, sessions, _operator_id = pc2
    tenant_id, _owner_id, target_id = _seed_tenant(factory)
    preview = lifecycle.preview_owner_recovery(
        _actor(sessions),
        tenant_id=tenant_id,
        target_user_id=target_id,
        now=NOW + timedelta(seconds=2),
    )
    assert preview.blockers == ("owner_still_active",)


def test_platform_identity_conflict_review_assigns_or_blocks_without_direct_link(pc2) -> None:
    factory, lifecycle, sessions, operator_id = pc2
    candidate_id = uuid4()
    assigned_conflict_id = uuid4()
    blocked_conflict_id = uuid4()
    with factory.begin() as db:
        db.add(
            GlobalUser(
                id=candidate_id,
                status="active",
                primary_email_normalized="candidate@example.test",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.add_all(
            [
                IdentityConflict(
                    id=assigned_conflict_id,
                    provider="oidc",
                    issuer="https://customer-idp.example.test",
                    subject="ambiguous-assigned",
                    email_normalized="candidate@example.test",
                    status="pending",
                    version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                IdentityConflict(
                    id=blocked_conflict_id,
                    provider="oidc",
                    issuer="https://customer-idp.example.test",
                    subject="ambiguous-blocked",
                    email_normalized="candidate@example.test",
                    status="pending",
                    version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            ]
        )
    actor = _actor(sessions)
    cases = lifecycle.list_identity_conflicts(actor, now=NOW + timedelta(seconds=2))
    assert {value.conflict_id for value in cases} == {
        assigned_conflict_id,
        blocked_conflict_id,
    }
    assigned = lifecycle.review_identity_conflict(
        actor,
        conflict_id=assigned_conflict_id,
        decision="assign",
        candidate_user_id=candidate_id,
        expected_version=1,
        approval_ref="approval-conflict-assignment",
        reason="verified enterprise identity ownership",
        idempotency_key="identity-conflict-assign",
        now=NOW + timedelta(seconds=3),
    )
    assert assigned.result == {
        "status": "pending",
        "version": 2,
        "platform_review_status": "assigned",
        "candidate_user_id": str(candidate_id),
        "customer_reauthentication_required": True,
        "identity_connection_created": False,
    }
    replay = lifecycle.review_identity_conflict(
        actor,
        conflict_id=assigned_conflict_id,
        decision="assign",
        candidate_user_id=candidate_id,
        expected_version=1,
        approval_ref="approval-conflict-assignment",
        reason="verified enterprise identity ownership",
        idempotency_key="identity-conflict-assign",
        now=NOW + timedelta(seconds=4),
    )
    assert replay.operation_id == assigned.operation_id
    assert replay.replayed is True
    with factory() as db:
        assert db.query(IdentityConnection).count() == 0
        conflict = db.get(IdentityConflict, assigned_conflict_id)
        assert conflict is not None
        assert conflict.platform_reviewed_by_principal_id == operator_id

    confirmed = IdentityManagementService(factory).resolve_identity_conflict(
        user_id=candidate_id,
        conflict_id=assigned_conflict_id,
        decision="approve",
        reason="candidate confirmed the new identity",
        reauthenticated_at=NOW + timedelta(seconds=4),
        idempotency_key="candidate-conflict-confirm",
        expected_security_version=1,
        now=NOW + timedelta(seconds=5),
    )
    assert confirmed.identity_connection_id is not None

    blocked = lifecycle.review_identity_conflict(
        actor,
        conflict_id=blocked_conflict_id,
        decision="block",
        candidate_user_id=None,
        expected_version=1,
        approval_ref="approval-conflict-block",
        reason="verified hostile identity assertion",
        idempotency_key="identity-conflict-block",
        now=NOW + timedelta(seconds=5),
    )
    assert blocked.result["platform_review_status"] == "blocked"
    with pytest.raises(LifecycleError) as blocked_login:
        IdentityManagementService(factory).resolve_verified_login(
            VerifiedIdentityAssertion(
                provider="oidc",
                issuer="https://customer-idp.example.test",
                subject="ambiguous-blocked",
                email="candidate@example.test",
                email_verified=True,
            )
        )
    assert blocked_login.value.code == "identity_conflict_rejected"


def cast_int(value: int | None) -> int:
    assert value is not None
    return value
