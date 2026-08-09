from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import (
    GlobalUser,
    IdentityConnection,
    MembershipInvitation,
    PasswordCredential,
    SaasBase,
    Tenant,
    TenantMembership,
)
from saas.control_plane.enterprise_identity import EnterpriseScimService
from saas.control_plane.enterprise_identity_models import (
    EnterpriseScimDirectoryRecord,
    EnterpriseScimEventRecord,
    EnterpriseScimUserRecord,
)
from saas.control_plane.identity import (
    IdentityManagementService,
    VerifiedIdentityAssertion,
)
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    PlatformSessionService,
    StaffIdentityAssertion,
)
from saas.control_plane.privacy_lifecycle import (
    DeletionEvidenceKey,
    DeletionSurfaceEvidence,
    PrivacyLifecycleService,
    sign_surface_evidence,
)
from saas.control_plane.privacy_models import (
    PrivacyDeletionManifestRecord,
    PrivacyIdentityTombstoneRecord,
    PrivacyLegalHoldRecord,
)

ORIGIN = "https://platform-admin.example.test"
AUDIENCE = "omnigent-platform-admin"
NOW = datetime(2026, 8, 9, 7, 0, tzinfo=timezone.utc)
EVIDENCE_KEY = DeletionEvidenceKey("deletion-test-key", b"d" * 32)


@pytest.fixture
def privacy() -> tuple[
    sessionmaker[Session],
    PrivacyLifecycleService,
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
        identity_connection_ref="staff-idp:privacy",
        issuer="https://staff-idp.example.test",
        subject="privacy",
        now=NOW,
    )
    assigner_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:assigner",
        issuer="https://staff-idp.example.test",
        subject="assigner",
        now=NOW,
    )
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                principal_id=operator_id,
                role="compliance_operator",
                status="active",
                version=1,
                assigned_by_principal_id=assigner_id,
                approval_ref="bootstrap-privacy",
                reason="PC5 privacy acceptance",
                created_at=NOW,
                updated_at=NOW,
            )
        )
    return (
        factory,
        PrivacyLifecycleService(factory, evidence_verifier=EVIDENCE_KEY),
        sessions,
        operator_id,
    )


def _actor(sessions: PlatformSessionService):
    issued = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="privacy",
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


def _seed_user(factory: sessionmaker[Session]) -> tuple[UUID, UUID, UUID, str, str]:
    tenant_id = uuid4()
    user_id = uuid4()
    directory_id = uuid4()
    scim_user_id = uuid4()
    raw_token = "scim-deletion-token"
    with factory.begin() as db:
        db.add_all(
            [
                GlobalUser(
                    id=user_id,
                    status="active",
                    display_name="Privacy Subject",
                    primary_email_normalized="subject@example.test",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                Tenant(
                    id=tenant_id,
                    slug="privacy-tenant",
                    name="Privacy Tenant",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    lifecycle_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    role="admin",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
                IdentityConnection(
                    id=uuid4(),
                    user_id=user_id,
                    provider="oidc",
                    issuer="https://idp.example.test",
                    subject="subject-123",
                    email_normalized="subject@example.test",
                    email_verified=True,
                    status="active",
                    created_at=NOW,
                    updated_at=NOW,
                ),
                PasswordCredential(
                    user_id=user_id,
                    login_email_normalized="subject@example.test",
                    password_hash="test-password-hash",
                    password_version=1,
                    failed_attempts=0,
                    updated_at=NOW,
                ),
                MembershipInvitation(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    email_normalized="subject@example.test",
                    tenant_role="member",
                    token_hash=sha256(b"privacy-pending-invitation").hexdigest(),
                    status="pending",
                    expires_at=NOW + timedelta(days=7),
                    created_by=user_id,
                    version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                MembershipInvitation(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    email_normalized="accepted-subject@example.test",
                    tenant_role="member",
                    token_hash=sha256(b"privacy-accepted-invitation").hexdigest(),
                    status="accepted",
                    expires_at=NOW + timedelta(days=7),
                    accepted_by=user_id,
                    accepted_at=NOW,
                    created_by=user_id,
                    version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                EnterpriseScimDirectoryRecord(
                    id=directory_id,
                    tenant_id=tenant_id,
                    display_name="Workforce",
                    token_hash=sha256(raw_token.encode()).hexdigest(),
                    token_prefix="scim-del",
                    status="active",
                    version=1,
                    configured_by=user_id,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            ]
        )
        db.flush()
        db.add(
            EnterpriseScimUserRecord(
                id=scim_user_id,
                tenant_id=tenant_id,
                directory_id=directory_id,
                external_id="external-subject-123",
                user_id=user_id,
                user_name_normalized="subject@example.test",
                display_name="Privacy Subject",
                active=True,
                version=1,
                source_version=1,
                source_state_hash="a" * 64,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.flush()
        db.add(
            EnterpriseScimEventRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                directory_id=directory_id,
                event_id="provision-subject",
                resource_type="User",
                resource_id=scim_user_id,
                source_version=1,
                request_hash="b" * 64,
                disposition="applied",
                result={
                    "external_id": "external-subject-123",
                    "user_name": "subject@example.test",
                    "display_name": "Privacy Subject",
                    "resource_id": str(scim_user_id),
                },
                created_at=NOW,
            )
        )
    return user_id, tenant_id, directory_id, raw_token, "external-subject-123"


def _surface(
    manifest_id: UUID,
    name: str,
    disposition: str,
    now: datetime,
) -> DeletionSurfaceEvidence:
    common = {
        "manifest_id": manifest_id,
        "surface": name,
        "disposition": disposition,
        "evidence_sha256": sha256(name.encode()).hexdigest(),
        "remaining_item_count": 0,
        "runtime_accessible": False,
        "direct_identifiers_remaining": False,
        "observed_at": now,
    }
    if disposition in {"erase", "cryptographic_erase"}:
        evidence = DeletionSurfaceEvidence(status="erased", **common)
    elif disposition == "redact_and_retain":
        evidence = DeletionSurfaceEvidence(
            status="retained",
            retention_until=now + timedelta(days=30),
            retention_basis="security_log_retention",
            **common,
        )
    elif disposition == "anonymize_and_retain":
        evidence = DeletionSurfaceEvidence(
            status="retained",
            retention_until=now + timedelta(days=2555),
            retention_basis="statutory_record_retention",
            **common,
        )
    else:
        evidence = DeletionSurfaceEvidence(
            status="pending_retention",
            remaining_item_count=1,
            retention_until=now + timedelta(days=35),
            retention_basis="immutable_backup_retention",
            tombstone_sha256=sha256(b"backup-tombstone").hexdigest(),
            **{key: value for key, value in common.items() if key != "remaining_item_count"},
        )
    return sign_surface_evidence(evidence, EVIDENCE_KEY)


def test_legal_hold_blocks_deletion_until_exact_version_release(privacy) -> None:
    factory, service, sessions, _operator_id = privacy
    user_id, _tenant_id, _directory_id, _token, _external = _seed_user(factory)
    actor = _actor(sessions)
    hold = service.place_legal_hold(
        actor,
        target_type="global_user",
        target_id=user_id,
        scope=("identity", "audit"),
        authority_ref="case-2026-100",
        reason="regulatory preservation request",
        review_due_at=NOW + timedelta(days=30),
        now=NOW + timedelta(seconds=2),
    )
    assert hold.review_due_at == NOW + timedelta(days=30)
    preview = service.preview_deletion(
        actor,
        target_type="global_user",
        target_id=user_id,
        now=NOW + timedelta(seconds=3),
    )
    assert preview.blockers == ("active_legal_hold",)
    with pytest.raises(PlatformSecurityError) as blocked:
        service.start_deletion(
            actor,
            target_type="global_user",
            target_id=user_id,
            expected_target_version=preview.target_version,
            preview_hash=preview.preview_hash,
            approval_ref="privacy-delete-approval",
            reason="verified erasure request",
            idempotency_key="delete-held-user",
            now=NOW + timedelta(seconds=4),
        )
    assert blocked.value.code == "platform_privacy_deletion_blocked"

    released = service.release_legal_hold(
        actor,
        target_type="global_user",
        target_id=user_id,
        hold_id=hold.hold_id,
        expected_version=hold.version,
        reason="preservation authority released the case",
        now=NOW + timedelta(seconds=5),
    )
    assert released.status == "released"
    with factory() as db:
        assert db.get(PrivacyLegalHoldRecord, hold.hold_id).version == 2

    second = service.place_legal_hold(
        actor,
        target_type="global_user",
        target_id=user_id,
        scope=("audit",),
        authority_ref="case-2026-101",
        reason="second preservation request",
        review_due_at=NOW + timedelta(days=31),
        now=NOW + timedelta(seconds=6),
    )
    service.release_legal_hold(
        actor,
        target_type="global_user",
        target_id=user_id,
        hold_id=second.hold_id,
        expected_version=second.version,
        reason="second preservation authority released the case",
        now=NOW + timedelta(seconds=7),
    )
    third = service.place_legal_hold(
        actor,
        target_type="global_user",
        target_id=user_id,
        scope=("identity",),
        authority_ref="case-2026-102",
        reason="third preservation request",
        review_due_at=NOW + timedelta(days=32),
        now=NOW + timedelta(seconds=8),
    )
    page = service.list_legal_holds(
        actor,
        target_type="global_user",
        target_id=user_id,
        limit=2,
        now=NOW + timedelta(seconds=9),
    )
    assert tuple(item.hold_id for item in page.items) == (third.hold_id, second.hold_id)
    assert page.next_cursor == second.hold_id
    older = service.list_legal_holds(
        actor,
        target_type="global_user",
        target_id=user_id,
        cursor=page.next_cursor,
        limit=2,
        now=NOW + timedelta(seconds=9),
    )
    assert tuple(item.hold_id for item in older.items) == (hold.hold_id,)
    assert older.next_cursor is None
    with pytest.raises(PlatformSecurityError, match="cursor is invalid"):
        service.list_legal_holds(
            actor,
            target_type="global_user",
            target_id=user_id,
            status="released",
            cursor=third.hold_id,
            now=NOW + timedelta(seconds=9),
        )


def test_manifest_history_uses_stable_time_and_id_keyset(privacy) -> None:
    factory, service, sessions, operator_id = privacy
    user_id, _tenant_id, _directory_id, _token, _external = _seed_user(factory)
    actor = _actor(sessions)
    manifests = []
    with factory.begin() as db:
        for index in range(3):
            manifest = PrivacyDeletionManifestRecord(
                target_type="global_user",
                target_id=user_id,
                tenant_id=None,
                requested_by_principal_id=operator_id,
                idempotency_key=f"history-{index}",
                request_hash=str(index) * 64,
                approval_ref=f"approval-{index}",
                completion_approval_ref=f"completion-{index}",
                reason="history pagination fixture",
                expected_target_version=1,
                preview_hash=str(index + 1) * 64,
                status="completed",
                blockers=[],
                surface_outcomes={},
                manifest_hash=str(index + 2) * 64,
                version=1,
                started_at=NOW + timedelta(minutes=index),
                completed_at=NOW + timedelta(minutes=index, seconds=30),
                updated_at=NOW + timedelta(minutes=index, seconds=30),
            )
            db.add(manifest)
            manifests.append(manifest)
    page = service.list_manifests(
        actor,
        target_type="global_user",
        target_id=user_id,
        limit=2,
        now=NOW + timedelta(minutes=4),
    )
    assert tuple(item.manifest_id for item in page.items) == (
        manifests[2].id,
        manifests[1].id,
    )
    assert page.next_cursor == manifests[1].id
    older = service.list_manifests(
        actor,
        target_type="global_user",
        target_id=user_id,
        cursor=page.next_cursor,
        limit=2,
        now=NOW + timedelta(minutes=4),
    )
    assert tuple(item.manifest_id for item in older.items) == (manifests[0].id,)
    assert older.next_cursor is None


def test_user_deletion_anonymizes_identity_blocks_replay_and_requires_all_surfaces(
    privacy,
) -> None:
    factory, service, sessions, _operator_id = privacy
    user_id, _tenant_id, _directory_id, token, external = _seed_user(factory)
    actor = _actor(sessions)
    preview = service.preview_deletion(
        actor,
        target_type="global_user",
        target_id=user_id,
        now=NOW + timedelta(seconds=2),
    )
    assert preview.blockers == ()
    started = service.start_deletion(
        actor,
        target_type="global_user",
        target_id=user_id,
        expected_target_version=preview.target_version,
        preview_hash=preview.preview_hash,
        approval_ref="privacy-delete-approval",
        reason="verified erasure request",
        idempotency_key="delete-user-1",
        now=NOW + timedelta(seconds=3),
    )
    assert started.status == "executing"
    assert len(started.surface_outcomes) == 15
    with factory() as db:
        user = db.get(GlobalUser, user_id)
        assert (user.status, user.display_name, user.primary_email_normalized) == (
            "suspended",
            None,
            None,
        )
        assert db.get(PasswordCredential, user_id) is None
        invitations = list(db.scalars(sa.select(MembershipInvitation)))
        assert {value.status for value in invitations} == {"accepted", "revoked"}
        assert all(value.email_normalized.startswith("deleted-") for value in invitations)
        assert all(value.accepted_by is None for value in invitations)
        assert all(value.deletion_manifest_id == started.manifest_id for value in invitations)
        assert db.query(PrivacyIdentityTombstoneRecord).count() == 2
        receipt = db.scalar(sa.select(EnterpriseScimEventRecord))
        assert receipt.redaction_manifest_id == started.manifest_id
        assert receipt.result["redacted"] is True

    assertion = VerifiedIdentityAssertion(
        provider="oidc",
        issuer="https://idp.example.test",
        subject="subject-123",
        email="subject@example.test",
        email_verified=True,
    )
    with pytest.raises(LifecycleError, match="cannot be reprovisioned"):
        IdentityManagementService(factory).provision_identity(assertion)
    with pytest.raises(LifecycleError, match="cannot be reprovisioned"):
        EnterpriseScimService(factory).upsert_user(
            token,
            event_id="replay-after-delete",
            external_id=external,
            user_name="subject@example.test",
            display_name="Privacy Subject",
            active=True,
            source_version=2,
        )

    manifest = started
    first_name, first_pending = next(iter(started.surface_outcomes.items()))
    with pytest.raises(PlatformSecurityError) as stale_surface:
        service.record_surface_evidence(
            replace(actor, authenticated_at=NOW - timedelta(minutes=6)),
            target_type="global_user",
            target_id=user_id,
            evidence=_surface(
                started.manifest_id,
                first_name,
                str(first_pending["disposition"]),
                NOW + timedelta(seconds=4),
            ),
            expected_manifest_version=manifest.version,
            now=NOW + timedelta(seconds=5),
        )
    assert stale_surface.value.code == "platform_fresh_auth_required"
    for name, pending in started.surface_outcomes.items():
        evidence = _surface(
            started.manifest_id,
            name,
            str(pending["disposition"]),
            NOW + timedelta(seconds=4),
        )
        manifest = service.record_surface_evidence(
            actor,
            target_type="global_user",
            target_id=user_id,
            evidence=evidence,
            expected_manifest_version=manifest.version,
            now=NOW + timedelta(seconds=5),
        )
    assert manifest.status == "ready_to_finalize"
    completed = service.finalize_deletion(
        actor,
        target_type="global_user",
        target_id=user_id,
        manifest_id=manifest.manifest_id,
        expected_manifest_version=manifest.version,
        approval_ref="privacy-delete-final-approval",
        now=NOW + timedelta(seconds=6),
    )
    assert completed.status == "completed"
    assert completed.manifest_hash is not None
    assert completed.completion_approval_ref == "privacy-delete-final-approval"
    with pytest.raises(PlatformSecurityError) as wrong_completion_replay:
        service.finalize_deletion(
            actor,
            target_type="global_user",
            target_id=user_id,
            manifest_id=manifest.manifest_id,
            expected_manifest_version=completed.version,
            approval_ref="different-final-approval",
            now=NOW + timedelta(seconds=7),
        )
    assert wrong_completion_replay.value.code == "platform_privacy_manifest_conflict"
    with factory() as db:
        assert db.get(GlobalUser, user_id).status == "deleted"
        stored = db.get(PrivacyDeletionManifestRecord, completed.manifest_id)
        assert stored.manifest_hash == completed.manifest_hash


def test_tenant_deletion_preview_requires_suspension_and_no_active_runs(privacy) -> None:
    factory, service, sessions, _operator_id = privacy
    _user_id, tenant_id, _directory_id, _token, _external = _seed_user(factory)
    actor = _actor(sessions)
    active = service.preview_deletion(
        actor,
        target_type="tenant",
        target_id=tenant_id,
        now=NOW + timedelta(seconds=2),
    )
    assert active.blockers == ("tenant_must_be_suspended",)
    with factory.begin() as db:
        tenant = db.get(Tenant, tenant_id)
        tenant.status = "suspended"
        tenant.lifecycle_version += 1
    ready = service.preview_deletion(
        actor,
        target_type="tenant",
        target_id=tenant_id,
        now=NOW + timedelta(seconds=3),
    )
    assert ready.blockers == ()
    started = service.start_deletion(
        actor,
        target_type="tenant",
        target_id=tenant_id,
        expected_target_version=ready.target_version,
        preview_hash=ready.preview_hash,
        approval_ref="privacy-tenant-delete-approval",
        reason="verified Tenant erasure request",
        idempotency_key="delete-tenant-1",
        now=NOW + timedelta(seconds=4),
    )
    assert started.status == "executing"
    with factory() as db:
        invitations = list(
            db.scalars(
                sa.select(MembershipInvitation).where(MembershipInvitation.tenant_id == tenant_id)
            )
        )
        assert all(value.email_normalized.startswith("deleted-") for value in invitations)
        assert all(value.accepted_by is None for value in invitations)
        assert all(value.deletion_manifest_id == started.manifest_id for value in invitations)
