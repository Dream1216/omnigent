from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase
from saas.control_plane.platform_models import (
    PlatformAuthSessionRecord,
    PlatformPasswordCredentialRecord,
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
    PlatformTenantProjectionRecord,
    PlatformUserProjectionRecord,
)
from saas.control_plane.platform_password_auth import (
    STAFF_PASSWORD_ISSUER,
    PlatformPasswordAuthenticationService,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSecurityError,
    PlatformSessionService,
    StaffIdentityAssertion,
    TenantProjectionInput,
    UserProjectionInput,
    mask_email,
)

ORIGIN = "https://platform-admin.example.test"
AUDIENCE = "omnigent-platform-admin"
NOW = datetime(2026, 8, 7, 13, 0, tzinfo=timezone.utc)


@pytest.fixture
def platform_control_plane() -> tuple[
    sessionmaker[Session],
    PlatformAuthorizationService,
    PlatformSessionService,
    PlatformProjectionService,
]:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    return (
        factory,
        PlatformAuthorizationService(factory),
        PlatformSessionService(factory, origin=ORIGIN, audience=AUDIENCE),
        PlatformProjectionService(factory),
    )


def _provision(
    authorization: PlatformAuthorizationService,
    name: str,
) -> UUID:
    return authorization.provision_staff_principal(
        identity_connection_ref=f"local-password:{name}",
        issuer=STAFF_PASSWORD_ISSUER,
        subject=name,
        display_name=name.title(),
        email_normalized=f"{name}@example.test",
        now=NOW,
    )


def _seed_role(
    factory: sessionmaker[Session],
    *,
    principal_id: UUID,
    assigned_by: UUID,
    role: str,
) -> UUID:
    assignment_id = uuid4()
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                id=assignment_id,
                principal_id=principal_id,
                role=role,
                status="active",
                version=1,
                assigned_by_principal_id=assigned_by,
                approval_ref="local-password-bootstrap-approval",
                reason="initial local Staff role assignment",
                created_at=NOW,
                updated_at=NOW,
            )
        )
    return assignment_id


def _issue(
    sessions: PlatformSessionService,
    subject: str,
):
    return sessions.issue_session(
        StaffIdentityAssertion(
            issuer=STAFF_PASSWORD_ISSUER,
            subject=subject,
            authn_method="password",
            mfa_strength="not_required",
            authenticated_at=NOW,
        ),
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )


def _validate(sessions: PlatformSessionService, token: str):
    return sessions.validate_session(
        token,
        origin=ORIGIN,
        audience=AUDIENCE,
        now=NOW + timedelta(seconds=1),
    )


def test_initial_local_password_operator_bootstrap_is_exactly_once(
    platform_control_plane,
) -> None:
    factory, _authorization, sessions, _projections = platform_control_plane
    passwords = PlatformPasswordAuthenticationService(factory, sessions)
    principal_id = passwords.bootstrap_initial_operator(
        username="admin",
        password="admin-password-2026",
        display_name="Initial Administrator",
        email_normalized="admin@jxhh.com",
        now=NOW,
    )

    with factory.begin() as db:
        principal = db.get(PlatformStaffPrincipalRecord, principal_id)
        credential = db.get(PlatformPasswordCredentialRecord, principal_id)
        assignment = db.scalar(
            sa.select(PlatformRoleAssignmentRecord).where(
                PlatformRoleAssignmentRecord.principal_id == principal_id
            )
        )
        assert principal is not None
        assert principal.issuer == STAFF_PASSWORD_ISSUER
        assert principal.subject == "admin"
        assert credential is not None
        assert credential.username_normalized == "admin"
        assert credential.password_hash != "admin-password-2026"
        assert assignment is not None
        assert assignment.role == "platform_operator"
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuthSessionRecord)) == 0

    with pytest.raises(PlatformSecurityError) as repeated:
        passwords.bootstrap_initial_operator(
            username="admin-2",
            password="admin-password-2026",
            now=NOW,
        )
    assert repeated.value.code == "platform_bootstrap_conflict"


def test_local_operator_transition_requires_existing_operator_and_is_idempotent(
    platform_control_plane,
) -> None:
    factory, authorization, sessions, _projections = platform_control_plane
    legacy_operator = authorization.provision_staff_principal(
        identity_connection_ref="single-owner-beta-bridge",
        issuer="urn:omnigent:single-owner-beta",
        subject="legacy-owner",
        now=NOW,
    )
    roleless_legacy = authorization.provision_staff_principal(
        identity_connection_ref="single-owner-beta-roleless",
        issuer="urn:omnigent:single-owner-beta",
        subject="legacy-roleless",
        now=NOW,
    )
    _seed_role(
        factory,
        principal_id=legacy_operator,
        assigned_by=roleless_legacy,
        role="platform_operator",
    )
    passwords = PlatformPasswordAuthenticationService(factory, sessions)

    principal_id = passwords.transition_local_operator(
        username="staff-admin",
        password="staff-admin-password-2026",
        authorized_by_principal_id=legacy_operator,
        approval_ref="BETA-LOCAL-STAFF-TRANSITION-20260917",
        reason="replace the temporary Tenant bridge with local Staff login",
        now=NOW,
    )
    assert (
        passwords.transition_local_operator(
            username="STAFF-ADMIN",
            password="staff-admin-password-2026",
            authorized_by_principal_id=legacy_operator,
            approval_ref="BETA-LOCAL-STAFF-TRANSITION-20260917",
            reason="replace the temporary Tenant bridge with local Staff login",
            now=NOW,
        )
        == principal_id
    )
    with factory.begin() as db:
        assignment = db.scalar(
            sa.select(PlatformRoleAssignmentRecord).where(
                PlatformRoleAssignmentRecord.principal_id == principal_id
            )
        )
        assert assignment is not None
        assert assignment.role == "platform_operator"
        assert assignment.assigned_by_principal_id == legacy_operator
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PlatformPasswordCredentialRecord))
            == 1
        )

    issued = passwords.authenticate("staff-admin", "staff-admin-password-2026", now=NOW)
    assert issued.principal_id == principal_id
    with pytest.raises(PlatformSecurityError) as unauthorized:
        passwords.transition_local_operator(
            username="second-admin",
            password="second-admin-password-2026",
            authorized_by_principal_id=roleless_legacy,
            approval_ref="BETA-LOCAL-STAFF-TRANSITION-20260917",
            reason="unauthorized retry",
            now=NOW,
        )
    assert unauthorized.value.code == "platform_transition_authority_invalid"


def test_local_staff_password_authentication_is_generic_and_locks_failures(
    platform_control_plane,
) -> None:
    factory, _authorization, sessions, _projections = platform_control_plane
    passwords = PlatformPasswordAuthenticationService(factory, sessions)
    passwords.provision_account(
        username="Case.Sensitive",
        password="correct-password-2026",
        now=NOW,
    )

    for username in ("unknown", "case.sensitive"):
        with pytest.raises(PlatformSecurityError) as denied:
            passwords.authenticate(username, "wrong-password-2026", now=NOW)
        assert denied.value.code == "platform_invalid_credentials"

    for _attempt in range(4):
        with pytest.raises(PlatformSecurityError) as denied:
            passwords.authenticate("CASE.SENSITIVE", "wrong-password-2026", now=NOW)
        assert denied.value.code == "platform_invalid_credentials"
    with pytest.raises(PlatformSecurityError) as locked:
        passwords.authenticate("case.sensitive", "correct-password-2026", now=NOW)
    assert locked.value.code == "platform_invalid_credentials"

    with pytest.raises(PlatformSecurityError) as expired_lock_failure:
        passwords.authenticate(
            "case.sensitive",
            "wrong-password-2026",
            now=NOW + timedelta(minutes=16),
        )
    assert expired_lock_failure.value.code == "platform_invalid_credentials"
    issued = passwords.authenticate(
        "case.sensitive",
        "correct-password-2026",
        now=NOW + timedelta(minutes=16, seconds=1),
    )
    assert _validate(sessions, issued.token).authn_method == "password"


def test_invalid_username_shape_cannot_lock_a_real_sentinel_named_account(
    platform_control_plane,
) -> None:
    factory, _authorization, sessions, _projections = platform_control_plane
    passwords = PlatformPasswordAuthenticationService(factory, sessions)
    passwords.provision_account(
        username="invalid-staff-user",
        password="sentinel-password-2026",
        now=NOW,
    )

    for _attempt in range(5):
        with pytest.raises(PlatformSecurityError) as denied:
            passwords.authenticate("invalid username!", "wrong-password-2026", now=NOW)
        assert denied.value.code == "platform_invalid_credentials"

    issued = passwords.authenticate(
        "invalid-staff-user",
        "sentinel-password-2026",
        now=NOW,
    )
    assert issued.principal_id is not None


def test_local_staff_password_reset_revokes_sessions_and_unlocks_account(
    platform_control_plane,
) -> None:
    factory, _authorization, sessions, _projections = platform_control_plane
    passwords = PlatformPasswordAuthenticationService(factory, sessions)
    principal_id = passwords.provision_account(
        username="resettable",
        password="initial-password-2026",
        now=NOW,
    )
    issued = passwords.authenticate("resettable", "initial-password-2026", now=NOW)

    assert (
        passwords.reset_password(
            principal_id=principal_id,
            new_password="replacement-password-2026",
            expected_version=1,
            now=NOW + timedelta(minutes=1),
        )
        == 2
    )
    with pytest.raises(PlatformSecurityError) as revoked:
        sessions.validate_session(
            issued.token,
            origin=ORIGIN,
            audience=AUDIENCE,
            now=NOW + timedelta(minutes=1, seconds=1),
        )
    assert revoked.value.code == "platform_session_invalid"
    with pytest.raises(PlatformSecurityError) as old_password:
        passwords.authenticate(
            "resettable",
            "initial-password-2026",
            now=NOW + timedelta(minutes=1),
        )
    assert old_password.value.code == "platform_invalid_credentials"
    replacement = passwords.authenticate(
        "resettable",
        "replacement-password-2026",
        now=NOW + timedelta(minutes=1),
    )
    assert replacement.principal_id == principal_id


def test_staff_realm_requires_local_password_identity_and_exact_origin(
    platform_control_plane,
) -> None:
    factory, authorization, sessions, _projections = platform_control_plane
    staff_id = _provision(authorization, "operator")
    with factory.begin() as db:
        db.add(
            GlobalUser(
                id=staff_id,
                status="active",
                display_name="customer identity with same UUID",
                security_version=1,
            )
        )

    with pytest.raises(PlatformSecurityError) as no_staff_identity:
        _issue(sessions, "customer-only-subject")
    assert no_staff_identity.value.code == "platform_principal_inactive"

    with pytest.raises(PlatformSecurityError) as disallowed_method:
        sessions.issue_session(
            StaffIdentityAssertion(
                issuer=STAFF_PASSWORD_ISSUER,
                subject="operator",
                authn_method="webauthn",
                mfa_strength="not_required",
                authenticated_at=NOW,
            ),
            expires_at=NOW + timedelta(hours=1),
            now=NOW,
        )
    assert disallowed_method.value.code == "platform_authn_method_invalid"

    issued = _issue(sessions, "operator")
    principal = _validate(sessions, issued.token)
    assert principal.principal_id == staff_id
    assert principal.roles == frozenset()
    assert principal.permissions == frozenset()
    sessions.validate_csrf(issued.token, issued.csrf_token)

    with pytest.raises(PlatformSecurityError) as wrong_origin:
        sessions.validate_session(
            issued.token,
            origin="https://tenant.example.test",
            audience=AUDIENCE,
            now=NOW + timedelta(seconds=2),
        )
    assert wrong_origin.value.code == "platform_session_invalid"

    with pytest.raises(PlatformSecurityError) as wrong_audience:
        sessions.validate_session(
            issued.token,
            origin=ORIGIN,
            audience="omnigent-tenant-admin",
            now=NOW + timedelta(seconds=2),
        )
    assert wrong_audience.value.code == "platform_session_invalid"


def test_role_assignment_is_two_person_fresh_and_revokes_stale_session_immediately(
    platform_control_plane,
) -> None:
    factory, authorization, sessions, projections = platform_control_plane
    operator_id = _provision(authorization, "operator")
    target_id = _provision(authorization, "target")
    _seed_role(
        factory,
        principal_id=operator_id,
        assigned_by=target_id,
        role="platform_operator",
    )
    operator = _validate(sessions, _issue(sessions, "operator").token)
    target_session = _issue(sessions, "target")
    target_without_role = _validate(sessions, target_session.token)

    with pytest.raises(PlatformSecurityError) as self_grant:
        authorization.assign_role(
            operator,
            principal_id=operator_id,
            role="platform_security_auditor",
            approval_ref="approval-self",
            reason="must fail",
            now=NOW + timedelta(seconds=2),
        )
    assert self_grant.value.code == "platform_separation_of_duties"

    assignment = authorization.assign_role(
        operator,
        principal_id=target_id,
        role="platform_security_auditor",
        approval_ref="approval-two-person-1",
        reason="security audit duty",
        now=NOW + timedelta(seconds=2),
    )
    target = sessions.validate_session(
        target_session.token,
        origin=ORIGIN,
        audience=AUDIENCE,
        now=NOW + timedelta(seconds=3),
    )
    assert "platform.user.read" in target.permissions

    projections.upsert_user(
        UserProjectionInput(
            user_id=uuid4(),
            status="active",
            display_name="Customer User",
            email_masked="c***@example.test",
            membership_count=2,
            security_version=4,
            source_version=1,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    assert len(projections.list_users(target).items) == 1

    revoked = authorization.revoke_assignment(
        operator,
        assignment_id=assignment.assignment_id,
        expected_version=assignment.version,
        approval_ref="approval-two-person-2",
        reason="duty ended",
        now=NOW + timedelta(seconds=4),
    )
    assert revoked.status == "revoked"
    with pytest.raises(PlatformSecurityError) as stale_session:
        projections.list_users(target)
    assert stale_session.value.code == "platform_permission_denied"

    with pytest.raises(PlatformSecurityError) as still_roleless:
        projections.list_users(target_without_role)
    assert still_roleless.value.code == "platform_permission_denied"


def test_content_blind_projections_filter_fields_and_use_stable_cursors(
    platform_control_plane,
) -> None:
    factory, authorization, sessions, projections = platform_control_plane
    operator_id = _provision(authorization, "operator")
    auditor_id = _provision(authorization, "auditor")
    _seed_role(
        factory,
        principal_id=operator_id,
        assigned_by=auditor_id,
        role="platform_operator",
    )
    _seed_role(
        factory,
        principal_id=auditor_id,
        assigned_by=operator_id,
        role="platform_security_auditor",
    )
    operator = _validate(sessions, _issue(sessions, "operator").token)
    auditor = _validate(sessions, _issue(sessions, "auditor").token)

    tenant_ids = sorted((uuid4(), uuid4()))
    for index, tenant_id in enumerate(tenant_ids, start=1):
        projections.upsert_tenant(
            TenantProjectionInput(
                tenant_id=tenant_id,
                slug=f"tenant-{index}",
                name=f"Tenant {index}",
                status="active",
                plan="team",
                home_region="cn-east-1",
                member_count=index,
                space_count=index,
                source_version=1,
                updated_at=NOW,
            )
        )
    first = projections.list_tenants(operator, limit=1)
    assert len(first.items) == 1
    assert first.next_cursor == str(tenant_ids[0])
    second = projections.list_tenants(
        operator,
        cursor=UUID(first.next_cursor),
        limit=1,
    )
    assert second.items[0]["tenant_id"] == tenant_ids[1]
    assert first.items[0].keys() == {
        "tenant_id",
        "slug",
        "name",
        "status",
        "plan",
        "home_region",
        "member_count",
        "space_count",
        "updated_at",
    }

    user_id = uuid4()
    projections.upsert_user(
        UserProjectionInput(
            user_id=user_id,
            status="active",
            display_name="Customer User",
            email_masked=mask_email("customer@example.test"),
            membership_count=3,
            security_version=9,
            source_version=1,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    user = projections.list_users(auditor).items[0]
    assert user["email_masked"] == "c***@example.test"
    assert user["security_version"] == 9
    assert "primary_email" not in user

    tenant_columns = set(PlatformTenantProjectionRecord.__table__.columns.keys())
    user_columns = set(PlatformUserProjectionRecord.__table__.columns.keys())
    forbidden = {"prompt", "message", "artifact", "secret", "code", "request_body"}
    assert not tenant_columns & forbidden
    assert not user_columns & forbidden
    assert "email_normalized" not in user_columns


def test_staff_provisioning_is_roleless_idempotent_and_conflict_safe(
    platform_control_plane,
) -> None:
    factory, authorization, _sessions, _projections = platform_control_plane
    principal_id = _provision(authorization, "auditor")
    replayed_id = authorization.provision_staff_principal(
        identity_connection_ref="local-password:auditor",
        issuer=STAFF_PASSWORD_ISSUER,
        subject="auditor",
        display_name="Updated Auditor",
        email_normalized="auditor@example.test",
        now=NOW + timedelta(seconds=1),
    )
    assert replayed_id == principal_id
    with factory() as db:
        principal = db.get(PlatformStaffPrincipalRecord, principal_id)
        assert principal is not None
        assert principal.display_name == "Updated Auditor"
        assert db.query(PlatformRoleAssignmentRecord).count() == 0

    with pytest.raises(PlatformSecurityError) as conflict:
        authorization.provision_staff_principal(
            identity_connection_ref="local-password:somebody-else",
            issuer=STAFF_PASSWORD_ISSUER,
            subject="auditor",
            now=NOW + timedelta(seconds=2),
        )
    assert conflict.value.code == "platform_identity_conflict"
