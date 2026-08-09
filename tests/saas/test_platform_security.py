from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
    PlatformTenantProjectionRecord,
    PlatformUserProjectionRecord,
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
        identity_connection_ref=f"staff-idp:{name}",
        issuer="https://staff-idp.example.test",
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
                approval_ref="staff-idp-bootstrap-approval",
                reason="initial Staff IdP role sync",
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
            issuer="https://staff-idp.example.test",
            subject=subject,
            authn_method="passkey",
            mfa_strength="phishing_resistant",
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


def test_staff_realm_requires_dedicated_identity_phishing_resistant_mfa_and_origin(
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

    with pytest.raises(PlatformSecurityError) as weak_mfa:
        sessions.issue_session(
            StaffIdentityAssertion(
                issuer="https://staff-idp.example.test",
                subject="operator",
                authn_method="password",
                mfa_strength="password_only",
                authenticated_at=NOW,
            ),
            expires_at=NOW + timedelta(hours=1),
            now=NOW,
        )
    assert weak_mfa.value.code == "platform_mfa_required"

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
        identity_connection_ref="staff-idp:auditor",
        issuer="https://staff-idp.example.test",
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
            identity_connection_ref="staff-idp:somebody-else",
            issuer="https://staff-idp.example.test",
            subject="auditor",
            now=NOW + timedelta(seconds=2),
        )
    assert conflict.value.code == "platform_identity_conflict"
