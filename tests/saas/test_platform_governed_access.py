from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase, Tenant, TenantMembership
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_governed_access import (
    AuditSigningKey,
    PlatformGovernedAccessService,
    TenantSupportActor,
)
from saas.control_plane.platform_governed_models import PlatformAuditExportRecord
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
    PlatformTenantProjectionRecord,
)
from saas.control_plane.platform_security import PlatformSecurityError, ValidatedPlatformPrincipal

NOW = datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc)

GovernedFixture = tuple[
    sessionmaker[Session],
    PlatformGovernedAccessService,
    dict[str, ValidatedPlatformPrincipal],
    UUID,
    UUID,
]


@pytest.fixture
def governed() -> GovernedFixture:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id, customer_id = uuid4(), uuid4()
    principal_ids = {name: uuid4() for name in ("support", "operator", "auditor")}
    with factory.begin() as db:
        db.add_all(
            [
                GlobalUser(
                    id=customer_id,
                    status="active",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                Tenant(
                    id=tenant_id,
                    slug=f"pc3-{tenant_id.hex}",
                    name="PC3 Tenant",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    lifecycle_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=customer_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
                PlatformTenantProjectionRecord(
                    tenant_id=tenant_id,
                    slug=f"pc3-{tenant_id.hex}",
                    name="PC3 Tenant",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    member_count=1,
                    space_count=1,
                    source_version=1,
                    updated_at=NOW,
                ),
            ]
        )
        for name, principal_id in principal_ids.items():
            db.add(
                PlatformStaffPrincipalRecord(
                    id=principal_id,
                    identity_connection_ref=f"staff-idp:{name}",
                    issuer="https://staff-idp.example.test",
                    subject=name,
                    status="active",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
        roles = {
            "support": "support_agent",
            "operator": "platform_operator",
            "auditor": "platform_security_auditor",
        }
        for name, role in roles.items():
            db.add(
                PlatformRoleAssignmentRecord(
                    id=uuid4(),
                    principal_id=principal_ids[name],
                    role=role,
                    status="active",
                    version=1,
                    assigned_by_principal_id=principal_ids["operator"],
                    approval_ref=f"pc3-{name}-bootstrap",
                    reason="PC3 governed access acceptance",
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
        db.add(
            PlatformRoleAssignmentRecord(
                id=uuid4(),
                principal_id=principal_ids["support"],
                role="platform_operator",
                status="active",
                version=1,
                assigned_by_principal_id=principal_ids["operator"],
                approval_ref="pc3-support-sod-test",
                reason="prove requester and approver separation",
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.add(
            PlatformRoleAssignmentRecord(
                id=uuid4(),
                principal_id=principal_ids["auditor"],
                role="platform_operator",
                status="active",
                version=1,
                assigned_by_principal_id=principal_ids["operator"],
                approval_ref="pc3-auditor-sod-test",
                reason="prove audit requester and approver separation",
                created_at=NOW,
                updated_at=NOW,
            )
        )
    actors = {
        name: ValidatedPlatformPrincipal(
            session_id=uuid4(),
            principal_id=principal_ids[name],
            security_version=1,
            authn_method="passkey",
            authenticated_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            roles=frozenset({role}),
            permissions=PLATFORM_ROLE_PERMISSIONS[role],
        )
        for name, role in roles.items()
    }
    service = PlatformGovernedAccessService(
        factory,
        signing_key=AuditSigningKey(key_id="test-key-v1", secret=b"k" * 32),
    )
    return factory, service, actors, tenant_id, customer_id


def test_standard_support_requires_customer_and_distinct_staff_approval_then_revokes(
    governed: GovernedFixture,
) -> None:
    _factory, service, actors, tenant_id, customer_id = governed
    project_id = uuid4()
    grant = service.request_support_grant(
        actors["support"],
        tenant_id=tenant_id,
        mode="standard",
        scopes=("project.content.read",),
        project_ids=(project_id,),
        reason="investigate a tenant-authorized project incident",
        incident_ref=None,
        expires_at=NOW + timedelta(minutes=45),
        idempotency_key="support-standard-1",
        now=NOW + timedelta(seconds=1),
    )
    assert grant.status == "pending_customer_approval"

    customer = TenantSupportActor(
        actor_id=customer_id,
        tenant_id=tenant_id,
        security_version=1,
    )
    with pytest.raises(PlatformSecurityError) as stale_customer:
        service.decide_customer_approval(
            TenantSupportActor(
                actor_id=customer_id,
                tenant_id=tenant_id,
                security_version=2,
            ),
            grant_id=grant.grant_id,
            expected_version=1,
            decision="approve",
            reason="stale browser session must not authorize support",
            reauthenticated_at=NOW,
            idempotency_key="customer-stale-session-1",
            now=NOW + timedelta(seconds=2),
        )
    assert stale_customer.value.code == "support_customer_permission_denied"
    grant = service.decide_customer_approval(
        customer,
        grant_id=grant.grant_id,
        expected_version=1,
        decision="approve",
        reason="tenant owner authorizes exact project diagnostics",
        reauthenticated_at=NOW,
        idempotency_key="customer-approve-1",
        now=NOW + timedelta(seconds=2),
    )
    assert grant.status == "pending_staff_approval"

    with pytest.raises(PlatformSecurityError, match="cannot approve"):
        service.decide_staff_approval(
            actors["support"],
            grant_id=grant.grant_id,
            expected_version=2,
            decision="approve",
            reason="self approval must fail",
            idempotency_key="staff-self-approve-1",
            now=NOW + timedelta(seconds=3),
        )

    grant = service.decide_staff_approval(
        actors["operator"],
        grant_id=grant.grant_id,
        expected_version=2,
        decision="approve",
        reason="independent operator approval",
        idempotency_key="staff-approve-1",
        now=NOW + timedelta(seconds=3),
    )
    assert grant.status == "active"
    issued = service.issue_support_session(
        actors["support"],
        grant_id=grant.grant_id,
        expected_version=3,
        idempotency_key="support-session-1",
        now=NOW + timedelta(seconds=4),
    )
    validated = service.validate_support_session(
        issued.token,
        tenant_id=tenant_id,
        required_scope="project.content.read",
        project_id=project_id,
        now=NOW + timedelta(seconds=5),
    )
    assert validated.grant_id == grant.grant_id
    with pytest.raises(PlatformSecurityError) as wrong_project:
        service.validate_support_session(
            issued.token,
            tenant_id=tenant_id,
            required_scope="project.content.read",
            project_id=uuid4(),
            now=NOW + timedelta(seconds=6),
        )
    assert wrong_project.value.code == "support_project_denied"

    revoked = service.revoke_support_grant_by_customer(
        customer,
        grant_id=grant.grant_id,
        expected_version=3,
        reason="incident investigation complete",
        reauthenticated_at=NOW,
        idempotency_key="customer-revoke-1",
        now=NOW + timedelta(seconds=7),
    )
    assert revoked.status == "revoked"
    with pytest.raises(PlatformSecurityError) as revoked_session:
        service.validate_support_session(
            issued.token,
            tenant_id=tenant_id,
            required_scope="project.content.read",
            project_id=project_id,
            now=NOW + timedelta(seconds=8),
        )
    assert revoked_session.value.code == "support_session_invalid"
    assert service.verify_audit_chain() is True


def test_break_glass_is_short_lived_and_audit_export_is_two_person_signed(
    governed: GovernedFixture,
) -> None:
    factory, service, actors, tenant_id, _customer_id = governed
    with pytest.raises(PlatformSecurityError) as long_break_glass:
        service.request_support_grant(
            actors["support"],
            tenant_id=tenant_id,
            mode="break_glass",
            scopes=("runtime.diagnostics.read",),
            project_ids=(),
            reason="restore service during declared incident",
            incident_ref="INC-2026-0808",
            expires_at=NOW + timedelta(minutes=16),
            idempotency_key="break-glass-too-long",
            now=NOW,
        )
    assert long_break_glass.value.code == "support_expiry_invalid"

    grant = service.request_support_grant(
        actors["support"],
        tenant_id=tenant_id,
        mode="break_glass",
        scopes=("runtime.diagnostics.read",),
        project_ids=(),
        reason="restore service during declared incident",
        incident_ref="INC-2026-0808",
        expires_at=NOW + timedelta(minutes=15),
        idempotency_key="break-glass-1",
        now=NOW,
    )
    assert grant.status == "pending_staff_approval"
    approved = service.decide_staff_approval(
        actors["operator"],
        grant_id=grant.grant_id,
        expected_version=1,
        decision="approve",
        reason="incident commander confirms break-glass",
        idempotency_key="break-glass-approve-1",
        now=NOW + timedelta(seconds=1),
    )
    assert approved.status == "active"

    export_request = service.request_audit_export(
        actors["auditor"],
        tenant_id=tenant_id,
        from_sequence=1,
        to_sequence=2,
        reason="produce incident evidence package",
        idempotency_key="audit-export-1",
        now=NOW + timedelta(seconds=2),
    )
    with pytest.raises(PlatformSecurityError, match="cannot approve"):
        service.approve_audit_export(
            actors["auditor"],
            operation_id=export_request.operation_id,
            expected_version=1,
            approval_reason="self approval must fail",
            now=NOW + timedelta(seconds=3),
        )
    signed = service.approve_audit_export(
        actors["operator"],
        operation_id=export_request.operation_id,
        expected_version=1,
        approval_reason="independent audit export approval",
        now=NOW + timedelta(seconds=3),
    )
    assert signed.manifest["event_count"] == 2
    assert signed.manifest["proof_event_count"] == 2
    assert service.verify_signed_export(signed) is True
    assert service.verify_audit_chain() is True

    revoked = service.revoke_support_grant(
        actors["operator"],
        grant_id=approved.grant_id,
        expected_version=2,
        reason="incident commander closes break-glass access",
        idempotency_key="break-glass-revoke-1",
        now=NOW + timedelta(seconds=4),
    )
    assert revoked.status == "revoked"

    with factory.begin() as db:
        persisted = db.get(PlatformAuditExportRecord, signed.export_id)
        assert persisted is not None
        assert persisted.content_hash == signed.content_hash
