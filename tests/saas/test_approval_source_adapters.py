from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.compatibility import RequestContext
from saas.control_plane.approval_operations import (
    ApprovalActor,
    ApprovalAuthorityAdapter,
    ApprovalOperationsError,
    ApprovalOperationsService,
    ApprovalProjectionService,
    ApprovalSecretDigester,
)
from saas.control_plane.approval_source_adapters import (
    AuditExportApprovalSource,
    EnterpriseApprovalSource,
    PrivacyApprovalSource,
    SourceApprovalAudienceRouter,
    SupportApprovalSource,
    production_approval_scheduler_source_factory,
)
from saas.control_plane.approval_source_projection import (
    SourceApprovalProjectionBridge,
    SourceApprovalProjectionSpec,
)
from saas.control_plane.db_models import (
    GlobalUser,
    SaasBase,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.enterprise_access import EnterpriseAccessService
from saas.control_plane.enterprise_models import EnterpriseAccessPreflightRecord
from saas.control_plane.notification_delivery import (
    NotificationDeliveryService,
    NotificationErrorDigester,
)
from saas.control_plane.notification_models import ApprovalWorkItemRecord
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_governed_access import (
    AuditSigningKey,
    PlatformGovernedAccessService,
)
from saas.control_plane.platform_governed_models import PlatformAuditEventRecord
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
    PlatformTenantProjectionRecord,
)
from saas.control_plane.platform_security import (
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.privacy_lifecycle import DeletionEvidenceKey, PrivacyLifecycleService
from saas.control_plane.privacy_operations import PrivacyLocatorKey, PrivacyOperationService

NOW = datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class _Ids:
    tenant: UUID
    space: UUID
    enterprise_requester: UUID
    tenant_approver: UUID
    privacy_target: UUID
    staff_requester: UUID
    staff_approver: UUID


@dataclass(frozen=True, slots=True)
class _Runtime:
    sessions: sessionmaker[Session]
    ids: _Ids
    bridge: SourceApprovalProjectionBridge
    enterprise: EnterpriseAccessService
    governed: PlatformGovernedAccessService
    privacy: PrivacyOperationService
    lifecycle: PrivacyLifecycleService
    enterprise_source: EnterpriseApprovalSource
    support_source: SupportApprovalSource
    privacy_source: PrivacyApprovalSource
    audit_source: AuditExportApprovalSource
    operations: ApprovalOperationsService
    staff_requester: ValidatedPlatformPrincipal
    staff_approver: ValidatedPlatformPrincipal


def _staff_actor(value: ValidatedPlatformPrincipal) -> ApprovalActor:
    return ApprovalActor(
        realm="staff",
        actor_id=value.principal_id,
        tenant_id=None,
        security_version=value.security_version,
        authenticated_at=value.authenticated_at,
        expires_at=value.expires_at,
        permissions=value.permissions,
    )


def _tenant_actor(ids: _Ids, actor_id: UUID) -> ApprovalActor:
    return ApprovalActor(
        realm="tenant",
        actor_id=actor_id,
        tenant_id=ids.tenant,
        security_version=1,
        authenticated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _tenant_context(ids: _Ids, actor_id: UUID, trace: str) -> RequestContext:
    return RequestContext(
        actor_id=actor_id,
        tenant_id=ids.tenant,
        space_id=ids.space,
        project_id=None,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id=trace,
    )


def _principal(principal_id: UUID, roles: tuple[str, ...]) -> ValidatedPlatformPrincipal:
    return ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=principal_id,
        security_version=1,
        authn_method="passkey",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        roles=frozenset(roles),
        permissions=frozenset(
            permission for role in roles for permission in PLATFORM_ROLE_PERMISSIONS[role]
        ),
    )


@pytest.fixture
def runtime() -> _Runtime:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    ids = _Ids(*(uuid4() for _ in range(7)))
    requester_roles = (
        "support_agent",
        "compliance_operator",
        "platform_security_auditor",
    )
    approver_roles = ("platform_operator",)
    with sessions.begin() as db:
        db.add_all(
            GlobalUser(id=value, status="active", security_version=1)
            for value in (
                ids.enterprise_requester,
                ids.tenant_approver,
                ids.privacy_target,
            )
        )
        db.add(
            Tenant(
                id=ids.tenant,
                slug=f"source-{ids.tenant.hex}",
                name="Source Authority Tenant",
                status="active",
                plan="enterprise",
                home_region="cn-east-1",
                lifecycle_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=ids.tenant,
                    user_id=ids.enterprise_requester,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
                TenantMembership(
                    tenant_id=ids.tenant,
                    user_id=ids.tenant_approver,
                    role="admin",
                    status="active",
                    version=1,
                    joined_at=NOW,
                ),
            ]
        )
        db.add(
            Space(
                id=ids.space,
                tenant_id=ids.tenant,
                slug="source-operations",
                name="Source Operations",
                status="active",
            )
        )
        db.flush()
        db.add_all(
            SpaceMembership(
                tenant_id=ids.tenant,
                space_id=ids.space,
                user_id=user_id,
                role="owner",
                status="active",
                version=1,
            )
            for user_id in (ids.enterprise_requester, ids.tenant_approver)
        )
        db.add(
            PlatformTenantProjectionRecord(
                tenant_id=ids.tenant,
                slug=f"source-{ids.tenant.hex}",
                name="Source Authority Tenant",
                status="active",
                plan="enterprise",
                home_region="cn-east-1",
                member_count=2,
                space_count=1,
                source_version=1,
                updated_at=NOW,
            )
        )
        for principal_id, subject in (
            (ids.staff_requester, "requester"),
            (ids.staff_approver, "approver"),
        ):
            db.add(
                PlatformStaffPrincipalRecord(
                    id=principal_id,
                    identity_connection_ref=f"source:{subject}",
                    issuer="https://staff-idp.example.test",
                    subject=f"source-{subject}",
                    status="active",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
        db.flush()
        for principal_id, roles in (
            (ids.staff_requester, requester_roles),
            (ids.staff_approver, approver_roles),
        ):
            for role in roles:
                db.add(
                    PlatformRoleAssignmentRecord(
                        id=uuid4(),
                        principal_id=principal_id,
                        role=role,
                        status="active",
                        version=1,
                        assigned_by_principal_id=ids.staff_approver,
                        approval_ref=f"source-bootstrap:{principal_id}:{role}",
                        reason="source adapter acceptance",
                        created_at=NOW,
                        updated_at=NOW,
                    )
                )
    projection = ApprovalProjectionService()
    digester = ApprovalSecretDigester("source-hmac-v1", b"s" * 32)
    bridge = SourceApprovalProjectionBridge(projection, digester)
    enterprise = EnterpriseAccessService(sessions, approval_projection=bridge)
    governed = PlatformGovernedAccessService(
        sessions,
        signing_key=AuditSigningKey("audit-signing-v1", b"a" * 32),
        approval_projection=bridge,
    )
    lifecycle = PrivacyLifecycleService(
        sessions,
        evidence_verifier=DeletionEvidenceKey("privacy-evidence-v1", b"e" * 32),
    )
    privacy = PrivacyOperationService(
        sessions,
        lifecycle=lifecycle,
        locator_key=PrivacyLocatorKey("privacy-locator-v1", b"l" * 32),
        approval_projection=bridge,
    )
    enterprise_source = EnterpriseApprovalSource(sessions, service=enterprise, bridge=bridge)
    support_source = SupportApprovalSource(sessions, service=governed, bridge=bridge)
    privacy_source = PrivacyApprovalSource(sessions, service=privacy, bridge=bridge)
    audit_source = AuditExportApprovalSource(sessions, service=governed, bridge=bridge)
    adapters: dict[str, ApprovalAuthorityAdapter] = {
        "enterprise": enterprise_source,
        "support.customer": support_source,
        "support.staff": support_source,
        "privacy": privacy_source,
        "audit": audit_source,
    }
    operations = ApprovalOperationsService(
        sessions,
        projection=projection,
        adapters=adapters,
        digester=digester,
    )
    return _Runtime(
        sessions=sessions,
        ids=ids,
        bridge=bridge,
        enterprise=enterprise,
        governed=governed,
        privacy=privacy,
        lifecycle=lifecycle,
        enterprise_source=enterprise_source,
        support_source=support_source,
        privacy_source=privacy_source,
        audit_source=audit_source,
        operations=operations,
        staff_requester=_principal(ids.staff_requester, requester_roles),
        staff_approver=_principal(ids.staff_approver, approver_roles),
    )


def _work(runtime: _Runtime, operation_kind: str) -> ApprovalWorkItemRecord:
    with runtime.sessions.begin() as db:
        return db.execute(
            sa.select(ApprovalWorkItemRecord).where(
                ApprovalWorkItemRecord.operation_kind == operation_kind
            )
        ).scalar_one()


def test_four_sources_project_and_decide_through_real_authorities(runtime: _Runtime) -> None:
    ids = runtime.ids
    enterprise_requester = _tenant_context(ids, ids.enterprise_requester, "enterprise-request")
    group = runtime.enterprise.create_group(
        enterprise_requester,
        name="Source Adapter Group",
        description=None,
        idempotency_key="source-group",
    )
    preflight = runtime.enterprise.create_group_archive_preflight(
        enterprise_requester,
        group_id=group.id,
        expected_version=group.version,
        reason="prove source-owned enterprise approval",
        reauthenticated_at=NOW,
        idempotency_key="source-enterprise-request",
        now=NOW + timedelta(seconds=1),
    )
    enterprise_work = _work(runtime, "enterprise")
    assert enterprise_work.id == preflight.preflight_id
    enterprise_inbox = runtime.operations.list_work_items(
        _tenant_actor(ids, ids.tenant_approver),
        status="pending",
        now=NOW + timedelta(seconds=2),
    ).items
    assert enterprise_work.id in {value.id for value in enterprise_inbox}
    exact_work = next(value for value in enterprise_inbox if value.id == enterprise_work.id)
    with pytest.raises(ApprovalOperationsError) as wrong_scope:
        runtime.enterprise_source.authorize_work_item(
            _tenant_actor(ids, ids.tenant_approver),
            replace(exact_work, tenant_id=uuid4()),
            now=NOW + timedelta(seconds=2),
        )
    assert wrong_scope.value.code == "approval_authority_scope_denied"
    enterprise_result = runtime.operations.decide(
        _tenant_actor(ids, ids.tenant_approver),
        work_item_id=enterprise_work.id,
        expected_version=enterprise_work.version,
        decision="approve",
        decision_code="enterprise_source_approved",
        decision_reason="independent Tenant administrator confirms impact",
        idempotency_key="source-enterprise-decision",
        now=NOW + timedelta(seconds=2),
    )
    assert enterprise_result.status == "approved"

    grant = runtime.governed.request_support_grant(
        runtime.staff_requester,
        tenant_id=ids.tenant,
        mode="standard",
        scopes=("tenant.metadata.read",),
        project_ids=(),
        reason="diagnose a Tenant metadata incident",
        incident_ref=None,
        expires_at=NOW + timedelta(minutes=45),
        idempotency_key="source-support-request",
        now=NOW + timedelta(seconds=3),
    )
    customer_work = _work(runtime, "support.customer")
    assert customer_work.id in {
        value.id
        for value in runtime.operations.list_work_items(
            _tenant_actor(ids, ids.tenant_approver),
            status="pending",
            now=NOW + timedelta(seconds=4),
        ).items
    }
    customer_result = runtime.operations.decide(
        _tenant_actor(ids, ids.tenant_approver),
        work_item_id=customer_work.id,
        expected_version=customer_work.version,
        decision="approve",
        decision_code="support_customer_approved",
        decision_reason="Tenant administrator authorizes exact support scope",
        idempotency_key="source-support-customer",
        now=NOW + timedelta(seconds=4),
    )
    assert customer_result.status == "approved"
    staff_work = _work(runtime, "support.staff")
    assert staff_work.id in {
        value.id
        for value in runtime.operations.list_work_items(
            _staff_actor(runtime.staff_approver),
            status="pending",
            now=NOW + timedelta(seconds=5),
        ).items
    }
    staff_result = runtime.operations.decide(
        _staff_actor(runtime.staff_approver),
        work_item_id=staff_work.id,
        expected_version=staff_work.version,
        decision="approve",
        decision_code="support_staff_approved",
        decision_reason="independent Staff operator confirms the grant",
        idempotency_key="source-support-staff",
        now=NOW + timedelta(seconds=5),
    )
    assert staff_result.status == "approved"
    assert grant.grant_id == staff_work.operation_id

    preview = runtime.lifecycle.preview_deletion(
        runtime.staff_requester,
        target_type="global_user",
        target_id=ids.privacy_target,
        now=NOW + timedelta(seconds=6),
    )
    privacy_request = runtime.privacy.request_deletion_start(
        runtime.staff_requester,
        target_type="global_user",
        target_id=ids.privacy_target,
        expected_target_version=preview.target_version,
        preview_hash=preview.preview_hash,
        reason_code="data_subject_request",
        case_reference="source-adapter-case",
        expires_at=NOW + timedelta(minutes=20),
        idempotency_key="source-privacy-request",
        now=NOW + timedelta(seconds=7),
    )
    privacy_work = _work(runtime, "privacy")
    assert privacy_work.id == privacy_request.operation_id
    assert privacy_work.id in {
        value.id
        for value in runtime.operations.list_work_items(
            _staff_actor(runtime.staff_approver),
            status="pending",
            now=NOW + timedelta(seconds=8),
        ).items
    }
    privacy_result = runtime.operations.decide(
        _staff_actor(runtime.staff_approver),
        work_item_id=privacy_work.id,
        expected_version=privacy_work.version,
        decision="reject",
        decision_code="scope_rejected",
        decision_reason="scope requires correction before execution",
        idempotency_key="source-privacy-decision",
        now=NOW + timedelta(seconds=8),
    )
    assert privacy_result.status == "rejected"

    with runtime.sessions.begin() as db:
        last_sequence = db.scalar(sa.select(sa.func.max(PlatformAuditEventRecord.sequence_no)))
    assert isinstance(last_sequence, int) and last_sequence > 0
    audit_request = runtime.governed.request_audit_export(
        runtime.staff_requester,
        tenant_id=ids.tenant,
        from_sequence=1,
        to_sequence=last_sequence,
        reason="export exact source-adapter audit proof",
        idempotency_key="source-audit-request",
        now=NOW + timedelta(seconds=9),
    )
    audit_work = _work(runtime, "audit")
    assert audit_work.id == audit_request.operation_id
    assert audit_work.id in {
        value.id
        for value in runtime.operations.list_work_items(
            _staff_actor(runtime.staff_approver),
            status="pending",
            now=NOW + timedelta(seconds=10),
        ).items
    }
    audit_result = runtime.operations.decide(
        _staff_actor(runtime.staff_approver),
        work_item_id=audit_work.id,
        expected_version=audit_work.version,
        decision="approve",
        decision_code="audit_export_approved",
        decision_reason="independent Staff operator authorizes the signed export",
        idempotency_key="source-audit-decision",
        now=NOW + timedelta(seconds=10),
    )
    assert audit_result.status == "approved"

    with runtime.sessions.begin() as db:
        source = db.get(EnterpriseAccessPreflightRecord, preflight.preflight_id)
        assert source is not None and source.status == "approved"


def test_all_source_reconcilers_restore_legacy_terminal_projections(runtime: _Runtime) -> None:
    test_four_sources_project_and_decide_through_real_authorities(runtime)
    with runtime.sessions.begin() as db:
        db.execute(sa.delete(ApprovalWorkItemRecord))
    results = (
        runtime.enterprise_source.reconcile(
            runtime.bridge.projection, now=NOW + timedelta(minutes=1), limit=100
        ),
        runtime.support_source.reconcile(
            runtime.bridge.projection, now=NOW + timedelta(minutes=1), limit=100
        ),
        runtime.privacy_source.reconcile(
            runtime.bridge.projection, now=NOW + timedelta(minutes=1), limit=100
        ),
        runtime.audit_source.reconcile(
            runtime.bridge.projection, now=NOW + timedelta(minutes=1), limit=100
        ),
    )
    assert sum(value.projected for value in results) == 5
    assert sum(value.terminal_synced for value in results) == 5
    with runtime.sessions.begin() as db:
        statuses: dict[str, str] = {}
        for operation_kind, status in db.execute(
            sa.select(
                ApprovalWorkItemRecord.operation_kind,
                ApprovalWorkItemRecord.status,
            )
        ).all():
            statuses[operation_kind] = status
    assert statuses == {
        "enterprise": "approved",
        "support.customer": "approved",
        "support.staff": "approved",
        "privacy": "rejected",
        "audit": "approved",
    }


class _FailingNotifier:
    def enqueue_requested_in_transaction(
        self, _db: Session, _work_item: object, *, now: datetime
    ) -> None:
        _ = now
        raise RuntimeError("notification authority unavailable")

    def enqueue_terminal_in_transaction(
        self, _db: Session, _work_item: object, *, now: datetime
    ) -> None:
        _ = now
        raise RuntimeError("notification authority unavailable")


def test_source_transaction_rolls_back_projection_and_source_when_notification_fails(
    runtime: _Runtime,
) -> None:
    failing_bridge = SourceApprovalProjectionBridge(
        runtime.bridge.projection,
        ApprovalSecretDigester("source-hmac-v1", b"s" * 32),
        notifier=_FailingNotifier(),  # type: ignore[arg-type]
        production_mode=True,
    )
    enterprise = EnterpriseAccessService(
        runtime.sessions,
        approval_projection=failing_bridge,
    )
    requester = _tenant_context(
        runtime.ids,
        runtime.ids.enterprise_requester,
        "rollback-requester",
    )
    group = enterprise.create_group(
        requester,
        name="Rollback Group",
        description=None,
        idempotency_key="rollback-group",
    )
    with runtime.sessions.begin() as db:
        before_sources = db.scalar(sa.select(sa.func.count(EnterpriseAccessPreflightRecord.id)))
        before_projections = db.scalar(sa.select(sa.func.count(ApprovalWorkItemRecord.id)))
    with pytest.raises(RuntimeError, match="notification authority unavailable"):
        enterprise.create_group_archive_preflight(
            requester,
            group_id=group.id,
            expected_version=group.version,
            reason="the whole source transaction must roll back",
            reauthenticated_at=NOW,
            idempotency_key="rollback-preflight",
            now=NOW + timedelta(seconds=1),
        )
    with runtime.sessions.begin() as db:
        assert (
            db.scalar(sa.select(sa.func.count(EnterpriseAccessPreflightRecord.id)))
            == before_sources
        )
        assert db.scalar(sa.select(sa.func.count(ApprovalWorkItemRecord.id))) == before_projections


def test_projection_configuration_is_fail_closed_and_repr_is_content_blind() -> None:
    projection = ApprovalProjectionService()
    digester = ApprovalSecretDigester("safe-repr-v1", b"r" * 32)
    with pytest.raises(ValueError, match="requires a real notifier"):
        SourceApprovalProjectionBridge(
            projection,
            digester,
            production_mode=True,
        )
    router = SourceApprovalAudienceRouter()
    with pytest.raises(ValueError, match="router is incomplete"):
        router.require_complete()
    target_id, requester_id, operation_id = uuid4(), uuid4(), uuid4()
    spec = SourceApprovalProjectionSpec(
        authority="enterprise",
        work_item_id=uuid4(),
        source_subject_id=None,
        realm="tenant",
        tenant_id=uuid4(),
        requester_realm="tenant",
        requester_id=requester_id,
        operation_kind="enterprise",
        operation_id=operation_id,
        action="enterprise.group_archive",
        target_type="enterprise_group",
        target_id=target_id,
        required_permission="group.manage",
        risk_level="high",
        snapshot_hash="a" * 64,
        due_at=NOW + timedelta(minutes=15),
        escalation_at=NOW + timedelta(minutes=5),
    )
    rendered = repr(spec)
    assert str(target_id) not in rendered
    assert str(requester_id) not in rendered
    assert str(operation_id) not in rendered


def test_production_scheduler_factory_requires_five_sources_and_builds_stage_scoped_support(
    runtime: _Runtime,
) -> None:
    notifications = NotificationDeliveryService(
        runtime.sessions,
        digester=NotificationErrorDigester("notification-test-v1", b"n" * 32),
    )
    context = SimpleNamespace(
        source_sessions={
            "enterprise": runtime.sessions,
            "privacy": runtime.sessions,
            "audit": runtime.sessions,
            "support.customer": runtime.sessions,
            "support.staff": runtime.sessions,
        },
        projection=ApprovalProjectionService(),
        notifications=notifications,
        configuration={
            "approval_hmac_key_id": "approval-production-v1",
            "approval_hmac_secret_b64": base64.b64encode(b"p" * 32).decode(),
        },
    )
    sources = production_approval_scheduler_source_factory(context)
    assert set(sources) == {
        "enterprise",
        "privacy",
        "audit",
        "support.customer",
        "support.staff",
    }
    customer = sources["support.customer"]
    staff = sources["support.staff"]
    assert isinstance(customer, SupportApprovalSource)
    assert isinstance(staff, SupportApprovalSource)
    assert customer.is_scoped_to_operation_kind("support.customer")
    assert staff.is_scoped_to_operation_kind("support.staff")
    assert customer is not staff

    context.configuration = {}
    with pytest.raises(RuntimeError, match="key configuration is incomplete"):
        production_approval_scheduler_source_factory(context)


def test_audit_source_expiry_is_derived_and_late_approval_is_rejected(
    runtime: _Runtime,
) -> None:
    runtime.governed.request_support_grant(
        runtime.staff_requester,
        tenant_id=runtime.ids.tenant,
        mode="break_glass",
        scopes=("tenant.metadata.read",),
        project_ids=(),
        reason="seed an immutable audit event",
        incident_ref="INC-SOURCE-EXPIRY",
        expires_at=NOW + timedelta(minutes=10),
        idempotency_key="expiry-audit-seed",
        now=NOW,
    )
    request = runtime.governed.request_audit_export(
        runtime.staff_requester,
        tenant_id=runtime.ids.tenant,
        from_sequence=1,
        to_sequence=1,
        reason="approval deadline must be source-owned",
        idempotency_key="expiry-audit-request",
        now=NOW + timedelta(seconds=1),
    )
    result = runtime.audit_source.reconcile(
        runtime.bridge.projection,
        now=NOW + timedelta(hours=25),
        limit=100,
    )
    assert result.terminal_synced == 1
    with runtime.sessions.begin() as db:
        work = db.get(ApprovalWorkItemRecord, request.operation_id)
        assert work is not None and work.status == "expired"
    late_actor = replace(
        runtime.staff_approver,
        authenticated_at=NOW + timedelta(hours=25),
        expires_at=NOW + timedelta(hours=26),
    )
    with pytest.raises(PlatformSecurityError) as late:
        runtime.governed.approve_audit_export(
            late_actor,
            operation_id=request.operation_id,
            expected_version=1,
            approval_reason="must remain expired",
            now=NOW + timedelta(hours=25),
        )
    assert late.value.code == "audit_export_approval_expired"
