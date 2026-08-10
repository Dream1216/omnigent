"""Adapters that keep four existing approval authorities authoritative.

The unified inbox is a content-blind projection only.  Every authorization and
decision below re-reads the exact source row, re-evaluates current identity and
scope, and invokes the existing source service.  Reconciliation repairs rows
created before the projection migration and derives expiry from source-owned
deadlines.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, NoReturn, Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid5

import sqlalchemy as sa
from sqlalchemy.orm import Session, load_only, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.approval_operations import (
    ApprovalActor,
    ApprovalAuthorityAdapter,
    ApprovalOperationsError,
    ApprovalProjectionService,
    ApprovalSecretDigester,
    ApprovalWorkItemView,
    AuthorityDecisionCommand,
)
from saas.control_plane.approval_scheduler import (
    ApprovalReconcileResult,
    ApprovalSchedulerSource,
)
from saas.control_plane.approval_source_projection import (
    SourceApprovalProjectionBridge,
    SourceApprovalProjectionSpec,
    SourceApprovalRlsContext,
    apply_source_approval_rls_context,
)
from saas.control_plane.db_models import GlobalUser, SpaceMembership, TenantMembership
from saas.control_plane.enterprise_access import EnterpriseAccessService
from saas.control_plane.enterprise_models import EnterpriseAccessPreflightRecord
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.notification_delivery import NotificationDeliveryService
from saas.control_plane.notification_events import SourceApprovalNotificationService
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS, TENANT_ROLE_PERMISSIONS
from saas.control_plane.platform_governed_access import (
    PlatformGovernedAccessService,
    TenantSupportActor,
)
from saas.control_plane.platform_governed_models import (
    PlatformAdminOperationRecord,
    PlatformSupportGrantRecord,
)
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)
from saas.control_plane.platform_security import (
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.privacy_lifecycle import PrivacyLifecycleService
from saas.control_plane.privacy_models import PrivacyApprovalBindingRecord
from saas.control_plane.privacy_operations import PrivacyLocatorKey, PrivacyOperationService
from saas.control_plane.rls import (
    PlatformRlsContext,
    RlsContext,
    apply_platform_rls_context,
    apply_rls_context,
)

_AUDIT_APPROVAL_TTL = timedelta(hours=24)


class ApprovalSchedulerSourceFactoryContext(Protocol):
    """Narrow structural contract supplied by the isolated scheduler worker."""

    source_sessions: Mapping[str, sessionmaker[Session]]
    projection: ApprovalProjectionService
    notifications: NotificationDeliveryService
    configuration: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _DenyDeletionEvidenceVerifier:
    """Scheduler processes cannot verify or mint deletion evidence."""

    key_id: str = "approval-scheduler-disabled"

    def verify(self, content_hash: str, signature: str) -> bool:
        del content_hash, signature
        return False


class _DisabledPrivacyLocatorKey(PrivacyLocatorKey):
    """Fail closed if scheduler-only wiring reaches a locator-bearing operation."""

    def __init__(self) -> None:
        super().__init__("approval-scheduler-disabled", bytes(32))

    def hash(self, value: str) -> str:
        del value
        raise RuntimeError("approval scheduler cannot derive privacy locators")


class TransactionalApprovalSource(
    ApprovalAuthorityAdapter,
    ApprovalSchedulerSource,
    Protocol,
):
    """A source authority that can resolve notification recipients in-place."""

    def eligible_actor_ids_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]: ...

    def uses_projection_bridge(self, bridge: SourceApprovalProjectionBridge) -> bool: ...


class SourceApprovalAudienceRouter:
    """Late-bound audience router that closes the bridge/adapter composition cycle."""

    def __init__(self) -> None:
        self._sources: dict[str, TransactionalApprovalSource] = {}

    def register(self, operation_kind: str, source: TransactionalApprovalSource) -> None:
        if operation_kind in self._sources:
            raise ValueError(f"approval audience source already registered: {operation_kind}")
        self._sources[operation_kind] = source

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        source = self._sources.get(work_item.operation_kind)
        if source is None:
            raise ApprovalOperationsError("approval_authority_unavailable")
        return source.eligible_actor_ids(work_item, now=now, limit=limit)

    def eligible_actor_ids_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        """Resolve against the caller's transaction, including uncommitted source rows."""

        source = self._sources.get(work_item.operation_kind)
        if source is None:
            raise ApprovalOperationsError("approval_authority_unavailable")
        return source.eligible_actor_ids_in_transaction(
            db,
            work_item,
            now=now,
            limit=limit,
        )

    def require_complete(self) -> None:
        expected = {
            "enterprise",
            "support.customer",
            "support.staff",
            "privacy",
            "audit",
        }
        if set(self._sources) != expected:
            raise ValueError("production approval audience router is incomplete")


class EnterpriseApprovalSource:
    """Tenant Enterprise Access preflight authority and scheduler source."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        service: EnterpriseAccessService,
        bridge: SourceApprovalProjectionBridge,
    ) -> None:
        self._sessions = session_factory
        self._service = service
        self._bridge = bridge

    def uses_projection_bridge(self, bridge: SourceApprovalProjectionBridge) -> bool:
        return self._bridge is bridge and self._service._approval_projection is bridge

    def authorize(
        self,
        actor: ApprovalActor,
        *,
        permission: str,
        tenant_id: UUID | None,
        now: datetime,
    ) -> None:
        _utc(now)
        if actor.realm != "tenant" or tenant_id is None or actor.tenant_id != tenant_id:
            raise ApprovalOperationsError("approval_authority_scope_denied")
        with self._sessions.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor.actor_id, tenant_id=tenant_id))
            user, membership = _tenant_identity(db, actor.actor_id, tenant_id)
            if user.security_version != actor.security_version:
                raise ApprovalOperationsError("approval_actor_security_version_changed")
            if permission not in TENANT_ROLE_PERMISSIONS.get(membership.role, frozenset()):
                raise ApprovalOperationsError("approval_permission_denied")

    def authorize_work_item(
        self,
        actor: ApprovalActor,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None:
        _require_work_kind(work_item, "enterprise")
        if (
            actor.realm != "tenant"
            or work_item.realm != "tenant"
            or actor.tenant_id != work_item.tenant_id
        ):
            raise ApprovalOperationsError("approval_authority_scope_denied")
        try:
            with self._sessions.begin() as db:
                apply_rls_context(
                    db,
                    RlsContext(actor_id=actor.actor_id, tenant_id=work_item.tenant_id),
                )
                source = _enterprise_preflight(db, work_item.operation_id)
                if source.tenant_id != work_item.tenant_id:
                    raise ApprovalOperationsError("approval_source_binding_conflict")
                _require_source_snapshot(work_item, source.snapshot_hash)
                context = _enterprise_context(
                    db,
                    source,
                    actor.actor_id,
                    security_version=actor.security_version,
                )
                self._service._apply_context(db, context)
                self._service._require_preflight_permission(db, context, source)
                if source.status != "pending_approval" or _utc(source.expires_at) <= _utc(now):
                    raise ApprovalOperationsError("approval_source_not_pending")
        except (LifecycleError, PlatformSecurityError) as error:
            _raise_source(error)

    def authorize_identity(
        self,
        *,
        realm: str,
        actor_id: UUID,
        permission: str,
        tenant_id: UUID | None,
        operation_id: UUID,
        now: datetime,
    ) -> None:
        _utc(now)
        if realm != "tenant" or tenant_id is None:
            raise ApprovalOperationsError("approval_authority_scope_denied")
        try:
            with self._sessions.begin() as db:
                apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
                source = _enterprise_preflight(db, operation_id)
                expected_permission = (
                    "group.manage"
                    if source.operation_type == "group_archive"
                    else "custom_role.manage"
                )
                if permission != expected_permission:
                    raise ApprovalOperationsError("approval_permission_denied")
                context = _enterprise_context(db, source, actor_id)
                self._service._apply_context(db, context)
                self._service._require_preflight_permission(db, context, source)
        except (LifecycleError, PlatformSecurityError) as error:
            _raise_source(error)

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        with self._sessions.begin() as db:
            return self.eligible_actor_ids_in_transaction(
                db,
                work_item,
                now=now,
                limit=limit,
            )

    def eligible_actor_ids_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        _limit(limit)
        _utc(now)
        _require_work_kind(work_item, "enterprise")
        try:
            apply_source_approval_rls_context(
                db,
                SourceApprovalRlsContext(
                    source_kind="enterprise",
                    mutation="audience",
                    realm="tenant",
                    tenant_id=work_item.tenant_id,
                    operation_id=work_item.operation_id,
                    work_item_id=work_item.id,
                ),
            )
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=work_item.requester_id,
                    tenant_id=work_item.tenant_id,
                ),
            )
            source = _enterprise_scheduler_preflight(db, work_item.operation_id)
            candidates = tuple(
                db.execute(
                    sa.select(GlobalUser.id)
                    .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
                    .where(
                        TenantMembership.tenant_id == source.tenant_id,
                        TenantMembership.status == "active",
                        GlobalUser.status == "active",
                    )
                    .order_by(GlobalUser.id)
                    .limit(500)
                ).scalars()
            )
            eligible: list[UUID] = []
            for actor_id in candidates:
                try:
                    context = _enterprise_context(db, source, actor_id)
                    self._service._apply_context(db, context)
                    self._service._require_preflight_permission(
                        db,
                        context,
                        source,
                        persist_decisions=False,
                    )
                except LifecycleError:
                    continue
                eligible.append(actor_id)
                if len(eligible) >= limit:
                    break
            return tuple(eligible)
        except (LifecycleError, PlatformSecurityError) as error:
            _raise_source(error)

    def decide(
        self,
        actor: ApprovalActor,
        command: AuthorityDecisionCommand,
        *,
        projection: ApprovalProjectionService,
        now: datetime,
    ) -> None:
        _same_projection(self._bridge, projection)
        try:
            with self._sessions.begin() as db:
                apply_rls_context(
                    db,
                    RlsContext(actor_id=actor.actor_id, tenant_id=actor.tenant_id),
                )
                source = _enterprise_preflight(db, command.operation_id)
                if source.snapshot_hash != command.expected_snapshot_hash:
                    raise ApprovalOperationsError("approval_source_snapshot_changed")
                context = _enterprise_context(
                    db,
                    source,
                    actor.actor_id,
                    security_version=actor.security_version,
                    trace_id=f"approval-operation:{source.id}",
                )
            self._service.decide_enterprise_access_preflight(
                context,
                preflight_id=source.id,
                operation_type=source.operation_type,
                target_id=source.target_id,
                project_id=source.project_id,
                decision=command.decision,
                reason=command.decision_reason,
                reauthenticated_at=actor.authenticated_at,
                idempotency_key=command.idempotency_key,
                now=now,
                approval_projection_version=command.expected_projection_version,
                approval_decision_code=command.decision_code,
            )
        except (LifecycleError, PlatformSecurityError) as error:
            _raise_source(error)

    def reconcile(
        self,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
        limit: int,
    ) -> ApprovalReconcileResult:
        _same_projection(self._bridge, projection)
        _limit(limit, maximum=500)
        projected = terminal = 0
        with self._sessions.begin() as db:
            apply_source_approval_rls_context(
                db,
                SourceApprovalRlsContext(
                    source_kind="enterprise",
                    mutation="scan",
                    realm="tenant",
                ),
            )
            sources = tuple(
                db.execute(
                    sa.select(EnterpriseAccessPreflightRecord)
                    .options(
                        load_only(
                            EnterpriseAccessPreflightRecord.id,
                            EnterpriseAccessPreflightRecord.tenant_id,
                            EnterpriseAccessPreflightRecord.space_id,
                            EnterpriseAccessPreflightRecord.project_id,
                            EnterpriseAccessPreflightRecord.operation_type,
                            EnterpriseAccessPreflightRecord.target_id,
                            EnterpriseAccessPreflightRecord.requested_by,
                            EnterpriseAccessPreflightRecord.snapshot_hash,
                            EnterpriseAccessPreflightRecord.status,
                            EnterpriseAccessPreflightRecord.approved_by,
                            EnterpriseAccessPreflightRecord.approved_at,
                            EnterpriseAccessPreflightRecord.expires_at,
                            EnterpriseAccessPreflightRecord.created_at,
                        )
                    )
                    .order_by(EnterpriseAccessPreflightRecord.id)
                    .limit(limit)
                ).scalars()
            )
            for source in sources:
                spec = self._service._approval_spec(source, _utc(now))
                desired, code, decider, decided_at = _enterprise_terminal(source, now)
                created, settled = _reconcile_spec(
                    db,
                    self._bridge,
                    spec,
                    desired_status=desired,
                    decision_code=code,
                    decided_by_id=decider,
                    decided_at=decided_at,
                    now=now,
                )
                projected += created
                terminal += settled
        return ApprovalReconcileResult(projected=projected, terminal_synced=terminal)

    def expire(
        self,
        work_item: ApprovalWorkItemView,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
    ) -> None:
        _same_projection(self._bridge, projection)
        with self._sessions.begin() as db:
            apply_source_approval_rls_context(
                db,
                SourceApprovalRlsContext(
                    source_kind="enterprise",
                    mutation="terminal",
                    realm="tenant",
                    tenant_id=work_item.tenant_id,
                    operation_id=work_item.operation_id,
                    work_item_id=work_item.id,
                ),
            )
            source = _enterprise_scheduler_preflight(db, work_item.operation_id)
            if source.status != "pending_approval" or _utc(source.expires_at) > _utc(now):
                raise ApprovalOperationsError("approval_source_not_expired")
            self._bridge.terminal_in_transaction(
                db,
                self._service._approval_spec(source, _utc(now)),
                status="expired",
                decision_code="source_expired",
                decided_by_id=None,
                decided_at=_utc(now),
                expected_projection_version=work_item.version,
            )


class SupportApprovalSource:
    """Cross-Realm Support authority: Staff request, Tenant gate, Staff gate."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        service: PlatformGovernedAccessService,
        bridge: SourceApprovalProjectionBridge,
        operation_kind: Literal["support.customer", "support.staff"] | None = None,
    ) -> None:
        if operation_kind not in {None, "support.customer", "support.staff"}:
            raise ValueError("support approval source operation kind is invalid")
        self._sessions = session_factory
        self._service = service
        self._bridge = bridge
        self._operation_kind = operation_kind

    def uses_projection_bridge(self, bridge: SourceApprovalProjectionBridge) -> bool:
        return self._bridge is bridge and self._service._approval_projection is bridge

    def supports_operation_kind(self, operation_kind: str) -> bool:
        return self._operation_kind is None or self._operation_kind == operation_kind

    def is_scoped_to_operation_kind(self, operation_kind: str) -> bool:
        return self._operation_kind == operation_kind

    def authorize(
        self,
        actor: ApprovalActor,
        *,
        permission: str,
        tenant_id: UUID | None,
        now: datetime,
    ) -> None:
        expected = (
            "support.customer.approve"
            if actor.realm == "tenant"
            else "platform.support_grant.manage"
        )
        if permission != expected:
            raise ApprovalOperationsError("approval_permission_denied")
        if actor.realm == "tenant":
            if tenant_id is None or actor.tenant_id != tenant_id:
                raise ApprovalOperationsError("approval_authority_scope_denied")
            with self._sessions.begin() as db:
                apply_rls_context(db, RlsContext(actor_id=actor.actor_id, tenant_id=tenant_id))
                self._service._require_tenant_support_admin(
                    db,
                    TenantSupportActor(actor.actor_id, tenant_id, actor.security_version),
                )
            return
        self._authorize_staff(actor, "platform.support_grant.manage", now)

    def authorize_work_item(
        self,
        actor: ApprovalActor,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None:
        if work_item.operation_kind not in {"support.customer", "support.staff"}:
            raise ApprovalOperationsError("approval_source_binding_conflict")
        self._require_enabled_kind(work_item.operation_kind)
        try:
            with self._sessions.begin() as db:
                if actor.realm == "tenant":
                    if (
                        work_item.operation_kind != "support.customer"
                        or actor.tenant_id != work_item.tenant_id
                    ):
                        raise ApprovalOperationsError("approval_authority_scope_denied")
                    request = TenantSupportActor(
                        actor.actor_id,
                        actor.tenant_id,  # type: ignore[arg-type]
                        actor.security_version,
                    )
                    self._service._bind_customer(
                        db, request, support_grant_id=work_item.operation_id
                    )
                    self._service._require_tenant_support_admin(db, request)
                else:
                    principal = _staff_actor(actor)
                    self._service._bind_platform(
                        db, principal, support_grant_id=work_item.operation_id
                    )
                    self._service._authorize(
                        db, principal, "platform.support_grant.manage", _utc(now)
                    )
                grant, operation = _support_source(db, work_item.operation_id)
                if grant.tenant_id != work_item.tenant_id or work_item.realm != (
                    "tenant" if work_item.operation_kind == "support.customer" else "staff"
                ):
                    raise ApprovalOperationsError("approval_source_binding_conflict")
                _require_source_snapshot(work_item, operation.request_hash)
                if grant.status != (
                    "pending_customer_approval"
                    if work_item.operation_kind == "support.customer"
                    else "pending_staff_approval"
                ) or _utc(grant.expires_at) <= _utc(now):
                    raise ApprovalOperationsError("approval_source_not_pending")
        except (LifecycleError, PlatformSecurityError) as error:
            _raise_source(error)

    def authorize_identity(
        self,
        *,
        realm: str,
        actor_id: UUID,
        permission: str,
        tenant_id: UUID | None,
        operation_id: UUID,
        now: datetime,
    ) -> None:
        with self._sessions.begin() as db:
            grant, _ = _support_source(db, operation_id)
            expected = (
                "support.customer.approve"
                if realm == "tenant"
                else "platform.support_grant.manage"
            )
            if permission != expected:
                raise ApprovalOperationsError("approval_permission_denied")
            if realm == "tenant":
                if tenant_id != grant.tenant_id:
                    raise ApprovalOperationsError("approval_authority_scope_denied")
                user = db.get(GlobalUser, actor_id)
                if user is None:
                    raise ApprovalOperationsError("approval_identity_inactive")
                request = TenantSupportActor(actor_id, grant.tenant_id, user.security_version)
                self._service._require_tenant_support_admin(db, request)
                return
            principal = db.get(PlatformStaffPrincipalRecord, actor_id)
            if principal is None:
                raise ApprovalOperationsError("approval_identity_inactive")
            self._service._authorize(
                db,
                _synthetic_staff(principal, now),
                "platform.support_grant.manage",
                _utc(now),
            )

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        with self._sessions.begin() as db:
            return self.eligible_actor_ids_in_transaction(
                db,
                work_item,
                now=now,
                limit=limit,
            )

    def eligible_actor_ids_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        _limit(limit)
        self._require_enabled_kind(work_item.operation_kind)
        apply_source_approval_rls_context(
            db,
            SourceApprovalRlsContext(
                source_kind=work_item.operation_kind,
                mutation="audience",
                realm="tenant" if work_item.operation_kind == "support.customer" else "staff",
                tenant_id=work_item.tenant_id,
                operation_id=work_item.operation_id,
                subject_id=work_item.operation_id,
                work_item_id=work_item.id,
            ),
        )
        grant, operation = _support_scheduler_source(db, work_item.operation_id)
        if grant.tenant_id != work_item.tenant_id:
            raise ApprovalOperationsError("approval_source_binding_conflict")
        _require_source_snapshot(work_item, operation.request_hash)
        if _utc(grant.expires_at) <= _utc(now):
            raise ApprovalOperationsError("approval_source_not_pending")
        if work_item.operation_kind == "support.customer":
            if grant.status != "pending_customer_approval":
                raise ApprovalOperationsError("approval_source_not_pending")
            rows = db.execute(
                sa.select(GlobalUser.id, TenantMembership.role)
                .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
                .where(
                    TenantMembership.tenant_id == work_item.tenant_id,
                    TenantMembership.status == "active",
                    GlobalUser.status == "active",
                    TenantMembership.role.in_(tuple({"owner", "admin", "security_auditor"})),
                )
                .order_by(GlobalUser.id)
                .limit(limit)
            )
            return tuple(row.id for row in rows)
        if work_item.operation_kind != "support.staff":
            raise ApprovalOperationsError("approval_source_binding_conflict")
        if grant.status != "pending_staff_approval":
            raise ApprovalOperationsError("approval_source_not_pending")
        return _eligible_staff_in_transaction(
            db,
            "platform.support_grant.manage",
            now=now,
            limit=limit,
        )

    def decide(
        self,
        actor: ApprovalActor,
        command: AuthorityDecisionCommand,
        *,
        projection: ApprovalProjectionService,
        now: datetime,
    ) -> None:
        _same_projection(self._bridge, projection)
        try:
            with self._sessions.begin() as db:
                grant, operation = _support_source(db, command.operation_id)
                if operation.request_hash != command.expected_snapshot_hash:
                    raise ApprovalOperationsError("approval_source_snapshot_changed")
                source_version = grant.version
                stage = (
                    "customer"
                    if actor.realm == "tenant" and grant.status == "pending_customer_approval"
                    else "staff"
                )
            if stage == "customer":
                if actor.tenant_id != grant.tenant_id:
                    raise ApprovalOperationsError("approval_authority_scope_denied")
                self._service.decide_customer_approval(
                    TenantSupportActor(actor.actor_id, grant.tenant_id, actor.security_version),
                    grant_id=grant.id,
                    expected_version=source_version,
                    decision=command.decision,
                    reason=command.decision_reason,
                    reauthenticated_at=actor.authenticated_at,
                    idempotency_key=command.idempotency_key,
                    now=now,
                    approval_projection_version=command.expected_projection_version,
                    approval_decision_code=command.decision_code,
                )
                return
            if actor.realm != "staff" or grant.status != "pending_staff_approval":
                raise ApprovalOperationsError("approval_authority_scope_denied")
            self._service.decide_staff_approval(
                _staff_actor(actor),
                grant_id=grant.id,
                expected_version=source_version,
                decision=command.decision,
                reason=command.decision_reason,
                idempotency_key=command.idempotency_key,
                now=now,
                approval_projection_version=command.expected_projection_version,
                approval_decision_code=command.decision_code,
            )
        except (LifecycleError, PlatformSecurityError) as error:
            _raise_source(error)

    def reconcile(
        self,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
        limit: int,
    ) -> ApprovalReconcileResult:
        _same_projection(self._bridge, projection)
        _limit(limit, maximum=500)
        projected = terminal = 0
        with self._sessions.begin() as db:
            if self._operation_kind is not None:
                apply_source_approval_rls_context(
                    db,
                    SourceApprovalRlsContext(
                        source_kind=self._operation_kind,
                        mutation="scan",
                        realm=(
                            "tenant" if self._operation_kind == "support.customer" else "staff"
                        ),
                    ),
                )
            rows = tuple(
                db.execute(
                    sa.select(PlatformSupportGrantRecord, PlatformAdminOperationRecord)
                    .options(
                        load_only(
                            PlatformSupportGrantRecord.id,
                            PlatformSupportGrantRecord.operation_id,
                            PlatformSupportGrantRecord.tenant_id,
                            PlatformSupportGrantRecord.requested_by_principal_id,
                            PlatformSupportGrantRecord.mode,
                            PlatformSupportGrantRecord.status,
                            PlatformSupportGrantRecord.customer_approved_by_user_id,
                            PlatformSupportGrantRecord.customer_approved_at,
                            PlatformSupportGrantRecord.staff_approved_by_principal_id,
                            PlatformSupportGrantRecord.staff_approved_at,
                            PlatformSupportGrantRecord.requested_at,
                            PlatformSupportGrantRecord.expires_at,
                        ),
                        load_only(
                            PlatformAdminOperationRecord.id,
                            PlatformAdminOperationRecord.request_hash,
                            PlatformAdminOperationRecord.completed_at,
                        ),
                    )
                    .join(
                        PlatformAdminOperationRecord,
                        PlatformAdminOperationRecord.id == PlatformSupportGrantRecord.operation_id,
                    )
                    .order_by(PlatformSupportGrantRecord.id)
                    .limit(limit)
                ).all()
            )
            for grant, operation in rows:
                desired = _support_desired(grant, operation, now)
                for stage, status, code, decider, decided_at in desired:
                    if not self.supports_operation_kind(f"support.{stage}"):
                        continue
                    spec = self._service._support_approval_spec(
                        grant,
                        operation,
                        stage=cast(Literal["customer", "staff"], stage),
                        now=_utc(now),
                    )
                    created, settled = _reconcile_spec(
                        db,
                        self._bridge,
                        spec,
                        desired_status=status,
                        decision_code=code,
                        decided_by_id=decider,
                        decided_at=decided_at,
                        now=now,
                    )
                    projected += created
                    terminal += settled
        return ApprovalReconcileResult(projected=projected, terminal_synced=terminal)

    def expire(
        self,
        work_item: ApprovalWorkItemView,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
    ) -> None:
        _same_projection(self._bridge, projection)
        self._require_enabled_kind(work_item.operation_kind)
        with self._sessions.begin() as db:
            apply_source_approval_rls_context(
                db,
                SourceApprovalRlsContext(
                    source_kind=work_item.operation_kind,
                    mutation="terminal",
                    realm="tenant" if work_item.operation_kind == "support.customer" else "staff",
                    tenant_id=work_item.tenant_id,
                    operation_id=work_item.operation_id,
                    subject_id=work_item.operation_id,
                    work_item_id=work_item.id,
                ),
            )
            grant, operation = _support_scheduler_source(db, work_item.operation_id)
            if _utc(grant.expires_at) > _utc(now) or grant.status not in {
                "pending_customer_approval",
                "pending_staff_approval",
            }:
                raise ApprovalOperationsError("approval_source_not_expired")
            stage = "customer" if work_item.operation_kind == "support.customer" else "staff"
            self._bridge.terminal_in_transaction(
                db,
                self._service._support_approval_spec(grant, operation, stage=stage, now=_utc(now)),
                status="expired",
                decision_code="source_expired",
                decided_by_id=None,
                decided_at=_utc(now),
                expected_projection_version=work_item.version,
            )

    def _require_enabled_kind(self, operation_kind: str) -> None:
        if not self.supports_operation_kind(operation_kind):
            raise ApprovalOperationsError("approval_authority_scope_denied")

    def _authorize_staff(self, actor: ApprovalActor, permission: str, now: datetime) -> None:
        if actor.realm != "staff":
            raise ApprovalOperationsError("approval_authority_scope_denied")
        principal = _staff_actor(actor)
        try:
            with self._sessions.begin() as db:
                self._service._bind_platform(db, principal)
                self._service._authorize(db, principal, permission, _utc(now))
        except PlatformSecurityError as error:
            _raise_source(error)


class PrivacyApprovalSource:
    """Staff Privacy operation authority and reconciliation source."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        service: PrivacyOperationService,
        bridge: SourceApprovalProjectionBridge,
    ) -> None:
        self._sessions = session_factory
        self._service = service
        self._bridge = bridge

    def uses_projection_bridge(self, bridge: SourceApprovalProjectionBridge) -> bool:
        return self._bridge is bridge and self._service._approval_projection is bridge

    def authorize(
        self,
        actor: ApprovalActor,
        *,
        permission: str,
        tenant_id: UUID | None,
        now: datetime,
    ) -> None:
        if permission != "platform.data_request.approve":
            raise ApprovalOperationsError("approval_permission_denied")
        _ = tenant_id
        _authorize_staff_permission(
            self._sessions,
            actor,
            "platform.data_request.approve",
            now=now,
        )

    def authorize_work_item(
        self,
        actor: ApprovalActor,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None:
        _require_work_kind(work_item, "privacy")
        _authorize_staff_permission(
            self._sessions,
            actor,
            "platform.data_request.approve",
            now=now,
        )
        with self._sessions.begin() as db:
            operation, binding = _privacy_source(db, work_item.operation_id)
            if work_item.realm != "staff" or binding.tenant_id != work_item.tenant_id:
                raise ApprovalOperationsError("approval_source_binding_conflict")
            _require_source_snapshot(work_item, binding.snapshot_hash)
            if operation.status != "pending_staff_approval" or _utc(binding.expires_at) <= _utc(
                now
            ):
                raise ApprovalOperationsError("approval_source_not_pending")

    def authorize_identity(
        self,
        *,
        realm: str,
        actor_id: UUID,
        permission: str,
        tenant_id: UUID | None,
        operation_id: UUID,
        now: datetime,
    ) -> None:
        if realm != "staff":
            raise ApprovalOperationsError("approval_authority_scope_denied")
        if permission != "platform.data_request.approve":
            raise ApprovalOperationsError("approval_permission_denied")
        _ = tenant_id
        _authorize_staff_identity(
            self._sessions,
            actor_id,
            "platform.data_request.approve",
            now=now,
        )
        with self._sessions.begin() as db:
            _privacy_source(db, operation_id)

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        with self._sessions.begin() as db:
            return self.eligible_actor_ids_in_transaction(
                db,
                work_item,
                now=now,
                limit=limit,
            )

    def eligible_actor_ids_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        _require_work_kind(work_item, "privacy")
        apply_source_approval_rls_context(
            db,
            SourceApprovalRlsContext(
                source_kind="privacy",
                mutation="audience",
                realm="staff",
                tenant_id=work_item.tenant_id,
                operation_id=work_item.operation_id,
                work_item_id=work_item.id,
            ),
        )
        operation, binding = _privacy_scheduler_source(db, work_item.operation_id)
        if binding.tenant_id != work_item.tenant_id or work_item.realm != "staff":
            raise ApprovalOperationsError("approval_source_binding_conflict")
        _require_source_snapshot(work_item, binding.snapshot_hash)
        if operation.status != "pending_staff_approval" or _utc(binding.expires_at) <= _utc(now):
            raise ApprovalOperationsError("approval_source_not_pending")
        return _eligible_staff_in_transaction(
            db,
            "platform.data_request.approve",
            now=now,
            limit=limit,
        )

    def decide(
        self,
        actor: ApprovalActor,
        command: AuthorityDecisionCommand,
        *,
        projection: ApprovalProjectionService,
        now: datetime,
    ) -> None:
        _same_projection(self._bridge, projection)
        try:
            with self._sessions.begin() as db:
                operation, binding = _privacy_source(db, command.operation_id)
                if binding.snapshot_hash != command.expected_snapshot_hash:
                    raise ApprovalOperationsError("approval_source_snapshot_changed")
                source_version = operation.version
                target_type = binding.target_type
                target_id = binding.target_id
            self._service.decide(
                _staff_actor(actor),
                target_type=target_type,  # type: ignore[arg-type]
                target_id=target_id,
                operation_id=command.operation_id,
                expected_version=source_version,
                decision=command.decision,
                decision_code=command.decision_code,
                idempotency_key=command.idempotency_key,
                now=now,
                approval_projection_version=command.expected_projection_version,
            )
        except (LifecycleError, PlatformSecurityError) as error:
            _raise_source(error)

    def reconcile(
        self,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
        limit: int,
    ) -> ApprovalReconcileResult:
        _same_projection(self._bridge, projection)
        _limit(limit, maximum=500)
        projected = terminal = 0
        with self._sessions.begin() as db:
            apply_source_approval_rls_context(
                db,
                SourceApprovalRlsContext(
                    source_kind="privacy",
                    mutation="scan",
                    realm="staff",
                ),
            )
            rows = tuple(
                db.execute(
                    sa.select(PlatformAdminOperationRecord, PrivacyApprovalBindingRecord)
                    .options(
                        load_only(
                            PlatformAdminOperationRecord.id,
                            PlatformAdminOperationRecord.action,
                            PlatformAdminOperationRecord.tenant_id,
                            PlatformAdminOperationRecord.requested_by_principal_id,
                            PlatformAdminOperationRecord.approved_by_principal_id,
                            PlatformAdminOperationRecord.status,
                            PlatformAdminOperationRecord.error_code,
                            PlatformAdminOperationRecord.approved_at,
                            PlatformAdminOperationRecord.completed_at,
                        ),
                        load_only(
                            PrivacyApprovalBindingRecord.operation_id,
                            PrivacyApprovalBindingRecord.phase,
                            PrivacyApprovalBindingRecord.target_type,
                            PrivacyApprovalBindingRecord.target_id,
                            PrivacyApprovalBindingRecord.tenant_id,
                            PrivacyApprovalBindingRecord.snapshot_hash,
                            PrivacyApprovalBindingRecord.expires_at,
                            PrivacyApprovalBindingRecord.created_at,
                        ),
                    )
                    .join(
                        PrivacyApprovalBindingRecord,
                        PrivacyApprovalBindingRecord.operation_id
                        == PlatformAdminOperationRecord.id,
                    )
                    .order_by(PlatformAdminOperationRecord.id)
                    .limit(limit)
                ).all()
            )
            for operation, binding in rows:
                spec = self._service._approval_spec(operation, binding, _utc(now))
                desired, code, decider, decided_at = _privacy_terminal(operation, binding, now)
                created, settled = _reconcile_spec(
                    db,
                    self._bridge,
                    spec,
                    desired_status=desired,
                    decision_code=code,
                    decided_by_id=decider,
                    decided_at=decided_at,
                    now=now,
                )
                projected += created
                terminal += settled
        return ApprovalReconcileResult(projected=projected, terminal_synced=terminal)

    def expire(
        self,
        work_item: ApprovalWorkItemView,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
    ) -> None:
        _same_projection(self._bridge, projection)
        with self._sessions.begin() as db:
            apply_source_approval_rls_context(
                db,
                SourceApprovalRlsContext(
                    source_kind="privacy",
                    mutation="terminal",
                    realm="staff",
                    tenant_id=work_item.tenant_id,
                    operation_id=work_item.operation_id,
                    work_item_id=work_item.id,
                ),
            )
            operation, binding = _privacy_scheduler_source(db, work_item.operation_id)
            if operation.status != "pending_staff_approval" or _utc(binding.expires_at) > _utc(
                now
            ):
                raise ApprovalOperationsError("approval_source_not_expired")
            self._bridge.terminal_in_transaction(
                db,
                self._service._approval_spec(operation, binding, _utc(now)),
                status="expired",
                decision_code="approval_expired",
                decided_by_id=None,
                decided_at=_utc(now),
                expected_projection_version=work_item.version,
            )


class AuditExportApprovalSource:
    """Staff Audit Export authority, including explicit rejection and expiry."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        service: PlatformGovernedAccessService,
        bridge: SourceApprovalProjectionBridge,
    ) -> None:
        self._sessions = session_factory
        self._service = service
        self._bridge = bridge

    def uses_projection_bridge(self, bridge: SourceApprovalProjectionBridge) -> bool:
        return self._bridge is bridge and self._service._approval_projection is bridge

    def authorize(
        self,
        actor: ApprovalActor,
        *,
        permission: str,
        tenant_id: UUID | None,
        now: datetime,
    ) -> None:
        if permission != "platform.operation.approve":
            raise ApprovalOperationsError("approval_permission_denied")
        _ = tenant_id
        _authorize_staff_permission(self._sessions, actor, "platform.operation.approve", now=now)

    def authorize_work_item(
        self,
        actor: ApprovalActor,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None:
        _require_work_kind(work_item, "audit")
        _authorize_staff_permission(self._sessions, actor, "platform.operation.approve", now=now)
        with self._sessions.begin() as db:
            source = _audit_source(db, work_item.operation_id)
            if work_item.realm != "staff" or source.tenant_id != work_item.tenant_id:
                raise ApprovalOperationsError("approval_source_binding_conflict")
            _require_source_snapshot(work_item, source.request_hash)
            if source.status != "pending_staff_approval" or _utc(
                source.created_at
            ) + _AUDIT_APPROVAL_TTL <= _utc(now):
                raise ApprovalOperationsError("approval_source_not_pending")

    def authorize_identity(
        self,
        *,
        realm: str,
        actor_id: UUID,
        permission: str,
        tenant_id: UUID | None,
        operation_id: UUID,
        now: datetime,
    ) -> None:
        if realm != "staff":
            raise ApprovalOperationsError("approval_authority_scope_denied")
        if permission != "platform.operation.approve":
            raise ApprovalOperationsError("approval_permission_denied")
        _ = tenant_id
        _authorize_staff_identity(self._sessions, actor_id, "platform.operation.approve", now=now)
        with self._sessions.begin() as db:
            _audit_source(db, operation_id)

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        with self._sessions.begin() as db:
            return self.eligible_actor_ids_in_transaction(
                db,
                work_item,
                now=now,
                limit=limit,
            )

    def eligible_actor_ids_in_transaction(
        self,
        db: Session,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        _require_work_kind(work_item, "audit")
        apply_source_approval_rls_context(
            db,
            SourceApprovalRlsContext(
                source_kind="audit",
                mutation="audience",
                realm="staff",
                tenant_id=work_item.tenant_id,
                operation_id=work_item.operation_id,
                work_item_id=work_item.id,
            ),
        )
        source = _audit_scheduler_source(db, work_item.operation_id)
        if work_item.realm != "staff" or source.tenant_id != work_item.tenant_id:
            raise ApprovalOperationsError("approval_source_binding_conflict")
        _require_source_snapshot(work_item, source.request_hash)
        if source.status != "pending_staff_approval" or _utc(
            source.created_at
        ) + _AUDIT_APPROVAL_TTL <= _utc(now):
            raise ApprovalOperationsError("approval_source_not_pending")
        return _eligible_staff_in_transaction(
            db,
            "platform.operation.approve",
            now=now,
            limit=limit,
        )

    def decide(
        self,
        actor: ApprovalActor,
        command: AuthorityDecisionCommand,
        *,
        projection: ApprovalProjectionService,
        now: datetime,
    ) -> None:
        _same_projection(self._bridge, projection)
        try:
            with self._sessions.begin() as db:
                source = _audit_source(db, command.operation_id)
                if source.request_hash != command.expected_snapshot_hash:
                    raise ApprovalOperationsError("approval_source_snapshot_changed")
                source_version = source.version
            if command.decision == "approve":
                self._service.approve_audit_export(
                    _staff_actor(actor),
                    operation_id=source.id,
                    expected_version=source_version,
                    approval_reason=command.decision_reason,
                    now=now,
                    approval_projection_version=command.expected_projection_version,
                    approval_decision_code=command.decision_code,
                )
                return
            self._service.reject_audit_export(
                _staff_actor(actor),
                operation_id=source.id,
                expected_version=source_version,
                rejection_reason=command.decision_reason,
                idempotency_key=command.idempotency_key,
                now=now,
                approval_projection_version=command.expected_projection_version,
                approval_decision_code=command.decision_code,
            )
        except (LifecycleError, PlatformSecurityError) as error:
            _raise_source(error)

    def reconcile(
        self,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
        limit: int,
    ) -> ApprovalReconcileResult:
        _same_projection(self._bridge, projection)
        _limit(limit, maximum=500)
        projected = terminal = 0
        with self._sessions.begin() as db:
            apply_source_approval_rls_context(
                db,
                SourceApprovalRlsContext(
                    source_kind="audit",
                    mutation="scan",
                    realm="staff",
                ),
            )
            sources = tuple(
                db.execute(
                    sa.select(PlatformAdminOperationRecord)
                    .options(
                        load_only(
                            PlatformAdminOperationRecord.id,
                            PlatformAdminOperationRecord.action,
                            PlatformAdminOperationRecord.tenant_id,
                            PlatformAdminOperationRecord.target_id,
                            PlatformAdminOperationRecord.requested_by_principal_id,
                            PlatformAdminOperationRecord.approved_by_principal_id,
                            PlatformAdminOperationRecord.request_hash,
                            PlatformAdminOperationRecord.status,
                            PlatformAdminOperationRecord.error_code,
                            PlatformAdminOperationRecord.approved_at,
                            PlatformAdminOperationRecord.completed_at,
                            PlatformAdminOperationRecord.created_at,
                        )
                    )
                    .where(PlatformAdminOperationRecord.action == "audit_export")
                    .order_by(PlatformAdminOperationRecord.id)
                    .limit(limit)
                ).scalars()
            )
            for source in sources:
                spec = self._service._audit_approval_spec(source, _utc(now))
                desired, code, decider, decided_at = _audit_terminal(source, now)
                created, settled = _reconcile_spec(
                    db,
                    self._bridge,
                    spec,
                    desired_status=desired,
                    decision_code=code,
                    decided_by_id=decider,
                    decided_at=decided_at,
                    now=now,
                )
                projected += created
                terminal += settled
        return ApprovalReconcileResult(projected=projected, terminal_synced=terminal)

    def expire(
        self,
        work_item: ApprovalWorkItemView,
        projection: ApprovalProjectionService,
        *,
        now: datetime,
    ) -> None:
        _same_projection(self._bridge, projection)
        with self._sessions.begin() as db:
            apply_source_approval_rls_context(
                db,
                SourceApprovalRlsContext(
                    source_kind="audit",
                    mutation="terminal",
                    realm="staff",
                    tenant_id=work_item.tenant_id,
                    operation_id=work_item.operation_id,
                    work_item_id=work_item.id,
                ),
            )
            source = _audit_scheduler_source(db, work_item.operation_id)
            if source.status != "pending_staff_approval" or _utc(
                source.created_at
            ) + _AUDIT_APPROVAL_TTL > _utc(now):
                raise ApprovalOperationsError("approval_source_not_expired")
            self._bridge.terminal_in_transaction(
                db,
                self._service._audit_approval_spec(source, _utc(now)),
                status="expired",
                decision_code="audit_export_approval_expired",
                decided_by_id=None,
                decided_at=_utc(now),
                expected_projection_version=work_item.version,
            )


@dataclass(frozen=True, slots=True)
class SourceApprovalRegistry:
    """One complete production wiring for authority, audience, and scheduler use."""

    enterprise: EnterpriseApprovalSource
    support_customer: SupportApprovalSource
    support_staff: SupportApprovalSource
    privacy: PrivacyApprovalSource
    audit: AuditExportApprovalSource
    audience: SourceApprovalAudienceRouter
    bridge: SourceApprovalProjectionBridge

    def authority_adapters(self) -> dict[str, ApprovalAuthorityAdapter]:
        return {
            "enterprise": self.enterprise,
            "support.customer": self.support_customer,
            "support.staff": self.support_staff,
            "privacy": self.privacy,
            "audit": self.audit,
        }

    def scheduler_sources(self) -> dict[str, ApprovalSchedulerSource]:
        return {
            "enterprise": self.enterprise,
            "support.customer": self.support_customer,
            "support.staff": self.support_staff,
            "privacy": self.privacy,
            "audit": self.audit,
        }


def compose_source_approval_registry(
    *,
    bridge: SourceApprovalProjectionBridge,
    audience: SourceApprovalAudienceRouter,
    enterprise: EnterpriseApprovalSource,
    support_customer: SupportApprovalSource,
    support_staff: SupportApprovalSource,
    privacy: PrivacyApprovalSource,
    audit: AuditExportApprovalSource,
    production_mode: bool = True,
) -> SourceApprovalRegistry:
    """Fail closed unless every source uses the same notifying projection bridge."""

    sources: tuple[TransactionalApprovalSource, ...] = (
        enterprise,
        support_customer,
        support_staff,
        privacy,
        audit,
    )
    if any(not source.uses_projection_bridge(bridge) for source in sources):
        raise ValueError("approval source service is not wired to the projection bridge")
    if production_mode:
        if not bridge.production_mode or bridge.notifier is None:
            raise ValueError("production approval registry requires a notifying bridge")
        if getattr(bridge.notifier, "audience", None) is not audience:
            raise ValueError("production approval notifier is not wired to the audience router")
        if not support_customer.is_scoped_to_operation_kind(
            "support.customer"
        ) or not support_staff.is_scoped_to_operation_kind("support.staff"):
            raise ValueError("production support approval sources must be stage scoped")
    for operation_kind, source in (
        ("enterprise", enterprise),
        ("support.customer", support_customer),
        ("support.staff", support_staff),
        ("privacy", privacy),
        ("audit", audit),
    ):
        audience.register(operation_kind, source)
    audience.require_complete()
    return SourceApprovalRegistry(
        enterprise=enterprise,
        support_customer=support_customer,
        support_staff=support_staff,
        privacy=privacy,
        audit=audit,
        audience=audience,
        bridge=bridge,
    )


def production_approval_scheduler_source_factory(
    context: ApprovalSchedulerSourceFactoryContext,
) -> dict[str, ApprovalSchedulerSource]:
    """Build all five source adapters from five already-verified DB authorities."""

    required_sources = {
        "enterprise",
        "privacy",
        "audit",
        "support.customer",
        "support.staff",
    }
    if set(context.source_sessions) != required_sources:
        raise RuntimeError("approval scheduler source sessions are incomplete")
    approval_key_id, approval_secret = _factory_secret(
        context.configuration,
        key_id_name="approval_hmac_key_id",
        secret_name="approval_hmac_secret_b64",
    )
    audience = SourceApprovalAudienceRouter()
    notifier = SourceApprovalNotificationService(
        deliveries=context.notifications,
        audience=audience,
    )
    bridge = SourceApprovalProjectionBridge(
        projection=context.projection,
        digester=ApprovalSecretDigester(approval_key_id, approval_secret),
        notifier=notifier,
        production_mode=True,
    )
    enterprise_service = EnterpriseAccessService(
        context.source_sessions["enterprise"],
        approval_projection=bridge,
    )
    privacy_lifecycle = PrivacyLifecycleService(
        context.source_sessions["privacy"],
        evidence_verifier=_DenyDeletionEvidenceVerifier(),
    )
    privacy_service = PrivacyOperationService(
        context.source_sessions["privacy"],
        lifecycle=privacy_lifecycle,
        locator_key=_DisabledPrivacyLocatorKey(),
        approval_projection=bridge,
    )
    support_customer_service = PlatformGovernedAccessService(
        context.source_sessions["support.customer"],
        approval_projection=bridge,
    )
    support_staff_service = PlatformGovernedAccessService(
        context.source_sessions["support.staff"],
        approval_projection=bridge,
    )
    audit_service = PlatformGovernedAccessService(
        context.source_sessions["audit"],
        approval_projection=bridge,
    )
    registry = compose_source_approval_registry(
        bridge=bridge,
        audience=audience,
        enterprise=EnterpriseApprovalSource(
            context.source_sessions["enterprise"],
            service=enterprise_service,
            bridge=bridge,
        ),
        support_customer=SupportApprovalSource(
            context.source_sessions["support.customer"],
            service=support_customer_service,
            bridge=bridge,
            operation_kind="support.customer",
        ),
        support_staff=SupportApprovalSource(
            context.source_sessions["support.staff"],
            service=support_staff_service,
            bridge=bridge,
            operation_kind="support.staff",
        ),
        privacy=PrivacyApprovalSource(
            context.source_sessions["privacy"],
            service=privacy_service,
            bridge=bridge,
        ),
        audit=AuditExportApprovalSource(
            context.source_sessions["audit"],
            service=audit_service,
            bridge=bridge,
        ),
    )
    return registry.scheduler_sources()


def _factory_secret(
    configuration: Mapping[str, str],
    *,
    key_id_name: str,
    secret_name: str,
) -> tuple[str, bytes]:
    key_id = configuration.get(key_id_name, "").strip()
    encoded = configuration.get(secret_name, "").strip()
    if not key_id or not encoded:
        raise RuntimeError("approval scheduler source key configuration is incomplete")
    try:
        secret = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise RuntimeError("approval scheduler source key configuration is invalid") from error
    if len(secret) < 32:
        raise RuntimeError("approval scheduler source key configuration is invalid")
    return key_id, secret


def _enterprise_preflight(db: Session, operation_id: UUID) -> EnterpriseAccessPreflightRecord:
    value = db.get(EnterpriseAccessPreflightRecord, operation_id)
    if value is None:
        raise ApprovalOperationsError("approval_source_not_found")
    return value


def _enterprise_scheduler_preflight(
    db: Session, operation_id: UUID
) -> EnterpriseAccessPreflightRecord:
    value = db.execute(
        sa.select(EnterpriseAccessPreflightRecord)
        .options(
            load_only(
                EnterpriseAccessPreflightRecord.id,
                EnterpriseAccessPreflightRecord.tenant_id,
                EnterpriseAccessPreflightRecord.space_id,
                EnterpriseAccessPreflightRecord.project_id,
                EnterpriseAccessPreflightRecord.operation_type,
                EnterpriseAccessPreflightRecord.target_id,
                EnterpriseAccessPreflightRecord.requested_by,
                EnterpriseAccessPreflightRecord.snapshot_hash,
                EnterpriseAccessPreflightRecord.status,
                EnterpriseAccessPreflightRecord.approved_by,
                EnterpriseAccessPreflightRecord.approved_at,
                EnterpriseAccessPreflightRecord.expires_at,
                EnterpriseAccessPreflightRecord.created_at,
            )
        )
        .where(EnterpriseAccessPreflightRecord.id == operation_id)
    ).scalar_one_or_none()
    if value is None:
        raise ApprovalOperationsError("approval_source_not_found")
    return value


def _enterprise_context(
    db: Session,
    source: EnterpriseAccessPreflightRecord,
    actor_id: UUID,
    *,
    security_version: int | None = None,
    trace_id: str | None = None,
) -> RequestContext:
    statement = (
        sa.select(GlobalUser, TenantMembership, SpaceMembership)
        .options(
            load_only(GlobalUser.id, GlobalUser.status, GlobalUser.security_version),
            load_only(
                TenantMembership.tenant_id,
                TenantMembership.user_id,
                TenantMembership.role,
                TenantMembership.status,
                TenantMembership.version,
            ),
            load_only(
                SpaceMembership.tenant_id,
                SpaceMembership.space_id,
                SpaceMembership.user_id,
                SpaceMembership.role,
                SpaceMembership.status,
                SpaceMembership.version,
            ),
        )
        .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
        .join(
            SpaceMembership,
            sa.and_(
                SpaceMembership.user_id == GlobalUser.id,
                SpaceMembership.tenant_id == TenantMembership.tenant_id,
            ),
        )
        .where(
            GlobalUser.id == actor_id,
            GlobalUser.status == "active",
            TenantMembership.tenant_id == source.tenant_id,
            TenantMembership.status == "active",
            SpaceMembership.status == "active",
        )
        .order_by(SpaceMembership.space_id)
    )
    if source.space_id is not None:
        statement = statement.where(SpaceMembership.space_id == source.space_id)
    row = db.execute(statement.limit(1)).one_or_none()
    if row is None:
        raise ApprovalOperationsError("approval_identity_inactive")
    user, tenant_membership, space_membership = row
    if security_version is not None and user.security_version != security_version:
        raise ApprovalOperationsError("approval_actor_security_version_changed")
    return RequestContext(
        actor_id=actor_id,
        tenant_id=source.tenant_id,
        space_id=space_membership.space_id,
        project_id=source.project_id,
        user_security_version=user.security_version,
        tenant_membership_version=tenant_membership.version,
        space_membership_version=space_membership.version,
        trace_id=trace_id or f"approval-authorize:{source.id}:{actor_id}",
    )


def _tenant_identity(
    db: Session, actor_id: UUID, tenant_id: UUID
) -> tuple[GlobalUser, TenantMembership]:
    row = db.execute(
        sa.select(GlobalUser, TenantMembership)
        .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
        .where(
            GlobalUser.id == actor_id,
            GlobalUser.status == "active",
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.status == "active",
        )
    ).one_or_none()
    if row is None:
        raise ApprovalOperationsError("approval_identity_inactive")
    return row[0], row[1]


def _support_source(
    db: Session, grant_id: UUID
) -> tuple[PlatformSupportGrantRecord, PlatformAdminOperationRecord]:
    row = db.execute(
        sa.select(PlatformSupportGrantRecord, PlatformAdminOperationRecord)
        .join(
            PlatformAdminOperationRecord,
            PlatformAdminOperationRecord.id == PlatformSupportGrantRecord.operation_id,
        )
        .where(PlatformSupportGrantRecord.id == grant_id)
    ).one_or_none()
    if row is None:
        raise ApprovalOperationsError("approval_source_not_found")
    return row[0], row[1]


def _support_scheduler_source(
    db: Session, grant_id: UUID
) -> tuple[PlatformSupportGrantRecord, PlatformAdminOperationRecord]:
    row = db.execute(
        sa.select(PlatformSupportGrantRecord, PlatformAdminOperationRecord)
        .options(
            load_only(
                PlatformSupportGrantRecord.id,
                PlatformSupportGrantRecord.operation_id,
                PlatformSupportGrantRecord.tenant_id,
                PlatformSupportGrantRecord.requested_by_principal_id,
                PlatformSupportGrantRecord.mode,
                PlatformSupportGrantRecord.status,
                PlatformSupportGrantRecord.customer_approved_by_user_id,
                PlatformSupportGrantRecord.customer_approved_at,
                PlatformSupportGrantRecord.staff_approved_by_principal_id,
                PlatformSupportGrantRecord.staff_approved_at,
                PlatformSupportGrantRecord.requested_at,
                PlatformSupportGrantRecord.expires_at,
            ),
            load_only(
                PlatformAdminOperationRecord.id,
                PlatformAdminOperationRecord.request_hash,
                PlatformAdminOperationRecord.completed_at,
            ),
        )
        .join(
            PlatformAdminOperationRecord,
            PlatformAdminOperationRecord.id == PlatformSupportGrantRecord.operation_id,
        )
        .where(PlatformSupportGrantRecord.id == grant_id)
    ).one_or_none()
    if row is None:
        raise ApprovalOperationsError("approval_source_not_found")
    return row[0], row[1]


def _privacy_source(
    db: Session, operation_id: UUID
) -> tuple[PlatformAdminOperationRecord, PrivacyApprovalBindingRecord]:
    row = db.execute(
        sa.select(PlatformAdminOperationRecord, PrivacyApprovalBindingRecord)
        .join(
            PrivacyApprovalBindingRecord,
            PrivacyApprovalBindingRecord.operation_id == PlatformAdminOperationRecord.id,
        )
        .where(PlatformAdminOperationRecord.id == operation_id)
    ).one_or_none()
    if row is None:
        raise ApprovalOperationsError("approval_source_not_found")
    return row[0], row[1]


def _privacy_scheduler_source(
    db: Session, operation_id: UUID
) -> tuple[PlatformAdminOperationRecord, PrivacyApprovalBindingRecord]:
    row = db.execute(
        sa.select(PlatformAdminOperationRecord, PrivacyApprovalBindingRecord)
        .options(
            load_only(
                PlatformAdminOperationRecord.id,
                PlatformAdminOperationRecord.action,
                PlatformAdminOperationRecord.tenant_id,
                PlatformAdminOperationRecord.requested_by_principal_id,
                PlatformAdminOperationRecord.approved_by_principal_id,
                PlatformAdminOperationRecord.status,
                PlatformAdminOperationRecord.error_code,
                PlatformAdminOperationRecord.approved_at,
                PlatformAdminOperationRecord.completed_at,
            ),
            load_only(
                PrivacyApprovalBindingRecord.operation_id,
                PrivacyApprovalBindingRecord.phase,
                PrivacyApprovalBindingRecord.target_type,
                PrivacyApprovalBindingRecord.target_id,
                PrivacyApprovalBindingRecord.tenant_id,
                PrivacyApprovalBindingRecord.snapshot_hash,
                PrivacyApprovalBindingRecord.expires_at,
                PrivacyApprovalBindingRecord.created_at,
            ),
        )
        .join(
            PrivacyApprovalBindingRecord,
            PrivacyApprovalBindingRecord.operation_id == PlatformAdminOperationRecord.id,
        )
        .where(PlatformAdminOperationRecord.id == operation_id)
    ).one_or_none()
    if row is None:
        raise ApprovalOperationsError("approval_source_not_found")
    return row[0], row[1]


def _audit_source(db: Session, operation_id: UUID) -> PlatformAdminOperationRecord:
    value = db.get(PlatformAdminOperationRecord, operation_id)
    if value is None or value.action != "audit_export":
        raise ApprovalOperationsError("approval_source_not_found")
    return value


def _audit_scheduler_source(db: Session, operation_id: UUID) -> PlatformAdminOperationRecord:
    value = db.execute(
        sa.select(PlatformAdminOperationRecord)
        .options(
            load_only(
                PlatformAdminOperationRecord.id,
                PlatformAdminOperationRecord.action,
                PlatformAdminOperationRecord.tenant_id,
                PlatformAdminOperationRecord.target_id,
                PlatformAdminOperationRecord.requested_by_principal_id,
                PlatformAdminOperationRecord.approved_by_principal_id,
                PlatformAdminOperationRecord.request_hash,
                PlatformAdminOperationRecord.status,
                PlatformAdminOperationRecord.error_code,
                PlatformAdminOperationRecord.approved_at,
                PlatformAdminOperationRecord.completed_at,
                PlatformAdminOperationRecord.created_at,
            )
        )
        .where(
            PlatformAdminOperationRecord.id == operation_id,
            PlatformAdminOperationRecord.action == "audit_export",
        )
    ).scalar_one_or_none()
    if value is None:
        raise ApprovalOperationsError("approval_source_not_found")
    return value


def _staff_actor(actor: ApprovalActor) -> ValidatedPlatformPrincipal:
    if actor.realm != "staff":
        raise ApprovalOperationsError("approval_authority_scope_denied")
    return ValidatedPlatformPrincipal(
        session_id=uuid5(NAMESPACE_URL, f"omnigent:approval-session:{actor.actor_id}"),
        principal_id=actor.actor_id,
        security_version=actor.security_version,
        authn_method="approval-operations-cookie",
        authenticated_at=_utc(actor.authenticated_at),
        expires_at=_utc(actor.expires_at),
        roles=frozenset(),
        permissions=actor.permissions,
    )


def _synthetic_staff(
    principal: PlatformStaffPrincipalRecord, now: datetime
) -> ValidatedPlatformPrincipal:
    at = _utc(now)
    return ValidatedPlatformPrincipal(
        session_id=uuid5(NAMESPACE_URL, f"omnigent:approval-identity:{principal.id}"),
        principal_id=principal.id,
        security_version=principal.security_version,
        authn_method="approval-authority-check",
        authenticated_at=at,
        expires_at=at + timedelta(minutes=5),
        roles=frozenset(),
        permissions=frozenset(),
    )


def _authorize_staff_permission(
    sessions: sessionmaker[Session],
    actor: ApprovalActor,
    permission: str,
    *,
    now: datetime,
) -> None:
    principal = _staff_actor(actor)
    try:
        with sessions.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.actor_id))
            _require_staff_permission(db, principal, permission, now)
    except PlatformSecurityError as error:
        _raise_source(error)


def _authorize_staff_identity(
    sessions: sessionmaker[Session],
    actor_id: UUID,
    permission: str,
    *,
    now: datetime,
) -> None:
    with sessions.begin() as db:
        principal = db.get(PlatformStaffPrincipalRecord, actor_id)
        if principal is None:
            raise ApprovalOperationsError("approval_identity_inactive")
        _require_staff_permission(db, _synthetic_staff(principal, now), permission, now)


def _require_staff_permission(
    db: Session,
    actor: ValidatedPlatformPrincipal,
    permission: str,
    now: datetime,
) -> None:
    principal = db.get(PlatformStaffPrincipalRecord, actor.principal_id)
    if (
        principal is None
        or principal.status != "active"
        or principal.security_version != actor.security_version
    ):
        raise ApprovalOperationsError("approval_identity_inactive")
    roles = tuple(
        db.execute(
            sa.select(PlatformRoleAssignmentRecord.role).where(
                PlatformRoleAssignmentRecord.principal_id == actor.principal_id,
                PlatformRoleAssignmentRecord.status == "active",
                sa.or_(
                    PlatformRoleAssignmentRecord.expires_at.is_(None),
                    PlatformRoleAssignmentRecord.expires_at > _utc(now),
                ),
            )
        ).scalars()
    )
    permissions = {
        code for role in roles for code in PLATFORM_ROLE_PERMISSIONS.get(role, frozenset())
    }
    if permission not in permissions:
        raise ApprovalOperationsError("approval_permission_denied")


def _eligible_staff(
    sessions: sessionmaker[Session],
    permission: str,
    *,
    now: datetime,
    limit: int,
) -> tuple[UUID, ...]:
    with sessions.begin() as db:
        return _eligible_staff_in_transaction(
            db,
            permission,
            now=now,
            limit=limit,
        )


def _eligible_staff_in_transaction(
    db: Session,
    permission: str,
    *,
    now: datetime,
    limit: int,
) -> tuple[UUID, ...]:
    _limit(limit)
    rows = tuple(
        db.execute(
            sa.select(
                PlatformStaffPrincipalRecord.id,
                PlatformRoleAssignmentRecord.role,
            )
            .join(
                PlatformRoleAssignmentRecord,
                PlatformRoleAssignmentRecord.principal_id == PlatformStaffPrincipalRecord.id,
            )
            .where(
                PlatformStaffPrincipalRecord.status == "active",
                PlatformRoleAssignmentRecord.status == "active",
                sa.or_(
                    PlatformRoleAssignmentRecord.expires_at.is_(None),
                    PlatformRoleAssignmentRecord.expires_at > _utc(now),
                ),
            )
            .order_by(PlatformStaffPrincipalRecord.id)
        ).all()
    )
    eligible: list[UUID] = []
    for principal_id, role in rows:
        if permission not in PLATFORM_ROLE_PERMISSIONS.get(role, frozenset()):
            continue
        if principal_id not in eligible:
            eligible.append(principal_id)
        if len(eligible) >= limit:
            break
    return tuple(eligible)


def _projection_for_spec(
    db: Session,
    bridge: SourceApprovalProjectionBridge,
    spec: SourceApprovalProjectionSpec,
) -> ApprovalWorkItemView | None:
    try:
        return bridge.projection.get_for_source_in_transaction(
            db,
            work_item_id=spec.work_item_id,
            source_authority=spec.authority,
            source_subject_id=spec.source_subject_id,
            realm=spec.realm,
            tenant_id=spec.tenant_id,
            operation_id=spec.operation_id,
            actor_realm=spec.requester_realm,
            actor_id=spec.requester_id,
            mutation="source_reconcile_read",
        )
    except ApprovalOperationsError as error:
        if error.code == "approval_projection_not_found":
            return None
        raise


def _reconcile_spec(
    db: Session,
    bridge: SourceApprovalProjectionBridge,
    spec: SourceApprovalProjectionSpec,
    *,
    desired_status: str,
    decision_code: str,
    decided_by_id: UUID | None,
    decided_at: datetime,
    now: datetime,
) -> tuple[int, int]:
    apply_source_approval_rls_context(
        db,
        SourceApprovalRlsContext(
            source_kind=spec.operation_kind,
            mutation="project" if desired_status == "pending" else "terminal",
            realm=spec.realm,
            tenant_id=spec.tenant_id,
            operation_id=spec.operation_id,
            subject_id=spec.source_subject_id,
            work_item_id=spec.work_item_id,
        ),
    )
    existing = _projection_for_spec(db, bridge, spec)
    created = int(existing is None)
    if desired_status == "pending":
        if existing is None:
            bridge.project_in_transaction(db, spec, now=_utc(now))
        elif existing.status != "pending":
            raise ApprovalOperationsError("approval_projection_terminal_conflict")
        return created, 0
    if existing is not None and existing.status == desired_status:
        return 0, 0
    bridge.terminal_in_transaction(
        db,
        spec,
        status=desired_status,  # type: ignore[arg-type]
        decision_code=decision_code,
        decided_by_id=decided_by_id,
        decided_at=_utc(decided_at),
        expected_projection_version=existing.version if existing is not None else None,
    )
    return created, 1


def _enterprise_terminal(
    source: EnterpriseAccessPreflightRecord, now: datetime
) -> tuple[str, str, UUID | None, datetime]:
    if source.status == "pending_approval":
        if _utc(source.expires_at) <= _utc(now):
            return "expired", "source_expired", None, _utc(now)
        return "pending", "pending", None, _utc(now)
    if source.status in {"approved", "executed"}:
        return (
            "approved",
            "source_approved",
            source.approved_by,
            _utc(source.approved_at or now),
        )
    return "rejected", "source_rejected", source.approved_by, _utc(source.approved_at or now)


def _support_desired(
    grant: PlatformSupportGrantRecord,
    operation: PlatformAdminOperationRecord,
    now: datetime,
) -> tuple[tuple[str, str, str, UUID | None, datetime], ...]:
    at = _utc(now)
    expired = _utc(grant.expires_at) <= at
    values: list[tuple[str, str, str, UUID | None, datetime]] = []
    if grant.mode == "standard":
        if grant.status == "pending_customer_approval":
            values.append(
                (
                    "customer",
                    "expired" if expired else "pending",
                    "source_expired" if expired else "pending",
                    None,
                    at,
                )
            )
        else:
            customer_status = (
                "rejected"
                if grant.status == "rejected"
                and grant.customer_approved_at is not None
                and grant.staff_approved_at is None
                else "approved"
            )
            values.append(
                (
                    "customer",
                    customer_status,
                    f"customer_{customer_status}",
                    grant.customer_approved_by_user_id,
                    _utc(grant.customer_approved_at or operation.completed_at or now),
                )
            )
    if grant.mode == "break_glass" or grant.status not in {"pending_customer_approval"}:
        if grant.status == "pending_staff_approval":
            values.append(
                (
                    "staff",
                    "expired" if expired else "pending",
                    "source_expired" if expired else "pending",
                    None,
                    at,
                )
            )
        elif grant.staff_approved_at is not None:
            staff_status = "approved" if grant.status in {"active", "revoked"} else "rejected"
            values.append(
                (
                    "staff",
                    staff_status,
                    f"staff_{staff_status}",
                    grant.staff_approved_by_principal_id,
                    _utc(grant.staff_approved_at),
                )
            )
    return tuple(values)


def _privacy_terminal(
    operation: PlatformAdminOperationRecord,
    binding: PrivacyApprovalBindingRecord,
    now: datetime,
) -> tuple[str, str, UUID | None, datetime]:
    if operation.status == "pending_staff_approval":
        if _utc(binding.expires_at) <= _utc(now):
            return "expired", "approval_expired", None, _utc(now)
        return "pending", "pending", None, _utc(now)
    if operation.status == "succeeded":
        return (
            "approved",
            "source_approved",
            operation.approved_by_principal_id,
            _utc(operation.approved_at or now),
        )
    if operation.status == "rejected":
        return (
            "rejected",
            "source_rejected",
            operation.approved_by_principal_id,
            _utc(operation.approved_at or now),
        )
    status = "expired" if operation.error_code == "approval_expired" else "cancelled"
    return (
        status,
        operation.error_code or "source_failed",
        None,
        _utc(operation.completed_at or now),
    )


def _audit_terminal(
    operation: PlatformAdminOperationRecord, now: datetime
) -> tuple[str, str, UUID | None, datetime]:
    if operation.status == "pending_staff_approval":
        if _utc(operation.created_at) + _AUDIT_APPROVAL_TTL <= _utc(now):
            return "expired", "audit_export_approval_expired", None, _utc(now)
        return "pending", "pending", None, _utc(now)
    if operation.status == "succeeded":
        return (
            "approved",
            "audit_export_approved",
            operation.approved_by_principal_id,
            _utc(operation.approved_at or now),
        )
    return (
        "rejected",
        "audit_export_rejected",
        operation.approved_by_principal_id,
        _utc(operation.completed_at or now),
    )


def _require_work_kind(work: ApprovalWorkItemView, expected: str) -> None:
    if work.operation_kind != expected:
        raise ApprovalOperationsError("approval_source_binding_conflict")


def _require_source_snapshot(work: ApprovalWorkItemView, snapshot_hash: str) -> None:
    if work.snapshot_hash != snapshot_hash:
        raise ApprovalOperationsError("approval_source_snapshot_changed")


def _same_projection(
    bridge: SourceApprovalProjectionBridge, projection: ApprovalProjectionService
) -> None:
    if bridge.projection is not projection:
        raise ApprovalOperationsError("approval_projection_authority_mismatch")


def _limit(value: int, *, maximum: int = 100) -> None:
    if not 1 <= value <= maximum:
        raise ApprovalOperationsError("approval_page_limit_invalid")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _raise_source(error: LifecycleError | PlatformSecurityError) -> NoReturn:
    raise ApprovalOperationsError(error.code) from error


__all__ = [
    "ApprovalSchedulerSourceFactoryContext",
    "AuditExportApprovalSource",
    "EnterpriseApprovalSource",
    "PrivacyApprovalSource",
    "SourceApprovalAudienceRouter",
    "SourceApprovalRegistry",
    "SourceApprovalRlsContext",
    "SupportApprovalSource",
    "TransactionalApprovalSource",
    "apply_source_approval_rls_context",
    "compose_source_approval_registry",
    "production_approval_scheduler_source_factory",
]
