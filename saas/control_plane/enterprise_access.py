"""Enterprise groups and project-scoped custom-role governance."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    ProjectRecord,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.enterprise_models import (
    EnterpriseAccessPreflightRecord,
    EnterpriseCustomRoleRecord,
    EnterpriseGroupMembershipRecord,
    EnterpriseGroupRecord,
    EnterpriseGroupRoleAssignmentRecord,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.permissions import (
    PERMISSION_CATALOG,
    TENANT_ROLE_PERMISSIONS,
    PermissionRisk,
    PermissionScope,
)
from saas.control_plane.rls import RlsContext, apply_rls_context

_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_ENTERPRISE_PREFLIGHT_TTL = timedelta(minutes=15)


@dataclass(frozen=True, slots=True)
class EnterpriseGroupView:
    id: UUID
    tenant_id: UUID
    name: str
    description: str | None
    status: str
    version: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class EnterpriseGroupMembershipView:
    group_id: UUID
    user_id: UUID
    status: str
    expires_at: datetime | None
    version: int
    security_version: int | None = None
    revoked_session_count: int = 0
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class EnterpriseCustomRoleView:
    id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    name: str
    description: str | None
    permissions: tuple[str, ...]
    status: str
    version: int
    authorization_version: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class EnterpriseGroupRoleAssignmentView:
    id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    group_id: UUID
    custom_role_id: UUID
    status: str
    expires_at: datetime | None
    version: int
    authorization_version: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class EnterpriseGroupMembershipMutation:
    user_id: UUID
    action: str
    expires_at: datetime | None = None
    expected_version: int | None = None


@dataclass(frozen=True, slots=True)
class EnterpriseGroupMembershipBatchView:
    group_id: UUID
    memberships: tuple[EnterpriseGroupMembershipView, ...]
    affected_project_ids: tuple[UUID, ...]
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class EnterpriseAccessPreflightView:
    preflight_id: UUID
    tenant_id: UUID
    space_id: UUID | None
    project_id: UUID | None
    operation_type: str
    target_id: UUID
    target_version: int
    status: str
    requested_by: UUID
    approved_by: UUID | None
    approval_policy: str
    reason: str | None
    approval_reason: str | None
    impact_summary: dict[str, object]
    snapshot_hash: str
    expires_at: datetime
    created_at: datetime | None
    approved_at: datetime | None
    executed_at: datetime | None
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class EnterpriseGroupArchiveView:
    group_id: UUID
    status: str
    version: int
    archived_at: datetime
    archived_by: UUID
    archive_reason: str
    removed_membership_count: int
    revoked_assignment_count: int
    invalidated_user_count: int
    revoked_session_count: int
    affected_project_ids: tuple[UUID, ...]
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class EnterpriseCustomRoleRetirementView:
    custom_role_id: UUID
    status: str
    version: int
    retired_at: datetime
    retired_by: UUID
    retire_reason: str
    revoked_assignment_count: int
    authorization_version: int
    replayed: bool = False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clean_text(value: str, *, maximum: int, code: str) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise LifecycleError(code, "value is invalid")
    return cleaned


def _clean_description(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if len(cleaned) > 1024:
        raise LifecycleError("description_invalid", "description is invalid")
    return cleaned or None


def _idempotency(value: str) -> None:
    if not value or len(value) > 128:
        raise LifecycleError("invalid_idempotency_key", "idempotency key is invalid")


def _hash(payload: dict[str, object]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _comparable(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _require_fresh_auth(reauthenticated_at: datetime, now: datetime) -> None:
    authenticated = _comparable(reauthenticated_at)
    current = _comparable(now)
    if authenticated > current or current - authenticated > _FRESH_AUTH_WINDOW:
        raise LifecycleError("fresh_auth_required", "recent authentication is required")


class EnterpriseAccessService:
    """Own Group/custom-role lifecycle and invalidate every affected decision."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        authorizer: ProjectAuthorizer | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._authorizer = authorizer or ProjectAuthorizer(session_factory)

    def create_group(
        self,
        request: RequestContext,
        *,
        name: str,
        description: str | None,
        idempotency_key: str,
    ) -> EnterpriseGroupView:
        _idempotency(idempotency_key)
        cleaned_name = _clean_text(name, maximum=128, code="group_name_invalid")
        cleaned_description = _clean_description(description)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "name": cleaned_name,
            "description": cleaned_description,
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "group.created", digest
            )
            if receipt is not None:
                return self._group_result(receipt.payload, replayed=True)
            self._require_tenant_group_admin(db, request)
            group = EnterpriseGroupRecord(
                id=uuid4(),
                tenant_id=request.tenant_id,
                name=cleaned_name,
                description=cleaned_description,
                status="active",
                version=1,
                created_by=request.actor_id,
            )
            db.add(group)
            db.flush()
            event_payload = {
                **payload,
                "group_id": str(group.id),
                "status": group.status,
                "version": group.version,
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_group",
                aggregate_key=str(group.id),
                event_type="group.created",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._group(group)

    def list_groups(
        self,
        request: RequestContext,
        *,
        after_id: UUID | None = None,
        limit: int | None = None,
    ) -> tuple[EnterpriseGroupView, ...]:
        if limit is not None and not 1 <= limit <= 101:
            raise LifecycleError("page_limit_invalid", "page limit is invalid")
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            membership = self._require_tenant_member_snapshot(db, request)
            if "group.read" not in TENANT_ROLE_PERMISSIONS[membership.role]:
                raise LifecycleError("group_read_forbidden", "group read permission is required")
            statement = sa.select(EnterpriseGroupRecord).where(
                EnterpriseGroupRecord.tenant_id == request.tenant_id
            )
            if after_id is not None:
                statement = statement.where(EnterpriseGroupRecord.id > after_id)
            statement = statement.order_by(EnterpriseGroupRecord.id)
            if limit is not None:
                statement = statement.limit(limit)
            groups = db.execute(statement).scalars()
            return tuple(self._group(group) for group in groups)

    def list_requested_enterprise_access_preflights(
        self,
        request: RequestContext,
        *,
        status: str | None = None,
        after_id: UUID | None = None,
        limit: int | None = None,
    ) -> tuple[EnterpriseAccessPreflightView, ...]:
        """List only preflights created by the authenticated Tenant member."""

        self._validate_preflight_list(status=status, limit=limit)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._require_tenant_member_snapshot(db, request)
            statement = sa.select(EnterpriseAccessPreflightRecord).where(
                EnterpriseAccessPreflightRecord.tenant_id == request.tenant_id,
                EnterpriseAccessPreflightRecord.requested_by == request.actor_id,
            )
            statement = self._preflight_list_statement(
                statement,
                status=status,
                after_id=after_id,
                limit=limit,
                exclude_expired_pending=False,
            )
            return tuple(self._preflight_view(value) for value in db.execute(statement).scalars())

    def list_group_archive_preflights(
        self,
        request: RequestContext,
        *,
        status: str | None = "pending_approval",
        after_id: UUID | None = None,
        limit: int | None = None,
        now: datetime | None = None,
    ) -> tuple[EnterpriseAccessPreflightView, ...]:
        """List Tenant-wide Group approvals for a currently authorized administrator."""

        self._validate_preflight_list(status=status, limit=limit)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._require_tenant_group_admin(db, request)
            statement = sa.select(EnterpriseAccessPreflightRecord).where(
                EnterpriseAccessPreflightRecord.tenant_id == request.tenant_id,
                EnterpriseAccessPreflightRecord.operation_type == "group_archive",
                EnterpriseAccessPreflightRecord.space_id.is_(None),
                EnterpriseAccessPreflightRecord.project_id.is_(None),
                EnterpriseAccessPreflightRecord.requested_by != request.actor_id,
            )
            statement = self._preflight_list_statement(
                statement,
                status=status,
                after_id=after_id,
                limit=limit,
                exclude_expired_pending=True,
                now=now,
            )
            return tuple(self._preflight_view(value) for value in db.execute(statement).scalars())

    def list_custom_role_retire_preflights(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        status: str | None = "pending_approval",
        after_id: UUID | None = None,
        limit: int | None = None,
        now: datetime | None = None,
    ) -> tuple[EnterpriseAccessPreflightView, ...]:
        """List only the selected Project's custom-role retirement approvals."""

        self._validate_preflight_list(status=status, limit=limit)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._active_project(db, request, project_id, lock=False)
            self._require_project_permissions(
                db, request, project_id, ("grant.manage", "custom_role.manage")
            )
            statement = sa.select(EnterpriseAccessPreflightRecord).where(
                EnterpriseAccessPreflightRecord.tenant_id == request.tenant_id,
                EnterpriseAccessPreflightRecord.space_id == request.space_id,
                EnterpriseAccessPreflightRecord.project_id == project_id,
                EnterpriseAccessPreflightRecord.operation_type == "custom_role_retire",
                EnterpriseAccessPreflightRecord.requested_by != request.actor_id,
            )
            statement = self._preflight_list_statement(
                statement,
                status=status,
                after_id=after_id,
                limit=limit,
                exclude_expired_pending=True,
                now=now,
            )
            return tuple(self._preflight_view(value) for value in db.execute(statement).scalars())

    def create_group_archive_preflight(
        self,
        request: RequestContext,
        *,
        group_id: UUID,
        expected_version: int,
        reason: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> EnterpriseAccessPreflightView:
        """Persist an exact Group archive impact snapshot pending a second principal."""

        created_at = now or _utcnow()
        _idempotency(idempotency_key)
        _require_fresh_auth(reauthenticated_at, created_at)
        cleaned_reason = _clean_text(reason, maximum=512, code="group_archive_reason_invalid")
        request_payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "operation_type": "group_archive",
            "target_id": str(group_id),
            "target_version": expected_version,
            "reason": cleaned_reason,
        }
        digest = _hash(request_payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db,
                request.tenant_id,
                idempotency_key,
                "group.archive.preflighted",
                digest,
            )
            if receipt is not None:
                return self._preflight_result(receipt.payload, replayed=True)
            self._require_tenant_group_admin(db, request)
            snapshot = self._group_archive_snapshot(
                db,
                request,
                group_id=group_id,
                expected_version=expected_version,
                lock=True,
            )
            return self._persist_preflight(
                db,
                request=request,
                operation_type="group_archive",
                target_id=group_id,
                target_version=expected_version,
                reason=cleaned_reason,
                snapshot=snapshot,
                created_at=created_at,
                idempotency_key=idempotency_key,
                request_hash=digest,
                event_type="group.archive.preflighted",
            )

    def create_custom_role_retire_preflight(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        custom_role_id: UUID,
        expected_version: int,
        reason: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> EnterpriseAccessPreflightView:
        """Persist an exact custom-role retirement impact snapshot pending approval."""

        created_at = now or _utcnow()
        _idempotency(idempotency_key)
        _require_fresh_auth(reauthenticated_at, created_at)
        cleaned_reason = _clean_text(reason, maximum=512, code="custom_role_retire_reason_invalid")
        request_payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "operation_type": "custom_role_retire",
            "target_id": str(custom_role_id),
            "target_version": expected_version,
            "reason": cleaned_reason,
        }
        digest = _hash(request_payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db,
                request.tenant_id,
                idempotency_key,
                "custom_role.retire.preflighted",
                digest,
            )
            if receipt is not None:
                return self._preflight_result(receipt.payload, replayed=True)
            self._active_project(db, request, project_id, lock=True)
            self._require_project_permissions(
                db, request, project_id, ("grant.manage", "custom_role.manage")
            )
            snapshot = self._custom_role_retire_snapshot(
                db,
                request,
                project_id=project_id,
                custom_role_id=custom_role_id,
                expected_version=expected_version,
                lock=True,
            )
            return self._persist_preflight(
                db,
                request=request,
                operation_type="custom_role_retire",
                target_id=custom_role_id,
                target_version=expected_version,
                reason=cleaned_reason,
                snapshot=snapshot,
                created_at=created_at,
                idempotency_key=idempotency_key,
                request_hash=digest,
                event_type="custom_role.retire.preflighted",
                project_id=project_id,
            )

    def decide_enterprise_access_preflight(
        self,
        request: RequestContext,
        *,
        preflight_id: UUID,
        operation_type: str,
        target_id: UUID,
        project_id: UUID | None = None,
        decision: str,
        reason: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> EnterpriseAccessPreflightView:
        """Approve or reject as a currently authorized, distinct principal."""

        decided_at = now or _utcnow()
        _idempotency(idempotency_key)
        _require_fresh_auth(reauthenticated_at, decided_at)
        if decision not in {"approve", "reject"}:
            raise LifecycleError("approval_decision_invalid", "approval decision is invalid")
        cleaned_reason = _clean_text(reason, maximum=512, code="approval_reason_invalid")
        request_payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "preflight_id": str(preflight_id),
            "operation_type": operation_type,
            "target_id": str(target_id),
            "project_id": str(project_id) if project_id is not None else None,
            "decision": decision,
            "reason": cleaned_reason,
        }
        digest = _hash(request_payload)
        event_type = (
            "enterprise_access_preflight.approved"
            if decision == "approve"
            else "enterprise_access_preflight.rejected"
        )
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            preflight = db.execute(
                sa.select(EnterpriseAccessPreflightRecord)
                .where(
                    EnterpriseAccessPreflightRecord.id == preflight_id,
                    EnterpriseAccessPreflightRecord.tenant_id == request.tenant_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if preflight is None:
                raise LifecycleError(
                    "enterprise_preflight_not_found", "enterprise access preflight does not exist"
                )
            if (
                preflight.operation_type != operation_type
                or preflight.target_id != target_id
                or preflight.project_id != project_id
            ):
                raise LifecycleError(
                    "enterprise_preflight_mismatch", "preflight is bound to another operation"
                )
            self._require_preflight_permission(db, request, preflight)
            receipt = self._receipt(db, request.tenant_id, idempotency_key, event_type, digest)
            if receipt is not None:
                return self._preflight_result(receipt.payload, replayed=True)
            if preflight.requested_by == request.actor_id:
                raise LifecycleError(
                    "approval_separation_required",
                    "requester cannot approve or reject their own operation",
                )
            if preflight.status != "pending_approval":
                raise LifecycleError(
                    "enterprise_preflight_not_pending", "preflight is not pending approval"
                )
            if _comparable(preflight.expires_at) <= decided_at:
                raise LifecycleError("enterprise_preflight_expired", "preflight has expired")
            current_snapshot = self._snapshot_for_preflight(db, request, preflight, lock=True)
            if _hash(current_snapshot) != preflight.snapshot_hash:
                raise LifecycleError(
                    "enterprise_preflight_stale", "enterprise access impact changed"
                )
            preflight.status = "approved" if decision == "approve" else "rejected"
            preflight.approved_by = request.actor_id
            preflight.approval_reason = cleaned_reason
            preflight.approved_at = decided_at
            event_payload = self._preflight_payload(preflight)
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_access_preflight",
                aggregate_key=str(preflight.id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._preflight_view(preflight)

    def archive_group(
        self,
        request: RequestContext,
        *,
        group_id: UUID,
        expected_version: int,
        reason: str,
        idempotency_key: str,
        approval_preflight_id: UUID | None = None,
        reauthenticated_at: datetime | None = None,
        now: datetime | None = None,
    ) -> EnterpriseGroupArchiveView:
        changed_at = now or _utcnow()
        _idempotency(idempotency_key)
        if approval_preflight_id is not None:
            if reauthenticated_at is None:
                raise LifecycleError("fresh_auth_required", "recent authentication is required")
            _require_fresh_auth(reauthenticated_at, changed_at)
        cleaned_reason = _clean_text(reason, maximum=512, code="group_archive_reason_invalid")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "group_id": str(group_id),
            "expected_version": expected_version,
            "reason": cleaned_reason,
            "approval_preflight_id": (
                str(approval_preflight_id) if approval_preflight_id is not None else None
            ),
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "group.archived", digest
            )
            if receipt is not None:
                return self._group_archive_result(receipt.payload, replayed=True)
            self._require_tenant_group_admin(db, request)
            group = self._active_group(db, request.tenant_id, group_id, lock=True)
            if group.version != expected_version:
                raise LifecycleError("group_version_conflict", "group changed")
            approval = None
            if approval_preflight_id is not None:
                approval = self._require_approved_preflight(
                    db,
                    request,
                    preflight_id=approval_preflight_id,
                    operation_type="group_archive",
                    target_id=group_id,
                    target_version=expected_version,
                    reason=cleaned_reason,
                    now=changed_at,
                )
            memberships = tuple(
                db.execute(
                    sa.select(EnterpriseGroupMembershipRecord)
                    .where(
                        EnterpriseGroupMembershipRecord.tenant_id == request.tenant_id,
                        EnterpriseGroupMembershipRecord.group_id == group_id,
                        EnterpriseGroupMembershipRecord.status == "active",
                    )
                    .order_by(EnterpriseGroupMembershipRecord.user_id)
                    .with_for_update()
                ).scalars()
            )
            assignments = tuple(
                db.execute(
                    sa.select(EnterpriseGroupRoleAssignmentRecord)
                    .where(
                        EnterpriseGroupRoleAssignmentRecord.tenant_id == request.tenant_id,
                        EnterpriseGroupRoleAssignmentRecord.group_id == group_id,
                        EnterpriseGroupRoleAssignmentRecord.status == "active",
                    )
                    .order_by(EnterpriseGroupRoleAssignmentRecord.id)
                    .with_for_update()
                ).scalars()
            )
            affected_projects = tuple(
                sorted({assignment.project_id for assignment in assignments}, key=str)
            )
            group.status = "archived"
            group.version += 1
            group.archived_at = changed_at
            group.archived_by = request.actor_id
            group.archive_reason = cleaned_reason
            for membership in memberships:
                membership.status = "removed"
                membership.expires_at = None
                membership.version += 1
            for assignment in assignments:
                assignment.status = "revoked"
                assignment.expires_at = None
                assignment.version += 1
            revoked_sessions = 0
            for membership in memberships:
                _security_version, count = self._invalidate_user(
                    db, membership.user_id, changed_at
                )
                revoked_sessions += count
            self._increment_project_versions(db, affected_projects)
            if approval is not None:
                approval.status = "executed"
                approval.executed_at = changed_at
            event_payload = {
                **payload,
                "status": group.status,
                "version": group.version,
                "archived_at": changed_at.isoformat(),
                "removed_membership_count": len(memberships),
                "revoked_assignment_count": len(assignments),
                "invalidated_user_count": len(memberships),
                "revoked_session_count": revoked_sessions,
                "affected_project_ids": [str(value) for value in affected_projects],
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_group",
                aggregate_key=str(group.id),
                event_type="group.archived",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return EnterpriseGroupArchiveView(
                group_id=group.id,
                status=group.status,
                version=group.version,
                archived_at=changed_at,
                archived_by=request.actor_id,
                archive_reason=cleaned_reason,
                removed_membership_count=len(memberships),
                revoked_assignment_count=len(assignments),
                invalidated_user_count=len(memberships),
                revoked_session_count=revoked_sessions,
                affected_project_ids=affected_projects,
            )

    def add_group_member(
        self,
        request: RequestContext,
        *,
        group_id: UUID,
        user_id: UUID,
        expires_at: datetime | None,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> EnterpriseGroupMembershipView:
        changed_at = now or _utcnow()
        _idempotency(idempotency_key)
        if expires_at is not None and expires_at <= changed_at:
            raise LifecycleError("group_membership_expiry_invalid", "expiry must be in the future")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "group_id": str(group_id),
            "user_id": str(user_id),
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "group.membership.added", digest
            )
            if receipt is not None:
                return self._membership_result(receipt.payload, replayed=True)
            self._require_tenant_group_admin(db, request)
            self._active_group(db, request.tenant_id, group_id, lock=True)
            affected_projects = self._assigned_project_ids(
                db, request.tenant_id, group_id, changed_at
            )
            target = db.get(TenantMembership, (request.tenant_id, user_id))
            if target is None or target.status != "active":
                raise LifecycleError("group_member_invalid", "active Tenant member is required")
            membership = db.get(EnterpriseGroupMembershipRecord, (group_id, user_id))
            if membership is None:
                membership = EnterpriseGroupMembershipRecord(
                    tenant_id=request.tenant_id,
                    group_id=group_id,
                    user_id=user_id,
                    status="active",
                    expires_at=expires_at,
                    version=1,
                    created_by=request.actor_id,
                )
                db.add(membership)
            elif membership.status == "active":
                raise LifecycleError(
                    "group_membership_exists", "group membership is already active"
                )
            else:
                membership.status = "active"
                membership.expires_at = expires_at
                membership.version += 1
                membership.created_by = request.actor_id
            db.flush()
            self._increment_project_versions(db, affected_projects)
            event_payload = {
                **payload,
                "status": membership.status,
                "version": membership.version,
                "affected_project_ids": [str(value) for value in affected_projects],
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_group_membership",
                aggregate_key=f"{group_id}:{user_id}",
                event_type="group.membership.added",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._membership(membership)

    def remove_group_member(
        self,
        request: RequestContext,
        *,
        group_id: UUID,
        user_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> EnterpriseGroupMembershipView:
        changed_at = now or _utcnow()
        _idempotency(idempotency_key)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "group_id": str(group_id),
            "user_id": str(user_id),
            "expected_version": expected_version,
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "group.membership.removed", digest
            )
            if receipt is not None:
                return self._membership_result(receipt.payload, replayed=True)
            self._require_tenant_group_admin(db, request)
            membership = db.execute(
                sa.select(EnterpriseGroupMembershipRecord)
                .where(
                    EnterpriseGroupMembershipRecord.tenant_id == request.tenant_id,
                    EnterpriseGroupMembershipRecord.group_id == group_id,
                    EnterpriseGroupMembershipRecord.user_id == user_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if membership is None or membership.status != "active":
                raise LifecycleError(
                    "group_membership_not_active", "active membership is required"
                )
            if membership.version != expected_version:
                raise LifecycleError("group_membership_version_conflict", "membership changed")
            affected_projects = self._assigned_project_ids(
                db, request.tenant_id, group_id, changed_at
            )
            membership.status = "removed"
            membership.expires_at = None
            membership.version += 1
            security_version, revoked_sessions = self._invalidate_user(db, user_id, changed_at)
            self._increment_project_versions(db, affected_projects)
            event_payload = {
                **payload,
                "status": membership.status,
                "version": membership.version,
                "security_version": security_version,
                "revoked_session_count": revoked_sessions,
                "affected_project_ids": [str(value) for value in affected_projects],
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_group_membership",
                aggregate_key=f"{group_id}:{user_id}",
                event_type="group.membership.removed",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return EnterpriseGroupMembershipView(
                group_id=group_id,
                user_id=user_id,
                status="removed",
                expires_at=None,
                version=membership.version,
                security_version=security_version,
                revoked_session_count=revoked_sessions,
            )

    def change_group_members(
        self,
        request: RequestContext,
        *,
        group_id: UUID,
        mutations: list[EnterpriseGroupMembershipMutation]
        | tuple[EnterpriseGroupMembershipMutation, ...],
        idempotency_key: str,
        now: datetime | None = None,
    ) -> EnterpriseGroupMembershipBatchView:
        changed_at = now or _utcnow()
        _idempotency(idempotency_key)
        values = tuple(mutations)
        if not 1 <= len(values) <= 100:
            raise LifecycleError("group_membership_batch_size_invalid", "batch size is invalid")
        if len({value.user_id for value in values}) != len(values):
            raise LifecycleError(
                "group_membership_batch_duplicate", "each user may appear only once"
            )
        for value in values:
            if value.action not in {"add", "remove"}:
                raise LifecycleError(
                    "group_membership_batch_action_invalid", "batch action is invalid"
                )
            if value.expected_version is not None and value.expected_version < 1:
                raise LifecycleError(
                    "group_membership_version_invalid", "expected version is invalid"
                )
            if value.action == "add":
                if value.expires_at is not None and value.expires_at <= changed_at:
                    raise LifecycleError(
                        "group_membership_expiry_invalid", "expiry must be in the future"
                    )
            elif value.expires_at is not None or value.expected_version is None:
                raise LifecycleError(
                    "group_membership_batch_remove_invalid",
                    "remove requires expected_version and forbids expires_at",
                )
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "group_id": str(group_id),
            "mutations": [
                {
                    "user_id": str(value.user_id),
                    "action": value.action,
                    "expires_at": value.expires_at.isoformat() if value.expires_at else None,
                    "expected_version": value.expected_version,
                }
                for value in values
            ],
        }
        digest = _hash(payload)
        user_ids = tuple(value.user_id for value in values)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db,
                request.tenant_id,
                idempotency_key,
                "group.membership.batch.changed",
                digest,
            )
            if receipt is not None:
                return self._membership_batch_result(receipt.payload, replayed=True)
            self._require_tenant_group_admin(db, request)
            self._active_group(db, request.tenant_id, group_id, lock=True)
            tenant_memberships = {
                record.user_id: record
                for record in db.execute(
                    sa.select(TenantMembership)
                    .where(
                        TenantMembership.tenant_id == request.tenant_id,
                        TenantMembership.user_id.in_(user_ids),
                    )
                    .with_for_update()
                ).scalars()
            }
            existing = {
                record.user_id: record
                for record in db.execute(
                    sa.select(EnterpriseGroupMembershipRecord)
                    .where(
                        EnterpriseGroupMembershipRecord.tenant_id == request.tenant_id,
                        EnterpriseGroupMembershipRecord.group_id == group_id,
                        EnterpriseGroupMembershipRecord.user_id.in_(user_ids),
                    )
                    .with_for_update()
                ).scalars()
            }
            for value in values:
                membership = existing.get(value.user_id)
                if value.action == "add":
                    tenant_member = tenant_memberships.get(value.user_id)
                    if tenant_member is None or tenant_member.status != "active":
                        raise LifecycleError(
                            "group_member_invalid", "active Tenant member is required"
                        )
                    if membership is not None and membership.status == "active":
                        raise LifecycleError(
                            "group_membership_exists", "group membership is already active"
                        )
                    if (
                        membership is not None
                        and value.expected_version is not None
                        and membership.version != value.expected_version
                    ):
                        raise LifecycleError(
                            "group_membership_version_conflict", "membership changed"
                        )
                else:
                    if membership is None or membership.status != "active":
                        raise LifecycleError(
                            "group_membership_not_active", "active membership is required"
                        )
                    if membership.version != value.expected_version:
                        raise LifecycleError(
                            "group_membership_version_conflict", "membership changed"
                        )
            affected_projects = self._assigned_project_ids(
                db, request.tenant_id, group_id, changed_at
            )
            results: list[EnterpriseGroupMembershipView] = []
            event_items: list[dict[str, object]] = []
            for value in values:
                membership = existing.get(value.user_id)
                if value.action == "add":
                    if membership is None:
                        membership = EnterpriseGroupMembershipRecord(
                            tenant_id=request.tenant_id,
                            group_id=group_id,
                            user_id=value.user_id,
                            status="active",
                            expires_at=value.expires_at,
                            version=1,
                            created_by=request.actor_id,
                        )
                        db.add(membership)
                    else:
                        membership.status = "active"
                        membership.expires_at = value.expires_at
                        membership.version += 1
                        membership.created_by = request.actor_id
                    result = self._membership(membership)
                else:
                    if membership is None:  # guarded above; keeps the type checker honest
                        raise LifecycleError(
                            "group_membership_not_active", "active membership is required"
                        )
                    membership.status = "removed"
                    membership.expires_at = None
                    membership.version += 1
                    security_version, revoked_sessions = self._invalidate_user(
                        db, value.user_id, changed_at
                    )
                    result = EnterpriseGroupMembershipView(
                        group_id=group_id,
                        user_id=value.user_id,
                        status="removed",
                        expires_at=None,
                        version=membership.version,
                        security_version=security_version,
                        revoked_session_count=revoked_sessions,
                    )
                results.append(result)
                event_items.append(
                    {
                        "user_id": str(result.user_id),
                        "action": value.action,
                        "status": result.status,
                        "expires_at": result.expires_at.isoformat() if result.expires_at else None,
                        "version": result.version,
                        "security_version": result.security_version,
                        "revoked_session_count": result.revoked_session_count,
                    }
                )
            db.flush()
            self._increment_project_versions(db, affected_projects)
            event_payload = {
                **payload,
                "memberships": event_items,
                "affected_project_ids": [str(value) for value in affected_projects],
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_group_membership_batch",
                aggregate_key=str(group_id),
                event_type="group.membership.batch.changed",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return EnterpriseGroupMembershipBatchView(
                group_id=group_id,
                memberships=tuple(results),
                affected_project_ids=affected_projects,
            )

    def create_custom_role(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        name: str,
        description: str | None,
        permissions: list[str] | tuple[str, ...],
        idempotency_key: str,
    ) -> EnterpriseCustomRoleView:
        _idempotency(idempotency_key)
        cleaned_name = _clean_text(name, maximum=128, code="custom_role_name_invalid")
        cleaned_description = _clean_description(description)
        normalized = self._validate_permissions(permissions)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "name": cleaned_name,
            "description": cleaned_description,
            "permissions": list(normalized),
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "custom_role.created", digest
            )
            if receipt is not None:
                return self._role_result(receipt.payload, replayed=True)
            project = self._active_project(db, request, project_id, lock=True)
            self._require_delegable_permissions(db, request, project_id, normalized)
            role = EnterpriseCustomRoleRecord(
                id=uuid4(),
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=project_id,
                name=cleaned_name,
                description=cleaned_description,
                permissions=list(normalized),
                status="active",
                version=1,
                created_by=request.actor_id,
            )
            project.authorization_version += 1
            db.add(role)
            db.flush()
            event_payload = {
                **payload,
                "custom_role_id": str(role.id),
                "status": role.status,
                "version": role.version,
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_custom_role",
                aggregate_key=str(role.id),
                event_type="custom_role.created",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._role(role, project.authorization_version)

    def update_custom_role(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        custom_role_id: UUID,
        name: str,
        description: str | None,
        permissions: list[str] | tuple[str, ...],
        expected_version: int,
        idempotency_key: str,
    ) -> EnterpriseCustomRoleView:
        _idempotency(idempotency_key)
        cleaned_name = _clean_text(name, maximum=128, code="custom_role_name_invalid")
        cleaned_description = _clean_description(description)
        normalized = self._validate_permissions(permissions)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "custom_role_id": str(custom_role_id),
            "name": cleaned_name,
            "description": cleaned_description,
            "permissions": list(normalized),
            "expected_version": expected_version,
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "custom_role.updated", digest
            )
            if receipt is not None:
                return self._role_result(receipt.payload, replayed=True)
            project = self._active_project(db, request, project_id, lock=True)
            self._require_delegable_permissions(db, request, project_id, normalized)
            role = self._active_role(db, request, project_id, custom_role_id, lock=True)
            if role.version != expected_version:
                raise LifecycleError("custom_role_version_conflict", "custom role changed")
            role.name = cleaned_name
            role.description = cleaned_description
            role.permissions = list(normalized)
            role.version += 1
            project.authorization_version += 1
            event_payload = {
                **payload,
                "status": role.status,
                "version": role.version,
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_custom_role",
                aggregate_key=str(role.id),
                event_type="custom_role.updated",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._role(role, project.authorization_version)

    def list_custom_roles(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        after_id: UUID | None = None,
        limit: int | None = None,
    ) -> tuple[EnterpriseCustomRoleView, ...]:
        if limit is not None and not 1 <= limit <= 101:
            raise LifecycleError("page_limit_invalid", "page limit is invalid")
        decision = self._authorizer.require(
            request, action="custom_role.read", project_id=project_id
        )
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            statement = sa.select(EnterpriseCustomRoleRecord).where(
                EnterpriseCustomRoleRecord.tenant_id == request.tenant_id,
                EnterpriseCustomRoleRecord.space_id == request.space_id,
                EnterpriseCustomRoleRecord.project_id == project_id,
            )
            if after_id is not None:
                statement = statement.where(EnterpriseCustomRoleRecord.id > after_id)
            statement = statement.order_by(EnterpriseCustomRoleRecord.id)
            if limit is not None:
                statement = statement.limit(limit)
            roles = db.execute(statement).scalars()
            return tuple(
                self._role(role, decision.project_authorization_version or 1) for role in roles
            )

    def retire_custom_role(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        custom_role_id: UUID,
        expected_version: int,
        reason: str,
        idempotency_key: str,
        approval_preflight_id: UUID | None = None,
        reauthenticated_at: datetime | None = None,
        now: datetime | None = None,
    ) -> EnterpriseCustomRoleRetirementView:
        changed_at = now or _utcnow()
        _idempotency(idempotency_key)
        if approval_preflight_id is not None:
            if reauthenticated_at is None:
                raise LifecycleError("fresh_auth_required", "recent authentication is required")
            _require_fresh_auth(reauthenticated_at, changed_at)
        cleaned_reason = _clean_text(reason, maximum=512, code="custom_role_retire_reason_invalid")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "custom_role_id": str(custom_role_id),
            "expected_version": expected_version,
            "reason": cleaned_reason,
            "approval_preflight_id": (
                str(approval_preflight_id) if approval_preflight_id is not None else None
            ),
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "custom_role.retired", digest
            )
            if receipt is not None:
                return self._role_retirement_result(receipt.payload, replayed=True)
            project = self._active_project(db, request, project_id, lock=True)
            self._require_project_permissions(
                db, request, project_id, ("grant.manage", "custom_role.manage")
            )
            role = self._active_role(db, request, project_id, custom_role_id, lock=True)
            if role.version != expected_version:
                raise LifecycleError("custom_role_version_conflict", "custom role changed")
            approval = None
            if approval_preflight_id is not None:
                approval = self._require_approved_preflight(
                    db,
                    request,
                    preflight_id=approval_preflight_id,
                    operation_type="custom_role_retire",
                    target_id=custom_role_id,
                    target_version=expected_version,
                    reason=cleaned_reason,
                    now=changed_at,
                )
            assignments = tuple(
                db.execute(
                    sa.select(EnterpriseGroupRoleAssignmentRecord)
                    .where(
                        EnterpriseGroupRoleAssignmentRecord.tenant_id == request.tenant_id,
                        EnterpriseGroupRoleAssignmentRecord.space_id == request.space_id,
                        EnterpriseGroupRoleAssignmentRecord.project_id == project_id,
                        EnterpriseGroupRoleAssignmentRecord.custom_role_id == custom_role_id,
                        EnterpriseGroupRoleAssignmentRecord.status == "active",
                    )
                    .order_by(EnterpriseGroupRoleAssignmentRecord.id)
                    .with_for_update()
                ).scalars()
            )
            role.status = "retired"
            role.version += 1
            role.retired_at = changed_at
            role.retired_by = request.actor_id
            role.retire_reason = cleaned_reason
            for assignment in assignments:
                assignment.status = "revoked"
                assignment.expires_at = None
                assignment.version += 1
            project.authorization_version += 1
            if approval is not None:
                approval.status = "executed"
                approval.executed_at = changed_at
            event_payload = {
                **payload,
                "status": role.status,
                "version": role.version,
                "retired_at": changed_at.isoformat(),
                "revoked_assignment_count": len(assignments),
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_custom_role",
                aggregate_key=str(role.id),
                event_type="custom_role.retired",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return EnterpriseCustomRoleRetirementView(
                custom_role_id=role.id,
                status=role.status,
                version=role.version,
                retired_at=changed_at,
                retired_by=request.actor_id,
                retire_reason=cleaned_reason,
                revoked_assignment_count=len(assignments),
                authorization_version=project.authorization_version,
            )

    def assign_group_role(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        group_id: UUID,
        custom_role_id: UUID,
        expires_at: datetime | None,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> EnterpriseGroupRoleAssignmentView:
        changed_at = now or _utcnow()
        _idempotency(idempotency_key)
        if expires_at is not None and expires_at <= changed_at:
            raise LifecycleError("group_role_expiry_invalid", "expiry must be in the future")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "group_id": str(group_id),
            "custom_role_id": str(custom_role_id),
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "group.custom_role.assigned", digest
            )
            if receipt is not None:
                return self._assignment_result(receipt.payload, replayed=True)
            project = self._active_project(db, request, project_id, lock=True)
            self._active_group(db, request.tenant_id, group_id, lock=True)
            role = self._active_role(db, request, project_id, custom_role_id, lock=True)
            normalized = tuple(cast(list[str], role.permissions))
            self._require_delegable_permissions(db, request, project_id, normalized)
            assignment = db.execute(
                sa.select(EnterpriseGroupRoleAssignmentRecord)
                .where(
                    EnterpriseGroupRoleAssignmentRecord.tenant_id == request.tenant_id,
                    EnterpriseGroupRoleAssignmentRecord.space_id == request.space_id,
                    EnterpriseGroupRoleAssignmentRecord.project_id == project_id,
                    EnterpriseGroupRoleAssignmentRecord.group_id == group_id,
                    EnterpriseGroupRoleAssignmentRecord.custom_role_id == custom_role_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if assignment is None:
                assignment = EnterpriseGroupRoleAssignmentRecord(
                    id=uuid4(),
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    group_id=group_id,
                    custom_role_id=custom_role_id,
                    status="active",
                    expires_at=expires_at,
                    version=1,
                    created_by=request.actor_id,
                )
                db.add(assignment)
            elif assignment.status == "active":
                raise LifecycleError("group_role_assignment_exists", "assignment is active")
            else:
                assignment.status = "active"
                assignment.expires_at = expires_at
                assignment.version += 1
                assignment.created_by = request.actor_id
            project.authorization_version += 1
            db.flush()
            event_payload = {
                **payload,
                "assignment_id": str(assignment.id),
                "status": assignment.status,
                "version": assignment.version,
                "custom_role_version": role.version,
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_group_role_assignment",
                aggregate_key=str(assignment.id),
                event_type="group.custom_role.assigned",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._assignment(assignment, project.authorization_version)

    def revoke_group_role(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        assignment_id: UUID,
        expected_version: int,
        idempotency_key: str,
    ) -> EnterpriseGroupRoleAssignmentView:
        _idempotency(idempotency_key)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "assignment_id": str(assignment_id),
            "expected_version": expected_version,
        }
        digest = _hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            self._lock_tenant_writes(db, request.tenant_id)
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "group.custom_role.revoked", digest
            )
            if receipt is not None:
                return self._assignment_result(receipt.payload, replayed=True)
            project = self._active_project(db, request, project_id, lock=True)
            self._require_project_permissions(
                db, request, project_id, ("grant.manage", "custom_role.manage")
            )
            assignment = db.execute(
                sa.select(EnterpriseGroupRoleAssignmentRecord)
                .where(
                    EnterpriseGroupRoleAssignmentRecord.id == assignment_id,
                    EnterpriseGroupRoleAssignmentRecord.tenant_id == request.tenant_id,
                    EnterpriseGroupRoleAssignmentRecord.space_id == request.space_id,
                    EnterpriseGroupRoleAssignmentRecord.project_id == project_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if assignment is None or assignment.status != "active":
                raise LifecycleError(
                    "group_role_assignment_not_active", "active assignment required"
                )
            if assignment.version != expected_version:
                raise LifecycleError(
                    "group_role_assignment_version_conflict", "assignment changed"
                )
            assignment.status = "revoked"
            assignment.expires_at = None
            assignment.version += 1
            project.authorization_version += 1
            event_payload = {
                **payload,
                "group_id": str(assignment.group_id),
                "custom_role_id": str(assignment.custom_role_id),
                "status": assignment.status,
                "version": assignment.version,
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request.tenant_id,
                aggregate_type="enterprise_group_role_assignment",
                aggregate_key=str(assignment.id),
                event_type="group.custom_role.revoked",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._assignment(assignment, project.authorization_version)

    def _persist_preflight(
        self,
        db: Session,
        *,
        request: RequestContext,
        operation_type: str,
        target_id: UUID,
        target_version: int,
        reason: str,
        snapshot: dict[str, object],
        created_at: datetime,
        idempotency_key: str,
        request_hash: str,
        event_type: str,
        project_id: UUID | None = None,
    ) -> EnterpriseAccessPreflightView:
        record = EnterpriseAccessPreflightRecord(
            id=uuid4(),
            tenant_id=request.tenant_id,
            space_id=request.space_id if project_id is not None else None,
            project_id=project_id,
            operation_type=operation_type,
            target_id=target_id,
            target_version=target_version,
            requested_by=request.actor_id,
            reason=reason,
            approval_policy="different_principal",
            impact_snapshot=snapshot,
            snapshot_hash=_hash(snapshot),
            status="pending_approval",
            expires_at=created_at + _ENTERPRISE_PREFLIGHT_TTL,
        )
        db.add(record)
        db.flush()
        payload = self._preflight_payload(record)
        self._event(
            db,
            request.tenant_id,
            aggregate_type="enterprise_access_preflight",
            aggregate_key=str(record.id),
            event_type=event_type,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            payload=payload,
        )
        return self._preflight_view(record)

    def _group_archive_snapshot(
        self,
        db: Session,
        request: RequestContext,
        *,
        group_id: UUID,
        expected_version: int,
        lock: bool,
    ) -> dict[str, object]:
        group = self._active_group(db, request.tenant_id, group_id, lock=lock)
        if group.version != expected_version:
            raise LifecycleError("group_version_conflict", "group changed")
        membership_statement = (
            sa.select(EnterpriseGroupMembershipRecord)
            .where(
                EnterpriseGroupMembershipRecord.tenant_id == request.tenant_id,
                EnterpriseGroupMembershipRecord.group_id == group_id,
                EnterpriseGroupMembershipRecord.status == "active",
            )
            .order_by(EnterpriseGroupMembershipRecord.user_id)
        )
        assignment_statement = (
            sa.select(EnterpriseGroupRoleAssignmentRecord)
            .where(
                EnterpriseGroupRoleAssignmentRecord.tenant_id == request.tenant_id,
                EnterpriseGroupRoleAssignmentRecord.group_id == group_id,
                EnterpriseGroupRoleAssignmentRecord.status == "active",
            )
            .order_by(EnterpriseGroupRoleAssignmentRecord.id)
        )
        if lock:
            membership_statement = membership_statement.with_for_update()
            assignment_statement = assignment_statement.with_for_update()
        memberships = tuple(db.execute(membership_statement).scalars())
        assignments = tuple(db.execute(assignment_statement).scalars())
        user_ids = tuple(sorted({row.user_id for row in memberships}, key=str))
        project_ids = tuple(sorted({row.project_id for row in assignments}, key=str))
        users = (
            db.execute(
                sa.select(GlobalUser.id, GlobalUser.security_version)
                .where(GlobalUser.id.in_(user_ids))
                .order_by(GlobalUser.id)
            ).all()
            if user_ids
            else []
        )
        session_counts: dict[UUID, int] = {}
        if user_ids:
            for user_id, count in db.execute(
                sa.select(AuthSessionRecord.user_id, sa.func.count(AuthSessionRecord.id))
                .where(
                    AuthSessionRecord.user_id.in_(user_ids),
                    AuthSessionRecord.revoked_at.is_(None),
                )
                .group_by(AuthSessionRecord.user_id)
            ):
                session_counts[user_id] = count
        projects = (
            db.execute(
                sa.select(ProjectRecord.id, ProjectRecord.authorization_version)
                .where(ProjectRecord.id.in_(project_ids))
                .order_by(ProjectRecord.id)
            ).all()
            if project_ids
            else []
        )
        return {
            "operation_type": "group_archive",
            "tenant_id": str(request.tenant_id),
            "target_id": str(group_id),
            "target_version": group.version,
            "group": {"name": group.name, "status": group.status},
            "memberships": [
                {
                    "user_id": str(row.user_id),
                    "version": row.version,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                }
                for row in memberships
            ],
            "assignments": [
                {
                    "id": str(row.id),
                    "space_id": str(row.space_id),
                    "project_id": str(row.project_id),
                    "custom_role_id": str(row.custom_role_id),
                    "version": row.version,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                }
                for row in assignments
            ],
            "users": [
                {
                    "user_id": str(user_id),
                    "security_version": security_version,
                    "revocable_session_count": session_counts.get(user_id, 0),
                }
                for user_id, security_version in users
            ],
            "projects": [
                {"project_id": str(project_id), "authorization_version": version}
                for project_id, version in projects
            ],
            "summary": {
                "target_name": group.name,
                "removed_membership_count": len(memberships),
                "revoked_assignment_count": len(assignments),
                "invalidated_user_count": len(user_ids),
                "revoked_session_count": sum(session_counts.values()),
                "affected_project_count": len(project_ids),
                "affected_project_ids": [str(value) for value in project_ids],
            },
        }

    def _custom_role_retire_snapshot(
        self,
        db: Session,
        request: RequestContext,
        *,
        project_id: UUID,
        custom_role_id: UUID,
        expected_version: int,
        lock: bool,
    ) -> dict[str, object]:
        project = self._active_project(db, request, project_id, lock=lock)
        role = self._active_role(db, request, project_id, custom_role_id, lock=lock)
        if role.version != expected_version:
            raise LifecycleError("custom_role_version_conflict", "custom role changed")
        assignment_statement = (
            sa.select(EnterpriseGroupRoleAssignmentRecord)
            .where(
                EnterpriseGroupRoleAssignmentRecord.tenant_id == request.tenant_id,
                EnterpriseGroupRoleAssignmentRecord.space_id == request.space_id,
                EnterpriseGroupRoleAssignmentRecord.project_id == project_id,
                EnterpriseGroupRoleAssignmentRecord.custom_role_id == custom_role_id,
                EnterpriseGroupRoleAssignmentRecord.status == "active",
            )
            .order_by(EnterpriseGroupRoleAssignmentRecord.id)
        )
        if lock:
            assignment_statement = assignment_statement.with_for_update()
        assignments = tuple(db.execute(assignment_statement).scalars())
        group_ids = tuple(sorted({row.group_id for row in assignments}, key=str))
        membership_statement = (
            sa.select(EnterpriseGroupMembershipRecord)
            .where(
                EnterpriseGroupMembershipRecord.tenant_id == request.tenant_id,
                EnterpriseGroupMembershipRecord.group_id.in_(group_ids),
                EnterpriseGroupMembershipRecord.status == "active",
            )
            .order_by(
                EnterpriseGroupMembershipRecord.group_id,
                EnterpriseGroupMembershipRecord.user_id,
            )
        )
        if lock:
            membership_statement = membership_statement.with_for_update()
        memberships = tuple(db.execute(membership_statement).scalars()) if group_ids else ()
        affected_users = tuple(sorted({row.user_id for row in memberships}, key=str))
        return {
            "operation_type": "custom_role_retire",
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "target_id": str(custom_role_id),
            "target_version": role.version,
            "role": {
                "name": role.name,
                "status": role.status,
                "permissions": sorted(cast(list[str], role.permissions)),
            },
            "project_authorization_version": project.authorization_version,
            "assignments": [
                {
                    "id": str(row.id),
                    "group_id": str(row.group_id),
                    "version": row.version,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                }
                for row in assignments
            ],
            "memberships": [
                {
                    "group_id": str(row.group_id),
                    "user_id": str(row.user_id),
                    "version": row.version,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                }
                for row in memberships
            ],
            "summary": {
                "target_name": role.name,
                "permission_count": len(cast(list[str], role.permissions)),
                "revoked_assignment_count": len(assignments),
                "affected_group_count": len(group_ids),
                "affected_user_count": len(affected_users),
                "affected_group_ids": [str(value) for value in group_ids],
                "affected_user_ids": [str(value) for value in affected_users],
            },
        }

    def _snapshot_for_preflight(
        self,
        db: Session,
        request: RequestContext,
        preflight: EnterpriseAccessPreflightRecord,
        *,
        lock: bool,
    ) -> dict[str, object]:
        if preflight.operation_type == "group_archive":
            return self._group_archive_snapshot(
                db,
                request,
                group_id=preflight.target_id,
                expected_version=preflight.target_version,
                lock=lock,
            )
        if preflight.operation_type == "custom_role_retire" and preflight.project_id is not None:
            return self._custom_role_retire_snapshot(
                db,
                request,
                project_id=preflight.project_id,
                custom_role_id=preflight.target_id,
                expected_version=preflight.target_version,
                lock=lock,
            )
        raise LifecycleError("enterprise_preflight_invalid", "preflight scope is invalid")

    def _require_approved_preflight(
        self,
        db: Session,
        request: RequestContext,
        *,
        preflight_id: UUID,
        operation_type: str,
        target_id: UUID,
        target_version: int,
        reason: str,
        now: datetime,
    ) -> EnterpriseAccessPreflightRecord:
        preflight = db.execute(
            sa.select(EnterpriseAccessPreflightRecord)
            .where(
                EnterpriseAccessPreflightRecord.id == preflight_id,
                EnterpriseAccessPreflightRecord.tenant_id == request.tenant_id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if preflight is None:
            raise LifecycleError(
                "enterprise_preflight_not_found", "enterprise access preflight does not exist"
            )
        if (
            preflight.operation_type != operation_type
            or preflight.target_id != target_id
            or preflight.target_version != target_version
            or preflight.reason != reason
        ):
            raise LifecycleError(
                "enterprise_preflight_mismatch", "preflight is bound to another operation"
            )
        if preflight.requested_by != request.actor_id:
            raise LifecycleError(
                "enterprise_preflight_requester_mismatch",
                "only the requester can execute the approved operation",
            )
        if preflight.status != "approved":
            raise LifecycleError(
                "enterprise_preflight_not_approved", "approved preflight is required"
            )
        if _comparable(preflight.expires_at) <= now:
            raise LifecycleError("enterprise_preflight_expired", "preflight has expired")
        self._require_approver_still_authorized(db, request, preflight)
        current_snapshot = self._snapshot_for_preflight(db, request, preflight, lock=True)
        if _hash(current_snapshot) != preflight.snapshot_hash:
            raise LifecycleError("enterprise_preflight_stale", "enterprise access impact changed")
        return preflight

    def _require_preflight_permission(
        self,
        db: Session,
        request: RequestContext,
        preflight: EnterpriseAccessPreflightRecord,
    ) -> None:
        if preflight.operation_type == "group_archive":
            self._require_tenant_group_admin(db, request)
            return
        if (
            preflight.operation_type != "custom_role_retire"
            or preflight.space_id != request.space_id
            or preflight.project_id is None
        ):
            raise LifecycleError("enterprise_preflight_not_found", "preflight is not in scope")
        self._active_project(db, request, preflight.project_id, lock=False)
        self._require_project_permissions(
            db, request, preflight.project_id, ("grant.manage", "custom_role.manage")
        )

    def _require_approver_still_authorized(
        self,
        db: Session,
        request: RequestContext,
        preflight: EnterpriseAccessPreflightRecord,
    ) -> None:
        approver_id = preflight.approved_by
        if approver_id is None or approver_id == preflight.requested_by:
            raise LifecycleError("approval_invalid", "approval principal is invalid")
        if preflight.operation_type == "group_archive":
            row = db.execute(
                sa.select(GlobalUser, TenantMembership)
                .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
                .where(
                    GlobalUser.id == approver_id,
                    TenantMembership.tenant_id == request.tenant_id,
                )
            ).one_or_none()
            if row is None:
                raise LifecycleError("approval_invalidated", "approver is no longer authorized")
            user, membership = row
            if (
                user.status != "active"
                or membership.status != "active"
                or "group.manage" not in TENANT_ROLE_PERMISSIONS[membership.role]
            ):
                raise LifecycleError("approval_invalidated", "approver is no longer authorized")
            return
        if preflight.space_id is None or preflight.project_id is None:
            raise LifecycleError("approval_invalidated", "approval scope is invalid")
        approver_context = self._current_actor_context(
            db,
            tenant_id=request.tenant_id,
            space_id=preflight.space_id,
            actor_id=approver_id,
            project_id=preflight.project_id,
            trace_id=f"approval-recheck:{preflight.id}",
        )
        self._require_project_permissions(
            db,
            approver_context,
            preflight.project_id,
            ("grant.manage", "custom_role.manage"),
        )

    @staticmethod
    def _current_actor_context(
        db: Session,
        *,
        tenant_id: UUID,
        space_id: UUID,
        actor_id: UUID,
        project_id: UUID,
        trace_id: str,
    ) -> RequestContext:
        row = db.execute(
            sa.select(GlobalUser, TenantMembership, SpaceMembership)
            .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
            .join(
                SpaceMembership,
                sa.and_(
                    SpaceMembership.tenant_id == TenantMembership.tenant_id,
                    SpaceMembership.user_id == GlobalUser.id,
                ),
            )
            .where(
                GlobalUser.id == actor_id,
                TenantMembership.tenant_id == tenant_id,
                SpaceMembership.space_id == space_id,
            )
        ).one_or_none()
        if row is None:
            raise LifecycleError("approval_invalidated", "approver is no longer authorized")
        user, tenant_membership, space_membership = row
        if (
            user.status != "active"
            or tenant_membership.status != "active"
            or space_membership.status != "active"
        ):
            raise LifecycleError("approval_invalidated", "approver is no longer authorized")
        return RequestContext(
            actor_id=actor_id,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            user_security_version=user.security_version,
            tenant_membership_version=tenant_membership.version,
            space_membership_version=space_membership.version,
            trace_id=trace_id,
        )

    @staticmethod
    def _validate_preflight_list(*, status: str | None, limit: int | None) -> None:
        if status is not None and status not in {
            "pending_approval",
            "approved",
            "rejected",
            "executed",
        }:
            raise LifecycleError("enterprise_preflight_status_invalid", "status is invalid")
        if limit is not None and not 1 <= limit <= 101:
            raise LifecycleError("page_limit_invalid", "page limit is invalid")

    @staticmethod
    def _preflight_list_statement(
        statement: sa.Select[tuple[EnterpriseAccessPreflightRecord]],
        *,
        status: str | None,
        after_id: UUID | None,
        limit: int | None,
        exclude_expired_pending: bool,
        now: datetime | None = None,
    ) -> sa.Select[tuple[EnterpriseAccessPreflightRecord]]:
        if status is not None:
            statement = statement.where(EnterpriseAccessPreflightRecord.status == status)
        if exclude_expired_pending and status == "pending_approval":
            statement = statement.where(
                EnterpriseAccessPreflightRecord.expires_at > (now or _utcnow())
            )
        if after_id is not None:
            statement = statement.where(EnterpriseAccessPreflightRecord.id > after_id)
        statement = statement.order_by(EnterpriseAccessPreflightRecord.id)
        if limit is not None:
            statement = statement.limit(limit)
        return statement

    @staticmethod
    def _preflight_payload(record: EnterpriseAccessPreflightRecord) -> dict[str, object]:
        summary = cast(dict[str, object], record.impact_snapshot.get("summary", {}))
        return {
            "preflight_id": str(record.id),
            "tenant_id": str(record.tenant_id),
            "space_id": str(record.space_id) if record.space_id else None,
            "project_id": str(record.project_id) if record.project_id else None,
            "operation_type": record.operation_type,
            "target_id": str(record.target_id),
            "target_version": record.target_version,
            "status": record.status,
            "requested_by": str(record.requested_by),
            "approved_by": str(record.approved_by) if record.approved_by else None,
            "approval_policy": record.approval_policy,
            "reason": record.reason,
            "approval_reason": record.approval_reason,
            "impact_summary": summary,
            "snapshot_hash": record.snapshot_hash,
            "expires_at": record.expires_at.isoformat(),
            "created_at": record.created_at.isoformat(),
            "approved_at": record.approved_at.isoformat() if record.approved_at else None,
            "executed_at": record.executed_at.isoformat() if record.executed_at else None,
        }

    @classmethod
    def _preflight_view(
        cls, record: EnterpriseAccessPreflightRecord
    ) -> EnterpriseAccessPreflightView:
        return cls._preflight_result(cls._preflight_payload(record), replayed=False)

    @staticmethod
    def _preflight_result(
        payload: dict[str, object], *, replayed: bool
    ) -> EnterpriseAccessPreflightView:
        approved_by = cast(str | None, payload.get("approved_by"))
        space_id = cast(str | None, payload.get("space_id"))
        project_id = cast(str | None, payload.get("project_id"))
        created_at = cast(str | None, payload.get("created_at"))
        approved_at = cast(str | None, payload.get("approved_at"))
        executed_at = cast(str | None, payload.get("executed_at"))
        return EnterpriseAccessPreflightView(
            preflight_id=UUID(cast(str, payload["preflight_id"])),
            tenant_id=UUID(cast(str, payload["tenant_id"])),
            space_id=UUID(space_id) if space_id else None,
            project_id=UUID(project_id) if project_id else None,
            operation_type=cast(str, payload["operation_type"]),
            target_id=UUID(cast(str, payload["target_id"])),
            target_version=cast(int, payload["target_version"]),
            status=cast(str, payload["status"]),
            requested_by=UUID(cast(str, payload["requested_by"])),
            approved_by=UUID(approved_by) if approved_by else None,
            approval_policy=cast(str, payload["approval_policy"]),
            reason=cast(str | None, payload.get("reason")),
            approval_reason=cast(str | None, payload.get("approval_reason")),
            impact_summary=cast(dict[str, object], payload["impact_summary"]),
            snapshot_hash=cast(str, payload["snapshot_hash"]),
            expires_at=_comparable(datetime.fromisoformat(cast(str, payload["expires_at"]))),
            created_at=_comparable(datetime.fromisoformat(created_at)) if created_at else None,
            approved_at=_comparable(datetime.fromisoformat(approved_at)) if approved_at else None,
            executed_at=_comparable(datetime.fromisoformat(executed_at)) if executed_at else None,
            replayed=replayed,
        )

    @staticmethod
    def _validate_permissions(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(values)))
        if not normalized or len(normalized) > 64:
            raise LifecycleError("custom_role_permissions_invalid", "permissions are invalid")
        for value in normalized:
            definition = PERMISSION_CATALOG.get(value)
            if definition is None or definition.scope != PermissionScope.PROJECT:
                raise LifecycleError(
                    "custom_role_permission_not_allowed", "permission is not Project-scoped"
                )
            if definition.risk == PermissionRisk.CRITICAL or value in {
                "grant.manage",
                "custom_role.manage",
            }:
                raise LifecycleError(
                    "custom_role_permission_not_allowed",
                    "critical and delegation-management permissions are not customizable",
                )
        return normalized

    def _require_delegable_permissions(
        self,
        db: Session,
        request: RequestContext,
        project_id: UUID,
        permissions: tuple[str, ...],
    ) -> None:
        self._require_project_permissions(
            db,
            request,
            project_id,
            ("grant.manage", "custom_role.manage", *permissions),
        )

    def _require_project_permissions(
        self,
        db: Session,
        request: RequestContext,
        project_id: UUID,
        permissions: tuple[str, ...],
    ) -> None:
        for permission in permissions:
            decision = self._authorizer.evaluate_in_session(
                db, request, action=permission, project_id=project_id, mode="enforce"
            )
            if not decision.allowed:
                raise LifecycleError("permission_not_granted", "delegated permission is not held")

    @staticmethod
    def _apply_context(db: Session, request: RequestContext) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
            ),
        )

    @staticmethod
    def _lock_tenant_writes(db: Session, tenant_id: UUID) -> None:
        if db.get_bind().dialect.name != "postgresql":
            return
        lock_key = int.from_bytes(
            sha256(f"enterprise-access:{tenant_id}".encode()).digest()[:8],
            byteorder="big",
            signed=True,
        )
        db.execute(
            sa.text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": lock_key},
        )

    @staticmethod
    def _require_tenant_member_snapshot(db: Session, request: RequestContext) -> TenantMembership:
        row = db.execute(
            sa.select(GlobalUser, Tenant, TenantMembership, Space, SpaceMembership)
            .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
            .join(Tenant, Tenant.id == TenantMembership.tenant_id)
            .join(
                Space,
                sa.and_(Space.tenant_id == Tenant.id, Space.id == request.space_id),
            )
            .join(
                SpaceMembership,
                sa.and_(
                    SpaceMembership.tenant_id == Tenant.id,
                    SpaceMembership.space_id == Space.id,
                    SpaceMembership.user_id == GlobalUser.id,
                ),
            )
            .where(GlobalUser.id == request.actor_id, Tenant.id == request.tenant_id)
        ).one_or_none()
        if row is None:
            raise LifecycleError("scope_not_authorized", "scope is not accessible")
        user, tenant, membership, space, space_membership = row
        if (
            user.status != "active"
            or tenant.status not in {"trial", "active"}
            or membership.status != "active"
            or space.status != "active"
            or space_membership.status != "active"
        ):
            raise LifecycleError("scope_not_authorized", "scope is not active")
        if (
            user.security_version != request.user_security_version
            or membership.version != request.tenant_membership_version
            or space_membership.version != request.space_membership_version
        ):
            raise LifecycleError("authorization_snapshot_stale", "authorization changed")
        return membership

    @classmethod
    def _require_tenant_group_admin(cls, db: Session, request: RequestContext) -> None:
        membership = cls._require_tenant_member_snapshot(db, request)
        if "group.manage" not in TENANT_ROLE_PERMISSIONS[membership.role]:
            raise LifecycleError("group_manage_forbidden", "Tenant Owner or Admin is required")

    @staticmethod
    def _active_group(
        db: Session, tenant_id: UUID, group_id: UUID, *, lock: bool
    ) -> EnterpriseGroupRecord:
        statement = sa.select(EnterpriseGroupRecord).where(
            EnterpriseGroupRecord.id == group_id,
            EnterpriseGroupRecord.tenant_id == tenant_id,
            EnterpriseGroupRecord.status == "active",
        )
        if lock:
            statement = statement.with_for_update()
        group = db.execute(statement).scalar_one_or_none()
        if group is None:
            raise LifecycleError("group_not_active", "active group is required")
        return group

    @staticmethod
    def _active_project(
        db: Session, request: RequestContext, project_id: UUID, *, lock: bool
    ) -> ProjectRecord:
        statement = sa.select(ProjectRecord).where(
            ProjectRecord.id == project_id,
            ProjectRecord.tenant_id == request.tenant_id,
            ProjectRecord.space_id == request.space_id,
            ProjectRecord.status == "active",
        )
        if lock:
            statement = statement.with_for_update()
        project = db.execute(statement).scalar_one_or_none()
        if project is None:
            raise LifecycleError("project_not_active", "active Project is required")
        return project

    @staticmethod
    def _active_role(
        db: Session,
        request: RequestContext,
        project_id: UUID,
        custom_role_id: UUID,
        *,
        lock: bool,
    ) -> EnterpriseCustomRoleRecord:
        statement = sa.select(EnterpriseCustomRoleRecord).where(
            EnterpriseCustomRoleRecord.id == custom_role_id,
            EnterpriseCustomRoleRecord.tenant_id == request.tenant_id,
            EnterpriseCustomRoleRecord.space_id == request.space_id,
            EnterpriseCustomRoleRecord.project_id == project_id,
            EnterpriseCustomRoleRecord.status == "active",
        )
        if lock:
            statement = statement.with_for_update()
        role = db.execute(statement).scalar_one_or_none()
        if role is None:
            raise LifecycleError("custom_role_not_active", "active custom role is required")
        return role

    @staticmethod
    def _assigned_project_ids(
        db: Session, tenant_id: UUID, group_id: UUID, now: datetime
    ) -> tuple[UUID, ...]:
        values = db.execute(
            sa.select(EnterpriseGroupRoleAssignmentRecord.project_id)
            .where(
                EnterpriseGroupRoleAssignmentRecord.tenant_id == tenant_id,
                EnterpriseGroupRoleAssignmentRecord.group_id == group_id,
                EnterpriseGroupRoleAssignmentRecord.status == "active",
                sa.or_(
                    EnterpriseGroupRoleAssignmentRecord.expires_at.is_(None),
                    EnterpriseGroupRoleAssignmentRecord.expires_at > now,
                ),
            )
            .distinct()
        ).scalars()
        return tuple(sorted(values, key=str))

    @staticmethod
    def _increment_project_versions(db: Session, project_ids: tuple[UUID, ...]) -> None:
        if project_ids:
            db.execute(
                sa.update(ProjectRecord)
                .where(ProjectRecord.id.in_(project_ids))
                .values(authorization_version=ProjectRecord.authorization_version + 1)
                .execution_options(synchronize_session=False)
            )

    @staticmethod
    def _invalidate_user(db: Session, user_id: UUID, changed_at: datetime) -> tuple[int, int]:
        security_version = db.execute(
            sa.update(GlobalUser)
            .where(GlobalUser.id == user_id)
            .values(security_version=GlobalUser.security_version + 1)
            .returning(GlobalUser.security_version)
            .execution_options(synchronize_session=False)
        ).scalar_one_or_none()
        if security_version is None:
            raise LifecycleError("group_member_invalid", "group member user is missing")
        result = cast(
            CursorResult[tuple[object]],
            db.execute(
                sa.update(AuthSessionRecord)
                .where(
                    AuthSessionRecord.user_id == user_id,
                    AuthSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=changed_at)
                .execution_options(synchronize_session=False)
            ),
        )
        return security_version, result.rowcount

    @staticmethod
    def _receipt(
        db: Session,
        tenant_id: UUID,
        idempotency_key: str,
        event_type: str,
        request_hash: str,
    ) -> ControlPlaneOutboxEvent | None:
        receipt = db.execute(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key
                == scoped_idempotency_key("tenant", tenant_id, idempotency_key)
            )
        ).scalar_one_or_none()
        if receipt is not None and (
            receipt.event_type != event_type or receipt.request_hash != request_hash
        ):
            raise LifecycleError(
                "idempotency_conflict", "idempotency key belongs to another request"
            )
        return receipt

    @staticmethod
    def _event(
        db: Session,
        tenant_id: UUID,
        *,
        aggregate_type: str,
        aggregate_key: str,
        event_type: str,
        idempotency_key: str,
        request_hash: str,
        payload: dict[str, object],
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=tenant_id,
                aggregate_type=aggregate_type,
                aggregate_key=aggregate_key,
                event_type=event_type,
                idempotency_key=scoped_idempotency_key("tenant", tenant_id, idempotency_key),
                request_hash=request_hash,
                payload=payload,
                attempt_count=0,
            )
        )

    @staticmethod
    def _group(record: EnterpriseGroupRecord) -> EnterpriseGroupView:
        return EnterpriseGroupView(
            id=record.id,
            tenant_id=record.tenant_id,
            name=record.name,
            description=record.description,
            status=record.status,
            version=record.version,
        )

    @staticmethod
    def _group_result(payload: dict[str, object], *, replayed: bool) -> EnterpriseGroupView:
        return EnterpriseGroupView(
            id=UUID(cast(str, payload["group_id"])),
            tenant_id=UUID(cast(str, payload["tenant_id"])),
            name=cast(str, payload["name"]),
            description=cast(str | None, payload.get("description")),
            status=cast(str, payload["status"]),
            version=cast(int, payload["version"]),
            replayed=replayed,
        )

    @staticmethod
    def _membership(
        record: EnterpriseGroupMembershipRecord,
    ) -> EnterpriseGroupMembershipView:
        return EnterpriseGroupMembershipView(
            group_id=record.group_id,
            user_id=record.user_id,
            status=record.status,
            expires_at=record.expires_at,
            version=record.version,
        )

    @staticmethod
    def _membership_result(
        payload: dict[str, object], *, replayed: bool
    ) -> EnterpriseGroupMembershipView:
        expires_at = cast(str | None, payload.get("expires_at"))
        return EnterpriseGroupMembershipView(
            group_id=UUID(cast(str, payload["group_id"])),
            user_id=UUID(cast(str, payload["user_id"])),
            status=cast(str, payload["status"]),
            expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
            version=cast(int, payload["version"]),
            security_version=cast(int | None, payload.get("security_version")),
            revoked_session_count=cast(int, payload.get("revoked_session_count", 0)),
            replayed=replayed,
        )

    @classmethod
    def _membership_batch_result(
        cls, payload: dict[str, object], *, replayed: bool
    ) -> EnterpriseGroupMembershipBatchView:
        memberships = tuple(
            cls._membership_result(
                {
                    "group_id": payload["group_id"],
                    **item,
                },
                replayed=replayed,
            )
            for item in cast(list[dict[str, object]], payload["memberships"])
        )
        return EnterpriseGroupMembershipBatchView(
            group_id=UUID(cast(str, payload["group_id"])),
            memberships=memberships,
            affected_project_ids=tuple(
                UUID(value) for value in cast(list[str], payload["affected_project_ids"])
            ),
            replayed=replayed,
        )

    @staticmethod
    def _group_archive_result(
        payload: dict[str, object], *, replayed: bool
    ) -> EnterpriseGroupArchiveView:
        return EnterpriseGroupArchiveView(
            group_id=UUID(cast(str, payload["group_id"])),
            status=cast(str, payload["status"]),
            version=cast(int, payload["version"]),
            archived_at=datetime.fromisoformat(cast(str, payload["archived_at"])),
            archived_by=UUID(cast(str, payload["actor_id"])),
            archive_reason=cast(str, payload["reason"]),
            removed_membership_count=cast(int, payload["removed_membership_count"]),
            revoked_assignment_count=cast(int, payload["revoked_assignment_count"]),
            invalidated_user_count=cast(int, payload["invalidated_user_count"]),
            revoked_session_count=cast(int, payload["revoked_session_count"]),
            affected_project_ids=tuple(
                UUID(value) for value in cast(list[str], payload["affected_project_ids"])
            ),
            replayed=replayed,
        )

    @staticmethod
    def _role(
        record: EnterpriseCustomRoleRecord, authorization_version: int
    ) -> EnterpriseCustomRoleView:
        return EnterpriseCustomRoleView(
            id=record.id,
            tenant_id=record.tenant_id,
            space_id=record.space_id,
            project_id=record.project_id,
            name=record.name,
            description=record.description,
            permissions=tuple(cast(list[str], record.permissions)),
            status=record.status,
            version=record.version,
            authorization_version=authorization_version,
        )

    @staticmethod
    def _role_result(payload: dict[str, object], *, replayed: bool) -> EnterpriseCustomRoleView:
        return EnterpriseCustomRoleView(
            id=UUID(cast(str, payload["custom_role_id"])),
            tenant_id=UUID(cast(str, payload["tenant_id"])),
            space_id=UUID(cast(str, payload["space_id"])),
            project_id=UUID(cast(str, payload["project_id"])),
            name=cast(str, payload["name"]),
            description=cast(str | None, payload.get("description")),
            permissions=tuple(cast(list[str], payload["permissions"])),
            status=cast(str, payload["status"]),
            version=cast(int, payload["version"]),
            authorization_version=cast(int, payload["authorization_version"]),
            replayed=replayed,
        )

    @staticmethod
    def _role_retirement_result(
        payload: dict[str, object], *, replayed: bool
    ) -> EnterpriseCustomRoleRetirementView:
        return EnterpriseCustomRoleRetirementView(
            custom_role_id=UUID(cast(str, payload["custom_role_id"])),
            status=cast(str, payload["status"]),
            version=cast(int, payload["version"]),
            retired_at=datetime.fromisoformat(cast(str, payload["retired_at"])),
            retired_by=UUID(cast(str, payload["actor_id"])),
            retire_reason=cast(str, payload["reason"]),
            revoked_assignment_count=cast(int, payload["revoked_assignment_count"]),
            authorization_version=cast(int, payload["authorization_version"]),
            replayed=replayed,
        )

    @staticmethod
    def _assignment(
        record: EnterpriseGroupRoleAssignmentRecord, authorization_version: int
    ) -> EnterpriseGroupRoleAssignmentView:
        return EnterpriseGroupRoleAssignmentView(
            id=record.id,
            tenant_id=record.tenant_id,
            space_id=record.space_id,
            project_id=record.project_id,
            group_id=record.group_id,
            custom_role_id=record.custom_role_id,
            status=record.status,
            expires_at=record.expires_at,
            version=record.version,
            authorization_version=authorization_version,
        )

    @staticmethod
    def _assignment_result(
        payload: dict[str, object], *, replayed: bool
    ) -> EnterpriseGroupRoleAssignmentView:
        expires_at = cast(str | None, payload.get("expires_at"))
        return EnterpriseGroupRoleAssignmentView(
            id=UUID(cast(str, payload["assignment_id"])),
            tenant_id=UUID(cast(str, payload["tenant_id"])),
            space_id=UUID(cast(str, payload["space_id"])),
            project_id=UUID(cast(str, payload["project_id"])),
            group_id=UUID(cast(str, payload["group_id"])),
            custom_role_id=UUID(cast(str, payload["custom_role_id"])),
            status=cast(str, payload["status"]),
            expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
            version=cast(int, payload["version"]),
            authorization_version=cast(int, payload["authorization_version"]),
            replayed=replayed,
        )
