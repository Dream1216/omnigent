"""Enterprise groups and project-scoped custom-role governance."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
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
            receipt = self._receipt(
                db, request.tenant_id, idempotency_key, "group.membership.added", digest
            )
            if receipt is not None:
                return self._membership_result(receipt.payload, replayed=True)
            self._require_tenant_group_admin(db, request)
            self._active_group(db, request.tenant_id, group_id, lock=True)
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
            event_payload = {
                **payload,
                "status": membership.status,
                "version": membership.version,
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
            .where(GlobalUser.id == user_id, GlobalUser.status == "active")
            .values(security_version=GlobalUser.security_version + 1)
            .returning(GlobalUser.security_version)
            .execution_options(synchronize_session=False)
        ).scalar_one_or_none()
        if security_version is None:
            raise LifecycleError("group_member_invalid", "active user is required")
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
