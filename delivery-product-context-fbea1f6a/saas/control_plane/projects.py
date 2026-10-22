"""Transactional Project administration and scoped-grant lifecycle."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    ResourceGrantRecord,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.permissions import (
    PROJECT_ROLE_PERMISSIONS,
    RESOURCE_ROLE_PERMISSIONS,
    SPACE_ROLE_PERMISSIONS,
    TENANT_ROLE_PERMISSIONS,
)
from saas.control_plane.rls import RlsContext, apply_rls_context


@dataclass(frozen=True, slots=True)
class ProjectCreated:
    project_id: UUID
    authorization_version: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class ProjectChanged:
    project_id: UUID
    authorization_version: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class ScopedGrantChanged:
    project_id: UUID
    grant_id: UUID | None
    subject_type: str
    subject_id: UUID
    role: str
    status: str
    authorization_version: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class ProjectMetadata:
    project_id: UUID
    tenant_id: UUID
    space_id: UUID
    name: str
    visibility: str
    status: str
    authorization_version: int


@dataclass(frozen=True, slots=True)
class _ScopeRoles:
    user_status: str
    security_version: int
    tenant_status: str
    tenant_membership_status: str
    tenant_membership_version: int
    tenant_role: str
    space_status: str
    space_membership_status: str
    space_membership_version: int
    space_role: str


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _request_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


def _validate_idempotency_key(value: str) -> None:
    if not value or len(value) > 128:
        raise LifecycleError("invalid_idempotency_key", "idempotency key is invalid")


def _validate_subject(subject_type: str, subject_id: UUID, space_id: UUID) -> None:
    if subject_type not in {"user", "space"}:
        raise LifecycleError("grant_subject_invalid", "grant subject is invalid")
    if subject_type == "space" and subject_id != space_id:
        raise LifecycleError("grant_subject_invalid", "Space grant must target its own Space")


class ProjectAdministrationService:
    """Own Project mutations; each authorization change increments one version."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        authorizer: ProjectAuthorizer | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._authorizer = authorizer or ProjectAuthorizer(session_factory)

    def get_project_metadata(
        self, request: RequestContext, *, project_id: UUID
    ) -> ProjectMetadata:
        """Return non-content metadata only after an explicit Project decision."""

        self._authorizer.require(request, action="project.read_metadata", project_id=project_id)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            project = self._project(db, request, project_id, lock=False)
            return self._metadata(project)

    def list_project_metadata(self, request: RequestContext) -> tuple[ProjectMetadata, ...]:
        """Filter Space projects through Authorizer without leaking inaccessible rows."""

        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            project_ids = tuple(
                db.execute(
                    sa.select(ProjectRecord.id).where(
                        ProjectRecord.tenant_id == request.tenant_id,
                        ProjectRecord.space_id == request.space_id,
                        ProjectRecord.status == "active",
                    )
                ).scalars()
            )
        visible: list[ProjectMetadata] = []
        for project_id in project_ids:
            decision = self._authorizer.evaluate(
                request,
                action="project.read_metadata",
                project_id=project_id,
                mode="enforce",
            )
            if decision.allowed:
                with self._session_factory.begin() as db:
                    self._apply_context(db, request)
                    project = self._project(db, request, project_id, lock=False)
                    visible.append(self._metadata(project))
        return tuple(visible)

    def create_project(
        self,
        request: RequestContext,
        *,
        name: str,
        visibility: str,
        idempotency_key: str,
    ) -> ProjectCreated:
        """Create a Project and its non-orphanable creator Owner membership atomically."""

        _validate_idempotency_key(idempotency_key)
        cleaned_name = name.strip()
        if not cleaned_name or len(cleaned_name) > 256:
            raise LifecycleError("project_name_invalid", "project name is invalid")
        if visibility not in {"private", "space", "restricted"}:
            raise LifecycleError("project_visibility_invalid", "project visibility is invalid")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "name": cleaned_name,
            "visibility": visibility,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            receipt = self._receipt(db, request, idempotency_key, "project.created", digest)
            if receipt is not None:
                return ProjectCreated(
                    project_id=UUID(cast(str, receipt.payload["project_id"])),
                    authorization_version=cast(int, receipt.payload["authorization_version"]),
                    replayed=True,
                )
            self._require_space_permission(db, request, "project.create")
            project_id = uuid4()
            db.add(
                ProjectRecord(
                    id=project_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    name=cleaned_name,
                    visibility=visibility,
                    created_by=request.actor_id,
                    status="active",
                    authorization_version=1,
                )
            )
            db.flush()
            db.add(
                ProjectMembershipRecord(
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    subject_type="user",
                    subject_id=request.actor_id,
                    role="owner",
                    status="active",
                    created_by=request.actor_id,
                    version=1,
                )
            )
            event_payload: dict[str, object] = {
                **payload,
                "project_id": str(project_id),
                "authorization_version": 1,
            }
            self._event(
                db,
                request,
                aggregate_key=str(project_id),
                event_type="project.created",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return ProjectCreated(project_id, 1, False)

    def update_visibility(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        visibility: str,
        expected_authorization_version: int,
        idempotency_key: str,
    ) -> ProjectChanged:
        """Change visibility under optimistic concurrency and invalidate cached decisions."""

        _validate_idempotency_key(idempotency_key)
        if visibility not in {"private", "space", "restricted"}:
            raise LifecycleError("project_visibility_invalid", "project visibility is invalid")
        self._authorizer.require(request, action="project.update", project_id=project_id)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "visibility": visibility,
            "expected_authorization_version": expected_authorization_version,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            receipt = self._receipt(
                db, request, idempotency_key, "project.visibility.updated", digest
            )
            if receipt is not None:
                return ProjectChanged(
                    project_id=project_id,
                    authorization_version=cast(int, receipt.payload["authorization_version"]),
                    replayed=True,
                )
            project = self._project(db, request, project_id, lock=True)
            if project.authorization_version != expected_authorization_version:
                raise LifecycleError(
                    "project_version_conflict", "Project authorization facts changed concurrently"
                )
            project.visibility = visibility
            project.authorization_version += 1
            self._event(
                db,
                request,
                aggregate_key=str(project_id),
                event_type="project.visibility.updated",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload={**payload, "authorization_version": project.authorization_version},
            )
            return ProjectChanged(project_id, project.authorization_version, False)

    def set_project_membership(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        subject_type: str,
        subject_id: UUID,
        role: str,
        expires_at: datetime | None,
        idempotency_key: str,
    ) -> ScopedGrantChanged:
        """Create or replace one Project role after verifying delegation scope."""

        _validate_idempotency_key(idempotency_key)
        _validate_subject(subject_type, subject_id, request.space_id)
        if role not in {"owner", "manage", "operate", "edit", "read"}:
            raise LifecycleError("project_role_invalid", "Project role is invalid")
        if role == "owner" and (subject_type != "user" or expires_at is not None):
            raise LifecycleError(
                "project_owner_grant_invalid",
                "Project Owner must be a non-expiring user membership",
            )
        if expires_at is not None and expires_at <= _utcnow():
            raise LifecycleError("grant_expiry_invalid", "grant expiry must be in the future")
        self._authorizer.require(request, action="grant.manage", project_id=project_id)
        self._require_delegable_role(request, project_id=project_id, role=role)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "subject_type": subject_type,
            "subject_id": str(subject_id),
            "role": role,
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            receipt = self._receipt(db, request, idempotency_key, "project.membership.set", digest)
            if receipt is not None:
                return self._grant_result(receipt, replayed=True)
            project = self._project(db, request, project_id, lock=True)
            self._require_subject_membership(db, request, subject_type, subject_id)
            membership = db.get(
                ProjectMembershipRecord,
                (project_id, subject_type, subject_id),
            )
            if membership is None:
                membership = ProjectMembershipRecord(
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    subject_type=subject_type,
                    subject_id=subject_id,
                    role=role,
                    status="active",
                    expires_at=expires_at,
                    created_by=request.actor_id,
                    version=1,
                )
                db.add(membership)
            else:
                membership.role = role
                membership.status = "active"
                membership.expires_at = expires_at
                membership.version += 1
            project.authorization_version += 1
            event_payload: dict[str, object] = {
                **payload,
                "grant_id": None,
                "status": "active",
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request,
                aggregate_key=str(project_id),
                event_type="project.membership.set",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._grant_result_payload(event_payload, replayed=False)

    def revoke_project_membership(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        subject_type: str,
        subject_id: UUID,
        idempotency_key: str,
    ) -> ScopedGrantChanged:
        """Revoke a Project role while preserving the last-Owner invariant."""

        _validate_idempotency_key(idempotency_key)
        _validate_subject(subject_type, subject_id, request.space_id)
        self._authorizer.require(request, action="grant.manage", project_id=project_id)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "subject_type": subject_type,
            "subject_id": str(subject_id),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            receipt = self._receipt(
                db, request, idempotency_key, "project.membership.revoked", digest
            )
            if receipt is not None:
                return self._grant_result(receipt, replayed=True)
            project = self._project(db, request, project_id, lock=True)
            membership = db.execute(
                sa.select(ProjectMembershipRecord)
                .where(
                    ProjectMembershipRecord.project_id == project_id,
                    ProjectMembershipRecord.subject_type == subject_type,
                    ProjectMembershipRecord.subject_id == subject_id,
                    ProjectMembershipRecord.status == "active",
                )
                .with_for_update()
            ).scalar_one_or_none()
            if membership is None:
                raise LifecycleError("project_membership_not_active", "active grant is required")
            self._require_delegable_role_in_session(
                db,
                request,
                project_id=project_id,
                role=membership.role,
            )
            if membership.role == "owner":
                owners = db.execute(
                    sa.select(sa.func.count())
                    .select_from(ProjectMembershipRecord)
                    .where(
                        ProjectMembershipRecord.project_id == project_id,
                        ProjectMembershipRecord.role == "owner",
                        ProjectMembershipRecord.status == "active",
                        sa.or_(
                            ProjectMembershipRecord.expires_at.is_(None),
                            ProjectMembershipRecord.expires_at > _utcnow(),
                        ),
                    )
                ).scalar_one()
                if owners <= 1:
                    raise LifecycleError(
                        "last_project_owner", "last active Project Owner cannot be removed"
                    )
            membership.status = "revoked"
            membership.version += 1
            project.authorization_version += 1
            event_payload: dict[str, object] = {
                **payload,
                "grant_id": None,
                "role": membership.role,
                "status": "revoked",
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request,
                aggregate_key=str(project_id),
                event_type="project.membership.revoked",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._grant_result_payload(event_payload, replayed=False)

    def revoke_resource_grant(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        grant_id: UUID,
        idempotency_key: str,
    ) -> ScopedGrantChanged:
        """Revoke one exact Resource Grant without accepting client-owned selectors."""

        _validate_idempotency_key(idempotency_key)
        self._authorizer.require(request, action="grant.manage", project_id=project_id)
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "grant_id": str(grant_id),
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            receipt = self._receipt(db, request, idempotency_key, "resource.grant.revoked", digest)
            if receipt is not None:
                return self._grant_result(receipt, replayed=True)
            project = self._project(db, request, project_id, lock=True)
            grant = db.execute(
                sa.select(ResourceGrantRecord)
                .where(
                    ResourceGrantRecord.id == grant_id,
                    ResourceGrantRecord.tenant_id == request.tenant_id,
                    ResourceGrantRecord.space_id == request.space_id,
                    ResourceGrantRecord.project_id == project_id,
                    ResourceGrantRecord.status == "active",
                )
                .with_for_update()
            ).scalar_one_or_none()
            if grant is None:
                raise LifecycleError("resource_grant_not_active", "active grant is required")
            self._require_delegable_role_in_session(
                db,
                request,
                project_id=project_id,
                role=grant.role,
                resource_type=grant.resource_type,
                resource_id=grant.resource_id,
            )
            grant.status = "revoked"
            grant.version += 1
            project.authorization_version += 1
            event_payload: dict[str, object] = {
                **payload,
                "resource_type": grant.resource_type,
                "resource_id": str(grant.resource_id),
                "subject_type": grant.subject_type,
                "subject_id": str(grant.subject_id),
                "role": grant.role,
                "status": "revoked",
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request,
                aggregate_key=str(grant.resource_id),
                event_type="resource.grant.revoked",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._grant_result_payload(event_payload, replayed=False)

    def set_resource_grant(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        resource_type: str,
        resource_id: UUID,
        subject_type: str,
        subject_id: UUID,
        role: str,
        expires_at: datetime | None,
        idempotency_key: str,
    ) -> ScopedGrantChanged:
        """Add a role for exactly one resource without widening Project membership."""

        _validate_idempotency_key(idempotency_key)
        _validate_subject(subject_type, subject_id, request.space_id)
        cleaned_type = resource_type.strip()
        if not cleaned_type or len(cleaned_type) > 64:
            raise LifecycleError("resource_type_invalid", "resource type is invalid")
        if role not in {"owner", "manage", "operate", "edit", "read"}:
            raise LifecycleError("project_role_invalid", "Project role is invalid")
        resource_roles = RESOURCE_ROLE_PERMISSIONS.get(cleaned_type)
        if resource_roles is None:
            raise LifecycleError(
                "resource_type_unsupported", "resource type has no reviewed permission mapping"
            )
        if not resource_roles[role]:
            raise LifecycleError(
                "resource_role_has_no_effect", "role grants no permissions for resource type"
            )
        if expires_at is not None and expires_at <= _utcnow():
            raise LifecycleError("grant_expiry_invalid", "grant expiry must be in the future")
        self._authorizer.require(request, action="grant.manage", project_id=project_id)
        self._require_delegable_role(
            request,
            project_id=project_id,
            role=role,
            resource_type=cleaned_type,
            resource_id=resource_id,
        )
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "resource_type": cleaned_type,
            "resource_id": str(resource_id),
            "subject_type": subject_type,
            "subject_id": str(subject_id),
            "role": role,
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
        digest = _request_hash(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            receipt = self._receipt(db, request, idempotency_key, "resource.grant.set", digest)
            if receipt is not None:
                return self._grant_result(receipt, replayed=True)
            project = self._project(db, request, project_id, lock=True)
            self._require_subject_membership(db, request, subject_type, subject_id)
            grant = (
                db.execute(
                    sa.select(ResourceGrantRecord)
                    .where(
                        ResourceGrantRecord.tenant_id == request.tenant_id,
                        ResourceGrantRecord.space_id == request.space_id,
                        ResourceGrantRecord.project_id == project_id,
                        ResourceGrantRecord.resource_type == cleaned_type,
                        ResourceGrantRecord.resource_id == resource_id,
                        ResourceGrantRecord.subject_type == subject_type,
                        ResourceGrantRecord.subject_id == subject_id,
                    )
                    .order_by(ResourceGrantRecord.version.desc())
                )
                .scalars()
                .first()
            )
            if grant is None:
                grant = ResourceGrantRecord(
                    id=uuid4(),
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    resource_type=cleaned_type,
                    resource_id=resource_id,
                    subject_type=subject_type,
                    subject_id=subject_id,
                    role=role,
                    status="active",
                    expires_at=expires_at,
                    created_by=request.actor_id,
                    version=1,
                )
                db.add(grant)
            else:
                grant.role = role
                grant.status = "active"
                grant.expires_at = expires_at
                grant.version += 1
            project.authorization_version += 1
            event_payload: dict[str, object] = {
                **payload,
                "grant_id": str(grant.id),
                "status": "active",
                "authorization_version": project.authorization_version,
            }
            self._event(
                db,
                request,
                aggregate_key=str(resource_id),
                event_type="resource.grant.set",
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=event_payload,
            )
            return self._grant_result_payload(event_payload, replayed=False)

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
    def _receipt(
        db: Session,
        request: RequestContext,
        idempotency_key: str,
        event_type: str,
        request_hash: str,
    ) -> ControlPlaneOutboxEvent | None:
        receipt_key = scoped_idempotency_key("tenant", request.tenant_id, idempotency_key)
        receipt = db.execute(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key == receipt_key
            )
        ).scalar_one_or_none()
        if receipt is not None and (
            receipt.event_type != event_type or receipt.request_hash != request_hash
        ):
            raise LifecycleError("idempotency_conflict", "idempotency key was already used")
        return receipt

    @staticmethod
    def _event(
        db: Session,
        request: RequestContext,
        *,
        aggregate_key: str,
        event_type: str,
        idempotency_key: str,
        request_hash: str,
        payload: dict[str, object],
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=request.tenant_id,
                aggregate_type="project",
                aggregate_key=aggregate_key,
                event_type=event_type,
                payload=payload,
                idempotency_key=scoped_idempotency_key(
                    "tenant", request.tenant_id, idempotency_key
                ),
                request_hash=request_hash,
                attempt_count=0,
            )
        )

    @staticmethod
    def _project(
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
            raise LifecycleError("resource_not_accessible", "resource is not accessible")
        return project

    @staticmethod
    def _load_scope_roles(db: Session, request: RequestContext) -> _ScopeRoles | None:
        row = db.execute(
            sa.select(
                GlobalUser.status,
                GlobalUser.security_version,
                Tenant.status,
                TenantMembership.status,
                TenantMembership.version,
                TenantMembership.role,
                Space.status,
                SpaceMembership.status,
                SpaceMembership.version,
                SpaceMembership.role,
            )
            .join(TenantMembership, TenantMembership.user_id == GlobalUser.id)
            .join(Tenant, Tenant.id == TenantMembership.tenant_id)
            .join(Space, sa.and_(Space.tenant_id == Tenant.id, Space.id == request.space_id))
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
        return _ScopeRoles(*row) if row is not None else None

    def _require_space_permission(
        self, db: Session, request: RequestContext, permission: str
    ) -> None:
        facts = self._load_scope_roles(db, request)
        if facts is None:
            raise LifecycleError("scope_not_authorized", "resource is not accessible")
        if (
            facts.user_status != "active"
            or facts.tenant_status not in {"trial", "active"}
            or facts.tenant_membership_status != "active"
            or facts.space_status != "active"
            or facts.space_membership_status != "active"
        ):
            raise LifecycleError("scope_not_active", "resource is not accessible")
        if (
            facts.security_version != request.user_security_version
            or facts.tenant_membership_version != request.tenant_membership_version
            or facts.space_membership_version != request.space_membership_version
        ):
            raise LifecycleError("authorization_snapshot_stale", "resource is not accessible")
        permissions = (
            TENANT_ROLE_PERMISSIONS[facts.tenant_role] | SPACE_ROLE_PERMISSIONS[facts.space_role]
        )
        if permission not in permissions:
            raise LifecycleError("permission_not_granted", "resource is not accessible")

    def _require_delegable_role(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        role: str,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
    ) -> None:
        permissions = self._delegated_permissions(role, resource_type)
        for permission in permissions:
            decision = self._authorizer.evaluate(
                request,
                action=permission,
                project_id=project_id,
                resource_type=resource_type,
                resource_id=resource_id,
                mode="enforce",
            )
            if not decision.allowed:
                raise LifecycleError(
                    "delegation_scope_exceeded",
                    "requested role exceeds the caller's delegable permissions",
                )

    def _require_delegable_role_in_session(
        self,
        db: Session,
        request: RequestContext,
        *,
        project_id: UUID,
        role: str,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
    ) -> None:
        permissions = self._delegated_permissions(role, resource_type)
        for permission in permissions:
            decision = self._authorizer.evaluate_in_session(
                db,
                request,
                action=permission,
                project_id=project_id,
                resource_type=resource_type,
                resource_id=resource_id,
                mode="enforce",
            )
            if not decision.allowed:
                raise LifecycleError(
                    "delegation_scope_exceeded",
                    "target role exceeds the caller's delegable permissions",
                )

    @staticmethod
    def _delegated_permissions(role: str, resource_type: str | None) -> frozenset[str]:
        if resource_type is None:
            return PROJECT_ROLE_PERMISSIONS[role]
        role_map = RESOURCE_ROLE_PERMISSIONS.get(resource_type)
        if role_map is None or not role_map[role]:
            raise LifecycleError(
                "resource_role_has_no_effect", "role grants no permissions for resource type"
            )
        return role_map[role]

    @staticmethod
    def _require_subject_membership(
        db: Session,
        request: RequestContext,
        subject_type: str,
        subject_id: UUID,
    ) -> None:
        if subject_type == "space":
            return
        active = db.execute(
            sa.select(SpaceMembership.user_id).where(
                SpaceMembership.tenant_id == request.tenant_id,
                SpaceMembership.space_id == request.space_id,
                SpaceMembership.user_id == subject_id,
                SpaceMembership.status == "active",
            )
        ).scalar_one_or_none()
        if active is None:
            raise LifecycleError("grant_subject_not_active", "grant subject is not active")

    @staticmethod
    def _grant_result(receipt: ControlPlaneOutboxEvent, *, replayed: bool) -> ScopedGrantChanged:
        return ProjectAdministrationService._grant_result_payload(
            receipt.payload, replayed=replayed
        )

    @staticmethod
    def _grant_result_payload(payload: dict[str, object], *, replayed: bool) -> ScopedGrantChanged:
        raw_grant_id = cast(str | None, payload["grant_id"])
        return ScopedGrantChanged(
            project_id=UUID(cast(str, payload["project_id"])),
            grant_id=UUID(raw_grant_id) if raw_grant_id else None,
            subject_type=cast(str, payload["subject_type"]),
            subject_id=UUID(cast(str, payload["subject_id"])),
            role=cast(str, payload["role"]),
            status=cast(str, payload["status"]),
            authorization_version=cast(int, payload["authorization_version"]),
            replayed=replayed,
        )

    @staticmethod
    def _metadata(project: ProjectRecord) -> ProjectMetadata:
        return ProjectMetadata(
            project_id=project.id,
            tenant_id=project.tenant_id,
            space_id=project.space_id,
            name=project.name,
            visibility=project.visibility,
            status=project.status,
            authorization_version=project.authorization_version,
        )
