"""Fail-closed RBAC plus additive scoped grants for Project resources."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.db_models import (
    AuthorizationDecisionRecord,
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    ResourceGrantRecord,
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
from saas.control_plane.permissions import (
    PERMISSION_CATALOG,
    POLICY_VERSION,
    PROJECT_ROLE_PERMISSIONS,
    RESOURCE_ROLE_PERMISSIONS,
    SPACE_ROLE_PERMISSIONS,
    TENANT_ROLE_PERMISSIONS,
)
from saas.control_plane.rls import RlsContext, apply_rls_context


class ProjectAuthorizationError(PermissionError):
    """Transport-neutral non-disclosing authorization failure."""

    def __init__(self, code: str, message: str = "resource is not accessible") -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class AuthorizationSource:
    """One additive reason considered by the policy engine."""

    source_type: str
    role: str
    subject_type: str
    subject_id: UUID
    role_id: UUID | None = None
    role_version: int | None = None

    def payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "source_type": self.source_type,
            "role": self.role,
            "subject_type": self.subject_type,
            "subject_id": str(self.subject_id),
        }
        if self.role_id is not None:
            payload["role_id"] = str(self.role_id)
        if self.role_version is not None:
            payload["role_version"] = self.role_version
        return payload


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Persisted decision result suitable for shadow comparison and explanation."""

    decision_id: UUID
    allowed: bool
    reason: str
    action: str
    project_id: UUID
    project_authorization_version: int | None
    sources: tuple[AuthorizationSource, ...]
    policy_version: str
    mode: str


@dataclass(frozen=True, slots=True)
class _ScopeFacts:
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


class ProjectAuthorizer:
    """Authoritative Project decision point; clients cannot supply trusted roles."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def evaluate(
        self,
        request: RequestContext,
        *,
        action: str,
        project_id: UUID,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
        mode: str = "enforce",
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        """Compute and persist an enforce or shadow decision in one transaction."""

        with self._session_factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=request.actor_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                ),
            )
            return self.evaluate_in_session(
                db,
                request,
                action=action,
                project_id=project_id,
                resource_type=resource_type,
                resource_id=resource_id,
                mode=mode,
                now=now,
            )

    def require(
        self,
        request: RequestContext,
        *,
        action: str,
        project_id: UUID,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        """Persist the decision and reject denied access without revealing existence."""

        decision = self.evaluate(
            request,
            action=action,
            project_id=project_id,
            resource_type=resource_type,
            resource_id=resource_id,
            mode="enforce",
            now=now,
        )
        if not decision.allowed:
            raise ProjectAuthorizationError(decision.reason)
        return decision

    def bind_project_context(
        self,
        request: RequestContext,
        *,
        action: str,
        project_id: UUID,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
        now: datetime | None = None,
    ) -> RequestContext:
        """Return a Project-scoped context only after an enforce decision succeeds."""

        self.require(
            request,
            action=action,
            project_id=project_id,
            resource_type=resource_type,
            resource_id=resource_id,
            now=now,
        )
        return replace(request, project_id=project_id)

    def evaluate_in_session(
        self,
        db: Session,
        request: RequestContext,
        *,
        action: str,
        project_id: UUID,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
        mode: str = "enforce",
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        """Evaluate within an already Space-scoped transaction and append an audit record."""

        checked_at = now or _utcnow()
        if mode not in {"shadow", "enforce"}:
            raise ValueError("authorization mode must be shadow or enforce")
        if action not in PERMISSION_CATALOG:
            return self._record(
                db,
                request,
                action=action,
                project_id=project_id,
                resource_type=resource_type,
                resource_id=resource_id,
                mode=mode,
                allowed=False,
                reason="permission_not_registered",
                sources=(),
                project_version=None,
            )
        if (resource_type is None) != (resource_id is None):
            return self._record(
                db,
                request,
                action=action,
                project_id=project_id,
                resource_type=resource_type,
                resource_id=resource_id,
                mode=mode,
                allowed=False,
                reason="resource_selector_invalid",
                sources=(),
                project_version=None,
            )
        if request.project_id is not None and request.project_id != project_id:
            return self._record(
                db,
                request,
                action=action,
                project_id=project_id,
                resource_type=resource_type,
                resource_id=resource_id,
                mode=mode,
                allowed=False,
                reason="project_context_mismatch",
                sources=(),
                project_version=None,
            )

        facts = self._load_scope_facts(db, request)
        scope_reason = self._scope_denial_reason(facts, request)
        project = db.execute(
            sa.select(ProjectRecord).where(
                ProjectRecord.id == project_id,
                ProjectRecord.tenant_id == request.tenant_id,
                ProjectRecord.space_id == request.space_id,
            )
        ).scalar_one_or_none()
        if scope_reason is not None or project is None or project.status != "active":
            return self._record(
                db,
                request,
                action=action,
                project_id=project_id,
                resource_type=resource_type,
                resource_id=resource_id,
                mode=mode,
                allowed=False,
                reason=scope_reason or "resource_not_accessible",
                sources=(),
                project_version=project.authorization_version if project else None,
            )
        if facts is None:
            raise RuntimeError("scope facts disappeared after an allowed scope decision")

        sources: list[AuthorizationSource] = []
        granted_permissions: set[str] = set()
        self._add_role_source(
            sources,
            granted_permissions,
            source_type="tenant_membership",
            role=facts.tenant_role,
            subject_type="user",
            subject_id=request.actor_id,
            permissions=TENANT_ROLE_PERMISSIONS[facts.tenant_role],
        )
        self._add_role_source(
            sources,
            granted_permissions,
            source_type="space_membership",
            role=facts.space_role,
            subject_type="user",
            subject_id=request.actor_id,
            permissions=SPACE_ROLE_PERMISSIONS[facts.space_role],
        )

        project_roles = db.execute(
            sa.select(ProjectMembershipRecord).where(
                ProjectMembershipRecord.tenant_id == request.tenant_id,
                ProjectMembershipRecord.space_id == request.space_id,
                ProjectMembershipRecord.project_id == project_id,
                ProjectMembershipRecord.status == "active",
                sa.or_(
                    ProjectMembershipRecord.expires_at.is_(None),
                    ProjectMembershipRecord.expires_at > checked_at,
                ),
                sa.or_(
                    sa.and_(
                        ProjectMembershipRecord.subject_type == "user",
                        ProjectMembershipRecord.subject_id == request.actor_id,
                    ),
                    sa.and_(
                        ProjectMembershipRecord.subject_type == "space",
                        ProjectMembershipRecord.subject_id == request.space_id,
                    ),
                ),
            )
        ).scalars()
        for membership in project_roles:
            self._add_role_source(
                sources,
                granted_permissions,
                source_type="project_membership",
                role=membership.role,
                subject_type=membership.subject_type,
                subject_id=membership.subject_id,
                permissions=PROJECT_ROLE_PERMISSIONS[membership.role],
            )

        group_roles = db.execute(
            sa.select(
                EnterpriseGroupRoleAssignmentRecord,
                EnterpriseCustomRoleRecord,
            )
            .join(
                EnterpriseGroupMembershipRecord,
                sa.and_(
                    EnterpriseGroupMembershipRecord.tenant_id
                    == EnterpriseGroupRoleAssignmentRecord.tenant_id,
                    EnterpriseGroupMembershipRecord.group_id
                    == EnterpriseGroupRoleAssignmentRecord.group_id,
                ),
            )
            .join(
                EnterpriseGroupRecord,
                sa.and_(
                    EnterpriseGroupRecord.tenant_id
                    == EnterpriseGroupRoleAssignmentRecord.tenant_id,
                    EnterpriseGroupRecord.id == EnterpriseGroupRoleAssignmentRecord.group_id,
                ),
            )
            .join(
                EnterpriseCustomRoleRecord,
                sa.and_(
                    EnterpriseCustomRoleRecord.tenant_id
                    == EnterpriseGroupRoleAssignmentRecord.tenant_id,
                    EnterpriseCustomRoleRecord.space_id
                    == EnterpriseGroupRoleAssignmentRecord.space_id,
                    EnterpriseCustomRoleRecord.project_id
                    == EnterpriseGroupRoleAssignmentRecord.project_id,
                    EnterpriseCustomRoleRecord.id
                    == EnterpriseGroupRoleAssignmentRecord.custom_role_id,
                ),
            )
            .where(
                EnterpriseGroupRoleAssignmentRecord.tenant_id == request.tenant_id,
                EnterpriseGroupRoleAssignmentRecord.space_id == request.space_id,
                EnterpriseGroupRoleAssignmentRecord.project_id == project_id,
                EnterpriseGroupRoleAssignmentRecord.status == "active",
                EnterpriseGroupRecord.status == "active",
                EnterpriseGroupMembershipRecord.user_id == request.actor_id,
                EnterpriseGroupMembershipRecord.status == "active",
                EnterpriseCustomRoleRecord.status == "active",
                sa.or_(
                    EnterpriseGroupRoleAssignmentRecord.expires_at.is_(None),
                    EnterpriseGroupRoleAssignmentRecord.expires_at > checked_at,
                ),
                sa.or_(
                    EnterpriseGroupMembershipRecord.expires_at.is_(None),
                    EnterpriseGroupMembershipRecord.expires_at > checked_at,
                ),
            )
        ).all()
        for assignment, role in group_roles:
            self._add_role_source(
                sources,
                granted_permissions,
                source_type="enterprise_group_custom_role",
                role=role.name,
                subject_type="group",
                subject_id=assignment.group_id,
                permissions=frozenset(role.permissions),
                role_id=role.id,
                role_version=role.version,
            )

        if project.visibility == "space":
            self._add_role_source(
                sources,
                granted_permissions,
                source_type="project_visibility",
                role="read",
                subject_type="space",
                subject_id=request.space_id,
                permissions=PROJECT_ROLE_PERMISSIONS["read"],
            )

        if resource_type is not None and resource_id is not None:
            grants = db.execute(
                sa.select(ResourceGrantRecord).where(
                    ResourceGrantRecord.tenant_id == request.tenant_id,
                    ResourceGrantRecord.space_id == request.space_id,
                    ResourceGrantRecord.project_id == project_id,
                    ResourceGrantRecord.resource_type == resource_type,
                    ResourceGrantRecord.resource_id == resource_id,
                    ResourceGrantRecord.status == "active",
                    sa.or_(
                        ResourceGrantRecord.expires_at.is_(None),
                        ResourceGrantRecord.expires_at > checked_at,
                    ),
                    sa.or_(
                        sa.and_(
                            ResourceGrantRecord.subject_type == "user",
                            ResourceGrantRecord.subject_id == request.actor_id,
                        ),
                        sa.and_(
                            ResourceGrantRecord.subject_type == "space",
                            ResourceGrantRecord.subject_id == request.space_id,
                        ),
                    ),
                )
            ).scalars()
            for grant in grants:
                resource_permissions = RESOURCE_ROLE_PERMISSIONS.get(resource_type, {}).get(
                    grant.role, frozenset()
                )
                self._add_role_source(
                    sources,
                    granted_permissions,
                    source_type="resource_grant",
                    role=grant.role,
                    subject_type=grant.subject_type,
                    subject_id=grant.subject_id,
                    permissions=resource_permissions,
                )

        allowed = action in granted_permissions
        return self._record(
            db,
            request,
            action=action,
            project_id=project_id,
            resource_type=resource_type,
            resource_id=resource_id,
            mode=mode,
            allowed=allowed,
            reason="allowed" if allowed else "permission_not_granted",
            sources=tuple(sources),
            project_version=project.authorization_version,
        )

    @staticmethod
    def _load_scope_facts(db: Session, request: RequestContext) -> _ScopeFacts | None:
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
        return _ScopeFacts(*row) if row is not None else None

    @staticmethod
    def _scope_denial_reason(facts: _ScopeFacts | None, request: RequestContext) -> str | None:
        if facts is None:
            return "scope_not_authorized"
        if facts.user_status != "active":
            return "user_not_active"
        if facts.tenant_status not in {"trial", "active"}:
            return "tenant_not_active"
        if facts.tenant_membership_status != "active":
            return "tenant_membership_not_active"
        if facts.space_status != "active":
            return "space_not_active"
        if facts.space_membership_status != "active":
            return "space_membership_not_active"
        if (
            facts.security_version != request.user_security_version
            or facts.tenant_membership_version != request.tenant_membership_version
            or facts.space_membership_version != request.space_membership_version
        ):
            return "authorization_snapshot_stale"
        return None

    @staticmethod
    def _add_role_source(
        sources: list[AuthorizationSource],
        granted_permissions: set[str],
        *,
        source_type: str,
        role: str,
        subject_type: str,
        subject_id: UUID,
        permissions: frozenset[str],
        role_id: UUID | None = None,
        role_version: int | None = None,
    ) -> None:
        sources.append(
            AuthorizationSource(
                source_type=source_type,
                role=role,
                subject_type=subject_type,
                subject_id=subject_id,
                role_id=role_id,
                role_version=role_version,
            )
        )
        granted_permissions.update(permissions)

    @staticmethod
    def _record(
        db: Session,
        request: RequestContext,
        *,
        action: str,
        project_id: UUID,
        resource_type: str | None,
        resource_id: UUID | None,
        mode: str,
        allowed: bool,
        reason: str,
        sources: tuple[AuthorizationSource, ...],
        project_version: int | None,
    ) -> AuthorizationDecision:
        decision_id = uuid4()
        db.add(
            AuthorizationDecisionRecord(
                id=decision_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=project_id,
                actor_id=request.actor_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                mode=mode,
                allowed=allowed,
                reason=reason,
                sources=[source.payload() for source in sources],
                policy_version=POLICY_VERSION,
                trace_id=request.trace_id,
            )
        )
        return AuthorizationDecision(
            decision_id=decision_id,
            allowed=allowed,
            reason=reason,
            action=action,
            project_id=project_id,
            project_authorization_version=project_version,
            sources=sources,
            policy_version=POLICY_VERSION,
            mode=mode,
        )
