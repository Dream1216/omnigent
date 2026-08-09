"""PC1 Staff Realm sessions, platform authorization, and safe projections."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.permissions import (
    PERMISSION_CATALOG,
    PLATFORM_FIELD_PERMISSIONS,
    PLATFORM_ROLE_PERMISSIONS,
    POLICY_VERSION,
)
from saas.control_plane.platform_models import (
    PLATFORM_ROLES,
    PlatformAuthSessionRecord,
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
    PlatformTenantProjectionRecord,
    PlatformUserProjectionRecord,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context

_PHISHING_RESISTANT_METHODS = frozenset({"passkey", "webauthn", "oidc:acr:phishing-resistant"})
_MAX_SESSION_TTL = timedelta(hours=8)
_FRESH_AUTH_WINDOW = timedelta(minutes=5)


class PlatformSecurityError(RuntimeError):
    """Stable fail-closed error for Staff Realm and platform policy failures."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PlatformSecurityError("platform_time_invalid", f"{field} must include a timezone")


def _comparable(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _secret_hash(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _current_permissions(
    db: Session,
    *,
    principal_id: UUID,
    security_version: int,
    now: datetime,
) -> frozenset[str]:
    principal = db.get(PlatformStaffPrincipalRecord, principal_id)
    if (
        principal is None
        or principal.status != "active"
        or principal.security_version != security_version
    ):
        raise PlatformSecurityError(
            "platform_principal_inactive", "active Staff principal is required"
        )
    roles = db.execute(
        sa.select(PlatformRoleAssignmentRecord.role).where(
            PlatformRoleAssignmentRecord.principal_id == principal_id,
            PlatformRoleAssignmentRecord.status == "active",
            sa.or_(
                PlatformRoleAssignmentRecord.expires_at.is_(None),
                PlatformRoleAssignmentRecord.expires_at > now,
            ),
        )
    ).scalars()
    return frozenset(
        permission
        for role in roles
        for permission in PLATFORM_ROLE_PERMISSIONS.get(role, frozenset())
    )


@dataclass(frozen=True, slots=True)
class StaffIdentityAssertion:
    """Verified assertion supplied only by the dedicated Staff IdP adapter."""

    issuer: str
    subject: str
    authn_method: str
    mfa_strength: str
    authenticated_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedPlatformSession:
    session_id: UUID
    principal_id: UUID
    token: str
    csrf_token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ValidatedPlatformPrincipal:
    session_id: UUID
    principal_id: UUID
    security_version: int
    authn_method: str
    authenticated_at: datetime
    expires_at: datetime
    roles: frozenset[str]
    permissions: frozenset[str]


@dataclass(frozen=True, slots=True)
class PlatformRoleAssignmentView:
    assignment_id: UUID
    principal_id: UUID
    role: str
    status: str
    version: int
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class TenantProjectionInput:
    tenant_id: UUID
    slug: str
    name: str
    status: str
    plan: str
    home_region: str
    member_count: int
    space_count: int
    source_version: int
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class UserProjectionInput:
    user_id: UUID
    status: str
    display_name: str | None
    email_masked: str | None
    membership_count: int
    security_version: int
    source_version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PlatformProjectionPage:
    items: tuple[dict[str, object], ...]
    next_cursor: str | None
    policy_version: str = POLICY_VERSION


class PlatformSessionService:
    """Issue and validate an Origin/Audience-bound Staff Realm session."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        origin: str,
        audience: str,
    ) -> None:
        if not origin.startswith("https://") or not audience:
            raise ValueError("platform Staff Realm requires an HTTPS Origin and Audience")
        self._sessions = session_factory
        self.origin = origin.rstrip("/")
        self.audience = audience

    def issue_session(
        self,
        assertion: StaffIdentityAssertion,
        *,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> IssuedPlatformSession:
        """Issue only after a current phishing-resistant Staff IdP assertion."""

        issued_at = now or _utcnow()
        for value, field in (
            (issued_at, "now"),
            (expires_at, "expires_at"),
            (assertion.authenticated_at, "authenticated_at"),
        ):
            _require_aware(value, field)
        if assertion.mfa_strength != "phishing_resistant":
            raise PlatformSecurityError(
                "platform_mfa_required", "phishing-resistant Staff MFA is required"
            )
        if assertion.authn_method not in _PHISHING_RESISTANT_METHODS:
            raise PlatformSecurityError(
                "platform_authn_method_invalid", "Staff authentication method is not accepted"
            )
        if not assertion.issuer or not assertion.subject:
            raise PlatformSecurityError(
                "platform_identity_invalid", "Staff identity assertion is incomplete"
            )
        if (
            assertion.authenticated_at > issued_at
            or issued_at - assertion.authenticated_at > _FRESH_AUTH_WINDOW
        ):
            raise PlatformSecurityError(
                "platform_fresh_auth_required", "Staff authentication is not fresh"
            )
        if expires_at <= issued_at or expires_at - issued_at > _MAX_SESSION_TTL:
            raise PlatformSecurityError(
                "platform_session_expiry_invalid", "Staff session expiry is outside policy"
            )

        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        token_hash = _secret_hash(token)
        session_id = uuid4()
        with self._sessions.begin() as db:
            apply_platform_rls_context(
                db,
                PlatformRlsContext(
                    identity_issuer=assertion.issuer,
                    identity_subject=assertion.subject,
                ),
            )
            principal = db.execute(
                sa.select(PlatformStaffPrincipalRecord).where(
                    PlatformStaffPrincipalRecord.issuer == assertion.issuer,
                    PlatformStaffPrincipalRecord.subject == assertion.subject,
                )
            ).scalar_one_or_none()
            if principal is None or principal.status != "active":
                raise PlatformSecurityError(
                    "platform_principal_inactive", "active Staff principal is required"
                )
            apply_platform_rls_context(
                db,
                PlatformRlsContext(
                    principal_id=principal.id,
                    session_token_hash=token_hash,
                ),
            )
            db.add(
                PlatformAuthSessionRecord(
                    id=session_id,
                    principal_id=principal.id,
                    token_hash=token_hash,
                    csrf_token_hash=_secret_hash(csrf_token),
                    security_version=principal.security_version,
                    audience=self.audience,
                    origin=self.origin,
                    authn_method=assertion.authn_method,
                    mfa_strength=assertion.mfa_strength,
                    authenticated_at=assertion.authenticated_at,
                    expires_at=expires_at,
                    last_seen_at=issued_at,
                    created_at=issued_at,
                )
            )
            principal_id = principal.id

        return IssuedPlatformSession(
            session_id=session_id,
            principal_id=principal_id,
            token=token,
            csrf_token=csrf_token,
            expires_at=expires_at,
        )

    def validate_session(
        self,
        token: str,
        *,
        origin: str,
        audience: str,
        now: datetime | None = None,
    ) -> ValidatedPlatformPrincipal:
        """Validate realm, token, security version, expiry, and active roles."""

        checked_at = now or _utcnow()
        _require_aware(checked_at, "now")
        if not token or origin.rstrip("/") != self.origin or audience != self.audience:
            raise PlatformSecurityError(
                "platform_session_invalid", "Staff session is invalid for this Realm"
            )
        token_hash = _secret_hash(token)
        with self._sessions.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(session_token_hash=token_hash))
            auth_session = db.execute(
                sa.select(PlatformAuthSessionRecord).where(
                    PlatformAuthSessionRecord.token_hash == token_hash,
                    PlatformAuthSessionRecord.revoked_at.is_(None),
                    PlatformAuthSessionRecord.expires_at > checked_at,
                    PlatformAuthSessionRecord.origin == self.origin,
                    PlatformAuthSessionRecord.audience == self.audience,
                    PlatformAuthSessionRecord.mfa_strength == "phishing_resistant",
                )
            ).scalar_one_or_none()
            if auth_session is None:
                raise PlatformSecurityError(
                    "platform_session_invalid", "Staff session is invalid for this Realm"
                )
            apply_platform_rls_context(
                db,
                PlatformRlsContext(
                    principal_id=auth_session.principal_id,
                    session_token_hash=token_hash,
                ),
            )
            principal = db.get(PlatformStaffPrincipalRecord, auth_session.principal_id)
            if (
                principal is None
                or principal.status != "active"
                or principal.security_version != auth_session.security_version
            ):
                raise PlatformSecurityError(
                    "platform_session_invalid", "Staff session is invalid for this Realm"
                )
            roles = frozenset(
                db.execute(
                    sa.select(PlatformRoleAssignmentRecord.role).where(
                        PlatformRoleAssignmentRecord.principal_id == principal.id,
                        PlatformRoleAssignmentRecord.status == "active",
                        sa.or_(
                            PlatformRoleAssignmentRecord.expires_at.is_(None),
                            PlatformRoleAssignmentRecord.expires_at > checked_at,
                        ),
                    )
                ).scalars()
            )
            auth_session.last_seen_at = checked_at
            permissions = frozenset(
                permission
                for role in roles
                for permission in PLATFORM_ROLE_PERMISSIONS.get(role, frozenset())
            )
            return ValidatedPlatformPrincipal(
                session_id=auth_session.id,
                principal_id=principal.id,
                security_version=principal.security_version,
                authn_method=auth_session.authn_method,
                authenticated_at=_comparable(auth_session.authenticated_at),
                expires_at=_comparable(auth_session.expires_at),
                roles=roles,
                permissions=permissions,
            )

    def validate_csrf(self, token: str, csrf_token: str) -> None:
        """Validate the platform-only double-submit token against one session."""

        if not token or not csrf_token:
            raise PlatformSecurityError("platform_csrf_invalid", "platform CSRF token is invalid")
        token_hash = _secret_hash(token)
        with self._sessions.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(session_token_hash=token_hash))
            session_id = db.execute(
                sa.select(PlatformAuthSessionRecord.id).where(
                    PlatformAuthSessionRecord.token_hash == token_hash,
                    PlatformAuthSessionRecord.csrf_token_hash == _secret_hash(csrf_token),
                    PlatformAuthSessionRecord.revoked_at.is_(None),
                )
            ).scalar_one_or_none()
        if session_id is None:
            raise PlatformSecurityError("platform_csrf_invalid", "platform CSRF token is invalid")

    def revoke_session(self, token: str, *, now: datetime | None = None) -> bool:
        """Revoke one exact Staff Realm session."""

        if not token:
            return False
        revoked_at = now or _utcnow()
        _require_aware(revoked_at, "now")
        token_hash = _secret_hash(token)
        with self._sessions.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(session_token_hash=token_hash))
            result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(PlatformAuthSessionRecord)
                    .where(
                        PlatformAuthSessionRecord.token_hash == token_hash,
                        PlatformAuthSessionRecord.revoked_at.is_(None),
                    )
                    .values(revoked_at=revoked_at)
                ),
            )
            return result.rowcount == 1


class PlatformAuthorizationService:
    """Evaluate Staff assignments without consulting customer Memberships."""

    def __init__(
        self,
        application_factory: sessionmaker[Session],
        *,
        governance_factory: sessionmaker[Session] | None = None,
    ) -> None:
        self._application = application_factory
        self._governance = governance_factory or application_factory

    def provision_staff_principal(
        self,
        *,
        identity_connection_ref: str,
        issuer: str,
        subject: str,
        display_name: str | None = None,
        email_normalized: str | None = None,
        now: datetime | None = None,
    ) -> UUID:
        """Provision a role-less Staff identity from the dedicated IdP sync."""

        provisioned_at = now or _utcnow()
        _require_aware(provisioned_at, "now")
        identity_connection_ref = identity_connection_ref.strip()
        issuer = issuer.strip()
        subject = subject.strip()
        if not identity_connection_ref or not issuer or not subject:
            raise PlatformSecurityError(
                "platform_identity_invalid", "Staff identity source is incomplete"
            )
        with self._governance.begin() as db:
            principal = db.execute(
                sa.select(PlatformStaffPrincipalRecord).where(
                    PlatformStaffPrincipalRecord.issuer == issuer,
                    PlatformStaffPrincipalRecord.subject == subject,
                )
            ).scalar_one_or_none()
            if principal is not None:
                if principal.identity_connection_ref != identity_connection_ref:
                    raise PlatformSecurityError(
                        "platform_identity_conflict", "Staff identity source has changed"
                    )
                principal.display_name = display_name
                principal.email_normalized = email_normalized
                principal.updated_at = provisioned_at
                return principal.id
            principal_id = uuid4()
            db.add(
                PlatformStaffPrincipalRecord(
                    id=principal_id,
                    identity_connection_ref=identity_connection_ref,
                    issuer=issuer,
                    subject=subject,
                    display_name=display_name,
                    email_normalized=email_normalized,
                    status="active",
                    security_version=1,
                    created_at=provisioned_at,
                    updated_at=provisioned_at,
                )
            )
            return principal_id

    @staticmethod
    def require(principal: ValidatedPlatformPrincipal, permission: str) -> None:
        definition = PERMISSION_CATALOG.get(permission)
        if (
            definition is None
            or not permission.startswith("platform.")
            or permission not in principal.permissions
        ):
            raise PlatformSecurityError(
                "platform_permission_denied", "platform permission is denied"
            )

    @staticmethod
    def require_current(
        db: Session,
        principal: ValidatedPlatformPrincipal,
        permission: str,
        *,
        now: datetime,
    ) -> None:
        """Re-evaluate one permission inside the command transaction."""

        PlatformAuthorizationService.require(principal, permission)
        if permission not in _current_permissions(
            db,
            principal_id=principal.principal_id,
            security_version=principal.security_version,
            now=now,
        ):
            raise PlatformSecurityError(
                "platform_permission_denied", "platform permission is denied"
            )

    def assign_role(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        principal_id: UUID,
        role: str,
        approval_ref: str,
        reason: str,
        expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> PlatformRoleAssignmentView:
        """Assign a role with fresh auth, external approval, and no self-grant."""

        self.require(actor, "platform.role.manage")
        changed_at = now or _utcnow()
        _require_aware(changed_at, "now")
        if role not in PLATFORM_ROLES or not approval_ref.strip() or not reason.strip():
            raise PlatformSecurityError(
                "platform_assignment_invalid", "platform role assignment is incomplete"
            )
        if actor.principal_id == principal_id:
            raise PlatformSecurityError(
                "platform_separation_of_duties", "Staff cannot assign a role to itself"
            )
        if (
            actor.authenticated_at > changed_at
            or changed_at - actor.authenticated_at > _FRESH_AUTH_WINDOW
        ):
            raise PlatformSecurityError(
                "platform_fresh_auth_required", "fresh Staff authentication is required"
            )
        if expires_at is not None:
            _require_aware(expires_at, "expires_at")
            if expires_at <= changed_at:
                raise PlatformSecurityError(
                    "platform_assignment_invalid", "assignment expiry must be in the future"
                )

        assignment_id = uuid4()
        with self._governance.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.principal_id))
            current_permissions = _current_permissions(
                db,
                principal_id=actor.principal_id,
                security_version=actor.security_version,
                now=changed_at,
            )
            if "platform.role.manage" not in current_permissions:
                raise PlatformSecurityError(
                    "platform_permission_denied", "platform permission is denied"
                )
            target = db.get(PlatformStaffPrincipalRecord, principal_id)
            if target is None or target.status != "active":
                raise PlatformSecurityError(
                    "platform_principal_inactive", "active Staff principal is required"
                )
            existing = db.execute(
                sa.select(PlatformRoleAssignmentRecord.id).where(
                    PlatformRoleAssignmentRecord.principal_id == principal_id,
                    PlatformRoleAssignmentRecord.role == role,
                    PlatformRoleAssignmentRecord.status == "active",
                    sa.or_(
                        PlatformRoleAssignmentRecord.expires_at.is_(None),
                        PlatformRoleAssignmentRecord.expires_at > changed_at,
                    ),
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise PlatformSecurityError(
                    "platform_assignment_conflict", "active platform role already exists"
                )
            db.add(
                PlatformRoleAssignmentRecord(
                    id=assignment_id,
                    principal_id=principal_id,
                    role=role,
                    status="active",
                    expires_at=expires_at,
                    version=1,
                    assigned_by_principal_id=actor.principal_id,
                    approval_ref=approval_ref.strip(),
                    reason=reason.strip(),
                    created_at=changed_at,
                    updated_at=changed_at,
                )
            )
        return PlatformRoleAssignmentView(
            assignment_id=assignment_id,
            principal_id=principal_id,
            role=role,
            status="active",
            version=1,
            expires_at=expires_at,
        )

    def revoke_assignment(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        assignment_id: UUID,
        expected_version: int,
        approval_ref: str,
        reason: str,
        now: datetime | None = None,
    ) -> PlatformRoleAssignmentView:
        """Revoke one exact assignment with optimistic concurrency."""

        self.require(actor, "platform.role.manage")
        changed_at = now or _utcnow()
        _require_aware(changed_at, "now")
        if not approval_ref.strip() or not reason.strip():
            raise PlatformSecurityError(
                "platform_assignment_invalid", "platform role revocation is incomplete"
            )
        if (
            actor.authenticated_at > changed_at
            or changed_at - actor.authenticated_at > _FRESH_AUTH_WINDOW
        ):
            raise PlatformSecurityError(
                "platform_fresh_auth_required", "fresh Staff authentication is required"
            )
        with self._governance.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(principal_id=actor.principal_id))
            current_permissions = _current_permissions(
                db,
                principal_id=actor.principal_id,
                security_version=actor.security_version,
                now=changed_at,
            )
            if "platform.role.manage" not in current_permissions:
                raise PlatformSecurityError(
                    "platform_permission_denied", "platform permission is denied"
                )
            assignment = db.execute(
                sa.select(PlatformRoleAssignmentRecord)
                .where(PlatformRoleAssignmentRecord.id == assignment_id)
                .with_for_update()
            ).scalar_one_or_none()
            if assignment is None:
                raise PlatformSecurityError(
                    "platform_assignment_not_found", "platform role assignment was not found"
                )
            if assignment.principal_id == actor.principal_id:
                raise PlatformSecurityError(
                    "platform_separation_of_duties", "Staff cannot revoke its own role"
                )
            if assignment.status != "active" or assignment.version != expected_version:
                raise PlatformSecurityError(
                    "platform_assignment_conflict", "platform role assignment has changed"
                )
            assignment.status = "revoked"
            assignment.revoked_at = changed_at
            assignment.revoked_by_principal_id = actor.principal_id
            assignment.reason = f"{reason.strip()} [approval:{approval_ref.strip()}]"
            assignment.version += 1
            assignment.updated_at = changed_at
            return PlatformRoleAssignmentView(
                assignment_id=assignment.id,
                principal_id=assignment.principal_id,
                role=assignment.role,
                status=assignment.status,
                version=assignment.version,
                expires_at=(
                    _comparable(assignment.expires_at)
                    if assignment.expires_at is not None
                    else None
                ),
            )


class PlatformProjectionService:
    """Write explicit safe facts and expose field-filtered stable cursor pages."""

    def __init__(
        self,
        application_factory: sessionmaker[Session],
        *,
        projector_factory: sessionmaker[Session] | None = None,
    ) -> None:
        self._application = application_factory
        self._projector = projector_factory or application_factory

    def upsert_tenant(self, item: TenantProjectionInput) -> None:
        _require_aware(item.updated_at, "updated_at")
        if item.member_count < 0 or item.space_count < 0 or item.source_version <= 0:
            raise PlatformSecurityError(
                "platform_projection_invalid", "Tenant projection is invalid"
            )
        with self._projector.begin() as db:
            current = db.get(PlatformTenantProjectionRecord, item.tenant_id)
            if current is not None and current.source_version >= item.source_version:
                return
            values = {
                "slug": item.slug,
                "name": item.name,
                "status": item.status,
                "plan": item.plan,
                "home_region": item.home_region,
                "member_count": item.member_count,
                "space_count": item.space_count,
                "source_version": item.source_version,
                "updated_at": item.updated_at,
            }
            if current is None:
                db.add(PlatformTenantProjectionRecord(tenant_id=item.tenant_id, **values))
            else:
                for field, value in values.items():
                    setattr(current, field, value)

    def upsert_user(self, item: UserProjectionInput) -> None:
        _require_aware(item.created_at, "created_at")
        _require_aware(item.updated_at, "updated_at")
        if (
            item.membership_count < 0
            or item.security_version <= 0
            or item.source_version <= 0
            or (item.email_masked is not None and "@" not in item.email_masked)
        ):
            raise PlatformSecurityError(
                "platform_projection_invalid", "User projection is invalid"
            )
        with self._projector.begin() as db:
            current = db.get(PlatformUserProjectionRecord, item.user_id)
            if current is not None and current.source_version >= item.source_version:
                return
            values = {
                "status": item.status,
                "display_name": item.display_name,
                "email_masked": item.email_masked,
                "membership_count": item.membership_count,
                "security_version": item.security_version,
                "source_version": item.source_version,
                "created_at": item.created_at,
                "updated_at": item.updated_at,
            }
            if current is None:
                db.add(PlatformUserProjectionRecord(user_id=item.user_id, **values))
            else:
                for field, value in values.items():
                    setattr(current, field, value)

    def list_tenants(
        self,
        principal: ValidatedPlatformPrincipal,
        *,
        cursor: UUID | None = None,
        limit: int = 50,
    ) -> PlatformProjectionPage:
        PlatformAuthorizationService.require(principal, "platform.tenant.read")
        if not 1 <= limit <= 200:
            raise PlatformSecurityError("platform_page_invalid", "page limit is invalid")
        with self._application.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(principal_id=principal.principal_id))
            permissions = _current_permissions(
                db,
                principal_id=principal.principal_id,
                security_version=principal.security_version,
                now=_utcnow(),
            )
            if "platform.tenant.read" not in permissions:
                raise PlatformSecurityError(
                    "platform_permission_denied", "platform permission is denied"
                )
            statement = sa.select(PlatformTenantProjectionRecord)
            if cursor is not None:
                statement = statement.where(PlatformTenantProjectionRecord.tenant_id > cursor)
            records = list(
                db.execute(
                    statement.order_by(PlatformTenantProjectionRecord.tenant_id).limit(limit + 1)
                ).scalars()
            )
        has_more = len(records) > limit
        visible = records[:limit]
        items = tuple(
            self._filter_fields(
                "tenant",
                {
                    "tenant_id": record.tenant_id,
                    "slug": record.slug,
                    "name": record.name,
                    "status": record.status,
                    "plan": record.plan,
                    "home_region": record.home_region,
                    "member_count": record.member_count,
                    "space_count": record.space_count,
                    "updated_at": _comparable(record.updated_at).isoformat(),
                },
                permissions,
            )
            for record in visible
        )
        return PlatformProjectionPage(
            items=items,
            next_cursor=str(visible[-1].tenant_id) if has_more and visible else None,
        )

    def list_users(
        self,
        principal: ValidatedPlatformPrincipal,
        *,
        cursor: UUID | None = None,
        limit: int = 50,
    ) -> PlatformProjectionPage:
        PlatformAuthorizationService.require(principal, "platform.user.read")
        if not 1 <= limit <= 200:
            raise PlatformSecurityError("platform_page_invalid", "page limit is invalid")
        with self._application.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(principal_id=principal.principal_id))
            permissions = _current_permissions(
                db,
                principal_id=principal.principal_id,
                security_version=principal.security_version,
                now=_utcnow(),
            )
            if "platform.user.read" not in permissions:
                raise PlatformSecurityError(
                    "platform_permission_denied", "platform permission is denied"
                )
            statement = sa.select(PlatformUserProjectionRecord)
            if cursor is not None:
                statement = statement.where(PlatformUserProjectionRecord.user_id > cursor)
            records = list(
                db.execute(
                    statement.order_by(PlatformUserProjectionRecord.user_id).limit(limit + 1)
                ).scalars()
            )
        has_more = len(records) > limit
        visible = records[:limit]
        items = tuple(
            self._filter_fields(
                "user",
                {
                    "user_id": record.user_id,
                    "status": record.status,
                    "display_name": record.display_name,
                    "email_masked": record.email_masked,
                    "membership_count": record.membership_count,
                    "security_version": record.security_version,
                    "created_at": _comparable(record.created_at).isoformat(),
                    "updated_at": _comparable(record.updated_at).isoformat(),
                },
                permissions,
            )
            for record in visible
        )
        return PlatformProjectionPage(
            items=items,
            next_cursor=str(visible[-1].user_id) if has_more and visible else None,
        )

    @staticmethod
    def _filter_fields(
        projection: str,
        values: dict[str, object],
        permissions: frozenset[str],
    ) -> dict[str, object]:
        field_policy = PLATFORM_FIELD_PERMISSIONS[projection]
        return {
            field: value
            for field, value in values.items()
            if field_policy.get(field) in permissions
        }


def mask_email(value: str | None) -> str | None:
    """Return a stable display mask without preserving the local part."""

    if value is None:
        return None
    normalized = value.strip().lower()
    local, separator, domain = normalized.partition("@")
    if not separator or not local or not domain:
        raise PlatformSecurityError("platform_projection_invalid", "email is invalid")
    return f"{local[0]}***@{domain}"
