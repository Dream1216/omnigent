"""Transactional identity, invitation, and membership lifecycle services."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import (
    SPACE_ROLES,
    TENANT_ROLES,
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    MembershipInvitation,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)


class LifecycleError(RuntimeError):
    """Stable, transport-neutral failure raised by lifecycle operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class IssuedAuthSession:
    """New bearer token returned once; only its digest is persisted."""

    session_id: UUID
    token: str
    security_version: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ValidatedAuthSession:
    """Server-validated session identity and current security version."""

    session_id: UUID
    user_id: UUID
    security_version: int
    authn_method: str


@dataclass(frozen=True, slots=True)
class InvitationCreated:
    """Invitation creation result; idempotent replay cannot reveal the secret again."""

    invitation_id: UUID
    token: str | None
    replayed: bool


@dataclass(frozen=True, slots=True)
class InvitationAccepted:
    """Membership versions created by one successful invitation redemption."""

    tenant_id: UUID
    space_id: UUID | None
    tenant_membership_version: int
    space_membership_version: int | None
    replayed: bool


@dataclass(frozen=True, slots=True)
class MembershipChanged:
    """Committed membership and security invalidation versions."""

    scope: str
    membership_version: int
    security_version: int
    revoked_session_count: int
    replayed: bool


def normalize_email(email: str) -> str:
    """Return the comparison form used for invitation binding."""

    normalized = email.strip().casefold()
    if (
        not normalized
        or len(normalized) > 320
        or normalized.count("@") != 1
        or any(character.isspace() for character in normalized)
    ):
        raise LifecycleError("invalid_email", "email is not a valid comparison identity")
    local, domain = normalized.split("@", 1)
    if not local or not domain:
        raise LifecycleError("invalid_email", "email is not a valid comparison identity")
    return normalized


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LifecycleError("invalid_timestamp", f"{field} must include a timezone")


def _secret_hash(secret: str) -> str:
    return sha256(secret.encode("utf-8")).hexdigest()


def _request_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode("utf-8")).hexdigest()


def _validate_idempotency_key(value: str) -> None:
    if not value or len(value) > 128:
        raise LifecycleError(
            "invalid_idempotency_key", "idempotency key must contain 1 to 128 characters"
        )


class MembershipLifecycleService:
    """Own security-sensitive control-plane mutations and their outbox events."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def issue_auth_session(
        self,
        *,
        user_id: UUID,
        authn_method: str,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> IssuedAuthSession:
        """Issue a revocable opaque bearer token for one active Global User."""

        issued_at = now or _utcnow()
        _require_aware(issued_at, "now")
        _require_aware(expires_at, "expires_at")
        if expires_at <= issued_at:
            raise LifecycleError("invalid_expiry", "auth session must expire in the future")
        if not authn_method or len(authn_method) > 64:
            raise LifecycleError("invalid_authn_method", "authentication method is invalid")

        raw_token = secrets.token_urlsafe(32)
        session_id = uuid4()
        with self._session_factory.begin() as db:
            user = db.get(GlobalUser, user_id)
            if user is None or user.status != "active":
                raise LifecycleError("user_inactive", "active user is required")
            db.add(
                AuthSessionRecord(
                    id=session_id,
                    user_id=user_id,
                    token_hash=_secret_hash(raw_token),
                    security_version=user.security_version,
                    authn_method=authn_method,
                    expires_at=expires_at,
                    last_seen_at=issued_at,
                )
            )
            security_version = user.security_version

        return IssuedAuthSession(
            session_id=session_id,
            token=raw_token,
            security_version=security_version,
            expires_at=expires_at,
        )

    def validate_auth_session(
        self, token: str, *, now: datetime | None = None
    ) -> ValidatedAuthSession:
        """Validate token digest, expiry, revocation, user state, and security version."""

        checked_at = now or _utcnow()
        _require_aware(checked_at, "now")
        if not token:
            raise LifecycleError("invalid_session", "authentication session is invalid")

        with self._session_factory.begin() as db:
            row = db.execute(
                sa.select(AuthSessionRecord, GlobalUser)
                .join(GlobalUser, GlobalUser.id == AuthSessionRecord.user_id)
                .where(
                    AuthSessionRecord.token_hash == _secret_hash(token),
                    AuthSessionRecord.revoked_at.is_(None),
                    AuthSessionRecord.expires_at > checked_at,
                    GlobalUser.status == "active",
                    GlobalUser.security_version == AuthSessionRecord.security_version,
                )
            ).one_or_none()
            if row is None:
                raise LifecycleError("invalid_session", "authentication session is invalid")
            auth_session, user = row
            auth_session.last_seen_at = checked_at
            return ValidatedAuthSession(
                session_id=auth_session.id,
                user_id=user.id,
                security_version=user.security_version,
                authn_method=auth_session.authn_method,
            )

    def create_invitation(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        email: str,
        tenant_role: str,
        expires_at: datetime,
        idempotency_key: str,
        space_id: UUID | None = None,
        space_role: str | None = None,
        now: datetime | None = None,
    ) -> InvitationCreated:
        """Create an email- and scope-bound invitation, returning its secret once."""

        created_at = now or _utcnow()
        _require_aware(created_at, "now")
        _require_aware(expires_at, "expires_at")
        _validate_idempotency_key(idempotency_key)
        normalized_email = normalize_email(email)
        self._validate_invitation_roles(tenant_role, space_id, space_role)
        if expires_at <= created_at:
            raise LifecycleError("invalid_expiry", "invitation must expire in the future")

        request: dict[str, object] = {
            "actor_id": str(actor_id),
            "tenant_id": str(tenant_id),
            "space_id": str(space_id) if space_id else None,
            "email_normalized": normalized_email,
            "tenant_role": tenant_role,
            "space_role": space_role,
            "expires_at": expires_at.isoformat(),
        }
        request_digest = _request_hash(request)
        raw_token = secrets.token_urlsafe(32)
        invitation_id = uuid4()

        with self._session_factory.begin() as db:
            replay = self._load_receipt(
                db, idempotency_key, request_digest, "membership.invitation.created"
            )
            if replay is not None:
                return InvitationCreated(
                    invitation_id=UUID(cast(str, replay["invitation_id"])),
                    token=None,
                    replayed=True,
                )

            self._authorize_invitation(
                db,
                actor_id=actor_id,
                tenant_id=tenant_id,
                tenant_role=tenant_role,
                space_id=space_id,
                space_role=space_role,
            )
            invitation = MembershipInvitation(
                id=invitation_id,
                tenant_id=tenant_id,
                space_id=space_id,
                email_normalized=normalized_email,
                tenant_role=tenant_role,
                space_role=space_role,
                token_hash=_secret_hash(raw_token),
                status="pending",
                expires_at=expires_at,
                created_by=actor_id,
                version=1,
            )
            db.add(invitation)
            self._add_outbox_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="membership_invitation",
                aggregate_key=str(invitation_id),
                event_type="membership.invitation.created",
                idempotency_key=idempotency_key,
                request_hash=request_digest,
                payload={
                    "invitation_id": str(invitation_id),
                    "tenant_id": str(tenant_id),
                    "space_id": str(space_id) if space_id else None,
                    "email_normalized": normalized_email,
                    "tenant_role": tenant_role,
                    "space_role": space_role,
                    "expires_at": expires_at.isoformat(),
                    "created_by": str(actor_id),
                },
            )

        return InvitationCreated(invitation_id=invitation_id, token=raw_token, replayed=False)

    def accept_invitation(
        self,
        *,
        actor_id: UUID,
        token: str,
        now: datetime | None = None,
    ) -> InvitationAccepted:
        """Atomically consume an invitation after verified-email binding checks."""

        accepted_at = now or _utcnow()
        _require_aware(accepted_at, "now")
        if not token:
            raise LifecycleError("invalid_invitation", "invitation is invalid or expired")

        with self._session_factory.begin() as db:
            invitation = db.execute(
                sa.select(MembershipInvitation).where(
                    MembershipInvitation.token_hash == _secret_hash(token)
                )
            ).scalar_one_or_none()
            if invitation is None:
                raise LifecycleError("invalid_invitation", "invitation is invalid or expired")
            if invitation.status == "accepted" and invitation.accepted_by == actor_id:
                return self._accepted_invitation_result(db, invitation, replayed=True)
            if (
                invitation.status != "pending"
                or _comparable_time(invitation.expires_at) <= accepted_at
            ):
                raise LifecycleError("invalid_invitation", "invitation is invalid or expired")

            user = db.get(GlobalUser, actor_id)
            if user is None or user.status != "active":
                raise LifecycleError("user_inactive", "active user is required")
            verified_users = set(
                db.execute(
                    sa.select(IdentityConnection.user_id).where(
                        IdentityConnection.status == "active",
                        IdentityConnection.email_verified.is_(True),
                        IdentityConnection.email_normalized == invitation.email_normalized,
                    )
                ).scalars()
            )
            if actor_id not in verified_users:
                raise LifecycleError(
                    "invitation_identity_mismatch",
                    "invitation must be accepted by its verified email identity",
                )
            if len(verified_users) != 1:
                raise LifecycleError(
                    "invitation_identity_ambiguous",
                    "verified email is linked to multiple Global Users",
                )

            tenant = db.get(Tenant, invitation.tenant_id)
            if tenant is None or tenant.status not in ("trial", "active"):
                raise LifecycleError("tenant_inactive", "invitation Tenant is not active")
            if invitation.space_id is not None:
                space = db.get(Space, invitation.space_id)
                if (
                    space is None
                    or space.tenant_id != invitation.tenant_id
                    or space.status != "active"
                ):
                    raise LifecycleError("space_inactive", "invitation Space is not active")

            tenant_membership = db.get(TenantMembership, (invitation.tenant_id, actor_id))
            if tenant_membership is None:
                tenant_membership = TenantMembership(
                    tenant_id=invitation.tenant_id,
                    user_id=actor_id,
                    role=invitation.tenant_role,
                    status="active",
                    version=1,
                    joined_at=accepted_at,
                )
                db.add(tenant_membership)
            elif tenant_membership.status != "active":
                raise LifecycleError(
                    "membership_requires_admin_action",
                    "suspended or removed memberships cannot be restored by invitation",
                )
            elif invitation.space_id is None:
                raise LifecycleError("already_member", "user is already an active Tenant member")

            space_membership: SpaceMembership | None = None
            if invitation.space_id is not None:
                space_membership = db.get(
                    SpaceMembership, (invitation.tenant_id, invitation.space_id, actor_id)
                )
                if space_membership is not None:
                    if space_membership.status == "active":
                        raise LifecycleError(
                            "already_space_member", "user is already an active Space member"
                        )
                    raise LifecycleError(
                        "membership_requires_admin_action",
                        "suspended or removed memberships cannot be restored by invitation",
                    )
                space_membership = SpaceMembership(
                    tenant_id=invitation.tenant_id,
                    space_id=invitation.space_id,
                    user_id=actor_id,
                    role=cast(str, invitation.space_role),
                    status="active",
                    version=1,
                    joined_at=accepted_at,
                )
                db.add(space_membership)

            result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(MembershipInvitation)
                    .where(
                        MembershipInvitation.id == invitation.id,
                        MembershipInvitation.status == "pending",
                        MembershipInvitation.version == invitation.version,
                        MembershipInvitation.expires_at > accepted_at,
                    )
                    .values(
                        status="accepted",
                        accepted_by=actor_id,
                        accepted_at=accepted_at,
                        version=invitation.version + 1,
                        updated_at=accepted_at,
                    )
                    .execution_options(synchronize_session=False)
                ),
            )
            if result.rowcount != 1:
                raise LifecycleError("invitation_conflict", "invitation was consumed concurrently")

            acceptance_key = f"invitation.accept:{invitation.id}"
            acceptance_request_hash = _request_hash(
                {"invitation_id": str(invitation.id), "actor_id": str(actor_id)}
            )
            self._add_outbox_event(
                db,
                tenant_id=invitation.tenant_id,
                aggregate_type="membership_invitation",
                aggregate_key=str(invitation.id),
                event_type="membership.invitation.accepted",
                idempotency_key=acceptance_key,
                request_hash=acceptance_request_hash,
                payload={
                    "invitation_id": str(invitation.id),
                    "tenant_id": str(invitation.tenant_id),
                    "space_id": str(invitation.space_id) if invitation.space_id else None,
                    "accepted_by": str(actor_id),
                    "tenant_membership_version": tenant_membership.version,
                    "space_membership_version": (
                        space_membership.version if space_membership else None
                    ),
                },
            )
            return InvitationAccepted(
                tenant_id=invitation.tenant_id,
                space_id=invitation.space_id,
                tenant_membership_version=tenant_membership.version,
                space_membership_version=space_membership.version if space_membership else None,
                replayed=False,
            )

    def update_tenant_membership(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        role: str,
        status: str,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> MembershipChanged:
        """CAS-update one Tenant membership and invalidate all user sessions."""

        changed_at = now or _utcnow()
        _require_aware(changed_at, "now")
        _validate_idempotency_key(idempotency_key)
        if role not in TENANT_ROLES or status not in ("active", "suspended", "removed"):
            raise LifecycleError(
                "invalid_membership", "Tenant membership role or status is invalid"
            )
        if status == "removed":
            raise LifecycleError(
                "membership_removal_preflight_required",
                "member removal requires resource impact preview and transfer",
            )
        if expected_version < 1:
            raise LifecycleError("invalid_membership_version", "expected version must be positive")

        request_digest = _request_hash(
            {
                "actor_id": str(actor_id),
                "tenant_id": str(tenant_id),
                "user_id": str(user_id),
                "role": role,
                "status": status,
                "expected_version": expected_version,
            }
        )
        event_type = "tenant.membership.updated"
        with self._session_factory.begin() as db:
            replay = self._load_receipt(db, idempotency_key, request_digest, event_type)
            if replay is not None:
                return self._membership_result(replay, replayed=True)

            actor_membership = self._active_tenant_admin(db, tenant_id, actor_id)
            target = db.get(TenantMembership, (tenant_id, user_id))
            if target is None:
                raise LifecycleError("membership_not_found", "Tenant membership does not exist")
            if target.status == "invited":
                raise LifecycleError(
                    "invitation_acceptance_required",
                    "invited membership must use invitation acceptance",
                )
            if target.status == "removed":
                raise LifecycleError(
                    "membership_restore_operation_required",
                    "removed membership requires an audited restore operation",
                )
            if target.role == "owner" or role == "owner":
                raise LifecycleError(
                    "ownership_transfer_required",
                    "Tenant Owner changes require the ownership-transfer workflow",
                )
            if role == "admin" and target.role != "admin":
                raise LifecycleError(
                    "privileged_role_operation_required",
                    "Tenant admin elevation requires fresh authentication "
                    "and an audited operation",
                )
            if (target.role == "admin" or role == "admin") and actor_membership.role != "owner":
                raise LifecycleError("forbidden", "only a Tenant Owner can change admin roles")
            if target.role == role and target.status == status:
                raise LifecycleError("membership_unchanged", "membership already has these values")

            new_version = expected_version + 1
            update_result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(TenantMembership)
                    .where(
                        TenantMembership.tenant_id == tenant_id,
                        TenantMembership.user_id == user_id,
                        TenantMembership.version == expected_version,
                    )
                    .values(role=role, status=status, version=new_version)
                ),
            )
            if update_result.rowcount != 1:
                raise LifecycleError(
                    "membership_version_conflict", "Tenant membership changed concurrently"
                )

            security_version, revoked_count = self._invalidate_user_sessions(
                db, user_id=user_id, revoked_at=changed_at
            )
            payload: dict[str, object] = {
                "scope": "tenant",
                "tenant_id": str(tenant_id),
                "user_id": str(user_id),
                "role": role,
                "status": status,
                "membership_version": new_version,
                "security_version": security_version,
                "revoked_session_count": revoked_count,
                "changed_by": str(actor_id),
            }
            self._add_outbox_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="tenant_membership",
                aggregate_key=f"{tenant_id}:{user_id}",
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=request_digest,
                payload=payload,
            )
            return self._membership_result(payload, replayed=False)

    def update_space_membership(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        user_id: UUID,
        role: str,
        status: str,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> MembershipChanged:
        """CAS-update one Space membership and invalidate all user sessions."""

        changed_at = now or _utcnow()
        _require_aware(changed_at, "now")
        _validate_idempotency_key(idempotency_key)
        if role not in SPACE_ROLES or status not in ("active", "suspended", "removed"):
            raise LifecycleError(
                "invalid_membership", "Space membership role or status is invalid"
            )
        if status == "removed":
            raise LifecycleError(
                "membership_removal_preflight_required",
                "member removal requires resource impact preview and transfer",
            )
        if expected_version < 1:
            raise LifecycleError("invalid_membership_version", "expected version must be positive")

        request_digest = _request_hash(
            {
                "actor_id": str(actor_id),
                "tenant_id": str(tenant_id),
                "space_id": str(space_id),
                "user_id": str(user_id),
                "role": role,
                "status": status,
                "expected_version": expected_version,
            }
        )
        event_type = "space.membership.updated"
        with self._session_factory.begin() as db:
            replay = self._load_receipt(db, idempotency_key, request_digest, event_type)
            if replay is not None:
                return self._membership_result(replay, replayed=True)

            actor_tenant = db.get(TenantMembership, (tenant_id, actor_id))
            tenant_admin = (
                actor_tenant is not None
                and actor_tenant.status == "active"
                and actor_tenant.role in ("owner", "admin")
            )
            actor_space = db.get(SpaceMembership, (tenant_id, space_id, actor_id))
            space_admin = (
                actor_space is not None
                and actor_space.status == "active"
                and actor_space.role in ("owner", "admin")
            )
            if not tenant_admin and not space_admin:
                raise LifecycleError("forbidden", "active Space administrator is required")

            target = db.get(SpaceMembership, (tenant_id, space_id, user_id))
            if target is None:
                raise LifecycleError("membership_not_found", "Space membership does not exist")
            if target.status == "invited":
                raise LifecycleError(
                    "invitation_acceptance_required",
                    "invited membership must use invitation acceptance",
                )
            if target.status == "removed":
                raise LifecycleError(
                    "membership_restore_operation_required",
                    "removed membership requires an audited restore operation",
                )
            if target.role == "owner" or role == "owner":
                raise LifecycleError(
                    "ownership_transfer_required",
                    "Space Owner changes require the ownership-transfer workflow",
                )
            if role == "admin" and target.role != "admin":
                raise LifecycleError(
                    "privileged_role_operation_required",
                    "Space admin elevation requires fresh authentication and an audited operation",
                )
            if (
                (target.role == "admin" or role == "admin")
                and not tenant_admin
                and (actor_space is None or actor_space.role != "owner")
            ):
                raise LifecycleError("forbidden", "Space Owner or Tenant admin is required")
            if status == "active":
                tenant_target = db.get(TenantMembership, (tenant_id, user_id))
                if tenant_target is None or tenant_target.status != "active":
                    raise LifecycleError(
                        "tenant_membership_inactive",
                        "active Space membership requires active Tenant membership",
                    )
            if target.role == role and target.status == status:
                raise LifecycleError("membership_unchanged", "membership already has these values")

            new_version = expected_version + 1
            update_result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(SpaceMembership)
                    .where(
                        SpaceMembership.tenant_id == tenant_id,
                        SpaceMembership.space_id == space_id,
                        SpaceMembership.user_id == user_id,
                        SpaceMembership.version == expected_version,
                    )
                    .values(role=role, status=status, version=new_version)
                ),
            )
            if update_result.rowcount != 1:
                raise LifecycleError(
                    "membership_version_conflict", "Space membership changed concurrently"
                )

            security_version, revoked_count = self._invalidate_user_sessions(
                db, user_id=user_id, revoked_at=changed_at
            )
            payload: dict[str, object] = {
                "scope": "space",
                "tenant_id": str(tenant_id),
                "space_id": str(space_id),
                "user_id": str(user_id),
                "role": role,
                "status": status,
                "membership_version": new_version,
                "security_version": security_version,
                "revoked_session_count": revoked_count,
                "changed_by": str(actor_id),
            }
            self._add_outbox_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="space_membership",
                aggregate_key=f"{tenant_id}:{space_id}:{user_id}",
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=request_digest,
                payload=payload,
            )
            return self._membership_result(payload, replayed=False)

    @staticmethod
    def _validate_invitation_roles(
        tenant_role: str, space_id: UUID | None, space_role: str | None
    ) -> None:
        if tenant_role not in TENANT_ROLES:
            raise LifecycleError("invalid_role", "invitation Tenant role is invalid")
        if (space_id is None) != (space_role is None):
            raise LifecycleError("invalid_scope", "Space and Space role must be supplied together")
        if space_role is not None and space_role not in SPACE_ROLES:
            raise LifecycleError("invalid_role", "invitation Space role is invalid")
        if tenant_role == "owner" or space_role == "owner":
            raise LifecycleError(
                "ownership_transfer_required", "Owner roles cannot be granted by invitation"
            )

    @staticmethod
    def _authorize_invitation(
        db: Session,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        tenant_role: str,
        space_id: UUID | None,
        space_role: str | None,
    ) -> None:
        user = db.get(GlobalUser, actor_id)
        tenant = db.get(Tenant, tenant_id)
        if user is None or user.status != "active":
            raise LifecycleError("user_inactive", "active user is required")
        if tenant is None or tenant.status not in ("trial", "active"):
            raise LifecycleError("tenant_inactive", "active Tenant is required")

        tenant_membership = db.get(TenantMembership, (tenant_id, actor_id))
        if (
            tenant_membership is not None
            and tenant_membership.status == "active"
            and tenant_membership.role in ("owner", "admin")
        ):
            if space_id is not None:
                space = db.get(Space, space_id)
                if space is None or space.tenant_id != tenant_id or space.status != "active":
                    raise LifecycleError("space_inactive", "active Space is required")
            return

        if space_id is None or tenant_role != "member" or space_role == "owner":
            raise LifecycleError("forbidden", "Tenant administrator is required")
        space = db.get(Space, space_id)
        space_membership = db.get(SpaceMembership, (tenant_id, space_id, actor_id))
        if (
            space is None
            or space.tenant_id != tenant_id
            or space.status != "active"
            or tenant_membership is None
            or tenant_membership.status != "active"
            or space_membership is None
            or space_membership.status != "active"
            or space_membership.role not in ("owner", "admin")
        ):
            raise LifecycleError("forbidden", "active Space administrator is required")

    @staticmethod
    def _active_tenant_admin(db: Session, tenant_id: UUID, actor_id: UUID) -> TenantMembership:
        actor = db.get(TenantMembership, (tenant_id, actor_id))
        if actor is None or actor.status != "active" or actor.role not in ("owner", "admin"):
            raise LifecycleError("forbidden", "active Tenant administrator is required")
        return actor

    @staticmethod
    def _invalidate_user_sessions(
        db: Session, *, user_id: UUID, revoked_at: datetime
    ) -> tuple[int, int]:
        security_version = db.execute(
            sa.update(GlobalUser)
            .where(GlobalUser.id == user_id, GlobalUser.status != "deleted")
            .values(security_version=GlobalUser.security_version + 1)
            .returning(GlobalUser.security_version)
            .execution_options(synchronize_session=False)
        ).scalar_one_or_none()
        if security_version is None:
            raise LifecycleError("user_inactive", "target user does not exist")
        result = cast(
            CursorResult[tuple[object]],
            db.execute(
                sa.update(AuthSessionRecord)
                .where(
                    AuthSessionRecord.user_id == user_id,
                    AuthSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=revoked_at)
            ),
        )
        return security_version, result.rowcount

    @staticmethod
    def _load_receipt(
        db: Session, idempotency_key: str, request_hash: str, event_type: str
    ) -> dict[str, object] | None:
        receipt = db.execute(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key == idempotency_key
            )
        ).scalar_one_or_none()
        if receipt is None:
            return None
        if receipt.request_hash != request_hash or receipt.event_type != event_type:
            raise LifecycleError(
                "idempotency_conflict", "idempotency key was used for another request"
            )
        return receipt.payload

    @staticmethod
    def _add_outbox_event(
        db: Session,
        *,
        tenant_id: UUID,
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
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=payload,
                attempt_count=0,
            )
        )

    @staticmethod
    def _membership_result(payload: dict[str, object], *, replayed: bool) -> MembershipChanged:
        return MembershipChanged(
            scope=cast(str, payload["scope"]),
            membership_version=cast(int, payload["membership_version"]),
            security_version=cast(int, payload["security_version"]),
            revoked_session_count=cast(int, payload["revoked_session_count"]),
            replayed=replayed,
        )

    @staticmethod
    def _accepted_invitation_result(
        db: Session, invitation: MembershipInvitation, *, replayed: bool
    ) -> InvitationAccepted:
        tenant_membership = db.get(
            TenantMembership, (invitation.tenant_id, cast(UUID, invitation.accepted_by))
        )
        if tenant_membership is None:
            raise LifecycleError(
                "invitation_state_invalid", "accepted invitation has no Tenant membership"
            )
        space_version: int | None = None
        if invitation.space_id is not None:
            space_membership = db.get(
                SpaceMembership,
                (
                    invitation.tenant_id,
                    invitation.space_id,
                    cast(UUID, invitation.accepted_by),
                ),
            )
            if space_membership is None:
                raise LifecycleError(
                    "invitation_state_invalid", "accepted invitation has no Space membership"
                )
            space_version = space_membership.version
        return InvitationAccepted(
            tenant_id=invitation.tenant_id,
            space_id=invitation.space_id,
            tenant_membership_version=tenant_membership.version,
            space_membership_version=space_version,
            replayed=replayed,
        )


def _comparable_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
