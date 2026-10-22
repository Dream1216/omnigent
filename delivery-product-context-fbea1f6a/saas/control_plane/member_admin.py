"""Tenant-member directory and invitation administration projections."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import (
    INVITATION_STATUSES,
    MEMBERSHIP_STATUSES,
    TENANT_ROLES,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    MembershipInvitation,
    Space,
    SpaceMembership,
    TenantMembership,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.permissions import TENANT_ROLE_PERMISSIONS
from saas.control_plane.rls import RlsContext, apply_rls_context


@dataclass(frozen=True, slots=True)
class MemberLoginMethodView:
    """Non-secret login-method posture visible to a Tenant administrator."""

    provider: str
    status: str
    email_verified: bool


@dataclass(frozen=True, slots=True)
class MemberSpaceAccessView:
    """One versioned Space membership projected into the Tenant directory."""

    space_id: UUID
    space_name: str
    role: str
    status: str
    version: int


@dataclass(frozen=True, slots=True)
class TenantMemberView:
    """Privacy-bounded Tenant member row; identity subjects are never exposed."""

    user_id: UUID
    display_name: str | None
    primary_email_normalized: str | None
    user_status: str
    tenant_role: str
    tenant_status: str
    tenant_membership_version: int
    joined_at: datetime | None
    login_methods: tuple[MemberLoginMethodView, ...]
    space_access: tuple[MemberSpaceAccessView, ...]


@dataclass(frozen=True, slots=True)
class MembershipInvitationView:
    """Pending or historical invitation metadata without its bearer secret."""

    invitation_id: UUID
    email_normalized: str
    tenant_role: str
    space_id: UUID | None
    space_name: str | None
    space_role: str | None
    status: str
    version: int
    expires_at: datetime
    created_by: UUID
    accepted_by: UUID | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class InvitationReissued:
    """Rotated invitation token returned once and never persisted in plaintext."""

    invitation_id: UUID
    token: str | None
    version: int
    expires_at: datetime
    replayed: bool


@dataclass(frozen=True, slots=True)
class InvitationRevoked:
    """Committed invitation revocation version."""

    invitation_id: UUID
    version: int
    replayed: bool


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _comparable(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LifecycleError("invalid_timestamp", f"{field} must include a timezone")


def _validate_idempotency_key(value: str) -> None:
    if not value or len(value) > 128:
        raise LifecycleError(
            "invalid_idempotency_key", "idempotency key must contain 1 to 128 characters"
        )


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode("utf-8")).hexdigest()


def _token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def _escaped_like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


class TenantMemberAdministrationService:
    """Expose scope-safe member administration without a second identity authority."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def list_members(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        query: str | None = None,
        status: str | None = None,
        role: str | None = None,
        exact_user_id: UUID | None = None,
        after_id: UUID | None = None,
        limit: int | None = None,
    ) -> tuple[TenantMemberView, ...]:
        """List only members of one authorized Tenant with bounded login metadata."""

        cleaned_query = query.strip().casefold() if query is not None else ""
        if len(cleaned_query) > 128:
            raise LifecycleError("member_query_invalid", "member query is too long")
        if status is not None and status not in MEMBERSHIP_STATUSES:
            raise LifecycleError("member_status_invalid", "member status filter is invalid")
        if role is not None and role not in TENANT_ROLES:
            raise LifecycleError("member_role_invalid", "member role filter is invalid")
        self._validate_page_limit(limit)

        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            self._require_permission(db, actor_id, tenant_id, "membership.read")
            statement = (
                sa.select(TenantMembership, GlobalUser)
                .join(GlobalUser, GlobalUser.id == TenantMembership.user_id)
                .where(TenantMembership.tenant_id == tenant_id)
            )
            if status is not None:
                statement = statement.where(TenantMembership.status == status)
            if role is not None:
                statement = statement.where(TenantMembership.role == role)
            if exact_user_id is not None:
                statement = statement.where(TenantMembership.user_id == exact_user_id)
            if after_id is not None:
                statement = statement.where(TenantMembership.user_id > after_id)
            if cleaned_query:
                pattern = _escaped_like(cleaned_query)
                statement = statement.where(
                    sa.or_(
                        sa.func.lower(sa.func.coalesce(GlobalUser.display_name, "")).like(
                            pattern, escape="\\"
                        ),
                        sa.func.lower(
                            sa.func.coalesce(GlobalUser.primary_email_normalized, "")
                        ).like(pattern, escape="\\"),
                        sa.cast(GlobalUser.id, sa.String).like(pattern, escape="\\"),
                    )
                )
            statement = statement.order_by(TenantMembership.user_id)
            if limit is not None:
                statement = statement.limit(limit)
            rows = list(db.execute(statement).all())
            if not rows:
                return ()

            user_ids = tuple(membership.user_id for membership, _user in rows)
            spaces_by_user: dict[UUID, list[MemberSpaceAccessView]] = {
                user_id: [] for user_id in user_ids
            }
            space_rows = db.execute(
                sa.select(SpaceMembership, Space)
                .join(
                    Space,
                    sa.and_(
                        Space.tenant_id == SpaceMembership.tenant_id,
                        Space.id == SpaceMembership.space_id,
                    ),
                )
                .where(
                    SpaceMembership.tenant_id == tenant_id,
                    SpaceMembership.user_id.in_(user_ids),
                )
                .order_by(SpaceMembership.user_id, Space.name, SpaceMembership.space_id)
            ).all()
            for membership, space in space_rows:
                spaces_by_user[membership.user_id].append(
                    MemberSpaceAccessView(
                        space_id=membership.space_id,
                        space_name=space.name,
                        role=membership.role,
                        status=membership.status,
                        version=membership.version,
                    )
                )

            methods_by_user: dict[UUID, list[MemberLoginMethodView]] = {
                user_id: [] for user_id in user_ids
            }
            identity_rows = db.execute(
                sa.select(
                    IdentityConnection.user_id,
                    IdentityConnection.provider,
                    IdentityConnection.status,
                    IdentityConnection.email_verified,
                )
                .where(IdentityConnection.user_id.in_(user_ids))
                .order_by(IdentityConnection.user_id, IdentityConnection.provider)
            ).all()
            for user_id, provider, identity_status, email_verified in identity_rows:
                methods_by_user[user_id].append(
                    MemberLoginMethodView(
                        provider=provider,
                        status=identity_status,
                        email_verified=email_verified,
                    )
                )

            return tuple(
                TenantMemberView(
                    user_id=membership.user_id,
                    display_name=user.display_name,
                    primary_email_normalized=user.primary_email_normalized,
                    user_status=user.status,
                    tenant_role=membership.role,
                    tenant_status=membership.status,
                    tenant_membership_version=membership.version,
                    joined_at=membership.joined_at,
                    login_methods=tuple(methods_by_user[membership.user_id]),
                    space_access=tuple(spaces_by_user[membership.user_id]),
                )
                for membership, user in rows
            )

    def get_member(self, *, actor_id: UUID, tenant_id: UUID, user_id: UUID) -> TenantMemberView:
        """Return one exact member after applying the same directory authorization."""

        values = self.list_members(
            actor_id=actor_id,
            tenant_id=tenant_id,
            exact_user_id=user_id,
            limit=2,
        )
        for value in values:
            if value.user_id == user_id:
                return value
        raise LifecycleError("membership_not_found", "Tenant membership does not exist")

    def list_invitations(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        query: str | None = None,
        status: str | None = None,
        after_id: UUID | None = None,
        limit: int | None = None,
        now: datetime | None = None,
    ) -> tuple[MembershipInvitationView, ...]:
        """List invitation metadata while deriving expiry from server time."""

        checked_at = now or _now()
        _require_aware(checked_at, "now")
        cleaned_query = query.strip().casefold() if query is not None else ""
        if len(cleaned_query) > 128:
            raise LifecycleError("invitation_query_invalid", "invitation query is too long")
        if status is not None and status not in INVITATION_STATUSES:
            raise LifecycleError("invitation_status_invalid", "invitation status is invalid")
        self._validate_page_limit(limit)

        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            self._require_permission(db, actor_id, tenant_id, "membership.read")
            statement = (
                sa.select(MembershipInvitation, Space.name)
                .outerjoin(
                    Space,
                    sa.and_(
                        Space.tenant_id == MembershipInvitation.tenant_id,
                        Space.id == MembershipInvitation.space_id,
                    ),
                )
                .where(MembershipInvitation.tenant_id == tenant_id)
            )
            if status == "pending":
                statement = statement.where(
                    MembershipInvitation.status == "pending",
                    MembershipInvitation.expires_at > checked_at,
                )
            elif status == "expired":
                statement = statement.where(
                    sa.or_(
                        MembershipInvitation.status == "expired",
                        sa.and_(
                            MembershipInvitation.status == "pending",
                            MembershipInvitation.expires_at <= checked_at,
                        ),
                    )
                )
            elif status is not None:
                statement = statement.where(MembershipInvitation.status == status)
            if after_id is not None:
                statement = statement.where(MembershipInvitation.id > after_id)
            if cleaned_query:
                statement = statement.where(
                    sa.func.lower(MembershipInvitation.email_normalized).like(
                        _escaped_like(cleaned_query), escape="\\"
                    )
                )
            statement = statement.order_by(MembershipInvitation.id)
            if limit is not None:
                statement = statement.limit(limit)
            values = db.execute(statement).all()
            return tuple(
                self._invitation_view(invitation, space_name, checked_at)
                for invitation, space_name in values
            )

    def reissue_invitation(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        invitation_id: UUID,
        expected_version: int,
        expires_at: datetime,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> InvitationReissued:
        """Rotate one unconsumed invitation token and extend its bounded expiry."""

        changed_at = now or _now()
        _require_aware(changed_at, "now")
        _require_aware(expires_at, "expires_at")
        _validate_idempotency_key(idempotency_key)
        cleaned_reason = reason.strip()
        if expected_version < 1:
            raise LifecycleError("invitation_version_invalid", "invitation version is invalid")
        if expires_at <= changed_at or expires_at > changed_at + timedelta(days=30):
            raise LifecycleError(
                "invitation_expiry_invalid", "invitation expiry must be within 30 days"
            )
        if not cleaned_reason or len(cleaned_reason) > 512:
            raise LifecycleError("reason_invalid", "reason must contain 1 to 512 characters")
        request_hash = _digest(
            {
                "actor_id": str(actor_id),
                "tenant_id": str(tenant_id),
                "invitation_id": str(invitation_id),
                "expected_version": expected_version,
                "expires_at": expires_at.isoformat(),
                "reason": cleaned_reason,
            }
        )
        event_type = "membership.invitation.reissued"
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            invitation = db.execute(
                sa.select(MembershipInvitation)
                .where(
                    MembershipInvitation.id == invitation_id,
                    MembershipInvitation.tenant_id == tenant_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if invitation is None:
                raise LifecycleError("invitation_not_found", "invitation does not exist")
            self._require_invitation_manager(db, actor_id, invitation)
            replay = self._receipt(db, tenant_id, idempotency_key, request_hash, event_type)
            if replay is not None:
                return InvitationReissued(
                    invitation_id=UUID(cast(str, replay["invitation_id"])),
                    token=None,
                    version=cast(int, replay["version"]),
                    expires_at=datetime.fromisoformat(cast(str, replay["expires_at"])),
                    replayed=True,
                )
            if invitation.status not in ("pending", "expired"):
                raise LifecycleError(
                    "invitation_not_reissuable",
                    "accepted or revoked invitation cannot be reissued",
                )
            if invitation.version != expected_version:
                raise LifecycleError(
                    "invitation_version_conflict", "invitation changed concurrently"
                )
            raw_token = secrets.token_urlsafe(32)
            invitation.token_hash = _token_hash(raw_token)
            invitation.status = "pending"
            invitation.expires_at = expires_at
            invitation.version += 1
            payload: dict[str, object] = {
                "invitation_id": str(invitation.id),
                "tenant_id": str(invitation.tenant_id),
                "space_id": str(invitation.space_id) if invitation.space_id else None,
                "email_normalized": invitation.email_normalized,
                "tenant_role": invitation.tenant_role,
                "space_role": invitation.space_role,
                "expires_at": expires_at.isoformat(),
                "version": invitation.version,
                "changed_by": str(actor_id),
                "reason": cleaned_reason,
            }
            self._event(
                db,
                tenant_id=tenant_id,
                invitation_id=invitation.id,
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=payload,
            )
            return InvitationReissued(
                invitation_id=invitation.id,
                token=raw_token,
                version=invitation.version,
                expires_at=expires_at,
                replayed=False,
            )

    def revoke_invitation(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        invitation_id: UUID,
        expected_version: int,
        reason: str,
        idempotency_key: str,
    ) -> InvitationRevoked:
        """CAS-revoke one invitation and its bearer token."""

        cleaned_reason = reason.strip()
        _validate_idempotency_key(idempotency_key)
        if expected_version < 1:
            raise LifecycleError("invitation_version_invalid", "invitation version is invalid")
        if not cleaned_reason or len(cleaned_reason) > 512:
            raise LifecycleError("reason_invalid", "reason must contain 1 to 512 characters")
        request_hash = _digest(
            {
                "actor_id": str(actor_id),
                "tenant_id": str(tenant_id),
                "invitation_id": str(invitation_id),
                "expected_version": expected_version,
                "reason": cleaned_reason,
            }
        )
        event_type = "membership.invitation.revoked"
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            invitation = db.execute(
                sa.select(MembershipInvitation)
                .where(
                    MembershipInvitation.id == invitation_id,
                    MembershipInvitation.tenant_id == tenant_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if invitation is None:
                raise LifecycleError("invitation_not_found", "invitation does not exist")
            self._require_invitation_manager(db, actor_id, invitation)
            replay = self._receipt(db, tenant_id, idempotency_key, request_hash, event_type)
            if replay is not None:
                return InvitationRevoked(
                    invitation_id=UUID(cast(str, replay["invitation_id"])),
                    version=cast(int, replay["version"]),
                    replayed=True,
                )
            if invitation.status not in ("pending", "expired"):
                raise LifecycleError(
                    "invitation_not_revocable", "accepted or revoked invitation cannot be revoked"
                )
            if invitation.version != expected_version:
                raise LifecycleError(
                    "invitation_version_conflict", "invitation changed concurrently"
                )
            invitation.status = "revoked"
            invitation.version += 1
            payload: dict[str, object] = {
                "invitation_id": str(invitation.id),
                "tenant_id": str(invitation.tenant_id),
                "space_id": str(invitation.space_id) if invitation.space_id else None,
                "email_normalized": invitation.email_normalized,
                "version": invitation.version,
                "reason": cleaned_reason,
                "changed_by": str(actor_id),
            }
            self._event(
                db,
                tenant_id=tenant_id,
                invitation_id=invitation.id,
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=payload,
            )
            return InvitationRevoked(
                invitation_id=invitation.id,
                version=invitation.version,
                replayed=False,
            )

    @staticmethod
    def _validate_page_limit(limit: int | None) -> None:
        if limit is not None and not 1 <= limit <= 101:
            raise LifecycleError("page_limit_invalid", "page limit is invalid")

    @staticmethod
    def _require_permission(
        db: Session, actor_id: UUID, tenant_id: UUID, permission: str
    ) -> TenantMembership:
        actor = db.get(TenantMembership, (tenant_id, actor_id))
        if (
            actor is None
            or actor.status != "active"
            or permission not in TENANT_ROLE_PERMISSIONS[actor.role]
        ):
            raise LifecycleError("forbidden", f"{permission} permission is required")
        return actor

    @staticmethod
    def _require_invitation_manager(
        db: Session, actor_id: UUID, invitation: MembershipInvitation
    ) -> None:
        tenant_actor = db.get(TenantMembership, (invitation.tenant_id, actor_id))
        if (
            tenant_actor is not None
            and tenant_actor.status == "active"
            and "membership.invite" in TENANT_ROLE_PERMISSIONS[tenant_actor.role]
        ):
            return
        if invitation.space_id is None or invitation.tenant_role != "member":
            raise LifecycleError("forbidden", "membership.invite permission is required")
        space_actor = db.get(
            SpaceMembership, (invitation.tenant_id, invitation.space_id, actor_id)
        )
        if (
            tenant_actor is None
            or tenant_actor.status != "active"
            or space_actor is None
            or space_actor.status != "active"
            or space_actor.role not in ("owner", "admin")
        ):
            raise LifecycleError("forbidden", "active Space administrator is required")

    @staticmethod
    def _receipt(
        db: Session,
        tenant_id: UUID,
        idempotency_key: str,
        request_hash: str,
        event_type: str,
    ) -> dict[str, object] | None:
        receipt = db.execute(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key
                == scoped_idempotency_key("tenant", tenant_id, idempotency_key)
            )
        ).scalar_one_or_none()
        if receipt is None:
            return None
        if receipt.request_hash != request_hash or receipt.event_type != event_type:
            raise LifecycleError(
                "idempotency_conflict", "idempotency key belongs to another request"
            )
        return receipt.payload

    @staticmethod
    def _event(
        db: Session,
        *,
        tenant_id: UUID,
        invitation_id: UUID,
        event_type: str,
        idempotency_key: str,
        request_hash: str,
        payload: dict[str, object],
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=tenant_id,
                aggregate_type="membership_invitation",
                aggregate_key=str(invitation_id),
                event_type=event_type,
                idempotency_key=scoped_idempotency_key("tenant", tenant_id, idempotency_key),
                request_hash=request_hash,
                payload=payload,
                attempt_count=0,
            )
        )

    @staticmethod
    def _invitation_view(
        invitation: MembershipInvitation, space_name: str | None, now: datetime
    ) -> MembershipInvitationView:
        status = invitation.status
        if status == "pending" and _comparable(invitation.expires_at) <= now:
            status = "expired"
        return MembershipInvitationView(
            invitation_id=invitation.id,
            email_normalized=invitation.email_normalized,
            tenant_role=invitation.tenant_role,
            space_id=invitation.space_id,
            space_name=space_name,
            space_role=invitation.space_role,
            status=status,
            version=invitation.version,
            expires_at=_comparable(invitation.expires_at),
            created_by=invitation.created_by,
            accepted_by=invitation.accepted_by,
            created_at=_comparable(invitation.created_at),
        )
