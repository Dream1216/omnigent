"""PC2 global user, Tenant lifecycle, and Owner Recovery authority."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.api_credential_models import ApiCredentialRecord, ServiceAccountRecord
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConflict,
    OidcLoginTransaction,
    Tenant,
    TenantMembership,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.platform_models import PlatformLifecycleOperationRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context

_FRESH_AUTH_WINDOW = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class PlatformLifecycleResult:
    operation_id: UUID
    action: str
    target_id: UUID
    result: dict[str, object]
    replayed: bool


@dataclass(frozen=True, slots=True)
class OwnerRecoveryPreview:
    tenant_id: UUID
    source_owner_id: UUID | None
    target_user_id: UUID
    tenant_version: int
    source_membership_version: int | None
    target_membership_version: int | None
    blockers: tuple[str, ...]
    preview_hash: str


@dataclass(frozen=True, slots=True)
class IdentityConflictCaseView:
    conflict_id: UUID
    provider: str
    candidate_user_id: UUID | None
    status: str
    version: int
    platform_review_status: str
    platform_reviewed_by_principal_id: UUID | None
    platform_reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class _UserState:
    status: str
    security_version: int


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


def _required_text(value: str, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise PlatformSecurityError("platform_command_invalid", f"{field} is invalid")
    return cleaned


def _require_fresh(actor: ValidatedPlatformPrincipal, changed_at: datetime) -> None:
    authenticated_at = _as_utc(actor.authenticated_at)
    if authenticated_at > changed_at or changed_at - authenticated_at > _FRESH_AUTH_WINDOW:
        raise PlatformSecurityError(
            "platform_fresh_auth_required", "fresh Staff authentication is required"
        )


def _rowcount(result: object) -> int:
    return cast(CursorResult[tuple[object]], result).rowcount


class PlatformLifecycleService:
    """Execute content-blind, target-bound PC2 lifecycle commands."""

    def __init__(self, governance_factory: sessionmaker[Session]) -> None:
        self._governance = governance_factory

    def list_identity_conflicts(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        status: str | None = "pending",
        cursor: UUID | None = None,
        limit: int = 50,
        now: datetime | None = None,
    ) -> tuple[IdentityConflictCaseView, ...]:
        """Return content-blind conflict cases; raw email, issuer, and subject never leave auth."""

        if limit < 1 or limit > 200:
            raise PlatformSecurityError("platform_query_invalid", "limit is invalid")
        if status not in {None, "pending", "approved", "rejected"}:
            raise PlatformSecurityError("platform_query_invalid", "status is invalid")
        checked_at = now or _now()
        with self._governance.begin() as db:
            self._bind(db, actor)
            self._authorize(db, actor, "platform.identity_conflict.read", checked_at)
            query = sa.select(
                IdentityConflict.id,
                IdentityConflict.provider,
                IdentityConflict.candidate_user_id,
                IdentityConflict.status,
                IdentityConflict.version,
                IdentityConflict.platform_review_status,
                IdentityConflict.platform_reviewed_by_principal_id,
                IdentityConflict.platform_reviewed_at,
                IdentityConflict.created_at,
                IdentityConflict.updated_at,
            )
            if status is not None:
                query = query.where(IdentityConflict.status == status)
            if cursor is not None:
                query = query.where(IdentityConflict.id > cursor)
            rows = db.execute(query.order_by(IdentityConflict.id).limit(limit)).all()
            return tuple(
                IdentityConflictCaseView(
                    conflict_id=row.id,
                    provider=row.provider,
                    candidate_user_id=row.candidate_user_id,
                    status=row.status,
                    version=row.version,
                    platform_review_status=row.platform_review_status,
                    platform_reviewed_by_principal_id=row.platform_reviewed_by_principal_id,
                    platform_reviewed_at=row.platform_reviewed_at,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
                for row in rows
            )

    def review_identity_conflict(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        conflict_id: UUID,
        decision: Literal["assign", "block"],
        candidate_user_id: UUID | None,
        expected_version: int,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PlatformLifecycleResult:
        """Assign one candidate or block a conflict; Staff can never directly link the subject."""

        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        if decision not in {"assign", "block"}:
            raise PlatformSecurityError("platform_command_invalid", "decision is invalid")
        if (decision == "assign") != (candidate_user_id is not None):
            raise PlatformSecurityError(
                "platform_command_invalid",
                "assign requires one candidate and block forbids a candidate",
            )
        cleaned_approval = _required_text(approval_ref, "approval_ref", 256)
        cleaned_reason = _required_text(reason, "reason", 1024)
        key = _required_text(idempotency_key, "idempotency_key", 128)
        payload: dict[str, object] = {
            "action": f"identity_conflict_{decision}",
            "conflict_id": str(conflict_id),
            "candidate_user_id": str(candidate_user_id) if candidate_user_id else None,
            "expected_version": expected_version,
            "approval_ref": cleaned_approval,
            "reason": cleaned_reason,
        }
        request_hash = _digest(payload)
        with self._governance.begin() as db:
            self._bind(
                db,
                actor,
                user_id=candidate_user_id,
                identity_conflict_id=conflict_id,
            )
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, "platform.identity_conflict.manage", changed_at)
            replay = self._replay(db, actor.principal_id, key, request_hash)
            if replay is not None:
                return replay
            conflict = db.execute(
                sa.select(
                    IdentityConflict.id,
                    IdentityConflict.status,
                    IdentityConflict.version,
                    IdentityConflict.platform_review_status,
                )
                .where(IdentityConflict.id == conflict_id)
                .with_for_update()
            ).one_or_none()
            if conflict is None:
                raise PlatformSecurityError(
                    "platform_identity_conflict_not_found", "Identity Conflict was not found"
                )
            if (
                conflict.status != "pending"
                or conflict.version != expected_version
                or conflict.platform_review_status != "unreviewed"
            ):
                raise PlatformSecurityError(
                    "platform_identity_conflict_conflict",
                    "Identity Conflict changed or was already reviewed",
                )
            if candidate_user_id is not None:
                candidate = db.execute(
                    sa.select(GlobalUser.status).where(GlobalUser.id == candidate_user_id)
                ).scalar_one_or_none()
                if candidate != "active":
                    raise PlatformSecurityError(
                        "platform_identity_conflict_blocked",
                        "assigned candidate must be an active Global User",
                    )
            next_version = conflict.version + 1
            next_review_status = "assigned" if decision == "assign" else "blocked"
            updated = db.execute(
                sa.update(IdentityConflict)
                .where(
                    IdentityConflict.id == conflict_id,
                    IdentityConflict.status == "pending",
                    IdentityConflict.version == expected_version,
                    IdentityConflict.platform_review_status == "unreviewed",
                )
                .values(
                    candidate_user_id=candidate_user_id,
                    version=next_version,
                    platform_review_status=next_review_status,
                    platform_reviewed_by_principal_id=actor.principal_id,
                    platform_review_approval_ref=cleaned_approval,
                    platform_review_reason=cleaned_reason,
                    platform_reviewed_at=changed_at,
                    updated_at=changed_at,
                )
            )
            if _rowcount(updated) != 1:
                raise PlatformSecurityError(
                    "platform_identity_conflict_conflict",
                    "Identity Conflict changed concurrently",
                )
            result: dict[str, object] = {
                "status": "pending",
                "version": next_version,
                "platform_review_status": next_review_status,
                "candidate_user_id": (
                    str(candidate_user_id) if candidate_user_id is not None else None
                ),
                "customer_reauthentication_required": decision == "assign",
                "identity_connection_created": False,
            }
            return self._record(
                db,
                actor=actor,
                target_type="identity_conflict",
                target_id=conflict_id,
                tenant_id=None,
                action=f"identity_conflict_{decision}",
                key=key,
                request_hash=request_hash,
                approval_ref=cleaned_approval,
                reason=cleaned_reason,
                result=result,
                occurred_at=changed_at,
            )

    def suspend_user(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        user_id: UUID,
        expected_security_version: int,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PlatformLifecycleResult:
        return self._change_user_state(
            actor,
            user_id=user_id,
            expected_security_version=expected_security_version,
            expected_status="active",
            next_status="suspended",
            action="user_suspend",
            permission="platform.user.suspend",
            approval_ref=approval_ref,
            reason=reason,
            idempotency_key=idempotency_key,
            now=now,
        )

    def restore_user(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        user_id: UUID,
        expected_security_version: int,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PlatformLifecycleResult:
        return self._change_user_state(
            actor,
            user_id=user_id,
            expected_security_version=expected_security_version,
            expected_status="suspended",
            next_status="active",
            action="user_restore",
            permission="platform.user.restore",
            approval_ref=approval_ref,
            reason=reason,
            idempotency_key=idempotency_key,
            now=now,
        )

    def revoke_user_sessions(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        user_id: UUID,
        expected_security_version: int,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PlatformLifecycleResult:
        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        cleaned_reason = _required_text(reason, "reason", 1024)
        key = _required_text(idempotency_key, "idempotency_key", 128)
        payload: dict[str, object] = {
            "action": "user_sessions_revoke",
            "user_id": str(user_id),
            "expected_security_version": expected_security_version,
            "reason": cleaned_reason,
        }
        request_hash = _digest(payload)
        with self._governance.begin() as db:
            self._bind(db, actor, user_id=user_id)
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, "platform.user.sessions.revoke", changed_at)
            replay = self._replay(db, actor.principal_id, key, request_hash)
            if replay is not None:
                return replay
            user = self._locked_user(db, user_id)
            if user.status == "deleted" or user.security_version != expected_security_version:
                raise PlatformSecurityError(
                    "platform_user_conflict", "Global User state changed concurrently"
                )
            next_version = user.security_version + 1
            db.execute(
                sa.update(GlobalUser)
                .where(
                    GlobalUser.id == user_id,
                    GlobalUser.security_version == user.security_version,
                )
                .values(security_version=next_version, updated_at=changed_at)
            )
            revoked = self._revoke_sessions(db, user_id, changed_at)
            result: dict[str, object] = {
                "status": user.status,
                "security_version": next_version,
                "revoked_session_count": revoked,
            }
            return self._record(
                db,
                actor=actor,
                target_type="global_user",
                target_id=user_id,
                tenant_id=None,
                action="user_sessions_revoke",
                key=key,
                request_hash=request_hash,
                approval_ref="not-required:session-revocation",
                reason=cleaned_reason,
                result=result,
                occurred_at=changed_at,
            )

    def suspend_tenant(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID,
        expected_lifecycle_version: int,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PlatformLifecycleResult:
        return self._change_tenant_state(
            actor,
            tenant_id=tenant_id,
            expected_lifecycle_version=expected_lifecycle_version,
            allowed_statuses={"trial", "active"},
            next_status="suspended",
            action="tenant_suspend",
            approval_ref=approval_ref,
            reason=reason,
            idempotency_key=idempotency_key,
            now=now,
        )

    def restore_tenant(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID,
        expected_lifecycle_version: int,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PlatformLifecycleResult:
        return self._change_tenant_state(
            actor,
            tenant_id=tenant_id,
            expected_lifecycle_version=expected_lifecycle_version,
            allowed_statuses={"suspended"},
            next_status="active",
            action="tenant_restore",
            approval_ref=approval_ref,
            reason=reason,
            idempotency_key=idempotency_key,
            now=now,
        )

    def preview_owner_recovery(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID,
        target_user_id: UUID,
        now: datetime | None = None,
    ) -> OwnerRecoveryPreview:
        checked_at = now or _now()
        with self._governance.begin() as db:
            self._bind(db, actor, tenant_id=tenant_id)
            self._authorize(db, actor, "platform.tenant.owner_recover", checked_at)
            return self._owner_recovery_preview(db, tenant_id, target_user_id)

    def recover_tenant_owner(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID,
        target_user_id: UUID,
        expected_tenant_version: int,
        expected_source_membership_version: int,
        expected_target_membership_version: int,
        preview_hash: str,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PlatformLifecycleResult:
        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        cleaned_approval = _required_text(approval_ref, "approval_ref", 256)
        cleaned_reason = _required_text(reason, "reason", 1024)
        key = _required_text(idempotency_key, "idempotency_key", 128)
        supplied_preview = _required_text(preview_hash, "preview_hash", 64)
        payload: dict[str, object] = {
            "action": "tenant_owner_recover",
            "tenant_id": str(tenant_id),
            "target_user_id": str(target_user_id),
            "expected_tenant_version": expected_tenant_version,
            "expected_source_membership_version": expected_source_membership_version,
            "expected_target_membership_version": expected_target_membership_version,
            "preview_hash": supplied_preview,
            "approval_ref": cleaned_approval,
            "reason": cleaned_reason,
        }
        request_hash = _digest(payload)
        with self._governance.begin() as db:
            self._bind(db, actor, tenant_id=tenant_id)
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, "platform.tenant.owner_recover", changed_at)
            replay = self._replay(db, actor.principal_id, key, request_hash)
            if replay is not None:
                return replay
            preview = self._owner_recovery_preview(db, tenant_id, target_user_id, lock=True)
            if preview.blockers:
                raise PlatformSecurityError(
                    "platform_owner_recovery_blocked", "; ".join(preview.blockers)
                )
            if (
                preview.preview_hash != supplied_preview
                or preview.tenant_version != expected_tenant_version
                or preview.source_membership_version != expected_source_membership_version
                or preview.target_membership_version != expected_target_membership_version
                or preview.source_owner_id is None
            ):
                raise PlatformSecurityError(
                    "platform_owner_recovery_conflict", "Owner Recovery preflight is stale"
                )
            source = db.get(TenantMembership, (tenant_id, preview.source_owner_id))
            target = db.get(TenantMembership, (tenant_id, target_user_id))
            tenant = db.get(Tenant, tenant_id)
            if source is None or target is None or tenant is None:
                raise PlatformSecurityError(
                    "platform_owner_recovery_conflict", "Owner Recovery target changed"
                )
            source.role = "admin"
            source.version += 1
            target.role = "owner"
            target.version += 1
            tenant.lifecycle_version += 1
            tenant.updated_at = changed_at
            result: dict[str, object] = {
                "status": tenant.status,
                "lifecycle_version": tenant.lifecycle_version,
                "source_owner_id": str(source.user_id),
                "source_membership_version": source.version,
                "target_owner_id": str(target.user_id),
                "target_membership_version": target.version,
            }
            return self._record(
                db,
                actor=actor,
                target_type="tenant",
                target_id=tenant_id,
                tenant_id=tenant_id,
                action="tenant_owner_recover",
                key=key,
                request_hash=request_hash,
                approval_ref=cleaned_approval,
                reason=cleaned_reason,
                result=result,
                occurred_at=changed_at,
            )

    def _change_user_state(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        user_id: UUID,
        expected_security_version: int,
        expected_status: str,
        next_status: str,
        action: str,
        permission: str,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None,
    ) -> PlatformLifecycleResult:
        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        cleaned_approval = _required_text(approval_ref, "approval_ref", 256)
        cleaned_reason = _required_text(reason, "reason", 1024)
        key = _required_text(idempotency_key, "idempotency_key", 128)
        payload: dict[str, object] = {
            "action": action,
            "user_id": str(user_id),
            "expected_security_version": expected_security_version,
            "approval_ref": cleaned_approval,
            "reason": cleaned_reason,
        }
        request_hash = _digest(payload)
        with self._governance.begin() as db:
            self._bind(db, actor, user_id=user_id)
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, permission, changed_at)
            replay = self._replay(db, actor.principal_id, key, request_hash)
            if replay is not None:
                return replay
            user = self._locked_user(db, user_id)
            if (
                user.status != expected_status
                or user.security_version != expected_security_version
            ):
                raise PlatformSecurityError(
                    "platform_user_conflict", "Global User state changed concurrently"
                )
            next_version = user.security_version + 1
            db.execute(
                sa.update(GlobalUser)
                .where(
                    GlobalUser.id == user_id,
                    GlobalUser.status == expected_status,
                    GlobalUser.security_version == user.security_version,
                )
                .values(
                    status=next_status,
                    security_version=next_version,
                    updated_at=changed_at,
                )
            )
            revoked_sessions = self._revoke_sessions(db, user_id, changed_at)
            suspended_accounts = 0
            revoked_credentials = 0
            if next_status == "suspended":
                account_ids = list(
                    db.execute(
                        sa.select(ServiceAccountRecord.id).where(
                            ServiceAccountRecord.steward_user_id == user_id,
                            ServiceAccountRecord.status == "active",
                        )
                    ).scalars()
                )
                if account_ids:
                    suspended_accounts = _rowcount(
                        db.execute(
                            sa.update(ServiceAccountRecord)
                            .where(ServiceAccountRecord.id.in_(account_ids))
                            .values(
                                status="suspended",
                                security_version=ServiceAccountRecord.security_version + 1,
                                updated_at=changed_at,
                            )
                        )
                    )
                    revoked_credentials = _rowcount(
                        db.execute(
                            sa.update(ApiCredentialRecord)
                            .where(
                                ApiCredentialRecord.service_account_id.in_(account_ids),
                                ApiCredentialRecord.status == "active",
                            )
                            .values(status="revoked", revoked_at=changed_at)
                        )
                    )
                db.execute(
                    sa.update(OidcLoginTransaction)
                    .where(
                        OidcLoginTransaction.target_user_id == user_id,
                        OidcLoginTransaction.status == "pending",
                    )
                    .values(status="failed", consumed_at=changed_at)
                )
            result: dict[str, object] = {
                "status": next_status,
                "security_version": next_version,
                "revoked_session_count": revoked_sessions,
                "suspended_service_account_count": suspended_accounts,
                "revoked_api_credential_count": revoked_credentials,
            }
            return self._record(
                db,
                actor=actor,
                target_type="global_user",
                target_id=user_id,
                tenant_id=None,
                action=action,
                key=key,
                request_hash=request_hash,
                approval_ref=cleaned_approval,
                reason=cleaned_reason,
                result=result,
                occurred_at=changed_at,
            )

    def _change_tenant_state(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID,
        expected_lifecycle_version: int,
        allowed_statuses: set[str],
        next_status: str,
        action: str,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None,
    ) -> PlatformLifecycleResult:
        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        cleaned_approval = _required_text(approval_ref, "approval_ref", 256)
        cleaned_reason = _required_text(reason, "reason", 1024)
        key = _required_text(idempotency_key, "idempotency_key", 128)
        payload: dict[str, object] = {
            "action": action,
            "tenant_id": str(tenant_id),
            "expected_lifecycle_version": expected_lifecycle_version,
            "approval_ref": cleaned_approval,
            "reason": cleaned_reason,
        }
        request_hash = _digest(payload)
        with self._governance.begin() as db:
            self._bind(db, actor, tenant_id=tenant_id)
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, "platform.tenant.lifecycle.manage", changed_at)
            replay = self._replay(db, actor.principal_id, key, request_hash)
            if replay is not None:
                return replay
            tenant = db.execute(
                sa.select(Tenant).where(Tenant.id == tenant_id).with_for_update()
            ).scalar_one_or_none()
            if (
                tenant is None
                or tenant.status not in allowed_statuses
                or tenant.lifecycle_version != expected_lifecycle_version
            ):
                raise PlatformSecurityError(
                    "platform_tenant_conflict", "Tenant state changed concurrently"
                )
            tenant.status = next_status
            tenant.lifecycle_version += 1
            tenant.updated_at = changed_at
            revoked_sessions = 0
            suspended_accounts = 0
            revoked_credentials = 0
            if next_status == "suspended":
                user_ids = list(
                    db.execute(
                        sa.select(TenantMembership.user_id).where(
                            TenantMembership.tenant_id == tenant_id,
                            TenantMembership.status == "active",
                        )
                    ).scalars()
                )
                if user_ids:
                    db.execute(
                        sa.update(GlobalUser)
                        .where(GlobalUser.id.in_(user_ids), GlobalUser.status == "active")
                        .values(
                            security_version=GlobalUser.security_version + 1,
                            updated_at=changed_at,
                        )
                    )
                    revoked_sessions = _rowcount(
                        db.execute(
                            sa.update(AuthSessionRecord)
                            .where(
                                AuthSessionRecord.user_id.in_(user_ids),
                                AuthSessionRecord.revoked_at.is_(None),
                            )
                            .values(revoked_at=changed_at)
                        )
                    )
                account_ids = list(
                    db.execute(
                        sa.select(ServiceAccountRecord.id).where(
                            ServiceAccountRecord.tenant_id == tenant_id,
                            ServiceAccountRecord.status == "active",
                        )
                    ).scalars()
                )
                if account_ids:
                    suspended_accounts = _rowcount(
                        db.execute(
                            sa.update(ServiceAccountRecord)
                            .where(ServiceAccountRecord.id.in_(account_ids))
                            .values(
                                status="suspended",
                                security_version=ServiceAccountRecord.security_version + 1,
                                updated_at=changed_at,
                            )
                        )
                    )
                    revoked_credentials = _rowcount(
                        db.execute(
                            sa.update(ApiCredentialRecord)
                            .where(
                                ApiCredentialRecord.service_account_id.in_(account_ids),
                                ApiCredentialRecord.status == "active",
                            )
                            .values(status="revoked", revoked_at=changed_at)
                        )
                    )
            result: dict[str, object] = {
                "status": tenant.status,
                "lifecycle_version": tenant.lifecycle_version,
                "revoked_session_count": revoked_sessions,
                "suspended_service_account_count": suspended_accounts,
                "revoked_api_credential_count": revoked_credentials,
            }
            return self._record(
                db,
                actor=actor,
                target_type="tenant",
                target_id=tenant_id,
                tenant_id=tenant_id,
                action=action,
                key=key,
                request_hash=request_hash,
                approval_ref=cleaned_approval,
                reason=cleaned_reason,
                result=result,
                occurred_at=changed_at,
            )

    @staticmethod
    def _bind(
        db: Session,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID | None = None,
        user_id: UUID | None = None,
        identity_conflict_id: UUID | None = None,
    ) -> None:
        apply_platform_rls_context(
            db,
            PlatformRlsContext(
                principal_id=actor.principal_id,
                target_tenant_id=tenant_id,
                target_user_id=user_id,
                target_identity_conflict_id=identity_conflict_id,
            ),
        )

    @staticmethod
    def _serialize(db: Session, principal_id: UUID, key: str) -> None:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"platform-lifecycle:{principal_id}:{key}"},
            )

    @staticmethod
    def _authorize(
        db: Session,
        actor: ValidatedPlatformPrincipal,
        permission: str,
        now: datetime,
    ) -> None:
        PlatformAuthorizationService.require_current(db, actor, permission, now=now)

    @staticmethod
    def _locked_user(db: Session, user_id: UUID) -> _UserState:
        user = db.execute(
            sa.select(GlobalUser.status, GlobalUser.security_version)
            .where(GlobalUser.id == user_id)
            .with_for_update()
        ).one_or_none()
        if user is None:
            raise PlatformSecurityError("platform_user_not_found", "Global User was not found")
        return _UserState(status=user.status, security_version=user.security_version)

    @staticmethod
    def _revoke_sessions(db: Session, user_id: UUID, changed_at: datetime) -> int:
        return _rowcount(
            db.execute(
                sa.update(AuthSessionRecord)
                .where(
                    AuthSessionRecord.user_id == user_id,
                    AuthSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=changed_at)
            )
        )

    @staticmethod
    def _replay(
        db: Session,
        principal_id: UUID,
        key: str,
        request_hash: str,
    ) -> PlatformLifecycleResult | None:
        operation = db.execute(
            sa.select(PlatformLifecycleOperationRecord).where(
                PlatformLifecycleOperationRecord.actor_principal_id == principal_id,
                PlatformLifecycleOperationRecord.idempotency_key == key,
            )
        ).scalar_one_or_none()
        if operation is None:
            return None
        if operation.request_hash != request_hash:
            raise PlatformSecurityError(
                "platform_idempotency_conflict", "idempotency key was reused"
            )
        return PlatformLifecycleResult(
            operation_id=operation.id,
            action=operation.action,
            target_id=operation.target_id,
            result=dict(operation.result),
            replayed=True,
        )

    @staticmethod
    def _record(
        db: Session,
        *,
        actor: ValidatedPlatformPrincipal,
        target_type: str,
        target_id: UUID,
        tenant_id: UUID | None,
        action: str,
        key: str,
        request_hash: str,
        approval_ref: str,
        reason: str,
        result: dict[str, object],
        occurred_at: datetime,
    ) -> PlatformLifecycleResult:
        operation_id = uuid4()
        db.add(
            PlatformLifecycleOperationRecord(
                id=operation_id,
                actor_principal_id=actor.principal_id,
                target_type=target_type,
                target_id=target_id,
                tenant_id=tenant_id,
                action=action,
                idempotency_key=key,
                request_hash=request_hash,
                approval_ref=approval_ref,
                reason=reason,
                result=result,
                occurred_at=occurred_at,
            )
        )
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=tenant_id,
                aggregate_type=f"platform_{target_type}",
                aggregate_key=str(target_id),
                event_type=f"platform.{action.replace('_', '.')}",
                payload={
                    "operation_id": str(operation_id),
                    "actor_principal_id": str(actor.principal_id),
                    "target_id": str(target_id),
                    "action": action,
                    "result": result,
                },
                idempotency_key=scoped_idempotency_key("platform", actor.principal_id, key),
                request_hash=request_hash,
                attempt_count=0,
                created_at=occurred_at,
            )
        )
        return PlatformLifecycleResult(
            operation_id=operation_id,
            action=action,
            target_id=target_id,
            result=result,
            replayed=False,
        )

    @staticmethod
    def _owner_recovery_preview(
        db: Session,
        tenant_id: UUID,
        target_user_id: UUID,
        *,
        lock: bool = False,
    ) -> OwnerRecoveryPreview:
        tenant_statement = sa.select(Tenant).where(Tenant.id == tenant_id)
        memberships_statement = sa.select(TenantMembership).where(
            TenantMembership.tenant_id == tenant_id
        )
        if lock:
            tenant_statement = tenant_statement.with_for_update()
            memberships_statement = memberships_statement.with_for_update()
        tenant = db.execute(tenant_statement).scalar_one_or_none()
        memberships = list(db.execute(memberships_statement).scalars())
        target = next((item for item in memberships if item.user_id == target_user_id), None)
        owners = [item for item in memberships if item.role == "owner"]
        source = owners[0] if len(owners) == 1 else None
        user_ids = [item.user_id for item in (source, target) if item is not None]
        users = {
            row.id: row.status
            for row in db.execute(
                sa.select(GlobalUser.id, GlobalUser.status).where(GlobalUser.id.in_(user_ids))
            )
        }
        blockers: list[str] = []
        if tenant is None:
            blockers.append("tenant_not_found")
        elif tenant.status in {"pending_deletion", "deleted"}:
            blockers.append("tenant_terminal")
        if len(owners) != 1:
            blockers.append("owner_cardinality_invalid")
        if source is not None:
            source_status = users.get(source.user_id)
            if source.status == "active" and source_status == "active":
                blockers.append("owner_still_active")
        if target is None:
            blockers.append("target_membership_not_found")
        else:
            target_status = users.get(target.user_id)
            if target.status != "active" or target_status != "active":
                blockers.append("target_not_active")
            if target.role == "owner":
                blockers.append("target_already_owner")
        facts: dict[str, object] = {
            "tenant_id": str(tenant_id),
            "target_user_id": str(target_user_id),
            "tenant_version": tenant.lifecycle_version if tenant is not None else 0,
            "source_owner_id": str(source.user_id) if source is not None else None,
            "source_membership_version": source.version if source is not None else None,
            "target_membership_version": target.version if target is not None else None,
            "blockers": sorted(blockers),
        }
        return OwnerRecoveryPreview(
            tenant_id=tenant_id,
            source_owner_id=source.user_id if source is not None else None,
            target_user_id=target_user_id,
            tenant_version=tenant.lifecycle_version if tenant is not None else 0,
            source_membership_version=source.version if source is not None else None,
            target_membership_version=target.version if target is not None else None,
            blockers=tuple(sorted(blockers)),
            preview_hash=_digest(facts),
        )
