"""PC3 governed JIT support, Admin Operations, and signed audit exports."""

from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from itertools import pairwise
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent, GlobalUser, TenantMembership
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_governed_models import (
    PLATFORM_SUPPORT_SCOPES,
    PlatformAdminOperationRecord,
    PlatformAuditChainHeadRecord,
    PlatformAuditEventRecord,
    PlatformAuditExportRecord,
    PlatformSupportGrantRecord,
    PlatformSupportSessionRecord,
)
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
    PlatformTenantProjectionRecord,
)
from saas.control_plane.platform_security import (
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.rls import (
    PlatformRlsContext,
    RlsContext,
    apply_platform_rls_context,
    apply_rls_context,
)

_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_STANDARD_MAX_TTL = timedelta(hours=1)
_BREAK_GLASS_MAX_TTL = timedelta(minutes=15)
_ZERO_HASH = "0" * 64
_TENANT_SUPPORT_ROLES = frozenset({"owner", "admin", "security_auditor"})


class AuditSigner(Protocol):
    """Pluggable signing boundary; production implementations keep keys in KMS/HSM."""

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> str: ...

    def sign(self, content_hash: str) -> str: ...

    def verify(self, content_hash: str, signature: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class AuditSigningKey:
    """In-process HMAC signer for local development and deterministic acceptance tests."""

    key_id: str
    secret: bytes

    def __post_init__(self) -> None:
        if not self.key_id.strip() or len(self.secret) < 32:
            raise ValueError("audit signing key id and at least 256 bits are required")

    def sign(self, content_hash: str) -> str:
        return hmac.new(self.secret, content_hash.encode(), sha256).hexdigest()

    @property
    def algorithm(self) -> str:
        return "hmac-sha256"

    def verify(self, content_hash: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(content_hash), signature)


@dataclass(frozen=True, slots=True)
class TenantSupportActor:
    """Customer Realm identity accepted only after Cookie authentication."""

    actor_id: UUID
    tenant_id: UUID
    security_version: int


@dataclass(frozen=True, slots=True)
class SupportGrantView:
    grant_id: UUID
    operation_id: UUID
    tenant_id: UUID
    requested_by_principal_id: UUID
    mode: str
    scopes: tuple[str, ...]
    project_ids: tuple[UUID, ...]
    status: str
    version: int
    customer_approval_required: bool
    customer_approved_by_user_id: UUID | None
    staff_approved_by_principal_id: UUID | None
    requested_at: datetime
    starts_at: datetime | None
    expires_at: datetime
    incident_ref: str | None


@dataclass(frozen=True, slots=True)
class IssuedSupportSession:
    session_id: UUID
    grant_id: UUID
    tenant_id: UUID
    principal_id: UUID
    scopes: tuple[str, ...]
    token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ValidatedSupportSession:
    session_id: UUID
    grant_id: UUID
    tenant_id: UUID
    principal_id: UUID
    mode: str
    scopes: frozenset[str]
    project_ids: tuple[UUID, ...]
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AdminOperationView:
    operation_id: UUID
    action: str
    risk_level: str
    tenant_id: UUID | None
    target_type: str
    target_id: UUID
    requested_by_principal_id: UUID
    approved_by_principal_id: UUID | None
    status: str
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class AuditEventView:
    event_id: UUID
    sequence_no: int
    tenant_id: UUID | None
    actor_type: str
    actor_id: UUID
    event_type: str
    target_type: str
    target_id: UUID
    operation_id: UUID | None
    payload: dict[str, object]
    previous_hash: str
    event_hash: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class AuditExportRequest:
    operation_id: UUID
    export_id: UUID
    status: str
    version: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class SignedAuditExport:
    export_id: UUID
    operation_id: UUID
    manifest: dict[str, object]
    content_hash: str
    signing_key_id: str
    signature: str
    replayed: bool


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PlatformSecurityError("platform_time_invalid", f"{field} must include a timezone")


def _fresh(actor: ValidatedPlatformPrincipal, changed_at: datetime) -> None:
    authenticated_at = _as_utc(actor.authenticated_at)
    if authenticated_at > changed_at or changed_at - authenticated_at > _FRESH_AUTH_WINDOW:
        raise PlatformSecurityError(
            "platform_fresh_auth_required", "fresh Staff authentication is required"
        )


def _fresh_customer(authenticated_at: datetime, changed_at: datetime) -> None:
    _require_aware(authenticated_at, "authenticated_at")
    comparable = _as_utc(authenticated_at)
    if comparable > changed_at or changed_at - comparable > _FRESH_AUTH_WINDOW:
        raise PlatformSecurityError(
            "support_customer_fresh_auth_required",
            "fresh Tenant administrator authentication is required",
        )


def _clean(value: str, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise PlatformSecurityError("platform_command_invalid", f"{field} is invalid")
    return cleaned


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def _digest(payload: object) -> str:
    return sha256(_canonical(payload)).hexdigest()


def _rowcount(value: object) -> int:
    return cast(CursorResult[tuple[object]], value).rowcount


def _outbox_idempotency(value: str) -> str:
    """Preserve short keys and hash composite keys to the durable 128-byte contract."""

    return value if len(value) <= 128 else f"pc3:{sha256(value.encode()).hexdigest()}"


class PlatformGovernedAccessService:
    """Govern tenant-visible, expiring Staff access without emergency authority."""

    def __init__(
        self,
        platform_factory: sessionmaker[Session],
        *,
        tenant_factory: sessionmaker[Session] | None = None,
        support_factory: sessionmaker[Session] | None = None,
        signing_key: AuditSigner | None = None,
    ) -> None:
        self._platform = platform_factory
        self._tenant = tenant_factory or platform_factory
        self._support = support_factory or platform_factory
        self._signing_key = signing_key

    def request_support_grant(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID,
        mode: Literal["standard", "break_glass"],
        scopes: tuple[str, ...],
        project_ids: tuple[UUID, ...],
        reason: str,
        incident_ref: str | None,
        expires_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> SupportGrantView:
        requested_at = now or _now()
        _require_aware(requested_at, "now")
        _require_aware(expires_at, "expires_at")
        _fresh(actor, requested_at)
        cleaned_reason = _clean(reason, "reason", 1024)
        key = _clean(idempotency_key, "idempotency_key", 128)
        normalized_scopes = tuple(sorted(set(scopes)))
        normalized_projects = tuple(sorted(set(project_ids), key=str))
        self._validate_support_scope(normalized_scopes, normalized_projects)
        if mode not in {"standard", "break_glass"}:
            raise PlatformSecurityError("support_mode_invalid", "support mode is invalid")
        ttl = expires_at - requested_at
        maximum = _STANDARD_MAX_TTL if mode == "standard" else _BREAK_GLASS_MAX_TTL
        if ttl <= timedelta(0) or ttl > maximum:
            raise PlatformSecurityError("support_expiry_invalid", "support grant TTL is invalid")
        cleaned_incident = incident_ref.strip() if incident_ref is not None else None
        if mode == "break_glass" and not cleaned_incident:
            raise PlatformSecurityError(
                "break_glass_incident_required", "break-glass requires an incident reference"
            )
        if cleaned_incident is not None and len(cleaned_incident) > 256:
            raise PlatformSecurityError("support_incident_invalid", "incident_ref is invalid")

        grant_id, operation_id = uuid4(), uuid4()
        payload: dict[str, object] = {
            "action": "support_grant_request",
            "tenant_id": str(tenant_id),
            "mode": mode,
            "scopes": list(normalized_scopes),
            "project_ids": [str(value) for value in normalized_projects],
            "reason": cleaned_reason,
            "incident_ref": cleaned_incident,
            "expires_at": expires_at.isoformat(),
        }
        request_hash = _digest(payload)
        with self._platform.begin() as db:
            self._bind_platform(
                db,
                actor,
                tenant_id=tenant_id,
                support_grant_id=grant_id,
                admin_operation_id=operation_id,
            )
            self._authorize(
                db,
                actor,
                (
                    "platform.break_glass.request"
                    if mode == "break_glass"
                    else "platform.support.request"
                ),
                requested_at,
            )
            existing = self._operation_replay(db, actor.principal_id, key, request_hash)
            if existing is not None:
                grant = db.execute(
                    sa.select(PlatformSupportGrantRecord).where(
                        PlatformSupportGrantRecord.operation_id == existing.id
                    )
                ).scalar_one()
                return self._grant_view(grant)
            tenant = db.get(PlatformTenantProjectionRecord, tenant_id)
            if tenant is None or tenant.status != "active":
                raise PlatformSecurityError(
                    "support_tenant_unavailable", "active Tenant projection is required"
                )
            initial_status = (
                "pending_customer_approval" if mode == "standard" else "pending_staff_approval"
            )
            operation = PlatformAdminOperationRecord(
                id=operation_id,
                action="support_grant_request",
                risk_level="critical" if mode == "break_glass" else "high",
                tenant_id=tenant_id,
                target_type="support_grant",
                target_id=grant_id,
                requested_by_principal_id=actor.principal_id,
                idempotency_key=key,
                request_hash=request_hash,
                reason=cleaned_reason,
                status=initial_status,
                version=1,
                created_at=requested_at,
                updated_at=requested_at,
            )
            grant = PlatformSupportGrantRecord(
                id=grant_id,
                operation_id=operation_id,
                tenant_id=tenant_id,
                requested_by_principal_id=actor.principal_id,
                mode=mode,
                scopes=list(normalized_scopes),
                project_ids=[str(value) for value in normalized_projects],
                reason=cleaned_reason,
                incident_ref=cleaned_incident,
                customer_approval_required=mode == "standard",
                status=initial_status,
                version=1,
                requested_at=requested_at,
                expires_at=expires_at,
                created_at=requested_at,
                updated_at=requested_at,
            )
            db.add_all((operation, grant))
            audit_payload: dict[str, object] = {
                "mode": mode,
                "scopes": list(normalized_scopes),
                "project_ids": [str(value) for value in normalized_projects],
                "reason_hash": _digest(cleaned_reason),
                "incident_ref_hash": (
                    _digest(cleaned_incident) if cleaned_incident is not None else None
                ),
                "expires_at": expires_at.isoformat(),
                "customer_approval_required": mode == "standard",
            }
            self._append_audit(
                db,
                tenant_id=tenant_id,
                actor_type="staff",
                actor_id=actor.principal_id,
                event_type=(
                    "platform.break_glass.requested"
                    if mode == "break_glass"
                    else "platform.support_grant.requested"
                ),
                target_type="support_grant",
                target_id=grant_id,
                operation_id=operation_id,
                payload=audit_payload,
                occurred_at=requested_at,
            )
            self._outbox(
                db,
                tenant_id=tenant_id,
                aggregate_key=str(grant_id),
                event_type=(
                    "platform.break_glass.requested"
                    if mode == "break_glass"
                    else "platform.support_grant.requested"
                ),
                idempotency_key=f"pc3:request:{actor.principal_id}:{key}",
                request_hash=request_hash,
                payload={
                    "grant_id": str(grant_id),
                    "tenant_id": str(tenant_id),
                    "mode": mode,
                    "status": initial_status,
                    "expires_at": expires_at.isoformat(),
                },
            )
            return self._grant_view(grant)

    def decide_customer_approval(
        self,
        request: TenantSupportActor,
        *,
        grant_id: UUID,
        expected_version: int,
        decision: Literal["approve", "reject"],
        reason: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> SupportGrantView:
        decided_at = now or _now()
        _fresh_customer(reauthenticated_at, decided_at)
        if decision not in {"approve", "reject"}:
            raise PlatformSecurityError(
                "support_customer_decision_invalid", "customer decision is invalid"
            )
        cleaned_reason = _clean(reason, "reason", 1024)
        key = _clean(idempotency_key, "idempotency_key", 128)
        payload: dict[str, object] = {
            "action": "support_grant_customer_decision",
            "tenant_id": str(request.tenant_id),
            "grant_id": str(grant_id),
            "expected_version": expected_version,
            "decision": decision,
            "reason": cleaned_reason,
        }
        request_hash = _digest(payload)
        outbox_key = f"pc3:customer:{request.tenant_id}:{request.actor_id}:{key}"
        with self._tenant.begin() as db:
            self._bind_customer(db, request, support_grant_id=grant_id)
            self._require_tenant_support_admin(db, request)
            replay = self._outbox_replay(db, outbox_key, request_hash)
            self._lock_support_grant(db, grant_id)
            grant = db.execute(
                sa.select(PlatformSupportGrantRecord)
                .where(
                    PlatformSupportGrantRecord.id == grant_id,
                    PlatformSupportGrantRecord.tenant_id == request.tenant_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if grant is None:
                raise PlatformSecurityError(
                    "support_grant_not_found", "support grant was not found"
                )
            if replay:
                return self._grant_view(grant)
            if grant.mode != "standard" or grant.status != "pending_customer_approval":
                raise PlatformSecurityError(
                    "support_grant_conflict", "support grant is not awaiting customer approval"
                )
            if grant.version != expected_version or _as_utc(grant.expires_at) <= decided_at:
                raise PlatformSecurityError(
                    "support_grant_conflict", "support grant changed or expired"
                )
            grant.customer_approved_by_user_id = request.actor_id
            grant.customer_approval_reason = cleaned_reason
            grant.customer_approved_at = decided_at
            grant.status = "pending_staff_approval" if decision == "approve" else "rejected"
            grant.version += 1
            grant.updated_at = decided_at
            operation = db.execute(
                sa.select(PlatformAdminOperationRecord)
                .where(PlatformAdminOperationRecord.id == grant.operation_id)
                .with_for_update()
            ).scalar_one()
            operation.status = grant.status
            operation.version += 1
            operation.updated_at = decided_at
            if decision == "reject":
                operation.completed_at = decided_at
                operation.result = {"status": "rejected", "grant_id": str(grant.id)}
            event_type = (
                "platform.support_grant.customer_approved"
                if decision == "approve"
                else "platform.support_grant.customer_rejected"
            )
            self._append_audit(
                db,
                tenant_id=request.tenant_id,
                actor_type="customer",
                actor_id=request.actor_id,
                event_type=event_type,
                target_type="support_grant",
                target_id=grant.id,
                operation_id=grant.operation_id,
                payload={
                    "decision": decision,
                    "reason_hash": _digest(cleaned_reason),
                    "version": grant.version,
                },
                occurred_at=decided_at,
            )
            self._outbox(
                db,
                tenant_id=request.tenant_id,
                aggregate_key=str(grant.id),
                event_type=event_type,
                idempotency_key=outbox_key,
                request_hash=request_hash,
                payload={
                    "grant_id": str(grant.id),
                    "tenant_id": str(request.tenant_id),
                    "status": grant.status,
                    "version": grant.version,
                },
            )
            return self._grant_view(grant)

    def decide_staff_approval(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        grant_id: UUID,
        expected_version: int,
        decision: Literal["approve", "reject"],
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> SupportGrantView:
        decided_at = now or _now()
        _fresh(actor, decided_at)
        if decision not in {"approve", "reject"}:
            raise PlatformSecurityError(
                "support_staff_decision_invalid", "Staff decision is invalid"
            )
        cleaned_reason = _clean(reason, "reason", 1024)
        key = _clean(idempotency_key, "idempotency_key", 128)
        with self._platform.begin() as db:
            self._bind_platform(db, actor, support_grant_id=grant_id)
            self._authorize(db, actor, "platform.support_grant.manage", decided_at)
            self._lock_support_grant(db, grant_id)
            grant = db.execute(
                sa.select(PlatformSupportGrantRecord)
                .where(PlatformSupportGrantRecord.id == grant_id)
                .with_for_update()
            ).scalar_one_or_none()
            if grant is None:
                raise PlatformSecurityError(
                    "support_grant_not_found", "support grant was not found"
                )
            self._bind_platform(
                db,
                actor,
                tenant_id=grant.tenant_id,
                support_grant_id=grant.id,
                admin_operation_id=grant.operation_id,
            )
            payload: dict[str, object] = {
                "action": "support_grant_staff_decision",
                "grant_id": str(grant.id),
                "expected_version": expected_version,
                "decision": decision,
                "reason": cleaned_reason,
            }
            request_hash = _digest(payload)
            outbox_key = f"pc3:staff-decision:{actor.principal_id}:{key}"
            if self._outbox_replay(db, outbox_key, request_hash):
                return self._grant_view(grant)
            if grant.requested_by_principal_id == actor.principal_id:
                raise PlatformSecurityError(
                    "platform_separation_of_duties",
                    "support requester cannot approve its own grant",
                )
            if grant.status != "pending_staff_approval" or grant.version != expected_version:
                raise PlatformSecurityError(
                    "support_grant_conflict", "support grant is not awaiting Staff approval"
                )
            if _as_utc(grant.expires_at) <= decided_at:
                raise PlatformSecurityError("support_grant_expired", "support grant has expired")
            if grant.customer_approval_required and grant.customer_approved_at is None:
                raise PlatformSecurityError(
                    "support_customer_approval_required",
                    "customer approval is required before Staff approval",
                )
            grant.staff_approved_by_principal_id = actor.principal_id
            grant.staff_approval_reason = cleaned_reason
            grant.staff_approved_at = decided_at
            grant.status = "active" if decision == "approve" else "rejected"
            grant.starts_at = decided_at if decision == "approve" else None
            grant.version += 1
            grant.updated_at = decided_at
            operation = db.execute(
                sa.select(PlatformAdminOperationRecord)
                .where(PlatformAdminOperationRecord.id == grant.operation_id)
                .with_for_update()
            ).scalar_one()
            operation.approved_by_principal_id = actor.principal_id
            operation.approved_at = decided_at
            operation.completed_at = decided_at
            operation.status = "succeeded" if decision == "approve" else "rejected"
            operation.version += 1
            operation.result = {
                "status": grant.status,
                "grant_id": str(grant.id),
                "expires_at": grant.expires_at.isoformat(),
            }
            operation.updated_at = decided_at
            event_type = (
                "platform.break_glass.activated"
                if grant.mode == "break_glass" and decision == "approve"
                else (
                    "platform.support_grant.staff_approved"
                    if decision == "approve"
                    else "platform.support_grant.staff_rejected"
                )
            )
            self._append_audit(
                db,
                tenant_id=grant.tenant_id,
                actor_type="staff",
                actor_id=actor.principal_id,
                event_type=event_type,
                target_type="support_grant",
                target_id=grant.id,
                operation_id=grant.operation_id,
                payload={
                    "decision": decision,
                    "mode": grant.mode,
                    "reason_hash": _digest(cleaned_reason),
                    "version": grant.version,
                    "expires_at": grant.expires_at.isoformat(),
                },
                occurred_at=decided_at,
            )
            self._outbox(
                db,
                tenant_id=grant.tenant_id,
                aggregate_key=str(grant.id),
                event_type=event_type,
                idempotency_key=outbox_key,
                request_hash=request_hash,
                payload={
                    "grant_id": str(grant.id),
                    "tenant_id": str(grant.tenant_id),
                    "mode": grant.mode,
                    "status": grant.status,
                    "expires_at": grant.expires_at.isoformat(),
                },
            )
            return self._grant_view(grant)

    def issue_support_session(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        grant_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IssuedSupportSession:
        issued_at = now or _now()
        _fresh(actor, issued_at)
        key = _clean(idempotency_key, "idempotency_key", 128)
        token = secrets.token_urlsafe(32)
        token_hash = sha256(token.encode()).hexdigest()
        session_id, operation_id = uuid4(), uuid4()
        with self._platform.begin() as db:
            self._bind_platform(
                db,
                actor,
                support_grant_id=grant_id,
                admin_operation_id=operation_id,
            )
            self._authorize(db, actor, "platform.support.request", issued_at)
            self._lock_support_grant(db, grant_id)
            grant = db.execute(
                sa.select(PlatformSupportGrantRecord).where(
                    PlatformSupportGrantRecord.id == grant_id
                )
            ).scalar_one_or_none()
            if grant is None:
                raise PlatformSecurityError(
                    "support_grant_not_found", "support grant was not found"
                )
            payload = {
                "action": "support_session_issue",
                "grant_id": str(grant.id),
                "expected_version": expected_version,
            }
            request_hash = _digest(payload)
            existing = self._operation_replay(db, actor.principal_id, key, request_hash)
            if existing is not None:
                raise PlatformSecurityError(
                    "support_session_token_already_disclosed",
                    "support session was already issued and its token cannot be replayed",
                )
            if grant.requested_by_principal_id != actor.principal_id:
                raise PlatformSecurityError(
                    "support_grant_principal_mismatch",
                    "only the approved requester can issue a support session",
                )
            if (
                grant.status != "active"
                or grant.version != expected_version
                or _as_utc(grant.expires_at) <= issued_at
            ):
                raise PlatformSecurityError(
                    "support_grant_inactive", "an active, current support grant is required"
                )
            session = PlatformSupportSessionRecord(
                id=session_id,
                grant_id=grant.id,
                principal_id=actor.principal_id,
                token_hash=token_hash,
                scopes=list(grant.scopes),
                issued_at=issued_at,
                expires_at=grant.expires_at,
                created_at=issued_at,
            )
            operation = PlatformAdminOperationRecord(
                id=operation_id,
                action="support_session_issue",
                risk_level="critical" if grant.mode == "break_glass" else "high",
                tenant_id=grant.tenant_id,
                target_type="support_session",
                target_id=session_id,
                requested_by_principal_id=actor.principal_id,
                idempotency_key=key,
                request_hash=request_hash,
                reason="issue approved JIT support session",
                status="succeeded",
                version=1,
                result={
                    "session_id": str(session_id),
                    "grant_id": str(grant.id),
                    "expires_at": grant.expires_at.isoformat(),
                },
                completed_at=issued_at,
                created_at=issued_at,
                updated_at=issued_at,
            )
            db.add_all((session, operation))
            self._append_audit(
                db,
                tenant_id=grant.tenant_id,
                actor_type="staff",
                actor_id=actor.principal_id,
                event_type="platform.support_session.issued",
                target_type="support_session",
                target_id=session_id,
                operation_id=operation_id,
                payload={
                    "grant_id": str(grant.id),
                    "mode": grant.mode,
                    "scopes": list(grant.scopes),
                    "expires_at": grant.expires_at.isoformat(),
                },
                occurred_at=issued_at,
            )
            return IssuedSupportSession(
                session_id=session_id,
                grant_id=grant.id,
                tenant_id=grant.tenant_id,
                principal_id=actor.principal_id,
                scopes=tuple(grant.scopes),
                token=token,
                expires_at=grant.expires_at,
            )

    def validate_support_session(
        self,
        token: str,
        *,
        tenant_id: UUID,
        required_scope: str,
        project_id: UUID | None = None,
        now: datetime | None = None,
    ) -> ValidatedSupportSession:
        checked_at = now or _now()
        if required_scope not in PLATFORM_SUPPORT_SCOPES:
            raise PlatformSecurityError("support_scope_invalid", "support scope is invalid")
        token_hash = sha256(token.encode()).hexdigest()
        with self._support.begin() as db:
            apply_platform_rls_context(
                db,
                PlatformRlsContext(
                    support_session_token_hash=token_hash,
                    target_tenant_id=tenant_id,
                ),
            )
            session = db.execute(
                sa.select(PlatformSupportSessionRecord).where(
                    PlatformSupportSessionRecord.token_hash == token_hash
                )
            ).scalar_one_or_none()
            if session is None or session.revoked_at is not None:
                raise PlatformSecurityError(
                    "support_session_invalid", "support session is invalid"
                )
            grant = db.get(PlatformSupportGrantRecord, session.grant_id)
            if (
                grant is None
                or grant.tenant_id != tenant_id
                or grant.status != "active"
                or _as_utc(grant.expires_at) <= checked_at
                or _as_utc(session.expires_at) <= checked_at
            ):
                raise PlatformSecurityError(
                    "support_session_invalid", "support grant is inactive or expired"
                )
            if required_scope not in session.scopes:
                raise PlatformSecurityError(
                    "support_scope_denied", "support session does not include the scope"
                )
            project_ids = tuple(UUID(value) for value in grant.project_ids)
            if required_scope == "project.content.read":
                if project_id is None or project_id not in project_ids:
                    raise PlatformSecurityError(
                        "support_project_denied", "support session is not bound to the project"
                    )
            principal = db.get(PlatformStaffPrincipalRecord, session.principal_id)
            assignment = db.execute(
                sa.select(PlatformRoleAssignmentRecord.id).where(
                    PlatformRoleAssignmentRecord.principal_id == session.principal_id,
                    PlatformRoleAssignmentRecord.role == "support_agent",
                    PlatformRoleAssignmentRecord.status == "active",
                    sa.or_(
                        PlatformRoleAssignmentRecord.expires_at.is_(None),
                        PlatformRoleAssignmentRecord.expires_at > checked_at,
                    ),
                )
            ).scalar_one_or_none()
            if principal is None or principal.status != "active" or assignment is None:
                raise PlatformSecurityError(
                    "support_session_invalid", "support Staff authority is inactive"
                )
            session.last_seen_at = checked_at
            return ValidatedSupportSession(
                session_id=session.id,
                grant_id=grant.id,
                tenant_id=grant.tenant_id,
                principal_id=session.principal_id,
                mode=grant.mode,
                scopes=frozenset(session.scopes),
                project_ids=project_ids,
                expires_at=session.expires_at,
            )

    def revoke_support_grant(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        grant_id: UUID,
        expected_version: int,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> SupportGrantView:
        changed_at = now or _now()
        _fresh(actor, changed_at)
        cleaned_reason = _clean(reason, "reason", 1024)
        key = _clean(idempotency_key, "idempotency_key", 128)
        operation_id = uuid4()
        with self._platform.begin() as db:
            self._bind_platform(
                db,
                actor,
                support_grant_id=grant_id,
                admin_operation_id=operation_id,
            )
            self._authorize(db, actor, "platform.support_grant.manage", changed_at)
            self._lock_support_grant(db, grant_id)
            grant = db.execute(
                sa.select(PlatformSupportGrantRecord)
                .where(PlatformSupportGrantRecord.id == grant_id)
                .with_for_update()
            ).scalar_one_or_none()
            if grant is None:
                raise PlatformSecurityError(
                    "support_grant_not_found", "support grant was not found"
                )
            payload = {
                "action": "support_grant_revoke",
                "grant_id": str(grant.id),
                "expected_version": expected_version,
                "reason": cleaned_reason,
            }
            request_hash = _digest(payload)
            existing = self._operation_replay(db, actor.principal_id, key, request_hash)
            if existing is not None:
                return self._grant_view(grant)
            if (
                grant.status
                not in {
                    "pending_customer_approval",
                    "pending_staff_approval",
                    "active",
                }
                or grant.version != expected_version
            ):
                raise PlatformSecurityError(
                    "support_grant_conflict", "support grant changed or is terminal"
                )
            grant.status = "revoked"
            grant.version += 1
            grant.revoked_by_actor_type = "staff"
            grant.revoked_by_actor_id = actor.principal_id
            grant.revocation_reason = cleaned_reason
            grant.revoked_at = changed_at
            grant.updated_at = changed_at
            revoked = db.execute(
                sa.update(PlatformSupportSessionRecord)
                .where(
                    PlatformSupportSessionRecord.grant_id == grant.id,
                    PlatformSupportSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=changed_at)
            )
            operation = PlatformAdminOperationRecord(
                id=operation_id,
                action="support_grant_revoke",
                risk_level="critical" if grant.mode == "break_glass" else "high",
                tenant_id=grant.tenant_id,
                target_type="support_grant",
                target_id=grant.id,
                requested_by_principal_id=actor.principal_id,
                idempotency_key=key,
                request_hash=request_hash,
                reason=cleaned_reason,
                status="succeeded",
                version=1,
                result={
                    "status": "revoked",
                    "revoked_session_count": _rowcount(revoked),
                },
                completed_at=changed_at,
                created_at=changed_at,
                updated_at=changed_at,
            )
            db.add(operation)
            self._append_audit(
                db,
                tenant_id=grant.tenant_id,
                actor_type="staff",
                actor_id=actor.principal_id,
                event_type="platform.support_grant.revoked",
                target_type="support_grant",
                target_id=grant.id,
                operation_id=operation_id,
                payload={
                    "reason_hash": _digest(cleaned_reason),
                    "version": grant.version,
                    "revoked_session_count": _rowcount(revoked),
                },
                occurred_at=changed_at,
            )
            self._outbox(
                db,
                tenant_id=grant.tenant_id,
                aggregate_key=str(grant.id),
                event_type="platform.support_grant.revoked",
                idempotency_key=f"pc3:revoke:{actor.principal_id}:{key}",
                request_hash=request_hash,
                payload={
                    "grant_id": str(grant.id),
                    "tenant_id": str(grant.tenant_id),
                    "status": grant.status,
                    "version": grant.version,
                },
            )
            return self._grant_view(grant)

    def revoke_support_grant_by_customer(
        self,
        request: TenantSupportActor,
        *,
        grant_id: UUID,
        expected_version: int,
        reason: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> SupportGrantView:
        """Let an authorized Tenant administrator stop Staff access immediately."""

        changed_at = now or _now()
        _fresh_customer(reauthenticated_at, changed_at)
        cleaned_reason = _clean(reason, "reason", 1024)
        key = _clean(idempotency_key, "idempotency_key", 128)
        payload: dict[str, object] = {
            "action": "support_grant_customer_revoke",
            "tenant_id": str(request.tenant_id),
            "grant_id": str(grant_id),
            "expected_version": expected_version,
            "reason": cleaned_reason,
        }
        request_hash = _digest(payload)
        outbox_key = f"pc3:customer-revoke:{request.tenant_id}:{request.actor_id}:{key}"
        with self._tenant.begin() as db:
            self._bind_customer(db, request, support_grant_id=grant_id)
            self._require_tenant_support_admin(db, request)
            replay = self._outbox_replay(db, outbox_key, request_hash)
            self._lock_support_grant(db, grant_id)
            grant = db.execute(
                sa.select(PlatformSupportGrantRecord)
                .where(
                    PlatformSupportGrantRecord.id == grant_id,
                    PlatformSupportGrantRecord.tenant_id == request.tenant_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if grant is None:
                raise PlatformSecurityError(
                    "support_grant_not_found", "support grant was not found"
                )
            if replay:
                return self._grant_view(grant)
            if (
                grant.status
                not in {
                    "pending_customer_approval",
                    "pending_staff_approval",
                    "active",
                }
                or grant.version != expected_version
            ):
                raise PlatformSecurityError(
                    "support_grant_conflict", "support grant changed or is terminal"
                )
            grant.status = "revoked"
            grant.version += 1
            grant.revoked_by_actor_type = "customer"
            grant.revoked_by_actor_id = request.actor_id
            grant.revocation_reason = cleaned_reason
            grant.revoked_at = changed_at
            grant.updated_at = changed_at
            revoked = db.execute(
                sa.update(PlatformSupportSessionRecord)
                .where(
                    PlatformSupportSessionRecord.grant_id == grant.id,
                    PlatformSupportSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=changed_at)
            )
            operation = db.execute(
                sa.select(PlatformAdminOperationRecord)
                .where(PlatformAdminOperationRecord.id == grant.operation_id)
                .with_for_update()
            ).scalar_one()
            operation.status = "revoked"
            operation.version += 1
            operation.completed_at = changed_at
            operation.updated_at = changed_at
            operation.result = {
                **(operation.result or {}),
                "status": "revoked",
                "revoked_by": "customer",
                "revoked_session_count": _rowcount(revoked),
            }
            event_type = "platform.support_grant.customer_revoked"
            self._append_audit(
                db,
                tenant_id=request.tenant_id,
                actor_type="customer",
                actor_id=request.actor_id,
                event_type=event_type,
                target_type="support_grant",
                target_id=grant.id,
                operation_id=grant.operation_id,
                payload={
                    "reason_hash": _digest(cleaned_reason),
                    "version": grant.version,
                    "revoked_session_count": _rowcount(revoked),
                },
                occurred_at=changed_at,
            )
            self._outbox(
                db,
                tenant_id=request.tenant_id,
                aggregate_key=str(grant.id),
                event_type=event_type,
                idempotency_key=outbox_key,
                request_hash=request_hash,
                payload={
                    "grant_id": str(grant.id),
                    "tenant_id": str(request.tenant_id),
                    "status": grant.status,
                    "version": grant.version,
                },
            )
            return self._grant_view(grant)

    def list_support_grants(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID | None = None,
        status: str | None = None,
        cursor: UUID | None = None,
        limit: int = 50,
        now: datetime | None = None,
    ) -> tuple[SupportGrantView, ...]:
        checked_at = now or _now()
        if limit < 1 or limit > 200:
            raise PlatformSecurityError("platform_query_invalid", "limit is invalid")
        with self._platform.begin() as db:
            self._bind_platform(db, actor, tenant_id=tenant_id)
            self._authorize(db, actor, "platform.support.read", checked_at)
            query = sa.select(PlatformSupportGrantRecord)
            if tenant_id is not None:
                query = query.where(PlatformSupportGrantRecord.tenant_id == tenant_id)
            if status is not None:
                query = query.where(PlatformSupportGrantRecord.status == status)
            if cursor is not None:
                query = query.where(PlatformSupportGrantRecord.id > cursor)
            values = db.execute(
                query.order_by(PlatformSupportGrantRecord.id).limit(limit)
            ).scalars()
            return tuple(self._grant_view(value) for value in values)

    def list_tenant_support_grants(
        self,
        request: TenantSupportActor,
        *,
        cursor: UUID | None = None,
        limit: int = 50,
    ) -> tuple[SupportGrantView, ...]:
        if limit < 1 or limit > 200:
            raise PlatformSecurityError("platform_query_invalid", "limit is invalid")
        with self._tenant.begin() as db:
            self._bind_customer(db, request)
            self._require_tenant_support_admin(db, request)
            query = sa.select(PlatformSupportGrantRecord).where(
                PlatformSupportGrantRecord.tenant_id == request.tenant_id
            )
            if cursor is not None:
                query = query.where(PlatformSupportGrantRecord.id > cursor)
            values = db.execute(
                query.order_by(PlatformSupportGrantRecord.id).limit(limit)
            ).scalars()
            return tuple(self._grant_view(value) for value in values)

    def list_admin_operations(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        cursor: UUID | None = None,
        limit: int = 50,
        now: datetime | None = None,
    ) -> tuple[AdminOperationView, ...]:
        checked_at = now or _now()
        if limit < 1 or limit > 200:
            raise PlatformSecurityError("platform_query_invalid", "limit is invalid")
        with self._platform.begin() as db:
            self._bind_platform(db, actor)
            self._authorize(db, actor, "platform.operations.read", checked_at)
            query = sa.select(PlatformAdminOperationRecord)
            if cursor is not None:
                query = query.where(PlatformAdminOperationRecord.id > cursor)
            values = db.execute(
                query.order_by(PlatformAdminOperationRecord.id).limit(limit)
            ).scalars()
            return tuple(self._operation_view(value) for value in values)

    def list_audit_events(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID | None = None,
        after_sequence: int = 0,
        limit: int = 100,
        now: datetime | None = None,
    ) -> tuple[AuditEventView, ...]:
        checked_at = now or _now()
        if after_sequence < 0 or limit < 1 or limit > 500:
            raise PlatformSecurityError("platform_query_invalid", "audit query is invalid")
        with self._platform.begin() as db:
            self._bind_platform(db, actor, tenant_id=tenant_id)
            self._authorize(db, actor, "platform.audit.read", checked_at)
            query = sa.select(PlatformAuditEventRecord).where(
                PlatformAuditEventRecord.sequence_no > after_sequence
            )
            if tenant_id is not None:
                query = query.where(PlatformAuditEventRecord.tenant_id == tenant_id)
            events = db.execute(
                query.order_by(PlatformAuditEventRecord.sequence_no).limit(limit)
            ).scalars()
            return tuple(self._audit_view(event) for event in events)

    def request_audit_export(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID | None,
        from_sequence: int,
        to_sequence: int,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> AuditExportRequest:
        requested_at = now or _now()
        _fresh(actor, requested_at)
        if from_sequence < 1 or to_sequence < from_sequence:
            raise PlatformSecurityError("audit_export_range_invalid", "audit range is invalid")
        cleaned_reason = _clean(reason, "reason", 1024)
        key = _clean(idempotency_key, "idempotency_key", 128)
        export_id, operation_id = uuid4(), uuid4()
        payload: dict[str, object] = {
            "action": "audit_export",
            "tenant_id": str(tenant_id) if tenant_id is not None else None,
            "from_sequence": from_sequence,
            "to_sequence": to_sequence,
            "reason": cleaned_reason,
        }
        request_hash = _digest(payload)
        with self._platform.begin() as db:
            self._bind_platform(
                db,
                actor,
                tenant_id=tenant_id,
                admin_operation_id=operation_id,
            )
            self._authorize(db, actor, "platform.audit.export", requested_at)
            existing = self._operation_replay(db, actor.principal_id, key, request_hash)
            if existing is not None:
                return AuditExportRequest(
                    operation_id=existing.id,
                    export_id=existing.target_id,
                    status=existing.status,
                    version=existing.version,
                    replayed=True,
                )
            operation = PlatformAdminOperationRecord(
                id=operation_id,
                action="audit_export",
                risk_level="high",
                tenant_id=tenant_id,
                target_type="audit_export",
                target_id=export_id,
                requested_by_principal_id=actor.principal_id,
                idempotency_key=key,
                request_hash=request_hash,
                reason=cleaned_reason,
                status="pending_staff_approval",
                version=1,
                created_at=requested_at,
                updated_at=requested_at,
            )
            db.add(operation)
            self._append_audit(
                db,
                tenant_id=tenant_id,
                actor_type="staff",
                actor_id=actor.principal_id,
                event_type="platform.audit_export.requested",
                target_type="audit_export",
                target_id=export_id,
                operation_id=operation_id,
                payload={
                    "from_sequence": from_sequence,
                    "to_sequence": to_sequence,
                    "tenant_id": str(tenant_id) if tenant_id is not None else None,
                    "reason_hash": _digest(cleaned_reason),
                },
                occurred_at=requested_at,
            )
            return AuditExportRequest(
                operation_id=operation_id,
                export_id=export_id,
                status="pending_staff_approval",
                version=1,
                replayed=False,
            )

    def approve_audit_export(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        operation_id: UUID,
        expected_version: int,
        approval_reason: str,
        now: datetime | None = None,
    ) -> SignedAuditExport:
        approved_at = now or _now()
        _fresh(actor, approved_at)
        cleaned_reason = _clean(approval_reason, "approval_reason", 1024)
        if self._signing_key is None:
            raise PlatformSecurityError(
                "audit_signing_unavailable", "audit signing authority is unavailable"
            )
        if (
            self._signing_key.algorithm != "hmac-sha256"
            or not self._signing_key.key_id.strip()
            or len(self._signing_key.key_id) > 128
        ):
            raise PlatformSecurityError(
                "audit_signing_configuration_invalid",
                "audit signing algorithm or key identity is invalid",
            )
        with self._platform.begin() as db:
            self._bind_platform(db, actor, admin_operation_id=operation_id)
            self._authorize(db, actor, "platform.operation.approve", approved_at)
            operation = db.execute(
                sa.select(PlatformAdminOperationRecord)
                .where(PlatformAdminOperationRecord.id == operation_id)
                .with_for_update()
            ).scalar_one_or_none()
            if operation is None or operation.action != "audit_export":
                raise PlatformSecurityError(
                    "platform_operation_not_found", "audit export operation was not found"
                )
            existing = db.execute(
                sa.select(PlatformAuditExportRecord).where(
                    PlatformAuditExportRecord.operation_id == operation.id
                )
            ).scalar_one_or_none()
            if existing is not None:
                return self._signed_export(existing, replayed=True)
            if operation.requested_by_principal_id == actor.principal_id:
                raise PlatformSecurityError(
                    "platform_separation_of_duties",
                    "audit export requester cannot approve its own export",
                )
            if (
                operation.status != "pending_staff_approval"
                or operation.version != expected_version
            ):
                raise PlatformSecurityError(
                    "platform_operation_conflict", "audit export operation changed"
                )
            request_payload = json.loads(
                json.dumps(
                    {
                        "tenant_id": (
                            str(operation.tenant_id) if operation.tenant_id is not None else None
                        )
                    }
                )
            )
            requested_range = self._audit_export_range_from_hash_bound_operation(
                operation,
                db,
            )
            from_sequence, to_sequence = requested_range
            query = sa.select(PlatformAuditEventRecord).where(
                PlatformAuditEventRecord.sequence_no >= from_sequence,
                PlatformAuditEventRecord.sequence_no <= to_sequence,
            )
            proof_events = tuple(
                db.execute(query.order_by(PlatformAuditEventRecord.sequence_no)).scalars()
            )
            if (
                not proof_events
                or proof_events[0].sequence_no != from_sequence
                or proof_events[-1].sequence_no != to_sequence
                or len(proof_events) != to_sequence - from_sequence + 1
                or any(
                    current.previous_hash != previous.event_hash
                    for previous, current in pairwise(proof_events)
                )
            ):
                raise PlatformSecurityError(
                    "audit_export_range_incomplete",
                    "audit export range is not a complete contiguous chain segment",
                )
            events = tuple(
                value
                for value in proof_events
                if operation.tenant_id is None or value.tenant_id == operation.tenant_id
            )
            if not events:
                raise PlatformSecurityError(
                    "audit_export_empty", "audit export range has no visible events"
                )
            included_hashes = {value.event_hash for value in events}
            manifest: dict[str, object] = {
                "schema": "omnigent.platform-audit-export.v1",
                "tenant_id": request_payload["tenant_id"],
                "from_sequence": from_sequence,
                "to_sequence": to_sequence,
                "event_count": len(events),
                "proof_event_count": len(proof_events),
                "range_previous_hash": proof_events[0].previous_hash,
                "first_event_hash": proof_events[0].event_hash,
                "chain_head_hash": proof_events[-1].event_hash,
                "events": [self._audit_manifest_event(value) for value in events],
                "chain_proof": [
                    {
                        "sequence_no": value.sequence_no,
                        "previous_hash": value.previous_hash,
                        "event_hash": value.event_hash,
                        "included": value.event_hash in included_hashes,
                    }
                    for value in proof_events
                ],
                "approved_by_principal_id": str(actor.principal_id),
                "approval_reason_hash": _digest(cleaned_reason),
                "created_at": approved_at.isoformat(),
            }
            content_hash = _digest(manifest)
            signature = self._signing_key.sign(content_hash)
            if len(signature) != 64 or any(value not in "0123456789abcdef" for value in signature):
                raise PlatformSecurityError(
                    "audit_signature_invalid",
                    "audit signer returned an invalid HMAC-SHA256 encoding",
                )
            export = PlatformAuditExportRecord(
                id=operation.target_id,
                operation_id=operation.id,
                requested_by_principal_id=operation.requested_by_principal_id,
                approved_by_principal_id=actor.principal_id,
                tenant_id=operation.tenant_id,
                from_sequence=from_sequence,
                to_sequence=to_sequence,
                event_count=len(events),
                chain_head_hash=proof_events[-1].event_hash,
                manifest=manifest,
                content_hash=content_hash,
                signature_algorithm=self._signing_key.algorithm,
                signing_key_id=self._signing_key.key_id,
                signature=signature,
                created_at=approved_at,
            )
            db.add(export)
            operation.approved_by_principal_id = actor.principal_id
            operation.approved_at = approved_at
            operation.completed_at = approved_at
            operation.status = "succeeded"
            operation.version += 1
            operation.result = {
                "export_id": str(export.id),
                "event_count": len(events),
                "content_hash": content_hash,
                "signing_key_id": self._signing_key.key_id,
            }
            operation.updated_at = approved_at
            self._append_audit(
                db,
                tenant_id=operation.tenant_id,
                actor_type="staff",
                actor_id=actor.principal_id,
                event_type="platform.audit_export.completed",
                target_type="audit_export",
                target_id=export.id,
                operation_id=operation.id,
                payload={
                    "event_count": len(events),
                    "content_hash": content_hash,
                    "signing_key_id": self._signing_key.key_id,
                },
                occurred_at=approved_at,
            )
            return self._signed_export(export, replayed=False)

    def verify_audit_chain(
        self,
        actor: ValidatedPlatformPrincipal | None = None,
        *,
        now: datetime | None = None,
    ) -> bool:
        with self._platform.begin() as db:
            if actor is None:
                if db.get_bind().dialect.name == "postgresql":
                    raise PlatformSecurityError(
                        "platform_audit_verification_context_required",
                        "Staff audit authority is required for PostgreSQL verification",
                    )
            else:
                checked_at = now or _now()
                self._bind_platform(db, actor)
                self._authorize(db, actor, "platform.audit.read", checked_at)
            events = tuple(
                db.execute(
                    sa.select(PlatformAuditEventRecord).order_by(
                        PlatformAuditEventRecord.sequence_no
                    )
                ).scalars()
            )
            previous_hash = _ZERO_HASH
            for expected_sequence, event in enumerate(events, start=1):
                if event.sequence_no != expected_sequence or event.previous_hash != previous_hash:
                    return False
                if event.payload_hash != _digest(event.payload):
                    return False
                if event.event_hash != self._event_hash(event):
                    return False
                previous_hash = event.event_hash
            return True

    def verify_signed_export(self, value: SignedAuditExport) -> bool:
        if self._signing_key is None or value.signing_key_id != self._signing_key.key_id:
            return False
        if value.content_hash != _digest(value.manifest):
            return False
        return self._verify_export_manifest(value.manifest) and self._signing_key.verify(
            value.content_hash, value.signature
        )

    @staticmethod
    def _verify_export_manifest(manifest: dict[str, object]) -> bool:
        proof = manifest.get("chain_proof")
        events = manifest.get("events")
        from_sequence = manifest.get("from_sequence")
        to_sequence = manifest.get("to_sequence")
        event_count = manifest.get("event_count")
        proof_count = manifest.get("proof_event_count")
        if (
            not isinstance(proof, list)
            or not isinstance(events, list)
            or not isinstance(from_sequence, int)
            or not isinstance(to_sequence, int)
            or not isinstance(event_count, int)
            or not isinstance(proof_count, int)
            or len(proof) != proof_count
            or len(events) != event_count
            or proof_count != to_sequence - from_sequence + 1
        ):
            return False
        previous_hash = manifest.get("range_previous_hash")
        included_hashes: set[str] = set()
        for offset, raw in enumerate(proof):
            if not isinstance(raw, dict):
                return False
            sequence_no = raw.get("sequence_no")
            event_hash = raw.get("event_hash")
            if (
                sequence_no != from_sequence + offset
                or raw.get("previous_hash") != previous_hash
                or not isinstance(event_hash, str)
                or len(event_hash) != 64
                or not isinstance(raw.get("included"), bool)
            ):
                return False
            if raw["included"]:
                included_hashes.add(event_hash)
            previous_hash = event_hash
        detailed_hashes = {raw.get("event_hash") for raw in events if isinstance(raw, dict)}
        return (
            detailed_hashes == included_hashes and manifest.get("chain_head_hash") == previous_hash
        )

    def _audit_export_range_from_hash_bound_operation(
        self,
        operation: PlatformAdminOperationRecord,
        db: Session,
    ) -> tuple[int, int]:
        requested = db.execute(
            sa.select(PlatformAuditEventRecord.payload).where(
                PlatformAuditEventRecord.operation_id == operation.id,
                PlatformAuditEventRecord.event_type == "platform.audit_export.requested",
            )
        ).scalar_one_or_none()
        if requested is None:
            raise PlatformSecurityError(
                "audit_export_request_missing", "hash-bound audit export request is missing"
            )
        from_sequence = requested.get("from_sequence")
        to_sequence = requested.get("to_sequence")
        if not isinstance(from_sequence, int) or not isinstance(to_sequence, int):
            raise PlatformSecurityError(
                "audit_export_request_invalid", "audit export request range is invalid"
            )
        return from_sequence, to_sequence

    def _validate_support_scope(
        self,
        scopes: tuple[str, ...],
        project_ids: tuple[UUID, ...],
    ) -> None:
        if not scopes or any(value not in PLATFORM_SUPPORT_SCOPES for value in scopes):
            raise PlatformSecurityError("support_scope_invalid", "support scopes are invalid")
        content_requested = "project.content.read" in scopes
        if content_requested != bool(project_ids):
            raise PlatformSecurityError(
                "support_project_scope_invalid",
                "project content scope requires exact projects and other scopes forbid them",
            )

    def _bind_platform(
        self,
        db: Session,
        actor: ValidatedPlatformPrincipal,
        *,
        tenant_id: UUID | None = None,
        support_grant_id: UUID | None = None,
        admin_operation_id: UUID | None = None,
    ) -> None:
        apply_platform_rls_context(
            db,
            PlatformRlsContext(
                principal_id=actor.principal_id,
                target_tenant_id=tenant_id,
                target_support_grant_id=support_grant_id,
                target_admin_operation_id=admin_operation_id,
            ),
        )

    def _bind_customer(
        self,
        db: Session,
        request: TenantSupportActor,
        *,
        support_grant_id: UUID | None = None,
    ) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                target_support_grant_id=support_grant_id,
            ),
        )

    def _authorize(
        self,
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
            raise PlatformSecurityError(
                "platform_principal_inactive", "active Staff principal is required"
            )
        roles = tuple(
            db.execute(
                sa.select(PlatformRoleAssignmentRecord.role).where(
                    PlatformRoleAssignmentRecord.principal_id == actor.principal_id,
                    PlatformRoleAssignmentRecord.status == "active",
                    sa.or_(
                        PlatformRoleAssignmentRecord.expires_at.is_(None),
                        PlatformRoleAssignmentRecord.expires_at > now,
                    ),
                )
            ).scalars()
        )
        current_permissions = {
            value for role in roles for value in PLATFORM_ROLE_PERMISSIONS.get(role, frozenset())
        }
        if permission not in current_permissions:
            raise PlatformSecurityError(
                "platform_permission_denied", "platform permission is denied"
            )

    def _lock_support_grant(self, db: Session, grant_id: UUID) -> None:
        """Serialize issue/decision/revoke without granting Support UPDATE authority."""

        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:grant_id, 0))"),
                {"grant_id": str(grant_id)},
            )

    def _require_tenant_support_admin(self, db: Session, request: TenantSupportActor) -> None:
        user = db.execute(
            sa.select(GlobalUser.status, GlobalUser.security_version).where(
                GlobalUser.id == request.actor_id
            )
        ).one_or_none()
        membership = db.execute(
            sa.select(TenantMembership.role, TenantMembership.status).where(
                TenantMembership.tenant_id == request.tenant_id,
                TenantMembership.user_id == request.actor_id,
            )
        ).one_or_none()
        if (
            user is None
            or user.status != "active"
            or user.security_version != request.security_version
            or membership is None
            or membership.status != "active"
            or membership.role not in _TENANT_SUPPORT_ROLES
        ):
            raise PlatformSecurityError(
                "support_customer_permission_denied",
                "Tenant Owner, Admin, or Security Auditor is required",
            )

    def _operation_replay(
        self,
        db: Session,
        principal_id: UUID,
        idempotency_key: str,
        request_hash: str,
    ) -> PlatformAdminOperationRecord | None:
        operation = db.execute(
            sa.select(PlatformAdminOperationRecord).where(
                PlatformAdminOperationRecord.requested_by_principal_id == principal_id,
                PlatformAdminOperationRecord.idempotency_key == idempotency_key,
            )
        ).scalar_one_or_none()
        if operation is not None and operation.request_hash != request_hash:
            raise PlatformSecurityError(
                "platform_idempotency_conflict", "idempotency key was reused"
            )
        return operation

    def _outbox_replay(self, db: Session, key: str, request_hash: str) -> bool:
        event = db.execute(
            sa.select(ControlPlaneOutboxEvent.request_hash).where(
                ControlPlaneOutboxEvent.idempotency_key == _outbox_idempotency(key)
            )
        ).scalar_one_or_none()
        if event is not None and event != request_hash:
            raise PlatformSecurityError(
                "platform_idempotency_conflict", "idempotency key was reused"
            )
        return event is not None

    def _append_audit(
        self,
        db: Session,
        *,
        tenant_id: UUID | None,
        actor_type: str,
        actor_id: UUID,
        event_type: str,
        target_type: str,
        target_id: UUID,
        operation_id: UUID | None,
        payload: dict[str, object],
        occurred_at: datetime,
    ) -> PlatformAuditEventRecord:
        head = db.execute(
            sa.select(PlatformAuditChainHeadRecord)
            .where(PlatformAuditChainHeadRecord.partition_key == "platform")
            .with_for_update()
        ).scalar_one_or_none()
        if head is None:
            head = PlatformAuditChainHeadRecord(
                partition_key="platform",
                last_sequence=0,
                last_event_hash=_ZERO_HASH,
                updated_at=occurred_at,
            )
            db.add(head)
        sequence_no = head.last_sequence + 1
        payload_hash = _digest(payload)
        event_data = {
            "sequence_no": sequence_no,
            "tenant_id": str(tenant_id) if tenant_id is not None else None,
            "actor_type": actor_type,
            "actor_id": str(actor_id),
            "event_type": event_type,
            "target_type": target_type,
            "target_id": str(target_id),
            "operation_id": str(operation_id) if operation_id is not None else None,
            "payload_hash": payload_hash,
            "previous_hash": head.last_event_hash,
            "occurred_at": occurred_at.isoformat(),
        }
        event = PlatformAuditEventRecord(
            id=uuid4(),
            sequence_no=sequence_no,
            tenant_id=tenant_id,
            actor_type=actor_type,
            actor_id=actor_id,
            event_type=event_type,
            target_type=target_type,
            target_id=target_id,
            operation_id=operation_id,
            payload=payload,
            payload_hash=payload_hash,
            previous_hash=head.last_event_hash,
            event_hash=_digest(event_data),
            occurred_at=occurred_at,
            created_at=occurred_at,
        )
        db.add(event)
        head.last_sequence = sequence_no
        head.last_event_hash = event.event_hash
        head.updated_at = occurred_at
        return event

    def _event_hash(self, event: PlatformAuditEventRecord) -> str:
        return _digest(
            {
                "sequence_no": event.sequence_no,
                "tenant_id": str(event.tenant_id) if event.tenant_id is not None else None,
                "actor_type": event.actor_type,
                "actor_id": str(event.actor_id),
                "event_type": event.event_type,
                "target_type": event.target_type,
                "target_id": str(event.target_id),
                "operation_id": (
                    str(event.operation_id) if event.operation_id is not None else None
                ),
                "payload_hash": event.payload_hash,
                "previous_hash": event.previous_hash,
                "occurred_at": _as_utc(event.occurred_at).isoformat(),
            }
        )

    def _outbox(
        self,
        db: Session,
        *,
        tenant_id: UUID | None,
        aggregate_key: str,
        event_type: str,
        idempotency_key: str,
        request_hash: str,
        payload: dict[str, object],
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=tenant_id,
                aggregate_type="platform_support",
                aggregate_key=aggregate_key,
                event_type=event_type,
                payload=payload,
                idempotency_key=_outbox_idempotency(idempotency_key),
                request_hash=request_hash,
            )
        )

    def _grant_view(self, value: PlatformSupportGrantRecord) -> SupportGrantView:
        return SupportGrantView(
            grant_id=value.id,
            operation_id=value.operation_id,
            tenant_id=value.tenant_id,
            requested_by_principal_id=value.requested_by_principal_id,
            mode=value.mode,
            scopes=tuple(value.scopes),
            project_ids=tuple(UUID(item) for item in value.project_ids),
            status=value.status,
            version=value.version,
            customer_approval_required=value.customer_approval_required,
            customer_approved_by_user_id=value.customer_approved_by_user_id,
            staff_approved_by_principal_id=value.staff_approved_by_principal_id,
            requested_at=value.requested_at,
            starts_at=value.starts_at,
            expires_at=value.expires_at,
            incident_ref=value.incident_ref,
        )

    def _operation_view(self, value: PlatformAdminOperationRecord) -> AdminOperationView:
        return AdminOperationView(
            operation_id=value.id,
            action=value.action,
            risk_level=value.risk_level,
            tenant_id=value.tenant_id,
            target_type=value.target_type,
            target_id=value.target_id,
            requested_by_principal_id=value.requested_by_principal_id,
            approved_by_principal_id=value.approved_by_principal_id,
            status=value.status,
            version=value.version,
            created_at=value.created_at,
            updated_at=value.updated_at,
        )

    def _audit_view(self, value: PlatformAuditEventRecord) -> AuditEventView:
        return AuditEventView(
            event_id=value.id,
            sequence_no=value.sequence_no,
            tenant_id=value.tenant_id,
            actor_type=value.actor_type,
            actor_id=value.actor_id,
            event_type=value.event_type,
            target_type=value.target_type,
            target_id=value.target_id,
            operation_id=value.operation_id,
            payload=value.payload,
            previous_hash=value.previous_hash,
            event_hash=value.event_hash,
            occurred_at=value.occurred_at,
        )

    def _audit_manifest_event(self, value: PlatformAuditEventRecord) -> dict[str, object]:
        return {
            "event_id": str(value.id),
            "sequence_no": value.sequence_no,
            "tenant_id": str(value.tenant_id) if value.tenant_id is not None else None,
            "actor_type": value.actor_type,
            "actor_id": str(value.actor_id),
            "event_type": value.event_type,
            "target_type": value.target_type,
            "target_id": str(value.target_id),
            "operation_id": str(value.operation_id) if value.operation_id is not None else None,
            "payload": value.payload,
            "payload_hash": value.payload_hash,
            "previous_hash": value.previous_hash,
            "event_hash": value.event_hash,
            "occurred_at": _as_utc(value.occurred_at).isoformat(),
        }

    def _signed_export(
        self,
        value: PlatformAuditExportRecord,
        *,
        replayed: bool,
    ) -> SignedAuditExport:
        return SignedAuditExport(
            export_id=value.id,
            operation_id=value.operation_id,
            manifest=value.manifest,
            content_hash=value.content_hash,
            signing_key_id=value.signing_key_id,
            signature=value.signature,
            replayed=replayed,
        )
