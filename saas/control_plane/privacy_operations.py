"""Two-person Staff approval authority for high-risk Privacy operations."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent, GlobalUser, Tenant
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS, POLICY_VERSION
from saas.control_plane.platform_governed_models import (
    PlatformAdminOperationRecord,
    PlatformAuditChainHeadRecord,
    PlatformAuditEventRecord,
)
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.privacy_lifecycle import (
    PrivacyLifecycleService,
    deletion_target_state,
    expected_deletion_target_status,
)
from saas.control_plane.privacy_models import (
    PrivacyApprovalBindingRecord,
    PrivacyBackupRetentionItemRecord,
    PrivacyDeletionAttemptRecord,
    PrivacyDeletionManifestRecord,
    PrivacyDeletionWorkItemRecord,
    PrivacyEvidenceAttestationRecord,
    PrivacyLegalHoldRecord,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context

PrivacyTargetType = Literal["global_user", "tenant"]
PrivacyOperationPhase = Literal[
    "deletion_start",
    "deletion_finalize",
    "surface_replay",
    "backup_purge_replay",
]
PrivacyDecision = Literal["approve", "reject"]

_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_MAX_APPROVAL_WINDOW = timedelta(minutes=30)
_ZERO_HASH = "0" * 64
_REASON_CODES = frozenset(
    {
        "contract_expiry",
        "data_subject_request",
        "legal_authority",
        "security_response",
        "tenant_termination",
        "verified_operational_replay",
    }
)
_DECISION_CODES = frozenset(
    {"policy_confirmed", "scope_rejected", "stale_request", "verified_replay"}
)
_APPROVAL_CODE_BY_PHASE: dict[str, str] = {
    "deletion_start": "policy_confirmed",
    "deletion_finalize": "policy_confirmed",
    "surface_replay": "verified_replay",
    "backup_purge_replay": "verified_replay",
}
_REJECTION_CODES = frozenset({"scope_rejected", "stale_request"})
_ACTION_BY_PHASE: dict[str, str] = {
    "deletion_start": "privacy_deletion_start",
    "deletion_finalize": "privacy_deletion_finalize",
    "surface_replay": "privacy_surface_replay",
    "backup_purge_replay": "privacy_backup_purge_replay",
}
_ADAPTER_BY_SURFACE: dict[str, str] = {
    "control_plane_database": "control-plane-database.v1",
    "runtime_database": "runtime-database.v1",
    "object_and_artifact_store": "object-artifact-store.v1",
    "vector_and_search_indexes": "vector-search-index.v1",
    "caches": "cache.v1",
    "queues_and_dlq": "queue-dlq.v1",
    "provider_and_connector_state": "provider-connector.v1",
    "enterprise_identity_provisioning_state": "enterprise-provisioning.v1",
    "enterprise_identity_event_receipts": "enterprise-receipt.v1",
    "runner_worktree_and_recovery_material": "runner-worktree.v1",
    "webhook_state": "webhook-state.v1",
    "secret_and_kms_references": "secret-kms.v1",
    "logs_and_traces": "logs-traces.v1",
    "immutable_audit_and_ledger": "audit-ledger.v1",
    "backups_and_snapshots": "backup-catalog.v1",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise PlatformSecurityError("platform_time_invalid", "time must include a timezone")
    return value.astimezone(timezone.utc)


def _stored_utc(value: datetime) -> datetime:
    """Normalize ORM timestamps; SQLite drops timezone metadata on round-trip."""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _required(value: str, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise PlatformSecurityError("platform_privacy_invalid", f"{field} is invalid")
    return cleaned


def _fresh(actor: ValidatedPlatformPrincipal, at: datetime) -> None:
    authenticated_at = _utc(actor.authenticated_at)
    if (
        authenticated_at > at
        or at - authenticated_at > _FRESH_AUTH_WINDOW
        or _utc(actor.expires_at) <= at
    ):
        raise PlatformSecurityError(
            "platform_fresh_auth_required", "fresh Staff authentication is required"
        )


@dataclass(frozen=True, slots=True)
class PrivacyLocatorKey:
    """HMAC authority for non-correlatable target and resource locators."""

    key_id: str
    secret: bytes

    def __post_init__(self) -> None:
        if not self.key_id.strip() or len(self.secret) < 32:
            raise ValueError("privacy locator key requires an identity and 256-bit secret")

    def hash(self, value: str) -> str:
        return hmac.new(self.secret, value.encode("utf-8"), sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class PrivacyOperationView:
    operation_id: UUID
    phase: str
    target_type: str
    target_id: UUID
    manifest_id: UUID | None
    subject_id: UUID | None
    status: str
    version: int
    snapshot_hash: str
    requested_by_principal_id: UUID
    approved_by_principal_id: UUID | None
    expires_at: datetime
    created_at: datetime
    completed_at: datetime | None
    error_code: str | None
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class PrivacyOperationPage:
    items: tuple[PrivacyOperationView, ...]
    next_cursor: UUID | None


@dataclass(frozen=True, slots=True)
class PrivacyWorkItemView:
    work_item_id: UUID
    surface: str
    disposition: str
    adapter_type: str
    status: str
    attempt_count: int
    max_attempts: int
    available_at: datetime
    leased_at: datetime | None
    lease_expires_at: datetime | None
    lease_generation: int
    replay_generation: int
    last_error_code: str | None
    last_error_sha256: str | None
    outcome_content_sha256: str | None
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PrivacyWorkItemPage:
    items: tuple[PrivacyWorkItemView, ...]
    next_cursor: UUID | None


@dataclass(frozen=True, slots=True)
class PrivacyAttemptView:
    attempt_id: UUID
    work_item_id: UUID | None
    backup_item_id: UUID | None
    surface: str
    attempt_number: int
    lease_generation: int
    replay_generation: int
    provider_idempotency_sha256: str
    outcome: str
    error_code: str | None
    error_sha256: str | None
    evidence_payload_sha256: str | None
    started_at: datetime
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class PrivacyAttemptPage:
    items: tuple[PrivacyAttemptView, ...]
    next_cursor: UUID | None


@dataclass(frozen=True, slots=True)
class PrivacyAttestationView:
    attestation_id: UUID
    subject_kind: str
    subject_id: UUID
    surface: str | None
    payload_type: str
    payload_sha256: str
    envelope_sha256: str
    immutability_receipt_sha256: str
    kms_audit_receipt_sha256: str
    signature_algorithm: str
    record_sha256: str | None
    product_revision: str
    upstream_revision: str
    schema_revision: str
    adapter_contract_version: str
    verifier_policy_version: str
    signed_at: datetime
    verified_at: datetime
    created_at: datetime


@dataclass(frozen=True, slots=True)
class PrivacyAttestationPage:
    items: tuple[PrivacyAttestationView, ...]
    next_cursor: UUID | None


@dataclass(frozen=True, slots=True)
class PrivacyBackupView:
    backup_item_id: UUID
    provider: str
    backup_data_class: str
    catalog_snapshot_sha256: str
    tombstone_sha256: str
    object_lock_until: datetime | None
    purge_due_at: datetime
    status: str
    attempt_count: int
    max_attempts: int
    available_at: datetime
    leased_at: datetime | None
    lease_expires_at: datetime | None
    lease_generation: int
    replay_generation: int
    last_error_code: str | None
    last_error_sha256: str | None
    purge_evidence_sha256: str | None
    purged_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PrivacyBackupPage:
    items: tuple[PrivacyBackupView, ...]
    next_cursor: UUID | None


class PrivacyOperationService:
    """Bind exact snapshots to an independent Staff decision and atomic execution."""

    def __init__(
        self,
        governance_factory: sessionmaker[Session],
        *,
        lifecycle: PrivacyLifecycleService,
        locator_key: PrivacyLocatorKey,
    ) -> None:
        self._governance = governance_factory
        self._lifecycle = lifecycle
        self._locator_key = locator_key

    def request_deletion_start(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        expected_target_version: int,
        preview_hash: str,
        reason_code: str,
        case_reference: str,
        expires_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PrivacyOperationView:
        requested_at = _utc(now or _now())
        _fresh(actor, requested_at)
        reason = self._reason(reason_code)
        case_ref = _required(case_reference, "case_reference", 256)
        key = _required(idempotency_key, "idempotency_key", 128)
        expiry = self._expiry(expires_at, requested_at)
        operation_id = uuid4()
        with self._governance.begin() as db:
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                operation_id=operation_id,
            )
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, "platform.data_request.request", requested_at)
            self._lifecycle._lock_target(db, target_type, target_id)
            preview = self._lifecycle._preview(db, target_type, target_id, lock=True)
            if preview.blockers:
                raise PlatformSecurityError(
                    "platform_privacy_deletion_blocked", "; ".join(preview.blockers)
                )
            if (
                expected_target_version != preview.target_version
                or preview_hash != preview.preview_hash
            ):
                raise PlatformSecurityError(
                    "platform_privacy_deletion_conflict", "deletion preview is stale"
                )
            snapshot: dict[str, object] = {
                "schema_version": 1,
                "phase": "deletion_start",
                "target_type": target_type,
                "target_id": str(target_id),
                "target_status": preview.target_status,
                "target_version": preview.target_version,
                "preview_hash": preview.preview_hash,
                "impact_counts": dict(sorted(preview.impact_counts.items())),
                "surface_policy_sha256": self._surface_policy_hash(),
                "reason_code": reason,
                "case_reference_hmac": self._locator_key.hash(case_ref),
                "requester_principal_id": str(actor.principal_id),
                "requester_security_version": actor.security_version,
                "policy_version": POLICY_VERSION,
                "expires_at": expiry.isoformat(),
            }
            return self._create_request(
                db,
                actor=actor,
                operation_id=operation_id,
                phase="deletion_start",
                target_type=target_type,
                target_id=target_id,
                manifest_id=None,
                subject_id=None,
                expected_target_version=preview.target_version,
                expected_manifest_version=None,
                snapshot=snapshot,
                reason_code=reason,
                expires_at=expiry,
                idempotency_key=key,
                requested_at=requested_at,
            )

    def request_deletion_finalize(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        expected_manifest_version: int,
        reason_code: str,
        case_reference: str,
        expires_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PrivacyOperationView:
        requested_at = _utc(now or _now())
        _fresh(actor, requested_at)
        reason = self._reason(reason_code)
        case_ref = _required(case_reference, "case_reference", 256)
        key = _required(idempotency_key, "idempotency_key", 128)
        expiry = self._expiry(expires_at, requested_at)
        operation_id = uuid4()
        with self._governance.begin() as db:
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                operation_id=operation_id,
                manifest_id=manifest_id,
            )
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, "platform.data_request.request", requested_at)
            self._lifecycle._lock_target(db, target_type, target_id)
            manifest = self._manifest(db, target_type, target_id, manifest_id, lock=True)
            if manifest.version != expected_manifest_version:
                raise PlatformSecurityError(
                    "platform_privacy_manifest_conflict", "deletion Manifest changed"
                )
            snapshot = self._finalization_snapshot(db, manifest)
            snapshot.update(
                {
                    "reason_code": reason,
                    "case_reference_hmac": self._locator_key.hash(case_ref),
                    "requester_principal_id": str(actor.principal_id),
                    "requester_security_version": actor.security_version,
                    "expires_at": expiry.isoformat(),
                }
            )
            return self._create_request(
                db,
                actor=actor,
                operation_id=operation_id,
                phase="deletion_finalize",
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest.id,
                subject_id=None,
                expected_target_version=manifest.expected_target_version,
                expected_manifest_version=manifest.version,
                snapshot=snapshot,
                reason_code=reason,
                expires_at=expiry,
                idempotency_key=key,
                requested_at=requested_at,
            )

    def request_dead_letter_replay(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        subject_id: UUID,
        subject_kind: Literal["work_item", "backup_item"],
        expected_version: int,
        reason_code: str,
        case_reference: str,
        expires_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PrivacyOperationView:
        requested_at = _utc(now or _now())
        _fresh(actor, requested_at)
        reason = self._reason(reason_code)
        case_ref = _required(case_reference, "case_reference", 256)
        key = _required(idempotency_key, "idempotency_key", 128)
        expiry = self._expiry(expires_at, requested_at)
        phase: PrivacyOperationPhase = (
            "surface_replay" if subject_kind == "work_item" else "backup_purge_replay"
        )
        operation_id = uuid4()
        with self._governance.begin() as db:
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                operation_id=operation_id,
                manifest_id=manifest_id,
            )
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, "platform.data_request.request", requested_at)
            self._lifecycle._lock_target(db, target_type, target_id)
            manifest = self._manifest(db, target_type, target_id, manifest_id, lock=False)
            subject = (
                db.get(PrivacyDeletionWorkItemRecord, subject_id)
                if subject_kind == "work_item"
                else db.get(PrivacyBackupRetentionItemRecord, subject_id)
            )
            if (
                subject is None
                or subject.manifest_id != manifest.id
                or subject.target_type != target_type
                or subject.target_id != target_id
            ):
                raise PlatformSecurityError(
                    "platform_privacy_subject_not_found", "Privacy replay subject was not found"
                )
            if subject.status != "dead_letter" or subject.version != expected_version:
                raise PlatformSecurityError(
                    "platform_privacy_replay_conflict", "Privacy replay subject changed"
                )
            snapshot: dict[str, object] = {
                "schema_version": 1,
                "phase": phase,
                "target_type": target_type,
                "target_id": str(target_id),
                "manifest_id": str(manifest.id),
                "manifest_version": manifest.version,
                "subject_id": str(subject.id),
                "subject_version": subject.version,
                "replay_generation": subject.replay_generation,
                "last_error_code": subject.last_error_code,
                "last_error_sha256": subject.last_error_sha256,
                "reason_code": reason,
                "case_reference_hmac": self._locator_key.hash(case_ref),
                "requester_principal_id": str(actor.principal_id),
                "requester_security_version": actor.security_version,
                "policy_version": POLICY_VERSION,
                "expires_at": expiry.isoformat(),
            }
            return self._create_request(
                db,
                actor=actor,
                operation_id=operation_id,
                phase=phase,
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest.id,
                subject_id=subject.id,
                expected_target_version=manifest.expected_target_version,
                expected_manifest_version=manifest.version,
                snapshot=snapshot,
                reason_code=reason,
                expires_at=expiry,
                idempotency_key=key,
                requested_at=requested_at,
            )

    def decide(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        operation_id: UUID,
        expected_version: int,
        decision: PrivacyDecision,
        decision_code: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PrivacyOperationView:
        decided_at = _utc(now or _now())
        _fresh(actor, decided_at)
        key = _required(idempotency_key, "idempotency_key", 128)
        if decision_code not in _DECISION_CODES:
            raise PlatformSecurityError("platform_privacy_invalid", "decision_code is invalid")
        with self._governance.begin() as db:
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                operation_id=operation_id,
            )
            self._authorize(db, actor, "platform.data_request.approve", decided_at)
            operation = db.execute(
                sa.select(PlatformAdminOperationRecord)
                .where(PlatformAdminOperationRecord.id == operation_id)
                .with_for_update()
            ).scalar_one_or_none()
            binding = db.get(PrivacyApprovalBindingRecord, operation_id)
            if (
                operation is None
                or binding is None
                or binding.target_type != target_type
                or binding.target_id != target_id
                or operation.action != _ACTION_BY_PHASE.get(binding.phase)
            ):
                raise PlatformSecurityError(
                    "platform_privacy_operation_not_found", "Privacy operation was not found"
                )
            if (
                decision == "approve" and decision_code != _APPROVAL_CODE_BY_PHASE[binding.phase]
            ) or (decision == "reject" and decision_code not in _REJECTION_CODES):
                raise PlatformSecurityError(
                    "platform_privacy_invalid",
                    "decision_code is not valid for this Privacy decision",
                )
            if operation.requested_by_principal_id == actor.principal_id:
                raise PlatformSecurityError(
                    "platform_separation_of_duties",
                    "Privacy operation requester cannot approve the same operation",
                )
            decision_receipt_sha256 = _digest(
                {
                    "operation_id": str(operation.id),
                    "actor_id": str(actor.principal_id),
                    "expected_version": expected_version,
                    "decision": decision,
                    "decision_code": decision_code,
                    "idempotency_key": key,
                }
            )
            existing_receipt = (operation.result or {}).get("decision_idempotency_sha256")
            if operation.status != "pending_staff_approval":
                if (
                    existing_receipt == decision_receipt_sha256
                    and operation.approved_by_principal_id == actor.principal_id
                ):
                    return self._view(operation, binding, replayed=True)
                raise PlatformSecurityError(
                    "platform_idempotency_conflict",
                    "Privacy decision idempotency key was reused",
                )
            if operation.version != expected_version:
                raise PlatformSecurityError(
                    "platform_privacy_operation_conflict", "Privacy operation changed"
                )
            operation.result = {
                **(operation.result or {}),
                "decision_idempotency_sha256": decision_receipt_sha256,
            }
            self._lifecycle._lock_target(db, target_type, target_id)
            if binding.manifest_id is not None:
                self._bind(
                    db,
                    actor,
                    target_type=target_type,
                    target_id=target_id,
                    operation_id=operation_id,
                    manifest_id=binding.manifest_id,
                )
            if decided_at >= _stored_utc(binding.expires_at):
                return self._finish_failed(
                    db,
                    operation,
                    binding,
                    actor,
                    "approval_expired",
                    decided_at,
                )
            try:
                self._require_requester_current(db, operation, binding, decided_at)
            except PlatformSecurityError as error:
                if error.code in {"platform_principal_inactive", "platform_permission_denied"}:
                    return self._finish_failed(
                        db,
                        operation,
                        binding,
                        actor,
                        "requester_authority_revoked",
                        decided_at,
                    )
                raise
            if decision == "reject":
                operation.status = "rejected"
                operation.approved_by_principal_id = actor.principal_id
                operation.approved_at = decided_at
                operation.completed_at = decided_at
                operation.version += 1
                operation.result = {
                    **(operation.result or {}),
                    "decision": "rejected",
                    "decision_code": decision_code,
                }
                operation.updated_at = decided_at
                self._append_audit(
                    db,
                    tenant_id=binding.tenant_id,
                    actor_id=actor.principal_id,
                    event_type="platform.privacy_operation.rejected",
                    target_type=f"privacy_{target_type}",
                    target_id=target_id,
                    operation_id=operation.id,
                    payload={
                        "phase": binding.phase,
                        "snapshot_hash": binding.snapshot_hash,
                        "decision_code": decision_code,
                    },
                    occurred_at=decided_at,
                )
                return self._view(operation, binding)
            try:
                result = self._execute_approved(db, operation, binding, actor, decided_at)
            except PlatformSecurityError as error:
                if error.code.endswith("_conflict") or error.code.endswith("_blocked"):
                    return self._finish_failed(
                        db,
                        operation,
                        binding,
                        actor,
                        "approval_stale",
                        decided_at,
                    )
                raise
            operation.status = "succeeded"
            operation.approved_by_principal_id = actor.principal_id
            operation.approved_at = decided_at
            operation.completed_at = decided_at
            operation.version += 1
            operation.result = {
                **(operation.result or {}),
                "decision": "approved",
                "decision_code": decision_code,
                **result,
            }
            operation.updated_at = decided_at
            self._append_audit(
                db,
                tenant_id=binding.tenant_id,
                actor_id=actor.principal_id,
                event_type="platform.privacy_operation.executed",
                target_type=f"privacy_{target_type}",
                target_id=target_id,
                operation_id=operation.id,
                payload={
                    "phase": binding.phase,
                    "snapshot_hash": binding.snapshot_hash,
                    "result_hash": _digest(result),
                },
                occurred_at=decided_at,
            )
            return self._view(operation, binding)

    def list_operations(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        cursor: UUID | None = None,
        limit: int = 50,
        now: datetime | None = None,
    ) -> PrivacyOperationPage:
        checked_at = _utc(now or _now())
        if not 1 <= limit <= 100:
            raise PlatformSecurityError("platform_privacy_invalid", "limit is invalid")
        with self._governance.begin() as db:
            self._bind(db, actor, target_type=target_type, target_id=target_id)
            self._authorize(db, actor, "platform.privacy.read", checked_at)
            filters = (
                PrivacyApprovalBindingRecord.target_type == target_type,
                PrivacyApprovalBindingRecord.target_id == target_id,
            )
            query = (
                sa.select(PlatformAdminOperationRecord, PrivacyApprovalBindingRecord)
                .join(
                    PrivacyApprovalBindingRecord,
                    PrivacyApprovalBindingRecord.operation_id == PlatformAdminOperationRecord.id,
                )
                .where(*filters)
            )
            if cursor is not None:
                cursor_row = db.execute(
                    sa.select(
                        PlatformAdminOperationRecord.created_at,
                        PlatformAdminOperationRecord.id,
                    )
                    .join(PrivacyApprovalBindingRecord)
                    .where(*filters, PlatformAdminOperationRecord.id == cursor)
                ).one_or_none()
                if cursor_row is None:
                    raise PlatformSecurityError(
                        "platform_privacy_invalid", "Privacy operation cursor is invalid"
                    )
                query = query.where(
                    sa.or_(
                        PlatformAdminOperationRecord.created_at < cursor_row.created_at,
                        sa.and_(
                            PlatformAdminOperationRecord.created_at == cursor_row.created_at,
                            PlatformAdminOperationRecord.id < cursor_row.id,
                        ),
                    )
                )
            values = db.execute(
                query.order_by(
                    PlatformAdminOperationRecord.created_at.desc(),
                    PlatformAdminOperationRecord.id.desc(),
                ).limit(limit + 1)
            ).all()
            page = values[:limit]
            return PrivacyOperationPage(
                items=tuple(self._view(operation, binding) for operation, binding in page),
                next_cursor=(page[-1][0].id if len(values) > limit else None),
            )

    def list_work_items(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        cursor: UUID | None = None,
        limit: int = 50,
        now: datetime | None = None,
    ) -> PrivacyWorkItemPage:
        checked_at = _utc(now or _now())
        self._validate_page_limit(limit)
        with self._governance.begin() as db:
            self._prepare_manifest_read(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest_id,
                checked_at=checked_at,
            )
            filters = (
                PrivacyDeletionWorkItemRecord.manifest_id == manifest_id,
                PrivacyDeletionWorkItemRecord.target_type == target_type,
                PrivacyDeletionWorkItemRecord.target_id == target_id,
            )
            query = sa.select(PrivacyDeletionWorkItemRecord).where(*filters)
            if cursor is not None:
                cursor_row = db.execute(
                    sa.select(
                        PrivacyDeletionWorkItemRecord.created_at,
                        PrivacyDeletionWorkItemRecord.id,
                    ).where(*filters, PrivacyDeletionWorkItemRecord.id == cursor)
                ).one_or_none()
                if cursor_row is None:
                    raise PlatformSecurityError(
                        "platform_privacy_invalid", "Privacy Work Item cursor is invalid"
                    )
                query = query.where(
                    sa.or_(
                        PrivacyDeletionWorkItemRecord.created_at < cursor_row.created_at,
                        sa.and_(
                            PrivacyDeletionWorkItemRecord.created_at == cursor_row.created_at,
                            PrivacyDeletionWorkItemRecord.id < cursor_row.id,
                        ),
                    )
                )
            values = tuple(
                db.scalars(
                    query.order_by(
                        PrivacyDeletionWorkItemRecord.created_at.desc(),
                        PrivacyDeletionWorkItemRecord.id.desc(),
                    ).limit(limit + 1)
                )
            )
            page = values[:limit]
            return PrivacyWorkItemPage(
                items=tuple(self._work_item_view(value) for value in page),
                next_cursor=(page[-1].id if len(values) > limit else None),
            )

    def list_attempts(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        surface: str | None = None,
        cursor: UUID | None = None,
        limit: int = 50,
        now: datetime | None = None,
    ) -> PrivacyAttemptPage:
        checked_at = _utc(now or _now())
        self._validate_page_limit(limit)
        selected_surface = _required(surface, "surface", 96) if surface is not None else None
        with self._governance.begin() as db:
            self._prepare_manifest_read(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest_id,
                checked_at=checked_at,
            )
            filters = [
                PrivacyDeletionAttemptRecord.manifest_id == manifest_id,
                PrivacyDeletionAttemptRecord.target_type == target_type,
                PrivacyDeletionAttemptRecord.target_id == target_id,
            ]
            if selected_surface is not None:
                filters.append(PrivacyDeletionAttemptRecord.surface == selected_surface)
            query = sa.select(PrivacyDeletionAttemptRecord).where(*filters)
            if cursor is not None:
                cursor_row = db.execute(
                    sa.select(
                        PrivacyDeletionAttemptRecord.completed_at,
                        PrivacyDeletionAttemptRecord.id,
                    ).where(*filters, PrivacyDeletionAttemptRecord.id == cursor)
                ).one_or_none()
                if cursor_row is None:
                    raise PlatformSecurityError(
                        "platform_privacy_invalid", "Privacy Attempt cursor is invalid"
                    )
                query = query.where(
                    sa.or_(
                        PrivacyDeletionAttemptRecord.completed_at < cursor_row.completed_at,
                        sa.and_(
                            PrivacyDeletionAttemptRecord.completed_at == cursor_row.completed_at,
                            PrivacyDeletionAttemptRecord.id < cursor_row.id,
                        ),
                    )
                )
            values = tuple(
                db.scalars(
                    query.order_by(
                        PrivacyDeletionAttemptRecord.completed_at.desc(),
                        PrivacyDeletionAttemptRecord.id.desc(),
                    ).limit(limit + 1)
                )
            )
            page = values[:limit]
            return PrivacyAttemptPage(
                items=tuple(self._attempt_view(value) for value in page),
                next_cursor=(page[-1].id if len(values) > limit else None),
            )

    def list_attestations(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        cursor: UUID | None = None,
        limit: int = 50,
        now: datetime | None = None,
    ) -> PrivacyAttestationPage:
        checked_at = _utc(now or _now())
        self._validate_page_limit(limit)
        with self._governance.begin() as db:
            self._prepare_manifest_read(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest_id,
                checked_at=checked_at,
            )
            filters = (
                PrivacyEvidenceAttestationRecord.manifest_id == manifest_id,
                PrivacyEvidenceAttestationRecord.target_type == target_type,
                PrivacyEvidenceAttestationRecord.target_id == target_id,
            )
            query = sa.select(PrivacyEvidenceAttestationRecord).where(*filters)
            if cursor is not None:
                cursor_row = db.execute(
                    sa.select(
                        PrivacyEvidenceAttestationRecord.verified_at,
                        PrivacyEvidenceAttestationRecord.id,
                    ).where(*filters, PrivacyEvidenceAttestationRecord.id == cursor)
                ).one_or_none()
                if cursor_row is None:
                    raise PlatformSecurityError(
                        "platform_privacy_invalid", "Privacy Attestation cursor is invalid"
                    )
                query = query.where(
                    sa.or_(
                        PrivacyEvidenceAttestationRecord.verified_at < cursor_row.verified_at,
                        sa.and_(
                            PrivacyEvidenceAttestationRecord.verified_at == cursor_row.verified_at,
                            PrivacyEvidenceAttestationRecord.id < cursor_row.id,
                        ),
                    )
                )
            values = tuple(
                db.scalars(
                    query.order_by(
                        PrivacyEvidenceAttestationRecord.verified_at.desc(),
                        PrivacyEvidenceAttestationRecord.id.desc(),
                    ).limit(limit + 1)
                )
            )
            page = values[:limit]
            return PrivacyAttestationPage(
                items=tuple(self._attestation_view(value) for value in page),
                next_cursor=(page[-1].id if len(values) > limit else None),
            )

    def list_backups(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        cursor: UUID | None = None,
        limit: int = 50,
        now: datetime | None = None,
    ) -> PrivacyBackupPage:
        checked_at = _utc(now or _now())
        self._validate_page_limit(limit)
        with self._governance.begin() as db:
            self._prepare_manifest_read(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest_id,
                checked_at=checked_at,
            )
            filters = (
                PrivacyBackupRetentionItemRecord.manifest_id == manifest_id,
                PrivacyBackupRetentionItemRecord.target_type == target_type,
                PrivacyBackupRetentionItemRecord.target_id == target_id,
            )
            query = sa.select(PrivacyBackupRetentionItemRecord).where(*filters)
            if cursor is not None:
                cursor_row = db.execute(
                    sa.select(
                        PrivacyBackupRetentionItemRecord.created_at,
                        PrivacyBackupRetentionItemRecord.id,
                    ).where(*filters, PrivacyBackupRetentionItemRecord.id == cursor)
                ).one_or_none()
                if cursor_row is None:
                    raise PlatformSecurityError(
                        "platform_privacy_invalid", "Privacy Backup cursor is invalid"
                    )
                query = query.where(
                    sa.or_(
                        PrivacyBackupRetentionItemRecord.created_at < cursor_row.created_at,
                        sa.and_(
                            PrivacyBackupRetentionItemRecord.created_at == cursor_row.created_at,
                            PrivacyBackupRetentionItemRecord.id < cursor_row.id,
                        ),
                    )
                )
            values = tuple(
                db.scalars(
                    query.order_by(
                        PrivacyBackupRetentionItemRecord.created_at.desc(),
                        PrivacyBackupRetentionItemRecord.id.desc(),
                    ).limit(limit + 1)
                )
            )
            page = values[:limit]
            return PrivacyBackupPage(
                items=tuple(self._backup_view(value) for value in page),
                next_cursor=(page[-1].id if len(values) > limit else None),
            )

    def _prepare_manifest_read(
        self,
        db: Session,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        checked_at: datetime,
    ) -> None:
        self._bind(
            db,
            actor,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
        )
        self._authorize(db, actor, "platform.privacy.read", checked_at)
        self._manifest(db, target_type, target_id, manifest_id, lock=False)

    @staticmethod
    def _validate_page_limit(limit: int) -> None:
        if not 1 <= limit <= 100:
            raise PlatformSecurityError("platform_privacy_invalid", "limit is invalid")

    def _create_request(
        self,
        db: Session,
        *,
        actor: ValidatedPlatformPrincipal,
        operation_id: UUID,
        phase: PrivacyOperationPhase,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID | None,
        subject_id: UUID | None,
        expected_target_version: int,
        expected_manifest_version: int | None,
        snapshot: dict[str, object],
        reason_code: str,
        expires_at: datetime,
        idempotency_key: str,
        requested_at: datetime,
    ) -> PrivacyOperationView:
        snapshot_hash = _digest(snapshot)
        existing = db.execute(
            sa.select(PlatformAdminOperationRecord).where(
                PlatformAdminOperationRecord.requested_by_principal_id == actor.principal_id,
                PlatformAdminOperationRecord.idempotency_key == idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            if (
                existing.request_hash != snapshot_hash
                or existing.action != _ACTION_BY_PHASE[phase]
            ):
                raise PlatformSecurityError(
                    "platform_idempotency_conflict", "idempotency key was reused"
                )
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                operation_id=existing.id,
                manifest_id=manifest_id,
            )
            binding = db.get(PrivacyApprovalBindingRecord, existing.id)
            if (
                binding is None
                or binding.target_type != target_type
                or binding.target_id != target_id
            ):
                raise PlatformSecurityError(
                    "platform_privacy_invariant_broken", "Privacy approval binding is missing"
                )
            return self._view(existing, binding, replayed=True)
        operation = PlatformAdminOperationRecord(
            id=operation_id,
            action=_ACTION_BY_PHASE[phase],
            risk_level="critical",
            tenant_id=target_id if target_type == "tenant" else None,
            target_type=f"privacy_{target_type}",
            target_id=target_id,
            requested_by_principal_id=actor.principal_id,
            idempotency_key=idempotency_key,
            request_hash=snapshot_hash,
            reason=reason_code,
            status="pending_staff_approval",
            version=1,
            result={
                "phase": phase,
                "snapshot_hash": snapshot_hash,
                "expires_at": expires_at.isoformat(),
            },
            created_at=requested_at,
            updated_at=requested_at,
        )
        binding = PrivacyApprovalBindingRecord(
            operation_id=operation.id,
            phase=phase,
            target_type=target_type,
            target_id=target_id,
            tenant_id=target_id if target_type == "tenant" else None,
            manifest_id=manifest_id,
            subject_id=subject_id,
            expected_target_version=expected_target_version,
            expected_manifest_version=expected_manifest_version,
            impact_snapshot=snapshot,
            snapshot_hash=snapshot_hash,
            authentication_assertion_sha256=self._authentication_hash(actor),
            expires_at=expires_at,
            created_at=requested_at,
        )
        db.add_all((operation, binding))
        db.flush()
        self._append_audit(
            db,
            tenant_id=binding.tenant_id,
            actor_id=actor.principal_id,
            event_type="platform.privacy_operation.requested",
            target_type=f"privacy_{target_type}",
            target_id=target_id,
            operation_id=operation.id,
            payload={
                "phase": phase,
                "snapshot_hash": snapshot_hash,
                "expires_at": expires_at.isoformat(),
            },
            occurred_at=requested_at,
        )
        return self._view(operation, binding)

    def _execute_approved(
        self,
        db: Session,
        operation: PlatformAdminOperationRecord,
        binding: PrivacyApprovalBindingRecord,
        actor: ValidatedPlatformPrincipal,
        decided_at: datetime,
    ) -> dict[str, object]:
        phase = cast(PrivacyOperationPhase, binding.phase)
        if phase == "deletion_start":
            return self._execute_start(db, operation, binding, actor, decided_at)
        if phase == "deletion_finalize":
            return self._execute_finalize(db, operation, binding, actor, decided_at)
        return self._execute_replay(db, operation, binding, decided_at)

    def _execute_start(
        self,
        db: Session,
        operation: PlatformAdminOperationRecord,
        binding: PrivacyApprovalBindingRecord,
        actor: ValidatedPlatformPrincipal,
        decided_at: datetime,
    ) -> dict[str, object]:
        snapshot = binding.impact_snapshot
        preview = self._lifecycle._preview(
            db, cast(PrivacyTargetType, binding.target_type), binding.target_id, lock=True
        )
        current = {
            **snapshot,
            "target_status": preview.target_status,
            "target_version": preview.target_version,
            "preview_hash": preview.preview_hash,
            "impact_counts": dict(sorted(preview.impact_counts.items())),
        }
        if preview.blockers or _digest(current) != binding.snapshot_hash:
            raise PlatformSecurityError(
                "platform_privacy_deletion_conflict", "approved deletion snapshot is stale"
            )
        existing = db.execute(
            sa.select(PrivacyDeletionManifestRecord).where(
                PrivacyDeletionManifestRecord.start_operation_id == operation.id
            )
        ).scalar_one_or_none()
        if existing is not None:
            return {"manifest_id": str(existing.id), "replayed": True}
        manifest = PrivacyDeletionManifestRecord(
            id=uuid4(),
            target_type=binding.target_type,
            target_id=binding.target_id,
            tenant_id=binding.tenant_id,
            requested_by_principal_id=operation.requested_by_principal_id,
            start_operation_id=operation.id,
            approval_provenance="governed_operation",
            idempotency_key=operation.idempotency_key,
            request_hash=operation.request_hash,
            approval_ref=f"operation:{operation.id}",
            reason=operation.reason,
            expected_target_version=binding.expected_target_version,
            preview_hash=cast(str, snapshot["preview_hash"]),
            status="executing",
            blockers=[],
            surface_outcomes=self._lifecycle._pending_surfaces(),
            version=1,
            started_at=decided_at,
            retention_status="pending",
            updated_at=decided_at,
        )
        db.add(manifest)
        db.flush()
        self._bind(
            db,
            actor,
            target_type=cast(PrivacyTargetType, binding.target_type),
            target_id=binding.target_id,
            operation_id=operation.id,
            manifest_id=manifest.id,
        )
        if binding.target_type == "global_user":
            self._lifecycle._anonymize_user(db, manifest, decided_at)
        else:
            self._lifecycle._anonymize_tenant(db, manifest, decided_at)
        target_type = cast(PrivacyTargetType, binding.target_type)
        target_status, target_version = deletion_target_state(
            db, target_type, binding.target_id, lock=False
        )
        if (
            target_status != expected_deletion_target_status(target_type)
            or target_version != binding.expected_target_version + 1
        ):
            raise PlatformSecurityError(
                "platform_privacy_invariant_broken",
                "deletion start did not bind the exact target state",
            )
        manifest.expected_target_version = target_version
        for surface, (disposition, _retention_days) in self._surface_policy().items():
            db.add(
                PrivacyDeletionWorkItemRecord(
                    id=uuid4(),
                    manifest_id=manifest.id,
                    target_type=manifest.target_type,
                    target_id=manifest.target_id,
                    tenant_id=manifest.tenant_id,
                    runtime_partition_id=None,
                    surface=surface,
                    disposition=disposition,
                    resource_scope_hmac=self._locator_key.hash(
                        f"{manifest.id}:{surface}:logical-authority"
                    ),
                    adapter_type=_ADAPTER_BY_SURFACE[surface],
                    status="pending",
                    attempt_count=0,
                    max_attempts=8,
                    available_at=decided_at,
                    lease_generation=0,
                    replay_generation=0,
                    version=1,
                    created_at=decided_at,
                    updated_at=decided_at,
                )
            )
        self._outbox(
            db,
            manifest,
            event_type="privacy.deletion.approved_and_started",
            key=f"governed-start:{operation.id}",
            request_hash=operation.request_hash,
            payload={
                "manifest_id": str(manifest.id),
                "operation_id": str(operation.id),
                "surface_count": len(self._surface_policy()),
            },
            occurred_at=decided_at,
        )
        return {
            "manifest_id": str(manifest.id),
            "work_item_count": len(self._surface_policy()),
            "target_status": target_status,
            "target_version": target_version,
        }

    def _execute_finalize(
        self,
        db: Session,
        operation: PlatformAdminOperationRecord,
        binding: PrivacyApprovalBindingRecord,
        actor: ValidatedPlatformPrincipal,
        decided_at: datetime,
    ) -> dict[str, object]:
        if binding.manifest_id is None:
            raise PlatformSecurityError(
                "platform_privacy_invariant_broken", "Finalize binding has no Manifest"
            )
        manifest = self._manifest(
            db,
            cast(PrivacyTargetType, binding.target_type),
            binding.target_id,
            binding.manifest_id,
            lock=True,
        )
        if _digest(self._finalization_snapshot(db, manifest)) != binding.snapshot_hash:
            snapshot = dict(binding.impact_snapshot)
            for key in (
                "reason_code",
                "case_reference_hmac",
                "requester_principal_id",
                "requester_security_version",
                "expires_at",
            ):
                snapshot.pop(key, None)
            if _digest(self._finalization_snapshot(db, manifest)) != _digest(snapshot):
                raise PlatformSecurityError(
                    "platform_privacy_manifest_conflict", "approved finalization snapshot is stale"
                )
        start_operation = (
            db.get(PlatformAdminOperationRecord, manifest.start_operation_id)
            if manifest.start_operation_id is not None
            else None
        )
        if (
            start_operation is None
            or start_operation.approved_by_principal_id is None
            or start_operation.approved_by_principal_id == actor.principal_id
        ):
            raise PlatformSecurityError(
                "platform_separation_of_duties",
                "Finalize approver must differ from the Start approver",
            )
        if (
            manifest.status != "ready_to_finalize"
            or manifest.version != binding.expected_manifest_version
            or manifest.expected_target_version != binding.expected_target_version
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_conflict", "deletion Manifest is not finalizable"
            )
        if db.scalar(
            sa.select(sa.func.count())
            .select_from(PrivacyLegalHoldRecord)
            .where(
                PrivacyLegalHoldRecord.target_type == binding.target_type,
                PrivacyLegalHoldRecord.target_id == binding.target_id,
                PrivacyLegalHoldRecord.status == "active",
            )
        ):
            raise PlatformSecurityError(
                "platform_privacy_deletion_blocked", "an active Legal Hold blocks completion"
            )
        if binding.target_type == "global_user":
            target = db.get(GlobalUser, binding.target_id)
            if (
                target is None
                or target.status
                != expected_deletion_target_status(cast(PrivacyTargetType, binding.target_type))
                or target.security_version != manifest.expected_target_version
            ):
                raise PlatformSecurityError(
                    "platform_privacy_deletion_conflict", "Global User state changed"
                )
            target.status = "deleted"
            target.security_version += 1
            target.updated_at = decided_at
        else:
            tenant = db.get(Tenant, binding.target_id)
            if (
                tenant is None
                or tenant.status
                != expected_deletion_target_status(cast(PrivacyTargetType, binding.target_type))
                or tenant.lifecycle_version != manifest.expected_target_version
            ):
                raise PlatformSecurityError(
                    "platform_privacy_deletion_conflict", "Tenant state changed"
                )
            tenant.status = "deleted"
            tenant.lifecycle_version += 1
            tenant.updated_at = decided_at
        manifest_hash = _digest(
            {
                "manifest_id": str(manifest.id),
                "target_type": binding.target_type,
                "target_locator_hmac": self._locator_key.hash(
                    f"{binding.target_type}:{binding.target_id}"
                ),
                "request_hash": manifest.request_hash,
                "preview_hash": manifest.preview_hash,
                "surface_outcomes": manifest.surface_outcomes,
                "approved_snapshot_hash": binding.snapshot_hash,
                "manifest_record_sha256": binding.impact_snapshot.get("manifest_record_sha256"),
                "completion_operation_id": str(operation.id),
                "completed_at": decided_at.isoformat(),
            }
        )
        manifest.manifest_hash = manifest_hash
        manifest.completion_operation_id = operation.id
        manifest.completion_approval_ref = f"operation:{operation.id}"
        manifest.status = "completed"
        manifest.completed_at = decided_at
        manifest.updated_at = decided_at
        manifest.version += 1
        self._outbox(
            db,
            manifest,
            event_type="privacy.deletion.governed_completed",
            key=f"governed-finalize:{operation.id}",
            request_hash=manifest_hash,
            payload={
                "manifest_id": str(manifest.id),
                "operation_id": str(operation.id),
                "manifest_hash": manifest_hash,
                "retention_status": manifest.retention_status,
            },
            occurred_at=decided_at,
        )
        return {
            "manifest_id": str(manifest.id),
            "manifest_hash": manifest_hash,
            "retention_status": manifest.retention_status,
        }

    def _execute_replay(
        self,
        db: Session,
        operation: PlatformAdminOperationRecord,
        binding: PrivacyApprovalBindingRecord,
        decided_at: datetime,
    ) -> dict[str, object]:
        if binding.subject_id is None or binding.manifest_id is None:
            raise PlatformSecurityError(
                "platform_privacy_invariant_broken", "Replay binding has no subject"
            )
        model = (
            PrivacyDeletionWorkItemRecord
            if binding.phase == "surface_replay"
            else PrivacyBackupRetentionItemRecord
        )
        subject = db.execute(
            sa.select(model).where(model.id == binding.subject_id).with_for_update()
        ).scalar_one_or_none()
        snapshot = binding.impact_snapshot
        if (
            subject is None
            or subject.manifest_id != binding.manifest_id
            or subject.status != "dead_letter"
            or subject.version != cast(int, snapshot["subject_version"])
            or subject.replay_generation != cast(int, snapshot["replay_generation"])
        ):
            raise PlatformSecurityError(
                "platform_privacy_replay_conflict", "approved replay subject is stale"
            )
        subject.status = "retry"
        subject.attempt_count = 0
        subject.available_at = decided_at
        subject.replay_generation += 1
        subject.last_error_code = None
        subject.last_error_sha256 = None
        subject.version += 1
        subject.updated_at = decided_at
        manifest = self._manifest(
            db,
            cast(PrivacyTargetType, binding.target_type),
            binding.target_id,
            binding.manifest_id,
            lock=False,
        )
        self._outbox(
            db,
            manifest,
            event_type="privacy.dead_letter.requeued",
            key=f"governed-replay:{operation.id}",
            request_hash=operation.request_hash,
            payload={
                "operation_id": str(operation.id),
                "subject_id": str(subject.id),
                "phase": binding.phase,
                "replay_generation": subject.replay_generation,
            },
            occurred_at=decided_at,
        )
        return {
            "subject_id": str(subject.id),
            "status": subject.status,
            "replay_generation": subject.replay_generation,
        }

    def _finalization_snapshot(
        self, db: Session, manifest: PrivacyDeletionManifestRecord
    ) -> dict[str, object]:
        record = self._finalization_record(db, manifest)
        return {**record, "manifest_record_sha256": _digest(record)}

    def _finalization_record(
        self, db: Session, manifest: PrivacyDeletionManifestRecord
    ) -> dict[str, object]:
        if manifest.approval_provenance != "governed_operation":
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked", "legacy approval cannot be finalized"
            )
        if (
            manifest.status != "ready_to_finalize"
            or manifest.completion_operation_id is not None
            or manifest.completed_at is not None
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked", "deletion Manifest is not ready to finalize"
            )
        target_type = cast(PrivacyTargetType, manifest.target_type)
        target_status, target_version = deletion_target_state(
            db, target_type, manifest.target_id, lock=True
        )
        if (
            target_status != expected_deletion_target_status(target_type)
            or target_version != manifest.expected_target_version
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_conflict",
                "deletion target no longer matches its Manifest",
            )
        work_items = tuple(
            db.scalars(
                sa.select(PrivacyDeletionWorkItemRecord)
                .where(PrivacyDeletionWorkItemRecord.manifest_id == manifest.id)
                .order_by(PrivacyDeletionWorkItemRecord.surface, PrivacyDeletionWorkItemRecord.id)
            )
        )
        expected_surfaces = set(self._surface_policy())
        if (
            len(work_items) != len(expected_surfaces)
            or {item.surface for item in work_items} != expected_surfaces
            or any(item.status != "succeeded" for item in work_items)
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked", "all deletion Work Items must succeed"
            )
        attestations = tuple(
            db.scalars(
                sa.select(PrivacyEvidenceAttestationRecord)
                .where(
                    PrivacyEvidenceAttestationRecord.manifest_id == manifest.id,
                    PrivacyEvidenceAttestationRecord.subject_kind == "surface",
                )
                .order_by(PrivacyEvidenceAttestationRecord.subject_id)
            )
        )
        by_subject = {value.subject_id: value for value in attestations}
        if len(attestations) != len(work_items) or {value.id for value in work_items} != set(
            by_subject
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked", "every Work Item needs verified DSSE"
            )
        for item in work_items:
            receipt = by_subject[item.id]
            if (
                receipt.target_type != manifest.target_type
                or receipt.target_id != manifest.target_id
                or receipt.tenant_id != manifest.tenant_id
                or receipt.surface != item.surface
                or receipt.signature_algorithm != "ed25519"
                or receipt.payload_sha256 != item.outcome_content_sha256
            ):
                raise PlatformSecurityError(
                    "platform_privacy_manifest_blocked",
                    "Work Item DSSE receipt does not match its final projection",
                )
        active_holds = int(
            db.scalar(
                sa.select(sa.func.count())
                .select_from(PrivacyLegalHoldRecord)
                .where(
                    PrivacyLegalHoldRecord.target_type == manifest.target_type,
                    PrivacyLegalHoldRecord.target_id == manifest.target_id,
                    PrivacyLegalHoldRecord.status == "active",
                )
            )
            or 0
        )
        if active_holds:
            raise PlatformSecurityError(
                "platform_privacy_deletion_blocked", "an active Legal Hold blocks completion"
            )
        backups = tuple(
            db.scalars(
                sa.select(PrivacyBackupRetentionItemRecord)
                .where(PrivacyBackupRetentionItemRecord.manifest_id == manifest.id)
                .order_by(PrivacyBackupRetentionItemRecord.id)
            )
        )
        if manifest.retention_status not in {"pending", "not_applicable", "completed"}:
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked", "Backup retention needs operator attention"
            )
        if any(
            value.status in {"dead_letter", "legacy_reconciliation_required"} for value in backups
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked", "Backup retention has an unresolved failure"
            )
        if (manifest.retention_status == "pending" and not backups) or (
            manifest.retention_status == "not_applicable" and backups
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked",
                "Backup retention projection does not match its catalog",
            )
        if manifest.retention_status == "pending" and all(
            value.status == "purged" for value in backups
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked", "pending Backup retention is inconsistent"
            )
        if manifest.retention_status == "completed" and (
            not backups or any(value.status != "purged" for value in backups)
        ):
            raise PlatformSecurityError(
                "platform_privacy_manifest_blocked", "completed Backup retention is inconsistent"
            )
        return {
            "schema_version": 1,
            "phase": "deletion_finalize",
            "target_type": manifest.target_type,
            "target_id": str(manifest.target_id),
            "target_status": target_status,
            "target_version": target_version,
            "manifest_id": str(manifest.id),
            "manifest_version": manifest.version,
            "manifest_status": manifest.status,
            "approval_provenance": manifest.approval_provenance,
            "start_operation_id": str(manifest.start_operation_id),
            "retention_status": manifest.retention_status,
            "surface_outcomes_sha256": _digest(manifest.surface_outcomes),
            "work_items": [
                {
                    "id": str(value.id),
                    "surface": value.surface,
                    "outcome_content_sha256": value.outcome_content_sha256,
                    "replay_generation": value.replay_generation,
                }
                for value in work_items
            ],
            "attestations": [
                {
                    "subject_id": str(value.subject_id),
                    "payload_sha256": value.payload_sha256,
                    "envelope_sha256": value.envelope_sha256,
                    "product_revision": value.product_revision,
                    "schema_revision": value.schema_revision,
                }
                for value in attestations
            ],
            "backup_retention": [
                {
                    "id": str(value.id),
                    "status": value.status,
                    "purge_due_at": _stored_utc(value.purge_due_at).isoformat(),
                    "tombstone_sha256": value.tombstone_sha256,
                }
                for value in backups
            ],
            "active_hold_count": active_holds,
            "surface_policy_sha256": self._surface_policy_hash(),
            "policy_version": POLICY_VERSION,
        }

    def _finish_failed(
        self,
        db: Session,
        operation: PlatformAdminOperationRecord,
        binding: PrivacyApprovalBindingRecord,
        actor: ValidatedPlatformPrincipal,
        error_code: str,
        at: datetime,
    ) -> PrivacyOperationView:
        operation.status = "failed"
        operation.approved_by_principal_id = actor.principal_id
        operation.approved_at = at
        operation.completed_at = at
        operation.error_code = error_code
        operation.version += 1
        operation.result = {**(operation.result or {}), "decision": "failed"}
        operation.updated_at = at
        self._append_audit(
            db,
            tenant_id=binding.tenant_id,
            actor_id=actor.principal_id,
            event_type="platform.privacy_operation.failed",
            target_type=f"privacy_{binding.target_type}",
            target_id=binding.target_id,
            operation_id=operation.id,
            payload={
                "phase": binding.phase,
                "snapshot_hash": binding.snapshot_hash,
                "error_code": error_code,
            },
            occurred_at=at,
        )
        return self._view(operation, binding)

    def _require_requester_current(
        self,
        db: Session,
        operation: PlatformAdminOperationRecord,
        binding: PrivacyApprovalBindingRecord,
        at: datetime,
    ) -> None:
        principal = db.get(PlatformStaffPrincipalRecord, operation.requested_by_principal_id)
        expected_version = binding.impact_snapshot.get("requester_security_version")
        if (
            principal is None
            or principal.status != "active"
            or principal.security_version != expected_version
        ):
            raise PlatformSecurityError(
                "platform_principal_inactive", "Privacy requester is no longer active"
            )
        roles = tuple(
            db.scalars(
                sa.select(PlatformRoleAssignmentRecord.role).where(
                    PlatformRoleAssignmentRecord.principal_id == principal.id,
                    PlatformRoleAssignmentRecord.status == "active",
                    sa.or_(
                        PlatformRoleAssignmentRecord.expires_at.is_(None),
                        PlatformRoleAssignmentRecord.expires_at > at,
                    ),
                )
            )
        )
        permissions = {
            permission
            for role in roles
            for permission in PLATFORM_ROLE_PERMISSIONS.get(role, frozenset())
        }
        if "platform.data_request.request" not in permissions:
            raise PlatformSecurityError(
                "platform_permission_denied", "Privacy requester permission was revoked"
            )

    @staticmethod
    def _serialize(db: Session, principal_id: UUID, key: str) -> None:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"privacy-operation:{principal_id}:{key}"},
            )

    @staticmethod
    def _authorize(
        db: Session,
        actor: ValidatedPlatformPrincipal,
        permission: str,
        at: datetime,
    ) -> None:
        PlatformAuthorizationService.require_current(db, actor, permission, now=at)

    @staticmethod
    def _bind(
        db: Session,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        operation_id: UUID | None = None,
        manifest_id: UUID | None = None,
    ) -> None:
        apply_platform_rls_context(
            db,
            PlatformRlsContext(
                principal_id=actor.principal_id,
                target_tenant_id=target_id if target_type == "tenant" else None,
                target_user_id=target_id if target_type == "global_user" else None,
                target_admin_operation_id=operation_id,
                privacy_manifest_id=manifest_id,
            ),
        )

    @staticmethod
    def _manifest(
        db: Session,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        *,
        lock: bool,
    ) -> PrivacyDeletionManifestRecord:
        query = sa.select(PrivacyDeletionManifestRecord).where(
            PrivacyDeletionManifestRecord.id == manifest_id,
            PrivacyDeletionManifestRecord.target_type == target_type,
            PrivacyDeletionManifestRecord.target_id == target_id,
        )
        if lock:
            query = query.with_for_update()
        manifest = db.execute(query).scalar_one_or_none()
        if manifest is None:
            raise PlatformSecurityError(
                "platform_privacy_manifest_not_found", "deletion Manifest was not found"
            )
        return manifest

    @staticmethod
    def _reason(value: str) -> str:
        if value not in _REASON_CODES:
            raise PlatformSecurityError("platform_privacy_invalid", "reason_code is invalid")
        return value

    @staticmethod
    def _expiry(value: datetime, at: datetime) -> datetime:
        expiry = _utc(value)
        if expiry <= at or expiry > at + _MAX_APPROVAL_WINDOW:
            raise PlatformSecurityError(
                "platform_privacy_invalid", "approval expiry must be within 30 minutes"
            )
        return expiry

    @staticmethod
    def _authentication_hash(actor: ValidatedPlatformPrincipal) -> str:
        return _digest(
            {
                "session_id": str(actor.session_id),
                "principal_id": str(actor.principal_id),
                "security_version": actor.security_version,
                "authn_method": actor.authn_method,
                "authenticated_at": _utc(actor.authenticated_at).isoformat(),
            }
        )

    @staticmethod
    def _surface_policy() -> dict[str, tuple[str, int]]:
        from saas.control_plane.privacy_lifecycle import _SURFACE_POLICY

        return dict(_SURFACE_POLICY)

    def _surface_policy_hash(self) -> str:
        return _digest(self._surface_policy())

    def _outbox(
        self,
        db: Session,
        manifest: PrivacyDeletionManifestRecord,
        *,
        event_type: str,
        key: str,
        request_hash: str,
        payload: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        target_locator_hmac = self._locator_key.hash(
            f"privacy-outbox-v1:{manifest.target_type}:{manifest.target_id}"
        )
        db.add(
            ControlPlaneOutboxEvent(
                id=uuid4(),
                tenant_id=manifest.tenant_id,
                aggregate_type=f"privacy_{manifest.target_type}",
                aggregate_key=target_locator_hmac,
                event_type=event_type,
                payload=payload,
                idempotency_key=scoped_idempotency_key("privacy", target_locator_hmac, key),
                request_hash=request_hash,
                attempt_count=0,
                available_at=occurred_at,
                created_at=occurred_at,
            )
        )

    @staticmethod
    def _append_audit(
        db: Session,
        *,
        tenant_id: UUID | None,
        actor_id: UUID,
        event_type: str,
        target_type: str,
        target_id: UUID,
        operation_id: UUID,
        payload: dict[str, object],
        occurred_at: datetime,
    ) -> None:
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
            db.flush()
        sequence = head.last_sequence + 1
        payload_hash = _digest(payload)
        event_data = {
            "sequence_no": sequence,
            "tenant_id": str(tenant_id) if tenant_id is not None else None,
            "actor_type": "staff",
            "actor_id": str(actor_id),
            "event_type": event_type,
            "target_type": target_type,
            "target_id": str(target_id),
            "operation_id": str(operation_id),
            "payload_hash": payload_hash,
            "previous_hash": head.last_event_hash,
            "occurred_at": occurred_at.isoformat(),
        }
        event = PlatformAuditEventRecord(
            id=uuid4(),
            sequence_no=sequence,
            tenant_id=tenant_id,
            actor_type="staff",
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
        head.last_sequence = sequence
        head.last_event_hash = event.event_hash
        head.updated_at = occurred_at

    @staticmethod
    def _work_item_view(value: PrivacyDeletionWorkItemRecord) -> PrivacyWorkItemView:
        return PrivacyWorkItemView(
            work_item_id=value.id,
            surface=value.surface,
            disposition=value.disposition,
            adapter_type=value.adapter_type,
            status=value.status,
            attempt_count=value.attempt_count,
            max_attempts=value.max_attempts,
            available_at=_stored_utc(value.available_at),
            leased_at=_stored_utc(value.leased_at) if value.leased_at else None,
            lease_expires_at=(
                _stored_utc(value.lease_expires_at) if value.lease_expires_at else None
            ),
            lease_generation=value.lease_generation,
            replay_generation=value.replay_generation,
            last_error_code=value.last_error_code,
            last_error_sha256=value.last_error_sha256,
            outcome_content_sha256=value.outcome_content_sha256,
            version=value.version,
            created_at=_stored_utc(value.created_at),
            updated_at=_stored_utc(value.updated_at),
        )

    @staticmethod
    def _attempt_view(value: PrivacyDeletionAttemptRecord) -> PrivacyAttemptView:
        return PrivacyAttemptView(
            attempt_id=value.id,
            work_item_id=value.work_item_id,
            backup_item_id=value.backup_retention_item_id,
            surface=value.surface,
            attempt_number=value.attempt_number,
            lease_generation=value.lease_generation,
            replay_generation=value.replay_generation,
            provider_idempotency_sha256=value.provider_idempotency_sha256,
            outcome=value.outcome,
            error_code=value.error_code,
            error_sha256=value.error_sha256,
            evidence_payload_sha256=value.evidence_payload_sha256,
            started_at=_stored_utc(value.started_at),
            completed_at=_stored_utc(value.completed_at),
        )

    @staticmethod
    def _attestation_view(
        value: PrivacyEvidenceAttestationRecord,
    ) -> PrivacyAttestationView:
        return PrivacyAttestationView(
            attestation_id=value.id,
            subject_kind=value.subject_kind,
            subject_id=value.subject_id,
            surface=value.surface,
            payload_type=value.payload_type,
            payload_sha256=value.payload_sha256,
            envelope_sha256=value.envelope_sha256,
            immutability_receipt_sha256=value.immutability_receipt_sha256,
            kms_audit_receipt_sha256=value.kms_audit_receipt_sha256,
            signature_algorithm=value.signature_algorithm,
            record_sha256=value.record_sha256,
            product_revision=value.product_revision,
            upstream_revision=value.upstream_revision,
            schema_revision=value.schema_revision,
            adapter_contract_version=value.adapter_contract_version,
            verifier_policy_version=value.verifier_policy_version,
            signed_at=_stored_utc(value.signed_at),
            verified_at=_stored_utc(value.verified_at),
            created_at=_stored_utc(value.created_at),
        )

    @staticmethod
    def _backup_view(value: PrivacyBackupRetentionItemRecord) -> PrivacyBackupView:
        return PrivacyBackupView(
            backup_item_id=value.id,
            provider=value.provider,
            backup_data_class=value.backup_data_class,
            catalog_snapshot_sha256=value.catalog_snapshot_sha256,
            tombstone_sha256=value.tombstone_sha256,
            object_lock_until=(
                _stored_utc(value.object_lock_until) if value.object_lock_until else None
            ),
            purge_due_at=_stored_utc(value.purge_due_at),
            status=value.status,
            attempt_count=value.attempt_count,
            max_attempts=value.max_attempts,
            available_at=_stored_utc(value.available_at),
            leased_at=_stored_utc(value.leased_at) if value.leased_at else None,
            lease_expires_at=(
                _stored_utc(value.lease_expires_at) if value.lease_expires_at else None
            ),
            lease_generation=value.lease_generation,
            replay_generation=value.replay_generation,
            last_error_code=value.last_error_code,
            last_error_sha256=value.last_error_sha256,
            purge_evidence_sha256=value.purge_evidence_sha256,
            purged_at=_stored_utc(value.purged_at) if value.purged_at else None,
            version=value.version,
            created_at=_stored_utc(value.created_at),
            updated_at=_stored_utc(value.updated_at),
        )

    @staticmethod
    def _view(
        operation: PlatformAdminOperationRecord,
        binding: PrivacyApprovalBindingRecord,
        *,
        replayed: bool = False,
    ) -> PrivacyOperationView:
        return PrivacyOperationView(
            operation_id=operation.id,
            phase=binding.phase,
            target_type=binding.target_type,
            target_id=binding.target_id,
            manifest_id=binding.manifest_id,
            subject_id=binding.subject_id,
            status=operation.status,
            version=operation.version,
            snapshot_hash=binding.snapshot_hash,
            requested_by_principal_id=operation.requested_by_principal_id,
            approved_by_principal_id=operation.approved_by_principal_id,
            expires_at=_stored_utc(binding.expires_at),
            created_at=_stored_utc(operation.created_at),
            completed_at=(_stored_utc(operation.completed_at) if operation.completed_at else None),
            error_code=operation.error_code,
            replayed=replayed,
        )


__all__ = [
    "PrivacyAttemptPage",
    "PrivacyAttemptView",
    "PrivacyAttestationPage",
    "PrivacyAttestationView",
    "PrivacyBackupPage",
    "PrivacyBackupView",
    "PrivacyLocatorKey",
    "PrivacyOperationPage",
    "PrivacyOperationService",
    "PrivacyOperationView",
    "PrivacyWorkItemPage",
    "PrivacyWorkItemView",
]
