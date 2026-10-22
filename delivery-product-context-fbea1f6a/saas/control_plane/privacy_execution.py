"""Lease-fenced Privacy execution authority for deletion and Backup purge work."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal, cast
from uuid import UUID, uuid4, uuid5

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent, RuntimePartitionRecord
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.platform_security import PlatformSecurityError
from saas.control_plane.privacy_attestation import (
    PrivacyAttestationVerifier,
    PrivacyDsseEnvelope,
    VerifiedPrivacyAttestation,
    canonical_json,
    privacy_verifier_receipt_sha256,
)
from saas.control_plane.privacy_models import (
    PrivacyBackupRetentionItemRecord,
    PrivacyDeletionAttemptRecord,
    PrivacyDeletionManifestRecord,
    PrivacyDeletionWorkItemRecord,
    PrivacyEvidenceAttestationRecord,
    PrivacyLegalHoldRecord,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context

PrivacyTargetType = Literal["global_user", "tenant"]

PRIVACY_RETRYABLE_ERROR_CODES = frozenset(
    {
        "privacy_adapter_unavailable",
        "privacy_provider_rate_limited",
        "privacy_provider_timeout",
        "privacy_resource_lock_pending",
        "privacy_temporary_dependency_failure",
    }
)
PRIVACY_TERMINAL_ERROR_CODES = frozenset(
    {
        "privacy_adapter_contract_invalid",
        "privacy_evidence_rejected",
        "privacy_provider_access_denied",
        "privacy_resource_scope_invalid",
    }
)
PRIVACY_EXECUTION_ERROR_CODES = PRIVACY_RETRYABLE_ERROR_CODES | PRIVACY_TERMINAL_ERROR_CODES
PRIVACY_EXECUTION_EVENT_TYPES = frozenset(
    {
        "privacy.execution.backup_dead_lettered",
        "privacy.execution.backup_purged",
        "privacy.execution.backup_retry_scheduled",
        "privacy.execution.retention_attention_required",
        "privacy.execution.retention_completed",
        "privacy.execution.work_dead_lettered",
        "privacy.execution.work_retry_scheduled",
        "privacy.execution.work_succeeded",
    }
)

_ATTEMPT_NAMESPACE = UUID("686cc1c8-1498-4c82-b0e1-cd389bb96c74")
_LEASE_LOST_CODE = "privacy_execution_lease_expired"
_ATTEMPT_BUDGET_CODE = "privacy_execution_attempt_budget_exhausted"
_LEGAL_HOLD_CODE = "privacy_legal_hold_active"
_RETENTION_WAIT_CODE = "privacy_retention_not_due"
_HASH_ALPHABET = frozenset("0123456789abcdef")
_RETAINED_DISPOSITIONS = frozenset(
    {"anonymize_and_retain", "redact_and_retain", "tombstone_then_expire"}
)


def _utc_input(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PlatformSecurityError("platform_time_invalid", f"{field} must include a timezone")
    return value.astimezone(timezone.utc)


def _db_utc(value: datetime) -> datetime:
    """SQLite loses timezone metadata; persisted timestamps are defined as UTC."""

    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _digest_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _domain_hmac(key: bytes, domain: str, value: object) -> str:
    if len(key) < 32:
        raise ValueError("Privacy locator HMAC key must contain at least 32 bytes")
    return hmac.new(
        key,
        canonical_json({"domain": domain, "value": value}),
        digestmod=sha256,
    ).hexdigest()


def privacy_target_locator_hmac(
    key: bytes, target_type: PrivacyTargetType, target_id: UUID
) -> str:
    """Return a domain-separated, non-reversible locator for execution events."""

    return _domain_hmac(
        key,
        "omnigent/privacy/event-target/v1",
        {"target_type": target_type, "target_id": str(target_id)},
    )


def privacy_backup_locator_hmac(key: bytes, provider: str, resource_handle_ref: str) -> str:
    """Bind an opaque provider handle without persisting or signing the raw value."""

    return _domain_hmac(
        key,
        "omnigent/privacy/backup-resource/v1",
        {"provider": provider, "resource_handle_ref": resource_handle_ref},
    )


def privacy_adapter_error_hmac(key: bytes, item_id: UUID, error_code: str, raw_error: str) -> str:
    """Return a domain-separated diagnostic digest scoped to one work item."""

    return _domain_hmac(
        key,
        "omnigent/privacy/adapter-error/v1",
        {
            "item_id": str(item_id),
            "error_code": error_code,
            "raw_error": raw_error,
        },
    )


def _require_sha256(value: str, field: str) -> str:
    if len(value) != 64 or any(character not in _HASH_ALPHABET for character in value):
        raise PlatformSecurityError(
            "platform_privacy_execution_invalid", f"{field} must be a lowercase SHA256"
        )
    return value


def _attempt_id(kind: str, item_id: UUID, replay_generation: int, attempt_number: int) -> UUID:
    return uuid5(
        _ATTEMPT_NAMESPACE,
        f"{kind}:{item_id}:{replay_generation}:{attempt_number}",
    )


def _idempotency_digest(
    kind: str, item_id: UUID, replay_generation: int, attempt_number: int
) -> str:
    return _digest_text(f"{kind}:{item_id}:{replay_generation}:{attempt_number}")


@dataclass(frozen=True, slots=True)
class WorkloadIdentity:
    """Verified machine identity; intentionally cannot carry a Staff session or cookie."""

    issuer: str
    subject: str
    audience: str
    authenticated_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PrivacyExecutionPolicy:
    """Pinned revisions and bounded lease/retry policy for one worker deployment."""

    audience: str
    trusted_issuers: frozenset[str]
    product_revision: str
    upstream_revision: str
    schema_revision: str
    adapter_contract_version: str
    verifier_policy_version: str
    lease_duration: timedelta = timedelta(minutes=5)
    base_backoff: timedelta = timedelta(seconds=5)
    max_backoff: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.product_revision, "product_revision"),
            (self.upstream_revision, "upstream_revision"),
        ):
            if len(value) != 40 or any(character not in _HASH_ALPHABET for character in value):
                raise ValueError(f"{field_name} must be a lowercase 40-character revision")
        if not all(
            value.strip()
            for value in (
                self.audience,
                self.schema_revision,
                self.adapter_contract_version,
                self.verifier_policy_version,
            )
        ):
            raise ValueError("Privacy execution revision and audience values are required")
        if not self.trusted_issuers or any(not value.strip() for value in self.trusted_issuers):
            raise ValueError("Privacy execution requires at least one trusted Workload issuer")
        if (
            self.lease_duration <= timedelta(0)
            or self.base_backoff <= timedelta(0)
            or self.max_backoff < self.base_backoff
        ):
            raise ValueError("Privacy execution lease and backoff policy is invalid")


@dataclass(frozen=True, slots=True)
class PrivacyEvidenceOutcome:
    """Executor-observed claims that are exact-bound to the signed DSSE payload."""

    evidence_sha256: str
    remaining_item_count: int = 0
    runtime_accessible: bool = False
    direct_identifiers_remaining: bool = False
    retention_until: datetime | None = None
    retention_basis: str | None = None
    tombstone_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class PrivacyBackupCatalogEntry:
    """One provider Backup resource discovered by the signed catalog workflow."""

    provider: str
    backup_data_class: str
    backup_locator_hmac: str
    resource_handle_ref: str = field(repr=False)
    catalog_snapshot_sha256: str
    tombstone_sha256: str
    purge_due_at: datetime
    object_lock_until: datetime | None = None
    runtime_partition_id: UUID | None = None


def privacy_backup_catalog_digest(entries: tuple[PrivacyBackupCatalogEntry, ...]) -> str:
    """Bind public catalog facts to DSSE without exposing opaque provider handles."""

    rows = [
        {
            "provider": entry.provider,
            "backup_data_class": entry.backup_data_class,
            "backup_locator_hmac": entry.backup_locator_hmac,
            "runtime_partition_id": (
                str(entry.runtime_partition_id) if entry.runtime_partition_id is not None else None
            ),
            "catalog_snapshot_sha256": entry.catalog_snapshot_sha256,
            "object_lock_until": (
                _utc_input(entry.object_lock_until, "object_lock_until").isoformat()
                if entry.object_lock_until is not None
                else None
            ),
            "purge_due_at": _utc_input(entry.purge_due_at, "purge_due_at").isoformat(),
            "tombstone_sha256": entry.tombstone_sha256,
        }
        for entry in entries
    ]
    rows.sort(
        key=lambda value: (
            cast(str, value["backup_locator_hmac"]),
            cast(str, value["catalog_snapshot_sha256"]),
            cast(str, value["tombstone_sha256"]),
        )
    )
    return sha256(canonical_json(rows)).hexdigest()


@dataclass(frozen=True, slots=True)
class ClaimedPrivacyWorkItem:
    item_id: UUID
    manifest_id: UUID
    target_type: PrivacyTargetType
    target_id: UUID
    tenant_id: UUID | None
    surface: str
    disposition: str
    resource_scope_hmac: str
    adapter_type: str
    attempt_id: UUID
    attempt_number: int
    lease_generation: int
    replay_generation: int
    lease_token: str = field(repr=False)
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class ClaimedPrivacyBackupItem:
    item_id: UUID
    manifest_id: UUID
    target_type: PrivacyTargetType
    target_id: UUID
    tenant_id: UUID | None
    provider: str
    backup_data_class: str
    backup_locator_hmac: str
    resource_handle_ref: str = field(repr=False)
    catalog_snapshot_sha256: str
    tombstone_sha256: str
    attempt_id: UUID
    attempt_number: int
    lease_generation: int
    replay_generation: int
    lease_token: str = field(repr=False)
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class PrivacyExecutionFailure:
    item_id: UUID
    attempt_id: UUID
    status: Literal["retry", "dead_letter", "held", "retention_wait"]
    available_at: datetime


@dataclass(frozen=True, slots=True)
class PrivacyExecutionCompletion:
    item_id: UUID
    attempt_id: UUID
    attestation_id: UUID
    status: Literal["succeeded", "purged"]


@dataclass(frozen=True, slots=True)
class PrivacyDestructiveAuthorization:
    """Short-lived proof that an exact destructive lease passed the Hold fence."""

    item_id: UUID
    attempt_id: UUID
    lease_generation: int
    replay_generation: int
    authorized_at: datetime
    expires_at: datetime
    authorization_sha256: str


class PrivacyExecutionService:
    """Claim, fence, execute, and attest Privacy work without a human principal."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        verifier_session_factory: sessionmaker[Session],
        verifier: PrivacyAttestationVerifier,
        policy: PrivacyExecutionPolicy,
        locator_hmac_key: bytes,
    ) -> None:
        self._sessions = session_factory
        self._verifier_sessions = verifier_session_factory
        self._verifier = verifier
        self._policy = policy
        if len(locator_hmac_key) < 32:
            raise ValueError("Privacy locator HMAC key must contain at least 32 bytes")
        self._locator_hmac_key = locator_hmac_key

    def claim_work_item(
        self,
        identity: WorkloadIdentity,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        now: datetime | None = None,
    ) -> ClaimedPrivacyWorkItem | None:
        """Claim one exact-scope deletion item using SKIP LOCKED where supported."""

        at = self._at(now)
        executor_hash = self._identity_hash(identity, at)
        with self._sessions.begin() as db:
            self._bind(db, target_type, target_id, manifest_id)
            self._lock_target(db, target_type, target_id)
            if self._has_active_hold(db, target_type, target_id):
                return None
            item = db.execute(
                sa.select(PrivacyDeletionWorkItemRecord)
                .where(
                    PrivacyDeletionWorkItemRecord.manifest_id == manifest_id,
                    PrivacyDeletionWorkItemRecord.target_type == target_type,
                    PrivacyDeletionWorkItemRecord.target_id == target_id,
                    sa.or_(
                        sa.and_(
                            PrivacyDeletionWorkItemRecord.status.in_(("pending", "retry")),
                            PrivacyDeletionWorkItemRecord.available_at <= at,
                        ),
                        sa.and_(
                            PrivacyDeletionWorkItemRecord.status == "leased",
                            PrivacyDeletionWorkItemRecord.lease_expires_at <= at,
                        ),
                    ),
                )
                .order_by(
                    PrivacyDeletionWorkItemRecord.available_at,
                    PrivacyDeletionWorkItemRecord.id,
                )
                .with_for_update(skip_locked=True)
                .limit(1)
            ).scalar_one_or_none()
            if item is None:
                return None
            if item.status == "leased":
                self._append_lost_attempt(db, item, backup=False, completed_at=at)
                self._clear_lease(item)
                item.last_error_code = _LEASE_LOST_CODE
                item.last_error_sha256 = _digest_text(_LEASE_LOST_CODE)
                if item.attempt_count >= item.max_attempts:
                    item.status = "dead_letter"
                    item.version += 1
                    item.updated_at = at
                    self._append_outbox_event(
                        db,
                        item,
                        event_type="privacy.execution.work_dead_lettered",
                        status="dead_letter",
                        content_sha256=cast(str, item.last_error_sha256),
                        occurred_at=at,
                        error_code=cast(str, item.last_error_code),
                    )
                    return None
            if item.attempt_count >= item.max_attempts:
                item.status = "dead_letter"
                item.last_error_code = item.last_error_code or _ATTEMPT_BUDGET_CODE
                item.last_error_sha256 = item.last_error_sha256 or _digest_text(
                    _ATTEMPT_BUDGET_CODE
                )
                item.version += 1
                item.updated_at = at
                self._append_outbox_event(
                    db,
                    item,
                    event_type="privacy.execution.work_dead_lettered",
                    status="dead_letter",
                    content_sha256=cast(str, item.last_error_sha256),
                    occurred_at=at,
                    error_code=item.last_error_code,
                )
                return None
            return self._lease_work_item(item, executor_hash=executor_hash, leased_at=at)

    def claim_backup_item(
        self,
        identity: WorkloadIdentity,
        *,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
        now: datetime | None = None,
    ) -> ClaimedPrivacyBackupItem | None:
        """Claim one due, unlocked Backup item after serializing with Legal Hold changes."""

        at = self._at(now)
        executor_hash = self._identity_hash(identity, at)
        with self._sessions.begin() as db:
            self._bind(db, target_type, target_id, manifest_id)
            self._lock_target(db, target_type, target_id)
            hold_active = self._has_active_hold(db, target_type, target_id)
            item = db.execute(
                sa.select(PrivacyBackupRetentionItemRecord)
                .where(
                    PrivacyBackupRetentionItemRecord.manifest_id == manifest_id,
                    PrivacyBackupRetentionItemRecord.target_type == target_type,
                    PrivacyBackupRetentionItemRecord.target_id == target_id,
                    sa.or_(
                        sa.and_(
                            PrivacyBackupRetentionItemRecord.status.in_(
                                ("retention_wait", "held", "retry")
                            ),
                            PrivacyBackupRetentionItemRecord.available_at <= at,
                            PrivacyBackupRetentionItemRecord.purge_due_at <= at,
                            sa.or_(
                                PrivacyBackupRetentionItemRecord.object_lock_until.is_(None),
                                PrivacyBackupRetentionItemRecord.object_lock_until <= at,
                            ),
                        ),
                        sa.and_(
                            PrivacyBackupRetentionItemRecord.status == "leased",
                            PrivacyBackupRetentionItemRecord.lease_expires_at <= at,
                        ),
                    ),
                )
                .order_by(
                    PrivacyBackupRetentionItemRecord.purge_due_at,
                    PrivacyBackupRetentionItemRecord.available_at,
                    PrivacyBackupRetentionItemRecord.id,
                )
                .with_for_update(skip_locked=True)
                .limit(1)
            ).scalar_one_or_none()
            if item is None:
                return None
            if item.status == "leased":
                self._append_lost_attempt(db, item, backup=True, completed_at=at)
                self._clear_lease(item)
                item.last_error_code = _LEASE_LOST_CODE
                item.last_error_sha256 = _digest_text(_LEASE_LOST_CODE)
                if item.attempt_count >= item.max_attempts:
                    item.status = "dead_letter"
                    item.version += 1
                    item.updated_at = at
                    self._mark_retention_attention(db, item, at)
                    self._append_outbox_event(
                        db,
                        item,
                        event_type="privacy.execution.backup_dead_lettered",
                        status="dead_letter",
                        content_sha256=cast(str, item.last_error_sha256),
                        occurred_at=at,
                        error_code=cast(str, item.last_error_code),
                    )
                    return None
            if hold_active:
                item.status = "held"
                item.last_error_code = _LEGAL_HOLD_CODE
                item.last_error_sha256 = _digest_text(_LEGAL_HOLD_CODE)
                item.version += 1
                item.updated_at = at
                return None
            if item.attempt_count >= item.max_attempts:
                item.status = "dead_letter"
                item.last_error_code = item.last_error_code or _ATTEMPT_BUDGET_CODE
                item.last_error_sha256 = item.last_error_sha256 or _digest_text(
                    _ATTEMPT_BUDGET_CODE
                )
                item.version += 1
                item.updated_at = at
                self._mark_retention_attention(db, item, at)
                self._append_outbox_event(
                    db,
                    item,
                    event_type="privacy.execution.backup_dead_lettered",
                    status="dead_letter",
                    content_sha256=cast(str, item.last_error_sha256),
                    occurred_at=at,
                    error_code=item.last_error_code,
                )
                return None
            return self._lease_backup_item(item, executor_hash=executor_hash, leased_at=at)

    def authorize_destructive_execution(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        *,
        now: datetime | None = None,
    ) -> PrivacyDestructiveAuthorization:
        """Revalidate an exact lease and Hold fence immediately before provider I/O."""

        at = self._at(now)
        executor_hash = self._identity_hash(identity, at)
        with self._sessions.begin() as db:
            self._bind(db, claim.target_type, claim.target_id, claim.manifest_id)
            self._lock_target(db, claim.target_type, claim.target_id)
            if isinstance(claim, ClaimedPrivacyBackupItem):
                item = self._locked_backup_item(db, claim)
            else:
                item = self._locked_work_item(db, claim)
            self._require_lease(item, claim, executor_hash, at)
            if self._has_active_hold(db, claim.target_type, claim.target_id):
                raise PlatformSecurityError(
                    "platform_privacy_execution_blocked",
                    "an active Legal Hold blocks destructive execution",
                )
            if isinstance(item, PrivacyBackupRetentionItemRecord) and (
                _db_utc(item.purge_due_at) > at
                or (item.object_lock_until is not None and _db_utc(item.object_lock_until) > at)
            ):
                raise PlatformSecurityError(
                    "platform_privacy_execution_blocked",
                    "Backup retention governance blocks destructive execution",
                )
            expires_at = _db_utc(cast(datetime, item.lease_expires_at))
            token_hash = cast(str, item.lease_token_hash)
            authorization_sha256 = sha256(
                canonical_json(
                    {
                        "attempt_id": str(claim.attempt_id),
                        "item_id": str(item.id),
                        "lease_expires_at": expires_at.isoformat(),
                        "lease_generation": item.lease_generation,
                        "lease_token_sha256": token_hash,
                        "replay_generation": item.replay_generation,
                    }
                )
            ).hexdigest()
            return PrivacyDestructiveAuthorization(
                item_id=item.id,
                attempt_id=claim.attempt_id,
                lease_generation=item.lease_generation,
                replay_generation=item.replay_generation,
                authorized_at=at,
                expires_at=expires_at,
                authorization_sha256=authorization_sha256,
            )

    def complete_work_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        *,
        outcome: PrivacyEvidenceOutcome,
        envelope: PrivacyDsseEnvelope,
        backup_catalog: tuple[PrivacyBackupCatalogEntry, ...] = (),
        now: datetime | None = None,
    ) -> PrivacyExecutionCompletion:
        """Verify DSSE and atomically append Attempt/Attestation plus projections."""

        at = self._at(now)
        executor_hash = self._identity_hash(identity, at)
        attestation_id, payload_sha256 = self._persist_verifier_receipt(
            identity,
            claim,
            outcome=outcome,
            envelope=envelope,
            subject_kind="surface",
            backup_catalog=backup_catalog,
            at=at,
        )
        with self._sessions.begin() as db:
            self._bind(db, claim.target_type, claim.target_id, claim.manifest_id)
            self._lock_target(db, claim.target_type, claim.target_id)
            item = self._locked_work_item(db, claim)
            self._require_lease(item, claim, executor_hash, at)
            if self._has_active_hold(db, claim.target_type, claim.target_id):
                raise PlatformSecurityError(
                    "platform_privacy_execution_blocked",
                    "an active Legal Hold blocks destructive execution completion",
                )
            self._validate_outcome(outcome, disposition=item.disposition, at=at)
            self._validate_backup_catalog(db, item, outcome, backup_catalog, at)
            attestation = db.get(PrivacyEvidenceAttestationRecord, attestation_id)
            if attestation is None:
                raise PlatformSecurityError(
                    "platform_privacy_attestation_invalid",
                    "independent Privacy verifier receipt is unavailable",
                )
            self._require_verifier_receipt(
                attestation,
                item=item,
                claim=claim,
                subject_kind="surface",
                expected_payload_sha256=payload_sha256,
            )
            attempt = self._append_success_attempt(
                db,
                item,
                backup=False,
                evidence_payload_sha256=payload_sha256,
                completed_at=at,
            )
            item.status = "succeeded"
            item.outcome_content_sha256 = payload_sha256
            item.evidence_attestation_id = attestation.id
            item.last_error_code = None
            item.last_error_sha256 = None
            self._clear_lease(item)
            item.version += 1
            item.updated_at = at
            self._materialize_backup_catalog(db, item, backup_catalog, at)
            self._project_work_success(
                db,
                item,
                outcome,
                payload_sha256,
                at,
                backup_catalog_count=(
                    len(backup_catalog) if item.surface == "backups_and_snapshots" else None
                ),
            )
            self._append_outbox_event(
                db,
                item,
                event_type="privacy.execution.work_succeeded",
                status="succeeded",
                content_sha256=payload_sha256,
                occurred_at=at,
            )
            return PrivacyExecutionCompletion(
                item_id=item.id,
                attempt_id=attempt.id,
                attestation_id=attestation.id,
                status="succeeded",
            )

    def fail_work_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem,
        *,
        error_code: str,
        raw_error: str,
        now: datetime | None = None,
    ) -> PrivacyExecutionFailure:
        """Persist only an allowlisted code and a digest of the raw adapter error."""

        at = self._at(now)
        executor_hash = self._identity_hash(identity, at)
        self._require_error_code(error_code)
        error_hash = self._error_hash(claim.item_id, error_code, raw_error)
        with self._sessions.begin() as db:
            self._bind(db, claim.target_type, claim.target_id, claim.manifest_id)
            self._lock_target(db, claim.target_type, claim.target_id)
            item = self._locked_work_item(db, claim)
            self._require_lease(item, claim, executor_hash, at)
            status = self._failure_status(item, error_code)
            available_at = at if status == "dead_letter" else at + self._backoff(item)
            self._append_failure_attempt(
                db,
                item,
                backup=False,
                outcome=status,
                error_code=error_code,
                error_sha256=error_hash,
                completed_at=at,
            )
            item.status = status
            item.available_at = available_at
            item.last_error_code = error_code
            item.last_error_sha256 = error_hash
            self._clear_lease(item)
            item.version += 1
            item.updated_at = at
            self._append_outbox_event(
                db,
                item,
                event_type=(
                    "privacy.execution.work_dead_lettered"
                    if status == "dead_letter"
                    else "privacy.execution.work_retry_scheduled"
                ),
                status=status,
                content_sha256=error_hash,
                occurred_at=at,
                error_code=error_code,
                available_at=available_at if status == "retry" else None,
            )
            return PrivacyExecutionFailure(
                item_id=item.id,
                attempt_id=claim.attempt_id,
                status=cast(Literal["retry", "dead_letter"], status),
                available_at=available_at,
            )

    def complete_backup_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        *,
        evidence_sha256: str,
        envelope: PrivacyDsseEnvelope,
        now: datetime | None = None,
    ) -> PrivacyExecutionCompletion:
        """Purge a due Backup only when Hold/object-lock gates still permit commit."""

        at = self._at(now)
        executor_hash = self._identity_hash(identity, at)
        evidence_hash = _require_sha256(evidence_sha256, "evidence_sha256")
        outcome = PrivacyEvidenceOutcome(
            evidence_sha256=evidence_hash,
            tombstone_sha256=claim.tombstone_sha256,
        )
        attestation_id, payload_sha256 = self._persist_verifier_receipt(
            identity,
            claim,
            outcome=outcome,
            envelope=envelope,
            subject_kind="backup",
            at=at,
        )
        blocked_code: str | None = None
        completion: PrivacyExecutionCompletion | None = None
        with self._sessions.begin() as db:
            self._bind(db, claim.target_type, claim.target_id, claim.manifest_id)
            self._lock_target(db, claim.target_type, claim.target_id)
            item = self._locked_backup_item(db, claim)
            self._require_lease(item, claim, executor_hash, at)
            if self._has_active_hold(db, claim.target_type, claim.target_id):
                blocked_code = _LEGAL_HOLD_CODE
                blocked_status = "held"
            elif _db_utc(item.purge_due_at) > at or (
                item.object_lock_until is not None and _db_utc(item.object_lock_until) > at
            ):
                blocked_code = _RETENTION_WAIT_CODE
                blocked_status = "retention_wait"
            else:
                blocked_status = None
            if blocked_code is not None and blocked_status is not None:
                self._append_failure_attempt(
                    db,
                    item,
                    backup=True,
                    outcome="retry",
                    error_code=blocked_code,
                    error_sha256=_digest_text(blocked_code),
                    completed_at=at,
                )
                item.status = blocked_status
                item.last_error_code = blocked_code
                item.last_error_sha256 = _digest_text(blocked_code)
                self._clear_lease(item)
                item.version += 1
                item.updated_at = at
                self._append_outbox_event(
                    db,
                    item,
                    event_type="privacy.execution.backup_retry_scheduled",
                    status=blocked_status,
                    content_sha256=_digest_text(blocked_code),
                    occurred_at=at,
                    error_code=blocked_code,
                    available_at=item.available_at,
                )
            else:
                attestation = db.get(PrivacyEvidenceAttestationRecord, attestation_id)
                if attestation is None:
                    raise PlatformSecurityError(
                        "platform_privacy_attestation_invalid",
                        "independent Privacy verifier receipt is unavailable",
                    )
                self._require_verifier_receipt(
                    attestation,
                    item=item,
                    claim=claim,
                    subject_kind="backup",
                    expected_payload_sha256=payload_sha256,
                )
                attempt = self._append_success_attempt(
                    db,
                    item,
                    backup=True,
                    evidence_payload_sha256=payload_sha256,
                    completed_at=at,
                )
                item.status = "purged"
                item.purge_evidence_sha256 = payload_sha256
                item.evidence_attestation_id = attestation.id
                item.purged_at = at
                item.last_error_code = None
                item.last_error_sha256 = None
                self._clear_lease(item)
                item.version += 1
                item.updated_at = at
                db.flush()
                self._project_backup_completion(db, item, at)
                self._append_outbox_event(
                    db,
                    item,
                    event_type="privacy.execution.backup_purged",
                    status="purged",
                    content_sha256=payload_sha256,
                    occurred_at=at,
                )
                completion = PrivacyExecutionCompletion(
                    item_id=item.id,
                    attempt_id=attempt.id,
                    attestation_id=attestation.id,
                    status="purged",
                )
        if blocked_code is not None:
            raise PlatformSecurityError(
                "platform_privacy_backup_blocked",
                "Backup purge is blocked by current retention governance",
            )
        if completion is None:
            raise PlatformSecurityError(
                "platform_privacy_execution_invariant_broken",
                "Backup purge completed without an execution receipt",
            )
        return completion

    def fail_backup_item(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyBackupItem,
        *,
        error_code: str,
        raw_error: str,
        now: datetime | None = None,
    ) -> PrivacyExecutionFailure:
        """Retry or dead-letter one fenced Backup purge without storing raw errors."""

        at = self._at(now)
        executor_hash = self._identity_hash(identity, at)
        self._require_error_code(error_code)
        error_hash = self._error_hash(claim.item_id, error_code, raw_error)
        with self._sessions.begin() as db:
            self._bind(db, claim.target_type, claim.target_id, claim.manifest_id)
            self._lock_target(db, claim.target_type, claim.target_id)
            item = self._locked_backup_item(db, claim)
            self._require_lease(item, claim, executor_hash, at)
            status = self._failure_status(item, error_code)
            available_at = at if status == "dead_letter" else at + self._backoff(item)
            self._append_failure_attempt(
                db,
                item,
                backup=True,
                outcome=status,
                error_code=error_code,
                error_sha256=error_hash,
                completed_at=at,
            )
            item.status = status
            item.available_at = available_at
            item.last_error_code = error_code
            item.last_error_sha256 = error_hash
            self._clear_lease(item)
            item.version += 1
            item.updated_at = at
            if status == "dead_letter":
                self._mark_retention_attention(db, item, at)
            self._append_outbox_event(
                db,
                item,
                event_type=(
                    "privacy.execution.backup_dead_lettered"
                    if status == "dead_letter"
                    else "privacy.execution.backup_retry_scheduled"
                ),
                status=status,
                content_sha256=error_hash,
                occurred_at=at,
                error_code=error_code,
                available_at=available_at if status == "retry" else None,
            )
            return PrivacyExecutionFailure(
                item_id=item.id,
                attempt_id=claim.attempt_id,
                status=cast(Literal["retry", "dead_letter"], status),
                available_at=available_at,
            )

    def _at(self, value: datetime | None) -> datetime:
        return _utc_input(value or datetime.now(timezone.utc), "now")

    def _identity_hash(self, identity: WorkloadIdentity, at: datetime) -> str:
        if type(identity) is not WorkloadIdentity:
            raise PlatformSecurityError(
                "platform_privacy_workload_identity_invalid",
                "a dedicated Privacy Workload Identity is required",
            )
        authenticated_at = _utc_input(identity.authenticated_at, "authenticated_at")
        expires_at = _utc_input(identity.expires_at, "expires_at")
        if (
            not identity.issuer.strip()
            or not identity.subject.strip()
            or identity.audience != self._policy.audience
            or identity.issuer not in self._policy.trusted_issuers
            or authenticated_at > at
            or expires_at <= at
            or expires_at <= authenticated_at
        ):
            raise PlatformSecurityError(
                "platform_privacy_workload_identity_invalid",
                "Privacy Workload Identity is incomplete, expired, or has the wrong audience",
            )
        return sha256(
            canonical_json(
                {
                    "audience": identity.audience,
                    "issuer": identity.issuer,
                    "subject": identity.subject,
                }
            )
        ).hexdigest()

    def _error_hash(self, item_id: UUID, error_code: str, raw_error: str) -> str:
        """Digest adapter diagnostics without enabling cross-item correlation."""

        return privacy_adapter_error_hmac(
            self._locator_hmac_key,
            item_id,
            error_code,
            raw_error,
        )

    def _bind(
        self,
        db: Session,
        target_type: PrivacyTargetType,
        target_id: UUID,
        manifest_id: UUID,
    ) -> None:
        apply_platform_rls_context(
            db,
            PlatformRlsContext(
                target_tenant_id=target_id if target_type == "tenant" else None,
                target_user_id=target_id if target_type == "global_user" else None,
                privacy_manifest_id=manifest_id,
                privacy_locator_hash=privacy_target_locator_hmac(
                    self._locator_hmac_key, target_type, target_id
                ),
            ),
        )

    @staticmethod
    def _lock_target(db: Session, target_type: PrivacyTargetType, target_id: UUID) -> None:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:target, 0))"),
                {"target": f"privacy-target:{target_type}:{target_id}"},
            )

    @staticmethod
    def _has_active_hold(db: Session, target_type: PrivacyTargetType, target_id: UUID) -> bool:
        return bool(
            db.scalar(
                sa.select(sa.func.count())
                .select_from(PrivacyLegalHoldRecord)
                .where(
                    PrivacyLegalHoldRecord.target_type == target_type,
                    PrivacyLegalHoldRecord.target_id == target_id,
                    PrivacyLegalHoldRecord.status == "active",
                )
            )
        )

    def _lease_work_item(
        self,
        item: PrivacyDeletionWorkItemRecord,
        *,
        executor_hash: str,
        leased_at: datetime,
    ) -> ClaimedPrivacyWorkItem:
        token = secrets.token_urlsafe(32)
        item.status = "leased"
        item.attempt_count += 1
        item.lease_generation += 1
        item.leased_at = leased_at
        item.lease_expires_at = leased_at + self._policy.lease_duration
        item.lease_token_hash = _digest_text(token)
        item.executor_identity_sha256 = executor_hash
        item.last_error_code = None
        item.last_error_sha256 = None
        item.version += 1
        item.updated_at = leased_at
        return ClaimedPrivacyWorkItem(
            item_id=item.id,
            manifest_id=item.manifest_id,
            target_type=cast(PrivacyTargetType, item.target_type),
            target_id=item.target_id,
            tenant_id=item.tenant_id,
            surface=item.surface,
            disposition=item.disposition,
            resource_scope_hmac=item.resource_scope_hmac,
            adapter_type=item.adapter_type,
            attempt_id=_attempt_id("surface", item.id, item.replay_generation, item.attempt_count),
            attempt_number=item.attempt_count,
            lease_generation=item.lease_generation,
            replay_generation=item.replay_generation,
            lease_token=token,
            lease_expires_at=cast(datetime, item.lease_expires_at),
        )

    def _lease_backup_item(
        self,
        item: PrivacyBackupRetentionItemRecord,
        *,
        executor_hash: str,
        leased_at: datetime,
    ) -> ClaimedPrivacyBackupItem:
        if item.resource_handle_ref is None:
            raise PlatformSecurityError(
                "platform_privacy_backup_invalid", "Backup resource handle is unavailable"
            )
        token = secrets.token_urlsafe(32)
        item.status = "leased"
        item.attempt_count += 1
        item.lease_generation += 1
        item.leased_at = leased_at
        item.lease_expires_at = leased_at + self._policy.lease_duration
        item.lease_token_hash = _digest_text(token)
        item.executor_identity_sha256 = executor_hash
        item.last_error_code = None
        item.last_error_sha256 = None
        item.version += 1
        item.updated_at = leased_at
        return ClaimedPrivacyBackupItem(
            item_id=item.id,
            manifest_id=item.manifest_id,
            target_type=cast(PrivacyTargetType, item.target_type),
            target_id=item.target_id,
            tenant_id=item.tenant_id,
            provider=item.provider,
            backup_data_class=item.backup_data_class,
            backup_locator_hmac=item.backup_locator_hmac,
            resource_handle_ref=item.resource_handle_ref,
            catalog_snapshot_sha256=item.catalog_snapshot_sha256,
            tombstone_sha256=item.tombstone_sha256,
            attempt_id=_attempt_id("backup", item.id, item.replay_generation, item.attempt_count),
            attempt_number=item.attempt_count,
            lease_generation=item.lease_generation,
            replay_generation=item.replay_generation,
            lease_token=token,
            lease_expires_at=cast(datetime, item.lease_expires_at),
        )

    @staticmethod
    def _clear_lease(
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
    ) -> None:
        item.leased_at = None
        item.lease_expires_at = None
        item.lease_token_hash = None
        item.executor_identity_sha256 = None

    @staticmethod
    def _locked_work_item(
        db: Session, claim: ClaimedPrivacyWorkItem
    ) -> PrivacyDeletionWorkItemRecord:
        item = db.execute(
            sa.select(PrivacyDeletionWorkItemRecord)
            .where(
                PrivacyDeletionWorkItemRecord.id == claim.item_id,
                PrivacyDeletionWorkItemRecord.manifest_id == claim.manifest_id,
                PrivacyDeletionWorkItemRecord.target_type == claim.target_type,
                PrivacyDeletionWorkItemRecord.target_id == claim.target_id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if item is None:
            raise PlatformSecurityError(
                "platform_privacy_work_item_not_found", "Privacy Work Item was not found"
            )
        return item

    @staticmethod
    def _locked_backup_item(
        db: Session, claim: ClaimedPrivacyBackupItem
    ) -> PrivacyBackupRetentionItemRecord:
        item = db.execute(
            sa.select(PrivacyBackupRetentionItemRecord)
            .where(
                PrivacyBackupRetentionItemRecord.id == claim.item_id,
                PrivacyBackupRetentionItemRecord.manifest_id == claim.manifest_id,
                PrivacyBackupRetentionItemRecord.target_type == claim.target_type,
                PrivacyBackupRetentionItemRecord.target_id == claim.target_id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if item is None:
            raise PlatformSecurityError(
                "platform_privacy_backup_not_found", "Privacy Backup item was not found"
            )
        return item

    @staticmethod
    def _require_lease(
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        executor_hash: str,
        at: datetime,
    ) -> None:
        expected_token_hash = _digest_text(claim.lease_token)
        if (
            item.status != "leased"
            or item.attempt_count != claim.attempt_number
            or item.lease_generation != claim.lease_generation
            or item.replay_generation != claim.replay_generation
            or item.lease_token_hash is None
            or not hmac.compare_digest(item.lease_token_hash, expected_token_hash)
            or item.executor_identity_sha256 is None
            or not hmac.compare_digest(item.executor_identity_sha256, executor_hash)
            or item.lease_expires_at is None
            or _db_utc(item.lease_expires_at) <= at
        ):
            raise PlatformSecurityError(
                "platform_privacy_execution_lease_lost",
                "Privacy execution lease is missing, expired, or fenced by a newer generation",
            )

    @staticmethod
    def _append_lost_attempt(
        db: Session,
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
        *,
        backup: bool,
        completed_at: datetime,
    ) -> None:
        identity_hash = item.executor_identity_sha256
        if identity_hash is None or item.leased_at is None:
            raise PlatformSecurityError(
                "platform_privacy_execution_invariant_broken",
                "expired Privacy lease has no executor identity",
            )
        db.add(
            PrivacyDeletionAttemptRecord(
                id=_attempt_id(
                    "backup" if backup else "surface",
                    item.id,
                    item.replay_generation,
                    item.attempt_count,
                ),
                work_item_id=None if backup else item.id,
                backup_retention_item_id=item.id if backup else None,
                manifest_id=item.manifest_id,
                target_type=item.target_type,
                target_id=item.target_id,
                tenant_id=item.tenant_id,
                surface="backups_and_snapshots"
                if backup
                else cast(PrivacyDeletionWorkItemRecord, item).surface,
                attempt_number=item.attempt_count,
                lease_generation=item.lease_generation,
                replay_generation=item.replay_generation,
                provider_idempotency_sha256=_idempotency_digest(
                    "backup" if backup else "surface",
                    item.id,
                    item.replay_generation,
                    item.attempt_count,
                ),
                executor_identity_sha256=identity_hash,
                outcome="lease_lost",
                error_code=_LEASE_LOST_CODE,
                error_sha256=_digest_text(_LEASE_LOST_CODE),
                evidence_payload_sha256=None,
                started_at=_db_utc(item.leased_at),
                completed_at=completed_at,
            )
        )

    @staticmethod
    def _append_success_attempt(
        db: Session,
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
        *,
        backup: bool,
        evidence_payload_sha256: str,
        completed_at: datetime,
    ) -> PrivacyDeletionAttemptRecord:
        identity_hash = item.executor_identity_sha256
        if identity_hash is None or item.leased_at is None:
            raise PlatformSecurityError(
                "platform_privacy_execution_invariant_broken",
                "Privacy success has no active executor identity",
            )
        attempt = PrivacyDeletionAttemptRecord(
            id=_attempt_id(
                "backup" if backup else "surface",
                item.id,
                item.replay_generation,
                item.attempt_count,
            ),
            work_item_id=None if backup else item.id,
            backup_retention_item_id=item.id if backup else None,
            manifest_id=item.manifest_id,
            target_type=item.target_type,
            target_id=item.target_id,
            tenant_id=item.tenant_id,
            surface="backups_and_snapshots"
            if backup
            else cast(PrivacyDeletionWorkItemRecord, item).surface,
            attempt_number=item.attempt_count,
            lease_generation=item.lease_generation,
            replay_generation=item.replay_generation,
            provider_idempotency_sha256=_idempotency_digest(
                "backup" if backup else "surface",
                item.id,
                item.replay_generation,
                item.attempt_count,
            ),
            executor_identity_sha256=identity_hash,
            outcome="succeeded",
            error_code=None,
            error_sha256=None,
            evidence_payload_sha256=evidence_payload_sha256,
            started_at=_db_utc(item.leased_at),
            completed_at=completed_at,
        )
        db.add(attempt)
        return attempt

    @staticmethod
    def _append_failure_attempt(
        db: Session,
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
        *,
        backup: bool,
        outcome: str,
        error_code: str,
        error_sha256: str,
        completed_at: datetime,
    ) -> None:
        identity_hash = item.executor_identity_sha256
        if identity_hash is None or item.leased_at is None:
            raise PlatformSecurityError(
                "platform_privacy_execution_invariant_broken",
                "Privacy failure has no active executor identity",
            )
        db.add(
            PrivacyDeletionAttemptRecord(
                id=_attempt_id(
                    "backup" if backup else "surface",
                    item.id,
                    item.replay_generation,
                    item.attempt_count,
                ),
                work_item_id=None if backup else item.id,
                backup_retention_item_id=item.id if backup else None,
                manifest_id=item.manifest_id,
                target_type=item.target_type,
                target_id=item.target_id,
                tenant_id=item.tenant_id,
                surface="backups_and_snapshots"
                if backup
                else cast(PrivacyDeletionWorkItemRecord, item).surface,
                attempt_number=item.attempt_count,
                lease_generation=item.lease_generation,
                replay_generation=item.replay_generation,
                provider_idempotency_sha256=_idempotency_digest(
                    "backup" if backup else "surface",
                    item.id,
                    item.replay_generation,
                    item.attempt_count,
                ),
                executor_identity_sha256=identity_hash,
                outcome=outcome,
                error_code=error_code,
                error_sha256=error_sha256,
                evidence_payload_sha256=None,
                started_at=_db_utc(item.leased_at),
                completed_at=completed_at,
            )
        )

    def _persist_verifier_receipt(
        self,
        identity: WorkloadIdentity,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        *,
        outcome: PrivacyEvidenceOutcome,
        envelope: PrivacyDsseEnvelope,
        subject_kind: Literal["surface", "backup"],
        backup_catalog: tuple[PrivacyBackupCatalogEntry, ...] = (),
        at: datetime,
    ) -> tuple[UUID, str]:
        """Verify and append evidence through the independent verifier session."""

        executor_hash = self._identity_hash(identity, at)
        with self._verifier_sessions.begin() as db:
            self._bind(db, claim.target_type, claim.target_id, claim.manifest_id)
            item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord | None
            if subject_kind == "surface":
                item = db.execute(
                    sa.select(PrivacyDeletionWorkItemRecord).where(
                        PrivacyDeletionWorkItemRecord.id == claim.item_id,
                        PrivacyDeletionWorkItemRecord.manifest_id == claim.manifest_id,
                        PrivacyDeletionWorkItemRecord.target_type == claim.target_type,
                        PrivacyDeletionWorkItemRecord.target_id == claim.target_id,
                    )
                ).scalar_one_or_none()
            else:
                item = db.execute(
                    sa.select(PrivacyBackupRetentionItemRecord).where(
                        PrivacyBackupRetentionItemRecord.id == claim.item_id,
                        PrivacyBackupRetentionItemRecord.manifest_id == claim.manifest_id,
                        PrivacyBackupRetentionItemRecord.target_type == claim.target_type,
                        PrivacyBackupRetentionItemRecord.target_id == claim.target_id,
                    )
                ).scalar_one_or_none()
            if item is None:
                raise PlatformSecurityError(
                    "platform_privacy_attestation_invalid",
                    "Privacy verifier subject was not found",
                )
            self._require_lease(item, claim, executor_hash, at)
            if subject_kind == "surface":
                work_item = cast(PrivacyDeletionWorkItemRecord, item)
                self._validate_outcome(outcome, disposition=work_item.disposition, at=at)
                self._validate_backup_catalog(db, work_item, outcome, backup_catalog, at)
                surface = work_item.surface
                phase: Literal["primary_erasure", "retention_purge"] = "primary_erasure"
                payload_subject: Literal["surface_attempt", "backup_purge"] = "surface_attempt"
                target_locator_hmac = work_item.resource_scope_hmac
                disposition = work_item.disposition
            else:
                backup_item = cast(PrivacyBackupRetentionItemRecord, item)
                if outcome.tombstone_sha256 != backup_item.tombstone_sha256:
                    raise PlatformSecurityError(
                        "platform_privacy_evidence_invalid",
                        "Backup purge evidence does not bind the catalog tombstone",
                    )
                _require_sha256(outcome.evidence_sha256, "evidence_sha256")
                surface = "backups_and_snapshots"
                phase = "retention_purge"
                payload_subject = "backup_purge"
                target_locator_hmac = backup_item.backup_locator_hmac
                disposition = "tombstone_then_expire"
            expected = self._expected_claims(
                identity=identity,
                manifest_id=item.manifest_id,
                work_item_id=item.id,
                attempt_id=claim.attempt_id,
                subject_kind=payload_subject,
                surface=surface,
                phase=phase,
                target_locator_hmac=target_locator_hmac,
                disposition=disposition,
                outcome=outcome,
            )
            expected.update(
                {
                    "artifact_uri": envelope.artifact_uri,
                    "immutability_receipt_sha256": envelope.immutability_receipt_sha256,
                    "kms_audit_receipt_sha256": envelope.kms_audit_receipt_sha256,
                }
            )
            verified = self._verifier.verify(envelope, expected_claims=expected, now=at)
            existing = db.scalar(
                sa.select(PrivacyEvidenceAttestationRecord).where(
                    PrivacyEvidenceAttestationRecord.execution_attempt_id == claim.attempt_id
                )
            )
            if existing is not None:
                self._require_verifier_receipt(
                    existing,
                    item=item,
                    claim=claim,
                    subject_kind=subject_kind,
                    expected_payload_sha256=verified.payload_sha256,
                )
                return existing.id, existing.payload_sha256
            attestation = self._new_attestation(
                item,
                claim=claim,
                subject_kind=subject_kind,
                verified=verified,
                envelope=envelope,
            )
            db.add(attestation)
            db.flush()
            return attestation.id, attestation.payload_sha256

    def _new_attestation(
        self,
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
        *,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        subject_kind: Literal["surface", "backup"],
        verified: VerifiedPrivacyAttestation,
        envelope: PrivacyDsseEnvelope,
    ) -> PrivacyEvidenceAttestationRecord:
        attestation_id = uuid4()
        surface = (
            "backups_and_snapshots"
            if subject_kind == "backup"
            else cast(PrivacyDeletionWorkItemRecord, item).surface
        )
        attestation = PrivacyEvidenceAttestationRecord(
            id=attestation_id,
            manifest_id=item.manifest_id,
            target_type=item.target_type,
            target_id=item.target_id,
            tenant_id=item.tenant_id,
            subject_kind=subject_kind,
            subject_id=item.id,
            execution_attempt_id=claim.attempt_id,
            attempt_number=claim.attempt_number,
            lease_generation=claim.lease_generation,
            replay_generation=claim.replay_generation,
            surface=surface,
            payload_type=verified.payload_type,
            payload_sha256=verified.payload_sha256,
            envelope_sha256=verified.envelope_sha256,
            envelope=dict(envelope.envelope),
            envelope_uri=verified.artifact_uri,
            immutability_receipt_sha256=verified.immutability_receipt_sha256,
            kms_audit_receipt_sha256=verified.kms_audit_receipt_sha256,
            signature_algorithm=verified.signature_algorithm,
            signer_key_id=verified.key_id,
            workflow_identity=verified.workflow_identity,
            attestor_role=None,
            actor_identity_hmac=None,
            record_sha256=None,
            product_revision=self._policy.product_revision,
            upstream_revision=self._policy.upstream_revision,
            schema_revision=self._policy.schema_revision,
            adapter_contract_version=self._policy.adapter_contract_version,
            verifier_policy_version=self._policy.verifier_policy_version,
            verifier_receipt_sha256="0" * 64,
            observed_at=verified.observed_at,
            signed_at=verified.issued_at,
            verified_at=verified.verified_at,
        )
        attestation.verifier_receipt_sha256 = privacy_verifier_receipt_sha256(
            self._verifier_receipt_facts(attestation)
        )
        return attestation

    def _require_verifier_receipt(
        self,
        attestation: PrivacyEvidenceAttestationRecord,
        *,
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
        claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
        subject_kind: Literal["surface", "backup"],
        expected_payload_sha256: str,
    ) -> None:
        surface = (
            "backups_and_snapshots"
            if subject_kind == "backup"
            else cast(PrivacyDeletionWorkItemRecord, item).surface
        )
        if (
            attestation.manifest_id != item.manifest_id
            or attestation.target_type != item.target_type
            or attestation.target_id != item.target_id
            or attestation.tenant_id != item.tenant_id
            or attestation.subject_kind != subject_kind
            or attestation.subject_id != item.id
            or attestation.execution_attempt_id != claim.attempt_id
            or attestation.attempt_number != claim.attempt_number
            or attestation.lease_generation != claim.lease_generation
            or attestation.replay_generation != claim.replay_generation
            or attestation.surface != surface
            or attestation.payload_sha256 != expected_payload_sha256
            or sha256(canonical_json(attestation.envelope)).hexdigest()
            != attestation.envelope_sha256
            or not hmac.compare_digest(
                attestation.verifier_receipt_sha256,
                privacy_verifier_receipt_sha256(self._verifier_receipt_facts(attestation)),
            )
        ):
            raise PlatformSecurityError(
                "platform_privacy_attestation_invalid",
                "independent Privacy verifier receipt does not match the execution attempt",
            )

    @staticmethod
    def _verifier_receipt_facts(
        value: PrivacyEvidenceAttestationRecord,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "attestation_id": str(value.id),
            "manifest_id": str(value.manifest_id),
            "target_type": value.target_type,
            "target_id": str(value.target_id),
            "subject_kind": value.subject_kind,
            "subject_id": str(value.subject_id),
            "execution_attempt_id": (
                str(value.execution_attempt_id) if value.execution_attempt_id is not None else None
            ),
            "attempt_number": value.attempt_number,
            "lease_generation": value.lease_generation,
            "replay_generation": value.replay_generation,
            "surface": value.surface,
            "payload_sha256": value.payload_sha256,
            "envelope_sha256": value.envelope_sha256,
            "artifact_uri": value.envelope_uri,
            "immutability_receipt_sha256": value.immutability_receipt_sha256,
            "kms_audit_receipt_sha256": value.kms_audit_receipt_sha256,
            "signer_key_id": value.signer_key_id,
            "workflow_identity": value.workflow_identity,
            "observed_at": _db_utc(value.observed_at).isoformat(),
            "signed_at": _db_utc(value.signed_at).isoformat(),
            "verified_at": _db_utc(value.verified_at).isoformat(),
            "verifier_policy_version": value.verifier_policy_version,
        }

    def _expected_claims(
        self,
        *,
        identity: WorkloadIdentity,
        manifest_id: UUID,
        work_item_id: UUID,
        attempt_id: UUID,
        subject_kind: Literal["surface_attempt", "backup_purge"],
        surface: str,
        phase: Literal["primary_erasure", "retention_purge"],
        target_locator_hmac: str,
        disposition: str,
        outcome: PrivacyEvidenceOutcome,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "subject_kind": subject_kind,
            "manifest_id": str(manifest_id),
            "work_item_id": str(work_item_id),
            "attempt_id": str(attempt_id),
            "surface": surface,
            "phase": phase,
            "target_locator_hmac": target_locator_hmac,
            "disposition": disposition,
            "outcome": "succeeded",
            "evidence_sha256": outcome.evidence_sha256,
            "remaining_item_count": outcome.remaining_item_count,
            "runtime_accessible": outcome.runtime_accessible,
            "direct_identifiers_remaining": outcome.direct_identifiers_remaining,
            "retention_until": (
                _utc_input(outcome.retention_until, "retention_until").isoformat()
                if outcome.retention_until is not None
                else None
            ),
            "retention_basis": outcome.retention_basis,
            "tombstone_sha256": outcome.tombstone_sha256,
            "product_revision": self._policy.product_revision,
            "upstream_revision": self._policy.upstream_revision,
            "schema_revision": self._policy.schema_revision,
            "adapter_contract_version": self._policy.adapter_contract_version,
            "policy_version": self._policy.verifier_policy_version,
            "workflow_identity": identity.subject,
        }

    @staticmethod
    def _validate_outcome(
        outcome: PrivacyEvidenceOutcome, *, disposition: str, at: datetime
    ) -> None:
        _require_sha256(outcome.evidence_sha256, "evidence_sha256")
        if outcome.remaining_item_count < 0:
            raise PlatformSecurityError(
                "platform_privacy_evidence_invalid", "remaining_item_count cannot be negative"
            )
        if outcome.runtime_accessible or outcome.direct_identifiers_remaining:
            raise PlatformSecurityError(
                "platform_privacy_evidence_invalid",
                "successful Privacy evidence cannot remain runtime-accessible or identifiable",
            )
        if disposition == "tombstone_then_expire":
            return
        if disposition in _RETAINED_DISPOSITIONS:
            if (
                outcome.retention_until is None
                or _utc_input(outcome.retention_until, "retention_until") <= at
                or not outcome.retention_basis
            ):
                raise PlatformSecurityError(
                    "platform_privacy_evidence_invalid",
                    "retained Privacy evidence requires a future retention deadline and basis",
                )
            if outcome.tombstone_sha256 is not None:
                raise PlatformSecurityError(
                    "platform_privacy_evidence_invalid",
                    "retained surface has an invalid tombstone",
                )
            return
        if (
            outcome.remaining_item_count != 0
            or outcome.retention_until is not None
            or outcome.retention_basis is not None
            or outcome.tombstone_sha256 is not None
        ):
            raise PlatformSecurityError(
                "platform_privacy_evidence_invalid",
                "erasure evidence cannot retain items, deadlines, bases, or tombstones",
            )

    def _validate_backup_catalog(
        self,
        db: Session,
        item: PrivacyDeletionWorkItemRecord,
        outcome: PrivacyEvidenceOutcome,
        entries: tuple[PrivacyBackupCatalogEntry, ...],
        at: datetime,
    ) -> None:
        if item.surface != "backups_and_snapshots":
            if entries:
                raise PlatformSecurityError(
                    "platform_privacy_backup_catalog_invalid",
                    "a non-Backup surface cannot materialize a Backup catalog",
                )
            return
        if item.disposition != "tombstone_then_expire":
            raise PlatformSecurityError(
                "platform_privacy_backup_catalog_invalid",
                "Backup catalog Work Item has an invalid disposition",
            )
        if outcome.remaining_item_count != len(entries):
            raise PlatformSecurityError(
                "platform_privacy_backup_catalog_invalid",
                "signed remaining_item_count does not match the Backup catalog",
            )
        if not entries:
            if (
                outcome.retention_until is not None
                or outcome.retention_basis is not None
                or outcome.tombstone_sha256 is not None
            ):
                raise PlatformSecurityError(
                    "platform_privacy_backup_catalog_invalid",
                    "an empty Backup catalog cannot assert retention or tombstones",
                )
            return
        locators: set[str] = set()
        latest_purge_due: datetime | None = None
        for entry in entries:
            if (
                not entry.provider.strip()
                or len(entry.provider) > 96
                or not entry.backup_data_class.strip()
                or len(entry.backup_data_class) > 32
                or not entry.resource_handle_ref.strip()
                or len(entry.resource_handle_ref) > 512
            ):
                raise PlatformSecurityError(
                    "platform_privacy_backup_catalog_invalid",
                    "Backup provider, data class, or opaque handle is invalid",
                )
            for value, field_name in (
                (entry.backup_locator_hmac, "backup_locator_hmac"),
                (entry.catalog_snapshot_sha256, "catalog_snapshot_sha256"),
                (entry.tombstone_sha256, "tombstone_sha256"),
            ):
                _require_sha256(value, field_name)
            expected_locator = privacy_backup_locator_hmac(
                self._locator_hmac_key,
                entry.provider,
                entry.resource_handle_ref,
            )
            if not hmac.compare_digest(entry.backup_locator_hmac, expected_locator):
                raise PlatformSecurityError(
                    "platform_privacy_backup_catalog_invalid",
                    "Backup locator does not authenticate its provider and opaque handle",
                )
            if entry.runtime_partition_id is not None:
                partition = db.get(RuntimePartitionRecord, entry.runtime_partition_id)
                if partition is None or (
                    item.target_type == "tenant" and partition.tenant_id != item.target_id
                ):
                    raise PlatformSecurityError(
                        "platform_privacy_backup_catalog_invalid",
                        "Backup runtime partition is outside the deletion impact scope",
                    )
                if item.target_type == "global_user" and not db.scalar(
                    sa.select(sa.func.count())
                    .select_from(PrivacyDeletionWorkItemRecord)
                    .where(
                        PrivacyDeletionWorkItemRecord.manifest_id == item.manifest_id,
                        PrivacyDeletionWorkItemRecord.runtime_partition_id
                        == entry.runtime_partition_id,
                    )
                ):
                    raise PlatformSecurityError(
                        "platform_privacy_backup_catalog_invalid",
                        "Backup runtime partition is absent from the approved impact inventory",
                    )
            if entry.backup_locator_hmac in locators:
                raise PlatformSecurityError(
                    "platform_privacy_backup_catalog_invalid",
                    "Backup catalog locators must be unique",
                )
            locators.add(entry.backup_locator_hmac)
            purge_due = _utc_input(entry.purge_due_at, "purge_due_at")
            if purge_due <= at:
                raise PlatformSecurityError(
                    "platform_privacy_backup_catalog_invalid",
                    "new Backup retention must have a future purge deadline",
                )
            if entry.object_lock_until is not None:
                object_lock = _utc_input(entry.object_lock_until, "object_lock_until")
                if object_lock > purge_due:
                    raise PlatformSecurityError(
                        "platform_privacy_backup_catalog_invalid",
                        "Backup object lock cannot outlive the purge deadline",
                    )
            if latest_purge_due is None or purge_due > latest_purge_due:
                latest_purge_due = purge_due
        if (
            outcome.retention_until is None
            or latest_purge_due is None
            or _utc_input(outcome.retention_until, "retention_until") != latest_purge_due
            or not outcome.retention_basis
        ):
            raise PlatformSecurityError(
                "platform_privacy_backup_catalog_invalid",
                "signed retention claims do not match Backup purge deadlines",
            )
        expected_tombstone = privacy_backup_catalog_digest(entries)
        if outcome.tombstone_sha256 is None or not hmac.compare_digest(
            outcome.tombstone_sha256, expected_tombstone
        ):
            raise PlatformSecurityError(
                "platform_privacy_backup_catalog_invalid",
                "signed aggregate tombstone does not bind the Backup catalog",
            )

    @staticmethod
    def _materialize_backup_catalog(
        db: Session,
        item: PrivacyDeletionWorkItemRecord,
        entries: tuple[PrivacyBackupCatalogEntry, ...],
        at: datetime,
    ) -> None:
        if item.surface != "backups_and_snapshots":
            return
        existing = int(
            db.scalar(
                sa.select(sa.func.count())
                .select_from(PrivacyBackupRetentionItemRecord)
                .where(PrivacyBackupRetentionItemRecord.manifest_id == item.manifest_id)
            )
            or 0
        )
        if existing:
            raise PlatformSecurityError(
                "platform_privacy_backup_catalog_conflict",
                "Backup retention catalog was already materialized",
            )
        db.add_all(
            PrivacyBackupRetentionItemRecord(
                id=uuid4(),
                manifest_id=item.manifest_id,
                target_type=item.target_type,
                target_id=item.target_id,
                tenant_id=item.tenant_id,
                runtime_partition_id=entry.runtime_partition_id,
                provider=entry.provider,
                backup_data_class=entry.backup_data_class,
                backup_locator_hmac=entry.backup_locator_hmac,
                resource_handle_ref=entry.resource_handle_ref,
                catalog_snapshot_sha256=entry.catalog_snapshot_sha256,
                tombstone_sha256=entry.tombstone_sha256,
                object_lock_until=(
                    _utc_input(entry.object_lock_until, "object_lock_until")
                    if entry.object_lock_until is not None
                    else None
                ),
                purge_due_at=_utc_input(entry.purge_due_at, "purge_due_at"),
                status="retention_wait",
                attempt_count=0,
                max_attempts=8,
                available_at=at,
                lease_generation=0,
                replay_generation=0,
                version=1,
                created_at=at,
                updated_at=at,
            )
            for entry in entries
        )

    @staticmethod
    def _require_error_code(error_code: str) -> None:
        if error_code not in PRIVACY_EXECUTION_ERROR_CODES:
            raise PlatformSecurityError(
                "platform_privacy_error_code_invalid",
                "Privacy adapter error code is not in the stable allowlist",
            )

    @staticmethod
    def _failure_status(
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
        error_code: str,
    ) -> Literal["retry", "dead_letter"]:
        if error_code in PRIVACY_TERMINAL_ERROR_CODES or item.attempt_count >= item.max_attempts:
            return "dead_letter"
        return "retry"

    def _backoff(
        self, item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord
    ) -> timedelta:
        exponent = min(max(item.attempt_count - 1, 0), 20)
        jitter_seed = sha256(
            f"{item.id}:{item.replay_generation}:{item.attempt_count}".encode("ascii")
        ).digest()
        unit = int.from_bytes(jitter_seed[:8], "big") / ((1 << 64) - 1)
        jitter = 0.75 + (0.5 * unit)
        seconds = min(
            self._policy.max_backoff.total_seconds(),
            self._policy.base_backoff.total_seconds() * (2**exponent) * jitter,
        )
        return timedelta(seconds=seconds)

    def _append_outbox_event(
        self,
        db: Session,
        item: PrivacyDeletionWorkItemRecord | PrivacyBackupRetentionItemRecord,
        *,
        event_type: str,
        status: str,
        content_sha256: str,
        occurred_at: datetime,
        error_code: str | None = None,
        available_at: datetime | None = None,
    ) -> None:
        if event_type not in PRIVACY_EXECUTION_EVENT_TYPES:
            raise PlatformSecurityError(
                "platform_privacy_execution_invariant_broken",
                "Privacy execution event is not in the stable allowlist",
            )
        _require_sha256(content_sha256, "content_sha256")
        kind = "backup" if isinstance(item, PrivacyBackupRetentionItemRecord) else "surface"
        attempt_id = _attempt_id(
            kind,
            item.id,
            item.replay_generation,
            item.attempt_count,
        )
        payload: dict[str, object] = {
            "schema_version": 1,
            "manifest_id": str(item.manifest_id),
            "target_type": item.target_type,
            "target_locator_hmac": privacy_target_locator_hmac(
                self._locator_hmac_key,
                cast(PrivacyTargetType, item.target_type),
                item.target_id,
            ),
            "item_id": str(item.id),
            "attempt_id": str(attempt_id),
            "status": status,
            "content_sha256": content_sha256,
            "surface": (
                "backups_and_snapshots"
                if kind == "backup"
                else cast(PrivacyDeletionWorkItemRecord, item).surface
            ),
            "replay_generation": item.replay_generation,
            "attempt_number": item.attempt_count,
            "error_code": error_code,
            "available_at": available_at.isoformat() if available_at is not None else None,
        }
        db.add(
            ControlPlaneOutboxEvent(
                id=uuid4(),
                tenant_id=item.tenant_id,
                aggregate_type="privacy_manifest",
                aggregate_key=str(item.manifest_id),
                event_type=event_type,
                payload=payload,
                idempotency_key=scoped_idempotency_key(
                    "privacy-execution",
                    str(item.manifest_id),
                    (f"{event_type}:{item.id}:{item.replay_generation}:{item.attempt_count}"),
                ),
                request_hash=sha256(canonical_json(payload)).hexdigest(),
                attempt_count=0,
                available_at=occurred_at,
                created_at=occurred_at,
            )
        )

    def _project_work_success(
        self,
        db: Session,
        item: PrivacyDeletionWorkItemRecord,
        outcome: PrivacyEvidenceOutcome,
        payload_sha256: str,
        at: datetime,
        *,
        backup_catalog_count: int | None,
    ) -> None:
        manifest = db.execute(
            sa.select(PrivacyDeletionManifestRecord)
            .where(PrivacyDeletionManifestRecord.id == item.manifest_id)
            .with_for_update()
        ).scalar_one()
        projected_status = (
            "pending_retention"
            if item.disposition == "tombstone_then_expire"
            else "retained"
            if item.disposition in _RETAINED_DISPOSITIONS
            else "erased"
        )
        outcomes = dict(manifest.surface_outcomes)
        outcomes[item.surface] = {
            "content_hash": payload_sha256,
            "disposition": item.disposition,
            "direct_identifiers_remaining": outcome.direct_identifiers_remaining,
            "evidence_sha256": outcome.evidence_sha256,
            "remaining_item_count": outcome.remaining_item_count,
            "retention_basis": outcome.retention_basis,
            "retention_until": (
                _utc_input(outcome.retention_until, "retention_until").isoformat()
                if outcome.retention_until is not None
                else None
            ),
            "runtime_accessible": outcome.runtime_accessible,
            "status": projected_status,
            "tombstone_sha256": outcome.tombstone_sha256,
        }
        manifest.surface_outcomes = outcomes
        if backup_catalog_count is not None:
            if backup_catalog_count == 0:
                manifest.retention_status = "not_applicable"
                manifest.retention_completed_at = at
                self._append_outbox_event(
                    db,
                    item,
                    event_type="privacy.execution.retention_completed",
                    status="not_applicable",
                    content_sha256=payload_sha256,
                    occurred_at=at,
                )
            else:
                manifest.retention_status = "pending"
                manifest.retention_completed_at = None
        db.flush()
        remaining = int(
            db.scalar(
                sa.select(sa.func.count())
                .select_from(PrivacyDeletionWorkItemRecord)
                .where(
                    PrivacyDeletionWorkItemRecord.manifest_id == item.manifest_id,
                    PrivacyDeletionWorkItemRecord.status != "succeeded",
                )
            )
            or 0
        )
        if remaining == 0 and manifest.status == "executing":
            manifest.status = "ready_to_finalize"
        manifest.version += 1
        manifest.updated_at = at

    def _project_backup_completion(
        self, db: Session, item: PrivacyBackupRetentionItemRecord, at: datetime
    ) -> None:
        remaining = int(
            db.scalar(
                sa.select(sa.func.count())
                .select_from(PrivacyBackupRetentionItemRecord)
                .where(
                    PrivacyBackupRetentionItemRecord.manifest_id == item.manifest_id,
                    PrivacyBackupRetentionItemRecord.status != "purged",
                )
            )
            or 0
        )
        if remaining:
            return
        manifest = db.execute(
            sa.select(PrivacyDeletionManifestRecord)
            .where(PrivacyDeletionManifestRecord.id == item.manifest_id)
            .with_for_update()
        ).scalar_one()
        manifest.retention_status = "completed"
        manifest.retention_completed_at = at
        manifest.version += 1
        manifest.updated_at = at
        self._append_outbox_event(
            db,
            item,
            event_type="privacy.execution.retention_completed",
            status="completed",
            content_sha256=cast(str, item.purge_evidence_sha256),
            occurred_at=at,
        )

    def _mark_retention_attention(
        self, db: Session, item: PrivacyBackupRetentionItemRecord, at: datetime
    ) -> None:
        manifest = db.execute(
            sa.select(PrivacyDeletionManifestRecord)
            .where(PrivacyDeletionManifestRecord.id == item.manifest_id)
            .with_for_update()
        ).scalar_one()
        if manifest.retention_status != "completed":
            manifest.retention_status = "attention_required"
            manifest.retention_completed_at = None
            manifest.version += 1
            manifest.updated_at = at
            self._append_outbox_event(
                db,
                item,
                event_type="privacy.execution.retention_attention_required",
                status="attention_required",
                content_sha256=cast(str, item.last_error_sha256),
                occurred_at=at,
                error_code=item.last_error_code,
            )
