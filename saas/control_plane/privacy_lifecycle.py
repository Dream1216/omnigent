"""PC5 governed privacy, Legal Hold, and deletion execution authority."""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.api_credential_models import ApiCredentialRecord, ServiceAccountRecord
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    MembershipInvitation,
    PasswordCredential,
    ProjectMembershipRecord,
    ResourceGrantRecord,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.enterprise_identity_models import (
    EnterpriseScimDirectoryRecord,
    EnterpriseScimEventRecord,
    EnterpriseScimGroupRecord,
    EnterpriseScimUserRecord,
)
from saas.control_plane.enterprise_models import EnterpriseGroupMembershipRecord
from saas.control_plane.execution_models import TERMINAL_RUN_STATUSES, RunRecord
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.platform_governed_models import PlatformSupportGrantRecord
from saas.control_plane.platform_models import PlatformUserProjectionRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.privacy_models import (
    PrivacyDeletionManifestRecord,
    PrivacyIdentityTombstoneRecord,
    PrivacyLegalHoldRecord,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context

_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_SURFACE_POLICY: Mapping[str, tuple[str, int]] = {
    "control_plane_database": ("erase", 0),
    "runtime_database": ("erase", 0),
    "object_and_artifact_store": ("erase", 0),
    "vector_and_search_indexes": ("erase", 0),
    "caches": ("erase", 0),
    "queues_and_dlq": ("erase", 0),
    "provider_and_connector_state": ("erase", 0),
    "enterprise_identity_provisioning_state": ("erase", 0),
    "enterprise_identity_event_receipts": ("anonymize_and_retain", 2555),
    "runner_worktree_and_recovery_material": ("erase", 0),
    "webhook_state": ("erase", 0),
    "secret_and_kms_references": ("cryptographic_erase", 0),
    "logs_and_traces": ("redact_and_retain", 30),
    "immutable_audit_and_ledger": ("anonymize_and_retain", 2555),
    "backups_and_snapshots": ("tombstone_then_expire", 35),
}


class DeletionEvidenceVerifier(Protocol):
    """Verifier boundary; production keys stay outside the application process."""

    @property
    def key_id(self) -> str: ...

    def verify(self, content_hash: str, signature: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class DeletionEvidenceKey:
    """Local HMAC implementation for deterministic tests and development only."""

    key_id: str
    secret: bytes

    def __post_init__(self) -> None:
        if not self.key_id.strip() or len(self.secret) < 32:
            raise ValueError("deletion evidence key id and at least 256 bits are required")

    def sign(self, content_hash: str) -> str:
        return hmac.new(self.secret, content_hash.encode(), sha256).hexdigest()

    def verify(self, content_hash: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(content_hash), signature)


@dataclass(frozen=True, slots=True)
class DeletionSurfaceEvidence:
    manifest_id: UUID
    surface: str
    disposition: str
    status: str
    evidence_sha256: str
    remaining_item_count: int
    runtime_accessible: bool
    direct_identifiers_remaining: bool
    observed_at: datetime
    retention_until: datetime | None = None
    retention_basis: str | None = None
    tombstone_sha256: str | None = None
    key_id: str = ""
    signature: str = ""

    def content_hash(self) -> str:
        return _digest(self.payload())

    def payload(self) -> dict[str, object]:
        return {
            "manifest_id": str(self.manifest_id),
            "surface": self.surface,
            "disposition": self.disposition,
            "status": self.status,
            "evidence_sha256": self.evidence_sha256,
            "remaining_item_count": self.remaining_item_count,
            "runtime_accessible": self.runtime_accessible,
            "direct_identifiers_remaining": self.direct_identifiers_remaining,
            "observed_at": _as_utc(self.observed_at).isoformat(),
            "retention_until": (
                _as_utc(self.retention_until).isoformat()
                if self.retention_until is not None
                else None
            ),
            "retention_basis": self.retention_basis,
            "tombstone_sha256": self.tombstone_sha256,
            "key_id": self.key_id,
        }


@dataclass(frozen=True, slots=True)
class PrivacyDeletionPreview:
    target_type: Literal["global_user", "tenant"]
    target_id: UUID
    target_status: str
    target_version: int
    blockers: tuple[str, ...]
    impact_counts: dict[str, int]
    preview_hash: str


@dataclass(frozen=True, slots=True)
class PrivacyLegalHoldView:
    hold_id: UUID
    target_type: str
    target_id: UUID
    status: str
    scope: tuple[str, ...]
    authority_ref: str
    version: int
    created_at: datetime
    review_due_at: datetime
    released_at: datetime | None


@dataclass(frozen=True, slots=True)
class PrivacyDeletionManifestView:
    manifest_id: UUID
    target_type: str
    target_id: UUID
    status: str
    version: int
    blockers: tuple[str, ...]
    surface_outcomes: dict[str, object]
    manifest_hash: str | None
    completion_approval_ref: str | None
    started_at: datetime
    completed_at: datetime | None
    replayed: bool = False


def oidc_identity_locator_hash(issuer: str, subject: str) -> str:
    """Hash an OIDC subject without retaining either direct identifier."""

    return _digest({"kind": "oidc_subject", "issuer": issuer, "subject": subject})


def scim_user_locator_hash(directory_id: UUID, external_id: str) -> str:
    """Hash one Directory-local SCIM identifier for replay prevention."""

    return _digest(
        {"kind": "scim_user", "directory_id": str(directory_id), "external_id": external_id}
    )


def sign_surface_evidence(
    evidence: DeletionSurfaceEvidence,
    key: DeletionEvidenceKey,
) -> DeletionSurfaceEvidence:
    """Return an evidence envelope bound to every canonical outcome field."""

    unsigned = DeletionSurfaceEvidence(
        manifest_id=evidence.manifest_id,
        surface=evidence.surface,
        disposition=evidence.disposition,
        status=evidence.status,
        evidence_sha256=evidence.evidence_sha256,
        remaining_item_count=evidence.remaining_item_count,
        runtime_accessible=evidence.runtime_accessible,
        direct_identifiers_remaining=evidence.direct_identifiers_remaining,
        observed_at=evidence.observed_at,
        retention_until=evidence.retention_until,
        retention_basis=evidence.retention_basis,
        tombstone_sha256=evidence.tombstone_sha256,
        key_id=key.key_id,
    )
    return replace(unsigned, signature=key.sign(unsigned.content_hash()))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


def _required(value: str, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise PlatformSecurityError("platform_privacy_invalid", f"{field} is invalid")
    return cleaned


def _require_sha256(value: str, field: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) != 64 or any(item not in "0123456789abcdef" for item in cleaned):
        raise PlatformSecurityError("platform_privacy_invalid", f"{field} is invalid")
    return cleaned


def _require_fresh(actor: ValidatedPlatformPrincipal, changed_at: datetime) -> None:
    authenticated_at = _as_utc(actor.authenticated_at)
    if authenticated_at > changed_at or changed_at - authenticated_at > _FRESH_AUTH_WINDOW:
        raise PlatformSecurityError(
            "platform_fresh_auth_required", "fresh Staff authentication is required"
        )


def _rowcount(result: object) -> int:
    return cast(CursorResult[tuple[object]], result).rowcount


def _contains_identifier(value: object, identifiers: frozenset[str]) -> bool:
    if isinstance(value, str):
        return value in identifiers or any(
            len(identifier) >= 8 and identifier in value for identifier in identifiers
        )
    if isinstance(value, list):
        return any(_contains_identifier(item, identifiers) for item in value)
    if isinstance(value, dict):
        return any(
            _contains_identifier(key, identifiers) or _contains_identifier(item, identifiers)
            for key, item in value.items()
        )
    return False


class PrivacyLifecycleService:
    """Execute deletion only through exact previews, signed surfaces, and Legal Hold checks."""

    def __init__(
        self,
        governance_factory: sessionmaker[Session],
        *,
        evidence_verifier: DeletionEvidenceVerifier,
    ) -> None:
        self._governance = governance_factory
        self._evidence_verifier = evidence_verifier

    def place_legal_hold(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        scope: tuple[str, ...],
        authority_ref: str,
        reason: str,
        review_due_at: datetime,
        now: datetime | None = None,
    ) -> PrivacyLegalHoldView:
        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        review_due = _as_utc(review_due_at)
        if review_due <= changed_at or review_due > changed_at + timedelta(days=366):
            raise PlatformSecurityError(
                "platform_privacy_invalid",
                "review_due_at must be within the next 366 days",
            )
        if (
            not scope
            or len(scope) > 32
            or any(not item.strip() or len(item) > 64 for item in scope)
        ):
            raise PlatformSecurityError("platform_privacy_invalid", "scope is invalid")
        authority = _required(authority_ref, "authority_ref", 256)
        cleaned_reason = _required(reason, "reason", 1024)
        with self._governance.begin() as db:
            self._bind(db, actor, target_type=target_type, target_id=target_id)
            self._authorize(db, actor, changed_at)
            self._require_target(db, target_type, target_id)
            existing = db.execute(
                sa.select(PrivacyLegalHoldRecord).where(
                    PrivacyLegalHoldRecord.target_type == target_type,
                    PrivacyLegalHoldRecord.target_id == target_id,
                    PrivacyLegalHoldRecord.status == "active",
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise PlatformSecurityError(
                    "platform_privacy_hold_conflict", "an active Legal Hold already exists"
                )
            hold = PrivacyLegalHoldRecord(
                id=uuid4(),
                target_type=target_type,
                target_id=target_id,
                tenant_id=target_id if target_type == "tenant" else None,
                status="active",
                scope=sorted({item.strip() for item in scope}),
                authority_ref=authority,
                reason=cleaned_reason,
                review_due_at=review_due,
                placed_by_principal_id=actor.principal_id,
                version=1,
                created_at=changed_at,
                updated_at=changed_at,
            )
            db.add(hold)
            self._outbox(
                db,
                tenant_id=hold.tenant_id,
                target_type=target_type,
                target_id=target_id,
                event_type="privacy.legal_hold.placed",
                idempotency_key=f"hold:{hold.id}",
                request_hash=_digest(
                    {
                        "target_type": target_type,
                        "target_id": str(target_id),
                        "scope": hold.scope,
                        "authority_ref": authority,
                        "review_due_at": review_due.isoformat(),
                    }
                ),
                payload={
                    "hold_id": str(hold.id),
                    "target_type": target_type,
                    "review_due_at": review_due.isoformat(),
                },
                occurred_at=changed_at,
            )
            return self._hold_view(hold)

    def release_legal_hold(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        hold_id: UUID,
        expected_version: int,
        reason: str,
        now: datetime | None = None,
    ) -> PrivacyLegalHoldView:
        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        cleaned_reason = _required(reason, "reason", 1024)
        with self._governance.begin() as db:
            self._bind(db, actor, target_type=target_type, target_id=target_id)
            self._authorize(db, actor, changed_at)
            hold = db.execute(
                sa.select(PrivacyLegalHoldRecord)
                .where(
                    PrivacyLegalHoldRecord.id == hold_id,
                    PrivacyLegalHoldRecord.target_type == target_type,
                    PrivacyLegalHoldRecord.target_id == target_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if hold is None:
                raise PlatformSecurityError(
                    "platform_privacy_hold_not_found", "Legal Hold was not found"
                )
            if hold.status != "active" or hold.version != expected_version:
                raise PlatformSecurityError(
                    "platform_privacy_hold_conflict", "Legal Hold changed concurrently"
                )
            hold.status = "released"
            hold.version += 1
            hold.released_by_principal_id = actor.principal_id
            hold.release_reason = cleaned_reason
            hold.released_at = changed_at
            hold.updated_at = changed_at
            self._outbox(
                db,
                tenant_id=hold.tenant_id,
                target_type=target_type,
                target_id=target_id,
                event_type="privacy.legal_hold.released",
                idempotency_key=f"hold-release:{hold.id}:{hold.version}",
                request_hash=_digest(
                    {"hold_id": str(hold.id), "version": hold.version, "reason": cleaned_reason}
                ),
                payload={"hold_id": str(hold.id), "target_type": target_type},
                occurred_at=changed_at,
            )
            return self._hold_view(hold)

    def preview_deletion(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        now: datetime | None = None,
    ) -> PrivacyDeletionPreview:
        checked_at = now or _now()
        with self._governance.begin() as db:
            self._bind(db, actor, target_type=target_type, target_id=target_id)
            self._authorize(db, actor, checked_at)
            return self._preview(db, target_type, target_id)

    def start_deletion(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        expected_target_version: int,
        preview_hash: str,
        approval_ref: str,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> PrivacyDeletionManifestView:
        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        supplied_preview = _require_sha256(preview_hash, "preview_hash")
        approval = _required(approval_ref, "approval_ref", 256)
        cleaned_reason = _required(reason, "reason", 1024)
        key = _required(idempotency_key, "idempotency_key", 128)
        request_hash = _digest(
            {
                "target_type": target_type,
                "target_id": str(target_id),
                "expected_target_version": expected_target_version,
                "preview_hash": supplied_preview,
                "approval_ref": approval,
                "reason": cleaned_reason,
            }
        )
        with self._governance.begin() as db:
            self._bind(db, actor, target_type=target_type, target_id=target_id)
            self._serialize(db, actor.principal_id, key)
            self._authorize(db, actor, changed_at)
            replay = db.execute(
                sa.select(PrivacyDeletionManifestRecord).where(
                    PrivacyDeletionManifestRecord.requested_by_principal_id == actor.principal_id,
                    PrivacyDeletionManifestRecord.idempotency_key == key,
                )
            ).scalar_one_or_none()
            if replay is not None:
                if replay.request_hash != request_hash:
                    raise PlatformSecurityError(
                        "platform_idempotency_conflict", "idempotency key was reused"
                    )
                return self._manifest_view(replay, replayed=True)
            preview = self._preview(db, target_type, target_id, lock=True)
            if preview.blockers:
                raise PlatformSecurityError(
                    "platform_privacy_deletion_blocked", "; ".join(preview.blockers)
                )
            if (
                preview.target_version != expected_target_version
                or preview.preview_hash != supplied_preview
            ):
                raise PlatformSecurityError(
                    "platform_privacy_deletion_conflict", "deletion preview is stale"
                )
            manifest = PrivacyDeletionManifestRecord(
                id=uuid4(),
                target_type=target_type,
                target_id=target_id,
                tenant_id=target_id if target_type == "tenant" else None,
                requested_by_principal_id=actor.principal_id,
                idempotency_key=key,
                request_hash=request_hash,
                approval_ref=approval,
                reason=cleaned_reason,
                expected_target_version=expected_target_version,
                preview_hash=supplied_preview,
                status="executing",
                blockers=[],
                surface_outcomes=self._pending_surfaces(),
                version=1,
                started_at=changed_at,
                updated_at=changed_at,
            )
            db.add(manifest)
            db.flush()
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest.id,
            )
            if target_type == "global_user":
                self._anonymize_user(db, manifest, changed_at)
            else:
                self._anonymize_tenant(db, manifest, changed_at)
            self._outbox(
                db,
                tenant_id=manifest.tenant_id,
                target_type=target_type,
                target_id=target_id,
                event_type="privacy.deletion.started",
                idempotency_key=key,
                request_hash=request_hash,
                payload={
                    "manifest_id": str(manifest.id),
                    "target_type": target_type,
                    "surface_count": len(_SURFACE_POLICY),
                },
                occurred_at=changed_at,
            )
            return self._manifest_view(manifest)

    def record_surface_evidence(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        evidence: DeletionSurfaceEvidence,
        expected_manifest_version: int,
        now: datetime | None = None,
    ) -> PrivacyDeletionManifestView:
        checked_at = now or _now()
        self._validate_surface_evidence(evidence, checked_at)
        with self._governance.begin() as db:
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                manifest_id=evidence.manifest_id,
            )
            self._authorize(db, actor, checked_at)
            manifest = db.execute(
                sa.select(PrivacyDeletionManifestRecord)
                .where(
                    PrivacyDeletionManifestRecord.id == evidence.manifest_id,
                    PrivacyDeletionManifestRecord.target_type == target_type,
                    PrivacyDeletionManifestRecord.target_id == target_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if manifest is None:
                raise PlatformSecurityError(
                    "platform_privacy_manifest_not_found", "deletion Manifest was not found"
                )
            if manifest.status == "completed":
                current = cast(dict[str, object], manifest.surface_outcomes.get(evidence.surface))
                if current.get("content_hash") == evidence.content_hash():
                    return self._manifest_view(manifest, replayed=True)
                raise PlatformSecurityError(
                    "platform_privacy_manifest_conflict", "completed Manifest is immutable"
                )
            if manifest.version != expected_manifest_version:
                raise PlatformSecurityError(
                    "platform_privacy_manifest_conflict", "deletion Manifest changed concurrently"
                )
            outcomes = dict(manifest.surface_outcomes)
            current = cast(dict[str, object], outcomes[evidence.surface])
            if current.get("content_hash") == evidence.content_hash():
                return self._manifest_view(manifest, replayed=True)
            if current.get("status") != "pending":
                raise PlatformSecurityError(
                    "platform_privacy_surface_conflict", "surface evidence is already recorded"
                )
            outcomes[evidence.surface] = {
                **evidence.payload(),
                "content_hash": evidence.content_hash(),
                "signature": evidence.signature,
            }
            manifest.surface_outcomes = outcomes
            manifest.version += 1
            manifest.updated_at = checked_at
            if all(
                isinstance(value, dict) and value.get("status") != "pending"
                for value in outcomes.values()
            ):
                manifest.status = "ready_to_finalize"
            return self._manifest_view(manifest)

    def finalize_deletion(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        expected_manifest_version: int,
        approval_ref: str,
        now: datetime | None = None,
    ) -> PrivacyDeletionManifestView:
        changed_at = now or _now()
        _require_fresh(actor, changed_at)
        approval = _required(approval_ref, "approval_ref", 256)
        with self._governance.begin() as db:
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest_id,
            )
            self._authorize(db, actor, changed_at)
            manifest = db.execute(
                sa.select(PrivacyDeletionManifestRecord)
                .where(
                    PrivacyDeletionManifestRecord.id == manifest_id,
                    PrivacyDeletionManifestRecord.target_type == target_type,
                    PrivacyDeletionManifestRecord.target_id == target_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if manifest is None:
                raise PlatformSecurityError(
                    "platform_privacy_manifest_not_found", "deletion Manifest was not found"
                )
            if manifest.status == "completed":
                if manifest.completion_approval_ref != approval:
                    raise PlatformSecurityError(
                        "platform_privacy_manifest_conflict",
                        "completed Manifest approval does not match",
                    )
                return self._manifest_view(manifest, replayed=True)
            if (
                manifest.status != "ready_to_finalize"
                or manifest.version != expected_manifest_version
            ):
                raise PlatformSecurityError(
                    "platform_privacy_manifest_conflict", "deletion Manifest is not finalizable"
                )
            active_hold = db.execute(
                sa.select(PrivacyLegalHoldRecord.id).where(
                    PrivacyLegalHoldRecord.target_type == target_type,
                    PrivacyLegalHoldRecord.target_id == target_id,
                    PrivacyLegalHoldRecord.status == "active",
                )
            ).scalar_one_or_none()
            if active_hold is not None:
                raise PlatformSecurityError(
                    "platform_privacy_deletion_blocked", "an active Legal Hold blocks completion"
                )
            if target_type == "global_user":
                user = db.get(GlobalUser, target_id)
                if user is None or user.status != "suspended":
                    raise PlatformSecurityError(
                        "platform_privacy_deletion_conflict", "Global User state changed"
                    )
                user.status = "deleted"
                user.security_version += 1
                user.updated_at = changed_at
            else:
                tenant = db.get(Tenant, target_id)
                if tenant is None or tenant.status != "pending_deletion":
                    raise PlatformSecurityError(
                        "platform_privacy_deletion_conflict", "Tenant state changed"
                    )
                tenant.status = "deleted"
                tenant.lifecycle_version += 1
                tenant.updated_at = changed_at
            manifest_payload = {
                "manifest_id": str(manifest.id),
                "target_type": target_type,
                "target_id_hash": _digest(str(target_id)),
                "request_hash": manifest.request_hash,
                "preview_hash": manifest.preview_hash,
                "surface_outcomes": manifest.surface_outcomes,
                "approval_ref_hash": _digest(approval),
                "completed_at": changed_at.isoformat(),
            }
            manifest.manifest_hash = _digest(manifest_payload)
            manifest.completion_approval_ref = approval
            manifest.status = "completed"
            manifest.completed_at = changed_at
            manifest.updated_at = changed_at
            manifest.version += 1
            self._outbox(
                db,
                tenant_id=manifest.tenant_id,
                target_type=target_type,
                target_id=target_id,
                event_type="privacy.deletion.completed",
                idempotency_key=f"deletion-complete:{manifest.id}",
                request_hash=manifest.manifest_hash,
                payload={
                    "manifest_id": str(manifest.id),
                    "target_type": target_type,
                    "manifest_hash": manifest.manifest_hash,
                },
                occurred_at=changed_at,
            )
            return self._manifest_view(manifest)

    def get_manifest(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        now: datetime | None = None,
    ) -> PrivacyDeletionManifestView:
        checked_at = now or _now()
        with self._governance.begin() as db:
            self._bind(
                db,
                actor,
                target_type=target_type,
                target_id=target_id,
                manifest_id=manifest_id,
            )
            self._authorize(db, actor, checked_at)
            manifest = db.get(PrivacyDeletionManifestRecord, manifest_id)
            if (
                manifest is None
                or manifest.target_type != target_type
                or manifest.target_id != target_id
            ):
                raise PlatformSecurityError(
                    "platform_privacy_manifest_not_found", "deletion Manifest was not found"
                )
            return self._manifest_view(manifest)

    def _preview(
        self,
        db: Session,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        *,
        lock: bool = False,
    ) -> PrivacyDeletionPreview:
        active_holds = int(
            db.scalar(
                sa.select(sa.func.count())
                .select_from(PrivacyLegalHoldRecord)
                .where(
                    PrivacyLegalHoldRecord.target_type == target_type,
                    PrivacyLegalHoldRecord.target_id == target_id,
                    PrivacyLegalHoldRecord.status == "active",
                )
            )
            or 0
        )
        blockers = ["active_legal_hold"] if active_holds else []
        if target_type == "global_user":
            statement = sa.select(GlobalUser).where(GlobalUser.id == target_id)
            user = db.execute(
                statement.with_for_update() if lock else statement
            ).scalar_one_or_none()
            if user is None:
                raise PlatformSecurityError("platform_user_not_found", "Global User was not found")
            owners = int(
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(TenantMembership)
                    .where(
                        TenantMembership.user_id == target_id,
                        TenantMembership.status == "active",
                        TenantMembership.role == "owner",
                    )
                )
                or 0
            )
            stewarded = int(
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(ServiceAccountRecord)
                    .where(
                        ServiceAccountRecord.steward_user_id == target_id,
                        ServiceAccountRecord.status == "active",
                    )
                )
                or 0
            )
            if user.status == "deleted":
                blockers.append("target_already_deleted")
            if owners:
                blockers.append("owner_transfer_required")
            if stewarded:
                blockers.append("service_account_steward_transfer_required")
            counts = {
                "active_legal_holds": active_holds,
                "owner_memberships": owners,
                "active_stewarded_service_accounts": stewarded,
                "memberships": int(
                    db.scalar(
                        sa.select(sa.func.count())
                        .select_from(TenantMembership)
                        .where(TenantMembership.user_id == target_id)
                    )
                    or 0
                ),
                "identity_connections": int(
                    db.scalar(
                        sa.select(sa.func.count())
                        .select_from(IdentityConnection)
                        .where(IdentityConnection.user_id == target_id)
                    )
                    or 0
                ),
                "scim_subjects": int(
                    db.scalar(
                        sa.select(sa.func.count())
                        .select_from(EnterpriseScimUserRecord)
                        .where(EnterpriseScimUserRecord.user_id == target_id)
                    )
                    or 0
                ),
            }
            status = user.status
            version = user.security_version
        else:
            statement = sa.select(Tenant).where(Tenant.id == target_id)
            tenant = db.execute(
                statement.with_for_update() if lock else statement
            ).scalar_one_or_none()
            if tenant is None:
                raise PlatformSecurityError("platform_tenant_not_found", "Tenant was not found")
            nonterminal_runs = int(
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(RunRecord)
                    .where(
                        RunRecord.tenant_id == target_id,
                        RunRecord.status.not_in(TERMINAL_RUN_STATUSES),
                    )
                )
                or 0
            )
            active_support = int(
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(PlatformSupportGrantRecord)
                    .where(
                        PlatformSupportGrantRecord.tenant_id == target_id,
                        PlatformSupportGrantRecord.status.in_(
                            ("pending_customer_approval", "pending_staff_approval", "active")
                        ),
                    )
                )
                or 0
            )
            if tenant.status != "suspended":
                blockers.append("tenant_must_be_suspended")
            if nonterminal_runs:
                blockers.append("nonterminal_runs_present")
            if active_support:
                blockers.append("active_support_access_present")
            counts = {
                "active_legal_holds": active_holds,
                "nonterminal_runs": nonterminal_runs,
                "active_support_grants": active_support,
                "memberships": int(
                    db.scalar(
                        sa.select(sa.func.count())
                        .select_from(TenantMembership)
                        .where(TenantMembership.tenant_id == target_id)
                    )
                    or 0
                ),
                "scim_directories": int(
                    db.scalar(
                        sa.select(sa.func.count())
                        .select_from(EnterpriseScimDirectoryRecord)
                        .where(EnterpriseScimDirectoryRecord.tenant_id == target_id)
                    )
                    or 0
                ),
            }
            status = tenant.status
            version = tenant.lifecycle_version
        facts: dict[str, object] = {
            "target_type": target_type,
            "target_id": str(target_id),
            "target_status": status,
            "target_version": version,
            "blockers": sorted(blockers),
            "impact_counts": counts,
            "surface_policy": dict(_SURFACE_POLICY),
        }
        return PrivacyDeletionPreview(
            target_type=target_type,
            target_id=target_id,
            target_status=status,
            target_version=version,
            blockers=tuple(sorted(blockers)),
            impact_counts=counts,
            preview_hash=_digest(facts),
        )

    def _anonymize_user(
        self,
        db: Session,
        manifest: PrivacyDeletionManifestRecord,
        changed_at: datetime,
    ) -> None:
        user = db.get(GlobalUser, manifest.target_id)
        if user is None or user.status == "deleted":
            raise PlatformSecurityError(
                "platform_privacy_deletion_conflict", "Global User state changed"
            )
        primary_email = user.primary_email_normalized
        connections = list(
            db.scalars(sa.select(IdentityConnection).where(IdentityConnection.user_id == user.id))
        )
        for connection in connections:
            locator = oidc_identity_locator_hash(connection.issuer, connection.subject)
            self._add_tombstone(
                db,
                manifest=manifest,
                target_user_id=user.id,
                tenant_id=None,
                locator_kind="oidc_subject",
                locator_hash=locator,
                created_at=changed_at,
            )
            connection.provider = "deleted"
            connection.issuer = f"urn:omnigent:deleted:{locator}"
            connection.subject = locator
            connection.email_normalized = None
            connection.email_verified = False
            connection.status = "revoked"
            connection.updated_at = changed_at

        scim_users = list(
            db.scalars(
                sa.select(EnterpriseScimUserRecord).where(
                    EnterpriseScimUserRecord.user_id == user.id
                )
            )
        )
        sensitive = {str(user.id)}
        for scim_user in scim_users:
            sensitive.update(
                filter(
                    None,
                    (
                        str(scim_user.id),
                        scim_user.external_id,
                        scim_user.user_name_normalized,
                        scim_user.display_name,
                    ),
                )
            )
        self._redact_scim_events(
            db,
            manifest=manifest,
            identifiers=frozenset(sensitive),
            directory_ids=frozenset(value.directory_id for value in scim_users),
            changed_at=changed_at,
        )
        for scim_user in scim_users:
            locator = scim_user_locator_hash(scim_user.directory_id, scim_user.external_id)
            self._add_tombstone(
                db,
                manifest=manifest,
                target_user_id=user.id,
                tenant_id=scim_user.tenant_id,
                locator_kind="scim_user",
                locator_hash=locator,
                created_at=changed_at,
            )
            # The transformed SCIM row no longer carries user_id. Persist the
            # exact locator Tombstone first so PostgreSQL WITH CHECK can prove
            # this is the same governed subject, not an unrelated tenant row.
            db.flush()
            scim_user.external_id = f"deleted:{locator}"
            scim_user.user_name_normalized = f"deleted-{locator}@invalid"
            scim_user.display_name = None
            scim_user.user_id = None
            scim_user.active = False
            scim_user.version += 1
            scim_user.source_version += 1
            scim_user.source_state_hash = _digest(
                {"deleted": True, "manifest_id": str(manifest.id), "locator": locator}
            )
            scim_user.deprovisioned_at = changed_at
            scim_user.updated_at = changed_at

        db.execute(sa.delete(PasswordCredential).where(PasswordCredential.user_id == user.id))
        invitation_predicates = [MembershipInvitation.accepted_by == user.id]
        if primary_email:
            invitation_predicates.append(MembershipInvitation.email_normalized == primary_email)
        invitations = list(
            db.scalars(sa.select(MembershipInvitation).where(sa.or_(*invitation_predicates)))
        )
        for invitation in invitations:
            locator = _digest(
                {
                    "manifest_id": str(manifest.id),
                    "invitation_id": str(invitation.id),
                    "email": invitation.email_normalized,
                }
            )
            invitation.email_normalized = f"deleted-{locator}@invalid"
            invitation.accepted_by = None
            invitation.deletion_manifest_id = manifest.id
            if invitation.status == "pending":
                invitation.status = "revoked"
            invitation.version += 1
            invitation.updated_at = changed_at
        db.execute(
            sa.update(AuthSessionRecord)
            .where(AuthSessionRecord.user_id == user.id, AuthSessionRecord.revoked_at.is_(None))
            .values(revoked_at=changed_at)
        )
        db.execute(
            sa.update(TenantMembership)
            .where(TenantMembership.user_id == user.id)
            .values(status="removed", version=TenantMembership.version + 1)
        )
        db.execute(
            sa.update(SpaceMembership)
            .where(SpaceMembership.user_id == user.id)
            .values(status="removed", version=SpaceMembership.version + 1)
        )
        db.execute(
            sa.update(ProjectMembershipRecord)
            .where(
                ProjectMembershipRecord.subject_type == "user",
                ProjectMembershipRecord.subject_id == user.id,
                ProjectMembershipRecord.status == "active",
            )
            .values(status="revoked", version=ProjectMembershipRecord.version + 1)
        )
        db.execute(
            sa.update(ResourceGrantRecord)
            .where(
                ResourceGrantRecord.subject_type == "user",
                ResourceGrantRecord.subject_id == user.id,
                ResourceGrantRecord.status == "active",
            )
            .values(status="revoked", version=ResourceGrantRecord.version + 1)
        )
        db.execute(
            sa.update(EnterpriseGroupMembershipRecord)
            .where(
                EnterpriseGroupMembershipRecord.user_id == user.id,
                EnterpriseGroupMembershipRecord.status == "active",
            )
            .values(
                status="removed",
                version=EnterpriseGroupMembershipRecord.version + 1,
                updated_at=changed_at,
            )
        )
        user.status = "suspended"
        user.display_name = None
        user.primary_email_normalized = None
        user.security_version += 1
        user.updated_at = changed_at
        projection = db.get(PlatformUserProjectionRecord, user.id)
        if projection is not None:
            projection.status = "suspended"
            projection.display_name = None
            projection.email_masked = None
            projection.security_version = user.security_version
            projection.source_version += 1
            projection.updated_at = changed_at

    def _anonymize_tenant(
        self,
        db: Session,
        manifest: PrivacyDeletionManifestRecord,
        changed_at: datetime,
    ) -> None:
        tenant = db.get(Tenant, manifest.target_id)
        if tenant is None or tenant.status != "suspended":
            raise PlatformSecurityError(
                "platform_privacy_deletion_conflict", "Tenant state changed"
            )
        user_ids = tuple(
            db.scalars(
                sa.select(TenantMembership.user_id).where(TenantMembership.tenant_id == tenant.id)
            )
        )
        if user_ids:
            db.execute(
                sa.update(AuthSessionRecord)
                .where(
                    AuthSessionRecord.user_id.in_(user_ids),
                    AuthSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=changed_at)
            )
        account_ids = tuple(
            db.scalars(
                sa.select(ServiceAccountRecord.id).where(
                    ServiceAccountRecord.tenant_id == tenant.id
                )
            )
        )
        if account_ids:
            db.execute(
                sa.update(ServiceAccountRecord)
                .where(ServiceAccountRecord.id.in_(account_ids))
                .values(
                    status="deleted",
                    security_version=ServiceAccountRecord.security_version + 1,
                    name="deleted",
                    description=None,
                    updated_at=changed_at,
                )
            )
            db.execute(
                sa.update(ApiCredentialRecord)
                .where(
                    ApiCredentialRecord.service_account_id.in_(account_ids),
                    ApiCredentialRecord.status == "active",
                )
                .values(status="revoked", revoked_at=changed_at)
            )
        scim_users = list(
            db.scalars(
                sa.select(EnterpriseScimUserRecord).where(
                    EnterpriseScimUserRecord.tenant_id == tenant.id
                )
            )
        )
        identifiers = {
            item
            for value in scim_users
            for item in (
                str(value.id),
                value.external_id,
                value.user_name_normalized,
                value.display_name,
            )
            if item
        }
        directories = list(
            db.scalars(
                sa.select(EnterpriseScimDirectoryRecord).where(
                    EnterpriseScimDirectoryRecord.tenant_id == tenant.id
                )
            )
        )
        self._redact_scim_events(
            db,
            manifest=manifest,
            identifiers=frozenset(identifiers),
            directory_ids=frozenset(value.id for value in directories),
            changed_at=changed_at,
            redact_all=True,
        )
        for scim_user in scim_users:
            locator = scim_user_locator_hash(scim_user.directory_id, scim_user.external_id)
            self._add_tombstone(
                db,
                manifest=manifest,
                target_user_id=scim_user.user_id,
                tenant_id=tenant.id,
                locator_kind="scim_user",
                locator_hash=locator,
                created_at=changed_at,
            )
            db.flush()
            scim_user.external_id = f"deleted:{locator}"
            scim_user.user_name_normalized = f"deleted-{locator}@invalid"
            scim_user.display_name = None
            scim_user.user_id = None
            scim_user.active = False
            scim_user.version += 1
            scim_user.source_version += 1
            scim_user.source_state_hash = _digest(
                {"deleted": True, "manifest_id": str(manifest.id), "locator": locator}
            )
            scim_user.deprovisioned_at = changed_at
            scim_user.updated_at = changed_at
        for directory in directories:
            directory.display_name = "deleted"
            directory.token_hash = _digest(
                {"deleted": True, "manifest_id": str(manifest.id), "directory": str(directory.id)}
            )
            directory.token_prefix = "deleted"
            directory.successor_token_hash = None
            directory.successor_token_prefix = None
            directory.rotation_activates_at = None
            directory.rotation_grace_expires_at = None
            directory.status = "disabled"
            directory.version += 1
            directory.disabled_at = changed_at
            directory.updated_at = changed_at
        for group in db.scalars(
            sa.select(EnterpriseScimGroupRecord).where(
                EnterpriseScimGroupRecord.tenant_id == tenant.id
            )
        ):
            group.external_id = f"deleted:{_digest(str(group.id))[:32]}"
            group.display_name = "deleted"
            group.active = False
            group.version += 1
            group.source_version += 1
            group.source_state_hash = _digest(
                {"deleted": True, "manifest_id": str(manifest.id), "group": str(group.id)}
            )
            group.updated_at = changed_at
        db.execute(
            sa.update(SpaceMembership)
            .where(SpaceMembership.tenant_id == tenant.id)
            .values(status="removed", version=SpaceMembership.version + 1)
        )
        db.execute(
            sa.update(TenantMembership)
            .where(TenantMembership.tenant_id == tenant.id)
            .values(status="removed", version=TenantMembership.version + 1)
        )
        for invitation in db.scalars(
            sa.select(MembershipInvitation).where(MembershipInvitation.tenant_id == tenant.id)
        ):
            locator = _digest(
                {
                    "manifest_id": str(manifest.id),
                    "invitation_id": str(invitation.id),
                    "email": invitation.email_normalized,
                }
            )
            invitation.email_normalized = f"deleted-{locator}@invalid"
            invitation.accepted_by = None
            invitation.deletion_manifest_id = manifest.id
            if invitation.status == "pending":
                invitation.status = "revoked"
            invitation.version += 1
            invitation.updated_at = changed_at
        tombstone = _digest({"tenant_id": str(tenant.id), "manifest_id": str(manifest.id)})
        tenant.slug = f"deleted-{tombstone[:24]}"
        tenant.name = "Deleted Tenant"
        tenant.status = "pending_deletion"
        tenant.lifecycle_version += 1
        tenant.updated_at = changed_at

    def _redact_scim_events(
        self,
        db: Session,
        *,
        manifest: PrivacyDeletionManifestRecord,
        identifiers: frozenset[str],
        directory_ids: frozenset[UUID],
        changed_at: datetime,
        redact_all: bool = False,
    ) -> None:
        if not directory_ids:
            return
        events = db.scalars(
            sa.select(EnterpriseScimEventRecord).where(
                EnterpriseScimEventRecord.directory_id.in_(directory_ids),
                EnterpriseScimEventRecord.redacted_at.is_(None),
            )
        )
        for event in events:
            if not redact_all and not _contains_identifier(event.result, identifiers):
                continue
            event.original_result_hash = _digest(event.result)
            event.result = {
                "redacted": True,
                "manifest_id": str(manifest.id),
                "resource_type": event.resource_type,
                "resource_id_hash": _digest(str(event.resource_id)),
                "disposition": event.disposition,
            }
            event.redacted_at = changed_at
            event.redaction_manifest_id = manifest.id

    @staticmethod
    def _add_tombstone(
        db: Session,
        *,
        manifest: PrivacyDeletionManifestRecord,
        target_user_id: UUID | None,
        tenant_id: UUID | None,
        locator_kind: str,
        locator_hash: str,
        created_at: datetime,
    ) -> None:
        existing = db.execute(
            sa.select(PrivacyIdentityTombstoneRecord.id).where(
                PrivacyIdentityTombstoneRecord.locator_hash == locator_hash
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                PrivacyIdentityTombstoneRecord(
                    id=uuid4(),
                    manifest_id=manifest.id,
                    target_user_id=target_user_id,
                    tenant_id=tenant_id,
                    locator_kind=locator_kind,
                    locator_hash=locator_hash,
                    created_at=created_at,
                )
            )

    def _validate_surface_evidence(
        self,
        evidence: DeletionSurfaceEvidence,
        checked_at: datetime,
    ) -> None:
        policy = _SURFACE_POLICY.get(evidence.surface)
        if policy is None or evidence.disposition != policy[0]:
            raise PlatformSecurityError(
                "platform_privacy_surface_invalid", "surface disposition does not match policy"
            )
        _require_sha256(evidence.evidence_sha256, "evidence_sha256")
        if evidence.observed_at.tzinfo is None:
            raise PlatformSecurityError(
                "platform_time_invalid", "surface evidence time must include a timezone"
            )
        observed = _as_utc(evidence.observed_at)
        if observed > checked_at or checked_at - observed > timedelta(days=7):
            raise PlatformSecurityError(
                "platform_privacy_surface_invalid", "surface evidence is outside its time window"
            )
        if evidence.key_id != self._evidence_verifier.key_id or not self._evidence_verifier.verify(
            evidence.content_hash(), evidence.signature
        ):
            raise PlatformSecurityError(
                "platform_privacy_surface_invalid", "surface evidence signature is invalid"
            )
        if evidence.remaining_item_count < 0 or evidence.runtime_accessible:
            raise PlatformSecurityError(
                "platform_privacy_surface_blocked",
                "surface remains accessible or has invalid count",
            )
        disposition, retention_days = policy
        if disposition in {"erase", "cryptographic_erase"}:
            valid = (
                evidence.status == "erased"
                and evidence.remaining_item_count == 0
                and not evidence.direct_identifiers_remaining
                and evidence.retention_until is None
                and evidence.retention_basis is None
                and evidence.tombstone_sha256 is None
            )
        elif disposition in {"redact_and_retain", "anonymize_and_retain"}:
            if evidence.retention_until is not None and evidence.retention_until.tzinfo is None:
                raise PlatformSecurityError(
                    "platform_time_invalid", "surface retention time must include a timezone"
                )
            retention = (
                _as_utc(evidence.retention_until) if evidence.retention_until is not None else None
            )
            valid = (
                evidence.status == "retained"
                and not evidence.direct_identifiers_remaining
                and evidence.remaining_item_count >= 0
                and retention is not None
                and observed <= retention <= observed + timedelta(days=retention_days)
                and bool(evidence.retention_basis)
                and evidence.tombstone_sha256 is None
            )
        else:
            tombstone = evidence.tombstone_sha256 or ""
            _require_sha256(tombstone, "tombstone_sha256")
            if evidence.retention_until is not None and evidence.retention_until.tzinfo is None:
                raise PlatformSecurityError(
                    "platform_time_invalid", "surface retention time must include a timezone"
                )
            retention = (
                _as_utc(evidence.retention_until) if evidence.retention_until is not None else None
            )
            valid = (
                evidence.status == "pending_retention"
                and not evidence.direct_identifiers_remaining
                and retention is not None
                and observed <= retention <= observed + timedelta(days=retention_days)
                and bool(evidence.retention_basis)
            ) or (
                evidence.status == "erased"
                and evidence.remaining_item_count == 0
                and not evidence.direct_identifiers_remaining
                and retention is None
                and evidence.retention_basis is None
            )
        if not valid:
            raise PlatformSecurityError(
                "platform_privacy_surface_blocked", "surface outcome does not satisfy policy"
            )

    @staticmethod
    def _pending_surfaces() -> dict[str, object]:
        return {
            name: {
                "disposition": disposition,
                "max_retention_days": retention,
                "status": "pending",
            }
            for name, (disposition, retention) in _SURFACE_POLICY.items()
        }

    @staticmethod
    def _require_target(
        db: Session,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
    ) -> None:
        model = GlobalUser if target_type == "global_user" else Tenant
        if db.get(model, target_id) is None:
            raise PlatformSecurityError(
                f"platform_{'user' if target_type == 'global_user' else 'tenant'}_not_found",
                "privacy target was not found",
            )

    @staticmethod
    def _bind(
        db: Session,
        actor: ValidatedPlatformPrincipal,
        *,
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID | None = None,
    ) -> None:
        apply_platform_rls_context(
            db,
            PlatformRlsContext(
                principal_id=actor.principal_id,
                target_tenant_id=target_id if target_type == "tenant" else None,
                target_user_id=target_id if target_type == "global_user" else None,
                privacy_manifest_id=manifest_id,
            ),
        )

    @staticmethod
    def _authorize(
        db: Session,
        actor: ValidatedPlatformPrincipal,
        now: datetime,
    ) -> None:
        PlatformAuthorizationService.require_current(
            db, actor, "platform.data_request.manage", now=now
        )

    @staticmethod
    def _serialize(db: Session, principal_id: UUID, key: str) -> None:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"privacy-deletion:{principal_id}:{key}"},
            )

    @staticmethod
    def _hold_view(value: PrivacyLegalHoldRecord) -> PrivacyLegalHoldView:
        return PrivacyLegalHoldView(
            hold_id=value.id,
            target_type=value.target_type,
            target_id=value.target_id,
            status=value.status,
            scope=tuple(value.scope),
            authority_ref=value.authority_ref,
            version=value.version,
            created_at=_as_utc(value.created_at),
            review_due_at=_as_utc(value.review_due_at),
            released_at=_as_utc(value.released_at) if value.released_at else None,
        )

    @staticmethod
    def _manifest_view(
        value: PrivacyDeletionManifestRecord,
        *,
        replayed: bool = False,
    ) -> PrivacyDeletionManifestView:
        return PrivacyDeletionManifestView(
            manifest_id=value.id,
            target_type=value.target_type,
            target_id=value.target_id,
            status=value.status,
            version=value.version,
            blockers=tuple(value.blockers),
            surface_outcomes=dict(value.surface_outcomes),
            manifest_hash=value.manifest_hash,
            completion_approval_ref=value.completion_approval_ref,
            started_at=_as_utc(value.started_at),
            completed_at=_as_utc(value.completed_at) if value.completed_at else None,
            replayed=replayed,
        )

    @staticmethod
    def _outbox(
        db: Session,
        *,
        tenant_id: UUID | None,
        target_type: str,
        target_id: UUID,
        event_type: str,
        idempotency_key: str,
        request_hash: str,
        payload: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                id=uuid4(),
                tenant_id=tenant_id,
                aggregate_type=f"privacy_{target_type}",
                aggregate_key=str(target_id),
                event_type=event_type,
                payload=payload,
                idempotency_key=scoped_idempotency_key(
                    "privacy", f"{target_type}:{target_id}", idempotency_key
                ),
                request_hash=request_hash,
                attempt_count=0,
                available_at=occurred_at,
                created_at=occurred_at,
            )
        )
