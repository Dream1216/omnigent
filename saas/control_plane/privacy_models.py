"""PC5 privacy, Legal Hold, and deletion workflow records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

PRIVACY_TARGET_TYPES = ("global_user", "tenant")
LEGAL_HOLD_STATUSES = ("active", "released")
DELETION_MANIFEST_STATUSES = ("executing", "ready_to_finalize", "completed")
IDENTITY_TOMBSTONE_KINDS = ("oidc_subject", "scim_user")
PRIVACY_APPROVAL_PHASES = (
    "deletion_start",
    "deletion_finalize",
    "surface_replay",
    "backup_purge_replay",
)
PRIVACY_APPROVAL_PROVENANCE = ("legacy_unverified", "governed_operation")
PRIVACY_RETENTION_STATUSES = (
    "not_applicable",
    "pending",
    "attention_required",
    "completed",
    "legacy_reconciliation_required",
)
PRIVACY_WORK_ITEM_STATUSES = ("pending", "leased", "retry", "succeeded", "dead_letter")
PRIVACY_ATTEMPT_OUTCOMES = ("succeeded", "retry", "dead_letter", "lease_lost")
PRIVACY_EVIDENCE_SUBJECT_KINDS = (
    "surface",
    "backup",
    "manifest",
    "production_admission",
)
PRIVACY_MANIFEST_ATTESTOR_ROLES = ("privacy", "security", "data_owner")
PRIVACY_BACKUP_RETENTION_STATUSES = (
    "retention_wait",
    "held",
    "leased",
    "retry",
    "dead_letter",
    "purged",
    "legacy_reconciliation_required",
)


class PrivacyLegalHoldRecord(SaasBase):
    """Versioned Legal Hold that always wins over deletion completion."""

    __tablename__ = "saas_privacy_legal_holds"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    scope: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    authority_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    reason: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    review_due_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    placed_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    released_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    release_reason: Mapped[str | None] = mapped_column(sa.String(1024))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )
    released_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.CheckConstraint(
            f"target_type IN ({_values(PRIVACY_TARGET_TYPES)})",
            name="ck_privacy_hold_target_type",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(LEGAL_HOLD_STATUSES)})",
            name="ck_privacy_hold_status",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_hold_target_scope",
        ),
        sa.CheckConstraint("length(authority_ref) > 0", name="ck_privacy_hold_authority"),
        sa.CheckConstraint("length(reason) > 0", name="ck_privacy_hold_reason"),
        sa.CheckConstraint("review_due_at > created_at", name="ck_privacy_hold_review_deadline"),
        sa.CheckConstraint("version > 0", name="ck_privacy_hold_version"),
        sa.CheckConstraint(
            "(status = 'active' AND released_by_principal_id IS NULL "
            "AND release_reason IS NULL AND released_at IS NULL) OR "
            "(status = 'released' AND released_by_principal_id IS NOT NULL "
            "AND length(release_reason) > 0 AND released_at IS NOT NULL)",
            name="ck_privacy_hold_release_state",
        ),
        sa.Index(
            "uq_privacy_active_hold_target",
            "target_type",
            "target_id",
            unique=True,
            sqlite_where=sa.text("status = 'active'"),
            postgresql_where=sa.text("status = 'active'"),
        ),
        sa.Index(
            "ix_privacy_hold_target",
            "target_type",
            "target_id",
            "status",
            "id",
        ),
    )


class PrivacyDeletionManifestRecord(SaasBase):
    """CAS-bound deletion state and privacy-safe per-surface evidence digests."""

    __tablename__ = "saas_privacy_deletion_manifests"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    requested_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    start_operation_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_admin_operations.id", ondelete="RESTRICT")
    )
    completion_operation_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_admin_operations.id", ondelete="RESTRICT")
    )
    approval_provenance: Mapped[str] = mapped_column(
        sa.String(32),
        nullable=False,
        default="legacy_unverified",
        server_default="legacy_unverified",
    )
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    approval_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    completion_approval_ref: Mapped[str | None] = mapped_column(sa.String(256))
    reason: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    expected_target_version: Mapped[int] = mapped_column(nullable=False)
    preview_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="executing")
    blockers: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    surface_outcomes: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    manifest_hash: Mapped[str | None] = mapped_column(sa.String(64))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    retention_status: Mapped[str] = mapped_column(
        sa.String(48),
        nullable=False,
        default="legacy_reconciliation_required",
        server_default="legacy_reconciliation_required",
    )
    retention_completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"target_type IN ({_values(PRIVACY_TARGET_TYPES)})",
            name="ck_privacy_manifest_target_type",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(DELETION_MANIFEST_STATUSES)})",
            name="ck_privacy_manifest_status",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_manifest_target_scope",
        ),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_privacy_manifest_idempotency"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_privacy_manifest_request_hash"),
        sa.CheckConstraint("length(approval_ref) > 0", name="ck_privacy_manifest_approval"),
        sa.CheckConstraint(
            "completion_approval_ref IS NULL OR length(completion_approval_ref) > 0",
            name="ck_privacy_manifest_completion_approval",
        ),
        sa.CheckConstraint("length(reason) > 0", name="ck_privacy_manifest_reason"),
        sa.CheckConstraint(
            "expected_target_version > 0", name="ck_privacy_manifest_target_version"
        ),
        sa.CheckConstraint("length(preview_hash) = 64", name="ck_privacy_manifest_preview_hash"),
        sa.CheckConstraint("version > 0", name="ck_privacy_manifest_version"),
        sa.CheckConstraint(
            f"approval_provenance IN ({_values(PRIVACY_APPROVAL_PROVENANCE)})",
            name="ck_privacy_manifest_approval_provenance",
        ),
        sa.CheckConstraint(
            "(approval_provenance = 'legacy_unverified' AND start_operation_id IS NULL "
            "AND completion_operation_id IS NULL) OR "
            "(approval_provenance = 'governed_operation' AND start_operation_id IS NOT NULL)",
            name="ck_privacy_manifest_start_operation",
        ),
        sa.CheckConstraint(
            "completion_operation_id IS NULL OR approval_provenance = 'governed_operation'",
            name="ck_privacy_manifest_completion_operation",
        ),
        sa.CheckConstraint(
            "approval_provenance <> 'governed_operation' OR status <> 'completed' "
            "OR completion_operation_id IS NOT NULL",
            name="ck_privacy_manifest_governed_completion",
        ),
        sa.CheckConstraint(
            f"retention_status IN ({_values(PRIVACY_RETENTION_STATUSES)})",
            name="ck_privacy_manifest_retention_status",
        ),
        sa.CheckConstraint(
            "(retention_status IN ('completed', 'not_applicable') "
            "AND retention_completed_at IS NOT NULL) OR "
            "(retention_status NOT IN ('completed', 'not_applicable') "
            "AND retention_completed_at IS NULL)",
            name="ck_privacy_manifest_retention_completion",
        ),
        sa.CheckConstraint(
            "(status <> 'completed' AND completed_at IS NULL AND manifest_hash IS NULL "
            "AND completion_approval_ref IS NULL) OR "
            "(status = 'completed' AND completed_at IS NOT NULL AND length(manifest_hash) = 64 "
            "AND length(completion_approval_ref) > 0)",
            name="ck_privacy_manifest_completion",
        ),
        sa.UniqueConstraint(
            "requested_by_principal_id",
            "idempotency_key",
            name="uq_privacy_manifest_requester_idempotency",
        ),
        sa.UniqueConstraint("start_operation_id", name="uq_privacy_manifest_start_operation"),
        sa.UniqueConstraint(
            "completion_operation_id", name="uq_privacy_manifest_completion_operation"
        ),
        sa.Index(
            "uq_privacy_open_manifest_target",
            "target_type",
            "target_id",
            unique=True,
            sqlite_where=sa.text("status <> 'completed'"),
            postgresql_where=sa.text("status <> 'completed'"),
        ),
        sa.Index(
            "ix_privacy_manifest_target",
            "target_type",
            "target_id",
            "status",
            "id",
        ),
    )


class PrivacyIdentityTombstoneRecord(SaasBase):
    """Opaque locator that prevents OIDC or SCIM replay from recreating a deleted subject."""

    __tablename__ = "saas_privacy_identity_tombstones"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    manifest_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_manifests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_user_id: Mapped[UUID | None] = mapped_column()
    tenant_id: Mapped[UUID | None] = mapped_column()
    locator_kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    locator_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"locator_kind IN ({_values(IDENTITY_TOMBSTONE_KINDS)})",
            name="ck_privacy_tombstone_kind",
        ),
        sa.CheckConstraint("length(locator_hash) = 64", name="ck_privacy_tombstone_hash"),
        sa.Index(
            "ix_privacy_tombstone_target",
            "target_user_id",
            "tenant_id",
            "locator_kind",
        ),
    )


class PrivacyApprovalBindingRecord(SaasBase):
    """Immutable, hash-bound Privacy approval facts for one Platform Operation."""

    __tablename__ = "saas_privacy_approval_bindings"

    operation_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_admin_operations.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    phase: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    manifest_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_manifests.id", ondelete="RESTRICT")
    )
    subject_id: Mapped[UUID | None] = mapped_column()
    expected_target_version: Mapped[int] = mapped_column(nullable=False)
    expected_manifest_version: Mapped[int | None] = mapped_column()
    impact_snapshot: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    authentication_assertion_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"phase IN ({_values(PRIVACY_APPROVAL_PHASES)})",
            name="ck_privacy_approval_binding_phase",
        ),
        sa.CheckConstraint(
            f"target_type IN ({_values(PRIVACY_TARGET_TYPES)})",
            name="ck_privacy_approval_binding_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_approval_binding_target_scope",
        ),
        sa.CheckConstraint(
            "expected_target_version > 0 AND "
            "(expected_manifest_version IS NULL OR expected_manifest_version > 0)",
            name="ck_privacy_approval_binding_versions",
        ),
        sa.CheckConstraint(
            "length(snapshot_hash) = 64 AND length(authentication_assertion_sha256) = 64",
            name="ck_privacy_approval_binding_hashes",
        ),
        sa.CheckConstraint("expires_at > created_at", name="ck_privacy_approval_binding_expiry"),
        sa.CheckConstraint(
            "(phase = 'deletion_start' AND manifest_id IS NULL AND subject_id IS NULL "
            "AND expected_manifest_version IS NULL) OR "
            "(phase = 'deletion_finalize' AND manifest_id IS NOT NULL AND subject_id IS NULL "
            "AND expected_manifest_version IS NOT NULL) OR "
            "(phase IN ('surface_replay', 'backup_purge_replay') AND manifest_id IS NOT NULL "
            "AND subject_id IS NOT NULL AND expected_manifest_version IS NOT NULL)",
            name="ck_privacy_approval_binding_subject",
        ),
        sa.Index(
            "ix_privacy_approval_binding_target",
            "target_type",
            "target_id",
            "phase",
            "expires_at",
        ),
    )


class PrivacyDeletionWorkItemRecord(SaasBase):
    """Lease-fenced deletion work for one surface and physical resource scope."""

    __tablename__ = "saas_privacy_deletion_work_items"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    manifest_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_manifests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    runtime_partition_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_runtime_partitions.id", ondelete="RESTRICT")
    )
    surface: Mapped[str] = mapped_column(sa.String(96), nullable=False)
    disposition: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    resource_scope_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    adapter_type: Mapped[str] = mapped_column(sa.String(96), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(nullable=False, default=8)
    available_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    leased_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    lease_token_hash: Mapped[str | None] = mapped_column(sa.String(64))
    executor_identity_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    lease_generation: Mapped[int] = mapped_column(nullable=False, default=0)
    replay_generation: Mapped[int] = mapped_column(nullable=False, default=0)
    last_error_code: Mapped[str | None] = mapped_column(sa.String(128))
    last_error_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    outcome_content_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    evidence_attestation_id: Mapped[UUID | None] = mapped_column()
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"target_type IN ({_values(PRIVACY_TARGET_TYPES)})",
            name="ck_privacy_work_item_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_work_item_target_scope",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PRIVACY_WORK_ITEM_STATUSES)})",
            name="ck_privacy_work_item_status",
        ),
        sa.CheckConstraint(
            "length(surface) > 0 AND length(disposition) > 0 AND "
            "length(resource_scope_hmac) = 64 AND length(adapter_type) > 0",
            name="ck_privacy_work_item_identity",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 32 "
            "AND attempt_count <= max_attempts",
            name="ck_privacy_work_item_attempt_budget",
        ),
        sa.CheckConstraint(
            "lease_generation >= 0 AND replay_generation >= 0 AND version > 0",
            name="ck_privacy_work_item_generations",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND leased_at IS NOT NULL AND lease_expires_at > leased_at "
            "AND length(lease_token_hash) = 64 AND length(executor_identity_sha256) = 64) OR "
            "(status <> 'leased' AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hash IS NULL AND executor_identity_sha256 IS NULL)",
            name="ck_privacy_work_item_lease",
        ),
        sa.CheckConstraint(
            "(last_error_code IS NULL AND last_error_sha256 IS NULL) OR "
            "(length(last_error_code) > 0 AND length(last_error_sha256) = 64)",
            name="ck_privacy_work_item_error",
        ),
        sa.CheckConstraint(
            "(status = 'succeeded' AND length(outcome_content_sha256) = 64 "
            "AND evidence_attestation_id IS NOT NULL) OR "
            "(status <> 'succeeded' AND outcome_content_sha256 IS NULL "
            "AND evidence_attestation_id IS NULL)",
            name="ck_privacy_work_item_outcome",
        ),
        sa.UniqueConstraint(
            "manifest_id",
            "surface",
            "resource_scope_hmac",
            name="uq_privacy_work_item_manifest_surface_scope",
        ),
        sa.Index(
            "ix_privacy_work_item_dispatch",
            "status",
            "available_at",
            "lease_expires_at",
            "id",
        ),
        sa.Index("ix_privacy_work_item_target", "target_type", "target_id", "manifest_id", "id"),
    )


class PrivacyDeletionAttemptRecord(SaasBase):
    """Append-only result of one fenced deletion work-item attempt."""

    __tablename__ = "saas_privacy_deletion_attempts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    work_item_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_work_items.id", ondelete="RESTRICT"),
    )
    backup_retention_item_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_privacy_backup_retention_items.id", ondelete="RESTRICT"),
    )
    manifest_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_manifests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    surface: Mapped[str] = mapped_column(sa.String(96), nullable=False)
    attempt_number: Mapped[int] = mapped_column(nullable=False)
    lease_generation: Mapped[int] = mapped_column(nullable=False)
    replay_generation: Mapped[int] = mapped_column(nullable=False)
    provider_idempotency_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    executor_identity_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    error_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    evidence_payload_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint(
            f"target_type IN ({_values(PRIVACY_TARGET_TYPES)})",
            name="ck_privacy_attempt_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_attempt_target_scope",
        ),
        sa.CheckConstraint(
            f"outcome IN ({_values(PRIVACY_ATTEMPT_OUTCOMES)})",
            name="ck_privacy_attempt_outcome",
        ),
        sa.CheckConstraint(
            "attempt_number > 0 AND lease_generation > 0 AND replay_generation >= 0",
            name="ck_privacy_attempt_generations",
        ),
        sa.CheckConstraint(
            "length(surface) > 0 AND length(provider_idempotency_sha256) = 64 "
            "AND length(executor_identity_sha256) = 64",
            name="ck_privacy_attempt_identity",
        ),
        sa.CheckConstraint(
            "(work_item_id IS NOT NULL AND backup_retention_item_id IS NULL) OR "
            "(work_item_id IS NULL AND backup_retention_item_id IS NOT NULL "
            "AND surface = 'backups_and_snapshots')",
            name="ck_privacy_attempt_subject_xor",
        ),
        sa.CheckConstraint("completed_at >= started_at", name="ck_privacy_attempt_time"),
        sa.CheckConstraint(
            "(outcome = 'succeeded' AND error_code IS NULL AND error_sha256 IS NULL "
            "AND length(evidence_payload_sha256) = 64) OR "
            "(outcome <> 'succeeded' AND length(error_code) > 0 "
            "AND length(error_sha256) = 64 AND evidence_payload_sha256 IS NULL)",
            name="ck_privacy_attempt_result",
        ),
        sa.Index(
            "uq_privacy_attempt_work_item_generation_number",
            "work_item_id",
            "replay_generation",
            "attempt_number",
            unique=True,
            sqlite_where=sa.text("work_item_id IS NOT NULL"),
            postgresql_where=sa.text("work_item_id IS NOT NULL"),
        ),
        sa.Index(
            "uq_privacy_attempt_backup_generation_number",
            "backup_retention_item_id",
            "replay_generation",
            "attempt_number",
            unique=True,
            sqlite_where=sa.text("backup_retention_item_id IS NOT NULL"),
            postgresql_where=sa.text("backup_retention_item_id IS NOT NULL"),
        ),
        sa.Index(
            "ix_privacy_attempt_manifest",
            "manifest_id",
            "surface",
            "replay_generation",
            "attempt_number",
        ),
    )


class PrivacyEvidenceAttestationRecord(SaasBase):
    """Append-only DSSE verification receipt for a Privacy or admission subject."""

    __tablename__ = "saas_privacy_evidence_attestations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    manifest_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_manifests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    subject_kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    subject_id: Mapped[UUID] = mapped_column(nullable=False)
    execution_attempt_id: Mapped[UUID | None] = mapped_column()
    attempt_number: Mapped[int | None] = mapped_column()
    lease_generation: Mapped[int | None] = mapped_column()
    replay_generation: Mapped[int | None] = mapped_column()
    surface: Mapped[str | None] = mapped_column(sa.String(96))
    payload_type: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    envelope_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    envelope: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    envelope_uri: Mapped[str] = mapped_column(sa.String(2048), nullable=False)
    immutability_receipt_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    kms_audit_receipt_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    signer_key_id: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    workflow_identity: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    attestor_role: Mapped[str | None] = mapped_column(sa.String(32))
    actor_identity_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    record_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    product_revision: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    upstream_revision: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    schema_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    adapter_contract_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    verifier_policy_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    verifier_receipt_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"target_type IN ({_values(PRIVACY_TARGET_TYPES)})",
            name="ck_privacy_attestation_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_attestation_target_scope",
        ),
        sa.CheckConstraint(
            f"subject_kind IN ({_values(PRIVACY_EVIDENCE_SUBJECT_KINDS)})",
            name="ck_privacy_attestation_subject_kind",
        ),
        sa.CheckConstraint(
            "((subject_kind IN ('surface', 'backup')) AND length(surface) > 0) OR "
            "(subject_kind IN ('manifest', 'production_admission') AND surface IS NULL)",
            name="ck_privacy_attestation_surface",
        ),
        sa.CheckConstraint(
            "length(payload_type) > 0 AND length(payload_sha256) = 64 "
            "AND length(envelope_sha256) = 64 AND length(envelope_uri) > 0 "
            "AND length(immutability_receipt_sha256) = 64 "
            "AND length(kms_audit_receipt_sha256) = 64 "
            "AND length(verifier_receipt_sha256) = 64",
            name="ck_privacy_attestation_envelope",
        ),
        sa.CheckConstraint(
            "(subject_kind IN ('surface', 'backup') "
            "AND execution_attempt_id IS NOT NULL AND attempt_number > 0 "
            "AND lease_generation > 0 AND replay_generation >= 0) OR "
            "(subject_kind IN ('manifest', 'production_admission') "
            "AND execution_attempt_id IS NULL AND attempt_number IS NULL "
            "AND lease_generation IS NULL AND replay_generation IS NULL)",
            name="ck_privacy_attestation_execution",
        ),
        sa.CheckConstraint(
            "signature_algorithm = 'ed25519' AND length(signer_key_id) > 0 "
            "AND length(workflow_identity) > 0",
            name="ck_privacy_attestation_signer",
        ),
        sa.CheckConstraint(
            "length(product_revision) = 40 AND length(upstream_revision) = 40 "
            "AND length(schema_revision) > 0 AND length(adapter_contract_version) > 0 "
            "AND length(verifier_policy_version) > 0",
            name="ck_privacy_attestation_revisions",
        ),
        sa.CheckConstraint(
            "(subject_kind = 'manifest' "
            f"AND attestor_role IN ({_values(PRIVACY_MANIFEST_ATTESTOR_ROLES)}) "
            "AND length(actor_identity_hmac) = 64 AND length(record_sha256) = 64) OR "
            "(subject_kind <> 'manifest' AND attestor_role IS NULL "
            "AND actor_identity_hmac IS NULL AND record_sha256 IS NULL)",
            name="ck_privacy_attestation_manifest_actor",
        ),
        sa.CheckConstraint(
            "observed_at <= signed_at AND verified_at >= signed_at",
            name="ck_privacy_attestation_time",
        ),
        sa.Index(
            "uq_privacy_attestation_execution_attempt",
            "execution_attempt_id",
            unique=True,
            sqlite_where=sa.text("subject_kind IN ('surface', 'backup')"),
            postgresql_where=sa.text("subject_kind IN ('surface', 'backup')"),
        ),
        sa.Index(
            "uq_privacy_attestation_manifest_role",
            "manifest_id",
            "subject_id",
            "attestor_role",
            unique=True,
            sqlite_where=sa.text("subject_kind = 'manifest'"),
            postgresql_where=sa.text("subject_kind = 'manifest'"),
        ),
        sa.Index(
            "ix_privacy_attestation_manifest",
            "manifest_id",
            "subject_kind",
            "subject_id",
            "verified_at",
        ),
    )


class PrivacyBackupRetentionItemRecord(SaasBase):
    """Lease-fenced retention and purge state for one catalogued Backup resource."""

    __tablename__ = "saas_privacy_backup_retention_items"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    manifest_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_manifests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    runtime_partition_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_runtime_partitions.id", ondelete="RESTRICT")
    )
    provider: Mapped[str] = mapped_column(sa.String(96), nullable=False)
    backup_data_class: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    backup_locator_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    resource_handle_ref: Mapped[str | None] = mapped_column(sa.String(512))
    catalog_snapshot_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    tombstone_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    object_lock_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    purge_due_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(48), nullable=False)
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(nullable=False, default=8)
    available_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    leased_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    lease_token_hash: Mapped[str | None] = mapped_column(sa.String(64))
    executor_identity_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    lease_generation: Mapped[int] = mapped_column(nullable=False, default=0)
    replay_generation: Mapped[int] = mapped_column(nullable=False, default=0)
    last_error_code: Mapped[str | None] = mapped_column(sa.String(128))
    last_error_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    purge_evidence_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    evidence_attestation_id: Mapped[UUID | None] = mapped_column()
    purged_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"target_type IN ({_values(PRIVACY_TARGET_TYPES)})",
            name="ck_privacy_backup_retention_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_backup_retention_target_scope",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PRIVACY_BACKUP_RETENTION_STATUSES)})",
            name="ck_privacy_backup_retention_status",
        ),
        sa.CheckConstraint(
            "length(provider) > 0 AND length(backup_data_class) > 0 "
            "AND length(backup_locator_hmac) = 64 "
            "AND length(catalog_snapshot_sha256) = 64 AND length(tombstone_sha256) = 64",
            name="ck_privacy_backup_retention_identity",
        ),
        sa.CheckConstraint(
            "(status = 'legacy_reconciliation_required' AND resource_handle_ref IS NULL) OR "
            "(status <> 'legacy_reconciliation_required' AND length(resource_handle_ref) > 0)",
            name="ck_privacy_backup_retention_resource",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 32 "
            "AND attempt_count <= max_attempts",
            name="ck_privacy_backup_retention_attempt_budget",
        ),
        sa.CheckConstraint(
            "lease_generation >= 0 AND replay_generation >= 0 AND version > 0",
            name="ck_privacy_backup_retention_generations",
        ),
        sa.CheckConstraint(
            "object_lock_until IS NULL OR purge_due_at >= object_lock_until",
            name="ck_privacy_backup_retention_lock_order",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND leased_at IS NOT NULL AND lease_expires_at > leased_at "
            "AND length(lease_token_hash) = 64 AND length(executor_identity_sha256) = 64) OR "
            "(status <> 'leased' AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hash IS NULL AND executor_identity_sha256 IS NULL)",
            name="ck_privacy_backup_retention_lease",
        ),
        sa.CheckConstraint(
            "(last_error_code IS NULL AND last_error_sha256 IS NULL) OR "
            "(length(last_error_code) > 0 AND length(last_error_sha256) = 64)",
            name="ck_privacy_backup_retention_error",
        ),
        sa.CheckConstraint(
            "(status = 'purged' AND purged_at IS NOT NULL "
            "AND purged_at >= purge_due_at AND length(purge_evidence_sha256) = 64 "
            "AND evidence_attestation_id IS NOT NULL) OR "
            "(status <> 'purged' AND purged_at IS NULL AND purge_evidence_sha256 IS NULL "
            "AND evidence_attestation_id IS NULL)",
            name="ck_privacy_backup_retention_result",
        ),
        sa.UniqueConstraint(
            "manifest_id",
            "backup_locator_hmac",
            name="uq_privacy_backup_retention_manifest_locator",
        ),
        sa.Index(
            "ix_privacy_backup_retention_dispatch",
            "status",
            "purge_due_at",
            "available_at",
            "lease_expires_at",
            "id",
        ),
        sa.Index(
            "ix_privacy_backup_retention_target",
            "target_type",
            "target_id",
            "manifest_id",
            "id",
        ),
    )
