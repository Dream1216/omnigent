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
