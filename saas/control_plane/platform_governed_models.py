"""PC3 governed support, Admin Operation, and immutable audit models."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

PLATFORM_SUPPORT_MODES = ("standard", "break_glass")
PLATFORM_SUPPORT_SCOPES = (
    "tenant.metadata.read",
    "runtime.diagnostics.read",
    "project.content.read",
)
PLATFORM_SUPPORT_GRANT_STATUSES = (
    "pending_customer_approval",
    "pending_staff_approval",
    "active",
    "rejected",
    "revoked",
    "expired",
)
PLATFORM_ADMIN_OPERATION_ACTIONS = (
    "support_grant_request",
    "support_grant_staff_decision",
    "support_session_issue",
    "support_grant_revoke",
    "audit_export",
    "privacy_deletion_start",
    "privacy_deletion_finalize",
    "privacy_surface_replay",
    "privacy_backup_purge_replay",
)
PLATFORM_ADMIN_OPERATION_STATUSES = (
    "pending_customer_approval",
    "pending_staff_approval",
    "succeeded",
    "rejected",
    "revoked",
    "failed",
)
PLATFORM_AUDIT_ACTOR_TYPES = ("staff", "customer", "system")


class PlatformAdminOperationRecord(SaasBase):
    """Versioned state machine for one governed platform operation."""

    __tablename__ = "saas_platform_admin_operations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    action: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    risk_level: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    target_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    requested_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approved_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    reason: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    result: Mapped[dict[str, object] | None] = mapped_column(sa.JSON)
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    approved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            f"action IN ({_values(PLATFORM_ADMIN_OPERATION_ACTIONS)})",
            name="ck_platform_admin_operation_action",
        ),
        sa.CheckConstraint(
            "risk_level IN ('high', 'critical')",
            name="ck_platform_admin_operation_risk",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PLATFORM_ADMIN_OPERATION_STATUSES)})",
            name="ck_platform_admin_operation_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_platform_admin_operation_version"),
        sa.CheckConstraint(
            "length(idempotency_key) > 0",
            name="ck_platform_admin_operation_idempotency_nonempty",
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64", name="ck_platform_admin_operation_request_hash"
        ),
        sa.CheckConstraint(
            "length(reason) > 0", name="ck_platform_admin_operation_reason_nonempty"
        ),
        sa.CheckConstraint(
            "approved_by_principal_id IS NULL OR "
            "approved_by_principal_id <> requested_by_principal_id",
            name="ck_platform_admin_operation_distinct_approver",
        ),
        sa.UniqueConstraint(
            "requested_by_principal_id",
            "idempotency_key",
            name="uq_platform_admin_operation_actor_idempotency",
        ),
        sa.Index(
            "ix_platform_admin_operation_queue",
            "status",
            "created_at",
            "id",
        ),
        sa.Index(
            "ix_platform_admin_operation_target",
            "target_type",
            "target_id",
            "created_at",
        ),
    )


class PlatformSupportGrantRecord(SaasBase):
    """Tenant-bound, expiring JIT support or break-glass grant."""

    __tablename__ = "saas_platform_support_grants"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operation_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_admin_operations.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    requested_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    mode: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    project_ids: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    reason: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    incident_ref: Mapped[str | None] = mapped_column(sa.String(256))
    customer_approval_required: Mapped[bool] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    customer_approved_by_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    customer_approval_reason: Mapped[str | None] = mapped_column(sa.String(1024))
    customer_approved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    staff_approved_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    staff_approval_reason: Mapped[str | None] = mapped_column(sa.String(1024))
    staff_approved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    requested_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    starts_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    revoked_by_actor_type: Mapped[str | None] = mapped_column(sa.String(16))
    revoked_by_actor_id: Mapped[UUID | None] = mapped_column()
    revocation_reason: Mapped[str | None] = mapped_column(sa.String(1024))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            f"mode IN ({_values(PLATFORM_SUPPORT_MODES)})",
            name="ck_platform_support_grant_mode",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PLATFORM_SUPPORT_GRANT_STATUSES)})",
            name="ck_platform_support_grant_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_platform_support_grant_version"),
        sa.CheckConstraint("length(reason) > 0", name="ck_platform_support_grant_reason_nonempty"),
        sa.CheckConstraint(
            "requested_at < expires_at", name="ck_platform_support_grant_expiry_order"
        ),
        sa.CheckConstraint(
            "(mode = 'standard' AND customer_approval_required = true) OR "
            "(mode = 'break_glass' AND customer_approval_required = false "
            "AND length(incident_ref) > 0)",
            name="ck_platform_support_grant_mode_policy",
        ),
        sa.CheckConstraint(
            "staff_approved_by_principal_id IS NULL OR "
            "staff_approved_by_principal_id <> requested_by_principal_id",
            name="ck_platform_support_grant_distinct_staff_approver",
        ),
        sa.CheckConstraint(
            "revoked_by_actor_type IS NULL OR revoked_by_actor_type IN ('staff', 'customer')",
            name="ck_platform_support_grant_revoker_type",
        ),
        sa.Index(
            "ix_platform_support_grant_tenant",
            "tenant_id",
            "status",
            "expires_at",
            "id",
        ),
        sa.Index(
            "ix_platform_support_grant_requester",
            "requested_by_principal_id",
            "status",
            "expires_at",
        ),
    )


class PlatformSupportSessionRecord(SaasBase):
    """One-time disclosed token bound to an active support grant."""

    __tablename__ = "saas_platform_support_sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    grant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_support_grants.id", ondelete="RESTRICT"), nullable=False
    )
    principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    scopes: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            "length(token_hash) = 64", name="ck_platform_support_session_token_hash"
        ),
        sa.CheckConstraint(
            "issued_at < expires_at", name="ck_platform_support_session_expiry_order"
        ),
        sa.Index(
            "ix_platform_support_session_active",
            "grant_id",
            "principal_id",
            "revoked_at",
            "expires_at",
        ),
    )


class PlatformAuditChainHeadRecord(SaasBase):
    """Serialized head of the global platform audit hash chain."""

    __tablename__ = "saas_platform_audit_chain_heads"

    partition_key: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    last_sequence: Mapped[int] = mapped_column(nullable=False, default=0)
    last_event_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("last_sequence >= 0", name="ck_platform_audit_head_sequence"),
        sa.CheckConstraint("length(last_event_hash) = 64", name="ck_platform_audit_head_hash"),
    )


class PlatformAuditEventRecord(SaasBase):
    """Append-only, hash-linked, content-blind platform audit event."""

    __tablename__ = "saas_platform_audit_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    sequence_no: Mapped[int] = mapped_column(nullable=False, unique=True)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    actor_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    operation_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_admin_operations.id", ondelete="RESTRICT")
    )
    payload: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    payload_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    previous_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint("sequence_no > 0", name="ck_platform_audit_event_sequence"),
        sa.CheckConstraint(
            f"actor_type IN ({_values(PLATFORM_AUDIT_ACTOR_TYPES)})",
            name="ck_platform_audit_event_actor_type",
        ),
        sa.CheckConstraint("length(event_type) > 0", name="ck_platform_audit_event_type_nonempty"),
        sa.CheckConstraint(
            "length(target_type) > 0", name="ck_platform_audit_target_type_nonempty"
        ),
        sa.CheckConstraint("length(payload_hash) = 64", name="ck_platform_audit_payload_hash"),
        sa.CheckConstraint("length(previous_hash) = 64", name="ck_platform_audit_previous_hash"),
        sa.CheckConstraint("length(event_hash) = 64", name="ck_platform_audit_event_hash"),
        sa.Index(
            "ix_platform_audit_tenant_sequence",
            "tenant_id",
            "sequence_no",
        ),
        sa.Index(
            "ix_platform_audit_target_sequence",
            "target_type",
            "target_id",
            "sequence_no",
        ),
    )


class PlatformAuditExportRecord(SaasBase):
    """Immutable signed manifest over an exact audit-event range."""

    __tablename__ = "saas_platform_audit_exports"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operation_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_admin_operations.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    requested_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approved_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    from_sequence: Mapped[int] = mapped_column(nullable=False)
    to_sequence: Mapped[int] = mapped_column(nullable=False)
    event_count: Mapped[int] = mapped_column(nullable=False)
    chain_head_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    manifest: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    content_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    signature: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("from_sequence > 0", name="ck_platform_audit_export_from"),
        sa.CheckConstraint("to_sequence >= from_sequence", name="ck_platform_audit_export_range"),
        sa.CheckConstraint("event_count > 0", name="ck_platform_audit_export_count"),
        sa.CheckConstraint(
            "length(chain_head_hash) = 64", name="ck_platform_audit_export_chain_hash"
        ),
        sa.CheckConstraint(
            "length(content_hash) = 64", name="ck_platform_audit_export_content_hash"
        ),
        sa.CheckConstraint(
            "signature_algorithm = 'hmac-sha256'",
            name="ck_platform_audit_export_signature_algorithm",
        ),
        sa.CheckConstraint(
            "length(signing_key_id) > 0", name="ck_platform_audit_export_key_nonempty"
        ),
        sa.CheckConstraint("length(signature) = 64", name="ck_platform_audit_export_signature"),
        sa.CheckConstraint(
            "requested_by_principal_id <> approved_by_principal_id",
            name="ck_platform_audit_export_distinct_approver",
        ),
        sa.Index("ix_platform_audit_export_created", "created_at", "id"),
    )
