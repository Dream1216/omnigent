"""Content-blind notification, approval-operations, and batch records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

NOTIFICATION_REALMS = ("tenant", "staff")
NOTIFICATION_CHANNELS = ("in_app", "email")
APPROVAL_WORK_ITEM_STATUSES = ("pending", "approved", "rejected", "expired", "cancelled")
APPROVAL_WORK_ITEM_PRIORITIES = ("normal", "high", "critical")
APPROVAL_DELEGATION_STATUSES = ("active", "revoked", "expired")
NOTIFICATION_TEMPLATE_STATUSES = ("active", "retired")
NOTIFICATION_DELIVERY_STATUSES = (
    "pending",
    "leased",
    "retry",
    "succeeded",
    "dead_letter",
    "suppressed",
)
NOTIFICATION_ATTEMPT_OUTCOMES = (
    "succeeded",
    "retry",
    "dead_letter",
    "lease_lost",
    "suppressed",
)
OPERATION_BATCH_STATUSES = (
    "pending",
    "running",
    "partial",
    "succeeded",
    "failed",
    "cancelled",
)
OPERATION_BATCH_ITEM_STATUSES = ("pending", "running", "succeeded", "failed", "skipped")


def _realm_check(*, tenant_column: str, tenant_actor: str, staff_actor: str) -> str:
    return (
        f"(realm = 'tenant' AND {tenant_column} IS NOT NULL "
        f"AND {tenant_actor} IS NOT NULL AND {staff_actor} IS NULL) OR "
        f"(realm = 'staff' AND {tenant_actor} IS NULL AND {staff_actor} IS NOT NULL)"
    )


class ApprovalWorkItemRecord(SaasBase):
    """One content-blind approval inbox item in exactly one identity realm."""

    __tablename__ = "saas_approval_work_items"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    requester_realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    requested_by_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    requested_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    assignee_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    assignee_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    operation_kind: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(nullable=False)
    action: Mapped[str] = mapped_column(sa.String(96), nullable=False)
    target_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target_locator_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    hmac_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    required_permission: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    risk_level: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    priority: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="normal")
    due_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    escalation_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    escalation_count: Mapped[int] = mapped_column(nullable=False, default=0)
    decided_by_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    decided_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    decision_code: Mapped[str | None] = mapped_column(sa.String(128))
    decided_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            f"realm IN ({_values(NOTIFICATION_REALMS)})", name="ck_approval_work_realm"
        ),
        sa.CheckConstraint(
            "(realm = 'tenant' AND tenant_id IS NOT NULL) OR realm = 'staff'",
            name="ck_approval_work_queue_realm",
        ),
        sa.CheckConstraint(
            "(requester_realm = 'tenant' AND requested_by_user_id IS NOT NULL "
            "AND requested_by_principal_id IS NULL) OR "
            "(requester_realm = 'staff' AND requested_by_user_id IS NULL "
            "AND requested_by_principal_id IS NOT NULL)",
            name="ck_approval_work_requester_realm",
        ),
        sa.CheckConstraint(
            "(assignee_user_id IS NULL AND assignee_principal_id IS NULL) OR "
            "(realm = 'tenant' AND assignee_user_id IS NOT NULL "
            "AND assignee_principal_id IS NULL) OR "
            "(realm = 'staff' AND assignee_user_id IS NULL "
            "AND assignee_principal_id IS NOT NULL)",
            name="ck_approval_work_optional_assignee_realm",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(APPROVAL_WORK_ITEM_STATUSES)})",
            name="ck_approval_work_status",
        ),
        sa.CheckConstraint(
            f"priority IN ({_values(APPROVAL_WORK_ITEM_PRIORITIES)})",
            name="ck_approval_work_priority",
        ),
        sa.CheckConstraint(
            "length(operation_kind) > 0 AND length(action) > 0 "
            "AND length(target_type) > 0 AND length(required_permission) > 0",
            name="ck_approval_work_codes",
        ),
        sa.CheckConstraint("length(target_locator_hmac) = 64", name="ck_approval_work_target"),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_approval_work_hmac_key"
        ),
        sa.CheckConstraint("length(snapshot_hash) = 64", name="ck_approval_work_snapshot"),
        sa.CheckConstraint(
            "risk_level IN ('medium', 'high', 'critical')", name="ck_approval_work_risk"
        ),
        sa.CheckConstraint(
            "due_at > created_at AND escalation_at <= due_at AND escalation_count >= 0",
            name="ck_approval_work_deadlines",
        ),
        sa.CheckConstraint("version > 0", name="ck_approval_work_version"),
        sa.CheckConstraint(
            "(status = 'pending' AND decided_by_user_id IS NULL "
            "AND decided_by_principal_id IS NULL AND decision_code IS NULL "
            "AND decided_at IS NULL) OR "
            "(status IN ('approved', 'rejected') AND length(decision_code) > 0 "
            "AND decided_at IS NOT NULL AND ((realm = 'tenant' "
            "AND decided_by_user_id IS NOT NULL AND decided_by_principal_id IS NULL) OR "
            "(realm = 'staff' AND decided_by_user_id IS NULL "
            "AND decided_by_principal_id IS NOT NULL))) OR "
            "(status IN ('expired', 'cancelled') AND decided_by_user_id IS NULL "
            "AND decided_by_principal_id IS NULL AND length(decision_code) > 0 "
            "AND decided_at IS NOT NULL)",
            name="ck_approval_work_decision",
        ),
        sa.CheckConstraint(
            "requester_realm <> 'tenant' OR decided_by_user_id IS NULL "
            "OR decided_by_user_id <> requested_by_user_id",
            name="ck_approval_work_distinct_tenant_approver",
        ),
        sa.CheckConstraint(
            "requester_realm <> 'staff' OR decided_by_principal_id IS NULL "
            "OR decided_by_principal_id <> requested_by_principal_id",
            name="ck_approval_work_distinct_staff_approver",
        ),
        sa.UniqueConstraint(
            "realm",
            "operation_kind",
            "operation_id",
            "required_permission",
            name="uq_approval_work_operation_permission",
        ),
        sa.Index(
            "ix_approval_work_tenant_inbox",
            "tenant_id",
            "assignee_user_id",
            "status",
            "priority",
            "due_at",
            "id",
        ),
        sa.Index(
            "ix_approval_work_staff_inbox",
            "tenant_id",
            "assignee_principal_id",
            "status",
            "priority",
            "due_at",
            "id",
        ),
        sa.Index("ix_approval_work_escalation", "status", "escalation_at", "id"),
    )


class ApprovalDelegationRecord(SaasBase):
    """Time-bounded approval delegation that cannot cross identity realms."""

    __tablename__ = "saas_approval_delegations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    delegator_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    delegator_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    delegate_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    delegate_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    permission_code: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    scope_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    scope_id: Mapped[UUID] = mapped_column(nullable=False)
    starts_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
    reason_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    hmac_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    create_idempotency_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    create_request_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    revoke_idempotency_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    revoke_request_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            f"realm IN ({_values(NOTIFICATION_REALMS)})", name="ck_approval_delegation_realm"
        ),
        sa.CheckConstraint(
            _realm_check(
                tenant_column="tenant_id",
                tenant_actor="delegator_user_id",
                staff_actor="delegator_principal_id",
            ),
            name="ck_approval_delegation_delegator_realm",
        ),
        sa.CheckConstraint(
            "(realm = 'tenant' AND delegate_user_id IS NOT NULL "
            "AND delegate_principal_id IS NULL) OR "
            "(realm = 'staff' AND delegate_user_id IS NULL "
            "AND delegate_principal_id IS NOT NULL)",
            name="ck_approval_delegation_delegate_realm",
        ),
        sa.CheckConstraint(
            "(realm = 'tenant' AND delegate_user_id <> delegator_user_id) OR "
            "(realm = 'staff' AND delegate_principal_id <> delegator_principal_id)",
            name="ck_approval_delegation_distinct_actor",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(APPROVAL_DELEGATION_STATUSES)})",
            name="ck_approval_delegation_status",
        ),
        sa.CheckConstraint(
            "length(permission_code) > 0 AND length(scope_type) > 0",
            name="ck_approval_delegation_scope",
        ),
        sa.CheckConstraint("length(reason_hmac) = 64", name="ck_approval_delegation_reason"),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_approval_delegation_hmac_key"
        ),
        sa.CheckConstraint(
            "length(create_idempotency_hmac) = 64 AND length(create_request_hmac) = 64",
            name="ck_approval_delegation_create_idempotency",
        ),
        sa.CheckConstraint(
            "(revoke_idempotency_hmac IS NULL AND revoke_request_hmac IS NULL) OR "
            "(length(revoke_idempotency_hmac) = 64 AND length(revoke_request_hmac) = 64)",
            name="ck_approval_delegation_revoke_idempotency",
        ),
        sa.CheckConstraint(
            "starts_at < expires_at AND expires_at > created_at",
            name="ck_approval_delegation_expiry",
        ),
        sa.CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL) OR "
            "(status <> 'revoked' AND revoked_at IS NULL)",
            name="ck_approval_delegation_revocation",
        ),
        sa.CheckConstraint("version > 0", name="ck_approval_delegation_version"),
        sa.Index(
            "uq_approval_delegation_tenant_idempotency",
            "tenant_id",
            "delegator_user_id",
            "create_idempotency_hmac",
            unique=True,
            sqlite_where=sa.text("realm = 'tenant'"),
            postgresql_where=sa.text("realm = 'tenant'"),
        ),
        sa.Index(
            "uq_approval_delegation_staff_tenant_idempotency",
            "tenant_id",
            "delegator_principal_id",
            "create_idempotency_hmac",
            unique=True,
            sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
            postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
        ),
        sa.Index(
            "uq_approval_delegation_staff_global_idempotency",
            "delegator_principal_id",
            "create_idempotency_hmac",
            unique=True,
            sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
            postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
        ),
        sa.Index(
            "uq_approval_delegation_tenant_scope",
            "tenant_id",
            "delegator_user_id",
            "delegate_user_id",
            "permission_code",
            "scope_type",
            "scope_id",
            "starts_at",
            unique=True,
            sqlite_where=sa.text("realm = 'tenant'"),
            postgresql_where=sa.text("realm = 'tenant'"),
        ),
        sa.Index(
            "uq_approval_delegation_staff_tenant_scope",
            "tenant_id",
            "delegator_principal_id",
            "delegate_principal_id",
            "permission_code",
            "scope_type",
            "scope_id",
            "starts_at",
            unique=True,
            sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
            postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
        ),
        sa.Index(
            "uq_approval_delegation_staff_global_scope",
            "delegator_principal_id",
            "delegate_principal_id",
            "permission_code",
            "scope_type",
            "scope_id",
            "starts_at",
            unique=True,
            sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
            postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
        ),
        sa.Index(
            "ix_approval_delegation_tenant_active",
            "tenant_id",
            "delegate_user_id",
            "status",
            "expires_at",
            "id",
        ),
        sa.Index(
            "ix_approval_delegation_staff_active",
            "delegate_principal_id",
            "status",
            "expires_at",
            "id",
        ),
    )


class NotificationTemplateRecord(SaasBase):
    """Staff-owned immutable template metadata; Tenant actors are read-only consumers."""

    __tablename__ = "saas_notification_templates"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    created_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    template_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    channel: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    locale: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False)
    content_artifact_handle: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    content_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    variables_schema_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    hmac_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    create_idempotency_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    create_request_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    retire_idempotency_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    retire_request_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    retired_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.CheckConstraint("realm = 'staff'", name="ck_notification_template_realm"),
        sa.CheckConstraint(
            f"channel IN ({_values(NOTIFICATION_CHANNELS)})",
            name="ck_notification_template_channel",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(NOTIFICATION_TEMPLATE_STATUSES)})",
            name="ck_notification_template_status",
        ),
        sa.CheckConstraint(
            "length(template_key) > 0 AND length(locale) > 0 "
            "AND length(content_artifact_handle) BETWEEN 16 AND 128 "
            "AND content_artifact_handle NOT LIKE '%://%' "
            "AND content_artifact_handle NOT LIKE '/%' "
            "AND content_artifact_handle NOT LIKE '%/%' "
            "AND content_artifact_handle NOT LIKE '% %'",
            name="ck_notification_template_identity",
        ),
        sa.CheckConstraint(
            "length(content_sha256) = 64 AND length(variables_schema_sha256) = 64",
            name="ck_notification_template_hashes",
        ),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128 "
            "AND length(create_idempotency_hmac) = 64 "
            "AND length(create_request_hmac) = 64",
            name="ck_notification_template_create_idempotency",
        ),
        sa.CheckConstraint(
            "(status = 'active' AND retire_idempotency_hmac IS NULL "
            "AND retire_request_hmac IS NULL) OR "
            "(status = 'retired' AND length(retire_idempotency_hmac) = 64 "
            "AND length(retire_request_hmac) = 64)",
            name="ck_notification_template_retire_idempotency",
        ),
        sa.CheckConstraint("version > 0", name="ck_notification_template_version"),
        sa.CheckConstraint(
            "(status = 'active' AND retired_at IS NULL) OR "
            "(status = 'retired' AND retired_at IS NOT NULL)",
            name="ck_notification_template_retirement",
        ),
        sa.Index(
            "uq_notification_template_staff_tenant_idempotency",
            "tenant_id",
            "created_by_principal_id",
            "create_idempotency_hmac",
            unique=True,
            sqlite_where=sa.text("tenant_id IS NOT NULL"),
            postgresql_where=sa.text("tenant_id IS NOT NULL"),
        ),
        sa.Index(
            "uq_notification_template_staff_global_idempotency",
            "created_by_principal_id",
            "create_idempotency_hmac",
            unique=True,
            sqlite_where=sa.text("tenant_id IS NULL"),
            postgresql_where=sa.text("tenant_id IS NULL"),
        ),
        sa.Index(
            "uq_notification_template_staff_tenant_version",
            "tenant_id",
            "template_key",
            "channel",
            "locale",
            "version",
            unique=True,
            sqlite_where=sa.text("tenant_id IS NOT NULL"),
            postgresql_where=sa.text("tenant_id IS NOT NULL"),
        ),
        sa.Index(
            "uq_notification_template_staff_global_version",
            "template_key",
            "channel",
            "locale",
            "version",
            unique=True,
            sqlite_where=sa.text("tenant_id IS NULL"),
            postgresql_where=sa.text("tenant_id IS NULL"),
        ),
        sa.Index(
            "ix_notification_template_lookup",
            "realm",
            "tenant_id",
            "template_key",
            "channel",
            "locale",
            "status",
            "version",
        ),
    )


class NotificationPreferenceRecord(SaasBase):
    """Recipient channel preference without storing an address or message content."""

    __tablename__ = "saas_notification_preferences"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    recipient_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    recipient_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    event_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    channel: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    locale: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    idempotency_key_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    request_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    hmac_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
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
            f"realm IN ({_values(NOTIFICATION_REALMS)})",
            name="ck_notification_preference_realm",
        ),
        sa.CheckConstraint(
            _realm_check(
                tenant_column="tenant_id",
                tenant_actor="recipient_user_id",
                staff_actor="recipient_principal_id",
            ),
            name="ck_notification_preference_recipient_realm",
        ),
        sa.CheckConstraint(
            f"channel IN ({_values(NOTIFICATION_CHANNELS)})",
            name="ck_notification_preference_channel",
        ),
        sa.CheckConstraint(
            "length(event_type) > 0 AND length(locale) > 0",
            name="ck_notification_preference_identity",
        ),
        sa.CheckConstraint(
            "length(idempotency_key_hmac) = 64 AND length(request_hmac) = 64 "
            "AND length(hmac_key_id) BETWEEN 1 AND 128",
            name="ck_notification_preference_idempotency",
        ),
        sa.CheckConstraint("version > 0", name="ck_notification_preference_version"),
        sa.Index(
            "uq_notification_preference_tenant_recipient_event",
            "tenant_id",
            "recipient_user_id",
            "event_type",
            "channel",
            unique=True,
            sqlite_where=sa.text("realm = 'tenant'"),
            postgresql_where=sa.text("realm = 'tenant'"),
        ),
        sa.Index(
            "uq_notification_preference_staff_tenant_event",
            "tenant_id",
            "recipient_principal_id",
            "event_type",
            "channel",
            unique=True,
            sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
            postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
        ),
        sa.Index(
            "uq_notification_preference_staff_global_event",
            "recipient_principal_id",
            "event_type",
            "channel",
            unique=True,
            sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
            postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
        ),
        sa.Index(
            "ix_notification_preference_tenant_recipient",
            "tenant_id",
            "recipient_user_id",
            "event_type",
            "channel",
        ),
        sa.Index(
            "ix_notification_preference_staff_recipient",
            "recipient_principal_id",
            "event_type",
            "channel",
        ),
    )


class OperationBatchRecord(SaasBase):
    """Content-blind batch command summary in one identity realm."""

    __tablename__ = "saas_operation_batches"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    requested_by_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    requested_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    operation_kind: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    action: Mapped[str] = mapped_column(sa.String(96), nullable=False)
    decision_code: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    authority_decision_code: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    decision_reason_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    idempotency_key_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    request_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    hmac_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    item_count: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    success_count: Mapped[int] = mapped_column(nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(nullable=False, default=0)
    result_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    leased_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    lease_token_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    executor_identity_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    lease_generation: Mapped[int] = mapped_column(nullable=False, default=0)
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
            f"realm IN ({_values(NOTIFICATION_REALMS)})", name="ck_operation_batch_realm"
        ),
        sa.CheckConstraint(
            _realm_check(
                tenant_column="tenant_id",
                tenant_actor="requested_by_user_id",
                staff_actor="requested_by_principal_id",
            ),
            name="ck_operation_batch_requester_realm",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(OPERATION_BATCH_STATUSES)})",
            name="ck_operation_batch_status",
        ),
        sa.CheckConstraint(
            "length(operation_kind) > 0 AND length(action) > 0 "
            "AND length(idempotency_key_hmac) = 64",
            name="ck_operation_batch_identity",
        ),
        sa.CheckConstraint(
            "decision_code IN ('approve', 'reject')", name="ck_operation_batch_decision"
        ),
        sa.CheckConstraint(
            "length(authority_decision_code) BETWEEN 1 AND 128",
            name="ck_operation_batch_authority_decision",
        ),
        sa.CheckConstraint(
            "length(decision_reason_hmac) = 64", name="ck_operation_batch_decision_reason"
        ),
        sa.CheckConstraint("length(request_hmac) = 64", name="ck_operation_batch_request"),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_operation_batch_hmac_key"
        ),
        sa.CheckConstraint(
            "item_count BETWEEN 1 AND 25 AND success_count >= 0 AND failure_count >= 0 "
            "AND success_count + failure_count <= item_count",
            name="ck_operation_batch_counts",
        ),
        sa.CheckConstraint(
            "version > 0 AND lease_generation >= 0", name="ck_operation_batch_version"
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND started_at IS NULL AND completed_at IS NULL "
            "AND result_hmac IS NULL AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hmac IS NULL AND executor_identity_sha256 IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL "
            "AND result_hmac IS NULL AND leased_at IS NOT NULL "
            "AND lease_expires_at > leased_at AND length(lease_token_hmac) = 64 "
            "AND length(executor_identity_sha256) = 64) OR "
            "(status IN ('partial', 'succeeded', 'failed', 'cancelled') "
            "AND completed_at IS NOT NULL AND length(result_hmac) = 64 "
            "AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hmac IS NULL AND executor_identity_sha256 IS NULL)",
            name="ck_operation_batch_lifecycle",
        ),
        sa.Index(
            "uq_operation_batch_tenant_idempotency",
            "tenant_id",
            "requested_by_user_id",
            "idempotency_key_hmac",
            unique=True,
            sqlite_where=sa.text("realm = 'tenant'"),
            postgresql_where=sa.text("realm = 'tenant'"),
        ),
        sa.Index(
            "uq_operation_batch_staff_tenant_idempotency",
            "tenant_id",
            "requested_by_principal_id",
            "idempotency_key_hmac",
            unique=True,
            sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
            postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
        ),
        sa.Index(
            "uq_operation_batch_staff_global_idempotency",
            "requested_by_principal_id",
            "idempotency_key_hmac",
            unique=True,
            sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
            postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
        ),
        sa.Index(
            "ix_operation_batch_tenant_queue",
            "tenant_id",
            "requested_by_user_id",
            "status",
            "created_at",
            "id",
        ),
        sa.Index(
            "ix_operation_batch_staff_queue",
            "requested_by_principal_id",
            "status",
            "created_at",
            "id",
        ),
    )


class OperationBatchItemRecord(SaasBase):
    """One content-blind target result in an Operation Batch."""

    __tablename__ = "saas_operation_batch_items"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    batch_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_operation_batches.id", ondelete="RESTRICT"), nullable=False
    )
    realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    requested_by_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    requested_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    sequence: Mapped[int] = mapped_column(nullable=False)
    target_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target_locator_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    hmac_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    operation_id: Mapped[UUID | None] = mapped_column()
    approval_work_item_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_approval_work_items.id", ondelete="RESTRICT"), nullable=False
    )
    expected_work_item_version: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    error_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    result_hmac: Mapped[str | None] = mapped_column(sa.String(64))
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
            f"realm IN ({_values(NOTIFICATION_REALMS)})", name="ck_operation_batch_item_realm"
        ),
        sa.CheckConstraint(
            _realm_check(
                tenant_column="tenant_id",
                tenant_actor="requested_by_user_id",
                staff_actor="requested_by_principal_id",
            ),
            name="ck_operation_batch_item_requester_realm",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(OPERATION_BATCH_ITEM_STATUSES)})",
            name="ck_operation_batch_item_status",
        ),
        sa.CheckConstraint("sequence > 0", name="ck_operation_batch_item_sequence"),
        sa.CheckConstraint(
            "expected_work_item_version > 0", name="ck_operation_batch_item_expected_version"
        ),
        sa.CheckConstraint(
            "length(target_type) > 0 AND length(target_locator_hmac) = 64",
            name="ck_operation_batch_item_target",
        ),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_operation_batch_item_hmac_key"
        ),
        sa.CheckConstraint(
            "(error_code IS NULL AND error_hmac IS NULL) OR "
            "(length(error_code) > 0 AND length(error_hmac) = 64)",
            name="ck_operation_batch_item_error",
        ),
        sa.CheckConstraint(
            "(status IN ('pending', 'running') AND result_hmac IS NULL "
            "AND error_code IS NULL AND error_hmac IS NULL) OR "
            "(status = 'succeeded' AND length(result_hmac) = 64 "
            "AND error_code IS NULL AND error_hmac IS NULL) OR "
            "(status IN ('failed', 'skipped') AND length(result_hmac) = 64 "
            "AND length(error_code) > 0 AND length(error_hmac) = 64)",
            name="ck_operation_batch_item_result",
        ),
        sa.CheckConstraint("version > 0", name="ck_operation_batch_item_version"),
        sa.UniqueConstraint("batch_id", "sequence", name="uq_operation_batch_item_sequence"),
        sa.UniqueConstraint(
            "batch_id", "approval_work_item_id", name="uq_operation_batch_item_work_item"
        ),
        sa.UniqueConstraint(
            "batch_id", "target_type", "target_locator_hmac", name="uq_operation_batch_item_target"
        ),
        sa.Index("ix_operation_batch_item_queue", "batch_id", "status", "sequence", "id"),
    )


class NotificationDeliveryRecord(SaasBase):
    """Retryable notification envelope containing no address or rendered body."""

    __tablename__ = "saas_notification_deliveries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    recipient_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    recipient_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    event_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    channel: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    template_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_notification_templates.id", ondelete="RESTRICT"), nullable=False
    )
    source_delivery_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_notification_deliveries.id", ondelete="RESTRICT")
    )
    approval_work_item_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_approval_work_items.id", ondelete="RESTRICT")
    )
    operation_batch_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_operation_batches.id", ondelete="RESTRICT")
    )
    deduplication_key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    recipient_locator_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    render_context_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    hmac_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
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
    replay_receipt_generation: Mapped[int | None] = mapped_column()
    replay_idempotency_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    replay_request_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    provider_message_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    delivered_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    recipient_read_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    read_idempotency_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    read_request_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    suppression_code: Mapped[str | None] = mapped_column(sa.String(128))
    inflight_boundary_code: Mapped[str | None] = mapped_column(sa.String(64))
    last_error_code: Mapped[str | None] = mapped_column(sa.String(128))
    last_error_hmac: Mapped[str | None] = mapped_column(sa.String(64))
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
            f"realm IN ({_values(NOTIFICATION_REALMS)})", name="ck_notification_delivery_realm"
        ),
        sa.CheckConstraint(
            _realm_check(
                tenant_column="tenant_id",
                tenant_actor="recipient_user_id",
                staff_actor="recipient_principal_id",
            ),
            name="ck_notification_delivery_recipient_realm",
        ),
        sa.CheckConstraint(
            f"channel IN ({_values(NOTIFICATION_CHANNELS)})",
            name="ck_notification_delivery_channel",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(NOTIFICATION_DELIVERY_STATUSES)})",
            name="ck_notification_delivery_status",
        ),
        sa.CheckConstraint("length(event_type) > 0", name="ck_notification_delivery_event"),
        sa.CheckConstraint(
            "(event_type = 'notification.delivery_dead_letter' "
            "AND realm = 'staff' AND channel = 'in_app' "
            "AND source_delivery_id IS NOT NULL "
            "AND approval_work_item_id IS NULL AND operation_batch_id IS NULL) OR "
            "(event_type <> 'notification.delivery_dead_letter' "
            "AND source_delivery_id IS NULL)",
            name="ck_notification_delivery_dead_letter_source",
        ),
        sa.CheckConstraint(
            "length(deduplication_key) = 64 AND length(recipient_locator_hmac) = 64 "
            "AND length(render_context_hmac) = 64",
            name="ck_notification_delivery_hashes",
        ),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_notification_delivery_hmac_key"
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 8 "
            "AND attempt_count <= max_attempts",
            name="ck_notification_delivery_attempt_budget",
        ),
        sa.CheckConstraint(
            "lease_generation >= 0 AND replay_generation >= 0 AND version > 0",
            name="ck_notification_delivery_versions",
        ),
        sa.CheckConstraint(
            "(replay_generation = 0 AND replay_receipt_generation IS NULL "
            "AND replay_idempotency_hmac IS NULL AND replay_request_hmac IS NULL) OR "
            "(replay_generation > 0 AND replay_receipt_generation = replay_generation "
            "AND length(replay_idempotency_hmac) = 64 "
            "AND length(replay_request_hmac) = 64)",
            name="ck_notification_delivery_replay",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND leased_at IS NOT NULL AND lease_expires_at > leased_at "
            "AND length(lease_token_hash) = 64 "
            "AND length(executor_identity_sha256) = 64) OR "
            "(status <> 'leased' AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hash IS NULL AND executor_identity_sha256 IS NULL)",
            name="ck_notification_delivery_lease",
        ),
        sa.CheckConstraint(
            "(last_error_code IS NULL AND last_error_hmac IS NULL) OR "
            "(length(last_error_code) > 0 AND length(last_error_hmac) = 64)",
            name="ck_notification_delivery_error",
        ),
        sa.CheckConstraint(
            "(status = 'succeeded' AND length(provider_message_hmac) = 64 "
            "AND delivered_at IS NOT NULL AND suppression_code IS NULL "
            "AND last_error_code IS NULL AND last_error_hmac IS NULL) OR "
            "(status = 'suppressed' AND provider_message_hmac IS NULL "
            "AND delivered_at IS NULL AND length(suppression_code) > 0 "
            "AND last_error_code IS NULL AND last_error_hmac IS NULL) OR "
            "(status NOT IN ('succeeded', 'suppressed') AND provider_message_hmac IS NULL "
            "AND delivered_at IS NULL AND suppression_code IS NULL)",
            name="ck_notification_delivery_terminal",
        ),
        sa.CheckConstraint(
            "(recipient_read_at IS NULL AND acknowledged_at IS NULL "
            "AND read_idempotency_hmac IS NULL AND read_request_hmac IS NULL) OR "
            "(channel = 'in_app' AND status = 'succeeded' "
            "AND recipient_read_at IS NOT NULL "
            "AND length(read_idempotency_hmac) = 64 AND length(read_request_hmac) = 64 "
            "AND (acknowledged_at IS NULL OR acknowledged_at >= recipient_read_at))",
            name="ck_notification_delivery_recipient_ack",
        ),
        sa.CheckConstraint(
            "channel <> 'email' OR (recipient_read_at IS NULL AND acknowledged_at IS NULL "
            "AND read_idempotency_hmac IS NULL AND read_request_hmac IS NULL)",
            name="ck_notification_delivery_email_ack",
        ),
        sa.CheckConstraint(
            "inflight_boundary_code IS NULL OR (status = 'succeeded' "
            "AND inflight_boundary_code = 'approval_terminal_after_send')",
            name="ck_notification_delivery_inflight_boundary",
        ),
        sa.UniqueConstraint("deduplication_key", name="uq_notification_delivery_deduplication"),
        sa.Index(
            "ix_notification_delivery_dispatch",
            "status",
            "available_at",
            "lease_expires_at",
            "id",
        ),
        sa.Index(
            "ix_notification_delivery_tenant_recipient",
            "tenant_id",
            "recipient_user_id",
            "created_at",
            "id",
        ),
        sa.Index(
            "ix_notification_delivery_staff_recipient",
            "recipient_principal_id",
            "created_at",
            "id",
        ),
        sa.Index("ix_notification_delivery_source", "source_delivery_id", "id"),
    )


class NotificationDeliveryAttemptRecord(SaasBase):
    """Immutable, content-blind provider attempt fact."""

    __tablename__ = "saas_notification_delivery_attempts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    delivery_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_notification_deliveries.id", ondelete="RESTRICT"), nullable=False
    )
    realm: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    recipient_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    recipient_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    attempt_number: Mapped[int] = mapped_column(nullable=False)
    lease_generation: Mapped[int] = mapped_column(nullable=False)
    outcome: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    content_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    provider_request_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    provider_receipt_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    error_hmac: Mapped[str | None] = mapped_column(sa.String(64))
    inflight_boundary_code: Mapped[str | None] = mapped_column(sa.String(64))
    hmac_key_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    executor_identity_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    next_available_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"realm IN ({_values(NOTIFICATION_REALMS)})", name="ck_notification_attempt_realm"
        ),
        sa.CheckConstraint(
            _realm_check(
                tenant_column="tenant_id",
                tenant_actor="recipient_user_id",
                staff_actor="recipient_principal_id",
            ),
            name="ck_notification_attempt_recipient_realm",
        ),
        sa.CheckConstraint(
            f"outcome IN ({_values(NOTIFICATION_ATTEMPT_OUTCOMES)})",
            name="ck_notification_attempt_outcome",
        ),
        sa.CheckConstraint(
            "attempt_number > 0 AND lease_generation > 0",
            name="ck_notification_attempt_generation",
        ),
        sa.CheckConstraint(
            "length(content_hmac) = 64 AND length(executor_identity_sha256) = 64",
            name="ck_notification_attempt_hashes",
        ),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_notification_attempt_hmac_key"
        ),
        sa.CheckConstraint(
            "provider_request_hmac IS NULL OR length(provider_request_hmac) = 64",
            name="ck_notification_attempt_request",
        ),
        sa.CheckConstraint(
            "provider_receipt_hmac IS NULL OR length(provider_receipt_hmac) = 64",
            name="ck_notification_attempt_receipt",
        ),
        sa.CheckConstraint(
            "(error_code IS NULL AND error_hmac IS NULL) OR "
            "(length(error_code) > 0 AND length(error_hmac) = 64)",
            name="ck_notification_attempt_error",
        ),
        sa.CheckConstraint(
            "inflight_boundary_code IS NULL OR (outcome = 'succeeded' "
            "AND inflight_boundary_code = 'approval_terminal_after_send')",
            name="ck_notification_attempt_inflight_boundary",
        ),
        sa.CheckConstraint("completed_at >= started_at", name="ck_notification_attempt_time"),
        sa.CheckConstraint(
            "(outcome = 'succeeded' AND length(provider_request_hmac) = 64 "
            "AND length(provider_receipt_hmac) = 64 AND error_code IS NULL "
            "AND error_hmac IS NULL AND next_available_at IS NULL) OR "
            "(outcome = 'retry' AND length(error_code) > 0 "
            "AND length(error_hmac) = 64 AND next_available_at > completed_at) OR "
            "(outcome IN ('dead_letter', 'lease_lost') AND length(error_code) > 0 "
            "AND length(error_hmac) = 64 AND next_available_at IS NULL) OR "
            "(outcome = 'suppressed' AND provider_request_hmac IS NULL "
            "AND provider_receipt_hmac IS NULL AND length(error_code) > 0 "
            "AND length(error_hmac) = 64 AND next_available_at IS NULL)",
            name="ck_notification_attempt_result",
        ),
        sa.UniqueConstraint(
            "delivery_id",
            "lease_generation",
            "attempt_number",
            name="uq_notification_attempt_generation_number",
        ),
        sa.Index("ix_notification_attempt_delivery", "delivery_id", "attempt_number", "id"),
    )
