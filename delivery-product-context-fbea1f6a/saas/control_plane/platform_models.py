"""Independent Staff Realm, platform access, and content-blind projections."""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

PLATFORM_STAFF_STATUSES = ("active", "suspended", "deleted")
PLATFORM_ASSIGNMENT_STATUSES = ("active", "revoked", "expired")
PLATFORM_ROLES = (
    "platform_operator",
    "platform_security_auditor",
    "support_agent",
    "billing_operator",
    "compliance_operator",
)
PLATFORM_OPERATION_ACTIONS = (
    "user_suspend",
    "user_restore",
    "user_sessions_revoke",
    "tenant_suspend",
    "tenant_restore",
    "tenant_owner_recover",
    "identity_conflict_assign",
    "identity_conflict_block",
)
EMAIL_PROVIDER_PURPOSES = ("onboarding_verification",)
EMAIL_PROVIDER_SECURITY_MODES = ("starttls", "tls")
EMAIL_PROVIDER_RECEIPT_ACTIONS = (
    "configured",
    "disabled",
    "test_succeeded",
    "test_failed",
)
MODEL_PROVIDER_IDS = ("deepseek",)
MODEL_PROVIDER_API_TYPES = ("openai_chat_completions",)
MODEL_PROVIDER_VERIFICATION_STATUSES = ("never", "verified", "failed")
MODEL_PROVIDER_RECEIPT_ACTIONS = (
    "configured",
    "disabled",
    "verification_succeeded",
    "verification_failed",
)
MODEL_PROVIDER_BUDGET_RESERVATION_STATUSES = (
    "reserved",
    "settled",
    "released",
    "rejected",
    "expired",
)


class PlatformStaffPrincipalRecord(SaasBase):
    """Staff-only identity that never doubles as a customer Global User."""

    __tablename__ = "saas_platform_staff_principals"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    identity_connection_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    issuer: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    subject: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.String(256))
    email_normalized: Mapped[str | None] = mapped_column(sa.String(320))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    security_version: Mapped[int] = mapped_column(nullable=False, default=1)
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
            f"status IN ({_values(PLATFORM_STAFF_STATUSES)})",
            name="ck_platform_staff_status",
        ),
        sa.CheckConstraint("security_version > 0", name="ck_platform_staff_security_version"),
        sa.CheckConstraint(
            "length(identity_connection_ref) > 0",
            name="ck_platform_staff_identity_ref_nonempty",
        ),
        sa.CheckConstraint("length(issuer) > 0", name="ck_platform_staff_issuer_nonempty"),
        sa.CheckConstraint("length(subject) > 0", name="ck_platform_staff_subject_nonempty"),
        sa.UniqueConstraint("issuer", "subject", name="uq_platform_staff_subject"),
        sa.UniqueConstraint(
            "identity_connection_ref", name="uq_platform_staff_identity_connection_ref"
        ),
        sa.Index("ix_platform_staff_status", "status", "updated_at"),
    )


class PlatformPasswordCredentialRecord(SaasBase):
    """Argon2id credential for the independent local Staff Realm."""

    __tablename__ = "saas_platform_password_credentials"

    principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    username_normalized: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    password_version: Mapped[int] = mapped_column(nullable=False, default=1)
    failed_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            "length(username_normalized) >= 3",
            name="ck_platform_password_username_nonempty",
        ),
        sa.CheckConstraint(
            "length(password_hash) > 0",
            name="ck_platform_password_hash_nonempty",
        ),
        sa.CheckConstraint(
            "password_version > 0",
            name="ck_platform_password_version",
        ),
        sa.CheckConstraint(
            "failed_attempts >= 0",
            name="ck_platform_password_failed_attempts",
        ),
        sa.Index("ix_platform_password_lock", "locked_until"),
    )


class PlatformRoleAssignmentRecord(SaasBase):
    """Versioned, expiring assignment of one immutable platform role."""

    __tablename__ = "saas_platform_role_assignments"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    assigned_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approval_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    reason: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
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
            f"role IN ({_values(PLATFORM_ROLES)})", name="ck_platform_assignment_role"
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PLATFORM_ASSIGNMENT_STATUSES)})",
            name="ck_platform_assignment_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_platform_assignment_version"),
        sa.CheckConstraint(
            "length(approval_ref) > 0", name="ck_platform_assignment_approval_nonempty"
        ),
        sa.CheckConstraint("length(reason) > 0", name="ck_platform_assignment_reason_nonempty"),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL AND revoked_by_principal_id IS NULL) "
            "OR (status IN ('revoked', 'expired'))",
            name="ck_platform_assignment_revocation_state",
        ),
        sa.Index(
            "ix_platform_assignment_principal_status",
            "principal_id",
            "status",
            "expires_at",
        ),
    )


class PlatformAuthSessionRecord(SaasBase):
    """Origin- and Audience-bound local-password Staff Realm session."""

    __tablename__ = "saas_platform_auth_sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    csrf_token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    security_version: Mapped[int] = mapped_column(nullable=False)
    audience: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    origin: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    authn_method: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    mfa_strength: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    authenticated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint("length(token_hash) = 64", name="ck_platform_session_token_hash"),
        sa.CheckConstraint("length(csrf_token_hash) = 64", name="ck_platform_session_csrf_hash"),
        sa.CheckConstraint("security_version > 0", name="ck_platform_session_security_version"),
        sa.CheckConstraint("length(audience) > 0", name="ck_platform_session_audience_nonempty"),
        sa.CheckConstraint("length(origin) > 0", name="ck_platform_session_origin_nonempty"),
        sa.CheckConstraint(
            "length(authn_method) > 0", name="ck_platform_session_authn_method_nonempty"
        ),
        sa.CheckConstraint(
            "mfa_strength IN ('not_required', 'phishing_resistant')",
            name="ck_platform_session_mfa_strength",
        ),
        sa.CheckConstraint(
            "authenticated_at < expires_at", name="ck_platform_session_expiry_order"
        ),
        sa.Index(
            "ix_platform_session_principal_active",
            "principal_id",
            "revoked_at",
            "expires_at",
        ),
    )


class PlatformTenantProjectionRecord(SaasBase):
    """Cross-Tenant metadata projection with no customer content columns."""

    __tablename__ = "saas_platform_tenant_projections"

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    plan: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    home_region: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    member_count: Mapped[int] = mapped_column(nullable=False, default=0)
    space_count: Mapped[int] = mapped_column(nullable=False, default=0)
    source_version: Mapped[int] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("member_count >= 0", name="ck_platform_tenant_member_count"),
        sa.CheckConstraint("space_count >= 0", name="ck_platform_tenant_space_count"),
        sa.CheckConstraint("source_version > 0", name="ck_platform_tenant_source_version"),
        sa.Index("ix_platform_tenant_projection_list", "status", "tenant_id"),
    )


class PlatformUserProjectionRecord(SaasBase):
    """Global User metadata projection that stores only a masked email."""

    __tablename__ = "saas_platform_user_projections"

    user_id: Mapped[UUID] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.String(256))
    email_masked: Mapped[str | None] = mapped_column(sa.String(320))
    membership_count: Mapped[int] = mapped_column(nullable=False, default=0)
    security_version: Mapped[int] = mapped_column(nullable=False)
    source_version: Mapped[int] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("membership_count >= 0", name="ck_platform_user_membership_count"),
        sa.CheckConstraint("security_version > 0", name="ck_platform_user_security_version"),
        sa.CheckConstraint("source_version > 0", name="ck_platform_user_source_version"),
        sa.Index("ix_platform_user_projection_list", "status", "user_id"),
    )


class EmailProviderConfigurationRecord(SaasBase):
    """Platform-owned SMTP metadata plus non-exporting KMS/Vault ciphertext."""

    __tablename__ = "saas_email_provider_configurations"

    purpose: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=False)
    host: Mapped[str] = mapped_column(sa.String(253), nullable=False)
    port: Mapped[int] = mapped_column(nullable=False)
    security: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    username: Mapped[str] = mapped_column(sa.String(320), nullable=False)
    password_ciphertext: Mapped[str] = mapped_column(sa.Text, nullable=False)
    from_address: Mapped[str] = mapped_column(sa.String(320), nullable=False)
    reply_to_address: Mapped[str | None] = mapped_column(sa.String(320))
    timeout_seconds: Mapped[float] = mapped_column(nullable=False, default=10.0)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    updated_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint(
            f"purpose IN ({_values(EMAIL_PROVIDER_PURPOSES)})",
            name="ck_email_provider_configuration_purpose",
        ),
        sa.CheckConstraint(
            f"security IN ({_values(EMAIL_PROVIDER_SECURITY_MODES)})",
            name="ck_email_provider_configuration_security",
        ),
        sa.CheckConstraint(
            "port >= 1 AND port <= 65535", name="ck_email_provider_configuration_port"
        ),
        sa.CheckConstraint(
            "timeout_seconds > 0 AND timeout_seconds <= 30",
            name="ck_email_provider_configuration_timeout",
        ),
        sa.CheckConstraint("version > 0", name="ck_email_provider_configuration_version"),
        sa.CheckConstraint(
            "length(host) > 0 AND length(username) > 0 AND "
            "length(password_ciphertext) > 0 AND length(from_address) > 0",
            name="ck_email_provider_configuration_required_values",
        ),
    )


class EmailProviderConfigurationReceiptRecord(SaasBase):
    """Append-only, content-blind evidence for SMTP configuration actions."""

    __tablename__ = "saas_email_provider_configuration_receipts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    purpose: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    configuration_version: Mapped[int] = mapped_column(nullable=False)
    actor_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    configuration_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    password_rotated: Mapped[bool] = mapped_column(nullable=False, default=False)
    recipient_hash: Mapped[str | None] = mapped_column(sa.String(64))
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint(
            f"purpose IN ({_values(EMAIL_PROVIDER_PURPOSES)})",
            name="ck_email_provider_receipt_purpose",
        ),
        sa.CheckConstraint(
            f"action IN ({_values(EMAIL_PROVIDER_RECEIPT_ACTIONS)})",
            name="ck_email_provider_receipt_action",
        ),
        sa.CheckConstraint("configuration_version > 0", name="ck_email_provider_receipt_version"),
        sa.CheckConstraint(
            "length(configuration_hash) = 64", name="ck_email_provider_receipt_hash"
        ),
        sa.CheckConstraint(
            "recipient_hash IS NULL OR length(recipient_hash) = 64",
            name="ck_email_provider_receipt_recipient_hash",
        ),
        sa.Index(
            "ix_email_provider_receipt_purpose_time",
            "purpose",
            "occurred_at",
            "id",
        ),
    )


class ModelProviderConfigurationRecord(SaasBase):
    """Platform-owned model gateway policy plus non-exporting API-key ciphertext."""

    __tablename__ = "saas_model_provider_configurations"

    provider_id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=False)
    base_url: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    api_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    api_key_ciphertext: Mapped[str] = mapped_column(sa.Text, nullable=False)
    allowed_models: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    default_model: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    monthly_budget_microusd: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    per_tenant_daily_token_limit: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    verification_status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="never"
    )
    last_verified_model: Mapped[str | None] = mapped_column(sa.String(128))
    last_verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    updated_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint(
            f"provider_id IN ({_values(MODEL_PROVIDER_IDS)})",
            name="ck_model_provider_configuration_provider",
        ),
        sa.CheckConstraint(
            f"api_type IN ({_values(MODEL_PROVIDER_API_TYPES)})",
            name="ck_model_provider_configuration_api_type",
        ),
        sa.CheckConstraint(
            f"verification_status IN ({_values(MODEL_PROVIDER_VERIFICATION_STATUSES)})",
            name="ck_model_provider_configuration_verification",
        ),
        sa.CheckConstraint(
            "length(base_url) > 0 AND length(api_key_ciphertext) > 0 "
            "AND length(default_model) > 0",
            name="ck_model_provider_configuration_required_values",
        ),
        sa.CheckConstraint(
            "monthly_budget_microusd > 0",
            name="ck_model_provider_configuration_monthly_budget",
        ),
        sa.CheckConstraint(
            "per_tenant_daily_token_limit > 0",
            name="ck_model_provider_configuration_tenant_tokens",
        ),
        sa.CheckConstraint("version > 0", name="ck_model_provider_configuration_version"),
    )


class ModelProviderConfigurationReceiptRecord(SaasBase):
    """Append-only, secret-free evidence for managed model configuration actions."""

    __tablename__ = "saas_model_provider_configuration_receipts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    provider_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    configuration_version: Mapped[int] = mapped_column(nullable=False)
    actor_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    configuration_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    api_key_rotated: Mapped[bool] = mapped_column(nullable=False, default=False)
    model_id: Mapped[str | None] = mapped_column(sa.String(128))
    provider_request_id_hash: Mapped[str | None] = mapped_column(sa.String(64))
    latency_millis: Mapped[int | None] = mapped_column()
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint(
            f"provider_id IN ({_values(MODEL_PROVIDER_IDS)})",
            name="ck_model_provider_receipt_provider",
        ),
        sa.CheckConstraint(
            f"action IN ({_values(MODEL_PROVIDER_RECEIPT_ACTIONS)})",
            name="ck_model_provider_receipt_action",
        ),
        sa.CheckConstraint("configuration_version > 0", name="ck_model_provider_receipt_version"),
        sa.CheckConstraint(
            "length(configuration_hash) = 64", name="ck_model_provider_receipt_hash"
        ),
        sa.CheckConstraint(
            "provider_request_id_hash IS NULL OR length(provider_request_id_hash) = 64",
            name="ck_model_provider_receipt_request_hash",
        ),
        sa.CheckConstraint(
            "latency_millis IS NULL OR latency_millis >= 0",
            name="ck_model_provider_receipt_latency",
        ),
        sa.Index(
            "ix_model_provider_receipt_provider_time",
            "provider_id",
            "occurred_at",
            "id",
        ),
    )


class ModelProviderMonthlyBudgetRecord(SaasBase):
    """Serialized Platform-wide monthly spend counter for one Provider."""

    __tablename__ = "saas_model_provider_monthly_budgets"

    provider_id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    period_start: Mapped[date] = mapped_column(sa.Date, primary_key=True)
    reserved_microusd: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    settled_microusd: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint(
            f"provider_id IN ({_values(MODEL_PROVIDER_IDS)})",
            name="ck_model_provider_monthly_budget_provider",
        ),
        sa.CheckConstraint(
            "reserved_microusd >= 0 AND settled_microusd >= 0",
            name="ck_model_provider_monthly_budget_nonnegative",
        ),
        sa.CheckConstraint("version > 0", name="ck_model_provider_monthly_budget_version"),
    )


class ModelProviderTenantDailyUsageRecord(SaasBase):
    """Serialized per-Tenant daily token counter for Platform inference."""

    __tablename__ = "saas_model_provider_tenant_daily_usage"

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    provider_id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    usage_date: Mapped[date] = mapped_column(sa.Date, primary_key=True)
    reserved_tokens: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    settled_tokens: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint(
            f"provider_id IN ({_values(MODEL_PROVIDER_IDS)})",
            name="ck_model_provider_tenant_usage_provider",
        ),
        sa.CheckConstraint(
            "reserved_tokens >= 0 AND settled_tokens >= 0",
            name="ck_model_provider_tenant_usage_nonnegative",
        ),
        sa.CheckConstraint("version > 0", name="ck_model_provider_tenant_usage_version"),
        sa.Index(
            "ix_model_provider_tenant_usage_date",
            "provider_id",
            "usage_date",
            "tenant_id",
        ),
    )


class ModelProviderBudgetReservationRecord(SaasBase):
    """Idempotent reservation/settlement receipt for one managed-model Run."""

    __tablename__ = "saas_model_provider_budget_reservations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    provider_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    operation_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    configuration_version: Mapped[int] = mapped_column(nullable=False)
    period_start: Mapped[date] = mapped_column(sa.Date, nullable=False)
    usage_date: Mapped[date] = mapped_column(sa.Date, nullable=False)
    requested_microusd: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    requested_tokens: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    admitted_microusd: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    admitted_tokens: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    settled_microusd: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    settled_tokens: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    released_microusd: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    released_tokens: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    rejection_code: Mapped[str | None] = mapped_column(sa.String(64))
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False, default=1)

    __table_args__ = (
        sa.CheckConstraint(
            f"provider_id IN ({_values(MODEL_PROVIDER_IDS)})",
            name="ck_model_provider_budget_reservation_provider",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(MODEL_PROVIDER_BUDGET_RESERVATION_STATUSES)})",
            name="ck_model_provider_budget_reservation_status",
        ),
        sa.CheckConstraint(
            "requested_microusd > 0 AND requested_tokens > 0",
            name="ck_model_provider_budget_reservation_request",
        ),
        sa.CheckConstraint(
            "admitted_microusd >= 0 AND admitted_microusd <= requested_microusd "
            "AND admitted_tokens >= 0 AND admitted_tokens <= requested_tokens",
            name="ck_model_provider_budget_reservation_admitted",
        ),
        sa.CheckConstraint(
            "settled_microusd >= 0 AND released_microusd >= 0 "
            "AND settled_tokens >= 0 AND released_tokens >= 0 "
            "AND ((status = 'reserved' AND released_microusd = 0 "
            "AND released_tokens = 0 AND settled_microusd <= admitted_microusd "
            "AND settled_tokens <= admitted_tokens) "
            "OR (status <> 'reserved' "
            "AND settled_microusd + released_microusd = admitted_microusd "
            "AND settled_tokens + released_tokens = admitted_tokens))",
            name="ck_model_provider_budget_reservation_conservation",
        ),
        sa.CheckConstraint(
            "(status = 'reserved' AND admitted_microusd = requested_microusd "
            "AND admitted_tokens = requested_tokens "
            "AND released_microusd = 0 AND released_tokens = 0 "
            "AND rejection_code IS NULL) OR "
            "(status = 'settled' AND settled_microusd > 0 AND settled_tokens > 0 "
            "AND rejection_code IS NULL) OR "
            "(status IN ('released', 'expired') AND admitted_microusd > 0 "
            "AND admitted_tokens > 0 "
            "AND rejection_code IS NULL) OR "
            "(status = 'rejected' AND admitted_microusd = 0 AND admitted_tokens = 0 "
            "AND rejection_code IS NOT NULL)",
            name="ck_model_provider_budget_reservation_state",
        ),
        sa.CheckConstraint(
            "length(operation_key) > 0 AND length(request_hash) = 64",
            name="ck_model_provider_budget_reservation_identity",
        ),
        sa.CheckConstraint(
            "configuration_version > 0 AND version > 0",
            name="ck_model_provider_budget_reservation_version",
        ),
        sa.CheckConstraint(
            "created_at <= updated_at AND created_at < expires_at",
            name="ck_model_provider_budget_reservation_time",
        ),
        sa.UniqueConstraint(
            "provider_id",
            "operation_key",
            name="uq_model_provider_budget_reservation_operation",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_model_provider_budget_reservation_scope",
        ),
        sa.Index(
            "ix_model_provider_budget_reservation_expiry",
            "provider_id",
            "status",
            "expires_at",
            "id",
        ),
        sa.Index(
            "ix_model_provider_budget_reservation_run",
            "tenant_id",
            "run_id",
            "id",
        ),
    )


class PlatformLifecycleOperationRecord(SaasBase):
    """Immutable receipt for one high-risk PC2 platform lifecycle command."""

    __tablename__ = "saas_platform_lifecycle_operations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    actor_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    action: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    approval_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    reason: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    result: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant', 'identity_conflict')",
            name="ck_platform_lifecycle_target_type",
        ),
        sa.CheckConstraint(
            f"action IN ({_values(PLATFORM_OPERATION_ACTIONS)})",
            name="ck_platform_lifecycle_action",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) > 0", name="ck_platform_lifecycle_idempotency_nonempty"
        ),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_platform_lifecycle_request_hash"),
        sa.CheckConstraint(
            "length(approval_ref) > 0", name="ck_platform_lifecycle_approval_nonempty"
        ),
        sa.CheckConstraint("length(reason) > 0", name="ck_platform_lifecycle_reason_nonempty"),
        sa.CheckConstraint(
            "(target_type IN ('global_user', 'identity_conflict') AND tenant_id IS NULL) OR "
            "(target_type = 'tenant' AND tenant_id = target_id)",
            name="ck_platform_lifecycle_target_scope",
        ),
        sa.UniqueConstraint(
            "actor_principal_id",
            "idempotency_key",
            name="uq_platform_lifecycle_actor_idempotency",
        ),
        sa.Index(
            "ix_platform_lifecycle_target",
            "target_type",
            "target_id",
            "occurred_at",
        ),
    )
