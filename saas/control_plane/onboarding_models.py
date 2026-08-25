"""Durable self-service registration and Tenant onboarding authority."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase

SELF_SERVICE_REGISTRATION_STATUSES = (
    "pending_verification",
    "suppressed",
    "verified",
    "expired",
    "revoked",
)
EMAIL_VERIFICATION_CHALLENGE_STATUSES = (
    "pending",
    "consumed",
    "expired",
    "revoked",
)
EMAIL_VERIFICATION_DELIVERY_STATUSES = (
    "pending",
    "sent",
    "failed",
    "suppressed",
)
TENANT_ONBOARDING_STATUSES = (
    "tenant_created",
    "billing_ready",
    "runtime_ready",
    "project_ready",
    "active",
    "completed",
    "compensating",
    "compensated",
    "manual_review",
)
SELF_SERVICE_EVENT_AGGREGATE_TYPES = ("registration", "tenant_onboarding")
REGISTRATION_RATE_LIMIT_ACTIONS = (
    "registration.request",
    "registration.resend",
    "registration.verify",
)
REGISTRATION_RATE_LIMIT_SUBJECT_KINDS = ("email", "registration")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _lower_hex_64(column: str) -> str:
    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {column} = lower({column}) AND {remainder} = ''"


class SelfServiceRegistrationRecord(SaasBase):
    """Verified product intent and preallocated IDs; never stores a password or token."""

    __tablename__ = "saas_self_service_registrations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email_normalized: Mapped[str] = mapped_column(sa.String(320), nullable=False)
    email_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.String(256))
    tenant_name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    tenant_slug: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    default_space_name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    default_space_slug: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    plan_key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    plan_policy_revision: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    home_region: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(32), nullable=False, default="pending_verification"
    )
    challenge_generation: Mapped[int] = mapped_column(nullable=False, default=1)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    terminal_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    user_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    space_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    subscription_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    pricing_snapshot_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    entitlement_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    runtime_partition_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    default_project_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    runtime_binding_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    plan_snapshot: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    plan_snapshot_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    onboarding_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4, unique=True)
    idempotency_key: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    deletion_manifest_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_manifests.id", ondelete="RESTRICT"),
        server_default=sa.text("NULL"),
    )
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
            f"status IN ({_values(SELF_SERVICE_REGISTRATION_STATUSES)})",
            name="ck_self_service_registration_status",
        ),
        sa.CheckConstraint("length(email_hash) = 64", name="ck_self_service_email_hash"),
        sa.CheckConstraint("length(idempotency_key) = 64", name="ck_self_service_idempotency_key"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_self_service_request_hash"),
        sa.CheckConstraint(
            "deletion_manifest_id IS NULL OR status = 'revoked'",
            name="ck_self_service_registration_deletion_manifest",
        ),
        sa.CheckConstraint(
            "length(tenant_name) BETWEEN 1 AND 256",
            name="ck_self_service_tenant_name",
        ),
        sa.CheckConstraint(
            "length(tenant_slug) BETWEEN 1 AND 128 AND tenant_slug = lower(tenant_slug)",
            name="ck_self_service_tenant_slug",
        ),
        sa.CheckConstraint(
            "length(default_space_name) BETWEEN 1 AND 256",
            name="ck_self_service_space_name",
        ),
        sa.CheckConstraint(
            "length(default_space_slug) BETWEEN 1 AND 128 "
            "AND default_space_slug = lower(default_space_slug)",
            name="ck_self_service_space_slug",
        ),
        sa.CheckConstraint("length(plan_key) BETWEEN 1 AND 64", name="ck_self_service_plan_key"),
        sa.CheckConstraint(
            "length(plan_policy_revision) BETWEEN 1 AND 128",
            name="ck_self_service_plan_policy_revision",
        ),
        sa.CheckConstraint(
            "length(CAST(plan_snapshot AS TEXT)) > 2",
            name="ck_self_service_plan_snapshot_nonempty",
        ),
        sa.CheckConstraint(
            "length(plan_snapshot_hash) = 64",
            name="ck_self_service_plan_snapshot_hash",
        ),
        sa.CheckConstraint(
            "length(home_region) BETWEEN 1 AND 64", name="ck_self_service_home_region"
        ),
        sa.CheckConstraint(
            "challenge_generation > 0", name="ck_self_service_challenge_generation"
        ),
        sa.CheckConstraint("version > 0", name="ck_self_service_version"),
        sa.CheckConstraint("expires_at > created_at", name="ck_self_service_expiry"),
        sa.CheckConstraint(
            "(status = 'pending_verification' AND verified_at IS NULL "
            "AND terminal_at IS NULL) OR "
            "(status = 'verified' AND verified_at IS NOT NULL "
            "AND terminal_at = verified_at) OR "
            "(status IN ('suppressed', 'expired', 'revoked') "
            "AND verified_at IS NULL AND terminal_at IS NOT NULL)",
            name="ck_self_service_terminal_state",
        ),
        sa.UniqueConstraint("user_id", name="uq_self_service_registration_user"),
        sa.UniqueConstraint("tenant_id", name="uq_self_service_registration_tenant"),
        sa.UniqueConstraint("space_id", name="uq_self_service_registration_space"),
        sa.UniqueConstraint("subscription_id", name="uq_self_service_registration_subscription"),
        sa.UniqueConstraint(
            "pricing_snapshot_id", name="uq_self_service_registration_pricing_snapshot"
        ),
        sa.UniqueConstraint("entitlement_id", name="uq_self_service_registration_entitlement"),
        sa.UniqueConstraint("runtime_partition_id", name="uq_self_service_registration_partition"),
        sa.UniqueConstraint("default_project_id", name="uq_self_service_registration_project"),
        sa.UniqueConstraint(
            "runtime_binding_id", name="uq_self_service_registration_runtime_binding"
        ),
        sa.UniqueConstraint(
            "id", "onboarding_id", name="uq_self_service_registration_onboarding_scope"
        ),
        sa.Index(
            "uq_open_self_service_email",
            "email_hash",
            unique=True,
            sqlite_where=sa.text("status IN ('pending_verification', 'suppressed', 'verified')"),
            postgresql_where=sa.text(
                "status IN ('pending_verification', 'suppressed', 'verified')"
            ),
        ),
        sa.Index(
            "uq_open_self_service_tenant_slug",
            "tenant_slug",
            unique=True,
            sqlite_where=sa.text("status IN ('pending_verification', 'verified')"),
            postgresql_where=sa.text("status IN ('pending_verification', 'verified')"),
        ),
        sa.Index("ix_self_service_registration_expiry", "status", "expires_at"),
    )


class RegistrationRateLimitPolicyRecord(SaasBase):
    """Database-owned limits, retention, and bounded counter capacity."""

    __tablename__ = "saas_registration_rate_limit_policies"

    action: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    subject_kind: Mapped[str] = mapped_column(sa.String(32), primary_key=True)
    limit_count: Mapped[int] = mapped_column(nullable=False)
    window_seconds: Mapped[int] = mapped_column(nullable=False)
    retention_seconds: Mapped[int] = mapped_column(nullable=False)
    max_rows: Mapped[int] = mapped_column(nullable=False)
    current_rows: Mapped[int] = mapped_column(nullable=False, default=0)
    policy_revision: Mapped[str] = mapped_column(sa.String(128), nullable=False)
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
            f"action IN ({_values(REGISTRATION_RATE_LIMIT_ACTIONS)})",
            name="ck_registration_rate_limit_policy_action",
        ),
        sa.CheckConstraint(
            f"subject_kind IN ({_values(REGISTRATION_RATE_LIMIT_SUBJECT_KINDS)})",
            name="ck_registration_rate_limit_policy_subject_kind",
        ),
        sa.CheckConstraint(
            "limit_count BETWEEN 1 AND 1000",
            name="ck_registration_rate_limit_policy_limit",
        ),
        sa.CheckConstraint(
            "window_seconds BETWEEN 60 AND 86400",
            name="ck_registration_rate_limit_policy_window",
        ),
        sa.CheckConstraint(
            "retention_seconds BETWEEN window_seconds AND 604800",
            name="ck_registration_rate_limit_policy_retention",
        ),
        sa.CheckConstraint(
            "max_rows BETWEEN 1 AND 10000000",
            name="ck_registration_rate_limit_policy_max_rows",
        ),
        sa.CheckConstraint(
            "current_rows BETWEEN 0 AND max_rows",
            name="ck_registration_rate_limit_policy_current_rows",
        ),
        sa.CheckConstraint(
            "length(policy_revision) BETWEEN 1 AND 128",
            name="ck_registration_rate_limit_policy_revision",
        ),
    )


class RegistrationRateLimitRecord(SaasBase):
    """Keyed, expiring abuse counter shared by registration replicas."""

    __tablename__ = "saas_registration_rate_limits"

    action: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    subject_kind: Mapped[str] = mapped_column(sa.String(32), primary_key=True)
    key_id: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    subject_hmac: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    window_started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    request_count: Mapped[int] = mapped_column(nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    policy_revision: Mapped[str] = mapped_column(sa.String(128), nullable=False)
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
            f"action IN ({_values(REGISTRATION_RATE_LIMIT_ACTIONS)})",
            name="ck_registration_rate_limit_action",
        ),
        sa.CheckConstraint(
            f"subject_kind IN ({_values(REGISTRATION_RATE_LIMIT_SUBJECT_KINDS)})",
            name="ck_registration_rate_limit_subject_kind",
        ),
        sa.CheckConstraint(
            "length(key_id) BETWEEN 1 AND 64",
            name="ck_registration_rate_limit_key_id",
        ),
        sa.CheckConstraint(
            _lower_hex_64("subject_hmac"),
            name="ck_registration_rate_limit_subject_hmac",
        ),
        sa.CheckConstraint("request_count > 0", name="ck_registration_rate_limit_count"),
        sa.CheckConstraint(
            "expires_at > window_started_at",
            name="ck_registration_rate_limit_expiry",
        ),
        sa.CheckConstraint(
            "length(policy_revision) BETWEEN 1 AND 128",
            name="ck_registration_rate_limit_revision",
        ),
        sa.CheckConstraint("version > 0", name="ck_registration_rate_limit_version"),
        sa.ForeignKeyConstraint(
            ["action", "subject_kind"],
            [
                "saas_registration_rate_limit_policies.action",
                "saas_registration_rate_limit_policies.subject_kind",
            ],
            name="fk_registration_rate_limit_policy",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.Index(
            "ix_registration_rate_limit_expiry",
            "action",
            "subject_kind",
            "expires_at",
        ),
    )


class EmailVerificationChallengeRecord(SaasBase):
    """Hash-only, single-use verification challenge with independent delivery state."""

    __tablename__ = "saas_email_verification_challenges"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    registration_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_self_service_registrations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    generation: Mapped[int] = mapped_column(nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    delivery_status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    delivery_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    delivery_idempotency_key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    last_delivery_error_code: Mapped[str | None] = mapped_column(sa.String(128))
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    expired_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            f"status IN ({_values(EMAIL_VERIFICATION_CHALLENGE_STATUSES)})",
            name="ck_email_verification_challenge_status",
        ),
        sa.CheckConstraint(
            f"delivery_status IN ({_values(EMAIL_VERIFICATION_DELIVERY_STATUSES)})",
            name="ck_email_verification_delivery_status",
        ),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_email_challenge_token_hash"),
        sa.CheckConstraint(
            "length(delivery_idempotency_key) = 64",
            name="ck_email_verification_delivery_key",
        ),
        sa.CheckConstraint("generation > 0", name="ck_email_verification_generation"),
        sa.CheckConstraint(
            "delivery_attempts >= 0", name="ck_email_verification_delivery_attempts"
        ),
        sa.CheckConstraint("expires_at > created_at", name="ck_email_verification_expiry"),
        sa.CheckConstraint(
            "(status = 'pending' AND consumed_at IS NULL AND expired_at IS NULL "
            "AND revoked_at IS NULL) OR "
            "(status = 'consumed' AND consumed_at IS NOT NULL AND expired_at IS NULL "
            "AND revoked_at IS NULL) OR "
            "(status = 'expired' AND consumed_at IS NULL AND expired_at IS NOT NULL "
            "AND revoked_at IS NULL) OR "
            "(status = 'revoked' AND consumed_at IS NULL AND expired_at IS NULL "
            "AND revoked_at IS NOT NULL)",
            name="ck_email_verification_terminal_state",
        ),
        sa.CheckConstraint(
            "(delivery_status = 'sent' AND delivered_at IS NOT NULL) OR "
            "(delivery_status <> 'sent' AND delivered_at IS NULL)",
            name="ck_email_verification_delivery_result",
        ),
        sa.UniqueConstraint(
            "registration_id", "generation", name="uq_email_verification_generation"
        ),
        sa.UniqueConstraint(
            "registration_id",
            "delivery_idempotency_key",
            name="uq_email_verification_delivery_key",
        ),
        sa.Index(
            "uq_pending_email_verification_challenge",
            "registration_id",
            unique=True,
            sqlite_where=sa.text("status = 'pending'"),
            postgresql_where=sa.text("status = 'pending'"),
        ),
        sa.Index("ix_email_verification_expiry", "status", "expires_at"),
    )


class TenantOnboardingRecord(SaasBase):
    """Durable Saga between local Tenant creation, Billing, and Runtime provisioning."""

    __tablename__ = "saas_tenant_onboardings"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    registration_id: Mapped[UUID] = mapped_column(nullable=False, unique=True)
    user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    subscription_id: Mapped[UUID] = mapped_column(nullable=False)
    pricing_snapshot_id: Mapped[UUID] = mapped_column(nullable=False)
    entitlement_id: Mapped[UUID] = mapped_column(nullable=False)
    runtime_partition_id: Mapped[UUID] = mapped_column(nullable=False)
    runtime_placement_id: Mapped[UUID | None] = mapped_column()
    runtime_target_snapshot: Mapped[dict[str, object] | None] = mapped_column(sa.JSON)
    runtime_request_hash: Mapped[str | None] = mapped_column(sa.String(64))
    default_project_id: Mapped[UUID] = mapped_column(nullable=False)
    runtime_binding_id: Mapped[UUID] = mapped_column(nullable=False)
    plan_key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    plan_policy_revision: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    plan_snapshot: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    plan_snapshot_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    home_region: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    trial_days: Mapped[int] = mapped_column(nullable=False)
    trial_started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    trial_ends_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="tenant_created")
    idempotency_key: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    claim_token: Mapped[UUID | None] = mapped_column()
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(sa.String(128))
    last_error_detail: Mapped[str | None] = mapped_column(sa.String(2048))
    billing_ready_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    runtime_ready_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    project_ready_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    first_run_id: Mapped[UUID | None] = mapped_column()
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    failure_stage: Mapped[str | None] = mapped_column(sa.String(64))
    compensation_cursor: Mapped[str | None] = mapped_column(sa.String(64))
    compensated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_transition_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
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
        sa.ForeignKeyConstraint(
            ("registration_id", "id"),
            (
                "saas_self_service_registrations.id",
                "saas_self_service_registrations.onboarding_id",
            ),
            ondelete="RESTRICT",
            name="fk_tenant_onboarding_preallocated_id",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_tenant_onboarding_space",
        ),
        sa.ForeignKeyConstraint(
            ("runtime_placement_id",),
            ("saas_runtime_placements.id",),
            ondelete="RESTRICT",
            name="fk_tenant_onboarding_runtime_placement",
        ),
        sa.ForeignKeyConstraint(
            ("first_run_id", "tenant_id", "space_id", "default_project_id"),
            (
                "saas_runs.id",
                "saas_runs.tenant_id",
                "saas_runs.space_id",
                "saas_runs.project_id",
            ),
            ondelete="RESTRICT",
            name="fk_tenant_onboarding_first_run_scope",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(TENANT_ONBOARDING_STATUSES)})",
            name="ck_tenant_onboarding_status",
        ),
        sa.CheckConstraint(
            "length(plan_key) BETWEEN 1 AND 64", name="ck_tenant_onboarding_plan_key"
        ),
        sa.CheckConstraint(
            "length(plan_policy_revision) BETWEEN 1 AND 128",
            name="ck_tenant_onboarding_plan_policy_revision",
        ),
        sa.CheckConstraint(
            "length(CAST(plan_snapshot AS TEXT)) > 2",
            name="ck_tenant_onboarding_plan_snapshot_nonempty",
        ),
        sa.CheckConstraint(
            "length(plan_snapshot_hash) = 64",
            name="ck_tenant_onboarding_plan_snapshot_hash",
        ),
        sa.CheckConstraint(
            "length(home_region) BETWEEN 1 AND 64", name="ck_tenant_onboarding_region"
        ),
        sa.CheckConstraint(
            "trial_days BETWEEN 1 AND 90 AND "
            "((trial_started_at IS NULL AND trial_ends_at IS NULL) OR "
            "(trial_started_at IS NOT NULL AND trial_ends_at > trial_started_at))",
            name="ck_tenant_onboarding_trial",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) = 64", name="ck_tenant_onboarding_idempotency_key"
        ),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_tenant_onboarding_request_hash"),
        sa.CheckConstraint("version > 0", name="ck_tenant_onboarding_version"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_tenant_onboarding_attempts"),
        sa.CheckConstraint(
            "(runtime_placement_id IS NULL AND runtime_target_snapshot IS NULL "
            "AND runtime_request_hash IS NULL) OR "
            "(runtime_placement_id IS NOT NULL "
            "AND runtime_target_snapshot IS NOT NULL "
            "AND runtime_request_hash IS NOT NULL "
            "AND length(CAST(runtime_target_snapshot AS TEXT)) > 2 "
            "AND length(runtime_request_hash) = 64)",
            name="ck_tenant_onboarding_runtime_request",
        ),
        sa.CheckConstraint(
            "status <> 'tenant_created' OR runtime_placement_id IS NULL",
            name="ck_tenant_onboarding_initial_placement",
        ),
        sa.CheckConstraint(
            "status NOT IN ('runtime_ready', 'project_ready', 'active', 'completed') OR "
            "runtime_placement_id IS NOT NULL",
            name="ck_tenant_onboarding_ready_placement",
        ),
        sa.CheckConstraint(
            "failure_stage IS NULL OR failure_stage IN "
            "('tenant_created', 'billing_ready', 'runtime_ready', 'project_ready', "
            "'active', 'legacy_billing_ready', 'legacy_runtime_ready', 'legacy_active')",
            name="ck_tenant_onboarding_failure_stage",
        ),
        sa.CheckConstraint(
            "compensation_cursor IS NULL OR compensation_cursor IN "
            "('project', 'runtime', 'billing')",
            name="ck_tenant_onboarding_compensation_cursor",
        ),
        sa.CheckConstraint(
            "(claim_token IS NULL AND claimed_at IS NULL AND lease_expires_at IS NULL) OR "
            "(claim_token IS NOT NULL AND claimed_at IS NOT NULL "
            "AND lease_expires_at > claimed_at)",
            name="ck_tenant_onboarding_lease",
        ),
        sa.CheckConstraint(
            "(status = 'tenant_created' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NULL "
            "AND runtime_ready_at IS NULL AND project_ready_at IS NULL "
            "AND activated_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'billing_ready' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NULL AND project_ready_at IS NULL "
            "AND activated_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'runtime_ready' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND project_ready_at IS NULL "
            "AND activated_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'project_ready' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND project_ready_at IS NOT NULL "
            "AND activated_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'active' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND project_ready_at IS NOT NULL "
            "AND activated_at IS NOT NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'completed' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND project_ready_at IS NOT NULL "
            "AND activated_at IS NOT NULL AND first_run_id IS NOT NULL "
            "AND completed_at IS NOT NULL AND completed_at >= activated_at "
            "AND compensated_at IS NULL) OR "
            "(status = 'compensating' AND activated_at IS NULL "
            "AND first_run_id IS NULL AND completed_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'manual_review' AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'compensated' AND activated_at IS NULL "
            "AND first_run_id IS NULL AND completed_at IS NULL "
            "AND compensated_at IS NOT NULL)",
            name="ck_tenant_onboarding_state_evidence",
        ),
        sa.CheckConstraint(
            "(status IN ('tenant_created', 'billing_ready', 'runtime_ready', "
            "'project_ready', 'active', 'completed') "
            "AND failure_stage IS NULL AND compensation_cursor IS NULL) OR "
            "(status IN ('compensating', 'manual_review') "
            "AND failure_stage IS NOT NULL AND compensation_cursor IS NOT NULL) OR "
            "(status = 'compensated' AND failure_stage IS NOT NULL "
            "AND compensation_cursor IS NULL)",
            name="ck_tenant_onboarding_failure_evidence",
        ),
        sa.UniqueConstraint("tenant_id", name="uq_tenant_onboarding_tenant"),
        sa.UniqueConstraint("space_id", name="uq_tenant_onboarding_space"),
        sa.UniqueConstraint("subscription_id", name="uq_tenant_onboarding_subscription"),
        sa.UniqueConstraint("pricing_snapshot_id", name="uq_tenant_onboarding_pricing_snapshot"),
        sa.UniqueConstraint("entitlement_id", name="uq_tenant_onboarding_entitlement"),
        sa.UniqueConstraint("runtime_partition_id", name="uq_tenant_onboarding_runtime_partition"),
        sa.UniqueConstraint("default_project_id", name="uq_tenant_onboarding_default_project"),
        sa.UniqueConstraint("runtime_binding_id", name="uq_tenant_onboarding_runtime_binding"),
        sa.UniqueConstraint("first_run_id", name="uq_tenant_onboarding_first_run"),
        sa.Index("ix_tenant_onboarding_dispatch", "status", "available_at", "claimed_at"),
        sa.Index("ix_tenant_onboarding_user", "user_id", "created_at"),
    )


class SelfServiceEventRecord(SaasBase):
    """Append-only, hash-linked, PII-free evidence for registration and onboarding."""

    __tablename__ = "saas_self_service_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    aggregate_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    aggregate_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID | None] = mapped_column()
    user_id: Mapped[UUID | None] = mapped_column()
    sequence: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    from_status: Mapped[str | None] = mapped_column(sa.String(32))
    to_status: Mapped[str | None] = mapped_column(sa.String(32))
    facts: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    facts_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    previous_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"aggregate_type IN ({_values(SELF_SERVICE_EVENT_AGGREGATE_TYPES)})",
            name="ck_self_service_event_aggregate_type",
        ),
        sa.CheckConstraint("sequence > 0", name="ck_self_service_event_sequence"),
        sa.CheckConstraint(
            "length(event_type) BETWEEN 1 AND 128", name="ck_self_service_event_type"
        ),
        sa.CheckConstraint(
            "(from_status IS NULL AND to_status IS NULL) OR "
            "(from_status IS NOT NULL AND to_status IS NOT NULL)",
            name="ck_self_service_event_transition",
        ),
        sa.CheckConstraint("length(facts_hash) = 64", name="ck_self_service_event_facts_hash"),
        sa.CheckConstraint(
            "length(previous_hash) = 64", name="ck_self_service_event_previous_hash"
        ),
        sa.CheckConstraint("length(event_hash) = 64", name="ck_self_service_event_hash"),
        sa.UniqueConstraint(
            "aggregate_type",
            "aggregate_id",
            "sequence",
            name="uq_self_service_event_sequence",
        ),
        sa.Index("ix_self_service_event_replay", "aggregate_type", "aggregate_id", "sequence"),
        sa.Index("ix_self_service_event_tenant", "tenant_id", "occurred_at"),
        sa.Index("ix_self_service_event_user", "user_id", "occurred_at"),
    )


__all__ = [
    "EMAIL_VERIFICATION_CHALLENGE_STATUSES",
    "EMAIL_VERIFICATION_DELIVERY_STATUSES",
    "SELF_SERVICE_EVENT_AGGREGATE_TYPES",
    "SELF_SERVICE_REGISTRATION_STATUSES",
    "TENANT_ONBOARDING_STATUSES",
    "EmailVerificationChallengeRecord",
    "SelfServiceEventRecord",
    "SelfServiceRegistrationRecord",
    "TenantOnboardingRecord",
]
