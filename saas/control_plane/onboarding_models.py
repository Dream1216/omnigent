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
    "active",
    "compensating",
    "compensated",
    "manual_review",
)
SELF_SERVICE_EVENT_AGGREGATE_TYPES = ("registration", "tenant_onboarding")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


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
    runtime_partition_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    onboarding_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4, unique=True)
    idempotency_key: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
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
        sa.UniqueConstraint("runtime_partition_id", name="uq_self_service_registration_partition"),
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
    runtime_partition_id: Mapped[UUID] = mapped_column(nullable=False)
    plan_key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    plan_policy_revision: Mapped[str] = mapped_column(sa.String(128), nullable=False)
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
    activated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            "(claim_token IS NULL AND claimed_at IS NULL AND lease_expires_at IS NULL) OR "
            "(claim_token IS NOT NULL AND claimed_at IS NOT NULL "
            "AND lease_expires_at > claimed_at)",
            name="ck_tenant_onboarding_lease",
        ),
        sa.CheckConstraint(
            "(status = 'tenant_created' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NULL "
            "AND runtime_ready_at IS NULL AND activated_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'billing_ready' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NULL AND activated_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'runtime_ready' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND activated_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'active' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND activated_at IS NOT NULL "
            "AND compensated_at IS NULL) OR "
            "(status IN ('compensating', 'manual_review') AND activated_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'compensated' AND activated_at IS NULL "
            "AND compensated_at IS NOT NULL)",
            name="ck_tenant_onboarding_state_evidence",
        ),
        sa.UniqueConstraint("tenant_id", name="uq_tenant_onboarding_tenant"),
        sa.UniqueConstraint("space_id", name="uq_tenant_onboarding_space"),
        sa.UniqueConstraint("subscription_id", name="uq_tenant_onboarding_subscription"),
        sa.UniqueConstraint("runtime_partition_id", name="uq_tenant_onboarding_runtime_partition"),
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
