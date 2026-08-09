"""P5 durable outbound Webhook authority records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase

WEBHOOK_ENDPOINT_STATUSES = ("active", "disabled", "deleted")
WEBHOOK_DELIVERY_STATUSES = ("pending", "leased", "retry", "delivered", "dead_letter")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(repr(value) for value in values)


class WebhookEndpointRecord(SaasBase):
    """Tenant-owned endpoint metadata; signing material remains behind a Secret provider."""

    __tablename__ = "saas_webhook_endpoints"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    space_id: Mapped[UUID | None] = mapped_column()
    project_id: Mapped[UUID | None] = mapped_column()
    canonical_url: Mapped[str] = mapped_column(sa.String(2048), nullable=False)
    event_types: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    secret_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    active_secret_version: Mapped[int] = mapped_column(nullable=False)
    previous_secret_version: Mapped[int | None] = mapped_column()
    previous_secret_valid_until: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True)
    )
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    security_version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
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
        sa.UniqueConstraint("tenant_id", "id", name="uq_webhook_endpoint_tenant_id"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_webhook_endpoint_space",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            ondelete="RESTRICT",
            name="fk_webhook_endpoint_project",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(WEBHOOK_ENDPOINT_STATUSES)})",
            name="ck_webhook_endpoint_status",
        ),
        sa.CheckConstraint(
            "project_id IS NULL OR space_id IS NOT NULL",
            name="ck_webhook_endpoint_project_scope",
        ),
        sa.CheckConstraint(
            "length(canonical_url) BETWEEN 1 AND 2048",
            name="ck_webhook_endpoint_url",
        ),
        sa.CheckConstraint(
            "length(secret_ref) BETWEEN 1 AND 256",
            name="ck_webhook_endpoint_secret_ref",
        ),
        sa.CheckConstraint(
            "active_secret_version > 0 AND security_version > 0",
            name="ck_webhook_endpoint_versions",
        ),
        sa.CheckConstraint(
            "(previous_secret_version IS NULL AND previous_secret_valid_until IS NULL) OR "
            "(previous_secret_version IS NOT NULL AND previous_secret_version > 0 "
            "AND previous_secret_version <> active_secret_version "
            "AND previous_secret_valid_until IS NOT NULL)",
            name="ck_webhook_endpoint_rotation",
        ),
        sa.Index(
            "uq_active_webhook_endpoint_url",
            "tenant_id",
            "canonical_url",
            unique=True,
            sqlite_where=sa.text("status = 'active'"),
            postgresql_where=sa.text("status = 'active'"),
        ),
        sa.Index("ix_webhook_endpoint_scope", "tenant_id", "space_id", "project_id"),
    )


class WebhookDeliveryRecord(SaasBase):
    """Immutable event projection plus monotonic delivery lease and result state."""

    __tablename__ = "saas_webhook_deliveries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    endpoint_id: Mapped[UUID] = mapped_column(nullable=False)
    event_id: Mapped[UUID] = mapped_column(nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    event_version: Mapped[int] = mapped_column(nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(nullable=False, default=8)
    available_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    leased_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    lease_token_hash: Mapped[str | None] = mapped_column(sa.String(64))
    delivered_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    response_status: Mapped[int | None] = mapped_column()
    response_digest_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    last_error_code: Mapped[str | None] = mapped_column(sa.String(128))
    replay_generation: Mapped[int] = mapped_column(nullable=False, default=0)
    last_replayed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_replayed_by: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
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
            ("tenant_id", "endpoint_id"),
            ("saas_webhook_endpoints.tenant_id", "saas_webhook_endpoints.id"),
            ondelete="RESTRICT",
            name="fk_webhook_delivery_endpoint",
        ),
        sa.UniqueConstraint("endpoint_id", "event_id", name="uq_webhook_delivery_event"),
        sa.CheckConstraint(
            f"status IN ({_values(WEBHOOK_DELIVERY_STATUSES)})",
            name="ck_webhook_delivery_status",
        ),
        sa.CheckConstraint(
            "length(event_type) BETWEEN 1 AND 128 AND event_version > 0",
            name="ck_webhook_delivery_event",
        ),
        sa.CheckConstraint(
            "length(payload_sha256) = 64",
            name="ck_webhook_delivery_payload_hash",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 32 "
            "AND attempt_count <= max_attempts",
            name="ck_webhook_delivery_attempts",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND leased_at IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND lease_token_hash IS NOT NULL) OR "
            "(status <> 'leased' AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hash IS NULL)",
            name="ck_webhook_delivery_lease",
        ),
        sa.CheckConstraint(
            "(status = 'delivered' AND delivered_at IS NOT NULL "
            "AND response_status BETWEEN 200 AND 299 AND response_digest_sha256 IS NOT NULL) OR "
            "(status <> 'delivered' AND delivered_at IS NULL)",
            name="ck_webhook_delivery_result",
        ),
        sa.CheckConstraint(
            "response_digest_sha256 IS NULL OR length(response_digest_sha256) = 64",
            name="ck_webhook_delivery_response_hash",
        ),
        sa.CheckConstraint(
            "lease_token_hash IS NULL OR length(lease_token_hash) = 64",
            name="ck_webhook_delivery_lease_hash",
        ),
        sa.CheckConstraint(
            "(replay_generation = 0 AND last_replayed_at IS NULL "
            "AND last_replayed_by IS NULL) OR "
            "(replay_generation > 0 AND last_replayed_at IS NOT NULL "
            "AND last_replayed_by IS NOT NULL)",
            name="ck_webhook_delivery_replay",
        ),
        sa.Index(
            "ix_webhook_delivery_dispatch",
            "status",
            "available_at",
            "created_at",
        ),
        sa.Index("ix_webhook_delivery_tenant", "tenant_id", "created_at"),
    )


__all__ = [
    "WEBHOOK_DELIVERY_STATUSES",
    "WEBHOOK_ENDPOINT_STATUSES",
    "WebhookDeliveryRecord",
    "WebhookEndpointRecord",
]
