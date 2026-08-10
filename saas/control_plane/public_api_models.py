"""Durable receipts owned by the stable public API contract."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase


class PublicApiMutationReceiptRecord(SaasBase):
    """Secret-free idempotency receipt for mutable machine operations."""

    __tablename__ = "saas_public_api_mutation_receipts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    service_account_id: Mapped[UUID] = mapped_column(nullable=False)
    credential_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_api_credentials.id", ondelete="RESTRICT"), nullable=False
    )
    operation: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    idempotency_key_id: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    idempotency_hmac: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    resource_id: Mapped[UUID] = mapped_column(nullable=False)
    response_json: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_public_api_receipt_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "service_account_id"),
            ("saas_service_accounts.tenant_id", "saas_service_accounts.id"),
            name="fk_public_api_receipt_service_account",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("length(operation) > 0", name="ck_public_api_receipt_operation"),
        sa.CheckConstraint("length(idempotency_key_id) > 0", name="ck_public_api_receipt_key_id"),
        sa.CheckConstraint(
            "length(idempotency_hmac) = 64", name="ck_public_api_receipt_idempotency"
        ),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_public_api_receipt_request_hash"),
        sa.CheckConstraint(
            "length(resource_type) > 0", name="ck_public_api_receipt_resource_type"
        ),
        sa.UniqueConstraint(
            "credential_id",
            "operation",
            "idempotency_key_id",
            "idempotency_hmac",
            name="uq_public_api_receipt_idempotency",
        ),
        sa.Index(
            "ix_public_api_receipt_resource",
            "tenant_id",
            "space_id",
            "project_id",
            "resource_type",
            "resource_id",
        ),
    )


class PublicApiRateLimitRecord(SaasBase):
    """Database-authoritative fixed-window counter shared by every API replica."""

    __tablename__ = "saas_public_api_rate_limits"

    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    credential_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_api_credentials.id", ondelete="CASCADE"), primary_key=True
    )
    route_class: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    window_started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    request_count: Mapped[int] = mapped_column(nullable=False)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint("length(route_class) > 0", name="ck_public_api_rate_route"),
        sa.CheckConstraint("request_count > 0", name="ck_public_api_rate_count"),
        sa.CheckConstraint("version > 0", name="ck_public_api_rate_version"),
        sa.Index(
            "ix_public_api_rate_tenant_window",
            "tenant_id",
            "window_started_at",
        ),
    )
