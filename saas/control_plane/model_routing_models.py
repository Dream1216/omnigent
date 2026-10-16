"""Platform-owned connections, immutable credentials, and projection receipts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _hex64


class ModelConnectionRecord(SaasBase):
    __tablename__ = "saas_model_connections"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    display_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    provider_id: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    base_url: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False)
    credential_generation: Mapped[int] = mapped_column(nullable=False)
    updated_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("provider_id = 'deepseek'", name="ck_model_connection_provider"),
        sa.CheckConstraint(
            "base_url = 'https://api.deepseek.com'", name="ck_model_connection_url"
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 128", name="ck_model_connection_name"
        ),
        sa.CheckConstraint(
            "version > 0 AND credential_generation > 0", name="ck_model_connection_version"
        ),
    )


class ModelCredentialVersionRecord(SaasBase):
    """Append-only canonical secret; no plaintext or public fingerprint."""

    __tablename__ = "saas_model_credential_versions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    connection_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_model_connections.id", ondelete="RESTRICT"), nullable=False
    )
    generation: Mapped[int] = mapped_column(nullable=False)
    credential_name: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    api_key_ciphertext: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    created_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("connection_id", "generation", name="uq_model_credential_generation"),
        sa.UniqueConstraint("connection_id", "id", name="uq_model_credential_connection"),
        sa.CheckConstraint("generation > 0", name="ck_model_credential_generation"),
        sa.CheckConstraint(
            "length(api_key_ciphertext) > 0", name="ck_model_credential_ciphertext"
        ),
        sa.CheckConstraint(
            "length(credential_name) BETWEEN 1 AND 128", name="ck_model_credential_name"
        ),
    )


class ModelProjectionOperationRecord(SaasBase):
    """Durable admission; external completion is never inferred from a conflict."""

    __tablename__ = "saas_model_projection_operations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    connection_id: Mapped[UUID] = mapped_column(nullable=False)
    credential_version_id: Mapped[UUID] = mapped_column(nullable=False)
    action: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    actor_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    version: Mapped[int] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["connection_id", "credential_version_id"],
            ["saas_model_credential_versions.connection_id", "saas_model_credential_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "actor_principal_id", "idempotency_key", name="uq_model_projection_idempotency"
        ),
        sa.CheckConstraint(
            "action IN ('create_connection', 'rotate_credential')",
            name="ck_model_projection_action",
        ),
        sa.CheckConstraint(
            "status IN ('requested', 'applying', 'applied', 'verified', 'failed', 'uncertain')",
            name="ck_model_projection_status",
        ),
        sa.CheckConstraint(_hex64("request_hash"), name="ck_model_projection_request_hash"),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 128", name="ck_model_projection_idempotency"
        ),
        sa.CheckConstraint("version > 0", name="ck_model_projection_version"),
        sa.Index("ix_model_projection_status", "status", "created_at"),
    )


class ModelProjectionTransitionRecord(SaasBase):
    """Append-only domain receipt written with its operation's state change."""

    __tablename__ = "saas_model_projection_transitions"

    operation_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_model_projection_operations.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    version: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_control_plane_outbox.id", ondelete="RESTRICT"),
        nullable=False,
    )
    actor_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    previous_status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("version > 1", name="ck_model_projection_transition_version"),
        sa.CheckConstraint(
            "(previous_status = 'requested' AND status IN ('applying', 'failed')) OR "
            "(previous_status = 'applying' AND status IN ('applied', 'failed', 'uncertain'))",
            name="ck_model_projection_transition_edge",
        ),
    )
