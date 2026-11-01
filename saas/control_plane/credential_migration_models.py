"""Durable identity migration claims and hash-only provider receipts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _hex64

MIGRATION_RECEIPT_STATUSES = (
    "pending",
    "imported",
    "completed",
    "conflict",
    "failed",
    "recovered",
)
MIGRATION_IMMUTABLE_COLUMNS = (
    "id",
    "user_id",
    "batch_id",
    "issuer",
    "organization",
    "provider_subject",
    "provider_username",
    "source_password_version",
    "source_security_version",
    "source_password_sha256",
    "source_email_sha256",
    "policy_sha256",
    "idempotency_key",
    "request_hash",
    "created_at",
)


class CredentialMigrationRecord(SaasBase):
    """A resumable claim binds one exact source credential to one provider subject."""

    __tablename__ = "saas_credential_migration_receipts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    batch_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    issuer: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    organization: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    provider_subject: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    provider_username: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    source_password_version: Mapped[int] = mapped_column(nullable=False)
    source_security_version: Mapped[int] = mapped_column(nullable=False)
    source_password_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_email_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    policy_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    provider_snapshot_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    identity_connection_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_identity_connections.id", ondelete="RESTRICT")
    )
    last_error_code: Mapped[str | None] = mapped_column(sa.String(128))
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    claim_token: Mapped[UUID | None] = mapped_column()
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
    imported_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    recovered_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.UniqueConstraint("batch_id", "user_id", name="uq_credential_migration_batch_user"),
        sa.CheckConstraint(
            "status IN ('pending', 'imported', 'completed', 'conflict', 'failed', 'recovered')",
            name="ck_credential_migration_status",
        ),
        sa.CheckConstraint(
            "source_password_version > 0 AND source_security_version > 0 "
            "AND attempt_count >= 0 AND version > 0",
            name="ck_credential_migration_versions",
        ),
        sa.CheckConstraint(
            "length(batch_id) > 0 AND length(issuer) > 0 AND length(organization) > 0 "
            "AND length(provider_subject) > 0 AND length(provider_username) > 0",
            name="ck_credential_migration_target",
        ),
        *[
            sa.CheckConstraint(_hex64(name), name="ck_credential_migration_" + name)
            for name in (
                "source_password_sha256",
                "source_email_sha256",
                "policy_sha256",
                "idempotency_key",
                "request_hash",
            )
        ],
        sa.CheckConstraint(
            "provider_snapshot_sha256 IS NULL OR (" + _hex64("provider_snapshot_sha256") + ")",
            name="ck_credential_migration_snapshot_sha256",
        ),
        sa.CheckConstraint(
            "(claim_token IS NULL AND lease_expires_at IS NULL) OR "
            "(claim_token IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND status IN ('pending', 'imported'))",
            name="ck_credential_migration_lease",
        ),
        sa.CheckConstraint(
            "status NOT IN ('imported', 'completed', 'recovered') OR "
            "(imported_at IS NOT NULL AND provider_snapshot_sha256 IS NOT NULL)",
            name="ck_credential_migration_import_receipt",
        ),
        sa.CheckConstraint(
            "status NOT IN ('completed', 'recovered') OR "
            "(completed_at IS NOT NULL AND identity_connection_id IS NOT NULL)",
            name="ck_credential_migration_completion",
        ),
        sa.CheckConstraint(
            "(status = 'recovered') = (recovered_at IS NOT NULL)",
            name="ck_credential_migration_recovery",
        ),
        sa.Index(
            "uq_credential_migration_active_user",
            "user_id",
            unique=True,
            postgresql_where=sa.text("status IN ('pending', 'imported')"),
            sqlite_where=sa.text("status IN ('pending', 'imported')"),
        ),
    )
