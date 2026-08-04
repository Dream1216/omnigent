"""Durable Runner certificate lifecycle records for deployed service mTLS."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

RUNNER_CERTIFICATE_PURPOSES = ("preview_tunnel", "secret_broker")
RUNNER_CERTIFICATE_STATUSES = ("active", "retiring", "revoked")


class RunnerCertificateRecord(SaasBase):
    """Public leaf-certificate metadata bound to one exact Runner incarnation."""

    __tablename__ = "saas_runner_certificates"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    runner_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runner_registrations.id", ondelete="RESTRICT"), nullable=False
    )
    runner_connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    purpose: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    spki_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    serial_hex: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    spiffe_id: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    trust_bundle_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    rotation_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    certificate_not_before: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    certificate_not_after: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    activated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    retire_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(sa.String(256))
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
            f"purpose IN ({_values(RUNNER_CERTIFICATE_PURPOSES)})",
            name="ck_runner_certificate_purpose",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(RUNNER_CERTIFICATE_STATUSES)})",
            name="ck_runner_certificate_status",
        ),
        sa.CheckConstraint(
            "runner_connection_generation > 0", name="ck_runner_certificate_connection_generation"
        ),
        sa.CheckConstraint("rotation_generation > 0", name="ck_runner_certificate_rotation"),
        sa.CheckConstraint(
            "length(fingerprint_sha256) = 64", name="ck_runner_certificate_fingerprint"
        ),
        sa.CheckConstraint("length(spki_sha256) = 64", name="ck_runner_certificate_spki"),
        sa.CheckConstraint(
            "length(serial_hex) > 0 AND length(serial_hex) <= 64",
            name="ck_runner_certificate_serial",
        ),
        sa.CheckConstraint("length(spiffe_id) > 0", name="ck_runner_certificate_spiffe"),
        sa.CheckConstraint(
            "length(trust_bundle_version) > 0", name="ck_runner_certificate_trust_bundle"
        ),
        sa.CheckConstraint(
            "certificate_not_after > certificate_not_before",
            name="ck_runner_certificate_validity",
        ),
        sa.CheckConstraint(
            "(status = 'active' AND retire_at IS NULL AND revoked_at IS NULL "
            "AND revocation_reason IS NULL) OR "
            "(status = 'retiring' AND retire_at IS NOT NULL AND retire_at >= activated_at "
            "AND revoked_at IS NULL "
            "AND revocation_reason IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= activated_at "
            "AND length(revocation_reason) > 0)",
            name="ck_runner_certificate_lifecycle",
        ),
        sa.UniqueConstraint(
            "runner_id",
            "purpose",
            "rotation_generation",
            name="uq_runner_certificate_rotation",
        ),
        sa.Index(
            "ix_runner_certificate_authorize",
            "fingerprint_sha256",
            "purpose",
            "status",
        ),
        sa.Index(
            "ix_runner_certificate_rotation",
            "runner_id",
            "purpose",
            "rotation_generation",
        ),
        sa.Index(
            "uq_runner_certificate_active",
            "runner_id",
            "purpose",
            unique=True,
            postgresql_where=sa.text("status = 'active'"),
            sqlite_where=sa.text("status = 'active'"),
        ),
    )


__all__ = [
    "RUNNER_CERTIFICATE_PURPOSES",
    "RUNNER_CERTIFICATE_STATUSES",
    "RunnerCertificateRecord",
]
