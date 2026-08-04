"""Durable Preview Gateway discovery and Relay certificate records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

PREVIEW_GATEWAY_STATUSES = ("active", "draining", "released", "expired")
PREVIEW_GATEWAY_CERTIFICATE_PURPOSES = (
    "preview_relay_client",
    "preview_relay_server",
)
PREVIEW_GATEWAY_CERTIFICATE_STATUSES = ("active", "retiring", "revoked")


class PreviewGatewayInstanceRecord(SaasBase):
    """One process-lifetime Gateway identity and its trusted internal endpoint."""

    __tablename__ = "saas_preview_gateway_instances"

    id: Mapped[str] = mapped_column(sa.String(128), primary_key=True)
    connect_host: Mapped[str] = mapped_column(sa.String(253), nullable=False)
    connect_port: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    server_name: Mapped[str] = mapped_column(sa.String(253), nullable=False)
    failure_domain: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    source_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    adapter_contract_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    registration_token_hash: Mapped[str] = mapped_column(
        sa.String(64), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
    registered_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_heartbeat_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    release_reason: Mapped[str | None] = mapped_column(sa.String(256))
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
            f"status IN ({_values(PREVIEW_GATEWAY_STATUSES)})",
            name="ck_preview_gateway_status",
        ),
        sa.CheckConstraint(
            "connect_port >= 1 AND connect_port <= 65535",
            name="ck_preview_gateway_port",
        ),
        sa.CheckConstraint(
            "length(connect_host) > 0 AND length(server_name) > 0",
            name="ck_preview_gateway_endpoint",
        ),
        sa.CheckConstraint(
            "length(failure_domain) > 0 AND length(source_revision) > 0 "
            "AND length(adapter_contract_version) > 0",
            name="ck_preview_gateway_provenance",
        ),
        sa.CheckConstraint(
            "length(registration_token_hash) = 64",
            name="ck_preview_gateway_token_hash",
        ),
        sa.CheckConstraint(
            "last_heartbeat_at >= registered_at",
            name="ck_preview_gateway_heartbeat_order",
        ),
        sa.CheckConstraint(
            "lease_expires_at > registered_at",
            name="ck_preview_gateway_lease_window",
        ),
        sa.CheckConstraint(
            "(status IN ('active', 'draining') AND released_at IS NULL "
            "AND release_reason IS NULL) OR "
            "(status IN ('released', 'expired') AND released_at IS NOT NULL "
            "AND length(release_reason) > 0)",
            name="ck_preview_gateway_lifecycle",
        ),
        sa.Index(
            "ix_preview_gateway_discovery",
            "id",
            "status",
            "lease_expires_at",
        ),
    )


class PreviewGatewayCertificateRecord(SaasBase):
    """Public Relay leaf metadata bound to one immutable Gateway identity."""

    __tablename__ = "saas_preview_gateway_certificates"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    gateway_instance_id: Mapped[str] = mapped_column(
        sa.ForeignKey("saas_preview_gateway_instances.id", ondelete="RESTRICT"), nullable=False
    )
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
            f"purpose IN ({_values(PREVIEW_GATEWAY_CERTIFICATE_PURPOSES)})",
            name="ck_preview_gateway_certificate_purpose",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PREVIEW_GATEWAY_CERTIFICATE_STATUSES)})",
            name="ck_preview_gateway_certificate_status",
        ),
        sa.CheckConstraint(
            "rotation_generation > 0", name="ck_preview_gateway_certificate_rotation"
        ),
        sa.CheckConstraint(
            "length(fingerprint_sha256) = 64",
            name="ck_preview_gateway_certificate_fingerprint",
        ),
        sa.CheckConstraint("length(spki_sha256) = 64", name="ck_preview_gateway_certificate_spki"),
        sa.CheckConstraint(
            "length(serial_hex) > 0 AND length(serial_hex) <= 64",
            name="ck_preview_gateway_certificate_serial",
        ),
        sa.CheckConstraint(
            "length(spiffe_id) > 0 AND length(trust_bundle_version) > 0",
            name="ck_preview_gateway_certificate_identity",
        ),
        sa.CheckConstraint(
            "certificate_not_after > certificate_not_before",
            name="ck_preview_gateway_certificate_validity",
        ),
        sa.CheckConstraint(
            "(status = 'active' AND retire_at IS NULL AND revoked_at IS NULL "
            "AND revocation_reason IS NULL) OR "
            "(status = 'retiring' AND retire_at IS NOT NULL AND retire_at >= activated_at "
            "AND revoked_at IS NULL AND revocation_reason IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= activated_at "
            "AND length(revocation_reason) > 0)",
            name="ck_preview_gateway_certificate_lifecycle",
        ),
        sa.UniqueConstraint(
            "gateway_instance_id",
            "purpose",
            "rotation_generation",
            name="uq_preview_gateway_certificate_rotation",
        ),
        sa.Index(
            "ix_preview_gateway_certificate_authorize",
            "fingerprint_sha256",
            "purpose",
            "status",
        ),
        sa.Index(
            "uq_preview_gateway_certificate_active",
            "gateway_instance_id",
            "purpose",
            unique=True,
            postgresql_where=sa.text("status = 'active'"),
            sqlite_where=sa.text("status = 'active'"),
        ),
    )


__all__ = [
    "PREVIEW_GATEWAY_CERTIFICATE_PURPOSES",
    "PREVIEW_GATEWAY_CERTIFICATE_STATUSES",
    "PREVIEW_GATEWAY_STATUSES",
    "PreviewGatewayCertificateRecord",
    "PreviewGatewayInstanceRecord",
]
