"""Typed immutable consumer facts; none grants financial or audit-export approval."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase


class UsageReconciliationIngressRecord(SaasBase):
    """Actual Usage/Pricing ingestion by the reconciliation consumer."""

    __tablename__ = "saas_usage_reconciliation_ingress"

    outbox_event_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_control_plane_outbox.id", ondelete="RESTRICT"), primary_key=True
    )
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    usage_event_id: Mapped[UUID] = mapped_column(nullable=False, unique=True)
    pricing_snapshot_id: Mapped[UUID] = mapped_column(nullable=False)
    source_request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    facts_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    facts: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    product_revision: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    source_created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "usage_event_id"),
            ("saas_usage_events.tenant_id", "saas_usage_events.id"),
            ondelete="RESTRICT",
            name="fk_usage_ingress_source",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "pricing_snapshot_id"),
            ("saas_pricing_snapshots.tenant_id", "saas_pricing_snapshots.id"),
            ondelete="RESTRICT",
            name="fk_usage_ingress_pricing",
        ),
        sa.CheckConstraint("length(source_request_hash) = 64", name="ck_usage_ingress_request"),
        sa.CheckConstraint("length(facts_sha256) = 64", name="ck_usage_ingress_facts"),
        sa.CheckConstraint("length(product_revision) = 40", name="ck_usage_ingress_product"),
        sa.Index("ix_usage_ingress_tenant_received", "tenant_id", "received_at"),
    )


class PlatformAuditJournalDeliveryRecord(SaasBase):
    """Exact encrypted/signed retained audit journal version, never an export permit."""

    __tablename__ = "saas_platform_audit_journal_deliveries"

    outbox_event_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_control_plane_outbox.id", ondelete="RESTRICT"), primary_key=True
    )
    audit_event_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_audit_events.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    audit_sequence: Mapped[int] = mapped_column(nullable=False, unique=True)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    event_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    journal_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    storage_key: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    storage_version: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    product_revision: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    source_created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint("audit_sequence > 0", name="ck_audit_journal_sequence"),
        sa.CheckConstraint("length(event_hash) = 64", name="ck_audit_journal_event_hash"),
        sa.CheckConstraint("length(journal_sha256) = 64", name="ck_audit_journal_sha256"),
        sa.CheckConstraint("length(storage_version) > 0", name="ck_audit_journal_version"),
        sa.CheckConstraint("length(signing_key_id) > 0", name="ck_audit_journal_signer"),
        sa.CheckConstraint("length(product_revision) = 40", name="ck_audit_journal_product"),
    )


class RevocationReplicaAppliedRecord(SaasBase):
    """One actual replica cache application, with real process/Product identity."""

    __tablename__ = "saas_revocation_replica_applied"

    outbox_event_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_control_plane_outbox.id", ondelete="RESTRICT"), primary_key=True
    )
    replica_uid: Mapped[UUID] = mapped_column(primary_key=True)
    process_boot_uid: Mapped[UUID] = mapped_column(primary_key=True)
    listener_epoch_uid: Mapped[UUID] = mapped_column(primary_key=True)
    product_revision: Mapped[str] = mapped_column(sa.String(40), primary_key=True)
    version_floor: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    applied_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint("version_floor > 0", name="ck_revocation_applied_version"),
        sa.CheckConstraint("length(applied_digest) = 64", name="ck_revocation_applied_digest"),
        sa.CheckConstraint("length(product_revision) = 40", name="ck_revocation_applied_product"),
        sa.Index("ix_revocation_replica_applied", "replica_uid", "applied_at"),
    )
