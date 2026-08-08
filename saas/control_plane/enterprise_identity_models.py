"""Enterprise SCIM directory and convergent provisioning records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase


class EnterpriseScimDirectoryRecord(SaasBase):
    """Tenant-owned SCIM authority whose bearer credential is stored only as a hash."""

    __tablename__ = "saas_enterprise_scim_directories"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    display_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    token_prefix: Mapped[str] = mapped_column(sa.String(24), nullable=False)
    successor_token_hash: Mapped[str | None] = mapped_column(sa.String(64), unique=True)
    successor_token_prefix: Mapped[str | None] = mapped_column(sa.String(24))
    rotation_activates_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    rotation_grace_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    configured_by: Mapped[UUID] = mapped_column(
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
    rotated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.CheckConstraint("length(display_name) > 0", name="ck_scim_directory_name_nonempty"),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_scim_directory_token_hash"),
        sa.CheckConstraint("length(token_prefix) > 0", name="ck_scim_directory_token_prefix"),
        sa.CheckConstraint(
            "successor_token_hash IS NULL OR length(successor_token_hash) = 64",
            name="ck_scim_directory_successor_hash",
        ),
        sa.CheckConstraint(
            "successor_token_prefix IS NULL OR length(successor_token_prefix) > 0",
            name="ck_scim_directory_successor_prefix",
        ),
        sa.CheckConstraint(
            "(successor_token_hash IS NULL AND successor_token_prefix IS NULL "
            "AND rotation_activates_at IS NULL AND rotation_grace_expires_at IS NULL) OR "
            "(successor_token_hash IS NOT NULL AND successor_token_prefix IS NOT NULL "
            "AND rotation_activates_at IS NOT NULL AND rotation_grace_expires_at IS NOT NULL "
            "AND rotation_activates_at < rotation_grace_expires_at)",
            name="ck_scim_directory_rotation_state",
        ),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_scim_directory_status"),
        sa.CheckConstraint("version > 0", name="ck_scim_directory_version"),
        sa.CheckConstraint(
            "(status = 'active' AND disabled_at IS NULL) OR "
            "(status = 'disabled' AND disabled_at IS NOT NULL)",
            name="ck_scim_directory_disable_state",
        ),
        sa.UniqueConstraint("tenant_id", "display_name", name="uq_scim_directory_tenant_name"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_scim_directory_tenant_id"),
        sa.Index("ix_scim_directory_tenant_status", "tenant_id", "status", "id"),
    )


class EnterpriseScimUserRecord(SaasBase):
    """SCIM User resource plus a tombstone that survives deprovision ordering."""

    __tablename__ = "saas_enterprise_scim_users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    directory_id: Mapped[UUID] = mapped_column(nullable=False)
    external_id: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    user_name_normalized: Mapped[str] = mapped_column(sa.String(320), nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.String(256))
    active: Mapped[bool] = mapped_column(nullable=False)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    source_version: Mapped[int] = mapped_column(nullable=False)
    source_state_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    deprovisioned_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            ("tenant_id", "directory_id"),
            (
                "saas_enterprise_scim_directories.tenant_id",
                "saas_enterprise_scim_directories.id",
            ),
            ondelete="RESTRICT",
            name="fk_scim_user_directory",
        ),
        sa.CheckConstraint("length(external_id) > 0", name="ck_scim_user_external_nonempty"),
        sa.CheckConstraint("length(user_name_normalized) > 0", name="ck_scim_user_name_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_scim_user_version"),
        sa.CheckConstraint("source_version > 0", name="ck_scim_user_source_version"),
        sa.CheckConstraint("length(source_state_hash) = 64", name="ck_scim_user_state_hash"),
        sa.CheckConstraint(
            "(active = true AND user_id IS NOT NULL AND deprovisioned_at IS NULL) OR "
            "(active = false AND deprovisioned_at IS NOT NULL)",
            name="ck_scim_user_lifecycle",
        ),
        sa.UniqueConstraint(
            "tenant_id", "directory_id", "external_id", name="uq_scim_user_external"
        ),
        sa.UniqueConstraint("directory_id", "id", name="uq_scim_user_directory_id"),
        sa.UniqueConstraint("directory_id", "user_id", name="uq_scim_user_global_user"),
        sa.Index("ix_scim_user_directory_active", "tenant_id", "directory_id", "active", "id"),
    )


class EnterpriseScimGroupRecord(SaasBase):
    """SCIM Group mapped one-to-one to the existing enterprise Group authority."""

    __tablename__ = "saas_enterprise_scim_groups"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    directory_id: Mapped[UUID] = mapped_column(nullable=False)
    external_id: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    enterprise_group_id: Mapped[UUID] = mapped_column(nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    active: Mapped[bool] = mapped_column(nullable=False, default=True)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    source_version: Mapped[int] = mapped_column(nullable=False)
    source_state_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
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
            ("tenant_id", "directory_id"),
            (
                "saas_enterprise_scim_directories.tenant_id",
                "saas_enterprise_scim_directories.id",
            ),
            ondelete="RESTRICT",
            name="fk_scim_group_directory",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "enterprise_group_id"),
            ("saas_enterprise_groups.tenant_id", "saas_enterprise_groups.id"),
            ondelete="RESTRICT",
            name="fk_scim_group_enterprise_group",
        ),
        sa.CheckConstraint("length(external_id) > 0", name="ck_scim_group_external_nonempty"),
        sa.CheckConstraint("length(display_name) > 0", name="ck_scim_group_name_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_scim_group_version"),
        sa.CheckConstraint("source_version > 0", name="ck_scim_group_source_version"),
        sa.CheckConstraint("length(source_state_hash) = 64", name="ck_scim_group_state_hash"),
        sa.UniqueConstraint(
            "tenant_id", "directory_id", "external_id", name="uq_scim_group_external"
        ),
        sa.UniqueConstraint("directory_id", "id", name="uq_scim_group_directory_id"),
        sa.UniqueConstraint(
            "directory_id", "enterprise_group_id", name="uq_scim_group_enterprise_group"
        ),
        sa.Index("ix_scim_group_directory_active", "tenant_id", "directory_id", "active", "id"),
    )


class EnterpriseScimEventRecord(SaasBase):
    """Immutable request receipt for replay, stale-order and blocked-member evidence."""

    __tablename__ = "saas_enterprise_scim_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    directory_id: Mapped[UUID] = mapped_column(nullable=False)
    event_id: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    resource_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    resource_id: Mapped[UUID] = mapped_column(nullable=False)
    source_version: Mapped[int] = mapped_column(nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    disposition: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    result: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "directory_id"),
            (
                "saas_enterprise_scim_directories.tenant_id",
                "saas_enterprise_scim_directories.id",
            ),
            ondelete="RESTRICT",
            name="fk_scim_event_directory",
        ),
        sa.CheckConstraint("length(event_id) > 0", name="ck_scim_event_id_nonempty"),
        sa.CheckConstraint(
            "resource_type IN ('User', 'Group', 'Bulk')", name="ck_scim_event_resource_type"
        ),
        sa.CheckConstraint("source_version > 0", name="ck_scim_event_source_version"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_scim_event_request_hash"),
        sa.CheckConstraint(
            "disposition IN ('applied', 'stale', 'blocked')",
            name="ck_scim_event_disposition",
        ),
        sa.UniqueConstraint("directory_id", "event_id", name="uq_scim_event_request"),
        sa.Index(
            "ix_scim_event_directory_created", "tenant_id", "directory_id", "created_at", "id"
        ),
    )
