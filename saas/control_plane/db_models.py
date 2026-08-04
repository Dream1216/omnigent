"""SQLAlchemy records owned by the SaaS control plane."""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

USER_STATUSES = ("active", "suspended", "deleted")
TENANT_STATUSES = ("trial", "active", "suspended", "pending_deletion", "deleted")
SPACE_STATUSES = ("active", "suspended", "archived")
MEMBERSHIP_STATUSES = ("invited", "active", "suspended", "removed")
TENANT_ROLES = ("owner", "admin", "member")
SPACE_ROLES = ("owner", "admin", "operator", "member")
PLACEMENT_STATUSES = ("active", "draining", "quarantined", "retired")
PARTITION_STATUSES = (
    "provisioning",
    "active",
    "draining",
    "migrating",
    "quarantined",
    "retired",
)
BINDING_STATUSES = ("active", "suspended", "retired")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


class SaasBase(DeclarativeBase):
    """Declarative base kept separate from official Omnigent metadata."""

    type_annotation_map: ClassVar[dict[type[UUID], sa.Uuid]] = {UUID: sa.Uuid(as_uuid=True)}


class GlobalUser(SaasBase):
    """Stable SaaS user identity; authentication connections remain separate."""

    __tablename__ = "saas_global_users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    security_version: Mapped[int] = mapped_column(nullable=False, default=1)
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
        sa.CheckConstraint(f"status IN ({_values(USER_STATUSES)})", name="ck_user_status"),
        sa.CheckConstraint("security_version > 0", name="ck_user_security_version"),
    )


class Tenant(SaasBase):
    """Commercial, compliance, and data-residency boundary."""

    __tablename__ = "saas_tenants"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="trial")
    plan: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="trial")
    home_region: Mapped[str] = mapped_column(sa.String(64), nullable=False)
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
        sa.CheckConstraint(f"status IN ({_values(TENANT_STATUSES)})", name="ck_tenant_status"),
        sa.CheckConstraint("length(slug) > 0", name="ck_tenant_slug_nonempty"),
    )


class Space(SaasBase):
    """Organization/team collaboration boundary within a Tenant."""

    __tablename__ = "saas_spaces"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    slug: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
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
        sa.CheckConstraint(f"status IN ({_values(SPACE_STATUSES)})", name="ck_space_status"),
        sa.CheckConstraint("length(slug) > 0", name="ck_space_slug_nonempty"),
        sa.UniqueConstraint("tenant_id", "slug", name="uq_space_tenant_slug"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_space_tenant_id"),
    )


class TenantMembership(SaasBase):
    """Versioned user membership in a Tenant."""

    __tablename__ = "saas_tenant_memberships"

    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), primary_key=True
    )
    role: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="invited")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    joined_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.CheckConstraint(
            f"status IN ({_values(MEMBERSHIP_STATUSES)})", name="ck_tenant_membership_status"
        ),
        sa.CheckConstraint(f"role IN ({_values(TENANT_ROLES)})", name="ck_tenant_membership_role"),
        sa.CheckConstraint("version > 0", name="ck_tenant_membership_version"),
    )


class SpaceMembership(SaasBase):
    """Versioned user membership in one Space and its owning Tenant."""

    __tablename__ = "saas_space_memberships"

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    space_id: Mapped[UUID] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(primary_key=True)
    role: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="invited")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    joined_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_space_membership_space",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "user_id"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_space_membership_tenant_member",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(MEMBERSHIP_STATUSES)})", name="ck_space_membership_status"
        ),
        sa.CheckConstraint(f"role IN ({_values(SPACE_ROLES)})", name="ck_space_membership_role"),
        sa.CheckConstraint("version > 0", name="ck_space_membership_version"),
    )


class RuntimePlacementRecord(SaasBase):
    """Trusted deployment reference for one Omnigent runtime failure domain."""

    __tablename__ = "saas_runtime_placements"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    runtime_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    data_region: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    failure_domain: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    database_cluster_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    object_store_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    kms_key_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    official_schema_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    capacity_class: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
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
            f"status IN ({_values(PLACEMENT_STATUSES)})", name="ck_placement_status"
        ),
    )


class RuntimePartitionRecord(SaasBase):
    """Permanent mapping from a Space to a Placement-local physical partition."""

    __tablename__ = "saas_runtime_partitions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    placement_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runtime_placements.id", ondelete="RESTRICT"), nullable=False
    )
    runtime_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    runtime_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    physical_partition_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    placement_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    source_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    adapter_contract_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="provisioning")
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
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_runtime_partition_space",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PARTITION_STATUSES)})", name="ck_runtime_partition_status"
        ),
        sa.CheckConstraint("placement_generation > 0", name="ck_partition_generation"),
        sa.CheckConstraint("length(physical_partition_key) > 0", name="ck_partition_key_nonempty"),
        sa.UniqueConstraint(
            "placement_id",
            "runtime_type",
            "physical_partition_key",
            name="uq_partition_placement_physical_key",
        ),
        sa.UniqueConstraint("id", "tenant_id", "space_id", name="uq_partition_scope"),
    )


class RuntimeIdentityAliasRecord(SaasBase):
    """SaaS user projection into one official runtime partition."""

    __tablename__ = "saas_runtime_identity_aliases"

    runtime_partition_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runtime_partitions.id", ondelete="RESTRICT"), primary_key=True
    )
    user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), primary_key=True
    )
    runtime_user_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"status IN ({_values(BINDING_STATUSES)})", name="ck_identity_alias_status"
        ),
        sa.CheckConstraint("length(runtime_user_key) > 0", name="ck_runtime_user_key_nonempty"),
        sa.UniqueConstraint(
            "runtime_partition_id", "runtime_user_key", name="uq_partition_runtime_user_key"
        ),
    )


class RuntimeResourceBindingRecord(SaasBase):
    """Tenant-scoped lookup from a SaaS resource to an official resource."""

    __tablename__ = "saas_runtime_resource_bindings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    runtime_partition_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID | None] = mapped_column()
    resource_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    runtime_resource_id: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    saas_resource_id: Mapped[UUID] = mapped_column(nullable=False)
    partition_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    binding_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("runtime_partition_id", "tenant_id", "space_id"),
            (
                "saas_runtime_partitions.id",
                "saas_runtime_partitions.tenant_id",
                "saas_runtime_partitions.space_id",
            ),
            ondelete="RESTRICT",
            name="fk_runtime_binding_partition_scope",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(BINDING_STATUSES)})", name="ck_resource_binding_status"
        ),
        sa.CheckConstraint("partition_generation > 0", name="ck_binding_partition_generation"),
        sa.CheckConstraint("binding_generation > 0", name="ck_binding_generation"),
        sa.CheckConstraint("length(resource_type) > 0", name="ck_binding_resource_type_nonempty"),
        sa.CheckConstraint(
            "length(runtime_resource_id) > 0", name="ck_binding_runtime_resource_nonempty"
        ),
        sa.UniqueConstraint(
            "runtime_partition_id",
            "resource_type",
            "runtime_resource_id",
            name="uq_partition_runtime_resource",
        ),
        sa.Index(
            "uq_active_saas_resource_binding",
            "tenant_id",
            "space_id",
            "resource_type",
            "saas_resource_id",
            unique=True,
            sqlite_where=sa.text("status = 'active'"),
            postgresql_where=sa.text("status = 'active'"),
        ),
    )
