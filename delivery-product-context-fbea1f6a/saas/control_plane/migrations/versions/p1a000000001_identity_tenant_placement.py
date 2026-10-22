"""Create P1 identity, tenancy, membership, and runtime placement tables."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p1a000000001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def upgrade() -> None:
    """Create the first independent SaaS control-plane schema."""

    op.create_table(
        "saas_global_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("security_version", sa.Integer(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint("status IN ('active', 'suspended', 'deleted')", name="ck_user_status"),
        sa.CheckConstraint("security_version > 0", name="ck_user_security_version"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "saas_tenants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(128), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("plan", sa.String(64), nullable=False),
        sa.Column("home_region", sa.String(64), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('trial', 'active', 'suspended', 'pending_deletion', 'deleted')",
            name="ck_tenant_status",
        ),
        sa.CheckConstraint("length(slug) > 0", name="ck_tenant_slug_nonempty"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "saas_spaces",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(128), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'archived')", name="ck_space_status"
        ),
        sa.CheckConstraint("length(slug) > 0", name="ck_space_slug_nonempty"),
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_space_tenant_id"),
        sa.UniqueConstraint("tenant_id", "slug", name="uq_space_tenant_slug"),
    )
    op.create_table(
        "saas_tenant_memberships",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('invited', 'active', 'suspended', 'removed')",
            name="ck_tenant_membership_status",
        ),
        sa.CheckConstraint(
            "role IN ('owner', 'admin', 'member')", name="ck_tenant_membership_role"
        ),
        sa.CheckConstraint("version > 0", name="ck_tenant_membership_version"),
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(("user_id",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("tenant_id", "user_id"),
    )
    op.create_table(
        "saas_space_memberships",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('invited', 'active', 'suspended', 'removed')",
            name="ck_space_membership_status",
        ),
        sa.CheckConstraint(
            "role IN ('owner', 'admin', 'operator', 'member')",
            name="ck_space_membership_role",
        ),
        sa.CheckConstraint("version > 0", name="ck_space_membership_version"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            name="fk_space_membership_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "user_id"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            name="fk_space_membership_tenant_member",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "space_id", "user_id"),
    )
    op.create_table(
        "saas_runtime_placements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("runtime_type", sa.String(64), nullable=False),
        sa.Column("data_region", sa.String(64), nullable=False),
        sa.Column("failure_domain", sa.String(128), nullable=False),
        sa.Column("database_cluster_ref", sa.String(256), nullable=False),
        sa.Column("object_store_ref", sa.String(256), nullable=False),
        sa.Column("kms_key_ref", sa.String(256), nullable=False),
        sa.Column("official_schema_revision", sa.String(64), nullable=False),
        sa.Column("capacity_class", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('active', 'draining', 'quarantined', 'retired')",
            name="ck_placement_status",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "saas_runtime_partitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("placement_id", sa.Uuid(), nullable=False),
        sa.Column("runtime_type", sa.String(64), nullable=False),
        sa.Column("runtime_version", sa.String(64), nullable=False),
        sa.Column("physical_partition_key", sa.String(128), nullable=False),
        sa.Column("placement_generation", sa.BigInteger(), nullable=False),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("adapter_contract_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('provisioning', 'active', 'draining', 'migrating', "
            "'quarantined', 'retired')",
            name="ck_runtime_partition_status",
        ),
        sa.CheckConstraint("placement_generation > 0", name="ck_partition_generation"),
        sa.CheckConstraint("length(physical_partition_key) > 0", name="ck_partition_key_nonempty"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            name="fk_runtime_partition_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("placement_id",), ("saas_runtime_placements.id",), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "placement_id",
            "runtime_type",
            "physical_partition_key",
            name="uq_partition_placement_physical_key",
        ),
        sa.UniqueConstraint("id", "tenant_id", "space_id", name="uq_partition_scope"),
    )
    op.create_table(
        "saas_runtime_identity_aliases",
        sa.Column("runtime_partition_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("runtime_user_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'retired')", name="ck_identity_alias_status"
        ),
        sa.CheckConstraint("length(runtime_user_key) > 0", name="ck_runtime_user_key_nonempty"),
        sa.ForeignKeyConstraint(
            ("runtime_partition_id",),
            ("saas_runtime_partitions.id",),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(("user_id",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("runtime_partition_id", "user_id"),
        sa.UniqueConstraint(
            "runtime_partition_id",
            "runtime_user_key",
            name="uq_partition_runtime_user_key",
        ),
    )
    op.create_table(
        "saas_runtime_resource_bindings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("runtime_partition_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("runtime_resource_id", sa.String(256), nullable=False),
        sa.Column("saas_resource_id", sa.Uuid(), nullable=False),
        sa.Column("partition_generation", sa.BigInteger(), nullable=False),
        sa.Column("binding_generation", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'retired')", name="ck_resource_binding_status"
        ),
        sa.CheckConstraint("partition_generation > 0", name="ck_binding_partition_generation"),
        sa.CheckConstraint("binding_generation > 0", name="ck_binding_generation"),
        sa.CheckConstraint("length(resource_type) > 0", name="ck_binding_resource_type_nonempty"),
        sa.CheckConstraint(
            "length(runtime_resource_id) > 0", name="ck_binding_runtime_resource_nonempty"
        ),
        sa.ForeignKeyConstraint(
            ("runtime_partition_id", "tenant_id", "space_id"),
            (
                "saas_runtime_partitions.id",
                "saas_runtime_partitions.tenant_id",
                "saas_runtime_partitions.space_id",
            ),
            name="fk_runtime_binding_partition_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "runtime_partition_id",
            "resource_type",
            "runtime_resource_id",
            name="uq_partition_runtime_resource",
        ),
    )
    op.create_index(
        "uq_active_saas_resource_binding",
        "saas_runtime_resource_bindings",
        ("tenant_id", "space_id", "resource_type", "saas_resource_id"),
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    """Remove the independent SaaS control-plane schema."""

    op.drop_index(
        "uq_active_saas_resource_binding",
        table_name="saas_runtime_resource_bindings",
    )
    op.drop_table("saas_runtime_resource_bindings")
    op.drop_table("saas_runtime_identity_aliases")
    op.drop_table("saas_runtime_partitions")
    op.drop_table("saas_runtime_placements")
    op.drop_table("saas_space_memberships")
    op.drop_table("saas_tenant_memberships")
    op.drop_table("saas_spaces")
    op.drop_table("saas_tenants")
    op.drop_table("saas_global_users")
