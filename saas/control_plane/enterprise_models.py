"""Tenant groups and project-scoped enterprise custom-role records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase


class EnterpriseGroupRecord(SaasBase):
    """Tenant-owned group whose membership never implies a permission by itself."""

    __tablename__ = "saas_enterprise_groups"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.String(1024))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
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
        sa.CheckConstraint("length(name) > 0", name="ck_enterprise_group_name_nonempty"),
        sa.CheckConstraint("status IN ('active', 'archived')", name="ck_enterprise_group_status"),
        sa.CheckConstraint("version > 0", name="ck_enterprise_group_version"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_enterprise_group_tenant_id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_enterprise_group_tenant_name"),
        sa.Index("ix_enterprise_group_scope_status", "tenant_id", "status", "name"),
    )


class EnterpriseGroupMembershipRecord(SaasBase):
    """Versioned group membership for an existing Tenant member."""

    __tablename__ = "saas_enterprise_group_memberships"

    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    group_id: Mapped[UUID] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
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
        sa.ForeignKeyConstraint(
            ("tenant_id", "group_id"),
            ("saas_enterprise_groups.tenant_id", "saas_enterprise_groups.id"),
            ondelete="RESTRICT",
            name="fk_enterprise_group_membership_group",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "user_id"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_enterprise_group_membership_tenant_member",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'removed')", name="ck_enterprise_group_membership_status"
        ),
        sa.CheckConstraint("version > 0", name="ck_enterprise_group_membership_version"),
        sa.Index(
            "ix_enterprise_group_membership_user",
            "tenant_id",
            "user_id",
            "status",
            "expires_at",
        ),
    )


class EnterpriseCustomRoleRecord(SaasBase):
    """Project-scoped permission set compiled only from the canonical catalog."""

    __tablename__ = "saas_enterprise_custom_roles"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.String(1024))
    permissions: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
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
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            ondelete="RESTRICT",
            name="fk_enterprise_custom_role_project",
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_enterprise_custom_role_name_nonempty"),
        sa.CheckConstraint(
            "status IN ('active', 'retired')", name="ck_enterprise_custom_role_status"
        ),
        sa.CheckConstraint("version > 0", name="ck_enterprise_custom_role_version"),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "id",
            name="uq_enterprise_custom_role_scope_id",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "name",
            name="uq_enterprise_custom_role_scope_name",
        ),
        sa.Index(
            "ix_enterprise_custom_role_scope_status",
            "tenant_id",
            "space_id",
            "project_id",
            "status",
            "name",
        ),
    )


class EnterpriseGroupRoleAssignmentRecord(SaasBase):
    """Additive assignment from a Tenant group to one project custom role."""

    __tablename__ = "saas_enterprise_group_role_assignments"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    group_id: Mapped[UUID] = mapped_column(nullable=False)
    custom_role_id: Mapped[UUID] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
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
        sa.ForeignKeyConstraint(
            ("tenant_id", "group_id"),
            ("saas_enterprise_groups.tenant_id", "saas_enterprise_groups.id"),
            ondelete="RESTRICT",
            name="fk_enterprise_group_role_assignment_group",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id", "custom_role_id"),
            (
                "saas_enterprise_custom_roles.tenant_id",
                "saas_enterprise_custom_roles.space_id",
                "saas_enterprise_custom_roles.project_id",
                "saas_enterprise_custom_roles.id",
            ),
            ondelete="RESTRICT",
            name="fk_enterprise_group_role_assignment_role",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_enterprise_group_role_assignment_status"
        ),
        sa.CheckConstraint("version > 0", name="ck_enterprise_group_role_assignment_version"),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "group_id",
            "custom_role_id",
            name="uq_enterprise_group_role_assignment",
        ),
        sa.Index(
            "ix_enterprise_group_role_assignment_scope",
            "tenant_id",
            "space_id",
            "project_id",
            "status",
            "expires_at",
        ),
        sa.Index(
            "ix_enterprise_group_role_assignment_group",
            "tenant_id",
            "group_id",
            "status",
            "expires_at",
        ),
    )
