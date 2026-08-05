"""Service Account and one-time API credential records owned by the SaaS plane."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase

SERVICE_ACCOUNT_STATUSES = ("active", "suspended", "deleted")
API_CREDENTIAL_STATUSES = ("active", "revoked")


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


class ServiceAccountRecord(SaasBase):
    """Non-interactive machine identity with an explicit human steward."""

    __tablename__ = "saas_service_accounts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID | None] = mapped_column()
    project_id: Mapped[UUID | None] = mapped_column()
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.String(1024))
    steward_user_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
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
        sa.ForeignKeyConstraint(
            ("tenant_id", "steward_user_id"),
            ("saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"),
            ondelete="RESTRICT",
            name="fk_service_account_steward_tenant_member",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "steward_user_id"),
            (
                "saas_space_memberships.tenant_id",
                "saas_space_memberships.space_id",
                "saas_space_memberships.user_id",
            ),
            ondelete="RESTRICT",
            name="fk_service_account_steward_space_member",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_service_account_space",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            ondelete="RESTRICT",
            name="fk_service_account_project",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(SERVICE_ACCOUNT_STATUSES)})",
            name="ck_service_account_status",
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_service_account_name_nonempty"),
        sa.CheckConstraint("security_version > 0", name="ck_service_account_security_version"),
        sa.CheckConstraint(
            "project_id IS NULL OR space_id IS NOT NULL",
            name="ck_service_account_project_requires_space",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_service_account_tenant_id"),
        sa.Index(
            "ix_service_account_scope_status",
            "tenant_id",
            "space_id",
            "project_id",
            "status",
        ),
        sa.Index(
            "ix_service_account_steward",
            "tenant_id",
            "steward_user_id",
            "status",
        ),
    )


class ApiCredentialRecord(SaasBase):
    """Revocable API key; PostgreSQL stores only an HMAC digest, never the secret."""

    __tablename__ = "saas_api_credentials"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    service_account_id: Mapped[UUID] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    display_prefix: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    permission_scopes: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    allowed_networks: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    account_security_version: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_used_ip: Mapped[str | None] = mapped_column(sa.String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "service_account_id"),
            ("saas_service_accounts.tenant_id", "saas_service_accounts.id"),
            ondelete="RESTRICT",
            name="fk_api_credential_service_account",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(API_CREDENTIAL_STATUSES)})",
            name="ck_api_credential_status",
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_api_credential_name_nonempty"),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_api_credential_token_hash"),
        sa.CheckConstraint(
            "length(display_prefix) > 0", name="ck_api_credential_prefix_nonempty"
        ),
        sa.CheckConstraint(
            "account_security_version > 0", name="ck_api_credential_security_version"
        ),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL)",
            name="ck_api_credential_revocation",
        ),
        sa.Index(
            "ix_api_credential_account_status",
            "tenant_id",
            "service_account_id",
            "status",
            "expires_at",
        ),
    )
