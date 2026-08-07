"""Independent Staff Realm, platform access, and content-blind projections."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

PLATFORM_STAFF_STATUSES = ("active", "suspended", "deleted")
PLATFORM_ASSIGNMENT_STATUSES = ("active", "revoked", "expired")
PLATFORM_ROLES = (
    "platform_operator",
    "platform_security_auditor",
    "support_agent",
    "billing_operator",
    "compliance_operator",
)


class PlatformStaffPrincipalRecord(SaasBase):
    """Staff-only identity that never doubles as a customer Global User."""

    __tablename__ = "saas_platform_staff_principals"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    identity_connection_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    issuer: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    subject: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.String(256))
    email_normalized: Mapped[str | None] = mapped_column(sa.String(320))
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
        sa.CheckConstraint(
            f"status IN ({_values(PLATFORM_STAFF_STATUSES)})",
            name="ck_platform_staff_status",
        ),
        sa.CheckConstraint("security_version > 0", name="ck_platform_staff_security_version"),
        sa.CheckConstraint(
            "length(identity_connection_ref) > 0",
            name="ck_platform_staff_identity_ref_nonempty",
        ),
        sa.CheckConstraint("length(issuer) > 0", name="ck_platform_staff_issuer_nonempty"),
        sa.CheckConstraint("length(subject) > 0", name="ck_platform_staff_subject_nonempty"),
        sa.UniqueConstraint("issuer", "subject", name="uq_platform_staff_subject"),
        sa.UniqueConstraint(
            "identity_connection_ref", name="uq_platform_staff_identity_connection_ref"
        ),
        sa.Index("ix_platform_staff_status", "status", "updated_at"),
    )


class PlatformRoleAssignmentRecord(SaasBase):
    """Versioned, expiring assignment of one immutable platform role."""

    __tablename__ = "saas_platform_role_assignments"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    assigned_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approval_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    reason: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
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
        sa.CheckConstraint(
            f"role IN ({_values(PLATFORM_ROLES)})", name="ck_platform_assignment_role"
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PLATFORM_ASSIGNMENT_STATUSES)})",
            name="ck_platform_assignment_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_platform_assignment_version"),
        sa.CheckConstraint(
            "length(approval_ref) > 0", name="ck_platform_assignment_approval_nonempty"
        ),
        sa.CheckConstraint("length(reason) > 0", name="ck_platform_assignment_reason_nonempty"),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL AND revoked_by_principal_id IS NULL) "
            "OR (status IN ('revoked', 'expired'))",
            name="ck_platform_assignment_revocation_state",
        ),
        sa.Index(
            "ix_platform_assignment_principal_status",
            "principal_id",
            "status",
            "expires_at",
        ),
    )


class PlatformAuthSessionRecord(SaasBase):
    """Origin- and Audience-bound phishing-resistant Staff Realm session."""

    __tablename__ = "saas_platform_auth_sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    csrf_token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    security_version: Mapped[int] = mapped_column(nullable=False)
    audience: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    origin: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    authn_method: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    mfa_strength: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    authenticated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint("length(token_hash) = 64", name="ck_platform_session_token_hash"),
        sa.CheckConstraint("length(csrf_token_hash) = 64", name="ck_platform_session_csrf_hash"),
        sa.CheckConstraint("security_version > 0", name="ck_platform_session_security_version"),
        sa.CheckConstraint("length(audience) > 0", name="ck_platform_session_audience_nonempty"),
        sa.CheckConstraint("length(origin) > 0", name="ck_platform_session_origin_nonempty"),
        sa.CheckConstraint(
            "length(authn_method) > 0", name="ck_platform_session_authn_method_nonempty"
        ),
        sa.CheckConstraint(
            "mfa_strength = 'phishing_resistant'", name="ck_platform_session_mfa_strength"
        ),
        sa.CheckConstraint(
            "authenticated_at < expires_at", name="ck_platform_session_expiry_order"
        ),
        sa.Index(
            "ix_platform_session_principal_active",
            "principal_id",
            "revoked_at",
            "expires_at",
        ),
    )


class PlatformTenantProjectionRecord(SaasBase):
    """Cross-Tenant metadata projection with no customer content columns."""

    __tablename__ = "saas_platform_tenant_projections"

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    plan: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    home_region: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    member_count: Mapped[int] = mapped_column(nullable=False, default=0)
    space_count: Mapped[int] = mapped_column(nullable=False, default=0)
    source_version: Mapped[int] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("member_count >= 0", name="ck_platform_tenant_member_count"),
        sa.CheckConstraint("space_count >= 0", name="ck_platform_tenant_space_count"),
        sa.CheckConstraint("source_version > 0", name="ck_platform_tenant_source_version"),
        sa.Index("ix_platform_tenant_projection_list", "status", "tenant_id"),
    )


class PlatformUserProjectionRecord(SaasBase):
    """Global User metadata projection that stores only a masked email."""

    __tablename__ = "saas_platform_user_projections"

    user_id: Mapped[UUID] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.String(256))
    email_masked: Mapped[str | None] = mapped_column(sa.String(320))
    membership_count: Mapped[int] = mapped_column(nullable=False, default=0)
    security_version: Mapped[int] = mapped_column(nullable=False)
    source_version: Mapped[int] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("membership_count >= 0", name="ck_platform_user_membership_count"),
        sa.CheckConstraint("security_version > 0", name="ck_platform_user_security_version"),
        sa.CheckConstraint("source_version > 0", name="ck_platform_user_source_version"),
        sa.Index("ix_platform_user_projection_list", "status", "user_id"),
    )
