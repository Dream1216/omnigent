"""SQLAlchemy records owned by the SaaS control plane."""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

USER_STATUSES = ("active", "suspended", "deleted")
TENANT_STATUSES = (
    "provisioning",
    "trial",
    "active",
    "suspended",
    "pending_deletion",
    "deleted",
)
SPACE_STATUSES = ("active", "suspended", "archived")
MEMBERSHIP_STATUSES = ("invited", "active", "suspended", "removed")
TENANT_ROLES = (
    "owner",
    "admin",
    "billing_admin",
    "security_auditor",
    "operator",
    "member",
)
SPACE_ROLES = ("owner", "admin", "operator", "member", "viewer")
IDENTITY_CONNECTION_STATUSES = ("active", "revoked")
OIDC_LOGIN_TRANSACTION_STATUSES = ("pending", "consumed", "failed")
OIDC_LOGIN_PURPOSES = ("login", "link")
IDENTITY_CONFLICT_STATUSES = ("pending", "approved", "rejected")
IDENTITY_CONFLICT_PLATFORM_REVIEW_STATUSES = ("unreviewed", "assigned", "blocked")
INVITATION_STATUSES = ("pending", "accepted", "revoked", "expired")
OWNER_TRANSFER_STATUSES = ("completed", "cancelled")
REMOVAL_PREFLIGHT_STATUSES = ("ready", "blocked", "executed", "expired", "cancelled")
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
PROJECT_STATUSES = ("active", "suspended", "archived")
PROJECT_VISIBILITIES = ("private", "space", "restricted")
PROJECT_ROLES = ("owner", "manage", "operate", "edit", "read")
GRANT_SUBJECT_TYPES = ("user", "space")
GRANT_STATUSES = ("active", "revoked")
BINDING_SAGA_STATUSES = (
    "pending",
    "runtime_created",
    "bound",
    "compensating",
    "compensated",
    "failed",
)
OUTBOX_QUARANTINE_ACTIONS = ("quarantined",)


def _values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _hex64(column: str) -> str:
    """Return a SQLite/PostgreSQL portable lowercase SHA-256 check."""

    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {remainder} = ''"


class SaasBase(DeclarativeBase):
    """Declarative base kept separate from official Omnigent metadata."""

    type_annotation_map: ClassVar[dict[type[UUID], sa.Uuid]] = {UUID: sa.Uuid(as_uuid=True)}


class GlobalUser(SaasBase):
    """Stable SaaS user identity; authentication connections remain separate."""

    __tablename__ = "saas_global_users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    display_name: Mapped[str | None] = mapped_column(sa.String(256))
    primary_email_normalized: Mapped[str | None] = mapped_column(sa.String(320))
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


class IdentityConnection(SaasBase):
    """Authoritative authentication subject linked to one Global User."""

    __tablename__ = "saas_identity_connections"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    issuer: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    subject: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    email_normalized: Mapped[str | None] = mapped_column(sa.String(320))
    email_verified: Mapped[bool] = mapped_column(nullable=False, default=False)
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
            f"status IN ({_values(IDENTITY_CONNECTION_STATUSES)})",
            name="ck_identity_connection_status",
        ),
        sa.CheckConstraint("length(provider) > 0", name="ck_identity_provider_nonempty"),
        sa.CheckConstraint("length(issuer) > 0", name="ck_identity_issuer_nonempty"),
        sa.CheckConstraint("length(subject) > 0", name="ck_identity_subject_nonempty"),
        sa.UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),
        sa.Index("ix_identity_user_status", "user_id", "status"),
        sa.Index("ix_identity_verified_email", "email_normalized", "email_verified"),
    )


class AuthSessionRecord(SaasBase):
    """Revocable authentication session storing only a bearer-token digest."""

    __tablename__ = "saas_auth_sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    csrf_token_hash: Mapped[str | None] = mapped_column(sa.String(64))
    security_version: Mapped[int] = mapped_column(nullable=False)
    authn_method: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint("length(token_hash) = 64", name="ck_auth_session_token_hash"),
        sa.CheckConstraint(
            "csrf_token_hash IS NULL OR length(csrf_token_hash) = 64",
            name="ck_auth_session_csrf_hash",
        ),
        sa.CheckConstraint("security_version > 0", name="ck_auth_session_security_version"),
        sa.CheckConstraint("length(authn_method) > 0", name="ck_auth_session_method_nonempty"),
        sa.Index("ix_auth_session_user_active", "user_id", "revoked_at", "expires_at"),
    )


class PasswordCredential(SaasBase):
    """Argon2id password credential kept separate from the Global User."""

    __tablename__ = "saas_password_credentials"

    user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), primary_key=True
    )
    login_email_normalized: Mapped[str] = mapped_column(
        sa.String(320), nullable=False, unique=True
    )
    password_hash: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    password_version: Mapped[int] = mapped_column(nullable=False, default=1)
    failed_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.CheckConstraint(
            "length(login_email_normalized) > 0", name="ck_password_login_email_nonempty"
        ),
        sa.CheckConstraint("length(password_hash) > 0", name="ck_password_hash_nonempty"),
        sa.CheckConstraint("password_version > 0", name="ck_password_version"),
        sa.CheckConstraint("failed_attempts >= 0", name="ck_password_failed_attempts"),
    )


class OidcLoginTransaction(SaasBase):
    """One-time, replica-independent Authorization Code + PKCE transaction."""

    __tablename__ = "saas_oidc_login_transactions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    state_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    browser_binding_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    code_verifier_ciphertext: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    purpose: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    target_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    target_security_version: Mapped[int | None] = mapped_column()
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"status IN ({_values(OIDC_LOGIN_TRANSACTION_STATUSES)})",
            name="ck_oidc_login_transaction_status",
        ),
        sa.CheckConstraint(
            f"purpose IN ({_values(OIDC_LOGIN_PURPOSES)})",
            name="ck_oidc_login_transaction_purpose",
        ),
        sa.CheckConstraint("length(provider) > 0", name="ck_oidc_login_provider_nonempty"),
        sa.CheckConstraint("length(state_hash) = 64", name="ck_oidc_login_state_hash"),
        sa.CheckConstraint(
            "length(browser_binding_hash) = 64", name="ck_oidc_login_browser_binding_hash"
        ),
        sa.CheckConstraint("length(nonce_hash) = 64", name="ck_oidc_login_nonce_hash"),
        sa.CheckConstraint(
            "length(code_verifier_ciphertext) > 0", name="ck_oidc_login_verifier_nonempty"
        ),
        sa.CheckConstraint(
            "(purpose = 'login' AND target_user_id IS NULL "
            "AND target_security_version IS NULL) OR "
            "(purpose = 'link' AND target_user_id IS NOT NULL "
            "AND target_security_version > 0)",
            name="ck_oidc_login_target_by_purpose",
        ),
        sa.Index("ix_oidc_login_expiry", "status", "expires_at"),
    )


class IdentityConflict(SaasBase):
    """Verified OIDC subject awaiting explicit same-account confirmation."""

    __tablename__ = "saas_identity_conflicts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    issuer: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    subject: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    email_normalized: Mapped[str] = mapped_column(sa.String(320), nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.String(256))
    candidate_user_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    platform_review_status: Mapped[str] = mapped_column(
        sa.String(32), nullable=False, default="unreviewed"
    )
    platform_reviewed_by_principal_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT")
    )
    platform_review_approval_ref: Mapped[str | None] = mapped_column(sa.String(256))
    platform_review_reason: Mapped[str | None] = mapped_column(sa.String(1024))
    platform_reviewed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolved_by: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    resolution_reason: Mapped[str | None] = mapped_column(sa.String(1024))
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            f"status IN ({_values(IDENTITY_CONFLICT_STATUSES)})",
            name="ck_identity_conflict_status",
        ),
        sa.CheckConstraint("length(provider) > 0", name="ck_identity_conflict_provider"),
        sa.CheckConstraint("length(issuer) > 0", name="ck_identity_conflict_issuer"),
        sa.CheckConstraint("length(subject) > 0", name="ck_identity_conflict_subject"),
        sa.CheckConstraint("length(email_normalized) > 0", name="ck_identity_conflict_email"),
        sa.CheckConstraint("version > 0", name="ck_identity_conflict_version"),
        sa.CheckConstraint(
            f"platform_review_status IN ({_values(IDENTITY_CONFLICT_PLATFORM_REVIEW_STATUSES)})",
            name="ck_identity_conflict_platform_review_status",
        ),
        sa.CheckConstraint(
            "(platform_review_status = 'unreviewed' "
            "AND platform_reviewed_by_principal_id IS NULL "
            "AND platform_review_approval_ref IS NULL "
            "AND platform_review_reason IS NULL AND platform_reviewed_at IS NULL) OR "
            "(platform_review_status = 'assigned' AND candidate_user_id IS NOT NULL "
            "AND platform_reviewed_by_principal_id IS NOT NULL "
            "AND length(platform_review_approval_ref) > 0 "
            "AND length(platform_review_reason) > 0 AND platform_reviewed_at IS NOT NULL) OR "
            "(platform_review_status = 'blocked' AND candidate_user_id IS NULL "
            "AND platform_reviewed_by_principal_id IS NOT NULL "
            "AND length(platform_review_approval_ref) > 0 "
            "AND length(platform_review_reason) > 0 AND platform_reviewed_at IS NOT NULL)",
            name="ck_identity_conflict_platform_review",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND resolved_by IS NULL AND resolved_at IS NULL "
            "AND resolution_reason IS NULL) OR "
            "(status IN ('approved', 'rejected') AND resolved_by IS NOT NULL "
            "AND resolved_at IS NOT NULL AND length(resolution_reason) > 0)",
            name="ck_identity_conflict_resolution",
        ),
        sa.UniqueConstraint("issuer", "subject", name="uq_identity_conflict_issuer_subject"),
        sa.Index("ix_identity_conflict_candidate", "candidate_user_id", "status"),
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
    lifecycle_version: Mapped[int] = mapped_column(nullable=False, default=1)
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
        sa.CheckConstraint("lifecycle_version > 0", name="ck_tenant_lifecycle_version"),
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
        sa.Index(
            "ix_tenant_membership_directory",
            "tenant_id",
            "status",
            "role",
            "user_id",
        ),
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
        sa.Index(
            "ix_space_membership_member_directory",
            "tenant_id",
            "user_id",
            "status",
            "space_id",
        ),
    )


class ProjectRecord(SaasBase):
    """Project collaboration boundary; content access is never implied by Tenant admin."""

    __tablename__ = "saas_projects"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    visibility: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="private")
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    authorization_version: Mapped[int] = mapped_column(nullable=False, default=1)
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
            name="fk_project_space",
        ),
        sa.CheckConstraint(
            f"visibility IN ({_values(PROJECT_VISIBILITIES)})",
            name="ck_project_visibility",
        ),
        sa.CheckConstraint(f"status IN ({_values(PROJECT_STATUSES)})", name="ck_project_status"),
        sa.CheckConstraint("length(name) > 0", name="ck_project_name_nonempty"),
        sa.CheckConstraint("authorization_version > 0", name="ck_project_auth_version"),
        sa.UniqueConstraint("tenant_id", "space_id", "id", name="uq_project_scope"),
        sa.Index("ix_project_scope_status", "tenant_id", "space_id", "status"),
    )


class ProjectMembershipRecord(SaasBase):
    """Versioned scoped Project role for a user or the containing Space."""

    __tablename__ = "saas_project_memberships"

    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(primary_key=True)
    subject_type: Mapped[str] = mapped_column(sa.String(32), primary_key=True)
    subject_id: Mapped[UUID] = mapped_column(primary_key=True)
    role: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
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

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            ondelete="RESTRICT",
            name="fk_project_membership_project",
        ),
        sa.CheckConstraint(
            f"subject_type IN ({_values(GRANT_SUBJECT_TYPES)})",
            name="ck_project_membership_subject_type",
        ),
        sa.CheckConstraint(
            f"role IN ({_values(PROJECT_ROLES)})", name="ck_project_membership_role"
        ),
        sa.CheckConstraint(
            f"status IN ({_values(GRANT_STATUSES)})", name="ck_project_membership_status"
        ),
        sa.CheckConstraint(
            "subject_type <> 'space' OR subject_id = space_id",
            name="ck_project_membership_space_subject",
        ),
        sa.CheckConstraint("version > 0", name="ck_project_membership_version"),
        sa.Index(
            "ix_project_membership_subject",
            "tenant_id",
            "space_id",
            "subject_type",
            "subject_id",
            "status",
        ),
    )


class ResourceGrantRecord(SaasBase):
    """Additive resource-scoped role; strong policy restrictions are evaluated separately."""

    __tablename__ = "saas_resource_grants"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    resource_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    resource_id: Mapped[UUID] = mapped_column(nullable=False)
    subject_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    subject_id: Mapped[UUID] = mapped_column(nullable=False)
    role: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
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

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            ondelete="RESTRICT",
            name="fk_resource_grant_project",
        ),
        sa.CheckConstraint(
            f"subject_type IN ({_values(GRANT_SUBJECT_TYPES)})",
            name="ck_resource_grant_subject_type",
        ),
        sa.CheckConstraint(f"role IN ({_values(PROJECT_ROLES)})", name="ck_resource_grant_role"),
        sa.CheckConstraint(
            f"status IN ({_values(GRANT_STATUSES)})", name="ck_resource_grant_status"
        ),
        sa.CheckConstraint(
            "subject_type <> 'space' OR subject_id = space_id",
            name="ck_resource_grant_space_subject",
        ),
        sa.CheckConstraint("length(resource_type) > 0", name="ck_resource_grant_type_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_resource_grant_version"),
        sa.Index(
            "uq_active_resource_grant",
            "tenant_id",
            "space_id",
            "project_id",
            "resource_type",
            "resource_id",
            "subject_type",
            "subject_id",
            unique=True,
            sqlite_where=sa.text("status = 'active'"),
            postgresql_where=sa.text("status = 'active'"),
        ),
        sa.Index(
            "ix_resource_grant_subject",
            "tenant_id",
            "space_id",
            "subject_type",
            "subject_id",
            "status",
        ),
    )


class AuthorizationDecisionRecord(SaasBase):
    """Auditable shadow/enforced authorization result without resource content."""

    __tablename__ = "saas_authorization_decisions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID | None] = mapped_column()
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    action: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(sa.String(64))
    resource_id: Mapped[UUID | None] = mapped_column()
    mode: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    allowed: Mapped[bool] = mapped_column(nullable=False)
    reason: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    sources: Mapped[list[dict[str, object]]] = mapped_column(sa.JSON, nullable=False)
    policy_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    trace_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_authorization_decision_space",
        ),
        sa.CheckConstraint("mode IN ('shadow', 'enforce')", name="ck_authorization_mode"),
        sa.CheckConstraint("length(action) > 0", name="ck_authorization_action_nonempty"),
        sa.CheckConstraint("length(reason) > 0", name="ck_authorization_reason_nonempty"),
        sa.CheckConstraint("length(trace_id) > 0", name="ck_authorization_trace_nonempty"),
        sa.Index(
            "ix_authorization_decision_scope",
            "tenant_id",
            "space_id",
            "project_id",
            "created_at",
        ),
        sa.Index("ix_authorization_decision_actor", "actor_id", "created_at"),
    )


class RuntimeBindingSagaRecord(SaasBase):
    """Durable cross-database resource-provisioning and Binding state machine."""

    __tablename__ = "saas_runtime_binding_sagas"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    runtime_partition_id: Mapped[UUID] = mapped_column(nullable=False)
    resource_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    saas_resource_id: Mapped[UUID] = mapped_column(nullable=False)
    runtime_resource_id: Mapped[str | None] = mapped_column(sa.String(256))
    binding_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_runtime_resource_bindings.id", ondelete="RESTRICT")
    )
    partition_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(sa.String(2048))
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
            name="fk_binding_saga_project",
        ),
        sa.ForeignKeyConstraint(
            ("runtime_partition_id", "tenant_id", "space_id"),
            (
                "saas_runtime_partitions.id",
                "saas_runtime_partitions.tenant_id",
                "saas_runtime_partitions.space_id",
            ),
            ondelete="RESTRICT",
            name="fk_binding_saga_partition",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(BINDING_SAGA_STATUSES)})",
            name="ck_binding_saga_status",
        ),
        sa.CheckConstraint("length(resource_type) > 0", name="ck_binding_saga_type_nonempty"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_binding_saga_key_nonempty"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_binding_saga_request_hash"),
        sa.CheckConstraint("partition_generation > 0", name="ck_binding_saga_generation"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_binding_saga_attempt_count"),
        sa.CheckConstraint(
            "(status = 'pending' AND runtime_resource_id IS NULL) OR "
            "(status <> 'pending' AND runtime_resource_id IS NOT NULL)",
            name="ck_binding_saga_runtime_resource_state",
        ),
        sa.CheckConstraint(
            "(status = 'bound' AND binding_id IS NOT NULL) OR "
            "(status <> 'bound' AND binding_id IS NULL)",
            name="ck_binding_saga_binding_state",
        ),
        sa.Index(
            "ix_binding_saga_scope_status",
            "tenant_id",
            "space_id",
            "project_id",
            "status",
        ),
    )


class RuntimeProviderOperationJournalRecord(SaasBase):
    """Durable Provider invocation fence and immutable verified response."""

    __tablename__ = "saas_runtime_provider_operation_journal"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    provider_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    operation_kind: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    placement_id: Mapped[UUID] = mapped_column(nullable=False)
    binding_revision: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    binding_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    target_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    idempotency_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    receipt_hash: Mapped[str | None] = mapped_column(sa.String(64))
    attributes_hash: Mapped[str | None] = mapped_column(sa.String(64))
    response_hash: Mapped[str | None] = mapped_column(sa.String(64))
    receipt_json: Mapped[str | None] = mapped_column(sa.Text())
    attributes_json: Mapped[str | None] = mapped_column(sa.Text())
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.CheckConstraint(
            "operation_kind IN ('allocate_partition', 'provision_default_project', "
            "'compensate_default_project', 'compensate_partition')",
            name="ck_runtime_provider_journal_operation",
        ),
        sa.CheckConstraint(
            "length(provider_type) > 0", name="ck_runtime_provider_journal_provider"
        ),
        sa.CheckConstraint(
            "length(binding_revision) > 0", name="ck_runtime_provider_journal_revision"
        ),
        sa.CheckConstraint(
            _hex64("binding_hash"), name="ck_runtime_provider_journal_binding_hash"
        ),
        sa.CheckConstraint(_hex64("target_hash"), name="ck_runtime_provider_journal_target_hash"),
        sa.CheckConstraint(
            _hex64("idempotency_hash"), name="ck_runtime_provider_journal_idempotency_hash"
        ),
        sa.CheckConstraint(
            _hex64("request_hash"), name="ck_runtime_provider_journal_request_hash"
        ),
        sa.CheckConstraint(
            "(receipt_hash IS NULL AND attributes_hash IS NULL AND response_hash IS NULL "
            "AND receipt_json IS NULL AND attributes_json IS NULL AND verified_at IS NULL) OR "
            "(receipt_hash IS NOT NULL AND attributes_hash IS NOT NULL "
            "AND response_hash IS NOT NULL AND receipt_json IS NOT NULL "
            "AND attributes_json IS NOT NULL AND verified_at IS NOT NULL)",
            name="ck_runtime_provider_journal_response_atomic",
        ),
        sa.CheckConstraint(
            f"receipt_hash IS NULL OR ({_hex64('receipt_hash')})",
            name="ck_runtime_provider_journal_receipt_hash",
        ),
        sa.CheckConstraint(
            f"attributes_hash IS NULL OR ({_hex64('attributes_hash')})",
            name="ck_runtime_provider_journal_attributes_hash",
        ),
        sa.CheckConstraint(
            f"response_hash IS NULL OR ({_hex64('response_hash')})",
            name="ck_runtime_provider_journal_response_hash",
        ),
        sa.UniqueConstraint(
            "provider_type",
            "operation_kind",
            "idempotency_hash",
            name="uq_runtime_provider_journal_identity",
        ),
        sa.UniqueConstraint(
            "request_hash",
            name="uq_runtime_provider_journal_request_hash",
        ),
        sa.Index(
            "ix_runtime_provider_journal_pending",
            "created_at",
            postgresql_where=sa.text("response_hash IS NULL"),
            sqlite_where=sa.text("response_hash IS NULL"),
        ),
    )


class MembershipInvitation(SaasBase):
    """Single-use invitation bound to an email, Tenant, optional Space, and roles."""

    __tablename__ = "saas_membership_invitations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    space_id: Mapped[UUID | None] = mapped_column()
    email_normalized: Mapped[str] = mapped_column(sa.String(320), nullable=False)
    tenant_role: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    space_role: Mapped[str | None] = mapped_column(sa.String(32))
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    accepted_by: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    accepted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    deletion_manifest_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_privacy_deletion_manifests.id", ondelete="RESTRICT")
    )
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
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

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_invitation_space",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(INVITATION_STATUSES)})", name="ck_invitation_status"
        ),
        sa.CheckConstraint(
            f"tenant_role IN ({_values(TENANT_ROLES)})", name="ck_invitation_tenant_role"
        ),
        sa.CheckConstraint(
            f"space_role IS NULL OR space_role IN ({_values(SPACE_ROLES)})",
            name="ck_invitation_space_role",
        ),
        sa.CheckConstraint(
            "(space_id IS NULL AND space_role IS NULL) OR "
            "(space_id IS NOT NULL AND space_role IS NOT NULL)",
            name="ck_invitation_space_role_pair",
        ),
        sa.CheckConstraint("length(email_normalized) > 0", name="ck_invitation_email_nonempty"),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_invitation_token_hash"),
        sa.CheckConstraint("version > 0", name="ck_invitation_version"),
        sa.Index(
            "ix_invitation_scope_email_status",
            "tenant_id",
            "space_id",
            "email_normalized",
            "status",
        ),
        sa.Index(
            "ix_invitation_tenant_status_expiry",
            "tenant_id",
            "status",
            "expires_at",
            "id",
        ),
    )


class ControlPlaneOutboxEvent(SaasBase):
    """Persist-first control-plane event and idempotency receipt."""

    __tablename__ = "saas_control_plane_outbox"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    aggregate_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    aggregate_key: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    available_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    claimed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    claim_token: Mapped[UUID | None] = mapped_column()
    last_error: Mapped[str | None] = mapped_column(sa.String(2048), server_default=sa.text("NULL"))
    # Dispatcher-owned terminal metadata deliberately uses server-side NULL
    # defaults so ordinary producers omit these columns from INSERT and never
    # need privileges that would let them fabricate delivery evidence.
    last_error_code: Mapped[str | None] = mapped_column(
        sa.String(128), server_default=sa.text("NULL")
    )
    last_error_digest: Mapped[str | None] = mapped_column(
        sa.String(64), server_default=sa.text("NULL")
    )
    published_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    quarantined_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.text("NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint("length(aggregate_type) > 0", name="ck_outbox_aggregate_nonempty"),
        sa.CheckConstraint("length(aggregate_key) > 0", name="ck_outbox_key_nonempty"),
        sa.CheckConstraint("length(event_type) > 0", name="ck_outbox_event_nonempty"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_outbox_idempotency_nonempty"),
        sa.CheckConstraint(_hex64("request_hash"), name="ck_outbox_request_hash"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_outbox_attempt_count"),
        sa.CheckConstraint("last_error IS NULL", name="ck_outbox_legacy_error_null"),
        sa.CheckConstraint(
            "published_at IS NULL OR quarantined_at IS NULL",
            name="ck_outbox_terminal_exclusive",
        ),
        sa.CheckConstraint(
            "quarantined_at IS NULL OR "
            "(available_at IS NULL AND claimed_at IS NULL AND claim_token IS NULL)",
            name="ck_outbox_quarantine_dispatch_clear",
        ),
        sa.CheckConstraint(
            "(last_error_code IS NULL AND last_error_digest IS NULL) OR "
            "(length(last_error_code) BETWEEN 1 AND 128 AND last_error_digest IS NOT NULL)",
            name="ck_outbox_safe_error_pair",
        ),
        sa.CheckConstraint(
            f"last_error_digest IS NULL OR ({_hex64('last_error_digest')})",
            name="ck_outbox_safe_error_digest",
        ),
        sa.Index("ix_outbox_unpublished", "published_at", "created_at"),
        sa.Index("ix_outbox_dispatchable", "published_at", "available_at", "claimed_at"),
        sa.Index(
            "ix_outbox_dispatchable_v2",
            "quarantined_at",
            "published_at",
            "available_at",
            "claimed_at",
        ),
        sa.Index("ix_outbox_tenant_event", "tenant_id", "event_type", "created_at"),
        # Producers have no privilege to read dispatcher-owned defaults.  Avoid
        # PostgreSQL INSERT .. RETURNING of those columns; IDs are application
        # assigned and created_at can be read explicitly when needed.
        {"implicit_returning": False},
    )


class ControlPlaneOutboxQuarantineEvent(SaasBase):
    """Append-only, content-blind evidence for one terminal Outbox quarantine."""

    __tablename__ = "saas_outbox_quarantine_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    source_event_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_control_plane_outbox.id", ondelete="RESTRICT"), nullable=False
    )
    tenant_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT")
    )
    source_request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_attempt_count: Mapped[int] = mapped_column(nullable=False)
    action: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    error_code: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    error_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    sequence: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    previous_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            f"action IN ({_values(OUTBOX_QUARANTINE_ACTIONS)})",
            name="ck_outbox_quarantine_action",
        ),
        sa.CheckConstraint("source_attempt_count > 0", name="ck_outbox_quarantine_attempt_count"),
        sa.CheckConstraint(
            "length(error_code) BETWEEN 1 AND 128",
            name="ck_outbox_quarantine_error_code",
        ),
        sa.CheckConstraint(_hex64("source_request_hash"), name="ck_outbox_quarantine_source_hash"),
        sa.CheckConstraint(_hex64("error_digest"), name="ck_outbox_quarantine_error_digest"),
        sa.CheckConstraint("sequence > 0", name="ck_outbox_quarantine_sequence"),
        sa.CheckConstraint(_hex64("previous_hash"), name="ck_outbox_quarantine_previous_hash"),
        sa.CheckConstraint(_hex64("event_hash"), name="ck_outbox_quarantine_event_hash"),
        sa.UniqueConstraint(
            "source_event_id",
            "sequence",
            name="uq_outbox_quarantine_source_sequence",
        ),
        sa.Index(
            "uq_outbox_quarantine_once",
            "source_event_id",
            unique=True,
            sqlite_where=sa.text("action = 'quarantined'"),
            postgresql_where=sa.text("action = 'quarantined'"),
        ),
        sa.Index(
            "ix_outbox_quarantine_tenant_created",
            "tenant_id",
            "created_at",
            "id",
        ),
    )


class OwnershipTransferRecord(SaasBase):
    """Immutable receipt for an atomic Tenant or Space ownership transfer."""

    __tablename__ = "saas_ownership_transfers"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    space_id: Mapped[UUID | None] = mapped_column()
    from_user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    to_user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    requested_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    reason: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="completed")
    source_version_before: Mapped[int] = mapped_column(nullable=False)
    target_version_before: Mapped[int] = mapped_column(nullable=False)
    source_version_after: Mapped[int] = mapped_column(nullable=False)
    target_version_after: Mapped[int] = mapped_column(nullable=False)
    completed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_ownership_transfer_space",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(OWNER_TRANSFER_STATUSES)})",
            name="ck_ownership_transfer_status",
        ),
        sa.CheckConstraint("from_user_id <> to_user_id", name="ck_owner_transfer_distinct_users"),
        sa.CheckConstraint("length(reason) > 0", name="ck_owner_transfer_reason_nonempty"),
        sa.CheckConstraint(
            "source_version_before > 0 AND target_version_before > 0 AND "
            "source_version_after > source_version_before AND "
            "target_version_after > target_version_before",
            name="ck_owner_transfer_versions",
        ),
        sa.Index("ix_ownership_transfer_scope", "tenant_id", "space_id", "created_at"),
    )


class MemberRemovalPreflightRecord(SaasBase):
    """Time-limited, hash-bound resource impact snapshot for member removal."""

    __tablename__ = "saas_member_removal_preflights"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    space_id: Mapped[UUID | None] = mapped_column()
    user_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    requested_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    membership_version: Mapped[int] = mapped_column(nullable=False)
    impact_snapshot: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    blocking_count: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    executed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_member_removal_preflight_space",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(REMOVAL_PREFLIGHT_STATUSES)})",
            name="ck_member_removal_preflight_status",
        ),
        sa.CheckConstraint("membership_version > 0", name="ck_removal_membership_version"),
        sa.CheckConstraint("length(snapshot_hash) = 64", name="ck_removal_snapshot_hash"),
        sa.CheckConstraint("blocking_count >= 0", name="ck_removal_blocking_count"),
        sa.Index("ix_member_removal_scope", "tenant_id", "space_id", "user_id", "status"),
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
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            ondelete="RESTRICT",
            name="fk_runtime_binding_project_scope",
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
