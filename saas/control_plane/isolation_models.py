"""P4 server-chosen isolation, secret-broker, egress, and Preview facts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase

EGRESS_POLICY_STATUSES = frozenset({"active", "retired"})
EXECUTION_PROFILE_STATUSES = frozenset({"active", "retired"})
SECRET_BINDING_STATUSES = frozenset({"active", "disabled"})
ISOLATION_GRANT_STATUSES = frozenset({"active", "redeemed", "revoked"})
SECRET_LEASE_STATUSES = frozenset({"active", "redeemed", "revoked"})
PREVIEW_LEASE_STATUSES = frozenset({"active", "revoked"})
SANDBOX_BACKENDS = frozenset({"linux_bwrap", "darwin_seatbelt"})
CREDENTIAL_SCHEMES = frozenset({"basic", "bearer", "token"})


def _values(values: frozenset[str]) -> str:
    return ", ".join(f"'{value}'" for value in sorted(values))


class EgressPolicyRecord(SaasBase):
    """Immutable-versioned, default-deny L7 policy selected by the server."""

    __tablename__ = "saas_egress_policies"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    rules: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    rules_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    allow_private_destinations: Mapped[bool] = mapped_column(nullable=False, default=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
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
            name="fk_egress_policy_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(EGRESS_POLICY_STATUSES)})", name="ck_egress_policy_status"
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_egress_policy_name_nonempty"),
        sa.CheckConstraint("length(rules_hash) = 64", name="ck_egress_policy_hash"),
        sa.CheckConstraint(
            "allow_private_destinations = false", name="ck_egress_policy_no_private"
        ),
        sa.CheckConstraint("version > 0", name="ck_egress_policy_version"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_egress_policy_scope"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "name",
            "version",
            name="uq_egress_policy_project_name_version",
        ),
        sa.Index(
            "ix_egress_policy_project_status",
            "tenant_id",
            "space_id",
            "project_id",
            "status",
        ),
    )


class ExecutionProfileRecord(SaasBase):
    """Immutable-versioned sandbox and tool policy for managed Runs."""

    __tablename__ = "saas_execution_profiles"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    egress_policy_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    sandbox_backend: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    network_mode: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    root_read_only: Mapped[bool] = mapped_column(nullable=False, default=True)
    run_as_uid: Mapped[int] = mapped_column(nullable=False)
    run_as_gid: Mapped[int] = mapped_column(nullable=False)
    no_new_privileges: Mapped[bool] = mapped_column(nullable=False, default=True)
    host_socket_access: Mapped[bool] = mapped_column(nullable=False, default=False)
    syscall_profile_ref: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    cpu_millis: Mapped[int] = mapped_column(nullable=False)
    memory_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    pids_limit: Mapped[int] = mapped_column(nullable=False)
    allowed_tools: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    approval_required_tools: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    denied_tools: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    config_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
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
            name="fk_execution_profile_project_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("egress_policy_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_egress_policies.id",
                "saas_egress_policies.tenant_id",
                "saas_egress_policies.space_id",
                "saas_egress_policies.project_id",
            ),
            name="fk_execution_profile_egress_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"sandbox_backend IN ({_values(SANDBOX_BACKENDS)})",
            name="ck_execution_profile_backend",
        ),
        sa.CheckConstraint("network_mode = 'proxy_only'", name="ck_execution_profile_network"),
        sa.CheckConstraint("root_read_only = true", name="ck_execution_profile_readonly_root"),
        sa.CheckConstraint("run_as_uid > 0", name="ck_execution_profile_nonroot_uid"),
        sa.CheckConstraint("run_as_gid > 0", name="ck_execution_profile_nonroot_gid"),
        sa.CheckConstraint(
            "no_new_privileges = true", name="ck_execution_profile_no_new_privileges"
        ),
        sa.CheckConstraint(
            "host_socket_access = false", name="ck_execution_profile_no_host_socket"
        ),
        sa.CheckConstraint("cpu_millis > 0", name="ck_execution_profile_cpu"),
        sa.CheckConstraint("memory_bytes > 0", name="ck_execution_profile_memory"),
        sa.CheckConstraint("pids_limit > 0", name="ck_execution_profile_pids"),
        sa.CheckConstraint("length(name) > 0", name="ck_execution_profile_name_nonempty"),
        sa.CheckConstraint(
            "length(syscall_profile_ref) > 0", name="ck_execution_profile_syscall_nonempty"
        ),
        sa.CheckConstraint("length(config_hash) = 64", name="ck_execution_profile_hash"),
        sa.CheckConstraint(
            f"status IN ({_values(EXECUTION_PROFILE_STATUSES)})",
            name="ck_execution_profile_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_execution_profile_version"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_execution_profile_scope"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "space_id",
            "project_id",
            "name",
            "version",
            name="uq_execution_profile_project_name_version",
        ),
        sa.Index(
            "ix_execution_profile_project_status",
            "tenant_id",
            "space_id",
            "project_id",
            "status",
        ),
    )


class SecretBindingRecord(SaasBase):
    """Secret metadata and vault reference; plaintext is never persisted."""

    __tablename__ = "saas_secret_bindings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    execution_profile_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    vault_provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    vault_ref: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    version_ref: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    credential_scheme: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    host: Mapped[str] = mapped_column(sa.String(253), nullable=False)
    username: Mapped[str | None] = mapped_column(sa.String(128))
    inject_env: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    metadata_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
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
            ("execution_profile_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_execution_profiles.id",
                "saas_execution_profiles.tenant_id",
                "saas_execution_profiles.space_id",
                "saas_execution_profiles.project_id",
            ),
            name="fk_secret_binding_profile_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"credential_scheme IN ({_values(CREDENTIAL_SCHEMES)})",
            name="ck_secret_binding_scheme",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(SECRET_BINDING_STATUSES)})",
            name="ck_secret_binding_status",
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_secret_binding_name_nonempty"),
        sa.CheckConstraint(
            "length(vault_provider) > 0", name="ck_secret_binding_provider_nonempty"
        ),
        sa.CheckConstraint("length(vault_ref) > 0", name="ck_secret_binding_ref_nonempty"),
        sa.CheckConstraint(
            "length(version_ref) > 0", name="ck_secret_binding_version_ref_nonempty"
        ),
        sa.CheckConstraint("length(host) > 0", name="ck_secret_binding_host_nonempty"),
        sa.CheckConstraint("length(metadata_hash) = 64", name="ck_secret_binding_hash"),
        sa.CheckConstraint("version > 0", name="ck_secret_binding_version"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_secret_binding_scope"
        ),
        sa.UniqueConstraint(
            "execution_profile_id", "name", "version", name="uq_secret_binding_profile_name"
        ),
        sa.Index("ix_secret_binding_profile_status", "execution_profile_id", "status", "name"),
    )


class RunIsolationGrantRecord(SaasBase):
    """One-time Runner launch grant bound to all distributed fences."""

    __tablename__ = "saas_run_isolation_grants"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    runner_id: Mapped[UUID] = mapped_column(nullable=False)
    worktree_id: Mapped[UUID] = mapped_column(nullable=False)
    execution_profile_id: Mapped[UUID] = mapped_column(nullable=False)
    capability_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_capability_tokens.id", ondelete="RESTRICT"), nullable=False
    )
    run_fence_token: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    runner_connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    worktree_lease_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    grant_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    redeemed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_isolation_grant_run_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("worktree_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_worktree_instances.id",
                "saas_worktree_instances.tenant_id",
                "saas_worktree_instances.space_id",
                "saas_worktree_instances.project_id",
            ),
            name="fk_isolation_grant_worktree_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("execution_profile_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_execution_profiles.id",
                "saas_execution_profiles.tenant_id",
                "saas_execution_profiles.space_id",
                "saas_execution_profiles.project_id",
            ),
            name="fk_isolation_grant_profile_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_isolation_grant_token_hash"),
        sa.CheckConstraint("length(grant_hash) = 64", name="ck_isolation_grant_hash"),
        sa.CheckConstraint(
            f"status IN ({_values(ISOLATION_GRANT_STATUSES)})",
            name="ck_isolation_grant_status",
        ),
        sa.CheckConstraint("run_fence_token > 0", name="ck_isolation_grant_run_fence"),
        sa.CheckConstraint(
            "runner_connection_generation > 0", name="ck_isolation_grant_runner_generation"
        ),
        sa.CheckConstraint(
            "worktree_lease_generation > 0", name="ck_isolation_grant_worktree_generation"
        ),
        sa.CheckConstraint(
            "(status = 'active' AND redeemed_at IS NULL AND revoked_at IS NULL) OR "
            "(status = 'redeemed' AND redeemed_at IS NOT NULL AND revoked_at IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL)",
            name="ck_isolation_grant_lifecycle",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_isolation_grant_scope"
        ),
        sa.Index("ix_isolation_grant_expiry", "status", "expires_at"),
    )


class SecretAccessLeaseRecord(SaasBase):
    """One-time broker lease; only a vault reference is persisted."""

    __tablename__ = "saas_secret_access_leases"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    isolation_grant_id: Mapped[UUID] = mapped_column(nullable=False)
    secret_binding_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    runner_id: Mapped[UUID] = mapped_column(nullable=False)
    run_fence_token: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    runner_connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    redeemed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("isolation_grant_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_run_isolation_grants.id",
                "saas_run_isolation_grants.tenant_id",
                "saas_run_isolation_grants.space_id",
                "saas_run_isolation_grants.project_id",
            ),
            name="fk_secret_lease_isolation_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("secret_binding_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_secret_bindings.id",
                "saas_secret_bindings.tenant_id",
                "saas_secret_bindings.space_id",
                "saas_secret_bindings.project_id",
            ),
            name="fk_secret_lease_binding_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_secret_lease_run_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_secret_lease_token_hash"),
        sa.CheckConstraint(
            f"status IN ({_values(SECRET_LEASE_STATUSES)})", name="ck_secret_lease_status"
        ),
        sa.CheckConstraint("run_fence_token > 0", name="ck_secret_lease_run_fence"),
        sa.CheckConstraint(
            "runner_connection_generation > 0", name="ck_secret_lease_runner_generation"
        ),
        sa.CheckConstraint(
            "(status = 'active' AND redeemed_at IS NULL AND revoked_at IS NULL) OR "
            "(status = 'redeemed' AND redeemed_at IS NOT NULL AND revoked_at IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL)",
            name="ck_secret_lease_lifecycle",
        ),
        sa.UniqueConstraint(
            "isolation_grant_id", "secret_binding_id", name="uq_secret_lease_grant_binding"
        ),
        sa.Index("ix_secret_lease_expiry", "status", "expires_at"),
    )


class PreviewLeaseRecord(SaasBase):
    """Short-lived Preview gateway route on a cookie-isolated origin."""

    __tablename__ = "saas_preview_leases"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    runner_id: Mapped[UUID] = mapped_column(nullable=False)
    worktree_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    opaque_preview_key: Mapped[str] = mapped_column(sa.String(96), nullable=False, unique=True)
    preview_host: Mapped[str] = mapped_column(sa.String(253), nullable=False, unique=True)
    run_fence_token: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    runner_connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    worktree_lease_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    response_policy_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_accessed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_preview_lease_run_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("worktree_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_worktree_instances.id",
                "saas_worktree_instances.tenant_id",
                "saas_worktree_instances.space_id",
                "saas_worktree_instances.project_id",
            ),
            name="fk_preview_lease_worktree_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_preview_lease_token_hash"),
        sa.CheckConstraint("length(opaque_preview_key) > 0", name="ck_preview_lease_key_nonempty"),
        sa.CheckConstraint("length(preview_host) > 0", name="ck_preview_lease_host_nonempty"),
        sa.CheckConstraint(
            "length(response_policy_hash) = 64", name="ck_preview_lease_response_hash"
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PREVIEW_LEASE_STATUSES)})", name="ck_preview_lease_status"
        ),
        sa.CheckConstraint("run_fence_token > 0", name="ck_preview_lease_run_fence"),
        sa.CheckConstraint(
            "runner_connection_generation > 0", name="ck_preview_lease_runner_generation"
        ),
        sa.CheckConstraint(
            "worktree_lease_generation > 0", name="ck_preview_lease_worktree_generation"
        ),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL)",
            name="ck_preview_lease_lifecycle",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_preview_lease_scope"
        ),
        sa.Index("ix_preview_lease_expiry", "status", "expires_at"),
        sa.Index("ix_preview_lease_worktree", "worktree_id", "status"),
    )
