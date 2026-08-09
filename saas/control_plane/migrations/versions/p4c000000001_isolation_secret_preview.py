"""Create P4 isolation, Secret Broker, egress, and Preview authority.

Revision ID: p4c000000001
Revises: p4b000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p4c000000001"
down_revision: str | None = "p4b000000001"
branch_labels: str | None = None
depends_on: str | None = None

_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_APP = "pg_has_role(current_user, 'saas_app', 'member')"
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_governance', 'member')"
_SECRET_BROKER = "pg_has_role(current_user, 'saas_secret_broker', 'member')"
_PREVIEW_GATEWAY = "pg_has_role(current_user, 'saas_preview_gateway', 'member')"
_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_SPACE = "NULLIF(current_setting('app.space_id', true), '')::uuid"


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def _updated_at() -> sa.Column:
    return sa.Column(
        "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def _scope_columns() -> tuple[sa.Column, sa.Column, sa.Column]:
    return (
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "saas_egress_policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("rules_hash", sa.String(64), nullable=False),
        sa.Column("allow_private_destinations", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_egress_policy_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("status IN ('active', 'retired')", name="ck_egress_policy_status"),
        sa.CheckConstraint("length(name) > 0", name="ck_egress_policy_name_nonempty"),
        sa.CheckConstraint("length(rules_hash) = 64", name="ck_egress_policy_hash"),
        sa.CheckConstraint(
            "allow_private_destinations = false", name="ck_egress_policy_no_private"
        ),
        sa.CheckConstraint("version > 0", name="ck_egress_policy_version"),
        sa.PrimaryKeyConstraint("id"),
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
    )
    op.create_index(
        "ix_egress_policy_project_status",
        "saas_egress_policies",
        ("tenant_id", "space_id", "project_id", "status"),
    )

    op.create_table(
        "saas_execution_profiles",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("egress_policy_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("sandbox_backend", sa.String(32), nullable=False),
        sa.Column("network_mode", sa.String(32), nullable=False),
        sa.Column("root_read_only", sa.Boolean(), nullable=False),
        sa.Column("run_as_uid", sa.Integer(), nullable=False),
        sa.Column("run_as_gid", sa.Integer(), nullable=False),
        sa.Column("no_new_privileges", sa.Boolean(), nullable=False),
        sa.Column("host_socket_access", sa.Boolean(), nullable=False),
        sa.Column("syscall_profile_ref", sa.String(128), nullable=False),
        sa.Column("cpu_millis", sa.Integer(), nullable=False),
        sa.Column("memory_bytes", sa.BigInteger(), nullable=False),
        sa.Column("pids_limit", sa.Integer(), nullable=False),
        sa.Column("allowed_tools", sa.JSON(), nullable=False),
        sa.Column("approval_required_tools", sa.JSON(), nullable=False),
        sa.Column("denied_tools", sa.JSON(), nullable=False),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
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
            "sandbox_backend IN ('darwin_seatbelt', 'linux_bwrap')",
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
        sa.CheckConstraint("status IN ('active', 'retired')", name="ck_execution_profile_status"),
        sa.CheckConstraint("version > 0", name="ck_execution_profile_version"),
        sa.PrimaryKeyConstraint("id"),
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
    )
    op.create_index(
        "ix_execution_profile_project_status",
        "saas_execution_profiles",
        ("tenant_id", "space_id", "project_id", "status"),
    )

    op.create_table(
        "saas_secret_bindings",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("execution_profile_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("vault_provider", sa.String(64), nullable=False),
        sa.Column("vault_ref", sa.String(256), nullable=False),
        sa.Column("version_ref", sa.String(128), nullable=False),
        sa.Column("credential_scheme", sa.String(16), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("inject_env", sa.JSON(), nullable=False),
        sa.Column("metadata_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
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
            "credential_scheme IN ('basic', 'bearer', 'token')", name="ck_secret_binding_scheme"
        ),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_secret_binding_status"),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_secret_binding_scope"
        ),
        sa.UniqueConstraint(
            "execution_profile_id", "name", "version", name="uq_secret_binding_profile_name"
        ),
    )
    op.create_index(
        "ix_secret_binding_profile_status",
        "saas_secret_bindings",
        ("execution_profile_id", "status", "name"),
    )

    op.create_table(
        "saas_run_isolation_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        *_scope_columns(),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("worktree_id", sa.Uuid(), nullable=False),
        sa.Column("execution_profile_id", sa.Uuid(), nullable=False),
        sa.Column("capability_id", sa.Uuid(), nullable=False),
        sa.Column("run_fence_token", sa.BigInteger(), nullable=False),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("worktree_lease_generation", sa.BigInteger(), nullable=False),
        sa.Column("grant_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.ForeignKeyConstraint(
            ("capability_id",), ("saas_capability_tokens.id",), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
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
        sa.CheckConstraint("length(token_hash) = 64", name="ck_isolation_grant_token_hash"),
        sa.CheckConstraint("length(grant_hash) = 64", name="ck_isolation_grant_hash"),
        sa.CheckConstraint(
            "status IN ('active', 'redeemed', 'revoked')", name="ck_isolation_grant_status"
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_isolation_grant_scope"
        ),
    )
    op.create_index(
        "ix_isolation_grant_expiry", "saas_run_isolation_grants", ("status", "expires_at")
    )

    op.create_table(
        "saas_secret_access_leases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        *_scope_columns(),
        sa.Column("isolation_grant_id", sa.Uuid(), nullable=False),
        sa.Column("secret_binding_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("run_fence_token", sa.BigInteger(), nullable=False),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
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
        sa.CheckConstraint("length(token_hash) = 64", name="ck_secret_lease_token_hash"),
        sa.CheckConstraint(
            "status IN ('active', 'redeemed', 'revoked')", name="ck_secret_lease_status"
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
        sa.UniqueConstraint(
            "isolation_grant_id", "secret_binding_id", name="uq_secret_lease_grant_binding"
        ),
    )
    op.create_index(
        "ix_secret_lease_expiry", "saas_secret_access_leases", ("status", "expires_at")
    )

    op.create_table(
        "saas_preview_leases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        *_scope_columns(),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("worktree_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("opaque_preview_key", sa.String(96), nullable=False),
        sa.Column("preview_host", sa.String(253), nullable=False),
        sa.Column("run_fence_token", sa.BigInteger(), nullable=False),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("worktree_lease_generation", sa.BigInteger(), nullable=False),
        sa.Column("response_policy_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_accessed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
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
        sa.CheckConstraint("length(token_hash) = 64", name="ck_preview_lease_token_hash"),
        sa.CheckConstraint("length(opaque_preview_key) > 0", name="ck_preview_lease_key_nonempty"),
        sa.CheckConstraint("length(preview_host) > 0", name="ck_preview_lease_host_nonempty"),
        sa.CheckConstraint(
            "length(response_policy_hash) = 64", name="ck_preview_lease_response_hash"
        ),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="ck_preview_lease_status"),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
        sa.UniqueConstraint("opaque_preview_key"),
        sa.UniqueConstraint("preview_host"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_preview_lease_scope"
        ),
    )
    op.create_index("ix_preview_lease_expiry", "saas_preview_leases", ("status", "expires_at"))
    op.create_index("ix_preview_lease_worktree", "saas_preview_leases", ("worktree_id", "status"))

    _install_postgresql_rls_and_guards()


def _install_postgresql_rls_and_guards() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    scope = f"(tenant_id = {_TENANT} AND space_id = {_SPACE})"
    app_scope = f"({_PLATFORM} OR ({_APP} AND {scope}))"
    executor_scope = f"({_PLATFORM} OR ({_EXECUTOR} AND {scope}))"
    governance_scope = (
        f"({_GOVERNANCE} AND tenant_id = {_TENANT} AND ({_SPACE} IS NULL OR space_id = {_SPACE}))"
    )
    for table in ("saas_egress_policies", "saas_execution_profiles"):
        _enable_scope_policy(table, app_scope, governance_scope)
    _enable_scope_policy("saas_secret_bindings", app_scope, "false")
    op.execute(
        'CREATE POLICY "rls_saas_secret_bindings_broker" ON "saas_secret_bindings" '
        "FOR SELECT USING ("
        f"{_SECRET_BROKER} AND EXISTS ("
        "SELECT 1 FROM saas_secret_access_leases lease "
        "WHERE lease.secret_binding_id = saas_secret_bindings.id "
        "AND lease.token_hash = "
        "NULLIF(current_setting('app.secret_token_hash', true), '')"
        "))"
    )

    _enable_scope_policy(
        "saas_run_isolation_grants",
        executor_scope,
        "false",
        token_policy=(
            f"({_EXECUTOR} AND token_hash = "
            "NULLIF(current_setting('app.isolation_token_hash', true), ''))"
        ),
    )
    _enable_scope_policy(
        "saas_secret_access_leases",
        executor_scope,
        "false",
        token_policy=(
            f"({_SECRET_BROKER} AND token_hash = "
            "NULLIF(current_setting('app.secret_token_hash', true), ''))"
        ),
    )
    _enable_scope_policy(
        "saas_preview_leases",
        app_scope,
        governance_scope,
        token_policy=(
            f"({_PREVIEW_GATEWAY} AND token_hash = "
            "NULLIF(current_setting('app.preview_token_hash', true), ''))"
        ),
    )
    _harden_dependency_scope_policies(scope)
    _install_token_bound_dependency_policies()
    _install_immutability_guards()


def _enable_scope_policy(
    table: str,
    scope: str,
    governance_scope: str,
    *,
    token_policy: str | None = None,
) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY "rls_{table}_scope" ON "{table}" '
        f"FOR ALL USING ({scope}) WITH CHECK ({scope})"
    )
    if governance_scope != "false":
        op.execute(
            f'CREATE POLICY "rls_{table}_governance_read" ON "{table}" '
            f"FOR SELECT USING ({governance_scope})"
        )
    if token_policy is not None:
        op.execute(
            f'CREATE POLICY "rls_{table}_token" ON "{table}" FOR SELECT USING ({token_policy})'
        )
        op.execute(
            f'CREATE POLICY "rls_{table}_token_update" ON "{table}" '
            f"FOR UPDATE USING ({token_policy}) WITH CHECK ({token_policy})"
        )


def _install_token_bound_dependency_policies() -> None:
    secret_match = "lease.token_hash = NULLIF(current_setting('app.secret_token_hash', true), '')"
    preview_match = (
        "preview.token_hash = NULLIF(current_setting('app.preview_token_hash', true), '')"
    )
    op.execute(
        'CREATE POLICY "rls_saas_runs_secret_broker" ON "saas_runs" FOR SELECT USING ('
        f"{_SECRET_BROKER} AND EXISTS (SELECT 1 FROM saas_secret_access_leases lease "
        f"WHERE lease.run_id = saas_runs.id AND {secret_match}))"
    )
    op.execute(
        'CREATE POLICY "rls_saas_runner_registrations_secret_broker" '
        'ON "saas_runner_registrations" FOR SELECT USING ('
        f"{_SECRET_BROKER} AND EXISTS (SELECT 1 FROM saas_secret_access_leases lease "
        f"WHERE lease.runner_id = saas_runner_registrations.id AND {secret_match}))"
    )
    op.execute(
        'CREATE POLICY "rls_saas_runs_preview_gateway" ON "saas_runs" FOR SELECT USING ('
        f"{_PREVIEW_GATEWAY} AND EXISTS (SELECT 1 FROM saas_preview_leases preview "
        f"WHERE preview.run_id = saas_runs.id AND {preview_match}))"
    )
    op.execute(
        'CREATE POLICY "rls_saas_runner_registrations_preview_gateway" '
        'ON "saas_runner_registrations" FOR SELECT USING ('
        f"{_PREVIEW_GATEWAY} AND EXISTS (SELECT 1 FROM saas_preview_leases preview "
        f"WHERE preview.runner_id = saas_runner_registrations.id AND {preview_match}))"
    )
    op.execute(
        'CREATE POLICY "rls_saas_worktree_instances_preview_gateway" '
        'ON "saas_worktree_instances" FOR SELECT USING ('
        f"{_PREVIEW_GATEWAY} AND EXISTS (SELECT 1 FROM saas_preview_leases preview "
        f"WHERE preview.worktree_id = saas_worktree_instances.id AND {preview_match}))"
    )


def _harden_dependency_scope_policies(scope: str) -> None:
    """Prevent service roles from turning tenant settings into ambient access."""

    app_or_executor_scope = f"({_PLATFORM} OR {_EXECUTOR} OR ({_APP} AND {scope}))"
    for table in ("saas_runs", "saas_worktree_instances"):
        op.execute(f'DROP POLICY "rls_{table}_scope" ON "{table}"')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" FOR ALL '
            f"USING ({app_or_executor_scope}) WITH CHECK ({app_or_executor_scope})"
        )


def _restore_legacy_dependency_scope_policies() -> None:
    legacy_scope = (
        f"({_PLATFORM} OR {_EXECUTOR} OR (tenant_id = {_TENANT} AND space_id = {_SPACE}))"
    )
    for table in ("saas_runs", "saas_worktree_instances"):
        op.execute(f'DROP POLICY "rls_{table}_scope" ON "{table}"')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" FOR ALL '
            f"USING ({legacy_scope}) WITH CHECK ({legacy_scope})"
        )


def _install_immutability_guards() -> None:
    guards = {
        "egress_policy": (
            "saas_egress_policies",
            "id, tenant_id, space_id, project_id, created_by, name, rules::text, rules_hash, "
            "allow_private_destinations, version, created_at",
        ),
        "execution_profile": (
            "saas_execution_profiles",
            "id, tenant_id, space_id, project_id, egress_policy_id, created_by, name, "
            "sandbox_backend, network_mode, root_read_only, run_as_uid, run_as_gid, "
            "no_new_privileges, host_socket_access, syscall_profile_ref, cpu_millis, "
            "memory_bytes, pids_limit, allowed_tools::text, approval_required_tools::text, "
            "denied_tools::text, config_hash, version, created_at",
        ),
        "secret_binding": (
            "saas_secret_bindings",
            "id, tenant_id, space_id, project_id, execution_profile_id, created_by, name, "
            "vault_provider, vault_ref, version_ref, credential_scheme, host, username, "
            "inject_env::text, metadata_hash, version, created_at",
        ),
        "run_isolation_grant": (
            "saas_run_isolation_grants",
            "id, token_hash, tenant_id, space_id, project_id, run_id, runner_id, worktree_id, "
            "execution_profile_id, capability_id, run_fence_token, runner_connection_generation, "
            "worktree_lease_generation, grant_hash, expires_at, created_at",
        ),
        "secret_access_lease": (
            "saas_secret_access_leases",
            "id, token_hash, tenant_id, space_id, project_id, isolation_grant_id, "
            "secret_binding_id, run_id, runner_id, run_fence_token, "
            "runner_connection_generation, expires_at, created_at",
        ),
        "preview_lease": (
            "saas_preview_leases",
            "id, token_hash, tenant_id, space_id, project_id, run_id, runner_id, worktree_id, "
            "created_by, opaque_preview_key, preview_host, run_fence_token, "
            "runner_connection_generation, worktree_lease_generation, response_policy_hash, "
            "expires_at, created_at",
        ),
    }
    transitions = {
        "egress_policy": """
                IF OLD.status = 'retired' AND NEW.status <> 'retired' THEN
                    RAISE EXCEPTION 'Retired egress policies cannot be reactivated';
                END IF;
        """,
        "execution_profile": """
                IF OLD.status = 'retired' AND NEW.status <> 'retired' THEN
                    RAISE EXCEPTION 'Retired execution profiles cannot be reactivated';
                END IF;
        """,
        "secret_binding": """
                IF OLD.status = 'disabled' AND NEW.status <> 'disabled' THEN
                    RAISE EXCEPTION 'Disabled secret bindings cannot be reactivated';
                END IF;
        """,
        "run_isolation_grant": """
                IF NOT (
                    ROW(OLD.status, OLD.redeemed_at, OLD.revoked_at)
                        IS NOT DISTINCT FROM
                    ROW(NEW.status, NEW.redeemed_at, NEW.revoked_at)
                    OR (
                        OLD.status = 'active'
                        AND NEW.status = 'redeemed'
                        AND OLD.redeemed_at IS NULL
                        AND NEW.redeemed_at IS NOT NULL
                        AND OLD.revoked_at IS NULL
                        AND NEW.revoked_at IS NULL
                    )
                    OR (
                        OLD.status = 'active'
                        AND NEW.status = 'revoked'
                        AND OLD.redeemed_at IS NULL
                        AND NEW.redeemed_at IS NULL
                        AND OLD.revoked_at IS NULL
                        AND NEW.revoked_at IS NOT NULL
                    )
                ) THEN
                    RAISE EXCEPTION 'Isolation grant lifecycle is monotonic';
                END IF;
        """,
        "secret_access_lease": """
                IF NOT (
                    ROW(OLD.status, OLD.redeemed_at, OLD.revoked_at)
                        IS NOT DISTINCT FROM
                    ROW(NEW.status, NEW.redeemed_at, NEW.revoked_at)
                    OR (
                        OLD.status = 'active'
                        AND NEW.status = 'redeemed'
                        AND OLD.redeemed_at IS NULL
                        AND NEW.redeemed_at IS NOT NULL
                        AND OLD.revoked_at IS NULL
                        AND NEW.revoked_at IS NULL
                    )
                    OR (
                        OLD.status = 'active'
                        AND NEW.status = 'revoked'
                        AND OLD.redeemed_at IS NULL
                        AND NEW.redeemed_at IS NULL
                        AND OLD.revoked_at IS NULL
                        AND NEW.revoked_at IS NOT NULL
                    )
                ) THEN
                    RAISE EXCEPTION 'Secret lease lifecycle is monotonic';
                END IF;
        """,
        "preview_lease": """
                IF OLD.last_accessed_at IS NOT NULL
                   AND (
                       NEW.last_accessed_at IS NULL
                       OR NEW.last_accessed_at < OLD.last_accessed_at
                   ) THEN
                    RAISE EXCEPTION 'Preview access time is monotonic';
                END IF;
                IF NOT (
                    (
                        OLD.status = 'active'
                        AND OLD.status = NEW.status
                        AND OLD.revoked_at IS NOT DISTINCT FROM NEW.revoked_at
                    )
                    OR (
                        OLD.status = 'revoked'
                        AND NEW.status = 'revoked'
                        AND OLD.revoked_at IS NOT DISTINCT FROM NEW.revoked_at
                        AND OLD.last_accessed_at IS NOT DISTINCT FROM NEW.last_accessed_at
                    )
                    OR (
                        OLD.status = 'active'
                        AND NEW.status = 'revoked'
                        AND OLD.revoked_at IS NULL
                        AND NEW.revoked_at IS NOT NULL
                    )
                ) THEN
                    RAISE EXCEPTION 'Preview lease lifecycle is monotonic';
                END IF;
        """,
    }
    for name, (table, fields) in guards.items():
        op.execute(
            f"""
            CREATE FUNCTION saas_guard_{name}_immutable()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF ROW(NEW.{fields.replace(", ", ", NEW.")})
                   IS DISTINCT FROM ROW(OLD.{fields.replace(", ", ", OLD.")}) THEN
                    RAISE EXCEPTION 'Isolation authority bindings are immutable';
                END IF;
                {transitions[name]}
                RETURN NEW;
            END
            $$
            """
        )
        op.execute(
            f'CREATE TRIGGER "trg_{table}_immutable" BEFORE UPDATE ON "{table}" '
            f"FOR EACH ROW EXECUTE FUNCTION saas_guard_{name}_immutable()"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            'DROP POLICY IF EXISTS "rls_saas_secret_bindings_broker" ON "saas_secret_bindings"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_saas_worktree_instances_preview_gateway" '
            'ON "saas_worktree_instances"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_saas_runner_registrations_preview_gateway" '
            'ON "saas_runner_registrations"'
        )
        op.execute('DROP POLICY IF EXISTS "rls_saas_runs_preview_gateway" ON "saas_runs"')
        op.execute(
            'DROP POLICY IF EXISTS "rls_saas_runner_registrations_secret_broker" '
            'ON "saas_runner_registrations"'
        )
        op.execute('DROP POLICY IF EXISTS "rls_saas_runs_secret_broker" ON "saas_runs"')
        _restore_legacy_dependency_scope_policies()
        for name, table in (
            ("preview_lease", "saas_preview_leases"),
            ("secret_access_lease", "saas_secret_access_leases"),
            ("run_isolation_grant", "saas_run_isolation_grants"),
            ("secret_binding", "saas_secret_bindings"),
            ("execution_profile", "saas_execution_profiles"),
            ("egress_policy", "saas_egress_policies"),
        ):
            op.execute(f'DROP TRIGGER IF EXISTS "trg_{table}_immutable" ON "{table}"')
            op.execute(f"DROP FUNCTION IF EXISTS saas_guard_{name}_immutable()")
    op.drop_index("ix_preview_lease_worktree", table_name="saas_preview_leases")
    op.drop_index("ix_preview_lease_expiry", table_name="saas_preview_leases")
    op.drop_table("saas_preview_leases")
    op.drop_index("ix_secret_lease_expiry", table_name="saas_secret_access_leases")
    op.drop_table("saas_secret_access_leases")
    op.drop_index("ix_isolation_grant_expiry", table_name="saas_run_isolation_grants")
    op.drop_table("saas_run_isolation_grants")
    op.drop_index("ix_secret_binding_profile_status", table_name="saas_secret_bindings")
    op.drop_table("saas_secret_bindings")
    op.drop_index("ix_execution_profile_project_status", table_name="saas_execution_profiles")
    op.drop_table("saas_execution_profiles")
    op.drop_index("ix_egress_policy_project_status", table_name="saas_egress_policies")
    op.drop_table("saas_egress_policies")
