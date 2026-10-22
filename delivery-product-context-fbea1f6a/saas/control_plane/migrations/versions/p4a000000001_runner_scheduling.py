"""Create P4 fair scheduling, shared Runner registry, and capability authority.

Revision ID: p4a000000001
Revises: p3a000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p4a000000001"
down_revision: str | None = "p3a000000001"
branch_labels: str | None = None
depends_on: str | None = None

_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_governance', 'member')"
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


def upgrade() -> None:
    op.create_table(
        "saas_runner_pools",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("placement_id", sa.Uuid(), nullable=False),
        sa.Column("failure_domain", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("queue_class", sa.String(64), nullable=False),
        sa.Column("capacity_slots", sa.Integer(), nullable=False),
        sa.Column("reserved_slots", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("protocol_version", sa.Integer(), nullable=False),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("schema_revision", sa.String(64), nullable=False),
        sa.Column("adapter_contract_version", sa.String(32), nullable=False),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(
            ("placement_id",),
            ("saas_runtime_placements.id",),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'draining', 'disabled')", name="ck_runner_pool_status"
        ),
        sa.CheckConstraint("capacity_slots > 0", name="ck_runner_pool_capacity"),
        sa.CheckConstraint("reserved_slots >= 0", name="ck_runner_pool_reserved_nonnegative"),
        sa.CheckConstraint(
            "reserved_slots <= capacity_slots", name="ck_runner_pool_reserved_capacity"
        ),
        sa.CheckConstraint("protocol_version > 0", name="ck_runner_pool_protocol"),
        sa.CheckConstraint("length(name) > 0", name="ck_runner_pool_name_nonempty"),
        sa.CheckConstraint("length(queue_class) > 0", name="ck_runner_pool_queue_nonempty"),
        sa.CheckConstraint("length(failure_domain) > 0", name="ck_runner_pool_domain_nonempty"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "placement_id", "name", "queue_class", name="uq_runner_pool_placement_name_queue"
        ),
        sa.UniqueConstraint("id", "placement_id", name="uq_runner_pool_placement"),
    )
    op.create_index("ix_runner_pool_status_queue", "saas_runner_pools", ("status", "queue_class"))

    op.create_table(
        "saas_runner_registrations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("pool_id", sa.Uuid(), nullable=False),
        sa.Column("placement_id", sa.Uuid(), nullable=False),
        sa.Column("instance_key", sa.String(256), nullable=False),
        sa.Column("failure_domain", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("connection_token_hash", sa.String(64), nullable=False),
        sa.Column("protocol_version", sa.Integer(), nullable=False),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("schema_revision", sa.String(64), nullable=False),
        sa.Column("adapter_contract_version", sa.String(32), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("capabilities_hash", sa.String(64), nullable=False),
        sa.Column("max_concurrency", sa.Integer(), nullable=False),
        sa.Column("active_leases", sa.Integer(), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        _updated_at(),
        sa.ForeignKeyConstraint(
            ("pool_id", "placement_id"),
            ("saas_runner_pools.id", "saas_runner_pools.placement_id"),
            name="fk_runner_registration_pool_placement",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('online', 'draining', 'offline', 'quarantined')",
            name="ck_runner_registration_status",
        ),
        sa.CheckConstraint("connection_generation > 0", name="ck_runner_connection_generation"),
        sa.CheckConstraint("length(connection_token_hash) = 64", name="ck_runner_token_hash"),
        sa.CheckConstraint("protocol_version > 0", name="ck_runner_protocol"),
        sa.CheckConstraint("max_concurrency > 0", name="ck_runner_max_concurrency"),
        sa.CheckConstraint("active_leases >= 0", name="ck_runner_active_nonnegative"),
        sa.CheckConstraint("active_leases <= max_concurrency", name="ck_runner_active_capacity"),
        sa.CheckConstraint("length(instance_key) > 0", name="ck_runner_instance_nonempty"),
        sa.CheckConstraint("length(failure_domain) > 0", name="ck_runner_domain_nonempty"),
        sa.CheckConstraint("length(capabilities_hash) = 64", name="ck_runner_capabilities_hash"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("pool_id", "instance_key", name="uq_runner_pool_instance"),
    )
    op.create_index(
        "ix_runner_pool_status_heartbeat",
        "saas_runner_registrations",
        ("pool_id", "status", "last_heartbeat_at"),
    )

    op.create_table(
        "saas_tenant_queue_shares",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("pool_id", sa.Uuid(), nullable=False),
        sa.Column("queue_class", sa.String(64), nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.Column("max_concurrent", sa.Integer(), nullable=False),
        sa.Column("burst_limit", sa.Integer(), nullable=False),
        sa.Column("active_leases", sa.Integer(), nullable=False),
        sa.Column("virtual_runtime", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("last_dispatched_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(("pool_id",), ("saas_runner_pools.id",), ondelete="RESTRICT"),
        sa.CheckConstraint("weight > 0", name="ck_tenant_queue_weight"),
        sa.CheckConstraint("max_concurrent > 0", name="ck_tenant_queue_max_concurrent"),
        sa.CheckConstraint("burst_limit >= max_concurrent", name="ck_tenant_queue_burst"),
        sa.CheckConstraint("active_leases >= 0", name="ck_tenant_queue_active_nonnegative"),
        sa.CheckConstraint("active_leases <= burst_limit", name="ck_tenant_queue_active_burst"),
        sa.CheckConstraint("virtual_runtime >= 0", name="ck_tenant_queue_vruntime"),
        sa.CheckConstraint("version > 0", name="ck_tenant_queue_version"),
        sa.CheckConstraint("length(queue_class) > 0", name="ck_tenant_queue_class_nonempty"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "pool_id", "queue_class", name="uq_tenant_queue_share"),
    )
    op.create_index(
        "ix_tenant_queue_fair_claim",
        "saas_tenant_queue_shares",
        ("pool_id", "queue_class", "virtual_runtime", "last_dispatched_at"),
    )

    op.create_table(
        "saas_run_dispatches",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("pool_id", sa.Uuid(), nullable=False),
        sa.Column("queue_class", sa.String(64), nullable=False),
        sa.Column("required_capabilities", sa.JSON(), nullable=False),
        sa.Column("requirements_hash", sa.String(64), nullable=False),
        sa.Column("cost_units", sa.BigInteger(), nullable=False),
        sa.Column("eligible_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_wait_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("selected_runner_id", sa.Uuid(), nullable=True),
        sa.Column("selected_failure_domain", sa.String(128), nullable=True),
        sa.Column("dispatch_generation", sa.BigInteger(), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dead_letter_reason", sa.String(256), nullable=True),
        _created_at(),
        _updated_at(),
        sa.ForeignKeyConstraint(("pool_id",), ("saas_runner_pools.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("selected_runner_id",),
            ("saas_runner_registrations.id",),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_run_dispatch_run_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'leased', 'released', 'dead_letter')",
            name="ck_run_dispatch_status",
        ),
        sa.CheckConstraint("length(queue_class) > 0", name="ck_run_dispatch_queue_nonempty"),
        sa.CheckConstraint("length(requirements_hash) = 64", name="ck_run_dispatch_hash"),
        sa.CheckConstraint("cost_units > 0", name="ck_run_dispatch_cost"),
        sa.CheckConstraint("max_wait_at > eligible_at", name="ck_run_dispatch_wait_window"),
        sa.CheckConstraint("dispatch_generation >= 0", name="ck_run_dispatch_generation"),
        sa.CheckConstraint(
            "(status = 'leased' AND selected_runner_id IS NOT NULL "
            "AND selected_failure_domain IS NOT NULL AND dispatch_generation > 0 "
            "AND released_at IS NULL AND dead_letter_reason IS NULL) OR "
            "(status = 'pending' AND selected_runner_id IS NULL "
            "AND selected_failure_domain IS NULL AND released_at IS NULL "
            "AND dead_letter_reason IS NULL) OR "
            "(status = 'released' AND selected_runner_id IS NOT NULL "
            "AND selected_failure_domain IS NOT NULL AND released_at IS NOT NULL "
            "AND dead_letter_reason IS NULL) OR "
            "(status = 'dead_letter' AND released_at IS NOT NULL "
            "AND dead_letter_reason IS NOT NULL)",
            name="ck_run_dispatch_lifecycle",
        ),
        sa.PrimaryKeyConstraint("run_id"),
    )
    op.create_index(
        "ix_run_dispatch_claim",
        "saas_run_dispatches",
        ("pool_id", "queue_class", "status", "eligible_at", "max_wait_at"),
    )
    op.create_index(
        "ix_run_dispatch_runner", "saas_run_dispatches", ("selected_runner_id", "status")
    )

    op.create_table(
        "saas_capability_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("dispatch_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_token", sa.BigInteger(), nullable=False),
        sa.Column("allowed_actions", sa.JSON(), nullable=False),
        sa.Column("resource_scope", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(256), nullable=True),
        sa.ForeignKeyConstraint(
            ("runner_id",),
            ("saas_runner_registrations.id",),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_capability_run_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_capability_token_hash"),
        sa.CheckConstraint(
            "runner_connection_generation > 0", name="ck_capability_runner_generation"
        ),
        sa.CheckConstraint("dispatch_generation > 0", name="ck_capability_dispatch_generation"),
        sa.CheckConstraint("fence_token > 0", name="ck_capability_fence"),
        sa.CheckConstraint("expires_at > issued_at", name="ck_capability_expiry"),
        sa.CheckConstraint(
            "(revoked_at IS NULL AND revocation_reason IS NULL) OR "
            "(revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)",
            name="ck_capability_revocation",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_capability_run_expiry", "saas_capability_tokens", ("run_id", "expires_at"))
    op.create_index(
        "ix_capability_runner_active",
        "saas_capability_tokens",
        ("runner_id", "revoked_at", "expires_at"),
    )

    _install_postgresql_rls()


def _install_postgresql_rls() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    global_predicate = f"({_PLATFORM} OR {_EXECUTOR})"
    for table in ("saas_runner_pools", "saas_runner_registrations"):
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "rls_{table}_executor" ON "{table}" '
            f"FOR ALL USING ({global_predicate}) WITH CHECK ({global_predicate})"
        )

    tenant_predicate = f"({_PLATFORM} OR {_EXECUTOR} OR tenant_id = {_TENANT})"
    op.execute('ALTER TABLE "saas_tenant_queue_shares" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_tenant_queue_shares" FORCE ROW LEVEL SECURITY')
    op.execute(
        'CREATE POLICY "rls_saas_tenant_queue_shares_scope" '
        'ON "saas_tenant_queue_shares" FOR ALL '
        f"USING ({tenant_predicate}) WITH CHECK ({tenant_predicate})"
    )

    scoped_predicate = (
        f"({_PLATFORM} OR {_EXECUTOR} OR (tenant_id = {_TENANT} AND space_id = {_SPACE}))"
    )
    for table in ("saas_run_dispatches", "saas_capability_tokens"):
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" '
            f"FOR ALL USING ({scoped_predicate}) WITH CHECK ({scoped_predicate})"
        )

    governance_run_scope = (
        f"({_GOVERNANCE} AND tenant_id = {_TENANT} AND ({_SPACE} IS NULL OR space_id = {_SPACE}))"
    )
    op.execute(
        'CREATE POLICY "rls_saas_runs_governance_read" ON "saas_runs" '
        f"FOR SELECT USING ({governance_run_scope})"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute('DROP POLICY IF EXISTS "rls_saas_runs_governance_read" ON "saas_runs"')
    op.drop_index("ix_capability_runner_active", table_name="saas_capability_tokens")
    op.drop_index("ix_capability_run_expiry", table_name="saas_capability_tokens")
    op.drop_table("saas_capability_tokens")
    op.drop_index("ix_run_dispatch_runner", table_name="saas_run_dispatches")
    op.drop_index("ix_run_dispatch_claim", table_name="saas_run_dispatches")
    op.drop_table("saas_run_dispatches")
    op.drop_index("ix_tenant_queue_fair_claim", table_name="saas_tenant_queue_shares")
    op.drop_table("saas_tenant_queue_shares")
    op.drop_index("ix_runner_pool_status_heartbeat", table_name="saas_runner_registrations")
    op.drop_table("saas_runner_registrations")
    op.drop_index("ix_runner_pool_status_queue", table_name="saas_runner_pools")
    op.drop_table("saas_runner_pools")
