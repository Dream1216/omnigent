"""Durable P4 fair scheduling, shared Runner registry, and capability records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

RUNNER_POOL_STATUSES = ("active", "draining", "disabled")
RUNNER_STATUSES = ("online", "draining", "offline", "quarantined")
DISPATCH_STATUSES = ("pending", "leased", "released", "dead_letter")


class RunnerPoolRecord(SaasBase):
    """Platform-owned scheduling pool pinned to one reviewed Runtime Placement."""

    __tablename__ = "saas_runner_pools"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    placement_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runtime_placements.id", ondelete="RESTRICT"), nullable=False
    )
    failure_domain: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    queue_class: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    capacity_slots: Mapped[int] = mapped_column(nullable=False)
    reserved_slots: Mapped[int] = mapped_column(nullable=False, default=0)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    protocol_version: Mapped[int] = mapped_column(nullable=False)
    source_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    schema_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    adapter_contract_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
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
            f"status IN ({_values(RUNNER_POOL_STATUSES)})", name="ck_runner_pool_status"
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
        sa.UniqueConstraint(
            "placement_id", "name", "queue_class", name="uq_runner_pool_placement_name_queue"
        ),
        sa.UniqueConstraint("id", "placement_id", name="uq_runner_pool_placement"),
        sa.Index("ix_runner_pool_status_queue", "status", "queue_class"),
    )


class RunnerRegistrationRecord(SaasBase):
    """Shared, replica-independent Runner liveness and compatibility authority."""

    __tablename__ = "saas_runner_registrations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    pool_id: Mapped[UUID] = mapped_column(nullable=False)
    placement_id: Mapped[UUID] = mapped_column(nullable=False)
    instance_key: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    failure_domain: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="online")
    connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=1)
    connection_token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    protocol_version: Mapped[int] = mapped_column(nullable=False)
    source_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    schema_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    adapter_contract_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    capabilities_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    max_concurrency: Mapped[int] = mapped_column(nullable=False)
    active_leases: Mapped[int] = mapped_column(nullable=False, default=0)
    last_heartbeat_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    registered_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("pool_id", "placement_id"),
            ("saas_runner_pools.id", "saas_runner_pools.placement_id"),
            name="fk_runner_registration_pool_placement",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(RUNNER_STATUSES)})", name="ck_runner_registration_status"
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
        sa.UniqueConstraint("pool_id", "instance_key", name="uq_runner_pool_instance"),
        sa.Index("ix_runner_pool_status_heartbeat", "pool_id", "status", "last_heartbeat_at"),
    )


class TenantQueueShareRecord(SaasBase):
    """Durable tenant-level weighted-fair scheduling cursor and concurrency cap."""

    __tablename__ = "saas_tenant_queue_shares"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_tenants.id", ondelete="RESTRICT"), nullable=False
    )
    pool_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runner_pools.id", ondelete="RESTRICT"), nullable=False
    )
    queue_class: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    weight: Mapped[int] = mapped_column(nullable=False, default=1)
    max_concurrent: Mapped[int] = mapped_column(nullable=False)
    burst_limit: Mapped[int] = mapped_column(nullable=False)
    active_leases: Mapped[int] = mapped_column(nullable=False, default=0)
    virtual_runtime: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    last_dispatched_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
        sa.CheckConstraint("weight > 0", name="ck_tenant_queue_weight"),
        sa.CheckConstraint("max_concurrent > 0", name="ck_tenant_queue_max_concurrent"),
        sa.CheckConstraint("burst_limit >= max_concurrent", name="ck_tenant_queue_burst"),
        sa.CheckConstraint("active_leases >= 0", name="ck_tenant_queue_active_nonnegative"),
        sa.CheckConstraint("active_leases <= burst_limit", name="ck_tenant_queue_active_burst"),
        sa.CheckConstraint("virtual_runtime >= 0", name="ck_tenant_queue_vruntime"),
        sa.CheckConstraint("version > 0", name="ck_tenant_queue_version"),
        sa.CheckConstraint("length(queue_class) > 0", name="ck_tenant_queue_class_nonempty"),
        sa.UniqueConstraint("tenant_id", "pool_id", "queue_class", name="uq_tenant_queue_share"),
        sa.Index(
            "ix_tenant_queue_fair_claim",
            "pool_id",
            "queue_class",
            "virtual_runtime",
            "last_dispatched_at",
        ),
    )


class RunDispatchRecord(SaasBase):
    """Scheduling metadata for one Run; Run remains the execution status authority."""

    __tablename__ = "saas_run_dispatches"

    run_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    pool_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runner_pools.id", ondelete="RESTRICT"), nullable=False
    )
    execution_profile_id: Mapped[UUID] = mapped_column(nullable=False)
    execution_profile_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    egress_policy_id: Mapped[UUID] = mapped_column(nullable=False)
    egress_policy_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    queue_class: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    required_capabilities: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    requirements_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    cost_units: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=1)
    eligible_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    max_wait_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    selected_runner_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_runner_registrations.id", ondelete="RESTRICT")
    )
    selected_failure_domain: Mapped[str | None] = mapped_column(sa.String(128))
    dispatch_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    released_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    dead_letter_reason: Mapped[str | None] = mapped_column(sa.String(256))
    recovery_quarantined_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    recovery_quarantine_reason: Mapped[str | None] = mapped_column(sa.String(128))
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
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_run_dispatch_run_scope",
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
            name="fk_run_dispatch_execution_profile_scope",
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
            name="fk_run_dispatch_egress_policy_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(DISPATCH_STATUSES)})", name="ck_run_dispatch_status"
        ),
        sa.CheckConstraint("length(queue_class) > 0", name="ck_run_dispatch_queue_nonempty"),
        sa.CheckConstraint("length(requirements_hash) = 64", name="ck_run_dispatch_hash"),
        sa.CheckConstraint(
            "length(execution_profile_hash) = 64",
            name="ck_run_dispatch_execution_profile_binding",
        ),
        sa.CheckConstraint(
            "length(egress_policy_hash) = 64",
            name="ck_run_dispatch_egress_policy_binding",
        ),
        sa.CheckConstraint(
            "(recovery_quarantined_at IS NULL AND recovery_quarantine_reason IS NULL) OR "
            "(recovery_quarantined_at IS NOT NULL "
            "AND length(recovery_quarantine_reason) > 0)",
            name="ck_run_dispatch_recovery_quarantine",
        ),
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
        sa.Index(
            "ix_run_dispatch_claim",
            "pool_id",
            "queue_class",
            "status",
            "eligible_at",
            "max_wait_at",
        ),
        sa.Index("ix_run_dispatch_runner", "selected_runner_id", "status"),
    )


class CapabilityTokenRecord(SaasBase):
    """Hashed short-lived capability bound to Run fence and Runner incarnation."""

    __tablename__ = "saas_capability_tokens"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    runner_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runner_registrations.id", ondelete="RESTRICT"), nullable=False
    )
    runner_connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    dispatch_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    fence_token: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    allowed_actions: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False)
    resource_scope: Mapped[dict[str, str]] = mapped_column(sa.JSON, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(sa.String(256))

    __table_args__ = (
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
        sa.Index("ix_capability_run_expiry", "run_id", "expires_at"),
        sa.Index("ix_capability_runner_active", "runner_id", "revoked_at", "expires_at"),
    )
