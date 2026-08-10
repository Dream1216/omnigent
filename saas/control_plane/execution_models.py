"""Durable P3 task, session, run, quota, effect, and artifact records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _values

SESSION_STATUSES = ("active", "closed")
RUN_STATUSES = (
    "created",
    "queued",
    "leased",
    "starting",
    "running",
    "waiting_input",
    "waiting_approval",
    "cancelling",
    "cancelled",
    "succeeded",
    "failed",
    "timed_out",
    "orphaned",
)
TERMINAL_RUN_STATUSES = frozenset({"cancelled", "succeeded", "failed", "timed_out", "orphaned"})
RESERVATION_STATUSES = ("reserved", "consumed", "released")
EFFECT_TYPES = ("model", "tool", "external")
EFFECT_STATUSES = ("pending", "succeeded", "failed", "unknown")
UNKNOWN_EFFECT_POLICIES = ("retry_safe", "approval_required", "compensation_required")


class TaskRecord(SaasBase):
    """Durable unit of user intent; state is derived from its Runs."""

    __tablename__ = "saas_tasks"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    created_by_service_account_id: Mapped[UUID | None] = mapped_column()
    title: Mapped[str] = mapped_column(sa.String(256), nullable=False)
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
            name="fk_task_project_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id", "created_by_service_account_id"),
            (
                "saas_service_accounts.tenant_id",
                "saas_service_accounts.space_id",
                "saas_service_accounts.project_id",
                "saas_service_accounts.id",
            ),
            name="fk_task_service_account_actor",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(created_by IS NOT NULL) <> (created_by_service_account_id IS NOT NULL)",
            name="ck_task_actor_xor",
        ),
        sa.CheckConstraint("length(title) > 0", name="ck_task_title_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_task_version"),
        sa.UniqueConstraint("id", "tenant_id", "space_id", "project_id", name="uq_task_scope"),
        sa.Index("ix_task_project_created", "tenant_id", "space_id", "project_id", "created_at"),
        sa.Index(
            "ix_task_service_account_created",
            "tenant_id",
            "created_by_service_account_id",
            "created_at",
        ),
    )


class ExecutionSessionRecord(SaasBase):
    """Conversation/execution lifetime independent from any one Task."""

    __tablename__ = "saas_execution_sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="active")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    closed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            name="fk_execution_session_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(SESSION_STATUSES)})", name="ck_execution_session_status"
        ),
        sa.CheckConstraint("version > 0", name="ck_execution_session_version"),
        sa.CheckConstraint(
            "(status = 'active' AND closed_at IS NULL) OR "
            "(status = 'closed' AND closed_at IS NOT NULL)",
            name="ck_execution_session_closed_at",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_execution_session_scope"
        ),
        sa.Index(
            "ix_execution_session_project_status",
            "tenant_id",
            "space_id",
            "project_id",
            "status",
        ),
    )


class SessionTaskRecord(SaasBase):
    """Append-only association between independent Session and Task lifetimes."""

    __tablename__ = "saas_session_tasks"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    session_id: Mapped[UUID] = mapped_column(nullable=False)
    task_id: Mapped[UUID] = mapped_column(nullable=False)
    attached_by: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    attached_by_service_account_id: Mapped[UUID | None] = mapped_column()
    attached_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("session_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_execution_sessions.id",
                "saas_execution_sessions.tenant_id",
                "saas_execution_sessions.space_id",
                "saas_execution_sessions.project_id",
            ),
            name="fk_session_task_session_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("task_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_tasks.id",
                "saas_tasks.tenant_id",
                "saas_tasks.space_id",
                "saas_tasks.project_id",
            ),
            name="fk_session_task_task_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id", "attached_by_service_account_id"),
            (
                "saas_service_accounts.tenant_id",
                "saas_service_accounts.space_id",
                "saas_service_accounts.project_id",
                "saas_service_accounts.id",
            ),
            name="fk_session_task_service_account_actor",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(attached_by IS NOT NULL) <> (attached_by_service_account_id IS NOT NULL)",
            name="ck_session_task_actor_xor",
        ),
        sa.UniqueConstraint("session_id", "task_id", name="uq_session_task_link"),
        sa.Index("ix_session_task_task", "tenant_id", "space_id", "project_id", "task_id"),
    )


class RunRecord(SaasBase):
    """Authoritative Run state machine, queue row, and fencing lease."""

    __tablename__ = "saas_runs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    task_id: Mapped[UUID] = mapped_column(nullable=False)
    session_id: Mapped[UUID | None] = mapped_column()
    parent_run_id: Mapped[UUID | None] = mapped_column()
    created_by: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    created_by_service_account_id: Mapped[UUID | None] = mapped_column()
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="created")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    event_sequence: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    queue_class: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="interactive")
    priority: Mapped[int] = mapped_column(nullable=False, default=0)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    input: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    api_metadata: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False, default=dict)
    product_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    upstream_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    schema_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    adapter_contract_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(sa.String(256))
    lease_token: Mapped[UUID | None] = mapped_column()
    fence_token: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    terminal_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            ("task_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_tasks.id",
                "saas_tasks.tenant_id",
                "saas_tasks.space_id",
                "saas_tasks.project_id",
            ),
            name="fk_run_task_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("session_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_execution_sessions.id",
                "saas_execution_sessions.tenant_id",
                "saas_execution_sessions.space_id",
                "saas_execution_sessions.project_id",
            ),
            name="fk_run_session_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("parent_run_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_runs.id",
                "saas_runs.tenant_id",
                "saas_runs.space_id",
                "saas_runs.project_id",
            ),
            name="fk_run_parent_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id", "created_by_service_account_id"),
            (
                "saas_service_accounts.tenant_id",
                "saas_service_accounts.space_id",
                "saas_service_accounts.project_id",
                "saas_service_accounts.id",
            ),
            name="fk_run_service_account_actor",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(created_by IS NOT NULL) <> (created_by_service_account_id IS NOT NULL)",
            name="ck_run_actor_xor",
        ),
        sa.CheckConstraint(f"status IN ({_values(RUN_STATUSES)})", name="ck_run_status"),
        sa.CheckConstraint("version > 0", name="ck_run_version"),
        sa.CheckConstraint("event_sequence >= 0", name="ck_run_event_sequence"),
        sa.CheckConstraint("fence_token >= 0", name="ck_run_fence_token"),
        sa.CheckConstraint("length(queue_class) > 0", name="ck_run_queue_class_nonempty"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_run_idempotency_nonempty"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_run_request_hash"),
        sa.CheckConstraint(
            "(status IN ('leased', 'starting', 'running', 'waiting_input', "
            "'waiting_approval', 'cancelling') AND lease_owner IS NOT NULL "
            "AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL) OR "
            "(status NOT IN ('leased', 'starting', 'running', 'waiting_input', "
            "'waiting_approval', 'cancelling'))",
            name="ck_run_lease_required",
        ),
        sa.CheckConstraint(
            "(status IN ('cancelled', 'succeeded', 'failed', 'timed_out', 'orphaned') "
            "AND terminal_at IS NOT NULL) OR "
            "(status NOT IN ('cancelled', 'succeeded', 'failed', 'timed_out', 'orphaned') "
            "AND terminal_at IS NULL)",
            name="ck_run_terminal_at",
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_run_tenant_idempotency"),
        sa.UniqueConstraint("id", "tenant_id", "space_id", "project_id", name="uq_run_scope"),
        sa.Index(
            "ix_run_queue_claim",
            "status",
            "queue_class",
            "priority",
            "created_at",
        ),
        sa.Index("ix_run_task_created", "task_id", "created_at"),
        sa.Index("ix_run_parent_created", "parent_run_id", "created_at"),
        sa.Index(
            "ix_run_service_account_created",
            "tenant_id",
            "created_by_service_account_id",
            "created_at",
        ),
        sa.Index("ix_run_lease_expiry", "status", "lease_expires_at"),
    )


class RunEventRecord(SaasBase):
    """Persisted event ordered by a strictly monotonic per-Run sequence."""

    __tablename__ = "saas_run_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    sequence: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    trace_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_run_event_run_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("sequence > 0", name="ck_run_event_sequence"),
        sa.CheckConstraint("length(event_type) > 0", name="ck_run_event_type_nonempty"),
        sa.CheckConstraint("length(trace_id) > 0", name="ck_run_event_trace_nonempty"),
        sa.UniqueConstraint("run_id", "sequence", name="uq_run_event_sequence"),
        sa.Index("ix_run_event_replay", "run_id", "sequence"),
    )


class AdmissionQuotaRecord(SaasBase):
    """Versioned project quota with transactionally maintained counters."""

    __tablename__ = "saas_admission_quotas"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    resource: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    limit_units: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    reserved_units: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    consumed_units: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
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
            name="fk_admission_quota_project_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("length(resource) > 0", name="ck_admission_quota_resource_nonempty"),
        sa.CheckConstraint("limit_units > 0", name="ck_admission_quota_limit"),
        sa.CheckConstraint("reserved_units >= 0", name="ck_admission_quota_reserved"),
        sa.CheckConstraint("consumed_units >= 0", name="ck_admission_quota_consumed"),
        sa.CheckConstraint(
            "reserved_units + consumed_units <= limit_units", name="ck_admission_quota_capacity"
        ),
        sa.CheckConstraint("version > 0", name="ck_admission_quota_version"),
        sa.UniqueConstraint(
            "tenant_id", "space_id", "project_id", "resource", name="uq_admission_quota_scope"
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_admission_quota_id_scope"
        ),
    )


class QuotaReservationRecord(SaasBase):
    """Exactly-once quota hold coupled to one admitted Run."""

    __tablename__ = "saas_quota_reservations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    quota_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    units: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="reserved")
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    finalized_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("quota_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_admission_quotas.id",
                "saas_admission_quotas.tenant_id",
                "saas_admission_quotas.space_id",
                "saas_admission_quotas.project_id",
            ),
            name="fk_quota_reservation_quota_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_quota_reservation_run_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(RESERVATION_STATUSES)})", name="ck_quota_reservation_status"
        ),
        sa.CheckConstraint("units > 0", name="ck_quota_reservation_units"),
        sa.CheckConstraint("version > 0", name="ck_quota_reservation_version"),
        sa.CheckConstraint(
            "(status = 'reserved' AND finalized_at IS NULL) OR "
            "(status IN ('consumed', 'released') AND finalized_at IS NOT NULL)",
            name="ck_quota_reservation_finalized",
        ),
        sa.UniqueConstraint("run_id", "quota_id", name="uq_run_quota_reservation"),
        sa.Index("ix_quota_reservation_status", "quota_id", "status"),
    )


class EffectCallRecord(SaasBase):
    """Idempotency authority for model, tool, and external side effects."""

    __tablename__ = "saas_effect_calls"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(nullable=False)
    effect_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    effect_name: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    request: Mapped[dict[str, object]] = mapped_column(sa.JSON, nullable=False)
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="pending")
    unknown_policy: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    response: Mapped[dict[str, object] | None] = mapped_column(sa.JSON)
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
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
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_effect_call_run_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"effect_type IN ({_values(EFFECT_TYPES)})", name="ck_effect_call_type"
        ),
        sa.CheckConstraint(
            f"status IN ({_values(EFFECT_STATUSES)})", name="ck_effect_call_status"
        ),
        sa.CheckConstraint(
            f"unknown_policy IN ({_values(UNKNOWN_EFFECT_POLICIES)})",
            name="ck_effect_call_unknown_policy",
        ),
        sa.CheckConstraint("length(effect_name) > 0", name="ck_effect_call_name_nonempty"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_effect_call_idempotency"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_effect_call_request_hash"),
        sa.CheckConstraint("version > 0", name="ck_effect_call_version"),
        sa.UniqueConstraint("run_id", "idempotency_key", name="uq_effect_call_idempotency"),
        sa.Index("ix_effect_call_run_status", "run_id", "status"),
    )


class ArtifactRecord(SaasBase):
    """Content-addressed immutable artifact metadata."""

    __tablename__ = "saas_artifacts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    media_type: Mapped[str] = mapped_column(sa.String(256), nullable=False)
    object_uri: Mapped[str] = mapped_column(sa.String(2048), nullable=False)
    source_revision: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT")
    )
    created_by_service_account_id: Mapped[UUID | None] = mapped_column()
    metadata_json: Mapped[dict[str, object]] = mapped_column("metadata", sa.JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_artifact_project_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id", "created_by_service_account_id"),
            (
                "saas_service_accounts.tenant_id",
                "saas_service_accounts.space_id",
                "saas_service_accounts.project_id",
                "saas_service_accounts.id",
            ),
            name="fk_artifact_service_account_actor",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(created_by IS NOT NULL) <> (created_by_service_account_id IS NOT NULL)",
            name="ck_artifact_actor_xor",
        ),
        sa.CheckConstraint("length(sha256) = 64", name="ck_artifact_sha256"),
        sa.CheckConstraint("size_bytes >= 0", name="ck_artifact_size"),
        sa.CheckConstraint("length(media_type) > 0", name="ck_artifact_media_type_nonempty"),
        sa.CheckConstraint("length(object_uri) > 0", name="ck_artifact_uri_nonempty"),
        sa.CheckConstraint(
            "length(source_revision) > 0", name="ck_artifact_source_revision_nonempty"
        ),
        sa.UniqueConstraint(
            "tenant_id", "space_id", "project_id", "sha256", name="uq_artifact_content_scope"
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_artifact_id_scope"
        ),
        sa.Index(
            "ix_artifact_service_account_created",
            "tenant_id",
            "created_by_service_account_id",
            "created_at",
        ),
    )


class RunArtifactRecord(SaasBase):
    """Immutable association between a Run and a content-addressed artifact."""

    __tablename__ = "saas_run_artifacts"

    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    run_id: Mapped[UUID] = mapped_column(primary_key=True)
    artifact_id: Mapped[UUID] = mapped_column(primary_key=True)
    role: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_run_artifact_run_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("artifact_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_artifacts.id",
                "saas_artifacts.tenant_id",
                "saas_artifacts.space_id",
                "saas_artifacts.project_id",
            ),
            name="fk_run_artifact_artifact_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("length(role) > 0", name="ck_run_artifact_role_nonempty"),
        sa.Index("ix_run_artifact_artifact", "artifact_id"),
    )
