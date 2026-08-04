"""Create the durable P3 execution authority and forced PostgreSQL RLS."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p3a000000001"
down_revision: str | None = "p2a000000007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_SPACE = "NULLIF(current_setting('app.space_id', true), '')::uuid"
_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_P3_TABLES = (
    "saas_tasks",
    "saas_execution_sessions",
    "saas_session_tasks",
    "saas_runs",
    "saas_run_events",
    "saas_admission_quotas",
    "saas_quota_reservations",
    "saas_effect_calls",
    "saas_artifacts",
    "saas_run_artifacts",
)


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


def _project_scope_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ("tenant_id", "space_id", "project_id"),
        ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
        name=name,
        ondelete="RESTRICT",
    )


def _run_scope_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ("run_id", "tenant_id", "space_id", "project_id"),
        ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
        name=name,
        ondelete="RESTRICT",
    )


def _create_intent_tables() -> None:
    op.create_table(
        "saas_tasks",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.CheckConstraint("length(title) > 0", name="ck_task_title_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_task_version"),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        _project_scope_fk("fk_task_project_scope"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "tenant_id", "space_id", "project_id", name="uq_task_scope"),
    )
    op.create_index(
        "ix_task_project_created",
        "saas_tasks",
        ("tenant_id", "space_id", "project_id", "created_at"),
    )

    op.create_table(
        "saas_execution_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        _updated_at(),
        sa.CheckConstraint("status IN ('active', 'closed')", name="ck_execution_session_status"),
        sa.CheckConstraint("version > 0", name="ck_execution_session_version"),
        sa.CheckConstraint(
            "(status = 'active' AND closed_at IS NULL) OR "
            "(status = 'closed' AND closed_at IS NOT NULL)",
            name="ck_execution_session_closed_at",
        ),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        _project_scope_fk("fk_execution_session_project_scope"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_execution_session_scope"
        ),
    )
    op.create_index(
        "ix_execution_session_project_status",
        "saas_execution_sessions",
        ("tenant_id", "space_id", "project_id", "status"),
    )

    op.create_table(
        "saas_session_tasks",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("attached_by", sa.Uuid(), nullable=False),
        sa.Column(
            "attached_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
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
        sa.ForeignKeyConstraint(("attached_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", "task_id", name="uq_session_task_link"),
    )
    op.create_index(
        "ix_session_task_task",
        "saas_session_tasks",
        ("tenant_id", "space_id", "project_id", "task_id"),
    )


def _create_run_tables() -> None:
    op.create_table(
        "saas_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("queue_class", sa.String(64), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("input", sa.JSON(), nullable=False),
        sa.Column("product_revision", sa.String(64), nullable=False),
        sa.Column("upstream_revision", sa.String(64), nullable=False),
        sa.Column("schema_revision", sa.String(64), nullable=False),
        sa.Column("adapter_contract_version", sa.String(32), nullable=False),
        sa.Column("lease_owner", sa.String(256), nullable=True),
        sa.Column("lease_token", sa.Uuid(), nullable=True),
        sa.Column("fence_token", sa.BigInteger(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        _updated_at(),
        sa.CheckConstraint(
            "status IN ('created', 'queued', 'leased', 'starting', 'running', "
            "'waiting_input', 'waiting_approval', 'cancelling', 'cancelled', "
            "'succeeded', 'failed', 'timed_out', 'orphaned')",
            name="ck_run_status",
        ),
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
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_run_tenant_idempotency"),
        sa.UniqueConstraint("id", "tenant_id", "space_id", "project_id", name="uq_run_scope"),
    )
    op.create_index(
        "ix_run_queue_claim",
        "saas_runs",
        ("status", "queue_class", "priority", "created_at"),
    )
    op.create_index("ix_run_task_created", "saas_runs", ("task_id", "created_at"))
    op.create_index("ix_run_lease_expiry", "saas_runs", ("status", "lease_expires_at"))

    op.create_table(
        "saas_run_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("trace_id", sa.String(128), nullable=False),
        _created_at(),
        sa.CheckConstraint("sequence > 0", name="ck_run_event_sequence"),
        sa.CheckConstraint("length(event_type) > 0", name="ck_run_event_type_nonempty"),
        sa.CheckConstraint("length(trace_id) > 0", name="ck_run_event_trace_nonempty"),
        _run_scope_fk("fk_run_event_run_scope"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "sequence", name="uq_run_event_sequence"),
    )
    op.create_index("ix_run_event_replay", "saas_run_events", ("run_id", "sequence"))


def _create_quota_and_effect_tables() -> None:
    op.create_table(
        "saas_admission_quotas",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("limit_units", sa.BigInteger(), nullable=False),
        sa.Column("reserved_units", sa.BigInteger(), nullable=False),
        sa.Column("consumed_units", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.CheckConstraint("length(resource) > 0", name="ck_admission_quota_resource_nonempty"),
        sa.CheckConstraint("limit_units > 0", name="ck_admission_quota_limit"),
        sa.CheckConstraint("reserved_units >= 0", name="ck_admission_quota_reserved"),
        sa.CheckConstraint("consumed_units >= 0", name="ck_admission_quota_consumed"),
        sa.CheckConstraint(
            "reserved_units + consumed_units <= limit_units", name="ck_admission_quota_capacity"
        ),
        sa.CheckConstraint("version > 0", name="ck_admission_quota_version"),
        _project_scope_fk("fk_admission_quota_project_scope"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "space_id", "project_id", "resource", name="uq_admission_quota_scope"
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_admission_quota_id_scope"
        ),
    )

    op.create_table(
        "saas_quota_reservations",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("quota_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("units", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.CheckConstraint(
            "status IN ('reserved', 'consumed', 'released')",
            name="ck_quota_reservation_status",
        ),
        sa.CheckConstraint("units > 0", name="ck_quota_reservation_units"),
        sa.CheckConstraint("version > 0", name="ck_quota_reservation_version"),
        sa.CheckConstraint(
            "(status = 'reserved' AND finalized_at IS NULL) OR "
            "(status IN ('consumed', 'released') AND finalized_at IS NOT NULL)",
            name="ck_quota_reservation_finalized",
        ),
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
        _run_scope_fk("fk_quota_reservation_run_scope"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "quota_id", name="uq_run_quota_reservation"),
    )
    op.create_index(
        "ix_quota_reservation_status", "saas_quota_reservations", ("quota_id", "status")
    )

    op.create_table(
        "saas_effect_calls",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("effect_type", sa.String(32), nullable=False),
        sa.Column("effect_name", sa.String(256), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("unknown_policy", sa.String(32), nullable=False),
        sa.Column("response", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        _created_at(),
        _updated_at(),
        sa.CheckConstraint(
            "effect_type IN ('model', 'tool', 'external')", name="ck_effect_call_type"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'succeeded', 'failed', 'unknown')",
            name="ck_effect_call_status",
        ),
        sa.CheckConstraint(
            "unknown_policy IN ('retry_safe', 'approval_required', 'compensation_required')",
            name="ck_effect_call_unknown_policy",
        ),
        sa.CheckConstraint("length(effect_name) > 0", name="ck_effect_call_name_nonempty"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_effect_call_idempotency"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_effect_call_request_hash"),
        sa.CheckConstraint("version > 0", name="ck_effect_call_version"),
        _run_scope_fk("fk_effect_call_run_scope"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "idempotency_key", name="uq_effect_call_idempotency"),
    )
    op.create_index("ix_effect_call_run_status", "saas_effect_calls", ("run_id", "status"))


def _create_artifact_tables() -> None:
    op.create_table(
        "saas_artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("media_type", sa.String(256), nullable=False),
        sa.Column("object_uri", sa.String(2048), nullable=False),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        _created_at(),
        sa.CheckConstraint("length(sha256) = 64", name="ck_artifact_sha256"),
        sa.CheckConstraint("size_bytes >= 0", name="ck_artifact_size"),
        sa.CheckConstraint("length(media_type) > 0", name="ck_artifact_media_type_nonempty"),
        sa.CheckConstraint("length(object_uri) > 0", name="ck_artifact_uri_nonempty"),
        sa.CheckConstraint(
            "length(source_revision) > 0", name="ck_artifact_source_revision_nonempty"
        ),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        _project_scope_fk("fk_artifact_project_scope"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "space_id", "project_id", "sha256", name="uq_artifact_content_scope"
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_artifact_id_scope"
        ),
    )

    op.create_table(
        "saas_run_artifacts",
        *_scope_columns(),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("artifact_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(64), nullable=False),
        _created_at(),
        sa.CheckConstraint("length(role) > 0", name="ck_run_artifact_role_nonempty"),
        _run_scope_fk("fk_run_artifact_run_scope"),
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
        sa.PrimaryKeyConstraint("run_id", "artifact_id"),
    )
    op.create_index("ix_run_artifact_artifact", "saas_run_artifacts", ("artifact_id",))


def _install_postgresql_guards() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    predicate = f"({_PLATFORM} OR {_EXECUTOR} OR (tenant_id = {_TENANT} AND space_id = {_SPACE}))"
    for table in _P3_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" '
            f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
        )

    op.execute(
        """
        CREATE FUNCTION saas_reject_immutable_artifact_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'artifact metadata and Run links are immutable';
        END
        $$
        """
    )
    for table in ("saas_artifacts", "saas_run_artifacts"):
        op.execute(
            f'CREATE TRIGGER "trg_{table}_immutable" BEFORE UPDATE OR DELETE ON "{table}" '
            "FOR EACH ROW EXECUTE FUNCTION saas_reject_immutable_artifact_mutation()"
        )


def upgrade() -> None:
    """Install durable execution facts without modifying official runtime tables."""

    _create_intent_tables()
    _create_run_tables()
    _create_quota_and_effect_tables()
    _create_artifact_tables()
    _install_postgresql_guards()


def downgrade() -> None:
    """Remove P3 facts after dropping immutable guards and RLS policies."""

    if op.get_bind().dialect.name == "postgresql":
        for table in ("saas_run_artifacts", "saas_artifacts"):
            op.execute(f'DROP TRIGGER IF EXISTS "trg_{table}_immutable" ON "{table}"')
        op.execute("DROP FUNCTION IF EXISTS saas_reject_immutable_artifact_mutation()")
        for table in reversed(_P3_TABLES):
            op.execute(f'DROP POLICY IF EXISTS "rls_{table}_scope" ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')

    op.drop_index("ix_run_artifact_artifact", table_name="saas_run_artifacts")
    op.drop_table("saas_run_artifacts")
    op.drop_table("saas_artifacts")
    op.drop_index("ix_effect_call_run_status", table_name="saas_effect_calls")
    op.drop_table("saas_effect_calls")
    op.drop_index("ix_quota_reservation_status", table_name="saas_quota_reservations")
    op.drop_table("saas_quota_reservations")
    op.drop_table("saas_admission_quotas")
    op.drop_index("ix_run_event_replay", table_name="saas_run_events")
    op.drop_table("saas_run_events")
    op.drop_index("ix_run_lease_expiry", table_name="saas_runs")
    op.drop_index("ix_run_task_created", table_name="saas_runs")
    op.drop_index("ix_run_queue_claim", table_name="saas_runs")
    op.drop_table("saas_runs")
    op.drop_index("ix_session_task_task", table_name="saas_session_tasks")
    op.drop_table("saas_session_tasks")
    op.drop_index("ix_execution_session_project_status", table_name="saas_execution_sessions")
    op.drop_table("saas_execution_sessions")
    op.drop_index("ix_task_project_created", table_name="saas_tasks")
    op.drop_table("saas_tasks")
