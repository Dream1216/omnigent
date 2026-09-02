"""Durable P0S9 Preview execution, browser session, and tunnel facts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase

PREVIEW_EXECUTION_STATUSES = frozenset(
    {
        "requested",
        "queued",
        "materializing",
        "starting",
        "ready",
        "stopping",
        "stopped",
        "failed",
        "revoked",
    }
)
ACTIVE_PREVIEW_EXECUTION_STATUSES = frozenset(
    PREVIEW_EXECUTION_STATUSES - {"stopped", "failed", "revoked"}
)
PREVIEW_COMMAND_TYPES = frozenset({"start", "stop"})
PREVIEW_COMMAND_STATUSES = frozenset({"pending", "claimed", "succeeded", "failed", "cancelled"})
PREVIEW_SESSION_STATUSES = frozenset({"active", "revoked", "expired"})
PREVIEW_TUNNEL_REGISTRATION_STATUSES = frozenset(
    {"issued", "redeemed", "disconnected", "revoked", "expired"}
)
STATIC_WEB_PREVIEW_PROFILE = "static_web_v1"


def _values(values: frozenset[str]) -> str:
    return ", ".join(f"'{value}'" for value in sorted(values))


def _hex64(column: str) -> str:
    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {remainder} = ''"


class PreviewExecutionRecord(SaasBase):
    """Server-owned child Run and readonly Worktree Preview saga."""

    __tablename__ = "saas_preview_executions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    source_run_id: Mapped[UUID] = mapped_column(nullable=False)
    child_run_id: Mapped[UUID] = mapped_column(nullable=False, unique=True)
    change_set_id: Mapped[UUID] = mapped_column(nullable=False)
    created_by: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"), nullable=False
    )
    profile: Mapped[str] = mapped_column(
        sa.String(32), nullable=False, default=STATIC_WEB_PREVIEW_PROFILE
    )
    idempotency_key_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    opaque_preview_key: Mapped[str] = mapped_column(sa.String(96), nullable=False, unique=True)
    preview_host: Mapped[str] = mapped_column(sa.String(253), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(sa.String(24), nullable=False, default="requested")
    command_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=0)
    runner_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_runner_registrations.id", ondelete="RESTRICT")
    )
    placement_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_runtime_placements.id", ondelete="RESTRICT")
    )
    worktree_id: Mapped[UUID | None] = mapped_column()
    run_fence_token: Mapped[int | None] = mapped_column(sa.BigInteger)
    runner_connection_generation: Mapped[int | None] = mapped_column(sa.BigInteger)
    worktree_lease_generation: Mapped[int | None] = mapped_column(sa.BigInteger)
    exchange_token_hash: Mapped[str | None] = mapped_column(sa.String(64), unique=True)
    exchange_issued_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    exchange_consumed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    ready_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    terminal_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(sa.String(128))
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
            ("source_run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_preview_execution_source_run_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("child_run_id", "tenant_id", "space_id", "project_id"),
            ("saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"),
            name="fk_preview_execution_child_run_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("change_set_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_changesets.id",
                "saas_changesets.tenant_id",
                "saas_changesets.space_id",
                "saas_changesets.project_id",
            ),
            name="fk_preview_execution_changeset_scope",
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
            name="fk_preview_execution_worktree_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"profile = '{STATIC_WEB_PREVIEW_PROFILE}'",
            name="ck_preview_execution_profile",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PREVIEW_EXECUTION_STATUSES)})",
            name="ck_preview_execution_status",
        ),
        sa.CheckConstraint(_hex64("idempotency_key_hash"), name="ck_preview_execution_idem_hash"),
        sa.CheckConstraint(_hex64("request_hash"), name="ck_preview_execution_request_hash"),
        sa.CheckConstraint(
            f"exchange_token_hash IS NULL OR ({_hex64('exchange_token_hash')})",
            name="ck_preview_execution_exchange_hash",
        ),
        sa.CheckConstraint("length(opaque_preview_key) > 4", name="ck_preview_execution_key"),
        sa.CheckConstraint("length(preview_host) > 0", name="ck_preview_execution_host"),
        sa.CheckConstraint("command_generation >= 0", name="ck_preview_execution_command_gen"),
        sa.CheckConstraint("version > 0", name="ck_preview_execution_version"),
        sa.CheckConstraint(
            "(exchange_token_hash IS NULL AND exchange_issued_at IS NULL "
            "AND exchange_consumed_at IS NULL) OR "
            "(exchange_token_hash IS NOT NULL AND exchange_issued_at IS NOT NULL)",
            name="ck_preview_execution_exchange_lifecycle",
        ),
        sa.CheckConstraint(
            "(ready_at IS NULL AND status IN ('requested', 'queued', 'materializing', "
            "'starting', 'stopping', 'stopped', 'failed', 'revoked')) OR "
            "(ready_at IS NOT NULL AND status IN ('ready', 'stopping', 'stopped', "
            "'failed', 'revoked') AND runner_id IS NOT NULL "
            "AND placement_id IS NOT NULL AND worktree_id IS NOT NULL "
            "AND run_fence_token > 0 AND runner_connection_generation > 0 "
            "AND worktree_lease_generation > 0)",
            name="ck_preview_execution_ready_fence",
        ),
        sa.CheckConstraint(
            "(status IN ('stopped', 'failed', 'revoked') AND terminal_at IS NOT NULL) OR "
            "(status NOT IN ('stopped', 'failed', 'revoked') AND terminal_at IS NULL)",
            name="ck_preview_execution_terminal",
        ),
        sa.CheckConstraint(
            "(status = 'failed' AND length(failure_code) > 0) OR "
            "(status <> 'failed' AND failure_code IS NULL)",
            name="ck_preview_execution_failure",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "created_by",
            "idempotency_key_hash",
            name="uq_preview_execution_actor_idempotency",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_preview_execution_scope"
        ),
        sa.Index(
            "uq_preview_execution_active_source_profile",
            "tenant_id",
            "project_id",
            "source_run_id",
            "profile",
            unique=True,
            sqlite_where=sa.text(
                "status IN ('requested', 'queued', 'materializing', 'starting', "
                "'ready', 'stopping')"
            ),
            postgresql_where=sa.text(
                "status IN ('requested', 'queued', 'materializing', 'starting', "
                "'ready', 'stopping')"
            ),
        ),
        sa.Index("ix_preview_execution_status_expiry", "status", "expires_at"),
    )


class PreviewCommandRecord(SaasBase):
    """Closed start/stop command consumed only by the exact Preview Owner."""

    __tablename__ = "saas_preview_commands"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    preview_execution_id: Mapped[UUID] = mapped_column(nullable=False)
    command_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="pending")
    runner_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_runner_registrations.id", ondelete="RESTRICT")
    )
    placement_id: Mapped[UUID | None] = mapped_column(
        sa.ForeignKey("saas_runtime_placements.id", ondelete="RESTRICT")
    )
    runner_connection_generation: Mapped[int | None] = mapped_column(sa.BigInteger)
    run_fence_token: Mapped[int | None] = mapped_column(sa.BigInteger)
    claim_token_hash: Mapped[str | None] = mapped_column(sa.String(64), unique=True)
    claimed_by_gateway: Mapped[str | None] = mapped_column(sa.String(128))
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(sa.String(128))
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
            ("preview_execution_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_preview_executions.id",
                "saas_preview_executions.tenant_id",
                "saas_preview_executions.space_id",
                "saas_preview_executions.project_id",
            ),
            name="fk_preview_command_execution_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"command_type IN ({_values(PREVIEW_COMMAND_TYPES)})",
            name="ck_preview_command_type",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PREVIEW_COMMAND_STATUSES)})",
            name="ck_preview_command_status",
        ),
        sa.CheckConstraint("generation > 0", name="ck_preview_command_generation"),
        sa.CheckConstraint(_hex64("request_hash"), name="ck_preview_command_request_hash"),
        sa.CheckConstraint(
            f"claim_token_hash IS NULL OR ({_hex64('claim_token_hash')})",
            name="ck_preview_command_claim_hash",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_preview_command_attempts"),
        sa.CheckConstraint(
            "(status = 'pending' AND run_fence_token IS NULL) OR "
            "(status <> 'pending' AND run_fence_token > 0)",
            name="ck_preview_command_run_fence",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND claim_token_hash IS NULL AND claimed_at IS NULL "
            "AND completed_at IS NULL) OR "
            "(status = 'claimed' AND claim_token_hash IS NOT NULL "
            "AND claimed_by_gateway IS NOT NULL AND claimed_at IS NOT NULL "
            "AND completed_at IS NULL) OR "
            "(status IN ('succeeded', 'failed', 'cancelled') AND completed_at IS NOT NULL)",
            name="ck_preview_command_lifecycle",
        ),
        sa.CheckConstraint(
            "(status = 'failed' AND length(failure_code) > 0) OR "
            "(status <> 'failed' AND failure_code IS NULL)",
            name="ck_preview_command_failure",
        ),
        sa.UniqueConstraint(
            "preview_execution_id",
            "command_type",
            "generation",
            name="uq_preview_command_generation",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_preview_command_scope"
        ),
        sa.Index("ix_preview_command_claim", "status", "available_at", "id"),
    )


class PreviewSessionRecord(SaasBase):
    """Independent rotating browser cookie after one-time URL exchange."""

    __tablename__ = "saas_preview_sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    space_id: Mapped[UUID] = mapped_column(nullable=False)
    project_id: Mapped[UUID] = mapped_column(nullable=False)
    preview_execution_id: Mapped[UUID] = mapped_column(nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    previous_token_hash: Mapped[str | None] = mapped_column(sa.String(64), unique=True)
    previous_valid_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False, default=1)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="active")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_authenticated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    rotated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            ("preview_execution_id", "tenant_id", "space_id", "project_id"),
            (
                "saas_preview_executions.id",
                "saas_preview_executions.tenant_id",
                "saas_preview_executions.space_id",
                "saas_preview_executions.project_id",
            ),
            name="fk_preview_session_execution_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(_hex64("token_hash"), name="ck_preview_session_token_hash"),
        sa.CheckConstraint(
            f"previous_token_hash IS NULL OR ({_hex64('previous_token_hash')})",
            name="ck_preview_session_previous_token_hash",
        ),
        sa.CheckConstraint(
            "(previous_token_hash IS NULL AND previous_valid_until IS NULL) OR "
            "(previous_token_hash IS NOT NULL AND previous_valid_until IS NOT NULL "
            "AND previous_valid_until <= expires_at)",
            name="ck_preview_session_previous_token_lifecycle",
        ),
        sa.CheckConstraint("generation > 0", name="ck_preview_session_generation"),
        sa.CheckConstraint(
            f"status IN ({_values(PREVIEW_SESSION_STATUSES)})",
            name="ck_preview_session_status",
        ),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL) OR "
            "(status IN ('revoked', 'expired') AND revoked_at IS NOT NULL)",
            name="ck_preview_session_lifecycle",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_preview_session_scope"
        ),
        sa.Index(
            "uq_preview_session_active_execution",
            "preview_execution_id",
            unique=True,
            sqlite_where=sa.text("status = 'active'"),
            postgresql_where=sa.text("status = 'active'"),
        ),
        sa.Index("ix_preview_session_expiry", "status", "expires_at"),
    )


class PreviewTunnelRegistrationRecord(SaasBase):
    """One-use Runner-to-Owner registration bound to an exact incarnation."""

    __tablename__ = "saas_preview_tunnel_registrations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    runner_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runner_registrations.id", ondelete="RESTRICT"), nullable=False
    )
    placement_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_runtime_placements.id", ondelete="RESTRICT"), nullable=False
    )
    connection_generation: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    gateway_instance_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    certificate_fingerprint_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    audience: Mapped[str] = mapped_column(sa.String(253), nullable=False)
    jti_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    official_runner_id: Mapped[str | None] = mapped_column(sa.String(256))
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="issued")
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    redeemed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    disconnected_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
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
            "connection_generation > 0", name="ck_preview_tunnel_registration_generation"
        ),
        sa.CheckConstraint(
            _hex64("certificate_fingerprint_sha256"),
            name="ck_preview_tunnel_registration_certificate",
        ),
        sa.CheckConstraint(_hex64("jti_hash"), name="ck_preview_tunnel_registration_jti"),
        sa.CheckConstraint(_hex64("token_hash"), name="ck_preview_tunnel_registration_token"),
        sa.CheckConstraint(
            "length(gateway_instance_id) > 0 AND length(audience) > 0",
            name="ck_preview_tunnel_registration_endpoint",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(PREVIEW_TUNNEL_REGISTRATION_STATUSES)})",
            name="ck_preview_tunnel_registration_status",
        ),
        sa.CheckConstraint(
            "(status = 'issued' AND redeemed_at IS NULL AND disconnected_at IS NULL "
            "AND revoked_at IS NULL AND length(official_runner_id) > 0) OR "
            "(status = 'redeemed' AND redeemed_at IS NOT NULL "
            "AND disconnected_at IS NULL AND revoked_at IS NULL "
            "AND length(official_runner_id) > 0) OR "
            "(status = 'disconnected' AND redeemed_at IS NOT NULL "
            "AND disconnected_at IS NOT NULL AND revoked_at IS NULL) OR "
            "(status IN ('revoked', 'expired') AND revoked_at IS NOT NULL)",
            name="ck_preview_tunnel_registration_lifecycle",
        ),
        sa.Index(
            "uq_preview_tunnel_registration_active_incarnation",
            "runner_id",
            "placement_id",
            "connection_generation",
            unique=True,
            sqlite_where=sa.text("status = 'redeemed'"),
            postgresql_where=sa.text("status = 'redeemed'"),
        ),
        sa.Index("ix_preview_tunnel_registration_expiry", "status", "expires_at"),
    )


__all__ = [
    "ACTIVE_PREVIEW_EXECUTION_STATUSES",
    "PREVIEW_COMMAND_STATUSES",
    "PREVIEW_COMMAND_TYPES",
    "PREVIEW_EXECUTION_STATUSES",
    "PREVIEW_SESSION_STATUSES",
    "PREVIEW_TUNNEL_REGISTRATION_STATUSES",
    "STATIC_WEB_PREVIEW_PROFILE",
    "PreviewCommandRecord",
    "PreviewExecutionRecord",
    "PreviewSessionRecord",
    "PreviewTunnelRegistrationRecord",
]
