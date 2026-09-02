"""Install durable Preview child Runs, sessions, commands, and tunnel registration.

Revision ID: p0s000000009
Revises: p0s000000008
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000009"
down_revision: str | None = "p0s000000008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LEGACY_DRAIN = (
    "cannot apply p0s000000009: active legacy Preview leases must be revoked and drained"
)
_DOWNGRADE_DRAIN = (
    "cannot downgrade p0s000000009: Preview executions, commands, sessions, and tunnel "
    "registrations must be drained"
)
_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_SPACE = "NULLIF(current_setting('app.space_id', true), '')::uuid"
_PROJECT = "NULLIF(current_setting('app.project_id', true), '')::uuid"
_ACTOR = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_GATEWAY = "NULLIF(current_setting('app.preview_gateway_instance_id', true), '')"
_GATEWAY_TOKEN = "NULLIF(current_setting('app.preview_gateway_registration_token_hash', true), '')"
_EXCHANGE_HASH = "NULLIF(current_setting('app.preview_exchange_token_hash', true), '')"
_SESSION_HASH = "NULLIF(current_setting('app.preview_session_token_hash', true), '')"
_REGISTRATION_HASH = "NULLIF(current_setting('app.preview_registration_token_hash', true), '')"


def _scope_columns() -> tuple[sa.Column[Any], ...]:
    return (
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
    )


def _timestamps() -> tuple[sa.Column[Any], ...]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def _hex64(column: str) -> str:
    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {remainder} = ''"


def _lock_and_require_legacy_drain() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("LOCK TABLE public.saas_preview_leases IN ACCESS EXCLUSIVE MODE")
        op.execute("ALTER TABLE public.saas_preview_leases NO FORCE ROW LEVEL SECURITY")
    else:
        bind.exec_driver_sql(
            "UPDATE saas_preview_leases SET last_accessed_at = last_accessed_at WHERE 1 = 0"
        )
    occupied = bind.execute(
        sa.text("SELECT 1 FROM saas_preview_leases WHERE status = 'active' LIMIT 1")
    ).first()
    if occupied is not None:
        if bind.dialect.name == "postgresql":
            op.execute("ALTER TABLE public.saas_preview_leases FORCE ROW LEVEL SECURITY")
        raise RuntimeError(_LEGACY_DRAIN)
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE public.saas_preview_leases FORCE ROW LEVEL SECURITY")


def _create_execution_table() -> None:
    op.create_table(
        "saas_preview_executions",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("source_run_id", sa.Uuid(), nullable=False),
        sa.Column("child_run_id", sa.Uuid(), nullable=False),
        sa.Column("change_set_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("profile", sa.String(32), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("opaque_preview_key", sa.String(96), nullable=False),
        sa.Column("preview_host", sa.String(253), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("command_generation", sa.BigInteger(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=True),
        sa.Column("placement_id", sa.Uuid(), nullable=True),
        sa.Column("worktree_id", sa.Uuid(), nullable=True),
        sa.Column("run_fence_token", sa.BigInteger(), nullable=True),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=True),
        sa.Column("worktree_lease_generation", sa.BigInteger(), nullable=True),
        sa.Column("exchange_token_hash", sa.String(64), nullable=True),
        sa.Column("exchange_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exchange_consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ready_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(128), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(("created_by",), ("saas_global_users.id",), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ("placement_id",), ("saas_runtime_placements.id",), ondelete="RESTRICT"
        ),
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
        sa.CheckConstraint("profile = 'static_web_v1'", name="ck_preview_execution_profile"),
        sa.CheckConstraint(
            "status IN ('requested', 'queued', 'materializing', 'starting', 'ready', "
            "'stopping', 'stopped', 'failed', 'revoked')",
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
        sa.UniqueConstraint("child_run_id"),
        sa.UniqueConstraint("opaque_preview_key"),
        sa.UniqueConstraint("preview_host"),
        sa.UniqueConstraint("exchange_token_hash"),
        sa.UniqueConstraint(
            "tenant_id",
            "created_by",
            "idempotency_key_hash",
            name="uq_preview_execution_actor_idempotency",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_preview_execution_scope"
        ),
    )
    active = sa.text(
        "status IN ('requested', 'queued', 'materializing', 'starting', 'ready', 'stopping')"
    )
    op.create_index(
        "uq_preview_execution_active_source_profile",
        "saas_preview_executions",
        ("tenant_id", "project_id", "source_run_id", "profile"),
        unique=True,
        sqlite_where=active,
        postgresql_where=active,
    )
    op.create_index(
        "ix_preview_execution_status_expiry",
        "saas_preview_executions",
        ("status", "expires_at"),
    )


def _create_command_table() -> None:
    op.create_table(
        "saas_preview_commands",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("preview_execution_id", sa.Uuid(), nullable=False),
        sa.Column("command_type", sa.String(16), nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=True),
        sa.Column("placement_id", sa.Uuid(), nullable=True),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=True),
        sa.Column("run_fence_token", sa.BigInteger(), nullable=True),
        sa.Column("claim_token_hash", sa.String(64), nullable=True),
        sa.Column("claimed_by_gateway", sa.String(128), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(128), nullable=True),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ("placement_id",), ("saas_runtime_placements.id",), ondelete="RESTRICT"
        ),
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
        sa.CheckConstraint("command_type IN ('start', 'stop')", name="ck_preview_command_type"),
        sa.CheckConstraint(
            "status IN ('pending', 'claimed', 'succeeded', 'failed', 'cancelled')",
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
        sa.UniqueConstraint("claim_token_hash"),
        sa.UniqueConstraint(
            "preview_execution_id",
            "command_type",
            "generation",
            name="uq_preview_command_generation",
        ),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_preview_command_scope"
        ),
    )
    op.create_index(
        "ix_preview_command_claim",
        "saas_preview_commands",
        ("status", "available_at", "id"),
    )


def _create_session_table() -> None:
    op.create_table(
        "saas_preview_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        *_scope_columns(),
        sa.Column("preview_execution_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("previous_token_hash", sa.String(64), nullable=True),
        sa.Column("previous_valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
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
            "status IN ('active', 'revoked', 'expired')", name="ck_preview_session_status"
        ),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL) OR "
            "(status IN ('revoked', 'expired') AND revoked_at IS NOT NULL)",
            name="ck_preview_session_lifecycle",
        ),
        sa.UniqueConstraint("token_hash"),
        sa.UniqueConstraint("previous_token_hash"),
        sa.UniqueConstraint(
            "id", "tenant_id", "space_id", "project_id", name="uq_preview_session_scope"
        ),
    )
    active = sa.text("status = 'active'")
    op.create_index(
        "uq_preview_session_active_execution",
        "saas_preview_sessions",
        ("preview_execution_id",),
        unique=True,
        sqlite_where=active,
        postgresql_where=active,
    )
    op.create_index(
        "ix_preview_session_expiry",
        "saas_preview_sessions",
        ("status", "expires_at"),
    )


def _create_registration_table() -> None:
    op.create_table(
        "saas_preview_tunnel_registrations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("placement_id", sa.Uuid(), nullable=False),
        sa.Column("connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("gateway_instance_id", sa.String(128), nullable=False),
        sa.Column("certificate_fingerprint_sha256", sa.String(64), nullable=False),
        sa.Column("audience", sa.String(253), nullable=False),
        sa.Column("jti_hash", sa.String(64), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("official_runner_id", sa.String(256), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disconnected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ("placement_id",), ("saas_runtime_placements.id",), ondelete="RESTRICT"
        ),
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
            "status IN ('issued', 'redeemed', 'disconnected', 'revoked', 'expired')",
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
        sa.UniqueConstraint("jti_hash"),
        sa.UniqueConstraint("token_hash"),
    )
    active = sa.text("status = 'redeemed'")
    op.create_index(
        "uq_preview_tunnel_registration_active_incarnation",
        "saas_preview_tunnel_registrations",
        ("runner_id", "placement_id", "connection_generation"),
        unique=True,
        sqlite_where=active,
        postgresql_where=active,
    )
    op.create_index(
        "ix_preview_tunnel_registration_expiry",
        "saas_preview_tunnel_registrations",
        ("status", "expires_at"),
    )


def _enable_rls(table: str) -> None:
    op.execute(f'ALTER TABLE public."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE public."{table}" FORCE ROW LEVEL SECURITY')


def _definer_policy(table: str) -> None:
    """Allow only the direct table owner used by locked SECURITY DEFINER APIs."""

    op.execute(
        f'CREATE POLICY "rls_{table}_definer" ON public."{table}" '
        "FOR ALL USING (current_user = pg_get_userbyid((SELECT relation.relowner "
        "FROM pg_catalog.pg_class AS relation "
        f"WHERE relation.oid = 'public.{table}'::regclass))) "
        "WITH CHECK (current_user = pg_get_userbyid((SELECT relation.relowner "
        "FROM pg_catalog.pg_class AS relation "
        f"WHERE relation.oid = 'public.{table}'::regclass)))"
    )


def _definer_select_policy(table: str) -> None:
    """Let locked definer APIs revalidate existing durable routing facts."""

    op.execute(
        f'CREATE POLICY "rls_{table}_preview_definer" ON public."{table}" '
        "FOR SELECT USING (current_user = pg_get_userbyid((SELECT relation.relowner "
        "FROM pg_catalog.pg_class AS relation "
        f"WHERE relation.oid = 'public.{table}'::regclass)))"
    )


def _install_owner_route_predicate() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_issue_tunnel_registration_v1(
            expected_runner_id uuid,
            expected_connection_generation bigint,
            presented_connection_token_hash text,
            presented_certificate_fingerprint text,
            new_registration_id uuid,
            new_jti_hash text,
            new_token_hash text,
            new_official_runner_id text,
            requested_lifetime_seconds integer
        ) RETURNS TABLE (
            registration_id uuid,
            runner_id uuid,
            placement_id uuid,
            connection_generation bigint,
            gateway_instance_id text,
            endpoint_host text,
            server_name text,
            expires_at timestamptz
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            runner public.saas_runner_registrations%ROWTYPE;
            gateway public.saas_preview_gateway_instances%ROWTYPE;
            operation_at timestamptz := CURRENT_TIMESTAMP;
            new_expires_at timestamptz;
        BEGIN
            IF expected_runner_id IS NULL
               OR expected_connection_generation <= 0
               OR presented_connection_token_hash !~ '^[0-9a-f]{64}$'
               OR presented_certificate_fingerprint !~ '^[0-9a-f]{64}$'
               OR new_registration_id IS NULL
               OR new_jti_hash !~ '^[0-9a-f]{64}$'
               OR new_token_hash !~ '^[0-9a-f]{64}$'
               OR new_official_runner_id !~ '^runner_token_[0-9a-f]{32}$'
               OR requested_lifetime_seconds < 10
               OR requested_lifetime_seconds > 120 THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO runner
            FROM public.saas_runner_registrations AS candidate
            WHERE candidate.id = expected_runner_id
              AND candidate.connection_generation = expected_connection_generation
              AND candidate.connection_token_hash = presented_connection_token_hash
              AND candidate.status IN ('online', 'draining')
              AND candidate.capabilities::jsonb ? 'preview.static_web_v1'
              AND EXISTS (
                    SELECT 1
                    FROM public.saas_runner_certificates AS certificate
                    WHERE certificate.runner_id = candidate.id
                      AND certificate.runner_connection_generation =
                          candidate.connection_generation
                      AND certificate.fingerprint_sha256 =
                          presented_certificate_fingerprint
                      AND certificate.purpose = 'runner_control'
                      AND certificate.status IN ('active', 'retiring')
                      AND certificate.certificate_not_before <= operation_at
                      AND certificate.certificate_not_after > operation_at
                      AND (certificate.retire_at IS NULL
                           OR certificate.retire_at > operation_at)
              )
            FOR UPDATE;
            IF NOT FOUND THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO gateway
            FROM public.saas_preview_gateway_instances AS candidate
            WHERE candidate.failure_domain = runner.failure_domain
              AND candidate.source_revision = runner.source_revision
              AND candidate.status = 'active'
              AND candidate.lease_expires_at > operation_at
            ORDER BY candidate.id
            LIMIT 1;
            IF NOT FOUND THEN
                RETURN;
            END IF;
            UPDATE public.saas_preview_tunnel_registrations AS stale
            SET status = 'revoked', revoked_at = operation_at,
                updated_at = operation_at
            WHERE stale.runner_id = runner.id
              AND stale.connection_generation = runner.connection_generation
              AND stale.status = 'issued';
            new_expires_at := operation_at
                + make_interval(secs => requested_lifetime_seconds);
            INSERT INTO public.saas_preview_tunnel_registrations (
                id, runner_id, placement_id, connection_generation,
                gateway_instance_id, certificate_fingerprint_sha256, audience,
                jti_hash, token_hash, official_runner_id, status, expires_at,
                created_at, updated_at
            ) VALUES (
                new_registration_id, runner.id, runner.placement_id,
                runner.connection_generation, gateway.id,
                presented_certificate_fingerprint, gateway.server_name,
                new_jti_hash, new_token_hash, new_official_runner_id, 'issued',
                new_expires_at, operation_at, operation_at
            );
            RETURN QUERY SELECT new_registration_id, runner.id,
                runner.placement_id, runner.connection_generation, gateway.id::text,
                gateway.connect_host::text, gateway.server_name::text,
                new_expires_at;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_revoke_tunnel_registration_v1(
            expected_runner_id uuid,
            expected_connection_generation bigint,
            presented_connection_token_hash text,
            presented_certificate_fingerprint text,
            expected_registration_id uuid,
            presented_registration_hash text
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            operation_at timestamptz := CURRENT_TIMESTAMP;
            touched integer;
        BEGIN
            IF expected_runner_id IS NULL
               OR expected_connection_generation <= 0
               OR presented_connection_token_hash !~ '^[0-9a-f]{64}$'
               OR presented_certificate_fingerprint !~ '^[0-9a-f]{64}$'
               OR expected_registration_id IS NULL
               OR presented_registration_hash !~ '^[0-9a-f]{64}$'
               OR NOT EXISTS (
                    SELECT 1
                    FROM public.saas_runner_registrations AS runner
                    JOIN public.saas_runner_certificates AS certificate
                      ON certificate.runner_id = runner.id
                     AND certificate.runner_connection_generation =
                         runner.connection_generation
                     AND certificate.fingerprint_sha256 =
                         presented_certificate_fingerprint
                    WHERE runner.id = expected_runner_id
                      AND runner.connection_generation =
                          expected_connection_generation
                      AND runner.connection_token_hash =
                          presented_connection_token_hash
                      AND runner.status IN ('online', 'draining')
                      AND certificate.purpose = 'runner_control'
                      AND certificate.status IN ('active', 'retiring')
                      AND certificate.certificate_not_before <= operation_at
                      AND certificate.certificate_not_after > operation_at
                      AND (certificate.retire_at IS NULL
                           OR certificate.retire_at > operation_at)
               ) THEN
                RETURN false;
            END IF;
            UPDATE public.saas_preview_tunnel_registrations AS registration
            SET status = 'revoked', revoked_at = operation_at,
                updated_at = operation_at
            WHERE registration.id = expected_registration_id
              AND registration.runner_id = expected_runner_id
              AND registration.connection_generation =
                  expected_connection_generation
              AND registration.certificate_fingerprint_sha256 =
                  presented_certificate_fingerprint
              AND registration.token_hash = presented_registration_hash
              AND registration.status = 'issued';
            GET DIAGNOSTICS touched = ROW_COUNT;
            RETURN touched = 1;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_preauthorize_tunnel_v1(
            presented_registration_hash text,
            expected_official_runner_id text,
            expected_gateway_id text,
            presented_gateway_token_hash text,
            checked_at timestamptz
        ) RETURNS TABLE (
            registration_id uuid,
            runner_id uuid,
            placement_id uuid,
            connection_generation bigint,
            certificate_fingerprint_sha256 text
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
            SELECT registration.id, registration.runner_id,
                registration.placement_id, registration.connection_generation,
                registration.certificate_fingerprint_sha256::text
            FROM public.saas_preview_tunnel_registrations AS registration
            JOIN public.saas_runner_registrations AS runner
              ON runner.id = registration.runner_id
            JOIN public.saas_runner_certificates AS certificate
              ON certificate.runner_id = registration.runner_id
             AND certificate.runner_connection_generation =
                 registration.connection_generation
             AND certificate.fingerprint_sha256 =
                 registration.certificate_fingerprint_sha256
            JOIN public.saas_preview_gateway_instances AS gateway
              ON gateway.id = registration.gateway_instance_id
            WHERE presented_registration_hash ~ '^[0-9a-f]{64}$'
              AND presented_gateway_token_hash ~ '^[0-9a-f]{64}$'
              AND checked_at IS NOT NULL
              AND registration.token_hash = presented_registration_hash
              AND registration.official_runner_id = expected_official_runner_id
              AND registration.gateway_instance_id = expected_gateway_id
              AND registration.status = 'issued'
              AND registration.expires_at > checked_at
              AND runner.placement_id = registration.placement_id
              AND runner.connection_generation = registration.connection_generation
              AND runner.status IN ('online', 'draining')
              AND certificate.purpose = 'runner_control'
              AND certificate.status IN ('active', 'retiring')
              AND certificate.certificate_not_before <= checked_at
              AND certificate.certificate_not_after > checked_at
              AND (certificate.retire_at IS NULL OR certificate.retire_at > checked_at)
              AND gateway.registration_token_hash = presented_gateway_token_hash
              AND gateway.status = 'active'
              AND gateway.lease_expires_at > checked_at
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_redeem_tunnel_v1(
            presented_registration_hash text,
            expected_official_runner_id text,
            expected_gateway_id text,
            presented_gateway_token_hash text,
            new_placement_id uuid,
            new_ownership_token_hash text,
            operation_at timestamptz
        ) RETURNS TABLE (
            registration_id uuid,
            runner_id uuid,
            runtime_placement_id uuid,
            tunnel_placement_id uuid,
            connection_generation bigint,
            routing_generation bigint,
            relay_subject text
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            registration public.saas_preview_tunnel_registrations%ROWTYPE;
            next_routing_generation bigint;
            new_relay_subject text;
        BEGIN
            IF new_placement_id IS NULL
               OR new_ownership_token_hash !~ '^[0-9a-f]{64}$' THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO registration
            FROM public.saas_preview_tunnel_registrations AS candidate
            WHERE candidate.token_hash = presented_registration_hash
            FOR UPDATE;
            IF NOT FOUND OR registration.status <> 'issued'
               OR registration.official_runner_id <> expected_official_runner_id
               OR registration.gateway_instance_id <> expected_gateway_id
               OR registration.expires_at <= operation_at
               OR NOT EXISTS (
                    SELECT 1
                    FROM public.saas_preview_preauthorize_tunnel_v1(
                        presented_registration_hash, expected_official_runner_id,
                        expected_gateway_id, presented_gateway_token_hash, operation_at
                    )
               ) THEN
                RETURN;
            END IF;
            UPDATE public.saas_runner_tunnel_placements AS stale
            SET status = 'released', released_at = operation_at,
                release_reason = 'preview_runner_reconnected', updated_at = operation_at
            WHERE stale.runner_id = registration.runner_id
              AND stale.status IN ('active', 'draining');
            SELECT COALESCE(MAX(prior.routing_generation), 0) + 1
            INTO next_routing_generation
            FROM public.saas_runner_tunnel_placements AS prior
            WHERE prior.runner_id = registration.runner_id;
            new_relay_subject := 'rtp_' || replace(new_placement_id::text, '-', '');
            INSERT INTO public.saas_runner_tunnel_placements (
                id, runner_id, runner_connection_generation, routing_generation,
                gateway_instance_id, relay_subject, ownership_token_hash, status,
                claimed_at, last_heartbeat_at, lease_expires_at, created_at, updated_at
            ) VALUES (
                new_placement_id, registration.runner_id,
                registration.connection_generation, next_routing_generation,
                registration.gateway_instance_id, new_relay_subject,
                new_ownership_token_hash, 'active', operation_at, operation_at,
                operation_at + INTERVAL '45 seconds', operation_at, operation_at
            );
            UPDATE public.saas_preview_tunnel_registrations AS consumed
            SET status = 'redeemed', redeemed_at = operation_at, updated_at = operation_at
            WHERE consumed.id = registration.id;
            RETURN QUERY SELECT registration.id, registration.runner_id,
                registration.placement_id, new_placement_id,
                registration.connection_generation, next_routing_generation,
                new_relay_subject;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_heartbeat_tunnel_v1(
            presented_registration_hash text,
            expected_official_runner_id text,
            expected_gateway_id text,
            presented_gateway_token_hash text,
            operation_at timestamptz
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            touched integer;
        BEGIN
            UPDATE public.saas_runner_tunnel_placements AS placement
            SET last_heartbeat_at = operation_at,
                lease_expires_at = operation_at + INTERVAL '45 seconds',
                updated_at = operation_at
            FROM public.saas_preview_tunnel_registrations AS registration,
                 public.saas_runner_registrations AS runner,
                 public.saas_preview_gateway_instances AS gateway
            WHERE registration.token_hash = presented_registration_hash
              AND registration.official_runner_id = expected_official_runner_id
              AND registration.gateway_instance_id = expected_gateway_id
              AND registration.status = 'redeemed'
              AND runner.id = registration.runner_id
              AND runner.placement_id = registration.placement_id
              AND runner.connection_generation = registration.connection_generation
              AND runner.status IN ('online', 'draining')
              AND gateway.id = expected_gateway_id
              AND gateway.registration_token_hash = presented_gateway_token_hash
              AND gateway.status = 'active'
              AND gateway.lease_expires_at > operation_at
              AND placement.runner_id = registration.runner_id
              AND placement.runner_connection_generation = registration.connection_generation
              AND placement.gateway_instance_id = expected_gateway_id
              AND placement.status = 'active'
              AND placement.lease_expires_at > operation_at;
            GET DIAGNOSTICS touched = ROW_COUNT;
            RETURN touched = 1;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_disconnect_tunnel_v1(
            presented_registration_hash text,
            expected_official_runner_id text,
            expected_gateway_id text,
            presented_gateway_token_hash text,
            operation_at timestamptz
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            registration public.saas_preview_tunnel_registrations%ROWTYPE;
        BEGIN
            SELECT candidate.* INTO registration
            FROM public.saas_preview_tunnel_registrations AS candidate
            JOIN public.saas_preview_gateway_instances AS gateway
              ON gateway.id = candidate.gateway_instance_id
            WHERE candidate.token_hash = presented_registration_hash
              AND candidate.official_runner_id = expected_official_runner_id
              AND candidate.gateway_instance_id = expected_gateway_id
              AND candidate.status = 'redeemed'
              AND gateway.registration_token_hash = presented_gateway_token_hash
            FOR UPDATE OF candidate;
            IF NOT FOUND THEN
                RETURN false;
            END IF;
            UPDATE public.saas_runner_tunnel_placements AS placement
            SET status = 'released', released_at = operation_at,
                release_reason = 'preview_runner_disconnected',
                updated_at = operation_at
            WHERE placement.runner_id = registration.runner_id
              AND placement.runner_connection_generation = registration.connection_generation
              AND placement.gateway_instance_id = expected_gateway_id
              AND placement.status IN ('active', 'draining');
            UPDATE public.saas_preview_tunnel_registrations AS consumed
            SET status = 'disconnected', disconnected_at = operation_at,
                updated_at = operation_at
            WHERE consumed.id = registration.id;
            RETURN true;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_owner_route_match_v1(
            expected_runner_id uuid,
            expected_placement_id uuid,
            expected_connection_generation bigint,
            expected_gateway_id text,
            presented_gateway_token_hash text,
            checked_at timestamptz
        ) RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
            SELECT expected_runner_id IS NOT NULL
               AND expected_placement_id IS NOT NULL
               AND expected_connection_generation > 0
               AND length(expected_gateway_id) > 0
               AND presented_gateway_token_hash ~ '^[0-9a-f]{64}$'
               AND checked_at IS NOT NULL
               AND EXISTS (
                    SELECT 1
                    FROM public.saas_runner_tunnel_placements AS placement
                    JOIN public.saas_runner_registrations AS runner
                      ON runner.id = placement.runner_id
                    JOIN public.saas_preview_gateway_instances AS gateway
                      ON gateway.id = placement.gateway_instance_id
                    WHERE runner.id = expected_runner_id
                      AND runner.placement_id = expected_placement_id
                      AND runner.connection_generation = expected_connection_generation
                      AND runner.status IN ('online', 'draining')
                      AND placement.runner_connection_generation =
                          expected_connection_generation
                      AND placement.gateway_instance_id = expected_gateway_id
                      AND placement.status = 'active'
                      AND placement.lease_expires_at > checked_at
                      AND gateway.registration_token_hash =
                          presented_gateway_token_hash
                      AND gateway.status = 'active'
                      AND gateway.lease_expires_at > checked_at
               )
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_owner_heartbeat_gateway_v1(
            expected_gateway_id text,
            presented_gateway_token_hash text
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            touched integer;
        BEGIN
            IF length(expected_gateway_id) = 0
               OR presented_gateway_token_hash !~ '^[0-9a-f]{64}$' THEN
                RETURN false;
            END IF;
            UPDATE public.saas_preview_gateway_instances AS gateway
            SET last_heartbeat_at = CURRENT_TIMESTAMP,
                lease_expires_at = GREATEST(
                    gateway.lease_expires_at,
                    CURRENT_TIMESTAMP + INTERVAL '45 seconds'
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE gateway.id = expected_gateway_id
              AND gateway.registration_token_hash = presented_gateway_token_hash
              AND gateway.status = 'active'
              AND gateway.last_heartbeat_at <= CURRENT_TIMESTAMP
              AND gateway.lease_expires_at > CURRENT_TIMESTAMP;
            GET DIAGNOSTICS touched = ROW_COUNT;
            RETURN touched = 1;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_owner_release_gateway_v1(
            expected_gateway_id text,
            presented_gateway_token_hash text
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            touched integer;
        BEGIN
            IF length(expected_gateway_id) = 0
               OR presented_gateway_token_hash !~ '^[0-9a-f]{64}$' THEN
                RETURN false;
            END IF;
            UPDATE public.saas_preview_gateway_instances AS gateway
            SET status = 'released',
                released_at = CURRENT_TIMESTAMP,
                release_reason = 'preview_owner_shutdown',
                updated_at = CURRENT_TIMESTAMP
            WHERE gateway.id = expected_gateway_id
              AND gateway.registration_token_hash = presented_gateway_token_hash
              AND gateway.status IN ('active', 'draining')
              AND gateway.last_heartbeat_at <= CURRENT_TIMESTAMP;
            GET DIAGNOSTICS touched = ROW_COUNT;
            RETURN touched = 1;
        END
        $function$
        """
    )
    for signature in (
        "saas_preview_owner_route_match_v1(uuid,uuid,bigint,text,text,timestamptz)",
        "saas_preview_owner_heartbeat_gateway_v1(text,text)",
        "saas_preview_owner_release_gateway_v1(text,text)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION public.{signature} TO saas_preview_owner")


def _harden_placement_trigger_search_path() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.saas_require_live_preview_gateway_placement()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
            IF NEW.status IN ('active', 'draining') AND NOT EXISTS (
                SELECT 1 FROM public.saas_preview_gateway_instances AS gateway
                WHERE gateway.id = NEW.gateway_instance_id
                  AND gateway.status IN ('active', 'draining')
                  AND gateway.lease_expires_at > CURRENT_TIMESTAMP
            ) THEN
                RAISE EXCEPTION 'Runner tunnel Placement requires a live Preview Gateway';
            END IF;
            RETURN NEW;
        END
        $function$
        """
    )


def _install_postgresql_rls() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    scope = f"tenant_id = {_TENANT} AND space_id = {_SPACE} AND project_id = {_PROJECT}"
    actor_scope = f"{scope} AND created_by = {_ACTOR}"
    for table in (
        "saas_preview_executions",
        "saas_preview_commands",
        "saas_preview_sessions",
        "saas_preview_tunnel_registrations",
    ):
        _enable_rls(table)
    _definer_policy("saas_preview_executions")
    _definer_policy("saas_preview_sessions")
    _definer_policy("saas_runner_tunnel_placements")
    for table in (
        "saas_preview_gateway_instances",
        "saas_runner_registrations",
        "saas_runner_certificates",
    ):
        _definer_select_policy(table)
    owner_role = "pg_has_role(current_user, 'saas_preview_owner', 'member')"
    gateway_owner = (
        f"{owner_role} AND id = {_GATEWAY} AND registration_token_hash = {_GATEWAY_TOKEN} "
        "AND status = 'active' AND lease_expires_at > CURRENT_TIMESTAMP"
    )
    op.execute(
        'CREATE POLICY "rls_preview_gateway_instances_preview_owner" '
        "ON public.saas_preview_gateway_instances FOR SELECT TO saas_preview_owner "
        f"USING ({gateway_owner})"
    )
    placement_owner = (
        f"{owner_role} AND gateway_instance_id = {_GATEWAY} AND status = 'active' "
        "AND lease_expires_at > CURRENT_TIMESTAMP AND EXISTS ("
        "SELECT 1 FROM public.saas_preview_gateway_instances AS gateway "
        "WHERE gateway.id = saas_runner_tunnel_placements.gateway_instance_id)"
    )
    op.execute(
        'CREATE POLICY "rls_runner_tunnel_placements_preview_owner" '
        "ON public.saas_runner_tunnel_placements FOR SELECT TO saas_preview_owner "
        f"USING ({placement_owner})"
    )
    runner_owner = (
        f"{owner_role} AND status IN ('online', 'draining') AND EXISTS ("
        "SELECT 1 FROM public.saas_runner_tunnel_placements AS placement "
        "WHERE placement.runner_id = saas_runner_registrations.id "
        "AND placement.runner_connection_generation = "
        "saas_runner_registrations.connection_generation "
        f"AND placement.gateway_instance_id = {_GATEWAY})"
    )
    op.execute(
        'CREATE POLICY "rls_runner_registrations_preview_owner" '
        "ON public.saas_runner_registrations FOR SELECT TO saas_preview_owner "
        f"USING ({runner_owner})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_execution_app_select" '
        "ON public.saas_preview_executions "
        f"FOR SELECT TO saas_app USING ({actor_scope})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_execution_app_insert" '
        "ON public.saas_preview_executions "
        f"FOR INSERT TO saas_app WITH CHECK ({actor_scope} AND status = 'queued' "
        "AND command_generation = 0 AND runner_id IS NULL AND placement_id IS NULL "
        "AND worktree_id IS NULL AND run_fence_token IS NULL "
        "AND runner_connection_generation IS NULL "
        "AND worktree_lease_generation IS NULL AND exchange_token_hash IS NULL "
        "AND exchange_issued_at IS NULL AND exchange_consumed_at IS NULL "
        "AND ready_at IS NULL AND terminal_at IS NULL AND failure_code IS NULL "
        "AND version = 1)"
    )
    op.execute(
        'CREATE POLICY "rls_preview_execution_executor" ON public.saas_preview_executions '
        f"FOR SELECT TO saas_executor USING ({scope})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_execution_executor_update" '
        "ON public.saas_preview_executions FOR UPDATE TO saas_executor "
        f"USING ({scope}) WITH CHECK ({scope})"
    )
    owner_match = (
        "public.saas_preview_owner_route_match_v1("
        "runner_id, placement_id, runner_connection_generation, "
        f"{_GATEWAY}, {_GATEWAY_TOKEN}, CURRENT_TIMESTAMP)"
    )
    op.execute(
        'CREATE POLICY "rls_preview_execution_owner" ON public.saas_preview_executions '
        f"FOR SELECT TO saas_preview_owner USING ({owner_match})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_execution_owner_update" '
        "ON public.saas_preview_executions FOR UPDATE TO saas_preview_owner "
        f"USING ({owner_match}) WITH CHECK ({owner_match})"
    )
    command_actor = (
        f"{scope} AND EXISTS (SELECT 1 FROM public.saas_preview_executions AS execution "
        "WHERE execution.id = saas_preview_commands.preview_execution_id "
        f"AND execution.created_by = {_ACTOR})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_command_app_select" ON public.saas_preview_commands '
        f"FOR SELECT TO saas_app USING ({command_actor})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_command_executor" ON public.saas_preview_commands '
        f"FOR ALL TO saas_executor USING ({scope}) WITH CHECK ({scope})"
    )
    command_owner = (
        "public.saas_preview_owner_route_match_v1("
        "runner_id, placement_id, runner_connection_generation, "
        f"{_GATEWAY}, {_GATEWAY_TOKEN}, CURRENT_TIMESTAMP)"
    )
    op.execute(
        'CREATE POLICY "rls_preview_command_owner" ON public.saas_preview_commands '
        f"FOR ALL TO saas_preview_owner USING ({command_owner}) WITH CHECK ({command_owner})"
    )
    registration_owner = f"token_hash = {_REGISTRATION_HASH} AND gateway_instance_id = {_GATEWAY}"
    op.execute(
        'CREATE POLICY "rls_preview_registration_owner" '
        "ON public.saas_preview_tunnel_registrations FOR SELECT TO saas_preview_owner "
        f"USING ({registration_owner})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_registration_owner_update" '
        "ON public.saas_preview_tunnel_registrations FOR UPDATE TO saas_preview_owner "
        f"USING ({registration_owner}) WITH CHECK ({registration_owner})"
    )


_ROUTE_RESULT = """
    preview_execution_id uuid,
    tenant_id uuid,
    space_id uuid,
    project_id uuid,
    opaque_preview_key text,
    preview_host text,
    runner_id uuid,
    placement_id uuid,
    runner_connection_generation bigint,
    tunnel_placement_id uuid,
    routing_generation bigint,
    gateway_instance_id text,
    relay_subject text,
    tunnel_lease_expires_at timestamptz,
    run_id uuid,
    run_fence_token bigint,
    worktree_id uuid,
    worktree_lease_generation bigint,
    expires_at timestamptz,
    session_id uuid,
    session_generation bigint,
    rotated boolean
"""


def _install_security_definer_functions() -> None:
    """Expose narrow actor and content-blind token CAS operations."""

    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_issue_exchange_v1(
            expected_execution_id uuid,
            presented_exchange_hash text,
            issued_at timestamptz
        ) RETURNS TABLE (
            preview_execution_id uuid,
            preview_host text,
            expires_at timestamptz,
            replayed boolean
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            execution public.saas_preview_executions%ROWTYPE;
            was_replayed boolean;
        BEGIN
            IF expected_execution_id IS NULL
               OR presented_exchange_hash !~ '^[0-9a-f]{64}$'
               OR issued_at IS NULL THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.id = expected_execution_id
              AND candidate.tenant_id =
                  NULLIF(current_setting('app.tenant_id', true), '')::uuid
              AND candidate.space_id =
                  NULLIF(current_setting('app.space_id', true), '')::uuid
              AND candidate.project_id =
                  NULLIF(current_setting('app.project_id', true), '')::uuid
              AND candidate.created_by =
                  NULLIF(current_setting('app.actor_id', true), '')::uuid
            FOR UPDATE;
            IF NOT FOUND
               OR execution.status <> 'ready'
               OR execution.expires_at <= issued_at
               OR execution.exchange_consumed_at IS NOT NULL
               OR (
                    execution.exchange_token_hash IS NOT NULL
                    AND execution.exchange_token_hash <> presented_exchange_hash
               ) THEN
                RETURN;
            END IF;
            was_replayed := execution.exchange_token_hash IS NOT NULL;
            IF NOT was_replayed THEN
                UPDATE public.saas_preview_executions AS issued
                SET exchange_token_hash = presented_exchange_hash,
                    exchange_issued_at = issued_at,
                    updated_at = issued_at,
                    version = issued.version + 1
                WHERE issued.id = execution.id;
            END IF;
            RETURN QUERY SELECT execution.id, execution.preview_host::text,
                execution.expires_at, was_replayed;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_create_command_v1(
            expected_execution_id uuid,
            new_command_id uuid,
            requested_command_type text,
            expected_request_hash text,
            operation_at timestamptz
        ) RETURNS TABLE (
            preview_execution_id uuid,
            command_id uuid,
            command_generation bigint,
            command_type text,
            replayed boolean
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            execution public.saas_preview_executions%ROWTYPE;
            existing_command public.saas_preview_commands%ROWTYPE;
            next_generation bigint;
        BEGIN
            IF expected_execution_id IS NULL OR new_command_id IS NULL
               OR requested_command_type NOT IN ('start', 'stop')
               OR expected_request_hash !~ '^[0-9a-f]{64}$'
               OR operation_at IS NULL THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.id = expected_execution_id
              AND candidate.tenant_id =
                  NULLIF(current_setting('app.tenant_id', true), '')::uuid
              AND candidate.space_id =
                  NULLIF(current_setting('app.space_id', true), '')::uuid
              AND candidate.project_id =
                  NULLIF(current_setting('app.project_id', true), '')::uuid
              AND candidate.created_by =
                  NULLIF(current_setting('app.actor_id', true), '')::uuid
            FOR UPDATE;
            IF NOT FOUND THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO existing_command
            FROM public.saas_preview_commands AS candidate
            WHERE candidate.preview_execution_id = execution.id
              AND candidate.command_type = requested_command_type
              AND candidate.request_hash = expected_request_hash
            ORDER BY candidate.generation DESC
            LIMIT 1;
            IF FOUND THEN
                RETURN QUERY SELECT execution.id, existing_command.id,
                    existing_command.generation, existing_command.command_type::text, true;
                RETURN;
            END IF;
            IF requested_command_type = 'start' THEN
                IF execution.status <> 'queued' OR execution.command_generation <> 0 THEN
                    RETURN;
                END IF;
                next_generation := 1;
            ELSE
                IF execution.status NOT IN ('queued', 'materializing', 'starting', 'ready')
                   OR execution.expires_at <= operation_at THEN
                    RETURN;
                END IF;
                next_generation := execution.command_generation + 1;
                UPDATE public.saas_preview_sessions AS browser_session
                SET status = 'revoked', revoked_at = operation_at,
                    updated_at = operation_at
                WHERE browser_session.preview_execution_id = execution.id
                  AND browser_session.status = 'active';
            END IF;
            INSERT INTO public.saas_preview_commands (
                id, tenant_id, space_id, project_id, preview_execution_id,
                command_type, generation, request_hash, status, attempt_count,
                available_at, created_at, updated_at
            ) VALUES (
                new_command_id, execution.tenant_id, execution.space_id,
                execution.project_id, execution.id, requested_command_type,
                next_generation, expected_request_hash, 'pending', 0,
                operation_at, operation_at, operation_at
            ) RETURNING * INTO existing_command;
            UPDATE public.saas_preview_executions AS mutated
            SET command_generation = next_generation,
                status = CASE WHEN requested_command_type = 'stop'
                              THEN 'stopping' ELSE mutated.status END,
                updated_at = operation_at,
                version = mutated.version + 1
            WHERE mutated.id = execution.id;
            RETURN QUERY SELECT execution.id, existing_command.id,
                existing_command.generation, existing_command.command_type::text, false;
        END
        $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION public.saas_preview_exchange_v1(
            presented_exchange_hash text,
            new_session_id uuid,
            new_session_hash text,
            requested_session_expires_at timestamptz,
            exchanged_at timestamptz
        ) RETURNS TABLE ({_ROUTE_RESULT})
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            execution public.saas_preview_executions%ROWTYPE;
            created_session public.saas_preview_sessions%ROWTYPE;
            route public.saas_runner_tunnel_placements%ROWTYPE;
            bounded_expiry timestamptz;
        BEGIN
            IF presented_exchange_hash !~ '^[0-9a-f]{{64}}$'
               OR new_session_hash !~ '^[0-9a-f]{{64}}$'
               OR new_session_id IS NULL
               OR exchanged_at IS NULL
               OR requested_session_expires_at IS NULL
               OR requested_session_expires_at <= exchanged_at THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.exchange_token_hash = presented_exchange_hash
            FOR UPDATE;
            IF NOT FOUND
               OR execution.status <> 'ready'
               OR execution.exchange_consumed_at IS NOT NULL
               OR execution.expires_at <= exchanged_at
               OR execution.runner_id IS NULL
               OR execution.placement_id IS NULL
               OR execution.worktree_id IS NULL THEN
                RETURN;
            END IF;
            SELECT placement.* INTO route
            FROM public.saas_runner_tunnel_placements AS placement
            JOIN public.saas_runner_registrations AS runner
              ON runner.id = placement.runner_id
            JOIN public.saas_preview_gateway_instances AS gateway
              ON gateway.id = placement.gateway_instance_id
            WHERE runner.id = execution.runner_id
              AND runner.placement_id = execution.placement_id
              AND runner.connection_generation = execution.runner_connection_generation
              AND runner.status IN ('online', 'draining')
              AND placement.runner_connection_generation =
                  execution.runner_connection_generation
              AND placement.status = 'active'
              AND placement.lease_expires_at > exchanged_at
              AND gateway.status = 'active'
              AND gateway.lease_expires_at > exchanged_at;
            IF NOT FOUND THEN
                RETURN;
            END IF;
            bounded_expiry := LEAST(requested_session_expires_at, execution.expires_at);
            IF bounded_expiry <= exchanged_at OR EXISTS (
                SELECT 1 FROM public.saas_preview_sessions AS active_session
                WHERE active_session.preview_execution_id = execution.id
                  AND active_session.status = 'active'
            ) THEN
                RETURN;
            END IF;
            INSERT INTO public.saas_preview_sessions (
                id, tenant_id, space_id, project_id, preview_execution_id,
                token_hash, generation, status, expires_at, last_authenticated_at,
                rotated_at, revoked_at, created_at, updated_at
            ) VALUES (
                new_session_id, execution.tenant_id, execution.space_id,
                execution.project_id, execution.id, new_session_hash, 1, 'active',
                bounded_expiry, exchanged_at, exchanged_at, NULL, exchanged_at, exchanged_at
            ) RETURNING * INTO created_session;
            UPDATE public.saas_preview_executions AS consumed
            SET exchange_consumed_at = exchanged_at,
                updated_at = exchanged_at,
                version = consumed.version + 1
            WHERE consumed.id = execution.id;
            RETURN QUERY SELECT
                execution.id, execution.tenant_id, execution.space_id,
                execution.project_id, execution.opaque_preview_key::text,
                execution.preview_host::text, execution.runner_id,
                execution.placement_id, execution.runner_connection_generation,
                route.id, route.routing_generation, route.gateway_instance_id::text,
                route.relay_subject::text, route.lease_expires_at,
                execution.child_run_id, execution.run_fence_token,
                execution.worktree_id, execution.worktree_lease_generation,
                bounded_expiry, created_session.id, created_session.generation, false;
        END
        $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION public.saas_preview_authorize_session_v1(
            presented_session_hash text,
            requested_host text,
            authenticated_at timestamptz
        ) RETURNS TABLE ({_ROUTE_RESULT})
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            browser_session public.saas_preview_sessions%ROWTYPE;
            execution public.saas_preview_executions%ROWTYPE;
            route public.saas_runner_tunnel_placements%ROWTYPE;
        BEGIN
            IF presented_session_hash !~ '^[0-9a-f]{{64}}$'
               OR requested_host IS NULL OR authenticated_at IS NULL THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO browser_session
            FROM public.saas_preview_sessions AS candidate
            WHERE candidate.token_hash = presented_session_hash
               OR (candidate.previous_token_hash = presented_session_hash
                   AND candidate.previous_valid_until > authenticated_at)
            FOR UPDATE;
            IF NOT FOUND OR browser_session.status <> 'active'
               OR browser_session.expires_at <= authenticated_at THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.id = browser_session.preview_execution_id;
            IF NOT FOUND OR execution.status <> 'ready'
               OR execution.expires_at <= authenticated_at
               OR execution.preview_host <> lower(requested_host)
               OR execution.runner_id IS NULL OR execution.placement_id IS NULL
               OR execution.worktree_id IS NULL THEN
                RETURN;
            END IF;
            SELECT placement.* INTO route
            FROM public.saas_runner_tunnel_placements AS placement
            JOIN public.saas_runner_registrations AS runner
              ON runner.id = placement.runner_id
            JOIN public.saas_preview_gateway_instances AS gateway
              ON gateway.id = placement.gateway_instance_id
            WHERE runner.id = execution.runner_id
              AND runner.placement_id = execution.placement_id
              AND runner.connection_generation = execution.runner_connection_generation
              AND runner.status IN ('online', 'draining')
              AND placement.runner_connection_generation =
                  execution.runner_connection_generation
              AND placement.status = 'active'
              AND placement.lease_expires_at > authenticated_at
              AND gateway.status = 'active'
              AND gateway.lease_expires_at > authenticated_at;
            IF NOT FOUND THEN
                RETURN;
            END IF;
            UPDATE public.saas_preview_sessions AS authenticated
            SET last_authenticated_at = authenticated_at,
                updated_at = authenticated_at
            WHERE authenticated.id = browser_session.id;
            RETURN QUERY SELECT
                execution.id, execution.tenant_id, execution.space_id,
                execution.project_id, execution.opaque_preview_key::text,
                execution.preview_host::text, execution.runner_id,
                execution.placement_id, execution.runner_connection_generation,
                route.id, route.routing_generation, route.gateway_instance_id::text,
                route.relay_subject::text, route.lease_expires_at,
                execution.child_run_id, execution.run_fence_token,
                execution.worktree_id, execution.worktree_lease_generation,
                LEAST(browser_session.expires_at, execution.expires_at),
                browser_session.id, browser_session.generation, false;
        END
        $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION public.saas_preview_rotate_session_v1(
            presented_session_hash text,
            new_session_hash text,
            requested_host text,
            requested_session_expires_at timestamptz,
            operation_at timestamptz
        ) RETURNS TABLE ({_ROUTE_RESULT})
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            browser_session public.saas_preview_sessions%ROWTYPE;
            execution public.saas_preview_executions%ROWTYPE;
            route public.saas_runner_tunnel_placements%ROWTYPE;
            bounded_expiry timestamptz;
            did_rotate boolean := false;
        BEGIN
            IF presented_session_hash !~ '^[0-9a-f]{{64}}$'
               OR new_session_hash !~ '^[0-9a-f]{{64}}$'
               OR new_session_hash = presented_session_hash
               OR requested_host IS NULL OR operation_at IS NULL
               OR requested_session_expires_at IS NULL
               OR requested_session_expires_at <= operation_at THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO browser_session
            FROM public.saas_preview_sessions AS candidate
            WHERE candidate.token_hash = presented_session_hash
               OR (candidate.previous_token_hash = presented_session_hash
                   AND candidate.previous_valid_until > operation_at)
            FOR UPDATE;
            IF NOT FOUND OR browser_session.status <> 'active'
               OR browser_session.expires_at <= operation_at THEN
                RETURN;
            END IF;
            SELECT candidate.* INTO execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.id = browser_session.preview_execution_id;
            IF NOT FOUND OR execution.status <> 'ready'
               OR execution.expires_at <= operation_at
               OR execution.preview_host <> lower(requested_host) THEN
                RETURN;
            END IF;
            SELECT placement.* INTO route
            FROM public.saas_runner_tunnel_placements AS placement
            JOIN public.saas_runner_registrations AS runner
              ON runner.id = placement.runner_id
            JOIN public.saas_preview_gateway_instances AS gateway
              ON gateway.id = placement.gateway_instance_id
            WHERE runner.id = execution.runner_id
              AND runner.placement_id = execution.placement_id
              AND runner.connection_generation = execution.runner_connection_generation
              AND runner.status IN ('online', 'draining')
              AND placement.runner_connection_generation =
                  execution.runner_connection_generation
              AND placement.status = 'active'
              AND placement.lease_expires_at > operation_at
              AND gateway.status = 'active'
              AND gateway.lease_expires_at > operation_at;
            IF NOT FOUND THEN
                RETURN;
            END IF;
            bounded_expiry := LEAST(
                requested_session_expires_at,
                execution.expires_at,
                browser_session.expires_at
            );
            IF EXISTS (
                SELECT 1 FROM public.saas_preview_sessions AS collision
                WHERE collision.id <> browser_session.id
                  AND (collision.token_hash = new_session_hash
                       OR collision.previous_token_hash = new_session_hash)
            ) THEN
                RETURN;
            END IF;
            IF browser_session.token_hash = presented_session_hash
               AND browser_session.rotated_at <= operation_at - INTERVAL '5 minutes' THEN
                UPDATE public.saas_preview_sessions AS rotated
                SET previous_token_hash = rotated.token_hash,
                    previous_valid_until = LEAST(
                        bounded_expiry, operation_at + INTERVAL '30 seconds'
                    ),
                    token_hash = new_session_hash,
                    generation = rotated.generation + 1,
                    expires_at = bounded_expiry,
                    last_authenticated_at = operation_at,
                    rotated_at = operation_at,
                    updated_at = operation_at
                WHERE rotated.id = browser_session.id
                RETURNING * INTO browser_session;
                did_rotate := true;
            ELSE
                UPDATE public.saas_preview_sessions AS authenticated
                SET last_authenticated_at = operation_at,
                    updated_at = operation_at
                WHERE authenticated.id = browser_session.id;
            END IF;
            RETURN QUERY SELECT
                execution.id, execution.tenant_id, execution.space_id,
                execution.project_id, execution.opaque_preview_key::text,
                execution.preview_host::text, execution.runner_id,
                execution.placement_id, execution.runner_connection_generation,
                route.id, route.routing_generation, route.gateway_instance_id::text,
                route.relay_subject::text, route.lease_expires_at,
                execution.child_run_id, execution.run_fence_token,
                execution.worktree_id, execution.worktree_lease_generation,
                bounded_expiry, browser_session.id, browser_session.generation,
                did_rotate;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_preview_revoke_session_v1(
            presented_session_hash text,
            operation_at timestamptz
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            revoked_count integer;
        BEGIN
            IF presented_session_hash !~ '^[0-9a-f]{64}$' OR operation_at IS NULL THEN
                RETURN false;
            END IF;
            UPDATE public.saas_preview_sessions AS session
            SET status = 'revoked', revoked_at = operation_at, updated_at = operation_at
            WHERE (session.token_hash = presented_session_hash
                   OR (session.previous_token_hash = presented_session_hash
                       AND session.previous_valid_until > operation_at))
              AND session.status = 'active'
              AND session.expires_at > operation_at;
            GET DIAGNOSTICS revoked_count = ROW_COUNT;
            RETURN revoked_count = 1;
        END
        $function$
        """
    )
    for function in (
        "saas_preview_issue_tunnel_registration_v1(uuid,bigint,text,text,uuid,text,text,text,integer)",
        "saas_preview_revoke_tunnel_registration_v1(uuid,bigint,text,text,uuid,text)",
        "saas_preview_preauthorize_tunnel_v1(text,text,text,text,timestamptz)",
        "saas_preview_redeem_tunnel_v1(text,text,text,text,uuid,text,timestamptz)",
        "saas_preview_heartbeat_tunnel_v1(text,text,text,text,timestamptz)",
        "saas_preview_disconnect_tunnel_v1(text,text,text,text,timestamptz)",
        "saas_preview_issue_exchange_v1(uuid,text,timestamptz)",
        "saas_preview_create_command_v1(uuid,uuid,text,text,timestamptz)",
        "saas_preview_exchange_v1(text,uuid,text,timestamptz,timestamptz)",
        "saas_preview_authorize_session_v1(text,text,timestamptz)",
        "saas_preview_rotate_session_v1(text,text,text,timestamptz,timestamptz)",
        "saas_preview_revoke_session_v1(text,timestamptz)",
        "saas_preview_owner_heartbeat_gateway_v1(text,text)",
        "saas_preview_owner_release_gateway_v1(text,text)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION public.{function} FROM PUBLIC")
        if function.startswith(
            (
                "saas_preview_issue_tunnel_registration_v1",
                "saas_preview_revoke_tunnel_registration_v1",
            )
        ):
            target_role = "saas_executor"
        elif "_tunnel_v1" in function or "_owner_" in function:
            target_role = "saas_preview_owner"
        elif function.startswith(("saas_preview_issue_", "saas_preview_create_")):
            target_role = "saas_app"
        else:
            target_role = "saas_preview_edge"
        op.execute(f"GRANT EXECUTE ON FUNCTION public.{function} TO {target_role}")
    # The standalone Owner is the final relay receiver.  It uses the same
    # content-blind session CAS as Edge to reconstruct and compare the complete
    # Preview grant before touching its process-local Runner tunnel.
    op.execute(
        "GRANT EXECUTE ON FUNCTION "
        "public.saas_preview_authorize_session_v1(text,text,timestamptz) "
        "TO saas_preview_owner"
    )


def upgrade() -> None:
    _lock_and_require_legacy_drain()
    _create_execution_table()
    _create_command_table()
    _create_session_table()
    _create_registration_table()
    _harden_placement_trigger_search_path()
    _install_owner_route_predicate()
    _install_postgresql_rls()
    _install_security_definer_functions()


def _require_downgrade_drain() -> None:
    bind = op.get_bind()
    tables = (
        "saas_preview_sessions",
        "saas_preview_commands",
        "saas_preview_executions",
        "saas_preview_tunnel_registrations",
    )
    if bind.dialect.name == "postgresql":
        op.execute(
            "LOCK TABLE "
            + ", ".join(f"public.{table}" for table in tables)
            + " IN ACCESS EXCLUSIVE MODE"
        )
        for table in tables:
            op.execute(f"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY")
    else:
        bind.exec_driver_sql(
            "UPDATE saas_preview_executions SET updated_at = updated_at WHERE 1 = 0"
        )
    occupied = any(
        bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() is not None
        for table in tables
    )
    if occupied:
        if bind.dialect.name == "postgresql":
            for table in tables:
                op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        raise RuntimeError(_DOWNGRADE_DRAIN)


def downgrade() -> None:
    _require_downgrade_drain()
    if op.get_bind().dialect.name == "postgresql":
        for function in (
            "saas_preview_issue_tunnel_registration_v1(uuid,bigint,text,text,uuid,text,text,text,integer)",
            "saas_preview_revoke_tunnel_registration_v1(uuid,bigint,text,text,uuid,text)",
            "saas_preview_preauthorize_tunnel_v1(text,text,text,text,timestamptz)",
            "saas_preview_redeem_tunnel_v1(text,text,text,text,uuid,text,timestamptz)",
            "saas_preview_heartbeat_tunnel_v1(text,text,text,text,timestamptz)",
            "saas_preview_disconnect_tunnel_v1(text,text,text,text,timestamptz)",
            "saas_preview_issue_exchange_v1(uuid,text,timestamptz)",
            "saas_preview_create_command_v1(uuid,uuid,text,text,timestamptz)",
            "saas_preview_exchange_v1(text,uuid,text,timestamptz,timestamptz)",
            "saas_preview_authorize_session_v1(text,text,timestamptz)",
            "saas_preview_rotate_session_v1(text,text,text,timestamptz,timestamptz)",
            "saas_preview_revoke_session_v1(text,timestamptz)",
            "saas_preview_owner_heartbeat_gateway_v1(text,text)",
            "saas_preview_owner_release_gateway_v1(text,text)",
        ):
            op.execute(f"DROP FUNCTION public.{function}")
        op.execute(
            'DROP POLICY "rls_runner_registrations_preview_owner" '
            "ON public.saas_runner_registrations"
        )
        op.execute(
            'DROP POLICY "rls_runner_tunnel_placements_preview_owner" '
            "ON public.saas_runner_tunnel_placements"
        )
        op.execute(
            'DROP POLICY "rls_preview_gateway_instances_preview_owner" '
            "ON public.saas_preview_gateway_instances"
        )
        for table in (
            "saas_preview_gateway_instances",
            "saas_runner_registrations",
            "saas_runner_certificates",
        ):
            op.execute(f'DROP POLICY "rls_{table}_preview_definer" ON public."{table}"')
        op.execute(
            'DROP POLICY "rls_saas_runner_tunnel_placements_definer" '
            'ON public."saas_runner_tunnel_placements"'
        )
    op.drop_index(
        "ix_preview_tunnel_registration_expiry",
        table_name="saas_preview_tunnel_registrations",
    )
    op.drop_index(
        "uq_preview_tunnel_registration_active_incarnation",
        table_name="saas_preview_tunnel_registrations",
    )
    op.drop_table("saas_preview_tunnel_registrations")
    op.drop_index("ix_preview_session_expiry", table_name="saas_preview_sessions")
    op.drop_index("uq_preview_session_active_execution", table_name="saas_preview_sessions")
    op.drop_table("saas_preview_sessions")
    op.drop_index("ix_preview_command_claim", table_name="saas_preview_commands")
    op.drop_table("saas_preview_commands")
    op.drop_index("ix_preview_execution_status_expiry", table_name="saas_preview_executions")
    op.drop_index(
        "uq_preview_execution_active_source_profile",
        table_name="saas_preview_executions",
    )
    op.drop_table("saas_preview_executions")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP FUNCTION public.saas_preview_owner_route_match_v1("
            "uuid,uuid,bigint,text,text,timestamptz)"
        )
        op.execute(
            """
            CREATE OR REPLACE FUNCTION public.saas_require_live_preview_gateway_placement()
            RETURNS trigger LANGUAGE plpgsql AS $function$
            BEGIN
                IF NEW.status IN ('active', 'draining') AND NOT EXISTS (
                    SELECT 1 FROM saas_preview_gateway_instances gateway
                    WHERE gateway.id = NEW.gateway_instance_id
                      AND gateway.status IN ('active', 'draining')
                      AND gateway.lease_expires_at > CURRENT_TIMESTAMP
                ) THEN
                    RAISE EXCEPTION
                        'Runner tunnel Placement requires a live Preview Gateway';
                END IF;
                RETURN NEW;
            END
            $function$
            """
        )
