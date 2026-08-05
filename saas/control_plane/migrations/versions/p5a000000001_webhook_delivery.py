"""Create durable signed Webhook delivery and SSRF-safe endpoint authority.

Revision ID: p5a000000001
Revises: p4g000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p5a000000001"
down_revision: str | None = "p4g000000001"
branch_labels: str | None = None
depends_on: str | None = None


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _create_guard_functions() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION saas_guard_webhook_endpoint()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(NEW.id, NEW.tenant_id, NEW.space_id, NEW.project_id,
                   NEW.secret_ref, NEW.created_by, NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.tenant_id, OLD.space_id, OLD.project_id,
                   OLD.secret_ref, OLD.created_by, OLD.created_at) THEN
                RAISE EXCEPTION 'Webhook endpoint ownership fields are immutable';
            END IF;
            IF OLD.status = 'deleted' AND NEW.status <> 'deleted' THEN
                RAISE EXCEPTION 'Deleted Webhook endpoint is terminal';
            END IF;
            IF NEW.security_version < OLD.security_version THEN
                RAISE EXCEPTION 'Webhook endpoint security version is monotonic';
            END IF;
            IF (ROW(NEW.canonical_url, NEW.active_secret_version,
                   NEW.previous_secret_version, NEW.previous_secret_valid_until,
                   NEW.status)
               IS DISTINCT FROM
               ROW(OLD.canonical_url, OLD.active_secret_version,
                   OLD.previous_secret_version, OLD.previous_secret_valid_until,
                   OLD.status)
               OR NEW.event_types::jsonb IS DISTINCT FROM OLD.event_types::jsonb)
               AND NEW.security_version <= OLD.security_version THEN
                RAISE EXCEPTION 'Webhook endpoint change requires a new security version';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION saas_guard_webhook_delivery()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(NEW.id, NEW.tenant_id, NEW.endpoint_id, NEW.event_id,
                   NEW.event_type, NEW.event_version, NEW.occurred_at,
                   NEW.payload_sha256, NEW.max_attempts, NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.tenant_id, OLD.endpoint_id, OLD.event_id,
                   OLD.event_type, OLD.event_version, OLD.occurred_at,
                   OLD.payload_sha256, OLD.max_attempts, OLD.created_at)
               OR NEW.payload::jsonb IS DISTINCT FROM OLD.payload::jsonb THEN
                RAISE EXCEPTION 'Webhook delivery fact is immutable';
            END IF;
            IF NEW.attempt_count < OLD.attempt_count AND NOT (
                OLD.status = 'dead_letter' AND NEW.status = 'retry'
                AND NEW.attempt_count = 0
                AND NEW.replay_generation = OLD.replay_generation + 1
                AND NEW.last_replayed_at IS NOT NULL
                AND NEW.last_replayed_by IS NOT NULL
                AND (OLD.last_replayed_at IS NULL
                     OR NEW.last_replayed_at >= OLD.last_replayed_at)
                AND NEW.leased_at IS NULL AND NEW.lease_expires_at IS NULL
                AND NEW.lease_token_hash IS NULL AND NEW.delivered_at IS NULL
                AND NEW.response_status IS NULL AND NEW.response_digest_sha256 IS NULL
                AND NEW.last_error_code IS NULL
            ) THEN
                RAISE EXCEPTION 'Webhook delivery attempts are monotonic';
            END IF;
            IF OLD.status = 'delivered' AND ROW(
                NEW.status, NEW.attempt_count, NEW.available_at, NEW.leased_at,
                NEW.lease_expires_at, NEW.lease_token_hash, NEW.delivered_at,
                NEW.response_status, NEW.response_digest_sha256,
                NEW.last_error_code, NEW.replay_generation,
                NEW.last_replayed_at, NEW.last_replayed_by
            ) IS DISTINCT FROM ROW(
                OLD.status, OLD.attempt_count, OLD.available_at, OLD.leased_at,
                OLD.lease_expires_at, OLD.lease_token_hash, OLD.delivered_at,
                OLD.response_status, OLD.response_digest_sha256,
                OLD.last_error_code, OLD.replay_generation,
                OLD.last_replayed_at, OLD.last_replayed_by
            ) THEN
                RAISE EXCEPTION 'Delivered Webhook fact is terminal';
            END IF;
            IF OLD.status = 'dead_letter' AND NEW.status = 'dead_letter' AND ROW(
                NEW.attempt_count, NEW.available_at, NEW.leased_at,
                NEW.lease_expires_at, NEW.lease_token_hash,
                NEW.response_status, NEW.response_digest_sha256,
                NEW.last_error_code, NEW.replay_generation,
                NEW.last_replayed_at, NEW.last_replayed_by
            ) IS DISTINCT FROM ROW(
                OLD.attempt_count, OLD.available_at, OLD.leased_at,
                OLD.lease_expires_at, OLD.lease_token_hash,
                OLD.response_status, OLD.response_digest_sha256,
                OLD.last_error_code, OLD.replay_generation,
                OLD.last_replayed_at, OLD.last_replayed_by
            ) THEN
                RAISE EXCEPTION 'Dead-letter Webhook fact requires explicit replay';
            END IF;
            IF OLD.status <> 'dead_letter' AND ROW(
                NEW.replay_generation, NEW.last_replayed_at, NEW.last_replayed_by
            ) IS DISTINCT FROM ROW(
                OLD.replay_generation, OLD.last_replayed_at, OLD.last_replayed_by
            ) THEN
                RAISE EXCEPTION 'Webhook replay authority is invalid';
            END IF;
            IF NEW.status = 'leased' AND OLD.status IN ('pending', 'retry', 'leased')
               AND NEW.attempt_count <> OLD.attempt_count + 1 THEN
                RAISE EXCEPTION 'Webhook lease must consume exactly one attempt';
            END IF;
            IF OLD.status = 'leased' AND NEW.status = 'leased'
               AND NEW.leased_at < OLD.lease_expires_at THEN
                RAISE EXCEPTION 'Webhook lease cannot be reclaimed before expiry';
            END IF;
            IF OLD.status = 'leased' AND NEW.status IN
                ('retry', 'delivered', 'dead_letter')
               AND NEW.attempt_count <> OLD.attempt_count THEN
                RAISE EXCEPTION 'Webhook delivery result cannot rewrite attempts';
            END IF;
            IF NOT (
                (OLD.status IN ('pending', 'retry') AND NEW.status = 'leased') OR
                (OLD.status = 'leased' AND NEW.status IN
                    ('leased', 'retry', 'delivered', 'dead_letter')) OR
                (OLD.status = 'dead_letter' AND NEW.status = 'retry'
                    AND NEW.replay_generation = OLD.replay_generation + 1
                    AND NEW.attempt_count = 0
                    AND NEW.last_replayed_at IS NOT NULL
                    AND NEW.last_replayed_by IS NOT NULL
                    AND (OLD.last_replayed_at IS NULL
                         OR NEW.last_replayed_at >= OLD.last_replayed_at)
                    AND NEW.leased_at IS NULL AND NEW.lease_expires_at IS NULL
                    AND NEW.lease_token_hash IS NULL AND NEW.delivered_at IS NULL
                    AND NEW.response_status IS NULL
                    AND NEW.response_digest_sha256 IS NULL
                    AND NEW.last_error_code IS NULL) OR
                (OLD.status = NEW.status AND OLD.status IN
                    ('pending', 'retry', 'delivered', 'dead_letter'))
            ) THEN
                RAISE EXCEPTION 'Webhook delivery transition is invalid';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER trg_webhook_endpoint_guard BEFORE UPDATE ON "
        "saas_webhook_endpoints FOR EACH ROW EXECUTE FUNCTION saas_guard_webhook_endpoint()"
    )
    op.execute(
        "CREATE TRIGGER trg_webhook_delivery_guard BEFORE UPDATE ON "
        "saas_webhook_deliveries FOR EACH ROW EXECUTE FUNCTION saas_guard_webhook_delivery()"
    )


def _enable_rls() -> None:
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    app_scope = f"tenant_id = {tenant}"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    dispatcher = f"(pg_has_role(current_user, 'saas_webhook_dispatcher', 'member') OR {platform})"
    for table in ("saas_webhook_endpoints", "saas_webhook_deliveries"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY rls_webhook_endpoint_select ON saas_webhook_endpoints "
        f"FOR SELECT USING ({dispatcher} OR {app_scope})"
    )
    op.execute(
        "CREATE POLICY rls_webhook_endpoint_insert ON saas_webhook_endpoints "
        f"FOR INSERT WITH CHECK ({platform} OR {app_scope})"
    )
    op.execute(
        "CREATE POLICY rls_webhook_endpoint_update ON saas_webhook_endpoints "
        f"FOR UPDATE USING ({platform} OR {app_scope}) "
        f"WITH CHECK ({platform} OR {app_scope})"
    )
    op.execute(
        "CREATE POLICY rls_webhook_delivery_select ON saas_webhook_deliveries "
        f"FOR SELECT USING ({dispatcher} OR {app_scope})"
    )
    op.execute(
        "CREATE POLICY rls_webhook_delivery_insert ON saas_webhook_deliveries "
        f"FOR INSERT WITH CHECK ({platform} OR {app_scope})"
    )
    op.execute(
        "CREATE POLICY rls_webhook_delivery_update ON saas_webhook_deliveries "
        f"FOR UPDATE USING ({dispatcher}) WITH CHECK ({dispatcher})"
    )
    op.execute("DROP POLICY rls_outbox_insert ON saas_control_plane_outbox")
    op.execute(
        "CREATE POLICY rls_outbox_insert ON saas_control_plane_outbox FOR INSERT "
        "WITH CHECK ("
        "pg_has_role(current_user, 'saas_dispatcher', 'member') OR "
        "pg_has_role(current_user, 'saas_webhook_dispatcher', 'member') OR "
        f"{platform} OR tenant_id = {tenant} OR "
        "((pg_has_role(current_user, 'saas_authenticator', 'member') OR "
        "pg_has_role(current_user, 'saas_governance', 'member')) AND tenant_id IS NULL))"
    )


def upgrade() -> None:
    op.create_table(
        "saas_webhook_endpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=True),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("canonical_url", sa.String(length=2048), nullable=False),
        sa.Column("event_types", sa.JSON(), nullable=False),
        sa.Column("secret_ref", sa.String(length=256), nullable=False),
        sa.Column("active_secret_version", sa.Integer(), nullable=False),
        sa.Column("previous_secret_version", sa.Integer(), nullable=True),
        sa.Column("previous_secret_valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('active', 'disabled', 'deleted')", name="ck_webhook_endpoint_status"
        ),
        sa.CheckConstraint(
            "project_id IS NULL OR space_id IS NOT NULL", name="ck_webhook_endpoint_project_scope"
        ),
        sa.CheckConstraint(
            "length(canonical_url) BETWEEN 1 AND 2048", name="ck_webhook_endpoint_url"
        ),
        sa.CheckConstraint(
            "length(secret_ref) BETWEEN 1 AND 256", name="ck_webhook_endpoint_secret_ref"
        ),
        sa.CheckConstraint(
            "active_secret_version > 0 AND security_version > 0",
            name="ck_webhook_endpoint_versions",
        ),
        sa.CheckConstraint(
            "(previous_secret_version IS NULL AND previous_secret_valid_until IS NULL) OR "
            "(previous_secret_version IS NOT NULL AND previous_secret_version > 0 "
            "AND previous_secret_version <> active_secret_version "
            "AND previous_secret_valid_until IS NOT NULL)",
            name="ck_webhook_endpoint_rotation",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["saas_tenants.id"],
            name="fk_webhook_endpoint_tenant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id"],
            ["saas_spaces.tenant_id", "saas_spaces.id"],
            name="fk_webhook_endpoint_space",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id"],
            ["saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"],
            name="fk_webhook_endpoint_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["saas_global_users.id"],
            name="fk_webhook_endpoint_creator",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_webhook_endpoint_tenant_id"),
    )
    op.create_index(
        "uq_active_webhook_endpoint_url",
        "saas_webhook_endpoints",
        ["tenant_id", "canonical_url"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
        sqlite_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_webhook_endpoint_scope",
        "saas_webhook_endpoints",
        ["tenant_id", "space_id", "project_id"],
        unique=False,
    )
    op.create_table(
        "saas_webhook_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("event_version", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leased_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("response_digest_sha256", sa.String(length=64), nullable=True),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column("replay_generation", sa.Integer(), nullable=False),
        sa.Column("last_replayed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_replayed_by", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'leased', 'retry', 'delivered', 'dead_letter')",
            name="ck_webhook_delivery_status",
        ),
        sa.CheckConstraint(
            "length(event_type) BETWEEN 1 AND 128 AND event_version > 0",
            name="ck_webhook_delivery_event",
        ),
        sa.CheckConstraint("length(payload_sha256) = 64", name="ck_webhook_delivery_payload_hash"),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 32 "
            "AND attempt_count <= max_attempts",
            name="ck_webhook_delivery_attempts",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND leased_at IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND lease_token_hash IS NOT NULL) OR "
            "(status <> 'leased' AND leased_at IS NULL "
            "AND lease_expires_at IS NULL AND lease_token_hash IS NULL)",
            name="ck_webhook_delivery_lease",
        ),
        sa.CheckConstraint(
            "(status = 'delivered' AND delivered_at IS NOT NULL "
            "AND response_status BETWEEN 200 AND 299 "
            "AND response_digest_sha256 IS NOT NULL) OR "
            "(status <> 'delivered' AND delivered_at IS NULL)",
            name="ck_webhook_delivery_result",
        ),
        sa.CheckConstraint(
            "response_digest_sha256 IS NULL OR length(response_digest_sha256) = 64",
            name="ck_webhook_delivery_response_hash",
        ),
        sa.CheckConstraint(
            "lease_token_hash IS NULL OR length(lease_token_hash) = 64",
            name="ck_webhook_delivery_lease_hash",
        ),
        sa.CheckConstraint(
            "(replay_generation = 0 AND last_replayed_at IS NULL "
            "AND last_replayed_by IS NULL) OR "
            "(replay_generation > 0 AND last_replayed_at IS NOT NULL "
            "AND last_replayed_by IS NOT NULL)",
            name="ck_webhook_delivery_replay",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "endpoint_id"],
            ["saas_webhook_endpoints.tenant_id", "saas_webhook_endpoints.id"],
            name="fk_webhook_delivery_endpoint",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["last_replayed_by"],
            ["saas_global_users.id"],
            name="fk_webhook_delivery_replay_actor",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint_id", "event_id", name="uq_webhook_delivery_event"),
    )
    op.create_index(
        "ix_webhook_delivery_dispatch",
        "saas_webhook_deliveries",
        ["status", "available_at", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_webhook_delivery_tenant",
        "saas_webhook_deliveries",
        ["tenant_id", "created_at"],
        unique=False,
    )
    if _is_postgresql():
        _create_guard_functions()
        _enable_rls()


def downgrade() -> None:
    if _is_postgresql():
        tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
        platform = "pg_has_role(current_user, 'saas_platform', 'member')"
        op.execute("DROP POLICY rls_outbox_insert ON saas_control_plane_outbox")
        op.execute(
            "CREATE POLICY rls_outbox_insert ON saas_control_plane_outbox FOR INSERT "
            "WITH CHECK ("
            "pg_has_role(current_user, 'saas_dispatcher', 'member') OR "
            f"{platform} OR tenant_id = {tenant} OR "
            "((pg_has_role(current_user, 'saas_authenticator', 'member') OR "
            "pg_has_role(current_user, 'saas_governance', 'member')) AND tenant_id IS NULL))"
        )
        op.execute("DROP TRIGGER IF EXISTS trg_webhook_delivery_guard ON saas_webhook_deliveries")
        op.execute("DROP TRIGGER IF EXISTS trg_webhook_endpoint_guard ON saas_webhook_endpoints")
        op.execute("DROP FUNCTION IF EXISTS saas_guard_webhook_delivery()")
        op.execute("DROP FUNCTION IF EXISTS saas_guard_webhook_endpoint()")
    op.drop_index("ix_webhook_delivery_tenant", table_name="saas_webhook_deliveries")
    op.drop_index("ix_webhook_delivery_dispatch", table_name="saas_webhook_deliveries")
    op.drop_table("saas_webhook_deliveries")
    op.drop_index("ix_webhook_endpoint_scope", table_name="saas_webhook_endpoints")
    op.drop_index("uq_active_webhook_endpoint_url", table_name="saas_webhook_endpoints")
    op.drop_table("saas_webhook_endpoints")
