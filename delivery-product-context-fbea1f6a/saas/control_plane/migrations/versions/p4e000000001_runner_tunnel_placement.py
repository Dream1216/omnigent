"""Create durable cross-replica Runner tunnel placement authority.

Revision ID: p4e000000001
Revises: p4d000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p4e000000001"
down_revision: str | None = "p4d000000001"
branch_labels: str | None = None
depends_on: str | None = None

_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_PREVIEW_GATEWAY = "pg_has_role(current_user, 'saas_preview_gateway', 'member')"
_PREVIEW_HASH = "NULLIF(current_setting('app.preview_token_hash', true), '')"


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    op.create_table(
        "saas_runner_tunnel_placements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("routing_generation", sa.BigInteger(), nullable=False),
        sa.Column("gateway_instance_id", sa.String(length=128), nullable=False),
        sa.Column("relay_subject", sa.String(length=128), nullable=False),
        sa.Column("ownership_token_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("release_reason", sa.String(length=256), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('active', 'draining', 'released', 'expired')",
            name="ck_runner_tunnel_placement_status",
        ),
        sa.CheckConstraint(
            "runner_connection_generation > 0",
            name="ck_runner_tunnel_placement_connection_generation",
        ),
        sa.CheckConstraint(
            "routing_generation > 0", name="ck_runner_tunnel_placement_routing_generation"
        ),
        sa.CheckConstraint(
            "length(gateway_instance_id) > 0",
            name="ck_runner_tunnel_placement_gateway_nonempty",
        ),
        sa.CheckConstraint(
            "length(relay_subject) > 0", name="ck_runner_tunnel_placement_relay_nonempty"
        ),
        sa.CheckConstraint(
            "length(ownership_token_hash) = 64",
            name="ck_runner_tunnel_placement_token_hash",
        ),
        sa.CheckConstraint(
            "last_heartbeat_at >= claimed_at",
            name="ck_runner_tunnel_placement_heartbeat_order",
        ),
        sa.CheckConstraint(
            "lease_expires_at > claimed_at", name="ck_runner_tunnel_placement_lease_window"
        ),
        sa.CheckConstraint(
            "(status IN ('active', 'draining') AND released_at IS NULL "
            "AND release_reason IS NULL) OR "
            "(status IN ('released', 'expired') AND released_at IS NOT NULL "
            "AND release_reason IS NOT NULL)",
            name="ck_runner_tunnel_placement_lifecycle",
        ),
        sa.ForeignKeyConstraint(
            ("runner_id",), ("saas_runner_registrations.id",), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("relay_subject"),
        sa.UniqueConstraint("ownership_token_hash"),
        sa.UniqueConstraint(
            "runner_id", "routing_generation", name="uq_runner_tunnel_placement_generation"
        ),
    )
    op.create_index(
        "ix_runner_tunnel_placement_resolve",
        "saas_runner_tunnel_placements",
        ("runner_id", "runner_connection_generation", "status", "lease_expires_at"),
    )
    op.create_index(
        "uq_runner_tunnel_placement_live",
        "saas_runner_tunnel_placements",
        ("runner_id",),
        unique=True,
        postgresql_where=sa.text("status IN ('active', 'draining')"),
        sqlite_where=sa.text("status IN ('active', 'draining')"),
    )
    if not _is_postgresql():
        return

    op.execute('ALTER TABLE "saas_runner_tunnel_placements" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_runner_tunnel_placements" FORCE ROW LEVEL SECURITY')
    global_authority = f"({_PLATFORM} OR {_EXECUTOR})"
    op.execute(
        'CREATE POLICY "rls_runner_tunnel_placements_authority" '
        'ON "saas_runner_tunnel_placements" FOR ALL '
        f"USING ({global_authority}) WITH CHECK ({global_authority})"
    )
    preview_route = (
        f"{_PREVIEW_GATEWAY} AND status IN ('active', 'draining') "
        "AND lease_expires_at > CURRENT_TIMESTAMP "
        "AND EXISTS (SELECT 1 FROM saas_preview_leases preview "
        "WHERE preview.runner_id = saas_runner_tunnel_placements.runner_id "
        "AND preview.runner_connection_generation = "
        "saas_runner_tunnel_placements.runner_connection_generation "
        f"AND preview.token_hash = {_PREVIEW_HASH} "
        "AND preview.status = 'active' AND preview.expires_at > CURRENT_TIMESTAMP) "
        "AND EXISTS (SELECT 1 FROM saas_runner_registrations runner "
        "WHERE runner.id = saas_runner_tunnel_placements.runner_id "
        "AND runner.connection_generation = "
        "saas_runner_tunnel_placements.runner_connection_generation "
        "AND runner.status IN ('online', 'draining'))"
    )
    op.execute(
        'CREATE POLICY "rls_runner_tunnel_placements_preview_route" '
        'ON "saas_runner_tunnel_placements" FOR SELECT '
        f"USING ({preview_route})"
    )
    op.execute(
        'CREATE POLICY "rls_outbox_runner_tunnel_placement_executor" '
        'ON "saas_control_plane_outbox" FOR INSERT WITH CHECK ('
        f"{_EXECUTOR} AND tenant_id IS NULL "
        "AND aggregate_type = 'runner_tunnel_placement' "
        "AND event_type IN ('runner.tunnel_placement.claimed', "
        "'runner.tunnel_placement.draining', 'runner.tunnel_placement.released', "
        "'runner.tunnel_placement.expired') "
        "AND aggregate_key = payload ->> 'placement_id')"
    )
    op.execute(
        'CREATE POLICY "rls_outbox_runner_tunnel_placement_executor_read" '
        'ON "saas_control_plane_outbox" FOR SELECT USING ('
        f"{_EXECUTOR} AND tenant_id IS NULL "
        "AND aggregate_type = 'runner_tunnel_placement' "
        "AND event_type IN ('runner.tunnel_placement.claimed', "
        "'runner.tunnel_placement.draining', 'runner.tunnel_placement.released', "
        "'runner.tunnel_placement.expired') "
        "AND aggregate_key = payload ->> 'placement_id')"
    )
    op.execute(
        """
        CREATE FUNCTION saas_guard_runner_tunnel_placement()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(
                NEW.id, NEW.runner_id, NEW.runner_connection_generation,
                NEW.routing_generation, NEW.gateway_instance_id, NEW.relay_subject,
                NEW.ownership_token_hash, NEW.claimed_at, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.id, OLD.runner_id, OLD.runner_connection_generation,
                OLD.routing_generation, OLD.gateway_instance_id, OLD.relay_subject,
                OLD.ownership_token_hash, OLD.claimed_at, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'Runner tunnel placement authority fields are immutable';
            END IF;
            IF NEW.last_heartbeat_at < OLD.last_heartbeat_at
                OR NEW.lease_expires_at < OLD.lease_expires_at THEN
                RAISE EXCEPTION 'Runner tunnel placement time is monotonic';
            END IF;
            IF NOT (
                (
                    OLD.status = NEW.status AND OLD.status IN ('active', 'draining')
                    AND NEW.released_at IS NULL AND NEW.release_reason IS NULL
                )
                OR (
                    OLD.status = 'active' AND NEW.status = 'draining'
                    AND NEW.released_at IS NULL AND NEW.release_reason IS NULL
                )
                OR (
                    OLD.status IN ('active', 'draining')
                    AND NEW.status IN ('released', 'expired')
                    AND NEW.released_at IS NOT NULL AND NEW.release_reason IS NOT NULL
                )
                OR (
                    OLD.status = NEW.status AND OLD.status IN ('released', 'expired')
                    AND ROW(NEW.released_at, NEW.release_reason) IS NOT DISTINCT FROM
                        ROW(OLD.released_at, OLD.release_reason)
                    AND NEW.last_heartbeat_at = OLD.last_heartbeat_at
                    AND NEW.lease_expires_at = OLD.lease_expires_at
                )
            ) THEN
                RAISE EXCEPTION 'Runner tunnel placement lifecycle is monotonic';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_guard_runner_tunnel_placement
        BEFORE UPDATE ON saas_runner_tunnel_placements
        FOR EACH ROW EXECUTE FUNCTION saas_guard_runner_tunnel_placement()
        """
    )
    op.execute(
        """
        CREATE FUNCTION saas_reject_runner_tunnel_placement_delete()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Runner tunnel placement records are append-only';
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_reject_runner_tunnel_placement_delete
        BEFORE DELETE ON saas_runner_tunnel_placements
        FOR EACH ROW EXECUTE FUNCTION saas_reject_runner_tunnel_placement_delete()
        """
    )


def downgrade() -> None:
    if _is_postgresql():
        op.execute(
            'DROP POLICY IF EXISTS "rls_outbox_runner_tunnel_placement_executor_read" '
            'ON "saas_control_plane_outbox"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_outbox_runner_tunnel_placement_executor" '
            'ON "saas_control_plane_outbox"'
        )
        op.execute(
            "DROP TRIGGER IF EXISTS trg_reject_runner_tunnel_placement_delete "
            "ON saas_runner_tunnel_placements"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_reject_runner_tunnel_placement_delete()")
        op.execute(
            "DROP TRIGGER IF EXISTS trg_guard_runner_tunnel_placement "
            "ON saas_runner_tunnel_placements"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_guard_runner_tunnel_placement()")
        op.execute(
            'DROP POLICY IF EXISTS "rls_runner_tunnel_placements_preview_route" '
            'ON "saas_runner_tunnel_placements"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_runner_tunnel_placements_authority" '
            'ON "saas_runner_tunnel_placements"'
        )
    op.drop_index("uq_runner_tunnel_placement_live", table_name="saas_runner_tunnel_placements")
    op.drop_index("ix_runner_tunnel_placement_resolve", table_name="saas_runner_tunnel_placements")
    op.drop_table("saas_runner_tunnel_placements")
