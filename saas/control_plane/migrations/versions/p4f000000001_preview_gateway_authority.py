"""Create durable Preview Gateway discovery and Relay certificate authority.

Revision ID: p4f000000001
Revises: p4e000000001
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from alembic import op

revision: str = "p4f000000001"
down_revision: str | None = "p4e000000001"
branch_labels: str | None = None
depends_on: str | None = None

_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_PREVIEW_GATEWAY = "pg_has_role(current_user, 'saas_preview_gateway', 'member')"
_GATEWAY_TOKEN = "NULLIF(current_setting('app.gateway_registration_token_hash', true), '')"
_FINGERPRINT = "NULLIF(current_setting('app.presented_certificate_fingerprint', true), '')"
_PURPOSE = "NULLIF(current_setting('app.presented_certificate_purpose', true), '')"
_CURRENT_GATEWAY = "status IN ('active', 'draining') AND lease_expires_at > CURRENT_TIMESTAMP"
_CURRENT_CERTIFICATE = (
    "certificate_not_before <= CURRENT_TIMESTAMP "
    "AND certificate_not_after > CURRENT_TIMESTAMP "
    "AND (status = 'active' OR (status = 'retiring' AND retire_at > CURRENT_TIMESTAMP))"
)


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _create_instance_table() -> None:
    op.create_table(
        "saas_preview_gateway_instances",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("connect_host", sa.String(length=253), nullable=False),
        sa.Column("connect_port", sa.Integer(), nullable=False),
        sa.Column("server_name", sa.String(length=253), nullable=False),
        sa.Column("failure_domain", sa.String(length=128), nullable=False),
        sa.Column("source_revision", sa.String(length=64), nullable=False),
        sa.Column("adapter_contract_version", sa.String(length=32), nullable=False),
        sa.Column("registration_token_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
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
            name="ck_preview_gateway_status",
        ),
        sa.CheckConstraint(
            "connect_port >= 1 AND connect_port <= 65535",
            name="ck_preview_gateway_port",
        ),
        sa.CheckConstraint(
            "length(connect_host) > 0 AND length(server_name) > 0",
            name="ck_preview_gateway_endpoint",
        ),
        sa.CheckConstraint(
            "length(failure_domain) > 0 AND length(source_revision) > 0 "
            "AND length(adapter_contract_version) > 0",
            name="ck_preview_gateway_provenance",
        ),
        sa.CheckConstraint(
            "length(registration_token_hash) = 64", name="ck_preview_gateway_token_hash"
        ),
        sa.CheckConstraint(
            "last_heartbeat_at >= registered_at", name="ck_preview_gateway_heartbeat_order"
        ),
        sa.CheckConstraint(
            "lease_expires_at > registered_at", name="ck_preview_gateway_lease_window"
        ),
        sa.CheckConstraint(
            "(status IN ('active', 'draining') AND released_at IS NULL "
            "AND release_reason IS NULL) OR "
            "(status IN ('released', 'expired') AND released_at IS NOT NULL "
            "AND length(release_reason) > 0)",
            name="ck_preview_gateway_lifecycle",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("registration_token_hash"),
    )
    op.create_index(
        "ix_preview_gateway_discovery",
        "saas_preview_gateway_instances",
        ("id", "status", "lease_expires_at"),
    )


def _backfill_legacy_gateway_tombstones() -> None:
    """Preserve existing p4e references without claiming unknown endpoints are live."""

    connection = op.get_bind()
    gateway_ids = connection.execute(
        sa.text("SELECT DISTINCT gateway_instance_id FROM saas_runner_tunnel_placements")
    ).scalars()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    table = sa.table(
        "saas_preview_gateway_instances",
        sa.column("id"),
        sa.column("connect_host"),
        sa.column("connect_port"),
        sa.column("server_name"),
        sa.column("failure_domain"),
        sa.column("source_revision"),
        sa.column("adapter_contract_version"),
        sa.column("registration_token_hash"),
        sa.column("status"),
        sa.column("registered_at"),
        sa.column("last_heartbeat_at"),
        sa.column("lease_expires_at"),
        sa.column("released_at"),
        sa.column("release_reason"),
    )
    rows = [
        {
            "id": gateway_id,
            "connect_host": "migration.invalid",
            "connect_port": 443,
            "server_name": "migration.invalid",
            "failure_domain": "legacy-unregistered",
            "source_revision": "unknown",
            "adapter_contract_version": "unknown",
            "registration_token_hash": hashlib.sha256(
                f"legacy-preview-gateway:{gateway_id}".encode()
            ).hexdigest(),
            "status": "released",
            "registered_at": now,
            "last_heartbeat_at": now,
            "lease_expires_at": now + timedelta(seconds=1),
            "released_at": now,
            "release_reason": "migration_unregistered_gateway",
        }
        for gateway_id in gateway_ids
    ]
    if rows:
        connection.execute(sa.insert(table), rows)


def _create_certificate_table() -> None:
    op.create_table(
        "saas_preview_gateway_certificates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("gateway_instance_id", sa.String(length=128), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("spki_sha256", sa.String(length=64), nullable=False),
        sa.Column("serial_hex", sa.String(length=64), nullable=False),
        sa.Column("spiffe_id", sa.String(length=200), nullable=False),
        sa.Column("trust_bundle_version", sa.String(length=64), nullable=False),
        sa.Column("rotation_generation", sa.BigInteger(), nullable=False),
        sa.Column("certificate_not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("certificate_not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retire_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=256), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "purpose IN ('preview_relay_client', 'preview_relay_server')",
            name="ck_preview_gateway_certificate_purpose",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'retiring', 'revoked')",
            name="ck_preview_gateway_certificate_status",
        ),
        sa.CheckConstraint(
            "rotation_generation > 0", name="ck_preview_gateway_certificate_rotation"
        ),
        sa.CheckConstraint(
            "length(fingerprint_sha256) = 64",
            name="ck_preview_gateway_certificate_fingerprint",
        ),
        sa.CheckConstraint("length(spki_sha256) = 64", name="ck_preview_gateway_certificate_spki"),
        sa.CheckConstraint(
            "length(serial_hex) > 0 AND length(serial_hex) <= 64",
            name="ck_preview_gateway_certificate_serial",
        ),
        sa.CheckConstraint(
            "length(spiffe_id) > 0 AND length(trust_bundle_version) > 0",
            name="ck_preview_gateway_certificate_identity",
        ),
        sa.CheckConstraint(
            "certificate_not_after > certificate_not_before",
            name="ck_preview_gateway_certificate_validity",
        ),
        sa.CheckConstraint(
            "(status = 'active' AND retire_at IS NULL AND revoked_at IS NULL "
            "AND revocation_reason IS NULL) OR "
            "(status = 'retiring' AND retire_at IS NOT NULL AND retire_at >= activated_at "
            "AND revoked_at IS NULL AND revocation_reason IS NULL) OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= activated_at "
            "AND length(revocation_reason) > 0)",
            name="ck_preview_gateway_certificate_lifecycle",
        ),
        sa.ForeignKeyConstraint(
            ("gateway_instance_id",),
            ("saas_preview_gateway_instances.id",),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint_sha256"),
        sa.UniqueConstraint(
            "gateway_instance_id",
            "purpose",
            "rotation_generation",
            name="uq_preview_gateway_certificate_rotation",
        ),
    )
    op.create_index(
        "ix_preview_gateway_certificate_authorize",
        "saas_preview_gateway_certificates",
        ("fingerprint_sha256", "purpose", "status"),
    )
    op.create_index(
        "uq_preview_gateway_certificate_active",
        "saas_preview_gateway_certificates",
        ("gateway_instance_id", "purpose"),
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
        sqlite_where=sa.text("status = 'active'"),
    )


def upgrade() -> None:
    _create_instance_table()
    _backfill_legacy_gateway_tombstones()
    with op.batch_alter_table("saas_runner_tunnel_placements") as batch_op:
        batch_op.create_foreign_key(
            "fk_runner_tunnel_placement_gateway",
            "saas_preview_gateway_instances",
            ["gateway_instance_id"],
            ["id"],
            ondelete="RESTRICT",
        )
    _create_certificate_table()
    if not _is_postgresql():
        return

    op.execute('ALTER TABLE "saas_preview_gateway_instances" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_preview_gateway_instances" FORCE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_preview_gateway_certificates" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_preview_gateway_certificates" FORCE ROW LEVEL SECURITY')
    op.execute(
        'CREATE POLICY "rls_preview_gateway_instances_platform" '
        'ON "saas_preview_gateway_instances" FOR ALL '
        f"USING ({_PLATFORM}) WITH CHECK ({_PLATFORM})"
    )
    service_read = (
        f"({_EXECUTOR} OR {_PREVIEW_GATEWAY}) AND ({_CURRENT_GATEWAY})"
        f" OR ({_PREVIEW_GATEWAY} AND registration_token_hash = {_GATEWAY_TOKEN})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_gateway_instances_service_read" '
        'ON "saas_preview_gateway_instances" FOR SELECT '
        f"USING ({service_read})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_gateway_instances_self_update" '
        'ON "saas_preview_gateway_instances" FOR UPDATE '
        f"USING ({_PREVIEW_GATEWAY} AND registration_token_hash = {_GATEWAY_TOKEN}) "
        f"WITH CHECK ({_PREVIEW_GATEWAY} AND registration_token_hash = {_GATEWAY_TOKEN})"
    )
    op.execute(
        'CREATE POLICY "rls_preview_gateway_certificates_platform" '
        'ON "saas_preview_gateway_certificates" FOR ALL '
        f"USING ({_PLATFORM}) WITH CHECK ({_PLATFORM})"
    )
    certificate_read = (
        f"{_PREVIEW_GATEWAY} AND purpose = {_PURPOSE} "
        f"AND fingerprint_sha256 = {_FINGERPRINT} AND {_CURRENT_CERTIFICATE} "
        "AND EXISTS (SELECT 1 FROM saas_preview_gateway_instances gateway "
        "WHERE gateway.id = saas_preview_gateway_certificates.gateway_instance_id "
        "AND gateway.status IN ('active', 'draining') "
        "AND gateway.lease_expires_at > CURRENT_TIMESTAMP)"
    )
    op.execute(
        'CREATE POLICY "rls_preview_gateway_certificates_authorize" '
        'ON "saas_preview_gateway_certificates" FOR SELECT '
        f"USING ({certificate_read})"
    )
    op.execute(
        'CREATE POLICY "rls_outbox_preview_gateway_service_insert" '
        'ON "saas_control_plane_outbox" FOR INSERT WITH CHECK ('
        f"{_PREVIEW_GATEWAY} AND tenant_id IS NULL "
        "AND aggregate_type = 'preview_gateway_instance' "
        "AND event_type IN ('preview.gateway.draining', 'preview.gateway.released') "
        "AND aggregate_key = payload ->> 'gateway_instance_id')"
    )
    op.execute(
        'CREATE POLICY "rls_outbox_preview_gateway_service_read" '
        'ON "saas_control_plane_outbox" FOR SELECT USING ('
        f"{_PREVIEW_GATEWAY} AND tenant_id IS NULL "
        "AND aggregate_type = 'preview_gateway_instance' "
        "AND event_type IN ('preview.gateway.draining', 'preview.gateway.released') "
        "AND aggregate_key = payload ->> 'gateway_instance_id')"
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_runner_tunnel_placements_preview_route" '
        'ON "saas_runner_tunnel_placements"'
    )
    preview_hash = "NULLIF(current_setting('app.preview_token_hash', true), '')"
    preview_route = (
        f"{_PREVIEW_GATEWAY} AND status IN ('active', 'draining') "
        "AND lease_expires_at > CURRENT_TIMESTAMP "
        "AND EXISTS (SELECT 1 FROM saas_preview_gateway_instances gateway "
        "WHERE gateway.id = saas_runner_tunnel_placements.gateway_instance_id "
        "AND gateway.status IN ('active', 'draining') "
        "AND gateway.lease_expires_at > CURRENT_TIMESTAMP) "
        "AND EXISTS (SELECT 1 FROM saas_preview_leases preview "
        "WHERE preview.runner_id = saas_runner_tunnel_placements.runner_id "
        "AND preview.runner_connection_generation = "
        "saas_runner_tunnel_placements.runner_connection_generation "
        f"AND preview.token_hash = {preview_hash} "
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
    _create_postgresql_guards()


def _create_postgresql_guards() -> None:
    op.execute(
        """
        CREATE FUNCTION saas_guard_preview_gateway_instance()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(
                NEW.id, NEW.connect_host, NEW.connect_port, NEW.server_name,
                NEW.failure_domain, NEW.source_revision, NEW.adapter_contract_version,
                NEW.registration_token_hash, NEW.registered_at, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.id, OLD.connect_host, OLD.connect_port, OLD.server_name,
                OLD.failure_domain, OLD.source_revision, OLD.adapter_contract_version,
                OLD.registration_token_hash, OLD.registered_at, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'Preview Gateway authority fields are immutable';
            END IF;
            IF NEW.last_heartbeat_at < OLD.last_heartbeat_at
                OR NEW.lease_expires_at < OLD.lease_expires_at THEN
                RAISE EXCEPTION 'Preview Gateway time is monotonic';
            END IF;
            IF NOT (
                (OLD.status = NEW.status AND OLD.status IN ('active', 'draining')
                    AND NEW.released_at IS NULL AND NEW.release_reason IS NULL)
                OR (OLD.status = 'active' AND NEW.status = 'draining'
                    AND NEW.released_at IS NULL AND NEW.release_reason IS NULL)
                OR (OLD.status IN ('active', 'draining')
                    AND NEW.status IN ('released', 'expired')
                    AND NEW.released_at IS NOT NULL AND NEW.release_reason IS NOT NULL)
                OR (OLD.status = NEW.status AND OLD.status IN ('released', 'expired')
                    AND ROW(NEW.released_at, NEW.release_reason) IS NOT DISTINCT FROM
                        ROW(OLD.released_at, OLD.release_reason)
                    AND NEW.last_heartbeat_at = OLD.last_heartbeat_at
                    AND NEW.lease_expires_at = OLD.lease_expires_at)
            ) THEN
                RAISE EXCEPTION 'Preview Gateway lifecycle is monotonic';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER trg_guard_preview_gateway_instance "
        "BEFORE UPDATE ON saas_preview_gateway_instances "
        "FOR EACH ROW EXECUTE FUNCTION saas_guard_preview_gateway_instance()"
    )
    op.execute(
        """
        CREATE FUNCTION saas_reject_preview_gateway_instance_delete()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Preview Gateway instance records are append-only';
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER trg_reject_preview_gateway_instance_delete "
        "BEFORE DELETE ON saas_preview_gateway_instances "
        "FOR EACH ROW EXECUTE FUNCTION saas_reject_preview_gateway_instance_delete()"
    )
    op.execute(
        """
        CREATE FUNCTION saas_guard_preview_gateway_certificate()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(
                NEW.id, NEW.gateway_instance_id, NEW.purpose, NEW.fingerprint_sha256,
                NEW.spki_sha256, NEW.serial_hex, NEW.spiffe_id,
                NEW.trust_bundle_version, NEW.rotation_generation,
                NEW.certificate_not_before, NEW.certificate_not_after,
                NEW.activated_at, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.id, OLD.gateway_instance_id, OLD.purpose, OLD.fingerprint_sha256,
                OLD.spki_sha256, OLD.serial_hex, OLD.spiffe_id,
                OLD.trust_bundle_version, OLD.rotation_generation,
                OLD.certificate_not_before, OLD.certificate_not_after,
                OLD.activated_at, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'Preview Gateway certificate authority fields are immutable';
            END IF;
            IF NOT (
                ROW(OLD.status, OLD.retire_at, OLD.revoked_at, OLD.revocation_reason)
                    IS NOT DISTINCT FROM
                ROW(NEW.status, NEW.retire_at, NEW.revoked_at, NEW.revocation_reason)
                OR (OLD.status = 'active' AND NEW.status = 'retiring'
                    AND OLD.retire_at IS NULL AND NEW.retire_at IS NOT NULL
                    AND NEW.revoked_at IS NULL AND NEW.revocation_reason IS NULL)
                OR (OLD.status = 'retiring' AND NEW.status = 'retiring'
                    AND NEW.retire_at IS NOT NULL AND NEW.retire_at <= OLD.retire_at
                    AND NEW.revoked_at IS NULL AND NEW.revocation_reason IS NULL)
                OR (OLD.status IN ('active', 'retiring') AND NEW.status = 'revoked'
                    AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
                    AND NEW.revocation_reason IS NOT NULL)
            ) THEN
                RAISE EXCEPTION 'Preview Gateway certificate lifecycle is monotonic';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER trg_guard_preview_gateway_certificate "
        "BEFORE UPDATE ON saas_preview_gateway_certificates "
        "FOR EACH ROW EXECUTE FUNCTION saas_guard_preview_gateway_certificate()"
    )
    op.execute(
        """
        CREATE FUNCTION saas_reject_preview_gateway_certificate_delete()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Preview Gateway certificate records are append-only';
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER trg_reject_preview_gateway_certificate_delete "
        "BEFORE DELETE ON saas_preview_gateway_certificates "
        "FOR EACH ROW EXECUTE FUNCTION saas_reject_preview_gateway_certificate_delete()"
    )
    op.execute(
        """
        CREATE FUNCTION saas_require_live_preview_gateway_placement()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.status IN ('active', 'draining') AND NOT EXISTS (
                SELECT 1 FROM saas_preview_gateway_instances gateway
                WHERE gateway.id = NEW.gateway_instance_id
                    AND gateway.status IN ('active', 'draining')
                    AND gateway.lease_expires_at > CURRENT_TIMESTAMP
            ) THEN
                RAISE EXCEPTION 'Runner tunnel Placement requires a live Preview Gateway';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER trg_require_live_preview_gateway_placement "
        "BEFORE INSERT OR UPDATE ON saas_runner_tunnel_placements "
        "FOR EACH ROW EXECUTE FUNCTION saas_require_live_preview_gateway_placement()"
    )


def _restore_p4e_preview_route_policy() -> None:
    preview_hash = "NULLIF(current_setting('app.preview_token_hash', true), '')"
    preview_route = (
        f"{_PREVIEW_GATEWAY} AND status IN ('active', 'draining') "
        "AND lease_expires_at > CURRENT_TIMESTAMP "
        "AND EXISTS (SELECT 1 FROM saas_preview_leases preview "
        "WHERE preview.runner_id = saas_runner_tunnel_placements.runner_id "
        "AND preview.runner_connection_generation = "
        "saas_runner_tunnel_placements.runner_connection_generation "
        f"AND preview.token_hash = {preview_hash} "
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


def downgrade() -> None:
    if _is_postgresql():
        op.execute(
            "DROP TRIGGER IF EXISTS trg_require_live_preview_gateway_placement "
            "ON saas_runner_tunnel_placements"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_require_live_preview_gateway_placement()")
        op.execute(
            'DROP POLICY IF EXISTS "rls_runner_tunnel_placements_preview_route" '
            'ON "saas_runner_tunnel_placements"'
        )
        _restore_p4e_preview_route_policy()
        op.execute(
            'DROP POLICY IF EXISTS "rls_outbox_preview_gateway_service_read" '
            'ON "saas_control_plane_outbox"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_outbox_preview_gateway_service_insert" '
            'ON "saas_control_plane_outbox"'
        )
        op.execute(
            "DROP TRIGGER IF EXISTS trg_reject_preview_gateway_certificate_delete "
            "ON saas_preview_gateway_certificates"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_reject_preview_gateway_certificate_delete()")
        op.execute(
            "DROP TRIGGER IF EXISTS trg_guard_preview_gateway_certificate "
            "ON saas_preview_gateway_certificates"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_guard_preview_gateway_certificate()")
        op.execute(
            "DROP TRIGGER IF EXISTS trg_reject_preview_gateway_instance_delete "
            "ON saas_preview_gateway_instances"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_reject_preview_gateway_instance_delete()")
        op.execute(
            "DROP TRIGGER IF EXISTS trg_guard_preview_gateway_instance "
            "ON saas_preview_gateway_instances"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_guard_preview_gateway_instance()")
        op.execute(
            'DROP POLICY IF EXISTS "rls_preview_gateway_certificates_authorize" '
            'ON "saas_preview_gateway_certificates"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_preview_gateway_certificates_platform" '
            'ON "saas_preview_gateway_certificates"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_preview_gateway_instances_self_update" '
            'ON "saas_preview_gateway_instances"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_preview_gateway_instances_service_read" '
            'ON "saas_preview_gateway_instances"'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_preview_gateway_instances_platform" '
            'ON "saas_preview_gateway_instances"'
        )
    op.drop_index(
        "uq_preview_gateway_certificate_active",
        table_name="saas_preview_gateway_certificates",
    )
    op.drop_index(
        "ix_preview_gateway_certificate_authorize",
        table_name="saas_preview_gateway_certificates",
    )
    op.drop_table("saas_preview_gateway_certificates")
    with op.batch_alter_table("saas_runner_tunnel_placements") as batch_op:
        batch_op.drop_constraint("fk_runner_tunnel_placement_gateway", type_="foreignkey")
    op.drop_index("ix_preview_gateway_discovery", table_name="saas_preview_gateway_instances")
    op.drop_table("saas_preview_gateway_instances")
