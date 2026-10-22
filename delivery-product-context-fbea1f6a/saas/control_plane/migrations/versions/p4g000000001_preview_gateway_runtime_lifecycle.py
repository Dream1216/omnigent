"""Add two-phase Preview Gateway process activation.

Revision ID: p4g000000001
Revises: p4f000000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p4g000000001"
down_revision: str | None = "p4f000000001"
branch_labels: str | None = None
depends_on: str | None = None


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _create_p4g_constraints() -> None:
    with op.batch_alter_table("saas_preview_gateway_instances") as batch_op:
        batch_op.drop_constraint("ck_preview_gateway_status", type_="check")
        batch_op.drop_constraint("ck_preview_gateway_lifecycle", type_="check")
        batch_op.create_check_constraint(
            "ck_preview_gateway_status",
            "status IN ('starting', 'active', 'draining', 'released', 'expired')",
        )
        batch_op.create_check_constraint(
            "ck_preview_gateway_lifecycle",
            "(status = 'starting' AND activated_at IS NULL AND released_at IS NULL "
            "AND release_reason IS NULL) OR "
            "(status IN ('active', 'draining') AND activated_at IS NOT NULL "
            "AND activated_at >= registered_at AND released_at IS NULL "
            "AND release_reason IS NULL) OR "
            "(status IN ('released', 'expired') AND released_at IS NOT NULL "
            "AND released_at >= registered_at "
            "AND (activated_at IS NULL OR (activated_at >= registered_at "
            "AND released_at >= activated_at)) AND length(release_reason) > 0)",
        )


def _create_p4f_constraints() -> None:
    with op.batch_alter_table("saas_preview_gateway_instances") as batch_op:
        batch_op.drop_constraint("ck_preview_gateway_status", type_="check")
        batch_op.drop_constraint("ck_preview_gateway_lifecycle", type_="check")
        batch_op.create_check_constraint(
            "ck_preview_gateway_status",
            "status IN ('active', 'draining', 'released', 'expired')",
        )
        batch_op.create_check_constraint(
            "ck_preview_gateway_lifecycle",
            "(status IN ('active', 'draining') AND released_at IS NULL "
            "AND release_reason IS NULL) OR "
            "(status IN ('released', 'expired') AND released_at IS NOT NULL "
            "AND length(release_reason) > 0)",
        )


def _replace_p4g_guard() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.saas_guard_preview_gateway_instance()
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
                (OLD.status = NEW.status AND OLD.status = 'starting'
                    AND NEW.activated_at IS NULL
                    AND NEW.released_at IS NULL AND NEW.release_reason IS NULL)
                OR (OLD.status = 'starting' AND NEW.status = 'active'
                    AND OLD.activated_at IS NULL AND NEW.activated_at IS NOT NULL
                    AND NEW.activated_at >= NEW.registered_at
                    AND NEW.activated_at >= OLD.last_heartbeat_at
                    AND EXISTS (
                        SELECT 1
                        FROM public.saas_preview_gateway_certificates AS certificate
                        WHERE certificate.gateway_instance_id = NEW.id
                            AND certificate.status = 'active'
                            AND certificate.certificate_not_before <= NEW.activated_at
                            AND certificate.certificate_not_after > NEW.activated_at
                        GROUP BY certificate.gateway_instance_id
                        HAVING count(DISTINCT certificate.purpose) = 2
                            AND count(DISTINCT certificate.trust_bundle_version) = 1
                    )
                    AND NEW.released_at IS NULL AND NEW.release_reason IS NULL)
                OR (OLD.status = NEW.status AND OLD.status IN ('active', 'draining')
                    AND NEW.activated_at = OLD.activated_at
                    AND NEW.released_at IS NULL AND NEW.release_reason IS NULL)
                OR (OLD.status = 'active' AND NEW.status = 'draining'
                    AND NEW.activated_at = OLD.activated_at
                    AND NEW.released_at IS NULL AND NEW.release_reason IS NULL)
                OR (OLD.status IN ('starting', 'active', 'draining')
                    AND NEW.status IN ('released', 'expired')
                    AND NEW.activated_at IS NOT DISTINCT FROM OLD.activated_at
                    AND NEW.released_at >= OLD.last_heartbeat_at
                    AND NEW.released_at IS NOT NULL AND NEW.release_reason IS NOT NULL)
                OR (OLD.status = NEW.status AND OLD.status IN ('released', 'expired')
                    AND NEW.activated_at IS NOT DISTINCT FROM OLD.activated_at
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


def _restore_p4f_guard() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.saas_guard_preview_gateway_instance()
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


def upgrade() -> None:
    with op.batch_alter_table("saas_preview_gateway_instances") as batch_op:
        batch_op.add_column(sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(
        "UPDATE saas_preview_gateway_instances SET activated_at = registered_at "
        "WHERE status IN ('active', 'draining')"
    )
    _create_p4g_constraints()
    if _is_postgresql():
        _replace_p4g_guard()


def downgrade() -> None:
    op.execute(
        "UPDATE saas_preview_gateway_instances SET status = 'expired', "
        "released_at = CASE WHEN last_heartbeat_at > CURRENT_TIMESTAMP "
        "THEN last_heartbeat_at ELSE CURRENT_TIMESTAMP END, "
        "release_reason = 'p4g_downgrade_starting_gateway' "
        "WHERE status = 'starting'"
    )
    if _is_postgresql():
        _restore_p4f_guard()
    _create_p4f_constraints()
    with op.batch_alter_table("saas_preview_gateway_instances") as batch_op:
        batch_op.drop_column("activated_at")
