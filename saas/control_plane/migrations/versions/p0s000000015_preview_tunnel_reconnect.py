"""Close an earlier preview tunnel registration before reconnecting.

Revision ID: p0s000000015
Revises: p0s000000014
"""

from __future__ import annotations

from alembic import op

revision: str = "p0s000000015"
down_revision: str | None = "p0s000000014"
branch_labels: str | None = None
depends_on: str | None = None


def _install(*, close_prior_registration: bool) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    close_prior = (
        """
            UPDATE public.saas_preview_tunnel_registrations AS stale_registration
            SET status = 'disconnected', disconnected_at = operation_at,
                updated_at = operation_at
            WHERE stale_registration.runner_id = registration.runner_id
              AND stale_registration.placement_id = registration.placement_id
              AND stale_registration.connection_generation = registration.connection_generation
              AND stale_registration.status = 'redeemed';
    """
        if close_prior_registration
        else ""
    )
    runner_lock = (
        """
            PERFORM 1 FROM public.saas_runner_registrations AS current_runner
            WHERE current_runner.id = registration.runner_id FOR UPDATE;
        """
        if close_prior_registration
        else ""
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.saas_preview_redeem_tunnel_v1(
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
        """
        + runner_lock
        # Disconnect locks the prior registration before its placement; keep
        # that order so reconnect cannot deadlock with an in-flight disconnect.
        + close_prior
        + """
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


def upgrade() -> None:
    _install(close_prior_registration=True)


def downgrade() -> None:
    _install(close_prior_registration=False)
