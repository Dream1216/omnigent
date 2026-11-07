"""Bind every Runner database login to one immutable Runner incarnation.

Revision ID: p0s000000010
Revises: p0s000000009
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "p0s000000010"
down_revision: str | None = "p0s000000009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE = "saas_runner_agent"
_LEGACY_POLICY_ROLE_PROJECTIONS = {
    ("saas_capability_tokens", "rls_capability_tokens_metering_exact"): ("saas_metering",),
    ("saas_capability_tokens", "rls_capability_tokens_metering_lock"): ("saas_metering",),
    ("saas_run_dispatches", "rls_run_dispatches_metering_exact"): ("saas_metering",),
    ("saas_run_dispatches", "rls_run_dispatches_metering_lock"): ("saas_metering",),
    ("saas_runner_registrations", "rls_runner_registrations_certificate_service"): (
        "saas_secret_broker",
        "saas_preview_gateway",
    ),
    ("saas_runner_registrations", "rls_runner_registrations_metering_exact"): ("saas_metering",),
    ("saas_runner_registrations", "rls_runner_registrations_metering_lock"): ("saas_metering",),
    ("saas_runner_registrations", "rls_saas_runner_registrations_preview_gateway"): (
        "saas_preview_gateway",
    ),
    ("saas_runner_registrations", "rls_saas_runner_registrations_secret_broker"): (
        "saas_secret_broker",
    ),
    ("saas_runs", "rls_runs_metering_exact"): ("saas_metering",),
    ("saas_runs", "rls_runs_metering_lock"): ("saas_metering",),
    ("saas_runs", "rls_runs_privacy_auditor_read"): ("saas_platform_governance",),
    ("saas_runs", "rls_saas_runs_preview_gateway"): ("saas_preview_gateway",),
    ("saas_runs", "rls_saas_runs_privacy_target"): (
        "saas_platform",
        "saas_platform_governance",
    ),
    ("saas_runs", "rls_saas_runs_secret_broker"): ("saas_secret_broker",),
    ("saas_secret_bindings", "rls_saas_secret_bindings_broker"): ("saas_secret_broker",),
    ("saas_worktree_instances", "rls_saas_worktree_instances_preview_gateway"): (
        "saas_preview_gateway",
    ),
    ("saas_control_plane_outbox", "rls_outbox_pc3_platform_insert"): (
        "saas_platform",
        "saas_platform_governance",
    ),
    ("saas_control_plane_outbox", "rls_outbox_pc3_platform_read"): (
        "saas_platform",
        "saas_platform_governance",
    ),
    ("saas_control_plane_outbox", "rls_outbox_platform_insert"): (
        "saas_platform",
        "saas_platform_governance",
    ),
    ("saas_control_plane_outbox", "rls_outbox_privacy_insert"): (
        "saas_platform",
        "saas_platform_governance",
    ),
    ("saas_control_plane_outbox", "rls_outbox_privacy_dispatcher_insert"): (
        "saas_privacy_dispatcher",
    ),
}


def _registered(runner_id: str, generation: str) -> str:
    return f"public.saas_runner_agent_registered_v1({runner_id}, {generation})"


def _live_capability(alias: str, *required_actions: str) -> str:
    action = " OR ".join(
        f"({alias}.allowed_actions)::jsonb ? '{required_action}'"
        for required_action in required_actions
    )
    if not action:
        raise ValueError("Runner capability policy requires an action")
    return (
        f"{alias}.revoked_at IS NULL "
        f"AND {alias}.expires_at > statement_timestamp() "
        f"AND ({action}) "
        f"AND ({_registered(f'{alias}.runner_id', f'{alias}.runner_connection_generation')})"
    )


def _policy(
    table: str,
    suffix: str,
    *,
    command: str,
    expression: str,
    with_check: str | None = None,
    restrictive: bool = False,
) -> None:
    mode = "AS RESTRICTIVE " if restrictive else ""
    using = "" if command == "INSERT" else f" USING ({expression})"
    check = ""
    if command in {"ALL", "INSERT", "UPDATE"}:
        check = f" WITH CHECK ({with_check if with_check is not None else expression})"
    op.execute(
        f'CREATE POLICY "rls_{table}_runner_{suffix}" ON public."{table}" '
        f"{mode}FOR {command} TO {_ROLE}{using}{check}"
    )


def _exact_pair(
    table: str,
    suffix: str,
    *,
    command: str,
    expression: str,
    with_check: str | None = None,
) -> None:
    _policy(
        table,
        suffix,
        command=command,
        expression=expression,
        with_check=with_check,
    )
    _policy(
        table,
        f"{suffix}_fence",
        command=command,
        expression=expression,
        with_check=with_check,
        restrictive=True,
    )


def _drop_policy(table: str, suffix: str) -> None:
    op.execute(f'DROP POLICY IF EXISTS "rls_{table}_runner_{suffix}" ON public."{table}"')


def _definer_policy(table: str, *, command: str = "ALL") -> None:
    """Let only the direct table owner execute locked Runner API functions."""

    expression = (
        "current_user = pg_get_userbyid((SELECT relation.relowner "
        "FROM pg_catalog.pg_class AS relation "
        f"WHERE relation.oid = 'public.{table}'::regclass))"
    )
    using = "" if command == "INSERT" else f" USING ({expression})"
    check = "" if command == "SELECT" else f" WITH CHECK ({expression})"
    op.execute(
        f'CREATE POLICY "rls_{table}_runner_api_definer" ON public."{table}" '
        f"FOR {command}{using}{check}"
    )


def _restrict_legacy_policy_roles() -> None:
    """Keep unrelated PUBLIC policy joins out of the Runner query graph.

    Older policies used PUBLIC plus pg_has_role guards.  PostgreSQL still
    plans their protected-table subqueries for an unrelated narrow role,
    which both requires unrelated ACLs and can create RLS dependency cycles.
    The explicit role lists are semantically identical for the intended
    services and ensure the Runner sees only its own restrictive fence.
    """

    for (table, policy), roles in _LEGACY_POLICY_ROLE_PROJECTIONS.items():
        op.execute(f'ALTER POLICY "{policy}" ON public."{table}" TO {", ".join(roles)}')


def _install_runner_worktree_api() -> None:
    """Install the bounded Worktree mutation API used by Runner logins."""

    op.execute(
        "CREATE UNIQUE INDEX uq_worktree_runner_run_fence_v1 "
        "ON public.saas_worktree_instances (run_id, run_fence_token)"
    )
    for table in (
        "saas_runner_registrations",
        "saas_capability_tokens",
        "saas_run_dispatches",
        "saas_runs",
        "saas_repositories",
        "saas_changeset_groups",
        "saas_changesets",
        "saas_worktree_quotas",
        "saas_worktree_instances",
        "saas_worktree_events",
        "saas_control_plane_outbox",
    ):
        _definer_policy(table)

    op.execute(
        """
        CREATE FUNCTION public.saas_canonical_json_v1(value jsonb)
        RETURNS text
        LANGUAGE plpgsql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            canonical text;
        BEGIN
            CASE jsonb_typeof(value)
                WHEN 'object' THEN
                    IF EXISTS (
                        SELECT 1 FROM jsonb_each(value) AS candidate
                        WHERE octet_length(candidate.key) <> length(candidate.key)
                    ) THEN
                        RAISE EXCEPTION 'runner_canonical_json_non_ascii'
                            USING ERRCODE = '22023';
                    END IF;
                    SELECT '{' || COALESCE(string_agg(
                        to_json(pair.key)::text || ':' ||
                            public.saas_canonical_json_v1(pair.value),
                        ',' ORDER BY pair.key COLLATE "C"
                    ), '') || '}'
                    INTO canonical
                    FROM jsonb_each(value) AS pair;
                WHEN 'array' THEN
                    SELECT '[' || COALESCE(string_agg(
                        public.saas_canonical_json_v1(element.value),
                        ',' ORDER BY element.ordinality
                    ), '') || ']'
                    INTO canonical
                    FROM jsonb_array_elements(value)
                        WITH ORDINALITY AS element(value, ordinality);
                WHEN 'string' THEN
                    IF octet_length(value #>> '{}') <> length(value #>> '{}') THEN
                        RAISE EXCEPTION 'runner_canonical_json_non_ascii'
                            USING ERRCODE = '22023';
                    END IF;
                    canonical := value::text;
                WHEN 'number' THEN
                    IF value::text !~ '^-?(0|[1-9][0-9]*)$' THEN
                        RAISE EXCEPTION 'runner_canonical_json_non_integer'
                            USING ERRCODE = '22023';
                    END IF;
                    canonical := value::text;
                ELSE
                    canonical := value::text;
            END CASE;
            RETURN canonical;
        END
        $function$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION public.saas_canonical_json_v1(jsonb) FROM PUBLIC")
    op.execute(
        """
        CREATE FUNCTION public.saas_canonical_json_sha256_v1(value jsonb)
        RETURNS text
        LANGUAGE sql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
            SELECT encode(sha256(convert_to(
                public.saas_canonical_json_v1(value), 'UTF8'
            )), 'hex')
        $function$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION public.saas_canonical_json_sha256_v1(jsonb) FROM PUBLIC")
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_worktree_authority_live_v1(
            expected_capability_hash text,
            expected_runner_id uuid,
            expected_run_id uuid,
            expected_change_set_id uuid,
            expected_access_mode text,
            expected_run_fence_token bigint,
            allow_terminal_run boolean
        ) RETURNS boolean
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
            SELECT EXISTS (
                SELECT 1
                FROM public.saas_runner_registrations AS runner
                JOIN public.saas_capability_tokens AS capability
                  ON capability.runner_id = runner.id
                 AND capability.run_id = expected_run_id
                 AND capability.runner_connection_generation =
                     runner.connection_generation
                 AND capability.fence_token = expected_run_fence_token
                JOIN public.saas_runs AS run ON run.id = capability.run_id
                JOIN public.saas_run_dispatches AS dispatch
                  ON dispatch.run_id = run.id
                JOIN public.saas_changesets AS change_set
                  ON change_set.id = expected_change_set_id
                WHERE runner.id = expected_runner_id
                  AND runner.status IN ('online', 'draining')
                  AND session_user::text = 'runner_' ||
                      replace(runner.id::text, '-', '') || '_g' ||
                      runner.connection_generation::text
                  AND (expected_capability_hash IS NULL OR
                       capability.token_hash = expected_capability_hash)
                  AND capability.revoked_at IS NULL
                  AND capability.expires_at > clock_timestamp()
                  AND capability.resource_scope ->> 'change_set_id' =
                      expected_change_set_id::text
                  AND (capability.allowed_actions)::jsonb ? CASE
                      WHEN expected_access_mode = 'writer' THEN 'worktree.write'
                      ELSE 'worktree.read' END
                  AND run.tenant_id = capability.tenant_id
                  AND run.space_id = capability.space_id
                  AND run.project_id = capability.project_id
                  AND run.fence_token = expected_run_fence_token
                  AND (
                      (allow_terminal_run AND run.status IN (
                          'queued', 'succeeded', 'failed', 'cancelled',
                          'timed_out', 'orphaned'
                      )) OR (
                          NOT allow_terminal_run
                          AND run.status IN (
                              'leased', 'starting', 'running', 'waiting_input',
                              'waiting_approval', 'cancelling'
                          )
                          AND run.lease_owner = expected_runner_id::text
                          AND run.lease_token IS NOT NULL
                          AND run.lease_expires_at IS NOT NULL
                          AND run.lease_expires_at > clock_timestamp()
                      )
                  )
                  AND dispatch.status = 'leased'
                  AND dispatch.selected_runner_id = expected_runner_id
                  AND dispatch.dispatch_generation =
                      capability.dispatch_generation
                  AND change_set.tenant_id = run.tenant_id
                  AND change_set.space_id = run.space_id
                  AND change_set.project_id = run.project_id
                  AND change_set.status IN ('open', 'checkpointed', 'committed')
                  AND (expected_access_mode <> 'writer' OR
                       change_set.status <> 'committed')
                  AND (NOT ((capability.allowed_actions)::jsonb ? 'preview.serve') OR
                       (expected_access_mode = 'readonly'
                        AND change_set.status = 'committed'
                        AND change_set.head_revision IS NOT NULL
                        AND change_set.recovery_artifact_ref IS NOT NULL))
            )
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "public.saas_runner_worktree_authority_live_v1("
        "text,uuid,uuid,uuid,text,bigint,boolean) FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_append_worktree_event_v1(
            expected_worktree_id uuid,
            expected_event_type text,
            expected_payload jsonb,
            expected_trace_id text
        ) RETURNS bigint
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            selected_worktree public.saas_worktree_instances%ROWTYPE;
            next_sequence bigint;
            outbox_payload jsonb;
            database_now timestamptz := clock_timestamp();
        BEGIN
            IF expected_worktree_id IS NULL
               OR expected_event_type NOT IN (
                    'worktree.created', 'worktree.rebuilt',
                    'worktree.materializing', 'worktree.mounted',
                    'worktree.checkpointed', 'worktree.released',
                    'worktree.rebuild.source_consumed'
               )
               OR expected_payload IS NULL
               OR length(expected_trace_id) NOT BETWEEN 1 AND 128 THEN
                RAISE EXCEPTION 'runner_worktree_event_invalid'
                    USING ERRCODE = '22023';
            END IF;
            UPDATE public.saas_worktree_instances AS mutated
            SET event_sequence = mutated.event_sequence + 1,
                updated_at = database_now
            WHERE mutated.id = expected_worktree_id
            RETURNING mutated.* INTO selected_worktree;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'runner_worktree_not_found'
                    USING ERRCODE = 'P0002';
            END IF;
            next_sequence := selected_worktree.event_sequence;
            INSERT INTO public.saas_worktree_events (
                id, tenant_id, space_id, project_id, worktree_id,
                sequence, event_type, payload, trace_id, created_at
            ) VALUES (
                gen_random_uuid(), selected_worktree.tenant_id,
                selected_worktree.space_id, selected_worktree.project_id,
                selected_worktree.id, next_sequence, expected_event_type,
                expected_payload, expected_trace_id, database_now
            );
            outbox_payload := jsonb_build_object(
                'worktree_id', selected_worktree.id::text,
                'sequence', next_sequence,
                'status', selected_worktree.status
            ) || expected_payload;
            INSERT INTO public.saas_control_plane_outbox (
                id, tenant_id, aggregate_type, aggregate_key, event_type,
                payload, idempotency_key, request_hash, attempt_count,
                available_at, claimed_at, claim_token, published_at, created_at
            ) VALUES (
                gen_random_uuid(), selected_worktree.tenant_id,
                'WorktreeInstance', selected_worktree.id::text,
                expected_event_type, outbox_payload,
                'worktree:' || selected_worktree.id::text || ':' || next_sequence::text,
                public.saas_canonical_json_sha256_v1(outbox_payload),
                0, database_now, NULL, NULL, NULL, database_now
            );
            RETURN next_sequence;
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_append_worktree_event_v1("
        "uuid,text,jsonb,text) FROM PUBLIC"
    )

    op.execute(
        """
        CREATE FUNCTION public.saas_runner_allocate_worktree_v1(
            expected_capability_hash text,
            expected_runner_id uuid,
            expected_run_id uuid,
            expected_change_set_id uuid,
            requested_worktree_id uuid,
            requested_access_mode text,
            requested_reserved_bytes bigint,
            requested_lease_seconds integer,
            requested_lease_hash text,
            requested_trace_id text,
            requested_rebuild_from_id uuid
        ) RETURNS TABLE (
            worktree_id uuid,
            change_set_id uuid,
            run_id uuid,
            runner_id uuid,
            opaque_runtime_key text,
            access_mode text,
            lease_generation bigint,
            run_fence_token bigint,
            runner_connection_generation bigint,
            lease_expires_at timestamptz,
            replayed boolean
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            selected_runner public.saas_runner_registrations%ROWTYPE;
            selected_capability public.saas_capability_tokens%ROWTYPE;
            selected_dispatch public.saas_run_dispatches%ROWTYPE;
            selected_run public.saas_runs%ROWTYPE;
            selected_change_set public.saas_changesets%ROWTYPE;
            selected_source public.saas_worktree_instances%ROWTYPE;
            existing_worktree public.saas_worktree_instances%ROWTYPE;
            selected_quota public.saas_worktree_quotas%ROWTYPE;
            created_worktree public.saas_worktree_instances%ROWTYPE;
            required_action text;
            computed_expiry timestamptz;
            computed_maximum_lifetime timestamptz;
            recovery_ref text;
            environment_ref text;
            initial_event text;
            database_now timestamptz := clock_timestamp();
            generated_runtime_key text;
            allocation_request_hash text;
            existing_request_hash text;
        BEGIN
            IF expected_runner_id IS NULL
               OR expected_run_id IS NULL OR expected_change_set_id IS NULL
               OR requested_worktree_id IS NULL
               OR expected_capability_hash !~ '^[0-9a-f]{64}$'
               OR requested_lease_hash !~ '^[0-9a-f]{64}$'
               OR requested_access_mode NOT IN ('writer', 'readonly')
               OR requested_reserved_bytes <= 0
               OR requested_lease_seconds <= 0
               OR length(requested_trace_id) NOT BETWEEN 1 AND 128 THEN
                RAISE EXCEPTION 'runner_worktree_allocation_invalid'
                    USING ERRCODE = '22023';
            END IF;
            required_action := CASE requested_access_mode
                WHEN 'writer' THEN 'worktree.write' ELSE 'worktree.read' END;
            SELECT candidate.* INTO selected_runner
            FROM public.saas_runner_registrations AS candidate
            WHERE candidate.id = expected_runner_id;
            IF NOT FOUND
               OR selected_runner.status NOT IN ('online', 'draining')
               OR session_user::text <> 'runner_' ||
                    replace(expected_runner_id::text, '-', '') || '_g' ||
                    selected_runner.connection_generation::text THEN
                RAISE EXCEPTION 'runner_worktree_runner_stale'
                    USING ERRCODE = '42501';
            END IF;

            SELECT candidate.* INTO selected_capability
            FROM public.saas_capability_tokens AS candidate
            WHERE candidate.token_hash = expected_capability_hash
              AND candidate.run_id = expected_run_id
              AND candidate.runner_id = expected_runner_id;
            IF NOT FOUND
               OR selected_capability.token_hash <> expected_capability_hash
               OR selected_capability.revoked_at IS NOT NULL
               OR selected_capability.expires_at <= database_now
               OR selected_capability.run_id <> expected_run_id
               OR selected_capability.runner_id <> expected_runner_id
               OR selected_capability.runner_connection_generation <>
                    selected_runner.connection_generation
               OR NOT ((selected_capability.allowed_actions)::jsonb ? required_action)
               OR selected_capability.resource_scope ->> 'change_set_id' <>
                    expected_change_set_id::text THEN
                RAISE EXCEPTION 'runner_worktree_capability_stale'
                    USING ERRCODE = '42501';
            END IF;
            allocation_request_hash := encode(sha256(convert_to(concat_ws('|',
                selected_capability.id::text, expected_runner_id::text,
                expected_run_id::text, expected_change_set_id::text,
                requested_worktree_id::text, requested_access_mode,
                requested_reserved_bytes::text, requested_lease_seconds::text,
                requested_lease_hash,
                COALESCE(requested_rebuild_from_id::text, '')
            ), 'UTF8')), 'hex');

            SELECT candidate.* INTO selected_run
            FROM public.saas_runs AS candidate
            WHERE candidate.id = expected_run_id;
            IF NOT FOUND
               OR selected_run.tenant_id <> selected_capability.tenant_id
               OR selected_run.space_id <> selected_capability.space_id
               OR selected_run.project_id <> selected_capability.project_id
               OR selected_run.status NOT IN (
                    'leased', 'starting', 'running', 'waiting_input',
                    'waiting_approval', 'cancelling'
               )
               OR selected_run.fence_token <> selected_capability.fence_token
               OR selected_run.lease_owner <> expected_runner_id::text
               OR selected_run.lease_token IS NULL
               OR selected_run.lease_expires_at IS NULL
               OR selected_run.lease_expires_at <= database_now THEN
                RAISE EXCEPTION 'runner_worktree_run_stale'
                    USING ERRCODE = '42501';
            END IF;

            SELECT candidate.* INTO selected_dispatch
            FROM public.saas_run_dispatches AS candidate
            WHERE candidate.run_id = expected_run_id;
            IF NOT FOUND OR selected_dispatch.status <> 'leased'
               OR selected_dispatch.selected_runner_id <> expected_runner_id
               OR selected_dispatch.dispatch_generation <>
                    selected_capability.dispatch_generation THEN
                RAISE EXCEPTION 'runner_worktree_dispatch_stale'
                    USING ERRCODE = '42501';
            END IF;

            SELECT candidate.* INTO selected_change_set
            FROM public.saas_changesets AS candidate
            WHERE candidate.id = expected_change_set_id;
            IF NOT FOUND
               OR selected_change_set.tenant_id <> selected_run.tenant_id
               OR selected_change_set.space_id <> selected_run.space_id
               OR selected_change_set.project_id <> selected_run.project_id
               OR selected_change_set.status NOT IN ('open', 'checkpointed', 'committed')
               OR (selected_change_set.status = 'committed'
                   AND requested_access_mode <> 'readonly')
               OR (selected_change_set.status = 'committed'
                   AND (selected_change_set.head_revision IS NULL
                        OR selected_change_set.recovery_artifact_ref IS NULL))
               OR (requested_access_mode = 'readonly'
                   AND (selected_capability.allowed_actions)::jsonb ? 'preview.serve'
                   AND (selected_change_set.status <> 'committed'
                        OR selected_change_set.head_revision IS NULL
                        OR selected_change_set.recovery_artifact_ref IS NULL)) THEN
                RAISE EXCEPTION 'runner_worktree_changeset_stale'
                    USING ERRCODE = '42501';
            END IF;

            SELECT candidate.* INTO existing_worktree
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.run_id = expected_run_id
              AND candidate.run_fence_token = selected_run.fence_token
            FOR UPDATE;
            IF FOUND THEN
                database_now := clock_timestamp();
                IF NOT public.saas_runner_worktree_authority_live_v1(
                    expected_capability_hash, expected_runner_id, expected_run_id,
                    expected_change_set_id, requested_access_mode,
                    selected_run.fence_token, false
                ) THEN
                    RAISE EXCEPTION 'runner_worktree_capability_stale'
                        USING ERRCODE = '42501';
                END IF;
                SELECT event.payload ->> 'allocation_request_hash'
                INTO existing_request_hash
                FROM public.saas_worktree_events AS event
                WHERE event.worktree_id = existing_worktree.id
                  AND event.sequence = 1;
                IF existing_worktree.id = requested_worktree_id
                   AND existing_worktree.runner_id = expected_runner_id
                   AND existing_worktree.runner_connection_generation =
                        selected_runner.connection_generation
                   AND existing_worktree.change_set_id = expected_change_set_id
                   AND existing_worktree.access_mode = requested_access_mode
                   AND existing_worktree.reserved_bytes = requested_reserved_bytes
                   AND existing_worktree.lease_token_hash = requested_lease_hash
                   AND existing_request_hash = allocation_request_hash
                   AND existing_worktree.status IN (
                       'reserved', 'materializing', 'ready', 'checkpointing'
                   )
                   AND existing_worktree.lease_expires_at > database_now
                   AND existing_worktree.maximum_lifetime_at > database_now THEN
                    RETURN QUERY SELECT existing_worktree.id,
                        existing_worktree.change_set_id, existing_worktree.run_id,
                        existing_worktree.runner_id,
                        existing_worktree.opaque_runtime_key::text,
                        existing_worktree.access_mode::text,
                        existing_worktree.lease_generation,
                        existing_worktree.run_fence_token,
                        existing_worktree.runner_connection_generation,
                        existing_worktree.lease_expires_at, true;
                    RETURN;
                END IF;
                RAISE EXCEPTION 'runner_worktree_run_already_allocated'
                    USING ERRCODE = '23505';
            END IF;

            IF requested_rebuild_from_id IS NOT NULL THEN
                IF requested_access_mode <> 'writer' THEN
                    RAISE EXCEPTION 'runner_worktree_rebuild_requires_writer'
                        USING ERRCODE = '42501';
                END IF;
                SELECT candidate.* INTO selected_source
                FROM public.saas_worktree_instances AS candidate
                WHERE candidate.id = requested_rebuild_from_id
                FOR UPDATE;
                IF NOT FOUND
                   OR selected_source.change_set_id <> expected_change_set_id
                   OR selected_source.access_mode <> 'writer'
                   OR NOT selected_source.dirty
                   OR selected_source.status <> 'rebuild_pending'
                   OR selected_source.recovery_artifact_ref IS NULL THEN
                    RAISE EXCEPTION 'runner_worktree_rebuild_source_invalid'
                        USING ERRCODE = '42501';
                END IF;
            END IF;

            SELECT candidate.* INTO selected_quota
            FROM public.saas_worktree_quotas AS candidate
            WHERE candidate.tenant_id = selected_change_set.tenant_id
              AND candidate.space_id = selected_change_set.space_id
              AND candidate.project_id = selected_change_set.project_id
            FOR UPDATE;
            IF NOT FOUND OR requested_lease_seconds > selected_quota.max_lease_seconds
               OR selected_quota.active_instances >= selected_quota.max_active_instances
               OR (requested_access_mode = 'writer'
                   AND selected_quota.active_writers >= selected_quota.max_active_writers)
               OR selected_quota.reserved_bytes + requested_reserved_bytes >
                    selected_quota.max_reserved_bytes THEN
                RAISE EXCEPTION 'runner_worktree_quota_exceeded'
                    USING ERRCODE = '54000';
            END IF;
            IF requested_access_mode = 'writer' AND EXISTS (
                SELECT 1 FROM public.saas_worktree_instances AS candidate
                WHERE candidate.change_set_id = expected_change_set_id
                  AND candidate.access_mode = 'writer'
                  AND candidate.status IN ('reserved', 'materializing', 'ready', 'checkpointing')
            ) THEN
                RAISE EXCEPTION 'runner_worktree_writer_conflict'
                    USING ERRCODE = '23505';
            END IF;
            IF requested_access_mode = 'writer'
               AND requested_rebuild_from_id IS NULL
               AND EXISTS (
                    SELECT 1 FROM public.saas_worktree_instances AS candidate
                    WHERE candidate.change_set_id = expected_change_set_id
                      AND candidate.access_mode = 'writer'
                      AND candidate.status = 'rebuild_pending'
               ) THEN
                RAISE EXCEPTION 'runner_worktree_rebuild_source_required'
                    USING ERRCODE = '42501';
            END IF;

            database_now := clock_timestamp();
            IF NOT public.saas_runner_worktree_authority_live_v1(
                expected_capability_hash, expected_runner_id, expected_run_id,
                expected_change_set_id, requested_access_mode,
                selected_run.fence_token, false
            ) THEN
                RAISE EXCEPTION 'runner_worktree_capability_stale'
                    USING ERRCODE = '42501';
            END IF;

            computed_expiry := LEAST(
                database_now + make_interval(secs => requested_lease_seconds),
                selected_capability.expires_at,
                selected_run.lease_expires_at
            );
            computed_maximum_lifetime := database_now +
                make_interval(secs => selected_quota.max_lifetime_seconds);
            IF computed_expiry <= database_now THEN
                RAISE EXCEPTION 'runner_worktree_capability_expired'
                    USING ERRCODE = '42501';
            END IF;
            recovery_ref := CASE
                WHEN selected_change_set.status IN ('checkpointed', 'committed')
                THEN selected_change_set.recovery_artifact_ref ELSE NULL END;
            environment_ref := NULL;
            initial_event := 'worktree.created';
            generated_runtime_key := 'wti_' || substring(
                replace(gen_random_uuid()::text, '-', '') ||
                replace(gen_random_uuid()::text, '-', '') FROM 1 FOR 48
            );
            IF requested_rebuild_from_id IS NOT NULL THEN
                recovery_ref := selected_source.recovery_artifact_ref;
                environment_ref := selected_source.environment_snapshot_ref;
                UPDATE public.saas_worktree_instances AS source
                SET status = 'released', released_at = database_now,
                    updated_at = database_now
                WHERE source.id = selected_source.id;
                PERFORM public.saas_runner_append_worktree_event_v1(
                    selected_source.id, 'worktree.rebuild.source_consumed',
                    jsonb_build_object(
                        'replacement_worktree_id', requested_worktree_id::text
                    ), requested_trace_id
                );
                initial_event := 'worktree.rebuilt';
            END IF;

            UPDATE public.saas_worktree_quotas AS quota
            SET active_instances = quota.active_instances + 1,
                active_writers = quota.active_writers +
                    CASE WHEN requested_access_mode = 'writer' THEN 1 ELSE 0 END,
                reserved_bytes = quota.reserved_bytes + requested_reserved_bytes,
                version = quota.version + 1,
                updated_at = database_now
            WHERE quota.id = selected_quota.id;
            INSERT INTO public.saas_worktree_instances (
                id, tenant_id, space_id, project_id, change_set_id, run_id,
                runner_id, created_by, created_by_service_account_id,
                opaque_runtime_key, access_mode, status, lease_generation,
                run_fence_token, runner_connection_generation, lease_token_hash,
                lease_expires_at, heartbeat_at, maximum_lifetime_at,
                reserved_bytes, actual_bytes, dirty, recovery_artifact_ref,
                environment_snapshot_ref, event_sequence, released_at,
                quarantine_reason, deleted_at, created_at, updated_at
            ) VALUES (
                requested_worktree_id, selected_change_set.tenant_id,
                selected_change_set.space_id, selected_change_set.project_id,
                selected_change_set.id, selected_run.id, selected_runner.id,
                selected_run.created_by, selected_run.created_by_service_account_id,
                generated_runtime_key, requested_access_mode, 'reserved', 1,
                selected_run.fence_token, selected_runner.connection_generation,
                requested_lease_hash, computed_expiry, database_now,
                computed_maximum_lifetime, requested_reserved_bytes, 0, false,
                recovery_ref, environment_ref, 0, NULL, NULL, NULL,
                database_now, database_now
            ) RETURNING * INTO created_worktree;
            PERFORM public.saas_runner_append_worktree_event_v1(
                created_worktree.id, initial_event,
                jsonb_build_object(
                    'change_set_id', selected_change_set.id::text,
                    'run_id', selected_run.id::text,
                    'runner_id', selected_runner.id::text,
                    'access_mode', requested_access_mode,
                    'lease_generation', 1,
                    'run_fence_token', selected_run.fence_token,
                    'rebuild_from_id', requested_rebuild_from_id::text,
                    'capability_id', selected_capability.id::text,
                    'requested_lease_seconds', requested_lease_seconds,
                    'allocation_request_hash', allocation_request_hash
                ), requested_trace_id
            );
            RETURN QUERY SELECT created_worktree.id,
                created_worktree.change_set_id, created_worktree.run_id,
                created_worktree.runner_id, created_worktree.opaque_runtime_key::text,
                created_worktree.access_mode::text,
                created_worktree.lease_generation,
                created_worktree.run_fence_token,
                created_worktree.runner_connection_generation,
                created_worktree.lease_expires_at, false;
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_allocate_worktree_v1("
        "text,uuid,uuid,uuid,uuid,text,bigint,integer,text,text,uuid) "
        "FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_transition_worktree_v1(
            requested_operation text,
            expected_worktree_id uuid,
            expected_runner_id uuid,
            expected_lease_generation bigint,
            expected_run_fence_token bigint,
            expected_lease_hash text,
            requested_actual_bytes bigint,
            requested_dirty boolean,
            requested_lease_seconds integer,
            requested_head_revision text,
            requested_recovery_artifact_ref text,
            requested_environment_snapshot_ref text,
            requested_final_change_set_status text,
            requested_trace_id text
        ) RETURNS TABLE (
            worktree_id uuid,
            status text,
            lease_generation bigint,
            lease_expires_at timestamptz,
            actual_bytes bigint,
            dirty boolean,
            recovery_artifact_ref text,
            environment_snapshot_ref text,
            event_sequence bigint,
            replayed boolean
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            discovered public.saas_worktree_instances%ROWTYPE;
            selected_runner public.saas_runner_registrations%ROWTYPE;
            selected_capability public.saas_capability_tokens%ROWTYPE;
            selected_run public.saas_runs%ROWTYPE;
            selected_dispatch public.saas_run_dispatches%ROWTYPE;
            selected_change_set public.saas_changesets%ROWTYPE;
            selected_worktree public.saas_worktree_instances%ROWTYPE;
            selected_quota public.saas_worktree_quotas%ROWTYPE;
            selected_group public.saas_changeset_groups%ROWTYPE;
            required_action text;
            computed_expiry timestamptz;
            child_statuses text[];
            target_group_status text;
            database_now timestamptz := statement_timestamp();
            derived_final_change_set_status text;
            release_request_hash text;
            existing_release_request_hash text;
            checkpoint_event_count bigint;
            existing_checkpoint_payload jsonb;
            requested_checkpoint_payload jsonb;
        BEGIN
            IF requested_operation NOT IN (
                    'begin_materialization', 'acknowledge_ready', 'heartbeat',
                    'checkpoint', 'release'
               )
               OR expected_worktree_id IS NULL OR expected_runner_id IS NULL
               OR expected_lease_generation <= 0 OR expected_run_fence_token <= 0
               OR expected_lease_hash !~ '^[0-9a-f]{64}$'
               OR (requested_operation <> 'heartbeat'
                   AND length(requested_trace_id) NOT BETWEEN 1 AND 128) THEN
                RAISE EXCEPTION 'runner_worktree_transition_invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT candidate.* INTO discovered
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.id = expected_worktree_id;
            IF NOT FOUND OR discovered.runner_id <> expected_runner_id
               OR discovered.run_fence_token <> expected_run_fence_token THEN
                RAISE EXCEPTION 'runner_worktree_lease_stale'
                    USING ERRCODE = '42501';
            END IF;
            required_action := CASE discovered.access_mode
                WHEN 'writer' THEN 'worktree.write' ELSE 'worktree.read' END;

            SELECT candidate.* INTO selected_runner
            FROM public.saas_runner_registrations AS candidate
            WHERE candidate.id = expected_runner_id;
            IF NOT FOUND OR selected_runner.status NOT IN ('online', 'draining')
               OR selected_runner.connection_generation <>
                    discovered.runner_connection_generation
               OR session_user::text <> 'runner_' ||
                    replace(expected_runner_id::text, '-', '') || '_g' ||
                    selected_runner.connection_generation::text THEN
                RAISE EXCEPTION 'runner_worktree_runner_stale'
                    USING ERRCODE = '42501';
            END IF;

            SELECT candidate.* INTO selected_capability
            FROM public.saas_capability_tokens AS candidate
            WHERE candidate.run_id = discovered.run_id
              AND candidate.runner_id = expected_runner_id
              AND candidate.runner_connection_generation =
                    discovered.runner_connection_generation
              AND candidate.fence_token = expected_run_fence_token
              AND candidate.resource_scope ->> 'change_set_id' =
                    discovered.change_set_id::text
              AND candidate.revoked_at IS NULL
              AND candidate.expires_at > database_now
              AND (candidate.allowed_actions)::jsonb ? required_action
            ORDER BY candidate.id
            LIMIT 1;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'runner_worktree_capability_stale'
                    USING ERRCODE = '42501';
            END IF;

            SELECT candidate.* INTO selected_run
            FROM public.saas_runs AS candidate
            WHERE candidate.id = discovered.run_id;
            IF NOT FOUND OR selected_run.fence_token <> expected_run_fence_token
               OR selected_run.tenant_id <> discovered.tenant_id
               OR selected_run.space_id <> discovered.space_id
               OR selected_run.project_id <> discovered.project_id THEN
                RAISE EXCEPTION 'runner_worktree_run_stale'
                    USING ERRCODE = '42501';
            END IF;
            IF requested_operation <> 'release' AND (
                selected_run.status NOT IN (
                    'leased', 'starting', 'running', 'waiting_input',
                    'waiting_approval', 'cancelling'
                ) OR selected_run.lease_owner <> expected_runner_id::text
                OR selected_run.lease_token IS NULL
                OR selected_run.lease_expires_at IS NULL
                OR selected_run.lease_expires_at <= database_now
            ) THEN
                RAISE EXCEPTION 'runner_worktree_run_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_dispatch
            FROM public.saas_run_dispatches AS candidate
            WHERE candidate.run_id = discovered.run_id;
            IF NOT FOUND OR selected_dispatch.status <> 'leased'
               OR selected_dispatch.selected_runner_id <> expected_runner_id
               OR selected_dispatch.dispatch_generation <>
                    selected_capability.dispatch_generation THEN
                RAISE EXCEPTION 'runner_worktree_dispatch_stale'
                    USING ERRCODE = '42501';
            END IF;

            SELECT candidate.* INTO selected_change_set
            FROM public.saas_changesets AS candidate
            WHERE candidate.id = discovered.change_set_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'runner_worktree_changeset_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_worktree
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.id = expected_worktree_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'runner_worktree_lease_stale'
                    USING ERRCODE = '42501';
            END IF;
            release_request_hash := encode(sha256(convert_to(concat_ws('|',
                expected_worktree_id::text, expected_runner_id::text,
                expected_lease_generation::text, expected_run_fence_token::text,
                expected_lease_hash
            ), 'UTF8')), 'hex');
            IF requested_operation = 'release'
               AND selected_worktree.status = 'released'
               AND selected_worktree.lease_generation = expected_lease_generation + 1
               AND selected_worktree.runner_id = expected_runner_id
               AND selected_worktree.runner_connection_generation =
                    selected_runner.connection_generation
               AND selected_worktree.run_fence_token = expected_run_fence_token THEN
                SELECT event.payload ->> 'release_request_hash'
                INTO existing_release_request_hash
                FROM public.saas_worktree_events AS event
                WHERE event.worktree_id = selected_worktree.id
                  AND event.event_type = 'worktree.released'
                ORDER BY event.sequence DESC
                LIMIT 1;
                IF existing_release_request_hash <> release_request_hash THEN
                    RAISE EXCEPTION 'runner_worktree_release_replay_mismatch'
                        USING ERRCODE = '42501';
                END IF;
                RETURN QUERY SELECT selected_worktree.id,
                    selected_worktree.status::text,
                    selected_worktree.lease_generation,
                    selected_worktree.lease_expires_at,
                    selected_worktree.actual_bytes, selected_worktree.dirty,
                    selected_worktree.recovery_artifact_ref::text,
                    selected_worktree.environment_snapshot_ref::text,
                    selected_worktree.event_sequence, true;
                RETURN;
            END IF;
            IF selected_worktree.status NOT IN (
                    'reserved', 'materializing', 'ready', 'checkpointing'
               )
               OR selected_worktree.runner_id <> expected_runner_id
               OR selected_worktree.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_worktree.run_id <> selected_run.id
               OR selected_worktree.change_set_id <> selected_change_set.id
               OR selected_worktree.lease_generation <> expected_lease_generation
               OR selected_worktree.run_fence_token <> expected_run_fence_token
               OR selected_worktree.lease_token_hash <> expected_lease_hash
               OR selected_worktree.lease_expires_at IS NULL
               OR selected_worktree.lease_expires_at <= database_now
               OR selected_worktree.maximum_lifetime_at <= database_now THEN
                RAISE EXCEPTION 'runner_worktree_lease_stale'
                    USING ERRCODE = '42501';
            END IF;
            database_now := clock_timestamp();
            IF NOT public.saas_runner_worktree_authority_live_v1(
                NULL, expected_runner_id, selected_worktree.run_id,
                selected_worktree.change_set_id, selected_worktree.access_mode,
                expected_run_fence_token, requested_operation = 'release'
            ) OR (requested_operation <> 'release' AND (
                selected_worktree.lease_expires_at <= database_now
                OR selected_worktree.maximum_lifetime_at <= database_now
            )) THEN
                RAISE EXCEPTION 'runner_worktree_capability_stale'
                    USING ERRCODE = '42501';
            END IF;

            IF requested_operation = 'begin_materialization' THEN
                IF selected_worktree.status IN ('materializing', 'ready') THEN
                    NULL;
                ELSIF selected_worktree.status = 'reserved' THEN
                    UPDATE public.saas_worktree_instances AS mutated
                    SET status = 'materializing', updated_at = database_now
                    WHERE mutated.id = selected_worktree.id;
                    PERFORM public.saas_runner_append_worktree_event_v1(
                        selected_worktree.id, 'worktree.materializing',
                        jsonb_build_object(
                            'lease_generation', selected_worktree.lease_generation
                        ), requested_trace_id
                    );
                ELSE
                    RAISE EXCEPTION 'runner_worktree_transition_invalid'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF requested_operation = 'acknowledge_ready' THEN
                IF requested_actual_bytes IS NULL OR requested_actual_bytes < 0
                   OR requested_actual_bytes > selected_worktree.reserved_bytes THEN
                    RAISE EXCEPTION 'runner_worktree_size_invalid'
                        USING ERRCODE = '22023';
                END IF;
                IF selected_worktree.status = 'ready'
                   AND selected_worktree.actual_bytes = requested_actual_bytes THEN
                    NULL;
                ELSIF selected_worktree.status = 'ready' THEN
                    RAISE EXCEPTION 'runner_worktree_ready_replay_mismatch'
                        USING ERRCODE = '55000';
                ELSIF selected_worktree.status = 'materializing' THEN
                    UPDATE public.saas_worktree_instances AS mutated
                    SET status = 'ready', actual_bytes = requested_actual_bytes,
                        heartbeat_at = database_now, updated_at = database_now
                    WHERE mutated.id = selected_worktree.id;
                    PERFORM public.saas_runner_append_worktree_event_v1(
                        selected_worktree.id, 'worktree.mounted',
                        jsonb_build_object('actual_bytes', requested_actual_bytes),
                        requested_trace_id
                    );
                ELSE
                    RAISE EXCEPTION 'runner_worktree_transition_invalid'
                        USING ERRCODE = '55000';
                END IF;
            ELSIF requested_operation = 'heartbeat' THEN
                IF requested_actual_bytes IS NULL OR requested_actual_bytes < 0
                   OR requested_actual_bytes > selected_worktree.reserved_bytes
                   OR requested_dirty IS NULL
                   OR (requested_dirty AND selected_worktree.access_mode <> 'writer')
                   OR (requested_lease_seconds IS NOT NULL
                       AND requested_lease_seconds <= 0) THEN
                    RAISE EXCEPTION 'runner_worktree_heartbeat_invalid'
                        USING ERRCODE = '22023';
                END IF;
                -- The database, not the caller, bounds persistent heartbeat
                -- amplification.  Calls inside the one-second write window are
                -- strict no-ops even when the caller toggles mutable payload.
                IF selected_worktree.heartbeat_at IS NULL
                   OR selected_worktree.heartbeat_at <= database_now - interval '2 seconds' THEN
                    computed_expiry := selected_worktree.lease_expires_at;
                    IF requested_lease_seconds IS NOT NULL THEN
                        SELECT candidate.* INTO selected_quota
                        FROM public.saas_worktree_quotas AS candidate
                        WHERE candidate.tenant_id = selected_worktree.tenant_id
                          AND candidate.space_id = selected_worktree.space_id
                          AND candidate.project_id = selected_worktree.project_id
                        FOR UPDATE;
                        IF NOT FOUND
                           OR requested_lease_seconds > selected_quota.max_lease_seconds THEN
                            RAISE EXCEPTION 'runner_worktree_lease_too_long'
                                USING ERRCODE = '22023';
                        END IF;
                        database_now := clock_timestamp();
                        IF NOT public.saas_runner_worktree_authority_live_v1(
                            NULL, expected_runner_id, selected_worktree.run_id,
                            selected_worktree.change_set_id,
                            selected_worktree.access_mode,
                            expected_run_fence_token, false
                        ) OR selected_worktree.lease_expires_at <= database_now
                           OR selected_worktree.maximum_lifetime_at <= database_now THEN
                            RAISE EXCEPTION 'runner_worktree_capability_stale'
                                USING ERRCODE = '42501';
                        END IF;
                        computed_expiry := LEAST(
                            GREATEST(
                                selected_worktree.lease_expires_at,
                                database_now + make_interval(
                                    secs => requested_lease_seconds
                                )
                            ),
                            selected_run.lease_expires_at,
                            selected_worktree.maximum_lifetime_at
                        );
                        IF computed_expiry <= database_now THEN
                            RAISE EXCEPTION 'runner_worktree_lease_stale'
                                USING ERRCODE = '42501';
                        END IF;
                    END IF;
                    UPDATE public.saas_worktree_instances AS mutated
                    SET actual_bytes = requested_actual_bytes,
                        dirty = requested_dirty,
                        heartbeat_at = database_now,
                        lease_expires_at = computed_expiry,
                        updated_at = database_now
                    WHERE mutated.id = selected_worktree.id;
                END IF;
            ELSIF requested_operation = 'checkpoint' THEN
                IF selected_worktree.status <> 'ready'
                   OR selected_worktree.access_mode <> 'writer'
                   OR selected_change_set.status NOT IN ('open', 'checkpointed')
                   OR length(requested_head_revision) NOT BETWEEN 1 AND 128
                   OR length(requested_recovery_artifact_ref) NOT BETWEEN 1 AND 256
                   OR length(requested_environment_snapshot_ref) NOT BETWEEN 1 AND 256
                   OR requested_dirty IS DISTINCT FROM false THEN
                    RAISE EXCEPTION 'runner_worktree_checkpoint_denied'
                        USING ERRCODE = '42501';
                END IF;
                requested_checkpoint_payload := jsonb_build_object(
                    'head_revision', requested_head_revision,
                    'recovery_artifact_ref', requested_recovery_artifact_ref,
                    'environment_snapshot_ref', requested_environment_snapshot_ref,
                    'dirty_after', requested_dirty
                );
                SELECT count(*), (array_agg(event.payload ORDER BY event.sequence DESC))[1]
                INTO checkpoint_event_count, existing_checkpoint_payload
                FROM public.saas_worktree_events AS event
                WHERE event.worktree_id = selected_worktree.id
                  AND event.event_type = 'worktree.checkpointed';
                IF checkpoint_event_count > 1 THEN
                    RAISE EXCEPTION 'runner_worktree_checkpoint_inconsistent'
                        USING ERRCODE = '55000';
                ELSIF checkpoint_event_count = 1
                   AND existing_checkpoint_payload = requested_checkpoint_payload
                   AND selected_change_set.head_revision = requested_head_revision
                   AND selected_change_set.recovery_artifact_ref =
                       requested_recovery_artifact_ref
                   AND selected_change_set.status = 'checkpointed'
                   AND selected_worktree.recovery_artifact_ref =
                       requested_recovery_artifact_ref
                   AND selected_worktree.environment_snapshot_ref =
                       requested_environment_snapshot_ref
                   AND NOT selected_worktree.dirty THEN
                    NULL;
                ELSIF checkpoint_event_count = 1 THEN
                    RAISE EXCEPTION 'runner_worktree_checkpoint_replay_mismatch'
                        USING ERRCODE = '55000';
                ELSE
                    UPDATE public.saas_changesets AS mutated
                    SET head_revision = requested_head_revision,
                        recovery_artifact_ref = requested_recovery_artifact_ref,
                        status = 'checkpointed', version = mutated.version + 1,
                        updated_at = database_now
                    WHERE mutated.id = selected_change_set.id;
                    UPDATE public.saas_worktree_instances AS mutated
                    SET recovery_artifact_ref = requested_recovery_artifact_ref,
                        environment_snapshot_ref = requested_environment_snapshot_ref,
                        dirty = requested_dirty, heartbeat_at = database_now,
                        updated_at = database_now
                    WHERE mutated.id = selected_worktree.id;
                    PERFORM public.saas_runner_append_worktree_event_v1(
                        selected_worktree.id, 'worktree.checkpointed',
                        requested_checkpoint_payload, requested_trace_id
                    );
                END IF;
            ELSE
                IF requested_final_change_set_status IS NOT NULL THEN
                    RAISE EXCEPTION 'runner_worktree_final_status_caller_denied'
                        USING ERRCODE = '42501';
                END IF;
                SELECT count(*), (array_agg(event.payload ORDER BY event.sequence DESC))[1]
                INTO checkpoint_event_count, existing_checkpoint_payload
                FROM public.saas_worktree_events AS event
                WHERE event.worktree_id = selected_worktree.id
                  AND event.event_type = 'worktree.checkpointed';
                IF checkpoint_event_count > 1 THEN
                    RAISE EXCEPTION 'runner_worktree_checkpoint_inconsistent'
                        USING ERRCODE = '55000';
                END IF;
                derived_final_change_set_status := CASE
                    WHEN selected_worktree.access_mode <> 'writer' THEN NULL
                    WHEN selected_worktree.recovery_artifact_ref IS NULL
                         OR selected_change_set.head_revision IS NULL
                         OR selected_change_set.recovery_artifact_ref IS NULL THEN NULL
                    WHEN selected_run.status = 'succeeded'
                         AND NOT selected_worktree.dirty
                         AND checkpoint_event_count = 1
                         AND existing_checkpoint_payload ->> 'head_revision' =
                             selected_change_set.head_revision
                         AND existing_checkpoint_payload ->> 'recovery_artifact_ref' =
                             selected_worktree.recovery_artifact_ref
                         AND existing_checkpoint_payload ->> 'environment_snapshot_ref' =
                             selected_worktree.environment_snapshot_ref
                         AND existing_checkpoint_payload ->> 'dirty_after' = 'false'
                         THEN 'committed'
                    WHEN selected_run.status IN (
                        'failed', 'cancelled', 'timed_out', 'orphaned', 'succeeded'
                    ) THEN 'checkpointed'
                    ELSE NULL
                END;
                IF selected_run.status NOT IN (
                        'queued', 'succeeded', 'failed', 'cancelled', 'timed_out',
                        'orphaned'
                   )
                   OR (selected_worktree.dirty
                       AND selected_worktree.recovery_artifact_ref IS NULL)
                   OR (selected_worktree.access_mode = 'writer'
                       AND selected_run.status = 'succeeded'
                       AND derived_final_change_set_status IS DISTINCT FROM 'committed')
                   OR (derived_final_change_set_status = 'committed'
                       AND (selected_run.status <> 'succeeded'
                            OR selected_worktree.dirty)) THEN
                    RAISE EXCEPTION 'runner_worktree_release_invalid'
                        USING ERRCODE = '42501';
                END IF;
                SELECT candidate.* INTO selected_quota
                FROM public.saas_worktree_quotas AS candidate
                WHERE candidate.tenant_id = selected_worktree.tenant_id
                  AND candidate.space_id = selected_worktree.space_id
                  AND candidate.project_id = selected_worktree.project_id
                FOR UPDATE;
                IF NOT FOUND OR selected_quota.active_instances <= 0
                   OR selected_quota.reserved_bytes < selected_worktree.reserved_bytes
                   OR (selected_worktree.access_mode = 'writer'
                       AND selected_quota.active_writers <= 0) THEN
                    RAISE EXCEPTION 'runner_worktree_quota_inconsistent'
                        USING ERRCODE = '55000';
                END IF;
                IF selected_worktree.access_mode = 'writer' THEN
                    SELECT candidate.* INTO selected_group
                    FROM public.saas_changeset_groups AS candidate
                    WHERE candidate.id = selected_change_set.group_id
                    FOR UPDATE;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION 'runner_changeset_group_unavailable'
                            USING ERRCODE = '55000';
                    END IF;
                END IF;
                database_now := clock_timestamp();
                IF NOT public.saas_runner_worktree_authority_live_v1(
                    NULL, expected_runner_id, selected_worktree.run_id,
                    selected_worktree.change_set_id, selected_worktree.access_mode,
                    expected_run_fence_token, true
                ) THEN
                    RAISE EXCEPTION 'runner_worktree_capability_stale'
                        USING ERRCODE = '42501';
                END IF;
                SELECT candidate.* INTO selected_run
                FROM public.saas_runs AS candidate
                WHERE candidate.id = selected_worktree.run_id;
                derived_final_change_set_status := CASE
                    WHEN selected_worktree.access_mode <> 'writer' THEN NULL
                    WHEN selected_worktree.recovery_artifact_ref IS NULL
                         OR selected_change_set.head_revision IS NULL
                         OR selected_change_set.recovery_artifact_ref IS NULL THEN NULL
                    WHEN selected_run.status = 'succeeded'
                         AND NOT selected_worktree.dirty
                         AND checkpoint_event_count = 1
                         AND existing_checkpoint_payload ->> 'head_revision' =
                             selected_change_set.head_revision
                         AND existing_checkpoint_payload ->> 'recovery_artifact_ref' =
                             selected_worktree.recovery_artifact_ref
                         AND existing_checkpoint_payload ->> 'environment_snapshot_ref' =
                             selected_worktree.environment_snapshot_ref
                         AND existing_checkpoint_payload ->> 'dirty_after' = 'false'
                         THEN 'committed'
                    WHEN selected_run.status IN (
                        'failed', 'cancelled', 'timed_out', 'orphaned', 'succeeded'
                    ) THEN 'checkpointed'
                    ELSE NULL
                END;
                IF selected_run.status NOT IN (
                        'queued', 'succeeded', 'failed', 'cancelled', 'timed_out',
                        'orphaned'
                   ) OR (selected_worktree.access_mode = 'writer'
                       AND selected_run.status = 'succeeded'
                       AND derived_final_change_set_status IS DISTINCT FROM 'committed') THEN
                    RAISE EXCEPTION 'runner_worktree_release_invalid'
                        USING ERRCODE = '42501';
                END IF;
                IF derived_final_change_set_status IS NOT NULL THEN
                    UPDATE public.saas_changesets AS mutated
                    SET status = derived_final_change_set_status,
                        version = mutated.version + 1, updated_at = database_now
                    WHERE mutated.id = selected_change_set.id;
                    SELECT array_agg(candidate.status::text ORDER BY candidate.id)
                    INTO child_statuses
                    FROM public.saas_changesets AS candidate
                    WHERE candidate.group_id = selected_group.id;
                    target_group_status := CASE
                        WHEN child_statuses <@ ARRAY['committed']::text[] THEN 'completed'
                        WHEN child_statuses <@ ARRAY['committed', 'abandoned']::text[]
                            THEN 'abandoned'
                        ELSE 'open' END;
                    IF selected_group.status <> target_group_status THEN
                        UPDATE public.saas_changeset_groups AS mutated
                        SET status = target_group_status,
                            version = mutated.version + 1,
                            updated_at = database_now
                        WHERE mutated.id = selected_group.id;
                    END IF;
                END IF;
                UPDATE public.saas_worktree_quotas AS quota
                SET active_instances = quota.active_instances - 1,
                    active_writers = quota.active_writers -
                        CASE WHEN selected_worktree.access_mode = 'writer' THEN 1 ELSE 0 END,
                    reserved_bytes = quota.reserved_bytes -
                        selected_worktree.reserved_bytes,
                    version = quota.version + 1,
                    updated_at = database_now
                WHERE quota.id = selected_quota.id;
                UPDATE public.saas_worktree_instances AS mutated
                SET status = 'released', released_at = database_now,
                    lease_generation = mutated.lease_generation + 1,
                    lease_token_hash = NULL, lease_expires_at = NULL,
                    updated_at = database_now
                WHERE mutated.id = selected_worktree.id;
                PERFORM public.saas_runner_append_worktree_event_v1(
                    selected_worktree.id, 'worktree.released',
                    jsonb_build_object(
                        'run_status', selected_run.status,
                        'dirty', selected_worktree.dirty,
                        'checkpointed',
                            selected_worktree.recovery_artifact_ref IS NOT NULL,
                        'final_change_set_status', derived_final_change_set_status,
                        'release_request_hash', release_request_hash
                    ), requested_trace_id
                );
            END IF;
            SELECT candidate.* INTO selected_worktree
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.id = expected_worktree_id;
            RETURN QUERY SELECT selected_worktree.id,
                selected_worktree.status::text,
                selected_worktree.lease_generation,
                selected_worktree.lease_expires_at,
                selected_worktree.actual_bytes,
                selected_worktree.dirty,
                selected_worktree.recovery_artifact_ref::text,
                selected_worktree.environment_snapshot_ref::text,
                selected_worktree.event_sequence, false;
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_transition_worktree_v1("
        "text,uuid,uuid,bigint,bigint,text,bigint,boolean,integer,text,text,text,text,text"
        ") FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_materialization_grant_v1(
            expected_worktree_id uuid,
            expected_runner_id uuid,
            expected_lease_generation bigint,
            expected_run_fence_token bigint,
            expected_lease_hash text
        ) RETURNS TABLE (
            worktree_id uuid,
            change_set_id uuid,
            run_id uuid,
            runner_id uuid,
            opaque_runtime_key text,
            access_mode text,
            lease_generation bigint,
            run_fence_token bigint,
            runner_connection_generation bigint,
            reserved_bytes bigint,
            repository_source_binding_key text,
            base_revision text,
            head_revision text,
            branch_ref text,
            recovery_artifact_ref text,
            environment_snapshot_ref text
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            discovered public.saas_worktree_instances%ROWTYPE;
            selected_runner public.saas_runner_registrations%ROWTYPE;
            selected_capability public.saas_capability_tokens%ROWTYPE;
            selected_run public.saas_runs%ROWTYPE;
            selected_dispatch public.saas_run_dispatches%ROWTYPE;
            selected_change_set public.saas_changesets%ROWTYPE;
            selected_worktree public.saas_worktree_instances%ROWTYPE;
            selected_repository public.saas_repositories%ROWTYPE;
            required_action text;
            database_now timestamptz := statement_timestamp();
        BEGIN
            IF expected_worktree_id IS NULL OR expected_runner_id IS NULL
               OR expected_lease_generation <= 0 OR expected_run_fence_token <= 0
               OR expected_lease_hash !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'runner_materialization_grant_invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT candidate.* INTO discovered
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.id = expected_worktree_id;
            IF NOT FOUND OR discovered.runner_id <> expected_runner_id
               OR discovered.run_fence_token <> expected_run_fence_token THEN
                RAISE EXCEPTION 'runner_worktree_lease_stale'
                    USING ERRCODE = '42501';
            END IF;
            required_action := CASE discovered.access_mode
                WHEN 'writer' THEN 'worktree.write' ELSE 'worktree.read' END;
            SELECT candidate.* INTO selected_runner
            FROM public.saas_runner_registrations AS candidate
            WHERE candidate.id = expected_runner_id;
            IF NOT FOUND OR selected_runner.status NOT IN ('online', 'draining')
               OR selected_runner.connection_generation <>
                    discovered.runner_connection_generation
               OR session_user::text <> 'runner_' ||
                    replace(expected_runner_id::text, '-', '') || '_g' ||
                    selected_runner.connection_generation::text THEN
                RAISE EXCEPTION 'runner_worktree_runner_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_capability
            FROM public.saas_capability_tokens AS candidate
            WHERE candidate.run_id = discovered.run_id
              AND candidate.runner_id = expected_runner_id
              AND candidate.runner_connection_generation =
                    discovered.runner_connection_generation
              AND candidate.fence_token = expected_run_fence_token
              AND candidate.resource_scope ->> 'change_set_id' =
                    discovered.change_set_id::text
              AND candidate.revoked_at IS NULL
              AND candidate.expires_at > database_now
              AND (candidate.allowed_actions)::jsonb ? required_action
            ORDER BY candidate.id LIMIT 1;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'runner_worktree_capability_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_run
            FROM public.saas_runs AS candidate
            WHERE candidate.id = discovered.run_id;
            IF NOT FOUND OR selected_run.status NOT IN (
                    'leased', 'starting', 'running', 'waiting_input',
                    'waiting_approval', 'cancelling'
               )
               OR selected_run.fence_token <> expected_run_fence_token
               OR selected_run.lease_owner <> expected_runner_id::text
               OR selected_run.lease_token IS NULL
               OR selected_run.lease_expires_at IS NULL
               OR selected_run.lease_expires_at <= database_now THEN
                RAISE EXCEPTION 'runner_worktree_run_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_dispatch
            FROM public.saas_run_dispatches AS candidate
            WHERE candidate.run_id = discovered.run_id;
            IF NOT FOUND OR selected_dispatch.status <> 'leased'
               OR selected_dispatch.selected_runner_id <> expected_runner_id
               OR selected_dispatch.dispatch_generation <>
                    selected_capability.dispatch_generation THEN
                RAISE EXCEPTION 'runner_worktree_dispatch_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_change_set
            FROM public.saas_changesets AS candidate
            WHERE candidate.id = discovered.change_set_id;
            SELECT candidate.* INTO selected_worktree
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.id = expected_worktree_id;
            IF selected_change_set.id IS NULL OR NOT FOUND
               OR selected_change_set.tenant_id <> selected_run.tenant_id
               OR selected_change_set.space_id <> selected_run.space_id
               OR selected_change_set.project_id <> selected_run.project_id
               OR selected_worktree.status NOT IN ('materializing', 'ready')
               OR selected_worktree.runner_id <> expected_runner_id
               OR selected_worktree.run_id <> selected_run.id
               OR selected_worktree.change_set_id <> selected_change_set.id
               OR selected_worktree.run_fence_token <> expected_run_fence_token
               OR selected_worktree.tenant_id <> selected_run.tenant_id
               OR selected_worktree.space_id <> selected_run.space_id
               OR selected_worktree.project_id <> selected_run.project_id
               OR selected_worktree.lease_generation <> expected_lease_generation
               OR selected_worktree.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_worktree.lease_token_hash <> expected_lease_hash
               OR selected_worktree.lease_expires_at IS NULL
               OR selected_worktree.lease_expires_at <= database_now
               OR selected_worktree.maximum_lifetime_at IS NULL
               OR selected_worktree.maximum_lifetime_at <= database_now THEN
                RAISE EXCEPTION 'runner_worktree_lease_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_repository
            FROM public.saas_repositories AS candidate
            WHERE candidate.id = selected_change_set.repository_id;
            IF NOT FOUND
               OR selected_repository.tenant_id <> selected_worktree.tenant_id
               OR selected_repository.space_id <> selected_worktree.space_id
               OR selected_repository.project_id <> selected_worktree.project_id THEN
                RAISE EXCEPTION 'runner_worktree_repository_stale'
                    USING ERRCODE = '42501';
            END IF;
            RETURN QUERY SELECT selected_worktree.id,
                selected_worktree.change_set_id, selected_worktree.run_id,
                selected_worktree.runner_id,
                selected_worktree.opaque_runtime_key::text,
                selected_worktree.access_mode::text,
                selected_worktree.lease_generation,
                selected_worktree.run_fence_token,
                selected_worktree.runner_connection_generation,
                selected_worktree.reserved_bytes,
                selected_repository.source_binding_key::text,
                selected_change_set.base_revision::text,
                selected_change_set.head_revision::text,
                selected_change_set.branch_ref::text,
                selected_worktree.recovery_artifact_ref::text,
                selected_worktree.environment_snapshot_ref::text;
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_materialization_grant_v1("
        "uuid,uuid,bigint,bigint,text) FROM PUBLIC"
    )


def _install_runner_isolation_api() -> None:
    for table in (
        "saas_egress_policies",
        "saas_execution_profiles",
        "saas_secret_bindings",
        "saas_run_isolation_grants",
        "saas_secret_access_leases",
    ):
        _definer_policy(table)
    op.execute(
        "CREATE UNIQUE INDEX uq_runner_isolation_grant_capability_worktree_v1 "
        "ON public.saas_run_isolation_grants "
        "(capability_id, worktree_id, worktree_lease_generation)"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_issue_isolation_grant_v1(
            expected_capability_hash text,
            expected_runner_id uuid,
            expected_run_id uuid,
            expected_worktree_id uuid,
            expected_worktree_lease_generation bigint,
            expected_run_fence_token bigint,
            requested_grant_id uuid,
            requested_grant_token_hash text,
            requested_lifetime_seconds integer
        ) RETURNS TABLE (
            grant_id uuid,
            expires_at timestamptz,
            replayed boolean
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            selected_runner public.saas_runner_registrations%ROWTYPE;
            selected_capability public.saas_capability_tokens%ROWTYPE;
            selected_run public.saas_runs%ROWTYPE;
            selected_dispatch public.saas_run_dispatches%ROWTYPE;
            selected_change_set public.saas_changesets%ROWTYPE;
            selected_worktree public.saas_worktree_instances%ROWTYPE;
            selected_profile public.saas_execution_profiles%ROWTYPE;
            selected_policy public.saas_egress_policies%ROWTYPE;
            selected_grant public.saas_run_isolation_grants%ROWTYPE;
            database_now timestamptz := statement_timestamp();
            computed_expiry timestamptz;
            required_capabilities jsonb;
            grant_payload jsonb;
            outbox_payload jsonb;
            inserted_id uuid;
        BEGIN
            IF expected_capability_hash !~ '^[0-9a-f]{64}$'
               OR expected_runner_id IS NULL OR expected_run_id IS NULL
               OR expected_worktree_id IS NULL
               OR expected_worktree_lease_generation <= 0
               OR expected_run_fence_token <= 0
               OR requested_grant_id IS NULL
               OR requested_grant_token_hash !~ '^[0-9a-f]{64}$'
               OR requested_lifetime_seconds NOT BETWEEN 1 AND 120 THEN
                RAISE EXCEPTION 'runner_isolation_grant_invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT candidate.* INTO selected_runner
            FROM public.saas_runner_registrations AS candidate
            WHERE candidate.id = expected_runner_id;
            IF NOT FOUND OR selected_runner.status NOT IN ('online', 'draining')
               OR session_user::text <> 'runner_' ||
                    replace(expected_runner_id::text, '-', '') || '_g' ||
                    selected_runner.connection_generation::text THEN
                RAISE EXCEPTION 'runner_isolation_runner_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_capability
            FROM public.saas_capability_tokens AS candidate
            WHERE candidate.token_hash = expected_capability_hash
              AND candidate.run_id = expected_run_id
              AND candidate.runner_id = expected_runner_id
              AND candidate.runner_connection_generation =
                    selected_runner.connection_generation
              AND candidate.fence_token = expected_run_fence_token
              AND candidate.revoked_at IS NULL
              AND candidate.expires_at > database_now
              AND (candidate.allowed_actions)::jsonb ? 'sandbox.launch';
            IF NOT FOUND THEN
                RAISE EXCEPTION 'runner_isolation_capability_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_run
            FROM public.saas_runs AS candidate
            WHERE candidate.id = expected_run_id;
            IF NOT FOUND OR selected_run.status NOT IN (
                    'leased', 'starting', 'running', 'waiting_input',
                    'waiting_approval', 'cancelling'
               )
               OR selected_run.tenant_id <> selected_capability.tenant_id
               OR selected_run.space_id <> selected_capability.space_id
               OR selected_run.project_id <> selected_capability.project_id
               OR selected_run.fence_token <> expected_run_fence_token
               OR selected_run.lease_owner <> expected_runner_id::text
               OR selected_run.lease_token IS NULL
               OR selected_run.lease_expires_at IS NULL
               OR selected_run.lease_expires_at <= database_now THEN
                RAISE EXCEPTION 'runner_isolation_run_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_dispatch
            FROM public.saas_run_dispatches AS candidate
            WHERE candidate.run_id = expected_run_id;
            IF NOT FOUND OR selected_dispatch.status <> 'leased'
               OR selected_dispatch.selected_runner_id <> expected_runner_id
               OR selected_dispatch.dispatch_generation <>
                    selected_capability.dispatch_generation
               OR selected_dispatch.tenant_id <> selected_run.tenant_id
               OR selected_dispatch.space_id <> selected_run.space_id
               OR selected_dispatch.project_id <> selected_run.project_id THEN
                RAISE EXCEPTION 'runner_isolation_dispatch_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_change_set
            FROM public.saas_changesets AS candidate
            WHERE candidate.id = NULLIF(
                selected_capability.resource_scope ->> 'change_set_id', ''
            )::uuid;
            IF NOT FOUND OR selected_change_set.tenant_id <> selected_run.tenant_id
               OR selected_change_set.space_id <> selected_run.space_id
               OR selected_change_set.project_id <> selected_run.project_id THEN
                RAISE EXCEPTION 'runner_isolation_changeset_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_worktree
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.id = expected_worktree_id;
            IF NOT FOUND OR selected_worktree.status NOT IN ('materializing', 'ready')
               OR selected_worktree.tenant_id <> selected_run.tenant_id
               OR selected_worktree.space_id <> selected_run.space_id
               OR selected_worktree.project_id <> selected_run.project_id
               OR selected_worktree.change_set_id <> selected_change_set.id
               OR selected_worktree.run_id <> expected_run_id
               OR selected_worktree.runner_id <> expected_runner_id
               OR selected_worktree.run_fence_token <> expected_run_fence_token
               OR selected_worktree.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_worktree.lease_generation <>
                    expected_worktree_lease_generation
               OR selected_worktree.lease_expires_at IS NULL
               OR selected_worktree.lease_expires_at <= database_now
               OR selected_worktree.maximum_lifetime_at IS NULL
               OR selected_worktree.maximum_lifetime_at <= database_now THEN
                RAISE EXCEPTION 'runner_isolation_worktree_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_policy
            FROM public.saas_egress_policies AS candidate
            WHERE candidate.id = selected_dispatch.egress_policy_id;
            SELECT candidate.* INTO selected_profile
            FROM public.saas_execution_profiles AS candidate
            WHERE candidate.id = selected_dispatch.execution_profile_id;
            IF selected_policy.id IS NULL OR selected_profile.id IS NULL
               OR selected_profile.tenant_id <> selected_run.tenant_id
               OR selected_profile.space_id <> selected_run.space_id
               OR selected_profile.project_id <> selected_run.project_id
               OR selected_policy.tenant_id <> selected_run.tenant_id
               OR selected_policy.space_id <> selected_run.space_id
               OR selected_policy.project_id <> selected_run.project_id
               OR selected_profile.egress_policy_id <> selected_policy.id
               OR selected_profile.config_hash <>
                    selected_dispatch.execution_profile_hash
               OR selected_policy.rules_hash <> selected_dispatch.egress_policy_hash
               OR selected_profile.status NOT IN ('active', 'retired')
               OR selected_policy.status NOT IN ('active', 'retired')
               OR selected_profile.network_mode <> 'proxy_only'
               OR NOT selected_profile.root_read_only
               OR NOT selected_profile.no_new_privileges
               OR selected_profile.host_socket_access
               OR selected_policy.allow_private_destinations THEN
                RAISE EXCEPTION 'runner_isolation_profile_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT jsonb_agg(value ORDER BY value) INTO required_capabilities
            FROM jsonb_array_elements_text(jsonb_build_array(
                'sandbox.readonly_root', 'sandbox.nonroot',
                'sandbox.no_new_privileges', 'sandbox.no_host_socket',
                'sandbox.resource_limits', 'egress.proxy', 'secret.broker',
                'sandbox.' || selected_profile.sandbox_backend,
                'syscall.' || selected_profile.syscall_profile_ref
            )) AS value;
            IF NOT required_capabilities <@
                    (selected_dispatch.required_capabilities)::jsonb
               OR NOT required_capabilities <@ (selected_runner.capabilities)::jsonb THEN
                RAISE EXCEPTION 'runner_isolation_attestation_stale'
                    USING ERRCODE = '42501';
            END IF;
            computed_expiry := LEAST(
                database_now + make_interval(secs => requested_lifetime_seconds),
                selected_capability.expires_at,
                selected_run.lease_expires_at,
                selected_worktree.lease_expires_at,
                selected_worktree.maximum_lifetime_at
            );
            IF computed_expiry <= database_now THEN
                RAISE EXCEPTION 'runner_isolation_grant_stale'
                    USING ERRCODE = '42501';
            END IF;
            grant_payload := jsonb_build_object(
                'grant_id', requested_grant_id::text,
                'tenant_id', selected_run.tenant_id::text,
                'space_id', selected_run.space_id::text,
                'project_id', selected_run.project_id::text,
                'run_id', expected_run_id::text,
                'runner_id', expected_runner_id::text,
                'worktree_id', selected_worktree.id::text,
                'profile_id', selected_profile.id::text,
                'profile_hash', selected_profile.config_hash,
                'egress_policy_id', selected_policy.id::text,
                'egress_policy_hash', selected_policy.rules_hash,
                'run_fence_token', expected_run_fence_token,
                'runner_connection_generation', selected_runner.connection_generation,
                'worktree_lease_generation', selected_worktree.lease_generation,
                'expires_at', to_jsonb(computed_expiry)
            );
            INSERT INTO public.saas_run_isolation_grants (
                id, token_hash, tenant_id, space_id, project_id, run_id,
                runner_id, worktree_id, execution_profile_id, capability_id,
                run_fence_token, runner_connection_generation,
                worktree_lease_generation, grant_hash, status, expires_at
            ) VALUES (
                requested_grant_id, requested_grant_token_hash,
                selected_run.tenant_id, selected_run.space_id, selected_run.project_id,
                selected_run.id, selected_runner.id, selected_worktree.id,
                selected_profile.id, selected_capability.id,
                selected_run.fence_token, selected_runner.connection_generation,
                selected_worktree.lease_generation,
                public.saas_canonical_json_sha256_v1(grant_payload),
                'active', computed_expiry
            ) ON CONFLICT (
                capability_id, worktree_id, worktree_lease_generation
            ) DO NOTHING RETURNING id INTO inserted_id;
            SELECT candidate.* INTO selected_grant
            FROM public.saas_run_isolation_grants AS candidate
            WHERE candidate.capability_id = selected_capability.id
              AND candidate.worktree_id = selected_worktree.id
              AND candidate.worktree_lease_generation =
                    selected_worktree.lease_generation
            FOR UPDATE;
            IF NOT FOUND OR selected_grant.id <> requested_grant_id
               OR selected_grant.token_hash <> requested_grant_token_hash
               OR selected_grant.tenant_id <> selected_run.tenant_id
               OR selected_grant.space_id <> selected_run.space_id
               OR selected_grant.project_id <> selected_run.project_id
               OR selected_grant.run_id <> selected_run.id
               OR selected_grant.runner_id <> selected_runner.id
               OR selected_grant.execution_profile_id <> selected_profile.id
               OR selected_grant.run_fence_token <> selected_run.fence_token
               OR selected_grant.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_grant.status NOT IN ('active', 'redeemed') THEN
                RAISE EXCEPTION 'runner_isolation_grant_replay_mismatch'
                    USING ERRCODE = '55000';
            END IF;
            PERFORM public.saas_runner_isolation_snapshot_v1(
                requested_grant_token_hash, expected_runner_id, expected_run_id
            );
            database_now := clock_timestamp();
            IF inserted_id IS NOT NULL THEN
                outbox_payload := jsonb_build_object(
                    'grant_id', selected_grant.id::text,
                    'run_id', selected_grant.run_id::text,
                    'runner_id', selected_grant.runner_id::text,
                    'worktree_id', selected_grant.worktree_id::text,
                    'execution_profile_id', selected_grant.execution_profile_id::text,
                    'expires_at', to_jsonb(selected_grant.expires_at)
                );
                INSERT INTO public.saas_control_plane_outbox (
                    id, tenant_id, aggregate_type, aggregate_key, event_type,
                    payload, idempotency_key, request_hash, attempt_count,
                    available_at, claimed_at, claim_token, published_at, created_at
                ) VALUES (
                    gen_random_uuid(), selected_grant.tenant_id, 'RunIsolationGrant',
                    selected_grant.id::text, 'run.isolation_grant.issued',
                    outbox_payload, 'run-isolation:' || selected_grant.id::text ||
                        ':' || 'issued',
                    public.saas_canonical_json_sha256_v1(outbox_payload), 0,
                    database_now, NULL, NULL, NULL, database_now
                );
            END IF;
            RETURN QUERY SELECT selected_grant.id, selected_grant.expires_at,
                inserted_id IS NULL;
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_issue_isolation_grant_v1("
        "text,uuid,uuid,uuid,bigint,bigint,uuid,text,integer) FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_isolation_snapshot_v1(
            expected_grant_token_hash text,
            expected_runner_id uuid,
            expected_run_id uuid
        ) RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            discovered public.saas_run_isolation_grants%ROWTYPE;
            selected_runner public.saas_runner_registrations%ROWTYPE;
            selected_capability public.saas_capability_tokens%ROWTYPE;
            selected_run public.saas_runs%ROWTYPE;
            selected_dispatch public.saas_run_dispatches%ROWTYPE;
            selected_change_set public.saas_changesets%ROWTYPE;
            selected_worktree public.saas_worktree_instances%ROWTYPE;
            selected_policy public.saas_egress_policies%ROWTYPE;
            selected_profile public.saas_execution_profiles%ROWTYPE;
            selected_grant public.saas_run_isolation_grants%ROWTYPE;
            database_now timestamptz := clock_timestamp();
            required_capabilities jsonb;
            bindings jsonb;
        BEGIN
            IF expected_grant_token_hash !~ '^[0-9a-f]{64}$'
               OR expected_runner_id IS NULL OR expected_run_id IS NULL THEN
                RAISE EXCEPTION 'runner_isolation_grant_invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT candidate.* INTO discovered
            FROM public.saas_run_isolation_grants AS candidate
            WHERE candidate.token_hash = expected_grant_token_hash;
            IF NOT FOUND OR discovered.runner_id <> expected_runner_id
               OR discovered.run_id <> expected_run_id THEN
                RAISE EXCEPTION 'runner_isolation_grant_invalid'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_runner
            FROM public.saas_runner_registrations AS candidate
            WHERE candidate.id = expected_runner_id;
            IF NOT FOUND OR selected_runner.status NOT IN ('online', 'draining')
               OR selected_runner.connection_generation <>
                    discovered.runner_connection_generation
               OR session_user::text <> 'runner_' ||
                    replace(expected_runner_id::text, '-', '') || '_g' ||
                    selected_runner.connection_generation::text THEN
                RAISE EXCEPTION 'runner_isolation_runner_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_capability
            FROM public.saas_capability_tokens AS candidate
            WHERE candidate.id = discovered.capability_id;
            IF NOT FOUND OR selected_capability.run_id <> expected_run_id
               OR selected_capability.runner_id <> expected_runner_id
               OR selected_capability.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_capability.fence_token <> discovered.run_fence_token
               OR selected_capability.revoked_at IS NOT NULL
               OR selected_capability.expires_at <= database_now
               OR NOT (selected_capability.allowed_actions)::jsonb ? 'sandbox.launch' THEN
                RAISE EXCEPTION 'runner_isolation_capability_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_run
            FROM public.saas_runs AS candidate
            WHERE candidate.id = expected_run_id;
            IF NOT FOUND OR selected_run.status NOT IN (
                    'leased', 'starting', 'running', 'waiting_input',
                    'waiting_approval', 'cancelling'
               )
               OR selected_run.tenant_id <> discovered.tenant_id
               OR selected_run.space_id <> discovered.space_id
               OR selected_run.project_id <> discovered.project_id
               OR selected_run.fence_token <> discovered.run_fence_token
               OR selected_run.lease_owner <> expected_runner_id::text
               OR selected_run.lease_token IS NULL
               OR selected_run.lease_expires_at IS NULL
               OR selected_run.lease_expires_at <= database_now THEN
                RAISE EXCEPTION 'runner_isolation_run_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_dispatch
            FROM public.saas_run_dispatches AS candidate
            WHERE candidate.run_id = expected_run_id;
            IF NOT FOUND OR selected_dispatch.status <> 'leased'
               OR selected_dispatch.selected_runner_id <> expected_runner_id
               OR selected_dispatch.dispatch_generation <>
                    selected_capability.dispatch_generation
               OR selected_dispatch.execution_profile_id <>
                    discovered.execution_profile_id THEN
                RAISE EXCEPTION 'runner_isolation_dispatch_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_change_set
            FROM public.saas_changesets AS candidate
            WHERE candidate.id = NULLIF(
                selected_capability.resource_scope ->> 'change_set_id', ''
            )::uuid;
            IF NOT FOUND OR selected_change_set.tenant_id <> selected_run.tenant_id
               OR selected_change_set.space_id <> selected_run.space_id
               OR selected_change_set.project_id <> selected_run.project_id THEN
                RAISE EXCEPTION 'runner_isolation_changeset_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_worktree
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.id = discovered.worktree_id;
            IF NOT FOUND OR selected_worktree.status NOT IN ('materializing', 'ready')
               OR selected_worktree.tenant_id <> selected_run.tenant_id
               OR selected_worktree.space_id <> selected_run.space_id
               OR selected_worktree.project_id <> selected_run.project_id
               OR selected_worktree.change_set_id <> selected_change_set.id
               OR selected_worktree.run_id <> selected_run.id
               OR selected_worktree.runner_id <> selected_runner.id
               OR selected_worktree.run_fence_token <> selected_run.fence_token
               OR selected_worktree.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_worktree.lease_generation <>
                    discovered.worktree_lease_generation
               OR selected_worktree.lease_expires_at IS NULL
               OR selected_worktree.lease_expires_at <= database_now
               OR selected_worktree.maximum_lifetime_at IS NULL
               OR selected_worktree.maximum_lifetime_at <= database_now THEN
                RAISE EXCEPTION 'runner_isolation_worktree_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_policy
            FROM public.saas_egress_policies AS candidate
            WHERE candidate.id = selected_dispatch.egress_policy_id;
            SELECT candidate.* INTO selected_profile
            FROM public.saas_execution_profiles AS candidate
            WHERE candidate.id = selected_dispatch.execution_profile_id;
            IF selected_policy.id IS NULL OR selected_profile.id IS NULL
               OR selected_profile.tenant_id <> selected_run.tenant_id
               OR selected_profile.space_id <> selected_run.space_id
               OR selected_profile.project_id <> selected_run.project_id
               OR selected_policy.tenant_id <> selected_run.tenant_id
               OR selected_policy.space_id <> selected_run.space_id
               OR selected_policy.project_id <> selected_run.project_id
               OR selected_profile.egress_policy_id <> selected_policy.id
               OR selected_profile.config_hash <>
                    selected_dispatch.execution_profile_hash
               OR selected_policy.rules_hash <> selected_dispatch.egress_policy_hash
               OR selected_profile.status NOT IN ('active', 'retired')
               OR selected_policy.status NOT IN ('active', 'retired')
               OR selected_profile.network_mode <> 'proxy_only'
               OR NOT selected_profile.root_read_only
               OR NOT selected_profile.no_new_privileges
               OR selected_profile.host_socket_access
               OR selected_policy.allow_private_destinations THEN
                RAISE EXCEPTION 'runner_isolation_profile_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT jsonb_agg(value ORDER BY value) INTO required_capabilities
            FROM jsonb_array_elements_text(jsonb_build_array(
                'sandbox.readonly_root', 'sandbox.nonroot',
                'sandbox.no_new_privileges', 'sandbox.no_host_socket',
                'sandbox.resource_limits', 'egress.proxy', 'secret.broker',
                'sandbox.' || selected_profile.sandbox_backend,
                'syscall.' || selected_profile.syscall_profile_ref
            )) AS value;
            IF NOT required_capabilities <@
                    (selected_dispatch.required_capabilities)::jsonb
               OR NOT required_capabilities <@ (selected_runner.capabilities)::jsonb THEN
                RAISE EXCEPTION 'runner_isolation_attestation_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_grant
            FROM public.saas_run_isolation_grants AS candidate
            WHERE candidate.id = discovered.id;
            IF NOT FOUND OR selected_grant.token_hash <> expected_grant_token_hash
               OR selected_grant.status NOT IN ('active', 'redeemed')
               OR selected_grant.expires_at <= database_now
               OR selected_grant.expires_at > LEAST(
                    selected_capability.expires_at,
                    selected_run.lease_expires_at,
                    selected_worktree.lease_expires_at,
                    selected_worktree.maximum_lifetime_at
               )
               OR selected_grant.tenant_id <> selected_run.tenant_id
               OR selected_grant.space_id <> selected_run.space_id
               OR selected_grant.project_id <> selected_run.project_id
               OR selected_grant.runner_id <> selected_runner.id
               OR selected_grant.run_id <> selected_run.id
               OR selected_grant.worktree_id <> selected_worktree.id
               OR selected_grant.execution_profile_id <> selected_profile.id
               OR selected_grant.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_grant.run_fence_token <> selected_run.fence_token THEN
                RAISE EXCEPTION 'runner_isolation_grant_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT COALESCE(jsonb_agg(jsonb_build_object(
                'binding_id', binding.id::text,
                'name', binding.name,
                'host', binding.host,
                'credential_scheme', binding.credential_scheme,
                'username', binding.username,
                'inject_env', (binding.inject_env)::jsonb
            ) ORDER BY binding.name, binding.id), '[]'::jsonb)
            INTO bindings
            FROM public.saas_secret_bindings AS binding
            WHERE binding.execution_profile_id = selected_profile.id
              AND binding.tenant_id = selected_run.tenant_id
              AND binding.space_id = selected_run.space_id
              AND binding.project_id = selected_run.project_id
              AND binding.status = 'active';
            IF jsonb_array_length(bindings) > 128 THEN
                RAISE EXCEPTION 'runner_isolation_secret_binding_limit'
                    USING ERRCODE = '54000';
            END IF;
            RETURN jsonb_build_object(
                'grant_id', selected_grant.id::text,
                'status', selected_grant.status,
                'tenant_id', selected_grant.tenant_id::text,
                'space_id', selected_grant.space_id::text,
                'project_id', selected_grant.project_id::text,
                'run_id', selected_grant.run_id::text,
                'runner_id', selected_grant.runner_id::text,
                'worktree_id', selected_grant.worktree_id::text,
                'worktree_access_mode', selected_worktree.access_mode,
                'worktree_lease_generation', selected_grant.worktree_lease_generation,
                'run_fence_token', selected_grant.run_fence_token,
                'runner_connection_generation',
                    selected_grant.runner_connection_generation,
                'expires_at', to_jsonb(selected_grant.expires_at),
                'profile', jsonb_build_object(
                    'sandbox_backend', selected_profile.sandbox_backend,
                    'network_mode', selected_profile.network_mode,
                    'root_read_only', selected_profile.root_read_only,
                    'run_as_uid', selected_profile.run_as_uid,
                    'run_as_gid', selected_profile.run_as_gid,
                    'no_new_privileges', selected_profile.no_new_privileges,
                    'host_socket_access', selected_profile.host_socket_access,
                    'syscall_profile_ref', selected_profile.syscall_profile_ref,
                    'cpu_millis', selected_profile.cpu_millis,
                    'memory_bytes', selected_profile.memory_bytes,
                    'pids_limit', selected_profile.pids_limit,
                    'allowed_tools', (selected_profile.allowed_tools)::jsonb,
                    'approval_required_tools',
                        (selected_profile.approval_required_tools)::jsonb,
                    'denied_tools', (selected_profile.denied_tools)::jsonb,
                    'config_hash', selected_profile.config_hash
                ),
                'egress_rules', (selected_policy.rules)::jsonb,
                'egress_hash', selected_policy.rules_hash,
                'allow_private_destinations',
                    selected_policy.allow_private_destinations,
                'required_runner_capabilities', required_capabilities,
                'secret_bindings', bindings
            );
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_isolation_snapshot_v1("
        "text,uuid,uuid) FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_isolation_metadata_v1(
            expected_grant_token_hash text,
            expected_runner_id uuid,
            expected_run_id uuid
        ) RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
            RETURN public.saas_runner_isolation_snapshot_v1(
                expected_grant_token_hash, expected_runner_id, expected_run_id
            );
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_isolation_metadata_v1("
        "text,uuid,uuid) FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_redeem_isolation_grant_v1(
            expected_grant_token_hash text,
            expected_runner_id uuid,
            expected_run_id uuid,
            requested_secret_commitments jsonb
        ) RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            snapshot jsonb;
            bindings jsonb;
            commitment jsonb;
            selected_grant public.saas_run_isolation_grants%ROWTYPE;
            selected_lease public.saas_secret_access_leases%ROWTYPE;
            database_now timestamptz := statement_timestamp();
            outbox_payload jsonb;
            inserted_id uuid;
            first_redemption boolean := false;
            commitment_binding_id uuid;
            commitment_lease_id uuid;
            commitment_token_hash text;
            fresh_snapshot jsonb;
        BEGIN
            snapshot := public.saas_runner_isolation_snapshot_v1(
                expected_grant_token_hash, expected_runner_id, expected_run_id
            );
            bindings := snapshot -> 'secret_bindings';
            IF jsonb_typeof(requested_secret_commitments) <> 'array'
               OR jsonb_array_length(requested_secret_commitments) <>
                    jsonb_array_length(bindings)
               OR EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(requested_secret_commitments) AS item
                    WHERE jsonb_typeof(item) <> 'object'
                       OR (SELECT array_agg(key ORDER BY key)
                           FROM jsonb_object_keys(item) AS key) <>
                          ARRAY['binding_id', 'lease_id', 'token_hash']::text[]
                       OR item ->> 'token_hash' !~ '^[0-9a-f]{64}$'
               )
               OR (SELECT count(DISTINCT item ->> 'binding_id')
                   FROM jsonb_array_elements(requested_secret_commitments) AS item) <>
                  jsonb_array_length(bindings)
               OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements(bindings) AS binding
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements(requested_secret_commitments) AS item
                        WHERE item ->> 'binding_id' = binding ->> 'binding_id'
                    )
               ) THEN
                RAISE EXCEPTION 'runner_isolation_commitments_invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT candidate.* INTO selected_grant
            FROM public.saas_run_isolation_grants AS candidate
            WHERE candidate.id = (snapshot ->> 'grant_id')::uuid
            FOR UPDATE;
            IF NOT FOUND OR selected_grant.token_hash <> expected_grant_token_hash
               OR selected_grant.status NOT IN ('active', 'redeemed')
               OR selected_grant.expires_at <= database_now THEN
                RAISE EXCEPTION 'runner_isolation_grant_stale'
                    USING ERRCODE = '42501';
            END IF;
            IF selected_grant.status = 'redeemed' AND (
                (SELECT count(*) FROM public.saas_secret_access_leases AS lease
                 WHERE lease.isolation_grant_id = selected_grant.id) <>
                    jsonb_array_length(bindings)
                OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements(bindings) AS binding
                    WHERE NOT EXISTS (
                        SELECT 1 FROM public.saas_secret_access_leases AS lease
                        WHERE lease.isolation_grant_id = selected_grant.id
                          AND lease.secret_binding_id =
                              (binding ->> 'binding_id')::uuid
                    )
                )
                OR EXISTS (
                    SELECT 1 FROM public.saas_secret_access_leases AS lease
                    WHERE lease.isolation_grant_id = selected_grant.id
                      AND NOT EXISTS (
                          SELECT 1 FROM jsonb_array_elements(bindings) AS binding
                          WHERE (binding ->> 'binding_id')::uuid =
                                lease.secret_binding_id
                      )
                )
            ) THEN
                RAISE EXCEPTION 'runner_isolation_binding_drift'
                    USING ERRCODE = '42501';
            END IF;
            FOR commitment IN
                SELECT item
                FROM jsonb_array_elements(requested_secret_commitments) AS item
                ORDER BY item ->> 'binding_id'
            LOOP
                BEGIN
                    commitment_binding_id := (commitment ->> 'binding_id')::uuid;
                    commitment_lease_id := (commitment ->> 'lease_id')::uuid;
                    commitment_token_hash := commitment ->> 'token_hash';
                EXCEPTION WHEN invalid_text_representation THEN
                    RAISE EXCEPTION 'runner_isolation_commitments_invalid'
                        USING ERRCODE = '22023';
                END;
                IF selected_grant.status = 'active' THEN
                    INSERT INTO public.saas_secret_access_leases (
                        id, token_hash, tenant_id, space_id, project_id,
                        isolation_grant_id, secret_binding_id, run_id, runner_id,
                        run_fence_token, runner_connection_generation, status, expires_at
                    ) VALUES (
                        commitment_lease_id, commitment_token_hash,
                        selected_grant.tenant_id, selected_grant.space_id,
                        selected_grant.project_id, selected_grant.id,
                        commitment_binding_id, selected_grant.run_id,
                        selected_grant.runner_id, selected_grant.run_fence_token,
                        selected_grant.runner_connection_generation,
                        'active', selected_grant.expires_at
                    ) ON CONFLICT (isolation_grant_id, secret_binding_id)
                        DO NOTHING RETURNING id INTO inserted_id;
                END IF;
                SELECT candidate.* INTO selected_lease
                FROM public.saas_secret_access_leases AS candidate
                WHERE candidate.isolation_grant_id = selected_grant.id
                  AND candidate.secret_binding_id = commitment_binding_id
                FOR UPDATE;
                IF NOT FOUND OR selected_lease.id <> commitment_lease_id
                   OR selected_lease.token_hash <> commitment_token_hash
                   OR selected_lease.tenant_id <> selected_grant.tenant_id
                   OR selected_lease.space_id <> selected_grant.space_id
                   OR selected_lease.project_id <> selected_grant.project_id
                   OR selected_lease.run_id <> selected_grant.run_id
                   OR selected_lease.runner_id <> selected_grant.runner_id
                   OR selected_lease.run_fence_token <> selected_grant.run_fence_token
                   OR selected_lease.runner_connection_generation <>
                        selected_grant.runner_connection_generation
                   OR selected_lease.expires_at <> selected_grant.expires_at
                   OR selected_lease.status NOT IN ('active', 'redeemed') THEN
                    RAISE EXCEPTION 'runner_isolation_commitment_replay_mismatch'
                        USING ERRCODE = '55000';
                END IF;
            END LOOP;
            fresh_snapshot := public.saas_runner_isolation_snapshot_v1(
                expected_grant_token_hash, expected_runner_id, expected_run_id
            );
            IF fresh_snapshot -> 'secret_bindings' <> bindings THEN
                RAISE EXCEPTION 'runner_isolation_binding_drift'
                    USING ERRCODE = '42501';
            END IF;
            snapshot := fresh_snapshot;
            database_now := clock_timestamp();
            IF selected_grant.status = 'active' THEN
                UPDATE public.saas_run_isolation_grants AS mutated
                SET status = 'redeemed', redeemed_at = database_now
                WHERE mutated.id = selected_grant.id;
                first_redemption := true;
                outbox_payload := jsonb_build_object(
                    'grant_id', selected_grant.id::text,
                    'run_id', selected_grant.run_id::text,
                    'runner_id', selected_grant.runner_id::text,
                    'worktree_id', selected_grant.worktree_id::text,
                    'secret_binding_count', jsonb_array_length(bindings)
                );
                INSERT INTO public.saas_control_plane_outbox (
                    id, tenant_id, aggregate_type, aggregate_key, event_type,
                    payload, idempotency_key, request_hash, attempt_count,
                    available_at, claimed_at, claim_token, published_at, created_at
                ) VALUES (
                    gen_random_uuid(), selected_grant.tenant_id, 'RunIsolationGrant',
                    selected_grant.id::text, 'run.isolation_grant.redeemed',
                    outbox_payload, 'run-isolation:' || selected_grant.id::text ||
                        ':' || 'redeemed',
                    public.saas_canonical_json_sha256_v1(outbox_payload), 0,
                    database_now, NULL, NULL, NULL, database_now
                );
            END IF;
            RETURN snapshot || jsonb_build_object(
                'status', 'redeemed', 'replayed', NOT first_redemption
            );
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_redeem_isolation_grant_v1("
        "text,uuid,uuid,jsonb) FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_claim_secret_lease_v1(
            expected_secret_token_hash text,
            expected_runner_id uuid,
            expected_run_id uuid
        ) RETURNS TABLE (
            replayed boolean,
            binding_id uuid,
            binding_name text,
            vault_provider text,
            vault_ref text,
            version_ref text,
            credential_scheme text,
            host text,
            username text,
            inject_env jsonb
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            discovered public.saas_secret_access_leases%ROWTYPE;
            selected_runner public.saas_runner_registrations%ROWTYPE;
            selected_capability public.saas_capability_tokens%ROWTYPE;
            selected_run public.saas_runs%ROWTYPE;
            selected_dispatch public.saas_run_dispatches%ROWTYPE;
            selected_change_set public.saas_changesets%ROWTYPE;
            selected_worktree public.saas_worktree_instances%ROWTYPE;
            selected_policy public.saas_egress_policies%ROWTYPE;
            selected_profile public.saas_execution_profiles%ROWTYPE;
            selected_grant public.saas_run_isolation_grants%ROWTYPE;
            selected_binding public.saas_secret_bindings%ROWTYPE;
            selected_lease public.saas_secret_access_leases%ROWTYPE;
            fresh_snapshot jsonb;
            database_now timestamptz := statement_timestamp();
            outbox_payload jsonb;
            was_replayed boolean;
        BEGIN
            IF expected_secret_token_hash !~ '^[0-9a-f]{64}$'
               OR expected_runner_id IS NULL OR expected_run_id IS NULL THEN
                RAISE EXCEPTION 'runner_secret_lease_invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT candidate.* INTO discovered
            FROM public.saas_secret_access_leases AS candidate
            WHERE candidate.token_hash = expected_secret_token_hash;
            IF NOT FOUND OR discovered.runner_id <> expected_runner_id
               OR discovered.run_id <> expected_run_id THEN
                RAISE EXCEPTION 'runner_secret_lease_invalid'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_runner
            FROM public.saas_runner_registrations AS candidate
            WHERE candidate.id = expected_runner_id;
            IF NOT FOUND OR selected_runner.status NOT IN ('online', 'draining')
               OR selected_runner.connection_generation <>
                    discovered.runner_connection_generation
               OR session_user::text <> 'runner_' ||
                    replace(expected_runner_id::text, '-', '') || '_g' ||
                    selected_runner.connection_generation::text THEN
                RAISE EXCEPTION 'runner_secret_runner_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_grant
            FROM public.saas_run_isolation_grants AS candidate
            WHERE candidate.id = discovered.isolation_grant_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'runner_secret_grant_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_capability
            FROM public.saas_capability_tokens AS candidate
            WHERE candidate.id = selected_grant.capability_id;
            IF NOT FOUND OR selected_capability.run_id <> expected_run_id
               OR selected_capability.runner_id <> expected_runner_id
               OR selected_capability.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_capability.fence_token <> selected_grant.run_fence_token
               OR selected_capability.revoked_at IS NOT NULL
               OR selected_capability.expires_at <= database_now
               OR NOT (selected_capability.allowed_actions)::jsonb ? 'sandbox.launch' THEN
                RAISE EXCEPTION 'runner_secret_capability_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_run
            FROM public.saas_runs AS candidate
            WHERE candidate.id = expected_run_id;
            IF NOT FOUND OR selected_run.status NOT IN (
                    'leased', 'starting', 'running', 'waiting_input',
                    'waiting_approval', 'cancelling'
               )
               OR selected_run.tenant_id <> selected_grant.tenant_id
               OR selected_run.space_id <> selected_grant.space_id
               OR selected_run.project_id <> selected_grant.project_id
               OR selected_run.fence_token <> selected_grant.run_fence_token
               OR selected_run.lease_owner <> expected_runner_id::text
               OR selected_run.lease_token IS NULL
               OR selected_run.lease_expires_at IS NULL
               OR selected_run.lease_expires_at <= database_now THEN
                RAISE EXCEPTION 'runner_secret_run_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_dispatch
            FROM public.saas_run_dispatches AS candidate
            WHERE candidate.run_id = expected_run_id;
            IF NOT FOUND OR selected_dispatch.status <> 'leased'
               OR selected_dispatch.selected_runner_id <> expected_runner_id
               OR selected_dispatch.dispatch_generation <>
                    selected_capability.dispatch_generation
               OR selected_dispatch.execution_profile_id <>
                    selected_grant.execution_profile_id THEN
                RAISE EXCEPTION 'runner_secret_dispatch_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_change_set
            FROM public.saas_changesets AS candidate
            WHERE candidate.id = NULLIF(
                selected_capability.resource_scope ->> 'change_set_id', ''
            )::uuid;
            IF NOT FOUND OR selected_change_set.tenant_id <> selected_run.tenant_id
               OR selected_change_set.space_id <> selected_run.space_id
               OR selected_change_set.project_id <> selected_run.project_id THEN
                RAISE EXCEPTION 'runner_secret_changeset_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_worktree
            FROM public.saas_worktree_instances AS candidate
            WHERE candidate.id = selected_grant.worktree_id;
            IF NOT FOUND OR selected_worktree.status NOT IN ('materializing', 'ready')
               OR selected_worktree.change_set_id <> selected_change_set.id
               OR selected_worktree.run_id <> selected_run.id
               OR selected_worktree.runner_id <> selected_runner.id
               OR selected_worktree.run_fence_token <> selected_run.fence_token
               OR selected_worktree.runner_connection_generation <>
                    selected_runner.connection_generation
               OR selected_worktree.lease_generation <>
                    selected_grant.worktree_lease_generation
               OR selected_worktree.lease_expires_at IS NULL
               OR selected_worktree.lease_expires_at <= database_now
               OR selected_worktree.maximum_lifetime_at IS NULL
               OR selected_worktree.maximum_lifetime_at <= database_now THEN
                RAISE EXCEPTION 'runner_secret_worktree_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_policy
            FROM public.saas_egress_policies AS candidate
            WHERE candidate.id = selected_dispatch.egress_policy_id;
            SELECT candidate.* INTO selected_profile
            FROM public.saas_execution_profiles AS candidate
            WHERE candidate.id = selected_dispatch.execution_profile_id;
            IF selected_policy.id IS NULL OR selected_profile.id IS NULL
               OR selected_profile.tenant_id <> selected_run.tenant_id
               OR selected_profile.space_id <> selected_run.space_id
               OR selected_profile.project_id <> selected_run.project_id
               OR selected_policy.tenant_id <> selected_run.tenant_id
               OR selected_policy.space_id <> selected_run.space_id
               OR selected_policy.project_id <> selected_run.project_id
               OR selected_profile.egress_policy_id <> selected_policy.id
               OR selected_profile.config_hash <>
                    selected_dispatch.execution_profile_hash
               OR selected_policy.rules_hash <> selected_dispatch.egress_policy_hash
               OR selected_profile.status NOT IN ('active', 'retired')
               OR selected_policy.status NOT IN ('active', 'retired')
               OR selected_policy.allow_private_destinations THEN
                RAISE EXCEPTION 'runner_secret_profile_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_grant
            FROM public.saas_run_isolation_grants AS candidate
            WHERE candidate.id = discovered.isolation_grant_id
            FOR UPDATE;
            IF NOT FOUND OR selected_grant.status <> 'redeemed'
               OR selected_grant.expires_at <= database_now
               OR selected_grant.runner_id <> selected_runner.id
               OR selected_grant.run_id <> selected_run.id
               OR selected_grant.worktree_id <> selected_worktree.id
               OR selected_grant.execution_profile_id <> selected_profile.id
               OR selected_grant.run_fence_token <> selected_run.fence_token
               OR selected_grant.runner_connection_generation <>
                    selected_runner.connection_generation THEN
                RAISE EXCEPTION 'runner_secret_grant_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_binding
            FROM public.saas_secret_bindings AS candidate
            WHERE candidate.id = discovered.secret_binding_id;
            IF NOT FOUND OR selected_binding.status <> 'active'
               OR selected_binding.execution_profile_id <> selected_profile.id
               OR selected_binding.tenant_id <> selected_grant.tenant_id
               OR selected_binding.space_id <> selected_grant.space_id
               OR selected_binding.project_id <> selected_grant.project_id THEN
                RAISE EXCEPTION 'runner_secret_binding_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_lease
            FROM public.saas_secret_access_leases AS candidate
            WHERE candidate.id = discovered.id
            FOR UPDATE;
            IF NOT FOUND OR selected_lease.token_hash <> expected_secret_token_hash
               OR selected_lease.status <> 'active'
               OR selected_lease.expires_at <= database_now
               OR selected_lease.expires_at <> selected_grant.expires_at
               OR selected_lease.isolation_grant_id <> selected_grant.id
               OR selected_lease.secret_binding_id <> selected_binding.id
               OR selected_lease.tenant_id <> selected_grant.tenant_id
               OR selected_lease.space_id <> selected_grant.space_id
               OR selected_lease.project_id <> selected_grant.project_id
               OR selected_lease.run_id <> selected_grant.run_id
               OR selected_lease.runner_id <> selected_grant.runner_id
               OR selected_lease.run_fence_token <> selected_grant.run_fence_token
               OR selected_lease.runner_connection_generation <>
                    selected_grant.runner_connection_generation THEN
                RAISE EXCEPTION 'runner_secret_lease_stale'
                    USING ERRCODE = '42501';
            END IF;
            fresh_snapshot := public.saas_runner_isolation_snapshot_v1(
                selected_grant.token_hash, expected_runner_id, expected_run_id
            );
            database_now := clock_timestamp();
            SELECT candidate.* INTO selected_binding
            FROM public.saas_secret_bindings AS candidate
            WHERE candidate.id = selected_lease.secret_binding_id;
            IF NOT FOUND OR selected_binding.status <> 'active'
               OR selected_binding.execution_profile_id <>
                    selected_grant.execution_profile_id
               OR selected_binding.tenant_id <> selected_grant.tenant_id
               OR selected_binding.space_id <> selected_grant.space_id
               OR selected_binding.project_id <> selected_grant.project_id THEN
                RAISE EXCEPTION 'runner_secret_binding_stale'
                    USING ERRCODE = '42501';
            END IF;
            was_replayed := false;
            UPDATE public.saas_secret_access_leases AS mutated
            SET status = 'redeemed', redeemed_at = database_now
            WHERE mutated.id = selected_lease.id;
            outbox_payload := jsonb_build_object(
                'lease_id', selected_lease.id::text,
                'binding_id', selected_binding.id::text,
                'run_id', selected_lease.run_id::text,
                'runner_id', selected_lease.runner_id::text,
                'host', selected_binding.host
            );
            INSERT INTO public.saas_control_plane_outbox (
                id, tenant_id, aggregate_type, aggregate_key, event_type,
                payload, idempotency_key, request_hash, attempt_count,
                available_at, claimed_at, claim_token, published_at, created_at
            ) VALUES (
                gen_random_uuid(), selected_lease.tenant_id, 'SecretAccessLease',
                selected_lease.id::text, 'secret.access.redeemed', outbox_payload,
                'secret-access:' || selected_lease.id::text || ':' || 'redeemed',
                public.saas_canonical_json_sha256_v1(outbox_payload), 0,
                database_now, NULL, NULL, NULL, database_now
            );
            RETURN QUERY SELECT was_replayed, selected_binding.id,
                selected_binding.name::text, selected_binding.vault_provider::text,
                selected_binding.vault_ref::text, selected_binding.version_ref::text,
                selected_binding.credential_scheme::text,
                selected_binding.host::text, selected_binding.username::text,
                (selected_binding.inject_env)::jsonb;
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_claim_secret_lease_v1("
        "text,uuid,uuid) FROM PUBLIC"
    )


def _install_runner_preview_api() -> None:
    """Install possession-bound, bounded Preview command transitions."""

    for table in (
        "saas_preview_executions",
        "saas_preview_commands",
        "saas_preview_sessions",
    ):
        _definer_policy(table)

    op.execute(
        """
        CREATE FUNCTION public.saas_runner_preview_authority_v1(
            expected_capability_hash text,
            expected_runner_id uuid,
            expected_child_run_id uuid,
            expected_preview_execution_id uuid,
            expected_connection_generation bigint,
            expected_run_fence_token bigint
        ) RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            selected_runner public.saas_runner_registrations%ROWTYPE;
            selected_capability public.saas_capability_tokens%ROWTYPE;
            selected_run public.saas_runs%ROWTYPE;
            selected_dispatch public.saas_run_dispatches%ROWTYPE;
            selected_execution public.saas_preview_executions%ROWTYPE;
            selected_change_set public.saas_changesets%ROWTYPE;
            selected_profile public.saas_execution_profiles%ROWTYPE;
            selected_policy public.saas_egress_policies%ROWTYPE;
            checkpoint_revision text;
            database_now timestamptz := clock_timestamp();
        BEGIN
            IF expected_capability_hash !~ '^[0-9a-f]{64}$'
               OR expected_runner_id IS NULL OR expected_child_run_id IS NULL
               OR expected_preview_execution_id IS NULL
               OR expected_connection_generation <= 0
               OR expected_run_fence_token <= 0 THEN
                RAISE EXCEPTION 'runner_preview_authority_invalid'
                    USING ERRCODE = '22023';
            END IF;
            SELECT candidate.* INTO selected_runner
            FROM public.saas_runner_registrations AS candidate
            WHERE candidate.id = expected_runner_id;
            IF NOT FOUND OR selected_runner.status NOT IN ('online', 'draining')
               OR selected_runner.connection_generation <>
                    expected_connection_generation
               OR session_user::text <> 'runner_' ||
                    replace(expected_runner_id::text, '-', '') || '_g' ||
                    expected_connection_generation::text THEN
                RAISE EXCEPTION 'runner_preview_runner_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_capability
            FROM public.saas_capability_tokens AS candidate
            WHERE candidate.token_hash = expected_capability_hash
              AND candidate.run_id = expected_child_run_id
              AND candidate.runner_id = expected_runner_id;
            IF NOT FOUND OR selected_capability.runner_connection_generation <>
                    expected_connection_generation
               OR selected_capability.fence_token <> expected_run_fence_token
               OR selected_capability.revoked_at IS NOT NULL
               OR selected_capability.expires_at <= database_now
               OR NOT (selected_capability.allowed_actions)::jsonb ? 'run.execute'
               OR NOT (selected_capability.allowed_actions)::jsonb ? 'preview.serve'
               OR NOT (selected_capability.allowed_actions)::jsonb ? 'worktree.read' THEN
                RAISE EXCEPTION 'runner_preview_capability_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_run
            FROM public.saas_runs AS candidate
            WHERE candidate.id = expected_child_run_id;
            IF NOT FOUND OR selected_run.status <> 'running'
               OR selected_run.tenant_id <> selected_capability.tenant_id
               OR selected_run.space_id <> selected_capability.space_id
               OR selected_run.project_id <> selected_capability.project_id
               OR selected_run.lease_owner <> expected_runner_id::text
               OR selected_run.fence_token <> expected_run_fence_token
               OR selected_run.lease_token IS NULL
               OR selected_run.lease_expires_at IS NULL
               OR selected_run.lease_expires_at <= database_now THEN
                RAISE EXCEPTION 'runner_preview_run_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_dispatch
            FROM public.saas_run_dispatches AS candidate
            WHERE candidate.run_id = expected_child_run_id;
            IF NOT FOUND OR selected_dispatch.status <> 'leased'
               OR selected_dispatch.selected_runner_id <> expected_runner_id
               OR selected_dispatch.dispatch_generation <>
                    selected_capability.dispatch_generation THEN
                RAISE EXCEPTION 'runner_preview_dispatch_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.id = expected_preview_execution_id;
            IF NOT FOUND OR selected_execution.child_run_id <> selected_run.id
               OR selected_execution.tenant_id <> selected_run.tenant_id
               OR selected_execution.space_id <> selected_run.space_id
               OR selected_execution.project_id <> selected_run.project_id
               OR selected_execution.profile <> 'static_web_v1'
               OR selected_execution.status NOT IN (
                    'queued', 'materializing', 'starting', 'ready', 'stopping',
                    'stopped', 'failed', 'revoked'
               ) THEN
                RAISE EXCEPTION 'runner_preview_execution_stale'
                    USING ERRCODE = '42501';
            END IF;
            checkpoint_revision :=
                selected_run.input -> 'execution' ->> 'checkpoint_revision';
            SELECT candidate.* INTO selected_change_set
            FROM public.saas_changesets AS candidate
            WHERE candidate.id = selected_execution.change_set_id;
            IF NOT FOUND OR selected_change_set.status <> 'committed'
               OR selected_change_set.tenant_id <> selected_execution.tenant_id
               OR selected_change_set.space_id <> selected_execution.space_id
               OR selected_change_set.project_id <> selected_execution.project_id
               OR selected_change_set.head_revision IS NULL
               OR selected_change_set.recovery_artifact_ref IS NULL
               OR checkpoint_revision IS NULL
               OR checkpoint_revision <> selected_change_set.head_revision
               OR selected_run.input ->> 'change_set_id' <>
                    selected_change_set.id::text
               OR selected_run.input -> 'execution' ->> 'kind' <>
                    'omnigent.preview.v1'
               OR selected_run.input -> 'execution' ->> 'preview_execution_id' <>
                    selected_execution.id::text
               OR selected_capability.resource_scope ->> 'change_set_id' <>
                    selected_change_set.id::text THEN
                RAISE EXCEPTION 'runner_preview_checkpoint_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_profile
            FROM public.saas_execution_profiles AS candidate
            WHERE candidate.id = selected_dispatch.execution_profile_id;
            SELECT candidate.* INTO selected_policy
            FROM public.saas_egress_policies AS candidate
            WHERE candidate.id = selected_dispatch.egress_policy_id;
            IF selected_profile.id IS NULL OR selected_policy.id IS NULL
               OR selected_profile.tenant_id <> selected_execution.tenant_id
               OR selected_profile.space_id <> selected_execution.space_id
               OR selected_profile.project_id <> selected_execution.project_id
               OR selected_policy.tenant_id <> selected_execution.tenant_id
               OR selected_policy.space_id <> selected_execution.space_id
               OR selected_policy.project_id <> selected_execution.project_id
               OR selected_profile.egress_policy_id <> selected_policy.id
               OR selected_profile.config_hash <>
                    selected_dispatch.execution_profile_hash
               OR selected_policy.rules_hash <> selected_dispatch.egress_policy_hash
               OR selected_profile.status NOT IN ('active', 'retired')
               OR selected_policy.status NOT IN ('active', 'retired') THEN
                RAISE EXCEPTION 'runner_preview_profile_stale'
                    USING ERRCODE = '42501';
            END IF;
            RETURN jsonb_build_object(
                'capability_id', selected_capability.id::text,
                'tenant_id', selected_execution.tenant_id::text,
                'space_id', selected_execution.space_id::text,
                'project_id', selected_execution.project_id::text,
                'preview_execution_id', selected_execution.id::text,
                'child_run_id', selected_execution.child_run_id::text,
                'change_set_id', selected_execution.change_set_id::text,
                'checkpoint_revision', checkpoint_revision,
                'placement_id', selected_runner.placement_id::text,
                'expires_at', to_jsonb(selected_execution.expires_at)
            );
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_preview_authority_v1("
        "text,uuid,uuid,uuid,bigint,bigint) FROM PUBLIC"
    )

    op.execute(
        """
        CREATE FUNCTION public.saas_runner_claim_preview_start_v1(
            expected_capability_hash text,
            expected_runner_id uuid,
            expected_child_run_id uuid,
            expected_preview_execution_id uuid,
            expected_connection_generation bigint,
            expected_run_fence_token bigint,
            requested_claim_token_hash text
        ) RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            authority jsonb;
            selected_execution public.saas_preview_executions%ROWTYPE;
            selected_command public.saas_preview_commands%ROWTYPE;
            database_now timestamptz := statement_timestamp();
            replayed boolean := false;
            expected_request_hash text;
        BEGIN
            IF requested_claim_token_hash !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'runner_preview_claim_invalid'
                    USING ERRCODE = '22023';
            END IF;
            authority := public.saas_runner_preview_authority_v1(
                expected_capability_hash, expected_runner_id,
                expected_child_run_id, expected_preview_execution_id,
                expected_connection_generation, expected_run_fence_token
            );
            SELECT candidate.* INTO selected_execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.id = expected_preview_execution_id
            FOR UPDATE;
            SELECT candidate.* INTO selected_command
            FROM public.saas_preview_commands AS candidate
            WHERE candidate.preview_execution_id = expected_preview_execution_id
              AND candidate.command_type = 'start'
            ORDER BY candidate.generation DESC
            LIMIT 1 FOR UPDATE;
            authority := public.saas_runner_preview_authority_v1(
                expected_capability_hash, expected_runner_id,
                expected_child_run_id, expected_preview_execution_id,
                expected_connection_generation, expected_run_fence_token
            );
            database_now := clock_timestamp();
            expected_request_hash := public.saas_canonical_json_sha256_v1(
                jsonb_build_object(
                    'command_type', 'start', 'generation', 1,
                    'preview_execution_id', expected_preview_execution_id::text
                )
            );
            IF selected_execution.id IS NULL OR selected_command.id IS NULL
               OR selected_command.generation <> 1
               OR selected_command.request_hash <> expected_request_hash
               OR selected_execution.expires_at <= database_now THEN
                RAISE EXCEPTION 'runner_preview_start_command_stale'
                    USING ERRCODE = '42501';
            END IF;
            IF selected_command.status = 'claimed'
               AND selected_command.claim_token_hash = requested_claim_token_hash
               AND selected_command.runner_id = expected_runner_id
               AND selected_command.runner_connection_generation =
                    expected_connection_generation
               AND selected_command.run_fence_token = expected_run_fence_token
               AND selected_execution.status = 'materializing'
               AND selected_execution.runner_id = expected_runner_id
               AND selected_execution.runner_connection_generation =
                    expected_connection_generation
               AND selected_execution.run_fence_token = expected_run_fence_token THEN
                replayed := true;
            ELSIF selected_command.status = 'pending'
                  AND selected_execution.status = 'queued' THEN
                UPDATE public.saas_preview_commands AS mutated
                SET status = 'claimed', claim_token_hash = requested_claim_token_hash,
                    claimed_by_gateway = 'runner-control',
                    runner_id = expected_runner_id,
                    placement_id = (authority ->> 'placement_id')::uuid,
                    runner_connection_generation = expected_connection_generation,
                    run_fence_token = expected_run_fence_token,
                    claimed_at = database_now, completed_at = NULL,
                    failure_code = NULL, attempt_count = mutated.attempt_count + 1,
                    updated_at = database_now
                WHERE mutated.id = selected_command.id;
                UPDATE public.saas_preview_executions AS mutated
                SET status = 'materializing', runner_id = expected_runner_id,
                    placement_id = (authority ->> 'placement_id')::uuid,
                    runner_connection_generation = expected_connection_generation,
                    run_fence_token = expected_run_fence_token,
                    worktree_id = NULL, worktree_lease_generation = NULL,
                    ready_at = NULL, version = mutated.version + 1,
                    updated_at = database_now
                WHERE mutated.id = selected_execution.id;
                UPDATE public.saas_preview_sessions AS browser_session
                SET status = 'revoked', revoked_at = database_now,
                    updated_at = database_now
                WHERE browser_session.preview_execution_id = selected_execution.id
                  AND browser_session.status = 'active';
            ELSE
                RAISE EXCEPTION 'runner_preview_start_command_stale'
                    USING ERRCODE = '42501';
            END IF;
            RETURN authority || jsonb_build_object(
                'command_id', selected_command.id::text,
                'replayed', replayed
            );
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_claim_preview_start_v1("
        "text,uuid,uuid,uuid,bigint,bigint,text) FROM PUBLIC"
    )

    op.execute(
        """
        CREATE FUNCTION public.saas_runner_claim_preview_stop_v1(
            expected_capability_hash text,
            expected_runner_id uuid,
            expected_child_run_id uuid,
            expected_preview_execution_id uuid,
            expected_connection_generation bigint,
            expected_run_fence_token bigint,
            requested_claim_token_hash text
        ) RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            authority jsonb;
            selected_execution public.saas_preview_executions%ROWTYPE;
            selected_command public.saas_preview_commands%ROWTYPE;
            database_now timestamptz := statement_timestamp();
            generated_command_id uuid;
            generated_request_hash text;
            replayed boolean := false;
        BEGIN
            IF requested_claim_token_hash !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'runner_preview_claim_invalid'
                    USING ERRCODE = '22023';
            END IF;
            authority := public.saas_runner_preview_authority_v1(
                expected_capability_hash, expected_runner_id,
                expected_child_run_id, expected_preview_execution_id,
                expected_connection_generation, expected_run_fence_token
            );
            SELECT candidate.* INTO selected_execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.id = expected_preview_execution_id
            FOR UPDATE;
            authority := public.saas_runner_preview_authority_v1(
                expected_capability_hash, expected_runner_id,
                expected_child_run_id, expected_preview_execution_id,
                expected_connection_generation, expected_run_fence_token
            );
            database_now := clock_timestamp();
            IF selected_execution.status IN ('stopped', 'failed', 'revoked') THEN
                RETURN authority || jsonb_build_object(
                    'terminal', true, 'command_id', NULL, 'replayed', true
                );
            END IF;
            IF selected_execution.runner_id <> expected_runner_id
               OR selected_execution.runner_connection_generation <>
                    expected_connection_generation
               OR selected_execution.run_fence_token <> expected_run_fence_token THEN
                RAISE EXCEPTION 'runner_preview_execution_stale'
                    USING ERRCODE = '42501';
            END IF;
            SELECT candidate.* INTO selected_command
            FROM public.saas_preview_commands AS candidate
            WHERE candidate.preview_execution_id = expected_preview_execution_id
              AND candidate.command_type = 'stop'
            ORDER BY candidate.generation DESC
            LIMIT 1 FOR UPDATE;
            IF NOT FOUND AND selected_execution.expires_at <= database_now THEN
                generated_command_id := gen_random_uuid();
                generated_request_hash := public.saas_canonical_json_sha256_v1(
                    jsonb_build_object(
                        'operation', 'expire',
                        'preview_execution_id', selected_execution.id::text
                    )
                );
                INSERT INTO public.saas_preview_commands (
                    id, tenant_id, space_id, project_id, preview_execution_id,
                    command_type, generation, request_hash, status, runner_id,
                    placement_id, runner_connection_generation, run_fence_token,
                    claim_token_hash, claimed_by_gateway, attempt_count,
                    available_at, claimed_at, completed_at, failure_code,
                    created_at, updated_at
                ) VALUES (
                    generated_command_id, selected_execution.tenant_id,
                    selected_execution.space_id, selected_execution.project_id,
                    selected_execution.id, 'stop',
                    selected_execution.command_generation + 1,
                    generated_request_hash, 'pending', NULL, NULL, NULL, NULL,
                    NULL, NULL, 0, database_now, NULL, NULL, NULL,
                    database_now, database_now
                ) ON CONFLICT (preview_execution_id, command_type, generation)
                    DO NOTHING;
                SELECT candidate.* INTO selected_command
                FROM public.saas_preview_commands AS candidate
                WHERE candidate.preview_execution_id = expected_preview_execution_id
                  AND candidate.command_type = 'stop'
                  AND candidate.generation = selected_execution.command_generation + 1
                FOR UPDATE;
                UPDATE public.saas_preview_executions AS mutated
                SET command_generation = selected_command.generation,
                    version = mutated.version + 1, updated_at = database_now
                WHERE mutated.id = selected_execution.id
                  AND mutated.command_generation < selected_command.generation;
            END IF;
            authority := public.saas_runner_preview_authority_v1(
                expected_capability_hash, expected_runner_id,
                expected_child_run_id, expected_preview_execution_id,
                expected_connection_generation, expected_run_fence_token
            );
            database_now := clock_timestamp();
            IF selected_command.id IS NULL THEN
                RETURN authority || jsonb_build_object(
                    'terminal', false, 'command_id', NULL, 'replayed', false
                );
            END IF;
            IF selected_command.status = 'claimed'
               AND selected_command.claim_token_hash = requested_claim_token_hash
               AND selected_command.runner_id = expected_runner_id
               AND selected_command.runner_connection_generation =
                    expected_connection_generation
               AND selected_command.run_fence_token = expected_run_fence_token
               AND selected_execution.status = 'stopping' THEN
                replayed := true;
            ELSIF selected_command.status = 'pending' THEN
                UPDATE public.saas_preview_commands AS mutated
                SET status = 'claimed', claim_token_hash = requested_claim_token_hash,
                    claimed_by_gateway = 'runner-control',
                    runner_id = expected_runner_id,
                    placement_id = (authority ->> 'placement_id')::uuid,
                    runner_connection_generation = expected_connection_generation,
                    run_fence_token = expected_run_fence_token,
                    claimed_at = database_now,
                    attempt_count = mutated.attempt_count + 1,
                    updated_at = database_now
                WHERE mutated.id = selected_command.id;
                UPDATE public.saas_preview_executions AS mutated
                SET status = 'stopping', version = mutated.version + 1,
                    updated_at = database_now
                WHERE mutated.id = selected_execution.id;
                UPDATE public.saas_preview_sessions AS browser_session
                SET status = 'revoked', revoked_at = database_now,
                    updated_at = database_now
                WHERE browser_session.preview_execution_id = selected_execution.id
                  AND browser_session.status = 'active';
            ELSE
                RAISE EXCEPTION 'runner_preview_stop_command_stale'
                    USING ERRCODE = '42501';
            END IF;
            RETURN authority || jsonb_build_object(
                'terminal', false, 'command_id', selected_command.id::text,
                'replayed', replayed
            );
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_claim_preview_stop_v1("
        "text,uuid,uuid,uuid,bigint,bigint,text) FROM PUBLIC"
    )

    op.execute(
        """
        CREATE FUNCTION public.saas_runner_transition_preview_v1(
            requested_operation text,
            expected_capability_hash text,
            expected_runner_id uuid,
            expected_child_run_id uuid,
            expected_preview_execution_id uuid,
            expected_connection_generation bigint,
            expected_run_fence_token bigint,
            expected_command_id uuid,
            expected_claim_token_hash text,
            expected_worktree_id uuid,
            expected_worktree_lease_generation bigint,
            requested_success boolean,
            requested_cancelled boolean,
            requested_failure_code text
        ) RETURNS jsonb
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            authority jsonb;
            selected_execution public.saas_preview_executions%ROWTYPE;
            selected_command public.saas_preview_commands%ROWTYPE;
            selected_worktree public.saas_worktree_instances%ROWTYPE;
            database_now timestamptz := statement_timestamp();
            expected_command_type text;
            terminal_status text;
            derived_failure_code text;
        BEGIN
            IF requested_operation NOT IN (
                    'mark_starting', 'prepare_route', 'mark_ready',
                    'complete_stop', 'fail_start', 'abort_runtime'
               ) OR expected_command_id IS NULL
               OR expected_claim_token_hash !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'runner_preview_transition_invalid'
                    USING ERRCODE = '22023';
            END IF;
            authority := public.saas_runner_preview_authority_v1(
                expected_capability_hash, expected_runner_id,
                expected_child_run_id, expected_preview_execution_id,
                expected_connection_generation, expected_run_fence_token
            );
            expected_command_type := CASE
                WHEN requested_operation = 'complete_stop' THEN 'stop'
                ELSE 'start'
            END;
            SELECT candidate.* INTO selected_execution
            FROM public.saas_preview_executions AS candidate
            WHERE candidate.id = expected_preview_execution_id
            FOR UPDATE;
            SELECT candidate.* INTO selected_command
            FROM public.saas_preview_commands AS candidate
            WHERE candidate.id = expected_command_id
            FOR UPDATE;
            IF selected_execution.id IS NULL OR selected_command.id IS NULL
               OR selected_command.preview_execution_id <> selected_execution.id
               OR selected_command.command_type <> expected_command_type
               OR selected_command.claim_token_hash <> expected_claim_token_hash
               OR selected_command.runner_id <> expected_runner_id
               OR selected_command.runner_connection_generation <>
                    expected_connection_generation
               OR selected_command.run_fence_token <> expected_run_fence_token
               OR selected_execution.runner_id <> expected_runner_id
               OR selected_execution.runner_connection_generation <>
                    expected_connection_generation
               OR selected_execution.run_fence_token <> expected_run_fence_token THEN
                RAISE EXCEPTION 'runner_preview_command_claim_stale'
                    USING ERRCODE = '42501';
            END IF;
            IF requested_operation IN ('prepare_route', 'mark_ready') THEN
                SELECT candidate.* INTO selected_worktree
                FROM public.saas_worktree_instances AS candidate
                WHERE candidate.id = expected_worktree_id
                FOR UPDATE;
            END IF;
            authority := public.saas_runner_preview_authority_v1(
                expected_capability_hash, expected_runner_id,
                expected_child_run_id, expected_preview_execution_id,
                expected_connection_generation, expected_run_fence_token
            );
            database_now := clock_timestamp();
            IF requested_operation IN ('prepare_route', 'mark_ready') THEN
                IF selected_worktree.id IS NULL
                   OR selected_execution.status NOT IN ('starting', 'ready')
                   OR selected_execution.expires_at <= database_now
                   OR selected_worktree.run_id <> selected_execution.child_run_id
                   OR selected_worktree.change_set_id <> selected_execution.change_set_id
                   OR selected_worktree.runner_id <> expected_runner_id
                   OR selected_worktree.runner_connection_generation <>
                        expected_connection_generation
                   OR selected_worktree.run_fence_token <> expected_run_fence_token
                   OR selected_worktree.lease_generation <>
                        expected_worktree_lease_generation
                   OR selected_worktree.access_mode <> 'readonly'
                   OR selected_worktree.dirty
                   OR selected_worktree.status <> 'ready'
                   OR selected_worktree.lease_expires_at IS NULL
                   OR selected_worktree.lease_expires_at <= database_now
                   OR selected_worktree.maximum_lifetime_at IS NULL
                   OR selected_worktree.maximum_lifetime_at <= database_now THEN
                    RAISE EXCEPTION 'runner_preview_ready_fence_stale'
                        USING ERRCODE = '42501';
                END IF;
            END IF;
            IF requested_operation = 'mark_starting' THEN
                IF selected_command.status <> 'claimed'
                   OR selected_execution.status NOT IN ('materializing', 'starting')
                   OR selected_execution.expires_at <= database_now THEN
                    RAISE EXCEPTION 'runner_preview_execution_stale'
                        USING ERRCODE = '42501';
                END IF;
                IF selected_execution.status = 'materializing' THEN
                    UPDATE public.saas_preview_executions AS mutated
                    SET status = 'starting', version = mutated.version + 1,
                        updated_at = database_now
                    WHERE mutated.id = selected_execution.id;
                    UPDATE public.saas_preview_commands AS mutated
                    SET updated_at = database_now
                    WHERE mutated.id = selected_command.id;
                END IF;
            ELSIF requested_operation = 'prepare_route' THEN
                IF selected_command.status <> 'claimed' THEN
                    RAISE EXCEPTION 'runner_preview_command_claim_stale'
                        USING ERRCODE = '42501';
                END IF;
            ELSIF requested_operation = 'mark_ready' THEN
                IF selected_command.status = 'succeeded'
                   AND selected_execution.status = 'ready'
                   AND selected_execution.worktree_id = selected_worktree.id
                   AND selected_execution.worktree_lease_generation =
                        selected_worktree.lease_generation THEN
                    NULL;
                ELSIF selected_command.status = 'claimed'
                      AND selected_execution.status = 'starting' THEN
                    UPDATE public.saas_preview_executions AS mutated
                    SET status = 'ready', worktree_id = selected_worktree.id,
                        worktree_lease_generation = selected_worktree.lease_generation,
                        ready_at = database_now, version = mutated.version + 1,
                        updated_at = database_now
                    WHERE mutated.id = selected_execution.id;
                    UPDATE public.saas_preview_commands AS mutated
                    SET status = 'succeeded', completed_at = database_now,
                        updated_at = database_now
                    WHERE mutated.id = selected_command.id;
                ELSE
                    RAISE EXCEPTION 'runner_preview_ready_fence_stale'
                        USING ERRCODE = '42501';
                END IF;
            ELSIF requested_operation = 'complete_stop' THEN
                IF requested_success IS NULL THEN
                    RAISE EXCEPTION 'runner_preview_transition_invalid'
                        USING ERRCODE = '22023';
                END IF;
                terminal_status := CASE WHEN requested_success THEN 'stopped' ELSE 'failed' END;
                derived_failure_code := CASE
                    WHEN requested_success THEN NULL ELSE 'preview_stop_failed' END;
                IF ((requested_success AND selected_command.status = 'succeeded')
                    OR (NOT requested_success AND selected_command.status = 'failed'))
                   AND selected_execution.status = terminal_status THEN
                    NULL;
                ELSIF selected_command.status = 'claimed'
                      AND selected_execution.status = 'stopping' THEN
                    UPDATE public.saas_preview_commands AS mutated
                    SET status = CASE WHEN requested_success THEN 'succeeded' ELSE 'failed' END,
                        failure_code = derived_failure_code, completed_at = database_now,
                        updated_at = database_now
                    WHERE mutated.id = selected_command.id;
                    UPDATE public.saas_preview_executions AS mutated
                    SET status = terminal_status, failure_code = derived_failure_code,
                        terminal_at = database_now, version = mutated.version + 1,
                        updated_at = database_now
                    WHERE mutated.id = selected_execution.id;
                ELSE
                    RAISE EXCEPTION 'runner_preview_stop_command_stale'
                        USING ERRCODE = '42501';
                END IF;
            ELSIF requested_operation = 'fail_start' THEN
                derived_failure_code := CASE
                    WHEN requested_failure_code ~ '^[a-z][a-z0-9_]{2,63}$'
                    THEN requested_failure_code ELSE 'preview_start_failed' END;
                IF selected_command.status = 'failed'
                   AND selected_execution.status = 'failed'
                   AND selected_command.failure_code = derived_failure_code
                   AND selected_execution.failure_code = derived_failure_code THEN
                    NULL;
                ELSIF selected_command.status = 'claimed'
                      AND selected_execution.status IN (
                          'materializing', 'starting', 'ready'
                      ) THEN
                    UPDATE public.saas_preview_commands AS mutated
                    SET status = 'failed', failure_code = derived_failure_code,
                        completed_at = database_now, updated_at = database_now
                    WHERE mutated.id = selected_command.id;
                    UPDATE public.saas_preview_executions AS mutated
                    SET status = 'failed', failure_code = derived_failure_code,
                        terminal_at = database_now, version = mutated.version + 1,
                        updated_at = database_now
                    WHERE mutated.id = selected_execution.id;
                ELSE
                    RAISE EXCEPTION 'runner_preview_start_command_stale'
                        USING ERRCODE = '42501';
                END IF;
            ELSE
                IF requested_cancelled IS NULL THEN
                    RAISE EXCEPTION 'runner_preview_transition_invalid'
                        USING ERRCODE = '22023';
                END IF;
                terminal_status := CASE WHEN requested_cancelled THEN 'revoked' ELSE 'failed' END;
                derived_failure_code := CASE
                    WHEN requested_cancelled THEN NULL ELSE 'preview_runtime_failed' END;
                IF selected_execution.status = terminal_status THEN
                    NULL;
                ELSIF selected_execution.status NOT IN ('stopped', 'failed', 'revoked') THEN
                    IF selected_command.status = 'claimed' THEN
                        UPDATE public.saas_preview_commands AS mutated
                        SET status = CASE
                                WHEN requested_cancelled THEN 'cancelled'
                                ELSE 'failed'
                            END,
                            failure_code = derived_failure_code, completed_at = database_now,
                            updated_at = database_now
                        WHERE mutated.id = selected_command.id;
                    END IF;
                    UPDATE public.saas_preview_executions AS mutated
                    SET status = terminal_status, failure_code = derived_failure_code,
                        terminal_at = database_now, version = mutated.version + 1,
                        updated_at = database_now
                    WHERE mutated.id = selected_execution.id;
                ELSE
                    RAISE EXCEPTION 'runner_preview_execution_stale'
                        USING ERRCODE = '42501';
                END IF;
            END IF;
            IF requested_operation IN ('complete_stop', 'fail_start', 'abort_runtime') THEN
                UPDATE public.saas_preview_sessions AS browser_session
                SET status = 'revoked', revoked_at = database_now,
                    updated_at = database_now
                WHERE browser_session.preview_execution_id = selected_execution.id
                  AND browser_session.status = 'active';
            END IF;
            RETURN authority || jsonb_build_object(
                'worktree_id', CASE WHEN selected_worktree.id IS NULL THEN NULL
                    ELSE selected_worktree.id::text END,
                'worktree_lease_generation', selected_worktree.lease_generation,
                'opaque_preview_key', selected_execution.opaque_preview_key,
                'preview_host', selected_execution.preview_host
            );
        END
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_transition_preview_v1("
        "text,text,uuid,uuid,uuid,bigint,bigint,uuid,text,uuid,bigint,"
        "boolean,boolean,text) FROM PUBLIC"
    )


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    op.execute(
        """
        CREATE FUNCTION public.saas_runner_agent_identity_v1(
            expected_runner_id uuid,
            expected_generation bigint
        ) RETURNS boolean
        LANGUAGE sql
        STABLE
        PARALLEL SAFE
        SECURITY INVOKER
        SET search_path = pg_catalog
        AS $function$
            SELECT current_user = session_user
               AND expected_runner_id IS NOT NULL
               AND expected_generation > 0
               AND session_user::text =
                   'runner_' || replace(expected_runner_id::text, '-', '') ||
                   '_g' || expected_generation::text
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_agent_identity_v1(uuid,bigint) FROM PUBLIC"
    )
    # P0S10 first narrows every unrelated legacy registration policy to its
    # intended service roles.  The Runner's own exact registration policy is
    # therefore non-recursive and this predicate can remain an invoker.  FORCE
    # RLS must apply to a real NOBYPASSRLS schema owner as well as to tests.
    op.execute(
        """
        CREATE FUNCTION public.saas_runner_agent_registered_v1(
            expected_runner_id uuid,
            expected_generation bigint
        ) RETURNS boolean
        LANGUAGE sql
        STABLE
        PARALLEL SAFE
        SECURITY INVOKER
        SET search_path = pg_catalog
        AS $function$
            SELECT public.saas_runner_agent_identity_v1(
                       expected_runner_id,
                       expected_generation
                   )
               AND EXISTS (
                    SELECT 1
                    FROM public.saas_runner_registrations AS current_runner
                    WHERE current_runner.id = expected_runner_id
                      AND current_runner.connection_generation = expected_generation
                      AND current_runner.status IN ('online', 'draining')
               )
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_runner_agent_registered_v1(uuid,bigint) FROM PUBLIC"
    )
    _restrict_legacy_policy_roles()
    _install_runner_worktree_api()
    _install_runner_isolation_api()
    _install_runner_preview_api()

    registration = (
        "public.saas_runner_agent_identity_v1(id, connection_generation) "
        "AND status IN ('online', 'draining')"
    )
    capability = _live_capability("saas_capability_tokens", "run.execute")
    dispatch = (
        "status = 'leased' AND selected_runner_id IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.run_id = saas_run_dispatches.run_id "
        "AND runner_capability.runner_id = saas_run_dispatches.selected_runner_id "
        "AND runner_capability.dispatch_generation = saas_run_dispatches.dispatch_generation "
        f"AND {_live_capability('runner_capability', 'run.execute')})"
    )
    run = (
        "EXISTS (SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.run_id = saas_runs.id "
        "AND runner_capability.tenant_id = saas_runs.tenant_id "
        "AND runner_capability.space_id = saas_runs.space_id "
        "AND runner_capability.project_id = saas_runs.project_id "
        "AND runner_capability.fence_token = saas_runs.fence_token "
        "AND saas_runs.lease_owner = runner_capability.runner_id::text "
        "AND saas_runs.lease_expires_at > statement_timestamp() "
        f"AND {_live_capability('runner_capability', 'run.execute')})"
    )
    changeset_read = (
        "EXISTS (SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.tenant_id = saas_changesets.tenant_id "
        "AND runner_capability.space_id = saas_changesets.space_id "
        "AND runner_capability.project_id = saas_changesets.project_id "
        "AND runner_capability.resource_scope ->> 'change_set_id' = saas_changesets.id::text "
        f"AND {_live_capability('runner_capability', 'worktree.read', 'worktree.write')})"
    )
    _changeset_write = (
        "EXISTS (SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.tenant_id = saas_changesets.tenant_id "
        "AND runner_capability.space_id = saas_changesets.space_id "
        "AND runner_capability.project_id = saas_changesets.project_id "
        "AND runner_capability.resource_scope ->> 'change_set_id' = saas_changesets.id::text "
        f"AND {_live_capability('runner_capability', 'worktree.write')})"
    )
    repository = (
        "EXISTS (SELECT 1 FROM public.saas_changesets AS selected_changeset "
        "JOIN public.saas_capability_tokens AS runner_capability "
        "ON runner_capability.resource_scope ->> 'change_set_id' = selected_changeset.id::text "
        "WHERE selected_changeset.repository_id = saas_repositories.id "
        "AND selected_changeset.tenant_id = saas_repositories.tenant_id "
        "AND selected_changeset.space_id = saas_repositories.space_id "
        "AND selected_changeset.project_id = saas_repositories.project_id "
        f"AND {_live_capability('runner_capability', 'worktree.read', 'worktree.write')})"
    )
    changeset_group_read = (
        "EXISTS (SELECT 1 FROM public.saas_changesets AS selected_changeset "
        "JOIN public.saas_capability_tokens AS runner_capability "
        "ON runner_capability.resource_scope ->> 'change_set_id' = selected_changeset.id::text "
        "WHERE selected_changeset.group_id = saas_changeset_groups.id "
        "AND selected_changeset.tenant_id = saas_changeset_groups.tenant_id "
        "AND selected_changeset.space_id = saas_changeset_groups.space_id "
        "AND selected_changeset.project_id = saas_changeset_groups.project_id "
        f"AND {_live_capability('runner_capability', 'worktree.read', 'worktree.write')})"
    )
    _changeset_group_write = (
        "EXISTS (SELECT 1 FROM public.saas_changesets AS selected_changeset "
        "JOIN public.saas_capability_tokens AS runner_capability "
        "ON runner_capability.resource_scope ->> 'change_set_id' = selected_changeset.id::text "
        "WHERE selected_changeset.group_id = saas_changeset_groups.id "
        "AND selected_changeset.tenant_id = saas_changeset_groups.tenant_id "
        "AND selected_changeset.space_id = saas_changeset_groups.space_id "
        "AND selected_changeset.project_id = saas_changeset_groups.project_id "
        f"AND {_live_capability('runner_capability', 'worktree.write')})"
    )
    project_scope = (
        "EXISTS (SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.tenant_id = saas_worktree_quotas.tenant_id "
        "AND runner_capability.space_id = saas_worktree_quotas.space_id "
        "AND runner_capability.project_id = saas_worktree_quotas.project_id "
        f"AND {_live_capability('runner_capability', 'worktree.read', 'worktree.write')})"
    )
    own_worktree = (
        f"({_registered('runner_id', 'runner_connection_generation')}) AND "
        "((status IN ('rebuild_pending', 'released', 'quarantined', "
        "'gc_eligible', 'deleted')) OR "
        "(status IN ('reserved', 'materializing', 'ready', 'checkpointing') "
        "AND lease_expires_at > statement_timestamp() "
        "AND maximum_lifetime_at > statement_timestamp())) "
        "AND EXISTS (SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.run_id = saas_worktree_instances.run_id "
        "AND runner_capability.runner_id = saas_worktree_instances.runner_id "
        "AND runner_capability.runner_connection_generation = "
        "saas_worktree_instances.runner_connection_generation "
        "AND runner_capability.fence_token = saas_worktree_instances.run_fence_token "
        "AND runner_capability.resource_scope ->> 'change_set_id' = "
        "saas_worktree_instances.change_set_id::text "
        "AND ((saas_worktree_instances.access_mode = 'writer' AND "
        f"{_live_capability('runner_capability', 'worktree.write')}) OR "
        "(saas_worktree_instances.access_mode = 'readonly' AND "
        f"{_live_capability('runner_capability', 'worktree.read')})))"
    )
    recovery_worktree = (
        "status = 'rebuild_pending' AND access_mode = 'writer' AND dirty = true "
        "AND recovery_artifact_ref IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.tenant_id = saas_worktree_instances.tenant_id "
        "AND runner_capability.space_id = saas_worktree_instances.space_id "
        "AND runner_capability.project_id = saas_worktree_instances.project_id "
        "AND runner_capability.resource_scope ->> 'change_set_id' = "
        "saas_worktree_instances.change_set_id::text "
        f"AND {_live_capability('runner_capability', 'worktree.write')})"
    )
    worktree = f"(({own_worktree}) OR ({recovery_worktree}))"
    _worktree_insert = (
        "status = 'reserved' AND lease_generation = 1 AND lease_token_hash IS NOT NULL "
        "AND lease_expires_at > statement_timestamp() "
        "AND maximum_lifetime_at > lease_expires_at "
        "AND heartbeat_at IS NOT NULL AND released_at IS NULL "
        "AND quarantine_reason IS NULL AND deleted_at IS NULL "
        "AND actual_bytes = 0 AND dirty = false AND event_sequence = 0 AND EXISTS ("
        "SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "JOIN public.saas_runs AS selected_run ON selected_run.id = runner_capability.run_id "
        "JOIN public.saas_run_dispatches AS selected_dispatch "
        "ON selected_dispatch.run_id = runner_capability.run_id "
        "JOIN public.saas_changesets AS selected_changeset "
        "ON selected_changeset.id = saas_worktree_instances.change_set_id "
        "JOIN public.saas_worktree_quotas AS selected_quota "
        "ON selected_quota.tenant_id = saas_worktree_instances.tenant_id "
        "AND selected_quota.space_id = saas_worktree_instances.space_id "
        "AND selected_quota.project_id = saas_worktree_instances.project_id "
        "WHERE runner_capability.run_id = saas_worktree_instances.run_id "
        "AND runner_capability.runner_id = saas_worktree_instances.runner_id "
        "AND runner_capability.runner_connection_generation = "
        "saas_worktree_instances.runner_connection_generation "
        "AND runner_capability.fence_token = saas_worktree_instances.run_fence_token "
        "AND runner_capability.resource_scope ->> 'change_set_id' = "
        "saas_worktree_instances.change_set_id::text "
        "AND runner_capability.tenant_id = saas_worktree_instances.tenant_id "
        "AND runner_capability.space_id = saas_worktree_instances.space_id "
        "AND runner_capability.project_id = saas_worktree_instances.project_id "
        "AND selected_run.tenant_id = saas_worktree_instances.tenant_id "
        "AND selected_run.space_id = saas_worktree_instances.space_id "
        "AND selected_run.project_id = saas_worktree_instances.project_id "
        "AND selected_run.status IN ('leased', 'starting', 'running', 'waiting_input', "
        "'waiting_approval', 'cancelling') "
        "AND selected_run.lease_owner = saas_worktree_instances.runner_id::text "
        "AND selected_run.fence_token = saas_worktree_instances.run_fence_token "
        "AND selected_run.lease_expires_at > statement_timestamp() "
        "AND selected_dispatch.status = 'leased' "
        "AND selected_dispatch.selected_runner_id = saas_worktree_instances.runner_id "
        "AND selected_dispatch.dispatch_generation = runner_capability.dispatch_generation "
        "AND selected_changeset.tenant_id = saas_worktree_instances.tenant_id "
        "AND selected_changeset.space_id = saas_worktree_instances.space_id "
        "AND selected_changeset.project_id = saas_worktree_instances.project_id "
        "AND saas_worktree_instances.maximum_lifetime_at <= statement_timestamp() + "
        "make_interval(secs => selected_quota.max_lifetime_seconds) "
        "AND ((saas_worktree_instances.access_mode = 'writer' "
        "AND selected_changeset.status IN ('open', 'checkpointed') "
        f"AND {_live_capability('runner_capability', 'worktree.write')}) OR "
        "(saas_worktree_instances.access_mode = 'readonly' "
        "AND selected_changeset.status IN ('open', 'checkpointed', 'committed') "
        "AND (NOT ((runner_capability.allowed_actions)::jsonb ? 'preview.serve') OR "
        "(selected_changeset.status = 'committed' "
        "AND selected_changeset.head_revision IS NOT NULL "
        "AND selected_changeset.recovery_artifact_ref IS NOT NULL)) "
        f"AND {_live_capability('runner_capability', 'worktree.read')})) "
        "AND saas_worktree_instances.lease_expires_at <= runner_capability.expires_at "
        "AND saas_worktree_instances.lease_expires_at <= selected_run.lease_expires_at)"
    )
    worktree_event = (
        "EXISTS (SELECT 1 FROM public.saas_worktree_instances AS selected_worktree "
        "WHERE selected_worktree.id = saas_worktree_events.worktree_id)"
    )
    isolation_grant = (
        f"({_registered('runner_id', 'runner_connection_generation')}) AND EXISTS ("
        "SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.id = saas_run_isolation_grants.capability_id "
        "AND runner_capability.run_id = saas_run_isolation_grants.run_id "
        "AND runner_capability.fence_token = saas_run_isolation_grants.run_fence_token "
        f"AND {_live_capability('runner_capability', 'sandbox.launch')})"
    )
    _isolation_grant_insert = (
        "status = 'active' AND redeemed_at IS NULL AND revoked_at IS NULL "
        "AND expires_at > statement_timestamp() "
        "AND expires_at <= statement_timestamp() + interval '2 minutes' AND EXISTS ("
        "SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "JOIN public.saas_runs AS selected_run ON selected_run.id = runner_capability.run_id "
        "JOIN public.saas_run_dispatches AS selected_dispatch "
        "ON selected_dispatch.run_id = runner_capability.run_id "
        "JOIN public.saas_execution_profiles AS selected_profile "
        "ON selected_profile.id = selected_dispatch.execution_profile_id "
        "JOIN public.saas_egress_policies AS selected_egress "
        "ON selected_egress.id = selected_dispatch.egress_policy_id "
        "JOIN public.saas_worktree_instances AS selected_worktree "
        "ON selected_worktree.id = saas_run_isolation_grants.worktree_id "
        "WHERE runner_capability.id = saas_run_isolation_grants.capability_id "
        "AND runner_capability.tenant_id = saas_run_isolation_grants.tenant_id "
        "AND runner_capability.space_id = saas_run_isolation_grants.space_id "
        "AND runner_capability.project_id = saas_run_isolation_grants.project_id "
        "AND runner_capability.run_id = saas_run_isolation_grants.run_id "
        "AND runner_capability.runner_id = saas_run_isolation_grants.runner_id "
        "AND runner_capability.runner_connection_generation = "
        "saas_run_isolation_grants.runner_connection_generation "
        "AND runner_capability.fence_token = saas_run_isolation_grants.run_fence_token "
        "AND runner_capability.resource_scope ->> 'change_set_id' = "
        "selected_worktree.change_set_id::text "
        f"AND {_live_capability('runner_capability', 'sandbox.launch')} "
        "AND selected_run.status IN ('leased', 'starting', 'running', 'waiting_input', "
        "'waiting_approval', 'cancelling') "
        "AND selected_run.tenant_id = saas_run_isolation_grants.tenant_id "
        "AND selected_run.space_id = saas_run_isolation_grants.space_id "
        "AND selected_run.project_id = saas_run_isolation_grants.project_id "
        "AND selected_run.lease_owner = saas_run_isolation_grants.runner_id::text "
        "AND selected_run.fence_token = saas_run_isolation_grants.run_fence_token "
        "AND selected_run.lease_expires_at > statement_timestamp() "
        "AND selected_dispatch.status = 'leased' "
        "AND selected_dispatch.selected_runner_id = saas_run_isolation_grants.runner_id "
        "AND selected_dispatch.dispatch_generation = runner_capability.dispatch_generation "
        "AND selected_dispatch.execution_profile_id = "
        "saas_run_isolation_grants.execution_profile_id "
        "AND selected_dispatch.execution_profile_hash = selected_profile.config_hash "
        "AND selected_dispatch.egress_policy_id = selected_egress.id "
        "AND selected_dispatch.egress_policy_hash = selected_egress.rules_hash "
        "AND selected_profile.egress_policy_id = selected_egress.id "
        "AND selected_profile.status IN ('active', 'retired') "
        "AND selected_egress.status IN ('active', 'retired') "
        "AND selected_egress.allow_private_destinations = false "
        "AND selected_worktree.tenant_id = saas_run_isolation_grants.tenant_id "
        "AND selected_worktree.space_id = saas_run_isolation_grants.space_id "
        "AND selected_worktree.project_id = saas_run_isolation_grants.project_id "
        "AND selected_worktree.run_id = saas_run_isolation_grants.run_id "
        "AND selected_worktree.runner_id = saas_run_isolation_grants.runner_id "
        "AND selected_worktree.run_fence_token = saas_run_isolation_grants.run_fence_token "
        "AND selected_worktree.runner_connection_generation = "
        "saas_run_isolation_grants.runner_connection_generation "
        "AND selected_worktree.lease_generation = "
        "saas_run_isolation_grants.worktree_lease_generation "
        "AND selected_worktree.status IN ('materializing', 'ready', 'checkpointing') "
        "AND selected_worktree.lease_expires_at > statement_timestamp() "
        "AND selected_worktree.maximum_lifetime_at > statement_timestamp() "
        "AND saas_run_isolation_grants.expires_at <= runner_capability.expires_at "
        "AND saas_run_isolation_grants.expires_at <= selected_run.lease_expires_at "
        "AND saas_run_isolation_grants.expires_at <= selected_worktree.lease_expires_at)"
    )
    secret_lease = (
        f"({_registered('runner_id', 'runner_connection_generation')}) AND EXISTS ("
        "SELECT 1 FROM public.saas_run_isolation_grants AS selected_grant "
        "WHERE selected_grant.id = saas_secret_access_leases.isolation_grant_id "
        "AND selected_grant.run_id = saas_secret_access_leases.run_id "
        "AND selected_grant.runner_id = saas_secret_access_leases.runner_id "
        "AND selected_grant.run_fence_token = saas_secret_access_leases.run_fence_token "
        "AND selected_grant.runner_connection_generation = "
        "saas_secret_access_leases.runner_connection_generation "
        "AND EXISTS (SELECT 1 FROM public.saas_secret_bindings AS selected_binding "
        "WHERE selected_binding.id = saas_secret_access_leases.secret_binding_id "
        "AND selected_binding.execution_profile_id = selected_grant.execution_profile_id "
        "AND selected_binding.tenant_id = saas_secret_access_leases.tenant_id "
        "AND selected_binding.space_id = saas_secret_access_leases.space_id "
        "AND selected_binding.project_id = saas_secret_access_leases.project_id "
        "AND selected_binding.status = 'active'))"
    )
    _secret_lease_insert = (
        "status = 'active' AND redeemed_at IS NULL AND revoked_at IS NULL "
        "AND expires_at > statement_timestamp() AND EXISTS ("
        "SELECT 1 FROM public.saas_run_isolation_grants AS selected_grant "
        "JOIN public.saas_secret_bindings AS selected_binding "
        "ON selected_binding.id = saas_secret_access_leases.secret_binding_id "
        "WHERE selected_grant.id = saas_secret_access_leases.isolation_grant_id "
        "AND selected_grant.status = 'active' "
        "AND selected_grant.expires_at > statement_timestamp() "
        "AND selected_grant.tenant_id = saas_secret_access_leases.tenant_id "
        "AND selected_grant.space_id = saas_secret_access_leases.space_id "
        "AND selected_grant.project_id = saas_secret_access_leases.project_id "
        "AND selected_grant.run_id = saas_secret_access_leases.run_id "
        "AND selected_grant.runner_id = saas_secret_access_leases.runner_id "
        "AND selected_grant.run_fence_token = saas_secret_access_leases.run_fence_token "
        "AND selected_grant.runner_connection_generation = "
        "saas_secret_access_leases.runner_connection_generation "
        "AND selected_binding.execution_profile_id = selected_grant.execution_profile_id "
        "AND selected_binding.tenant_id = saas_secret_access_leases.tenant_id "
        "AND selected_binding.space_id = saas_secret_access_leases.space_id "
        "AND selected_binding.project_id = saas_secret_access_leases.project_id "
        "AND selected_binding.status = 'active' "
        "AND saas_secret_access_leases.expires_at <= selected_grant.expires_at)"
    )
    profile = (
        "EXISTS (SELECT 1 FROM public.saas_run_dispatches AS selected_dispatch "
        "JOIN public.saas_capability_tokens AS runner_capability "
        "ON runner_capability.run_id = selected_dispatch.run_id "
        "WHERE selected_dispatch.execution_profile_id = saas_execution_profiles.id "
        "AND selected_dispatch.status = 'leased' "
        "AND selected_dispatch.selected_runner_id = runner_capability.runner_id "
        "AND selected_dispatch.dispatch_generation = runner_capability.dispatch_generation "
        "AND runner_capability.tenant_id = saas_execution_profiles.tenant_id "
        "AND runner_capability.space_id = saas_execution_profiles.space_id "
        "AND runner_capability.project_id = saas_execution_profiles.project_id "
        f"AND {_live_capability('runner_capability', 'sandbox.launch')})"
    )
    egress = (
        "EXISTS (SELECT 1 FROM public.saas_run_dispatches AS selected_dispatch "
        "JOIN public.saas_capability_tokens AS runner_capability "
        "ON runner_capability.run_id = selected_dispatch.run_id "
        "WHERE selected_dispatch.egress_policy_id = saas_egress_policies.id "
        "AND selected_dispatch.status = 'leased' "
        "AND selected_dispatch.selected_runner_id = runner_capability.runner_id "
        "AND selected_dispatch.dispatch_generation = runner_capability.dispatch_generation "
        "AND runner_capability.tenant_id = saas_egress_policies.tenant_id "
        "AND runner_capability.space_id = saas_egress_policies.space_id "
        "AND runner_capability.project_id = saas_egress_policies.project_id "
        f"AND {_live_capability('runner_capability', 'sandbox.launch')})"
    )
    secret_binding = (
        "EXISTS (SELECT 1 FROM public.saas_execution_profiles AS selected_profile "
        "JOIN public.saas_run_dispatches AS selected_dispatch "
        "ON selected_dispatch.execution_profile_id = selected_profile.id "
        "JOIN public.saas_capability_tokens AS runner_capability "
        "ON runner_capability.run_id = selected_dispatch.run_id "
        "WHERE selected_profile.id = saas_secret_bindings.execution_profile_id "
        "AND selected_dispatch.status = 'leased' "
        "AND selected_dispatch.selected_runner_id = runner_capability.runner_id "
        "AND selected_dispatch.dispatch_generation = runner_capability.dispatch_generation "
        "AND runner_capability.tenant_id = saas_secret_bindings.tenant_id "
        "AND runner_capability.space_id = saas_secret_bindings.space_id "
        "AND runner_capability.project_id = saas_secret_bindings.project_id "
        f"AND {_live_capability('runner_capability', 'sandbox.launch')})"
    )
    preview_execution = (
        "EXISTS (SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.run_id = saas_preview_executions.child_run_id "
        "AND runner_capability.tenant_id = saas_preview_executions.tenant_id "
        "AND runner_capability.space_id = saas_preview_executions.space_id "
        "AND runner_capability.project_id = saas_preview_executions.project_id "
        f"AND {_live_capability('runner_capability', 'preview.serve')})"
    )
    preview_command = (
        "EXISTS (SELECT 1 FROM public.saas_preview_executions AS selected_preview "
        "WHERE selected_preview.id = saas_preview_commands.preview_execution_id)"
    )
    preview_session = (
        "EXISTS (SELECT 1 FROM public.saas_preview_executions AS selected_preview "
        "WHERE selected_preview.id = saas_preview_sessions.preview_execution_id)"
    )
    _outbox = (
        "tenant_id IS NOT NULL AND attempt_count = 0 AND available_at IS NOT NULL "
        "AND claimed_at IS NULL AND claim_token IS NULL AND last_error IS NULL "
        "AND last_error_code IS NULL AND last_error_digest IS NULL "
        "AND published_at IS NULL AND quarantined_at IS NULL AND (("
        "aggregate_type = 'RunIsolationGrant' "
        "AND event_type IN ('run.isolation_grant.issued', "
        "'run.isolation_grant.redeemed') "
        "AND aggregate_key = payload ->> 'grant_id' "
        "AND idempotency_key = 'run-isolation:' || aggregate_key || CASE event_type "
        "WHEN 'run.isolation_grant.issued' THEN ':' || 'issued' "
        "ELSE ':' || 'redeemed' END "
        "AND EXISTS (SELECT 1 FROM public.saas_run_isolation_grants AS selected_grant "
        "WHERE selected_grant.id::text = aggregate_key "
        "AND selected_grant.run_id::text = payload ->> 'run_id' "
        "AND selected_grant.runner_id::text = payload ->> 'runner_id' "
        "AND ((event_type = 'run.isolation_grant.issued' "
        "AND selected_grant.status = 'active') OR "
        "(event_type = 'run.isolation_grant.redeemed' "
        "AND selected_grant.status = 'redeemed'))) "
        "AND EXISTS (SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.tenant_id = saas_control_plane_outbox.tenant_id "
        "AND runner_capability.run_id::text = payload ->> 'run_id' "
        "AND runner_capability.runner_id::text = payload ->> 'runner_id' "
        f"AND {_live_capability('runner_capability', 'sandbox.launch')})) OR ("
        "aggregate_type = 'SecretAccessLease' "
        "AND event_type = 'secret.access.redeemed' "
        "AND aggregate_key = payload ->> 'lease_id' "
        "AND idempotency_key = 'secret-access:' || aggregate_key || ':' || 'redeemed' "
        "AND EXISTS (SELECT 1 FROM public.saas_secret_access_leases AS selected_lease "
        "WHERE selected_lease.id::text = aggregate_key "
        "AND selected_lease.run_id::text = payload ->> 'run_id' "
        "AND selected_lease.runner_id::text = payload ->> 'runner_id' "
        "AND selected_lease.secret_binding_id::text = payload ->> 'binding_id' "
        "AND selected_lease.status = 'redeemed') "
        "AND EXISTS (SELECT 1 FROM public.saas_capability_tokens AS runner_capability "
        "WHERE runner_capability.tenant_id = saas_control_plane_outbox.tenant_id "
        "AND runner_capability.run_id::text = payload ->> 'run_id' "
        "AND runner_capability.runner_id::text = payload ->> 'runner_id' "
        f"AND {_live_capability('runner_capability', 'sandbox.launch')})) OR ("
        "aggregate_type = 'WorktreeInstance' "
        "AND aggregate_key = payload ->> 'worktree_id' "
        "AND event_type IN ('worktree.created', 'worktree.rebuilt', "
        "'worktree.materializing', 'worktree.mounted', 'worktree.checkpointed', "
        "'worktree.released', 'worktree.rebuild.source_consumed', "
        "'worktree.rebuild_pending', 'worktree.quarantined', "
        "'worktree.gc_eligible', 'worktree.deleted') "
        "AND idempotency_key = 'worktree:' || aggregate_key || ':' || "
        "(payload ->> 'sequence') "
        "AND EXISTS (SELECT 1 FROM public.saas_worktree_events AS selected_event "
        "WHERE selected_event.worktree_id::text = aggregate_key "
        "AND selected_event.sequence::text = "
        "saas_control_plane_outbox.payload ->> 'sequence' "
        "AND selected_event.event_type = saas_control_plane_outbox.event_type) "
        "AND EXISTS (SELECT 1 FROM public.saas_worktree_instances AS selected_worktree "
        "WHERE selected_worktree.id::text = payload ->> 'worktree_id' "
        "AND selected_worktree.tenant_id = saas_control_plane_outbox.tenant_id)))"
    )

    for table, expression in (
        ("saas_runner_registrations", registration),
        ("saas_capability_tokens", capability),
        ("saas_run_dispatches", dispatch),
        ("saas_runs", run),
        ("saas_egress_policies", egress),
        ("saas_execution_profiles", profile),
    ):
        _exact_pair(table, "select", command="SELECT", expression=expression)

    _exact_pair("saas_repositories", "select", command="SELECT", expression=repository)
    _exact_pair("saas_secret_bindings", "select", command="SELECT", expression=secret_binding)
    _exact_pair(
        "saas_changeset_groups",
        "select",
        command="SELECT",
        expression=changeset_group_read,
    )
    _exact_pair(
        "saas_changesets",
        "select",
        command="SELECT",
        expression=changeset_read,
    )
    for table, expression in (
        ("saas_worktree_quotas", project_scope),
        ("saas_worktree_instances", worktree),
        ("saas_run_isolation_grants", isolation_grant),
        ("saas_secret_access_leases", secret_lease),
        ("saas_preview_executions", preview_execution),
        ("saas_preview_commands", preview_command),
    ):
        _exact_pair(table, "select", command="SELECT", expression=expression)

    _exact_pair(
        "saas_worktree_events",
        "select",
        command="SELECT",
        expression=worktree_event,
    )
    _exact_pair(
        "saas_preview_sessions",
        "select",
        command="SELECT",
        expression=preview_session,
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        DO $guard$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_catalog.pg_roles AS login
                WHERE login.rolcanlogin
                  AND login.rolname ~ '^runner_[0-9a-f]{32}_g[1-9][0-9]*$'
            ) OR EXISTS (
                SELECT 1
                FROM pg_catalog.pg_auth_members AS membership
                JOIN pg_catalog.pg_roles AS granted
                  ON granted.oid = membership.roleid
                WHERE granted.rolname = 'saas_runner_agent'
            ) OR EXISTS (
                SELECT 1
                FROM pg_catalog.pg_stat_activity AS activity
                WHERE activity.usename ~
                      '^runner_[0-9a-f]{32}_g[1-9][0-9]*$'
                  AND activity.pid <> pg_backend_pid()
            ) THEN
                RAISE EXCEPTION 'P0S10 Runner authority must be drained before downgrade'
                    USING ERRCODE = '55006';
            END IF;
        END
        $guard$
        """
    )
    for table, suffixes in (
        ("saas_preview_sessions", ("select_fence", "select")),
        ("saas_worktree_events", ("select_fence", "select")),
        ("saas_preview_commands", ("select_fence", "select")),
        ("saas_preview_executions", ("select_fence", "select")),
        ("saas_secret_access_leases", ("select_fence", "select")),
        ("saas_run_isolation_grants", ("select_fence", "select")),
        ("saas_worktree_instances", ("select_fence", "select")),
        ("saas_worktree_quotas", ("select_fence", "select")),
        ("saas_changesets", ("select_fence", "select")),
        ("saas_changeset_groups", ("select_fence", "select")),
        ("saas_secret_bindings", ("select_fence", "select")),
        ("saas_repositories", ("select_fence", "select")),
        ("saas_execution_profiles", ("lock_fence", "lock", "select_fence", "select")),
        ("saas_egress_policies", ("lock_fence", "lock", "select_fence", "select")),
        ("saas_runs", ("lock_fence", "lock", "select_fence", "select")),
        ("saas_run_dispatches", ("lock_fence", "lock", "select_fence", "select")),
        ("saas_capability_tokens", ("lock_fence", "lock", "select_fence", "select")),
        ("saas_runner_registrations", ("lock_fence", "lock", "select_fence", "select")),
    ):
        for suffix in suffixes:
            _drop_policy(table, suffix)
    for table in (
        "saas_preview_sessions",
        "saas_preview_commands",
        "saas_preview_executions",
        "saas_control_plane_outbox",
        "saas_worktree_events",
        "saas_worktree_instances",
        "saas_worktree_quotas",
        "saas_changesets",
        "saas_changeset_groups",
        "saas_runs",
        "saas_run_dispatches",
        "saas_capability_tokens",
        "saas_runner_registrations",
        "saas_repositories",
        "saas_egress_policies",
        "saas_execution_profiles",
        "saas_secret_bindings",
        "saas_run_isolation_grants",
        "saas_secret_access_leases",
    ):
        op.execute(f'DROP POLICY IF EXISTS "rls_{table}_runner_api_definer" ON public."{table}"')
    for table, policy in _LEGACY_POLICY_ROLE_PROJECTIONS:
        op.execute(f'ALTER POLICY "{policy}" ON public."{table}" TO PUBLIC')
    op.execute(
        "DROP FUNCTION public.saas_runner_transition_preview_v1("
        "text,text,uuid,uuid,uuid,bigint,bigint,uuid,text,uuid,bigint,"
        "boolean,boolean,text)"
    )
    op.execute(
        "DROP FUNCTION public.saas_runner_claim_preview_stop_v1("
        "text,uuid,uuid,uuid,bigint,bigint,text)"
    )
    op.execute(
        "DROP FUNCTION public.saas_runner_claim_preview_start_v1("
        "text,uuid,uuid,uuid,bigint,bigint,text)"
    )
    op.execute(
        "DROP FUNCTION public.saas_runner_preview_authority_v1(text,uuid,uuid,uuid,bigint,bigint)"
    )
    op.execute(
        "DROP FUNCTION public.saas_runner_allocate_worktree_v1("
        "text,uuid,uuid,uuid,uuid,text,bigint,integer,text,text,uuid)"
    )
    op.execute(
        "DROP FUNCTION public.saas_runner_transition_worktree_v1("
        "text,uuid,uuid,bigint,bigint,text,bigint,boolean,integer,"
        "text,text,text,text,text)"
    )
    op.execute(
        "DROP FUNCTION public.saas_runner_materialization_grant_v1(uuid,uuid,bigint,bigint,text)"
    )
    op.execute("DROP FUNCTION public.saas_runner_claim_secret_lease_v1(text,uuid,uuid)")
    op.execute("DROP FUNCTION public.saas_runner_redeem_isolation_grant_v1(text,uuid,uuid,jsonb)")
    op.execute("DROP FUNCTION public.saas_runner_isolation_metadata_v1(text,uuid,uuid)")
    op.execute("DROP FUNCTION public.saas_runner_isolation_snapshot_v1(text,uuid,uuid)")
    op.execute(
        "DROP FUNCTION public.saas_runner_issue_isolation_grant_v1("
        "text,uuid,uuid,uuid,bigint,bigint,uuid,text,integer)"
    )
    op.execute("DROP FUNCTION public.saas_runner_append_worktree_event_v1(uuid,text,jsonb,text)")
    op.execute(
        "DROP FUNCTION public.saas_runner_worktree_authority_live_v1("
        "text,uuid,uuid,uuid,text,bigint,boolean)"
    )
    op.execute("DROP FUNCTION public.saas_canonical_json_sha256_v1(jsonb)")
    op.execute("DROP FUNCTION public.saas_canonical_json_v1(jsonb)")
    op.execute("DROP INDEX public.uq_worktree_runner_run_fence_v1")
    op.execute("DROP INDEX public.uq_runner_isolation_grant_capability_worktree_v1")
    op.execute("DROP FUNCTION public.saas_runner_agent_registered_v1(uuid,bigint)")
    op.execute("DROP FUNCTION public.saas_runner_agent_identity_v1(uuid,bigint)")
