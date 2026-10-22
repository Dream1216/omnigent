"""Retain true-Run call lineage without rewriting legacy gateway evidence.

Revision ID: lm2g00000001
Revises: lm2f00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2g00000001"
down_revision = "lm2f00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_model_gateway_evidence"
_CONTRACT = "platform-model-gateway-evidence-v2"
_SIGNATURE = "public.saas_gateway_run_binding_v2(uuid,uuid,jsonb,timestamptz)"
_OWNER_READS = (
    "saas_capability_tokens",
    "saas_run_dispatches",
    "saas_runner_registrations",
    "saas_model_publication_versions",
)

_BINDING = """
SELECT EXISTS (
    SELECT 1 FROM public.saas_model_run_tokens t
    JOIN public.saas_runs r ON r.id=t.run_id
    JOIN public.saas_capability_tokens c ON c.id=t.capability_id
    JOIN public.saas_run_dispatches d ON d.run_id=r.id
    JOIN public.saas_runner_registrations runner ON runner.id=c.runner_id
    JOIN public.saas_model_publication_versions p ON p.tenant_id=r.tenant_id
       AND p.public_model_id=request->>'public_model_id' AND p.wire_api=request->>'wire_api'
       AND p.generation::text=request->'run_binding'->>'publication_generation'
    WHERE r.id=requested_run AND r.tenant_id=requested_tenant
      AND t.id::text=request->'run_binding'->>'model_token_id'
      AND (t.tenant_id,t.space_id,t.project_id,t.actor_id,t.fence_token)
          =(r.tenant_id,r.space_id,r.project_id,r.created_by,r.fence_token)
      AND t.issued_at<=requested_at AND t.expires_at>statement_timestamp()
      AND r.id::text=request->'run_binding'->>'run_id'
      AND r.session_id::text=request->'run_binding'->>'session_id'
      AND r.space_id::text=request->'run_binding'->>'space_id'
      AND r.project_id::text=request->'run_binding'->>'project_id'
      AND r.created_by::text=request->'run_binding'->>'actor_id'
      AND r.fence_token::text=request->'run_binding'->>'fence_token'
      AND r.customer_pricing_snapshot_id::text=request->'run_binding'->>'customer_pricing_snapshot_id'
      AND r.customer_pricing_frozen AND r.created_by_service_account_id IS NULL
      AND r.queue_class='managed_interactive' AND r.status='running'
      AND r.lease_expires_at>statement_timestamp() AND r.lease_owner=c.runner_id::text
      AND c.id::text=request->'run_binding'->>'capability_id'
      AND (c.run_id,c.tenant_id,c.space_id,c.project_id,c.fence_token)
          =(r.id,r.tenant_id,r.space_id,r.project_id,r.fence_token)
      AND c.revoked_at IS NULL AND c.expires_at>statement_timestamp()
      AND c.allowed_actions::jsonb @> '["run.execute","runtime.interactive.execute"]'::jsonb
      AND jsonb_array_length(c.allowed_actions::jsonb)=2
      AND d.status='leased' AND d.selected_runner_id=c.runner_id
      AND d.dispatch_generation=c.dispatch_generation
      AND runner.connection_generation=c.runner_connection_generation
      AND runner.status IN ('online','draining')
      AND p.snapshot_sha256=request->'run_binding'->>'publication_snapshot_sha256'
      AND encode(sha256(convert_to(p.canonical_snapshot,'UTF8')),'hex')=p.snapshot_sha256
      AND r.input::jsonb->'execution'->'model_publication'=jsonb_build_object(
          'schema_version',1,'public_model_id',p.public_model_id,'wire_api',p.wire_api,
          'generation',p.generation,'snapshot_sha256',p.snapshot_sha256)
      AND p.canonical_snapshot::jsonb->'provider_cost'->'price'=request->'model_price'
      AND p.canonical_snapshot::jsonb->'provider_cost'->>'pricing_revision'=request->>'pricing_revision'
      AND (request->>'output_token_limit')::integer BETWEEN 1
          AND (p.canonical_snapshot::jsonb->>'max_output_tokens')::integer
      AND requested_at<=statement_timestamp()+interval '5 seconds'
      AND requested_at>=statement_timestamp()-interval '5 minutes'
)
"""  # noqa: E501 - Preserve the source-bound SQL body.

_GUARD = """
DECLARE
    budget public.saas_model_provider_budget_reservations%ROWTYPE;
    original public.saas_model_gateway_evidence%ROWTYPE;
    value jsonb;
    request jsonb;
    binding jsonb;
    usage jsonb;
    prior_version integer;
BEGIN
    SELECT * INTO STRICT budget FROM public.saas_model_provider_budget_reservations
    WHERE id=NEW.reservation_id;
    value := NEW.canonical_evidence::jsonb;
    IF NEW.phase<>'request' THEN
        SELECT * INTO STRICT original FROM public.saas_model_gateway_evidence
        WHERE reservation_id=budget.id AND phase='request';
        IF value->>'contract' IS DISTINCT FROM original.canonical_evidence::jsonb->>'contract'
        THEN RAISE EXCEPTION 'gateway evidence contract changed' USING ERRCODE='23514'; END IF;
    END IF;
    IF value->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v2' THEN
        RETURN NEW;
    END IF;
    IF jsonb_typeof(value)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(value))<>16
       OR NOT value ?& ARRAY['contract','phase','reservation_id','tenant_id','run_id',
           'provider_id','configuration_version','budget_version','status','admission','request',
           'request_evidence_sha256','usage','actual_microusd','reason','occurred_at']
       OR value->>'phase' IS DISTINCT FROM NEW.phase
       OR value->>'reservation_id' IS DISTINCT FROM budget.id::text
       OR value->>'tenant_id' IS DISTINCT FROM budget.tenant_id::text
       OR NEW.tenant_id IS DISTINCT FROM budget.tenant_id
       OR value->>'run_id' IS DISTINCT FROM budget.run_id::text
       OR value->>'provider_id' IS DISTINCT FROM budget.provider_id
       OR value->>'configuration_version' IS DISTINCT FROM budget.configuration_version::text
       OR value->>'budget_version' IS DISTINCT FROM budget.version::text
       OR jsonb_typeof(value->'configuration_version') IS DISTINCT FROM 'number'
       OR jsonb_typeof(value->'budget_version') IS DISTINCT FROM 'number'
       OR NEW.budget_version<>budget.version OR budget.purpose<>'tenant_run'
       OR value->>'status' IS DISTINCT FROM budget.status
       OR value->'admission' IS DISTINCT FROM jsonb_build_object(
           'requested_microusd',budget.requested_microusd,'requested_tokens',budget.requested_tokens,
           'admitted_microusd',budget.admitted_microusd,'admitted_tokens',budget.admitted_tokens)
       OR (value->>'occurred_at')::timestamptz IS DISTINCT FROM NEW.created_at
       OR encode(sha256(convert_to(NEW.canonical_evidence,'UTF8')),'hex')<>NEW.evidence_sha256
    THEN RAISE EXCEPTION 'gateway Run evidence binding rejected' USING ERRCODE='23514'; END IF;
    IF NEW.phase='request' THEN
        request := value->'request';
        binding := request->'run_binding';
        IF budget.version<>1 OR budget.status NOT IN ('reserved','rejected')
           OR NEW.created_at IS DISTINCT FROM budget.created_at
           OR jsonb_typeof(request) IS DISTINCT FROM 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(request))<>6
           OR NOT request ?& ARRAY['public_model_id','wire_api','pricing_revision',
               'model_price','output_token_limit','run_binding']
           OR jsonb_typeof(binding) IS DISTINCT FROM 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(binding))<>11
           OR NOT binding ?& ARRAY['run_id','session_id','space_id','project_id','actor_id',
               'capability_id','model_token_id','customer_pricing_snapshot_id','fence_token',
               'publication_generation','publication_snapshot_sha256']
           OR EXISTS (SELECT 1 FROM jsonb_each(binding) pair
               WHERE pair.key IN ('run_id','session_id','space_id','project_id','actor_id',
                   'capability_id','model_token_id','customer_pricing_snapshot_id')
               AND (jsonb_typeof(pair.value)<>'string' OR (pair.value#>>'{}') !~
                   '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'))
           OR jsonb_typeof(binding->'fence_token') IS DISTINCT FROM 'number'
           OR jsonb_typeof(binding->'publication_generation') IS DISTINCT FROM 'number'
           OR jsonb_typeof(binding->'publication_snapshot_sha256') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'public_model_id') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'wire_api') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'pricing_revision') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'output_token_limit') IS DISTINCT FROM 'number'
           OR (request->>'output_token_limit') !~ '^[1-9][0-9]{0,5}$'
           OR value->'usage' IS DISTINCT FROM 'null'::jsonb
           OR value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
           OR value->'request_evidence_sha256' IS DISTINCT FROM 'null'::jsonb
           OR value->'reason' IS DISTINCT FROM 'null'::jsonb
           OR NOT public.saas_gateway_run_binding_v2(budget.tenant_id,budget.run_id,request,budget.created_at)
        THEN RAISE EXCEPTION 'gateway Run request authority rejected' USING ERRCODE='23514'; END IF;
        RETURN NEW;
    END IF;
    request := original.canonical_evidence::jsonb->'request';
    IF value->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR value->'admission' IS DISTINCT FROM original.canonical_evidence::jsonb->'admission'
       OR value->'request' IS DISTINCT FROM 'null'::jsonb OR NEW.phase<>budget.status
    THEN RAISE EXCEPTION 'gateway Run transition rejected' USING ERRCODE='23514'; END IF;
    SELECT max(budget_version) INTO prior_version FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id;
    IF NEW.budget_version<>prior_version+1
       OR (NEW.phase='in_flight' AND (prior_version<>1 OR NOT
           public.saas_gateway_run_binding_v2(budget.tenant_id,budget.run_id,request,budget.created_at)))
       OR (NEW.phase IN ('uncertain','settled') AND NOT EXISTS (
           SELECT 1 FROM public.saas_model_gateway_evidence WHERE reservation_id=budget.id
           AND phase='in_flight'))
    THEN RAISE EXCEPTION 'gateway Run sequence rejected' USING ERRCODE='23514'; END IF;
    usage := value->'usage';
    IF usage IS DISTINCT FROM 'null'::jsonb THEN
        IF budget.status NOT IN ('settled','released') OR jsonb_typeof(usage)<>'object'
           OR (SELECT count(*) FROM jsonb_object_keys(usage))<>5
           OR NOT usage ?& ARRAY['input_tokens','input_cache_hit_tokens',
               'input_cache_miss_tokens','output_tokens','total_tokens']
           OR EXISTS (SELECT 1 FROM jsonb_each(usage) pair WHERE jsonb_typeof(pair.value)<>'number'
               OR pair.value::text !~ '^[0-9]{1,19}$')
           OR (usage->>'total_tokens')::numeric<>budget.settled_tokens
           OR (usage->>'input_tokens')::numeric+(usage->>'output_tokens')::numeric<>budget.settled_tokens
           OR (usage->>'input_cache_hit_tokens')::numeric+(usage->>'input_cache_miss_tokens')::numeric
               <>(usage->>'input_tokens')::numeric
           OR (usage->>'output_tokens')::numeric>(request->>'output_token_limit')::integer
           OR value->>'actual_microusd' IS DISTINCT FROM budget.settled_microusd::text
           OR jsonb_typeof(value->'actual_microusd') IS DISTINCT FROM 'number'
           OR budget.outcome_evidence_sha256 IS DISTINCT FROM NEW.evidence_sha256
           OR value->'reason' IS DISTINCT FROM 'null'::jsonb
           OR NOT EXISTS (SELECT 1 FROM public.saas_model_gateway_evidence
               WHERE reservation_id=budget.id AND phase='in_flight')
        THEN RAISE EXCEPTION 'gateway Run usage evidence rejected' USING ERRCODE='23514'; END IF;
    ELSIF value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
       OR (budget.status='in_flight' AND value->'reason' IS DISTINCT FROM 'null'::jsonb)
       OR (budget.status='uncertain' AND COALESCE(value->>'reason','') NOT IN
           ('provider_outcome_unknown','provider_rejected','provider_unreachable','stream_incomplete','settlement_unavailable'))
       OR (budget.status IN ('released','expired')
           AND (value->>'reason' IS DISTINCT FROM 'not_sent' OR prior_version<>1))
       OR budget.status NOT IN ('in_flight','uncertain','released','expired')
    THEN RAISE EXCEPTION 'gateway Run pending evidence rejected' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END
"""  # noqa: E501 - Source-bound SQL is kept intact for catalog verification.


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _OWNER_READS:
        op.execute(
            f"CREATE POLICY rls_gateway_run_owner_read ON public.{table} FOR SELECT "
            "USING (current_user=pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
            f"WHERE oid='public.{table}'::regclass)))"
        )
    op.execute(
        "CREATE FUNCTION public.saas_gateway_run_binding_v2(requested_tenant uuid,"
        "requested_run uuid,request jsonb,requested_at timestamptz) RETURNS boolean "
        "LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog "
        f"AS $function${_BINDING}$function$"
    )
    op.execute(f"REVOKE ALL ON FUNCTION {_SIGNATURE} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_SIGNATURE} TO saas_billing")
    op.execute(
        "CREATE FUNCTION public.saas_gateway_run_evidence_guard_v2() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog "
        f"AS $function${_GUARD}$function$"
    )
    op.execute("REVOKE ALL ON FUNCTION public.saas_gateway_run_evidence_guard_v2() FROM PUBLIC")
    op.execute(f"DROP TRIGGER trg_model_gateway_evidence_guard ON public.{_TABLE}")
    op.execute(
        "CREATE TRIGGER trg_model_gateway_evidence_guard BEFORE UPDATE OR DELETE "
        f"ON public.{_TABLE} "
        "FOR EACH ROW EXECUTE FUNCTION public.saas_model_gateway_evidence_guard()"
    )
    op.execute(
        f"CREATE TRIGGER trg_model_gateway_evidence_v1_insert BEFORE INSERT ON public.{_TABLE} "
        "FOR EACH ROW WHEN "
        f"(COALESCE(NEW.canonical_evidence::jsonb->>'contract','')<>'{_CONTRACT}') "
        "EXECUTE FUNCTION public.saas_model_gateway_evidence_guard()"
    )
    op.execute(
        f"CREATE TRIGGER trg_model_gateway_evidence_v2_insert BEFORE INSERT ON public.{_TABLE} "
        "FOR EACH ROW EXECUTE FUNCTION public.saas_gateway_run_evidence_guard_v2()"
    )


def downgrade() -> None:
    postgresql = op.get_bind().dialect.name == "postgresql"
    if postgresql:
        op.execute(f"LOCK TABLE public.{_TABLE} IN ACCESS EXCLUSIVE MODE")
    contract = (
        "canonical_evidence::jsonb->>'contract'"
        if postgresql
        else "json_extract(canonical_evidence,'$.contract')"
    )
    if op.get_bind().scalar(
        sa.text(f"SELECT EXISTS(SELECT 1 FROM {_TABLE} WHERE {contract}=:contract)").bindparams(
            contract=_CONTRACT,
        )
    ):
        raise RuntimeError("retained Run gateway evidence prevents destructive downgrade")
    if not postgresql:
        return
    for name in (
        "trg_model_gateway_evidence_v1_insert",
        "trg_model_gateway_evidence_v2_insert",
        "trg_model_gateway_evidence_guard",
    ):
        op.execute(f"DROP TRIGGER {name} ON public.{_TABLE}")
    op.execute(
        f"CREATE TRIGGER trg_model_gateway_evidence_guard BEFORE INSERT OR UPDATE OR DELETE "
        f"ON public.{_TABLE} FOR EACH ROW "
        "EXECUTE FUNCTION public.saas_model_gateway_evidence_guard()"
    )
    op.execute("DROP FUNCTION public.saas_gateway_run_evidence_guard_v2()")
    op.execute(f"DROP FUNCTION {_SIGNATURE}")
    for table in _OWNER_READS:
        op.execute(f"DROP POLICY rls_gateway_run_owner_read ON public.{table}")
