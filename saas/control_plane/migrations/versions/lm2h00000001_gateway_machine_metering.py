"""Bind existing machine metering facts to immutable gateway outcomes.

Revision ID: lm2h00000001
Revises: lm2g00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2h00000001"
down_revision = "lm2g00000001"
branch_labels = None
depends_on = None

_BUDGET = "saas_model_provider_budget_reservations"
_EVIDENCE = "saas_model_gateway_evidence"
_OWNER_READS = (
    "saas_runner_certificates",
    _BUDGET,
    "saas_usage_events",
    "saas_billing_metering_receipts",
)
_TRIGGERS = (
    "saas_usage_events",
    "saas_billing_metering_receipts",
    "saas_control_plane_outbox",
)
_CAP = "NULLIF(current_setting('app.capability_token_hash',true),'')"
_RESERVATION = "NULLIF(current_setting('app.model_budget_reservation_id',true),'')::uuid"

_GUARD = """
DECLARE
    u public.saas_usage_events%ROWTYPE;
    r public.saas_runs%ROWTYPE;
    c public.saas_capability_tokens%ROWTYPE;
    certificate public.saas_runner_certificates%ROWTYPE;
    runner public.saas_runner_registrations%ROWTYPE;
    budget public.saas_model_provider_budget_reservations%ROWTYPE;
    original public.saas_model_gateway_evidence%ROWTYPE;
    sent public.saas_model_gateway_evidence%ROWTYPE;
    outcome public.saas_model_gateway_evidence%ROWTYPE;
    price public.saas_pricing_snapshots%ROWTYPE;
    receipt public.saas_billing_metering_receipts%ROWTYPE;
    binding jsonb;
    request jsonb;
    usage jsonb;
    attrs jsonb;
    body jsonb;
    rate jsonb;
    expected_quantity numeric;
    expected_key text;
    expected_hash text;
    expected_outbox_key text;
    happened text;
BEGIN
    IF TG_TABLE_NAME='saas_usage_events' THEN
        u := NEW;
    ELSIF TG_TABLE_NAME='saas_billing_metering_receipts' THEN
        SELECT * INTO u FROM public.saas_usage_events WHERE id=NEW.usage_event_id;
    ELSE
        IF NEW.event_type<>'billing.usage.recorded' OR NEW.aggregate_type<>'billing' THEN
            RETURN NEW;
        END IF;
        SELECT * INTO u FROM public.saas_usage_events WHERE id::text=NEW.payload->>'usage_event_id';
        IF NOT FOUND THEN
            SELECT * INTO r FROM public.saas_runs WHERE id::text=NEW.payload->>'run_id';
            IF r.queue_class='managed_interactive' THEN
                RAISE EXCEPTION 'gateway Usage is missing' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END IF;
    END IF;
    IF u.run_id IS NULL THEN RETURN NEW; END IF;
    SELECT * INTO r FROM public.saas_runs WHERE id=u.run_id;
    IF r.queue_class IS DISTINCT FROM 'managed_interactive' THEN RETURN NEW; END IF;
    IF NOT pg_has_role(session_user,'saas_metering','member') THEN
        RAISE EXCEPTION 'gateway customer usage requires machine metering' USING ERRCODE='23514';
    END IF;
    SELECT * INTO c FROM public.saas_capability_tokens
    WHERE token_hash=NULLIF(current_setting('app.capability_token_hash',true),'');
    SELECT * INTO certificate FROM public.saas_runner_certificates
    WHERE fingerprint_sha256=NULLIF(current_setting('app.presented_certificate_fingerprint',true),'')
      AND purpose='billing_metering';
    SELECT * INTO runner FROM public.saas_runner_registrations WHERE id=c.runner_id;
    SELECT * INTO budget FROM public.saas_model_provider_budget_reservations
    WHERE id=NULLIF(current_setting('app.model_budget_reservation_id',true),'')::uuid;
    IF c.id IS NULL OR certificate.id IS NULL OR runner.id IS NULL OR budget.id IS NULL
       OR NULLIF(current_setting('app.presented_certificate_purpose',true),'') IS DISTINCT FROM 'billing_metering'
       OR NOT (c.allowed_actions::jsonb @> '["run.execute","runtime.interactive.execute"]'::jsonb)
       OR jsonb_array_length(c.allowed_actions::jsonb)<>2
       OR (c.tenant_id,c.space_id,c.project_id,c.run_id)<>(r.tenant_id,r.space_id,r.project_id,r.id)
       OR (u.tenant_id,u.space_id,u.project_id)<>(r.tenant_id,r.space_id,r.project_id)
       OR certificate.runner_id<>c.runner_id
       OR certificate.runner_connection_generation<>c.runner_connection_generation
       OR runner.connection_generation<>c.runner_connection_generation
       OR runner.status NOT IN ('online','draining')
       OR certificate.certificate_not_before>statement_timestamp()
       OR certificate.certificate_not_after<=statement_timestamp()
       OR NOT (certificate.status='active' OR
          (certificate.status='retiring' AND certificate.retire_at>statement_timestamp()))
       OR budget.tenant_id<>r.tenant_id OR budget.run_id<>r.id OR budget.purpose<>'tenant_run'
       OR budget.provider_id<>'deepseek' OR budget.status NOT IN ('settled','released')
       OR budget.outcome_evidence_sha256 IS NULL
    THEN RAISE EXCEPTION 'gateway machine scope rejected' USING ERRCODE='23514'; END IF;
    SELECT * INTO original FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase='request';
    SELECT * INTO sent FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase='in_flight';
    SELECT * INTO outcome FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase=budget.status;
    IF original.id IS NULL OR sent.id IS NULL OR outcome.id IS NULL
       OR EXISTS (SELECT 1 FROM public.saas_model_gateway_evidence e WHERE e.id IN
          (original.id,sent.id,outcome.id) AND (
             encode(sha256(convert_to(e.canonical_evidence,'UTF8')),'hex')<>e.evidence_sha256
             OR e.canonical_evidence::jsonb->>'contract'<>'platform-model-gateway-evidence-v2'))
       OR sent.canonical_evidence::jsonb->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR outcome.canonical_evidence::jsonb->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR budget.outcome_evidence_sha256<>outcome.evidence_sha256
       OR outcome.budget_version<>budget.version
       OR original.created_at<c.issued_at OR sent.created_at<original.created_at
       OR sent.created_at>=c.expires_at OR outcome.created_at<sent.created_at
       OR (c.revoked_at IS NOT NULL AND c.revoked_at<=sent.created_at)
    THEN RAISE EXCEPTION 'gateway metering evidence rejected' USING ERRCODE='23514'; END IF;
    request := original.canonical_evidence::jsonb->'request';
    binding := request->'run_binding';
    usage := outcome.canonical_evidence::jsonb->'usage';
    IF binding->>'capability_id' IS DISTINCT FROM c.id::text
       OR binding->>'fence_token' IS DISTINCT FROM c.fence_token::text
       OR binding->>'run_id' IS DISTINCT FROM r.id::text
       OR binding->>'space_id' IS DISTINCT FROM r.space_id::text
       OR binding->>'project_id' IS DISTINCT FROM r.project_id::text
       OR binding->>'session_id' IS DISTINCT FROM r.session_id::text
       OR binding->>'actor_id' IS DISTINCT FROM r.created_by::text
       OR binding->>'customer_pricing_snapshot_id' IS DISTINCT FROM r.customer_pricing_snapshot_id::text
       OR NOT r.customer_pricing_frozen OR r.created_by_service_account_id IS NOT NULL
       OR NOT (c.resource_scope::jsonb @> jsonb_build_object(
          'tenant_id',r.tenant_id::text,'space_id',r.space_id::text,'project_id',r.project_id::text,
          'run_id',r.id::text,'runner_id',c.runner_id::text,'session_id',r.session_id::text))
       OR u.meter NOT IN ('llm.input_tokens','llm.output_tokens')
       OR u.unit<>'tokens' OR u.provider<>'deepseek'
       OR u.pricing_snapshot_id IS DISTINCT FROM r.customer_pricing_snapshot_id
       OR u.session_id IS DISTINCT FROM r.session_id OR u.user_id IS DISTINCT FROM r.created_by
       OR u.service_account_id IS NOT NULL
       OR u.occurred_at IS DISTINCT FROM original.created_at
       OR u.provider_request_id IS DISTINCT FROM 'model-gateway:'||budget.id::text
       OR (usage->>'total_tokens')::numeric IS DISTINCT FROM budget.settled_tokens::numeric
       OR (outcome.canonical_evidence::jsonb->>'actual_microusd')::numeric IS DISTINCT FROM budget.settled_microusd::numeric
    THEN RAISE EXCEPTION 'gateway customer binding rejected' USING ERRCODE='23514'; END IF;
    expected_quantity := (usage->>(CASE u.meter WHEN 'llm.input_tokens' THEN 'input_tokens' ELSE 'output_tokens' END))::numeric;
    expected_key := 'model-gateway:'||budget.id::text||':'||CASE u.meter WHEN 'llm.input_tokens' THEN 'input' ELSE 'output' END;
    attrs := jsonb_build_object('model',request->>'public_model_id','operation',
       CASE request->>'wire_api' WHEN 'openai_responses' THEN 'responses.create' ELSE 'chat.completions.create' END,
       'request_class','managed_gateway');
    SELECT * INTO price FROM public.saas_pricing_snapshots
    WHERE id=r.customer_pricing_snapshot_id AND tenant_id=r.tenant_id;
    rate := price.rates::jsonb->u.meter;
    IF expected_quantity IS NULL OR expected_quantity<=0 OR u.quantity IS DISTINCT FROM expected_quantity
       OR u.idempotency_key IS DISTINCT FROM expected_key OR u.attributes::jsonb IS DISTINCT FROM attrs
       OR price.id IS NULL OR u.currency IS DISTINCT FROM price.currency
       OR rate->>'unit' IS DISTINCT FROM 'tokens' OR (rate->>'unit_size')::numeric<=0
       OR (rate->>'minor_per_unit') !~ '^[1-9][0-9]{0,18}$'
       OR u.customer_charge_minor IS DISTINCT FROM
          ceil(expected_quantity/(rate->>'unit_size')::numeric*(rate->>'minor_per_unit')::numeric)::bigint
       OR NOT EXISTS (SELECT 1 FROM public.saas_billing_subscriptions s
           WHERE s.tenant_id=r.tenant_id AND s.status IN ('active','trialing'))
    THEN RAISE EXCEPTION 'gateway customer quantity or price rejected' USING ERRCODE='23514'; END IF;
    IF TG_TABLE_NAME='saas_usage_events' THEN RETURN NEW; END IF;
    happened := original.canonical_evidence::jsonb->>'occurred_at';
    body := jsonb_build_object(
       'tenant_id',r.tenant_id::text,'space_id',r.space_id::text,'project_id',r.project_id::text,
       'session_id',r.session_id::text,'run_id',r.id::text,'actor_kind','user','user_id',r.created_by::text,
       'service_account_id',NULL,'runner_id',c.runner_id::text,'pricing_snapshot_id',price.id::text,
       'meter',u.meter,'quantity',u.quantity::bigint::text,'unit',u.unit,'provider',u.provider,
       'provider_request_id',u.provider_request_id,'occurred_at',happened,'attributes',attrs,
       'model_budget_reservation_id',budget.id::text);
    expected_hash := public.saas_canonical_json_sha256_v1(body);
    IF TG_TABLE_NAME='saas_billing_metering_receipts' THEN
        receipt := NEW;
    ELSE
        SELECT * INTO receipt FROM public.saas_billing_metering_receipts
        WHERE id::text=NEW.payload->>'metering_receipt_id';
    END IF;
    IF receipt.id IS NULL OR receipt.usage_event_id<>u.id
       OR (receipt.tenant_id,receipt.space_id,receipt.project_id,receipt.run_id,receipt.runner_id)
          <>(r.tenant_id,r.space_id,r.project_id,r.id,c.runner_id)
       OR receipt.runner_certificate_id<>certificate.id
       OR receipt.certificate_fingerprint_sha256<>certificate.fingerprint_sha256
       OR receipt.capability_id<>c.id OR receipt.fence_token<>c.fence_token
       OR receipt.runner_connection_generation<>c.runner_connection_generation
       OR receipt.dispatch_generation<>c.dispatch_generation
       OR receipt.idempotency_key<>expected_key OR receipt.request_hash<>expected_hash
       OR receipt.model_budget_reservation_id IS DISTINCT FROM budget.id
    THEN RAISE EXCEPTION 'gateway customer receipt rejected' USING ERRCODE='23514'; END IF;
    IF TG_TABLE_NAME='saas_billing_metering_receipts' THEN RETURN NEW; END IF;
    expected_outbox_key := encode(sha256(convert_to('billing-metering','UTF8')||decode('00','hex')||
       convert_to(r.tenant_id::text,'UTF8')||decode('00','hex')||convert_to(expected_key,'UTF8')),'hex');
    IF NEW.tenant_id<>r.tenant_id OR NEW.aggregate_key<>u.id::text OR NEW.request_hash<>expected_hash
       OR NEW.idempotency_key<>expected_outbox_key
       OR NEW.payload::jsonb IS DISTINCT FROM body||jsonb_build_object(
          'usage_event_id',u.id::text,'metering_receipt_id',receipt.id::text,'capability_id',c.id::text,
          'runner_connection_generation',c.runner_connection_generation,'dispatch_generation',c.dispatch_generation,
          'fence_token',c.fence_token,'currency',price.currency,'customer_charge_minor',u.customer_charge_minor)
    THEN RAISE EXCEPTION 'gateway customer outbox rejected' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END
"""  # noqa: E501 - Keep source-pinned SQL intact.


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("GRANT SELECT (queue_class) ON public.saas_runs TO saas_metering")
    op.execute(f"GRANT SELECT ON public.{_BUDGET},public.{_EVIDENCE} TO saas_metering")
    cap = (
        "EXISTS (SELECT 1 FROM public.saas_capability_tokens c "
        f"WHERE c.token_hash={_CAP} AND c.tenant_id={_BUDGET}.tenant_id "
        f"AND c.run_id={_BUDGET}.run_id)"
    )
    op.execute(
        f"CREATE POLICY rls_gateway_metering_budget_read ON public.{_BUDGET} FOR SELECT "
        f"TO saas_metering USING (id={_RESERVATION} AND purpose='tenant_run' AND {cap})"
    )
    op.execute(
        f"CREATE POLICY rls_gateway_metering_evidence_read ON public.{_EVIDENCE} FOR SELECT "
        f"TO saas_metering USING (reservation_id={_RESERVATION} AND EXISTS "
        f"(SELECT 1 FROM public.{_BUDGET} b WHERE b.id={_EVIDENCE}.reservation_id "
        f"AND b.tenant_id={_EVIDENCE}.tenant_id))"
    )
    for table in _OWNER_READS:
        op.execute(
            f"CREATE POLICY rls_gateway_metering_owner_read ON public.{table} FOR SELECT "
            "USING (current_user=pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
            f"WHERE oid='public.{table}'::regclass)))"
        )
    op.execute(
        "CREATE FUNCTION public.saas_gateway_customer_usage_guard_v1() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp "
        f"AS $function${_GUARD}$function$"
    )
    op.execute("REVOKE ALL ON FUNCTION public.saas_gateway_customer_usage_guard_v1() FROM PUBLIC")
    for table in _TRIGGERS:
        op.execute(
            f"CREATE TRIGGER gateway_customer_usage_guard BEFORE INSERT ON public.{table} "
            "FOR EACH ROW EXECUTE FUNCTION public.saas_gateway_customer_usage_guard_v1()"
        )


def downgrade() -> None:
    postgresql = op.get_bind().dialect.name == "postgresql"
    if postgresql:
        for table in _TRIGGERS:
            op.execute(f"LOCK TABLE public.{table} IN ACCESS EXCLUSIVE MODE")
    contract = (
        "e.canonical_evidence::jsonb->>'contract'"
        if postgresql
        else "json_extract(e.canonical_evidence,'$.contract')"
    )
    reservation = (
        "e.canonical_evidence::jsonb->>'reservation_id'"
        if postgresql
        else "json_extract(e.canonical_evidence,'$.reservation_id')"
    )
    if op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM saas_usage_events u "
            "JOIN saas_model_provider_budget_reservations b "
            "ON u.run_id=b.run_id AND u.tenant_id=b.tenant_id JOIN saas_model_gateway_evidence e "
            "ON e.reservation_id=b.id WHERE e.phase='request' "
            f"AND {contract}='platform-model-gateway-evidence-v2' "
            f"AND u.provider_request_id='model-gateway:'||({reservation}))"
        )
    ):
        raise RuntimeError("retained gateway customer usage prevents destructive downgrade")
    if not postgresql:
        return
    for table in reversed(_TRIGGERS):
        op.execute(f"DROP TRIGGER gateway_customer_usage_guard ON public.{table}")
    op.execute("DROP FUNCTION public.saas_gateway_customer_usage_guard_v1()")
    for table in _OWNER_READS:
        op.execute(f"DROP POLICY rls_gateway_metering_owner_read ON public.{table}")
    op.execute(f"DROP POLICY rls_gateway_metering_evidence_read ON public.{_EVIDENCE}")
    op.execute(f"DROP POLICY rls_gateway_metering_budget_read ON public.{_BUDGET}")
    op.execute(f"REVOKE SELECT ON public.{_BUDGET},public.{_EVIDENCE} FROM saas_metering")
    op.execute("REVOKE SELECT (queue_class) ON public.saas_runs FROM saas_metering")
