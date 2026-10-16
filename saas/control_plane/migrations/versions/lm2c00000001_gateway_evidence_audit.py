"""Append retained gateway facts to the existing platform audit chain.

Revision ID: lm2c00000001
Revises: lm2b00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2c00000001"
down_revision = "lm2b00000001"
branch_labels = None
depends_on = None

_SIGNATURE = "public.saas_audit_model_gateway_evidence_v1(uuid,jsonb)"
_OWNER_POLICIES = (
    ("saas_model_gateway_evidence", "SELECT"),
    ("saas_control_plane_outbox", "SELECT"),
    ("saas_platform_audit_events", "SELECT"),
    ("saas_platform_audit_chain_heads", "SELECT"),
    ("saas_platform_audit_chain_heads", "UPDATE"),
)

_FUNCTION_BODY = """
DECLARE
    source public.saas_control_plane_outbox%ROWTYPE;
    evidence public.saas_model_gateway_evidence%ROWTYPE;
    head public.saas_platform_audit_chain_heads%ROWTYPE;
    prior public.saas_platform_audit_events%ROWTYPE;
    audit_payload jsonb;
    payload_digest text;
    occurred text;
    event_material jsonb;
    event_digest text;
    system_actor constant uuid := '21bb9380-44ca-51a9-8f87-c914945e332a';
BEGIN
    SELECT * INTO source FROM public.saas_control_plane_outbox WHERE id = source_event_id;
    IF NOT FOUND OR source.aggregate_type <> 'model_gateway_budget'
       OR source.event_type <> 'model_gateway.evidence_retained'
       OR source.payload::jsonb IS DISTINCT FROM expected_payload
       OR jsonb_typeof(expected_payload) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(expected_payload)) <> 5
       OR expected_payload->>'event_type' IS DISTINCT FROM source.event_type
       OR expected_payload->>'tenant_id' IS DISTINCT FROM source.tenant_id::text
       OR expected_payload->>'reservation_id' IS DISTINCT FROM source.aggregate_key
    THEN RAISE EXCEPTION 'model_gateway_audit_evidence_rejected' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO evidence FROM public.saas_model_gateway_evidence
    WHERE id::text = expected_payload->>'evidence_id';
    IF NOT FOUND OR evidence.tenant_id IS DISTINCT FROM source.tenant_id
       OR evidence.reservation_id::text IS DISTINCT FROM source.aggregate_key
       OR evidence.evidence_sha256 IS DISTINCT FROM source.request_hash
       OR evidence.evidence_sha256 IS DISTINCT FROM expected_payload->>'evidence_sha256'
       OR evidence.evidence_sha256 IS DISTINCT FROM
          encode(sha256(convert_to(evidence.canonical_evidence,'UTF8')),'hex')
       OR source.idempotency_key IS DISTINCT FROM
          'model-gateway-evidence:' || replace(evidence.id::text,'-','')
    THEN RAISE EXCEPTION 'model_gateway_audit_evidence_rejected' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT head FROM public.saas_platform_audit_chain_heads
    WHERE partition_key = 'platform' FOR UPDATE;
    IF (head.last_sequence = 0 AND (head.last_event_hash <> repeat('0',64)
        OR EXISTS (SELECT 1 FROM public.saas_platform_audit_events)))
       OR (head.last_sequence > 0 AND NOT EXISTS (
           SELECT 1 FROM public.saas_platform_audit_events
           WHERE sequence_no = head.last_sequence AND event_hash = head.last_event_hash))
    THEN RAISE EXCEPTION 'model_gateway_audit_chain_unavailable' USING ERRCODE = '23514';
    END IF;
    audit_payload := expected_payload || jsonb_build_object(
        'source_event_id',source.id::text,'phase',evidence.phase,
        'budget_version',evidence.budget_version);
    payload_digest := public.saas_canonical_json_sha256_v1(audit_payload);
    occurred := to_char(evidence.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')
        || CASE WHEN to_char(evidence.created_at AT TIME ZONE 'UTC','US') = '000000'
                THEN '' ELSE '.' || to_char(evidence.created_at AT TIME ZONE 'UTC','US') END
        || '+00:00';
    SELECT * INTO prior FROM public.saas_platform_audit_events WHERE id = source.id;
    IF FOUND THEN
        event_material := jsonb_build_object(
            'sequence_no',prior.sequence_no,'tenant_id',source.tenant_id::text,
            'actor_type','system','actor_id',system_actor::text,
            'event_type',source.event_type,'target_type',source.aggregate_type,
            'target_id',evidence.reservation_id::text,'operation_id',NULL,
            'payload_hash',payload_digest,'previous_hash',prior.previous_hash,
            'occurred_at',occurred);
        IF prior.sequence_no > head.last_sequence
           OR prior.tenant_id IS DISTINCT FROM source.tenant_id
           OR prior.actor_type <> 'system' OR prior.actor_id <> system_actor
           OR prior.event_type <> source.event_type OR prior.target_type <> source.aggregate_type
           OR prior.target_id <> evidence.reservation_id OR prior.operation_id IS NOT NULL
           OR prior.payload::jsonb IS DISTINCT FROM audit_payload
           OR prior.payload_hash <> payload_digest OR prior.occurred_at <> evidence.created_at
           OR prior.event_hash <> public.saas_canonical_json_sha256_v1(event_material)
        THEN RAISE EXCEPTION 'model_gateway_audit_replay_conflict' USING ERRCODE = '23514';
        END IF;
        RETURN false;
    END IF;
    event_material := jsonb_build_object(
        'sequence_no',head.last_sequence + 1,'tenant_id',source.tenant_id::text,
        'actor_type','system','actor_id',system_actor::text,
        'event_type',source.event_type,'target_type',source.aggregate_type,
        'target_id',evidence.reservation_id::text,'operation_id',NULL,
        'payload_hash',payload_digest,'previous_hash',head.last_event_hash,
        'occurred_at',occurred);
    event_digest := public.saas_canonical_json_sha256_v1(event_material);
    INSERT INTO public.saas_platform_audit_events(
        id,sequence_no,tenant_id,actor_type,actor_id,event_type,target_type,target_id,
        operation_id,payload,payload_hash,previous_hash,event_hash,occurred_at,created_at)
    VALUES(source.id,head.last_sequence + 1,source.tenant_id,'system',system_actor,
        source.event_type,source.aggregate_type,evidence.reservation_id,NULL,audit_payload,
        payload_digest,head.last_event_hash,event_digest,evidence.created_at,statement_timestamp());
    UPDATE public.saas_platform_audit_chain_heads
    SET last_sequence = head.last_sequence + 1,last_event_hash = event_digest,
        updated_at = statement_timestamp() WHERE partition_key = 'platform';
    RETURN true;
END
"""


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, action in _OWNER_POLICIES:
        owner = (
            "current_user = pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
            f"WHERE oid = 'public.{table}'::regclass))"
        )
        check = f" WITH CHECK ({owner})" if action == "UPDATE" else ""
        op.execute(
            f"CREATE POLICY rls_gateway_audit_owner_{action.lower()} ON public.{table} "
            f"FOR {action} USING ({owner}){check}"
        )
    op.execute(
        "CREATE POLICY rls_gateway_audit_owner_insert ON public.saas_platform_audit_events "
        "FOR INSERT WITH CHECK (current_user = pg_get_userbyid((SELECT relowner "
        "FROM pg_catalog.pg_class WHERE oid = 'public.saas_platform_audit_events'::regclass)) "
        "AND actor_type = 'system' AND actor_id = '21bb9380-44ca-51a9-8f87-c914945e332a'::uuid "
        "AND event_type = 'model_gateway.evidence_retained' "
        "AND target_type = 'model_gateway_budget' AND operation_id IS NULL)"
    )
    op.execute(
        "CREATE FUNCTION public.saas_audit_model_gateway_evidence_v1("
        "source_event_id uuid,expected_payload jsonb) RETURNS boolean "
        "LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp "
        "AS $function$" + _FUNCTION_BODY + "$function$"
    )
    op.execute(f"REVOKE ALL ON FUNCTION {_SIGNATURE} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_SIGNATURE} TO saas_dispatcher")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("LOCK TABLE public.saas_platform_audit_chain_heads IN ACCESS EXCLUSIVE MODE")
    op.execute("LOCK TABLE public.saas_platform_audit_events IN ACCESS EXCLUSIVE MODE")
    if op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM public.saas_platform_audit_events "
            "WHERE event_type='model_gateway.evidence_retained' "
            "AND target_type='model_gateway_budget')"
        )
    ):
        raise RuntimeError("cannot remove retained gateway audit authority")
    op.execute(f"DROP FUNCTION {_SIGNATURE}")
    op.execute("DROP POLICY rls_gateway_audit_owner_insert ON public.saas_platform_audit_events")
    for table, action in reversed(_OWNER_POLICIES):
        op.execute(f"DROP POLICY rls_gateway_audit_owner_{action.lower()} ON public.{table}")
