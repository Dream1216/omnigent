"""Deliver immutable model cutoffs to the existing platform audit chain.

Revision ID: lm2m00000001
Revises: lm2l00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2m00000001"
down_revision = "lm2l00000001"
branch_labels = None
depends_on = None

_SIGNATURE = "public.saas_audit_model_disablement_v1(uuid,jsonb)"
_FUNCTION_BODY = """
DECLARE
    source public.saas_control_plane_outbox%ROWTYPE;
    cutoff public.saas_model_publication_disablements%ROWTYPE;
    head public.saas_platform_audit_chain_heads%ROWTYPE;
    prior public.saas_platform_audit_events%ROWTYPE;
    audit_payload jsonb;
    payload_digest text;
    occurred text;
    event_material jsonb;
    event_digest text;
BEGIN
    SELECT * INTO source FROM public.saas_control_plane_outbox WHERE id=source_event_id;
    IF NOT FOUND OR source.tenant_id IS NOT NULL OR source.aggregate_type<>'platform_model'
       OR source.event_type<>'platform.model_publication.disabled'
       OR source.payload::jsonb IS DISTINCT FROM expected_payload
       OR jsonb_typeof(expected_payload) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(expected_payload))<>3
       OR expected_payload->>'event_type' IS DISTINCT FROM source.event_type
       OR expected_payload->'schema_version' IS DISTINCT FROM '1'::jsonb
       OR expected_payload->>'disablement_id' IS DISTINCT FROM source.aggregate_key
    THEN RAISE EXCEPTION 'model_disablement_audit_evidence_rejected' USING ERRCODE='22023';
    END IF;
    SELECT * INTO cutoff FROM public.saas_model_publication_disablements
        WHERE id::text=source.aggregate_key;
    IF NOT FOUND OR cutoff.request_hash IS DISTINCT FROM source.request_hash
       OR source.idempotency_key IS DISTINCT FROM 'model-disablement:'||cutoff.id::text
    THEN RAISE EXCEPTION 'model_disablement_audit_evidence_rejected' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT head FROM public.saas_platform_audit_chain_heads
        WHERE partition_key='platform' FOR UPDATE;
    IF (head.last_sequence=0 AND (head.last_event_hash<>repeat('0',64)
        OR EXISTS (SELECT 1 FROM public.saas_platform_audit_events)))
       OR (head.last_sequence>0 AND NOT EXISTS (
           SELECT 1 FROM public.saas_platform_audit_events
           WHERE sequence_no=head.last_sequence AND event_hash=head.last_event_hash))
    THEN RAISE EXCEPTION 'model_disablement_audit_chain_unavailable' USING ERRCODE='23514';
    END IF;
    audit_payload := expected_payload || jsonb_build_object(
        'source_event_id',source.id::text,'public_model_id',cutoff.public_model_id,
        'wire_api',cutoff.wire_api,'through_generation',cutoff.through_generation);
    payload_digest := public.saas_canonical_json_sha256_v1(audit_payload);
    occurred := to_char(cutoff.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')
        || CASE WHEN to_char(cutoff.created_at AT TIME ZONE 'UTC','US')='000000'
                THEN '' ELSE '.'||to_char(cutoff.created_at AT TIME ZONE 'UTC','US') END
        || '+00:00';
    SELECT * INTO prior FROM public.saas_platform_audit_events WHERE id=source.id;
    IF FOUND THEN
        event_material := jsonb_build_object(
            'sequence_no',prior.sequence_no,'tenant_id',cutoff.tenant_id::text,
            'actor_type','staff','actor_id',cutoff.principal_id::text,
            'event_type',source.event_type,'target_type','model_publication_disablement',
            'target_id',cutoff.id::text,'operation_id',NULL,
            'payload_hash',payload_digest,'previous_hash',prior.previous_hash,
            'occurred_at',occurred);
        IF prior.sequence_no>head.last_sequence
           OR prior.tenant_id IS DISTINCT FROM cutoff.tenant_id
           OR prior.actor_type<>'staff' OR prior.actor_id<>cutoff.principal_id
           OR prior.event_type<>source.event_type
           OR prior.target_type<>'model_publication_disablement'
           OR prior.target_id<>cutoff.id OR prior.operation_id IS NOT NULL
           OR prior.payload::jsonb IS DISTINCT FROM audit_payload
           OR prior.payload_hash<>payload_digest OR prior.occurred_at<>cutoff.created_at
           OR prior.event_hash<>public.saas_canonical_json_sha256_v1(event_material)
        THEN RAISE EXCEPTION 'model_disablement_audit_replay_conflict' USING ERRCODE='23514';
        END IF;
        RETURN false;
    END IF;
    event_material := jsonb_build_object(
        'sequence_no',head.last_sequence+1,'tenant_id',cutoff.tenant_id::text,
        'actor_type','staff','actor_id',cutoff.principal_id::text,
        'event_type',source.event_type,'target_type','model_publication_disablement',
        'target_id',cutoff.id::text,'operation_id',NULL,
        'payload_hash',payload_digest,'previous_hash',head.last_event_hash,
        'occurred_at',occurred);
    event_digest := public.saas_canonical_json_sha256_v1(event_material);
    INSERT INTO public.saas_platform_audit_events(
        id,sequence_no,tenant_id,actor_type,actor_id,event_type,target_type,target_id,
        operation_id,payload,payload_hash,previous_hash,event_hash,occurred_at,created_at)
    VALUES(source.id,head.last_sequence+1,cutoff.tenant_id,'staff',cutoff.principal_id,
        source.event_type,'model_publication_disablement',cutoff.id,NULL,audit_payload,
        payload_digest,head.last_event_hash,event_digest,cutoff.created_at,statement_timestamp());
    UPDATE public.saas_platform_audit_chain_heads
        SET last_sequence=head.last_sequence+1,last_event_hash=event_digest,
            updated_at=statement_timestamp() WHERE partition_key='platform';
    RETURN true;
END
"""


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "CREATE POLICY rls_disablement_audit_owner_read "
        "ON public.saas_model_publication_disablements FOR SELECT USING ("
        "current_user=pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
        "WHERE oid='public.saas_model_publication_disablements'::regclass)))"
    )
    op.execute(
        "CREATE POLICY rls_disablement_audit_owner_insert "
        "ON public.saas_platform_audit_events FOR INSERT WITH CHECK ("
        "current_user=pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
        "WHERE oid='public.saas_platform_audit_events'::regclass)) "
        "AND actor_type='staff' AND event_type='platform.model_publication.disabled' "
        "AND target_type='model_publication_disablement' AND operation_id IS NULL)"
    )
    op.execute(
        "CREATE FUNCTION public.saas_audit_model_disablement_v1("
        "source_event_id uuid,expected_payload jsonb) RETURNS boolean "
        "LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog, pg_temp "
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
            "WHERE event_type='platform.model_publication.disabled' "
            "AND target_type='model_publication_disablement') "
            "OR EXISTS(SELECT 1 FROM public.saas_model_publication_disablements)"
        )
    ):
        raise RuntimeError("cannot remove retained model disablement audit authority")
    op.execute(f"DROP FUNCTION {_SIGNATURE}")
    op.execute(
        "DROP POLICY rls_disablement_audit_owner_insert ON public.saas_platform_audit_events"
    )
    op.execute(
        "DROP POLICY rls_disablement_audit_owner_read "
        "ON public.saas_model_publication_disablements"
    )
