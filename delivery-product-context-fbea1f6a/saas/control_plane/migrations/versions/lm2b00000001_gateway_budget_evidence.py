"""Retain content-blind gateway evidence and reference-only budget Outbox facts.

Revision ID: lm2b00000001
Revises: lm2a00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64

revision = "lm2b00000001"
down_revision = "lm2a00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_model_gateway_evidence"
_BUDGET = "saas_model_provider_budget_reservations"
_OUTBOX = "saas_control_plane_outbox"


def _authority() -> None:
    op.execute(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(f"GRANT SELECT, INSERT ON {_TABLE} TO saas_billing")
    op.execute(f"GRANT SELECT ON {_TABLE} TO saas_platform, saas_platform_governance")
    op.execute(
        f"CREATE POLICY rls_gateway_evidence_billing_read ON {_TABLE} "
        "FOR SELECT TO saas_billing USING (true)"
    )
    op.execute(
        f"CREATE POLICY rls_gateway_evidence_billing_insert ON {_TABLE} "
        "FOR INSERT TO saas_billing WITH CHECK (true)"
    )
    op.execute(
        f"CREATE POLICY rls_gateway_evidence_recovery ON {_TABLE} "
        "FOR SELECT TO saas_platform, saas_platform_governance USING (true)"
    )
    envelope = (
        "aggregate_type = 'model_gateway_budget' "
        "AND event_type = 'model_gateway.evidence_retained' "
        "AND jsonb_typeof(payload::jsonb) = 'object' "
        "AND (SELECT count(*) FROM jsonb_object_keys(payload::jsonb)) = 5 "
        "AND payload->>'event_type' = event_type AND payload->>'tenant_id' = tenant_id::text "
        "AND payload->>'reservation_id' = aggregate_key "
        f"AND EXISTS (SELECT 1 FROM {_TABLE} evidence WHERE "
        "evidence.id::text = payload->>'evidence_id' "
        f"AND evidence.tenant_id = {_OUTBOX}.tenant_id "
        "AND evidence.reservation_id::text = aggregate_key "
        "AND evidence.evidence_sha256 = request_hash "
        "AND evidence.evidence_sha256 = payload->>'evidence_sha256' "
        "AND idempotency_key = 'model-gateway-evidence:' || replace(evidence.id::text, '-', ''))"
    )
    op.execute(
        f"CREATE POLICY rls_outbox_gateway_evidence_insert ON {_OUTBOX} "
        f"FOR INSERT TO saas_billing WITH CHECK ({envelope})"
    )
    op.execute(
        f"CREATE POLICY rls_outbox_gateway_evidence_read ON {_OUTBOX} "
        f"FOR SELECT TO saas_billing USING ({envelope})"
    )


def _guard() -> None:
    op.execute(f"""
    CREATE FUNCTION public.saas_model_gateway_evidence_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
    DECLARE
        budget public.{_BUDGET}%ROWTYPE;
        original public.{_TABLE}%ROWTYPE;
        value jsonb;
        usage jsonb;
        request jsonb;
        prior_version integer;
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'gateway evidence is immutable' USING ERRCODE = '23514';
        END IF;
        SELECT * INTO STRICT budget FROM public.{_BUDGET} WHERE id = NEW.reservation_id;
        value := NEW.canonical_evidence::jsonb;
        IF jsonb_typeof(value) <> 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(value)) <> 16
           OR value->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v1'
           OR value->>'phase' IS DISTINCT FROM NEW.phase
           OR value->>'reservation_id' IS DISTINCT FROM budget.id::text
           OR value->>'tenant_id' IS DISTINCT FROM budget.tenant_id::text
           OR NEW.tenant_id IS DISTINCT FROM budget.tenant_id
           OR value->>'session_id' IS DISTINCT FROM budget.run_id::text
           OR value->>'provider_id' IS DISTINCT FROM budget.provider_id
           OR value->>'configuration_version' IS DISTINCT FROM budget.configuration_version::text
           OR value->>'budget_version' IS DISTINCT FROM budget.version::text
           OR jsonb_typeof(value->'budget_version') IS DISTINCT FROM 'number'
           OR jsonb_typeof(value->'configuration_version') IS DISTINCT FROM 'number'
           OR NEW.budget_version <> budget.version OR budget.purpose <> 'tenant_run'
           OR value->>'status' IS DISTINCT FROM budget.status
           OR value->'admission' IS DISTINCT FROM jsonb_build_object(
               'requested_microusd',budget.requested_microusd,'requested_tokens',budget.requested_tokens,
               'admitted_microusd',budget.admitted_microusd,'admitted_tokens',budget.admitted_tokens)
           OR (value->>'occurred_at')::timestamptz IS DISTINCT FROM NEW.created_at
           OR encode(sha256(convert_to(NEW.canonical_evidence, 'UTF8')), 'hex')
              <> NEW.evidence_sha256
        THEN RAISE EXCEPTION 'gateway evidence binding rejected' USING ERRCODE = '23514'; END IF;
        IF NEW.phase = 'request' THEN
            request := value->'request';
            IF budget.version <> 1 OR budget.status NOT IN ('reserved', 'rejected')
               OR NEW.created_at IS DISTINCT FROM budget.created_at
               OR jsonb_typeof(request) <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(request)) <> 5
               OR NOT request ?& ARRAY['public_model_id','wire_api','pricing_revision',
                                       'model_price','output_token_limit']
               OR (request->>'public_model_id') !~ '^[!-~]{{1,128}}$'
               OR jsonb_typeof(request->'public_model_id') IS DISTINCT FROM 'string'
               OR request->>'wire_api' NOT IN ('openai_chat_completions','openai_responses')
               OR jsonb_typeof(request->'wire_api') IS DISTINCT FROM 'string'
               OR (request->>'pricing_revision') !~ '^[!-~]{{1,32}}$'
               OR jsonb_typeof(request->'pricing_revision') IS DISTINCT FROM 'string'
               OR (request->>'output_token_limit') !~ '^[1-9][0-9]{{0,5}}$'
               OR jsonb_typeof(request->'output_token_limit') IS DISTINCT FROM 'number'
               OR (request->>'output_token_limit')::integer > 65536
               OR jsonb_typeof(request->'model_price') <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(request->'model_price')) <> 7
               OR NOT (request->'model_price') ?& ARRAY['model_sha256',
                   'peak_input_cache_hit_microusd_per_million_tokens',
                   'peak_input_cache_miss_microusd_per_million_tokens',
                   'peak_output_microusd_per_million_tokens',
                   'off_peak_input_cache_hit_microusd_per_million_tokens',
                   'off_peak_input_cache_miss_microusd_per_million_tokens',
                   'off_peak_output_microusd_per_million_tokens']
               OR EXISTS (SELECT 1 FROM jsonb_each(request->'model_price') pair
                   WHERE pair.key <> 'model_sha256' AND (jsonb_typeof(pair.value) <> 'number'
                     OR pair.value::text !~ '^[1-9][0-9]{{0,12}}$'))
               OR EXISTS (SELECT 1 FROM jsonb_each(request->'model_price') pair
                   WHERE pair.key <> 'model_sha256' AND pair.value::text::numeric > 1000000000000)
               OR request->'model_price'->>'model_sha256' IS DISTINCT FROM
                  encode(sha256(convert_to(request->>'public_model_id','UTF8')), 'hex')
               OR value->'usage' IS DISTINCT FROM 'null'::jsonb
               OR value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
               OR value->'request_evidence_sha256' IS DISTINCT FROM 'null'::jsonb
               OR value->'reason' IS DISTINCT FROM 'null'::jsonb
            THEN RAISE EXCEPTION 'gateway request evidence rejected' USING ERRCODE = '23514';
            END IF;
        ELSE
            SELECT * INTO STRICT original FROM public.{_TABLE}
            WHERE reservation_id = budget.id AND phase = 'request';
            IF value->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
               OR value->'admission' IS DISTINCT FROM
                  original.canonical_evidence::jsonb->'admission'
               OR value->'request' IS DISTINCT FROM 'null'::jsonb
               OR NEW.phase <> budget.status
            THEN RAISE EXCEPTION 'gateway transition evidence rejected' USING ERRCODE = '23514';
            END IF;
            SELECT max(budget_version) INTO prior_version FROM public.{_TABLE}
            WHERE reservation_id = budget.id;
            IF NEW.budget_version <> prior_version + 1
               OR (NEW.phase = 'in_flight' AND prior_version <> 1)
               OR (NEW.phase IN ('uncertain','settled') AND NOT EXISTS (
                   SELECT 1 FROM public.{_TABLE} WHERE reservation_id = budget.id
                   AND phase = 'in_flight'))
            THEN RAISE EXCEPTION 'gateway evidence sequence rejected' USING ERRCODE = '23514';
            END IF;
            usage := value->'usage';
            IF usage IS DISTINCT FROM 'null'::jsonb THEN
                IF budget.status NOT IN ('settled','released') OR jsonb_typeof(usage) <> 'object'
                   OR (SELECT count(*) FROM jsonb_object_keys(usage)) <> 5
                   OR NOT usage ?& ARRAY['input_tokens','input_cache_hit_tokens',
                       'input_cache_miss_tokens','output_tokens','total_tokens']
                   OR EXISTS (SELECT 1 FROM jsonb_each(usage) pair
                              WHERE jsonb_typeof(pair.value) <> 'number'
                              OR pair.value::text !~ '^[0-9]{{1,19}}$')
                   OR (usage->>'total_tokens')::numeric <> budget.settled_tokens
                   OR (usage->>'input_tokens')::numeric + (usage->>'output_tokens')::numeric
                      <> budget.settled_tokens
                   OR (usage->>'input_cache_hit_tokens')::numeric
                      + (usage->>'input_cache_miss_tokens')::numeric
                      <> (usage->>'input_tokens')::numeric
                   OR (usage->>'output_tokens')::numeric >
                      (original.canonical_evidence::jsonb->'request'->>'output_token_limit')::integer
                   OR value->>'actual_microusd' IS DISTINCT FROM budget.settled_microusd::text
                   OR jsonb_typeof(value->'actual_microusd') IS DISTINCT FROM 'number'
                   OR budget.outcome_evidence_sha256 IS DISTINCT FROM NEW.evidence_sha256
                   OR value->'reason' IS DISTINCT FROM 'null'::jsonb
                   OR NOT EXISTS (SELECT 1 FROM public.{_TABLE}
                       WHERE reservation_id = budget.id AND phase = 'in_flight')
                THEN RAISE EXCEPTION 'gateway usage evidence rejected' USING ERRCODE = '23514';
                END IF;
            ELSIF value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
               OR (budget.status = 'in_flight' AND value->'reason' IS DISTINCT FROM 'null'::jsonb)
               OR (budget.status = 'uncertain' AND COALESCE(value->>'reason','') NOT IN
                   ('provider_outcome_unknown','provider_rejected','provider_unreachable','stream_incomplete','settlement_unavailable'))
               OR (budget.status IN ('released','expired')
                   AND (value->>'reason' IS DISTINCT FROM 'not_sent' OR prior_version <> 1))
               OR budget.status NOT IN ('in_flight','uncertain','released','expired')
            THEN RAISE EXCEPTION 'gateway pending evidence rejected' USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NEW;
    END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION public.saas_model_gateway_evidence_guard() FROM PUBLIC")
    op.execute(
        f"CREATE TRIGGER trg_model_gateway_evidence_guard BEFORE INSERT OR UPDATE OR DELETE "
        f"ON {_TABLE} FOR EACH ROW EXECUTE FUNCTION public.saas_model_gateway_evidence_guard()"
    )


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("reservation_id", sa.Uuid(), nullable=False),
        sa.Column("phase", sa.String(16), nullable=False),
        sa.Column("budget_version", sa.Integer(), nullable=False),
        sa.Column("canonical_evidence", sa.Text(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "reservation_id"],
            [f"{_BUDGET}.tenant_id", f"{_BUDGET}.id"],
            ondelete="RESTRICT",
            name="fk_model_gateway_evidence_budget",
        ),
        sa.UniqueConstraint("reservation_id", "phase", name="uq_model_gateway_evidence_phase"),
        sa.UniqueConstraint(
            "reservation_id", "budget_version", name="uq_model_gateway_evidence_version"
        ),
        sa.CheckConstraint(
            "phase IN ('request','in_flight','uncertain','settled','released','expired')",
            name="ck_model_gateway_evidence_phase",
        ),
        sa.CheckConstraint("budget_version > 0", name="ck_model_gateway_evidence_version"),
        sa.CheckConstraint(_hex64("evidence_sha256"), name="ck_model_gateway_evidence_hash"),
        sa.CheckConstraint(
            "length(canonical_evidence) BETWEEN 1 AND 16384",
            name="ck_model_gateway_evidence_bound",
        ),
    )
    op.create_index(
        "ix_model_gateway_evidence_scope", _TABLE, ["tenant_id", "reservation_id", "created_at"]
    )
    if op.get_bind().dialect.name == "postgresql":
        _authority()
        _guard()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE")
        op.execute(f"ALTER TABLE {_TABLE} NO FORCE ROW LEVEL SECURITY")
    if bind.scalar(sa.text(f"SELECT EXISTS (SELECT 1 FROM {_TABLE})")):
        raise RuntimeError("cannot remove retained gateway evidence")
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP POLICY rls_outbox_gateway_evidence_insert ON {_OUTBOX}")
        op.execute(f"DROP POLICY rls_outbox_gateway_evidence_read ON {_OUTBOX}")
        op.execute(f"DROP TRIGGER trg_model_gateway_evidence_guard ON {_TABLE}")
        op.execute("DROP FUNCTION public.saas_model_gateway_evidence_guard()")
    op.drop_table(_TABLE)
