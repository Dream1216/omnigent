"""Retain model cutoffs and their audit intent without changing published snapshots.

Revision ID: lm2l00000001
Revises: lm2k00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64

revision = "lm2l00000001"
down_revision = "lm2k00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_model_publication_disablements"
_SAFE = "tenant_id,public_model_id,wire_api,through_generation"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id',true),'')::uuid"
_ENVELOPE = (
    "tenant_id IS NULL AND aggregate_type='platform_model' "
    "AND event_type='platform.model_publication.disabled' "
    "AND payload->>'event_type'=event_type "
    "AND payload::jsonb->'schema_version'='1'::jsonb "
    "AND payload::jsonb-ARRAY['event_type','schema_version','disablement_id']::text[]='{}'::jsonb "
    f"AND EXISTS (SELECT 1 FROM public.{_TABLE} d WHERE d.id::text=aggregate_key "
    "AND d.id::text=payload->>'disablement_id' "
    "AND d.request_hash=saas_control_plane_outbox.request_hash "
    "AND saas_control_plane_outbox.idempotency_key='model-disablement:'||d.id::text "
    f"AND d.principal_id={_PRINCIPAL})"
)


def _authority() -> None:
    op.execute(f"ALTER TABLE public.{_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE public.{_TABLE} FORCE ROW LEVEL SECURITY")
    staff = (
        "EXISTS (SELECT 1 FROM public.saas_platform_role_assignments a "
        f"WHERE a.principal_id={_PRINCIPAL} AND a.status='active' "
        "AND a.role IN ('platform_operator','platform_security_auditor') "
        "AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()))"
    )
    op.execute(
        f"CREATE POLICY rls_model_disable_staff_read ON public.{_TABLE} "
        f"FOR SELECT TO saas_platform_app USING ({staff})"
    )
    op.execute(
        f"CREATE POLICY rls_model_disable_staff_insert ON public.{_TABLE} "
        f"FOR INSERT TO saas_platform_app WITH CHECK (principal_id={_PRINCIPAL} "
        "AND EXISTS (SELECT 1 FROM public.saas_platform_role_assignments a "
        f"WHERE a.principal_id={_PRINCIPAL} AND a.status='active' "
        "AND a.role='platform_operator' "
        "AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp())))"
    )
    op.execute(
        f"CREATE POLICY rls_model_disable_recovery_read ON public.{_TABLE} "
        "FOR SELECT TO saas_platform,saas_platform_governance USING (true)"
    )
    op.execute(
        f"CREATE POLICY rls_model_disable_billing_read ON public.{_TABLE} "
        "FOR SELECT TO saas_billing USING (true)"
    )
    op.execute(
        f"CREATE POLICY rls_model_disable_customer_read ON public.{_TABLE} "
        "FOR SELECT TO saas_app USING ("
        "tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid "
        "AND EXISTS (SELECT 1 FROM public.saas_tenant_memberships m "
        f"WHERE m.tenant_id={_TABLE}.tenant_id AND m.status='active' "
        "AND m.user_id=NULLIF(current_setting('app.actor_id',true),'')::uuid) "
        "AND EXISTS (SELECT 1 FROM public.saas_space_memberships m "
        f"WHERE m.tenant_id={_TABLE}.tenant_id AND m.status='active' "
        "AND m.user_id=NULLIF(current_setting('app.actor_id',true),'')::uuid "
        "AND m.space_id=NULLIF(current_setting('app.space_id',true),'')::uuid))"
    )
    op.execute(f"GRANT SELECT,INSERT ON public.{_TABLE} TO saas_platform_app")
    op.execute(f"GRANT SELECT ON public.{_TABLE} TO saas_platform,saas_platform_governance")
    op.execute(f"GRANT SELECT ({_SAFE}) ON public.{_TABLE} TO saas_app,saas_billing")
    op.execute(
        "GRANT SELECT (id,principal_id,security_version,authenticated_at,expires_at,revoked_at) "
        "ON public.saas_platform_auth_sessions TO saas_platform_app"
    )
    op.execute(
        "CREATE POLICY rls_model_disable_staff_session_read ON public.saas_platform_auth_sessions "
        f"FOR SELECT TO saas_platform_app USING (principal_id={_PRINCIPAL} AND {staff})"
    )
    op.execute(
        "GRANT SELECT (id,tenant_id,aggregate_type,aggregate_key,event_type,payload,"
        "request_hash,idempotency_key) ON public.saas_control_plane_outbox "
        "TO saas_platform_app"
    )
    for verb in ("SELECT", "INSERT"):
        op.execute(
            f"CREATE POLICY rls_outbox_model_disable_{verb.lower()} "
            f"ON public.saas_control_plane_outbox FOR {verb} TO saas_platform_app "
            f"{'USING' if verb == 'SELECT' else 'WITH CHECK'} ({_ENVELOPE})"
        )


def _guards() -> None:
    op.execute(f"""
CREATE FUNCTION public.saas_model_disablement_guard_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog SET lock_timeout='500ms' AS $body$
DECLARE latest_generation integer;
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'model disablement is immutable' USING ERRCODE='23514';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('platform-model-budget:deepseek',0));
    PERFORM pg_advisory_xact_lock(hashtextextended(
        NEW.tenant_id::text||':'||NEW.public_model_id||':'||NEW.wire_api,0));
    SELECT max(generation) INTO latest_generation FROM public.saas_model_publication_versions
        WHERE tenant_id=NEW.tenant_id AND public_model_id=NEW.public_model_id
        AND wire_api=NEW.wire_api;
    IF latest_generation IS DISTINCT FROM NEW.through_generation OR NOT EXISTS (
        SELECT 1 FROM public.saas_platform_auth_sessions s
        JOIN public.saas_platform_staff_principals p ON p.id=s.principal_id
        WHERE s.id=NEW.staff_session_id AND s.principal_id=NEW.principal_id
          AND s.security_version=NEW.staff_security_version
          AND p.security_version=NEW.staff_security_version AND p.status='active'
          AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
          AND s.authenticated_at<=clock_timestamp()
          AND s.authenticated_at>clock_timestamp()-interval '5 minutes'
          AND NEW.created_at<=clock_timestamp()
          AND NEW.created_at>clock_timestamp()-interval '5 minutes'
    ) THEN
        RAISE EXCEPTION 'model disablement authority changed' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END
$body$;
REVOKE ALL ON FUNCTION public.saas_model_disablement_guard_v1() FROM PUBLIC;
CREATE TRIGGER model_disablement_guard BEFORE INSERT OR UPDATE OR DELETE
ON public.{_TABLE} FOR EACH ROW EXECUTE FUNCTION public.saas_model_disablement_guard_v1();
CREATE FUNCTION public.saas_model_disablement_audit_guard_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $body$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.saas_control_plane_outbox e
        WHERE e.tenant_id IS NULL AND e.aggregate_type='platform_model'
        AND e.aggregate_key=NEW.id::text AND e.event_type='platform.model_publication.disabled'
        AND e.request_hash=NEW.request_hash
        AND e.idempotency_key='model-disablement:'||NEW.id::text
        AND e.payload::jsonb=jsonb_build_object('event_type',e.event_type,'schema_version',1,
                                              'disablement_id',NEW.id::text)) THEN
        RAISE EXCEPTION 'model disablement audit intent missing' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END
$body$;
REVOKE ALL ON FUNCTION public.saas_model_disablement_audit_guard_v1() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER model_disablement_audit_guard AFTER INSERT
ON public.{_TABLE} DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.saas_model_disablement_audit_guard_v1();
""")


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("public_model_id", sa.String(128), nullable=False),
        sa.Column("wire_api", sa.String(32), nullable=False),
        sa.Column("through_generation", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("staff_session_id", sa.Uuid(), nullable=False),
        sa.Column("staff_security_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "public_model_id", "wire_api", "through_generation"],
            [
                "saas_model_publication_versions." + name
                for name in ("tenant_id", "public_model_id", "wire_api", "generation")
            ],
            name="fk_model_disablement_publication",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["staff_session_id"], ["saas_platform_auth_sessions.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("principal_id", "idempotency_key", name="uq_model_disablement_key"),
        sa.UniqueConstraint(
            "tenant_id",
            "public_model_id",
            "wire_api",
            "through_generation",
            name="uq_model_disablement_cutoff",
        ),
        sa.CheckConstraint(
            "through_generation>0 AND staff_security_version>0",
            name="ck_model_disablement_generation",
        ),
        sa.CheckConstraint(_hex64("request_hash"), name="ck_model_disablement_hash"),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 128", name="ck_model_disablement_key"
        ),
    )
    if op.get_bind().dialect.name == "postgresql":
        _authority()
        _guards()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"LOCK TABLE public.{_TABLE} IN ACCESS EXCLUSIVE MODE")
        op.execute(f"ALTER TABLE public.{_TABLE} NO FORCE ROW LEVEL SECURITY")
    if bind.scalar(sa.text(f"SELECT EXISTS (SELECT 1 FROM {_TABLE})")):
        raise RuntimeError("cannot remove retained model disablement authority")
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP POLICY rls_model_disable_staff_session_read "
            "ON public.saas_platform_auth_sessions"
        )
        op.execute(
            "REVOKE SELECT (id,principal_id,security_version,authenticated_at,"
            "expires_at,revoked_at) ON public.saas_platform_auth_sessions "
            "FROM saas_platform_app"
        )
        for verb in ("select", "insert"):
            op.execute(
                f"DROP POLICY rls_outbox_model_disable_{verb} ON public.saas_control_plane_outbox"
            )
        op.execute(f"DROP TRIGGER model_disablement_audit_guard ON public.{_TABLE}")
        op.execute(f"DROP TRIGGER model_disablement_guard ON public.{_TABLE}")
        op.execute("DROP FUNCTION public.saas_model_disablement_audit_guard_v1()")
        op.execute("DROP FUNCTION public.saas_model_disablement_guard_v1()")
    op.drop_table(_TABLE)
