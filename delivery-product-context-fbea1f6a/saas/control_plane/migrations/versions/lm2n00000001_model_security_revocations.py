"""Retain model security intent independently of ordinary disablement.

Revision ID: lm2n00000001
Revises: lm2m00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64
from saas.control_plane.migrations.versions.lm2m00000001_model_disablement_audit import (
    _FUNCTION_BODY as _DISABLEMENT_AUDIT_BODY,
)

revision = "lm2n00000001"
down_revision = "lm2m00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_model_publication_revocations"
_SIGNATURE = "public.saas_audit_model_revocation_v1(uuid,jsonb)"
_SCOPE = "tenant_id,public_model_id,wire_api,through_generation"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id',true),'')::uuid"
_FUNCTION_BODY = _DISABLEMENT_AUDIT_BODY.replace("disablement", "revocation").replace(
    "platform.model_publication.disabled", "platform.model_publication.revocation_requested"
)
_GUARD_BODY = """
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'model security revocation is immutable' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.saas_model_publication_disablements d
        WHERE d.id=NEW.disablement_id AND d.tenant_id=NEW.tenant_id
          AND d.public_model_id=NEW.public_model_id AND d.wire_api=NEW.wire_api
          AND d.through_generation=NEW.through_generation)
       OR NOT EXISTS (SELECT 1 FROM public.saas_platform_auth_sessions s
        JOIN public.saas_platform_staff_principals p ON p.id=s.principal_id
        WHERE s.id=NEW.staff_session_id AND s.principal_id=NEW.principal_id
          AND s.security_version=NEW.staff_security_version
          AND p.security_version=NEW.staff_security_version AND p.status='active'
          AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
          AND s.authenticated_at<=clock_timestamp()
          AND s.authenticated_at>clock_timestamp()-interval '5 minutes'
          AND NEW.created_at<=clock_timestamp()
          AND NEW.created_at>clock_timestamp()-interval '5 minutes')
    THEN RAISE EXCEPTION 'model revocation authority changed' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END
"""
_AUDIT_GUARD_BODY = """
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.saas_control_plane_outbox e
        WHERE e.tenant_id IS NULL AND e.aggregate_type='platform_model'
          AND e.aggregate_key=NEW.id::text
          AND e.event_type='platform.model_publication.revocation_requested'
          AND e.request_hash=NEW.request_hash
          AND e.idempotency_key='model-revocation:'||NEW.id::text
          AND e.payload::jsonb=jsonb_build_object('event_type',e.event_type,'schema_version',1,
                                                 'revocation_id',NEW.id::text))
    THEN RAISE EXCEPTION 'model revocation audit intent missing' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END
"""


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
        f"CREATE POLICY rls_model_revoke_staff_read ON public.{_TABLE} "
        f"FOR SELECT TO saas_platform_app USING ({staff})"
    )
    op.execute(
        f"CREATE POLICY rls_model_revoke_staff_insert ON public.{_TABLE} "
        f"FOR INSERT TO saas_platform_app WITH CHECK (principal_id={_PRINCIPAL} "
        "AND EXISTS (SELECT 1 FROM public.saas_platform_role_assignments a "
        f"WHERE a.principal_id={_PRINCIPAL} AND a.status='active' "
        "AND a.role='platform_operator' "
        "AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp())))"
    )
    op.execute(
        f"CREATE POLICY rls_model_revoke_recovery_read ON public.{_TABLE} "
        "FOR SELECT TO saas_platform,saas_platform_governance,saas_executor USING (true)"
    )
    op.execute(
        f"CREATE POLICY rls_model_revoke_app_read ON public.{_TABLE} FOR SELECT TO saas_app "
        "USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid "
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
    op.execute(f"GRANT SELECT ({_SCOPE}) ON public.{_TABLE} TO saas_app")
    op.execute(f"GRANT SELECT (id,{_SCOPE},created_at) ON public.{_TABLE} TO saas_executor")
    op.execute(
        "GRANT SELECT (tenant_id,public_model_id,wire_api,generation,snapshot_sha256) "
        "ON public.saas_model_publication_versions TO saas_executor"
    )
    op.execute(
        "CREATE POLICY rls_model_revoke_executor_publication_read "
        "ON public.saas_model_publication_versions FOR SELECT TO saas_executor USING (true)"
    )
    envelope = (
        "tenant_id IS NULL AND aggregate_type='platform_model' "
        "AND event_type='platform.model_publication.revocation_requested' "
        "AND payload->>'event_type'=event_type AND payload::jsonb->'schema_version'='1'::jsonb "
        "AND payload::jsonb-ARRAY['event_type','schema_version','revocation_id']::text[]"
        "='{}'::jsonb "
        f"AND EXISTS (SELECT 1 FROM public.{_TABLE} r WHERE r.id::text=aggregate_key "
        "AND r.id::text=payload->>'revocation_id' "
        "AND r.request_hash=saas_control_plane_outbox.request_hash "
        "AND saas_control_plane_outbox.idempotency_key='model-revocation:'||r.id::text "
        f"AND r.principal_id={_PRINCIPAL})"
    )
    for verb in ("SELECT", "INSERT"):
        op.execute(
            "CREATE POLICY rls_outbox_model_revoke_"
            + verb.lower()
            + f" ON public.saas_control_plane_outbox FOR {verb} TO saas_platform_app "
            + ("USING" if verb == "SELECT" else "WITH CHECK")
            + f" ({envelope})"
        )


def _guards_and_audit() -> None:
    for name, body in (
        ("saas_model_revocation_guard_v1", _GUARD_BODY),
        ("saas_model_revocation_audit_guard_v1", _AUDIT_GUARD_BODY),
    ):
        op.execute(
            f"CREATE FUNCTION public.{name}() RETURNS trigger LANGUAGE plpgsql VOLATILE "
            "SET search_path=pg_catalog AS $body$" + body + "$body$"
        )
        op.execute(f"REVOKE ALL ON FUNCTION public.{name}() FROM PUBLIC")
    op.execute(
        f"CREATE TRIGGER model_revocation_guard BEFORE INSERT OR UPDATE OR DELETE "
        f"ON public.{_TABLE} FOR EACH ROW EXECUTE FUNCTION public.saas_model_revocation_guard_v1()"
    )
    op.execute(
        f"CREATE CONSTRAINT TRIGGER model_revocation_audit_guard AFTER INSERT "
        f"ON public.{_TABLE} DEFERRABLE INITIALLY DEFERRED "
        "FOR EACH ROW EXECUTE FUNCTION public.saas_model_revocation_audit_guard_v1()"
    )
    op.execute(
        f"CREATE POLICY rls_revocation_audit_owner_read ON public.{_TABLE} FOR SELECT USING ("
        "current_user=pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
        f"WHERE oid='public.{_TABLE}'::regclass)))"
    )
    op.execute(
        "CREATE POLICY rls_revocation_audit_owner_insert ON public.saas_platform_audit_events "
        "FOR INSERT WITH CHECK (current_user=pg_get_userbyid((SELECT relowner FROM "
        "pg_catalog.pg_class WHERE oid='public.saas_platform_audit_events'::regclass)) "
        "AND actor_type='staff' AND event_type='platform.model_publication.revocation_requested' "
        "AND target_type='model_publication_revocation' AND operation_id IS NULL)"
    )
    op.execute(
        "CREATE FUNCTION public.saas_audit_model_revocation_v1("
        "source_event_id uuid,expected_payload jsonb) "
        "RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER "
        "SET search_path=pg_catalog, pg_temp AS $function$" + _FUNCTION_BODY + "$function$"
    )
    op.execute(f"REVOKE ALL ON FUNCTION {_SIGNATURE} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_SIGNATURE} TO saas_dispatcher")


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("disablement_id", sa.Uuid(), nullable=False),
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
            ["disablement_id"], ["saas_model_publication_disablements.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["staff_session_id"], ["saas_platform_auth_sessions.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("disablement_id", name="uq_model_revocation_cutoff"),
        sa.UniqueConstraint("principal_id", "idempotency_key", name="uq_model_revocation_key"),
        sa.CheckConstraint(
            "through_generation>0 AND staff_security_version>0",
            name="ck_model_revocation_generation",
        ),
        sa.CheckConstraint(_hex64("request_hash"), name="ck_model_revocation_hash"),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 128", name="ck_model_revocation_key"
        ),
    )
    if op.get_bind().dialect.name == "postgresql":
        _authority()
        _guards_and_audit()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"LOCK TABLE public.{_TABLE} IN ACCESS EXCLUSIVE MODE")
        op.execute(f"ALTER TABLE public.{_TABLE} NO FORCE ROW LEVEL SECURITY")
    if bind.scalar(sa.text(f"SELECT EXISTS(SELECT 1 FROM {_TABLE})")):
        raise RuntimeError("cannot remove retained model security revocation authority")
    if bind.dialect.name == "postgresql":
        if bind.scalar(
            sa.text(
                "SELECT EXISTS(SELECT 1 FROM public.saas_platform_audit_events "
                "WHERE event_type='platform.model_publication.revocation_requested')"
            )
        ):
            raise RuntimeError("cannot remove retained model revocation audit evidence")
        op.execute(f"DROP FUNCTION {_SIGNATURE}")
        op.execute(
            "DROP POLICY rls_revocation_audit_owner_insert ON public.saas_platform_audit_events"
        )
        op.execute(
            "DROP POLICY rls_model_revoke_executor_publication_read "
            "ON public.saas_model_publication_versions"
        )
        op.execute(
            "REVOKE SELECT (tenant_id,public_model_id,wire_api,generation,snapshot_sha256) "
            "ON public.saas_model_publication_versions FROM saas_executor"
        )
        for verb in ("select", "insert"):
            op.execute(
                f"DROP POLICY rls_outbox_model_revoke_{verb} ON public.saas_control_plane_outbox"
            )
        op.execute(f"DROP TRIGGER model_revocation_guard ON public.{_TABLE}")
        op.execute(f"DROP TRIGGER model_revocation_audit_guard ON public.{_TABLE}")
        op.execute("DROP FUNCTION public.saas_model_revocation_guard_v1()")
        op.execute("DROP FUNCTION public.saas_model_revocation_audit_guard_v1()")
    op.drop_table(_TABLE)
