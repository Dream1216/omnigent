"""Bind renewable model credentials to an authorized, live interactive Run.

Revision ID: lm2f00000001
Revises: lm2e00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64

revision = "lm2f00000001"
down_revision = "lm2e00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_model_run_tokens"
_METADATA = (
    "id,tenant_id,space_id,project_id,actor_id,run_id,capability_id,fence_token,"
    "generation,parent_id,issued_at,expires_at"
)
_RUN = "NULLIF(current_setting('app.model_run_id',true),'')::uuid"
_CAP = "NULLIF(current_setting('app.model_capability_id',true),'')::uuid"
_SCOPE = (
    f"run_id={_RUN} AND capability_id={_CAP} "
    "AND tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid "
    "AND space_id=NULLIF(current_setting('app.space_id',true),'')::uuid "
    "AND project_id=NULLIF(current_setting('app.project_id',true),'')::uuid "
    "AND actor_id=NULLIF(current_setting('app.actor_id',true),'')::uuid "
    f"AND EXISTS (SELECT 1 FROM public.saas_runs r WHERE r.id={_TABLE}.run_id "
    f"AND r.created_by={_TABLE}.actor_id AND r.created_by_service_account_id IS NULL "
    "AND r.queue_class='managed_interactive' AND r.status='running' "
    f"AND r.fence_token={_TABLE}.fence_token AND r.lease_expires_at>statement_timestamp())"
)
_CAPABILITY = """
SELECT c.id,c.run_id,c.runner_id,c.fence_token,c.tenant_id,c.space_id,c.project_id,
       c.allowed_actions,c.expires_at,c.revoked_at
FROM public.saas_capability_tokens c JOIN public.saas_runs r ON r.id=c.run_id
WHERE r.id=requested_run AND c.id=requested_capability
  AND requested_run=NULLIF(current_setting('app.model_run_id',true),'')::uuid
  AND requested_capability=NULLIF(current_setting('app.model_capability_id',true),'')::uuid
  AND r.created_by=NULLIF(current_setting('app.actor_id',true),'')::uuid
  AND r.tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid
  AND r.space_id=NULLIF(current_setting('app.space_id',true),'')::uuid
  AND r.project_id=NULLIF(current_setting('app.project_id',true),'')::uuid
  AND r.created_by_service_account_id IS NULL AND r.queue_class='managed_interactive'
  AND r.status='running' AND r.lease_expires_at>statement_timestamp()
  AND c.fence_token=r.fence_token AND c.runner_id::text=r.lease_owner
  AND c.revoked_at IS NULL AND c.expires_at>statement_timestamp()
"""
_GUARD = """
DECLARE
    r public.saas_runs%ROWTYPE;
    parent record;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'model Run credentials are immutable' USING ERRCODE='23514';
    END IF;
    SELECT * INTO STRICT r FROM public.saas_runs WHERE id=NEW.run_id FOR UPDATE;
    IF (NEW.tenant_id,NEW.space_id,NEW.project_id,NEW.actor_id,NEW.fence_token)
       IS DISTINCT FROM (r.tenant_id,r.space_id,r.project_id,r.created_by,r.fence_token)
       OR r.created_by_service_account_id IS NOT NULL OR r.status<>'running'
       OR r.queue_class<>'managed_interactive' OR r.lease_expires_at IS NULL
       OR r.lease_expires_at<=statement_timestamp()
       OR NOT r.customer_pricing_frozen OR r.customer_pricing_snapshot_id IS NULL
       OR NEW.issued_at>statement_timestamp()+interval '5 seconds'
       OR NEW.issued_at<statement_timestamp()-interval '5 minutes'
       OR NEW.expires_at>NEW.issued_at+interval '8 hours'
       OR NOT EXISTS (SELECT 1 FROM
           public.saas_model_run_capability_v1(NEW.run_id,NEW.capability_id) c
           WHERE c.id=NEW.capability_id AND c.run_id=r.id AND c.fence_token=r.fence_token
           AND (c.tenant_id,c.space_id,c.project_id)=(r.tenant_id,r.space_id,r.project_id)
           AND c.runner_id::text=r.lease_owner AND c.revoked_at IS NULL
           AND c.expires_at>statement_timestamp()
           AND c.allowed_actions::jsonb @> '["run.execute","runtime.interactive.execute"]'::jsonb
           AND jsonb_array_length(c.allowed_actions::jsonb)=2)
    THEN RAISE EXCEPTION 'model Run authority rejected' USING ERRCODE='23514'; END IF;
    IF NEW.parent_id IS NOT NULL THEN
        SELECT id,tenant_id,space_id,project_id,actor_id,run_id,capability_id,fence_token,
               generation,issued_at,expires_at INTO STRICT parent
        FROM public.saas_model_run_tokens WHERE id=NEW.parent_id;
        IF (NEW.tenant_id,NEW.space_id,NEW.project_id,NEW.actor_id,NEW.run_id,
            NEW.capability_id,NEW.fence_token,NEW.generation)
           IS DISTINCT FROM (parent.tenant_id,parent.space_id,parent.project_id,parent.actor_id,
               parent.run_id,parent.capability_id,parent.fence_token,parent.generation+1)
           OR NEW.issued_at<parent.issued_at OR NEW.expires_at<=parent.expires_at
        THEN RAISE EXCEPTION 'model Run renewal rejected' USING ERRCODE='23514'; END IF;
    END IF;
    RETURN NEW;
END
"""


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        *(
            sa.Column(name, sa.Uuid(), nullable=False)
            for name in (
                "tenant_id",
                "space_id",
                "project_id",
                "actor_id",
                "run_id",
                "capability_id",
            )
        ),
        sa.Column("fence_token", sa.BigInteger(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("parent_id", sa.Uuid(), nullable=True, unique=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["capability_id"], ["saas_capability_tokens.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["parent_id"], [f"{_TABLE}.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id", "space_id", "project_id"],
            ["saas_runs.id", "saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id"],
            name="fk_model_run_token_scope",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(_hex64("token_hash"), name="ck_model_run_token_hash"),
        sa.CheckConstraint(
            "fence_token>0 AND generation BETWEEN 0 AND 256", name="ck_model_run_token_generation"
        ),
        sa.CheckConstraint(
            "(generation=0 AND parent_id IS NULL) OR (generation>0 AND parent_id IS NOT NULL)",
            name="ck_model_run_token_parent",
        ),
        sa.CheckConstraint("expires_at>issued_at", name="ck_model_run_token_expiry"),
        sa.UniqueConstraint(
            "run_id", "fence_token", "generation", name="uq_model_run_token_generation"
        ),
    )
    op.create_index("ix_model_run_token_run", _TABLE, ["run_id", "fence_token"])
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(f"ALTER TABLE public.{_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE public.{_TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY rls_model_run_owner_read ON public.{_TABLE} FOR SELECT "
        "USING (current_user=pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
        f"WHERE oid='public.{_TABLE}'::regclass)))"
    )
    op.execute(f"GRANT SELECT ({_METADATA}) ON public.{_TABLE} TO saas_app")
    op.execute(f"GRANT INSERT ON public.{_TABLE} TO saas_app")
    op.execute(f"GRANT SELECT ON public.{_TABLE} TO saas_authenticator")
    op.execute(
        "CREATE FUNCTION public.saas_model_run_capability_v1(requested_run uuid, "
        "requested_capability uuid) RETURNS TABLE (id uuid,run_id uuid,runner_id uuid,"
        "fence_token bigint,tenant_id uuid,space_id uuid,project_id uuid,allowed_actions json,"
        "expires_at timestamptz,revoked_at timestamptz) LANGUAGE sql STABLE SECURITY DEFINER "
        f"SET search_path=pg_catalog AS $function${_CAPABILITY}$function$"
    )
    op.execute("REVOKE ALL ON FUNCTION public.saas_model_run_capability_v1(uuid,uuid) FROM PUBLIC")
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.saas_model_run_capability_v1(uuid,uuid) TO saas_app"
    )
    op.execute(
        f"CREATE POLICY rls_model_run_read ON public.{_TABLE} "
        f"FOR SELECT TO saas_app USING ({_SCOPE})"
    )
    op.execute(
        f"CREATE POLICY rls_model_run_issue ON public.{_TABLE} "
        f"FOR INSERT TO saas_app WITH CHECK ({_SCOPE})"
    )
    op.execute(
        f"CREATE POLICY rls_model_run_authenticate ON public.{_TABLE} "
        "FOR SELECT TO saas_authenticator USING "
        "(token_hash=NULLIF(current_setting('app.model_token_hash',true),''))"
    )
    op.execute(
        "CREATE FUNCTION public.saas_model_run_token_guard() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog "
        f"AS $function${_GUARD}$function$"
    )
    op.execute("REVOKE ALL ON FUNCTION public.saas_model_run_token_guard() FROM PUBLIC")
    op.execute(
        f"CREATE TRIGGER model_run_token_guard BEFORE INSERT OR UPDATE OR DELETE "
        f"ON public.{_TABLE} FOR EACH ROW "
        "EXECUTE FUNCTION public.saas_model_run_token_guard()"
    )


def downgrade() -> None:
    if op.get_bind().execute(sa.text(f"SELECT EXISTS(SELECT 1 FROM {_TABLE})")).scalar_one():
        raise RuntimeError("retained model Run credentials prevent destructive downgrade")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"DROP TRIGGER model_run_token_guard ON public.{_TABLE}")
        op.execute("DROP FUNCTION public.saas_model_run_token_guard()")
        op.execute("DROP FUNCTION public.saas_model_run_capability_v1(uuid,uuid)")
    op.drop_index("ix_model_run_token_run", table_name=_TABLE)
    op.drop_table(_TABLE)
