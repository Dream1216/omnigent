"""Resolve one active delegated owner alias through authenticator-only lookup.

Revision ID: lm2j00000001
Revises: lm2i00000001
"""

from alembic import op

revision = "lm2j00000001"
down_revision = "lm2i00000001"
branch_labels = None
depends_on = None

_SIGNATURE = "public.saas_delegated_runner_actor_v1(bigint,text)"
_TABLES = (
    "saas_runtime_identity_aliases",
    "saas_runtime_partitions",
    "saas_runtime_placements",
)
_BODY = """
WITH matches AS (
    SELECT a.user_id
    FROM public.saas_runtime_identity_aliases a
    JOIN public.saas_runtime_partitions p ON p.id=a.runtime_partition_id
    JOIN public.saas_runtime_placements placement ON placement.id=p.placement_id
    WHERE requested_workspace>0 AND p.physical_partition_key=requested_workspace::text
      AND a.runtime_user_key=requested_owner AND length(requested_owner) BETWEEN 1 AND 128
      AND requested_owner=btrim(requested_owner)
      AND a.status='active' AND p.status='active' AND placement.status='active'
      AND p.runtime_type='omnigent' AND placement.runtime_type='omnigent'
      AND pg_catalog.pg_has_role(session_user,'saas_authenticator','MEMBER')
)
SELECT user_id FROM matches WHERE (SELECT count(*) FROM matches)=1
"""


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _TABLES:
        op.execute(
            f"CREATE POLICY rls_delegated_runner_identity_owner_read ON public.{table} "
            "FOR SELECT USING (current_user=pg_get_userbyid((SELECT relowner "
            f"FROM pg_catalog.pg_class WHERE oid='public.{table}'::regclass)))"
        )
    op.execute(
        "CREATE FUNCTION public.saas_delegated_runner_actor_v1(requested_workspace bigint, "
        "requested_owner text) RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER "
        f"SET search_path=pg_catalog AS $function${_BODY}$function$"
    )
    op.execute(f"REVOKE ALL ON FUNCTION {_SIGNATURE} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_SIGNATURE} TO saas_authenticator")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(f"DROP FUNCTION {_SIGNATURE}")
    for table in _TABLES:
        op.execute(f"DROP POLICY rls_delegated_runner_identity_owner_read ON public.{table}")
