"""Expose only historical interactive ownership, never expired execution authority.

Revision ID: lm2i00000001
Revises: lm2h00000001
"""

from alembic import op

revision = "lm2i00000001"
down_revision = "lm2h00000001"
branch_labels = None
depends_on = None

_SIGNATURE = "public.saas_interactive_recovery_owner_v1(uuid,bigint,uuid,bigint,jsonb)"
_BODY = """
SELECT EXISTS (
    SELECT 1 FROM public.saas_runs r
    JOIN public.saas_capability_tokens c ON c.run_id=r.id AND c.fence_token=r.fence_token
    JOIN public.saas_runner_registrations machine ON machine.id=c.runner_id
    WHERE r.id=requested_run AND r.fence_token=expected_fence
      AND c.runner_id=expected_runner AND c.runner_connection_generation=expected_generation
      AND machine.connection_generation=expected_generation AND machine.status IN ('online','draining')
      AND session_user::text='runner_'||replace(expected_runner::text,'-','')||'_g'||expected_generation::text
      AND pg_catalog.pg_has_role(session_user,'saas_runner_agent','MEMBER')
      AND r.queue_class='managed_interactive' AND r.created_by_service_account_id IS NULL
      AND c.allowed_actions::jsonb ? 'runtime.interactive.execute'
      AND (c.tenant_id,c.space_id,c.project_id)=(r.tenant_id,r.space_id,r.project_id)
      AND expected_binding=jsonb_build_object(
          'tenant_id',r.tenant_id::text,'space_id',r.space_id::text,'project_id',r.project_id::text,
          'actor_id',r.created_by::text,'session_id',r.session_id::text,'product_revision',r.product_revision,
          'partition_id',r.input::jsonb#>>'{execution,runtime_partition_id}',
          'official_session_id',r.input::jsonb#>>'{execution,runtime_session_id}',
          'publication_sha256',r.input::jsonb#>>'{execution,model_publication,snapshot_sha256}')
)
"""  # noqa: E501 - Preserve reviewable source-pinned SQL.


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "CREATE FUNCTION public.saas_interactive_recovery_owner_v1(requested_run uuid, "
        "expected_fence bigint, expected_runner uuid, expected_generation bigint, "
        "expected_binding jsonb) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER "
        f"SET search_path=pg_catalog AS $function${_BODY}$function$"
    )
    op.execute(f"REVOKE ALL ON FUNCTION {_SIGNATURE} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_SIGNATURE} TO saas_runner_agent")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"DROP FUNCTION {_SIGNATURE}")
