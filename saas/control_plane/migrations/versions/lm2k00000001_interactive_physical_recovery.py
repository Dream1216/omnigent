"""Persist an executor-only, immutable fence after exact interactive recovery.

Revision ID: lm2k00000001
Revises: lm2j00000001
"""

import sqlalchemy as sa
from alembic import op

revision = "lm2k00000001"
down_revision = "lm2j00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_run_dispatches"
_FUNCTION = "public.saas_interactive_physical_recovery_guard_v1()"
_BODY = """
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.physical_recovery_fence IS NOT NULL THEN
            RAISE EXCEPTION 'interactive recovery must follow dispatch' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.physical_recovery_fence IS NOT NULL
       AND NEW.physical_recovery_fence IS DISTINCT FROM OLD.physical_recovery_fence THEN
        RAISE EXCEPTION 'interactive recovery is immutable' USING ERRCODE='23514';
    END IF;
    IF NEW.physical_recovery_fence IS DISTINCT FROM OLD.physical_recovery_fence THEN
        IF NOT pg_catalog.pg_has_role(session_user,'saas_executor','MEMBER')
           OR NEW.status<>'released' OR NOT EXISTS (
                SELECT 1 FROM public.saas_runs r WHERE r.id=NEW.run_id
                  AND (r.tenant_id,r.space_id,r.project_id)=(NEW.tenant_id,NEW.space_id,NEW.project_id)
                  AND r.queue_class='managed_interactive' AND r.status='orphaned'
                  AND r.fence_token=NEW.physical_recovery_fence
           ) THEN
            RAISE EXCEPTION 'interactive recovery binding denied' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END
"""  # noqa: E501 - Preserve the source-pinned SQL body.


def upgrade() -> None:
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(sa.Column("physical_recovery_fence", sa.BigInteger(), nullable=True))
        batch.create_check_constraint(
            "ck_run_dispatch_physical_recovery_fence",
            "physical_recovery_fence IS NULL OR physical_recovery_fence > 0",
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            f"CREATE FUNCTION {_FUNCTION} RETURNS trigger LANGUAGE plpgsql VOLATILE "
            f"SET search_path=pg_catalog AS $function${_BODY}$function$"
        )
        op.execute(f"REVOKE ALL ON FUNCTION {_FUNCTION} FROM PUBLIC")
        op.execute(
            "CREATE TRIGGER interactive_physical_recovery BEFORE INSERT OR UPDATE "
            f"ON public.{_TABLE} FOR EACH ROW EXECUTE FUNCTION {_FUNCTION}"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"DROP TRIGGER interactive_physical_recovery ON public.{_TABLE}")
        op.execute(f"DROP FUNCTION {_FUNCTION}")
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_constraint("ck_run_dispatch_physical_recovery_fence", type_="check")
        batch.drop_column("physical_recovery_fence")
