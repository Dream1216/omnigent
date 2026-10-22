"""Freeze existing customer price references at Session and Run insertion.

Revision ID: lm2d00000001
Revises: lm2c00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2d00000001"
down_revision = "lm2c00000001"
branch_labels = None
depends_on = None

_TABLES = (("saas_execution_sessions", "session"), ("saas_runs", "run"))
_READS = (
    "saas_billing_subscriptions",
    "saas_pricing_snapshots",
    "saas_execution_sessions",
    "saas_runs",
)
_FUNCTION_BODY = """
DECLARE
    selected_plan text;
    subscription_status text;
    prices uuid[];
    frozen boolean;
    price uuid;
BEGIN
    IF TG_TABLE_NAME = 'saas_usage_events' THEN
        IF NEW.run_id IS NOT NULL THEN
            SELECT customer_pricing_frozen,customer_pricing_snapshot_id INTO STRICT frozen,price
            FROM public.saas_runs WHERE id = NEW.run_id AND tenant_id = NEW.tenant_id
              AND space_id = NEW.space_id AND project_id = NEW.project_id;
            IF frozen AND NEW.pricing_snapshot_id IS DISTINCT FROM price THEN
                RAISE EXCEPTION 'Usage differs from frozen customer pricing' USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.customer_pricing_frozen IS DISTINCT FROM OLD.customer_pricing_frozen
           OR NEW.customer_pricing_snapshot_id IS DISTINCT FROM OLD.customer_pricing_snapshot_id
        THEN RAISE EXCEPTION 'execution customer pricing is immutable' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    NEW.customer_pricing_frozen := false;
    NEW.customer_pricing_snapshot_id := NULL;
    IF TG_TABLE_NAME = 'saas_runs' THEN
        IF NEW.session_id IS NOT NULL THEN
            SELECT customer_pricing_frozen,customer_pricing_snapshot_id
            INTO STRICT NEW.customer_pricing_frozen,NEW.customer_pricing_snapshot_id
            FROM public.saas_execution_sessions WHERE id = NEW.session_id
              AND tenant_id = NEW.tenant_id AND space_id = NEW.space_id
              AND project_id = NEW.project_id;
            RETURN NEW;
        END IF;
    END IF;
    SELECT plan_key,status INTO selected_plan,subscription_status
    FROM public.saas_billing_subscriptions WHERE tenant_id = NEW.tenant_id;
    IF NOT FOUND THEN RETURN NEW; END IF;
    NEW.customer_pricing_frozen := true;
    IF subscription_status NOT IN ('active','trialing') THEN RETURN NEW; END IF;
    SELECT array_agg(id) INTO prices FROM public.saas_pricing_snapshots
    WHERE tenant_id = NEW.tenant_id AND plan_key = selected_plan
      AND effective_from <= NEW.created_at
      AND (effective_until IS NULL OR effective_until > NEW.created_at);
    IF cardinality(prices) = 1 THEN NEW.customer_pricing_snapshot_id := prices[1]; END IF;
    RETURN NEW;
END
"""  # noqa: E501 - Preserve the source-bound SQL diagnostic statement.


def upgrade() -> None:
    for table, label in _TABLES:
        with op.batch_alter_table(table) as batch:
            batch.add_column(
                sa.Column(
                    "customer_pricing_frozen",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.false(),
                )
            )
            batch.add_column(sa.Column("customer_pricing_snapshot_id", sa.Uuid(), nullable=True))
            batch.create_foreign_key(
                f"fk_{label}_customer_pricing",
                "saas_pricing_snapshots",
                ["tenant_id", "customer_pricing_snapshot_id"],
                ["tenant_id", "id"],
                ondelete="RESTRICT",
            )
            batch.create_check_constraint(
                f"ck_{label}_customer_pricing",
                "customer_pricing_frozen OR customer_pricing_snapshot_id IS NULL",
            )
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _READS:
        op.execute(
            f"CREATE POLICY rls_customer_price_owner_read ON public.{table} FOR SELECT "
            "USING (current_user = pg_get_userbyid((SELECT relowner "
            f"FROM pg_catalog.pg_class WHERE oid = 'public.{table}'::regclass)))"
        )
    op.execute(
        "CREATE FUNCTION public.saas_execution_customer_price_guard_v1() RETURNS trigger "
        "LANGUAGE plpgsql VOLATILE SECURITY DEFINER "
        "SET search_path = pg_catalog, pg_temp AS $function$" + _FUNCTION_BODY + "$function$"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_execution_customer_price_guard_v1() FROM PUBLIC"
    )
    for table, _label in _TABLES:
        op.execute(
            "CREATE TRIGGER execution_customer_price BEFORE INSERT OR UPDATE "
            f"ON public.{table} FOR EACH ROW "
            "EXECUTE FUNCTION public.saas_execution_customer_price_guard_v1()"
        )
    op.execute(
        "CREATE TRIGGER execution_customer_price BEFORE INSERT ON public.saas_usage_events "
        "FOR EACH ROW EXECUTE FUNCTION public.saas_execution_customer_price_guard_v1()"
    )
    op.execute(
        "GRANT SELECT (customer_pricing_frozen,customer_pricing_snapshot_id) "
        "ON public.saas_runs TO saas_metering"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table, _label in _TABLES:
            op.execute(f"LOCK TABLE public.{table} IN ACCESS EXCLUSIVE MODE")
    for table, _label in _TABLES:
        if op.get_bind().scalar(
            sa.text(f"SELECT EXISTS(SELECT 1 FROM {table} WHERE customer_pricing_frozen)")
        ):
            raise RuntimeError("cannot remove retained execution customer pricing")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER execution_customer_price ON public.saas_usage_events")
        for table, _label in _TABLES:
            op.execute(f"DROP TRIGGER execution_customer_price ON public.{table}")
        op.execute("DROP FUNCTION public.saas_execution_customer_price_guard_v1()")
        for table in _READS:
            op.execute(f"DROP POLICY rls_customer_price_owner_read ON public.{table}")
    for table, label in reversed(_TABLES):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(f"ck_{label}_customer_pricing", type_="check")
            batch.drop_constraint(f"fk_{label}_customer_pricing", type_="foreignkey")
            batch.drop_column("customer_pricing_snapshot_id")
            batch.drop_column("customer_pricing_frozen")
