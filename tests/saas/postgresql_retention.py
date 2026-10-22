"""Assert a refused migration preserves retained rows and database authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config


def _snapshot(connection: sa.Connection) -> str:
    tables = connection.exec_driver_sql(
        "SELECT relname,relowner,relacl::text,relrowsecurity,relforcerowsecurity "
        "FROM pg_class WHERE relnamespace='public'::regnamespace "
        "AND relkind IN ('r','p') ORDER BY relname"
    ).all()
    quote = connection.dialect.identifier_preparer.quote
    rows = [
        (
            table[0],
            connection.exec_driver_sql(
                "SELECT md5(COALESCE(jsonb_agg(to_jsonb(retained_row) "
                "ORDER BY to_jsonb(retained_row))::text,'[]')) "
                f"FROM public.{quote(table[0])} retained_row"
            ).scalar_one(),
        )
        for table in tables
    ]
    catalogs = [
        connection.exec_driver_sql(query).all()
        for query in (
            "SELECT nspname,nspowner,nspacl::text FROM pg_namespace "
            "WHERE nspname='public' ORDER BY nspname",
            "SELECT attrelid::regclass::text,attnum,attname,atttypid::regtype::text,"
            "attnotnull,attacl::text,attisdropped,attidentity,attgenerated,"
            "pg_get_expr(adbin,adrelid) FROM pg_attribute "
            "JOIN pg_class ON pg_class.oid=attrelid "
            "LEFT JOIN pg_attrdef ON adrelid=attrelid AND adnum=attnum "
            "WHERE relnamespace='public'::regnamespace AND relkind IN ('r','p') "
            "AND attnum>0 ORDER BY attrelid::regclass::text,attnum",
            "SELECT relname,relowner,relacl::text FROM pg_class "
            "WHERE relnamespace='public'::regnamespace AND relkind='S' ORDER BY relname",
            "SELECT granted.rolname,member.rolname,grantor.rolname,"
            "membership.admin_option,membership.inherit_option,membership.set_option "
            "FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=roleid "
            "JOIN pg_roles member ON member.oid=membership.member "
            "JOIN pg_roles grantor ON grantor.oid=membership.grantor ORDER BY 1,2,3",
            "SELECT tablename,policyname,roles::text,cmd,qual,with_check FROM pg_policies "
            "WHERE schemaname='public' ORDER BY tablename,policyname",
            "SELECT oid::regprocedure::text,proowner,proacl::text,pg_get_functiondef(oid) "
            "FROM pg_proc WHERE pronamespace='public'::regnamespace AND prokind='f' "
            "ORDER BY oid::regprocedure::text",
            "SELECT conrelid::regclass::text,conname,pg_get_constraintdef(oid) "
            "FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY 1,2",
            "SELECT tgrelid::regclass::text,tgname,pg_get_triggerdef(oid),tgenabled "
            "FROM pg_trigger WHERE NOT tgisinternal "
            "AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace) "
            "ORDER BY 1,2",
        )
    ]
    payload = [[tuple(row) for row in tables], rows]
    payload.extend([[tuple(row) for row in catalog] for catalog in catalogs])
    return hashlib.sha256(json.dumps(payload, default=str).encode()).hexdigest()


def assert_retained_downgrade_refused(
    engine: sa.Engine, target: str, *, expected_pattern: str
) -> None:
    """Keep the new earlier budget guard and the original feature guard strict."""
    with engine.begin() as connection:
        before = _snapshot(connection)
        owner_policy = connection.scalar(
            sa.text(
                "SELECT EXISTS(SELECT 1 FROM pg_policy WHERE "
                "polrelid=to_regclass('public.saas_model_provider_budget_reservations') "
                "AND polname='rls_model_budget_owner_settlement')"
            )
        )
        if owner_policy and connection.scalar(
            sa.text("SELECT EXISTS(SELECT 1 FROM public.saas_model_provider_budget_reservations)")
        ):
            expected_pattern = r"^retained model budgets require owner settlement policy$"
        config = Config(Path(__file__).resolve().parents[2] / "saas/control_plane/alembic.ini")
        config.attributes["connection"] = connection
        with pytest.raises(RuntimeError, match=expected_pattern), connection.begin_nested():
            command.downgrade(config, target)
        assert _snapshot(connection) == before
