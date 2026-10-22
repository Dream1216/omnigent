"""Exact P18 policy inverse under the existing fenced recovery composition."""

from __future__ import annotations

import psycopg
from psycopg import sql

from saas.control_plane.migrations.versions import (
    p0s000000018_runtime_maintenance_owner as contract,
)
from saas.production import postgresql_preserving_adapter as db
from saas.production import postgresql_preserving_native as native
from saas.production.postgresql_restore import _R_MODEL_HASH_TABLES


def policy_snapshot(connection) -> list[dict]:
    result = []
    for table, name, command in contract.POLICIES:
        row = db.one(
            connection,
            "SELECT p.oid::bigint,p.polrelid::bigint,p.polname,p.polcmd::text,"
            "p.polpermissive,p.polroles::text,p.polqual::text,p.polwithcheck::text,"
            "pg_get_expr(p.polqual,p.polrelid) AS using_expression,"
            "pg_get_expr(p.polwithcheck,p.polrelid) AS check_expression,"
            "c.relowner::bigint,pg_get_userbyid(c.relowner) AS owner,"
            "c.relrowsecurity,c.relforcerowsecurity FROM pg_catalog.pg_policy p "
            "JOIN pg_catalog.pg_class c ON c.oid=p.polrelid "
            "WHERE p.polrelid=to_regclass(%s) AND p.polname=%s",
            ("public." + table, name),
        )
        db.need(
            row["polcmd"] == ("w" if command == "UPDATE" else "r")
            and row["polpermissive"] is True
            and row["polroles"] == "{0}"
            and row["relrowsecurity"] is True
            and row["relforcerowsecurity"] is True,
            "p18_policy_contract_drift",
        )
        result.append({"table": table, **row})
    return result


INVERSE_RETAINED_TABLES = (
    "saas_execution_sessions",
    "saas_runs",
    *_R_MODEL_HASH_TABLES,
    "saas_model_provider_budget_reservations",
)
INVERSE_RETAINED_AUDIT_TYPES = (
    "model_gateway.evidence_retained",
    "platform.model_publication.disabled",
    "platform.model_publication.revocation_requested",
)


def require_source_inverse_possible(owner, *, maintenance, expected_identity: dict) -> dict:
    """Conservatively reject every retained lm1/lm2 guard before ANY mutation.

    The independent existing maintenance reader must actually have unfiltered
    access with row_security=on. No grant, role switch, FORCE change or fallback
    to an owner's possibly partial zero-row view is permitted.
    """
    db.require_idle(owner)
    db.require_idle(maintenance)
    try:
        db.need(native.head(owner) == "p0s000000018", "p18_inverse_head_required")
        db.need(
            db.database_identity(owner, maintenance) == expected_identity,
            "actual_database_identity_mismatch",
        )
        with maintenance.transaction():
            maintenance.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            maintenance.execute("SET LOCAL row_security=on")
            maintenance.execute("SET LOCAL search_path=pg_catalog,pg_temp")
            maintenance.execute("SET LOCAL statement_timeout='60s'")
            reader = db.one(
                maintenance, "SELECT current_user AS login,session_user AS session_login"
            )
            db.need(
                reader["login"] == reader["session_login"] != owner.info.user,
                "independent_existing_full_reader_required",
            )
            tables = (*INVERSE_RETAINED_TABLES, "saas_platform_audit_events")
            for table in tables:
                coverage = db.one(
                    maintenance,
                    "SELECT c.relkind::text,has_table_privilege(current_user,c.oid,'SELECT') "
                    "AS can_select,pg_catalog.row_security_active(c.oid) AS rls_active "
                    "FROM pg_catalog.pg_class c WHERE c.oid=to_regclass(%s)",
                    ("public." + table,),
                )
                db.need(
                    coverage["relkind"] == "r"
                    and coverage["can_select"] is True
                    and coverage["rls_active"] is False,
                    "existing_maintenance_full_visibility_required",
                )
            for table in INVERSE_RETAINED_TABLES:
                exists = maintenance.execute(
                    sql.SQL("SELECT EXISTS(SELECT 1 FROM public.{})").format(sql.Identifier(table))
                ).fetchone()[0]
                db.need(
                    exists is False, "retained_runtime_facts_require_original_database_restore"
                )
            audit = maintenance.execute(
                "SELECT EXISTS(SELECT 1 FROM public.saas_platform_audit_events "
                "WHERE event_type=ANY(%s))",
                (list(INVERSE_RETAINED_AUDIT_TYPES),),
            ).fetchone()[0]
            db.need(audit is False, "retained_model_audit_requires_original_database_restore")
            result = {
                "reader": reader["login"],
                "database_identity": expected_identity,
                "row_security": "on",
                "all_relations_unfiltered": True,
                "empty_retained_relations": list(INVERSE_RETAINED_TABLES),
                "absent_retained_audit_types": list(INVERSE_RETAINED_AUDIT_TYPES),
            }
        db.require_idle(owner)
        db.require_idle(maintenance)
        return result
    except psycopg.Error:
        raise db.Refused("source_inverse_full_reader_unavailable") from None


def remove_p18_policies(connection, expected: list[dict]) -> None:
    """Fixed inverse and head CAS in one transaction; no caller SQL or empty stamp."""
    db.require_idle(connection)
    with connection.transaction():
        connection.execute("SET LOCAL row_security=on")
        connection.execute("SET LOCAL search_path=pg_catalog,pg_temp")
        connection.execute("SET LOCAL lock_timeout='5s'")
        connection.execute("SET LOCAL statement_timeout='60s'")
        connection.execute("LOCK TABLE public.saas_alembic_version IN ACCESS EXCLUSIVE MODE")
        db.need(native.head(connection) == contract.revision, "p18_inverse_head_required")
        for table in dict.fromkeys(row[0] for row in contract.POLICIES):
            connection.execute(
                sql.SQL("LOCK TABLE public.{} IN SHARE ROW EXCLUSIVE MODE").format(
                    sql.Identifier(table)
                )
            )
        db.need(policy_snapshot(connection) == expected, "p18_policy_CAS_failed")
        owner = connection.execute("SELECT current_user,session_user").fetchone()
        db.need(
            owner[0] == owner[1] and all(row["owner"] == owner[0] for row in expected),
            "p18_direct_owner_required",
        )
        for table, name, _command in reversed(contract.POLICIES):
            connection.execute(
                sql.SQL("DROP POLICY {} ON public.{}").format(
                    sql.Identifier(name), sql.Identifier(table)
                )
            )
        changed = connection.execute(
            "UPDATE public.saas_alembic_version SET version_num=%s "
            "WHERE version_num=%s RETURNING version_num",
            (contract.down_revision, contract.revision),
        ).fetchall()
        db.need(changed == [(contract.down_revision,)], "p18_inverse_head_CAS_failed")
