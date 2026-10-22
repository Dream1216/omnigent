"""Exact P18 policy inverse under the existing fenced recovery composition."""

from __future__ import annotations

import hashlib

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
    with connection.transaction(force_rollback=True):
        connection.execute("SET LOCAL search_path=pg_catalog,pg_temp")
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


def capture_t_preserved_facts(
    owner,
    *,
    maintenance,
    expected_identity: dict,
    expected_tables: tuple[str, ...],
    max_copy_bytes: int,
    expected_head: str,
    receipt_schema: str = "public",
) -> dict:
    """Full bounded COPY under the existing independent maintenance authority.

    Table names come only from the source-verified inventory in prepare. All
    ordinary tables except the two intentional version rows are retained. This
    does not authorize a pair or establish consumer ACKs; the live coordinator
    must independently prove both before each phase while keeping its fence.
    """
    db.need(expected_head in {"p0s000000018", "lm2t00000001"}, "t_fact_head_invalid")
    db.need(
        expected_tables == tuple(sorted(set(expected_tables)))
        and set(db.TABLES) <= set(expected_tables)
        and not {"alembic_version", "saas_alembic_version"} & set(expected_tables),
        "t_fact_inventory_invalid",
    )
    db.need(type(max_copy_bytes) is int and max_copy_bytes > 0, "copy_bound_required")
    db.require_idle(owner)
    db.require_idle(maintenance)
    try:
        db.need(native.head(owner) == expected_head, "t_fact_head_changed")
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
                maintenance,
                "SELECT current_user AS login,session_user AS session_login,"
                "(r.rolsuper OR pg_has_role(current_user,'pg_read_all_stats','USAGE')) "
                "AS all_activity_visible FROM pg_catalog.pg_roles r WHERE r.rolname=current_user",
            )
            db.need(
                reader["login"] == reader["session_login"] != owner.info.user
                and reader["all_activity_visible"] is True,
                "independent_existing_full_reader_required",
            )
            db.need(
                maintenance.execute(
                    "SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_prepared_xacts "
                    "WHERE database=current_database()) AND NOT EXISTS("
                    "SELECT 1 FROM pg_catalog.pg_stat_activity WHERE datname=current_database() "
                    "AND pid<>pg_backend_pid() AND xact_start IS NOT NULL)"
                ).fetchone()[0]
                is True,
                "t_recovery_has_inflight_or_prepared_transactions",
            )
            db.need(
                maintenance.execute(
                    "SELECT NOT EXISTS(SELECT 1 FROM public.saas_runs WHERE "
                    "terminal_at IS NULL OR lease_expires_at>clock_timestamp()) "
                    "AND NOT EXISTS(SELECT 1 FROM public.saas_worktree_instances WHERE "
                    "lease_expires_at>clock_timestamp() OR status IN "
                    "('reserved','materializing','ready','checkpointing')) "
                    "AND NOT EXISTS(SELECT 1 FROM public.saas_capability_tokens WHERE "
                    "revoked_at IS NULL AND expires_at>clock_timestamp()) "
                    "AND NOT EXISTS(SELECT 1 FROM public.saas_runner_registrations "
                    "WHERE active_leases>0)"
                ).fetchone()[0]
                is True,
                "t_execution_not_drained",
            )
            actual = db.rows(
                maintenance,
                "SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') "
                "AND c.relname NOT IN ('alembic_version','saas_alembic_version') "
                "ORDER BY c.relname",
            )
            public_expected = set(expected_tables)
            if receipt_schema != "public":
                public_expected -= set(db.TABLES)
            db.need(
                [r["relname"] for r in actual] == sorted(public_expected),
                "t_complete_table_inventory_changed",
            )
            facts, total = {}, 0
            for table in expected_tables:
                schema = receipt_schema if table in db.TABLES else "public"
                relation = db.one(
                    maintenance,
                    "SELECT c.oid::bigint,c.relkind::text,"
                    "has_table_privilege(current_user,c.oid,'SELECT') AS can_select,"
                    "pg_catalog.row_security_active(c.oid) AS rls_active "
                    "FROM pg_catalog.pg_class c WHERE c.oid=to_regclass(%s)",
                    (schema + "." + table,),
                )
                db.need(
                    relation["relkind"] == "r"
                    and relation["can_select"] is True
                    and relation["rls_active"] is False,
                    "existing_maintenance_full_visibility_required",
                )
                columns = [
                    r["attname"]
                    for r in db.rows(
                        maintenance,
                        "SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid=%s "
                        "AND attnum>0 AND NOT attisdropped ORDER BY attnum",
                        (relation["oid"],),
                    )
                ]
                primary = db.one(
                    maintenance,
                    "SELECT array_agg(a.attname ORDER BY k.position) AS columns "
                    "FROM pg_catalog.pg_constraint c JOIN LATERAL unnest(c.conkey) "
                    "WITH ORDINALITY k(attnum,position) ON true JOIN pg_catalog.pg_attribute a "
                    "ON a.attrelid=c.conrelid AND a.attnum=k.attnum "
                    "WHERE c.conrelid=%s AND c.contype='p' GROUP BY c.oid",
                    (relation["oid"],),
                )["columns"]
                db.need(bool(columns) and bool(primary), "t_fact_primary_key_required")
                query = sql.SQL(
                    "COPY (SELECT {} FROM {}.{} ORDER BY {}) TO STDOUT (FORMAT binary)"
                ).format(
                    sql.SQL(",").join(map(sql.Identifier, columns)),
                    sql.Identifier(schema),
                    sql.Identifier(table),
                    sql.SQL(",").join(map(sql.Identifier, primary)),
                )
                digest, size = hashlib.sha256(), 0
                with maintenance.cursor() as cursor, cursor.copy(query) as stream:
                    for block in stream:
                        size += len(block)
                        total += len(block)
                        db.need(total <= max_copy_bytes, "t_total_copy_budget_exceeded")
                        digest.update(block)
                count = maintenance.execute(
                    sql.SQL("SELECT count(*) FROM {}.{}").format(
                        sql.Identifier(schema), sql.Identifier(table)
                    )
                ).fetchone()[0]
                facts[table] = {
                    "oid": relation["oid"],
                    "columns": columns,
                    "primary_key": primary,
                    "copy_sha256": digest.hexdigest(),
                    "copy_bytes": size,
                    "row_count": count,
                }
            builtin = db.one(
                maintenance,
                "SELECT p.oid::bigint,pg_get_userbyid(p.proowner) AS owner,"
                "p.proacl::text AS raw_acl FROM pg_catalog.pg_proc p "
                "WHERE p.oid=to_regprocedure('pg_catalog.pg_notify(text,text)')",
            )
            builtin["entries"] = db.rows(
                maintenance,
                "SELECT pg_get_userbyid(a.grantor) AS grantor,"
                "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END "
                "AS grantee,a.privilege_type,a.is_grantable FROM pg_catalog.pg_proc p "
                "CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a "
                "WHERE p.oid=to_regprocedure('pg_catalog.pg_notify(text,text)') "
                "ORDER BY 1,2,3,4",
            )
            return {
                "database_identity": expected_identity,
                "reader": reader["login"],
                "tables": facts,
                "builtin_pg_notify": builtin,
            }
    except psycopg.Error:
        raise db.Refused("t_preservation_full_reader_unavailable") from None
