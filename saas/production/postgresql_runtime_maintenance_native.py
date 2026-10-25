"""Exact P18 policy inverse under the existing fenced recovery composition."""

from __future__ import annotations

import hashlib
import time

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
    """Reobserve only a refused idle prerequisite in a fresh read-only snapshot.

    Five seconds bounds starting further observations; an in-flight original
    query retains its existing timeout. No COPY or mutation is ever retried.
    The original once function exits its transaction before this handler runs.
    """
    deadline = time.monotonic() + 5.0
    while True:
        try:
            return _capture_t_preserved_facts_once(
                owner,
                maintenance=maintenance,
                expected_identity=expected_identity,
                expected_tables=expected_tables,
                max_copy_bytes=max_copy_bytes,
                expected_head=expected_head,
                receipt_schema=receipt_schema,
            )
        except db.Refused as exc:
            if str(exc) != "t_recovery_has_inflight_or_prepared_transactions":
                raise
            # Never sleep with the rejected REPEATABLE READ snapshot open.
            db.require_idle(owner)
            db.require_idle(maintenance)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(0.05, remaining))
            if time.monotonic() >= deadline:
                raise


def _capture_t_preserved_facts_once(
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


def runtime_rows_snapshot(maintenance, *, expected_identity, owner, maximum):
    """Complete fixed Runtime relations, including other placements, under RLS."""
    db.require_idle(maintenance)
    db.need(
        db.database_identity(owner, maintenance) == expected_identity, "runtime_identity_changed"
    )
    db.need(type(maximum) is int and 0 < maximum <= 100000, "runtime_row_bound_required")
    tables = {
        "placements": ("saas_runtime_placements", "id"),
        "partitions": ("saas_runtime_partitions", "id"),
        "bindings": ("saas_runtime_resource_bindings", "id"),
        "aliases": ("saas_runtime_identity_aliases", "runtime_partition_id,user_id"),
    }
    result = {}
    with maintenance.transaction():
        maintenance.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        maintenance.execute("SET LOCAL row_security=on")
        maintenance.execute("SET LOCAL statement_timeout='60s'")
        maintenance.execute("SET LOCAL search_path=pg_catalog,pg_temp")
        for name, (table, ordering) in tables.items():
            visible = maintenance.execute(
                "SELECT has_table_privilege(current_user,%s,'SELECT'),"
                "pg_catalog.row_security_active(%s::regclass)",
                ("public." + table, "public." + table),
            ).fetchone()
            db.need(visible == (True, False), "runtime_full_reader_required")
            rows = maintenance.execute(
                sql.SQL("SELECT to_jsonb(r) FROM public.{} r ORDER BY {} LIMIT %s").format(
                    sql.Identifier(table),
                    sql.SQL(",").join(map(sql.Identifier, ordering.split(","))),
                ),
                (maximum + 1,),
            ).fetchall()
            db.need(len(rows) <= maximum, "runtime_complete_rows_exceed_bound")
            result[name] = [row[0] for row in rows]
    return result


def assert_runtime_transition_facts(
    before,
    after,
    *,
    expected_rows,
    actual_rows,
    maintenance,
    expected_request_hash,
    expected_payload,
    idempotency_key,
    maximum,
):
    """Only exact Runtime row projection and one proven source event may differ.

    Excluding the source-owned event here verifies the WHOLE original Outbox,
    not a sample/prefix. No rows, terminal fields, timestamps or hashes are edited.
    The stable event key/hash/payload must come from the native Runtime operation
    whose original read-only reconcile has already proved its committed scope.
    """
    db.need(actual_rows == expected_rows, "runtime_global_projection_changed")
    db.need(
        before["database_identity"] == after["database_identity"]
        and before["builtin_pg_notify"] == after["builtin_pg_notify"]
        and set(before["tables"]) == set(after["tables"]),
        "t_runtime_identity_builtin_or_inventory_changed",
    )
    runtime_tables = {
        "saas_runtime_placements",
        "saas_runtime_partitions",
        "saas_runtime_resource_bindings",
        "saas_runtime_identity_aliases",
    }
    outbox = "saas_control_plane_outbox"
    for table, original in before["tables"].items():
        current = after["tables"][table]
        if table not in runtime_tables | {outbox}:
            db.need(current == original, "t_nonruntime_fact_changed")
        else:

            def shape(row):
                return {
                    key: value
                    for key, value in row.items()
                    if key not in {"copy_sha256", "copy_bytes", "row_count"}
                }

            db.need(shape(original) == shape(current), "t_runtime_relation_shape_or_oid_changed")
            if table in runtime_tables:
                db.need(
                    current["row_count"] == original["row_count"], "t_runtime_row_count_changed"
                )
    original = before["tables"][outbox]
    db.need(
        after["tables"][outbox]["row_count"] == original["row_count"] + 1,
        "t_runtime_exactly_one_source_event_required",
    )
    db.require_idle(maintenance)
    with maintenance.transaction():
        maintenance.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        maintenance.execute("SET LOCAL row_security=on")
        maintenance.execute("SET LOCAL statement_timeout='60s'")
        maintenance.execute("SET LOCAL search_path=pg_catalog,pg_temp")
        db.need(
            maintenance.execute(
                "SELECT pg_catalog.row_security_active("
                "'public.saas_control_plane_outbox'::regclass)"
            ).fetchone()[0]
            is False,
            "runtime_outbox_full_reader_required",
        )
        events = maintenance.execute(
            "SELECT id,request_hash,payload,to_jsonb(e) FROM public.saas_control_plane_outbox e "
            "WHERE idempotency_key=%s AND aggregate_type='runtime_placement' "
            "AND event_type='runtime.placement.upgraded'",
            (idempotency_key,),
        ).fetchall()
        db.need(len(events) == 1, "runtime_source_event_missing_or_conflicting")
        event_id, request_hash, payload, document = events[0]
        db.need(
            request_hash == expected_request_hash and payload == expected_payload,
            "runtime_source_event_hash_or_payload_changed",
        )
        db.need(
            document["aggregate_key"] == expected_payload["placement_id"]
            and document["tenant_id"] is None,
            "runtime_source_event_scope_changed",
        )
        db.need(
            document["attempt_count"] == 0
            and all(
                document[name] is None
                for name in (
                    "available_at",
                    "claimed_at",
                    "claim_token",
                    "last_error",
                    "last_error_code",
                    "last_error_digest",
                    "published_at",
                    "quarantined_at",
                )
            ),
            "legacy_outbox_worker_not_fenced",
        )
        query = sql.SQL(
            "COPY (SELECT {} FROM public.saas_control_plane_outbox "
            "WHERE id<>%s ORDER BY {}) TO STDOUT (FORMAT binary)"
        ).format(
            sql.SQL(",").join(map(sql.Identifier, original["columns"])),
            sql.SQL(",").join(map(sql.Identifier, original["primary_key"])),
        )
        digest, length = hashlib.sha256(), 0
        with maintenance.cursor() as cursor, cursor.copy(query, (event_id,)) as blocks:
            for block in blocks:
                length += len(block)
                db.need(length <= maximum, "runtime_outbox_copy_exceeds_bound")
                digest.update(block)
        db.need(
            length == original["copy_bytes"] and digest.hexdigest() == original["copy_sha256"],
            "t_existing_outbox_fact_changed",
        )
    return {
        "idempotency_key": idempotency_key,
        "event": document,
        "event_sha256": db.sha(db.canonical(document)),
    }
