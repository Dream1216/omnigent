"""PostgreSQL read/COPY and narrowly scoped SET SCHEMA adapters.

The caller supplies dedicated connections under its existing backup, fence, and
maintenance authority. This module never opens connections or grants privileges.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus

TABLES = (
    "saas_usage_reconciliation_ingress",
    "saas_platform_audit_journal_deliveries",
    "saas_revocation_replica_applied",
)
PREFIX = "saas_delivery_archive_"


class Refused(RuntimeError):
    """A code only; never include driver exceptions, DSN, parameters or row values."""


def need(value: bool, code: str) -> None:
    if not value:
        raise Refused(code)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def rows(connection, statement, parameters=()) -> list[dict]:
    with connection.cursor() as cursor:
        cursor.execute(statement, parameters)
        names = [column.name for column in cursor.description]
        return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def one(connection, statement, parameters=()) -> dict:
    result = rows(connection, statement, parameters)
    need(len(result) == 1, "expected_exactly_one_catalog_row")
    return result[0]


def require_idle(connection) -> None:
    need(
        connection.info.transaction_status == TransactionStatus.IDLE,
        "dedicated_idle_connection_required",
    )


def archive_name(operation_id: str) -> str:
    value = UUID(operation_id)
    need(str(value) == operation_id, "noncanonical_operation_uuid")
    return PREFIX + value.hex


def database_identity(connection, identity_connection=None) -> dict:
    """Use an existing identity reader without granting the schema owner rights.

    Composition pins the real direct endpoint/TLS. If its actual table-owner role
    cannot read pg_control_system, a separate existing maintenance read connection
    may supply it; actual DB/process/address facts must agree. Never fake the ID.
    """
    reader = connection if identity_connection is None else identity_connection
    if reader is not connection:
        statement = """
            SELECT d.datname,d.oid::bigint,pg_postmaster_start_time()::text,
                   inet_server_addr()::text,inet_server_port()
            FROM pg_catalog.pg_database d WHERE d.datname=current_database()
        """
        need(
            one(connection, statement) == one(reader, statement),
            "identity_reader_endpoint_mismatch",
        )
    return one(
        reader,
        """
        SELECT (pg_catalog.pg_control_system()).system_identifier::text AS system_identifier,
               d.datname AS database_name, d.oid::bigint AS database_oid,
               pg_catalog.pg_get_userbyid(d.datdba) AS database_owner,
               current_setting('server_version_num')::int/10000 AS server_major
          FROM pg_catalog.pg_database d WHERE d.datname=current_database()
    """,
    )


def archive_catalog(connection) -> dict:
    """Complete namespace inventory, including unexpected objects; no deletion."""
    return {
        "namespace_dependents": rows(
            connection,
            """
            SELECT d.classid::bigint,d.objid::bigint,d.objsubid,d.refobjid::bigint,d.deptype::text
            FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_namespace n ON n.oid=d.refobjid
            WHERE d.refclassid='pg_catalog.pg_namespace'::regclass AND starts_with(n.nspname,%s)
            ORDER BY d.classid,d.objid,d.objsubid,d.refobjid,d.deptype
        """,
            (PREFIX,),
        ),
        "schemas": rows(
            connection,
            """
            SELECT oid::bigint,nspname,nspowner::bigint,nspacl::text
            FROM pg_catalog.pg_namespace WHERE starts_with(nspname,%s) ORDER BY oid
        """,
            (PREFIX,),
        ),
        "relations": rows(
            connection,
            """
            SELECT c.oid::bigint,c.relname,c.relkind::text,c.relowner::bigint,c.relnamespace::bigint
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE starts_with(n.nspname,%s) ORDER BY c.oid
        """,  # noqa: E501
            (PREFIX,),
        ),
        "types": rows(
            connection,
            """
            SELECT t.oid::bigint,t.typname,t.typowner::bigint,t.typnamespace::bigint
            FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
            WHERE starts_with(n.nspname,%s) ORDER BY t.oid
        """,
            (PREFIX,),
        ),
        "functions": rows(
            connection,
            """
            SELECT p.oid::bigint,p.proname,p.proowner::bigint,p.pronamespace::bigint,
              pg_get_function_identity_arguments(p.oid) AS arguments
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            WHERE starts_with(n.nspname,%s) ORDER BY p.oid
        """,
            (PREFIX,),
        ),
    }


# Object identity is represented by actual OIDs/attnums, not a SQL-text namespace
# substitution. Deparsed definitions are preserved separately as raw evidence.
TABLE_CATALOG = {
    "relation": """
        SELECT c.oid::bigint AS oid, c.reltype::bigint AS row_type_oid,
          c.relowner::bigint AS owner_oid, pg_get_userbyid(c.relowner) AS owner,
          c.relkind::text, c.relpersistence::text, c.relrowsecurity, c.relforcerowsecurity,
          c.relreplident::text, c.reloptions, c.relam::bigint, c.reltablespace::bigint,
          c.relacl::text, c.reltoastrelid::bigint, c.relispopulated
        FROM pg_catalog.pg_class c WHERE c.oid=%s
    """,
    "columns": """
        SELECT a.attnum, a.attname, a.atttypid::bigint, a.atttypmod,
          a.attcollation::bigint, a.attnotnull, a.attndims, a.attidentity::text,
          a.attgenerated::text, a.attstorage::text, a.attcompression::text,
          a.attstattarget, a.attacl::text, a.attoptions, a.attfdwoptions,
          a.attisdropped, to_jsonb(a) AS all_attribute_fields,
          d.oid::bigint AS default_oid, d.adbin::text AS default_expression_tree
        FROM pg_catalog.pg_attribute a
        LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE a.attrelid=%s AND a.attnum>0 ORDER BY a.attnum
    """,
    "constraints": """
        SELECT o.oid::bigint, o.conname, o.contype::text, o.condeferrable,
          o.condeferred, o.convalidated, o.conrelid::bigint, o.contypid::bigint,
          o.conindid::bigint, o.conparentid::bigint, o.confrelid::bigint,
          o.confupdtype::text, o.confdeltype::text, o.confmatchtype::text,
          o.conislocal, o.coninhcount, o.connoinherit, o.conkey, o.confkey,
          o.conpfeqop::text, o.conppeqop::text, o.conffeqop::text,
          o.conbin::text AS expression_tree,
          to_jsonb(o)-'connamespace' AS all_fields_except_owned_namespace
        FROM pg_catalog.pg_constraint o WHERE o.conrelid=%s ORDER BY o.oid
    """,
    "indexes": """
        SELECT i.indexrelid::bigint, i.indrelid::bigint, i.indnatts, i.indnkeyatts,
          i.indisunique, i.indnullsnotdistinct, i.indisprimary, i.indisexclusion,
          i.indimmediate, i.indisclustered, i.indisvalid, i.indcheckxmin,
          i.indisready, i.indislive, i.indisreplident, i.indkey::text,
          i.indcollation::text, i.indclass::text, i.indoption::text,
          i.indexprs::text, i.indpred::text, c.relowner::bigint,
          c.relam::bigint, c.reltablespace::bigint, c.reloptions, c.relname,
          to_jsonb(i) AS all_index_fields
        FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
        WHERE i.indrelid=%s ORDER BY i.indexrelid
    """,
    "triggers": """
        SELECT t.oid::bigint, t.tgname, t.tgfoid::bigint, t.tgtype,
          t.tgenabled::text, t.tgisinternal, t.tgconstrrelid::bigint,
          t.tgconstrindid::bigint, t.tgconstraint::bigint, t.tgdeferrable,
          t.tginitdeferred, t.tgnargs, t.tgattr::text,
          encode(t.tgargs,'hex') AS argument_bytes_hex, t.tgqual::text,
          t.tgoldtable, t.tgnewtable, to_jsonb(t) AS all_trigger_fields
        FROM pg_catalog.pg_trigger t WHERE t.tgrelid=%s ORDER BY t.oid
    """,
    "policies": """
        SELECT p.oid::bigint, p.polname, p.polcmd::text, p.polpermissive,
          p.polroles::text, p.polqual::text, p.polwithcheck::text
        FROM pg_catalog.pg_policy p WHERE p.polrelid=%s ORDER BY p.oid
    """,
    "incoming_foreign_keys": """
        SELECT c.oid::bigint, c.conrelid::bigint, c.confrelid::bigint,
          c.conname, c.conkey, c.confkey, c.confupdtype::text, c.confdeltype::text
        FROM pg_catalog.pg_constraint c WHERE c.confrelid=%s ORDER BY c.oid
    """,
}


def table_facts(
    connection, schema: str, name: str, columns: tuple[str, ...], *, max_copy_bytes: int
) -> dict:
    relation = one(
        connection,
        """
        SELECT c.oid::bigint, n.nspname AS schema_name, c.relname
          FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname=%s AND c.relname=%s AND c.relkind='r'
    """,
        (schema, name),
    )
    oid = relation["oid"]
    metadata = {
        key: rows(connection, statement, (oid,)) for key, statement in TABLE_CATALOG.items()
    }
    actual_columns = tuple(
        row["attname"] for row in metadata["columns"] if not row["attisdropped"]
    )
    need(actual_columns == columns, "source_column_order_drift")
    need(
        not any(row["attisdropped"] for row in metadata["columns"]),
        "unexpected_dropped_source_column",
    )
    metadata["row_types"] = rows(
        connection,
        """
        SELECT t.oid::bigint,t.typname,to_jsonb(t)-'typnamespace' AS all_fields_except_owned_namespace
        FROM pg_catalog.pg_type t JOIN pg_catalog.pg_class c ON c.oid=%s
        WHERE t.oid=c.reltype OR t.typelem=c.reltype ORDER BY t.oid
    """,  # noqa: E501
        (oid,),
    )
    pk = one(
        connection,
        """
        SELECT array_agg(a.attname ORDER BY k.position) AS columns
        FROM pg_catalog.pg_constraint c
        JOIN LATERAL unnest(c.conkey) WITH ORDINALITY k(attnum,position) ON true
        JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
        WHERE c.conrelid=%s AND c.contype='p' GROUP BY c.oid
    """,
        (oid,),
    )["columns"]
    need(bool(pk), "source_primary_key_missing")
    # This is a full actual COPY read, no retained plaintext file and no remote I/O.
    copy_sql = sql.SQL("COPY (SELECT {} FROM {}.{} ORDER BY {}) TO STDOUT (FORMAT binary)").format(
        sql.SQL(",").join(map(sql.Identifier, columns)),
        sql.Identifier(schema),
        sql.Identifier(name),
        sql.SQL(",").join(map(sql.Identifier, pk)),
    )
    content_hash, byte_count = hashlib.sha256(), 0
    with connection.cursor() as cursor:  # noqa: SIM117
        with cursor.copy(copy_sql) as stream:
            for block in stream:
                byte_count += len(block)
                need(byte_count <= max_copy_bytes, "copy_read_budget_exceeded")
                content_hash.update(block)
    count = one(
        connection,
        sql.SQL("SELECT count(*)::bigint AS rows FROM {}.{}").format(
            sql.Identifier(schema), sql.Identifier(name)
        ),
    )
    return {
        "schema": schema,
        "name": name,
        "oid": oid,
        "metadata": metadata,
        "metadata_sha256": sha(canonical(metadata)),
        "copy_sha256": content_hash.hexdigest(),
        "copy_bytes": byte_count,
        "row_count": count["rows"],
        "primary_key": pk,
    }


def capture(
    connection,
    *,
    expected_identity: dict,
    expected_principal: str,
    schema: str,
    columns: dict[str, tuple[str, ...]],
    max_copy_bytes: int,
    identity_connection=None,
) -> dict:
    """Actual read-only same-snapshot data/catalog capture under existing DB ACL.

    Root's reviewed composition must have already verified complete source policy
    gold for this actual reader. ON is explicit: no bypass grant/disabled FORCE RLS.
    No claim of all-row coverage is made just because this function returns hashes.
    """
    require_idle(connection)
    need(set(columns) == set(TABLES), "exact_receipt_table_inventory_required")
    need(type(max_copy_bytes) is int and max_copy_bytes > 0, "invalid_copy_budget")
    try:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            connection.execute("SET LOCAL row_security=on")
            connection.execute("SET LOCAL search_path=pg_catalog,pg_temp")
            connection.execute("SET LOCAL statement_timeout='60s'")
            principal = one(
                connection,
                """
                SELECT current_user AS login, session_user AS session_login,
                  r.rolsuper,r.rolbypassrls,r.rolcreatedb,r.rolcreaterole,r.rolreplication
                FROM pg_catalog.pg_roles r WHERE r.rolname=current_user
            """,
            )
            need(principal["login"] == expected_principal, "actual_principal_mismatch")
            identity = database_identity(connection, identity_connection)
            need(identity == expected_identity, "actual_database_identity_mismatch")
            need(identity["server_major"] in (16, 18), "unqualified_server_major")
            archives = rows(
                connection,
                """
                SELECT oid::bigint,nspname,pg_get_userbyid(nspowner) AS owner,nspacl::text
                FROM pg_catalog.pg_namespace WHERE starts_with(nspname,%s) ORDER BY nspname
            """,
                (PREFIX,),
            )
            facts = {
                name: table_facts(
                    connection, schema, name, columns[name], max_copy_bytes=max_copy_bytes
                )
                for name in TABLES
            }
            result = {
                "identity": identity,
                "principal": principal,
                "archive_schemas": archives,
                "tables": facts,
                "archive_catalog": archive_catalog(connection),
                "snapshot_isolation": "repeatable read/read only",
                "row_security": "on",
                "full_source_policy_gold_and_backup_validation_is_external": True,
            }
        need(connection.info.transaction_status == TransactionStatus.IDLE, "snapshot_not_released")
        return result
    except Refused:
        raise
    except Exception:  # noqa: BLE001
        raise Refused("postgres_capture_failed_no_driver_details") from None


@dataclass(frozen=True)
class MoveScope:
    operation_id: str
    direction: str
    expected_identity: dict
    expected_owner_principal: str
    expected_before_tables: dict
    columns: dict[str, tuple[str, ...]]
    max_copy_bytes: int
    expected_archive_catalog: dict | None


def require_archive_acl(connection, archive: str, database_owner: str, table_owner: str) -> None:
    """Fixed scope, never learned from a just-created schema/default ACL."""
    actual = rows(
        connection,
        """
        SELECT pg_get_userbyid(n.nspowner) AS schema_owner,
               CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
               pg_get_userbyid(a.grantor) AS grantor,a.privilege_type,a.is_grantable
        FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL
             aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
        WHERE n.nspname=%s ORDER BY 1,2,3,4,5
    """,
        (archive,),
    )
    allowed = sorted(
        {
            (database_owner, role, database_owner, privilege, False)
            for role in (database_owner, table_owner)
            for privilege in ("CREATE", "USAGE")
        }
    )
    need([tuple(row.values()) for row in actual] == allowed, "unexpected_archive_namespace_acl")


def prepare_archive(
    database_owner_connection,
    *,
    operation_id: str,
    expected_identity: dict,
    expected_table_owner: str,
    identity_connection=None,
) -> dict:
    """Existing DB-owner authority creates one exact private target namespace.

    No database CREATE or role/BYPASS grant is given to the table owner. Only this
    new archive's USAGE/CREATE is granted, allowing its own tables to move there.
    This is not a backup/fence authorization or a completed downgrade.
    """
    require_idle(database_owner_connection)
    archive = archive_name(operation_id)
    try:
        with database_owner_connection.transaction():
            database_owner_connection.execute("SET LOCAL search_path=pg_catalog,pg_temp")
            identity = database_identity(database_owner_connection, identity_connection)
            need(identity == expected_identity, "actual_database_identity_mismatch")
            actual = one(database_owner_connection, "SELECT current_user AS login")["login"]
            need(actual == identity["database_owner"], "exact_database_owner_required")
            owner = one(
                database_owner_connection,
                """
                SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication
                FROM pg_catalog.pg_roles WHERE rolname=%s
            """,
                (expected_table_owner,),
            )
            need(not any(owner.values()), "unsafe_target_table_owner")
            need(
                archive_catalog(database_owner_connection)["schemas"] == [],
                "unknown_or_existing_archive",
            )
            database_owner_connection.execute(
                sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(archive))
            )
            database_owner_connection.execute(
                sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(archive))
            )
            database_owner_connection.execute(
                sql.SQL("GRANT USAGE,CREATE ON SCHEMA {} TO {}").format(
                    sql.Identifier(archive), sql.Identifier(expected_table_owner)
                )
            )
            require_archive_acl(database_owner_connection, archive, actual, expected_table_owner)
            result = archive_catalog(database_owner_connection)
        return result  # noqa: RET504
    except Refused:
        raise
    except Exception:  # noqa: BLE001
        raise Refused("postgres_private_archive_prepare_failed_no_driver_details") from None


def move_receipts(
    connection: psycopg.Connection, scope: MoveScope, *, identity_connection=None
) -> dict:
    """Narrow metadata transaction for root review, NOT a P17 downgrade/upgrade.

    Root's existing maintenance composition owns actual fence and complete backup
    verification before invocation. DB ACLs enforce the real direct owner. This
    phase performs only SET SCHEMA into the database-owner-prepared archive; no
    DROP, role changes, function changes, data writes, version stamp or SQL file.
    Full P17 inverse/P16/nf work and old source verifier remain separate mandatory
    reviewed phases. A partial result is never a completed rollback receipt.
    """
    require_idle(connection)
    need(scope.direction in ("detach", "reattach"), "unknown_move_direction")
    need(set(scope.columns) == set(TABLES), "exact_receipt_table_inventory_required")
    archive = archive_name(scope.operation_id)
    source, target = ("public", archive) if scope.direction == "detach" else (archive, "public")
    try:
        with connection.transaction():
            connection.execute("SET LOCAL search_path=pg_catalog,pg_temp")
            connection.execute("SET LOCAL row_security=on")
            connection.execute("SET LOCAL lock_timeout='5s'")
            connection.execute("SET LOCAL statement_timeout='60s'")
            need(
                database_identity(connection, identity_connection) == scope.expected_identity,
                "actual_database_identity_mismatch",
            )
            actual = one(connection, "SELECT current_user AS login")["login"]
            need(actual == scope.expected_owner_principal, "actual_owner_principal_mismatch")
            require_archive_acl(
                connection, archive, scope.expected_identity["database_owner"], actual
            )
            # All three locks in fixed name order. Scope snapshot is re-read only
            # after acquiring them, closing the prepare->execute data-change race.
            for name in sorted(TABLES):
                connection.execute(
                    sql.SQL("LOCK TABLE {}.{} IN ACCESS EXCLUSIVE MODE").format(
                        sql.Identifier(source), sql.Identifier(name)
                    )
                )
            before = {
                name: table_facts(
                    connection,
                    source,
                    name,
                    scope.columns[name],
                    max_copy_bytes=scope.max_copy_bytes,
                )
                for name in TABLES
            }
            need(before == scope.expected_before_tables, "metadata_move_CAS_failed")
            need(
                all(row["metadata"]["relation"][0]["owner"] == actual for row in before.values()),
                "exact_direct_table_owner_required",
            )
            archives = rows(
                connection,
                "SELECT nspname FROM pg_catalog.pg_namespace WHERE starts_with(nspname,%s)",
                (PREFIX,),
            )
            need(archives == [{"nspname": archive}], "unknown_partial_or_multiple_archive")
            expected_archive_catalog = scope.expected_archive_catalog
            if (
                expected_archive_catalog is None
                or archive_catalog(connection) != expected_archive_catalog
            ):
                raise Refused("archive_inventory_CAS_failed")
            if scope.direction == "detach":
                need(
                    all(
                        expected_archive_catalog[key] == []
                        for key in ("namespace_dependents", "relations", "types", "functions")
                    ),
                    "archive_target_not_empty",
                )
            else:
                occupied = one(
                    connection,
                    """
                    SELECT count(*)::int AS count FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname='public' AND c.relname=ANY(%s)
                """,
                    (list(TABLES),),
                )["count"]
                need(occupied == 0, "public_receipt_name_collision")
            for name in TABLES:
                connection.execute(
                    sql.SQL("ALTER TABLE {}.{} SET SCHEMA {}").format(
                        sql.Identifier(source), sql.Identifier(name), sql.Identifier(target)
                    )
                )
            after = {
                name: table_facts(
                    connection,
                    target,
                    name,
                    scope.columns[name],
                    max_copy_bytes=scope.max_copy_bytes,
                )
                for name in TABLES
            }
            for name in TABLES:
                need(
                    {k: v for k, v in before[name].items() if k != "schema"}
                    == {k: v for k, v in after[name].items() if k != "schema"},
                    "metadata_move_changed_data_oid_or_definition",
                )
            result = {
                "phase": "receipt-metadata-move-only",
                "operation_id": scope.operation_id,
                "direction": scope.direction,
                "before_sha256": sha(canonical(before)),
                "after_sha256": sha(canonical(after)),
                "rollback_complete": False,
                "source_verifier_or_signed_stack_recovery_claimed": False,
            }
        return result  # noqa: RET504
    except Refused:
        raise
    except Exception:  # noqa: BLE001
        raise Refused("postgres_metadata_move_failed_no_driver_details") from None
