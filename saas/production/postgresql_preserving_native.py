"""Apply the fixed P17 source inverse and verify PostgreSQL metadata.

The recovery coordinator supplies the verified backup, write fence and operation
state. SQL and inverse ordering come from the pinned source-owned manifest.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import psycopg
from psycopg import sql

from saas.production.postgresql_preserving_adapter import TABLES, need, require_idle

MANIFEST_SHA = "bf2734f3a319b56ff41506c098d601a45741a6e59b9f2381bd4f715229d89500"


def load_manifest(path: Path):
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == MANIFEST_SHA, "preserving_load_manifest_19")
    value = json.loads(raw)
    need(
        value["revision"] == "p0s000000017" and value["down_revision"] == "p0s000000016",
        "preserving_load_manifest_21",
    )
    need(
        len(value["functions"]) == 14
        and len(value["old_table_policies_to_remove_before_N1"]) == 7
        and (len(value["old_table_triggers_to_remove_before_N1"]) == 5)
        and (len(value["old_table_indexes"]) == 1),
        "preserving_load_manifest_24",
    )
    return value


def source_inverse_sql(manifest):
    return (
        [x["inverse"] for x in manifest["old_table_triggers_to_remove_before_N1"]]
        + [x["inverse"] for x in manifest["old_table_policies_to_remove_before_N1"]]
        + [x["inverse"] for x in manifest["old_table_indexes"]]
        + [x["inverse"] for x in reversed(manifest["functions"])]
    )


def head(connection):
    return connection.execute("SELECT version_num FROM public.saas_alembic_version").fetchone()[0]


def remove_sources(connection, manifest, expected_old_snapshot, archive):
    need(
        connection.info.transaction_status == psycopg.pq.TransactionStatus.IDLE,
        "preserving_remove_sources_50",
    )
    with connection.transaction():
        connection.execute("SET LOCAL lock_timeout='2s'")
        connection.execute("SET LOCAL statement_timeout='60s'")
        need(head(connection) == "p0s000000017", "preserving_remove_sources_54")
        for table in manifest["tables"]:
            need(
                connection.execute(
                    "SELECT to_regclass(%s)", ("public." + table["name"],)
                ).fetchone()[0]
                is None,
                "preserving_remove_sources_56",
            )
            need(
                connection.execute(
                    "SELECT to_regclass(%s)", (archive + "." + table["name"],)
                ).fetchone()[0]
                is not None,
                "preserving_remove_sources_62",
            )
        connection.execute("LOCK TABLE public.saas_alembic_version IN ACCESS EXCLUSIVE MODE")
        need(
            source_snapshot(connection, manifest) == expected_old_snapshot,
            "preserving_remove_sources_71",
        )
        for statement in source_inverse_sql(manifest):
            connection.execute(statement)
        for item in manifest["functions"]:
            need(
                connection.execute(
                    "SELECT to_regprocedure(%s)", (item["inverse"].removeprefix("DROP FUNCTION "),)
                ).fetchone()[0]
                is None,
                "preserving_remove_sources_77",
            )
        changed = connection.execute(
            "UPDATE public.saas_alembic_version SET version_num='p0s000000016' WHERE version_num='p0s000000017' RETURNING version_num"  # noqa: E501
        ).fetchall()
        need(changed == [("p0s000000016",)], "preserving_remove_sources_89")


def source_snapshot(connection, manifest):
    result = {"functions": [], "policies": [], "triggers": [], "indexes": []}
    for item in manifest["functions"]:
        signature = item["inverse"].removeprefix("DROP FUNCTION ")
        row = connection.execute(
            "SELECT p.oid::bigint,pg_get_functiondef(p.oid),pg_get_userbyid(p.proowner),p.proacl::text,p.prosecdef,p.proconfig FROM pg_proc p WHERE p.oid=to_regprocedure(%s)",  # noqa: E501
            (signature,),
        ).fetchone()
        need(row is not None, "preserving_source_snapshot_100")
        result["functions"].append(
            {
                "signature": signature,
                "oid": row[0],
                "definition": row[1],
                "owner": row[2],
                "acl": row[3],
                "security_definer": row[4],
                "configuration": row[5],
            }
        )
    for item in manifest["old_table_policies_to_remove_before_N1"]:
        row = connection.execute(
            "SELECT polname,polcmd,polpermissive,polroles::text,pg_get_expr(polqual,polrelid),pg_get_expr(polwithcheck,polrelid) FROM pg_policy WHERE polrelid=to_regclass(%s) AND polname=%s",  # noqa: E501
            ("public." + item["table"], item["name"]),
        ).fetchone()
        need(row, "preserving_source_snapshot_117")
        result["policies"].append(list(row))
    for item in manifest["old_table_triggers_to_remove_before_N1"]:
        row = connection.execute(
            "SELECT tgname,pg_get_triggerdef(oid),tgenabled FROM pg_trigger WHERE tgrelid=to_regclass(%s) AND tgname=%s",  # noqa: E501
            ("public." + item["table"], item["name"]),
        ).fetchone()
        need(row, "preserving_source_snapshot_124")
        result["triggers"].append(list(row))
    for item in manifest["old_table_indexes"]:
        row = connection.execute(
            "SELECT pg_get_indexdef(indexrelid),indisvalid,indisready FROM pg_index WHERE indexrelid=to_regclass(%s)",  # noqa: E501
            ("public." + item["name"],),
        ).fetchone()
        need(row, "preserving_source_snapshot_131")
        result["indexes"].append(list(row))
    return result


def semantic_sources(snapshot):
    return {
        **snapshot,
        "functions": [{k: v for k, v in f.items() if k != "oid"} for f in snapshot["functions"]],
    }


def role_edges(connection):
    return [
        list(row)
        for row in connection.execute(
            "SELECT g.rolname,m.rolname,o.rolname,a.admin_option,a.inherit_option,a.set_option FROM pg_auth_members a JOIN pg_roles g ON g.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles o ON o.oid=a.grantor ORDER BY 1,2,3"  # noqa: E501
        ).fetchall()
    ]


def require_retained_delivery_role_dependencies(connection, receipt_tables, database_oid):
    """These retired capabilities may depend only on the original receipt objects."""
    roles = ("saas_usage_consumer", "saas_audit_delivery", "saas_revocation_consumer")
    need(set(receipt_tables) == set(TABLES), "explicit_t_receipt_dependency_scope_required")
    relation_oids = {table["oid"] for table in receipt_tables.values()}
    policy_oids = {
        policy["oid"]
        for table in receipt_tables.values()
        for policy in table["metadata"]["policies"]
    }
    require_idle(connection)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        role_ids = dict(
            connection.execute(
                "SELECT rolname,oid::bigint FROM pg_catalog.pg_roles "
                "WHERE rolname=ANY(%s) ORDER BY rolname",
                (list(roles),),
            ).fetchall()
        )
        need(set(role_ids) == set(roles), "explicit_t_retained_delivery_role_identity_missing")
        for role, table in zip(roles, TABLES, strict=True):
            policies = {
                row["polname"]: row["polroles"]
                for row in receipt_tables[table]["metadata"]["policies"]
            }
            need(
                all(
                    policies.get(f"rls_{table.removeprefix('saas_')}_delivery_consumer_{action}")
                    == "{" + str(role_ids[role]) + "}"
                    for action in ("read", "insert")
                ),
                "explicit_t_retained_delivery_role_oid_changed",
            )
        dependencies = connection.execute(
            "SELECT r.rolname,r.oid::bigint,d.dbid::bigint,"
            "d.classid='pg_catalog.pg_class'::regclass,"
            "d.classid='pg_catalog.pg_policy'::regclass,"
            "d.objid::bigint,d.objsubid,d.deptype::text "
            "FROM pg_catalog.pg_shdepend d JOIN pg_catalog.pg_roles r ON r.oid=d.refobjid "
            "WHERE d.refclassid='pg_catalog.pg_authid'::regclass AND r.rolname=ANY(%s) "
            "ORDER BY 1,3,4,5,6,7,8",
            (list(roles),),
        ).fetchall()
    need(
        all(
            role_oid == role_ids[role]
            and db_oid == database_oid
            and sub_id == 0
            and (
                (relation and not policy and object_oid in relation_oids and kind == "a")
                or (policy and not relation and object_oid in policy_oids and kind == "r")
            )
            for (
                role,
                role_oid,
                db_oid,
                relation,
                policy,
                object_oid,
                sub_id,
                kind,
            ) in dependencies
        ),
        "explicit_t_delivery_role_has_nonreceipt_dependency",
    )
    return dependencies


def reverse_additive_role_edges(connection, source_old, source_new):
    old = {tuple(x) for x in source_old}
    new = {tuple(x) for x in source_new}
    need(old <= new, "preserving_reverse_additive_role_edges_158")
    bootstrap = connection.execute("SELECT rolname FROM pg_roles WHERE oid=10").fetchone()[0]
    # Reverse the existing restore order: dependent service grants first,
    # then the bootstrap's ADMIN grants. Never revoke through CASCADE.
    added = sorted(new - old, key=lambda row: (row[2] == bootstrap, row))
    allowed = {
        "saas_usage_consumer",
        "saas_audit_delivery",
        "saas_revocation_consumer",
        "saas_model_projection",
    }
    need(all((row[0] in allowed for row in added)), "preserving_reverse_additive_role_edges_166")  # noqa: UP034
    need(role_edges(connection) == source_new, "preserving_reverse_additive_role_edges_167")
    with connection.transaction():
        for granted, member, grantor, admin, inherit, can_set in added:  # noqa: B007
            connection.execute(
                sql.SQL("REVOKE {} FROM {} GRANTED BY {}").format(
                    sql.Identifier(granted), sql.Identifier(member), sql.Identifier(grantor)
                )
            )
        need(role_edges(connection) == source_old, "preserving_reverse_additive_role_edges_179")
    return added


def restore_additive_role_edges(connection, source_old, source_new):
    need(role_edges(connection) == source_old, "preserving_restore_additive_role_edges_184")
    bootstrap = connection.execute("SELECT rolname FROM pg_roles WHERE oid=10").fetchone()[0]
    added = sorted(
        {tuple(x) for x in source_new} - {tuple(x) for x in source_old},
        key=lambda row: (row[2] != bootstrap, row),
    )
    with connection.transaction():
        for granted, member, grantor, admin, inherit, can_set in added:
            connection.execute(
                sql.SQL("GRANT {} TO {} WITH ADMIN {}, INHERIT {}, SET {} GRANTED BY {}").format(
                    sql.Identifier(granted),
                    sql.Identifier(member),
                    sql.SQL("TRUE" if admin else "FALSE"),
                    sql.SQL("TRUE" if inherit else "FALSE"),
                    sql.SQL("TRUE" if can_set else "FALSE"),
                    sql.Identifier(grantor),
                )
            )
        need(role_edges(connection) == source_new, "preserving_restore_additive_role_edges_207")


def exact_empty_archive_drop(
    database_owner, adapter, archive, identity, table_owner, identity_connection
):
    need(
        adapter.database_identity(database_owner, identity_connection) == identity,
        "preserving_exact_empty_archive_drop_213",
    )
    with database_owner.transaction():
        adapter.require_archive_acl(database_owner, archive, database_owner.info.user, table_owner)
        inventory = adapter.archive_catalog(database_owner)
        need(
            len(inventory["schemas"]) == 1 and inventory["schemas"][0]["nspname"] == archive,
            "preserving_exact_empty_archive_drop_219",
        )
        need(
            all(
                (  # noqa: UP034
                    inventory[k] == []
                    for k in ("relations", "types", "functions", "namespace_dependents")
                )
            ),
            "preserving_exact_empty_archive_drop_223",
        )
        database_owner.execute(sql.SQL("DROP SCHEMA {} RESTRICT").format(sql.Identifier(archive)))


def object_access(connection):
    return {
        "database": [
            list(x)
            for x in connection.execute(
                "SELECT pg_get_userbyid(a.grantee),pg_get_userbyid(a.grantor),a.privilege_type,a.is_grantable FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a WHERE d.datname=current_database() ORDER BY 1,2,3,4"  # noqa: E501
            )
        ],
        "public": [
            list(x)
            for x in connection.execute(
                "SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,pg_get_userbyid(a.grantor),a.privilege_type,a.is_grantable FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE n.nspname='public' ORDER BY 1,2,3,4"  # noqa: E501
            )
        ],
    }


def additive_access_delta(old, new):
    result = []
    for surface in ("database", "public"):
        before = {tuple(x) for x in old[surface]}
        after = {tuple(x) for x in new[surface]}
        need(before <= after, "preserving_additive_access_delta_254")
        for grantee, grantor, privilege, grantable in sorted(after - before):
            need(
                grantee
                in {
                    "saas_usage_consumer",
                    "saas_audit_delivery",
                    "saas_revocation_consumer",
                    "saas_model_projection",
                },
                "preserving_additive_access_delta_256",
            )
            need(
                not grantable and privilege == ("CONNECT" if surface == "database" else "USAGE"),
                "preserving_additive_access_delta_262",
            )
            result.append((surface, grantee, grantor, privilege))
    return result


def change_additive_access(connection, old, new, restore=False):
    need(
        object_access(connection) == (old if restore else new),
        "preserving_change_additive_access_270",
    )
    with connection.transaction():
        for surface, grantee, grantor, privilege in additive_access_delta(old, new):  # noqa: B007
            obj = (
                sql.SQL("DATABASE {}").format(sql.Identifier(connection.info.dbname))
                if surface == "database"
                else sql.SQL("SCHEMA public")
            )
            command = (
                sql.SQL("GRANT {} ON {} TO {}") if restore else sql.SQL("REVOKE {} ON {} FROM {}")
            )
            connection.execute(command.format(sql.SQL(privilege), obj, sql.Identifier(grantee)))
        need(
            object_access(connection) == (new if restore else old),
            "preserving_change_additive_access_286",
        )


def connect_url(url):
    from sqlalchemy import make_url

    value = make_url(url)
    args, kwargs = value.get_dialect()().create_connect_args(value)
    return psycopg.connect(*args, **kwargs, autocommit=True)
