"""PostgreSQL durability boundary for Runtime Provider operations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from hashlib import sha256
from types import MappingProxyType
from typing import ClassVar, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.engine import Engine

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.db_models import RuntimeProviderOperationJournalRecord
from saas.control_plane.postgresql_role_authority import (
    count_direct_acl_authorities,
    count_global_acl_authorities,
    count_owned_catalog_authorities,
)
from saas.control_plane.runtime_provider import (
    RuntimeProviderError,
    RuntimeProviderFailureDisposition,
    RuntimeProviderJournalEntry,
    RuntimeProviderOperation,
    RuntimeProviderOperationKind,
    RuntimeProviderOutcome,
    RuntimeProviderReceipt,
    RuntimeProviderResponse,
    canonical_json,
    canonical_sha256,
)

_JOURNAL_ROLE = "saas_runtime_provider_journal"
_JOURNAL_TABLE = "saas_runtime_provider_operation_journal"
_EXPECTED_RELATION_ACLS = {
    (_JOURNAL_TABLE, "r", "SELECT", False),
}
_EXPECTED_COLUMN_ACLS = {
    (_JOURNAL_TABLE, column, "INSERT", False)
    for column in (
        "id",
        "provider_type",
        "operation_kind",
        "placement_id",
        "binding_revision",
        "binding_hash",
        "target_hash",
        "idempotency_hash",
        "request_hash",
    )
} | {
    (_JOURNAL_TABLE, column, "UPDATE", False)
    for column in (
        "receipt_hash",
        "attributes_hash",
        "response_hash",
        "receipt_json",
        "attributes_json",
    )
}
_EXPECTED_POLICY_FACTS = {
    ("rls_runtime_provider_journal_insert", True, "a", 1, True, False, True),
    ("rls_runtime_provider_journal_select", True, "r", 1, True, True, False),
    ("rls_runtime_provider_journal_update", True, "w", 1, True, True, True),
}
_EXPECTED_COLUMN_SIGNATURE = (
    ("id", "uuid", True, "", "", True, None),
    ("provider_type", "character varying(128)", True, "", "", True, None),
    ("operation_kind", "character varying(64)", True, "", "", True, None),
    ("placement_id", "uuid", True, "", "", True, None),
    ("binding_revision", "character varying(128)", True, "", "", True, None),
    ("binding_hash", "character varying(64)", True, "", "", True, None),
    ("target_hash", "character varying(64)", True, "", "", True, None),
    ("idempotency_hash", "character varying(64)", True, "", "", True, None),
    ("request_hash", "character varying(64)", True, "", "", True, None),
    ("receipt_hash", "character varying(64)", False, "", "", True, None),
    ("attributes_hash", "character varying(64)", False, "", "", True, None),
    ("response_hash", "character varying(64)", False, "", "", True, None),
    ("receipt_json", "text", False, "", "", True, None),
    ("attributes_json", "text", False, "", "", True, None),
    ("created_at", "timestamp with time zone", True, "", "", True, "now()"),
    ("verified_at", "timestamp with time zone", False, "", "", True, None),
)
_JOURNAL_OPERATION_VALUES = (
    "allocate_partition",
    "provision_default_project",
    "compensate_default_project",
    "compensate_partition",
)
_EXPECTED_TRIGGER_FUNCTION_BODY = (
    "BEGIN "
    "IF TG_OP = 'DELETE' THEN "
    "RAISE EXCEPTION 'Runtime Provider journal rows are immutable'; "
    "END IF; "
    "IF ROW(NEW.id, NEW.provider_type, NEW.operation_kind, NEW.placement_id, "
    "NEW.binding_revision, NEW.binding_hash, NEW.target_hash, NEW.idempotency_hash, "
    "NEW.request_hash, NEW.created_at) IS DISTINCT FROM "
    "ROW(OLD.id, OLD.provider_type, OLD.operation_kind, OLD.placement_id, "
    "OLD.binding_revision, OLD.binding_hash, OLD.target_hash, OLD.idempotency_hash, "
    "OLD.request_hash, OLD.created_at) THEN "
    "RAISE EXCEPTION 'Runtime Provider journal fence is immutable'; "
    "END IF; "
    "IF OLD.response_hash IS NOT NULL THEN "
    "RAISE EXCEPTION 'Runtime Provider journal response is immutable'; "
    "END IF; "
    "IF NEW.receipt_hash IS NULL OR NEW.attributes_hash IS NULL "
    "OR NEW.response_hash IS NULL OR NEW.receipt_json IS NULL "
    "OR NEW.attributes_json IS NULL THEN "
    "RAISE EXCEPTION 'Runtime Provider journal response must be atomic'; "
    "END IF; "
    "NEW.verified_at := statement_timestamp(); "
    "RETURN NEW; "
    "END;"
)
_EXPECTED_TRIGGER_DEFINITION = (
    "CREATE TRIGGER trg_runtime_provider_journal_immutable "
    "BEFORE DELETE OR UPDATE ON saas_runtime_provider_operation_journal "
    "FOR EACH ROW EXECUTE FUNCTION saas_guard_runtime_provider_journal()"
)
_INSERT_COLUMNS = frozenset(
    {
        "id",
        "provider_type",
        "operation_kind",
        "placement_id",
        "binding_revision",
        "binding_hash",
        "target_hash",
        "idempotency_hash",
        "request_hash",
    }
)
_UPDATE_COLUMNS = frozenset(
    {
        "receipt_hash",
        "attributes_hash",
        "response_hash",
        "receipt_json",
        "attributes_json",
    }
)


def _compact_sql(value: str) -> str:
    return " ".join(value.split())


def _expected_hash_constraint(column: str, *, nullable: bool = False) -> str:
    expression = f"{column}::text"
    for character in "0123456789abcdef":
        expression = f"replace({expression}, '{character}'::text, ''::text)"
    predicate = f"length({column}::text) = 64 AND {expression} = ''::text"
    if nullable:
        predicate = f"{column} IS NULL OR {predicate}"
    return f"CHECK ({predicate})"


_EXPECTED_CONSTRAINTS = {
    "saas_runtime_provider_operation_journal_pkey": (
        "p",
        ("id",),
        "PRIMARY KEY (id)",
    ),
    "uq_runtime_provider_journal_identity": (
        "u",
        ("provider_type", "operation_kind", "idempotency_hash"),
        "UNIQUE (provider_type, operation_kind, idempotency_hash)",
    ),
    "uq_runtime_provider_journal_request_hash": (
        "u",
        ("request_hash",),
        "UNIQUE (request_hash)",
    ),
    "ck_runtime_provider_journal_operation": (
        "c",
        ("operation_kind",),
        "CHECK (operation_kind::text = ANY (ARRAY["
        + ", ".join(f"'{value}'::character varying" for value in _JOURNAL_OPERATION_VALUES)
        + "]::text[]))",
    ),
    "ck_runtime_provider_journal_provider": (
        "c",
        ("provider_type",),
        "CHECK (length(provider_type::text) > 0)",
    ),
    "ck_runtime_provider_journal_revision": (
        "c",
        ("binding_revision",),
        "CHECK (length(binding_revision::text) > 0)",
    ),
    **{
        f"ck_runtime_provider_journal_{column}": (
            "c",
            (column,),
            _expected_hash_constraint(column),
        )
        for column in (
            "binding_hash",
            "target_hash",
            "idempotency_hash",
            "request_hash",
        )
    },
    **{
        f"ck_runtime_provider_journal_{column}": (
            "c",
            (column,),
            _expected_hash_constraint(column, nullable=True),
        )
        for column in ("receipt_hash", "attributes_hash", "response_hash")
    },
    "ck_runtime_provider_journal_response_atomic": (
        "c",
        (
            "receipt_hash",
            "attributes_hash",
            "response_hash",
            "receipt_json",
            "attributes_json",
            "verified_at",
        ),
        "CHECK (receipt_hash IS NULL AND attributes_hash IS NULL "
        "AND response_hash IS NULL AND receipt_json IS NULL "
        "AND attributes_json IS NULL AND verified_at IS NULL OR "
        "receipt_hash IS NOT NULL AND attributes_hash IS NOT NULL "
        "AND response_hash IS NOT NULL AND receipt_json IS NOT NULL "
        "AND attributes_json IS NOT NULL AND verified_at IS NOT NULL)",
    ),
}


def verify_runtime_provider_journal_database_role(engine: Engine) -> None:
    """Fail closed unless ``engine`` is the one-purpose Journal LOGIN."""

    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production Runtime Provider journal requires PostgreSQL")
    with engine.connect() as connection:
        schema_facts = connection.execute(
            sa.text(
                "SELECT current_database(), current_schema(), current_schemas(false), "
                "has_schema_privilege(current_user, 'public', 'USAGE'), "
                "has_schema_privilege(current_user, 'public', 'CREATE'), "
                "has_database_privilege(current_user, current_database(), 'TEMP')"
            )
        ).one()
        login_facts = connection.execute(
            sa.text(
                "SELECT current_user, session_user, role.rolcanlogin, role.rolsuper, "
                "role.rolcreatedb, role.rolcreaterole, role.rolreplication, "
                "role.rolbypassrls, role.rolinherit, role.rolconnlimit, role.rolconfig "
                "FROM pg_roles AS role WHERE role.rolname = current_user"
            )
        ).one()
        base_facts = connection.execute(
            sa.text(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                "FROM pg_roles WHERE rolname = :role"
            ),
            {"role": _JOURNAL_ROLE},
        ).one_or_none()
        membership_projection = (
            "granted.rolname, membership.admin_option, "
            "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
            "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true) "
        )
        login_memberships = connection.execute(
            sa.text(
                f"SELECT {membership_projection}"
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "WHERE member.rolname = current_user ORDER BY granted.rolname"
            )
        ).all()
        base_memberships = connection.execute(
            sa.text(
                f"SELECT {membership_projection}"
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "WHERE member.rolname = :role ORDER BY granted.rolname"
            ),
            {"role": _JOURNAL_ROLE},
        ).all()
        direct_login_authority = connection.execute(
            sa.text(
                "WITH login AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
                "direct_authority AS ("
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(object.relacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_attribute attribute "
                "JOIN pg_class object ON object.oid = attribute.attrelid "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE namespace.nspname = 'public' AND attribute.attnum > 0 "
                "AND NOT attribute.attisdropped UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_namespace object "
                "CROSS JOIN LATERAL aclexplode(object.nspacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE object.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_database object "
                "CROSS JOIN LATERAL aclexplode(object.datacl) acl "
                "JOIN login ON acl.grantee = login.oid UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults "
                "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl "
                "JOIN login ON acl.grantee = login.oid UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults "
                "JOIN login ON defaults.defaclrole = login.oid UNION ALL "
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "JOIN login ON object.relowner = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "JOIN login ON object.proowner = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "JOIN login ON object.typowner = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_namespace object JOIN login "
                "ON object.nspowner = login.oid WHERE object.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_database object JOIN login ON object.datdba = login.oid) "
                "SELECT count(*) FROM direct_authority"
            )
        ).scalar_one()
        login_catalog_authority = count_direct_acl_authorities(
            connection,
            role=str(login_facts[0]),
        ) + count_owned_catalog_authorities(
            connection,
            role=str(login_facts[0]),
            include_role_settings=False,
        )
        base_catalog_authority = count_global_acl_authorities(
            connection,
            role=_JOURNAL_ROLE,
        ) + count_owned_catalog_authorities(
            connection,
            role=_JOURNAL_ROLE,
            include_role_settings=True,
        )
        direct_login_non_system_authority = connection.execute(
            sa.text(
                "WITH login AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
                "unexpected AS ("
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(object.relacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE namespace.nspname <> 'public' "
                "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND namespace.nspname NOT LIKE 'pg_toast%' "
                "AND namespace.nspname NOT LIKE 'pg_temp_%' UNION ALL "
                "SELECT 1 FROM pg_attribute attribute "
                "JOIN pg_class object ON object.oid = attribute.attrelid "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE attribute.attnum > 0 AND NOT attribute.attisdropped "
                "AND namespace.nspname <> 'public' "
                "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND namespace.nspname NOT LIKE 'pg_toast%' "
                "AND namespace.nspname NOT LIKE 'pg_temp_%' UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE namespace.nspname <> 'public' "
                "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND namespace.nspname NOT LIKE 'pg_toast%' "
                "AND namespace.nspname NOT LIKE 'pg_temp_%' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE namespace.nspname <> 'public' "
                "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND namespace.nspname NOT LIKE 'pg_toast%' "
                "AND namespace.nspname NOT LIKE 'pg_temp_%' UNION ALL "
                "SELECT 1 FROM pg_namespace object "
                "CROSS JOIN LATERAL aclexplode(object.nspacl) acl "
                "JOIN login ON acl.grantee = login.oid "
                "WHERE object.nspname <> 'public' "
                "AND object.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND object.nspname NOT LIKE 'pg_toast%' "
                "AND object.nspname NOT LIKE 'pg_temp_%' UNION ALL "
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "JOIN login ON object.relowner = login.oid "
                "WHERE namespace.nspname <> 'public' "
                "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND namespace.nspname NOT LIKE 'pg_toast%' "
                "AND namespace.nspname NOT LIKE 'pg_temp_%' UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "JOIN login ON object.proowner = login.oid "
                "WHERE namespace.nspname <> 'public' "
                "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND namespace.nspname NOT LIKE 'pg_toast%' "
                "AND namespace.nspname NOT LIKE 'pg_temp_%' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "JOIN login ON object.typowner = login.oid "
                "WHERE namespace.nspname <> 'public' "
                "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND namespace.nspname NOT LIKE 'pg_toast%' "
                "AND namespace.nspname NOT LIKE 'pg_temp_%' UNION ALL "
                "SELECT 1 FROM pg_namespace object "
                "JOIN login ON object.nspowner = login.oid "
                "WHERE object.nspname <> 'public' "
                "AND object.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND object.nspname NOT LIKE 'pg_toast%' "
                "AND object.nspname NOT LIKE 'pg_temp_%') "
                "SELECT count(*) FROM unexpected"
            )
        ).scalar_one()
        relation_acls = connection.execute(
            sa.text(
                "SELECT relation.relname, relation.relkind, acl.privilege_type, "
                "acl.is_grantable FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_roles AS journal ON journal.rolname = :role "
                "CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl "
                "WHERE namespace.nspname = 'public' AND acl.grantee = journal.oid "
                "ORDER BY relation.relname, acl.privilege_type"
            ),
            {"role": _JOURNAL_ROLE},
        ).all()
        column_acls = connection.execute(
            sa.text(
                "SELECT relation.relname, attribute.attname, acl.privilege_type, "
                "acl.is_grantable FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid "
                "JOIN pg_roles AS journal ON journal.rolname = :role "
                "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
                "WHERE namespace.nspname = 'public' AND attribute.attnum > 0 "
                "AND NOT attribute.attisdropped AND acl.grantee = journal.oid "
                "ORDER BY relation.relname, attribute.attnum, acl.privilege_type"
            ),
            {"role": _JOURNAL_ROLE},
        ).all()
        schema_acls = connection.execute(
            sa.text(
                "SELECT namespace.nspname, acl.privilege_type, acl.is_grantable "
                "FROM pg_namespace AS namespace "
                "JOIN pg_roles AS journal ON journal.rolname = :role "
                "CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl "
                "WHERE namespace.nspname = 'public' AND acl.grantee = journal.oid"
            ),
            {"role": _JOURNAL_ROLE},
        ).all()
        database_acls = connection.execute(
            sa.text(
                "SELECT object.datname, acl.privilege_type, "
                "acl.grantor = object.datdba AS granted_by_database_owner, "
                "acl.is_grantable FROM pg_database AS object "
                "JOIN pg_roles AS journal ON journal.rolname = :role "
                "CROSS JOIN LATERAL aclexplode(object.datacl) AS acl "
                "WHERE acl.grantee = journal.oid "
                "ORDER BY object.datname, acl.privilege_type"
            ),
            {"role": _JOURNAL_ROLE},
        ).all()
        base_other_authority = connection.execute(
            sa.text(
                "WITH journal AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
                "unexpected AS ("
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                "JOIN journal ON acl.grantee = journal.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                "JOIN journal ON acl.grantee = journal.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults "
                "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl "
                "JOIN journal ON acl.grantee = journal.oid UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults "
                "JOIN journal ON defaults.defaclrole = journal.oid UNION ALL "
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "JOIN journal ON object.relowner = journal.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "JOIN journal ON object.proowner = journal.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "JOIN journal ON object.typowner = journal.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_namespace object "
                "JOIN journal ON object.nspowner = journal.oid "
                "WHERE object.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_database object "
                "JOIN journal ON object.datdba = journal.oid) "
                "SELECT count(*) FROM unexpected"
            ),
            {"role": _JOURNAL_ROLE},
        ).scalar_one()
        base_non_system_authority = connection.execute(
            sa.text(
                "WITH journal AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
                "non_system AS (SELECT oid, nspname FROM pg_namespace "
                "WHERE nspname <> 'public' "
                "AND nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND nspname NOT LIKE 'pg_toast%' "
                "AND nspname NOT LIKE 'pg_temp_%'), "
                "unexpected AS ("
                "SELECT 1 FROM pg_class object "
                "JOIN non_system namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(object.relacl) acl "
                "JOIN journal ON acl.grantee = journal.oid UNION ALL "
                "SELECT 1 FROM pg_attribute attribute "
                "JOIN pg_class object ON object.oid = attribute.attrelid "
                "JOIN non_system namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
                "JOIN journal ON acl.grantee = journal.oid "
                "WHERE attribute.attnum > 0 AND NOT attribute.attisdropped UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN non_system namespace ON namespace.oid = object.pronamespace "
                "CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                "JOIN journal ON acl.grantee = journal.oid UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN non_system namespace ON namespace.oid = object.typnamespace "
                "CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                "JOIN journal ON acl.grantee = journal.oid UNION ALL "
                "SELECT 1 FROM non_system object "
                "CROSS JOIN LATERAL aclexplode(("
                "SELECT nspacl FROM pg_namespace WHERE oid = object.oid)) acl "
                "JOIN journal ON acl.grantee = journal.oid UNION ALL "
                "SELECT 1 FROM pg_class object "
                "JOIN non_system namespace ON namespace.oid = object.relnamespace "
                "JOIN journal ON object.relowner = journal.oid UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN non_system namespace ON namespace.oid = object.pronamespace "
                "JOIN journal ON object.proowner = journal.oid UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN non_system namespace ON namespace.oid = object.typnamespace "
                "JOIN journal ON object.typowner = journal.oid UNION ALL "
                "SELECT 1 FROM non_system object "
                "JOIN journal ON (SELECT nspowner FROM pg_namespace "
                "WHERE oid = object.oid) = journal.oid) "
                "SELECT count(*) FROM unexpected"
            ),
            {"role": _JOURNAL_ROLE},
        ).scalar_one()
        effective_non_system_schema_authority = connection.execute(
            sa.text(
                "SELECT count(*) FROM pg_namespace AS namespace "
                "WHERE namespace.nspname <> 'public' "
                "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND namespace.nspname NOT LIKE 'pg_toast%' "
                "AND namespace.nspname NOT LIKE 'pg_temp_%' "
                "AND (has_schema_privilege(current_user, namespace.oid, 'USAGE') "
                "OR has_schema_privilege(current_user, namespace.oid, 'CREATE') "
                "OR has_schema_privilege(:role, namespace.oid, 'USAGE') "
                "OR has_schema_privilege(:role, namespace.oid, 'CREATE'))"
            ),
            {"role": _JOURNAL_ROLE},
        ).scalar_one()
        forbidden_tables = connection.execute(
            sa.text(
                "SELECT count(*) FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p') "
                "AND relation.relname LIKE 'saas_%' AND relation.relname <> :table AND ("
                "has_table_privilege(current_user, relation.oid, "
                "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR "
                "has_any_column_privilege(current_user, relation.oid, "
                "'SELECT,INSERT,UPDATE,REFERENCES'))"
            ),
            {"table": _JOURNAL_TABLE},
        ).scalar_one()
        table_posture = connection.execute(
            sa.text(
                "SELECT relation.relrowsecurity, relation.relforcerowsecurity, "
                "owner.rolname = current_user, relation.relkind, "
                "relation.relpersistence, relation.relispartition "
                "FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table"
            ),
            {"table": _JOURNAL_TABLE},
        ).one_or_none()
        policy_facts = connection.execute(
            sa.text(
                "SELECT policy.polname, policy.polpermissive, policy.polcmd, "
                "cardinality(policy.polroles), journal.oid = ANY(policy.polroles), "
                "policy.polqual IS NOT NULL, policy.polwithcheck IS NOT NULL "
                "FROM pg_policy AS policy "
                "JOIN pg_class AS relation ON relation.oid = policy.polrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_roles AS journal ON journal.rolname = :role "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table "
                "ORDER BY policy.polname"
            ),
            {"role": _JOURNAL_ROLE, "table": _JOURNAL_TABLE},
        ).all()
        column_signature = connection.execute(
            sa.text(
                "SELECT attribute.attname, "
                "format_type(attribute.atttypid, attribute.atttypmod), "
                "attribute.attnotnull, attribute.attidentity, attribute.attgenerated, "
                "attribute.attcollation = type.typcollation, "
                "pg_get_expr(default_value.adbin, default_value.adrelid) "
                "FROM pg_attribute AS attribute "
                "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_type AS type ON type.oid = attribute.atttypid "
                "LEFT JOIN pg_attrdef AS default_value "
                "ON default_value.adrelid = attribute.attrelid "
                "AND default_value.adnum = attribute.attnum "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table "
                "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
                "ORDER BY attribute.attnum"
            ),
            {"table": _JOURNAL_TABLE},
        ).all()
        constraints = connection.execute(
            sa.text(
                "SELECT catalog_constraint.conname, catalog_constraint.contype, "
                "catalog_constraint.convalidated, catalog_constraint.connoinherit, "
                "ARRAY(SELECT attribute.attname "
                "FROM unnest(catalog_constraint.conkey) WITH ORDINALITY "
                "AS key(attnum, position) "
                "JOIN pg_attribute AS attribute "
                "ON attribute.attrelid = catalog_constraint.conrelid "
                "AND attribute.attnum = key.attnum ORDER BY key.position), "
                "pg_get_constraintdef(catalog_constraint.oid, true) "
                "FROM pg_constraint AS catalog_constraint "
                "JOIN pg_class AS relation ON relation.oid = catalog_constraint.conrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table "
                "AND catalog_constraint.contype IN ('c', 'p', 'u') "
                "ORDER BY catalog_constraint.conname"
            ),
            {"table": _JOURNAL_TABLE},
        ).all()
        trigger_facts = connection.execute(
            sa.text(
                "SELECT trigger.tgname, trigger.tgenabled, trigger.tgisinternal, "
                "function_namespace.nspname, function.proname, function.prosecdef, "
                "function.proconfig, language.lanname, function.prokind, "
                "function.provolatile, function.proparallel, function.proleakproof, "
                "function.proisstrict, "
                "pg_get_function_identity_arguments(function.oid), "
                "pg_get_function_result(function.oid), "
                "function.proowner = relation.relowner, "
                "(SELECT count(*) = 1 AND COALESCE(bool_and("
                "acl.grantor = function.proowner AND acl.grantee = function.proowner "
                "AND acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable), false) "
                "FROM aclexplode(function.proacl) AS acl), "
                "function.prosrc, pg_get_triggerdef(trigger.oid, true), "
                "trigger.tgattr::text, trigger.tgconstraint = 0, "
                "trigger.tgdeferrable, trigger.tginitdeferred "
                "FROM pg_trigger AS trigger "
                "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_proc AS function ON function.oid = trigger.tgfoid "
                "JOIN pg_namespace AS function_namespace "
                "ON function_namespace.oid = function.pronamespace "
                "JOIN pg_language AS language ON language.oid = function.prolang "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table "
                "AND NOT trigger.tgisinternal ORDER BY trigger.tgname"
            ),
            {"table": _JOURNAL_TABLE},
        ).all()
        effective_table_privileges = connection.execute(
            sa.text(
                "SELECT has_table_privilege(current_user, relation.oid, 'SELECT'), "
                "has_table_privilege(current_user, relation.oid, 'INSERT'), "
                "has_table_privilege(current_user, relation.oid, 'UPDATE'), "
                "has_table_privilege(current_user, relation.oid, 'DELETE'), "
                "has_table_privilege(current_user, relation.oid, 'TRUNCATE'), "
                "has_table_privilege(current_user, relation.oid, 'REFERENCES'), "
                "has_table_privilege(current_user, relation.oid, 'TRIGGER') "
                "FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table"
            ),
            {"table": _JOURNAL_TABLE},
        ).one_or_none()
        effective_column_privileges = connection.execute(
            sa.text(
                "SELECT attribute.attname, "
                "has_column_privilege(current_user, relation.oid, attribute.attnum, 'SELECT'), "
                "has_column_privilege(current_user, relation.oid, attribute.attnum, 'INSERT'), "
                "has_column_privilege(current_user, relation.oid, attribute.attnum, 'UPDATE'), "
                "has_column_privilege(current_user, relation.oid, attribute.attnum, 'REFERENCES') "
                "FROM pg_attribute AS attribute "
                "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table "
                "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
                "ORDER BY attribute.attnum"
            ),
            {"table": _JOURNAL_TABLE},
        ).all()
        unexpected_rules = connection.execute(
            sa.text(
                "SELECT count(*) FROM pg_rewrite AS rule "
                "JOIN pg_class AS relation ON relation.oid = rule.ev_class "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = 'public' AND relation.relname = :table "
                "AND rule.rulename <> '_RETURN'"
            ),
            {"table": _JOURNAL_TABLE},
        ).scalar_one()

    (
        database_name,
        current_schema,
        search_path,
        can_use_schema,
        can_create_in_schema,
        can_create_temporary_objects,
    ) = schema_facts
    if (
        current_schema != "public"
        or list(search_path) != ["public"]
        or not can_use_schema
        or can_create_in_schema
    ):
        raise RuntimeError("Runtime Provider journal LOGIN must use only public search_path")
    if can_create_temporary_objects:
        raise RuntimeError("Runtime Provider journal LOGIN must not create temporary objects")
    (
        current_user,
        session_user,
        can_login,
        is_superuser,
        can_create_database,
        can_create_role,
        can_replicate,
        bypasses_rls,
        inherits_roles,
        connection_limit,
        login_config,
    ) = login_facts
    if current_user != session_user:
        raise RuntimeError("Runtime Provider journal connection must not use an assumed role")
    if (
        not can_login
        or is_superuser
        or can_create_database
        or can_create_role
        or can_replicate
        or bypasses_rls
        or not inherits_roles
        or connection_limit != -1
        or list(login_config or []) != ["search_path=public"]
    ):
        raise RuntimeError("Runtime Provider journal LOGIN violates the non-bypass posture")
    if base_facts != (False, False, False, False, False, False, True, -1, None):
        raise RuntimeError("Runtime Provider journal base role facts are unsafe")
    if (
        len(login_memberships) != 1
        or login_memberships[0][0] != _JOURNAL_ROLE
        or tuple(login_memberships[0][1:]) != (False, True, False)
        or base_memberships
    ):
        raise RuntimeError("Runtime Provider journal LOGIN membership is unsafe")
    if direct_login_authority or direct_login_non_system_authority or login_catalog_authority:
        raise RuntimeError("Runtime Provider journal LOGIN has direct database authority")
    relation_acl_facts = {
        (str(row[0]), str(row[1]), str(row[2]), bool(row[3])) for row in relation_acls
    }
    column_acl_facts = {
        (str(row[0]), str(row[1]), str(row[2]), bool(row[3])) for row in column_acls
    }
    schema_acl_facts = {(str(row[0]), str(row[1]), bool(row[2])) for row in schema_acls}
    database_acl_facts = {
        (str(row[0]), str(row[1]), bool(row[2]), bool(row[3])) for row in database_acls
    }
    if (
        relation_acl_facts != _EXPECTED_RELATION_ACLS
        or column_acl_facts != _EXPECTED_COLUMN_ACLS
        or schema_acl_facts != {("public", "USAGE", False)}
        or database_acl_facts != {(database_name, "CONNECT", True, False)}
        or len(database_acl_facts) != 1
        or base_other_authority
        or base_non_system_authority
        or effective_non_system_schema_authority
        or base_catalog_authority
    ):
        raise RuntimeError("Runtime Provider journal base role authority is unsafe")
    if forbidden_tables:
        raise RuntimeError("Runtime Provider journal LOGIN can access another SaaS table")
    if table_posture != (True, True, False, "r", "p", False):
        raise RuntimeError("Runtime Provider journal table is not FORCE-RLS isolated")
    normalized_policy_facts = {
        (
            str(row[0]),
            bool(row[1]),
            str(row[2]),
            int(row[3]),
            bool(row[4]),
            bool(row[5]),
            bool(row[6]),
        )
        for row in policy_facts
    }
    if normalized_policy_facts != _EXPECTED_POLICY_FACTS:
        raise RuntimeError("Runtime Provider journal RLS policy set is unsafe")
    if effective_table_privileges != (True, False, False, False, False, False, False):
        raise RuntimeError("Runtime Provider journal effective table authority is unsafe")
    normalized_effective_columns = {
        (str(row[0]), bool(row[1]), bool(row[2]), bool(row[3]), bool(row[4]))
        for row in effective_column_privileges
    }
    expected_effective_columns = {
        (
            str(column[0]),
            True,
            str(column[0]) in _INSERT_COLUMNS,
            str(column[0]) in _UPDATE_COLUMNS,
            False,
        )
        for column in _EXPECTED_COLUMN_SIGNATURE
    }
    if normalized_effective_columns != expected_effective_columns:
        raise RuntimeError("Runtime Provider journal effective column authority is unsafe")
    if unexpected_rules:
        raise RuntimeError("Runtime Provider journal rewrite rule set is unsafe")
    normalized_column_signature = tuple(
        (
            str(row[0]),
            str(row[1]),
            bool(row[2]),
            str(row[3]),
            str(row[4]),
            bool(row[5]),
            None if row[6] is None else _compact_sql(str(row[6])),
        )
        for row in column_signature
    )
    if normalized_column_signature != _EXPECTED_COLUMN_SIGNATURE:
        raise RuntimeError("Runtime Provider journal column signature is unsafe")
    normalized_constraints = {
        str(row[0]): (
            str(row[1]),
            tuple(str(column) for column in row[4]),
            _compact_sql(str(row[5])),
        )
        for row in constraints
    }
    if (
        any(not bool(row[2]) for row in constraints)
        or any(str(row[1]) == "c" and bool(row[3]) for row in constraints)
        or normalized_constraints != _EXPECTED_CONSTRAINTS
    ):
        raise RuntimeError("Runtime Provider journal constraint set is unsafe")
    if len(trigger_facts) != 1:
        raise RuntimeError("Runtime Provider journal immutability trigger set is unsafe")
    trigger = trigger_facts[0]
    if (
        str(trigger[0]) != "trg_runtime_provider_journal_immutable"
        or str(trigger[1]) != "O"
        or bool(trigger[2])
        or str(trigger[3]) != "public"
        or str(trigger[4]) != "saas_guard_runtime_provider_journal"
        or bool(trigger[5])
        or list(trigger[6] or []) != ["search_path=pg_catalog"]
        or str(trigger[7]) != "plpgsql"
        or str(trigger[8]) != "f"
        or str(trigger[9]) != "v"
        or str(trigger[10]) != "u"
        or bool(trigger[11])
        or bool(trigger[12])
        or str(trigger[13]) != ""
        or str(trigger[14]) != "trigger"
        or not bool(trigger[15])
        or not bool(trigger[16])
        or _compact_sql(str(trigger[17])) != _EXPECTED_TRIGGER_FUNCTION_BODY
        or _compact_sql(str(trigger[18])) != _EXPECTED_TRIGGER_DEFINITION
        or str(trigger[19]) != ""
        or not bool(trigger[20])
        or bool(trigger[21])
        or bool(trigger[22])
    ):
        raise RuntimeError("Runtime Provider journal immutability trigger is unsafe")


class PostgresqlRuntimeProviderOperationJournal:
    """Atomic Provider effect fence backed by one FORCE-RLS PostgreSQL table."""

    __slots__ = ("_session",)

    production_capable: ClassVar[bool] = True
    durable: ClassVar[bool] = True
    conflict_safe: ClassVar[bool] = True

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise TypeError("Runtime Provider journal requires a SQLAlchemy Engine")
        if engine.dialect.name != "postgresql":
            raise ValueError("Runtime Provider journal requires PostgreSQL")
        if not engine.hide_parameters:
            raise ValueError("Runtime Provider journal requires hidden SQL parameters")
        verify_runtime_provider_journal_database_role(engine)
        self._session = make_named_managed_session_maker(
            engine,
            query_name_prefix="saas.runtime_provider_operation_journal",
            # Provider execution begins immediately after begin() returns.
            # Never join an ambient shared_read_scope transaction: the fence
            # must already be committed and visible to a second connection.
            immediate=True,
        )

    def lookup(
        self,
        operation: RuntimeProviderOperation,
    ) -> RuntimeProviderJournalEntry | None:
        with self._session("lookup") as session:
            row = session.execute(
                sa.select(RuntimeProviderOperationJournalRecord).where(
                    *_identity_predicate(operation)
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            return _entry_from_row(row, operation)

    def begin(self, operation: RuntimeProviderOperation) -> RuntimeProviderJournalEntry:
        statement = (
            postgresql_insert(RuntimeProviderOperationJournalRecord)
            .values(
                id=uuid4(),
                provider_type=operation.provider_type,
                operation_kind=operation.kind.value,
                placement_id=operation.placement_id,
                binding_revision=operation.binding_revision,
                binding_hash=operation.binding_hash,
                target_hash=operation.target_hash,
                idempotency_hash=operation.idempotency_hash,
                request_hash=operation.request_hash,
            )
            .on_conflict_do_nothing()
            .returning(RuntimeProviderOperationJournalRecord.id)
        )
        with self._session("begin_effect_fence") as session:
            inserted_id = session.execute(statement).scalar_one_or_none()
            if inserted_id is not None:
                return RuntimeProviderJournalEntry(
                    request_hash=operation.request_hash,
                    is_new=True,
                )
            row = session.execute(
                sa.select(RuntimeProviderOperationJournalRecord).where(
                    *_identity_predicate(operation)
                )
            ).scalar_one_or_none()
            if row is None:
                raise _conflict("provider_journal_identity_conflict")
            return _entry_from_row(row, operation)

    def record_verified(
        self,
        *,
        operation: RuntimeProviderOperation,
        response: RuntimeProviderResponse,
    ) -> None:
        persisted = _serialize_verified_response(operation, response)
        statement = (
            sa.update(RuntimeProviderOperationJournalRecord)
            .where(
                *_fence_predicate(operation),
                RuntimeProviderOperationJournalRecord.response_hash.is_(None),
            )
            .values(
                receipt_hash=persisted.receipt_hash,
                attributes_hash=persisted.attributes_hash,
                response_hash=persisted.response_hash,
                receipt_json=persisted.receipt_json,
                attributes_json=persisted.attributes_json,
            )
            .returning(RuntimeProviderOperationJournalRecord.id)
        )
        with self._session("record_verified_response") as session:
            updated_id = session.execute(statement).scalar_one_or_none()
            if updated_id is not None:
                return
            row = session.execute(
                sa.select(RuntimeProviderOperationJournalRecord).where(
                    *_identity_predicate(operation)
                )
            ).scalar_one_or_none()
            if row is None or not _row_matches_operation(row, operation):
                raise _conflict("provider_journal_fence_conflict")
            if (
                row.receipt_hash,
                row.attributes_hash,
                row.response_hash,
                row.receipt_json,
                row.attributes_json,
            ) != (
                persisted.receipt_hash,
                persisted.attributes_hash,
                persisted.response_hash,
                persisted.receipt_json,
                persisted.attributes_json,
            ):
                raise _conflict("provider_journal_receipt_conflict")


class _PersistedResponse:
    __slots__ = (
        "attributes_hash",
        "attributes_json",
        "receipt_hash",
        "receipt_json",
        "response_hash",
    )

    def __init__(
        self,
        *,
        receipt_hash: str,
        attributes_hash: str,
        response_hash: str,
        receipt_json: str,
        attributes_json: str,
    ) -> None:
        self.receipt_hash = receipt_hash
        self.attributes_hash = attributes_hash
        self.response_hash = response_hash
        self.receipt_json = receipt_json
        self.attributes_json = attributes_json


def _identity_predicate(
    operation: RuntimeProviderOperation,
) -> tuple[sa.ColumnElement[bool], ...]:
    return (
        RuntimeProviderOperationJournalRecord.provider_type == operation.provider_type,
        RuntimeProviderOperationJournalRecord.operation_kind == operation.kind.value,
        RuntimeProviderOperationJournalRecord.idempotency_hash == operation.idempotency_hash,
    )


def _fence_predicate(
    operation: RuntimeProviderOperation,
) -> tuple[sa.ColumnElement[bool], ...]:
    return (
        *_identity_predicate(operation),
        RuntimeProviderOperationJournalRecord.placement_id == operation.placement_id,
        RuntimeProviderOperationJournalRecord.binding_revision == operation.binding_revision,
        RuntimeProviderOperationJournalRecord.binding_hash == operation.binding_hash,
        RuntimeProviderOperationJournalRecord.target_hash == operation.target_hash,
        RuntimeProviderOperationJournalRecord.request_hash == operation.request_hash,
    )


def _row_matches_operation(
    row: RuntimeProviderOperationJournalRecord,
    operation: RuntimeProviderOperation,
) -> bool:
    return (
        row.provider_type == operation.provider_type
        and row.operation_kind == operation.kind.value
        and row.placement_id == operation.placement_id
        and row.binding_revision == operation.binding_revision
        and row.binding_hash == operation.binding_hash
        and row.target_hash == operation.target_hash
        and row.idempotency_hash == operation.idempotency_hash
        and row.request_hash == operation.request_hash
    )


def _entry_from_row(
    row: RuntimeProviderOperationJournalRecord,
    operation: RuntimeProviderOperation,
) -> RuntimeProviderJournalEntry:
    if not _row_matches_operation(row, operation):
        raise _conflict("provider_journal_fence_conflict")
    response = None
    if row.response_hash is not None:
        try:
            response = _deserialize_response(row)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise RuntimeProviderError(
                "provider_journal_corrupt",
                RuntimeProviderFailureDisposition.RECEIPT_INVALID,
            ) from None
    return RuntimeProviderJournalEntry(
        request_hash=row.request_hash,
        is_new=False,
        response=response,
    )


def _serialize_verified_response(
    operation: RuntimeProviderOperation,
    response: RuntimeProviderResponse,
) -> _PersistedResponse:
    receipt = response.receipt
    try:
        attributes = dict(response.attributes)
        attributes_json = canonical_json(attributes)
        attributes_hash = sha256(attributes_json.encode("utf-8")).hexdigest()
        receipt_document = {
            **receipt.unsigned_document(),
            "signature_hex": receipt.signature_hex,
        }
        receipt_json = canonical_json(receipt_document)
        response_hash = canonical_sha256(
            {
                "schema_version": 1,
                "receipt": receipt_document,
                "attributes": attributes,
            }
        )
    except (TypeError, ValueError):
        raise RuntimeProviderError(
            "provider_journal_response_invalid",
            RuntimeProviderFailureDisposition.RECEIPT_INVALID,
        ) from None
    if not (
        receipt.provider_type == operation.provider_type
        and receipt.operation is operation.kind
        and receipt.placement_id == operation.placement_id
        and receipt.binding_revision == operation.binding_revision
        and receipt.binding_hash == operation.binding_hash
        and receipt.target_hash == operation.target_hash
        and receipt.idempotency_hash == operation.idempotency_hash
        and receipt.request_hash == operation.request_hash
        and receipt.result_hash == attributes_hash
        and receipt.receipt_hash == sha256(receipt.unsigned_payload()).hexdigest()
    ):
        raise RuntimeProviderError(
            "provider_journal_response_invalid",
            RuntimeProviderFailureDisposition.RECEIPT_INVALID,
        )
    return _PersistedResponse(
        receipt_hash=receipt.receipt_hash,
        attributes_hash=attributes_hash,
        response_hash=response_hash,
        receipt_json=receipt_json,
        attributes_json=attributes_json,
    )


def _deserialize_response(
    row: RuntimeProviderOperationJournalRecord,
) -> RuntimeProviderResponse:
    if None in {
        row.receipt_hash,
        row.attributes_hash,
        row.response_hash,
        row.receipt_json,
        row.attributes_json,
        row.verified_at,
    }:
        raise ValueError("Runtime Provider journal response is incomplete")
    receipt_json = cast(str, row.receipt_json)
    attributes_json = cast(str, row.attributes_json)
    receipt_document = json.loads(receipt_json)
    attributes = json.loads(attributes_json)
    if not isinstance(receipt_document, dict) or not isinstance(attributes, dict):
        raise TypeError("Runtime Provider journal documents must be objects")
    if (
        canonical_json(receipt_document) != receipt_json
        or canonical_json(attributes) != attributes_json
    ):
        raise ValueError("Runtime Provider journal document is not canonical")
    receipt = RuntimeProviderReceipt(
        schema_version=_integer(receipt_document, "schema_version"),
        provider_type=_text(receipt_document, "provider_type"),
        operation=RuntimeProviderOperationKind(_text(receipt_document, "operation")),
        outcome=RuntimeProviderOutcome(_text(receipt_document, "outcome")),
        placement_id=UUID(_text(receipt_document, "placement_id")),
        binding_revision=_text(receipt_document, "binding_revision"),
        binding_hash=_text(receipt_document, "binding_hash"),
        target_hash=_text(receipt_document, "target_hash"),
        idempotency_hash=_text(receipt_document, "idempotency_hash"),
        request_hash=_text(receipt_document, "request_hash"),
        credential_ref_hash=_text(receipt_document, "credential_ref_hash"),
        credential_version_hash=_text(receipt_document, "credential_version_hash"),
        result_hash=_text(receipt_document, "result_hash"),
        provider_request_id=_text(receipt_document, "provider_request_id"),
        provider_resource_id=_optional_text(receipt_document, "provider_resource_id"),
        observed_at=datetime.fromisoformat(_text(receipt_document, "observed_at")),
        receipt_hash=cast(str, row.receipt_hash),
        signature_key_id=_text(receipt_document, "signature_key_id"),
        signature_hex=_text(receipt_document, "signature_hex"),
    )
    attributes_hash = sha256(attributes_json.encode("utf-8")).hexdigest()
    response_hash = canonical_sha256(
        {
            "schema_version": 1,
            "receipt": receipt_document,
            "attributes": attributes,
        }
    )
    if (
        receipt.provider_type != row.provider_type
        or receipt.operation.value != row.operation_kind
        or receipt.placement_id != row.placement_id
        or receipt.binding_revision != row.binding_revision
        or receipt.binding_hash != row.binding_hash
        or receipt.target_hash != row.target_hash
        or receipt.idempotency_hash != row.idempotency_hash
        or receipt.request_hash != row.request_hash
        or receipt.result_hash != attributes_hash
        or receipt.receipt_hash != sha256(receipt.unsigned_payload()).hexdigest()
        or receipt.receipt_hash != row.receipt_hash
        or attributes_hash != row.attributes_hash
        or response_hash != row.response_hash
    ):
        raise ValueError("Runtime Provider journal response hash mismatch")
    return RuntimeProviderResponse(
        receipt=receipt,
        attributes=MappingProxyType(cast(dict[str, object], attributes)),
    )


def _text(document: Mapping[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError(f"Runtime Provider journal {key} must be text")
    return value


def _optional_text(document: Mapping[str, object], key: str) -> str | None:
    value = document[key]
    if value is None or isinstance(value, str):
        return value
    raise TypeError(f"Runtime Provider journal {key} must be optional text")


def _integer(document: Mapping[str, object], key: str) -> int:
    value = document[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"Runtime Provider journal {key} must be an integer")
    return value


def _conflict(code: str) -> RuntimeProviderError:
    return RuntimeProviderError(
        code,
        RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT,
    )


__all__ = [
    "PostgresqlRuntimeProviderOperationJournal",
    "verify_runtime_provider_journal_database_role",
]
