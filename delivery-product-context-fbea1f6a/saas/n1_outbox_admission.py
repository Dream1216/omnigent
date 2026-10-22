"""Fail-closed admission for the pinned N-1 Outbox compatibility login."""

from __future__ import annotations

import os
import re
from hashlib import sha256
from typing import Never

import sqlalchemy as sa
from sqlalchemy.engine import Engine

_COMPAT_ROLE = "saas_dispatcher_n1_compat"
_BASE_ROLE = "saas_dispatcher"
_LOGIN_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,62}")
_REJECTION = "N-1 Outbox compatibility login admission rejected"
_SANITIZER_SOURCE_SHA256 = "06622ed237a21880bf84846f082deb876c3935597cd692f283d6f505cb616e3a"
_N1_OUTBOX_SELECT_COLUMNS = frozenset(
    {
        "id",
        "published_at",
        "available_at",
        "claimed_at",
        "created_at",
        "claim_token",
        "event_type",
        "aggregate_type",
        "aggregate_key",
        "payload",
        "attempt_count",
    }
)
_N1_OUTBOX_UPDATE_COLUMNS = frozenset(
    {
        "attempt_count",
        "available_at",
        "claimed_at",
        "claim_token",
        "last_error",
        "published_at",
    }
)
_N1_COLUMN_ACLS = (
    {
        ("saas_platform_role_assignments", "expires_at", "SELECT", False),
        ("saas_platform_role_assignments", "principal_id", "SELECT", False),
        ("saas_platform_role_assignments", "role", "SELECT", False),
        ("saas_platform_role_assignments", "status", "SELECT", False),
        ("saas_platform_support_sessions", "expires_at", "SELECT", False),
        ("saas_platform_support_sessions", "principal_id", "SELECT", False),
        ("saas_platform_support_sessions", "revoked_at", "SELECT", False),
        ("saas_platform_support_sessions", "token_hash", "SELECT", False),
    }
    | {
        ("saas_control_plane_outbox", column, "SELECT", False)
        for column in _N1_OUTBOX_SELECT_COLUMNS
    }
    | {
        ("saas_control_plane_outbox", column, "UPDATE", False)
        for column in _N1_OUTBOX_UPDATE_COLUMNS
    }
)
_OUTBOX_SCHEMA_SIGNATURE = [
    (1, "id", "uuid", True, None, "", ""),
    (2, "tenant_id", "uuid", False, None, "", ""),
    (3, "aggregate_type", "character varying(64)", True, None, "", ""),
    (4, "aggregate_key", "character varying(256)", True, None, "", ""),
    (5, "event_type", "character varying(128)", True, None, "", ""),
    (6, "payload", "json", True, None, "", ""),
    (7, "idempotency_key", "character varying(128)", True, None, "", ""),
    (8, "request_hash", "character varying(64)", True, None, "", ""),
    (9, "attempt_count", "integer", True, None, "", ""),
    (10, "published_at", "timestamp with time zone", False, None, "", ""),
    (11, "created_at", "timestamp with time zone", True, "now()", "", ""),
    (12, "available_at", "timestamp with time zone", False, None, "", ""),
    (13, "claimed_at", "timestamp with time zone", False, None, "", ""),
    (14, "claim_token", "uuid", False, None, "", ""),
    (15, "last_error", "character varying(2048)", False, None, "", ""),
    (16, "last_error_code", "character varying(128)", False, "NULL::character varying", "", ""),
    (17, "last_error_digest", "character varying(64)", False, "NULL::character varying", "", ""),
    (18, "quarantined_at", "timestamp with time zone", False, None, "", ""),
]


def _reject() -> Never:
    raise RuntimeError(_REJECTION) from None


def verify_n1_outbox_compatibility_schema_login(
    engine: Engine,
    *,
    expected_login: str,
) -> None:
    """Verify the schema bridge and one login without enabling production.

    ``engine`` must connect as ``expected_login`` itself.  The password or
    short-lived database credential is provisioned outside this package (for
    example by KMS/HSM-backed deployment automation); this verifier neither
    accepts nor creates it.  This proves database shape only: upstream 9451a64
    can still expose its raw ``last_error`` bind value through client logging,
    so passing this function is not production admission.  Every rejection
    uses one content-free error.
    """

    if engine.dialect.name != "postgresql" or not _LOGIN_PATTERN.fullmatch(expected_login):
        _reject()
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                sa.text(
                    "SELECT current_user, session_user, current_schema(), "
                    "current_schemas(false), "
                    "has_schema_privilege(current_user, 'public', 'CREATE')"
                )
            ).one()
            login_facts = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit "
                    "FROM pg_roles WHERE rolname = :role"
                ),
                {"role": expected_login},
            ).one_or_none()
            compat_facts = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit "
                    "FROM pg_roles WHERE rolname = :role"
                ),
                {"role": _COMPAT_ROLE},
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
                    "WHERE member.rolname = :role ORDER BY granted.rolname"
                ),
                {"role": expected_login},
            ).all()
            compat_memberships = connection.execute(
                sa.text(
                    f"SELECT {membership_projection}"
                    "FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE member.rolname = :role ORDER BY granted.rolname"
                ),
                {"role": _COMPAT_ROLE},
            ).all()
            incoming_members = connection.execute(
                sa.text(
                    "SELECT member.rolname, membership.admin_option, "
                    "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
                    "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true) "
                    "FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE granted.rolname = :role "
                    "AND (NOT membership.admin_option "
                    "OR COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true) "
                    "OR COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true)) "
                    "ORDER BY member.rolname"
                ),
                {"role": _COMPAT_ROLE},
            ).all()
            login_incoming_members = connection.execute(
                sa.text(
                    "SELECT member.rolname, membership.admin_option, "
                    "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
                    "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true) "
                    "FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE granted.rolname = :role ORDER BY member.rolname"
                ),
                {"role": expected_login},
            ).all()
            role_settings = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_db_role_setting AS setting "
                    "JOIN pg_roles AS role ON role.oid = setting.setrole "
                    "WHERE role.rolname IN (:login, :compat)"
                ),
                {"login": expected_login, "compat": _COMPAT_ROLE},
            ).scalar_one()
            authority_dependencies = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_shdepend AS dependency "
                    "JOIN pg_roles AS role ON role.oid = dependency.refobjid "
                    "WHERE dependency.refclassid = 'pg_authid'::regclass "
                    "AND dependency.deptype IN ('a', 'o') "
                    "AND role.rolname = :login"
                ),
                {"login": expected_login},
            ).scalar_one()
            outbox_privileges = connection.execute(
                sa.text(
                    "SELECT "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'SELECT'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'UPDATE'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'INSERT'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'DELETE'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'TRUNCATE'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'TRIGGER')"
                )
            ).one()
            outbox_direct_acls = connection.execute(
                sa.text(
                    "SELECT acl.privilege_type, acl.is_grantable "
                    "FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace "
                    "ON namespace.oid = relation.relnamespace "
                    "JOIN pg_roles AS compat ON compat.rolname = :compat "
                    "CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl "
                    "WHERE namespace.nspname = 'public' "
                    "AND relation.relname = 'saas_control_plane_outbox' "
                    "AND acl.grantee = compat.oid ORDER BY acl.privilege_type"
                ),
                {"compat": _COMPAT_ROLE},
            ).all()
            compat_column_acls = connection.execute(
                sa.text(
                    "SELECT relation.relname, attribute.attname, "
                    "acl.privilege_type, acl.is_grantable "
                    "FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace "
                    "ON namespace.oid = relation.relnamespace "
                    "JOIN pg_attribute AS attribute "
                    "ON attribute.attrelid = relation.oid "
                    "JOIN pg_roles AS compat ON compat.rolname = :compat "
                    "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
                    "WHERE namespace.nspname = 'public' "
                    "AND relation.relkind IN ('r', 'p') "
                    "AND left(relation.relname, 5) = 'saas_' "
                    "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
                    "AND acl.grantee = compat.oid "
                    "ORDER BY relation.relname, attribute.attname, acl.privilege_type"
                ),
                {"compat": _COMPAT_ROLE},
            ).all()
            outbox_schema_columns = connection.execute(
                sa.text(
                    "SELECT attribute.attnum, attribute.attname, "
                    "format_type(attribute.atttypid, attribute.atttypmod), "
                    "attribute.attnotnull, "
                    "pg_get_expr(default_value.adbin, default_value.adrelid), "
                    "attribute.attidentity, attribute.attgenerated "
                    "FROM pg_attribute AS attribute "
                    "LEFT JOIN pg_attrdef AS default_value "
                    "ON default_value.adrelid = attribute.attrelid "
                    "AND default_value.adnum = attribute.attnum "
                    "WHERE attribute.attrelid = "
                    "'public.saas_control_plane_outbox'::regclass "
                    "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
                    "ORDER BY attribute.attnum"
                )
            ).all()
            table_security = connection.execute(
                sa.text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid = 'public.saas_control_plane_outbox'::regclass"
                )
            ).one_or_none()
            planning_table_security = connection.execute(
                sa.text(
                    "SELECT relation.relname, relation.relrowsecurity, "
                    "relation.relforcerowsecurity FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace "
                    "ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'public' "
                    "AND relation.relname IN "
                    "('saas_platform_role_assignments', "
                    "'saas_platform_support_sessions') "
                    "ORDER BY relation.relname"
                )
            ).all()
            legacy_constraints = connection.execute(
                sa.text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'public.saas_control_plane_outbox'::regclass "
                    "AND conname = 'ck_outbox_legacy_error_null' "
                    "AND contype = 'c' AND convalidated"
                )
            ).all()
            compatibility_policies = connection.execute(
                sa.text(
                    "SELECT NOT policy.polpermissive, policy.polcmd, "
                    "cardinality(policy.polroles), compat.oid = ANY(policy.polroles), "
                    "pg_get_expr(policy.polqual, policy.polrelid), "
                    "pg_get_expr(policy.polwithcheck, policy.polrelid) "
                    "FROM pg_policy AS policy "
                    "JOIN pg_roles AS compat ON compat.rolname = :compat "
                    "WHERE policy.polrelid = "
                    "'public.saas_control_plane_outbox'::regclass "
                    "AND policy.polname = 'rls_outbox_n1_compat_dispatchable'"
                ),
                {"compat": _COMPAT_ROLE},
            ).all()
            planning_compatibility_policies = connection.execute(
                sa.text(
                    "SELECT relation.relname, policy.polname, NOT policy.polpermissive, "
                    "policy.polcmd, cardinality(policy.polroles), "
                    "compat.oid = ANY(policy.polroles), "
                    "pg_get_expr(policy.polqual, policy.polrelid), "
                    "pg_get_expr(policy.polwithcheck, policy.polrelid) "
                    "FROM pg_policy AS policy "
                    "JOIN pg_class AS relation ON relation.oid = policy.polrelid "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "JOIN pg_roles AS compat ON compat.rolname = :compat "
                    "WHERE namespace.nspname = 'public' "
                    "AND relation.relname IN "
                    "('saas_platform_role_assignments', "
                    "'saas_platform_support_sessions') "
                    "AND compat.oid = ANY(policy.polroles) "
                    "ORDER BY relation.relname, policy.polname"
                ),
                {"compat": _COMPAT_ROLE},
            ).all()
            sanitizer_functions = connection.execute(
                sa.text(
                    "SELECT sanitizer.proowner = outbox.relowner, "
                    "language.lanname, sanitizer.prosecdef, sanitizer.proleakproof, "
                    "sanitizer.provolatile, sanitizer.proparallel, sanitizer.proconfig, "
                    "sanitizer.prosrc, "
                    "(SELECT count(*) FROM aclexplode(sanitizer.proacl) AS acl "
                    "WHERE acl.grantee <> sanitizer.proowner), "
                    "has_function_privilege(compat.oid, sanitizer.oid, 'EXECUTE') "
                    "FROM pg_proc AS sanitizer "
                    "JOIN pg_language AS language ON language.oid = sanitizer.prolang "
                    "JOIN pg_class AS outbox "
                    "ON outbox.oid = 'public.saas_control_plane_outbox'::regclass "
                    "JOIN pg_roles AS compat ON compat.rolname = :compat "
                    "WHERE sanitizer.oid = "
                    "to_regprocedure('public.saas_bridge_n1_outbox_update()')"
                ),
                {"compat": _COMPAT_ROLE},
            ).all()
            before_update_triggers = connection.execute(
                sa.text(
                    "SELECT trigger.tgname, trigger.tgenabled, trigger.tgtype, "
                    "trigger.tgfoid = "
                    "to_regprocedure('public.saas_bridge_n1_outbox_update()') "
                    "FROM pg_trigger AS trigger "
                    "WHERE trigger.tgrelid = "
                    "'public.saas_control_plane_outbox'::regclass "
                    "AND NOT trigger.tgisinternal "
                    "AND (trigger.tgtype & 19) = 19 "
                    "ORDER BY trigger.tgname"
                )
            ).all()
            outbox_rewrite_rules = connection.execute(
                sa.text(
                    "SELECT rewrite.rulename FROM pg_rewrite AS rewrite "
                    "WHERE rewrite.ev_class = "
                    "'public.saas_control_plane_outbox'::regclass "
                    "AND rewrite.rulename <> '_RETURN' ORDER BY rewrite.rulename"
                )
            ).all()
            forbidden_tables = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'public' "
                    "AND relation.relkind IN ('r', 'p') "
                    "AND left(relation.relname, 5) = 'saas_' "
                    "AND relation.relname <> 'saas_control_plane_outbox' AND ("
                    "has_table_privilege(current_user, relation.oid, 'SELECT') OR "
                    "has_table_privilege(current_user, relation.oid, 'INSERT') OR "
                    "has_table_privilege(current_user, relation.oid, 'UPDATE') OR "
                    "has_table_privilege(current_user, relation.oid, 'DELETE') OR "
                    "has_table_privilege(current_user, relation.oid, 'TRUNCATE') OR "
                    "has_table_privilege(current_user, relation.oid, 'REFERENCES') OR "
                    "has_table_privilege(current_user, relation.oid, 'TRIGGER'))"
                )
            ).scalar_one()
    except Exception:  # noqa: BLE001 - all catalog/driver errors fail closed identically
        _reject()

    current_user, session_user, schema, search_path, can_create_schema = identity
    constraint_definitions = [
        re.sub(r"[\s()]", "", str(row[0])).upper() for row in legacy_constraints
    ]
    policy_facts = [
        (
            bool(row[0]),
            str(row[1]),
            int(row[2]),
            bool(row[3]),
            re.sub(r"[\s()]", "", str(row[4])).upper(),
            re.sub(r"[\s()]", "", str(row[5])).upper(),
        )
        for row in compatibility_policies
    ]
    planning_policy_facts = [
        (
            str(row[0]),
            str(row[1]),
            bool(row[2]),
            str(row[3]),
            int(row[4]),
            bool(row[5]),
            re.sub(r"[\s()]", "", str(row[6])).upper(),
            row[7] is None,
        )
        for row in planning_compatibility_policies
    ]
    sanitizer_facts = [
        (
            bool(row[0]),
            str(row[1]),
            bool(row[2]),
            bool(row[3]),
            str(row[4]),
            str(row[5]),
            list(row[6]) if row[6] is not None else None,
            sha256(str(row[7]).strip().encode()).hexdigest(),
            int(row[8]),
            bool(row[9]),
        )
        for row in sanitizer_functions
    ]
    outbox_acl_facts = [(str(row[0]), bool(row[1])) for row in outbox_direct_acls]
    compat_column_acl_facts = {
        (str(row[0]), str(row[1]), str(row[2]), bool(row[3])) for row in compat_column_acls
    }
    outbox_schema_facts = [
        (
            int(row[0]),
            str(row[1]),
            str(row[2]),
            bool(row[3]),
            None if row[4] is None else str(row[4]),
            str(row[5]),
            str(row[6]),
        )
        for row in outbox_schema_columns
    ]
    if (
        current_user != expected_login
        or session_user != expected_login
        or schema != "public"
        or list(search_path) != ["public"]
        or can_create_schema
        or login_facts != (True, False, False, False, False, False, True)
        or compat_facts != (False, False, False, False, False, False, True)
        or login_memberships != [(_COMPAT_ROLE, False, True, False)]
        or compat_memberships != [(_BASE_ROLE, False, False, False)]
        or incoming_members != [(expected_login, False, True, False)]
        or login_incoming_members
        or role_settings
        or authority_dependencies
        or outbox_privileges != (False, False, False, False, False, False)
        or outbox_acl_facts
        or compat_column_acl_facts != _N1_COLUMN_ACLS
        or len(compat_column_acl_facts) != len(_N1_COLUMN_ACLS)
        or outbox_schema_facts != _OUTBOX_SCHEMA_SIGNATURE
        or table_security != (True, True)
        or planning_table_security
        != [
            ("saas_platform_role_assignments", True, True),
            ("saas_platform_support_sessions", True, True),
        ]
        or constraint_definitions != ["CHECKLAST_ERRORISNULL"]
        or policy_facts
        != [
            (
                True,
                "*",
                1,
                True,
                "QUARANTINED_ATISNULL",
                "QUARANTINED_ATISNULL",
            )
        ]
        or planning_policy_facts
        != [
            (
                "saas_platform_role_assignments",
                "rls_n1_compat_role_assignments_deny",
                True,
                "r",
                1,
                True,
                "FALSE",
                True,
            ),
            (
                "saas_platform_support_sessions",
                "rls_n1_compat_support_sessions_deny",
                True,
                "r",
                1,
                True,
                "FALSE",
                True,
            ),
        ]
        or sanitizer_facts
        != [
            (
                True,
                "plpgsql",
                False,
                False,
                "v",
                "u",
                ["search_path=pg_catalog"],
                _SANITIZER_SOURCE_SHA256,
                0,
                False,
            )
        ]
        or before_update_triggers != [("trg_outbox_n1_compatibility", "O", 19, True)]
        or outbox_rewrite_rules
        or forbidden_tables
    ):
        _reject()


def admit_n1_outbox_compatibility_login(
    engine: Engine,
    *,
    expected_login: str,
) -> Never:
    """Refuse production enable until a patched artifact Receipt is verifiable.

    The pinned upstream 9451a64 worker logs the exception chain and SQL bind
    parameters without ``hide_parameters``, so its raw delivery error may leave
    the database client before the sanitizer runs.  A caller-provided digest or
    environment flag would be self-attestation, not artifact identity.  This
    gate therefore remains closed until an immutable patched-worker digest is
    bound to this login/credential and verified through a trusted external
    signature Receipt.
    """

    verify_n1_outbox_compatibility_schema_login(engine, expected_login=expected_login)
    _reject()


def main() -> int:
    """Verify schema shape, then refuse unreceipted production enable."""

    database_url = os.environ.get("OMNIGENT_SAAS_N1_COMPAT_DATABASE_URL", "").strip()
    expected_login = os.environ.get("OMNIGENT_SAAS_N1_COMPAT_EXPECTED_LOGIN", "").strip()
    if not database_url or not expected_login:
        _reject()
    engine: Engine | None = None
    try:
        engine = sa.create_engine(database_url, pool_pre_ping=True)
        admit_n1_outbox_compatibility_login(engine, expected_login=expected_login)
    except Exception:  # noqa: BLE001 - never expose a credential-bearing URL
        _reject()
    finally:
        if engine is not None:
            engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
