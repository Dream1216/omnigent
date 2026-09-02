"""Least-privilege production PostgreSQL migration orchestration.

The migration job deliberately uses four direct LOGIN identities.  Cluster
principals, database authority, official schema ownership, and SaaS schema
ownership are separate trust boundaries; application processes must not reuse
any of these URLs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, cast

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

from omnigent.db import ConversationBase, OmnigentBase
from saas.runtime_rls import install_runtime_rls, load_runtime_rls_contract, verify_runtime_rls

from .service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBindings,
)

AuthorityKind = Literal[
    "principal_operator",
    "database_owner",
    "official_owner",
    "saas_owner",
]

_AUTHORITY_KINDS: tuple[AuthorityKind, ...] = (
    "principal_operator",
    "database_owner",
    "official_owner",
    "saas_owner",
)
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_ALLOWED_QUERY_KEYS = frozenset(
    {
        "application_name",
        "connect_timeout",
        "sslcert",
        "sslkey",
        "sslmode",
        "sslrootcert",
        "target_session_attrs",
    }
)
_LOCK_NAME = "omnigent-saas-production-postgresql-migration-v1"
_RUNTIME_ROLE = "omnigent_runtime_app"
_SERVER_SERVICE_ROLES = {
    "runtime": _RUNTIME_ROLE,
    "authenticator": "saas_authenticator",
    "app": "saas_app",
    "governance": "saas_governance",
    "public_api": "saas_public_api",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECEIPT_BYTES = 16 * 1024
_PG_TRGM_VERSION = "1.6"
_PG_TRGM_INDEXES = {
    "ix_conversation_items_search_text_trgm": (
        "conversation_items",
        "lower(search_text)",
    ),
    "ix_conversations_title_trgm": ("conversations", "lower((title)::text)"),
}
_PG_TRGM_MEMBER_IDENTITIES = (
    ("pg_opclass", "operator class gin_trgm_ops for access method gin"),
    ("pg_opclass", "operator class gist_trgm_ops for access method gist"),
    ("pg_operator", "operator %(text,text)"),
    ("pg_operator", "operator %>(text,text)"),
    ("pg_operator", "operator %>>(text,text)"),
    ("pg_operator", "operator <%(text,text)"),
    ("pg_operator", "operator <->(text,text)"),
    ("pg_operator", "operator <->>(text,text)"),
    ("pg_operator", "operator <->>>(text,text)"),
    ("pg_operator", "operator <<%(text,text)"),
    ("pg_operator", "operator <<->(text,text)"),
    ("pg_operator", "operator <<<->(text,text)"),
    ("pg_opfamily", "operator family gin_trgm_ops for access method gin"),
    ("pg_opfamily", "operator family gist_trgm_ops for access method gist"),
    (
        "pg_proc",
        "function gin_extract_query_trgm(text,internal,smallint,internal,internal,"
        "internal,internal)",
    ),
    ("pg_proc", "function gin_extract_value_trgm(text,internal)"),
    (
        "pg_proc",
        "function gin_trgm_consistent(internal,smallint,text,integer,internal,internal,"
        "internal,internal)",
    ),
    (
        "pg_proc",
        "function gin_trgm_triconsistent(internal,smallint,text,integer,internal,internal,"
        "internal)",
    ),
    ("pg_proc", "function gtrgm_compress(internal)"),
    ("pg_proc", "function gtrgm_consistent(internal,text,smallint,oid,internal)"),
    ("pg_proc", "function gtrgm_decompress(internal)"),
    ("pg_proc", "function gtrgm_distance(internal,text,smallint,oid,internal)"),
    ("pg_proc", "function gtrgm_in(cstring)"),
    ("pg_proc", "function gtrgm_options(internal)"),
    ("pg_proc", "function gtrgm_out(gtrgm)"),
    ("pg_proc", "function gtrgm_penalty(internal,internal,internal)"),
    ("pg_proc", "function gtrgm_picksplit(internal,internal)"),
    ("pg_proc", "function gtrgm_same(gtrgm,gtrgm,internal)"),
    ("pg_proc", "function gtrgm_union(internal,internal)"),
    ("pg_proc", "function set_limit(real)"),
    ("pg_proc", "function show_limit()"),
    ("pg_proc", "function show_trgm(text)"),
    ("pg_proc", "function similarity(text,text)"),
    ("pg_proc", "function similarity_dist(text,text)"),
    ("pg_proc", "function similarity_op(text,text)"),
    ("pg_proc", "function strict_word_similarity(text,text)"),
    ("pg_proc", "function strict_word_similarity_commutator_op(text,text)"),
    ("pg_proc", "function strict_word_similarity_dist_commutator_op(text,text)"),
    ("pg_proc", "function strict_word_similarity_dist_op(text,text)"),
    ("pg_proc", "function strict_word_similarity_op(text,text)"),
    ("pg_proc", "function word_similarity(text,text)"),
    ("pg_proc", "function word_similarity_commutator_op(text,text)"),
    ("pg_proc", "function word_similarity_dist_commutator_op(text,text)"),
    ("pg_proc", "function word_similarity_dist_op(text,text)"),
    ("pg_proc", "function word_similarity_op(text,text)"),
    ("pg_type", "type gtrgm"),
)
_PG_TRGM_MEMBER_IDENTITIES_BY_MAJOR = {
    16: _PG_TRGM_MEMBER_IDENTITIES,
    # PostgreSQL 18 records the extension-owned array type explicitly.
    18: (*_PG_TRGM_MEMBER_IDENTITIES, ("pg_type", "type gtrgm[]")),
}
_PG_TRGM_FUNCTION_CONTRACTS = {
    (
        "gin_extract_query_trgm",
        "text, internal, smallint, internal, internal, internal, internal",
    ): ("internal", "i", True, "s"),
    ("gin_extract_value_trgm", "text, internal"): ("internal", "i", True, "s"),
    (
        "gin_trgm_consistent",
        "internal, smallint, text, integer, internal, internal, internal, internal",
    ): ("boolean", "i", True, "s"),
    (
        "gin_trgm_triconsistent",
        "internal, smallint, text, integer, internal, internal, internal",
    ): ('"char"', "i", True, "s"),
    ("gtrgm_compress", "internal"): ("internal", "i", True, "s"),
    ("gtrgm_consistent", "internal, text, smallint, oid, internal"): ("boolean", "i", True, "s"),
    ("gtrgm_decompress", "internal"): ("internal", "i", True, "s"),
    ("gtrgm_distance", "internal, text, smallint, oid, internal"): (
        "double precision",
        "i",
        True,
        "s",
    ),
    ("gtrgm_in", "cstring"): ("gtrgm", "i", True, "s"),
    ("gtrgm_options", "internal"): ("void", "i", False, "s"),
    ("gtrgm_out", "gtrgm"): ("cstring", "i", True, "s"),
    ("gtrgm_penalty", "internal, internal, internal"): ("internal", "i", True, "s"),
    ("gtrgm_picksplit", "internal, internal"): ("internal", "i", True, "s"),
    ("gtrgm_same", "gtrgm, gtrgm, internal"): ("internal", "i", True, "s"),
    ("gtrgm_union", "internal, internal"): ("gtrgm", "i", True, "s"),
    ("set_limit", "real"): ("real", "v", True, "u"),
    ("show_limit", ""): ("real", "s", True, "s"),
    ("show_trgm", "text"): ("text[]", "i", True, "s"),
    ("similarity", "text, text"): ("real", "i", True, "s"),
    ("similarity_dist", "text, text"): ("real", "i", True, "s"),
    ("similarity_op", "text, text"): ("boolean", "s", True, "s"),
    ("strict_word_similarity", "text, text"): ("real", "i", True, "s"),
    ("strict_word_similarity_commutator_op", "text, text"): ("boolean", "s", True, "s"),
    ("strict_word_similarity_dist_commutator_op", "text, text"): ("real", "i", True, "s"),
    ("strict_word_similarity_dist_op", "text, text"): ("real", "i", True, "s"),
    ("strict_word_similarity_op", "text, text"): ("boolean", "s", True, "s"),
    ("word_similarity", "text, text"): ("real", "i", True, "s"),
    ("word_similarity_commutator_op", "text, text"): ("boolean", "s", True, "s"),
    ("word_similarity_dist_commutator_op", "text, text"): ("real", "i", True, "s"),
    ("word_similarity_dist_op", "text, text"): ("real", "i", True, "s"),
    ("word_similarity_op", "text, text"): ("boolean", "s", True, "s"),
}
_PG_TRGM_OPCLASS_CONTRACTS = {
    ("gin_trgm_ops", "gin", "gin_trgm_ops", "text", "integer", False),
    ("gist_trgm_ops", "gist", "gist_trgm_ops", "text", "gtrgm", False),
}
# Generated from a clean, source-controlled official+SaaS Alembic replay.  The
# key binds the only supported PostgreSQL majors and both migration heads; the
# digest is deliberately not learned from a privileged migration receipt.
_PUBLIC_SCHEMA_INVENTORY_SHA256 = {
    (
        16,
        "e5d9bc8ac650",
        "p0s000000010",
    ): "3cb5ec014f391ecd3ddd30af9d6372582bb70d4c2060f1782dcc6248bb719c2b",
    (
        18,
        "e5d9bc8ac650",
        "p0s000000010",
    ): "f48b8e306eedd550140e5d3ed956ad84ea4bf5b0649e779aff81bce749343d71",
}
_SOURCE_SECURITY_CATALOG_SHA256 = {
    (
        16,
        "e5d9bc8ac650",
        "p0s000000010",
    ): "b0fc13c0021ad3350c7f3c89f857292b3d19972314d9c9633c60804bfed61a52",
    (
        18,
        "e5d9bc8ac650",
        "p0s000000010",
    ): "dc2193af26cdbb9e2c082ecfb900cd34885ac8490e75f6c0ffb21352c2c46256",
}
_CAPABILITY_ROLES = (
    "saas_app",
    "saas_authenticator",
    "saas_governance",
    "saas_dispatcher",
    "saas_dispatcher_n1_compat",
    "saas_executor",
    "saas_runner_agent",
    "saas_secret_broker",
    "saas_preview_gateway",
    "saas_preview_edge",
    "saas_preview_owner",
    "saas_webhook_dispatcher",
    "saas_billing",
    "saas_metering",
    "saas_public_api",
    "saas_platform",
    "saas_platform_authenticator",
    "saas_platform_app",
    "saas_platform_governance",
    "saas_platform_projector",
    "saas_platform_support",
    "saas_privacy_executor",
    "saas_privacy_dispatcher",
    "saas_privacy_verifier",
    "saas_notification_scheduler",
    "saas_notification_dispatcher",
    "saas_notification_directory",
    "saas_approval_scheduler_enterprise",
    "saas_approval_scheduler_privacy",
    "saas_approval_scheduler_audit",
    "saas_approval_scheduler_support_customer",
    "saas_approval_scheduler_support_staff",
    "saas_registration",
    "saas_onboarding",
    "saas_onboarding_status",
    "saas_runtime_provider_journal",
    _RUNTIME_ROLE,
)
_RoleGraphEdge = tuple[str, str, str, bool, bool, bool, int]


class PostgreSqlMigrationError(RuntimeError):
    """A content-free production migration rejection."""

    def __init__(self, code: str, phase: str) -> None:
        self.code = code
        self.phase = phase
        super().__init__(f"PostgreSQL migration rejected: phase={phase}; code={code}")


@dataclass(frozen=True, slots=True, repr=False)
class PostgreSqlAuthority:
    """One redacted direct-login PostgreSQL authority."""

    kind: AuthorityKind
    url: URL
    login: str

    def redacted_url(self) -> str:
        return self.url.render_as_string(hide_password=True)


@dataclass(frozen=True, slots=True, repr=False)
class ProductionPostgreSqlPlan:
    """Four-authority plan for one exact product and database target."""

    product_revision: str
    principal_operator: PostgreSqlAuthority
    database_owner: PostgreSqlAuthority
    official_owner: PostgreSqlAuthority
    saas_owner: PostgreSqlAuthority
    service_role_bindings: ProductionServiceRoleBindings
    require_tls: bool = True
    lock_timeout_seconds: float = 30.0

    @classmethod
    def from_urls(
        cls,
        *,
        product_revision: str,
        principal_operator_url: str,
        database_owner_url: str,
        official_owner_url: str,
        saas_owner_url: str,
        service_role_bindings: ProductionServiceRoleBindings,
        require_tls: bool = True,
        lock_timeout_seconds: float = 30.0,
    ) -> ProductionPostgreSqlPlan:
        return cls(
            product_revision=product_revision,
            principal_operator=parse_production_postgresql_url(
                principal_operator_url,
                kind="principal_operator",
                require_tls=require_tls,
            ),
            database_owner=parse_production_postgresql_url(
                database_owner_url,
                kind="database_owner",
                require_tls=require_tls,
            ),
            official_owner=parse_production_postgresql_url(
                official_owner_url,
                kind="official_owner",
                require_tls=require_tls,
            ),
            saas_owner=parse_production_postgresql_url(
                saas_owner_url,
                kind="saas_owner",
                require_tls=require_tls,
            ),
            service_role_bindings=service_role_bindings,
            require_tls=require_tls,
            lock_timeout_seconds=lock_timeout_seconds,
        )

    def authorities(self) -> tuple[PostgreSqlAuthority, ...]:
        return (
            self.principal_operator,
            self.database_owner,
            self.official_owner,
            self.saas_owner,
        )


@dataclass(frozen=True, slots=True)
class PostgreSqlMigrationReceipt:
    """Secret-free database state emitted only after complete verification."""

    schema_version: int
    status: str
    verify_only: bool
    product_revision: str
    database_identity_sha256: str
    official_head: str
    saas_head: str
    runtime_rls_table_count: int
    authorities: tuple[tuple[str, str], ...]
    phases: tuple[str, ...]
    catalog_sha256: str
    service_role_bindings_sha256: str
    completed_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "verify_only": self.verify_only,
            "product_revision": self.product_revision,
            "database_identity_sha256": self.database_identity_sha256,
            "official_head": self.official_head,
            "saas_head": self.saas_head,
            "runtime_rls_table_count": self.runtime_rls_table_count,
            "authorities": [{"kind": kind, "login": login} for kind, login in self.authorities],
            "phases": list(self.phases),
            "catalog_sha256": self.catalog_sha256,
            "service_role_bindings_sha256": self.service_role_bindings_sha256,
            "completed_at": self.completed_at,
        }


@dataclass(frozen=True, slots=True)
class _SessionFacts:
    kind: AuthorityKind
    login: str
    database: str
    database_oid: int
    database_owner: str
    server_version_num: int
    server_address: str
    server_port: int
    tls: bool


@dataclass(frozen=True, slots=True)
class _VerifiedState:
    official_head: str
    saas_head: str
    runtime_rls_table_count: int
    catalog_sha256: str


@dataclass(frozen=True, slots=True)
class _ServiceSessionFacts:
    login: str
    database: str
    database_oid: int
    database_owner: str
    server_version_num: int
    server_address: str
    server_port: int


@dataclass(frozen=True, slots=True)
class _RuntimeReceipt:
    product_revision: str
    official_head: str
    saas_head: str
    database_identity_sha256: str
    catalog_sha256: str
    service_role_bindings_sha256: str
    runtime_rls_table_count: int
    official_owner: str
    saas_owner: str
    principal_operator: str
    database_owner: str


def parse_production_postgresql_url(
    raw_url: str,
    *,
    kind: AuthorityKind,
    require_tls: bool = True,
) -> PostgreSqlAuthority:
    """Parse one explicit TCP psycopg URL without exposing its password."""

    if kind not in _AUTHORITY_KINDS:
        raise PostgreSqlMigrationError("authority_kind_invalid", "configuration")
    try:
        url = make_url(raw_url)
    except (TypeError, ValueError, sa.exc.ArgumentError):
        raise PostgreSqlMigrationError("authority_url_invalid", "configuration") from None
    if url.drivername != "postgresql+psycopg":
        raise PostgreSqlMigrationError("postgresql_psycopg_required", "configuration")
    if not url.username or not url.host or not url.port or not url.database:
        raise PostgreSqlMigrationError("authority_tcp_target_required", "configuration")
    if _ROLE_NAME.fullmatch(url.username) is None:
        raise PostgreSqlMigrationError("authority_login_invalid", "configuration")
    query_keys = frozenset(str(key) for key in url.query)
    if not query_keys.issubset(_ALLOWED_QUERY_KEYS):
        raise PostgreSqlMigrationError("authority_query_option_forbidden", "configuration")
    if any(isinstance(value, tuple) for value in url.query.values()):
        raise PostgreSqlMigrationError("authority_query_option_ambiguous", "configuration")
    sslmode = url.query.get("sslmode")
    if require_tls and sslmode != "verify-full":
        raise PostgreSqlMigrationError("authority_tls_verify_full_required", "configuration")
    target_session_attrs = url.query.get("target_session_attrs")
    if target_session_attrs is not None and target_session_attrs != "read-write":
        raise PostgreSqlMigrationError("authority_read_write_target_required", "configuration")
    return PostgreSqlAuthority(kind=kind, url=url, login=url.username)


def _installed_product_revision() -> str:
    try:
        from omnigent import _build_info

        value = _build_info.COMMIT_SHA
    except (AttributeError, ImportError):
        return ""
    return value if isinstance(value, str) else ""


def _validate_plan(plan: ProductionPostgreSqlPlan) -> None:
    if _FULL_GIT_SHA.fullmatch(plan.product_revision) is None:
        raise PostgreSqlMigrationError("product_revision_invalid", "configuration")
    if _installed_product_revision() != plan.product_revision:
        raise PostgreSqlMigrationError("installed_product_revision_mismatch", "configuration")
    if not 0 < plan.lock_timeout_seconds <= 300:
        raise PostgreSqlMigrationError("lock_timeout_invalid", "configuration")
    authorities = plan.authorities()
    if tuple(authority.kind for authority in authorities) != _AUTHORITY_KINDS:
        raise PostgreSqlMigrationError("authority_order_invalid", "configuration")
    logins = [authority.login for authority in authorities]
    if len(set(logins)) != len(logins):
        raise PostgreSqlMigrationError("authority_logins_not_distinct", "configuration")
    bindings = plan.service_role_bindings.bindings
    if (
        {binding.service: binding.base_role for binding in bindings}
        != dict(EXPECTED_PRODUCTION_SERVICE_ROLES)
        or len({binding.login for binding in bindings}) != len(bindings)
        or any(binding.login in _CAPABILITY_ROLES for binding in bindings)
        or set(logins) & {binding.login for binding in bindings}
        or _SHA256.fullmatch(plan.service_role_bindings.sha256) is None
    ):
        raise PostgreSqlMigrationError("service_role_bindings_invalid", "configuration")
    targets = {
        (
            authority.url.drivername,
            (authority.url.host or "").lower().rstrip("."),
            authority.url.port,
            authority.url.database,
        )
        for authority in authorities
    }
    if len(targets) != 1:
        raise PostgreSqlMigrationError("authority_targets_differ", "configuration")


def _create_engines(plan: ProductionPostgreSqlPlan) -> dict[AuthorityKind, Engine]:
    return {
        authority.kind: sa.create_engine(
            authority.url,
            pool_pre_ping=True,
            poolclass=NullPool,
        )
        for authority in plan.authorities()
    }


def _dispose_engines(engines: Mapping[AuthorityKind, Engine]) -> None:
    for engine in engines.values():
        engine.dispose()


def _authority_memberships_are_safe(
    kind: AuthorityKind,
    outgoing: tuple[tuple[str, bool, bool, bool], ...],
    incoming_count: int,
) -> bool:
    if incoming_count != 0:
        return False
    if kind != "principal_operator":
        return not outgoing
    role_names = [row[0] for row in outgoing]
    return (
        len(role_names) == len(set(role_names))
        and all(role_name in _CAPABILITY_ROLES for role_name in role_names)
        and all(admin and not inherit and not can_set for _, admin, inherit, can_set in outgoing)
    )


def _inspect_authority(
    engine: Engine,
    authority: PostgreSqlAuthority,
    *,
    require_tls: bool,
) -> _SessionFacts:
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                sa.text(
                    "SELECT current_user, session_user, current_database(), "
                    "current_schema(), current_schemas(false), database.oid, "
                    "pg_get_userbyid(database.datdba), "
                    "current_setting('server_version_num')::integer, "
                    "COALESCE(inet_server_addr()::text, ''), "
                    "COALESCE(inet_server_port(), 0), pg_is_in_recovery(), "
                    "COALESCE(ssl.ssl, false) "
                    "FROM pg_database AS database "
                    "LEFT JOIN pg_stat_ssl AS ssl ON ssl.pid = pg_backend_pid() "
                    "WHERE database.datname = current_database()"
                )
            ).one()
            role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            ).one_or_none()
            role_settings = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_db_role_setting AS setting "
                    "JOIN pg_roles AS role ON role.oid = setting.setrole "
                    "WHERE role.rolname = current_user"
                )
            ).scalar_one()
            outgoing_memberships = tuple(
                (
                    str(row[0]),
                    bool(row[1]),
                    bool(row[2]),
                    bool(row[3]),
                )
                for row in connection.execute(
                    sa.text(
                        "SELECT granted.rolname, membership.admin_option, "
                        "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, false), "
                        "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, false) "
                        "FROM pg_auth_members AS membership "
                        "JOIN pg_roles AS member ON member.oid = membership.member "
                        "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                        "WHERE member.rolname = current_user ORDER BY granted.rolname"
                    )
                ).all()
            )
            incoming_memberships = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS role ON role.oid = membership.roleid "
                    "WHERE role.rolname = current_user"
                )
            ).scalar_one()
    except sa.exc.SQLAlchemyError:
        raise PostgreSqlMigrationError("authority_connection_failed", "preflight") from None

    (
        current_user,
        session_user,
        database,
        current_schema,
        search_path,
        database_oid,
        database_owner,
        server_version_num,
        server_address,
        server_port,
        in_recovery,
        tls,
    ) = identity
    if current_user != authority.login or session_user != authority.login:
        raise PostgreSqlMigrationError("authority_session_identity_mismatch", "preflight")
    schemas = list(search_path)
    if authority.kind == "principal_operator":
        schema_target_safe = (current_schema is None and schemas == []) or (
            current_schema == "public" and schemas == ["public"]
        )
    else:
        schema_target_safe = current_schema == "public" and schemas == ["public"]
    if database != authority.url.database or not schema_target_safe:
        raise PostgreSqlMigrationError("authority_session_target_mismatch", "preflight")
    if in_recovery:
        raise PostgreSqlMigrationError("authority_target_is_read_only", "preflight")
    if require_tls and not tls:
        raise PostgreSqlMigrationError("authority_tls_not_active", "preflight")
    if (
        role is None
        or role_settings != 0
        or not _authority_memberships_are_safe(
            authority.kind,
            outgoing_memberships,
            int(incoming_memberships),
        )
    ):
        raise PostgreSqlMigrationError("authority_role_graph_unsafe", "preflight")
    (
        can_login,
        is_superuser,
        can_create_database,
        can_create_role,
        can_replicate,
        bypasses_rls,
        inherits_roles,
        connection_limit,
        role_config,
    ) = role
    common_safe = (
        can_login
        and not is_superuser
        and not can_replicate
        and not bypasses_rls
        and inherits_roles
        and connection_limit == -1
        and role_config is None
    )
    if authority.kind == "principal_operator":
        role_safe = common_safe and can_create_role and not can_create_database
    else:
        role_safe = common_safe and not can_create_role and not can_create_database
    if not role_safe:
        raise PostgreSqlMigrationError("authority_role_flags_unsafe", "preflight")
    if authority.kind == "database_owner":
        if database_owner != authority.login:
            raise PostgreSqlMigrationError("database_owner_identity_mismatch", "preflight")
    elif database_owner == authority.login:
        raise PostgreSqlMigrationError("authority_owns_database_unexpectedly", "preflight")
    return _SessionFacts(
        kind=authority.kind,
        login=authority.login,
        database=str(database),
        database_oid=int(database_oid),
        database_owner=str(database_owner),
        server_version_num=int(server_version_num),
        server_address=str(server_address),
        server_port=int(server_port),
        tls=bool(tls),
    )


def _preflight(
    plan: ProductionPostgreSqlPlan,
    engines: Mapping[AuthorityKind, Engine],
) -> tuple[_SessionFacts, ...]:
    facts = tuple(
        _inspect_authority(
            engines[authority.kind],
            authority,
            require_tls=plan.require_tls,
        )
        for authority in plan.authorities()
    )
    identities = {
        (
            item.database,
            item.database_oid,
            item.database_owner,
            item.server_version_num,
            item.server_address,
            item.server_port,
        )
        for item in facts
    }
    if len(identities) != 1:
        raise PostgreSqlMigrationError("authority_database_identity_drift", "preflight")
    if any(item.server_version_num < 160000 for item in facts):
        raise PostgreSqlMigrationError("postgresql_16_required", "preflight")
    if any(not item.server_address or item.server_port <= 0 for item in facts):
        raise PostgreSqlMigrationError("authority_server_identity_missing", "preflight")
    return facts


def _read_resource(package: str, name: str) -> str:
    return files(package).joinpath(name).read_text(encoding="utf-8")


def _verify_capability_principal_flags(
    connection: Connection,
    *,
    require_complete: bool,
) -> None:
    rows = connection.execute(
        sa.text(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
            "FROM pg_roles WHERE rolname = ANY(:roles) ORDER BY rolname"
        ),
        {"roles": list(_CAPABILITY_ROLES)},
    ).all()
    expected_flags = (False, False, False, False, False, False, True, -1, None)
    if (require_complete and len(rows) != len(_CAPABILITY_ROLES)) or any(
        tuple(row[1:]) != expected_flags for row in rows
    ):
        raise PostgreSqlMigrationError("capability_principal_projection_failed", "principals")


def _verify_service_principal_graph(
    connection: Connection,
    *,
    bindings: ProductionServiceRoleBindings,
    principal_operator: str,
    require_complete: bool,
) -> None:
    """Verify the complete cluster role boundary for production services."""

    service_logins = [binding.login for binding in bindings.bindings]
    login_rows = connection.execute(
        sa.text(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
            "FROM pg_roles WHERE rolname = ANY(:logins) ORDER BY rolname"
        ),
        {"logins": service_logins},
    ).all()
    expected_login_flags = (True, False, False, False, False, False, True, -1, None)
    if len(login_rows) != len(service_logins) or any(
        tuple(row[1:]) != expected_login_flags for row in login_rows
    ):
        raise PostgreSqlMigrationError("service_login_projection_failed", "principals")

    direct_authority = connection.execute(
        sa.text(
            "WITH service_login AS (SELECT oid FROM pg_roles WHERE rolname = ANY(:logins)), "
            "authority AS ("
            "SELECT 1 FROM pg_db_role_setting object JOIN service_login login "
            "ON object.setrole = login.oid UNION ALL "
            "SELECT 1 FROM pg_database object JOIN service_login login "
            "ON object.datdba = login.oid UNION ALL "
            "SELECT 1 FROM pg_namespace object JOIN service_login login "
            "ON object.nspowner = login.oid UNION ALL "
            "SELECT 1 FROM pg_class object JOIN service_login login "
            "ON object.relowner = login.oid UNION ALL "
            "SELECT 1 FROM pg_proc object JOIN service_login login "
            "ON object.proowner = login.oid UNION ALL "
            "SELECT 1 FROM pg_type object JOIN service_login login "
            "ON object.typowner = login.oid UNION ALL "
            "SELECT 1 FROM pg_default_acl object JOIN service_login login "
            "ON object.defaclrole = login.oid UNION ALL "
            "SELECT 1 FROM pg_database object CROSS JOIN LATERAL "
            "aclexplode(object.datacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_namespace object CROSS JOIN LATERAL "
            "aclexplode(object.nspacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_class object CROSS JOIN LATERAL "
            "aclexplode(object.relacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_attribute object CROSS JOIN LATERAL "
            "aclexplode(object.attacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid WHERE object.attnum > 0 "
            "AND NOT object.attisdropped UNION ALL "
            "SELECT 1 FROM pg_proc object CROSS JOIN LATERAL "
            "aclexplode(object.proacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_type object CROSS JOIN LATERAL "
            "aclexplode(object.typacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid UNION ALL "
            "SELECT 1 FROM pg_default_acl object CROSS JOIN LATERAL "
            "aclexplode(object.defaclacl) acl JOIN service_login login "
            "ON acl.grantee = login.oid) SELECT count(*) FROM authority"
        ),
        {"logins": service_logins},
    ).scalar_one()
    if direct_authority:
        raise PostgreSqlMigrationError("service_login_direct_authority", "principals")

    managed_roles = [*_CAPABILITY_ROLES, *service_logins, principal_operator]
    observed = {
        (
            str(granted),
            str(member),
            str(grantor),
            bool(admin),
            bool(inherit),
            bool(can_set),
            int(grantor_oid),
        )
        for granted, member, grantor, admin, inherit, can_set, grantor_oid in connection.execute(
            sa.text(
                "SELECT granted.rolname, member.rolname, grantor.rolname, "
                "membership.admin_option, "
                "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
                "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true), "
                "membership.grantor "
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS grantor ON grantor.oid = membership.grantor "
                "WHERE granted.rolname = ANY(:managed) OR member.rolname = ANY(:managed) "
                "ORDER BY 1, 2, 3"
            ),
            {"managed": managed_roles},
        ).all()
    }
    principal_operator_oid = int(
        connection.execute(
            sa.text("SELECT oid FROM pg_roles WHERE rolname = :principal_operator"),
            {"principal_operator": principal_operator},
        ).scalar_one()
    )
    bootstrap_name = connection.execute(
        sa.text("SELECT rolname FROM pg_roles WHERE oid = 10")
    ).scalar_one_or_none()
    if not bootstrap_name:
        raise PostgreSqlMigrationError("bootstrap_principal_missing", "principals")
    expected_complete = _expected_service_principal_graph(
        bindings=bindings,
        principal_operator=principal_operator,
        principal_operator_oid=principal_operator_oid,
        bootstrap_name=str(bootstrap_name),
    )
    if not _role_graph_projection_is_safe(
        observed,
        expected=expected_complete,
        require_complete=require_complete,
    ):
        raise PostgreSqlMigrationError("service_role_graph_drifted", "principals")


def _expected_service_principal_graph(
    *,
    bindings: ProductionServiceRoleBindings,
    principal_operator: str,
    principal_operator_oid: int,
    bootstrap_name: str,
) -> set[_RoleGraphEdge]:
    """Return the exact terminal role graph and each edge's real grantor."""

    service_edges: set[_RoleGraphEdge] = {
        (
            binding.base_role,
            binding.login,
            principal_operator,
            False,
            True,
            False,
            principal_operator_oid,
        )
        for binding in bindings.bindings
    }
    fixed_edges: set[_RoleGraphEdge] = {
        (
            "saas_dispatcher",
            "saas_dispatcher_n1_compat",
            principal_operator,
            False,
            False,
            False,
            principal_operator_oid,
        ),
        (
            "saas_platform_governance",
            "saas_privacy_executor",
            principal_operator,
            False,
            True,
            True,
            principal_operator_oid,
        ),
    }
    management_edges: set[_RoleGraphEdge] = {
        (
            role_name,
            principal_operator,
            bootstrap_name,
            True,
            False,
            False,
            10,
        )
        for role_name in _CAPABILITY_ROLES
    }
    return service_edges | fixed_edges | management_edges


def _role_graph_projection_is_safe(
    observed: set[_RoleGraphEdge],
    *,
    expected: set[_RoleGraphEdge],
    require_complete: bool,
) -> bool:
    """Allow a clean/bootstrap subset preflight, but require exact terminal state."""

    return observed.issubset(expected) and (not require_complete or observed == expected)


def _verify_capability_principals(
    connection: Connection,
    *,
    bindings: ProductionServiceRoleBindings,
    principal_operator: str,
) -> None:
    _verify_capability_principal_flags(connection, require_complete=True)
    _verify_service_principal_graph(
        connection,
        bindings=bindings,
        principal_operator=principal_operator,
        require_complete=True,
    )


def _apply_principals(
    engine: Engine,
    *,
    bindings: ProductionServiceRoleBindings,
    principal_operator: str,
) -> None:
    with engine.begin() as connection:
        _verify_capability_principal_flags(connection, require_complete=False)
        _verify_service_principal_graph(
            connection,
            bindings=bindings,
            principal_operator=principal_operator,
            require_complete=False,
        )
        connection.exec_driver_sql(
            _read_resource("saas.control_plane", "postgresql_principals.sql")
        )
        quote = connection.dialect.identifier_preparer.quote
        for binding in bindings.bindings:
            connection.exec_driver_sql(
                f"GRANT {quote(binding.base_role)} TO {quote(binding.login)} "
                "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            )
        _verify_capability_principals(
            connection,
            bindings=bindings,
            principal_operator=principal_operator,
        )


def _database_acl_projection(
    connection: Connection,
) -> set[tuple[str, str, str, bool]]:
    return {
        (str(grantee), str(grantor), str(privilege), bool(grantable))
        for grantee, grantor, privilege, grantable in connection.execute(
            sa.text(
                "SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
                "ELSE pg_get_userbyid(acl.grantee) END, "
                "pg_get_userbyid(acl.grantor), acl.privilege_type, acl.is_grantable "
                "FROM pg_database AS database CROSS JOIN LATERAL "
                "aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) acl "
                "WHERE database.datname = current_database()"
            )
        ).all()
    }


def _schema_acl_projection(
    connection: Connection,
) -> set[tuple[str, str, str, bool]]:
    return {
        (str(grantee), str(grantor), str(privilege), bool(grantable))
        for grantee, grantor, privilege, grantable in connection.execute(
            sa.text(
                "SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
                "ELSE pg_get_userbyid(acl.grantee) END, "
                "pg_get_userbyid(acl.grantor), acl.privilege_type, acl.is_grantable "
                "FROM pg_namespace AS namespace CROSS JOIN LATERAL "
                "aclexplode(COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))) acl "
                "WHERE namespace.nspname = 'public'"
            )
        ).all()
    }


def _public_schema_owner(connection: Connection) -> str:
    owner = connection.execute(
        sa.text(
            "SELECT pg_get_userbyid(namespace.nspowner) FROM pg_namespace AS namespace "
            "WHERE namespace.nspname = 'public'"
        )
    ).scalar_one_or_none()
    if not owner:
        raise PostgreSqlMigrationError("public_schema_owner_missing", "database")
    return str(owner)


def _preflight_database_acl_grantors(connection: Connection) -> None:
    unsafe = connection.execute(
        sa.text(
            "SELECT count(*) FROM ("
            "SELECT 1 FROM pg_database AS database CROSS JOIN LATERAL "
            "aclexplode(database.datacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE database.datname = current_database() "
            "AND acl.grantee <> database.datdba AND (acl.grantor <> database.datdba "
            "OR (acl.grantee <> 0 AND grantee.oid IS NULL)) UNION ALL "
            "SELECT 1 FROM pg_namespace AS namespace CROSS JOIN LATERAL "
            "aclexplode(namespace.nspacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND acl.grantee <> namespace.nspowner AND (acl.grantor <> namespace.nspowner "
            "OR (acl.grantee <> 0 AND grantee.oid IS NULL))) unsafe"
        )
    ).scalar_one()
    if unsafe:
        raise PostgreSqlMigrationError("database_foreign_grantor_drifted", "database")


def _owned_object_acl_grantees(
    connection: Connection,
    *,
    official_owner: str,
    saas_owner: str,
) -> set[str]:
    """Return exact capability roles that need public schema USAGE."""

    rows = connection.execute(
        sa.text(
            "WITH owner_roles AS (SELECT oid FROM pg_roles WHERE rolname = ANY(:owners)), "
            "grantee AS ("
            "SELECT acl.grantee FROM pg_class object JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace JOIN owner_roles owner "
            "ON owner.oid = object.relowner CROSS JOIN LATERAL aclexplode(object.relacl) acl "
            "WHERE namespace.nspname = 'public' AND acl.grantee <> object.relowner UNION "
            "SELECT acl.grantee FROM pg_attribute attribute JOIN pg_class object "
            "ON object.oid = attribute.attrelid JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace JOIN owner_roles owner "
            "ON owner.oid = object.relowner CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
            "WHERE namespace.nspname = 'public' AND attribute.attnum > 0 "
            "AND NOT attribute.attisdropped AND acl.grantee <> object.relowner UNION "
            "SELECT acl.grantee FROM pg_proc object JOIN pg_namespace namespace "
            "ON namespace.oid = object.pronamespace JOIN owner_roles owner "
            "ON owner.oid = object.proowner CROSS JOIN LATERAL "
            "aclexplode(COALESCE(object.proacl, acldefault('f', object.proowner))) acl "
            "WHERE namespace.nspname = 'public' AND acl.grantee <> object.proowner) "
            "SELECT CASE WHEN grantee.grantee = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(grantee.grantee) END FROM grantee ORDER BY 1"
        ),
        {"owners": [official_owner, saas_owner]},
    ).scalars()
    grantees = {str(role) for role in rows}
    if "PUBLIC" in grantees or not grantees.issubset(_CAPABILITY_ROLES):
        raise PostgreSqlMigrationError("object_acl_grantee_drifted", "database")
    return grantees


def _apply_database_authority(
    engine: Engine,
    *,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: ProductionServiceRoleBindings,
) -> None:
    with engine.begin() as connection:
        _preflight_database_acl_grantors(connection)
        connection.exec_driver_sql(_read_resource("saas.control_plane", "postgresql_database.sql"))
        _converge_database_acl_projection(
            connection,
            principal_operator=principal_operator,
            official_owner=official_owner,
            saas_owner=saas_owner,
            bindings=bindings,
            schema_usage_roles={
                official_owner,
                saas_owner,
                *_CAPABILITY_ROLES,
            },
        )


def _converge_database_acl_projection(
    connection: Connection,
    *,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: ProductionServiceRoleBindings,
    schema_usage_roles: set[str],
) -> None:
    quote = connection.dialect.identifier_preparer.quote
    database_name, database_owner = connection.execute(
        sa.text(
            "SELECT database.datname, pg_get_userbyid(database.datdba) "
            "FROM pg_database database WHERE database.datname = current_database()"
        )
    ).one()
    database_grantees = connection.execute(
        sa.text(
            "SELECT DISTINCT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(acl.grantee) END FROM pg_database database "
            "CROSS JOIN LATERAL aclexplode(database.datacl) acl "
            "WHERE database.datname = current_database() AND acl.grantee <> database.datdba"
        )
    ).scalars()
    schema_grantees = connection.execute(
        sa.text(
            "SELECT DISTINCT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(acl.grantee) END FROM pg_namespace namespace "
            "CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl "
            "WHERE namespace.nspname = 'public' AND acl.grantee <> namespace.nspowner"
        )
    ).scalars()
    for grantee in database_grantees:
        rendered = "PUBLIC" if grantee == "PUBLIC" else quote(str(grantee))
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON DATABASE {quote(str(database_name))} FROM {rendered}"
        )
    for grantee in schema_grantees:
        rendered = "PUBLIC" if grantee == "PUBLIC" else quote(str(grantee))
        connection.exec_driver_sql(f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {rendered}")

    connect_roles = {
        principal_operator,
        official_owner,
        saas_owner,
        "saas_runner_agent",
        *(binding.base_role for binding in bindings.bindings),
    }
    connection.exec_driver_sql(
        f"GRANT CONNECT ON DATABASE {quote(str(database_name))} TO "
        + ", ".join(quote(role_name) for role_name in sorted(connect_roles))
    )
    connection.exec_driver_sql(
        f"GRANT CREATE ON DATABASE {quote(str(database_name))} TO {quote(official_owner)}"
    )
    connection.exec_driver_sql(
        "GRANT USAGE ON SCHEMA public TO "
        + ", ".join(quote(role_name) for role_name in sorted(schema_usage_roles))
    )
    connection.exec_driver_sql(
        "GRANT CREATE ON SCHEMA public TO "
        + ", ".join(quote(role_name) for role_name in sorted({official_owner, saas_owner}))
    )
    _verify_database_acl_projection(
        connection,
        database_owner=str(database_owner),
        principal_operator=principal_operator,
        official_owner=official_owner,
        saas_owner=saas_owner,
        bindings=bindings,
        schema_usage_roles=schema_usage_roles,
    )


def _verify_database_acl_projection(
    connection: Connection,
    *,
    database_owner: str,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: ProductionServiceRoleBindings,
    schema_usage_roles: set[str],
) -> None:
    database_nonowner = {
        row for row in _database_acl_projection(connection) if row[0] != database_owner
    }
    expected_connect = {
        principal_operator,
        official_owner,
        saas_owner,
        "saas_runner_agent",
        *(binding.base_role for binding in bindings.bindings),
    }
    expected_database = {
        (role_name, database_owner, "CONNECT", False) for role_name in expected_connect
    } | {(official_owner, database_owner, "CREATE", False)}
    schema_owner = _public_schema_owner(connection)
    schema_nonowner = {row for row in _schema_acl_projection(connection) if row[0] != schema_owner}
    expected_schema = {
        (role_name, schema_owner, "USAGE", False) for role_name in schema_usage_roles
    } | {(role_name, schema_owner, "CREATE", False) for role_name in (official_owner, saas_owner)}
    if database_nonowner != expected_database or schema_nonowner != expected_schema:
        raise PostgreSqlMigrationError("database_acl_projection_drifted", "database")


def _migration_config(kind: Literal["official", "saas"]) -> Config:
    if kind == "official":
        ini_path = files("omnigent.db").joinpath("alembic.ini")
        script_path = files("omnigent.db").joinpath("migrations")
    else:
        ini_path = files("saas.control_plane").joinpath("alembic.ini")
        script_path = files("saas.control_plane").joinpath("migrations")
    config = Config(str(ini_path))
    config.set_main_option("script_location", str(script_path))
    return config


def _expected_head(kind: Literal["official", "saas"]) -> str:
    head = ScriptDirectory.from_config(_migration_config(kind)).get_current_head()
    if head is None:
        raise PostgreSqlMigrationError("migration_head_missing", f"{kind}_alembic")
    return head


def _upgrade(engine: Engine, kind: Literal["official", "saas"]) -> None:
    config = _migration_config(kind)
    # Official migrations contain an autocommit block; Alembic must own this
    # connection's transaction boundary.
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def _version_at_head(
    connection: Connection,
    *,
    kind: Literal["official", "saas"],
) -> str:
    table = "alembic_version" if kind == "official" else "saas_alembic_version"
    rows = connection.exec_driver_sql(f"SELECT version_num FROM {table}").scalars().all()
    expected = _expected_head(kind)
    if rows != [expected]:
        raise PostgreSqlMigrationError("migration_revision_not_at_head", f"{kind}_alembic")
    return expected


def _preflight_owner_acl_surface(connection: Connection, *, phase: str) -> None:
    """Reject ACL edges the direct object owner cannot safely converge."""

    foreign = connection.execute(
        sa.text(
            "WITH owner AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
            "unsafe AS ("
            "SELECT 1 FROM pg_class object JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(object.relacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.relowner = owner.oid AND object.relkind IN ('r','p','S','v','m','f') "
            "AND acl.grantee <> object.relowner AND (acl.grantor <> owner.oid "
            "OR (acl.grantee <> 0 AND grantee.oid IS NULL)) UNION ALL "
            "SELECT 1 FROM pg_attribute attribute JOIN pg_class object "
            "ON object.oid = attribute.attrelid JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.relowner = owner.oid AND attribute.attnum > 0 "
            "AND NOT attribute.attisdropped AND acl.grantee <> object.relowner "
            "AND (acl.grantor <> owner.oid OR (acl.grantee <> 0 AND grantee.oid IS NULL)) "
            "UNION ALL SELECT 1 FROM pg_proc object JOIN pg_namespace namespace "
            "ON namespace.oid = object.pronamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(object.proacl, "
            "acldefault('f', object.proowner))) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.proowner = owner.oid AND acl.grantee <> object.proowner "
            "AND (acl.grantor <> owner.oid OR (acl.grantee <> 0 AND grantee.oid IS NULL)) "
            "UNION ALL SELECT 1 FROM pg_type object JOIN pg_namespace namespace "
            "ON namespace.oid = object.typnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(object.typacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.typowner = owner.oid AND acl.grantee <> object.typowner "
            "AND (acl.grantor <> owner.oid OR (acl.grantee <> 0 AND grantee.oid IS NULL)) "
            "UNION ALL SELECT 1 FROM pg_default_acl object CROSS JOIN owner "
            "LEFT JOIN pg_namespace namespace ON namespace.oid = object.defaclnamespace "
            "CROSS JOIN LATERAL aclexplode(object.defaclacl) acl LEFT JOIN pg_roles grantee "
            "ON grantee.oid = acl.grantee WHERE object.defaclrole = owner.oid "
            "AND (namespace.nspname = 'public' OR object.defaclnamespace = 0) "
            "AND acl.grantee <> owner.oid AND (acl.grantor <> owner.oid "
            "OR (acl.grantee <> 0 AND grantee.oid IS NULL)) UNION ALL "
            "SELECT 1 FROM pg_default_acl object CROSS JOIN owner "
            "LEFT JOIN pg_namespace namespace ON namespace.oid = object.defaclnamespace "
            "WHERE object.defaclrole = owner.oid AND object.defaclnamespace <> 0 "
            "AND namespace.nspname IS DISTINCT FROM 'public') SELECT count(*) FROM unsafe"
        )
    ).scalar_one()
    if foreign:
        raise PostgreSqlMigrationError("owner_acl_foreign_grantor_drifted", phase)


def _revoke_owner_acl_surface(connection: Connection) -> None:
    """Remove every owner-granted non-owner edge before rebuilding exact ACLs."""

    quote = connection.dialect.identifier_preparer.quote

    def grantee_sql(value: str) -> str:
        return "PUBLIC" if value == "PUBLIC" else quote(value)

    relations = connection.execute(
        sa.text(
            "SELECT DISTINCT object.relname, object.relkind, "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END "
            "FROM pg_class object JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN LATERAL "
            "aclexplode(object.relacl) acl WHERE namespace.nspname = 'public' "
            "AND object.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND object.relkind IN ('r','p','S','v','m','f') "
            "AND acl.grantee <> object.relowner ORDER BY 1, 2, 3"
        )
    ).all()
    for name, relkind, grantee in relations:
        object_kind = "SEQUENCE" if relkind == "S" else "TABLE"
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON {object_kind} public.{quote(str(name))} "
            f"FROM {grantee_sql(str(grantee))}"
        )

    columns = connection.execute(
        sa.text(
            "SELECT object.relname, acl.privilege_type, "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END, "
            "string_agg(quote_ident(attribute.attname), ', ' ORDER BY attribute.attnum) "
            "FROM pg_attribute attribute JOIN pg_class object "
            "ON object.oid = attribute.attrelid JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN LATERAL "
            "aclexplode(attribute.attacl) acl WHERE namespace.nspname = 'public' "
            "AND object.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "AND acl.grantee <> object.relowner GROUP BY 1, 2, 3 ORDER BY 1, 2, 3"
        )
    ).all()
    for table, privilege, grantee, column_list in columns:
        connection.exec_driver_sql(
            f"REVOKE {privilege} ({column_list}) ON TABLE public.{quote(str(table))} "
            f"FROM {grantee_sql(str(grantee))}"
        )

    routines = connection.execute(
        sa.text(
            "SELECT DISTINCT quote_ident(object.proname) || '(' || "
            "pg_get_function_identity_arguments(object.oid) || ')', "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END "
            "FROM pg_proc object JOIN pg_namespace namespace "
            "ON namespace.oid = object.pronamespace CROSS JOIN LATERAL "
            "aclexplode(COALESCE(object.proacl, acldefault('f', object.proowner))) acl "
            "WHERE namespace.nspname = 'public' "
            "AND object.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND acl.grantee <> object.proowner ORDER BY 1, 2"
        )
    ).all()
    for signature, grantee in routines:
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON FUNCTION public.{signature} "
            f"FROM {grantee_sql(str(grantee))}"
        )

    types = connection.execute(
        sa.text(
            "SELECT DISTINCT object.typname, CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(acl.grantee) END FROM pg_type object "
            "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
            "CROSS JOIN LATERAL aclexplode(COALESCE(object.typacl, "
            "acldefault('T', object.typowner))) acl WHERE namespace.nspname = 'public' "
            "AND object.typowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND object.typelem = 0 AND acl.grantee <> object.typowner ORDER BY 1, 2"
        )
    ).all()
    for type_name, grantee in types:
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON TYPE public.{quote(str(type_name))} "
            f"FROM {grantee_sql(str(grantee))}"
        )

    # PostgreSQL's implicit defaults grant EXECUTE on every future function
    # and USAGE on every future type to PUBLIC.  Persist an explicit owner-wide
    # deny so a later migration cannot silently reopen either surface.
    connection.exec_driver_sql("ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
    connection.exec_driver_sql("ALTER DEFAULT PRIVILEGES REVOKE USAGE ON TYPES FROM PUBLIC")

    defaults = connection.execute(
        sa.text(
            "SELECT DISTINCT COALESCE(namespace.nspname, ''), object.defaclobjtype, "
            "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END "
            "FROM pg_default_acl object LEFT JOIN pg_namespace namespace "
            "ON namespace.oid = object.defaclnamespace CROSS JOIN LATERAL "
            "aclexplode(object.defaclacl) acl WHERE object.defaclrole = "
            "(SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND (namespace.nspname = 'public' OR object.defaclnamespace = 0) "
            "AND acl.grantee <> object.defaclrole ORDER BY 1, 2, 3"
        )
    ).all()
    object_types = {"r": "TABLES", "S": "SEQUENCES", "f": "FUNCTIONS", "T": "TYPES"}
    for namespace, object_type, grantee in defaults:
        if object_type not in object_types:
            raise PostgreSqlMigrationError("default_acl_object_type_unsupported", "acl")
        scope = f" IN SCHEMA {quote(str(namespace))}" if namespace else ""
        connection.exec_driver_sql(
            f"ALTER DEFAULT PRIVILEGES{scope} REVOKE ALL PRIVILEGES ON "
            f"{object_types[str(object_type)]} FROM {grantee_sql(str(grantee))}"
        )


def _verify_owner_acl_surface(connection: Connection, *, phase: str) -> None:
    unexpected = connection.execute(
        sa.text(
            "WITH owner AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
            "capability AS (SELECT oid FROM pg_roles WHERE rolname = ANY(:roles)), "
            "unexpected AS ("
            "SELECT 1 FROM pg_class object JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(object.relacl) acl LEFT JOIN capability allowed "
            "ON allowed.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.relowner = owner.oid AND object.relkind IN ('r','p','S','v','m','f') "
            "AND acl.grantee <> owner.oid AND (allowed.oid IS NULL OR acl.grantor <> owner.oid "
            "OR acl.is_grantable) UNION ALL "
            "SELECT 1 FROM pg_attribute attribute JOIN pg_class object "
            "ON object.oid = attribute.attrelid JOIN pg_namespace namespace "
            "ON namespace.oid = object.relnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl LEFT JOIN capability allowed "
            "ON allowed.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.relowner = owner.oid AND attribute.attnum > 0 "
            "AND NOT attribute.attisdropped AND acl.grantee <> owner.oid "
            "AND (allowed.oid IS NULL OR acl.grantor <> owner.oid OR acl.is_grantable) "
            "UNION ALL SELECT 1 FROM pg_proc object JOIN pg_namespace namespace "
            "ON namespace.oid = object.pronamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(object.proacl, "
            "acldefault('f', object.proowner))) acl LEFT JOIN capability allowed "
            "ON allowed.oid = acl.grantee WHERE namespace.nspname = 'public' "
            "AND object.proowner = owner.oid AND acl.grantee <> owner.oid "
            "AND (allowed.oid IS NULL OR acl.grantor <> owner.oid OR acl.is_grantable) "
            "UNION ALL SELECT 1 FROM pg_type object JOIN pg_namespace namespace "
            "ON namespace.oid = object.typnamespace CROSS JOIN owner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(object.typacl, "
            "acldefault('T', object.typowner))) acl WHERE namespace.nspname = 'public' "
            "AND object.typowner = owner.oid AND object.typelem = 0 "
            "AND acl.grantee <> owner.oid UNION ALL "
            "SELECT 1 FROM pg_default_acl object CROSS JOIN owner "
            "LEFT JOIN pg_namespace namespace ON namespace.oid = object.defaclnamespace "
            "CROSS JOIN LATERAL aclexplode(object.defaclacl) acl "
            "WHERE object.defaclrole = owner.oid "
            "AND (namespace.nspname = 'public' OR object.defaclnamespace = 0) "
            "AND acl.grantee <> owner.oid) SELECT count(*) FROM unexpected"
        ),
        {"roles": list(_CAPABILITY_ROLES)},
    ).scalar_one()
    if unexpected:
        raise PostgreSqlMigrationError("owner_acl_projection_drifted", phase)


def _apply_runtime_authority(engine: Engine) -> None:
    with engine.begin() as connection:
        _preflight_owner_acl_surface(connection, phase="runtime_authority")
        _revoke_owner_acl_surface(connection)
        install_runtime_rls(connection)
        verify_runtime_rls(connection)
        connection.exec_driver_sql(_read_resource("saas.runtime_rls", "postgresql_roles.sql"))
        _verify_owner_acl_surface(connection, phase="runtime_authority")


def _apply_control_plane_authority(engine: Engine) -> None:
    with engine.begin() as connection:
        _preflight_owner_acl_surface(connection, phase="control_plane_authority")
        _revoke_owner_acl_surface(connection)
        connection.exec_driver_sql(_read_resource("saas.control_plane", "postgresql_roles.sql"))
        _verify_owner_acl_surface(connection, phase="control_plane_authority")


def _finalize_database_authority(
    engine: Engine,
    *,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: ProductionServiceRoleBindings,
) -> None:
    with engine.begin() as connection:
        _preflight_database_acl_grantors(connection)
        object_grantees = _owned_object_acl_grantees(
            connection,
            official_owner=official_owner,
            saas_owner=saas_owner,
        )
        _converge_database_acl_projection(
            connection,
            principal_operator=principal_operator,
            official_owner=official_owner,
            saas_owner=saas_owner,
            bindings=bindings,
            schema_usage_roles={official_owner, saas_owner, *object_grantees},
        )


def _verify_database_boundary(
    connection: Connection,
    *,
    principal_operator: str,
    official_owner: str,
    saas_owner: str,
    bindings: ProductionServiceRoleBindings,
) -> None:
    database_owner = connection.execute(
        sa.text(
            "SELECT pg_get_userbyid(database.datdba) FROM pg_database database "
            "WHERE database.datname = current_database()"
        )
    ).scalar_one()
    object_grantees = _owned_object_acl_grantees(
        connection,
        official_owner=official_owner,
        saas_owner=saas_owner,
    )
    _verify_database_acl_projection(
        connection,
        database_owner=str(database_owner),
        principal_operator=principal_operator,
        official_owner=official_owner,
        saas_owner=saas_owner,
        bindings=bindings,
        schema_usage_roles={official_owner, saas_owner, *object_grantees},
    )


def _official_table_names() -> tuple[str, ...]:
    names: set[str] = {"alembic_version"}
    for metadata in (OmnigentBase.metadata, ConversationBase.metadata):
        names.update(table.name for table in metadata.tables.values() if table.schema is None)
    return tuple(sorted(names))


def _public_schema_inventory(
    connection: Connection,
    *,
    official_owner: str,
    saas_owner: str,
) -> list[list[str]]:
    """Return a stable, owner-normalized inventory of every public-schema object."""

    principal_rows = connection.execute(
        sa.text(
            "SELECT role.rolname, role.oid FROM pg_roles role "
            "WHERE role.rolname = ANY(:owners) OR role.oid = 10 ORDER BY role.oid"
        ),
        {"owners": [official_owner, saas_owner]},
    ).all()
    principal_oids = {str(name): int(oid) for name, oid in principal_rows}
    bootstrap_names = [str(name) for name, oid in principal_rows if int(oid) == 10]
    if (
        len(principal_rows) != 3
        or len(bootstrap_names) != 1
        or set(principal_oids) != {official_owner, saas_owner, bootstrap_names[0]}
        or principal_oids.get(official_owner) in {None, 10}
        or principal_oids.get(saas_owner) in {None, 10, principal_oids.get(official_owner)}
        or not any(int(oid) == 10 for _name, oid in principal_rows)
    ):
        raise PostgreSqlMigrationError("public_schema_owner_anchor_drifted", "verification")
    owner_classes = {
        10: "bootstrap",
        principal_oids[official_owner]: "official_owner",
        principal_oids[saas_owner]: "saas_owner",
    }

    schema_owner = connection.execute(
        sa.text(
            "SELECT owner.rolname FROM pg_namespace namespace JOIN pg_roles owner "
            "ON owner.oid = namespace.nspowner WHERE namespace.nspname = 'public'"
        )
    ).scalar_one_or_none()
    if schema_owner != "pg_database_owner":
        raise PostgreSqlMigrationError("public_schema_owner_anchor_drifted", "verification")

    inventory: list[list[str]] = [["namespace", "public", "database_owner"]]

    def add_owned(statement: str) -> None:
        for category, identity, owner_oid in connection.execute(sa.text(statement)).all():
            owner_class = owner_classes.get(int(owner_oid))
            if owner_class is None:
                raise PostgreSqlMigrationError(
                    "public_schema_foreign_owner_drifted", "verification"
                )
            inventory.append([str(category), str(identity), owner_class])

    add_owned(
        "SELECT 'relation', relation.relkind::text || ':' || relation.relname, "
        "relation.relowner FROM pg_class relation JOIN pg_namespace namespace "
        "ON namespace.oid = relation.relnamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'routine', routine.prokind::text || ':' || routine.proname || '(' || "
        "pg_get_function_identity_arguments(routine.oid) || ')', routine.proowner "
        "FROM pg_proc routine JOIN pg_namespace namespace "
        "ON namespace.oid = routine.pronamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'type', type.typtype::text || ':' || type.typname, type.typowner "
        "FROM pg_type type JOIN pg_namespace namespace ON namespace.oid = type.typnamespace "
        "WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'operator', operator.oprname || '(' || "
        "operator.oprleft::regtype::text || ',' || operator.oprright::regtype::text || ')', "
        "operator.oprowner FROM pg_operator operator JOIN pg_namespace namespace "
        "ON namespace.oid = operator.oprnamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'opclass', access.amname || ':' || opclass.opcname || '(' || "
        "opclass.opcintype::regtype::text || ')', opclass.opcowner FROM pg_opclass opclass "
        "JOIN pg_namespace namespace ON namespace.oid = opclass.opcnamespace "
        "JOIN pg_am access ON access.oid = opclass.opcmethod "
        "WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'opfamily', access.amname || ':' || family.opfname, family.opfowner "
        "FROM pg_opfamily family JOIN pg_namespace namespace "
        "ON namespace.oid = family.opfnamespace JOIN pg_am access "
        "ON access.oid = family.opfmethod WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'collation', object.collname || ':' || object.collprovider::text || ':' || "
        "object.collencoding::text, object.collowner FROM pg_collation object "
        "JOIN pg_namespace namespace ON namespace.oid = object.collnamespace "
        "WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'conversion', object.conname || '(' || object.conforencoding::text || "
        "',' || object.contoencoding::text || ')', object.conowner "
        "FROM pg_conversion object JOIN pg_namespace namespace "
        "ON namespace.oid = object.connamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'statistics', statistics.stxname, statistics.stxowner "
        "FROM pg_statistic_ext statistics JOIN pg_namespace namespace "
        "ON namespace.oid = statistics.stxnamespace WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'ts_config', config.cfgname, config.cfgowner FROM pg_ts_config config "
        "JOIN pg_namespace namespace ON namespace.oid = config.cfgnamespace "
        "WHERE namespace.nspname = 'public' UNION ALL "
        "SELECT 'ts_dictionary', dictionary.dictname, dictionary.dictowner "
        "FROM pg_ts_dict dictionary JOIN pg_namespace namespace "
        "ON namespace.oid = dictionary.dictnamespace WHERE namespace.nspname = 'public'"
    )

    # Constraints, triggers, policies, and rewrite rules do not carry their own
    # owner.  Bind each identity to its owning relation/type and, for triggers,
    # also to the exact trigger-function owner class.
    add_owned(
        "SELECT 'constraint', object.contype::text || ':' || object.conname || ':' || "
        "CASE WHEN object.conrelid <> 0 THEN object.conrelid::regclass::text "
        "ELSE object.contypid::regtype::text END, "
        "COALESCE(relation.relowner, type.typowner) FROM pg_constraint object "
        "LEFT JOIN pg_class relation ON relation.oid = object.conrelid "
        "LEFT JOIN pg_type type ON type.oid = object.contypid "
        "JOIN pg_namespace namespace ON namespace.oid = object.connamespace "
        "WHERE namespace.nspname = 'public'"
    )
    trigger_rows = connection.execute(
        sa.text(
            "SELECT relation.relname, trigger.tgname, routine.proname, "
            "pg_get_function_identity_arguments(routine.oid), relation.relowner, "
            "routine.proowner FROM pg_trigger trigger JOIN pg_class relation "
            "ON relation.oid = trigger.tgrelid JOIN pg_namespace namespace "
            "ON namespace.oid = relation.relnamespace JOIN pg_proc routine "
            "ON routine.oid = trigger.tgfoid WHERE namespace.nspname = 'public' "
            "AND NOT trigger.tgisinternal"
        )
    ).all()
    for table, trigger, routine, arguments, relation_owner, routine_owner in trigger_rows:
        relation_class = owner_classes.get(int(relation_owner))
        routine_class = owner_classes.get(int(routine_owner))
        if relation_class is None or routine_class is None:
            raise PostgreSqlMigrationError("public_schema_foreign_owner_drifted", "verification")
        inventory.append(
            [
                "trigger",
                f"{table}:{trigger}:{routine}({arguments}):{routine_class}",
                relation_class,
            ]
        )
    add_owned(
        "SELECT 'policy', relation.relname || ':' || policy.polname, relation.relowner "
        "FROM pg_policy policy JOIN pg_class relation ON relation.oid = policy.polrelid "
        "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = 'public'"
    )
    add_owned(
        "SELECT 'rewrite', relation.relname || ':' || rewrite.rulename, relation.relowner "
        "FROM pg_rewrite rewrite JOIN pg_class relation ON relation.oid = rewrite.ev_class "
        "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = 'public'"
    )
    inventory.append(
        [
            "extension",
            f"pg_trgm:{_PG_TRGM_VERSION}:public",
            "official_owner",
        ]
    )
    inventory.sort()
    return inventory


def _verify_public_schema_inventory(
    connection: Connection,
    *,
    official_owner: str,
    saas_owner: str,
) -> str:
    inventory = _public_schema_inventory(
        connection,
        official_owner=official_owner,
        saas_owner=saas_owner,
    )
    server_major = (
        int(
            connection.execute(
                sa.text("SELECT current_setting('server_version_num')::integer")
            ).scalar_one()
        )
        // 10000
    )
    key = (server_major, _expected_head("official"), _expected_head("saas"))
    return _verify_public_schema_inventory_digest(inventory, key=key)


def _verify_public_schema_inventory_digest(
    inventory: list[list[str]],
    *,
    key: tuple[int, str, str],
) -> str:
    """Validate a catalog against the source-pinned clean-replay digest."""

    expected_digest = _PUBLIC_SCHEMA_INVENTORY_SHA256.get(key)
    digest = hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if expected_digest is None or digest != expected_digest:
        raise PostgreSqlMigrationError("public_schema_inventory_drifted", "verification")
    return digest


def _source_catalog_role_aliases(
    *,
    principal_operator: str,
    database_owner: str,
    official_owner: str,
    saas_owner: str,
    bootstrap_name: str,
    bindings: ProductionServiceRoleBindings,
) -> dict[str, str]:
    """Map deployment-chosen login names to stable source-catalog classes."""

    aliases = {
        principal_operator: "authority:principal_operator",
        database_owner: "authority:database_owner",
        official_owner: "authority:official_owner",
        saas_owner: "authority:saas_owner",
        bootstrap_name: "authority:bootstrap",
    }
    aliases.update(
        {binding.login: f"service_login:{binding.service}" for binding in bindings.bindings}
    )
    if len(aliases) != 5 + len(bindings.bindings):
        raise PostgreSqlMigrationError("source_catalog_role_alias_drifted", "verification")
    return aliases


def _normalize_source_catalog(value: object, *, role_aliases: Mapping[str, str]) -> object:
    """Replace only exact role-name values before hashing a clean catalog."""

    if isinstance(value, str):
        return role_aliases.get(value, value)
    if isinstance(value, Mapping):
        return {
            str(key): _normalize_source_catalog(item, role_aliases=role_aliases)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_source_catalog(item, role_aliases=role_aliases) for item in value]
    return value


def _verify_source_security_catalog_digest(
    catalog: Mapping[str, object],
    *,
    key: tuple[int, str, str],
    role_aliases: Mapping[str, str],
) -> str:
    """Reject ACL/policy/role drift against a clean-replay source anchor."""

    normalized = _normalize_source_catalog(catalog, role_aliases=role_aliases)
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if _SOURCE_SECURITY_CATALOG_SHA256.get(key) != digest:
        raise PostgreSqlMigrationError("source_security_catalog_drifted", "verification")
    return digest


def _verify_object_ownership(
    official_connection: Connection,
    saas_connection: Connection,
    *,
    official_owner: str,
    saas_owner: str,
) -> tuple[tuple[str, str], ...]:
    official_names = _official_table_names()
    official_rows = official_connection.execute(
        sa.text(
            "SELECT relation.relname, owner.rolname FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relname = ANY(:table_names) ORDER BY relation.relname"
        ),
        {"table_names": list(official_names)},
    ).all()
    if len(official_rows) != len(official_names) or any(
        owner != official_owner for _table, owner in official_rows
    ):
        raise PostgreSqlMigrationError("official_object_ownership_drifted", "verification")
    saas_rows = saas_connection.execute(
        sa.text(
            "SELECT 'relation:' || relation.relname, owner.rolname "
            "FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' "
            "AND left(relation.relname, 5) = 'saas_' "
            "AND relation.relkind IN ('r', 'p', 'S', 'v', 'm', 'f') UNION ALL "
            "SELECT 'routine:' || routine.proname || '(' || "
            "pg_get_function_identity_arguments(routine.oid) || ')', owner.rolname "
            "FROM pg_proc routine JOIN pg_namespace namespace "
            "ON namespace.oid = routine.pronamespace JOIN pg_roles owner "
            "ON owner.oid = routine.proowner WHERE namespace.nspname = 'public' AND ("
            "left(routine.proname, 5) = 'saas_' OR routine.proname IN ("
            "'approval_source_work_binding_is_valid', "
            "'approval_notification_binding_is_valid') OR EXISTS ("
            "SELECT 1 FROM pg_trigger trigger JOIN pg_class relation "
            "ON relation.oid = trigger.tgrelid JOIN pg_namespace relation_namespace "
            "ON relation_namespace.oid = relation.relnamespace "
            "WHERE trigger.tgfoid = routine.oid AND NOT trigger.tgisinternal "
            "AND relation_namespace.nspname = 'public' "
            "AND left(relation.relname, 5) = 'saas_')) UNION ALL "
            "SELECT 'type:' || type.typname, owner.rolname FROM pg_type type "
            "JOIN pg_namespace namespace ON namespace.oid = type.typnamespace "
            "JOIN pg_roles owner ON owner.oid = type.typowner "
            "WHERE namespace.nspname = 'public' AND (left(type.typname, 5) = 'saas_' "
            "OR EXISTS (SELECT 1 FROM pg_class relation WHERE relation.reltype = type.oid "
            "AND left(relation.relname, 5) = 'saas_')) ORDER BY 1"
        )
    ).all()
    if not saas_rows or any(owner != saas_owner for _table, owner in saas_rows):
        raise PostgreSqlMigrationError("saas_object_ownership_drifted", "verification")
    _verify_public_schema_inventory(
        official_connection,
        official_owner=official_owner,
        saas_owner=saas_owner,
    )
    return tuple((str(table), str(owner)) for table, owner in (*official_rows, *saas_rows))


def _verify_runtime_acl(connection: Connection) -> tuple[tuple[str, str, bool], ...]:
    contracts = load_runtime_rls_contract()
    official_names = _official_table_names()
    expected = {
        (contract.table_name, privilege, False)
        for contract in contracts
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE")
    }
    relation_acls = {
        (str(table), str(privilege), bool(grantable))
        for table, privilege, grantable in connection.execute(
            sa.text(
                "SELECT relation.relname, acl.privilege_type, acl.is_grantable "
                "FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_roles AS role ON role.rolname = :role "
                "CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl "
                "WHERE namespace.nspname = 'public' AND acl.grantee = role.oid "
                "ORDER BY relation.relname, acl.privilege_type"
            ),
            {"role": _RUNTIME_ROLE},
        ).all()
    }
    schema_acls = connection.execute(
        sa.text(
            "SELECT acl.privilege_type, acl.is_grantable "
            "FROM pg_namespace AS namespace "
            "JOIN pg_roles AS role ON role.rolname = :role "
            "CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl "
            "WHERE namespace.nspname = 'public' AND acl.grantee = role.oid"
        ),
        {"role": _RUNTIME_ROLE},
    ).all()
    other_authority = connection.execute(
        sa.text(
            "WITH runtime AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
            "unexpected AS ("
            "SELECT 1 FROM pg_attribute AS attribute "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
            "JOIN runtime ON acl.grantee = runtime.oid "
            "WHERE attribute.attnum > 0 AND NOT attribute.attisdropped UNION ALL "
            "SELECT 1 FROM pg_proc AS routine "
            "CROSS JOIN LATERAL aclexplode(routine.proacl) AS acl "
            "JOIN runtime ON acl.grantee = runtime.oid UNION ALL "
            "SELECT 1 FROM pg_type AS type "
            "CROSS JOIN LATERAL aclexplode(type.typacl) AS acl "
            "JOIN runtime ON acl.grantee = runtime.oid UNION ALL "
            "SELECT 1 FROM pg_default_acl AS defaults "
            "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl "
            "JOIN runtime ON acl.grantee = runtime.oid) "
            "SELECT count(*) FROM unexpected"
        ),
        {"role": _RUNTIME_ROLE},
    ).scalar_one()
    unexpected_official_authority = connection.execute(
        sa.text(
            "WITH runtime AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
            "official_owner AS ("
            "SELECT relation.relowner AS oid FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'public' AND relation.relname = :anchor), "
            "unexpected AS ("
            "SELECT 1 FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl "
            "CROSS JOIN runtime CROSS JOIN official_owner "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relname = ANY(:official_names) "
            "AND acl.grantee <> relation.relowner AND NOT ("
            "relation.relname = ANY(:runtime_names) "
            "AND acl.grantee = runtime.oid AND acl.grantor = official_owner.oid "
            "AND acl.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE') "
            "AND NOT acl.is_grantable) UNION ALL "
            "SELECT 1 FROM pg_attribute AS attribute "
            "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relname = ANY(:official_names) "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "AND acl.grantee <> relation.relowner UNION ALL "
            "SELECT 1 FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "CROSS JOIN official_owner WHERE namespace.nspname = 'public' "
            "AND relation.relowner = official_owner.oid "
            "AND relation.relkind IN ('r','p','S','v','m','f') "
            "AND relation.relname <> ALL(:official_names) UNION ALL "
            "SELECT 1 FROM pg_proc AS routine "
            "JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace "
            "CROSS JOIN official_owner WHERE namespace.nspname = 'public' "
            "AND routine.proowner = official_owner.oid UNION ALL "
            "SELECT 1 FROM pg_type AS type "
            "JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace "
            "CROSS JOIN LATERAL aclexplode(type.typacl) AS acl "
            "CROSS JOIN official_owner WHERE namespace.nspname = 'public' "
            "AND type.typowner = official_owner.oid "
            "AND acl.grantee <> type.typowner UNION ALL "
            "SELECT 1 FROM pg_default_acl AS defaults CROSS JOIN official_owner "
            "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl "
            "WHERE defaults.defaclrole = official_owner.oid AND ("
            "defaults.defaclnamespace <> 0 OR defaults.defaclobjtype NOT IN ('f','T') "
            "OR acl.grantee <> official_owner.oid OR acl.grantor <> official_owner.oid "
            "OR acl.is_grantable OR (defaults.defaclobjtype = 'f' "
            "AND acl.privilege_type <> 'EXECUTE') OR (defaults.defaclobjtype = 'T' "
            "AND acl.privilege_type <> 'USAGE')) UNION ALL "
            "SELECT 1 FROM official_owner WHERE (SELECT count(*) FROM pg_default_acl defaults "
            "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl "
            "WHERE defaults.defaclrole = official_owner.oid "
            "AND defaults.defaclnamespace = 0 AND ((defaults.defaclobjtype = 'f' "
            "AND acl.grantee = official_owner.oid AND acl.grantor = official_owner.oid "
            "AND acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable) "
            "OR (defaults.defaclobjtype = 'T' AND acl.grantee = official_owner.oid "
            "AND acl.grantor = official_owner.oid AND acl.privilege_type = 'USAGE' "
            "AND NOT acl.is_grantable))) <> 2) "
            "SELECT count(*) FROM unexpected"
        ),
        {
            "role": _RUNTIME_ROLE,
            "anchor": official_names[0],
            "official_names": list(official_names),
            "runtime_names": [contract.table_name for contract in contracts],
        },
    ).scalar_one()
    if (
        relation_acls != expected
        or schema_acls != [("USAGE", False)]
        or other_authority
        or unexpected_official_authority
    ):
        raise PostgreSqlMigrationError("runtime_acl_projection_drifted", "verification")
    return tuple(sorted(relation_acls))


def _pg_trgm_security_catalog(
    connection: Connection,
    *,
    official_owner: str,
) -> dict[str, object]:
    server_major = (
        int(
            connection.execute(
                sa.text("SELECT current_setting('server_version_num')::integer")
            ).scalar_one()
        )
        // 10000
    )
    expected_members = _PG_TRGM_MEMBER_IDENTITIES_BY_MAJOR.get(server_major)
    if expected_members is None:
        raise PostgreSqlMigrationError("pg_trgm_member_contract_drifted", "verification")
    extension = connection.execute(
        sa.text(
            "SELECT extension.extversion, namespace.nspname, owner.rolname "
            "FROM pg_extension extension JOIN pg_namespace namespace "
            "ON namespace.oid = extension.extnamespace JOIN pg_roles owner "
            "ON owner.oid = extension.extowner WHERE extension.extname = 'pg_trgm'"
        )
    ).one_or_none()
    if extension is None or tuple(extension) != (_PG_TRGM_VERSION, "public", official_owner):
        raise PostgreSqlMigrationError("pg_trgm_extension_drifted", "verification")

    member_rows = connection.execute(
        sa.text(
            "SELECT dependency.classid::regclass::text, "
            "pg_describe_object(dependency.classid, dependency.objid, "
            "dependency.objsubid), CASE dependency.classid "
            "WHEN 'pg_proc'::regclass THEN (SELECT routine.proowner FROM pg_proc routine "
            "WHERE routine.oid = dependency.objid) "
            "WHEN 'pg_type'::regclass THEN (SELECT type.typowner FROM pg_type type "
            "WHERE type.oid = dependency.objid) "
            "WHEN 'pg_operator'::regclass THEN (SELECT operator.oprowner "
            "FROM pg_operator operator "
            "WHERE operator.oid = dependency.objid) "
            "WHEN 'pg_opclass'::regclass THEN (SELECT opclass.opcowner FROM pg_opclass opclass "
            "WHERE opclass.oid = dependency.objid) "
            "WHEN 'pg_opfamily'::regclass THEN (SELECT family.opfowner FROM pg_opfamily family "
            "WHERE family.oid = dependency.objid) END "
            "FROM pg_depend dependency JOIN pg_extension extension "
            "ON extension.oid = dependency.refobjid WHERE dependency.refclassid = "
            "'pg_extension'::regclass AND dependency.deptype = 'e' "
            "AND extension.extname = 'pg_trgm' ORDER BY 1, 2"
        )
    ).all()
    members = [
        [str(class_name), str(description), int(owner_oid)]
        for class_name, description, owner_oid in member_rows
    ]
    if tuple((row[0], row[1]) for row in members) != expected_members or any(
        row[2] != 10 for row in members
    ):
        raise PostgreSqlMigrationError("pg_trgm_member_contract_drifted", "verification")

    functions = [
        [
            str(name),
            str(arguments),
            str(result),
            int(owner_oid),
            str(language),
            str(binary),
            str(source),
            str(volatility),
            bool(strict),
            bool(security_definer),
            bool(leakproof),
            str(parallel),
            list(config) if config is not None else None,
            str(kind),
            bool(returns_set),
            float(cost),
            float(rows),
            int(variadic_oid),
        ]
        for (
            name,
            arguments,
            result,
            owner_oid,
            language,
            binary,
            source,
            volatility,
            strict,
            security_definer,
            leakproof,
            parallel,
            config,
            kind,
            returns_set,
            cost,
            rows,
            variadic_oid,
        ) in connection.execute(
            sa.text(
                "SELECT routine.proname, pg_get_function_identity_arguments(routine.oid), "
                "pg_get_function_result(routine.oid), routine.proowner, language.lanname, "
                "routine.probin, routine.prosrc, routine.provolatile, routine.proisstrict, "
                "routine.prosecdef, routine.proleakproof, routine.proparallel, routine.proconfig, "
                "routine.prokind, routine.proretset, routine.procost, routine.prorows, "
                "routine.provariadic "
                "FROM pg_depend dependency JOIN pg_extension extension "
                "ON extension.oid = dependency.refobjid JOIN pg_proc routine "
                "ON dependency.classid = 'pg_proc'::regclass "
                "AND routine.oid = dependency.objid JOIN pg_language language "
                "ON language.oid = routine.prolang WHERE extension.extname = 'pg_trgm' "
                "AND dependency.deptype = 'e' ORDER BY 1, 2"
            )
        ).all()
    ]
    observed_function_contracts = {
        (row[0], row[1]): (row[2], row[7], row[8], row[11]) for row in functions
    }
    if observed_function_contracts != _PG_TRGM_FUNCTION_CONTRACTS or any(
        row[3] != 10
        or row[4] != "c"
        or row[5] != "$libdir/pg_trgm"
        or row[6] != row[0]
        or row[9]
        or row[10]
        or row[12] is not None
        or row[13] != "f"
        or row[14]
        or row[15:18] != [1.0, 0.0, 0]
        for row in functions
    ):
        raise PostgreSqlMigrationError("pg_trgm_member_contract_drifted", "verification")

    function_acls = [
        list(row)
        for row in connection.execute(
            sa.text(
                "SELECT routine.proname, pg_get_function_identity_arguments(routine.oid), "
                "acl.grantee, acl.grantor, acl.privilege_type, acl.is_grantable "
                "FROM pg_depend dependency JOIN pg_extension extension "
                "ON extension.oid = dependency.refobjid JOIN pg_proc routine "
                "ON dependency.classid = 'pg_proc'::regclass AND routine.oid = dependency.objid "
                "CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, "
                "acldefault('f', routine.proowner))) acl WHERE extension.extname = 'pg_trgm' "
                "AND dependency.deptype = 'e' ORDER BY 1, 2, 3, 4, 5, 6"
            )
        ).all()
    ]
    expected_function_acls = {
        (name, arguments, grantee, 10, "EXECUTE", False)
        for name, arguments in _PG_TRGM_FUNCTION_CONTRACTS
        for grantee in (0, 10)
    }
    if {tuple(row) for row in function_acls} != expected_function_acls:
        raise PostgreSqlMigrationError("pg_trgm_function_acl_drifted", "verification")

    types = [
        list(row)
        for row in connection.execute(
            sa.text(
                "WITH extension_type AS (SELECT type.oid FROM pg_depend dependency "
                "JOIN pg_extension extension ON extension.oid = dependency.refobjid "
                "JOIN pg_type type ON dependency.classid = 'pg_type'::regclass "
                "AND type.oid = dependency.objid WHERE extension.extname = 'pg_trgm' "
                "AND dependency.deptype = 'e') SELECT type.typname, type.typowner, "
                "type.typtype, type.typcategory, type.typispreferred, type.typisdefined, "
                "type.typrelid, type.typelem::regtype::text, type.typarray::regtype::text, "
                "type.typinput::regproc::text, type.typoutput::regproc::text, "
                "type.typreceive::regproc::text, type.typsend::regproc::text, "
                "type.typmodin::regproc::text, type.typmodout::regproc::text, "
                "type.typanalyze::regproc::text, type.typsubscript::regproc::text, "
                "type.typcollation FROM pg_type type WHERE type.oid IN "
                "(SELECT oid FROM extension_type) OR type.typelem IN "
                "(SELECT oid FROM extension_type) ORDER BY type.typname"
            )
        ).all()
    ]
    expected_types = [
        [
            "_gtrgm",
            10,
            "b",
            "A",
            False,
            True,
            0,
            "gtrgm",
            "-",
            "array_in",
            "array_out",
            "array_recv",
            "array_send",
            "-",
            "-",
            "array_typanalyze",
            "array_subscript_handler",
            0,
        ],
        [
            "gtrgm",
            10,
            "b",
            "U",
            False,
            True,
            0,
            "-",
            "gtrgm[]",
            "gtrgm_in",
            "gtrgm_out",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            0,
        ],
    ]
    if types != expected_types:
        raise PostgreSqlMigrationError("pg_trgm_type_contract_drifted", "verification")
    type_acls = [
        list(row)
        for row in connection.execute(
            sa.text(
                "WITH extension_type AS (SELECT type.oid FROM pg_depend dependency "
                "JOIN pg_extension extension ON extension.oid = dependency.refobjid "
                "JOIN pg_type type ON dependency.classid = 'pg_type'::regclass "
                "AND type.oid = dependency.objid WHERE extension.extname = 'pg_trgm' "
                "AND dependency.deptype = 'e'), extension_and_array AS ("
                "SELECT type.* FROM pg_type type WHERE type.oid IN "
                "(SELECT oid FROM extension_type) "
                "OR type.typelem IN (SELECT oid FROM extension_type)) "
                "SELECT type.typname, acl.grantee, acl.grantor, acl.privilege_type, "
                "acl.is_grantable FROM extension_and_array type CROSS JOIN LATERAL "
                "aclexplode(COALESCE(type.typacl, acldefault('T', type.typowner))) acl "
                "ORDER BY 1, 2, 3, 4, 5"
            )
        ).all()
    ]
    expected_type_acls = {
        (name, grantee, 10, "USAGE", False) for name in ("_gtrgm", "gtrgm") for grantee in (0, 10)
    }
    if {tuple(row) for row in type_acls} != expected_type_acls:
        raise PostgreSqlMigrationError("pg_trgm_type_acl_drifted", "verification")

    opclasses = [
        [
            str(name),
            str(method),
            str(family),
            str(input_type),
            str(key_type) if key_type is not None else None,
            bool(is_default),
            int(owner_oid),
        ]
        for name, method, family, input_type, key_type, is_default, owner_oid in (
            connection.execute(
                sa.text(
                    "SELECT opclass.opcname, access.amname, family.opfname, "
                    "format_type(opclass.opcintype, NULL), "
                    "CASE WHEN opclass.opckeytype = 0 THEN NULL "
                    "ELSE format_type(opclass.opckeytype, NULL) END, "
                    "opclass.opcdefault, opclass.opcowner "
                    "FROM pg_depend dependency JOIN pg_extension extension "
                    "ON extension.oid = dependency.refobjid JOIN pg_opclass opclass "
                    "ON dependency.classid = 'pg_opclass'::regclass "
                    "AND opclass.oid = dependency.objid JOIN pg_am access "
                    "ON access.oid = opclass.opcmethod JOIN pg_opfamily family "
                    "ON family.oid = opclass.opcfamily WHERE extension.extname = 'pg_trgm' "
                    "AND dependency.deptype = 'e' ORDER BY 1, 2"
                )
            ).all()
        )
    ]
    if {tuple(row[:6]) for row in opclasses} != _PG_TRGM_OPCLASS_CONTRACTS or any(
        row[6] != 10 for row in opclasses
    ):
        raise PostgreSqlMigrationError("pg_trgm_opclass_drifted", "verification")

    indexes = [
        [
            str(index_namespace),
            str(index_name),
            str(table_namespace),
            str(table_name),
            str(owner),
            str(method),
            str(opclass),
            bool(valid),
            bool(ready),
            bool(live),
            int(attribute_count),
            str(expression) if expression is not None else None,
            str(predicate) if predicate is not None else None,
        ]
        for (
            index_namespace,
            index_name,
            table_namespace,
            table_name,
            owner,
            method,
            opclass,
            valid,
            ready,
            live,
            attribute_count,
            expression,
            predicate,
        ) in connection.execute(
            sa.text(
                "SELECT index_namespace.nspname, index_relation.relname, "
                "table_namespace.nspname, table_relation.relname, "
                "pg_get_userbyid(index_relation.relowner), access.amname, opclass.opcname, "
                "index.indisvalid, index.indisready, index.indislive, index.indnkeyatts, "
                "pg_get_expr(index.indexprs, index.indrelid), "
                "pg_get_expr(index.indpred, index.indrelid) FROM pg_index index "
                "JOIN pg_class index_relation ON index_relation.oid = index.indexrelid "
                "JOIN pg_class table_relation ON table_relation.oid = index.indrelid "
                "JOIN pg_namespace index_namespace "
                "ON index_namespace.oid = index_relation.relnamespace "
                "JOIN pg_namespace table_namespace "
                "ON table_namespace.oid = table_relation.relnamespace "
                "JOIN pg_am access ON access.oid = index_relation.relam "
                "JOIN pg_opclass opclass ON opclass.oid = index.indclass[0] "
                "JOIN pg_depend opclass_dependency ON opclass_dependency.classid = "
                "'pg_opclass'::regclass AND opclass_dependency.objid = opclass.oid "
                "AND opclass_dependency.deptype = 'e' JOIN pg_extension extension "
                "ON extension.oid = opclass_dependency.refobjid "
                "WHERE extension.extname = 'pg_trgm' ORDER BY 1, 2"
            )
        ).all()
    ]
    observed_indexes = {
        row[1]: (row[3], row[11])
        for row in indexes
        if row[0] == "public"
        and row[2] == "public"
        and row[4] == official_owner
        and row[5] == "gin"
        and row[6] == "gin_trgm_ops"
        and row[7:11] == [True, True, True, 1]
        and row[12] is None
    }
    if observed_indexes != _PG_TRGM_INDEXES or len(indexes) != len(_PG_TRGM_INDEXES):
        raise PostgreSqlMigrationError("pg_trgm_index_contract_drifted", "verification")
    return {
        "extension": [str(value) for value in extension],
        "members": members,
        "functions": functions,
        "function_acls": function_acls,
        "types": types,
        "type_acls": type_acls,
        "opclasses": opclasses,
        "indexes": indexes,
    }


def _preflight_pg_trgm_extension(connection: Connection, *, official_owner: str) -> None:
    exists = bool(
        connection.execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')")
        ).scalar_one()
    )
    if not exists:
        return
    at_head = False
    if connection.execute(sa.text("SELECT to_regclass('public.alembic_version')")).scalar_one():
        at_head = _version_at_head(connection, kind="official") == _expected_head("official")
    if not at_head:
        raise PostgreSqlMigrationError("pg_trgm_preexisting_before_head", "official_alembic")
    _pg_trgm_security_catalog(connection, official_owner=official_owner)


def _official_security_catalog(
    connection: Connection,
    *,
    official_owner: str,
) -> dict[str, object]:
    """Return the full official-owner security projection for receipt binding."""

    def rows(statement: str, parameters: Mapping[str, object] | None = None) -> list[list[object]]:
        return [
            [list(value) if isinstance(value, tuple) else value for value in row]
            for row in connection.execute(sa.text(statement), parameters or {}).all()
        ]

    role_name = "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END"
    grantor_name = "CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantor) END"
    parameters = {"owner": official_owner}
    return {
        "pg_trgm": _pg_trgm_security_catalog(
            connection,
            official_owner=official_owner,
        ),
        "relations": rows(
            "SELECT relation.relname, relation.relkind, relation.relrowsecurity, "
            "relation.relforcerowsecurity FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY relation.relname, relation.relkind",
            parameters,
        ),
        "relation_acls": rows(
            f"SELECT relation.relname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, "
            "acldefault(CASE WHEN relation.relkind = 'S' THEN 's'::\"char\" "
            "ELSE 'r'::\"char\" END, relation.relowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND relation.relkind IN ('r','p','S','v','m','f') "
            "ORDER BY 1, 2, 3, 4, 5",
            parameters,
        ),
        "column_acls": rows(
            f"SELECT relation.relname, attribute.attname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_attribute AS attribute "
            "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
        "routines": rows(
            f"SELECT routine.proname, pg_get_function_identity_arguments(routine.oid), "
            f"routine.prokind, routine.prosecdef, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_proc AS routine "
            "JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace "
            "JOIN pg_roles AS owner ON owner.oid = routine.proowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, "
            "acldefault('f', routine.proowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY 1, 2, 3, 4, 5, 6, 7, 8",
            parameters,
        ),
        "types": rows(
            f"SELECT type.typname, type.typtype, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_type AS type "
            "JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace "
            "JOIN pg_roles AS owner ON owner.oid = type.typowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(type.typacl, "
            "acldefault('T', type.typowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND type.typelem = 0 "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
        "policies": rows(
            "SELECT relation.relname, policy.polname, policy.polpermissive, "
            "policy.polcmd, ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(role_oid) END FROM unnest(policy.polroles) AS role_oid "
            "ORDER BY 1), pg_get_expr(policy.polqual, policy.polrelid), "
            "pg_get_expr(policy.polwithcheck, policy.polrelid) "
            "FROM pg_policy AS policy JOIN pg_class AS relation "
            "ON relation.oid = policy.polrelid JOIN pg_namespace AS namespace "
            "ON namespace.oid = relation.relnamespace JOIN pg_roles AS owner "
            "ON owner.oid = relation.relowner WHERE namespace.nspname = 'public' "
            "AND owner.rolname = :owner ORDER BY relation.relname, policy.polname",
            parameters,
        ),
        "triggers": rows(
            "SELECT relation.relname, trigger.tgname, trigger.tgenabled, "
            "pg_get_triggerdef(trigger.oid, true) FROM pg_trigger AS trigger "
            "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND NOT trigger.tgisinternal ORDER BY relation.relname, trigger.tgname",
            parameters,
        ),
        "default_acls": rows(
            f"SELECT COALESCE(namespace.nspname, ''), defaults.defaclobjtype, "
            f"{role_name}, {grantor_name}, acl.privilege_type, acl.is_grantable "
            "FROM pg_default_acl AS defaults JOIN pg_roles AS owner "
            "ON owner.oid = defaults.defaclrole LEFT JOIN pg_namespace AS namespace "
            "ON namespace.oid = defaults.defaclnamespace CROSS JOIN LATERAL "
            "aclexplode(defaults.defaclacl) AS acl WHERE owner.rolname = :owner "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
    }


def _control_plane_security_catalog(
    connection: Connection,
    *,
    saas_owner: str,
) -> dict[str, list[list[object]]]:
    """Project security-relevant SaaS catalog state into a stable hash input.

    The role SQL remains the authority that proves the expected projection.
    This read-only snapshot makes every later startup prove that the exact role
    graph, ACL, RLS, policy, trigger, and ownership facts have not drifted since
    the privileged migration receipt was issued.
    """

    def rows(statement: str, parameters: Mapping[str, object] | None = None) -> list[list[object]]:
        return [
            [list(value) if isinstance(value, tuple) else value for value in row]
            for row in connection.execute(sa.text(statement), parameters or {}).all()
        ]

    roles = list(_CAPABILITY_ROLES)
    role_name = "CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END"
    grantor_name = "CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantor) END"
    parameters = {"owner": saas_owner}
    return {
        "roles": rows(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls, rolinherit, rolconnlimit, "
            "COALESCE(to_jsonb(rolconfig)::text, 'null') FROM pg_roles "
            "WHERE rolname = ANY(:roles) ORDER BY rolname",
            {"roles": roles},
        ),
        "memberships": rows(
            "SELECT granted.rolname, member.rolname, grantor.rolname, "
            "membership.admin_option, "
            "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
            "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true) "
            "FROM pg_auth_members AS membership "
            "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
            "JOIN pg_roles AS member ON member.oid = membership.member "
            "JOIN pg_roles AS grantor ON grantor.oid = membership.grantor "
            "WHERE granted.rolname = ANY(:roles) OR member.rolname = ANY(:roles) "
            "ORDER BY granted.rolname, member.rolname, grantor.rolname",
            {"roles": roles},
        ),
        "database_acls": rows(
            f"SELECT {role_name}, {grantor_name}, acl.privilege_type, acl.is_grantable "
            "FROM pg_database AS database CROSS JOIN LATERAL aclexplode(COALESCE("
            "database.datacl, acldefault('d', database.datdba))) AS acl "
            "WHERE database.datname = current_database() "
            "ORDER BY 1, 2, 3, 4"
        ),
        "schema_acls": rows(
            f"SELECT {role_name}, {grantor_name}, acl.privilege_type, acl.is_grantable "
            "FROM pg_namespace AS namespace CROSS JOIN LATERAL aclexplode(COALESCE("
            "namespace.nspacl, acldefault('n', namespace.nspowner))) AS acl "
            "WHERE namespace.nspname = 'public' ORDER BY 1, 2, 3, 4"
        ),
        "relations": rows(
            "SELECT relation.relname, relation.relkind, owner.rolname, "
            "relation.relrowsecurity, relation.relforcerowsecurity "
            "FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY relation.relname",
            parameters,
        ),
        "relation_acls": rows(
            f"SELECT relation.relname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, "
            "acldefault(CASE WHEN relation.relkind = 'S' THEN 's'::\"char\" "
            "ELSE 'r'::\"char\" END, relation.relowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND relation.relkind IN ('r','p','S','v','m','f') "
            "ORDER BY 1, 2, 3, 4, 5",
            parameters,
        ),
        "column_acls": rows(
            f"SELECT relation.relname, attribute.attname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_attribute AS attribute "
            "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
        "routines": rows(
            f"SELECT routine.proname, pg_get_function_identity_arguments(routine.oid), "
            f"owner.rolname, {role_name}, {grantor_name}, acl.privilege_type, "
            "acl.is_grantable, routine.prosecdef FROM pg_proc AS routine "
            "JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace "
            "JOIN pg_roles AS owner ON owner.oid = routine.proowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, "
            "acldefault('f', routine.proowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY 1, 2, 3, 4, 5, 6, 7, 8",
            parameters,
        ),
        "types": rows(
            f"SELECT type.typname, owner.rolname, {role_name}, {grantor_name}, "
            "acl.privilege_type, acl.is_grantable FROM pg_type AS type "
            "JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace "
            "JOIN pg_roles AS owner ON owner.oid = type.typowner "
            "CROSS JOIN LATERAL aclexplode(COALESCE(type.typacl, "
            "acldefault('T', type.typowner))) AS acl "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND type.typelem = 0 "
            "ORDER BY 1, 2, 3, 4, 5, 6",
            parameters,
        ),
        "policies": rows(
            "SELECT relation.relname, policy.polname, policy.polpermissive, policy.polcmd, "
            "ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(role_oid) END FROM unnest(policy.polroles) AS role_oid "
            "ORDER BY 1), pg_get_expr(policy.polqual, policy.polrelid), "
            "pg_get_expr(policy.polwithcheck, policy.polrelid) FROM pg_policy AS policy "
            "JOIN pg_class AS relation ON relation.oid = policy.polrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "ORDER BY relation.relname, policy.polname",
            parameters,
        ),
        "triggers": rows(
            "SELECT relation.relname, trigger.tgname, trigger.tgenabled, "
            "pg_get_triggerdef(trigger.oid, true) FROM pg_trigger AS trigger "
            "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' AND owner.rolname = :owner "
            "AND NOT trigger.tgisinternal ORDER BY relation.relname, trigger.tgname",
            parameters,
        ),
        "default_acls": rows(
            f"SELECT owner.rolname, COALESCE(namespace.nspname, ''), defaults.defaclobjtype, "
            f"{role_name}, {grantor_name}, acl.privilege_type, acl.is_grantable "
            "FROM pg_default_acl AS defaults "
            "JOIN pg_roles AS owner ON owner.oid = defaults.defaclrole "
            "LEFT JOIN pg_namespace AS namespace ON namespace.oid = defaults.defaclnamespace "
            "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl "
            "WHERE owner.rolname = :owner AND (namespace.nspname = 'public' "
            "OR defaults.defaclnamespace = 0) ORDER BY 1, 2, 3, 4, 5, 6, 7",
            parameters,
        ),
    }


def _verify_state(
    plan: ProductionPostgreSqlPlan,
    engines: Mapping[AuthorityKind, Engine],
) -> _VerifiedState:
    with engines["principal_operator"].connect() as principal_connection:
        _verify_capability_principals(
            principal_connection,
            bindings=plan.service_role_bindings,
            principal_operator=plan.principal_operator.login,
        )
    with engines["database_owner"].connect() as database_connection:
        _verify_database_boundary(
            database_connection,
            principal_operator=plan.principal_operator.login,
            official_owner=plan.official_owner.login,
            saas_owner=plan.saas_owner.login,
            bindings=plan.service_role_bindings,
        )
    with engines["official_owner"].connect() as official_connection:
        server_version_num, bootstrap_name = official_connection.execute(
            sa.text(
                "SELECT current_setting('server_version_num')::integer, "
                "(SELECT rolname FROM pg_roles WHERE oid = 10)"
            )
        ).one()
        official_head = _version_at_head(official_connection, kind="official")
        verify_runtime_rls(official_connection)
        runtime_acls = _verify_runtime_acl(official_connection)
        official_security = _official_security_catalog(
            official_connection,
            official_owner=plan.official_owner.login,
        )
        with engines["saas_owner"].connect() as saas_connection:
            saas_head = _version_at_head(saas_connection, kind="saas")
            ownership = _verify_object_ownership(
                official_connection,
                saas_connection,
                official_owner=plan.official_owner.login,
                saas_owner=plan.saas_owner.login,
            )
            control_plane_security = _control_plane_security_catalog(
                saas_connection,
                saas_owner=plan.saas_owner.login,
            )
    catalog = {
        "official_head": official_head,
        "saas_head": saas_head,
        "ownership": ownership,
        "runtime_acls": runtime_acls,
        "runtime_rls_tables": [contract.table_name for contract in load_runtime_rls_contract()],
        "official_security": official_security,
        "control_plane_security": control_plane_security,
    }
    _verify_source_security_catalog_digest(
        catalog,
        key=(int(server_version_num) // 10000, official_head, saas_head),
        role_aliases=_source_catalog_role_aliases(
            principal_operator=plan.principal_operator.login,
            database_owner=plan.database_owner.login,
            official_owner=plan.official_owner.login,
            saas_owner=plan.saas_owner.login,
            bootstrap_name=str(bootstrap_name),
            bindings=plan.service_role_bindings,
        ),
    )
    digest = hashlib.sha256(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return _VerifiedState(
        official_head=official_head,
        saas_head=saas_head,
        runtime_rls_table_count=len(load_runtime_rls_contract()),
        catalog_sha256=digest,
    )


def _load_runtime_receipt(config: Any) -> _RuntimeReceipt:
    configured = getattr(config, "migration_receipt", None)
    path_value = getattr(configured, "path", None)
    if configured is None or not isinstance(path_value, Path) or not path_value.is_absolute():
        raise PostgreSqlMigrationError("migration_receipt_missing", "runtime_verification")
    try:
        metadata = path_value.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_RECEIPT_BYTES
            or mode & 0o277
            or not mode & 0o400
        ):
            raise OSError
        document = json.loads(path_value.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PostgreSqlMigrationError(
            "migration_receipt_invalid", "runtime_verification"
        ) from None
    if not isinstance(document, dict):
        raise PostgreSqlMigrationError("migration_receipt_invalid", "runtime_verification")

    product_revision = getattr(config, "product_revision", None)
    official_head = getattr(config, "official_schema_revision", None)
    saas_head = getattr(config, "control_plane_schema_revision", None)
    bindings = {
        "product_revision": product_revision,
        "official_head": official_head,
        "saas_head": saas_head,
    }
    if (
        document.get("schema_version") != 1
        or document.get("status") != "pass"
        or any(document.get(key) != value for key, value in bindings.items())
        or any(getattr(configured, key, None) != value for key, value in bindings.items())
        or product_revision != _installed_product_revision()
        or official_head != _expected_head("official")
        or saas_head != _expected_head("saas")
    ):
        raise PostgreSqlMigrationError(
            "migration_receipt_binding_mismatch", "runtime_verification"
        )
    database_identity = document.get("database_identity_sha256")
    catalog = document.get("catalog_sha256")
    service_bindings = document.get("service_role_bindings_sha256")
    table_count = document.get("runtime_rls_table_count")
    if (
        not isinstance(database_identity, str)
        or _SHA256.fullmatch(database_identity) is None
        or not isinstance(catalog, str)
        or _SHA256.fullmatch(catalog) is None
        or not isinstance(service_bindings, str)
        or _SHA256.fullmatch(service_bindings) is None
        or service_bindings != config.service_role_bindings.sha256
        or getattr(configured, "service_role_bindings_sha256", None) != service_bindings
        or isinstance(table_count, bool)
        or table_count != len(load_runtime_rls_contract())
        or getattr(configured, "database_identity_sha256", None) != database_identity
        or getattr(configured, "catalog_sha256", None) != catalog
        or getattr(configured, "runtime_rls_table_count", None) != table_count
        or "state:verified" not in document.get("phases", [])
    ):
        raise PostgreSqlMigrationError("migration_receipt_facts_invalid", "runtime_verification")
    raw_authorities = document.get("authorities")
    if not isinstance(raw_authorities, list):
        raise PostgreSqlMigrationError(
            "migration_receipt_authorities_invalid", "runtime_verification"
        )
    authorities: dict[str, str] = {}
    for item in raw_authorities:
        if (
            not isinstance(item, dict)
            or set(item) != {"kind", "login"}
            or item.get("kind") not in _AUTHORITY_KINDS
            or not isinstance(item.get("login"), str)
            or _ROLE_NAME.fullmatch(item["login"]) is None
            or item["kind"] in authorities
        ):
            raise PostgreSqlMigrationError(
                "migration_receipt_authorities_invalid", "runtime_verification"
            )
        authorities[item["kind"]] = item["login"]
    if set(authorities) != set(_AUTHORITY_KINDS):
        raise PostgreSqlMigrationError(
            "migration_receipt_authorities_invalid", "runtime_verification"
        )
    return _RuntimeReceipt(
        product_revision=str(product_revision),
        official_head=str(official_head),
        saas_head=str(saas_head),
        database_identity_sha256=database_identity,
        catalog_sha256=catalog,
        service_role_bindings_sha256=service_bindings,
        runtime_rls_table_count=cast(int, table_count),
        official_owner=authorities["official_owner"],
        saas_owner=authorities["saas_owner"],
        principal_operator=authorities["principal_operator"],
        database_owner=authorities["database_owner"],
    )


def _inspect_service_login(
    engine: Engine,
    *,
    expected_login: str,
    expected_role: str,
) -> _ServiceSessionFacts:
    if engine.dialect.name != "postgresql" or _ROLE_NAME.fullmatch(expected_login) is None:
        raise PostgreSqlMigrationError("service_engine_invalid", "runtime_verification")
    try:
        with engine.connect() as connection:
            identity = connection.execute(
                sa.text(
                    "SELECT current_user, session_user, current_database(), current_schema(), "
                    "current_schemas(false), database.oid, pg_get_userbyid(database.datdba), "
                    "current_setting('server_version_num')::integer, "
                    "COALESCE(inet_server_addr()::text, ''), COALESCE(inet_server_port(), 0), "
                    "pg_is_in_recovery(), COALESCE(ssl.ssl, false), "
                    "has_schema_privilege(current_user, 'public', 'CREATE') "
                    "FROM pg_database AS database LEFT JOIN pg_stat_ssl AS ssl "
                    "ON ssl.pid = pg_backend_pid() WHERE database.datname = current_database()"
                )
            ).one()
            login_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            ).one_or_none()
            base_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                    "FROM pg_roles WHERE rolname = :role"
                ),
                {"role": expected_role},
            ).one_or_none()
            membership_projection = (
                "granted.rolname, membership.admin_option, "
                "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
                "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true) "
            )
            login_memberships = [
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        f"SELECT {membership_projection}"
                        "FROM pg_auth_members AS membership "
                        "JOIN pg_roles AS member ON member.oid = membership.member "
                        "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                        "WHERE member.rolname = current_user ORDER BY granted.rolname"
                    )
                ).all()
            ]
            base_memberships = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "WHERE member.rolname = :role"
                ),
                {"role": expected_role},
            ).scalar_one()
            login_incoming = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE granted.rolname = current_user"
                )
            ).scalar_one()
            role_settings = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_db_role_setting AS setting "
                    "JOIN pg_roles AS role ON role.oid = setting.setrole "
                    "WHERE role.rolname IN (:login, :base)"
                ),
                {"login": expected_login, "base": expected_role},
            ).scalar_one()
            direct_authority = connection.execute(
                sa.text(
                    "WITH login AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
                    "authority AS ("
                    "SELECT 1 FROM pg_database object JOIN login ON object.datdba = login.oid "
                    "UNION ALL SELECT 1 FROM pg_namespace object "
                    "JOIN login ON object.nspowner = login.oid "
                    "UNION ALL SELECT 1 FROM pg_class object "
                    "JOIN login ON object.relowner = login.oid "
                    "UNION ALL SELECT 1 FROM pg_proc object "
                    "JOIN login ON object.proowner = login.oid "
                    "UNION ALL SELECT 1 FROM pg_type object "
                    "JOIN login ON object.typowner = login.oid "
                    "UNION ALL SELECT 1 FROM pg_default_acl object "
                    "JOIN login ON object.defaclrole = login.oid "
                    "UNION ALL SELECT 1 FROM pg_database object "
                    "CROSS JOIN LATERAL aclexplode(object.datacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_namespace object "
                    "CROSS JOIN LATERAL aclexplode(object.nspacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_class object "
                    "CROSS JOIN LATERAL aclexplode(object.relacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_attribute object "
                    "CROSS JOIN LATERAL aclexplode(object.attacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "WHERE object.attnum > 0 AND NOT object.attisdropped "
                    "UNION ALL SELECT 1 FROM pg_proc object "
                    "CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_type object "
                    "CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                    "JOIN login ON acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_default_acl object "
                    "CROSS JOIN LATERAL aclexplode(object.defaclacl) acl "
                    "JOIN login ON acl.grantee = login.oid) "
                    "SELECT count(*) FROM authority"
                )
            ).scalar_one()
    except sa.exc.SQLAlchemyError:
        raise PostgreSqlMigrationError(
            "service_login_probe_failed", "runtime_verification"
        ) from None

    (
        current_user,
        session_user,
        database,
        current_schema,
        search_path,
        database_oid,
        database_owner,
        server_version_num,
        server_address,
        server_port,
        in_recovery,
        tls,
        can_create_schema,
    ) = identity
    expected_login_flags = (True, False, False, False, False, False, True, -1, None)
    expected_base_flags = (False, False, False, False, False, False, True, -1, None)
    if (
        current_user != expected_login
        or session_user != expected_login
        or current_schema != "public"
        or list(search_path) != ["public"]
        or in_recovery
        or not tls
        or can_create_schema
        or tuple(login_role or ()) != expected_login_flags
        or tuple(base_role or ()) != expected_base_flags
        or login_memberships != [(expected_role, False, True, False)]
        or base_memberships
        or login_incoming
        or role_settings
        or direct_authority
    ):
        raise PostgreSqlMigrationError("service_login_authority_drifted", "runtime_verification")
    return _ServiceSessionFacts(
        login=expected_login,
        database=str(database),
        database_oid=int(database_oid),
        database_owner=str(database_owner),
        server_version_num=int(server_version_num),
        server_address=str(server_address),
        server_port=int(server_port),
    )


def verify_production_postgresql_state(
    *,
    engines: Mapping[str, Engine],
    config: Any,
) -> None:
    """Verify an immutable migration receipt against five live service logins.

    This startup path performs catalog reads only.  It never opens an owner
    authority, runs Alembic, changes a role, or grants a privilege.
    """

    try:
        receipt = _load_runtime_receipt(config)
        if set(engines) != set(_SERVER_SERVICE_ROLES):
            raise PostgreSqlMigrationError("service_engine_set_invalid", "runtime_verification")
        configured_urls = config.secrets.database_urls.as_mapping()
        if set(configured_urls) != set(_SERVER_SERVICE_ROLES):
            raise PostgreSqlMigrationError("service_url_set_invalid", "runtime_verification")
        facts: list[_ServiceSessionFacts] = []
        for service, expected_role in _SERVER_SERVICE_ROLES.items():
            parsed = make_url(configured_urls[service])
            if parsed.username is None:
                raise PostgreSqlMigrationError("service_url_login_missing", "runtime_verification")
            if parsed.username != config.service_role_bindings.login_for(service):
                raise PostgreSqlMigrationError(
                    "service_url_binding_mismatch", "runtime_verification"
                )
            facts.append(
                _inspect_service_login(
                    engines[service],
                    expected_login=parsed.username,
                    expected_role=expected_role,
                )
            )
        if len({fact.login for fact in facts}) != len(_SERVER_SERVICE_ROLES):
            raise PostgreSqlMigrationError("service_login_not_distinct", "runtime_verification")
        database_facts = {
            (
                fact.database,
                fact.database_oid,
                fact.database_owner,
                fact.server_version_num,
                fact.server_address,
                fact.server_port,
            )
            for fact in facts
        }
        if len(database_facts) != 1:
            raise PostgreSqlMigrationError(
                "service_database_identity_drifted", "runtime_verification"
            )
        first = facts[0]
        identity_payload = {
            "database": first.database,
            "database_oid": first.database_oid,
            "database_owner": first.database_owner,
            "server_version_num": first.server_version_num,
            "server_address": first.server_address,
            "server_port": first.server_port,
        }
        identity_digest = hashlib.sha256(
            json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if identity_digest != receipt.database_identity_sha256:
            raise PostgreSqlMigrationError(
                "service_database_receipt_mismatch", "runtime_verification"
            )
        with engines["runtime"].connect() as connection:
            server_version_num, bootstrap_name = connection.execute(
                sa.text(
                    "SELECT current_setting('server_version_num')::integer, "
                    "(SELECT rolname FROM pg_roles WHERE oid = 10)"
                )
            ).one()
            _verify_capability_principals(
                connection,
                bindings=config.service_role_bindings,
                principal_operator=receipt.principal_operator,
            )
            _verify_database_boundary(
                connection,
                principal_operator=receipt.principal_operator,
                official_owner=receipt.official_owner,
                saas_owner=receipt.saas_owner,
                bindings=config.service_role_bindings,
            )
            verify_runtime_rls(connection)
            runtime_acls = _verify_runtime_acl(connection)
            official_security = _official_security_catalog(
                connection,
                official_owner=receipt.official_owner,
            )
            control_plane_security = _control_plane_security_catalog(
                connection,
                saas_owner=receipt.saas_owner,
            )
            ownership = _verify_object_ownership(
                connection,
                connection,
                official_owner=receipt.official_owner,
                saas_owner=receipt.saas_owner,
            )
        catalog = {
            "official_head": receipt.official_head,
            "saas_head": receipt.saas_head,
            "ownership": ownership,
            "runtime_acls": runtime_acls,
            "runtime_rls_tables": [
                contract.table_name for contract in load_runtime_rls_contract()
            ],
            "official_security": official_security,
            "control_plane_security": control_plane_security,
        }
        _verify_source_security_catalog_digest(
            catalog,
            key=(
                int(server_version_num) // 10000,
                receipt.official_head,
                receipt.saas_head,
            ),
            role_aliases=_source_catalog_role_aliases(
                principal_operator=receipt.principal_operator,
                database_owner=receipt.database_owner,
                official_owner=receipt.official_owner,
                saas_owner=receipt.saas_owner,
                bootstrap_name=str(bootstrap_name),
                bindings=config.service_role_bindings,
            ),
        )
        catalog_digest = hashlib.sha256(
            json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if catalog_digest != receipt.catalog_sha256:
            raise PostgreSqlMigrationError(
                "service_catalog_receipt_mismatch", "runtime_verification"
            )
    except PostgreSqlMigrationError:
        raise
    except Exception:  # noqa: BLE001 - startup verification never leaks DSN/provider data
        raise PostgreSqlMigrationError(
            "runtime_verification_failed", "runtime_verification"
        ) from None


@contextmanager
def _migration_lock(engine: Engine, *, timeout_seconds: float) -> Iterator[None]:
    with engine.connect() as connection:
        deadline = time.monotonic() + timeout_seconds
        acquired = False
        while time.monotonic() < deadline:
            try:
                acquired = bool(
                    connection.execute(
                        sa.text("SELECT pg_try_advisory_lock(hashtextextended(:name, 0))"),
                        {"name": _LOCK_NAME},
                    ).scalar_one()
                )
                # Session-level advisory locks survive COMMIT.  Ending SQLAlchemy's
                # implicit transaction here is required because the official
                # Alembic stream contains CREATE INDEX CONCURRENTLY; leaving this
                # connection idle in transaction makes that DDL wait forever on
                # this session's virtual xid.
                connection.commit()
            except sa.exc.SQLAlchemyError:
                connection.rollback()
                raise
            if acquired:
                break
            time.sleep(0.1)
        if not acquired:
            raise PostgreSqlMigrationError("migration_lock_timeout", "lock")
        try:
            yield
        finally:
            try:
                connection.execute(
                    sa.text("SELECT pg_advisory_unlock(hashtextextended(:name, 0))"),
                    {"name": _LOCK_NAME},
                ).scalar_one()
                connection.commit()
            except sa.exc.SQLAlchemyError:
                connection.rollback()


def _phase(name: str, operation: Callable[[], None]) -> None:
    try:
        operation()
    except PostgreSqlMigrationError:
        raise
    except Exception:  # noqa: BLE001 - never expose driver/Alembic text containing DSNs
        raise PostgreSqlMigrationError("phase_execution_failed", name) from None


def run_production_postgresql_migration(
    plan: ProductionPostgreSqlPlan,
    *,
    verify_only: bool = False,
) -> PostgreSqlMigrationReceipt:
    """Apply the ordered authority chain, or verify it without mutations."""

    _validate_plan(plan)
    engines = _create_engines(plan)
    phases: list[str] = []
    try:
        session_facts = _preflight(plan, engines)
        phases.append("preflight:verified")
        with engines["official_owner"].connect() as official_connection:
            _preflight_pg_trgm_extension(
                official_connection,
                official_owner=plan.official_owner.login,
            )
        phases.append("pg_trgm_preflight:verified")
        if not verify_only:
            with _migration_lock(
                engines["database_owner"],
                timeout_seconds=plan.lock_timeout_seconds,
            ):
                locked_session_facts = _preflight(plan, engines)
                if locked_session_facts != session_facts:
                    raise PostgreSqlMigrationError(
                        "authority_identity_changed_under_lock",
                        "preflight",
                    )
                phases.append("lock_preflight:verified")
                with engines["official_owner"].connect() as official_connection:
                    _preflight_pg_trgm_extension(
                        official_connection,
                        official_owner=plan.official_owner.login,
                    )
                phases.append("lock_pg_trgm_preflight:verified")
                _phase(
                    "principals",
                    lambda: _apply_principals(
                        engines["principal_operator"],
                        bindings=plan.service_role_bindings,
                        principal_operator=plan.principal_operator.login,
                    ),
                )
                phases.append("principals:applied")
                _phase(
                    "database",
                    lambda: _apply_database_authority(
                        engines["database_owner"],
                        principal_operator=plan.principal_operator.login,
                        official_owner=plan.official_owner.login,
                        saas_owner=plan.saas_owner.login,
                        bindings=plan.service_role_bindings,
                    ),
                )
                phases.append("database:applied")
                _phase("official_alembic", lambda: _upgrade(engines["official_owner"], "official"))
                phases.append("official_alembic:applied")
                _phase("saas_alembic", lambda: _upgrade(engines["saas_owner"], "saas"))
                phases.append("saas_alembic:applied")
                _phase(
                    "runtime_authority",
                    lambda: _apply_runtime_authority(engines["official_owner"]),
                )
                phases.append("runtime_authority:applied")
                _phase(
                    "control_plane_authority",
                    lambda: _apply_control_plane_authority(engines["saas_owner"]),
                )
                phases.append("control_plane_authority:applied")
                _phase(
                    "database_acl_finalize",
                    lambda: _finalize_database_authority(
                        engines["database_owner"],
                        principal_operator=plan.principal_operator.login,
                        official_owner=plan.official_owner.login,
                        saas_owner=plan.saas_owner.login,
                        bindings=plan.service_role_bindings,
                    ),
                )
                phases.append("database_acl_finalize:applied")
        verified = _verify_state(plan, engines)
        phases.append("state:verified")
    except PostgreSqlMigrationError:
        raise
    except Exception:  # noqa: BLE001 - verification errors stay content-free
        raise PostgreSqlMigrationError("verification_failed", "verification") from None
    finally:
        _dispose_engines(engines)

    identity_payload = {
        "database": session_facts[0].database,
        "database_oid": session_facts[0].database_oid,
        "database_owner": session_facts[0].database_owner,
        "server_version_num": session_facts[0].server_version_num,
        "server_address": session_facts[0].server_address,
        "server_port": session_facts[0].server_port,
    }
    identity_sha256 = hashlib.sha256(
        json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return PostgreSqlMigrationReceipt(
        schema_version=1,
        status="pass",
        verify_only=verify_only,
        product_revision=plan.product_revision,
        database_identity_sha256=identity_sha256,
        official_head=verified.official_head,
        saas_head=verified.saas_head,
        runtime_rls_table_count=verified.runtime_rls_table_count,
        authorities=tuple((authority.kind, authority.login) for authority in plan.authorities()),
        phases=tuple(phases),
        catalog_sha256=verified.catalog_sha256,
        service_role_bindings_sha256=plan.service_role_bindings.sha256,
        completed_at=datetime.now(UTC).isoformat(),
    )


__all__ = [
    "PostgreSqlAuthority",
    "PostgreSqlMigrationError",
    "PostgreSqlMigrationReceipt",
    "ProductionPostgreSqlPlan",
    "parse_production_postgresql_url",
    "run_production_postgresql_migration",
    "verify_production_postgresql_state",
]
