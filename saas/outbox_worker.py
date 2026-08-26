"""Production process loop for the control-plane Outbox dispatcher."""

from __future__ import annotations

import importlib
import logging
import os
import signal
import threading
from dataclasses import dataclass
from typing import Protocol, cast

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.outbox import DispatchResult, OutboxDispatcher, OutboxPublisher
from saas.onboarding_composition import validate_production_outbox_publisher

_LOGGER = logging.getLogger("omnigent-saas-outbox")
_EXPECTED_DISPATCHER_RELATION_ACLS = {
    ("public", "saas_control_plane_outbox", "r", "SELECT", False),
    ("public", "saas_outbox_quarantine_events", "r", "INSERT", False),
    ("public", "saas_outbox_quarantine_events", "r", "SELECT", False),
}
_EXPECTED_DISPATCHER_SCHEMA_ACLS = {("public", "USAGE", False)}
_EXPECTED_DISPATCHER_COLUMN_ACLS = {
    ("public", "saas_control_plane_outbox", column, "UPDATE", False)
    for column in (
        "attempt_count",
        "available_at",
        "claimed_at",
        "claim_token",
        "last_error_code",
        "last_error_digest",
        "published_at",
        "quarantined_at",
    )
} | {
    ("public", table, column, "SELECT", False)
    for table, columns in (
        (
            "saas_platform_role_assignments",
            ("principal_id", "role", "status", "expires_at"),
        ),
        (
            "saas_platform_support_sessions",
            ("principal_id", "token_hash", "revoked_at", "expires_at"),
        ),
    )
    for column in columns
}


class _Dispatcher(Protocol):
    def dispatch_once(self, *, batch_size: int = 100) -> DispatchResult: ...


class _StopSignal(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


@dataclass(frozen=True, slots=True)
class OutboxWorkerStats:
    """Aggregate counters returned after a graceful worker stop."""

    cycles: int
    claimed: int
    published: int
    event_failures: int
    quarantined: int
    infrastructure_failures: int


class OutboxWorker:
    """Drain ready events, idle efficiently, and survive transient DB failures."""

    def __init__(
        self,
        dispatcher: _Dispatcher,
        *,
        batch_size: int = 100,
        idle_interval: float = 0.5,
        error_backoff: float = 1.0,
        max_error_backoff: float = 30.0,
        logger: logging.Logger | None = None,
    ) -> None:
        if not 1 <= batch_size <= 1000:
            raise ValueError("Outbox worker batch_size must be between 1 and 1000")
        if min(idle_interval, error_backoff, max_error_backoff) <= 0:
            raise ValueError("Outbox worker intervals must be positive")
        if max_error_backoff < error_backoff:
            raise ValueError("maximum error backoff must not be smaller than initial backoff")
        self._dispatcher = dispatcher
        self._batch_size = batch_size
        self._idle_interval = idle_interval
        self._error_backoff = error_backoff
        self._max_error_backoff = max_error_backoff
        self._logger = logger or _LOGGER

    def run(self, stop: _StopSignal) -> OutboxWorkerStats:
        """Run until ``stop`` is set, returning counters for shutdown logs."""

        cycles = claimed = published = event_failures = quarantined = infrastructure_failures = 0
        consecutive_errors = 0
        while not stop.is_set():
            try:
                result = self._dispatcher.dispatch_once(batch_size=self._batch_size)
            except Exception:  # noqa: BLE001 - the long-running worker retries infrastructure faults
                infrastructure_failures += 1
                consecutive_errors += 1
                delay = min(
                    self._max_error_backoff,
                    self._error_backoff * (2 ** min(consecutive_errors - 1, 10)),
                )
                # A dispatcher failure can occur while handling a Provider
                # exception.  Never serialize the exception chain: transport
                # messages and SQL bind values are not an observability API.
                self._logger.error(
                    "Outbox dispatch cycle failed; retrying in %.3fs",
                    delay,
                )
            else:
                cycles += 1
                claimed += result.claimed
                published += result.published
                event_failures += result.failed
                quarantined += result.quarantined
                consecutive_errors = 0
                # A full batch probably means backlog remains. Drain without
                # sleeping, but yield when a partial/empty batch is observed.
                delay = 0.0 if result.claimed == self._batch_size else self._idle_interval
            if delay > 0 and stop.wait(delay):
                break
        return OutboxWorkerStats(
            cycles=cycles,
            claimed=claimed,
            published=published,
            event_failures=event_failures,
            quarantined=quarantined,
            infrastructure_failures=infrastructure_failures,
        )


def verify_dispatcher_database_role(engine: Engine) -> None:
    """Fail startup unless the connection is a non-bypass dispatcher login."""

    if engine.dialect.name != "postgresql":
        raise RuntimeError("the production Outbox worker requires PostgreSQL")
    with engine.connect() as connection:
        schema_facts = connection.execute(
            sa.text(
                "SELECT current_schema(), current_schemas(false), "
                "has_schema_privilege(current_user, 'public', 'CREATE'), "
                "has_database_privilege(current_user, current_database(), 'TEMP')"
            )
        ).one()
        facts = connection.execute(
            sa.text(
                """
                SELECT current_user,
                       session_user,
                       role.rolcanlogin,
                       role.rolsuper,
                       role.rolcreatedb,
                       role.rolcreaterole,
                       role.rolreplication,
                       role.rolbypassrls,
                       role.rolinherit,
                       pg_has_role(current_user, 'saas_dispatcher', 'member'),
                       pg_has_role(current_user, 'saas_platform', 'member'),
                       pg_has_role(current_user, 'saas_app', 'member'),
                       pg_has_role(current_user, 'saas_authenticator', 'member'),
                       pg_has_role(current_user, 'saas_governance', 'member'),
                       pg_has_role(current_user, 'saas_executor', 'member')
                FROM pg_roles AS role
                WHERE role.rolname = current_user
                """
            )
        ).one()
        base_facts = connection.execute(
            sa.text(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit "
                "FROM pg_roles WHERE rolname = 'saas_dispatcher'"
            )
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
                "WHERE member.rolname = 'saas_dispatcher' ORDER BY granted.rolname"
            )
        ).all()
        direct_login_authority = connection.execute(
            sa.text(
                "WITH login AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
                "direct_authority AS ("
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(object.relacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_attribute attribute "
                "JOIN pg_class object ON object.oid = attribute.attrelid "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(attribute.attacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' "
                "AND attribute.attnum > 0 "
                "AND NOT attribute.attisdropped UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "CROSS JOIN LATERAL aclexplode(object.proacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "CROSS JOIN LATERAL aclexplode(object.typacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_namespace object "
                "CROSS JOIN LATERAL aclexplode(object.nspacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE object.nspname !~ '^pg_' "
                "AND object.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_database object "
                "CROSS JOIN LATERAL aclexplode(object.datacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE object.datname = current_database() UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults "
                "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults JOIN login "
                "ON defaults.defaclrole = login.oid UNION ALL "
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "JOIN login ON object.relowner = login.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "JOIN login ON object.proowner = login.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "JOIN login ON object.typowner = login.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_namespace object JOIN login "
                "ON object.nspowner = login.oid WHERE object.nspname !~ '^pg_' "
                "AND object.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_database object JOIN login ON object.datdba = login.oid "
                "WHERE object.datname = current_database()) "
                "SELECT count(*) FROM direct_authority"
            )
        ).scalar_one()
        base_relation_acls = connection.execute(
            sa.text(
                "SELECT namespace.nspname, relation.relname, relation.relkind, "
                "acl.privilege_type, "
                "acl.is_grantable FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_roles AS dispatcher ON dispatcher.rolname = 'saas_dispatcher' "
                "CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' "
                "AND acl.grantee = dispatcher.oid "
                "ORDER BY namespace.nspname, relation.relname, acl.privilege_type"
            )
        ).all()
        base_column_acls = connection.execute(
            sa.text(
                "SELECT namespace.nspname, relation.relname, attribute.attname, "
                "acl.privilege_type, "
                "acl.is_grantable FROM pg_class AS relation "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid "
                "JOIN pg_roles AS dispatcher ON dispatcher.rolname = 'saas_dispatcher' "
                "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' "
                "AND attribute.attnum > 0 "
                "AND NOT attribute.attisdropped AND acl.grantee = dispatcher.oid "
                "ORDER BY namespace.nspname, relation.relname, attribute.attnum, "
                "acl.privilege_type"
            )
        ).all()
        base_schema_acls = connection.execute(
            sa.text(
                "SELECT namespace.nspname, acl.privilege_type, acl.is_grantable "
                "FROM pg_namespace AS namespace "
                "JOIN pg_roles AS dispatcher ON dispatcher.rolname = 'saas_dispatcher' "
                "CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' "
                "AND acl.grantee = dispatcher.oid "
                "ORDER BY acl.privilege_type"
            )
        ).all()
        base_non_relation_authority = connection.execute(
            sa.text(
                "WITH dispatcher AS ("
                "SELECT oid FROM pg_roles WHERE rolname = 'saas_dispatcher'), "
                "unexpected AS ("
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                "JOIN dispatcher ON acl.grantee = dispatcher.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                "JOIN dispatcher ON acl.grantee = dispatcher.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_database object "
                "CROSS JOIN LATERAL aclexplode(object.datacl) acl "
                "JOIN dispatcher ON acl.grantee = dispatcher.oid "
                "WHERE object.datname = current_database() UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults "
                "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl "
                "JOIN dispatcher ON acl.grantee = dispatcher.oid UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults JOIN dispatcher "
                "ON defaults.defaclrole = dispatcher.oid UNION ALL "
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "JOIN dispatcher ON object.relowner = dispatcher.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "JOIN dispatcher ON object.proowner = dispatcher.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_type object "
                "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                "JOIN dispatcher ON object.typowner = dispatcher.oid "
                "WHERE namespace.nspname !~ '^pg_' "
                "AND namespace.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_namespace object JOIN dispatcher "
                "ON object.nspowner = dispatcher.oid "
                "WHERE object.nspname !~ '^pg_' "
                "AND object.nspname <> 'information_schema' UNION ALL "
                "SELECT 1 FROM pg_database object JOIN dispatcher "
                "ON object.datdba = dispatcher.oid "
                "WHERE object.datname = current_database()) "
                "SELECT count(*) FROM unexpected"
            )
        ).scalar_one()
        owned_tables = connection.execute(
            sa.text(
                """
                SELECT count(*)
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                JOIN pg_roles AS owner ON owner.oid = relation.relowner
                WHERE namespace.nspname = 'public'
                  AND relation.relkind IN ('r', 'p')
                  AND relation.relname LIKE 'saas_%'
                  AND owner.rolname = current_user
                """
            )
        ).scalar_one()
        forbidden_table_privileges = connection.execute(
            sa.text(
                """
                SELECT count(*)
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname <> 'information_schema'
                  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                  AND NOT (
                      namespace.nspname = 'public'
                      AND relation.relname IN (
                          'saas_control_plane_outbox', 'saas_outbox_quarantine_events',
                          'saas_platform_role_assignments',
                          'saas_platform_support_sessions'
                      )
                  )
                  AND (
                      (
                          relation.relkind = 'S'
                          AND has_sequence_privilege(
                              current_user, relation.oid, 'USAGE,SELECT,UPDATE'
                          )
                      )
                      OR (
                          relation.relkind <> 'S'
                          AND (
                              has_table_privilege(current_user, relation.oid, 'SELECT')
                              OR has_table_privilege(current_user, relation.oid, 'INSERT')
                              OR has_table_privilege(current_user, relation.oid, 'UPDATE')
                              OR has_table_privilege(current_user, relation.oid, 'DELETE')
                              OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                              OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
                              OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                              OR has_any_column_privilege(current_user, relation.oid, 'SELECT')
                              OR has_any_column_privilege(current_user, relation.oid, 'INSERT')
                              OR has_any_column_privilege(current_user, relation.oid, 'UPDATE')
                              OR has_any_column_privilege(
                                  current_user, relation.oid, 'REFERENCES'
                              )
                          )
                      )
                  )
                """
            )
        ).scalar_one()
        executable_security_definers = connection.execute(
            sa.text(
                """
                SELECT count(*)
                FROM pg_proc AS function
                JOIN pg_namespace AS namespace ON namespace.oid = function.pronamespace
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname <> 'information_schema'
                  AND function.prosecdef
                  AND has_function_privilege(current_user, function.oid, 'EXECUTE')
                """
            )
        ).scalar_one()
        forbidden_schema_privileges = connection.execute(
            sa.text(
                """
                SELECT count(*)
                FROM pg_namespace AS namespace
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname NOT IN ('information_schema', 'public')
                  AND (
                      has_schema_privilege(current_user, namespace.oid, 'USAGE')
                      OR has_schema_privilege(current_user, namespace.oid, 'CREATE')
                  )
                """
            )
        ).scalar_one()
        planning_privileges = connection.execute(
            sa.text(
                """
                WITH allowed(table_name, column_name) AS (
                    VALUES
                        ('saas_platform_role_assignments', 'principal_id'),
                        ('saas_platform_role_assignments', 'role'),
                        ('saas_platform_role_assignments', 'status'),
                        ('saas_platform_role_assignments', 'expires_at'),
                        ('saas_platform_support_sessions', 'principal_id'),
                        ('saas_platform_support_sessions', 'token_hash'),
                        ('saas_platform_support_sessions', 'revoked_at'),
                        ('saas_platform_support_sessions', 'expires_at')
                )
                SELECT
                    bool_and(has_column_privilege(
                        current_user,
                        'public.' || allowed.table_name,
                        allowed.column_name,
                        'SELECT'
                    )),
                    (
                        SELECT count(*)
                        FROM information_schema.columns AS candidate
                        WHERE candidate.table_schema = 'public'
                          AND candidate.table_name IN (
                              'saas_platform_role_assignments',
                              'saas_platform_support_sessions'
                          )
                          AND NOT EXISTS (
                              SELECT 1 FROM allowed
                              WHERE allowed.table_name = candidate.table_name
                                AND allowed.column_name = candidate.column_name
                          )
                          AND has_column_privilege(
                              current_user,
                              'public.' || candidate.table_name,
                              candidate.column_name,
                              'SELECT'
                          )
                    ),
                    (
                        SELECT count(*)
                        FROM pg_class AS relation
                        JOIN pg_namespace AS namespace
                          ON namespace.oid = relation.relnamespace
                        WHERE namespace.nspname = 'public'
                          AND relation.relname IN (
                              'saas_platform_role_assignments',
                              'saas_platform_support_sessions'
                          )
                          AND (
                              has_table_privilege(
                                  current_user, relation.oid,
                                  'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
                              )
                              OR has_any_column_privilege(
                                  current_user, relation.oid,
                                  'INSERT,UPDATE,REFERENCES'
                              )
                          )
                    )
                FROM allowed
                """
            )
        ).one()
        outbox_privileges = connection.execute(
            sa.text(
                """
                SELECT has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'SELECT'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'UPDATE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'INSERT'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'DELETE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'TRUNCATE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'REFERENCES'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_control_plane_outbox', 'TRIGGER'
                       ),
                       has_any_column_privilege(
                           current_user, 'public.saas_control_plane_outbox',
                           'INSERT,REFERENCES'
                       )
                """
            )
        ).one()
        outbox_update_columns = connection.execute(
            sa.text(
                """
                WITH allowed(column_name) AS (
                    VALUES
                        ('attempt_count'),
                        ('available_at'),
                        ('claimed_at'),
                        ('claim_token'),
                        ('last_error_code'),
                        ('last_error_digest'),
                        ('published_at'),
                        ('quarantined_at')
                )
                SELECT
                    bool_and(has_column_privilege(
                        current_user,
                        'public.saas_control_plane_outbox',
                        allowed.column_name,
                        'UPDATE'
                    )),
                    (
                        SELECT count(*)
                        FROM information_schema.columns AS candidate
                        WHERE candidate.table_schema = 'public'
                          AND candidate.table_name = 'saas_control_plane_outbox'
                          AND NOT EXISTS (
                              SELECT 1 FROM allowed
                              WHERE allowed.column_name = candidate.column_name
                          )
                          AND has_column_privilege(
                              current_user,
                              'public.saas_control_plane_outbox',
                              candidate.column_name,
                              'UPDATE'
                          )
                    )
                FROM allowed
                """
            )
        ).one()
        quarantine_privileges = connection.execute(
            sa.text(
                """
                SELECT has_table_privilege(
                           current_user, 'public.saas_outbox_quarantine_events', 'SELECT'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_outbox_quarantine_events', 'INSERT'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_outbox_quarantine_events', 'UPDATE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_outbox_quarantine_events', 'DELETE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_outbox_quarantine_events', 'TRUNCATE'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_outbox_quarantine_events', 'REFERENCES'
                       ),
                       has_table_privilege(
                           current_user, 'public.saas_outbox_quarantine_events', 'TRIGGER'
                       ),
                       has_any_column_privilege(
                           current_user, 'public.saas_outbox_quarantine_events',
                           'UPDATE,REFERENCES'
                       )
                """
            )
        ).one()
    current_schema, search_path, can_create_in_schema, can_create_temporary_schema = schema_facts
    if current_schema != "public" or list(search_path) != ["public"] or can_create_in_schema:
        raise RuntimeError("Outbox database login must use only the public search_path")
    if can_create_temporary_schema:
        raise RuntimeError("Outbox database login must not create temporary schemas")
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
        is_dispatcher,
        is_platform,
        is_app,
        is_authenticator,
        is_governance,
        is_executor,
    ) = facts
    if current_user != session_user:
        raise RuntimeError("Outbox connection must not start under an assumed database role")
    if (
        not can_login
        or is_superuser
        or can_create_database
        or can_create_role
        or can_replicate
        or bypasses_rls
        or not inherits_roles
    ):
        raise RuntimeError("Outbox database login violates the non-bypass RLS posture")
    if base_facts != (False, False, False, False, False, False, True):
        raise RuntimeError("saas_dispatcher must remain a NOLOGIN non-bypass base role")
    if not is_dispatcher or any(
        (is_platform, is_app, is_authenticator, is_governance, is_executor)
    ):
        raise RuntimeError(
            "Outbox database login must have only the dispatcher privilege boundary"
        )
    if (
        len(login_memberships) != 1
        or login_memberships[0][0] != "saas_dispatcher"
        or tuple(login_memberships[0][1:]) != (False, True, True)
        or base_memberships
    ):
        raise RuntimeError("Outbox database login has unsafe role membership options")
    if direct_login_authority:
        raise RuntimeError("Outbox database login must not hold direct database authority")
    relation_acl_facts = {
        (str(row[0]), str(row[1]), str(row[2]), str(row[3]), bool(row[4]))
        for row in base_relation_acls
    }
    column_acl_facts = {
        (str(row[0]), str(row[1]), str(row[2]), str(row[3]), bool(row[4]))
        for row in base_column_acls
    }
    schema_acl_facts = {(str(row[0]), str(row[1]), bool(row[2])) for row in base_schema_acls}
    if (
        relation_acl_facts != _EXPECTED_DISPATCHER_RELATION_ACLS
        or len(relation_acl_facts) != len(_EXPECTED_DISPATCHER_RELATION_ACLS)
        or column_acl_facts != _EXPECTED_DISPATCHER_COLUMN_ACLS
        or len(column_acl_facts) != len(_EXPECTED_DISPATCHER_COLUMN_ACLS)
        or schema_acl_facts != _EXPECTED_DISPATCHER_SCHEMA_ACLS
        or len(schema_acl_facts) != len(_EXPECTED_DISPATCHER_SCHEMA_ACLS)
        or base_non_relation_authority
    ):
        raise RuntimeError("saas_dispatcher has an unsafe direct or delegable authority set")
    if (
        owned_tables
        or forbidden_table_privileges
        or executable_security_definers
        or forbidden_schema_privileges
    ):
        raise RuntimeError(
            "Outbox database login must not own or access non-contract database objects"
        )
    exact_planning_columns, extra_planning_columns, unsafe_planning_writes = planning_privileges
    if not exact_planning_columns or extra_planning_columns or unsafe_planning_writes:
        raise RuntimeError("Outbox database login has unsafe planning-only grants")
    (
        can_select,
        can_update,
        can_insert,
        can_delete,
        can_truncate,
        can_reference,
        can_trigger,
        has_unsafe_column_create_authority,
    ) = outbox_privileges
    exact_update_columns, forbidden_update_columns = outbox_update_columns
    if (
        not can_select
        or can_update
        or not exact_update_columns
        or forbidden_update_columns
        or any(
            (
                can_insert,
                can_delete,
                can_truncate,
                can_reference,
                can_trigger,
                has_unsafe_column_create_authority,
            )
        )
    ):
        raise RuntimeError("Outbox database login has an unsafe Outbox table grant set")
    (
        can_read_quarantine,
        can_insert_quarantine,
        can_update_quarantine,
        can_delete_quarantine,
        can_truncate_quarantine,
        can_reference_quarantine,
        can_trigger_quarantine,
        has_unsafe_quarantine_column_authority,
    ) = quarantine_privileges
    if (
        not can_read_quarantine
        or not can_insert_quarantine
        or any(
            (
                can_update_quarantine,
                can_delete_quarantine,
                can_truncate_quarantine,
                can_reference_quarantine,
                can_trigger_quarantine,
                has_unsafe_quarantine_column_authority,
            )
        )
    ):
        raise RuntimeError("Outbox database login has an unsafe quarantine ledger grant set")


def _load_publisher(reference: str) -> OutboxPublisher:
    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        raise ValueError("publisher must use the 'module:attribute' form")
    candidate = getattr(importlib.import_module(module_name), attribute_name)
    if isinstance(candidate, type):
        publisher = candidate()
    elif callable(getattr(candidate, "publish", None)):
        publisher = candidate
    elif callable(candidate):
        publisher = candidate()
    else:
        raise TypeError("configured Outbox publisher is not an object, class, or factory")
    if not callable(getattr(publisher, "publish", None)):
        raise TypeError("configured Outbox publisher does not provide publish()")
    validate_production_outbox_publisher(cast(OutboxPublisher, publisher))
    return cast(OutboxPublisher, publisher)


def _positive_number(name: str, default: str, *, integer: bool = False) -> float | int:
    raw = os.environ.get(name, default)
    try:
        value = int(raw) if integer else float(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be a number") from error
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


def main() -> int:
    """Load a publisher adapter and run one RLS-constrained worker process."""

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    database_url = os.environ.get("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL", "").strip()
    publisher_reference = os.environ.get("OMNIGENT_SAAS_OUTBOX_PUBLISHER", "").strip()
    if not database_url:
        raise RuntimeError("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL is required")
    if not publisher_reference:
        raise RuntimeError("OMNIGENT_SAAS_OUTBOX_PUBLISHER is required")

    engine = sa.create_engine(database_url, pool_pre_ping=True)
    try:
        verify_dispatcher_database_role(engine)
        sessions = sessionmaker(engine, expire_on_commit=False, class_=Session)
        max_attempts = cast(
            int,
            _positive_number("OMNIGENT_SAAS_OUTBOX_MAX_ATTEMPTS", "8", integer=True),
        )
        if max_attempts > 32:
            raise RuntimeError("OMNIGENT_SAAS_OUTBOX_MAX_ATTEMPTS must not exceed 32")
        dispatcher = OutboxDispatcher(
            sessions,
            _load_publisher(publisher_reference),
            max_attempts=max_attempts,
        )
        stop = threading.Event()

        def _stop(_signum: int, _frame: object) -> None:
            stop.set()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        worker = OutboxWorker(
            dispatcher,
            batch_size=cast(
                int,
                _positive_number("OMNIGENT_SAAS_OUTBOX_BATCH_SIZE", "100", integer=True),
            ),
            idle_interval=cast(
                float,
                _positive_number("OMNIGENT_SAAS_OUTBOX_IDLE_SECONDS", "0.5"),
            ),
            error_backoff=cast(
                float,
                _positive_number("OMNIGENT_SAAS_OUTBOX_ERROR_BACKOFF_SECONDS", "1"),
            ),
            max_error_backoff=cast(
                float,
                _positive_number("OMNIGENT_SAAS_OUTBOX_MAX_BACKOFF_SECONDS", "30"),
            ),
        )
        stats = worker.run(stop)
        _LOGGER.info("Outbox worker stopped: %s", stats)
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
