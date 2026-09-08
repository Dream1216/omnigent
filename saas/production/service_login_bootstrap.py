"""Fail-closed service-login bootstrap and managed posture convergence."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import BinaryIO

import sqlalchemy as sa
from psycopg import sql
from sqlalchemy.engine import URL, Connection, Engine

from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_database_url_file,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_MAX_PASSWORD_BYTES = 16 * 1024
_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_SERVICE = "platform_governance"
_BASE_ROLE = "saas_platform_governance"
_RUNTIME_PROVIDER_JOURNAL_SERVICE = "runtime_provider_journal"
_RUNTIME_PROVIDER_JOURNAL_BASE_ROLE = "saas_runtime_provider_journal"
_RUNTIME_PROVIDER_JOURNAL_ROLE_CONFIG = ["search_path=public"]
_PRINCIPAL_OPERATOR_LOGIN = "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_LOGIN"
_EXPECTED_LOGIN_FLAGS = (
    True,
    False,
    False,
    False,
    False,
    False,
    True,
    -1,
    None,
)
_EXPECTED_BASE_FLAGS = (
    False,
    False,
    False,
    False,
    False,
    False,
    True,
    -1,
    None,
)
_EXPECTED_OPERATOR_FLAGS = (
    True,
    False,
    False,
    True,
    False,
    False,
    True,
    -1,
    None,
)


class ProductionServiceLoginBootstrapError(RuntimeError):
    """Content-free rejection for the one admitted service-login expansion."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Production service-login bootstrap rejected: {code}")


def _read_password(stream: BinaryIO) -> tuple[str, bytearray]:
    raw = bytearray(stream.read(_MAX_PASSWORD_BYTES + 1))
    if len(raw) > _MAX_PASSWORD_BYTES:
        raw[:] = b"\0" * len(raw)
        raise ProductionServiceLoginBootstrapError("password_too_large")
    if raw.endswith(b"\r\n"):
        del raw[-2:]
    elif raw.endswith(b"\n"):
        del raw[-1:]
    if not raw or b"\0" in raw or b"\r" in raw or b"\n" in raw:
        raw[:] = b"\0" * len(raw)
        raise ProductionServiceLoginBootstrapError("password_invalid")
    try:
        return raw.decode("utf-8"), raw
    except UnicodeError:
        raw[:] = b"\0" * len(raw)
        raise ProductionServiceLoginBootstrapError("password_invalid") from None


def _binding(environ: Mapping[str, str]) -> ProductionServiceRoleBinding:
    return _binding_for_service(environ, service=_SERVICE, base_role=_BASE_ROLE)


def _binding_for_service(
    environ: Mapping[str, str],
    *,
    service: str,
    base_role: str,
) -> ProductionServiceRoleBinding:
    try:
        binding = load_production_service_role_bindings(environ).by_service[service]
    except (KeyError, ProductionServiceRoleBindingsError):
        raise ProductionServiceLoginBootstrapError("authority_invalid") from None
    if binding.base_role != base_role:
        raise ProductionServiceLoginBootstrapError("authority_invalid")
    return binding


def _database_authority(environ: Mapping[str, str], role: str) -> tuple[str, URL]:
    try:
        url, authority, _path = load_production_database_url_file(environ, role)
    except ProductionServerConfigError:
        raise ProductionServiceLoginBootstrapError("authority_invalid") from None
    return url, authority


def _engine(url: str, engine_factory: Callable[[str], Engine]) -> Engine:
    engine = engine_factory(url)
    if engine.dialect.name != "postgresql":
        engine.dispose()
        raise ProductionServiceLoginBootstrapError("authority_invalid")
    return engine


def _role_flags(connection: Connection, role: str) -> tuple[object, ...] | None:
    row = connection.execute(
        sa.text(
            "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
            "FROM pg_roles WHERE rolname = :role"
        ),
        {"role": role},
    ).one_or_none()
    return tuple(row) if row is not None else None


def _memberships(connection: Connection, login: str) -> list[tuple[object, ...]]:
    return [
        tuple(row)
        for row in connection.execute(
            sa.text(
                "SELECT granted.rolname, membership.admin_option, "
                "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
                "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true), "
                "grantor.rolname "
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "JOIN pg_roles AS grantor ON grantor.oid = membership.grantor "
                "WHERE member.rolname = :login ORDER BY granted.rolname, grantor.rolname"
            ),
            {"login": login},
        ).all()
    ]


def _incoming_membership_count(connection: Connection, login: str) -> int:
    return int(
        connection.execute(
            sa.text(
                "SELECT count(*) FROM pg_auth_members AS membership "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "WHERE granted.rolname = :login"
            ),
            {"login": login},
        ).scalar_one()
    )


def _create_login(connection: Connection, *, login: str, password: str) -> None:
    driver = connection.connection.driver_connection
    if driver is None:
        raise ProductionServiceLoginBootstrapError("bootstrap_failed")
    with driver.cursor() as cursor:
        cursor.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "INHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD {}"
            ).format(sql.Identifier(login), sql.Literal(password))
        )


def _create_base_role(connection: Connection) -> None:
    driver = connection.connection.driver_connection
    if driver is None:
        raise ProductionServiceLoginBootstrapError("bootstrap_failed")
    with driver.cursor() as cursor:
        cursor.execute(
            sql.SQL(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "INHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1"
            ).format(sql.Identifier(_BASE_ROLE))
        )


def _grant_operator_management(connection: Connection, *, operator: str) -> None:
    driver = connection.connection.driver_connection
    if driver is None:
        raise ProductionServiceLoginBootstrapError("bootstrap_failed")
    with driver.cursor() as cursor:
        cursor.execute(
            sql.SQL("GRANT {} TO {} WITH ADMIN OPTION, INHERIT FALSE, SET FALSE").format(
                sql.Identifier(_BASE_ROLE), sql.Identifier(operator)
            )
        )


def _set_login_password(connection: Connection, *, login: str, password: str) -> None:
    driver = connection.connection.driver_connection
    if driver is None:
        raise ProductionServiceLoginBootstrapError("bootstrap_failed")
    with driver.cursor() as cursor:
        cursor.execute(
            sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                sql.Identifier(login),
                sql.Literal(password),
            )
        )


def _set_login_search_path(connection: Connection, *, login: str) -> None:
    driver = connection.connection.driver_connection
    if driver is None:
        raise ProductionServiceLoginBootstrapError("bootstrap_failed")
    with driver.cursor() as cursor:
        cursor.execute(
            sql.SQL("ALTER ROLE {} SET search_path = public").format(sql.Identifier(login))
        )


def _grant_base_role(connection: Connection, *, login: str) -> None:
    driver = connection.connection.driver_connection
    if driver is None:
        raise ProductionServiceLoginBootstrapError("bootstrap_failed")
    with driver.cursor() as cursor:
        cursor.execute(
            sql.SQL("GRANT {} TO {} WITH INHERIT TRUE, SET FALSE").format(
                sql.Identifier(_BASE_ROLE),
                sql.Identifier(login),
            )
        )


def _identity(connection: Connection) -> tuple[object, ...]:
    return tuple(connection.execute(sa.text("SELECT current_user, session_user")).one())


def _bootstrap_name(connection: Connection) -> str | None:
    value = connection.execute(
        sa.text("SELECT rolname FROM pg_roles WHERE oid = 10")
    ).scalar_one_or_none()
    return str(value) if value is not None else None


def _superuser_flags_are_safe(flags: tuple[object, ...] | None) -> bool:
    if flags is None:
        return False
    (
        can_login,
        is_superuser,
        _can_create_database,
        can_create_role,
        _can_replicate,
        bypasses_rls,
        inherits_roles,
        _connection_limit,
        role_config,
    ) = flags
    return bool(
        can_login
        and is_superuser
        and can_create_role
        and bypasses_rls
        and inherits_roles
        and role_config is None
    )


def prepare_platform_governance_service_login(
    *,
    environ: Mapping[str, str],
    password_stream: BinaryIO,
    engine_factory: Callable[[str], Engine] = lambda url: sa.create_engine(
        url,
        pool_pre_ping=True,
        poolclass=sa.pool.NullPool,
    ),
) -> dict[str, object]:
    """Create or rotate a bare login through the managed superuser authority."""

    binding = _binding(environ)
    superuser_url, superuser_authority = _database_authority(environ, "superuser")
    principal_operator = environ.get(_PRINCIPAL_OPERATOR_LOGIN, "")
    if (
        principal_operator != principal_operator.strip()
        or _ROLE_NAME.fullmatch(principal_operator) is None
    ):
        raise ProductionServiceLoginBootstrapError("authority_invalid")
    expected_memberships = [(_BASE_ROLE, False, True, False, principal_operator)]
    expected_management = (
        _BASE_ROLE,
        True,
        False,
        False,
        str(superuser_authority.username),
    )
    password, mutable_password = _read_password(password_stream)
    engine: Engine | None = None
    created = False
    base_created = False
    management_granted = False
    try:
        engine = _engine(superuser_url, engine_factory)
        with engine.begin() as connection:
            if (
                _identity(connection)
                != (superuser_authority.username, superuser_authority.username)
                or _bootstrap_name(connection) != superuser_authority.username
                or not _superuser_flags_are_safe(
                    _role_flags(connection, str(superuser_authority.username))
                )
                or _role_flags(connection, principal_operator) != _EXPECTED_OPERATOR_FLAGS
            ):
                raise ProductionServiceLoginBootstrapError("authority_invalid")

            base_flags = _role_flags(connection, _BASE_ROLE)
            management_rows = [
                row for row in _memberships(connection, principal_operator) if row[0] == _BASE_ROLE
            ]
            if base_flags is None:
                if management_rows:
                    raise ProductionServiceLoginBootstrapError("login_projection_invalid")
                _create_base_role(connection)
                base_created = True
            elif base_flags != _EXPECTED_BASE_FLAGS:
                raise ProductionServiceLoginBootstrapError("authority_invalid")
            if management_rows == []:
                _grant_operator_management(connection, operator=principal_operator)
                management_granted = True
            elif management_rows != [expected_management]:
                raise ProductionServiceLoginBootstrapError("login_projection_invalid")
            if _role_flags(connection, _BASE_ROLE) != _EXPECTED_BASE_FLAGS or [
                row for row in _memberships(connection, principal_operator) if row[0] == _BASE_ROLE
            ] != [expected_management]:
                raise ProductionServiceLoginBootstrapError("login_projection_invalid")

            login_flags = _role_flags(connection, binding.login)
            existing_memberships = _memberships(connection, binding.login)
            if _incoming_membership_count(connection, binding.login):
                raise ProductionServiceLoginBootstrapError("login_projection_invalid")
            if login_flags is None:
                if existing_memberships:
                    raise ProductionServiceLoginBootstrapError("login_projection_invalid")
                _create_login(connection, login=binding.login, password=password)
                created = True
            else:
                if login_flags != _EXPECTED_LOGIN_FLAGS or existing_memberships not in (
                    [],
                    expected_memberships,
                ):
                    raise ProductionServiceLoginBootstrapError("login_projection_invalid")
                _set_login_password(connection, login=binding.login, password=password)

            if (
                _role_flags(connection, binding.login) != _EXPECTED_LOGIN_FLAGS
                or _incoming_membership_count(connection, binding.login)
                or _memberships(connection, binding.login) not in ([], expected_memberships)
            ):
                raise ProductionServiceLoginBootstrapError("login_projection_invalid")
    except ProductionServiceLoginBootstrapError:
        raise
    except (sa.exc.SQLAlchemyError, AttributeError, TypeError, ValueError):
        raise ProductionServiceLoginBootstrapError("bootstrap_failed") from None
    finally:
        mutable_password[:] = b"\0" * len(mutable_password)
        password = ""
        if engine is not None:
            engine.dispose()

    return {
        "schema_version": 1,
        "status": "pass",
        "production_authority": False,
        "stage": "prepared",
        "service": _SERVICE,
        "login": binding.login,
        "base_role": binding.base_role,
        "created": created,
        "base_role_created": base_created,
        "operator_management_granted": management_granted,
    }


def bind_platform_governance_service_login(
    *,
    environ: Mapping[str, str],
    engine_factory: Callable[[str], Engine] = lambda url: sa.create_engine(
        url,
        pool_pre_ping=True,
        poolclass=sa.pool.NullPool,
    ),
) -> dict[str, object]:
    """Grant the sole base-role edge through the principal-operator authority."""

    binding = _binding(environ)
    operator_url, operator_authority = _database_authority(environ, "principal_operator")
    expected_memberships = [(_BASE_ROLE, False, True, False, str(operator_authority.username))]
    engine: Engine | None = None
    granted = False
    try:
        engine = _engine(operator_url, engine_factory)
        with engine.begin() as connection:
            bootstrap_name = _bootstrap_name(connection)
            if bootstrap_name is None:
                raise ProductionServiceLoginBootstrapError("authority_invalid")
            expected_management = (
                _BASE_ROLE,
                True,
                False,
                False,
                bootstrap_name,
            )
            if (
                _identity(connection) != (operator_authority.username, operator_authority.username)
                or _role_flags(connection, str(operator_authority.username))
                != _EXPECTED_OPERATOR_FLAGS
                or _role_flags(connection, _BASE_ROLE) != _EXPECTED_BASE_FLAGS
                or _role_flags(connection, binding.login) != _EXPECTED_LOGIN_FLAGS
                or _incoming_membership_count(connection, binding.login)
                or expected_management
                not in _memberships(connection, str(operator_authority.username))
            ):
                raise ProductionServiceLoginBootstrapError("authority_invalid")

            memberships = _memberships(connection, binding.login)
            if memberships == []:
                _grant_base_role(connection, login=binding.login)
                granted = True
            elif memberships != expected_memberships:
                raise ProductionServiceLoginBootstrapError("login_projection_invalid")

            if (
                _role_flags(connection, binding.login) != _EXPECTED_LOGIN_FLAGS
                or _incoming_membership_count(connection, binding.login)
                or _memberships(connection, binding.login) != expected_memberships
            ):
                raise ProductionServiceLoginBootstrapError("login_projection_invalid")
    except ProductionServiceLoginBootstrapError:
        raise
    except (sa.exc.SQLAlchemyError, AttributeError, TypeError, ValueError):
        raise ProductionServiceLoginBootstrapError("bootstrap_failed") from None
    finally:
        if engine is not None:
            engine.dispose()

    return {
        "schema_version": 1,
        "status": "pass",
        "production_authority": False,
        "stage": "bound",
        "service": _SERVICE,
        "login": binding.login,
        "base_role": binding.base_role,
        "granted": granted,
    }


def converge_runtime_provider_journal_login_posture(
    *,
    environ: Mapping[str, str],
    engine_factory: Callable[[str], Engine] = lambda url: sa.create_engine(
        url,
        pool_pre_ping=True,
        poolclass=sa.pool.NullPool,
    ),
) -> dict[str, object]:
    """Pin the journal LOGIN search path through the managed superuser only."""

    binding = _binding_for_service(
        environ,
        service=_RUNTIME_PROVIDER_JOURNAL_SERVICE,
        base_role=_RUNTIME_PROVIDER_JOURNAL_BASE_ROLE,
    )
    superuser_url, superuser_authority = _database_authority(environ, "superuser")
    principal_operator = environ.get(_PRINCIPAL_OPERATOR_LOGIN, "")
    if (
        principal_operator != principal_operator.strip()
        or _ROLE_NAME.fullmatch(principal_operator) is None
    ):
        raise ProductionServiceLoginBootstrapError("authority_invalid")

    expected_memberships = [
        (
            _RUNTIME_PROVIDER_JOURNAL_BASE_ROLE,
            False,
            True,
            False,
            principal_operator,
        )
    ]
    bare_login_flags = _EXPECTED_LOGIN_FLAGS
    configured_login_flags = (*_EXPECTED_LOGIN_FLAGS[:-1], _RUNTIME_PROVIDER_JOURNAL_ROLE_CONFIG)
    engine: Engine | None = None
    changed = False
    try:
        engine = _engine(superuser_url, engine_factory)
        with engine.begin() as connection:
            authority_login = str(superuser_authority.username)
            if (
                _identity(connection)
                != (superuser_authority.username, superuser_authority.username)
                or _bootstrap_name(connection) != superuser_authority.username
                or not _superuser_flags_are_safe(_role_flags(connection, authority_login))
                or _role_flags(connection, principal_operator) != _EXPECTED_OPERATOR_FLAGS
                or _role_flags(connection, binding.base_role) != _EXPECTED_BASE_FLAGS
                or _incoming_membership_count(connection, binding.login)
                or _memberships(connection, binding.login) != expected_memberships
            ):
                raise ProductionServiceLoginBootstrapError("authority_invalid")

            login_flags = _role_flags(connection, binding.login)
            if login_flags == bare_login_flags:
                _set_login_search_path(connection, login=binding.login)
                changed = True
            elif login_flags != configured_login_flags:
                raise ProductionServiceLoginBootstrapError("login_projection_invalid")

            if (
                _role_flags(connection, binding.login) != configured_login_flags
                or _incoming_membership_count(connection, binding.login)
                or _memberships(connection, binding.login) != expected_memberships
            ):
                raise ProductionServiceLoginBootstrapError("login_projection_invalid")
    except ProductionServiceLoginBootstrapError:
        raise
    except (sa.exc.SQLAlchemyError, AttributeError, TypeError, ValueError):
        raise ProductionServiceLoginBootstrapError("bootstrap_failed") from None
    finally:
        if engine is not None:
            engine.dispose()

    return {
        "schema_version": 1,
        "status": "pass",
        "production_authority": False,
        "stage": "runtime_journal_login_posture_converged",
        "service": _RUNTIME_PROVIDER_JOURNAL_SERVICE,
        "login": binding.login,
        "base_role": binding.base_role,
        "changed": changed,
        "role_config": list(_RUNTIME_PROVIDER_JOURNAL_ROLE_CONFIG),
    }


__all__ = [
    "ProductionServiceLoginBootstrapError",
    "bind_platform_governance_service_login",
    "converge_runtime_provider_journal_login_posture",
    "prepare_platform_governance_service_login",
]
