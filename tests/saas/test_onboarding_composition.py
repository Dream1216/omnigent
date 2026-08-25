from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

import saas.onboarding_composition as onboarding_composition
from saas.onboarding_composition import (
    TenantOnboardingDependencies,
    verify_onboarding_database_authority,
)


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def one(self) -> object:
        return self._value

    def one_or_none(self) -> object:
        return self._value

    def scalar_one(self) -> object:
        return self._value

    def scalars(self) -> _Result:
        return self

    def all(self) -> object:
        return self._value


@dataclass(frozen=True, slots=True)
class _AuthorityFacts:
    schema: tuple[str, tuple[str, ...], bool] = ("public", ("public",), False)
    login: tuple[str, str, bool, bool, bool, bool, bool, bool, bool] = (
        "registration_login",
        "registration_login",
        True,
        False,
        False,
        False,
        False,
        False,
        True,
    )
    base: tuple[bool, bool, bool, bool, bool, bool, bool] | None = (
        False,
        False,
        False,
        False,
        False,
        False,
        True,
    )
    memberships: tuple[tuple[str, bool, bool, bool], ...] = (
        ("saas_registration", False, True, True),
    )
    base_memberships: tuple[tuple[str, bool, bool, bool], ...] = ()
    direct_object_authorities: int = 0
    server_version_num: int = 180000
    status_delegable_authorities: int = 0
    status_column_authorities: tuple[tuple[str, str, str], ...] = tuple(
        sorted(onboarding_composition._STATUS_COLUMN_AUTHORITIES)
    )
    status_table_authorities: tuple[tuple[str, str], ...] = ()
    status_sequence_authorities: tuple[tuple[str, str], ...] = ()


class _Connection:
    def __init__(self, facts: _AuthorityFacts, observed_sql: list[str]) -> None:
        self._facts = facts
        self._observed_sql = observed_sql

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(
        self,
        statement: object,
        parameters: dict[str, object] | None = None,
    ) -> _Result:
        sql = str(statement)
        self._observed_sql.append(sql)
        if "current_schema()" in sql:
            return _Result(self._facts.schema)
        if "role.rolname = current_user" in sql and "rolcanlogin" in sql:
            return _Result(self._facts.login)
        if "direct_authority" in sql:
            return _Result(self._facts.direct_object_authorities)
        if "delegable_authority AS" in sql:
            return _Result(self._facts.status_delegable_authorities)
        if "server_version_num" in sql:
            return _Result(self._facts.server_version_num)
        if "has_column_privilege(CAST(:expected_role" in sql:
            return _Result(list(self._facts.status_column_authorities))
        if "has_table_privilege(CAST(:expected_role" in sql:
            return _Result(list(self._facts.status_table_authorities))
        if "has_sequence_privilege(CAST(:expected_role" in sql:
            return _Result(list(self._facts.status_sequence_authorities))
        if "FROM pg_roles WHERE rolname =" in sql:
            return _Result(self._facts.base)
        if "pg_auth_members" in sql and "member.rolname = current_user" in sql:
            assert "to_jsonb(membership)" in sql
            assert "membership.inherit_option" not in sql
            assert "membership.set_option" not in sql
            return _Result(list(self._facts.memberships))
        if "pg_auth_members" in sql and parameters is not None:
            assert "to_jsonb(membership)" in sql
            assert "membership.inherit_option" not in sql
            assert "membership.set_option" not in sql
            return _Result(list(self._facts.base_memberships))
        raise AssertionError(f"unexpected authority query: {sql}")


class _PostgresqlEngine:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self, facts: _AuthorityFacts | None = None) -> None:
        self._facts = facts or _AuthorityFacts()
        self.observed_sql: list[str] = []

    def connect(self) -> _Connection:
        return _Connection(self._facts, self.observed_sql)


def _engine(facts: _AuthorityFacts | None = None) -> Engine:
    return cast(Engine, _PostgresqlEngine(facts))


def test_authority_validator_accepts_exact_non_bypass_login() -> None:
    verify_onboarding_database_authority(_engine(), authority="registration")


def test_status_authority_uses_dedicated_status_role() -> None:
    facts = replace(
        _AuthorityFacts(),
        memberships=(("saas_onboarding_status", False, True, True),),
    )

    verify_onboarding_database_authority(_engine(facts), authority="status")


def test_status_authority_rejects_grant_options_and_default_acl_authority() -> None:
    facts = replace(
        _AuthorityFacts(),
        memberships=(("saas_onboarding_status", False, True, True),),
        status_delegable_authorities=1,
    )
    engine = _PostgresqlEngine(facts)

    with pytest.raises(RuntimeError, match=r"grant options.*default ACLs"):
        verify_onboarding_database_authority(cast(Engine, engine), authority="status")

    delegable_query = next(sql for sql in engine.observed_sql if "delegable_authority AS" in sql)
    assert "pg_attribute" in delegable_query
    assert "grant_acl.is_grantable" in delegable_query
    assert "pg_default_acl" in delegable_query


@pytest.mark.parametrize(
    ("server_version_num", "expects_maintain"),
    [(150000, False), (160000, False), (170000, True), (180000, True)],
)
def test_status_authority_checks_maintain_only_when_supported(
    server_version_num: int,
    expects_maintain: bool,
) -> None:
    facts = replace(
        _AuthorityFacts(),
        memberships=(("saas_onboarding_status", False, True, True),),
        server_version_num=server_version_num,
    )
    engine = _PostgresqlEngine(facts)

    verify_onboarding_database_authority(cast(Engine, engine), authority="status")

    table_query = next(
        sql for sql in engine.observed_sql if "has_table_privilege(CAST(:expected_role" in sql
    )
    assert ("MAINTAIN" in table_query) is expects_maintain


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "status_column_authorities",
            (
                *sorted(onboarding_composition._STATUS_COLUMN_AUTHORITIES),
                ("saas_tenant_onboardings", "last_error_detail", "SELECT"),
            ),
        ),
        ("status_table_authorities", (("saas_tenant_onboardings", "DELETE"),)),
        ("status_table_authorities", (("saas_tenant_onboardings", "MAINTAIN"),)),
        ("status_sequence_authorities", (("unexpected_sequence", "USAGE"),)),
    ],
)
def test_status_authority_rejects_base_role_privilege_drift(
    field: str,
    value: tuple[tuple[str, ...], ...],
) -> None:
    facts = replace(
        _AuthorityFacts(),
        memberships=(("saas_onboarding_status", False, True, True),),
        **{field: value},
    )

    with pytest.raises(RuntimeError, match="exact read-only projection"):
        verify_onboarding_database_authority(_engine(facts), authority="status")


@pytest.mark.parametrize(
    ("facts", "message"),
    [
        (
            replace(
                _AuthorityFacts(),
                schema=("public", ("private", "public"), False),
            ),
            "search_path",
        ),
        (
            replace(_AuthorityFacts(), schema=("public", ("public",), True)),
            "search_path",
        ),
        (
            replace(
                _AuthorityFacts(),
                login=(
                    "registration_login",
                    "owner",
                    True,
                    False,
                    False,
                    False,
                    False,
                    False,
                    True,
                ),
            ),
            "assumed database role",
        ),
        (
            replace(
                _AuthorityFacts(),
                login=(
                    "registration_login",
                    "registration_login",
                    True,
                    True,
                    False,
                    False,
                    False,
                    False,
                    True,
                ),
            ),
            "non-bypass RLS posture",
        ),
        (
            replace(
                _AuthorityFacts(),
                base=(True, False, False, False, False, False, True),
            ),
            "NOLOGIN",
        ),
        (
            replace(
                _AuthorityFacts(),
                memberships=(
                    ("saas_platform", False, True, True),
                    ("saas_registration", False, True, True),
                ),
            ),
            "inherit only saas_registration",
        ),
        (
            replace(
                _AuthorityFacts(),
                base_memberships=(("saas_platform", False, True, True),),
            ),
            "must not inherit another database role",
        ),
        (
            replace(_AuthorityFacts(), direct_object_authorities=1),
            "must not own objects or receive direct object grants",
        ),
    ],
)
def test_authority_validator_fails_closed_on_role_drift(
    facts: _AuthorityFacts,
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        verify_onboarding_database_authority(_engine(facts), authority="registration")


@pytest.mark.parametrize("elevated_index", [4, 5, 6])
def test_authority_validator_rejects_createdb_createrole_and_replication(
    elevated_index: int,
) -> None:
    facts = _AuthorityFacts()
    login = list(facts.login)
    login[elevated_index] = True

    with pytest.raises(RuntimeError, match="non-bypass RLS posture"):
        verify_onboarding_database_authority(
            _engine(replace(facts, login=cast(tuple, tuple(login)))),
            authority="registration",
        )


@pytest.mark.parametrize("elevated_index", [2, 3, 4])
def test_authority_validator_rejects_elevated_base_role(elevated_index: int) -> None:
    facts = _AuthorityFacts()
    assert facts.base is not None
    base = list(facts.base)
    base[elevated_index] = True

    with pytest.raises(RuntimeError, match="NOLOGIN non-bypass base role"):
        verify_onboarding_database_authority(
            _engine(replace(facts, base=cast(tuple, tuple(base)))),
            authority="registration",
        )


@pytest.mark.parametrize(
    "membership",
    [
        ("saas_registration", True, True, True),
        ("saas_registration", False, False, True),
        ("saas_registration", False, True, False),
    ],
)
def test_authority_validator_rejects_unsafe_membership_options(
    membership: tuple[str, bool, bool, bool],
) -> None:
    with pytest.raises(RuntimeError, match="unsafe role membership options"):
        verify_onboarding_database_authority(
            _engine(replace(_AuthorityFacts(), memberships=(membership,))),
            authority="registration",
        )


def test_dependencies_validate_three_separate_postgresql_engines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engines = tuple(_engine() for _ in range(3))
    sessions = tuple(sessionmaker(engine) for engine in engines)
    observed: list[tuple[Engine, str]] = []
    monkeypatch.setattr(
        onboarding_composition,
        "verify_onboarding_database_authority",
        lambda engine, *, authority: observed.append((engine, authority)),
    )
    candidate = SimpleNamespace(
        registration_sessions=sessions[0],
        onboarding_sessions=sessions[1],
        execution_sessions=sessions[2],
    )

    TenantOnboardingDependencies._require_separate_postgresql_authorities(candidate)

    assert observed == [
        (engines[0], "registration"),
        (engines[1], "onboarding"),
        (engines[2], "execution"),
    ]


def test_dependencies_reject_reused_postgresql_engine_before_role_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine()
    sessions: sessionmaker[Session] = sessionmaker(engine)
    monkeypatch.setattr(
        onboarding_composition,
        "verify_onboarding_database_authority",
        lambda *_args, **_kwargs: pytest.fail("authority check must not run"),
    )
    candidate = SimpleNamespace(
        registration_sessions=sessions,
        onboarding_sessions=sessions,
        execution_sessions=sessions,
    )

    with pytest.raises(RuntimeError, match="separate PostgreSQL engines"):
        TenantOnboardingDependencies._require_separate_postgresql_authorities(candidate)


def test_postgresql_dependencies_assert_runtime_production_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ReadyRuntime:
        def __init__(self) -> None:
            self.assertions = 0

        def assert_production_ready(self) -> None:
            self.assertions += 1

    monkeypatch.setattr(
        onboarding_composition,
        "ProductionRuntimePartitionAdapter",
        _ReadyRuntime,
    )
    runtime = _ReadyRuntime()
    sessions = tuple(sessionmaker(_engine()) for _ in range(3))
    candidate = SimpleNamespace(
        registration_sessions=sessions[0],
        onboarding_sessions=sessions[1],
        execution_sessions=sessions[2],
        runtime=runtime,
    )

    TenantOnboardingDependencies._require_production_runtime_for_postgresql(candidate)

    assert runtime.assertions == 1


def test_postgresql_dependencies_propagate_runtime_readiness_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NotReadyRuntime:
        def assert_production_ready(self) -> None:
            raise RuntimeError("runtime readiness failed")

    monkeypatch.setattr(
        onboarding_composition,
        "ProductionRuntimePartitionAdapter",
        _NotReadyRuntime,
    )
    sessions = tuple(sessionmaker(_engine()) for _ in range(3))
    candidate = SimpleNamespace(
        registration_sessions=sessions[0],
        onboarding_sessions=sessions[1],
        execution_sessions=sessions[2],
        runtime=_NotReadyRuntime(),
    )

    with pytest.raises(RuntimeError, match="runtime readiness failed"):
        TenantOnboardingDependencies._require_production_runtime_for_postgresql(candidate)
