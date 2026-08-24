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

    def scalars(self) -> _Result:
        return self

    def all(self) -> object:
        return self._value


@dataclass(frozen=True, slots=True)
class _AuthorityFacts:
    schema: tuple[str, tuple[str, ...]] = ("public", ("public",))
    login: tuple[str, str, bool, bool, bool, bool] = (
        "registration_login",
        "registration_login",
        True,
        False,
        False,
        True,
    )
    base: tuple[bool, bool, bool, bool] | None = (False, False, False, True)
    memberships: tuple[str, ...] = ("saas_registration",)
    base_memberships: tuple[str, ...] = ()


class _Connection:
    def __init__(self, facts: _AuthorityFacts) -> None:
        self._facts = facts

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
        if "current_schema()" in sql:
            return _Result(self._facts.schema)
        if "role.rolname = current_user" in sql and "rolcanlogin" in sql:
            return _Result(self._facts.login)
        if "FROM pg_roles WHERE rolname =" in sql:
            return _Result(self._facts.base)
        if "pg_auth_members" in sql and "member.rolname = current_user" in sql:
            return _Result(list(self._facts.memberships))
        if "pg_auth_members" in sql and parameters is not None:
            return _Result(list(self._facts.base_memberships))
        raise AssertionError(f"unexpected authority query: {sql}")


class _PostgresqlEngine:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self, facts: _AuthorityFacts | None = None) -> None:
        self._facts = facts or _AuthorityFacts()

    def connect(self) -> _Connection:
        return _Connection(self._facts)


def _engine(facts: _AuthorityFacts | None = None) -> Engine:
    return cast(Engine, _PostgresqlEngine(facts))


def test_authority_validator_accepts_exact_non_bypass_login() -> None:
    verify_onboarding_database_authority(_engine(), authority="registration")


@pytest.mark.parametrize(
    ("facts", "message"),
    [
        (
            replace(_AuthorityFacts(), schema=("public", ("private", "public"))),
            "search_path",
        ),
        (
            replace(
                _AuthorityFacts(),
                login=("registration_login", "owner", True, False, False, True),
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
                    True,
                ),
            ),
            "non-bypass RLS posture",
        ),
        (replace(_AuthorityFacts(), base=(True, False, False, True)), "NOLOGIN"),
        (
            replace(
                _AuthorityFacts(),
                memberships=("saas_platform", "saas_registration"),
            ),
            "inherit only saas_registration",
        ),
        (
            replace(_AuthorityFacts(), base_memberships=("saas_platform",)),
            "inherit only saas_registration",
        ),
    ],
)
def test_authority_validator_fails_closed_on_role_drift(
    facts: _AuthorityFacts,
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        verify_onboarding_database_authority(_engine(facts), authority="registration")


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
