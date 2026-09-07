from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace

import sqlalchemy as sa

from saas.production import service_login_bootstrap


class _Result:
    def __init__(self, identity: tuple[str, str]) -> None:
        self._identity = identity

    def one(self) -> tuple[str, str]:
        return self._identity


class _Connection:
    def __init__(self, identity: tuple[str, str]) -> None:
        self._identity = identity

    def execute(self, _statement):
        return _Result(self._identity)


class _Engine:
    dialect = SimpleNamespace(name="postgresql")
    disposed = False

    def __init__(self, identity: tuple[str, str]) -> None:
        self._identity = identity

    @contextmanager
    def begin(self):
        yield _Connection(self._identity)

    def dispose(self) -> None:
        self.disposed = True


def _binding() -> SimpleNamespace:
    return SimpleNamespace(
        by_service={
            "platform_governance": SimpleNamespace(
                login="platform_governance_login",
                base_role="saas_platform_governance",
            )
        }
    )


def test_prepare_creates_bare_login_only_as_superuser(monkeypatch) -> None:
    engine = _Engine(("bootstrap", "bootstrap"))
    superuser_flags = (True, True, True, True, True, True, True, -1, None)
    base_flags = (False, False, False, False, False, False, True, -1, None)
    login_flags = (True, False, False, False, False, False, True, -1, None)
    created = False
    received_passwords: list[str] = []
    management = [("saas_platform_governance", True, False, False, "bootstrap")]

    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_database_url_file",
        lambda _source, role: (
            "postgresql+psycopg://bootstrap:redacted@example.invalid/omnigent",
            sa.make_url("postgresql+psycopg://bootstrap:redacted@example.invalid/omnigent"),
            f"/{role}-dsn",
        ),
    )
    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_service_role_bindings",
        lambda _source: _binding(),
    )

    def role_flags(_connection, role: str):
        if role == "bootstrap":
            return superuser_flags
        if role == "principal_operator":
            return (True, False, False, True, False, False, True, -1, None)
        if role == "saas_platform_governance":
            return base_flags
        if role == "platform_governance_login":
            return login_flags if created else None
        raise AssertionError(role)

    monkeypatch.setattr(service_login_bootstrap, "_role_flags", role_flags)
    monkeypatch.setattr(
        service_login_bootstrap,
        "_memberships",
        lambda _connection, login: list(management) if login == "principal_operator" else [],
    )
    monkeypatch.setattr(service_login_bootstrap, "_incoming_membership_count", lambda *_args: 0)
    monkeypatch.setattr(service_login_bootstrap, "_bootstrap_name", lambda *_args: "bootstrap")

    def create_login(_connection, *, login: str, password: str) -> None:
        nonlocal created
        assert login == "platform_governance_login"
        received_passwords.append(password)
        created = True

    monkeypatch.setattr(service_login_bootstrap, "_create_login", create_login)

    result = service_login_bootstrap.prepare_platform_governance_service_login(
        environ={"OMNIGENT_SAAS_PRINCIPAL_OPERATOR_LOGIN": "principal_operator"},
        password_stream=BytesIO(b"database password\n"),
        engine_factory=lambda _url: engine,
    )

    assert result == {
        "schema_version": 1,
        "status": "pass",
        "production_authority": False,
        "stage": "prepared",
        "service": "platform_governance",
        "login": "platform_governance_login",
        "base_role": "saas_platform_governance",
        "created": True,
        "base_role_created": False,
        "operator_management_granted": False,
    }
    assert received_passwords == ["database password"]
    assert "database password" not in str(result)
    assert engine.disposed is True


def test_bind_grants_exact_edge_as_principal_operator(monkeypatch) -> None:
    engine = _Engine(("principal_operator", "principal_operator"))
    operator_flags = (True, False, False, True, False, False, True, -1, None)
    base_flags = (False, False, False, False, False, False, True, -1, None)
    login_flags = (True, False, False, False, False, False, True, -1, None)
    memberships: list[tuple[object, ...]] = []
    management = [("saas_platform_governance", True, False, False, "bootstrap")]

    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_database_url_file",
        lambda _source, role: (
            "postgresql+psycopg://principal_operator:redacted@example.invalid/omnigent",
            sa.make_url(
                "postgresql+psycopg://principal_operator:redacted@example.invalid/omnigent"
            ),
            f"/{role}-dsn",
        ),
    )
    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_service_role_bindings",
        lambda _source: _binding(),
    )

    def role_flags(_connection, role: str):
        return {
            "principal_operator": operator_flags,
            "saas_platform_governance": base_flags,
            "platform_governance_login": login_flags,
        }[role]

    def grant(_connection, *, login: str) -> None:
        assert login == "platform_governance_login"
        memberships.append(
            (
                "saas_platform_governance",
                False,
                True,
                False,
                "principal_operator",
            )
        )

    monkeypatch.setattr(service_login_bootstrap, "_role_flags", role_flags)
    monkeypatch.setattr(
        service_login_bootstrap,
        "_memberships",
        lambda _connection, login: (
            list(management) if login == "principal_operator" else list(memberships)
        ),
    )
    monkeypatch.setattr(service_login_bootstrap, "_incoming_membership_count", lambda *_args: 0)
    monkeypatch.setattr(service_login_bootstrap, "_bootstrap_name", lambda *_args: "bootstrap")
    monkeypatch.setattr(service_login_bootstrap, "_grant_base_role", grant)

    result = service_login_bootstrap.bind_platform_governance_service_login(
        environ={},
        engine_factory=lambda _url: engine,
    )

    assert result["stage"] == "bound"
    assert result["granted"] is True
    assert memberships == [
        (
            "saas_platform_governance",
            False,
            True,
            False,
            "principal_operator",
        )
    ]
    assert engine.disposed is True


def test_prepare_creates_missing_base_and_management_edge(monkeypatch) -> None:
    engine = _Engine(("bootstrap", "bootstrap"))
    base_exists = False
    login_exists = False
    management: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_database_url_file",
        lambda _source, role: (
            "postgresql+psycopg://bootstrap:redacted@example.invalid/omnigent",
            sa.make_url("postgresql+psycopg://bootstrap:redacted@example.invalid/omnigent"),
            f"/{role}-dsn",
        ),
    )
    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_service_role_bindings",
        lambda _source: _binding(),
    )
    monkeypatch.setattr(service_login_bootstrap, "_bootstrap_name", lambda *_args: "bootstrap")

    def role_flags(_connection, role: str):
        if role == "bootstrap":
            return (True, True, True, True, True, True, True, -1, None)
        if role == "principal_operator":
            return (True, False, False, True, False, False, True, -1, None)
        if role == "saas_platform_governance":
            return (
                (False, False, False, False, False, False, True, -1, None) if base_exists else None
            )
        if role == "platform_governance_login":
            return (
                (True, False, False, False, False, False, True, -1, None) if login_exists else None
            )
        raise AssertionError(role)

    def memberships(_connection, login: str):
        return list(management) if login == "principal_operator" else []

    def create_base(_connection) -> None:
        nonlocal base_exists
        base_exists = True

    def grant_management(_connection, *, operator: str) -> None:
        assert operator == "principal_operator"
        management.append(("saas_platform_governance", True, False, False, "bootstrap"))

    def create_login(_connection, *, login: str, password: str) -> None:
        nonlocal login_exists
        assert login == "platform_governance_login"
        assert password == "database password"
        login_exists = True

    monkeypatch.setattr(service_login_bootstrap, "_role_flags", role_flags)
    monkeypatch.setattr(service_login_bootstrap, "_memberships", memberships)
    monkeypatch.setattr(service_login_bootstrap, "_incoming_membership_count", lambda *_args: 0)
    monkeypatch.setattr(service_login_bootstrap, "_create_base_role", create_base)
    monkeypatch.setattr(service_login_bootstrap, "_grant_operator_management", grant_management)
    monkeypatch.setattr(service_login_bootstrap, "_create_login", create_login)

    result = service_login_bootstrap.prepare_platform_governance_service_login(
        environ={"OMNIGENT_SAAS_PRINCIPAL_OPERATOR_LOGIN": "principal_operator"},
        password_stream=BytesIO(b"database password\n"),
        engine_factory=lambda _url: engine,
    )

    assert result["created"] is True
    assert result["base_role_created"] is True
    assert result["operator_management_granted"] is True
    assert management == [("saas_platform_governance", True, False, False, "bootstrap")]


def test_prepare_rejects_creator_auto_membership_edge(monkeypatch) -> None:
    engine = _Engine(("bootstrap", "bootstrap"))
    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_database_url_file",
        lambda _source, role: (
            "postgresql+psycopg://bootstrap:redacted@example.invalid/omnigent",
            sa.make_url("postgresql+psycopg://bootstrap:redacted@example.invalid/omnigent"),
            f"/{role}-dsn",
        ),
    )
    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_service_role_bindings",
        lambda _source: _binding(),
    )
    monkeypatch.setattr(
        service_login_bootstrap,
        "_role_flags",
        lambda _connection, role: {
            "bootstrap": (True, True, True, True, True, True, True, -1, None),
            "principal_operator": (
                True,
                False,
                False,
                True,
                False,
                False,
                True,
                -1,
                None,
            ),
            "saas_platform_governance": (
                False,
                False,
                False,
                False,
                False,
                False,
                True,
                -1,
                None,
            ),
            "platform_governance_login": (
                True,
                False,
                False,
                False,
                False,
                False,
                True,
                -1,
                None,
            ),
        }[role],
    )
    monkeypatch.setattr(
        service_login_bootstrap,
        "_memberships",
        lambda _connection, login: (
            [("saas_platform_governance", True, False, False, "bootstrap")]
            if login == "principal_operator"
            else []
        ),
    )
    monkeypatch.setattr(service_login_bootstrap, "_incoming_membership_count", lambda *_args: 1)
    monkeypatch.setattr(service_login_bootstrap, "_bootstrap_name", lambda *_args: "bootstrap")

    try:
        service_login_bootstrap.prepare_platform_governance_service_login(
            environ={"OMNIGENT_SAAS_PRINCIPAL_OPERATOR_LOGIN": "principal_operator"},
            password_stream=BytesIO(b"database password\n"),
            engine_factory=lambda _url: engine,
        )
    except service_login_bootstrap.ProductionServiceLoginBootstrapError as error:
        assert error.code == "login_projection_invalid"
    else:
        raise AssertionError("creator auto-membership edge was accepted")


def test_prepare_rejects_tenant_governance_binding(monkeypatch) -> None:
    monkeypatch.setattr(
        service_login_bootstrap,
        "load_production_service_role_bindings",
        lambda _source: SimpleNamespace(
            by_service={
                "platform_governance": SimpleNamespace(
                    login="governance_login",
                    base_role="saas_governance",
                )
            }
        ),
    )

    try:
        service_login_bootstrap.prepare_platform_governance_service_login(
            environ={"OMNIGENT_SAAS_PRINCIPAL_OPERATOR_LOGIN": "principal_operator"},
            password_stream=BytesIO(b"database password\n"),
        )
    except service_login_bootstrap.ProductionServiceLoginBootstrapError as error:
        assert error.code == "authority_invalid"
    else:
        raise AssertionError("tenant-governance authority was accepted")
