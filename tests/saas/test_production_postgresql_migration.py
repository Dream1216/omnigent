from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from saas.production import postgresql_migration as migration
from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
)
from saas.scripts.run_postgresql_migration import _write_exclusive

_REVISION = "a" * 40


def _bindings() -> ProductionServiceRoleBindings:
    return ProductionServiceRoleBindings(
        path=Path("/bindings.json"),
        sha256="b" * 64,
        bindings=tuple(
            ProductionServiceRoleBinding(
                service=service,
                login=f"{service}_login",
                base_role=base_role,
            )
            for service, base_role in sorted(EXPECTED_PRODUCTION_SERVICE_ROLES.items())
        ),
    )


def _url(login: str, *, database: str = "omnigent", tls: bool = True) -> str:
    query = "?sslmode=verify-full&target_session_attrs=read-write" if tls else ""
    return f"postgresql+psycopg://{login}:top-secret@db.example:5432/{database}{query}"


def _plan(*, tls: bool = True) -> migration.ProductionPostgreSqlPlan:
    return migration.ProductionPostgreSqlPlan.from_urls(
        product_revision=_REVISION,
        principal_operator_url=_url("principal_operator", tls=tls),
        database_owner_url=_url("database_owner", tls=tls),
        official_owner_url=_url("official_owner", tls=tls),
        saas_owner_url=_url("saas_owner", tls=tls),
        service_role_bindings=_bindings(),
        require_tls=tls,
    )


def test_production_postgresql_url_is_explicit_and_redacted() -> None:
    authority = migration.parse_production_postgresql_url(
        _url("official_owner"),
        kind="official_owner",
    )

    assert authority.login == "official_owner"
    assert authority.url.host == "db.example"
    assert "top-secret" not in authority.redacted_url()
    assert "***" in authority.redacted_url()
    assert "top-secret" not in repr(authority)


@pytest.mark.parametrize(
    "url, code",
    [
        ("sqlite:///db.sqlite", "postgresql_psycopg_required"),
        (
            "postgresql+psycopg:///omnigent?sslmode=verify-full",
            "authority_tcp_target_required",
        ),
        (
            "postgresql+psycopg://Owner@db.example:5432/omnigent?sslmode=verify-full",
            "authority_login_invalid",
        ),
        (
            "postgresql+psycopg://owner@db.example:5432/omnigent?sslmode=require",
            "authority_tls_verify_full_required",
        ),
        (
            "postgresql+psycopg://owner@db.example:5432/omnigent"
            "?sslmode=verify-full&options=-c%20role%3Dpostgres",
            "authority_query_option_forbidden",
        ),
        (
            "postgresql+psycopg://owner@db.example:5432/omnigent"
            "?sslmode=verify-full&target_session_attrs=any",
            "authority_read_write_target_required",
        ),
    ],
)
def test_production_postgresql_url_rejects_ambiguous_authority(url: str, code: str) -> None:
    with pytest.raises(migration.PostgreSqlMigrationError) as exc_info:
        migration.parse_production_postgresql_url(url, kind="official_owner")

    assert exc_info.value.code == code
    assert "db.example" not in str(exc_info.value)
    assert "role=postgres" not in str(exc_info.value)


def test_plan_requires_distinct_logins_and_one_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: _REVISION)
    plan = _plan()
    migration._validate_plan(plan)

    duplicate = migration.ProductionPostgreSqlPlan(
        product_revision=plan.product_revision,
        principal_operator=plan.principal_operator,
        database_owner=plan.database_owner,
        official_owner=plan.official_owner,
        saas_owner=migration.PostgreSqlAuthority(
            kind="saas_owner",
            url=plan.official_owner.url,
            login=plan.official_owner.login,
        ),
        service_role_bindings=plan.service_role_bindings,
    )
    with pytest.raises(migration.PostgreSqlMigrationError) as duplicate_error:
        migration._validate_plan(duplicate)
    assert duplicate_error.value.code == "authority_logins_not_distinct"

    other_target = migration.ProductionPostgreSqlPlan(
        product_revision=plan.product_revision,
        principal_operator=plan.principal_operator,
        database_owner=plan.database_owner,
        official_owner=plan.official_owner,
        saas_owner=migration.parse_production_postgresql_url(
            _url("saas_owner", database="another"),
            kind="saas_owner",
        ),
        service_role_bindings=plan.service_role_bindings,
    )
    with pytest.raises(migration.PostgreSqlMigrationError) as target_error:
        migration._validate_plan(other_target)
    assert target_error.value.code == "authority_targets_differ"


def test_product_revision_is_bound_before_engine_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    engine_created = False

    def unexpected_create(_plan: object) -> dict[object, object]:
        nonlocal engine_created
        engine_created = True
        return {}

    monkeypatch.setattr(migration, "_installed_product_revision", lambda: "b" * 40)
    monkeypatch.setattr(migration, "_create_engines", unexpected_create)

    with pytest.raises(migration.PostgreSqlMigrationError) as exc_info:
        migration.run_production_postgresql_migration(_plan())

    assert exc_info.value.code == "installed_product_revision_mismatch"
    assert engine_created is False


def test_principal_operator_allows_only_non_runtime_admin_edges() -> None:
    assert migration._authority_memberships_are_safe(
        "principal_operator",
        (("saas_app", True, False, False), ("omnigent_runtime_app", True, False, False)),
        0,
    )
    assert not migration._authority_memberships_are_safe(
        "principal_operator", (("saas_app", True, True, False),), 0
    )
    assert not migration._authority_memberships_are_safe(
        "principal_operator", (("saas_app", True, False, True),), 0
    )
    assert not migration._authority_memberships_are_safe(
        "principal_operator", (("unreviewed_role", True, False, False),), 0
    )
    assert not migration._authority_memberships_are_safe(
        "principal_operator", (("saas_app", True, False, False),), 1
    )
    for kind in ("database_owner", "official_owner", "saas_owner"):
        assert migration._authority_memberships_are_safe(kind, (), 0)
        assert not migration._authority_memberships_are_safe(
            kind, (("saas_app", True, False, False),), 0
        )


def test_role_graph_requires_complete_bootstrap_granted_management_edges() -> None:
    expected: set[migration._RoleGraphEdge] = {
        ("saas_app", "principal_operator", "postgres", True, False, False, 10),
        (
            "saas_app",
            "app_login",
            "principal_operator",
            False,
            True,
            False,
            42,
        ),
    }
    assert migration._role_graph_projection_is_safe(
        set(expected), expected=expected, require_complete=True
    )

    missing_management = {edge for edge in expected if edge[1] != "principal_operator"}
    assert migration._role_graph_projection_is_safe(
        missing_management,
        expected=expected,
        require_complete=False,
    )
    assert not migration._role_graph_projection_is_safe(
        missing_management,
        expected=expected,
        require_complete=True,
    )

    wrong_grantor = set(expected)
    wrong_grantor.remove(("saas_app", "principal_operator", "postgres", True, False, False, 10))
    wrong_grantor.add(("saas_app", "principal_operator", "other", True, False, False, 99))
    assert not migration._role_graph_projection_is_safe(
        wrong_grantor,
        expected=expected,
        require_complete=False,
    )
    assert not migration._role_graph_projection_is_safe(
        wrong_grantor,
        expected=expected,
        require_complete=True,
    )


def test_fixed_capability_edges_are_granted_by_the_principal_operator() -> None:
    graph = migration._expected_service_principal_graph(
        bindings=_bindings(),
        principal_operator="principal_operator",
        principal_operator_oid=42,
        bootstrap_name="postgres",
    )

    assert (
        "saas_dispatcher",
        "saas_dispatcher_n1_compat",
        "principal_operator",
        False,
        False,
        False,
        42,
    ) in graph
    assert (
        "saas_platform_governance",
        "saas_privacy_executor",
        "principal_operator",
        False,
        True,
        True,
        42,
    ) in graph
    assert (
        "saas_app",
        "principal_operator",
        "postgres",
        True,
        False,
        False,
        10,
    ) in graph


def test_public_schema_inventory_digest_rejects_extra_object_and_unknown_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = [["namespace", "public", "database_owner"]]
    digest = migration.hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    key = (16, "official", "saas")
    monkeypatch.setattr(migration, "_PUBLIC_SCHEMA_INVENTORY_SHA256", {key: digest})

    assert migration._verify_public_schema_inventory_digest(inventory, key=key) == digest
    with pytest.raises(migration.PostgreSqlMigrationError) as extra_error:
        migration._verify_public_schema_inventory_digest(
            [*inventory, ["routine", "f:foreign()", "official_owner"]],
            key=key,
        )
    assert extra_error.value.code == "public_schema_inventory_drifted"

    with pytest.raises(migration.PostgreSqlMigrationError) as version_error:
        migration._verify_public_schema_inventory_digest(inventory, key=(17, "official", "saas"))
    assert version_error.value.code == "public_schema_inventory_drifted"


def test_source_security_catalog_normalizes_roles_and_rejects_acl_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = (16, "official", "saas")
    aliases = {"deployment_owner": "authority:saas_owner"}
    catalog = {"relation_acls": [["saas_runs", "deployment_owner", "SELECT"]]}
    normalized = migration._normalize_source_catalog(catalog, role_aliases=aliases)
    digest = migration.hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    monkeypatch.setattr(migration, "_SOURCE_SECURITY_CATALOG_SHA256", {key: digest})

    assert (
        migration._verify_source_security_catalog_digest(
            catalog,
            key=key,
            role_aliases=aliases,
        )
        == digest
    )
    with pytest.raises(migration.PostgreSqlMigrationError) as drift:
        migration._verify_source_security_catalog_digest(
            {"relation_acls": [*catalog["relation_acls"], ["saas_runs", "PUBLIC", "UPDATE"]]},
            key=key,
            role_aliases=aliases,
        )
    assert drift.value.code == "source_security_catalog_drifted"


def test_pg_trgm_contract_pins_all_members_and_both_operator_classes() -> None:
    assert len(migration._PG_TRGM_MEMBER_IDENTITIES) == 46
    assert len(set(migration._PG_TRGM_MEMBER_IDENTITIES)) == 46
    assert migration._PG_TRGM_MEMBER_IDENTITIES_BY_MAJOR[16] == (
        migration._PG_TRGM_MEMBER_IDENTITIES
    )
    assert migration._PG_TRGM_MEMBER_IDENTITIES_BY_MAJOR[18] == (
        *migration._PG_TRGM_MEMBER_IDENTITIES,
        ("pg_type", "type gtrgm[]"),
    )
    assert len(migration._PG_TRGM_FUNCTION_CONTRACTS) == 31
    assert {
        ("gin_trgm_ops", "gin", "gin_trgm_ops", "text", "integer", False),
        ("gist_trgm_ops", "gist", "gist_trgm_ops", "text", "gtrgm", False),
    } == migration._PG_TRGM_OPCLASS_CONTRACTS


def test_pg_trgm_member_projection_is_independent_of_database_collation() -> None:
    rows = [
        ("pg_proc", "function similarity_dist(text,text)", 10),
        ("pg_proc", "function similarity(text,text)", 10),
        ("pg_operator", "operator %(text,text)", 10),
    ]

    assert migration._canonical_pg_trgm_members(rows) == [
        ["pg_operator", "operator %(text,text)", 10],
        ["pg_proc", "function similarity(text,text)", 10],
        ["pg_proc", "function similarity_dist(text,text)", 10],
    ]


class _FakeEngine:
    def __init__(self, events: list[str], name: str) -> None:
        self._events = events
        self._name = name

    def dispose(self) -> None:
        self._events.append(f"dispose:{self._name}")

    @contextmanager
    def connect(self):
        yield object()


def _fake_facts() -> tuple[migration._SessionFacts, ...]:
    return tuple(
        migration._SessionFacts(
            kind=kind,
            login=f"{kind}_login",
            database="omnigent",
            database_oid=42,
            database_owner="database_owner_login",
            server_version_num=180000,
            server_address="10.0.0.1",
            server_port=5432,
            tls=True,
        )
        for kind in migration._AUTHORITY_KINDS
    )


def test_migration_lock_ends_implicit_transactions_around_session_lock() -> None:
    events: list[str] = []

    class _Scalar:
        def __init__(self, value: bool) -> None:
            self._value = value

        def scalar_one(self) -> bool:
            return self._value

    class _Connection:
        def __enter__(self) -> _Connection:
            events.append("connect")
            return self

        def __exit__(self, *_args: object) -> None:
            events.append("close")

        def execute(self, statement: object, _parameters: object) -> _Scalar:
            sql = str(statement)
            if "pg_try_advisory_lock" in sql:
                events.append("acquire")
            else:
                assert "pg_advisory_unlock" in sql
                events.append("release")
            return _Scalar(True)

        def commit(self) -> None:
            events.append("commit")

        def rollback(self) -> None:
            events.append("rollback")

    class _Engine:
        def connect(self) -> _Connection:
            return _Connection()

    with migration._migration_lock(_Engine(), timeout_seconds=1.0):  # type: ignore[arg-type]
        events.append("yield")

    assert events == [
        "connect",
        "acquire",
        "commit",
        "yield",
        "release",
        "commit",
        "close",
    ]


def _patch_execution_boundary(
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> dict[migration.AuthorityKind, _FakeEngine]:
    engines = {kind: _FakeEngine(events, kind) for kind in migration._AUTHORITY_KINDS}
    monkeypatch.setattr(migration, "_validate_plan", lambda _plan: events.append("validate"))
    monkeypatch.setattr(migration, "_create_engines", lambda _plan: engines)
    monkeypatch.setattr(
        migration,
        "_preflight",
        lambda _plan, _engines: events.append("preflight") or _fake_facts(),
    )
    monkeypatch.setattr(
        migration,
        "_preflight_pg_trgm_extension",
        lambda *_args, **_kwargs: events.append("pg_trgm"),
    )

    @contextmanager
    def lock(_engine: object, *, timeout_seconds: float) -> Iterator[None]:
        assert timeout_seconds == 30.0
        events.append("lock:enter")
        yield
        events.append("lock:exit")

    monkeypatch.setattr(migration, "_migration_lock", lock)
    monkeypatch.setattr(
        migration,
        "_apply_principals",
        lambda _engine, **_kwargs: events.append("principals"),
    )
    monkeypatch.setattr(
        migration,
        "_apply_database_authority",
        lambda _engine, **_kwargs: events.append("database"),
    )
    monkeypatch.setattr(
        migration,
        "_upgrade",
        lambda _engine, kind: events.append(f"alembic:{kind}"),
    )
    monkeypatch.setattr(
        migration,
        "_apply_runtime_authority",
        lambda _engine: events.append("runtime"),
    )
    monkeypatch.setattr(
        migration,
        "_apply_control_plane_authority",
        lambda _engine: events.append("control"),
    )
    monkeypatch.setattr(
        migration,
        "_finalize_database_authority",
        lambda _engine, **_kwargs: events.append("database:finalize"),
    )
    monkeypatch.setattr(
        migration,
        "_verify_state",
        lambda _plan, _engines: (
            events.append("verify")
            or migration._VerifiedState(
                official_head="official-head",
                saas_head="saas-head",
                runtime_rls_table_count=17,
                catalog_sha256="c" * 64,
            )
        ),
    )
    return engines


def test_migration_executes_the_seven_authority_phases_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _patch_execution_boundary(monkeypatch, events)

    receipt = migration.run_production_postgresql_migration(_plan())

    assert events[:15] == [
        "validate",
        "preflight",
        "pg_trgm",
        "lock:enter",
        "preflight",
        "pg_trgm",
        "principals",
        "database",
        "alembic:official",
        "alembic:saas",
        "runtime",
        "control",
        "database:finalize",
        "lock:exit",
        "verify",
    ]
    assert receipt.phases == (
        "preflight:verified",
        "pg_trgm_preflight:verified",
        "lock_preflight:verified",
        "lock_pg_trgm_preflight:verified",
        "principals:applied",
        "database:applied",
        "official_alembic:applied",
        "saas_alembic:applied",
        "runtime_authority:applied",
        "control_plane_authority:applied",
        "database_acl_finalize:applied",
        "state:verified",
    )
    rendered = json.dumps(receipt.to_dict(), sort_keys=True)
    assert "top-secret" not in rendered


def test_verify_only_performs_no_lock_or_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    _patch_execution_boundary(monkeypatch, events)

    receipt = migration.run_production_postgresql_migration(_plan(), verify_only=True)

    assert events[:4] == ["validate", "preflight", "pg_trgm", "verify"]
    assert not any(
        item in events
        for item in (
            "lock:enter",
            "principals",
            "database",
            "alembic:official",
            "alembic:saas",
            "runtime",
            "control",
            "database:finalize",
        )
    )
    assert receipt.verify_only is True
    assert receipt.phases == (
        "preflight:verified",
        "pg_trgm_preflight:verified",
        "state:verified",
    )


def test_phase_failure_stops_before_later_authorities_and_disposes_engines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    engines = _patch_execution_boundary(monkeypatch, events)

    def fail_database(_engine: object, **_kwargs: object) -> None:
        events.append("database:failed")
        raise RuntimeError("driver detail must not escape")

    monkeypatch.setattr(migration, "_apply_database_authority", fail_database)

    with pytest.raises(migration.PostgreSqlMigrationError) as exc_info:
        migration.run_production_postgresql_migration(_plan())

    assert exc_info.value.phase == "database"
    assert exc_info.value.code == "phase_execution_failed"
    assert "driver detail" not in str(exc_info.value)
    assert "alembic:official" not in events
    assert {event for event in events if event.startswith("dispose:")} == {
        f"dispose:{kind}" for kind in engines
    }


def test_database_and_runtime_sql_keep_cluster_and_object_authority_separate() -> None:
    root = Path(__file__).resolve().parents[2]
    principals = (root / "saas/control_plane/postgresql_principals.sql").read_text(
        encoding="utf-8"
    )
    database = (root / "saas/control_plane/postgresql_database.sql").read_text(encoding="utf-8")
    runtime = (root / "saas/runtime_rls/postgresql_roles.sql").read_text(encoding="utf-8")
    wrapper = (root / "saas/runtime_rls/postgresql_roles.psql").read_text(encoding="utf-8")

    assert "'omnigent_runtime_app'" in principals
    assert "immutable role flags are unsafe" in principals
    assert "NOLOGIN NOCREATEROLE INHERIT CONNECTION LIMIT -1" in principals
    assert "' NOSUPERUSER" not in principals
    assert "' NOBYPASSRLS" not in principals
    assert "REVOKE USAGE, CREATE ON SCHEMA public FROM PUBLIC" in database
    assert "REVOKE CONNECT, TEMPORARY, CREATE ON DATABASE" in database
    assert "PUBLIC schema CREATE remains enabled" in database
    assert "CREATE ROLE" not in runtime
    assert "ALTER ROLE" not in runtime
    assert runtime.index("official table ownership drifted") < runtime.index(
        "REVOKE ALL PRIVILEGES ON TABLE"
    )
    assert "GRANT USAGE ON SCHEMA public" not in runtime
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public" not in runtime
    assert "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public" not in runtime
    assert "Runtime principal has unmanaged authority" in runtime
    assert runtime.index("Runtime principal has unmanaged authority") < runtime.index(
        "REVOKE ALL PRIVILEGES ON TABLE"
    )
    assert "REVOKE ALL PRIVILEGES ON TABLE\n    account_tokens" in runtime
    assert "exact ACL projection failed" in runtime
    assert wrapper.index("\\set ON_ERROR_STOP on") < wrapper.index("BEGIN;")
    assert wrapper.index("BEGIN;") < wrapper.index("\\ir postgresql_roles.sql")
    assert wrapper.index("\\ir postgresql_roles.sql") < wrapper.index("COMMIT;")
    assert "foreign owner ACL drifted" in (
        root / "saas/control_plane/postgresql_roles.sql"
    ).read_text(encoding="utf-8")
    control_roles = (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
    assert "grantee.rolname = 'saas_executor'" in control_roles
    assert "acl.grantor = database.datdba" in control_roles
    assert "acl.privilege_type = 'CONNECT'" in control_roles
    migration_source = Path(migration.__file__).read_text(encoding="utf-8")
    assert "defaults.defaclobjtype NOT IN ('f','T')" in migration_source
    assert "acl.privilege_type = 'EXECUTE'" in migration_source


def test_database_create_authority_is_exactly_the_official_owner() -> None:
    source = Path(migration.__file__).read_text(encoding="utf-8")

    assert "GRANT CREATE ON DATABASE" in source
    assert "expected_database" in source
    assert '"database_acl_projection_drifted"' in source
    assert "GRANT USAGE ON SCHEMA public TO" in source
    assert "_owned_object_acl_grantees" in source


def test_initial_schema_usage_covers_every_nologin_capability_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authority SQL must remain executable after PUBLIC schema USAGE is removed."""

    observed: dict[str, object] = {}

    class _Connection:
        def exec_driver_sql(self, _statement: str) -> None:
            return None

    class _Begin:
        def __enter__(self) -> _Connection:
            return _Connection()

        def __exit__(self, *_args: object) -> None:
            return None

    class _Engine:
        def begin(self) -> _Begin:
            return _Begin()

    def capture(_connection: object, **kwargs: object) -> None:
        observed.update(kwargs)

    monkeypatch.setattr(migration, "_preflight_database_acl_grantors", lambda _connection: None)
    monkeypatch.setattr(migration, "_read_resource", lambda *_args: "SELECT 1")
    monkeypatch.setattr(migration, "_converge_database_acl_projection", capture)
    migration._apply_database_authority(
        _Engine(),  # type: ignore[arg-type]
        principal_operator="principal_operator",
        official_owner="official_owner",
        saas_owner="saas_owner",
        bindings=_bindings(),
    )

    assert observed["schema_usage_roles"] == {
        "official_owner",
        "saas_owner",
        *migration._CAPABILITY_ROLES,
    }


def test_receipt_write_is_exclusive_and_owner_only(tmp_path: Path) -> None:
    output = tmp_path / "receipt.json"
    _write_exclusive(output, "{}\n")

    assert output.read_text(encoding="utf-8") == "{}\n"
    assert os.stat(output).st_mode & 0o777 == 0o400
    with pytest.raises(FileExistsError):
        _write_exclusive(output, '{"replacement":true}\n')
    assert output.read_text(encoding="utf-8") == "{}\n"


def test_runtime_verify_only_binds_receipt_and_five_service_logins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contracts = migration.load_runtime_rls_contract()
    catalog = {
        "official_head": "official-head",
        "saas_head": "saas-head",
        "ownership": (),
        "runtime_acls": (),
        "runtime_rls_tables": [contract.table_name for contract in contracts],
        "official_security": {},
        "control_plane_security": {},
    }
    catalog_digest = migration.hashlib.sha256(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    facts = migration._ServiceSessionFacts(
        login="placeholder",
        database="omnigent",
        database_oid=42,
        database_owner="database_owner",
        server_version_num=180000,
        server_address="10.0.0.1",
        server_port=5432,
    )
    identity_digest = migration.hashlib.sha256(
        json.dumps(
            {
                "database": facts.database,
                "database_oid": facts.database_oid,
                "database_owner": facts.database_owner,
                "server_version_num": facts.server_version_num,
                "server_address": facts.server_address,
                "server_port": facts.server_port,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    monkeypatch.setattr(
        migration,
        "_load_runtime_receipt",
        lambda _config: migration._RuntimeReceipt(
            product_revision=_REVISION,
            official_head="official-head",
            saas_head="saas-head",
            database_identity_sha256=identity_digest,
            catalog_sha256=catalog_digest,
            service_role_bindings_sha256=_bindings().sha256,
            runtime_rls_table_count=len(contracts),
            official_owner="official_owner",
            saas_owner="saas_owner",
            principal_operator="principal_operator",
            database_owner="database_owner",
        ),
    )
    observed: list[tuple[str, str]] = []

    def inspect(_engine: object, *, expected_login: str, expected_role: str):
        observed.append((expected_login, expected_role))
        return migration._ServiceSessionFacts(
            login=expected_login,
            database=facts.database,
            database_oid=facts.database_oid,
            database_owner=facts.database_owner,
            server_version_num=facts.server_version_num,
            server_address=facts.server_address,
            server_port=facts.server_port,
        )

    monkeypatch.setattr(migration, "_inspect_service_login", inspect)
    monkeypatch.setattr(
        migration,
        "_verify_capability_principals",
        lambda _connection, **_kwargs: None,
    )
    monkeypatch.setattr(migration, "_verify_database_boundary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(migration, "verify_runtime_rls", lambda _connection: None)
    monkeypatch.setattr(migration, "_verify_runtime_acl", lambda _connection: ())
    monkeypatch.setattr(
        migration,
        "_official_security_catalog",
        lambda _connection, **_kwargs: {},
    )
    monkeypatch.setattr(
        migration,
        "_control_plane_security_catalog",
        lambda _connection, **_kwargs: {},
    )
    monkeypatch.setattr(migration, "_verify_object_ownership", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(
        migration,
        "_verify_source_security_catalog_digest",
        lambda *_args, **_kwargs: "c" * 64,
    )

    class FakeEngine:
        @contextmanager
        def connect(self):
            yield SimpleNamespace(
                execute=lambda _statement: SimpleNamespace(
                    one=lambda: (facts.server_version_num, "postgres")
                )
            )

    urls = {
        service: f"postgresql+psycopg://{service}_login:secret@db/omnigent"
        for service in migration._SERVER_SERVICE_ROLES
    }
    config = SimpleNamespace(
        secrets=SimpleNamespace(database_urls=SimpleNamespace(as_mapping=lambda: urls)),
        service_role_bindings=_bindings(),
    )
    engines = {service: FakeEngine() for service in migration._SERVER_SERVICE_ROLES}

    migration.verify_production_postgresql_state(engines=engines, config=config)

    assert observed == [
        (f"{service}_login", base_role)
        for service, base_role in migration._SERVER_SERVICE_ROLES.items()
    ]
