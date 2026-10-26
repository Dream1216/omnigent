from __future__ import annotations

import json
from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace

import pytest

from saas.production import postgresql_migration as migration
from saas.production.server_config import ProductionMigrationReceipt
from saas.production.service_bindings import compose_production_service_role_graph
from tests.saas.test_production_postgresql_migration import _REVISION, _bindings, _plan

_P0 = "p0s000000015"
_R = "lm2r00000001"
_S = "lm2s00000001"
_T = "lm2t00000001"
_D = "dp1a00000001"
_OFFICIAL = "mm1a2b3c4d5e"


def _receipt(tmp_path, monkeypatch, *, installed, requested, verify_only=True):
    bindings = _bindings()
    graph = compose_production_service_role_graph(bindings, None, None)
    table_count = len(migration.load_runtime_rls_contract())
    document = {
        "schema_version": 2,
        "status": "pass",
        "verify_only": verify_only,
        "product_revision": _REVISION,
        "official_head": _OFFICIAL,
        "saas_head": requested,
        "database_identity_sha256": "b" * 64,
        "catalog_sha256": "c" * 64,
        "service_role_bindings_sha256": bindings.sha256,
        "service_role_graph_sha256": graph.sha256,
        "runtime_rls_table_count": table_count,
        "phases": ["preflight:verified", "state:verified"],
        "authorities": [{"kind": kind, "login": kind} for kind in migration._AUTHORITY_KINDS],
    }
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(document))
    path.chmod(0o400)
    configured = ProductionMigrationReceipt(
        path=path,
        product_revision=_REVISION,
        official_head=_OFFICIAL,
        saas_head=requested,
        database_identity_sha256="b" * 64,
        catalog_sha256="c" * 64,
        service_role_bindings_sha256=bindings.sha256,
        service_role_graph_sha256=graph.sha256,
        runtime_rls_table_count=table_count,
    )
    config = SimpleNamespace(
        product_revision=_REVISION,
        official_schema_revision=_OFFICIAL,
        control_plane_schema_revision=requested,
        migration_receipt=configured,
        service_role_bindings=bindings,
        service_role_graph=graph,
    )
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: _REVISION)
    monkeypatch.setattr(
        migration, "_expected_head", lambda kind: installed if kind == "saas" else _OFFICIAL
    )
    return config


@pytest.mark.parametrize(
    "installed,requested",
    [
        (_P0, _P0),
        (_P0, _R),
        (_R, _R),
        (_P0, _S),
        (_R, _S),
        (_S, _S),
        (_P0, _T),
        (_R, _T),
        (_S, _T),
        (_T, _T),
        (_D, _T),
        (_D, _D),
    ],
)
def test_receipt_accepts_only_explicit_compatible_application_schema_pairs(
    tmp_path, monkeypatch, installed, requested
):
    config = _receipt(tmp_path, monkeypatch, installed=installed, requested=requested)
    observed = migration._load_runtime_receipt(config)
    assert observed.product_revision == _REVISION
    assert observed.saas_head == requested


@pytest.mark.parametrize(
    "installed,requested",
    [
        (_R, _P0),
        (_S, _P0),
        (_S, _R),
        (_T, _P0),
        (_T, _R),
        (_T, _S),
        (_D, _P0),
        (_D, _R),
        (_D, _S),
        (_P0, _D),
        (_R, _D),
        (_S, _D),
        (_T, _D),
        (_P0, "lm2q00000001"),
        (_P0, "future"),
        ("future", "future"),
    ],
)
def test_receipt_rejects_unsupported_or_future_schema_pairs(
    tmp_path, monkeypatch, installed, requested
):
    config = _receipt(tmp_path, monkeypatch, installed=installed, requested=requested)
    with pytest.raises(migration.PostgreSqlMigrationError):
        migration._load_runtime_receipt(config)


@pytest.mark.parametrize("requested", [_R, _S, _T])
def test_cross_schema_receipt_requires_read_only_verification(tmp_path, monkeypatch, requested):
    config = _receipt(tmp_path, monkeypatch, installed=_P0, requested=requested, verify_only=False)
    with pytest.raises(migration.PostgreSqlMigrationError):
        migration._load_runtime_receipt(config)


@pytest.mark.parametrize("requested", [_R, _S, _T])
def test_cross_schema_receipt_cannot_borrow_the_schema_producer_sha(
    tmp_path, monkeypatch, requested
):
    config = _receipt(tmp_path, monkeypatch, installed=_P0, requested=requested)
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: "f" * 40)
    with pytest.raises(migration.PostgreSqlMigrationError) as error:
        migration._load_runtime_receipt(config)
    assert error.value.code == "migration_receipt_binding_mismatch"


@pytest.mark.parametrize("mode", [0o600, 0o444])
def test_cross_schema_receipt_retains_owner_only_read_only_file_requirement(
    tmp_path, monkeypatch, mode
):
    config = _receipt(tmp_path, monkeypatch, installed=_P0, requested=_R)
    config.migration_receipt.path.chmod(mode)
    with pytest.raises(migration.PostgreSqlMigrationError) as error:
        migration._load_runtime_receipt(config)
    assert error.value.code == "migration_receipt_invalid"


@pytest.mark.parametrize("verify_only,requested", [(False, _R), (False, _T), (True, "future")])
def test_schema_override_is_rejected_before_any_authority_connection(
    monkeypatch, verify_only, requested
):
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: _REVISION)
    monkeypatch.setattr(
        migration, "_expected_head", lambda kind: _P0 if kind == "saas" else _OFFICIAL
    )
    monkeypatch.setattr(
        migration, "_create_engines", lambda _plan: pytest.fail("authority opened")
    )
    plan = replace(_plan(), verification_saas_head=requested)
    with pytest.raises(migration.PostgreSqlMigrationError):
        migration.run_production_postgresql_migration(plan, verify_only=verify_only)


def test_verify_only_schema_override_never_executes_a_mutating_phase(monkeypatch):
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: _REVISION)
    monkeypatch.setattr(
        migration, "_expected_head", lambda kind: _P0 if kind == "saas" else _OFFICIAL
    )
    engines = {
        kind: SimpleNamespace(connect=lambda: nullcontext(object()))
        for kind in migration._AUTHORITY_KINDS
    }
    fact = migration._SessionFacts(
        kind="principal_operator",
        login="principal_operator",
        database="app",
        database_oid=42,
        database_owner="database_owner",
        server_version_num=180000,
        server_address="127.0.0.1",
        server_port=5432,
        tls=True,
    )
    monkeypatch.setattr(migration, "_create_engines", lambda _plan: engines)
    monkeypatch.setattr(migration, "_preflight", lambda *_args: (fact,))
    monkeypatch.setattr(migration, "_preflight_pg_trgm_extension", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(migration, "_dispose_engines", lambda _engines: None)
    for name in (
        "_apply_principals",
        "_apply_database_authority",
        "_upgrade",
        "_apply_runtime_authority",
        "_apply_control_plane_authority",
        "_finalize_database_authority",
        "_migration_lock",
    ):
        monkeypatch.setattr(
            migration, name, lambda *_args, **_kwargs: pytest.fail("mutation attempted")
        )

    def verified(plan, _engines):
        assert plan.verification_saas_head == _R
        return migration._VerifiedState(
            _OFFICIAL, _R, len(migration.load_runtime_rls_contract()), "c" * 64
        )

    monkeypatch.setattr(migration, "_verify_state", verified)
    result = migration.run_production_postgresql_migration(
        replace(_plan(), verification_saas_head=_R), verify_only=True
    )
    assert result.verify_only is True and result.product_revision == _REVISION
    assert result.saas_head == _R and result.schema_version == 2
    assert not any(phase.endswith(":applied") for phase in result.phases)


def test_verification_cli_rejects_override_without_read_only_mode_before_reading_secrets(
    monkeypatch, capsys
):
    from saas.scripts import run_postgresql_migration as cli

    monkeypatch.setattr("sys.argv", ["migration", "--verification-saas-head", _R])
    monkeypatch.setattr(
        cli, "_required_url_file", lambda *_args: pytest.fail("authority file read")
    )
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert "--verification-saas-head requires --verify-only" in capsys.readouterr().err
