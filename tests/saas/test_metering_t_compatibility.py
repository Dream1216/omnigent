"""Old-T profile/receipt compatibility, not full LiteLLM product acceptance."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from saas.production import postgresql_migration as migration
from saas.production import service_bindings as bindings
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_server_config,
)
from saas.scripts import run_postgresql_migration as cli
from tests.saas.test_production_postgresql_migration import (
    _plan,
    _platform_admin_bindings,
    _platform_bindings,
)
from tests.saas.test_production_server_config import _environment

PREFIX = "OMNIGENT_SAAS_MACHINE_METERING_SERVICE_ROLE_BINDINGS"


def _metering(tmp_path):
    path = tmp_path / "machine-metering.json"
    path.write_text(
        bindings.render_production_service_role_bindings(
            (bindings.ProductionServiceRoleBinding("metering", "rollback_meter", "saas_metering"),)
        )
    )
    path.chmod(0o400)
    source = {PREFIX + "_FILE": str(path)}
    return source, bindings.load_machine_metering_service_role_bindings(source)


def test_old_target_loads_dedicated_metering_metadata_without_database_access(tmp_path):
    source, profile = _metering(tmp_path)
    assert len(profile.bindings) == 1
    assert profile.login_for("metering") == "rollback_meter"
    assert (
        profile.sha256 == hashlib.sha256(Path(source[PREFIX + "_FILE"]).read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("profile_name", ["core", "model", "admin", "projection"])
def test_old_target_uses_only_exact_new_T_catalogs(tmp_path, profile_name):
    _, metering = _metering(tmp_path)
    projection = bindings.ProductionServiceRoleBindings(
        Path("/projection.json"),
        "e" * 64,
        (
            bindings.ProductionServiceRoleBinding(
                "model_projection", "projection_login", "saas_model_projection"
            ),
        ),
    )
    plan = replace(
        _plan(),
        machine_metering_service_role_bindings=metering,
        platform_model_service_role_bindings=_platform_bindings()
        if profile_name != "core"
        else None,
        platform_admin_service_role_bindings=_platform_admin_bindings()
        if profile_name in {"admin", "projection"}
        else None,
        model_projection_service_role_bindings=projection
        if profile_name == "projection"
        else None,
    )
    selected = migration._source_security_catalog_baselines(plan.service_role_graph)
    assert selected is migration._MACHINE_METERING_SOURCE_SECURITY_CATALOGS[profile_name]
    assert set(selected) == {(major, "mm1a2b3c4d5e", "lm2t00000001") for major in (16, 18)}
    original = migration._source_security_catalog_baselines(
        replace(plan, machine_metering_service_role_bindings=None).service_role_graph
    )
    assert all(digest != original[key] for key, digest in selected.items())
    for major in (16, 18):
        migration._require_source_catalog_baselines(major, bindings=plan.service_role_graph)
        with pytest.raises(
            migration.PostgreSqlMigrationError, match="runtime_schema_not_supported"
        ):
            migration._require_source_catalog_baselines(
                major, bindings=plan.service_role_graph, saas_head="p0s000000015"
            )


@pytest.mark.parametrize("change", ["role", "capability", "authority", "shared", "sha"])
def test_old_target_rejects_bad_new_authority_before_database_access(
    tmp_path, monkeypatch, change
):
    _, profile = _metering(tmp_path)
    binding = profile.bindings[0]
    if change == "role":
        binding = replace(binding, base_role="saas_app")
    elif change in {"capability", "authority", "shared"}:
        binding = replace(
            binding,
            login={
                "capability": "saas_metering",
                "authority": "official_owner",
                "shared": "app_login",
            }[change],
        )
    profile = replace(
        profile, bindings=(binding,), sha256="invalid" if change == "sha" else profile.sha256
    )
    plan = replace(_plan(), machine_metering_service_role_bindings=profile)
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: plan.product_revision)
    with pytest.raises(migration.PostgreSqlMigrationError, match="service_role_bindings_invalid"):
        migration._validate_plan(plan)


def test_old_app_receipt_includes_metering_but_not_its_database_secret(tmp_path):
    source = _environment(tmp_path)
    metering_source, _ = _metering(tmp_path)
    source.update(metering_source)
    graph = bindings.load_production_service_role_graph(source)
    receipt = Path(source["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"])
    value = json.loads(receipt.read_text())
    value["service_role_graph_sha256"] = graph.sha256
    receipt.chmod(0o600)
    receipt.write_text(json.dumps(value))
    receipt.chmod(0o400)
    config = load_production_server_config(source)
    assert config.machine_metering_service_role_bindings is not None
    assert config.machine_metering_service_role_bindings.login_for("metering") == "rollback_meter"
    assert config.service_role_graph.sha256 == graph.sha256
    assert "metering" not in config.secrets.database_urls.as_mapping()


def test_old_app_refuses_sha_only_metering_declaration(tmp_path):
    source = _environment(tmp_path)
    source[PREFIX + "_SHA256"] = "a" * 64
    with pytest.raises(ProductionServerConfigError):
        load_production_server_config(source)


def test_old_cli_passes_exact_optional_profile(tmp_path, monkeypatch):
    source = _environment(tmp_path)
    metering_source, profile = _metering(tmp_path)
    source.update(metering_source)
    for name, value in source.items():
        monkeypatch.setenv(name, value)
    for name in cli._DIRECT_URL_ENVIRONMENTS:
        monkeypatch.delenv(name, raising=False)
    for field, name in cli._URL_ENVIRONMENTS.items():
        path = tmp_path / field
        path.write_text(
            f"postgresql+psycopg://{field}:isolated@localhost:5432/db?sslmode=verify-full"
        )
        path.chmod(0o400)
        monkeypatch.setenv(name, str(path))
    captured = []
    monkeypatch.setattr(cli, "_verify_installed_build_revision", lambda *_: None)
    monkeypatch.setattr(
        cli,
        "run_production_postgresql_migration",
        lambda plan, **_: captured.append(plan) or SimpleNamespace(to_dict=dict),
    )
    monkeypatch.setattr("sys.argv", ["migrate", "--product-revision", "1" * 40])
    assert cli.main() == 0
    assert captured[0].machine_metering_service_role_bindings == profile


def test_old_target_missing_metering_pin_refuses_before_mutation(tmp_path, monkeypatch):
    _, profile = _metering(tmp_path)
    plan = replace(_plan(), machine_metering_service_role_bindings=profile)
    monkeypatch.setitem(migration._MACHINE_METERING_SOURCE_SECURITY_CATALOGS, "core", {})
    with pytest.raises(
        migration.PostgreSqlMigrationError, match="source_catalog_baseline_missing"
    ):
        migration._require_source_catalog_baselines(18, bindings=plan.service_role_graph)
