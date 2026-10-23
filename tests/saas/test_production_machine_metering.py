"""Production composition contracts; these fixtures are not migration admission."""

from __future__ import annotations

import asyncio
import json
import ssl
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.production import machine_metering as production
from saas.production.postgresql_migration import PostgreSqlMigrationError
from saas.production.service_bindings import (
    ProductionServiceRoleBinding,
    load_machine_metering_service_role_bindings,
    load_production_service_role_graph,
    render_production_service_role_bindings,
)
from tests.saas.test_billing_metering_transport import _certificate_fixture
from tests.saas.test_production_model_projection import _environment as projection_environment
from tests.saas.test_production_postgresql_migration import _plan


def _rewrite(path: Path, value: str, *, mode: int = 0o400) -> None:
    if path.exists():
        path.chmod(0o600)
    path.write_text(value)
    path.chmod(mode)


def _declare_metering_profile(source, tmp_path):
    profile = tmp_path / "machine-metering.json"
    _rewrite(
        profile,
        render_production_service_role_bindings(
            (ProductionServiceRoleBinding("metering", "metering_receiver_login", "saas_metering"),)
        ),
    )
    source["OMNIGENT_SAAS_MACHINE_METERING_SERVICE_ROLE_BINDINGS_FILE"] = str(profile)
    graph = load_production_service_role_graph(source)
    receipt = Path(source["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"])
    document = json.loads(receipt.read_text())
    document["service_role_graph_sha256"] = graph.sha256
    _rewrite(receipt, json.dumps(document))
    return graph


@pytest.fixture
def environment(tmp_path):
    source = {
        name: value
        for name, value in projection_environment(tmp_path).items()
        if not name.endswith("_DATABASE_URL_FILE") and "LITELLM" not in name
    }
    _declare_metering_profile(source, tmp_path)
    source["OMNIGENT_SAAS_IMAGE_DIGEST"] = "sha256:" + "b" * 64
    database = tmp_path / "metering-database-url"
    _rewrite(
        database,
        "postgresql+psycopg://metering_receiver_login:isolated-metering-password"
        "@db.example:5432/omnigent?sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt",
    )
    source["OMNIGENT_SAAS_METERING_DATABASE_URL_FILE"] = str(database)
    certificates = _certificate_fixture(tmp_path, (uuid4(),))
    server = certificates["server"]
    server.private_key.chmod(0o600)
    source.update(
        {
            "OMNIGENT_SAAS_METERING_CLIENT_CA_FILE": str(server.ca),
            "OMNIGENT_SAAS_METERING_TLS_CERT_FILE": str(server.certificate),
            "OMNIGENT_SAAS_METERING_TLS_KEY_FILE": str(server.private_key),
            "OMNIGENT_SAAS_METERING_TRUST_BUNDLE_VERSION": "test-v1",
        }
    )
    return source


def test_metering_config_binds_dedicated_profile_and_redacts_database_secret(environment):
    config = production.load_production_machine_metering_config(environment)
    assert config.service_role_graph.login_for("metering") == "metering_receiver_login"
    assert config.migration_receipt.service_role_graph_sha256 == config.service_role_graph.sha256
    assert config.bind_host == "127.0.0.1" and config.bind_port == 9446
    assert config.expected_host == "billing-metering.internal"
    assert "isolated-metering-password" not in repr(config)


@pytest.mark.parametrize("consumer", ["projection", "application"])
def test_receipt_consumers_keep_the_complete_declared_metering_graph(tmp_path, consumer):
    from saas.production.model_projection import load_production_model_projection_config
    from saas.production.server_config import ProductionServerConfig, load_production_server_config
    from tests.saas.test_production_server_config import _environment as server_environment

    source = (projection_environment if consumer == "projection" else server_environment)(tmp_path)
    graph = _declare_metering_profile(source, tmp_path)
    config = (
        load_production_model_projection_config
        if consumer == "projection"
        else load_production_server_config
    )(source)
    assert config.service_role_graph.sha256 == graph.sha256
    assert config.migration_receipt.service_role_graph_sha256 == graph.sha256
    if consumer == "application":
        assert isinstance(config, ProductionServerConfig)
        assert "metering" not in config.secrets.database_urls.as_mapping()


@pytest.mark.parametrize(
    "change",
    (
        "ambient_url",
        "other_service",
        "raw_metering_url",
        "wrong_login",
        "wrong_role",
        "shared_login",
        "profile_mode",
        "profile_symlink",
        "key_mode",
        "key_symlink",
        "stale_graph",
        "revision",
        "unrendered",
        "image",
        "public_bind",
        "port",
        "timeout",
        "nan_timeout",
        "external_name",
        "trust_bundle",
        "weak_database_tls",
        "database_options",
        "missing_profile",
        "capability_login",
    ),
)
def test_metering_configuration_refuses_authority_or_evidence_drift(environment, tmp_path, change):
    source = dict(environment)
    profile_name = "OMNIGENT_SAAS_MACHINE_METERING_SERVICE_ROLE_BINDINGS_FILE"
    database_name = "OMNIGENT_SAAS_METERING_DATABASE_URL_FILE"
    if change in {"ambient_url", "other_service", "raw_metering_url"}:
        name = {
            "ambient_url": "DATABASE_URL",
            "other_service": "OMNIGENT_SAAS_APP_DATABASE_URL_FILE",
            "raw_metering_url": "OMNIGENT_SAAS_METERING_DATABASE_URL",
        }[change]
        source[name] = "not-an-authorized-service-authority"
    elif change in {"wrong_login", "weak_database_tls", "database_options"}:
        path = Path(source[database_name])
        value = path.read_text()
        if change == "wrong_login":
            value = value.replace("metering_receiver_login", "billing_login")
        elif change == "weak_database_tls":
            value = value.replace("verify-full", "require")
        else:
            value += "&options=role%3Dsaas_metering"
        _rewrite(path, value)
    elif change in {"wrong_role", "shared_login"}:
        path = Path(source[profile_name])
        value = path.read_text().replace(
            "saas_metering" if change == "wrong_role" else "metering_receiver_login",
            "saas_billing" if change == "wrong_role" else "prod_app",
        )
        _rewrite(path, value)
    elif change == "capability_login":
        for name in (profile_name, database_name):
            path = Path(source[name])
            _rewrite(path, path.read_text().replace("metering_receiver_login", "saas_metering"))
    elif change in {"profile_mode", "key_mode"}:
        Path(
            source[
                profile_name if change == "profile_mode" else "OMNIGENT_SAAS_METERING_TLS_KEY_FILE"
            ]
        ).chmod(0o644)
    elif change in {"profile_symlink", "key_symlink"}:
        name = (
            profile_name if change == "profile_symlink" else "OMNIGENT_SAAS_METERING_TLS_KEY_FILE"
        )
        path = tmp_path / "untrusted-link"
        path.symlink_to(source[name])
        source[name] = str(path)
    elif change == "stale_graph":
        path = Path(source["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"])
        value = json.loads(path.read_text())
        value["service_role_graph_sha256"] = "f" * 64
        _rewrite(path, json.dumps(value))
    elif change == "missing_profile":
        source.pop(profile_name)
    else:
        name, value = {
            "revision": ("OMNIGENT_SAAS_SOURCE_SHA", "c" * 40),
            "unrendered": ("OMNIGENT_SAAS_PRODUCT_REVISION", "0" * 40),
            "image": ("OMNIGENT_SAAS_IMAGE_DIGEST", "mutable:latest"),
            "public_bind": ("OMNIGENT_SAAS_METERING_BIND_HOST", "8.8.8.8"),
            "port": ("OMNIGENT_SAAS_METERING_PORT", "0"),
            "timeout": ("OMNIGENT_SAAS_METERING_REQUEST_TIMEOUT_SECONDS", "31"),
            "nan_timeout": ("OMNIGENT_SAAS_METERING_REQUEST_TIMEOUT_SECONDS", "nan"),
            "external_name": ("OMNIGENT_SAAS_METERING_EXPECTED_HOST", "public.example.com"),
            "trust_bundle": ("OMNIGENT_SAAS_METERING_TRUST_BUNDLE_VERSION", "bad/bundle"),
        }[change]
        source[name] = value
    with pytest.raises(production.ProductionMachineMeteringError) as refused:
        production.load_production_machine_metering_config(source)
    assert str(refused.value) == "machine_metering_configuration_invalid"
    assert refused.value.__cause__ is None


@pytest.mark.parametrize("profile", ["core", "model", "admin", "projection"])
@pytest.mark.parametrize("delivery", [False, True])
def test_new_declared_profile_uses_only_its_independent_source_catalog(
    environment, profile, delivery
):
    from saas.production import postgresql_migration as migration
    from tests.saas.test_production_postgresql_migration import (
        _platform_admin_bindings,
        _platform_bindings,
        _projection_bindings,
    )

    base = _plan()
    plan = replace(
        base,
        platform_model_service_role_bindings=_platform_bindings() if profile != "core" else None,
        platform_admin_service_role_bindings=(
            _platform_admin_bindings() if profile in {"admin", "projection"} else None
        ),
        model_projection_service_role_bindings=(
            _projection_bindings() if profile == "projection" else None
        ),
        business_delivery_service_role_bindings=(
            base.business_delivery_service_role_bindings if delivery else None
        ),
        machine_metering_service_role_bindings=load_machine_metering_service_role_bindings(
            environment
        ),
    )
    selected = migration._source_security_catalog_baselines(plan.service_role_graph)
    assert selected is migration._MACHINE_METERING_SOURCE_SECURITY_CATALOGS[(profile, delivery)]
    original = migration._source_security_catalog_baselines(
        replace(plan, machine_metering_service_role_bindings=None).service_role_graph
    )
    assert selected is not original
    official, saas = (
        ("nf12ab34cd56", "p0s000000018") if delivery else ("mm1a2b3c4d5e", "lm2t00000001")
    )
    assert set(selected) == {(major, official, saas) for major in (16, 18)}
    assert all(digest != original[key] for key, digest in selected.items())


def test_metering_missing_current_catalog_refuses_without_falling_back(environment, monkeypatch):
    from saas.production import postgresql_migration as migration

    plan = replace(
        _plan(),
        machine_metering_service_role_bindings=load_machine_metering_service_role_bindings(
            environment
        ),
    )
    monkeypatch.setitem(migration._MACHINE_METERING_SOURCE_SECURITY_CATALOGS, ("core", True), {})
    with pytest.raises(PostgreSqlMigrationError) as refused:
        migration._require_source_catalog_baselines(18, bindings=plan.service_role_graph)
    assert refused.value.code == "source_catalog_baseline_missing"


def test_migration_plan_retains_declared_metering_authority_in_its_full_graph(environment):
    binding = load_machine_metering_service_role_bindings(environment)
    plan = replace(_plan(), machine_metering_service_role_bindings=binding)
    assert plan.machine_metering_service_role_bindings == binding
    assert plan.service_role_graph.login_for("metering") == "metering_receiver_login"
    assert "metering" not in _plan().service_role_graph.by_service


def test_metering_rejects_installed_build_drift(environment, monkeypatch):
    from omnigent import _build_info

    config = production.load_production_machine_metering_config(environment)
    monkeypatch.setattr(_build_info, "COMMIT_SHA", "f" * 40)
    with pytest.raises(production.ProductionMachineMeteringError, match="installed_revision"):
        production.verify_installed_machine_metering_lineage(config)
    monkeypatch.setattr(_build_info, "COMMIT_SHA", config.product_revision)
    production.verify_installed_machine_metering_lineage(config)


def test_metering_catalog_refusal_precedes_tls_and_listener_construction(environment, monkeypatch):
    config = production.load_production_machine_metering_config(environment)
    calls = []

    def refuse(**_kwargs):
        calls.append("catalog")
        raise PostgreSqlMigrationError("fixture_refusal", "runtime_verification")

    monkeypatch.setattr(production, "verify_machine_metering_postgresql_state", refuse)
    monkeypatch.setattr(
        production, "build_server_tls_context", lambda _config: calls.append("tls")
    )
    engine = sa.create_engine("sqlite+pysqlite://")
    try:
        with pytest.raises(PostgreSqlMigrationError):
            production.build_production_machine_metering_server(config, engine)
    finally:
        engine.dispose()
    assert calls == ["catalog"]


def test_metering_composes_existing_authority_transport_and_durable_certificates(
    environment, monkeypatch
):
    config = production.load_production_machine_metering_config(environment)
    engine = sa.create_engine("sqlite+pysqlite://")
    observations = []
    # Unit composition only; this is not a successful PostgreSQL/catalog admission.
    monkeypatch.setattr(
        production,
        "verify_machine_metering_postgresql_state",
        lambda **kwargs: observations.append(kwargs),
    )
    try:
        server = production.build_production_machine_metering_server(config, engine)
        assert observations == [
            {"engine": engine, "database_url": config.database_url, "config": config}
        ]
        assert isinstance(server._authority, BillingMeteringAuthority)
        assert isinstance(server._certificate_authorizer, RunnerCertificateAuthority)
        assert server._tls_context.minimum_version == ssl.TLSVersion.TLSv1_3
        assert server._tls_context.maximum_version == ssl.TLSVersion.TLSv1_3
        assert server._tls_context.verify_mode == ssl.CERT_REQUIRED
    finally:
        engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("check_only", [True, False])
async def test_metering_check_and_serve_lifecycle_dispose_only_owned_engine(
    environment, monkeypatch, check_only
):
    config = production.load_production_machine_metering_config(environment)
    calls: list[object] = []

    class Engine:
        def dispose(self):
            calls.append("dispose")

    class Receiver:
        async def start(self, *, host, port):
            calls.append(("start", host, port))

        async def aclose(self):
            calls.append("close")

    def compose(*_args):
        calls.append("verify-and-compose")
        return Receiver()

    monkeypatch.setattr(production.sa, "create_engine", lambda *_args, **_kwargs: Engine())
    monkeypatch.setattr(production, "build_production_machine_metering_server", compose)
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "add_signal_handler", lambda _signal, callback: callback())
    await production._run(config, check_only=check_only)
    assert calls == (
        ["verify-and-compose", "dispose"]
        if check_only
        else [
            "verify-and-compose",
            ("start", config.bind_host, config.bind_port),
            "close",
            "dispose",
        ]
    )


def test_metering_main_does_not_emit_secret_bearing_startup_errors(monkeypatch, caplog):
    monkeypatch.setattr(
        production,
        "load_production_machine_metering_config",
        lambda _source: (_ for _ in ()).throw(ValueError("private-dsn-value")),
    )
    assert production.main(["--check"]) == 1
    assert "machine_metering_startup_rejected" in caplog.text
    assert "private-dsn-value" not in caplog.text


def test_metering_main_reports_unqualified_profile_as_unavailable(
    environment, monkeypatch, caplog
):
    config = production.load_production_machine_metering_config(environment)
    monkeypatch.setattr(
        production, "load_production_machine_metering_config", lambda _source: config
    )
    monkeypatch.setattr(
        production, "verify_installed_machine_metering_lineage", lambda _config: None
    )

    async def refuse(*_args, **_kwargs):
        raise PostgreSqlMigrationError(
            "machine_metering_source_catalog_baseline_missing", "preflight"
        )

    monkeypatch.setattr(production, "_run", refuse)
    assert production.main(["--check"]) == 1
    assert (
        "machine_metering_unavailable:machine_metering_source_catalog_baseline_missing"
        in caplog.text
    )
