from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
import yaml
from sqlalchemy.engine import Engine

import saas.production.onboarding as production_onboarding
from saas.control_plane.db_models import SaasBase
from saas.control_plane.runtime_provider import ProductionRuntimePartitionAdapter
from saas.production.onboarding import (
    ProductionOnboardingConfigError,
    build_production_onboarding_http_services,
    build_production_onboarding_outbox_composition,
    build_production_onboarding_outbox_publisher,
    load_production_onboarding_http_config,
    load_production_onboarding_worker_config,
)


def _write(path: Path, value: str | bytes) -> Path:
    path.write_bytes(value.encode("ascii") if isinstance(value, str) else value)
    path.chmod(0o400)
    return path


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def _key(value: int) -> str:
    return base64.b64encode(bytes([value]) * 32).decode("ascii")


def _environment(tmp_path: Path) -> dict[str, str]:
    manifest = {
        "schema_version": 1,
        "bindings": [
            {
                "service": "executor",
                "login": "login_executor",
                "base_role": "saas_executor",
            },
            {
                "service": "onboarding",
                "login": "login_onboarding",
                "base_role": "saas_onboarding",
            },
            {
                "service": "onboarding_status",
                "login": "login_onboarding_status",
                "base_role": "saas_onboarding_status",
            },
            {
                "service": "registration",
                "login": "login_registration",
                "base_role": "saas_registration",
            },
        ],
    }
    policy = {
        "schema_version": 1,
        "plans": [
            {
                "key": "starter",
                "policy_revision": "starter-2026-09-02",
                "trial_days": 14,
                "currency": "USD",
                "trial_run_limit": 100,
                "trial_concurrency_limit": 2,
                "runtime_type": "omnigent",
                "capacity_class": "starter",
                "default_project_name": "Getting Started",
                "default_project_visibility": "private",
                "quota_resource": "interactive_runs",
                "quota_limit": 100,
            }
        ],
        "home_regions": ["cn-east-1"],
        "reserved_slugs": ["admin"],
        "verification_ttl_seconds": 1800,
    }
    envelope = {
        "schema_version": 1,
        "active_key_id": "envelope-v1",
        "keys": {"envelope-v1": _key(1)},
    }
    rate_limit = {
        "schema_version": 1,
        "active_key_id": "rate-v1",
        "previous_key_id": None,
        "anchor_key_id": "rate-v1",
        "write_key_id": "rate-v1",
        "previous_writers_drained": False,
        "keys": {"rate-v1": _key(2)},
    }
    source = {
        "OMNIGENT_SAAS_PUBLIC_ORIGIN": "https://next.jxhh.com",
        "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": str(
            _write(tmp_path / "bindings.json", _canonical(manifest))
        ),
        "OMNIGENT_SAAS_ONBOARDING_POLICY_FILE": str(
            _write(tmp_path / "policy.json", _canonical(policy))
        ),
        "OMNIGENT_SAAS_VERIFICATION_ENVELOPE_KEYS_FILE": str(
            _write(tmp_path / "envelope.json", _canonical(envelope))
        ),
        "OMNIGENT_SAAS_REGISTRATION_RATE_LIMIT_KEYS_FILE": str(
            _write(tmp_path / "rate-limit.json", _canonical(rate_limit))
        ),
        "OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS": "10.42.0.0/16,fd00:42::/48",
        "OMNIGENT_SAAS_EMAIL_FROM": "verify@jxhh.com",
        "OMNIGENT_SAAS_EMAIL_PROVIDER_TOKEN_FILE": str(
            _write(tmp_path / "email-token", "resend-token-value\n")
        ),
        "OMNIGENT_SAAS_RUNTIME_PROVIDER_FACTORY": "deployment.runtime:build_runtime",
    }
    for service in ("registration", "onboarding", "onboarding_status", "executor"):
        login = f"login_{service}"
        dsn = (
            f"postgresql+psycopg://{login}:password@postgres.example.test/omnigent"
            "?sslmode=verify-full&sslrootcert=%2Fruntime%2Fpostgresql-ca.crt"
        )
        source[f"OMNIGENT_SAAS_{service.upper()}_DATABASE_URL_FILE"] = str(
            _write(tmp_path / f"{service}-dsn", dsn + "\n")
        )
    return source


def test_http_config_loads_exact_roles_policy_and_secret_files(tmp_path: Path) -> None:
    source = _environment(tmp_path)

    config = load_production_onboarding_http_config(source)

    assert config.common.public_origin == "https://next.jxhh.com"
    assert config.common.policy.require_plan("starter").trial_days == 14
    assert config.common.bindings.login_for("registration") == "login_registration"
    assert config.common.bindings.login_for("onboarding_status") == "login_onboarding_status"
    assert config.trusted_client_network.trusted_proxy_cidrs == (
        "10.42.0.0/16",
        "fd00:42::/48",
    )
    rendered = repr(config)
    assert "password" not in rendered
    assert _key(1) not in rendered
    assert _key(2) not in rendered


def test_worker_config_is_distinct_from_dispatcher_and_status(tmp_path: Path) -> None:
    source = _environment(tmp_path)

    config = load_production_onboarding_worker_config(source)

    assert "login_registration" in config.registration_database_url
    assert "login_onboarding" in config.onboarding_database_url
    assert "login_executor" in config.execution_database_url
    assert not hasattr(config, "dispatcher_database_url")
    assert not hasattr(config, "status_database_url")
    assert config.runtime_provider_factory == "deployment.runtime:build_runtime"
    assert "resend-token-value" not in repr(config)


def test_manifest_rejects_old_profile_without_three_onboarding_roles(tmp_path: Path) -> None:
    source = _environment(tmp_path)
    path = Path(source["OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE"])
    document = json.loads(path.read_text())
    document["bindings"] = [
        row for row in document["bindings"] if row["service"] != "onboarding_status"
    ]
    path.chmod(0o600)
    _write(path, _canonical(document))

    with pytest.raises(ProductionOnboardingConfigError, match="onboarding_status"):
        load_production_onboarding_http_config(source)


def test_database_url_must_match_manifest_login_and_tls_contract(tmp_path: Path) -> None:
    source = _environment(tmp_path)
    path = Path(source["OMNIGENT_SAAS_REGISTRATION_DATABASE_URL_FILE"])
    path.chmod(0o600)
    _write(
        path,
        "postgresql+psycopg://wrong_login:password@postgres.example.test/omnigent"
        "?sslmode=require\n",
    )

    with pytest.raises(ProductionOnboardingConfigError, match="exact postgresql"):
        load_production_onboarding_http_config(source)


def test_direct_secret_environment_is_rejected_without_value_disclosure(
    tmp_path: Path,
) -> None:
    source = _environment(tmp_path)
    source["OMNIGENT_SAAS_EMAIL_PROVIDER_TOKEN"] = "must-not-appear"

    with pytest.raises(ProductionOnboardingConfigError) as raised:
        load_production_onboarding_http_config(source)

    assert "must-not-appear" not in str(raised.value)


@pytest.mark.parametrize(
    "origin",
    (
        "http://next.jxhh.com",
        "https://127.0.0.1",
        "https://localhost",
        "https://next.jxhh.com/path",
    ),
)
def test_http_config_rejects_non_public_https_origin(tmp_path: Path, origin: str) -> None:
    source = _environment(tmp_path)
    source["OMNIGENT_SAAS_PUBLIC_ORIGIN"] = origin

    with pytest.raises(ProductionOnboardingConfigError, match="PUBLIC_ORIGIN is invalid"):
        load_production_onboarding_http_config(source)


def test_config_files_require_exact_owner_only_read_only_mode(tmp_path: Path) -> None:
    source = _environment(tmp_path)
    Path(source["OMNIGENT_SAAS_ONBOARDING_POLICY_FILE"]).chmod(0o600)

    with pytest.raises(ProductionOnboardingConfigError, match="owner-readable"):
        load_production_onboarding_http_config(source)


def _sqlite_engine_factory(_database_url: str) -> Engine:
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    SaasBase.metadata.create_all(engine)
    return engine


def test_http_builder_returns_exact_all_or_none_integration_keywords(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _environment(tmp_path)
    observed: list[str] = []
    monkeypatch.setattr(
        production_onboarding,
        "verify_onboarding_database_authority",
        lambda _engine, *, authority: observed.append(authority),
    )

    services = build_production_onboarding_http_services(
        source,
        engine_factory=_sqlite_engine_factory,
    )
    try:
        assert set(services.integration_kwargs) == {
            "onboarding",
            "onboarding_status",
            "onboarding_client_network",
        }
        assert observed == ["registration"]
    finally:
        services.close()


class _Runtime:
    def assert_production_ready(self) -> None:
        return None

    def binding_snapshot(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def allocate_partition(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def provision_default_project(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def compensate_default_project(self, *_args: object, **_kwargs: object) -> None:
        return None

    def compensate_partition(self, *_args: object, **_kwargs: object) -> None:
        return None


def test_worker_builder_returns_validated_zero_dispatcher_publisher(tmp_path: Path) -> None:
    source = _environment(tmp_path)
    runtime = cast(ProductionRuntimePartitionAdapter, _Runtime())

    publisher = build_production_onboarding_outbox_composition(
        source,
        engine_factory=_sqlite_engine_factory,
        runtime_loader=lambda reference: (
            runtime
            if reference == "deployment.runtime:build_runtime"
            else pytest.fail("wrong factory reference")
        ),
    )
    try:
        publisher.validate_outbox_configuration()
        assert not hasattr(publisher, "dispatcher")
        assert len(publisher._engines) == 3
    finally:
        publisher.close()


def test_exported_outbox_factory_is_zero_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = cast(Any, object())
    monkeypatch.setattr(
        production_onboarding,
        "build_production_onboarding_outbox_composition",
        lambda: sentinel,
    )

    assert build_production_onboarding_outbox_publisher() is sentinel


def test_runtime_factory_must_be_public_zero_argument(tmp_path: Path) -> None:
    source = _environment(tmp_path)
    source["OMNIGENT_SAAS_RUNTIME_PROVIDER_FACTORY"] = "deployment.runtime:_private"

    with pytest.raises(ProductionOnboardingConfigError, match="PROVIDER_FACTORY is invalid"):
        load_production_onboarding_worker_config(source)


def test_policy_document_must_be_canonical_and_fully_explicit(tmp_path: Path) -> None:
    source = _environment(tmp_path)
    policy_path = Path(source["OMNIGENT_SAAS_ONBOARDING_POLICY_FILE"])
    policy_path.chmod(0o600)
    document = json.loads(policy_path.read_text())
    policy_path.write_text(json.dumps(document, indent=2))
    policy_path.chmod(0o400)

    with pytest.raises(ProductionOnboardingConfigError, match="canonical JSON"):
        load_production_onboarding_http_config(source)


def test_secret_file_path_cannot_be_relative(tmp_path: Path) -> None:
    source = _environment(tmp_path)
    source["OMNIGENT_SAAS_VERIFICATION_ENVELOPE_KEYS_FILE"] = "envelope.json"

    with pytest.raises(ProductionOnboardingConfigError, match="absolute path"):
        load_production_onboarding_http_config(source)


def test_binding_manifest_digest_covers_all_services(tmp_path: Path) -> None:
    source = _environment(tmp_path)
    config = load_production_onboarding_http_config(source)
    raw = Path(source["OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE"]).read_bytes()

    assert config.common.bindings.sha256 == hashlib.sha256(raw).hexdigest()


def test_worker_manifest_keeps_provider_and_domain_authorities_out_of_server() -> None:
    root = Path(__file__).parents[2]
    worker = yaml.safe_load(
        (root / "saas/deployment/onboarding/kubernetes.worker.yaml").read_text()
    )
    items = worker["items"]
    deployment = next(item for item in items if item.get("kind") == "Deployment")
    network = next(item for item in items if item.get("kind") == "NetworkPolicy")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    names = {entry["name"] for entry in container["env"]}

    assert "OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL_FILE" in names
    assert "OMNIGENT_SAAS_REGISTRATION_DATABASE_URL_FILE" in names
    assert "OMNIGENT_SAAS_ONBOARDING_DATABASE_URL_FILE" in names
    assert "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE" in names
    assert "OMNIGENT_SAAS_ONBOARDING_STATUS_DATABASE_URL_FILE" not in names
    assert "OMNIGENT_SAAS_EMAIL_PROVIDER_TOKEN_FILE" in names
    assert network["spec"]["ingress"] == []
    rendered_network = json.dumps(network["spec"]["egress"], sort_keys=True)
    assert "0.0.0.0/0" not in rendered_network
    assert "443" not in rendered_network


def test_server_patch_has_only_http_onboarding_authorities() -> None:
    root = Path(__file__).parents[2]
    patch = yaml.safe_load(
        (root / "saas/deployment/onboarding/kubernetes.server-onboarding.patch.yaml").read_text()
    )
    container = patch["spec"]["template"]["spec"]["containers"][0]
    names = {entry["name"] for entry in container["env"]}

    assert "OMNIGENT_SAAS_REGISTRATION_DATABASE_URL_FILE" in names
    assert "OMNIGENT_SAAS_ONBOARDING_STATUS_DATABASE_URL_FILE" in names
    assert "OMNIGENT_SAAS_ONBOARDING_DATABASE_URL_FILE" not in names
    assert "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE" not in names
    assert "OMNIGENT_SAAS_EMAIL_PROVIDER_TOKEN_FILE" not in names


def test_deployment_example_freezes_exact_thirteen_service_profile() -> None:
    root = Path(__file__).parents[2]
    document = json.loads(
        (root / "saas/deployment/onboarding/service-role-bindings.example.json").read_text()
    )
    rows = document["bindings"]

    assert len(rows) == 13
    assert {row["service"] for row in rows} == {
        "app",
        "authenticator",
        "dispatcher",
        "executor",
        "governance",
        "onboarding",
        "onboarding_status",
        "preview_edge",
        "preview_owner",
        "public_api",
        "registration",
        "runtime",
        "secret_broker",
    }
    assert all(row["service"] != "preview_gateway" for row in rows)
    rendered = (root / "saas/deployment/onboarding/service-role-bindings.example.json").read_text()
    assert rendered == _canonical(document)
