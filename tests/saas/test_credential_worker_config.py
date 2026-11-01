from __future__ import annotations

import json
from pathlib import Path

import pytest

from saas.production.credential_worker_config import load_credential_worker_config
from saas.production.server_config import ProductionServerConfigError
from tests.saas.test_production_server_config import _environment


def minimal_environment(tmp_path):
    full = _environment(tmp_path)
    names = {
        "OMNIGENT_SAAS_PRODUCT_REVISION",
        "OMNIGENT_SAAS_SOURCE_SHA",
        "OMNIGENT_SAAS_UPSTREAM_REVISION",
        "OMNIGENT_SAAS_IMAGE_DIGEST",
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION",
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION",
        "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE",
        "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE",
        "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE",
    }
    source = {name: value for name, value in full.items() if name in names}
    public = tmp_path / "casdoor.json"
    public.write_text(
        json.dumps(
            {
                "issuer": "https://auth.example.test",
                "application": "customer-web",
                "organization": "customers",
                "client_id": "public-oidc-client",
                "token_endpoint_auth_method": "client_secret_basic",
            }
        )
    )
    source["OMNIGENT_SAAS_CASDOOR_CONFIG_FILE"] = str(public)
    return source


def test_narrow_config_loads_with_no_web_oidc_s3_or_other_database_secrets(tmp_path):
    config = load_credential_worker_config(minimal_environment(tmp_path))
    assert config.identity.organization == "customers"
    assert config.service_role_graph.login_for("authenticator") == "authenticator_login"
    assert "postgresql" not in repr(config)
    assert not hasattr(config, "secrets")


@pytest.mark.parametrize(
    "name",
    [
        "DATABASE_URL",
        "PGPASSWORD",
        "PGOPTIONS",
        "OMNIGENT_SAAS_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_CASDOOR_CLIENT_SECRET_FILE",
        "OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE",
    ],
)
def test_worker_refuses_unrelated_secret_mounts_before_reading_them(tmp_path, name):
    source = minimal_environment(tmp_path)
    source[name] = "/never-read/private-secret"
    with pytest.raises(ProductionServerConfigError, match="unrelated secret authority"):
        load_credential_worker_config(source)


def test_worker_rejects_receipt_source_or_login_drift(tmp_path):
    source = minimal_environment(tmp_path)
    source["OMNIGENT_SAAS_SOURCE_SHA"] = "9" * 40
    with pytest.raises(ProductionServerConfigError, match="source lineage"):
        load_credential_worker_config(source)
    source["OMNIGENT_SAAS_SOURCE_SHA"] = source["OMNIGENT_SAAS_PRODUCT_REVISION"]
    path = Path(source["OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE"])
    path.write_text(path.read_text().replace("authenticator_login", "foreign_authenticator_login"))
    with pytest.raises(ProductionServerConfigError, match="login does not match"):
        load_credential_worker_config(source)
