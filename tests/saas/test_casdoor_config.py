from __future__ import annotations

import json
from pathlib import Path

import pytest

from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_identity_config,
)


def _configuration(tmp_path: Path) -> tuple[dict[str, str], dict[str, str]]:
    payload = {
        "issuer": "https://auth.example.test",
        "application": "stbz-next-web",
        "organization": "stbz-users",
        "client_id": "public-client-id",
        "token_endpoint_auth_method": "client_secret_basic",
    }
    files = {
        "OMNIGENT_SAAS_CASDOOR_CONFIG_FILE": json.dumps(payload).encode(),
        "OMNIGENT_SAAS_CASDOOR_CLIENT_SECRET_FILE": b"not-a-production-client-secret\n",
        "OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE": b"a" * 31 + b"\n",
    }
    environ = {"OMNIGENT_SAAS_AUTH_MODE": "dual"}
    for name, content in files.items():
        path = tmp_path / name.lower()
        path.write_bytes(content)
        path.chmod(0o600)
        environ[name] = str(path)
    return environ, payload


def test_legacy_has_no_network_or_secret_dependency() -> None:
    result = load_production_identity_config({}, public_origin="https://next.example.test")
    assert result.mode == "legacy"
    assert result.provider is None
    assert result.transaction_key is None


@pytest.mark.parametrize("mode", ["legacy", "dual", "casdoor"])
def test_pinned_application_and_binary_key_preserve_security_boundaries(
    tmp_path: Path, mode: str
) -> None:
    environ, _ = _configuration(tmp_path)
    environ["OMNIGENT_SAAS_AUTH_MODE"] = mode
    result = load_production_identity_config(environ, public_origin="https://next.example.test")
    assert result.mode == mode
    assert result.transaction_key == b"a" * 31 + b"\n"
    assert result.provider is not None
    assert result.provider.jwks_uri == "https://auth.example.test/.well-known/stbz-next-web/jwks"
    assert (
        result.provider.redirect_uri == "https://next.example.test/saas/auth/oidc/casdoor/callback"
    )
    assert result.provider.allowed_identity_owners == ("stbz-users",)
    assert result.provider.allowed_algorithms == ("RS256",)
    assert result.provider.ui_locale_parameter == "language"
    assert result.provider.signup_endpoint == "https://auth.example.test/signup/oauth/authorize"
    assert "not-a-production-client-secret" not in repr(result)
    assert "not-a-production-client-secret" not in repr(result.provider)
    assert "aaaaaaaa" not in repr(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", "http://auth.example.test"),
        ("issuer", "https://auth.example.test/"),
        ("issuer", "https://auth.example.test?issuer=other"),
        ("organization", "built-in"),
        ("application", "app-built-in"),
        ("application", "../other-app"),
        ("organization", ""),
        ("token_endpoint_auth_method", "none"),
        ("client_secret", "secret-in-config"),
    ],
)
def test_invalid_customer_configuration_is_rejected(
    tmp_path: Path, field: str, value: str
) -> None:
    environ, payload = _configuration(tmp_path)
    payload[field] = value
    Path(environ["OMNIGENT_SAAS_CASDOOR_CONFIG_FILE"]).write_text(json.dumps(payload))
    with pytest.raises(ProductionServerConfigError):
        load_production_identity_config(environ, public_origin="https://next.example.test")


@pytest.mark.parametrize(
    "name",
    [
        "OMNIGENT_SAAS_CASDOOR_CONFIG_FILE",
        "OMNIGENT_SAAS_CASDOOR_CLIENT_SECRET_FILE",
        "OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE",
    ],
)
def test_partial_configuration_never_silently_disables_oidc(tmp_path: Path, name: str) -> None:
    environ, _ = _configuration(tmp_path)
    del environ[name]
    with pytest.raises(ProductionServerConfigError):
        load_production_identity_config(environ, public_origin="https://next.example.test")


def test_world_readable_transaction_key_is_rejected(tmp_path: Path) -> None:
    environ, _ = _configuration(tmp_path)
    Path(environ["OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE"]).chmod(0o644)
    with pytest.raises(ProductionServerConfigError):
        load_production_identity_config(environ, public_origin="https://next.example.test")
