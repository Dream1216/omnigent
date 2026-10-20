from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from saas.production.tenant_model_keys import (
    TenantModelKeyBinding,
    TenantModelTokenVerifier,
    load_tenant_model_bindings,
)
from saas.runner_adapter.platform_model_gateway import (
    PlatformModelGatewayTokenAuthority,
    PlatformModelGatewayTokenError,
    PlatformModelGatewayTokenExpired,
)

LEGACY = UUID(int=17)
TENANT = UUID(int=91)
LEGACY_KEY = b"a" * 32
TENANT_KEY = b"b" * 32


def _binding(tmp_path: Path) -> TenantModelKeyBinding:
    path = tmp_path / "tenant-key"
    path.write_bytes(TENANT_KEY)
    path.chmod(0o400)
    return TenantModelKeyBinding(TENANT, 91, f"omnigent-sandbox-model-{TENANT.hex}", path)


def _document(binding: TenantModelKeyBinding) -> dict:
    return {
        "schema_version": 1,
        "bindings": [
            {
                "tenant_id": str(binding.tenant_id),
                "workspace_id": binding.workspace_id,
                "sandbox_secret_name": binding.sandbox_secret_name,
                "gateway_key_file": str(binding.gateway_key_file),
            }
        ],
    }


def _source(tmp_path: Path, document: dict) -> dict[str, str]:
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path = tmp_path / "bindings.json"
    path.write_bytes(raw)
    path.chmod(0o400)
    return {
        "OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_FILE": str(path),
        "OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_SHA256": hashlib.sha256(raw).hexdigest(),
    }


def _verifier(binding: TenantModelKeyBinding) -> TenantModelTokenVerifier:
    legacy = PlatformModelGatewayTokenAuthority(signing_key=LEGACY_KEY, tenant_id=LEGACY)
    return TenantModelTokenVerifier(legacy, LEGACY_KEY, (binding,))


def test_hash_pinned_allowlist_loads_metadata_without_reading_private_key(tmp_path):
    binding = _binding(tmp_path)
    source = _source(tmp_path, _document(binding))
    binding.gateway_key_file.unlink()
    assert load_tenant_model_bindings(source) == (binding,)


def test_optional_configuration_preserves_legacy_profile():
    assert load_tenant_model_bindings({}) == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("workspace_id", True),
        ("workspace_id", 0),
        ("workspace_id", -1),
        ("workspace_id", 1.5),
        ("tenant_id", str(UUID(int=0))),
        ("sandbox_secret_name", "foreign-secret"),
        ("gateway_key_file", "relative/key"),
        ("gateway_key_file", "/runtime/../other/key"),
        ("extra", "not-allowed"),
    ],
)
def test_malformed_binding_is_rejected(tmp_path, field, value):
    document = _document(_binding(tmp_path))
    document["bindings"][0][field] = value
    with pytest.raises(ValueError, match="Tenant model bindings are invalid"):
        load_tenant_model_bindings(_source(tmp_path, document))


@pytest.mark.parametrize("kind", ["duplicate", "boolean-schema", "empty", "extra", "too-many"])
def test_unreviewed_registry_is_rejected(tmp_path, kind):
    document = _document(_binding(tmp_path))
    if kind == "duplicate":
        document["bindings"] *= 2
    elif kind == "boolean-schema":
        document["schema_version"] = True
    elif kind == "empty":
        document["bindings"] = []
    elif kind == "extra":
        document["extra"] = "not-allowed"
    else:
        document["bindings"] *= 33
    with pytest.raises(ValueError):
        load_tenant_model_bindings(_source(tmp_path, document))


@pytest.mark.parametrize(
    "kind", ["symlink", "hardlink", "writable", "wrong-hash", "noncanonical", "oversized"]
)
def test_unsafe_registry_file_is_rejected(tmp_path, kind):
    source = _source(tmp_path, _document(_binding(tmp_path)))
    path = Path(source["OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_FILE"])
    if kind == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        source["OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_FILE"] = str(link)
    elif kind == "hardlink":
        os.link(path, tmp_path / "other.json")
    elif kind == "writable":
        path.chmod(0o666)
    elif kind == "wrong-hash":
        source["OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_SHA256"] = "0" * 64
    else:
        path.chmod(0o600)
        path.write_bytes(b" " * 32769 if kind == "oversized" else path.read_bytes() + b" ")
        source["OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_SHA256"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    with pytest.raises(ValueError):
        load_tenant_model_bindings(source)


def test_independent_tenant_and_legacy_tokens_validate_without_cross_acceptance(tmp_path):
    verifier = _verifier(_binding(tmp_path))
    session = uuid4()
    for tenant, key in [(TENANT, TENANT_KEY), (LEGACY, LEGACY_KEY)]:
        token = PlatformModelGatewayTokenAuthority(signing_key=key, tenant_id=tenant).issue(
            session_id=session,
            ttl_seconds=60,
            now=100,
        )
        claims = verifier.validate(token, now=120)
        assert claims.tenant_id == tenant and claims.session_id == session
        with pytest.raises(PlatformModelGatewayTokenExpired):
            verifier.validate(token, now=161)


@pytest.mark.parametrize(
    "tenant,key", [(TENANT, LEGACY_KEY), (LEGACY, TENANT_KEY), (UUID(int=92), TENANT_KEY)]
)
def test_foreign_key_or_unlisted_tenant_cannot_authenticate(tmp_path, tenant, key):
    verifier = _verifier(_binding(tmp_path))
    token = PlatformModelGatewayTokenAuthority(signing_key=key, tenant_id=tenant).issue(
        session_id=uuid4(),
        now=100,
    )
    with pytest.raises(PlatformModelGatewayTokenError):
        verifier.validate(token, now=101)


@pytest.mark.parametrize("kind", ["shared-key", "short", "world-readable", "symlink", "missing"])
def test_unsafe_signing_authority_fails_gateway_startup(tmp_path, kind):
    binding = _binding(tmp_path)
    path = binding.gateway_key_file
    if kind in {"shared-key", "short"}:
        path.chmod(0o600)
        path.write_bytes(LEGACY_KEY if kind == "shared-key" else b"short")
    elif kind == "world-readable":
        path.chmod(0o644)
    elif kind == "symlink":
        path.unlink()
        target = tmp_path / "real-key"
        target.write_bytes(TENANT_KEY)
        target.chmod(0o400)
        path.symlink_to(target)
    else:
        path.unlink()
    with pytest.raises(ValueError):
        _verifier(binding)


@pytest.mark.parametrize(
    "token", ["", "not-json.signature", "x" * 8193, "W10.signature", "bnVsbA.signature"]
)
def test_malformed_tokens_are_rejected_without_echoing_input(tmp_path, token):
    verifier = _verifier(_binding(tmp_path))
    with pytest.raises(PlatformModelGatewayTokenError) as error:
        verifier.validate(token)
    assert str(error.value) == "invalid tenant authority"
