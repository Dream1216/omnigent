from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from saas.production.aliyun_server_profile import (
    PROFILE_FILE_ENV,
    PROFILE_HASH_ENV,
    load_aliyun_server_profile,
)
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_server_config,
)
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority
from tests.saas.test_production_server_config import _environment


@pytest.fixture
def profile_case(tmp_path):
    def secret(name, contents):
        path = tmp_path / name
        path.write_bytes(contents)
        path.chmod(0o600)
        return str(path)

    tenant = uuid4()
    document = {
        "schema_version": 1,
        "product_revision": "1" * 40,
        "server_image_digest": "sha256:" + "3" * 64,
        "region": "cn-hangzhou",
        "team_id": str(uuid4()),
        "generation": 2,
        "template_id": "t" * 20,
        "host_image": "ghcr.io/example/host@sha256:" + "4" * 64,
        "server_origin": "https://next.example.test",
        "model_gateway_url": "https://models.example.test/v1",
        "lifetime_seconds": 1800,
        "credential_file": secret("aliyun-key", b"e2b_" + b"a" * 32),
        "lease_key_file": secret("lease-key", b"l" * 32),
        "lease_key_sha256": hashlib.sha256(b"l" * 32).hexdigest(),
        "tenants": [
            {
                "tenant_id": str(tenant),
                "workspace_id": 91,
                "gateway_key_file": secret("model-key", b"m" * 32),
                "gateway_key_sha256": hashlib.sha256(b"m" * 32).hexdigest(),
            }
        ],
    }
    path = tmp_path / "aliyun-profile.json"
    source = {}

    def save():
        if path.exists():
            path.chmod(0o600)
        raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        path.write_bytes(raw)
        path.chmod(0o400)
        source.update(
            {PROFILE_FILE_ENV: str(path), PROFILE_HASH_ENV: hashlib.sha256(raw).hexdigest()}
        )
        return source

    def load():
        return load_aliyun_server_profile(
            source,
            product_revision="1" * 40,
            server_image_digest="sha256:" + "3" * 64,
            public_origin="https://next.example.test",
        )

    save()
    return SimpleNamespace(
        document=document,
        path=path,
        source=source,
        save=save,
        load=load,
        secret=secret,
        tenant=tenant,
    )


def _enable_storage(case):
    now = int(time.time())
    credential = {
        "schema_version": 1,
        "issued_at": now - 1,
        "expires_at": now + 1800,
        "access_key_id": "STS." + "a" * 24,
        "access_key_secret": "s" * 32,
        "security_token": "t" * 64,
    }
    case.document["schema_version"] = 2
    case.document["storage"] = {
        "credential_file": case.secret(
            "storage-sts.json",
            (json.dumps(credential, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        ),
        "tenants": [
            {
                "tenant_id": case.document["tenants"][0]["tenant_id"],
                "bucket": "omnigent-storage-test",
                "role_arn": "acs:ram::1000000000000000:role/omnigent-storage-test",
                "prefix": "omnigent/aliyun/v1",
            }
        ],
    }
    return case.document["storage"]


def _enable_artifacts(case):
    storage = _enable_storage(case)
    case.document["schema_version"] = 3
    now = int(time.time())
    storage["artifact_credential_file"] = case.secret(
        "artifact-reader.json",
        (
            json.dumps(
                {
                    "schema_version": 1,
                    "issued_at": now - 1,
                    "expires_at": now + 1800,
                    "access_key_id": "STS." + "r" * 24,
                    "access_key_secret": "s" * 32,
                    "security_token": "t" * 64,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode(),
    )
    return storage


def test_v3_explicitly_adds_independent_output_read_credentials(profile_case):
    c = profile_case
    storage = _enable_artifacts(c)
    c.save()
    profile = c.load()
    assert profile is not None
    assert str(profile.artifact_credential_file) == storage["artifact_credential_file"]
    assert profile.artifact_credential_file != profile.storage_credential_file
    profile.assert_ready()


@pytest.mark.parametrize("change", ["v2", "missing", "alias", "same_identity", "unknown"])
def test_output_read_authority_requires_explicit_v3_and_independent_sts(profile_case, change):
    c = profile_case
    storage = _enable_artifacts(c)
    if change == "v2":
        c.document["schema_version"] = 2
    elif change == "missing":
        del storage["artifact_credential_file"]
    elif change == "alias":
        storage["artifact_credential_file"] = storage["credential_file"]
    elif change == "same_identity":
        Path(storage["artifact_credential_file"]).write_bytes(
            Path(storage["credential_file"]).read_bytes()
        )
    else:
        storage["artifact_access_key"] = "must-not-be-inline"
    c.save()
    with pytest.raises(ValueError, match="profile configuration"):
        c.load()


def test_output_readiness_reloads_independent_expired_reader_file(profile_case):
    c = profile_case
    storage = _enable_artifacts(c)
    c.save()
    profile = c.load()
    assert profile is not None
    path = Path(storage["artifact_credential_file"])
    document = json.loads(path.read_text())
    document["expires_at"] = document["issued_at"] + 1
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(ValueError, match="expired"):
        profile.assert_ready()


def test_v2_profile_explicitly_enables_team_and_workspace_bound_storage(profile_case):
    c = profile_case
    storage = _enable_storage(c)
    c.save()
    profile = c.load()
    assert profile is not None and len(profile.storage_configs) == 1
    config = profile.storage_configs[0]
    assert str(config.team_id) == c.document["team_id"]
    assert str(config.tenant_id) == c.document["tenants"][0]["tenant_id"]
    assert config.workspace_id == c.document["tenants"][0]["workspace_id"]
    assert str(profile.storage_credential_file) == storage["credential_file"]
    profile.assert_ready()


@pytest.mark.parametrize(
    "change", ["v1", "missing", "credential_alias", "unknown_tenant", "bucket", "role", "prefix"]
)
def test_storage_profile_rejects_implicit_enablement_and_scope_drift(profile_case, change):
    c = profile_case
    storage = _enable_storage(c)
    if change == "v1":
        c.document["schema_version"] = 1
    elif change == "missing":
        del c.document["storage"]
    elif change == "credential_alias":
        storage["credential_file"] = c.document["lease_key_file"]
    else:
        key, value = {
            "unknown_tenant": ("tenant_id", str(uuid4())),
            "bucket": ("bucket", "bucket/*"),
            "role": ("role_arn", "acs:ram::*:role/admin"),
            "prefix": ("prefix", "a/../b"),
        }[change]
        storage["tenants"][0][key] = value
    c.save()
    with pytest.raises(ValueError, match="profile configuration"):
        c.load()


def test_storage_readiness_reloads_sts_credentials_after_startup(profile_case):
    c = profile_case
    storage = _enable_storage(c)
    c.save()
    profile = c.load()
    assert profile is not None
    path = Path(storage["credential_file"])
    data = json.loads(path.read_text())
    data["expires_at"] = data["issued_at"] + 1
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(ValueError, match="expired"):
        profile.assert_ready()


def test_absent_profile_keeps_provider_disabled_without_reading_credentials():
    assert (
        load_aliyun_server_profile(
            {},
            product_revision="1" * 40,
            server_image_digest="sha256:" + "3" * 64,
            public_origin="https://next.example.test",
        )
        is None
    )


def test_profile_load_is_offline_and_selects_the_explicit_model_authority(
    profile_case, monkeypatch
):
    def forbidden_network(*args, **kwargs):
        raise AssertionError("profile loading must not make a network request")

    monkeypatch.setattr("httpx.Client.send", forbidden_network)
    c = profile_case
    profile = c.load()
    assert profile is not None
    assert profile.source_sha256 == c.source[PROFILE_HASH_ENV]
    assert profile.managed.scopes[0].tenant_id == c.tenant
    assert profile.managed.scopes[0].workspace_id == 91
    assert profile.managed.server_url == c.document["server_origin"]
    assert profile.managed.model_gateway_url == c.document["model_gateway_url"]
    session = uuid4()
    token = profile.authorities[c.tenant].issue(session_id=session, ttl_seconds=300)
    verifier = PlatformModelGatewayTokenAuthority(signing_key=b"m" * 32, tenant_id=c.tenant)
    assert verifier.validate(token).session_id == session
    assert "e2b_" not in repr(profile) and "m" * 32 not in repr(profile)
    with pytest.raises(KeyError):
        profile.authorities[uuid4()]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("product_revision", "2" * 40),
        ("server_image_digest", "sha256:" + "5" * 64),
        ("region", "cn-shanghai"),
        ("generation", 1),
        ("generation", True),
        ("team_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
        ("template_id", "base"),
        ("host_image", "ghcr.io/example/host:latest"),
        ("host_image", "ghcr.io/example/../host@sha256:" + "4" * 64),
        ("host_image", "registry.example.test/host@sha256:" + "4" * 64),
        ("server_origin", "https://foreign.example.test"),
        ("model_gateway_url", "http://models.example.test/v1"),
        ("model_gateway_url", "https://user:password@models.example.test/v1"),
        ("lifetime_seconds", True),
        ("lifetime_seconds", 3601),
        ("tenants", []),
        ("inline_api_key", "must-not-be-accepted"),
    ],
)
def test_stale_unbound_or_unqualified_profile_is_rejected(profile_case, field, value):
    c = profile_case
    c.document[field] = value
    c.save()
    with pytest.raises(ValueError, match="configuration is invalid"):
        c.load()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "00000000-0000-0000-0000-000000000000"),
        ("workspace_id", True),
        ("workspace_id", 0),
        ("workspace_id", 2**63),
        ("gateway_key_file", "relative-key"),
        ("gateway_key_sha256", "0" * 64),
    ],
)
def test_invalid_tenant_scope_or_authority_is_rejected(profile_case, field, value):
    c = profile_case
    c.document["tenants"][0][field] = value
    c.save()
    with pytest.raises(ValueError, match="configuration is invalid"):
        c.load()


@pytest.mark.parametrize("reuse", ["tenant", "workspace", "key_material", "key_file"])
def test_two_tenants_cannot_share_scope_or_signing_authority(profile_case, reuse):
    c = profile_case
    row = deepcopy(c.document["tenants"][0])
    row.update(
        {
            "tenant_id": str(uuid4()),
            "workspace_id": 92,
            "gateway_key_file": c.secret("second-model-key", b"n" * 32),
            "gateway_key_sha256": hashlib.sha256(b"n" * 32).hexdigest(),
        }
    )
    if reuse == "tenant":
        row["tenant_id"] = str(c.tenant)
    elif reuse == "workspace":
        row["workspace_id"] = 91
    elif reuse == "key_material":
        row["gateway_key_file"] = c.secret("second-model-key", b"m" * 32)
        row["gateway_key_sha256"] = hashlib.sha256(b"m" * 32).hexdigest()
    else:
        row = {**c.document["tenants"][0], "tenant_id": str(uuid4()), "workspace_id": 92}
    c.document["tenants"].append(row)
    c.save()
    with pytest.raises(ValueError, match="configuration is invalid"):
        c.load()


@pytest.mark.parametrize("authority", ["lease", "management"])
def test_model_authority_cannot_reuse_lease_or_management_material(profile_case, authority):
    c = profile_case
    key = b"l" * 32 if authority == "lease" else b"e2b_" + b"a" * 32
    c.document["tenants"][0].update(
        {
            "gateway_key_file": c.secret("reused-key", key),
            "gateway_key_sha256": hashlib.sha256(key).hexdigest(),
        }
    )
    c.save()
    with pytest.raises(ValueError, match="configuration is invalid"):
        c.load()


def test_profile_digest_and_canonical_bytes_are_both_required(profile_case):
    c = profile_case
    c.path.chmod(0o600)
    c.path.write_text(json.dumps(c.document, indent=2))
    with pytest.raises(ValueError, match="digest"):
        c.load()
    c.source[PROFILE_HASH_ENV] = hashlib.sha256(c.path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="configuration is invalid"):
        c.load()


def test_profile_readiness_detects_key_replacement_and_shared_permissions(profile_case):
    c = profile_case
    profile = c.load()
    assert profile is not None
    c.secret("model-key", b"z" * 32)
    with pytest.raises(ValueError, match="does not match"):
        profile.assert_ready()
    c.secret("model-key", b"m" * 32)
    Path(c.document["credential_file"]).chmod(0o640)
    with pytest.raises(ValueError, match="authority file"):
        profile.assert_ready()


def test_management_key_rotation_cannot_alias_a_model_signing_key(profile_case):
    c = profile_case
    key = b"e2b_" + b"b" * 32
    c.document["tenants"][0].update(
        {
            "gateway_key_file": c.secret("model-key", key),
            "gateway_key_sha256": hashlib.sha256(key).hexdigest(),
        }
    )
    c.save()
    profile = c.load()
    assert profile is not None
    c.secret("aliyun-key", key)
    with pytest.raises(ValueError, match="must be independent"):
        profile.assert_ready()


@pytest.mark.parametrize(
    "bad_env",
    [
        {PROFILE_FILE_ENV: "/missing"},
        {PROFILE_HASH_ENV: "a" * 64},
        {"OMNIGENT_SAAS_ALIYUN_ENABLED": "true"},
    ],
)
def test_partial_or_unknown_activation_fails_closed(bad_env):
    with pytest.raises(ValueError):
        load_aliyun_server_profile(
            bad_env,
            product_revision="1" * 40,
            server_image_digest="sha256:" + "3" * 64,
            public_origin="https://next.example.test",
        )


def test_real_server_config_loads_profile_and_exposes_only_its_digest(profile_case, tmp_path):
    c = profile_case
    config = load_production_server_config({**_environment(tmp_path), **c.source})
    assert config.aliyun_profile is not None
    version = dict(config.version_document)
    assert version["aliyun_sandbox_profile_sha256"] == c.source[PROFILE_HASH_ENV]
    assert "e2b_" not in json.dumps(version) and "gateway_key_file" not in json.dumps(version)
    assert "aliyun_profile" not in repr(config)


def test_real_server_config_rejects_a_profile_from_another_release(profile_case, tmp_path):
    c = profile_case
    c.document["product_revision"] = "2" * 40
    c.save()
    with pytest.raises(ProductionServerConfigError, match="Aliyun sandbox profile"):
        load_production_server_config({**_environment(tmp_path), **c.source})
