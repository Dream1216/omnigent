from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_server_config,
)
from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    load_production_service_role_bindings,
    render_production_service_role_bindings,
)


def _secret(path: Path, value: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return str(path)


def _bindings(path: Path) -> str:
    bindings = tuple(
        ProductionServiceRoleBinding(
            service=service,
            login=f"{service}_login",
            base_role=base_role,
        )
        for service, base_role in sorted(EXPECTED_PRODUCTION_SERVICE_ROLES.items())
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_production_service_role_bindings(bindings), encoding="ascii")
    path.chmod(0o400)
    return str(path)


def _receipt(path: Path, *, service_role_bindings_sha256: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "pass",
                "verify_only": False,
                "product_revision": "1" * 40,
                "database_identity_sha256": "4" * 64,
                "official_head": "e5d9bc8ac650",
                "saas_head": "p0s000000007",
                "runtime_rls_table_count": 15,
                "authorities": [
                    {"kind": "principal_operator", "login": "principal_operator_login"},
                    {"kind": "database_owner", "login": "database_owner_login"},
                    {"kind": "official_owner", "login": "official_owner_login"},
                    {"kind": "saas_owner", "login": "saas_owner_login"},
                ],
                "phases": ["state:verified"],
                "catalog_sha256": "5" * 64,
                "service_role_bindings_sha256": service_role_bindings_sha256,
                "completed_at": "2026-09-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o400)
    return str(path)


def _artifact_receipt(path: Path, *, credential_revision: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "pass",
                "product_revision": "1" * 40,
                "source_revision": "1" * 40,
                "image_digest": "sha256:" + "3" * 64,
                "release_incarnation": "4" * 32,
                "artifact_store_uri_sha256": hashlib.sha256(
                    b"s3://omnigent-production/artifacts"
                ).hexdigest(),
                "artifact_endpoint_url_sha256": hashlib.sha256(
                    b"https://objects.example.test"
                ).hexdigest(),
                "artifact_region": "production-1",
                "credential_revision": credential_revision,
                "verified_key_spaces": [
                    "admission",
                    "file_id",
                    "agent_bundle",
                    "executor_storage",
                ],
                "object_key_sha256s": {
                    "admission": "1" * 64,
                    "file_id": "2" * 64,
                    "agent_bundle": "3" * 64,
                    "executor_storage": "4" * 64,
                },
                "operations": ["put", "head", "get_hash", "delete"],
                "completed_at": "2026-09-01T00:00:00+00:00",
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    path.chmod(0o400)
    return str(path)


def _environment(tmp_path: Path) -> dict[str, str]:
    bindings_path = _bindings(tmp_path / "service-role-bindings.json")
    bindings = load_production_service_role_bindings(
        {"OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": bindings_path}
    )
    artifact_credentials_file = _secret(
        tmp_path / "artifact-credentials",
        "[omnigent-saas-artifacts]\n"
        "aws_access_key_id = access-key-id-123456\n"
        "aws_secret_access_key = secret-access-key-1234567890\n",
    )
    artifact_credentials_sha256 = hashlib.sha256(
        Path(artifact_credentials_file).read_bytes()
    ).hexdigest()
    environment = {
        "OMNIGENT_SAAS_PRODUCT_REVISION": "1" * 40,
        "OMNIGENT_SAAS_SOURCE_SHA": "1" * 40,
        "OMNIGENT_SAAS_UPSTREAM_REVISION": "2" * 40,
        "OMNIGENT_SAAS_IMAGE_DIGEST": "sha256:" + "3" * 64,
        "OMNIGENT_SAAS_RELEASE_INCARNATION": "4" * 32,
        "OMNIGENT_SAAS_RUNTIME_VERSION": "0.9.0",
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": "e5d9bc8ac650",
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": "p0s000000007",
        "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION": "0.2.0",
        "OMNIGENT_SAAS_PUBLIC_ORIGIN": "https://next.example.test",
        "OMNIGENT_SAAS_CAPABILITIES": "tenant,run",
        "OMNIGENT_SAAS_ARTIFACT_STORE_URI": "s3://omnigent-production/artifacts",
        "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL": "https://objects.example.test",
        "OMNIGENT_SAAS_ARTIFACT_REGION": "production-1",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE": "omnigent-saas-artifacts",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION": (f"sha256:{artifact_credentials_sha256}"),
        "OMNIGENT_SAAS_ARTIFACT_READINESS_KEY": "readiness/omnigent-saas-canary-v1",
        "OMNIGENT_SAAS_ARTIFACT_READINESS_SHA256": "e" * 64,
        "OMNIGENT_SAAS_ARTIFACT_CACHE_DIR": str(tmp_path / "artifact-cache"),
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE": artifact_credentials_file,
        "AWS_EC2_METADATA_DISABLED": "true",
        "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": bindings_path,
        "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE": _receipt(
            tmp_path / "migration-receipt.json",
            service_role_bindings_sha256=bindings.sha256,
        ),
        "OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE": _artifact_receipt(
            tmp_path / "artifact-admission-receipt.json",
            credential_revision=f"sha256:{artifact_credentials_sha256}",
        ),
        "OMNIGENT_SAAS_API_CREDENTIAL_PEPPER_FILE": _secret(tmp_path / "api-pepper", "a" * 32),
        "OMNIGENT_SAAS_CURSOR_HMAC_KEY_FILE": _secret(tmp_path / "cursor-key", "b" * 32),
        "OMNIGENT_SAAS_IDEMPOTENCY_HMAC_KEY_FILE": _secret(tmp_path / "idempotency-key", "c" * 32),
        "OMNIGENT_SAAS_CONTEXT_SNAPSHOT_KEY_FILE": _secret(tmp_path / "snapshot-key", "d" * 32),
        "OMNIGENT_SAAS_PREVIEW_EXCHANGE_HMAC_KEY_FILE": _secret(
            tmp_path / "preview-exchange-key", "e" * 32
        ),
    }
    artifact_receipt_path = Path(environment["OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE"])
    environment["OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION"] = (
        "sha256:" + hashlib.sha256(artifact_receipt_path.read_bytes()).hexdigest()
    )
    for index, role in enumerate(
        ("runtime", "authenticator", "app", "governance", "public_api"), start=1
    ):
        environment[f"OMNIGENT_SAAS_{role.upper()}_DATABASE_URL_FILE"] = _secret(
            tmp_path / f"{role}-database-url",
            (
                f"postgresql+psycopg://{role}_login:password-{index}"
                "@postgres.internal:5432/omnigent?sslmode=verify-full"
                "&sslrootcert=/runtime/postgresql-ca.crt"
            ),
        )
    return environment


def test_loads_exact_release_and_owner_only_secret_files(tmp_path: Path) -> None:
    config = load_production_server_config(_environment(tmp_path))

    assert config.product_revision == "1" * 40
    assert config.upstream_revision == "2" * 40
    assert config.public_origin == "https://next.example.test"
    assert config.release_incarnation == "4" * 32
    assert config.capabilities == frozenset({"tenant", "run"})
    assert config.secrets.database_urls.runtime.startswith("postgresql+psycopg://")
    rendered = repr(config)
    assert "password-1" not in rendered
    assert "a" * 32 not in rendered
    assert config.version_document["image_digest"] == "sha256:" + "3" * 64
    assert config.artifact_endpoint_url == "https://objects.example.test"
    assert config.artifact_region == "production-1"
    assert config.artifact_credential_revision.startswith("sha256:")
    assert config.artifact_credential_revision == (
        f"sha256:{config.secrets.artifact_credentials.source_sha256}"
    )
    assert config.artifact_readiness_key == "readiness/omnigent-saas-canary-v1"
    assert config.secrets.artifact_credentials.profile == "omnigent-saas-artifacts"
    assert config.secrets.preview_exchange_hmac_key is None
    assert "secret-access-key" not in repr(config)
    assert config.migration_receipt.catalog_sha256 == "5" * 64
    assert config.artifact_admission_receipt.image_digest == "sha256:" + "3" * 64
    assert config.artifact_admission_receipt.verified_key_spaces == (
        "admission",
        "file_id",
        "agent_bundle",
        "executor_storage",
    )
    assert config.official_builtin_agent_seed_enabled is False
    assert config.official_cross_workspace_scheduler_enabled is False


@pytest.mark.parametrize(
    ("name", "value", "message"),
    (
        ("OMNIGENT_SAAS_PRODUCT_REVISION", "abc", "full Git SHA"),
        ("OMNIGENT_SAAS_SOURCE_SHA", "abc", "full Git SHA"),
        ("OMNIGENT_SAAS_UPSTREAM_REVISION", "ABC" * 14, "full Git SHA"),
        ("OMNIGENT_SAAS_IMAGE_DIGEST", "sha256:1234", "sha256 digest"),
        (
            "OMNIGENT_SAAS_RELEASE_INCARNATION",
            "ABC",
            "32 lowercase hexadecimal",
        ),
        ("OMNIGENT_SAAS_PUBLIC_ORIGIN", "http://next.example.test", "exact HTTPS origin"),
        (
            "OMNIGENT_SAAS_PUBLIC_ORIGIN",
            "https://next.example.test/path",
            "exact HTTPS origin",
        ),
        ("OMNIGENT_SAAS_CAPABILITIES", "tenant", "tenant and run"),
        ("OMNIGENT_SAAS_CAPABILITIES", "tenant,run,unknown", "invalid entries"),
        ("OMNIGENT_SAAS_CAPABILITIES", "tenant,run,run", "invalid entries"),
        ("OMNIGENT_SAAS_ARTIFACT_STORE_URI", "file:///data", "durable s3"),
        ("OMNIGENT_SAAS_ARTIFACT_STORE_URI", "S3://bucket/prefix", "durable s3"),
        ("OMNIGENT_SAAS_ARTIFACT_STORE_URI", "s3://bucket:443/prefix", "durable s3"),
        ("OMNIGENT_SAAS_ARTIFACT_STORE_URI", "s3://bucket/prefix/", "durable s3"),
        (
            "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL",
            "http://objects.example.test",
            "exact HTTPS origin",
        ),
        (
            "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL",
            "https://objects.example.test:99999",
            "exact HTTPS origin",
        ),
        (
            "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL",
            "https://[malformed-ipv6",
            "exact HTTPS origin",
        ),
        ("OMNIGENT_SAAS_ARTIFACT_REGION", "bad region", "is invalid"),
        ("OMNIGENT_SAAS_ARTIFACT_REGION", "us_east_1", "is invalid"),
        (
            "OMNIGENT_SAAS_ARTIFACT_READINESS_KEY",
            "../readiness",
            "is invalid",
        ),
        (
            "OMNIGENT_SAAS_ARTIFACT_READINESS_SHA256",
            "not-a-sha",
            "must be SHA-256",
        ),
    ),
)
def test_rejects_invalid_public_configuration(
    tmp_path: Path,
    name: str,
    value: str,
    message: str,
) -> None:
    environment = _environment(tmp_path)
    environment[name] = value
    with pytest.raises(ProductionServerConfigError, match=message):
        load_production_server_config(environment)


def test_rejects_ambient_owner_and_migration_database_urls(tmp_path: Path) -> None:
    for forbidden in (
        "DATABASE_URL",
        "OMNIGENT_SAAS_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_SCHEMA_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_MIGRATION_DATABASE_URL_FILE",
    ):
        environment = _environment(tmp_path / forbidden.lower().replace("_", "-"))
        environment[forbidden] = "forbidden"
        with pytest.raises(ProductionServerConfigError, match="must not receive"):
            load_production_server_config(environment)


@pytest.mark.parametrize(
    "name",
    (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CREDENTIAL_FILE",
        "AWS_FUTURE_PROVIDER_EXAMPLE",
        "BOTO_CONFIG",
    ),
)
def test_rejects_every_ambient_aws_credential_provider(
    tmp_path: Path,
    name: str,
) -> None:
    environment = _environment(tmp_path / name.lower().replace("_", "-"))
    environment[name] = "forbidden"
    with pytest.raises(ProductionServerConfigError, match="ambient AWS"):
        load_production_server_config(environment)


def test_rejects_empty_or_whitespace_ambient_aws_configuration(tmp_path: Path) -> None:
    for index, value in enumerate(("", " ")):
        environment = _environment(tmp_path / f"empty-ambient-{index}")
        environment["AWS_ACCESS_KEY_ID"] = value
        with pytest.raises(ProductionServerConfigError, match="ambient AWS"):
            load_production_server_config(environment)


def test_requires_metadata_provider_to_be_explicitly_disabled(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    del environment["AWS_EC2_METADATA_DISABLED"]
    with pytest.raises(ProductionServerConfigError, match="instance metadata"):
        load_production_server_config(environment)


@pytest.mark.parametrize(
    "name",
    (
        "DATABRICKS_TOKEN",
        "DATABRICKS_CONFIG_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CLOUDSDK_CONFIG",
    ),
)
def test_rejects_ambient_non_aws_cloud_authority(tmp_path: Path, name: str) -> None:
    environment = _environment(tmp_path / name.lower().replace("_", "-"))
    environment[name] = "forbidden"
    with pytest.raises(ProductionServerConfigError, match="ambient cloud"):
        load_production_server_config(environment)


def test_requires_one_owner_only_explicit_artifact_profile(tmp_path: Path) -> None:
    environment = _environment(tmp_path / "extra-profile")
    credentials = Path(environment["OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE"])
    credentials.write_text(
        credentials.read_text(encoding="utf-8")
        + "[another-profile]\n"
        + "aws_access_key_id = another-access-key\n"
        + "aws_secret_access_key = another-secret-key\n",
        encoding="utf-8",
    )
    with pytest.raises(ProductionServerConfigError, match="exactly the selected"):
        load_production_server_config(environment)

    environment = _environment(tmp_path / "default-profile")
    credentials = Path(environment["OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE"])
    credentials.write_text(
        "[DEFAULT]\n"
        "aws_access_key_id = inherited-access-key\n"
        "aws_secret_access_key = inherited-secret-key\n"
        "[omnigent-saas-artifacts]\n",
        encoding="utf-8",
    )
    with pytest.raises(ProductionServerConfigError, match="exactly the selected"):
        load_production_server_config(environment)

    environment = _environment(tmp_path / "group-readable")
    credentials = Path(environment["OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE"])
    credentials.chmod(0o640)
    with pytest.raises(ProductionServerConfigError, match="group or other"):
        load_production_server_config(environment)


def test_malformed_artifact_profile_never_chains_secret_parser_text(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    leaked = "secret-access-key-must-not-reach-traceback"
    credentials = Path(environment["OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE"])
    credentials.write_text(
        "[omnigent-saas-artifacts]\n" + f"aws_secret_access_key {leaked}\n",
        encoding="utf-8",
    )

    with pytest.raises(ProductionServerConfigError) as captured:
        load_production_server_config(environment)
    assert captured.value.__cause__ is None
    assert leaked not in str(captured.value)
    assert leaked not in repr(captured.value)


def test_rejects_product_and_source_revision_drift(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    environment["OMNIGENT_SAAS_SOURCE_SHA"] = "9" * 40

    with pytest.raises(ProductionServerConfigError, match="must match exactly"):
        load_production_server_config(environment)


def test_rejects_group_readable_or_symlinked_secret(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    pepper = Path(environment["OMNIGENT_SAAS_API_CREDENTIAL_PEPPER_FILE"])
    pepper.chmod(0o640)
    with pytest.raises(ProductionServerConfigError, match="group or other"):
        load_production_server_config(environment)

    pepper.chmod(0o600)
    link = tmp_path / "pepper-link"
    link.symlink_to(pepper)
    environment["OMNIGENT_SAAS_API_CREDENTIAL_PEPPER_FILE"] = str(link)
    with pytest.raises(ProductionServerConfigError, match="non-symlink"):
        load_production_server_config(environment)


def test_rejects_group_or_other_writable_official_config(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    official = tmp_path / "official.yaml"
    official.write_text("execution_timeout: 600\n", encoding="utf-8")
    official.chmod(0o666)
    environment["OMNIGENT_SAAS_OFFICIAL_CONFIG_FILE"] = str(official)
    with pytest.raises(ProductionServerConfigError, match="group or other writable"):
        load_production_server_config(environment)


def test_rejects_reused_database_login_file_or_role_escalation(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    environment["OMNIGENT_SAAS_APP_DATABASE_URL_FILE"] = environment[
        "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE"
    ]
    with pytest.raises(ProductionServerConfigError, match="distinct secret files"):
        load_production_server_config(environment)

    environment = _environment(tmp_path / "set-role")
    environment["OMNIGENT_SAAS_APP_DATABASE_URL_FILE"] = _secret(
        tmp_path / "set-role" / "app-role-url",
        "postgresql+psycopg://app_login:password@postgres.internal/omnigent"
        "?sslmode=verify-full&options=-c%20role%3Dsaas_app",
    )
    with pytest.raises(ProductionServerConfigError, match="SET ROLE"):
        load_production_server_config(environment)


def test_rejects_owner_shaped_service_login(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    environment["OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE"] = _secret(
        tmp_path / "owner-runtime-url",
        "postgresql+psycopg://schema_owner:password@postgres.internal/omnigent",
    )
    with pytest.raises(ProductionServerConfigError, match="owner/admin"):
        load_production_server_config(environment)


def test_requires_tls_verify_full_on_every_service_login(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    environment["OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE"] = _secret(
        tmp_path / "runtime-without-tls",
        "postgresql+psycopg://runtime_login:password@postgres.internal/omnigent",
    )
    with pytest.raises(ProductionServerConfigError, match="sslmode=verify-full"):
        load_production_server_config(environment)


def test_runner_and_preview_factories_are_capability_bound(tmp_path: Path) -> None:
    missing = _environment(tmp_path / "missing")
    missing["OMNIGENT_SAAS_CAPABILITIES"] = "tenant,run,runner"
    with pytest.raises(ProductionServerConfigError, match="runner capability requires"):
        load_production_server_config(missing)

    configured = _environment(tmp_path / "configured")
    configured["OMNIGENT_SAAS_CAPABILITIES"] = "tenant,run,runner,preview"
    configured["OMNIGENT_SAAS_RUNNER_ADAPTER_FACTORY"] = "omnigent_saas_deployment.runner:factory"
    configured["OMNIGENT_SAAS_PREVIEW_ADAPTER_FACTORY"] = (
        "omnigent_saas_deployment.preview:factory"
    )
    configured["OMNIGENT_SAAS_PREVIEW_ROOT_DOMAIN"] = "preview.example.net"
    loaded = load_production_server_config(configured)
    assert loaded.runner_adapter_factory == "omnigent_saas_deployment.runner:factory"
    assert loaded.preview_adapter_factory == "omnigent_saas_deployment.preview:factory"
    assert loaded.preview_root_domain == "preview.example.net"
    assert loaded.secrets.preview_exchange_hmac_key == b"e" * 32

    unexpected = _environment(tmp_path / "unexpected")
    unexpected["OMNIGENT_SAAS_RUNNER_ADAPTER_FACTORY"] = "deployment.runner:factory"
    with pytest.raises(ProductionServerConfigError, match="forbidden unless"):
        load_production_server_config(unexpected)


def test_migration_receipt_is_read_only_and_exactly_revision_bound(tmp_path: Path) -> None:
    writable = _environment(tmp_path / "writable")
    receipt = Path(writable["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"])
    receipt.chmod(0o600)
    with pytest.raises(ProductionServerConfigError, match="read-only"):
        load_production_server_config(writable)

    mismatched = _environment(tmp_path / "mismatched")
    receipt = Path(mismatched["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"])
    document = json.loads(receipt.read_text(encoding="utf-8"))
    document["product_revision"] = "9" * 40
    receipt.chmod(0o600)
    receipt.write_text(json.dumps(document), encoding="utf-8")
    receipt.chmod(0o400)
    with pytest.raises(ProductionServerConfigError, match="revision binding"):
        load_production_server_config(mismatched)


def test_artifact_admission_receipt_is_read_only_and_exactly_bound(tmp_path: Path) -> None:
    writable = _environment(tmp_path / "writable-artifact-receipt")
    receipt = Path(writable["OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE"])
    receipt.chmod(0o600)
    with pytest.raises(ProductionServerConfigError, match="read-only"):
        load_production_server_config(writable)

    mismatched = _environment(tmp_path / "mismatched-artifact-receipt")
    receipt = Path(mismatched["OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE"])
    document = json.loads(receipt.read_text(encoding="utf-8"))
    document["image_digest"] = "sha256:" + "9" * 64
    receipt.chmod(0o600)
    receipt.write_text(json.dumps(document), encoding="utf-8")
    receipt.chmod(0o400)
    with pytest.raises(ProductionServerConfigError, match="authority binding"):
        load_production_server_config(mismatched)

    incomplete = _environment(tmp_path / "incomplete-artifact-receipt")
    receipt = Path(incomplete["OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE"])
    document = json.loads(receipt.read_text(encoding="utf-8"))
    document["verified_key_spaces"] = ["admission"]
    receipt.chmod(0o600)
    receipt.write_text(json.dumps(document), encoding="utf-8")
    receipt.chmod(0o400)
    with pytest.raises(ProductionServerConfigError, match="key-space proof"):
        load_production_server_config(incomplete)

    tampered = _environment(tmp_path / "tampered-artifact-receipt")
    receipt = Path(tampered["OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE"])
    document = json.loads(receipt.read_text(encoding="utf-8"))
    document["completed_at"] = "2026-09-01T00:00:01+00:00"
    receipt.chmod(0o600)
    receipt.write_text(json.dumps(document), encoding="utf-8")
    receipt.chmod(0o400)
    with pytest.raises(ProductionServerConfigError, match="does not match the receipt file"):
        load_production_server_config(tampered)
