"""Strict, side-effect-free configuration for the downstream SaaS server.

Nothing is read at import time.  Production secrets are supplied only through
rooted, owner-only files; environment variables contain file names and
non-secret release facts, never credentials or key material.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from collections.abc import Mapping
from configparser import Error as ConfigParserError
from configparser import RawConfigParser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from urllib.parse import urlsplit

from sqlalchemy.engine import URL, make_url

from saas.production.service_bindings import (
    ProductionServiceRoleBindings,
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_INCARNATION = re.compile(r"^[0-9a-f]{32}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FACTORY_REFERENCE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*:[A-Za-z][A-Za-z0-9_]*$"
)
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_CAPABILITIES = frozenset({"tenant", "run", "runner", "preview"})
_CORE_CAPABILITIES = frozenset({"tenant", "run"})
_DATABASE_ROLES = ("runtime", "authenticator", "app", "governance", "public_api")
_MAX_SECRET_FILE_BYTES = 16 * 1024
_FORBIDDEN_DATABASE_LOGIN_FRAGMENTS = ("admin", "migration", "owner", "postgres", "root")
_ALLOWED_AWS_ENVIRONMENT = frozenset({"AWS_EC2_METADATA_DISABLED"})
_AMBIENT_CLOUD_ENVIRONMENT_PREFIXES = ("DATABRICKS_",)
_AMBIENT_CLOUD_ENVIRONMENT_NAMES = frozenset({"CLOUDSDK_CONFIG", "GOOGLE_APPLICATION_CREDENTIALS"})
_ARTIFACT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_ARTIFACT_BUCKET = re.compile(
    r"^(?=.{3,63}$)(?!.*\.\.)(?!.*\.-)(?!.*-\.)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$"
)
_ARTIFACT_REGION = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ARTIFACT_ADMISSION_KEY_SPACES = (
    "admission",
    "file_id",
    "agent_bundle",
    "executor_storage",
)
_ARTIFACT_ADMISSION_OPERATIONS = (
    "put",
    "head",
    "get_hash",
    "delete",
)


class ProductionServerConfigError(ValueError):
    """Stable fail-closed configuration error raised before any socket is bound."""


@dataclass(frozen=True, slots=True)
class ProductionMigrationReceipt:
    """Immutable, secret-free handoff from the privileged migration job."""

    path: Path
    product_revision: str
    official_head: str
    saas_head: str
    database_identity_sha256: str
    catalog_sha256: str
    service_role_bindings_sha256: str
    runtime_rls_table_count: int


@dataclass(frozen=True, slots=True)
class ProductionDatabaseUrls:
    """Narrow service-login URLs; values are redacted from object reprs."""

    runtime: str = field(repr=False)
    authenticator: str = field(repr=False)
    app: str = field(repr=False)
    governance: str = field(repr=False)
    public_api: str = field(repr=False)

    def as_mapping(self) -> Mapping[str, str]:
        """Return a read-only role-to-URL mapping."""

        return MappingProxyType(
            {
                "runtime": self.runtime,
                "authenticator": self.authenticator,
                "app": self.app,
                "governance": self.governance,
                "public_api": self.public_api,
            }
        )


@dataclass(frozen=True, slots=True)
class ProductionS3Credentials:
    """One explicitly selected, in-memory S3 credential profile."""

    source_path: Path
    source_sha256: str
    profile: str
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProductionArtifactStoreConfig:
    """Narrow release-bound artifact authority shared with the admission Job."""

    product_revision: str
    source_revision: str
    image_digest: str
    release_incarnation: str
    store_uri: str
    endpoint_url: str
    region: str
    credential_revision: str
    credentials: ProductionS3Credentials = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProductionArtifactAdmissionReceipt:
    """Read-only CRUD proof bound to one image, release, and S3 authority."""

    path: Path
    source_sha256: str
    product_revision: str
    source_revision: str
    image_digest: str
    release_incarnation: str
    artifact_store_uri_sha256: str
    artifact_endpoint_url_sha256: str
    artifact_region: str
    credential_revision: str
    verified_key_spaces: tuple[str, ...]
    object_key_sha256s: tuple[tuple[str, str], ...]
    operations: tuple[str, ...]
    completed_at: str


@dataclass(frozen=True, slots=True)
class ProductionServerSecrets:
    """Resolved secret bytes; every field is omitted from dataclass reprs."""

    database_urls: ProductionDatabaseUrls = field(repr=False)
    api_credential_pepper: bytes = field(repr=False)
    cursor_hmac_key: bytes = field(repr=False)
    idempotency_hmac_key: bytes = field(repr=False)
    context_snapshot_key: bytes = field(repr=False)
    preview_exchange_hmac_key: bytes | None = field(repr=False)
    artifact_credentials: ProductionS3Credentials = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProductionServerConfig:
    """Validated release, network, capability, and secret configuration."""

    product_revision: str
    upstream_revision: str
    image_digest: str
    release_incarnation: str
    runtime_version: str
    official_schema_revision: str
    control_plane_schema_revision: str
    adapter_contract_version: str
    public_origin: str
    capabilities: frozenset[str]
    artifact_store_uri: str
    artifact_endpoint_url: str
    artifact_region: str
    artifact_credential_revision: str
    artifact_admission_receipt_revision: str
    artifact_readiness_key: str
    artifact_readiness_sha256: str
    artifact_cache_dir: Path
    host: str
    port: int
    cookie_name: str
    session_ttl_seconds: int
    snapshot_ttl_seconds: int
    active_key_id: str
    official_config_path: Path | None
    runner_adapter_factory: str | None
    preview_adapter_factory: str | None
    service_role_bindings: ProductionServiceRoleBindings = field(repr=False)
    migration_receipt: ProductionMigrationReceipt
    artifact_admission_receipt: ProductionArtifactAdmissionReceipt
    secrets: ProductionServerSecrets = field(repr=False)
    preview_root_domain: str | None = None
    preview_lease_seconds: int = 300
    official_builtin_agent_seed_enabled: bool = field(default=False, init=False)
    official_cross_workspace_scheduler_enabled: bool = field(default=False, init=False)

    @property
    def version_document(self) -> Mapping[str, object]:
        """Return the non-secret immutable version response."""

        return MappingProxyType(
            {
                "product_revision": self.product_revision,
                "upstream_revision": self.upstream_revision,
                "image_digest": self.image_digest,
                "release_incarnation": self.release_incarnation,
                "runtime_version": self.runtime_version,
                "official_schema_revision": self.official_schema_revision,
                "control_plane_schema_revision": self.control_plane_schema_revision,
                "adapter_contract_version": self.adapter_contract_version,
                "service_role_bindings_sha256": self.service_role_bindings.sha256,
                "artifact_credential_revision": self.artifact_credential_revision,
                "artifact_admission_receipt_sha256": (
                    self.artifact_admission_receipt.source_sha256
                ),
                "capabilities": sorted(self.capabilities),
            }
        )


def _required(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name)
    if value is None or not value.strip():
        raise ProductionServerConfigError(f"{name} is required")
    if value != value.strip() or "\x00" in value:
        raise ProductionServerConfigError(f"{name} is malformed")
    return value


def _bounded_integer(
    environ: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise ProductionServerConfigError(f"{name} must be an integer") from error
    if value < minimum or value > maximum:
        raise ProductionServerConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _absolute_regular_file(path_value: str, *, name: str, owner_only: bool) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        raise ProductionServerConfigError(f"{name} must be an absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProductionServerConfigError(f"{name} cannot be inspected") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProductionServerConfigError(f"{name} must name a regular non-symlink file")
    if metadata.st_uid != os.geteuid():
        raise ProductionServerConfigError(f"{name} must be owned by the server user")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o022:
        raise ProductionServerConfigError(f"{name} must not be group or other writable")
    if owner_only and mode & 0o077:
        raise ProductionServerConfigError(f"{name} must not grant group or other permissions")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_SECRET_FILE_BYTES:
        raise ProductionServerConfigError(f"{name} has an invalid size")
    return path


def _secret_bytes(environ: Mapping[str, str], name: str, *, minimum: int = 32) -> bytes:
    path = _absolute_regular_file(_required(environ, name), name=name, owner_only=True)
    try:
        value = path.read_bytes()
    except OSError as error:
        raise ProductionServerConfigError(f"{name} cannot be read") from error
    # Secret mounts commonly append one line ending.  Remove only line-ending
    # bytes, never arbitrary spaces that could silently change a credential.
    value = value.rstrip(b"\r\n")
    if len(value) < minimum or b"\x00" in value:
        raise ProductionServerConfigError(f"{name} does not contain valid secret material")
    return value


def _database_url(environ: Mapping[str, str], role: str) -> tuple[str, URL, Path]:
    env_name = f"OMNIGENT_SAAS_{role.upper()}_DATABASE_URL_FILE"
    path = _absolute_regular_file(_required(environ, env_name), name=env_name, owner_only=True)
    try:
        raw = path.read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError) as error:
        raise ProductionServerConfigError(f"{env_name} cannot be read") from error
    if not raw or raw != raw.strip() or "\x00" in raw or "\n" in raw or "\r" in raw:
        raise ProductionServerConfigError(f"{env_name} contains a malformed database URL")
    try:
        parsed = make_url(raw)
    except Exception as error:  # SQLAlchemy exposes multiple parse exception types.
        raise ProductionServerConfigError(
            f"{env_name} contains a malformed database URL"
        ) from error
    if (
        parsed.drivername != "postgresql+psycopg"
        or not parsed.username
        or parsed.password is None
        or not parsed.host
        or not parsed.database
    ):
        raise ProductionServerConfigError(
            f"{env_name} must contain a complete postgresql+psycopg service-login URL"
        )
    login = parsed.username.lower()
    if any(fragment in login for fragment in _FORBIDDEN_DATABASE_LOGIN_FRAGMENTS):
        raise ProductionServerConfigError(f"{env_name} must not contain an owner/admin login")
    query_names = {str(key).lower() for key in parsed.query}
    if "role" in query_names or "options" in query_names:
        raise ProductionServerConfigError(f"{env_name} must not request SET ROLE or libpq options")
    if parsed.query.get("sslmode") != "verify-full":
        raise ProductionServerConfigError(f"{env_name} must require sslmode=verify-full")
    if parsed.query.get("sslrootcert") != "/runtime/postgresql-ca.crt":
        raise ProductionServerConfigError(
            f"{env_name} must pin sslrootcert=/runtime/postgresql-ca.crt"
        )
    return raw, parsed, path


def load_production_database_url_file(
    environ: Mapping[str, str],
    role: str,
) -> tuple[str, URL, Path]:
    """Load one owner-only service DSN using the shared production contract.

    The caller still has to verify the live PostgreSQL login's exact base role;
    this helper validates only the file, URL, TLS, and no-``SET ROLE`` boundary.
    """

    if _REVISION.fullmatch(role) is None:
        raise ProductionServerConfigError("production database role name is invalid")
    return _database_url(environ, role)


def _load_database_urls(environ: Mapping[str, str]) -> ProductionDatabaseUrls:
    if any(
        name in environ and environ[name].strip()
        for name in (
            "DATABASE_URL",
            "OMNIGENT_SAAS_OWNER_DATABASE_URL_FILE",
            "OMNIGENT_SAAS_SCHEMA_OWNER_DATABASE_URL_FILE",
            "OMNIGENT_SAAS_MIGRATION_DATABASE_URL_FILE",
        )
    ):
        raise ProductionServerConfigError(
            "production server process must not receive ambient, owner, or migration database URLs"
        )
    loaded = {role: _database_url(environ, role) for role in _DATABASE_ROLES}
    urls = [value[0] for value in loaded.values()]
    paths = [value[2] for value in loaded.values()]
    logins = [value[1].username for value in loaded.values()]
    if len(set(urls)) != len(urls) or len(set(paths)) != len(paths):
        raise ProductionServerConfigError(
            "database service roles require distinct secret files and URLs"
        )
    if len(set(logins)) != len(logins):
        raise ProductionServerConfigError(
            "database service roles require distinct login principals"
        )
    endpoints = {
        (value[1].host, value[1].port or 5432, value[1].database) for value in loaded.values()
    }
    if len(endpoints) != 1:
        raise ProductionServerConfigError(
            "database service roles must target one reviewed database"
        )
    return ProductionDatabaseUrls(**{role: loaded[role][0] for role in _DATABASE_ROLES})


def _https_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != f"https://{parsed.netloc}"
    ):
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_PUBLIC_ORIGIN must be one exact HTTPS origin without a path"
        )
    return value


def _artifact_uri(value: str) -> str:
    try:
        parsed = urlsplit(value)
        bucket = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_STORE_URI must be a durable s3:// URI"
        ) from None
    prefix = parsed.path.removeprefix("/")
    if (
        not value.startswith("s3://")
        or parsed.scheme != "s3"
        or bucket is None
        or parsed.netloc != bucket
        or port is not None
        or _ARTIFACT_BUCKET.fullmatch(bucket) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (prefix and _ARTIFACT_KEY.fullmatch(prefix) is None)
        or any(part in {"", ".", ".."} for part in PurePosixPath(prefix).parts)
        or "//" in parsed.path
        or "\\" in value
        or parsed.path.endswith("/")
        or value != f"s3://{bucket}" + (f"/{prefix}" if prefix else "")
    ):
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_STORE_URI must be a durable s3:// URI"
        )
    try:
        ipaddress.ip_address(bucket)
    except ValueError:
        pass
    else:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_STORE_URI must use a canonical bucket name"
        )
    return value


def _artifact_endpoint(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL must be one exact HTTPS origin"
        ) from None
    authority = hostname or ""
    if port is not None:
        authority = f"{authority}:{port}"
    if (
        not value.startswith("https://")
        or parsed.scheme != "https"
        or hostname is None
        or _HOSTNAME.fullmatch(hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or parsed.netloc != authority
        or value != f"https://{authority}"
    ):
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL must be one exact HTTPS origin"
        )
    return value


def _artifact_region(value: str) -> str:
    if _ARTIFACT_REGION.fullmatch(value) is None:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_REGION is invalid; expected a canonical region identifier"
        )
    return value


def _artifact_key(value: str) -> str:
    parts = PurePosixPath(value).parts
    if (
        _ARTIFACT_KEY.fullmatch(value) is None
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or "//" in value
        or "\\" in value
        or PurePosixPath(value).is_absolute()
        or PureWindowsPath(value).is_absolute()
    ):
        raise ProductionServerConfigError("OMNIGENT_SAAS_ARTIFACT_READINESS_KEY is invalid")
    return value


def _artifact_credentials(source: Mapping[str, str]) -> ProductionS3Credentials:
    # Future botocore releases may add providers.  Deny the entire AWS
    # environment namespace instead of maintaining a bypass-prone enumeration;
    # the sole exception disables instance metadata for any dependency that
    # might create a second boto client in this process.
    ambient = sorted(
        name
        for name in source
        if (name.startswith("AWS_") and name not in _ALLOWED_AWS_ENVIRONMENT)
        or name == "BOTO_CONFIG"
    )
    if ambient:
        raise ProductionServerConfigError(
            "production server must not receive ambient AWS credential providers"
        )
    ambient_cloud = sorted(
        name
        for name in source
        if name in _AMBIENT_CLOUD_ENVIRONMENT_NAMES
        or name.startswith(_AMBIENT_CLOUD_ENVIRONMENT_PREFIXES)
    )
    if ambient_cloud:
        raise ProductionServerConfigError(
            "production server must not receive ambient cloud credential providers"
        )
    if source.get("AWS_EC2_METADATA_DISABLED") != "true":
        raise ProductionServerConfigError(
            "production server must disable the AWS instance metadata provider"
        )

    profile = _required(source, "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE")
    if _REVISION.fullmatch(profile) is None or len(profile) > 64 or profile.lower() == "default":
        raise ProductionServerConfigError("OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE is invalid")
    file_name = "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE"
    path = _absolute_regular_file(
        _required(source, file_name),
        name=file_name,
        owner_only=True,
    )
    try:
        raw = path.read_bytes()
        decoded = raw.decode("utf-8")
    except (OSError, UnicodeError, ConfigParserError):
        # ConfigParser error text can echo an invalid line, including secret
        # material.  Deliberately suppress exception chaining at this boundary.
        raise ProductionServerConfigError(f"{file_name} cannot be loaded") from None
    parser = RawConfigParser(interpolation=None, strict=True)
    try:
        parser.read_file(StringIO(decoded))
    except ConfigParserError:
        raise ProductionServerConfigError(f"{file_name} cannot be loaded") from None
    if parser.defaults() or parser.sections() != [profile]:
        raise ProductionServerConfigError(
            f"{file_name} must contain exactly the selected credential profile"
        )
    values = dict(parser.items(profile, raw=True))
    if set(values) != {"aws_access_key_id", "aws_secret_access_key"}:
        raise ProductionServerConfigError(f"{file_name} has an invalid credential shape")
    if any(
        not value or value != value.strip() or "\x00" in value or "\n" in value or "\r" in value
        for value in values.values()
    ):
        raise ProductionServerConfigError(f"{file_name} contains malformed credentials")
    access_key_id = values["aws_access_key_id"]
    secret_access_key = values["aws_secret_access_key"]
    if not 16 <= len(access_key_id) <= 256 or not 16 <= len(secret_access_key) <= 512:
        raise ProductionServerConfigError(f"{file_name} contains malformed credentials")
    return ProductionS3Credentials(
        source_path=path,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        profile=profile,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
    )


def load_production_artifact_store_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionArtifactStoreConfig:
    """Load only the exact Server artifact authority needed by admission."""

    source: Mapping[str, str] = os.environ if environ is None else environ
    product_revision = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
    source_revision = _required(source, "OMNIGENT_SAAS_SOURCE_SHA")
    if _FULL_GIT_SHA.fullmatch(product_revision) is None:
        raise ProductionServerConfigError("OMNIGENT_SAAS_PRODUCT_REVISION must be a full Git SHA")
    if _FULL_GIT_SHA.fullmatch(source_revision) is None:
        raise ProductionServerConfigError("OMNIGENT_SAAS_SOURCE_SHA must be a full Git SHA")
    if source_revision != product_revision:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_PRODUCT_REVISION and OMNIGENT_SAAS_SOURCE_SHA must match exactly"
        )
    image_digest = _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
    if _IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise ProductionServerConfigError("OMNIGENT_SAAS_IMAGE_DIGEST must be a sha256 digest")
    release_incarnation = _required(source, "OMNIGENT_SAAS_RELEASE_INCARNATION")
    if _RELEASE_INCARNATION.fullmatch(release_incarnation) is None:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_RELEASE_INCARNATION must be 32 lowercase hexadecimal characters"
        )
    credentials = _artifact_credentials(source)
    credential_revision = _required(source, "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION")
    if credential_revision != f"sha256:{credentials.source_sha256}":
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION does not match the credential file"
        )
    return ProductionArtifactStoreConfig(
        product_revision=product_revision,
        source_revision=source_revision,
        image_digest=image_digest,
        release_incarnation=release_incarnation,
        store_uri=_artifact_uri(_required(source, "OMNIGENT_SAAS_ARTIFACT_STORE_URI")),
        endpoint_url=_artifact_endpoint(_required(source, "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL")),
        region=_artifact_region(_required(source, "OMNIGENT_SAAS_ARTIFACT_REGION")),
        credential_revision=credential_revision,
        credentials=credentials,
    )


def load_production_artifact_admission_receipt(
    source: Mapping[str, str],
    *,
    artifact_config: ProductionArtifactStoreConfig,
) -> ProductionArtifactAdmissionReceipt:
    """Load one immutable CRUD receipt bound to the exact runtime authority."""

    name = "OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE"
    path = _absolute_regular_file(_required(source, name), name=name, owner_only=True)
    mode = stat.S_IMODE(path.lstat().st_mode)
    if mode & 0o222 or not mode & 0o400:
        raise ProductionServerConfigError(f"{name} must be owner-readable and read-only")
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProductionServerConfigError(f"{name} cannot be loaded") from error
    expected_fields = {
        "schema_version",
        "status",
        "product_revision",
        "source_revision",
        "image_digest",
        "release_incarnation",
        "artifact_store_uri_sha256",
        "artifact_endpoint_url_sha256",
        "artifact_region",
        "credential_revision",
        "verified_key_spaces",
        "object_key_sha256s",
        "operations",
        "completed_at",
    }
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise ProductionServerConfigError(f"{name} fields do not match the schema")
    if document.get("schema_version") != 1 or document.get("status") != "pass":
        raise ProductionServerConfigError(f"{name} does not contain a successful admission")
    expected_bindings = {
        "product_revision": artifact_config.product_revision,
        "source_revision": artifact_config.source_revision,
        "image_digest": artifact_config.image_digest,
        "release_incarnation": artifact_config.release_incarnation,
        "artifact_store_uri_sha256": hashlib.sha256(
            artifact_config.store_uri.encode("utf-8")
        ).hexdigest(),
        "artifact_endpoint_url_sha256": hashlib.sha256(
            artifact_config.endpoint_url.encode("utf-8")
        ).hexdigest(),
        "artifact_region": artifact_config.region,
        "credential_revision": artifact_config.credential_revision,
    }
    if any(document.get(key) != value for key, value in expected_bindings.items()):
        raise ProductionServerConfigError(f"{name} authority binding does not match the server")
    key_spaces = document.get("verified_key_spaces")
    operations = document.get("operations")
    key_hashes = document.get("object_key_sha256s")
    if not isinstance(key_spaces, list) or key_spaces != list(_ARTIFACT_ADMISSION_KEY_SPACES):
        raise ProductionServerConfigError(f"{name} key-space proof is incomplete")
    if not isinstance(operations, list) or operations != list(_ARTIFACT_ADMISSION_OPERATIONS):
        raise ProductionServerConfigError(f"{name} operation proof is incomplete")
    if (
        not isinstance(key_hashes, dict)
        or set(key_hashes) != set(_ARTIFACT_ADMISSION_KEY_SPACES)
        or any(
            not isinstance(value, str) or _SHA256.fullmatch(value) is None
            for value in key_hashes.values()
        )
    ):
        raise ProductionServerConfigError(f"{name} object-key facts are invalid")
    completed_at = document.get("completed_at")
    if not isinstance(completed_at, str):
        raise ProductionServerConfigError(f"{name} completion time is invalid")
    try:
        completed = datetime.fromisoformat(completed_at)
    except (TypeError, ValueError):
        raise ProductionServerConfigError(f"{name} completion time is invalid") from None
    if (
        not completed_at.endswith("+00:00")
        or completed.utcoffset() != timezone.utc.utcoffset(completed)
        or completed.microsecond != 0
    ):
        raise ProductionServerConfigError(f"{name} completion time is invalid")
    return ProductionArtifactAdmissionReceipt(
        path=path,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        product_revision=artifact_config.product_revision,
        source_revision=artifact_config.source_revision,
        image_digest=artifact_config.image_digest,
        release_incarnation=artifact_config.release_incarnation,
        artifact_store_uri_sha256=expected_bindings["artifact_store_uri_sha256"],
        artifact_endpoint_url_sha256=expected_bindings["artifact_endpoint_url_sha256"],
        artifact_region=artifact_config.region,
        credential_revision=artifact_config.credential_revision,
        verified_key_spaces=tuple(key_spaces),
        object_key_sha256s=tuple((name, key_hashes[name]) for name in key_spaces),
        operations=tuple(operations),
        completed_at=completed_at,
    )


def _preview_root_domain(source: Mapping[str, str], *, required: bool) -> str | None:
    raw = source.get("OMNIGENT_SAAS_PREVIEW_ROOT_DOMAIN")
    if raw is None or not raw.strip():
        if required:
            raise ProductionServerConfigError(
                "preview capability requires OMNIGENT_SAAS_PREVIEW_ROOT_DOMAIN"
            )
        return None
    if raw != raw.strip() or raw != raw.lower() or _HOSTNAME.fullmatch(raw) is None:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_PREVIEW_ROOT_DOMAIN must be one canonical DNS root"
        )
    return raw


def _capabilities(value: str) -> frozenset[str]:
    parts = value.split(",")
    if any(not part or part != part.strip() for part in parts):
        raise ProductionServerConfigError("OMNIGENT_SAAS_CAPABILITIES is malformed")
    if len(set(parts)) != len(parts) or not set(parts).issubset(_CAPABILITIES):
        raise ProductionServerConfigError("OMNIGENT_SAAS_CAPABILITIES contains invalid entries")
    selected = frozenset(parts)
    if not _CORE_CAPABILITIES.issubset(selected):
        raise ProductionServerConfigError("tenant and run are mandatory production capabilities")
    return selected


def _revision(environ: Mapping[str, str], name: str) -> str:
    value = _required(environ, name)
    if _REVISION.fullmatch(value) is None:
        raise ProductionServerConfigError(f"{name} is invalid")
    return value


def _factory_reference(
    source: Mapping[str, str],
    *,
    capability: str,
) -> str | None:
    name = f"OMNIGENT_SAAS_{capability.upper()}_ADAPTER_FACTORY"
    raw = source.get(name)
    if raw is None or not raw.strip():
        return None
    if raw != raw.strip() or _FACTORY_REFERENCE.fullmatch(raw) is None:
        raise ProductionServerConfigError(f"{name} must use a public module:attribute reference")
    module_name, attribute = raw.split(":", 1)
    if any(part.startswith("_") for part in module_name.split(".")) or attribute.startswith("_"):
        raise ProductionServerConfigError(f"{name} must not reference private code")
    return raw


def _migration_receipt(
    source: Mapping[str, str],
    *,
    product_revision: str,
    official_head: str,
    saas_head: str,
    service_role_bindings_sha256: str,
) -> ProductionMigrationReceipt:
    name = "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"
    path = _absolute_regular_file(_required(source, name), name=name, owner_only=True)
    mode = stat.S_IMODE(path.lstat().st_mode)
    if mode & 0o222 or not mode & 0o400:
        raise ProductionServerConfigError(f"{name} must be owner-readable and read-only")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProductionServerConfigError(f"{name} cannot be loaded") from error
    if not isinstance(document, dict):
        raise ProductionServerConfigError(f"{name} must contain a JSON object")
    if document.get("status") != "pass" or document.get("schema_version") != 1:
        raise ProductionServerConfigError(f"{name} does not contain a successful migration")
    phases = document.get("phases")
    authorities = document.get("authorities")
    expected_authorities = {
        "principal_operator",
        "database_owner",
        "official_owner",
        "saas_owner",
    }
    if not isinstance(phases, list) or "state:verified" not in phases:
        raise ProductionServerConfigError(f"{name} does not contain final verification")
    if not isinstance(authorities, list) or len(authorities) != len(expected_authorities):
        raise ProductionServerConfigError(f"{name} authority facts are invalid")
    authority_kinds: set[str] = set()
    for authority in authorities:
        if (
            not isinstance(authority, dict)
            or set(authority) != {"kind", "login"}
            or authority.get("kind") not in expected_authorities
            or not isinstance(authority.get("login"), str)
            or _REVISION.fullmatch(authority["login"]) is None
        ):
            raise ProductionServerConfigError(f"{name} authority facts are invalid")
        authority_kinds.add(authority["kind"])
    if authority_kinds != expected_authorities:
        raise ProductionServerConfigError(f"{name} authority facts are invalid")
    bindings = {
        "product_revision": product_revision,
        "official_head": official_head,
        "saas_head": saas_head,
    }
    if any(document.get(key) != expected for key, expected in bindings.items()):
        raise ProductionServerConfigError(f"{name} revision binding does not match the server")
    database_identity = document.get("database_identity_sha256")
    catalog = document.get("catalog_sha256")
    receipt_bindings = document.get("service_role_bindings_sha256")
    table_count = document.get("runtime_rls_table_count")
    if (
        not isinstance(database_identity, str)
        or _SHA256.fullmatch(database_identity) is None
        or not isinstance(catalog, str)
        or _SHA256.fullmatch(catalog) is None
        or receipt_bindings != service_role_bindings_sha256
        or isinstance(table_count, bool)
        or not isinstance(table_count, int)
        or table_count <= 0
    ):
        raise ProductionServerConfigError(f"{name} verification facts are invalid")
    return ProductionMigrationReceipt(
        path=path,
        product_revision=product_revision,
        official_head=official_head,
        saas_head=saas_head,
        database_identity_sha256=database_identity,
        catalog_sha256=catalog,
        service_role_bindings_sha256=service_role_bindings_sha256,
        runtime_rls_table_count=table_count,
    )


def load_production_migration_receipt(
    source: Mapping[str, str],
    *,
    product_revision: str,
    official_head: str,
    saas_head: str,
    service_role_bindings_sha256: str,
) -> ProductionMigrationReceipt:
    """Load the immutable migration handoff shared by server and workers."""

    return _migration_receipt(
        source,
        product_revision=product_revision,
        official_head=official_head,
        saas_head=saas_head,
        service_role_bindings_sha256=service_role_bindings_sha256,
    )


def load_production_server_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionServerConfig:
    """Load and validate production server configuration without mutating the environment."""

    source: Mapping[str, str] = os.environ if environ is None else environ
    product_revision = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
    source_revision = _required(source, "OMNIGENT_SAAS_SOURCE_SHA")
    upstream_revision = _required(source, "OMNIGENT_SAAS_UPSTREAM_REVISION")
    if _FULL_GIT_SHA.fullmatch(product_revision) is None:
        raise ProductionServerConfigError("OMNIGENT_SAAS_PRODUCT_REVISION must be a full Git SHA")
    if _FULL_GIT_SHA.fullmatch(source_revision) is None:
        raise ProductionServerConfigError("OMNIGENT_SAAS_SOURCE_SHA must be a full Git SHA")
    if source_revision != product_revision:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_PRODUCT_REVISION and OMNIGENT_SAAS_SOURCE_SHA must match exactly"
        )
    if _FULL_GIT_SHA.fullmatch(upstream_revision) is None:
        raise ProductionServerConfigError("OMNIGENT_SAAS_UPSTREAM_REVISION must be a full Git SHA")
    image_digest = _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
    if _IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise ProductionServerConfigError("OMNIGENT_SAAS_IMAGE_DIGEST must be a sha256 digest")
    artifact_config = load_production_artifact_store_config(source)
    artifact_admission_receipt = load_production_artifact_admission_receipt(
        source,
        artifact_config=artifact_config,
    )
    artifact_admission_receipt_revision = _required(
        source,
        "OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION",
    )
    if artifact_admission_receipt_revision != (
        f"sha256:{artifact_admission_receipt.source_sha256}"
    ):
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION does not match the receipt file"
        )

    host = source.get("OMNIGENT_SAAS_HOST", "0.0.0.0")
    try:
        ipaddress.ip_address(host)
    except ValueError as error:
        raise ProductionServerConfigError("OMNIGENT_SAAS_HOST must be an IP address") from error
    cache_dir = Path(_required(source, "OMNIGENT_SAAS_ARTIFACT_CACHE_DIR"))
    if not cache_dir.is_absolute() or cache_dir == Path("/") or ".." in cache_dir.parts:
        raise ProductionServerConfigError("OMNIGENT_SAAS_ARTIFACT_CACHE_DIR is invalid")

    config_path_raw = source.get("OMNIGENT_SAAS_OFFICIAL_CONFIG_FILE")
    config_path = (
        _absolute_regular_file(
            config_path_raw,
            name="OMNIGENT_SAAS_OFFICIAL_CONFIG_FILE",
            owner_only=False,
        )
        if config_path_raw
        else None
    )
    active_key_id = source.get("OMNIGENT_SAAS_ACTIVE_KEY_ID", "v1")
    if _REVISION.fullmatch(active_key_id) is None or len(active_key_id) > 16:
        raise ProductionServerConfigError("OMNIGENT_SAAS_ACTIVE_KEY_ID is invalid")

    try:
        service_role_bindings = load_production_service_role_bindings(source)
    except ProductionServiceRoleBindingsError as error:
        raise ProductionServerConfigError(str(error)) from error
    database_urls = _load_database_urls(source)
    for service, database_url in database_urls.as_mapping().items():
        if make_url(database_url).username != service_role_bindings.login_for(service):
            raise ProductionServerConfigError(
                f"{service} database URL login does not match service-role bindings"
            )
    capabilities = _capabilities(_required(source, "OMNIGENT_SAAS_CAPABILITIES"))
    secrets = ProductionServerSecrets(
        database_urls=database_urls,
        api_credential_pepper=_secret_bytes(source, "OMNIGENT_SAAS_API_CREDENTIAL_PEPPER_FILE"),
        cursor_hmac_key=_secret_bytes(source, "OMNIGENT_SAAS_CURSOR_HMAC_KEY_FILE"),
        idempotency_hmac_key=_secret_bytes(source, "OMNIGENT_SAAS_IDEMPOTENCY_HMAC_KEY_FILE"),
        context_snapshot_key=_secret_bytes(source, "OMNIGENT_SAAS_CONTEXT_SNAPSHOT_KEY_FILE"),
        preview_exchange_hmac_key=(
            _secret_bytes(source, "OMNIGENT_SAAS_PREVIEW_EXCHANGE_HMAC_KEY_FILE")
            if "preview" in capabilities
            else None
        ),
        artifact_credentials=artifact_config.credentials,
    )
    cookie_name = source.get("OMNIGENT_SAAS_COOKIE_NAME", "__Host-omnigent_saas_session")
    if not cookie_name.startswith("__Host-") or not _REVISION.fullmatch(cookie_name[7:]):
        raise ProductionServerConfigError("OMNIGENT_SAAS_COOKIE_NAME must use the __Host- prefix")

    runner_adapter_factory = _factory_reference(source, capability="runner")
    preview_adapter_factory = _factory_reference(source, capability="preview")
    for capability, factory in (
        ("runner", runner_adapter_factory),
        ("preview", preview_adapter_factory),
    ):
        if capability in capabilities and factory is None:
            raise ProductionServerConfigError(
                f"{capability} capability requires its production adapter factory"
            )
        if capability not in capabilities and factory is not None:
            raise ProductionServerConfigError(
                f"{capability} adapter factory is forbidden unless the capability is enabled"
            )
    preview_root_domain = _preview_root_domain(
        source,
        required="preview" in capabilities,
    )
    preview_lease_seconds = _bounded_integer(
        source,
        "OMNIGENT_SAAS_PREVIEW_LEASE_SECONDS",
        default=300,
        minimum=30,
        maximum=3600,
    )

    runtime_version = _revision(source, "OMNIGENT_SAAS_RUNTIME_VERSION")
    official_schema_revision = _revision(source, "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION")
    control_plane_schema_revision = _revision(
        source, "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION"
    )
    adapter_contract_version = _revision(source, "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION")
    receipt = load_production_migration_receipt(
        source,
        product_revision=product_revision,
        official_head=official_schema_revision,
        saas_head=control_plane_schema_revision,
        service_role_bindings_sha256=service_role_bindings.sha256,
    )
    artifact_readiness_sha256 = _required(source, "OMNIGENT_SAAS_ARTIFACT_READINESS_SHA256")
    if _SHA256.fullmatch(artifact_readiness_sha256) is None:
        raise ProductionServerConfigError(
            "OMNIGENT_SAAS_ARTIFACT_READINESS_SHA256 must be SHA-256"
        )

    return ProductionServerConfig(
        product_revision=product_revision,
        upstream_revision=upstream_revision,
        image_digest=image_digest,
        release_incarnation=artifact_config.release_incarnation,
        runtime_version=runtime_version,
        official_schema_revision=official_schema_revision,
        control_plane_schema_revision=control_plane_schema_revision,
        adapter_contract_version=adapter_contract_version,
        public_origin=_https_origin(_required(source, "OMNIGENT_SAAS_PUBLIC_ORIGIN")),
        capabilities=capabilities,
        artifact_store_uri=artifact_config.store_uri,
        artifact_endpoint_url=artifact_config.endpoint_url,
        artifact_region=artifact_config.region,
        artifact_credential_revision=artifact_config.credential_revision,
        artifact_admission_receipt_revision=artifact_admission_receipt_revision,
        artifact_readiness_key=_artifact_key(
            _required(source, "OMNIGENT_SAAS_ARTIFACT_READINESS_KEY")
        ),
        artifact_readiness_sha256=artifact_readiness_sha256,
        artifact_cache_dir=cache_dir,
        host=host,
        port=_bounded_integer(
            source, "OMNIGENT_SAAS_PORT", default=8000, minimum=1, maximum=65535
        ),
        cookie_name=cookie_name,
        session_ttl_seconds=_bounded_integer(
            source,
            "OMNIGENT_SAAS_SESSION_TTL_SECONDS",
            default=28800,
            minimum=300,
            maximum=86400,
        ),
        snapshot_ttl_seconds=_bounded_integer(
            source,
            "OMNIGENT_SAAS_SNAPSHOT_TTL_SECONDS",
            default=60,
            minimum=1,
            maximum=60,
        ),
        active_key_id=active_key_id,
        official_config_path=config_path,
        runner_adapter_factory=runner_adapter_factory,
        preview_adapter_factory=preview_adapter_factory,
        service_role_bindings=service_role_bindings,
        migration_receipt=receipt,
        artifact_admission_receipt=artifact_admission_receipt,
        secrets=secrets,
        preview_root_domain=preview_root_domain,
        preview_lease_seconds=preview_lease_seconds,
    )


__all__ = [
    "ProductionArtifactAdmissionReceipt",
    "ProductionArtifactStoreConfig",
    "ProductionDatabaseUrls",
    "ProductionMigrationReceipt",
    "ProductionS3Credentials",
    "ProductionServerConfig",
    "ProductionServerConfigError",
    "ProductionServerSecrets",
    "load_production_artifact_admission_receipt",
    "load_production_artifact_store_config",
    "load_production_database_url_file",
    "load_production_migration_receipt",
    "load_production_server_config",
]
