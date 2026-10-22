"""Strict, secret-free desired state for the Beta PostgreSQL data plane.

The renderer is deliberately offline. Release automation supplies locally
downloaded upstream manifests, whose bytes are bound by the owner-only spec.
No network client and no credential material exists in this module.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

import yaml

CNPG_VERSION = "1.30.0"
POSTGRESQL_VERSION = "18.4"
BARMAN_PLUGIN_VERSION = "0.14.0"
CERT_MANAGER_VERSION = "1.21.1"
KUBERNETES_VERSION = "1.36"
TARGET_PLATFORM = "linux/amd64"
CNPG_PLUGIN_NAME = "barman-cloud.cloudnative-pg.io"
OPERATOR_MANIFEST_URL = (
    "https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v1.30.0/cnpg-1.30.0.yaml"
)
OPERATOR_MANIFEST_SHA256 = "f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88"
CNPG_OPERATOR_IMAGE = (
    "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0@sha256:"
    "091d306935cfdf646debfe78010d59ebfb572150eb6eb922b0203873c0c68841"
)
POSTGRESQL_IMAGE = (
    "ghcr.io/cloudnative-pg/postgresql:18.4-standard-bookworm@sha256:"
    "d92906e5d4c9018365f26282d15bac23bd76932d492c033da86bf0346f4f8589"
)
BARMAN_MANIFEST_URL = (
    "https://github.com/cloudnative-pg/plugin-barman-cloud/releases/download/v0.14.0/manifest.yaml"
)
BARMAN_MANIFEST_SHA256 = "8d4f1719cc54891ddffd7633279ec93b5d2cc547df8684c3b84f3b156a615e7c"
BARMAN_OPERATOR_IMAGE = (
    "ghcr.io/cloudnative-pg/plugin-barman-cloud:v0.14.0@sha256:"
    "c37319ae990de072a8717def59811d147491d52f3c3a1d5aa5ea6ed3a9228e8e"
)
BARMAN_SIDECAR_IMAGE = (
    "ghcr.io/cloudnative-pg/plugin-barman-cloud-sidecar:v0.14.0@sha256:"
    "b1f980db3e97942eafd7a063fb99cda03300e651f9fe9561ff1bcbe481c157c8"
)
CERT_MANAGER_MANIFEST_URL = (
    "https://github.com/cert-manager/cert-manager/releases/download/v1.21.1/cert-manager.yaml"
)
CERT_MANAGER_MANIFEST_SHA256 = "5f6a499b8c1857d57f560f536e0dcc830914b45c420899fe7ad0692c8624e408"
CERT_MANAGER_CONTROLLER_IMAGE = (
    "quay.io/jetstack/cert-manager-controller:v1.21.1@sha256:"
    "4c2b5201fd66085b777dc6b256d96d7d346b6445404cec34db5f8aea86182cc5"
)
CERT_MANAGER_CAINJECTOR_IMAGE = (
    "quay.io/jetstack/cert-manager-cainjector:v1.21.1@sha256:"
    "1910ad7e134880e27d229e07affb43da1b07841a77f70c364f17467cb4e49bd9"
)
CERT_MANAGER_WEBHOOK_IMAGE = (
    "quay.io/jetstack/cert-manager-webhook:v1.21.1@sha256:"
    "741084291faf115a2909bfe3515458b54926c67f039ac20effd821bac69817a4"
)

SOURCE_URLS = (
    "https://cloudnative-pg.io/docs/1.30/backup/",
    "https://cloudnative-pg.io/docs/1.30/bootstrap/",
    "https://cloudnative-pg.io/docs/1.30/certificates/",
    "https://cloudnative-pg.io/docs/1.30/cnpg_i/",
    "https://cloudnative-pg.io/docs/1.30/networking/",
    "https://cloudnative-pg.io/docs/1.30/storage/",
    "https://github.com/cloudnative-pg/cloudnative-pg/releases/tag/v1.30.0",
    "https://raw.githubusercontent.com/cloudnative-pg/plugin-barman-cloud/"
    "v0.14.0/web/versioned_docs/version-0.14.0/concepts.md",
    "https://raw.githubusercontent.com/cloudnative-pg/plugin-barman-cloud/"
    "v0.14.0/web/versioned_docs/version-0.14.0/installation.mdx",
    "https://raw.githubusercontent.com/cloudnative-pg/plugin-barman-cloud/"
    "v0.14.0/web/versioned_docs/version-0.14.0/parameters.md",
    "https://raw.githubusercontent.com/cloudnative-pg/plugin-barman-cloud/"
    "v0.14.0/web/versioned_docs/version-0.14.0/usage.md",
    "https://github.com/cloudnative-pg/plugin-barman-cloud/releases/tag/v0.14.0",
    "https://github.com/cert-manager/cert-manager/releases/tag/v1.21.1",
    "https://cert-manager.io/docs/installation/kubectl/",
    "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
)

_MAX_SPEC_BYTES = 128 * 1024
_MAX_EVIDENCE_BYTES = 128 * 1024
_MAX_SOURCE_BYTES = 4 * 1024 * 1024
_MAX_GITOPS_FILE_BYTES = 1024 * 1024
_MAX_DOCUMENTS = 128
_SHA256 = re.compile(r"[0-9a-f]{64}")
_KUBERNETES_NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
_LABEL_KEY = re.compile(
    r"(?:[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?/)?"
    r"[A-Za-z0-9](?:[-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?"
)
_LABEL_VALUE = re.compile(r"(?:[A-Za-z0-9](?:[-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?)?")
_SECRET_KEY = re.compile(r"[A-Za-z0-9._-]{1,253}")
_POSTGRES_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,62}")
_SIZE = re.compile(r"[1-9][0-9]*(?:Mi|Gi|Ti)")
_IMAGE = re.compile(
    r"(?P<repository>[a-z0-9][a-z0-9._/-]*):(?P<tag>[A-Za-z0-9._-]+)"
    r"@sha256:(?P<digest>[0-9a-f]{64})"
)
_SAFE_FILE_COMPONENT = re.compile(r"[^a-z0-9.-]+")
_SENTINELS = ("changeme", "placeholder", "replace-me", "replace_me", "todo")
_RFC3339_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z"
)
_FAILURE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class BetaPostgresqlDataPlaneError(ValueError):
    """The requested data-plane release cannot be rendered safely."""


@dataclass(frozen=True, slots=True)
class BetaPostgresqlDataPlaneSpec:
    """Validated, canonical owner authority for one Beta data plane."""

    document: Mapping[str, object]
    sha256: str


@dataclass(frozen=True, slots=True)
class RenderedBetaPostgresqlDataPlane:
    """Secret-free receipt facts for one offline render."""

    output_directory: Path
    spec_sha256: str
    bundle_sha256: str
    receipt_sha256: str
    files: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdmittedRestoreDrillEvidence:
    """Validated, release-bound facts from one restore-drill execution record."""

    evidence_sha256: str
    deployment_id: str
    execution_status: str
    spec_sha256: str
    bundle_sha256: str
    recovery_target_time: str
    started_at: str
    completed_at: str
    source_backup_uid: str
    restored_cluster_uid: str
    data_validation_sha256: str
    database_owner_verified: bool
    pitr_target_reached: bool
    source_store_read_only: bool
    wal_replay_verified: bool
    failure_code: str | None
    failure_detail_sha256: str | None


ManifestLoader = Callable[[Path, str, str], list[dict[str, object]]]


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_uid,
        stat.S_IMODE(left.st_mode),
        left.st_nlink,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_uid,
        stat.S_IMODE(right.st_mode),
        right.st_nlink,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _read_stable_file(
    path: Path,
    *,
    maximum: int,
    field: str,
    owner_only: bool,
) -> bytes:
    if not path.is_absolute():
        raise BetaPostgresqlDataPlaneError(f"{field} path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BetaPostgresqlDataPlaneError(f"{field} cannot be opened safely") from error
    try:
        before_fd = os.fstat(descriptor)
        mode = stat.S_IMODE(before_fd.st_mode)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_uid != os.getuid()
            or before_fd.st_nlink != 1
            or before_fd.st_size <= 0
            or before_fd.st_size > maximum
            or (owner_only and mode not in {0o400, 0o600})
            or (not owner_only and mode & 0o022 != 0)
            or not _same_stat(before_path, before_fd)
        ):
            raise BetaPostgresqlDataPlaneError(f"{field} has unsafe ownership or metadata")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after_fd = os.fstat(descriptor)
    except OSError as error:
        raise BetaPostgresqlDataPlaneError(f"{field} cannot be read safely") from error
    finally:
        os.close(descriptor)
    try:
        after_path = path.lstat()
    except OSError as error:
        raise BetaPostgresqlDataPlaneError(f"{field} changed while being read") from error
    if (
        len(raw) > maximum
        or not _same_stat(before_fd, after_fd)
        or not _same_stat(after_fd, after_path)
    ):
        raise BetaPostgresqlDataPlaneError(f"{field} changed while being read")
    return raw


def _object(
    value: object,
    *,
    keys: set[str],
    field: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BetaPostgresqlDataPlaneError(f"{field} has an invalid shape")
    return cast(dict[str, object], value)


def _string(value: object, *, field: str, maximum: int = 253) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise BetaPostgresqlDataPlaneError(f"{field} must be a non-empty string")
    lowered = value.casefold()
    if any(token in lowered for token in _SENTINELS) or "${" in value or "<" in value:
        raise BetaPostgresqlDataPlaneError(f"{field} contains a sentinel")
    return value


def _name(value: object, *, field: str) -> str:
    result = _string(value, field=field)
    if result == "default" or _KUBERNETES_NAME.fullmatch(result) is None:
        raise BetaPostgresqlDataPlaneError(f"{field} must be an explicit Kubernetes name")
    return result


def _digest(value: object, *, field: str) -> str:
    result = _string(value, field=field, maximum=64)
    if _SHA256.fullmatch(result) is None or result == "0" * 64:
        raise BetaPostgresqlDataPlaneError(f"{field} must be a non-zero SHA-256")
    return result


def _image(
    value: object,
    *,
    repository: str,
    tag_pattern: str,
    field: str,
) -> str:
    result = _string(value, field=field, maximum=512)
    matched = _IMAGE.fullmatch(result)
    if (
        matched is None
        or matched["repository"] != repository
        or re.fullmatch(tag_pattern, matched["tag"]) is None
        or matched["digest"] == "0" * 64
        or "latest" in matched["tag"].casefold()
    ):
        raise BetaPostgresqlDataPlaneError(f"{field} must be an exact version and digest pin")
    return result


def _selector(value: object, *, field: str) -> dict[str, str]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 8:
        raise BetaPostgresqlDataPlaneError(f"{field} must contain explicit pod labels")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or _LABEL_KEY.fullmatch(key) is None
            or _LABEL_VALUE.fullmatch(item) is None
        ):
            raise BetaPostgresqlDataPlaneError(f"{field} contains an invalid label")
        result[key] = item
    return result


def _secret_reference(value: object, *, field: str) -> dict[str, str]:
    reference = _object(value, keys={"key", "name"}, field=field)
    key = _string(reference["key"], field=f"{field}.key")
    if _SECRET_KEY.fullmatch(key) is None:
        raise BetaPostgresqlDataPlaneError(f"{field}.key is invalid")
    return {
        "key": key,
        "name": _name(reference["name"], field=f"{field}.name"),
    }


def _local_secret_reference(value: object, *, field: str) -> dict[str, str]:
    reference = _object(value, keys={"name"}, field=field)
    return {"name": _name(reference["name"], field=f"{field}.name")}


def _postgres_identifier(value: object, *, field: str) -> str:
    result = _string(value, field=field, maximum=63)
    if _POSTGRES_IDENTIFIER.fullmatch(result) is None:
        raise BetaPostgresqlDataPlaneError(f"{field} must be a lowercase PostgreSQL identifier")
    return result


def _reject_unreviewed_values(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_unreviewed_values(key)
            _reject_unreviewed_values(item)
    elif isinstance(value, list):
        for item in value:
            _reject_unreviewed_values(item)
    elif isinstance(value, str):
        lowered = value.casefold()
        if (
            lowered == "default"
            or any(token in lowered for token in _SENTINELS)
            or "${" in value
            or "<" in value
        ):
            raise BetaPostgresqlDataPlaneError("spec contains an unreviewed default or sentinel")


def _cidrs(value: object, *, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise BetaPostgresqlDataPlaneError(f"{field} must contain explicit CIDRs")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise BetaPostgresqlDataPlaneError(f"{field} contains an invalid CIDR")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as error:
            raise BetaPostgresqlDataPlaneError(f"{field} contains an invalid CIDR") from error
        if (
            network.prefixlen == 0
            or network.is_unspecified
            or network.is_multicast
            or str(network) != item
        ):
            raise BetaPostgresqlDataPlaneError(f"{field} cannot contain a default route")
        result.append(item)
    if result != sorted(set(result)):
        raise BetaPostgresqlDataPlaneError(f"{field} must be unique and sorted")
    return result


def _validate_spec(document: object) -> Mapping[str, object]:
    _reject_unreviewed_values(document)
    top = _object(
        document,
        keys={
            "availability",
            "barman",
            "cert_manager",
            "cluster_name",
            "deployment_id",
            "kubernetes",
            "namespace",
            "network",
            "operator",
            "postgres",
            "restore_drill",
            "schema_version",
            "source_urls",
            "storage",
            "target_platform",
        },
        field="Beta PostgreSQL spec",
    )
    if isinstance(top["schema_version"], bool) or top["schema_version"] != 1:
        raise BetaPostgresqlDataPlaneError("schema_version must be 1")
    try:
        deployment_id = UUID(_string(top["deployment_id"], field="deployment_id"))
    except ValueError as error:
        raise BetaPostgresqlDataPlaneError("deployment_id must be a non-zero UUID") from error
    if deployment_id.int == 0 or str(deployment_id) != top["deployment_id"]:
        raise BetaPostgresqlDataPlaneError("deployment_id must be a canonical non-zero UUID")
    _name(top["namespace"], field="namespace")
    _name(top["cluster_name"], field="cluster_name")

    kubernetes = _object(top["kubernetes"], keys={"distribution", "version"}, field="kubernetes")
    if kubernetes != {"distribution": "k3s", "version": KUBERNETES_VERSION}:
        raise BetaPostgresqlDataPlaneError("kubernetes must be pinned to k3s 1.36")

    availability = _object(
        top["availability"],
        keys={
            "high_availability",
            "instances",
            "kubernetes_node_count",
            "physical_host_count",
        },
        field="availability",
    )
    if availability != {
        "high_availability": False,
        "instances": 1,
        "kubernetes_node_count": 3,
        "physical_host_count": 1,
    }:
        raise BetaPostgresqlDataPlaneError(
            "Beta availability must explicitly describe one non-HA instance on one host"
        )
    if top["target_platform"] != TARGET_PLATFORM:
        raise BetaPostgresqlDataPlaneError("target_platform must be exactly linux/amd64")

    operator = _object(
        top["operator"],
        keys={"image", "manifest_sha256", "manifest_url", "version"},
        field="operator",
    )
    if operator["version"] != CNPG_VERSION or operator["manifest_url"] != OPERATOR_MANIFEST_URL:
        raise BetaPostgresqlDataPlaneError("CloudNativePG source must be exactly v1.30.0")
    if operator["manifest_sha256"] != OPERATOR_MANIFEST_SHA256:
        raise BetaPostgresqlDataPlaneError("CloudNativePG manifest lock is invalid")
    operator_image = _image(
        operator["image"],
        repository="ghcr.io/cloudnative-pg/cloudnative-pg",
        tag_pattern=r"1\.30\.0",
        field="operator.image",
    )
    if operator_image != CNPG_OPERATOR_IMAGE:
        raise BetaPostgresqlDataPlaneError(
            "operator.image must be the reviewed linux/amd64 child manifest"
        )

    postgres = _object(
        top["postgres"],
        keys={
            "database",
            "image",
            "owner",
            "owner_secret",
            "server_ca_secret_name",
            "server_tls_secret_name",
            "version",
        },
        field="postgres",
    )
    if postgres["version"] != POSTGRESQL_VERSION:
        raise BetaPostgresqlDataPlaneError("PostgreSQL must be exactly 18.4")
    postgres_image = _image(
        postgres["image"],
        repository="ghcr.io/cloudnative-pg/postgresql",
        tag_pattern=r"18\.4-[A-Za-z0-9._-]+",
        field="postgres.image",
    )
    if postgres_image != POSTGRESQL_IMAGE:
        raise BetaPostgresqlDataPlaneError(
            "postgres.image must be the reviewed linux/amd64 child manifest"
        )
    _postgres_identifier(postgres["database"], field="postgres.database")
    _postgres_identifier(postgres["owner"], field="postgres.owner")
    _local_secret_reference(postgres["owner_secret"], field="postgres.owner_secret")
    _name(postgres["server_ca_secret_name"], field="postgres.server_ca_secret_name")
    _name(postgres["server_tls_secret_name"], field="postgres.server_tls_secret_name")

    barman = _object(
        top["barman"],
        keys={
            "access_key_secret",
            "backup_name",
            "destination_path",
            "endpoint_url",
            "manifest_sha256",
            "manifest_url",
            "object_store_name",
            "operator_image",
            "region_secret",
            "retention_policy",
            "schedule",
            "secret_key_secret",
            "sidecar_image",
            "version",
        },
        field="barman",
    )
    if barman["version"] != BARMAN_PLUGIN_VERSION or barman["manifest_url"] != BARMAN_MANIFEST_URL:
        raise BetaPostgresqlDataPlaneError("Barman Cloud Plugin must be exactly v0.14.0")
    if barman["manifest_sha256"] != BARMAN_MANIFEST_SHA256:
        raise BetaPostgresqlDataPlaneError("Barman manifest lock is invalid")
    barman_operator_image = _image(
        barman["operator_image"],
        repository="ghcr.io/cloudnative-pg/plugin-barman-cloud",
        tag_pattern=r"v0\.14\.0",
        field="barman.operator_image",
    )
    if barman_operator_image != BARMAN_OPERATOR_IMAGE:
        raise BetaPostgresqlDataPlaneError(
            "barman.operator_image must be the reviewed linux/amd64 child manifest"
        )
    barman_sidecar_image = _image(
        barman["sidecar_image"],
        repository="ghcr.io/cloudnative-pg/plugin-barman-cloud-sidecar",
        tag_pattern=r"v0\.14\.0",
        field="barman.sidecar_image",
    )
    if barman_sidecar_image != BARMAN_SIDECAR_IMAGE:
        raise BetaPostgresqlDataPlaneError(
            "barman.sidecar_image must be the reviewed linux/amd64 child manifest"
        )
    _name(barman["object_store_name"], field="barman.object_store_name")
    _name(barman["backup_name"], field="barman.backup_name")
    destination = urlsplit(_string(barman["destination_path"], field="barman.destination_path"))
    if (
        destination.scheme != "s3"
        or not destination.netloc
        or not destination.path.startswith("/")
        or destination.username is not None
        or destination.password is not None
        or destination.query
        or destination.fragment
    ):
        raise BetaPostgresqlDataPlaneError("barman.destination_path must be an explicit s3 path")
    endpoint = urlsplit(_string(barman["endpoint_url"], field="barman.endpoint_url"))
    try:
        endpoint_port = endpoint.port
    except ValueError as error:
        raise BetaPostgresqlDataPlaneError(
            "barman.endpoint_url must be credential-free HTTPS"
        ) from error
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint_port not in {None, 443}
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
    ):
        raise BetaPostgresqlDataPlaneError("barman.endpoint_url must be credential-free HTTPS")
    _secret_reference(barman["access_key_secret"], field="barman.access_key_secret")
    _secret_reference(barman["secret_key_secret"], field="barman.secret_key_secret")
    _secret_reference(barman["region_secret"], field="barman.region_secret")
    retention = _string(barman["retention_policy"], field="barman.retention_policy")
    matched_retention = re.fullmatch(r"([1-9][0-9]{0,2})d", retention)
    if matched_retention is None or not 7 <= int(matched_retention[1]) <= 365:
        raise BetaPostgresqlDataPlaneError("retention must be an owner-reviewed 7d..365d window")
    schedule = _string(barman["schedule"], field="barman.schedule")
    if re.fullmatch(r"0 (?:[0-5]?[0-9]) (?:[01]?[0-9]|2[0-3]) \* \* \*", schedule) is None:
        raise BetaPostgresqlDataPlaneError(
            "backup schedule must be one explicit daily six-field cron"
        )

    cert_manager = _object(
        top["cert_manager"],
        keys={
            "cainjector_image",
            "controller_image",
            "manifest_sha256",
            "manifest_url",
            "version",
            "webhook_image",
        },
        field="cert_manager",
    )
    if (
        cert_manager["version"] != CERT_MANAGER_VERSION
        or cert_manager["manifest_url"] != CERT_MANAGER_MANIFEST_URL
        or cert_manager["manifest_sha256"] != CERT_MANAGER_MANIFEST_SHA256
    ):
        raise BetaPostgresqlDataPlaneError("cert-manager source must be exactly v1.21.1")
    cert_manager_images = (
        (
            "controller_image",
            "quay.io/jetstack/cert-manager-controller",
            CERT_MANAGER_CONTROLLER_IMAGE,
        ),
        (
            "cainjector_image",
            "quay.io/jetstack/cert-manager-cainjector",
            CERT_MANAGER_CAINJECTOR_IMAGE,
        ),
        (
            "webhook_image",
            "quay.io/jetstack/cert-manager-webhook",
            CERT_MANAGER_WEBHOOK_IMAGE,
        ),
    )
    for key, repository, reviewed_image in cert_manager_images:
        image = _image(
            cert_manager[key],
            repository=repository,
            tag_pattern=r"v1\.21\.1",
            field=f"cert_manager.{key}",
        )
        if image != reviewed_image:
            raise BetaPostgresqlDataPlaneError(
                f"cert_manager.{key} must be the reviewed linux/amd64 child manifest"
            )

    storage = _object(
        top["storage"],
        keys={
            "class_name",
            "data_size",
            "parameters",
            "provisioner",
            "volume_binding_mode",
            "wal_size",
        },
        field="storage",
    )
    _name(storage["class_name"], field="storage.class_name")
    _string(storage["provisioner"], field="storage.provisioner")
    for size_field in ("data_size", "wal_size"):
        size = storage[size_field]
        if not isinstance(size, str) or _SIZE.fullmatch(size) is None:
            raise BetaPostgresqlDataPlaneError(f"storage.{size_field} is invalid")
    if storage["volume_binding_mode"] != "WaitForFirstConsumer":
        raise BetaPostgresqlDataPlaneError("storage must use WaitForFirstConsumer")
    parameters = storage["parameters"]
    if not isinstance(parameters, dict) or not all(
        isinstance(key, str)
        and isinstance(value, str)
        and 1 <= len(key) <= 253
        and 1 <= len(value) <= 253
        for key, value in parameters.items()
    ):
        raise BetaPostgresqlDataPlaneError("storage.parameters must be a string mapping")

    network = _object(
        top["network"],
        keys={
            "application_namespace",
            "application_pod_selector",
            "dns_namespace",
            "dns_pod_selector",
            "kubernetes_api_cidrs",
            "kubernetes_node_cidrs",
            "object_store_cidrs",
            "operator_namespace",
            "operator_pod_selector",
            "plugin_namespace",
            "plugin_pod_selector",
        },
        field="network",
    )
    for name_field in (
        "application_namespace",
        "dns_namespace",
        "operator_namespace",
        "plugin_namespace",
    ):
        _name(network[name_field], field=f"network.{name_field}")
    if (
        network["operator_namespace"] != "cnpg-system"
        or network["plugin_namespace"] != "cnpg-system"
    ):
        raise BetaPostgresqlDataPlaneError("operator and plugin must use cnpg-system")
    for selector_field in (
        "application_pod_selector",
        "dns_pod_selector",
        "operator_pod_selector",
        "plugin_pod_selector",
    ):
        _selector(network[selector_field], field=f"network.{selector_field}")
    for cidr_field in (
        "kubernetes_api_cidrs",
        "kubernetes_node_cidrs",
        "object_store_cidrs",
    ):
        _cidrs(network[cidr_field], field=f"network.{cidr_field}")

    restore = _object(
        top["restore_drill"],
        keys={"cluster_name", "namespace", "source_server_name", "target_time"},
        field="restore_drill",
    )
    restore_namespace = _name(restore["namespace"], field="restore_drill.namespace")
    _name(restore["cluster_name"], field="restore_drill.cluster_name")
    _name(restore["source_server_name"], field="restore_drill.source_server_name")
    if restore_namespace == top["namespace"]:
        raise BetaPostgresqlDataPlaneError("restore drill must use an isolated namespace")
    target_time = _string(restore["target_time"], field="restore_drill.target_time")
    try:
        parsed_target = datetime.fromisoformat(target_time.replace("Z", "+00:00"))
    except ValueError as error:
        raise BetaPostgresqlDataPlaneError("restore target_time must be RFC3339") from error
    if not target_time.endswith("Z") or parsed_target.tzinfo is None:
        raise BetaPostgresqlDataPlaneError("restore target_time must be UTC RFC3339")

    urls = top["source_urls"]
    if not isinstance(urls, list) or tuple(urls) != SOURCE_URLS:
        raise BetaPostgresqlDataPlaneError(
            "source_urls must exactly match the reviewed primary sources"
        )
    return top


def load_beta_postgresql_data_plane_spec(path: Path | str) -> BetaPostgresqlDataPlaneSpec:
    """Load a stable, owner-only, canonical JSON release authority."""

    raw = _read_stable_file(
        Path(path), maximum=_MAX_SPEC_BYTES, field="Beta PostgreSQL spec", owner_only=True
    )
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BetaPostgresqlDataPlaneError("Beta PostgreSQL spec is invalid JSON") from error
    if raw != _canonical_json(document):
        raise BetaPostgresqlDataPlaneError("Beta PostgreSQL spec must be canonical JSON")
    return BetaPostgresqlDataPlaneSpec(
        document=_validate_spec(document),
        sha256=_sha256(raw),
    )


def _namespace_selector(name: str) -> dict[str, object]:
    return {"matchLabels": {"kubernetes.io/metadata.name": name}}


def _peer(namespace: str, labels: Mapping[str, str]) -> dict[str, object]:
    return {
        "namespaceSelector": _namespace_selector(namespace),
        "podSelector": {"matchLabels": dict(labels)},
    }


def _cidr_peers(cidrs: Sequence[str]) -> list[dict[str, object]]:
    return [{"ipBlock": {"cidr": cidr}} for cidr in cidrs]


def _network_policy(
    *,
    name: str,
    namespace: str,
    pod_selector: Mapping[str, str],
    ingress: Sequence[Mapping[str, object]],
    egress: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": dict(pod_selector)},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": list(ingress),
            "egress": list(egress),
        },
    }


def _dns_egress(namespace: str, labels: Mapping[str, str]) -> dict[str, object]:
    return {
        "to": [_peer(namespace, labels)],
        "ports": [
            {"port": 53, "protocol": "UDP"},
            {"port": 53, "protocol": "TCP"},
        ],
    }


def _api_egress(cidrs: Sequence[str]) -> dict[str, object]:
    return {
        "to": _cidr_peers(cidrs),
        "ports": [{"port": 443, "protocol": "TCP"}],
    }


def _object_store(document: Mapping[str, object], *, namespace: str) -> dict[str, object]:
    barman = cast(Mapping[str, object], document["barman"])
    return {
        "apiVersion": "barmancloud.cnpg.io/v1",
        "kind": "ObjectStore",
        "metadata": {
            "name": barman["object_store_name"],
            "namespace": namespace,
            "annotations": {"argocd.argoproj.io/sync-options": "Prune=false"},
        },
        "spec": {
            "configuration": {
                "destinationPath": barman["destination_path"],
                "endpointURL": barman["endpoint_url"],
                "s3Credentials": {
                    "accessKeyId": barman["access_key_secret"],
                    "secretAccessKey": barman["secret_key_secret"],
                    "region": barman["region_secret"],
                },
                "data": {"compression": "gzip"},
                "wal": {"compression": "gzip"},
            },
            "retentionPolicy": barman["retention_policy"],
        },
    }


def _cluster(
    document: Mapping[str, object],
    *,
    namespace: str,
    cluster_name: str,
    recovery: bool,
) -> dict[str, object]:
    postgres = cast(Mapping[str, object], document["postgres"])
    barman = cast(Mapping[str, object], document["barman"])
    storage = cast(Mapping[str, object], document["storage"])
    spec: dict[str, object] = {
        "instances": 1,
        "imageName": postgres["image"],
        "imagePullPolicy": "IfNotPresent",
        "enableSuperuserAccess": False,
        "primaryUpdateStrategy": "unsupervised",
        "postgresql": {
            "parameters": {
                "max_notify_queue_pages": "64",
                "max_prepared_transactions": "0",
                "ssl_min_protocol_version": "TLSv1.3",
            }
        },
        "certificates": {
            "serverCASecret": postgres["server_ca_secret_name"],
            "serverTLSSecret": postgres["server_tls_secret_name"],
        },
        "storage": {
            "storageClass": storage["class_name"],
            "size": storage["data_size"],
        },
        "walStorage": {
            "storageClass": storage["class_name"],
            "size": storage["wal_size"],
        },
    }
    if recovery:
        restore = cast(Mapping[str, object], document["restore_drill"])
        spec["bootstrap"] = {
            "recovery": {
                "source": "reviewed-object-store-source",
                "recoveryTarget": {"targetTime": restore["target_time"]},
            }
        }
        spec["externalClusters"] = [
            {
                "name": "reviewed-object-store-source",
                "plugin": {
                    "name": CNPG_PLUGIN_NAME,
                    "parameters": {
                        "barmanObjectName": barman["object_store_name"],
                        "serverName": restore["source_server_name"],
                    },
                },
            }
        ]
    else:
        spec["bootstrap"] = {
            "initdb": {
                "database": postgres["database"],
                "owner": postgres["owner"],
                "secret": {"name": cast(Mapping[str, object], postgres["owner_secret"])["name"]},
                "dataChecksums": True,
                "encoding": "UTF8",
            }
        }
        spec["plugins"] = [
            {
                "name": CNPG_PLUGIN_NAME,
                "isWALArchiver": True,
                "parameters": {"barmanObjectName": barman["object_store_name"]},
            }
        ]
    annotations = {
        "argocd.argoproj.io/sync-options": "Prune=false",
        "omnigent.ai/availability": "single-instance-non-ha",
        "omnigent.ai/physical-host-count": "1",
    }
    if recovery:
        annotations["omnigent.ai/restore-drill-wal-archive"] = "disabled-to-protect-source"
    return {
        "apiVersion": "postgresql.cnpg.io/v1",
        "kind": "Cluster",
        "metadata": {
            "name": cluster_name,
            "namespace": namespace,
            "annotations": annotations,
        },
        "spec": spec,
    }


def _desired_state_documents(
    spec: BetaPostgresqlDataPlaneSpec,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    document = spec.document
    namespace = cast(str, document["namespace"])
    cluster_name = cast(str, document["cluster_name"])
    restore = cast(Mapping[str, object], document["restore_drill"])
    restore_namespace = cast(str, restore["namespace"])
    restore_cluster = cast(str, restore["cluster_name"])
    storage = cast(Mapping[str, object], document["storage"])
    barman = cast(Mapping[str, object], document["barman"])
    network = cast(Mapping[str, object], document["network"])
    operator_namespace = cast(str, network["operator_namespace"])
    plugin_namespace = cast(str, network["plugin_namespace"])
    operator_selector = cast(Mapping[str, str], network["operator_pod_selector"])
    plugin_selector = cast(Mapping[str, str], network["plugin_pod_selector"])
    dns_namespace = cast(str, network["dns_namespace"])
    dns_selector = cast(Mapping[str, str], network["dns_pod_selector"])
    app_namespace = cast(str, network["application_namespace"])
    app_selector = cast(Mapping[str, str], network["application_pod_selector"])
    api_cidrs = cast(list[str], network["kubernetes_api_cidrs"])
    node_cidrs = cast(list[str], network["kubernetes_node_cidrs"])
    object_store_cidrs = cast(list[str], network["object_store_cidrs"])
    data_labels = {"cnpg.io/cluster": cluster_name}
    restore_labels = {"cnpg.io/cluster": restore_cluster}
    protect = {
        "argocd.argoproj.io/sync-options": "Prune=false",
        "omnigent.ai/deletion-policy": "owner-approved-only",
    }

    primary_documents: list[dict[str, object]] = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": namespace, "annotations": protect},
        },
        {
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": {"name": storage["class_name"], "annotations": protect},
            "provisioner": storage["provisioner"],
            "parameters": storage["parameters"],
            "reclaimPolicy": "Retain",
            "allowVolumeExpansion": True,
            "volumeBindingMode": "WaitForFirstConsumer",
        },
        _object_store(document, namespace=namespace),
        _cluster(
            document,
            namespace=namespace,
            cluster_name=cluster_name,
            recovery=False,
        ),
        {
            "apiVersion": "postgresql.cnpg.io/v1",
            "kind": "ScheduledBackup",
            "metadata": {
                "name": barman["backup_name"],
                "namespace": namespace,
                "annotations": {"argocd.argoproj.io/sync-options": "Prune=false"},
            },
            "spec": {
                "schedule": barman["schedule"],
                "backupOwnerReference": "none",
                "cluster": {"name": cluster_name},
                "method": "plugin",
                "pluginConfiguration": {"name": CNPG_PLUGIN_NAME},
                "immediate": True,
                "suspend": False,
            },
        },
    ]
    restore_documents: list[dict[str, object]] = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": restore_namespace, "annotations": protect},
        },
        _object_store(document, namespace=restore_namespace),
        _cluster(
            document,
            namespace=restore_namespace,
            cluster_name=restore_cluster,
            recovery=True,
        ),
    ]

    for policy_namespace in (namespace, operator_namespace):
        primary_documents.append(
            _network_policy(
                name="default-deny-ingress-egress",
                namespace=policy_namespace,
                pod_selector={},
                ingress=[],
                egress=[],
            )
        )
    restore_documents.append(
        _network_policy(
            name="default-deny-ingress-egress",
            namespace=restore_namespace,
            pod_selector={},
            ingress=[],
            egress=[],
        )
    )

    data_ingress: list[Mapping[str, object]] = [
        {
            "from": [_peer(operator_namespace, operator_selector)],
            "ports": [
                {"port": 5432, "protocol": "TCP"},
                {"port": 8000, "protocol": "TCP"},
            ],
        },
        {
            "from": [_peer(app_namespace, app_selector)],
            "ports": [{"port": 5432, "protocol": "TCP"}],
        },
        {
            "from": [_peer(namespace, data_labels)],
            "ports": [{"port": 5432, "protocol": "TCP"}],
        },
        {
            "from": _cidr_peers(node_cidrs),
            "ports": [{"port": 8000, "protocol": "TCP"}],
        },
    ]
    data_egress: list[Mapping[str, object]] = [
        _dns_egress(dns_namespace, dns_selector),
        _api_egress(api_cidrs),
        {
            "to": [_peer(plugin_namespace, plugin_selector)],
            "ports": [{"port": 9090, "protocol": "TCP"}],
        },
        {
            "to": _cidr_peers(object_store_cidrs),
            "ports": [{"port": 443, "protocol": "TCP"}],
        },
        {
            "to": [_peer(namespace, data_labels)],
            "ports": [{"port": 5432, "protocol": "TCP"}],
        },
    ]
    primary_documents.append(
        _network_policy(
            name="allow-reviewed-postgresql-paths",
            namespace=namespace,
            pod_selector=data_labels,
            ingress=data_ingress,
            egress=data_egress,
        )
    )

    restore_ingress: list[Mapping[str, object]] = [
        {
            "from": [_peer(operator_namespace, operator_selector)],
            "ports": [
                {"port": 5432, "protocol": "TCP"},
                {"port": 8000, "protocol": "TCP"},
            ],
        },
        {
            "from": _cidr_peers(node_cidrs),
            "ports": [{"port": 8000, "protocol": "TCP"}],
        },
    ]
    restore_egress: list[Mapping[str, object]] = [
        _dns_egress(dns_namespace, dns_selector),
        _api_egress(api_cidrs),
        {
            "to": [_peer(plugin_namespace, plugin_selector)],
            "ports": [{"port": 9090, "protocol": "TCP"}],
        },
        {
            "to": _cidr_peers(object_store_cidrs),
            "ports": [{"port": 443, "protocol": "TCP"}],
        },
    ]
    restore_documents.append(
        _network_policy(
            name="allow-reviewed-restore-paths",
            namespace=restore_namespace,
            pod_selector=restore_labels,
            ingress=restore_ingress,
            egress=restore_egress,
        )
    )

    operator_ingress = [
        {
            "from": _cidr_peers(sorted(set(api_cidrs + node_cidrs))),
            "ports": [{"port": 9443, "protocol": "TCP"}],
        }
    ]
    operator_egress: list[Mapping[str, object]] = [
        _dns_egress(dns_namespace, dns_selector),
        _api_egress(api_cidrs),
        {
            "to": [_peer(namespace, data_labels)],
            "ports": [
                {"port": 5432, "protocol": "TCP"},
                {"port": 8000, "protocol": "TCP"},
            ],
        },
        {
            "to": [_peer(plugin_namespace, plugin_selector)],
            "ports": [{"port": 9090, "protocol": "TCP"}],
        },
    ]
    primary_documents.append(
        _network_policy(
            name="allow-cnpg-webhook-and-reconciliation",
            namespace=operator_namespace,
            pod_selector=operator_selector,
            ingress=operator_ingress,
            egress=operator_egress,
        )
    )

    plugin_ingress = [
        {
            "from": [_peer(operator_namespace, operator_selector)],
            "ports": [{"port": 9090, "protocol": "TCP"}],
        },
        {
            "from": [_peer(namespace, data_labels)],
            "ports": [{"port": 9090, "protocol": "TCP"}],
        },
        {
            "from": _cidr_peers(node_cidrs),
            "ports": [{"port": 9090, "protocol": "TCP"}],
        },
    ]
    primary_documents.append(
        _network_policy(
            name="allow-barman-plugin-api",
            namespace=plugin_namespace,
            pod_selector=plugin_selector,
            ingress=plugin_ingress,
            egress=[_dns_egress(dns_namespace, dns_selector), _api_egress(api_cidrs)],
        )
    )
    restore_documents.extend(
        [
            _network_policy(
                name="allow-cnpg-restore-reconciliation",
                namespace=operator_namespace,
                pod_selector=operator_selector,
                ingress=[],
                egress=[
                    {
                        "to": [_peer(restore_namespace, restore_labels)],
                        "ports": [
                            {"port": 5432, "protocol": "TCP"},
                            {"port": 8000, "protocol": "TCP"},
                        ],
                    }
                ],
            ),
            _network_policy(
                name="allow-barman-restore-api",
                namespace=plugin_namespace,
                pod_selector=plugin_selector,
                ingress=[
                    {
                        "from": [_peer(restore_namespace, restore_labels)],
                        "ports": [{"port": 9090, "protocol": "TCP"}],
                    }
                ],
                egress=[],
            ),
        ]
    )

    def apply_order(item: Mapping[str, object]) -> tuple[int, str, str]:
        metadata = cast(Mapping[str, object], item["metadata"])
        kind = cast(str, item["kind"])
        name = cast(str, metadata["name"])
        if kind == "Namespace":
            weight = 0
        elif kind == "StorageClass":
            weight = 1
        elif kind == "NetworkPolicy" and name == "default-deny-ingress-egress":
            weight = 2
        elif kind == "NetworkPolicy":
            weight = 3
        elif kind == "ObjectStore":
            weight = 4
        elif kind == "Cluster":
            weight = 5
        else:
            weight = 6
        return weight, kind, name

    primary_documents.sort(key=apply_order)
    restore_documents.sort(key=apply_order)
    return primary_documents, restore_documents


def restore_drill_evidence_schema() -> dict[str, object]:
    """Return the strict evidence contract; this does not claim a drill ran."""

    digest = {"type": "string", "pattern": "^(?!0{64}$)[0-9a-f]{64}$"}
    nonzero_uuid = {
        "type": "string",
        "format": "uuid",
        "pattern": (
            "^(?!00000000-0000-0000-0000-000000000000$)"
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    }
    utc_timestamp = {
        "type": "string",
        "format": "date-time",
        "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?Z$",
    }
    check_names = (
        "database_owner_verified",
        "pitr_target_reached",
        "source_store_read_only",
        "wal_replay_verified",
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:omnigent:beta-postgresql:restore-drill-evidence:v1",
        "title": "Beta PostgreSQL restore drill evidence",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "bundle_sha256",
            "checks",
            "completed_at",
            "deployment_id",
            "execution_status",
            "recovery_target_time",
            "restored_cluster_uid",
            "schema_version",
            "source_backup_uid",
            "spec_sha256",
            "started_at",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "deployment_id": nonzero_uuid,
            "execution_status": {"enum": ["pass", "fail"]},
            "spec_sha256": digest,
            "bundle_sha256": digest,
            "started_at": utc_timestamp,
            "completed_at": utc_timestamp,
            "recovery_target_time": utc_timestamp,
            "source_backup_uid": nonzero_uuid,
            "restored_cluster_uid": nonzero_uuid,
            "failure_code": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9_]{0,63}$",
            },
            "failure_detail_sha256": digest,
            "checks": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "data_validation_sha256",
                    "database_owner_verified",
                    "pitr_target_reached",
                    "source_store_read_only",
                    "wal_replay_verified",
                ],
                "properties": {
                    "data_validation_sha256": digest,
                    "database_owner_verified": {"type": "boolean"},
                    "pitr_target_reached": {"type": "boolean"},
                    "source_store_read_only": {"type": "boolean"},
                    "wal_replay_verified": {"type": "boolean"},
                },
            },
        },
        "allOf": [
            {
                "if": {
                    "properties": {"execution_status": {"const": "pass"}},
                    "required": ["execution_status"],
                },
                "then": {
                    "properties": {
                        "checks": {"properties": {name: {"const": True} for name in check_names}}
                    },
                    "not": {
                        "anyOf": [
                            {"required": ["failure_code"]},
                            {"required": ["failure_detail_sha256"]},
                        ]
                    },
                },
                "else": {
                    "required": ["failure_code", "failure_detail_sha256"],
                    "properties": {
                        "checks": {
                            "anyOf": [
                                {
                                    "properties": {name: {"const": False}},
                                    "required": [name],
                                }
                                for name in check_names
                            ]
                        }
                    },
                },
            }
        ],
    }


def _nonzero_uuid(value: object, *, field: str) -> str:
    result = _string(value, field=field, maximum=36)
    try:
        parsed = UUID(result)
    except ValueError as error:
        raise BetaPostgresqlDataPlaneError(f"{field} must be a canonical non-zero UUID") from error
    if parsed.int == 0 or str(parsed) != result:
        raise BetaPostgresqlDataPlaneError(f"{field} must be a canonical non-zero UUID")
    return result


def _utc_timestamp(value: object, *, field: str) -> tuple[str, datetime]:
    result = _string(value, field=field, maximum=64)
    if _RFC3339_UTC.fullmatch(result) is None:
        raise BetaPostgresqlDataPlaneError(f"{field} must be canonical UTC RFC3339")
    try:
        parsed = datetime.fromisoformat(result.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise BetaPostgresqlDataPlaneError(f"{field} must be canonical UTC RFC3339") from error
    if parsed.tzinfo != timezone.utc:
        raise BetaPostgresqlDataPlaneError(f"{field} must be canonical UTC RFC3339")
    return result, parsed


def admit_restore_drill_evidence(
    path: Path | str,
    *,
    expected_deployment_id: str,
    expected_spec_sha256: str,
    expected_bundle_sha256: str,
    expected_recovery_target_time: str,
) -> AdmittedRestoreDrillEvidence:
    """Load canonical evidence and bind it to one exact rendered restore release."""

    expected_deployment = _nonzero_uuid(expected_deployment_id, field="expected_deployment_id")
    expected_spec = _digest(expected_spec_sha256, field="expected_spec_sha256")
    expected_bundle = _digest(expected_bundle_sha256, field="expected_bundle_sha256")
    expected_target, expected_target_time = _utc_timestamp(
        expected_recovery_target_time,
        field="expected_recovery_target_time",
    )
    raw = _read_stable_file(
        Path(path),
        maximum=_MAX_EVIDENCE_BYTES,
        field="restore drill evidence",
        owner_only=True,
    )
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BetaPostgresqlDataPlaneError("restore drill evidence is invalid JSON") from error
    if raw != _canonical_json(document):
        raise BetaPostgresqlDataPlaneError("restore drill evidence must be canonical JSON")
    if not isinstance(document, dict):
        raise BetaPostgresqlDataPlaneError("restore drill evidence has an invalid shape")
    status = document.get("execution_status")
    common_keys = {
        "bundle_sha256",
        "checks",
        "completed_at",
        "deployment_id",
        "execution_status",
        "recovery_target_time",
        "restored_cluster_uid",
        "schema_version",
        "source_backup_uid",
        "spec_sha256",
        "started_at",
    }
    if status == "pass":
        evidence = _object(document, keys=common_keys, field="restore drill evidence")
    elif status == "fail":
        evidence = _object(
            document,
            keys=common_keys | {"failure_code", "failure_detail_sha256"},
            field="restore drill evidence",
        )
    else:
        raise BetaPostgresqlDataPlaneError("execution_status must be pass or fail")
    if isinstance(evidence["schema_version"], bool) or evidence["schema_version"] != 1:
        raise BetaPostgresqlDataPlaneError("restore drill evidence schema_version must be 1")
    deployment_id = _nonzero_uuid(evidence["deployment_id"], field="deployment_id")
    spec_sha256 = _digest(evidence["spec_sha256"], field="spec_sha256")
    bundle_sha256 = _digest(evidence["bundle_sha256"], field="bundle_sha256")
    if (
        deployment_id != expected_deployment
        or spec_sha256 != expected_spec
        or bundle_sha256 != expected_bundle
    ):
        raise BetaPostgresqlDataPlaneError("restore drill evidence release binding drifted")
    recovery_target, recovery_target_time = _utc_timestamp(
        evidence["recovery_target_time"], field="recovery_target_time"
    )
    started_at, started_time = _utc_timestamp(evidence["started_at"], field="started_at")
    completed_at, completed_time = _utc_timestamp(evidence["completed_at"], field="completed_at")
    if recovery_target != expected_target or not (
        recovery_target_time == expected_target_time <= started_time <= completed_time
    ):
        raise BetaPostgresqlDataPlaneError("restore drill evidence time binding drifted")
    source_backup_uid = _nonzero_uuid(evidence["source_backup_uid"], field="source_backup_uid")
    restored_cluster_uid = _nonzero_uuid(
        evidence["restored_cluster_uid"], field="restored_cluster_uid"
    )
    checks = _object(
        evidence["checks"],
        keys={
            "data_validation_sha256",
            "database_owner_verified",
            "pitr_target_reached",
            "source_store_read_only",
            "wal_replay_verified",
        },
        field="checks",
    )
    data_validation_sha256 = _digest(
        checks["data_validation_sha256"], field="checks.data_validation_sha256"
    )
    boolean_names = (
        "database_owner_verified",
        "pitr_target_reached",
        "source_store_read_only",
        "wal_replay_verified",
    )
    for name in boolean_names:
        if not isinstance(checks[name], bool):
            raise BetaPostgresqlDataPlaneError(f"checks.{name} must be boolean")
    check_values = [cast(bool, checks[name]) for name in boolean_names]
    failure_code: str | None = None
    failure_detail_sha256: str | None = None
    if status == "pass":
        if not all(check_values):
            raise BetaPostgresqlDataPlaneError("pass evidence requires every execution check")
    else:
        if all(check_values):
            raise BetaPostgresqlDataPlaneError("fail evidence requires at least one failed check")
        failure_code = _string(evidence["failure_code"], field="failure_code", maximum=64)
        if _FAILURE_CODE.fullmatch(failure_code) is None:
            raise BetaPostgresqlDataPlaneError("failure_code is invalid")
        failure_detail_sha256 = _digest(
            evidence["failure_detail_sha256"], field="failure_detail_sha256"
        )
    return AdmittedRestoreDrillEvidence(
        evidence_sha256=_sha256(raw),
        deployment_id=deployment_id,
        execution_status=cast(str, status),
        spec_sha256=spec_sha256,
        bundle_sha256=bundle_sha256,
        recovery_target_time=recovery_target,
        started_at=started_at,
        completed_at=completed_at,
        source_backup_uid=source_backup_uid,
        restored_cluster_uid=restored_cluster_uid,
        data_validation_sha256=data_validation_sha256,
        database_owner_verified=cast(bool, checks["database_owner_verified"]),
        pitr_target_reached=cast(bool, checks["pitr_target_reached"]),
        source_store_read_only=cast(bool, checks["source_store_read_only"]),
        wal_replay_verified=cast(bool, checks["wal_replay_verified"]),
        failure_code=failure_code,
        failure_detail_sha256=failure_detail_sha256,
    )


def _load_manifest(path: Path, expected_sha256: str, field: str) -> list[dict[str, object]]:
    raw = _read_stable_file(path, maximum=_MAX_SOURCE_BYTES, field=field, owner_only=False)
    if _sha256(raw) != expected_sha256:
        raise BetaPostgresqlDataPlaneError(f"{field} SHA-256 does not match the owner lock")
    try:
        parsed = list(yaml.safe_load_all(raw.decode("utf-8")))
    except (UnicodeError, yaml.YAMLError) as error:
        raise BetaPostgresqlDataPlaneError(f"{field} is not safe YAML") from error
    if not 1 <= len(parsed) <= _MAX_DOCUMENTS:
        raise BetaPostgresqlDataPlaneError(f"{field} has an invalid document count")
    documents: list[dict[str, object]] = []
    identities: set[tuple[str, str, str]] = set()
    for value in parsed:
        if not isinstance(value, dict):
            raise BetaPostgresqlDataPlaneError(f"{field} contains a non-object document")
        document = cast(dict[str, object], value)
        metadata = document.get("metadata")
        if not isinstance(document.get("kind"), str) or not isinstance(metadata, dict):
            raise BetaPostgresqlDataPlaneError(f"{field} contains an unidentified resource")
        name = metadata.get("name")
        namespace = metadata.get("namespace", "")
        if not isinstance(name, str) or not isinstance(namespace, str):
            raise BetaPostgresqlDataPlaneError(f"{field} contains an unidentified resource")
        identity = (document["kind"], namespace, name)
        if identity in identities:
            raise BetaPostgresqlDataPlaneError(f"{field} contains a duplicate resource")
        identities.add(identity)
        documents.append(document)
    return documents


def _deployment_container(
    document: dict[str, object], *, container_name: str, field: str
) -> dict[str, object]:
    try:
        spec = cast(dict[str, object], document["spec"])
        template = cast(dict[str, object], spec["template"])
        pod_spec = cast(dict[str, object], template["spec"])
        containers = cast(list[object], pod_spec["containers"])
    except (KeyError, TypeError) as error:
        raise BetaPostgresqlDataPlaneError(f"{field} Deployment is malformed") from error
    matches = [
        cast(dict[str, object], item)
        for item in containers
        if isinstance(item, dict) and item.get("name") == container_name
    ]
    if len(matches) != 1:
        raise BetaPostgresqlDataPlaneError(f"{field} container identity drifted")
    return matches[0]


def _pin_cert_manager_manifest(
    documents: list[dict[str, object]],
    *,
    controller_image: str,
    cainjector_image: str,
    webhook_image: str,
) -> list[dict[str, object]]:
    expected = {
        ("cert-manager", "cert-manager"): (
            "cert-manager-controller",
            "quay.io/jetstack/cert-manager-controller:v1.21.1",
            controller_image,
        ),
        ("cert-manager", "cert-manager-cainjector"): (
            "cert-manager-cainjector",
            "quay.io/jetstack/cert-manager-cainjector:v1.21.1",
            cainjector_image,
        ),
        ("cert-manager", "cert-manager-webhook"): (
            "cert-manager-webhook",
            "quay.io/jetstack/cert-manager-webhook:v1.21.1",
            webhook_image,
        ),
    }
    if any(item.get("kind") == "Secret" for item in documents):
        raise BetaPostgresqlDataPlaneError("cert-manager source cannot contain Secret resources")
    workload_kinds = {"CronJob", "DaemonSet", "Deployment", "Job", "Pod", "StatefulSet"}
    workloads = [item for item in documents if item.get("kind") in workload_kinds]
    deployments: dict[tuple[str, str], dict[str, object]] = {}
    source_images: list[tuple[str, str, str, str]] = []

    def collect_images(value: object, *, kind: str, namespace: str, name: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "image" and isinstance(item, str):
                    source_images.append((kind, namespace, name, item))
                collect_images(item, kind=kind, namespace=namespace, name=name)
        elif isinstance(value, list):
            for item in value:
                collect_images(item, kind=kind, namespace=namespace, name=name)

    for item in documents:
        metadata = cast(Mapping[str, object], item["metadata"])
        kind = cast(str, item["kind"])
        namespace = cast(str, metadata.get("namespace", ""))
        name = cast(str, metadata["name"])
        collect_images(item, kind=kind, namespace=namespace, name=name)
        if kind == "Deployment":
            deployments[(namespace, name)] = item
    if set(deployments) != set(expected) or len(workloads) != len(expected):
        raise BetaPostgresqlDataPlaneError("cert-manager workload inventory drifted")
    expected_source_images = sorted(
        ("Deployment", namespace, name, source_image)
        for (namespace, name), (_, source_image, _) in expected.items()
    )
    if sorted(source_images) != expected_source_images:
        raise BetaPostgresqlDataPlaneError("cert-manager source image inventory drifted")
    for identity, (container_name, source_image, pinned_image) in expected.items():
        deployment = deployments[identity]
        container = _deployment_container(
            deployment,
            container_name=container_name,
            field=f"cert-manager {identity[1]}",
        )
        try:
            pod_spec = cast(
                dict[str, object],
                cast(dict[str, object], cast(dict[str, object], deployment["spec"])["template"])[
                    "spec"
                ],
            )
            containers = cast(list[object], pod_spec["containers"])
        except (KeyError, TypeError) as error:
            raise BetaPostgresqlDataPlaneError("cert-manager Deployment is malformed") from error
        if (
            len(containers) != 1
            or pod_spec.get("initContainers") is not None
            or pod_spec.get("ephemeralContainers") is not None
            or container.get("image") != source_image
        ):
            raise BetaPostgresqlDataPlaneError("cert-manager container inventory drifted")
        container["image"] = pinned_image
        container["imagePullPolicy"] = "IfNotPresent"
    return documents


def _pin_operator_manifest(
    documents: list[dict[str, object]], image: str
) -> list[dict[str, object]]:
    deployments = [
        item
        for item in documents
        if item.get("kind") == "Deployment"
        and cast(Mapping[str, object], item["metadata"]).get("name") == "cnpg-controller-manager"
    ]
    if len(deployments) != 1 or any(item.get("kind") == "Secret" for item in documents):
        raise BetaPostgresqlDataPlaneError("CloudNativePG operator source identity drifted")
    container = _deployment_container(
        deployments[0], container_name="manager", field="CloudNativePG operator"
    )
    if container.get("image") != "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0":
        raise BetaPostgresqlDataPlaneError("CloudNativePG operator source image drifted")
    container["image"] = image
    environment = container.get("env")
    if not isinstance(environment, list):
        raise BetaPostgresqlDataPlaneError("CloudNativePG operator environment drifted")
    image_environment = [
        item
        for item in environment
        if isinstance(item, dict) and item.get("name") == "OPERATOR_IMAGE_NAME"
    ]
    if len(image_environment) != 1 or image_environment[0].get("value") != (
        "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0"
    ):
        raise BetaPostgresqlDataPlaneError("CloudNativePG operator image authority drifted")
    image_environment[0]["value"] = image
    return documents


def _pin_plugin_manifest(
    documents: list[dict[str, object]], *, operator_image: str, sidecar_image: str
) -> list[dict[str, object]]:
    secrets = [item for item in documents if item.get("kind") == "Secret"]
    if len(secrets) != 1:
        raise BetaPostgresqlDataPlaneError("Barman plugin source Secret identity drifted")
    secret = secrets[0]
    metadata = cast(Mapping[str, object], secret["metadata"])
    data = secret.get("data")
    if (
        metadata.get("namespace") != "cnpg-system"
        or not isinstance(metadata.get("name"), str)
        or not isinstance(data, dict)
        or set(data) != {"SIDECAR_IMAGE"}
    ):
        raise BetaPostgresqlDataPlaneError("Barman plugin source contains an unexpected Secret")
    secret_name = cast(str, metadata["name"])
    documents = [item for item in documents if item is not secret]
    deployments = [
        item
        for item in documents
        if item.get("kind") == "Deployment"
        and cast(Mapping[str, object], item["metadata"]).get("name") == "barman-cloud"
    ]
    if len(deployments) != 1:
        raise BetaPostgresqlDataPlaneError("Barman plugin Deployment identity drifted")
    container = _deployment_container(
        deployments[0], container_name="barman-cloud", field="Barman plugin"
    )
    if container.get("image") != "ghcr.io/cloudnative-pg/plugin-barman-cloud:v0.14.0":
        raise BetaPostgresqlDataPlaneError("Barman plugin source image drifted")
    container["image"] = operator_image
    container["imagePullPolicy"] = "IfNotPresent"
    environment = container.get("env")
    if not isinstance(environment, list):
        raise BetaPostgresqlDataPlaneError("Barman plugin environment drifted")
    matches = [
        item
        for item in environment
        if isinstance(item, dict) and item.get("name") == "SIDECAR_IMAGE"
    ]
    expected_reference = {"secretKeyRef": {"key": "SIDECAR_IMAGE", "name": secret_name}}
    if len(matches) != 1 or matches[0].get("valueFrom") != expected_reference:
        raise BetaPostgresqlDataPlaneError("Barman sidecar image authority drifted")
    matches[0].pop("valueFrom")
    matches[0]["value"] = sidecar_image
    return documents


def _yaml_bytes(document: Mapping[str, object]) -> bytes:
    raw = yaml.safe_dump(
        dict(document),
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
        width=1000,
    ).encode("ascii")
    if len(raw) > _MAX_GITOPS_FILE_BYTES:
        raise BetaPostgresqlDataPlaneError("one rendered GitOps resource exceeds 1 MiB")
    return raw


def _resource_filename(index: int, document: Mapping[str, object]) -> str:
    metadata = cast(Mapping[str, object], document["metadata"])
    kind = _SAFE_FILE_COMPONENT.sub("-", cast(str, document["kind"]).casefold()).strip("-")
    name = _SAFE_FILE_COMPONENT.sub("-", cast(str, metadata["name"]).casefold()).strip("-")
    return f"{index:03d}-{kind}-{name}.yaml"


def _write_file(root: Path, relative: str, raw: bytes) -> None:
    if len(raw) > _MAX_GITOPS_FILE_BYTES:
        raise BetaPostgresqlDataPlaneError(f"{relative} exceeds 1 MiB")
    target = root / relative
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_parent(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise BetaPostgresqlDataPlaneError("output directory must be an explicit absolute path")
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise BetaPostgresqlDataPlaneError("output parent cannot be inspected") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise BetaPostgresqlDataPlaneError("output parent must be owner-controlled")
    if path.exists() or path.is_symlink():
        raise BetaPostgresqlDataPlaneError("output directory must not already exist")
    return parent


def _source_lock(spec: BetaPostgresqlDataPlaneSpec) -> dict[str, object]:
    document = spec.document
    return {
        "schema_version": 1,
        "deployment_id": document["deployment_id"],
        "spec_sha256": spec.sha256,
        "compatibility": {
            "distribution": "k3s",
            "kubernetes": KUBERNETES_VERSION,
            "cloudnativepg": CNPG_VERSION,
            "postgresql": POSTGRESQL_VERSION,
            "barman_cloud_plugin": BARMAN_PLUGIN_VERSION,
            "cert_manager": CERT_MANAGER_VERSION,
        },
        "target_platform": document["target_platform"],
        "image_authority": {
            "digest_scope": "platform-child-manifest",
            "remote_registry_verified_during_render": False,
        },
        "availability": {
            "instances": 1,
            "high_availability": False,
            "physical_host_count": 1,
            "statement": "single instance; three Kubernetes nodes share one physical host",
        },
        "operator": document["operator"],
        "cert_manager": document["cert_manager"],
        "postgres_image": cast(Mapping[str, object], document["postgres"])["image"],
        "barman": {
            key: cast(Mapping[str, object], document["barman"])[key]
            for key in (
                "manifest_sha256",
                "manifest_url",
                "operator_image",
                "sidecar_image",
                "version",
            )
        },
        "network_ports": {
            "kubernetes_api": 443,
            "cnpg_webhook": 9443,
            "postgresql": 5432,
            "cnpg_status": 8000,
            "barman_plugin": 9090,
            "dns_tcp_udp": 53,
            "object_store_https": 443,
        },
        "packages": {
            "primary": {
                "path": "primary",
                "apply_by_default": True,
            },
            "restore_drill": {
                "path": "restore-drill",
                "apply_by_default": False,
                "requires_explicit_authorization": True,
            },
        },
        "source_urls": list(SOURCE_URLS),
    }


def render_beta_postgresql_data_plane(
    spec_path: Path | str,
    *,
    cert_manager_manifest: Path | str,
    operator_manifest: Path | str,
    plugin_manifest: Path | str,
    output_directory: Path | str,
    _manifest_loader: ManifestLoader = _load_manifest,
) -> RenderedBetaPostgresqlDataPlane:
    """Render one atomic, pinned, secret-free GitOps release bundle."""

    spec = load_beta_postgresql_data_plane_spec(spec_path)
    document = spec.document
    operator = cast(Mapping[str, object], document["operator"])
    barman = cast(Mapping[str, object], document["barman"])
    cert_manager = cast(Mapping[str, object], document["cert_manager"])
    cert_manager_documents = _manifest_loader(
        Path(cert_manager_manifest),
        cast(str, cert_manager["manifest_sha256"]),
        "cert-manager manifest",
    )
    operator_documents = _manifest_loader(
        Path(operator_manifest), cast(str, operator["manifest_sha256"]), "operator manifest"
    )
    plugin_documents = _manifest_loader(
        Path(plugin_manifest), cast(str, barman["manifest_sha256"]), "plugin manifest"
    )
    cert_manager_documents = _pin_cert_manager_manifest(
        cert_manager_documents,
        controller_image=cast(str, cert_manager["controller_image"]),
        cainjector_image=cast(str, cert_manager["cainjector_image"]),
        webhook_image=cast(str, cert_manager["webhook_image"]),
    )
    operator_documents = _pin_operator_manifest(operator_documents, cast(str, operator["image"]))
    plugin_documents = _pin_plugin_manifest(
        plugin_documents,
        operator_image=cast(str, barman["operator_image"]),
        sidecar_image=cast(str, barman["sidecar_image"]),
    )
    primary_documents, restore_documents = _desired_state_documents(spec)
    if any(
        item.get("kind") == "Secret"
        for item in cert_manager_documents
        + operator_documents
        + plugin_documents
        + primary_documents
        + restore_documents
    ):
        raise BetaPostgresqlDataPlaneError("rendered bundle cannot contain Secret resources")

    output = Path(output_directory)
    parent = _verify_parent(output)
    staging = parent / f".{output.name}.staging-{os.getpid()}-{os.urandom(8).hex()}"
    staging.mkdir(mode=0o700)
    artifacts: list[dict[str, object]] = []
    try:
        rendered: list[tuple[str, bytes]] = [
            ("00-source-lock.json", _canonical_json(_source_lock(spec))),
            (
                "restore-drill/90-restore-drill-evidence.schema.json",
                _canonical_json(restore_drill_evidence_schema()),
            ),
        ]
        rendered.extend(
            (
                f"upstream/cert-manager/{_resource_filename(index, item)}",
                _yaml_bytes(item),
            )
            for index, item in enumerate(cert_manager_documents)
        )
        rendered.extend(
            (
                f"upstream/operator/{_resource_filename(index, item)}",
                _yaml_bytes(item),
            )
            for index, item in enumerate(operator_documents)
        )
        rendered.extend(
            (
                f"upstream/barman-plugin/{_resource_filename(index, item)}",
                _yaml_bytes(item),
            )
            for index, item in enumerate(plugin_documents)
        )
        rendered.extend(
            (f"primary/{_resource_filename(index, item)}", _yaml_bytes(item))
            for index, item in enumerate(primary_documents)
        )
        rendered.extend(
            (f"restore-drill/{_resource_filename(index, item)}", _yaml_bytes(item))
            for index, item in enumerate(restore_documents)
        )
        rendered.sort(key=lambda item: item[0])
        if len({name for name, _ in rendered}) != len(rendered):
            raise BetaPostgresqlDataPlaneError("rendered artifact names collide")
        for relative, raw in rendered:
            _write_file(staging, relative, raw)
            artifacts.append({"path": relative, "sha256": _sha256(raw), "size": len(raw)})
        bundle_document = {
            "artifacts": artifacts,
            "deployment_id": document["deployment_id"],
            "schema_version": 1,
            "spec_sha256": spec.sha256,
        }
        bundle_sha256 = _sha256(_canonical_json(bundle_document))
        receipt = {
            **bundle_document,
            "bundle_sha256": bundle_sha256,
            "render_status": "rendered_not_applied",
            "restore_drill_execution": "not_executed",
            "restore_drill_requires_explicit_authorization": True,
            "secret_resources": 0,
        }
        receipt_raw = _canonical_json(receipt)
        _write_file(staging, "99-render-receipt.json", receipt_raw)
        receipt_sha256 = _sha256(receipt_raw)
        for directory, _, _ in os.walk(staging, topdown=False):
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.replace(staging, output)
        descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging)
        raise
    return RenderedBetaPostgresqlDataPlane(
        output_directory=output,
        spec_sha256=spec.sha256,
        bundle_sha256=bundle_sha256,
        receipt_sha256=receipt_sha256,
        files=tuple(cast(str, item["path"]) for item in artifacts),
    )


__all__ = [
    "BARMAN_MANIFEST_SHA256",
    "BARMAN_MANIFEST_URL",
    "BARMAN_OPERATOR_IMAGE",
    "BARMAN_PLUGIN_VERSION",
    "BARMAN_SIDECAR_IMAGE",
    "CERT_MANAGER_CAINJECTOR_IMAGE",
    "CERT_MANAGER_CONTROLLER_IMAGE",
    "CERT_MANAGER_MANIFEST_SHA256",
    "CERT_MANAGER_MANIFEST_URL",
    "CERT_MANAGER_VERSION",
    "CERT_MANAGER_WEBHOOK_IMAGE",
    "CNPG_OPERATOR_IMAGE",
    "CNPG_VERSION",
    "KUBERNETES_VERSION",
    "OPERATOR_MANIFEST_SHA256",
    "OPERATOR_MANIFEST_URL",
    "POSTGRESQL_IMAGE",
    "POSTGRESQL_VERSION",
    "SOURCE_URLS",
    "TARGET_PLATFORM",
    "AdmittedRestoreDrillEvidence",
    "BetaPostgresqlDataPlaneError",
    "BetaPostgresqlDataPlaneSpec",
    "RenderedBetaPostgresqlDataPlane",
    "admit_restore_drill_evidence",
    "load_beta_postgresql_data_plane_spec",
    "render_beta_postgresql_data_plane",
    "restore_drill_evidence_schema",
]
