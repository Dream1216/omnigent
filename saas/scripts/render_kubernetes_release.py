"""Render the complete public Kubernetes release contract in one trusted step.

The input is a canonical, owner-only JSON document containing release facts,
never credential values.  Rendering is semantic: resources, containers,
environment entries, and volumes are located by identity rather than List
position.  The existing namespace renderer remains the only authority allowed
to change namespaces and Kubernetes service-DNS suffixes.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final, cast
from urllib.parse import urlsplit
from uuid import UUID

import yaml

from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    render_production_service_role_bindings,
)
from saas.scripts.render_kubernetes_namespace import (
    MANIFEST_NAMES,
    SOURCE_NAMESPACE,
    TARGET_NAMESPACE,
    NamespaceRenderError,
    render_namespace_manifests,
)

EVIDENCE_FILE_NAME: Final = "release-render-evidence.json"

_MAX_SPEC_BYTES = 64 * 1024
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_ZERO_GIT_SHA = "0" * 40
_ZERO_SHA256_HEX = "0" * 64
_ZERO_DIGEST = f"sha256:{_ZERO_SHA256_HEX}"
_TEMPLATE_IMAGE = f"ghcr.io/omnigent-ai/omnigent-server@{_ZERO_DIGEST}"
_IMAGE_REPOSITORY = "ghcr.io/omnigent-ai/omnigent-server"
_TEMPLATE_RELEASE_INCARNATION = "0" * 32
_TEMPLATE_ARTIFACT_STORE_URI = "s3://replace-with-production-bucket/omnigent"
_TEMPLATE_ARTIFACT_ENDPOINT = "https://replace-artifact-endpoint.example.invalid"
_TEMPLATE_ARTIFACT_REGION = "replace-with-artifact-region"
_CONTROL_PLANE_SCHEMA_REVISION = "p0s000000011"
_TEMPLATE_SERVICE_LOGINS: Final = {
    service: "replace_runtime_login" if service == "runtime" else f"replace_{service}_login"
    for service in EXPECTED_PRODUCTION_SERVICE_ROLES
}
_RUNNER_FLEET_SECRET_ITEMS: Final = (
    ("runner-database-fleet.json", "runner-database-fleet.json"),
    ("evidence-context.json", "evidence-context.json"),
    ("trust-pins.json", "trust-pins.json"),
    ("environment-attestation.json", "environment-attestation.json"),
    ("environment-attestation.signature", "environment-attestation.signature"),
    ("environment-attestation-public.pem", "environment-attestation-public.pem"),
    ("admission-receipt.json", "admission-receipt.json"),
    ("admission-receipt.signature", "admission-receipt.signature"),
    ("admission-receipt-public.pem", "admission-receipt-public.pem"),
)
_PUBLIC_CA_SECRET_PROJECTIONS: Final = {
    "kubernetes.migration.yaml": {
        "omnigent-saas-postgresql-migration": {
            "postgresql-ca-source": "omnigent-saas-postgresql-ca"
        }
    },
    "kubernetes.production.yaml": {
        "omnigent-saas-server": {
            "postgresql-ca-source": "omnigent-saas-postgresql-ca",
            "runner-control-ca-source": "omnigent-saas-runner-control-ca",
            "preview-readiness-ca-source": "omnigent-saas-preview-readiness-ca",
        },
        "omnigent-saas-worker": {
            "postgresql-ca-source": "omnigent-saas-postgresql-ca",
            "preview-readiness-ca-source": "omnigent-saas-preview-readiness-ca",
        },
        "omnigent-saas-runner-agent-a": {
            "postgresql-ca-source": "omnigent-saas-postgresql-ca",
            "preview-runner-ca-source": "omnigent-saas-preview-runner-tunnel-ca",
        },
        "omnigent-saas-runner-agent-b": {
            "postgresql-ca-source": "omnigent-saas-postgresql-ca",
            "preview-runner-ca-source": "omnigent-saas-preview-runner-tunnel-ca",
        },
        "omnigent-saas-preview-edge": {"postgresql-ca-source": "omnigent-saas-postgresql-ca"},
        "omnigent-saas-preview-owner": {"postgresql-ca-source": "omnigent-saas-postgresql-ca"},
    },
}

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_INCARNATION = re.compile(r"^[0-9a-f]{32}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_ARTIFACT_BUCKET = re.compile(
    r"^(?=.{3,63}$)(?!.*\.\.)(?!.*\.-)(?!.*-\.)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$"
)
_ARTIFACT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_REGION = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FLEET_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_FLEET_ISSUER = re.compile(r"^[a-z0-9][a-z0-9./:_-]{2,255}$")
_SENTINEL = re.compile(
    r"(?:replace(?:[-_.]|\b)|change[-_.]?me|\btbd\b|\btodo\b|"
    r"example\.(?:invalid|net)|(?<![0-9a-f])0{32,}(?![0-9a-f]))",
    re.IGNORECASE,
)
_DEFAULT_ROUTE = re.compile(r"(?<![0-9A-Fa-f:.])(?:0\.0\.0\.0/0|::/0)(?![0-9A-Fa-f:.])")
_FORBIDDEN_LOGIN_FRAGMENTS = ("admin", "migration", "owner", "postgres", "root")
_MISSING: Final = object()


class ReleaseRenderError(RuntimeError):
    """Stable fail-closed release rendering error."""


@dataclass(frozen=True, slots=True)
class ArtifactReleaseSpec:
    store_uri: str
    endpoint_url: str
    endpoint_cidr: str
    region: str
    credentials_profile: str
    credential_revision: str
    readiness_key: str
    readiness_sha256: str
    receipt_revision: str


@dataclass(frozen=True, slots=True)
class PreviewReleaseSpec:
    root_domain: str
    pod_cidr: str
    service_cidr: str
    relay_trust_bundle_versions: tuple[str, ...]
    owner_incarnation: str
    gateway_instance_id: str


@dataclass(frozen=True, slots=True)
class RunnerReleaseSpec:
    runner_id: str
    connection_generation: int
    recovery_artifact_uri: str
    recovery_credentials_profile: str
    recovery_credential_revision: str
    recovery_credential_secret_name: str
    repository_credential_revision: str
    repository_spec_sha256: str
    repository_bindings_sha256: str
    repository_receipt_sha256: str
    repository_spec_secret_name: str
    repository_credentials_secret_name: str


@dataclass(frozen=True, slots=True)
class RunnerFleetReleaseSpec:
    namespace: str
    admission_epoch: int
    fleet_sha256: str
    evidence_context_sha256: str
    trust_pins_sha256: str
    attestation_issuer: str
    attestation_key_id: str
    attestation_public_key_sha256: str
    attestation_sha256: str
    attestation_signature_sha256: str
    receipt_issuer: str
    receipt_key_id: str
    receipt_public_key_sha256: str
    receipt_sha256: str
    receipt_signature_sha256: str
    secret_name: str


@dataclass(frozen=True, slots=True)
class KubernetesReleaseSpec:
    mode: str
    source_revision: str
    product_revision: str
    upstream_revision: str
    image_digest: str
    release_incarnation: str
    runtime_version: str
    official_schema_revision: str
    control_plane_schema_revision: str
    adapter_contract_version: str
    public_origin: str
    repository_endpoint_cidr: str
    artifact: ArtifactReleaseSpec
    preview: PreviewReleaseSpec
    ingress_namespace: str
    ingress_workload: str
    runners: Mapping[str, RunnerReleaseSpec]
    runner_fleet: RunnerFleetReleaseSpec
    service_logins: Mapping[str, str]
    source_sha256: str


@dataclass(frozen=True, slots=True)
class _SourceManifest:
    raw: bytes
    document: dict[str, Any]


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def _mapping(value: Any, *, name: str, fields: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ReleaseRenderError(f"{name} must be an object")
    result = cast(dict[str, Any], value)
    if fields is not None and set(result) != fields:
        raise ReleaseRenderError(f"{name} fields do not match the schema")
    return result


def _string(source: Mapping[str, Any], name: str, *, parent: str = "release spec") -> str:
    value = source.get(name)
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise ReleaseRenderError(f"{parent}.{name} must be one non-empty string")
    return value


def _nonzero_match(value: str, pattern: re.Pattern[str], *, name: str) -> str:
    payload = value.removeprefix("sha256:")
    if pattern.fullmatch(value) is None or not payload or set(payload) == {"0"}:
        raise ReleaseRenderError(f"{name} is invalid or all-zero")
    return value


def _revision(value: str, *, name: str) -> str:
    if _REVISION.fullmatch(value) is None or _SENTINEL.search(value):
        raise ReleaseRenderError(f"{name} is invalid")
    return value


def _canonical_uuid(value: str, *, name: str) -> str:
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError):
        raise ReleaseRenderError(f"{name} must be one canonical nonzero UUID") from None
    if parsed.int == 0 or str(parsed) != value:
        raise ReleaseRenderError(f"{name} must be one canonical nonzero UUID")
    return value


def _canonical_cidr(value: str, *, name: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ReleaseRenderError(f"{name} must be one canonical CIDR") from None
    if str(network) != value or network.prefixlen == 0:
        raise ReleaseRenderError(f"{name} must be one bounded canonical CIDR")
    return value


def _dns_name(value: str, *, name: str) -> str:
    if (
        _DNS_NAME.fullmatch(value) is None
        or value.endswith((".example", ".invalid", ".localhost", ".test"))
        or _SENTINEL.search(value)
    ):
        raise ReleaseRenderError(f"{name} must be one canonical routable DNS name")
    return value


def _https_origin(value: str, *, name: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ReleaseRenderError(f"{name} must be one exact HTTPS origin") from None
    authority = hostname or ""
    if port is not None:
        authority = f"{authority}:{port}"
    if (
        parsed.scheme != "https"
        or hostname is None
        or _dns_name(hostname, name=f"{name} hostname") != hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc != authority
        or value != f"https://{authority}"
    ):
        raise ReleaseRenderError(f"{name} must be one exact HTTPS origin")
    return value


def _artifact_store_uri(value: str) -> str:
    try:
        parsed = urlsplit(value)
        bucket = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ReleaseRenderError("artifact.store_uri must be one canonical s3 URI") from None
    prefix = parsed.path.removeprefix("/")
    if (
        parsed.scheme != "s3"
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
        or PureWindowsPath(value).is_absolute()
        or value != f"s3://{bucket}" + (f"/{prefix}" if prefix else "")
    ):
        raise ReleaseRenderError("artifact.store_uri must be one canonical s3 URI")
    try:
        ipaddress.ip_address(bucket)
    except ValueError:
        return value
    raise ReleaseRenderError("artifact.store_uri bucket must be a DNS name")


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
        raise ReleaseRenderError("artifact.readiness_key is invalid")
    return value


def _load_json_without_duplicate_keys(raw: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseRenderError("release spec contains a duplicate object key")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except json.JSONDecodeError as error:
        raise ReleaseRenderError("release spec is not valid JSON") from error


def _read_owner_only_spec(path: Path) -> tuple[bytes, dict[str, Any]]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise ReleaseRenderError("release spec is unavailable") from error
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or mode not in {0o400, 0o600}
            or not 1 <= before.st_size <= _MAX_SPEC_BYTES
        ):
            raise ReleaseRenderError(
                "release spec must be an owner-only regular file with mode 0400 or 0600"
            )
        chunks: list[bytes] = []
        observed_size = 0
        while observed_size <= _MAX_SPEC_BYTES:
            chunk = os.read(descriptor, min(16 * 1024, _MAX_SPEC_BYTES + 1 - observed_size))
            if not chunk:
                break
            chunks.append(chunk)
            observed_size += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            len(raw) != before.st_size
            or len(raw) > _MAX_SPEC_BYTES
            or any(getattr(before, field) != getattr(after, field) for field in stable_fields)
        ):
            raise ReleaseRenderError("release spec changed while it was being read")
        decoded = raw.decode("ascii")
    except ReleaseRenderError:
        raise
    except (OSError, UnicodeError) as error:
        raise ReleaseRenderError("release spec cannot be read as canonical ASCII JSON") from error
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
    document = _mapping(_load_json_without_duplicate_keys(decoded), name="release spec")
    if raw != _canonical_json(document):
        raise ReleaseRenderError("release spec must contain canonical JSON")
    return raw, document


def _parse_artifact(source: Any, *, mode: str) -> ArtifactReleaseSpec:
    fields = {
        "store_uri",
        "endpoint_url",
        "endpoint_cidr",
        "region",
        "credentials_profile",
        "credential_revision",
        "readiness_key",
        "readiness_sha256",
        "receipt_revision",
    }
    row = _mapping(source, name="artifact", fields=fields)
    receipt = _string(row, "receipt_revision", parent="artifact")
    if mode == "stage":
        if receipt != "pending":
            raise ReleaseRenderError("stage artifact.receipt_revision must equal pending")
    else:
        _nonzero_match(receipt, _DIGEST, name="artifact.receipt_revision")
    profile = _revision(
        _string(row, "credentials_profile", parent="artifact"),
        name="artifact.credentials_profile",
    )
    if len(profile) > 64 or profile.lower() == "default":
        raise ReleaseRenderError("artifact.credentials_profile is invalid")
    region = _string(row, "region", parent="artifact")
    if _REGION.fullmatch(region) is None:
        raise ReleaseRenderError("artifact.region is invalid")
    readiness_sha256 = _nonzero_match(
        _string(row, "readiness_sha256", parent="artifact"),
        _SHA256_HEX,
        name="artifact.readiness_sha256",
    )
    return ArtifactReleaseSpec(
        store_uri=_artifact_store_uri(_string(row, "store_uri", parent="artifact")),
        endpoint_url=_https_origin(
            _string(row, "endpoint_url", parent="artifact"),
            name="artifact.endpoint_url",
        ),
        endpoint_cidr=_canonical_cidr(
            _string(row, "endpoint_cidr", parent="artifact"),
            name="artifact.endpoint_cidr",
        ),
        region=region,
        credentials_profile=profile,
        credential_revision=_nonzero_match(
            _string(row, "credential_revision", parent="artifact"),
            _DIGEST,
            name="artifact.credential_revision",
        ),
        readiness_key=_artifact_key(_string(row, "readiness_key", parent="artifact")),
        readiness_sha256=readiness_sha256,
        receipt_revision=receipt,
    )


def _parse_preview(source: Any) -> PreviewReleaseSpec:
    fields = {
        "root_domain",
        "pod_cidr",
        "service_cidr",
        "relay_trust_bundle_versions",
        "owner_incarnation",
        "gateway_instance_id",
    }
    row = _mapping(source, name="preview", fields=fields)
    versions = row.get("relay_trust_bundle_versions")
    if (
        not isinstance(versions, list)
        or not versions
        or not all(isinstance(value, str) for value in versions)
    ):
        raise ReleaseRenderError("preview.relay_trust_bundle_versions must be a non-empty list")
    parsed_versions = tuple(
        _revision(value, name="preview.relay_trust_bundle_versions") for value in versions
    )
    if parsed_versions != tuple(sorted(set(parsed_versions))):
        raise ReleaseRenderError("preview.relay_trust_bundle_versions must be sorted and unique")
    return PreviewReleaseSpec(
        root_domain=_dns_name(
            _string(row, "root_domain", parent="preview"),
            name="preview.root_domain",
        ),
        pod_cidr=_canonical_cidr(
            _string(row, "pod_cidr", parent="preview"), name="preview.pod_cidr"
        ),
        service_cidr=_canonical_cidr(
            _string(row, "service_cidr", parent="preview"), name="preview.service_cidr"
        ),
        relay_trust_bundle_versions=parsed_versions,
        owner_incarnation=_nonzero_match(
            _string(row, "owner_incarnation", parent="preview"),
            _INCARNATION,
            name="preview.owner_incarnation",
        ),
        gateway_instance_id=_revision(
            _string(row, "gateway_instance_id", parent="preview"),
            name="preview.gateway_instance_id",
        ),
    )


def _parse_runner(
    source: Any, *, slot: str, store_uri: str, release_incarnation: str
) -> RunnerReleaseSpec:
    fields = {
        "runner_id",
        "connection_generation",
        "recovery_artifact_uri",
        "recovery_credentials_profile",
        "recovery_credential_revision",
        "recovery_credential_secret_name",
        "repository_credential_revision",
        "repository_spec_sha256",
        "repository_bindings_sha256",
        "repository_receipt_sha256",
    }
    row = _mapping(source, name=f"runners.{slot}", fields=fields)
    runner_id = _canonical_uuid(
        _string(row, "runner_id", parent=f"runners.{slot}"),
        name=f"runners.{slot}.runner_id",
    )
    generation = row.get("connection_generation")
    if type(generation) is not int or not 1 <= generation <= 2_147_483_647:
        raise ReleaseRenderError(f"runners.{slot}.connection_generation is invalid")
    expected_uri = f"{store_uri}/runtime-recovery/runner/{runner_id}/generation/{generation}"
    recovery_uri = _string(row, "recovery_artifact_uri", parent=f"runners.{slot}")
    if recovery_uri != expected_uri:
        raise ReleaseRenderError(
            f"runners.{slot}.recovery_artifact_uri does not bind the exact runner generation"
        )
    profile = _revision(
        _string(row, "recovery_credentials_profile", parent=f"runners.{slot}"),
        name=f"runners.{slot}.recovery_credentials_profile",
    )
    expected_profile = f"runner-{runner_id}-g{generation}"
    if profile != expected_profile:
        raise ReleaseRenderError(
            f"runners.{slot}.recovery_credentials_profile must bind the exact runner generation"
        )
    credential_revision = _nonzero_match(
        _string(row, "recovery_credential_revision", parent=f"runners.{slot}"),
        _DIGEST,
        name=f"runners.{slot}.recovery_credential_revision",
    )
    secret_name = _string(row, "recovery_credential_secret_name", parent=f"runners.{slot}")
    expected_secret_name = (
        f"omnigent-runner-{slot}-recovery-g{generation}-"
        f"{credential_revision.removeprefix('sha256:')[:12]}"
    )
    if secret_name != expected_secret_name or _DNS_LABEL.fullmatch(secret_name) is None:
        raise ReleaseRenderError(
            f"runners.{slot}.recovery_credential_secret_name must be the derived immutable name"
        )
    repository_hashes = {
        field: _nonzero_match(
            _string(row, field, parent=f"runners.{slot}"),
            _DIGEST,
            name=f"runners.{slot}.{field}",
        )
        for field in (
            "repository_credential_revision",
            "repository_spec_sha256",
            "repository_bindings_sha256",
            "repository_receipt_sha256",
        )
    }
    repository_spec_binding_sha256 = _sha256(
        _canonical_json(
            {
                "release_incarnation": release_incarnation,
                "runner_slot": slot,
                "spec_sha256": repository_hashes["repository_spec_sha256"],
            }
        )
    )
    repository_spec_secret_name = (
        f"omnigent-saas-runner-{slot}-repository-provisioning-"
        f"{repository_spec_binding_sha256.removeprefix('sha256:')[:12]}"
    )
    repository_credentials_secret_name = (
        f"omnigent-saas-runner-{slot}-repository-credentials-"
        f"{repository_hashes['repository_credential_revision'].removeprefix('sha256:')[:12]}"
    )
    if (
        _DNS_LABEL.fullmatch(repository_spec_secret_name) is None
        or _DNS_LABEL.fullmatch(repository_credentials_secret_name) is None
    ):
        raise ReleaseRenderError(f"runners.{slot} repository Secret derivation is invalid")
    return RunnerReleaseSpec(
        runner_id=runner_id,
        connection_generation=generation,
        recovery_artifact_uri=recovery_uri,
        recovery_credentials_profile=profile,
        recovery_credential_revision=credential_revision,
        recovery_credential_secret_name=secret_name,
        repository_credential_revision=repository_hashes["repository_credential_revision"],
        repository_spec_sha256=repository_hashes["repository_spec_sha256"],
        repository_bindings_sha256=repository_hashes["repository_bindings_sha256"],
        repository_receipt_sha256=repository_hashes["repository_receipt_sha256"],
        repository_spec_secret_name=repository_spec_secret_name,
        repository_credentials_secret_name=repository_credentials_secret_name,
    )


def _parse_runner_fleet(
    source: Any,
    *,
    mode: str,
    product_revision: str,
    schema_revision: str,
) -> RunnerFleetReleaseSpec:
    fields = {
        "namespace",
        "admission_epoch",
        "fleet_sha256",
        "evidence_context_sha256",
        "trust_pins_sha256",
        "attestation",
        "receipt",
        "secret_name",
    }
    row = _mapping(source, name="runner_fleet", fields=fields)
    namespace = _string(row, "namespace", parent="runner_fleet")
    if namespace != TARGET_NAMESPACE:
        raise ReleaseRenderError("runner_fleet.namespace must equal the target namespace")
    admission_epoch = row.get("admission_epoch")
    if type(admission_epoch) is not int or not 1 <= admission_epoch <= 2**63 - 1:
        raise ReleaseRenderError("runner_fleet.admission_epoch is invalid")

    sha_fields = {
        field: _nonzero_match(
            _string(row, field, parent="runner_fleet"),
            _DIGEST,
            name=f"runner_fleet.{field}",
        )
        for field in ("fleet_sha256", "evidence_context_sha256", "trust_pins_sha256")
    }
    signer_fields = {
        "issuer",
        "key_id",
        "public_key_sha256",
        "document_sha256",
        "signature_sha256",
    }
    attestation = _mapping(
        row.get("attestation"), name="runner_fleet.attestation", fields=signer_fields
    )
    receipt = _mapping(row.get("receipt"), name="runner_fleet.receipt", fields=signer_fields)
    attestation_issuer = _string(attestation, "issuer", parent="runner_fleet.attestation")
    attestation_key_id = _string(attestation, "key_id", parent="runner_fleet.attestation")
    receipt_issuer = _string(receipt, "issuer", parent="runner_fleet.receipt")
    receipt_key_id = _string(receipt, "key_id", parent="runner_fleet.receipt")
    if (
        _FLEET_ISSUER.fullmatch(attestation_issuer) is None
        or _FLEET_KEY_ID.fullmatch(attestation_key_id) is None
        or _FLEET_ISSUER.fullmatch(receipt_issuer) is None
        or _FLEET_KEY_ID.fullmatch(receipt_key_id) is None
    ):
        raise ReleaseRenderError("runner_fleet signer identities are invalid")
    attestation_hashes = {
        field: _nonzero_match(
            _string(attestation, field, parent="runner_fleet.attestation"),
            _DIGEST,
            name=f"runner_fleet.attestation.{field}",
        )
        for field in ("public_key_sha256", "document_sha256", "signature_sha256")
    }
    receipt_public_key_sha256 = _nonzero_match(
        _string(receipt, "public_key_sha256", parent="runner_fleet.receipt"),
        _DIGEST,
        name="runner_fleet.receipt.public_key_sha256",
    )
    receipt_sha256 = _string(receipt, "document_sha256", parent="runner_fleet.receipt")
    receipt_signature_sha256 = _string(receipt, "signature_sha256", parent="runner_fleet.receipt")
    if mode == "stage":
        if receipt_sha256 != "pending" or receipt_signature_sha256 != "pending":
            raise ReleaseRenderError("stage runner_fleet receipt hashes must equal pending")
        pinned_receipt_sha256: str | None = None
        pinned_receipt_signature_sha256: str | None = None
        stage = "admission"
    else:
        _nonzero_match(receipt_sha256, _DIGEST, name="runner_fleet.receipt.document_sha256")
        _nonzero_match(
            receipt_signature_sha256,
            _DIGEST,
            name="runner_fleet.receipt.signature_sha256",
        )
        pinned_receipt_sha256 = receipt_sha256.removeprefix("sha256:")
        pinned_receipt_signature_sha256 = receipt_signature_sha256.removeprefix("sha256:")
        stage = "runtime"

    pins_document: dict[str, Any] = {
        "admission_epoch": admission_epoch,
        "attestation_issuer": attestation_issuer,
        "attestation_key_id": attestation_key_id,
        "attestation_public_key_sha256": attestation_hashes["public_key_sha256"].removeprefix(
            "sha256:"
        ),
        "attestation_sha256": attestation_hashes["document_sha256"].removeprefix("sha256:"),
        "attestation_signature_sha256": attestation_hashes["signature_sha256"].removeprefix(
            "sha256:"
        ),
        "evidence_context_sha256": sha_fields["evidence_context_sha256"].removeprefix("sha256:"),
        "fleet_sha256": sha_fields["fleet_sha256"].removeprefix("sha256:"),
        "product_revision": product_revision,
        "receipt_issuer": receipt_issuer,
        "receipt_key_id": receipt_key_id,
        "receipt_public_key_sha256": receipt_public_key_sha256.removeprefix("sha256:"),
        "receipt_sha256": pinned_receipt_sha256,
        "receipt_signature_sha256": pinned_receipt_signature_sha256,
        "schema_revision": schema_revision,
        "schema_version": 1,
        "stage": stage,
    }
    expected_pins_sha256 = _sha256(_canonical_json(pins_document))
    if sha_fields["trust_pins_sha256"] != expected_pins_sha256:
        raise ReleaseRenderError(
            "runner_fleet.trust_pins_sha256 does not bind the canonical public pins"
        )
    secret_name = _string(row, "secret_name", parent="runner_fleet")
    expected_secret_name = (
        f"omnigent-saas-runner-database-fleet-{expected_pins_sha256.removeprefix('sha256:')[:12]}"
    )
    if secret_name != expected_secret_name:
        raise ReleaseRenderError(
            "runner_fleet.secret_name must be derived from the canonical trust pins"
        )
    return RunnerFleetReleaseSpec(
        namespace=namespace,
        admission_epoch=admission_epoch,
        fleet_sha256=sha_fields["fleet_sha256"],
        evidence_context_sha256=sha_fields["evidence_context_sha256"],
        trust_pins_sha256=sha_fields["trust_pins_sha256"],
        attestation_issuer=attestation_issuer,
        attestation_key_id=attestation_key_id,
        attestation_public_key_sha256=attestation_hashes["public_key_sha256"],
        attestation_sha256=attestation_hashes["document_sha256"],
        attestation_signature_sha256=attestation_hashes["signature_sha256"],
        receipt_issuer=receipt_issuer,
        receipt_key_id=receipt_key_id,
        receipt_public_key_sha256=receipt_public_key_sha256,
        receipt_sha256=receipt_sha256,
        receipt_signature_sha256=receipt_signature_sha256,
        secret_name=secret_name,
    )


def load_public_release_spec(path: Path) -> KubernetesReleaseSpec:
    """Load the exact owner-only canonical release spec without secret material."""

    raw, document = _read_owner_only_spec(path)
    fields = {
        "schema_version",
        "mode",
        "source_revision",
        "product_revision",
        "upstream_revision",
        "image_digest",
        "release_incarnation",
        "runtime_version",
        "official_schema_revision",
        "control_plane_schema_revision",
        "adapter_contract_version",
        "public_origin",
        "artifact",
        "preview",
        "repository_endpoint_cidr",
        "ingress",
        "runners",
        "runner_fleet",
        "service_logins",
    }
    _mapping(document, name="release spec", fields=fields)
    if document.get("schema_version") != 1:
        raise ReleaseRenderError("release spec schema_version must equal 1")
    mode = _string(document, "mode")
    if mode not in {"stage", "final"}:
        raise ReleaseRenderError("release spec mode must equal stage or final")
    source_revision = _nonzero_match(
        _string(document, "source_revision"), _FULL_GIT_SHA, name="source_revision"
    )
    product_revision = _nonzero_match(
        _string(document, "product_revision"), _FULL_GIT_SHA, name="product_revision"
    )
    if source_revision != product_revision:
        raise ReleaseRenderError("source_revision and product_revision must match exactly")
    release_incarnation = _nonzero_match(
        _string(document, "release_incarnation"),
        _INCARNATION,
        name="release_incarnation",
    )
    artifact = _parse_artifact(document.get("artifact"), mode=mode)
    preview = _parse_preview(document.get("preview"))
    control_plane_schema_revision = _string(document, "control_plane_schema_revision")
    if control_plane_schema_revision != _CONTROL_PLANE_SCHEMA_REVISION:
        raise ReleaseRenderError(
            "control_plane_schema_revision must equal the packaged p0s10 Alembic head"
        )
    runner_fleet = _parse_runner_fleet(
        document.get("runner_fleet"),
        mode=mode,
        product_revision=product_revision,
        schema_revision=control_plane_schema_revision,
    )
    ingress = _mapping(
        document.get("ingress"),
        name="ingress",
        fields={"namespace", "workload"},
    )
    ingress_namespace = _string(ingress, "namespace", parent="ingress")
    ingress_workload = _string(ingress, "workload", parent="ingress")
    if (
        _DNS_LABEL.fullmatch(ingress_namespace) is None
        or _DNS_LABEL.fullmatch(ingress_workload) is None
    ):
        raise ReleaseRenderError("ingress selectors must be canonical DNS labels")

    runner_rows = _mapping(document.get("runners"), name="runners", fields={"a", "b"})
    runners = {
        slot: _parse_runner(
            runner_rows[slot],
            slot=slot,
            store_uri=artifact.store_uri,
            release_incarnation=release_incarnation,
        )
        for slot in ("a", "b")
    }
    runner_values = tuple(runners.values())
    if (
        len({runner.runner_id for runner in runner_values}) != 2
        or len({runner.recovery_artifact_uri for runner in runner_values}) != 2
        or len({runner.recovery_credentials_profile for runner in runner_values}) != 2
        or len({runner.recovery_credential_revision for runner in runner_values}) != 2
        or len({runner.recovery_credential_secret_name for runner in runner_values}) != 2
        or len({runner.repository_credential_revision for runner in runner_values}) != 2
        or len({runner.repository_spec_sha256 for runner in runner_values}) != 2
        or len({runner.repository_bindings_sha256 for runner in runner_values}) != 2
        or len({runner.repository_receipt_sha256 for runner in runner_values}) != 2
        or len({runner.repository_spec_secret_name for runner in runner_values}) != 2
        or len({runner.repository_credentials_secret_name for runner in runner_values}) != 2
        or artifact.credential_revision
        in {
            revision
            for runner in runner_values
            for revision in (
                runner.recovery_credential_revision,
                runner.repository_credential_revision,
            )
        }
    ):
        raise ReleaseRenderError("Runner A/B identities and recovery credentials must be distinct")

    login_rows = _mapping(
        document.get("service_logins"),
        name="service_logins",
        fields=set(EXPECTED_PRODUCTION_SERVICE_ROLES),
    )
    service_logins = {
        service: _string(login_rows, service, parent="service_logins")
        for service in EXPECTED_PRODUCTION_SERVICE_ROLES
    }
    base_roles = set(EXPECTED_PRODUCTION_SERVICE_ROLES.values())
    if (
        len(set(service_logins.values())) != len(service_logins)
        or any(_ROLE_NAME.fullmatch(login) is None for login in service_logins.values())
        or any(login in base_roles for login in service_logins.values())
        or any(
            fragment in login
            for login in service_logins.values()
            for fragment in _FORBIDDEN_LOGIN_FRAGMENTS
        )
    ):
        raise ReleaseRenderError("service_logins must contain ten distinct narrow login roles")

    return KubernetesReleaseSpec(
        mode=mode,
        source_revision=source_revision,
        product_revision=product_revision,
        upstream_revision=_nonzero_match(
            _string(document, "upstream_revision"),
            _FULL_GIT_SHA,
            name="upstream_revision",
        ),
        image_digest=_nonzero_match(
            _string(document, "image_digest"), _DIGEST, name="image_digest"
        ),
        release_incarnation=release_incarnation,
        runtime_version=_revision(_string(document, "runtime_version"), name="runtime_version"),
        official_schema_revision=_revision(
            _string(document, "official_schema_revision"),
            name="official_schema_revision",
        ),
        control_plane_schema_revision=control_plane_schema_revision,
        adapter_contract_version=_revision(
            _string(document, "adapter_contract_version"),
            name="adapter_contract_version",
        ),
        public_origin=_https_origin(_string(document, "public_origin"), name="public_origin"),
        repository_endpoint_cidr=_canonical_cidr(
            _string(document, "repository_endpoint_cidr"),
            name="repository_endpoint_cidr",
        ),
        artifact=artifact,
        preview=preview,
        ingress_namespace=ingress_namespace,
        ingress_workload=ingress_workload,
        runners=runners,
        runner_fleet=runner_fleet,
        service_logins=service_logins,
        source_sha256=_sha256(raw),
    )


def _read_manifest(path: Path) -> _SourceManifest:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseRenderError(f"{path.name}: source manifest is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseRenderError(f"{path.name}: source manifest must be a regular file")
    if not 1 <= metadata.st_size <= _MAX_MANIFEST_BYTES:
        raise ReleaseRenderError(f"{path.name}: source manifest size is invalid")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        document = yaml.safe_load(text)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ReleaseRenderError(f"{path.name}: source manifest cannot be loaded") from error
    if not text.endswith("\n") or "\x00" in text:
        raise ReleaseRenderError(f"{path.name}: source manifest encoding is invalid")
    parsed = _mapping(document, name=f"{path.name} manifest")
    if parsed.get("apiVersion") != "v1" or parsed.get("kind") != "List":
        raise ReleaseRenderError(f"{path.name}: manifest must be apiVersion v1 kind List")
    items = parsed.get("items")
    if not isinstance(items, list) or not items:
        raise ReleaseRenderError(f"{path.name}: manifest List must not be empty")
    identities: set[tuple[str, str]] = set()
    for value in items:
        item = _mapping(value, name=f"{path.name} resource")
        metadata_row = _mapping(item.get("metadata"), name=f"{path.name} metadata")
        kind = item.get("kind")
        resource_name = metadata_row.get("name")
        if not isinstance(kind, str) or not isinstance(resource_name, str) or not resource_name:
            raise ReleaseRenderError(f"{path.name}: resource identity is invalid")
        if kind == "Secret":
            raise ReleaseRenderError(f"{path.name}: Secret resources are forbidden")
        if metadata_row.get("namespace") != SOURCE_NAMESPACE:
            raise ReleaseRenderError(
                f"{path.name}: every source namespace must equal {SOURCE_NAMESPACE}"
            )
        identity = (kind, resource_name)
        if identity in identities:
            raise ReleaseRenderError(f"{path.name}: duplicate resource identity")
        identities.add(identity)
    return _SourceManifest(raw=raw, document=parsed)


def _load_source_manifests(source_dir: Path) -> dict[str, _SourceManifest]:
    try:
        metadata = source_dir.lstat()
        entries = tuple(source_dir.iterdir())
    except OSError as error:
        raise ReleaseRenderError("source directory is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseRenderError("source directory must be a real directory")
    entry_names = {entry.name for entry in entries}
    allowed_entries = {*MANIFEST_NAMES, "README.md", "__init__.py"}
    if not set(MANIFEST_NAMES).issubset(entry_names) or not entry_names.issubset(allowed_entries):
        raise ReleaseRenderError(
            "source directory must contain only the exact four YAML manifests "
            "plus fixed package companions"
        )
    if any(entry.is_symlink() for entry in entries):
        raise ReleaseRenderError(
            "source manifest must be a regular file; symbolic links are forbidden"
        )
    return {name: _read_manifest(source_dir / name) for name in MANIFEST_NAMES}


def _items(document: Mapping[str, Any], *, name: str) -> list[dict[str, Any]]:
    values = document.get("items")
    if not isinstance(values, list):
        raise ReleaseRenderError(f"{name}: List items are invalid")
    return [_mapping(value, name=f"{name} resource") for value in values]


def _resource(
    document: Mapping[str, Any],
    *,
    kind: str,
    name: str | None = None,
    data_key: str | None = None,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for item in _items(document, name="manifest"):
        metadata = item.get("metadata")
        data = item.get("data")
        if item.get("kind") != kind or not isinstance(metadata, dict):
            continue
        if name is not None and metadata.get("name") != name:
            continue
        if data_key is not None and (not isinstance(data, dict) or data_key not in data):
            continue
        matches.append(item)
    if len(matches) != 1:
        identity = name or data_key or kind
        raise ReleaseRenderError(f"manifest must contain exactly one {kind} {identity}")
    return matches[0]


def _nested_mapping(source: Mapping[str, Any], *path: str) -> dict[str, Any]:
    current: Any = source
    for part in path:
        if not isinstance(current, dict):
            raise ReleaseRenderError(f"manifest path {'.'.join(path)} is invalid")
        current = current.get(part)
    return _mapping(current, name=f"manifest path {'.'.join(path)}")


def _named_row(rows: Any, *, name: str, row_type: str) -> dict[str, Any]:
    if not isinstance(rows, list):
        raise ReleaseRenderError(f"manifest {row_type} list is invalid")
    matches = [row for row in rows if isinstance(row, dict) and row.get("name") == name]
    if len(matches) != 1:
        raise ReleaseRenderError(f"manifest must contain exactly one {row_type} {name}")
    return cast(dict[str, Any], matches[0])


def _set_exact(target: dict[str, Any], key: str, value: Any, *, expected: Any, name: str) -> None:
    if target.get(key) != expected:
        raise ReleaseRenderError(f"{name} source projection is invalid")
    target[key] = value


def _replace_images(value: Any, image: str) -> int:
    count = 0
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "image":
                if child != _TEMPLATE_IMAGE:
                    raise ReleaseRenderError("source image projection is not the pinned template")
                value[key] = image
                count += 1
            else:
                count += _replace_images(child, image)
    elif isinstance(value, list):
        for child in value:
            count += _replace_images(child, image)
    return count


def _replace_exact_resource_token(
    value: Any,
    *,
    token: str,
    replacement: str,
    expected_count: int,
    name: str,
) -> None:
    count = 0

    def visit(child: Any) -> None:
        nonlocal count
        if isinstance(child, dict):
            for key, nested in tuple(child.items()):
                if isinstance(nested, str):
                    observed = nested.count(token)
                    if observed:
                        child[key] = nested.replace(token, replacement)
                        count += observed
                else:
                    visit(nested)
        elif isinstance(child, list):
            for index, nested in enumerate(tuple(child)):
                if isinstance(nested, str):
                    observed = nested.count(token)
                    if observed:
                        child[index] = nested.replace(token, replacement)
                        count += observed
                else:
                    visit(nested)

    visit(value)
    if count != expected_count:
        raise ReleaseRenderError(
            f"{name} must contain exactly {expected_count} authorized {token} projection(s)"
        )


def _service_bindings_text(spec: KubernetesReleaseSpec) -> str:
    return render_production_service_role_bindings(
        tuple(
            ProductionServiceRoleBinding(
                service=service,
                login=spec.service_logins[service],
                base_role=base_role,
            )
            for service, base_role in EXPECTED_PRODUCTION_SERVICE_ROLES.items()
        )
    )


def _template_service_bindings_text() -> str:
    return render_production_service_role_bindings(
        tuple(
            ProductionServiceRoleBinding(
                service=service,
                login=_TEMPLATE_SERVICE_LOGINS[service],
                base_role=base_role,
            )
            for service, base_role in EXPECTED_PRODUCTION_SERVICE_ROLES.items()
        )
    )


def _render_release_documents(
    sources: Mapping[str, _SourceManifest], spec: KubernetesReleaseSpec
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    documents = {name: copy.deepcopy(source.document) for name, source in sources.items()}
    migration = documents["kubernetes.migration.yaml"]
    artifact_admission = documents["kubernetes.artifact-admission.yaml"]
    production = documents["kubernetes.production.yaml"]
    network = documents["kubernetes.network-policy.yaml"]

    migration_release = _resource(
        migration, kind="ConfigMap", data_key="OMNIGENT_SAAS_PRODUCT_REVISION"
    )
    migration_data = _nested_mapping(migration_release, "data")
    _set_exact(
        migration_data,
        "OMNIGENT_SAAS_PRODUCT_REVISION",
        spec.product_revision,
        expected=_ZERO_GIT_SHA,
        name="migration product revision",
    )
    _set_exact(
        migration_data,
        "OMNIGENT_SAAS_SOURCE_SHA",
        spec.source_revision,
        expected=_ZERO_GIT_SHA,
        name="migration source revision",
    )

    artifact_release = _resource(
        artifact_admission, kind="ConfigMap", data_key="OMNIGENT_SAAS_IMAGE_DIGEST"
    )
    artifact_data = _nested_mapping(artifact_release, "data")
    artifact_values = {
        "OMNIGENT_SAAS_PRODUCT_REVISION": (spec.product_revision, _ZERO_GIT_SHA),
        "OMNIGENT_SAAS_SOURCE_SHA": (spec.source_revision, _ZERO_GIT_SHA),
        "OMNIGENT_SAAS_IMAGE_DIGEST": (spec.image_digest, _ZERO_DIGEST),
        "OMNIGENT_SAAS_RELEASE_INCARNATION": (
            spec.release_incarnation,
            _TEMPLATE_RELEASE_INCARNATION,
        ),
        "OMNIGENT_SAAS_ARTIFACT_STORE_URI": (
            spec.artifact.store_uri,
            _TEMPLATE_ARTIFACT_STORE_URI,
        ),
        "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL": (
            spec.artifact.endpoint_url,
            _TEMPLATE_ARTIFACT_ENDPOINT,
        ),
        "OMNIGENT_SAAS_ARTIFACT_REGION": (
            spec.artifact.region,
            _TEMPLATE_ARTIFACT_REGION,
        ),
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE": (
            spec.artifact.credentials_profile,
            "omnigent-saas-artifacts",
        ),
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION": (
            spec.artifact.credential_revision,
            _ZERO_DIGEST,
        ),
    }
    for field, (rendered, expected) in artifact_values.items():
        _set_exact(artifact_data, field, rendered, expected=expected, name=field)

    artifact_job = _resource(artifact_admission, kind="Job")
    artifact_annotations = _nested_mapping(
        artifact_job, "spec", "template", "metadata", "annotations"
    )
    _set_exact(
        artifact_annotations,
        "omnigent.io/artifact-credential-revision",
        spec.artifact.credential_revision,
        expected=_ZERO_DIGEST,
        name="artifact admission credential annotation",
    )
    _set_exact(
        artifact_annotations,
        "omnigent.io/release-incarnation",
        spec.release_incarnation,
        expected=_TEMPLATE_RELEASE_INCARNATION,
        name="artifact admission release annotation",
    )

    production_release = _resource(
        production, kind="ConfigMap", data_key="OMNIGENT_SAAS_UPSTREAM_REVISION"
    )
    production_data = _nested_mapping(production_release, "data")
    receipt_value = _ZERO_DIGEST if spec.mode == "stage" else spec.artifact.receipt_revision
    production_values = {
        "OMNIGENT_SAAS_PRODUCT_REVISION": (spec.product_revision, _ZERO_GIT_SHA),
        "OMNIGENT_SAAS_SOURCE_SHA": (spec.source_revision, _ZERO_GIT_SHA),
        "OMNIGENT_SAAS_UPSTREAM_REVISION": (spec.upstream_revision, _ZERO_GIT_SHA),
        "OMNIGENT_SAAS_IMAGE_DIGEST": (spec.image_digest, _ZERO_DIGEST),
        "OMNIGENT_SAAS_RELEASE_INCARNATION": (
            spec.release_incarnation,
            _TEMPLATE_RELEASE_INCARNATION,
        ),
        "OMNIGENT_SAAS_RUNTIME_VERSION": (
            spec.runtime_version,
            "replace-with-runtime-version",
        ),
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": (
            spec.official_schema_revision,
            "replace-with-official-schema-head",
        ),
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": (
            spec.control_plane_schema_revision,
            "p0s000000011",
        ),
        "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION": (
            spec.adapter_contract_version,
            "replace-with-adapter-contract",
        ),
        "OMNIGENT_SAAS_PUBLIC_ORIGIN": (spec.public_origin, "https://next.jxhh.com"),
        "OMNIGENT_SAAS_ARTIFACT_STORE_URI": (
            spec.artifact.store_uri,
            _TEMPLATE_ARTIFACT_STORE_URI,
        ),
        "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL": (
            spec.artifact.endpoint_url,
            _TEMPLATE_ARTIFACT_ENDPOINT,
        ),
        "OMNIGENT_SAAS_ARTIFACT_REGION": (
            spec.artifact.region,
            _TEMPLATE_ARTIFACT_REGION,
        ),
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE": (
            spec.artifact.credentials_profile,
            "omnigent-saas-artifacts",
        ),
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION": (
            spec.artifact.credential_revision,
            _ZERO_DIGEST,
        ),
        "OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION": (
            receipt_value,
            _ZERO_DIGEST,
        ),
        "OMNIGENT_SAAS_ARTIFACT_READINESS_KEY": (
            spec.artifact.readiness_key,
            "readiness/omnigent-saas-canary-v1",
        ),
        "OMNIGENT_SAAS_ARTIFACT_READINESS_SHA256": (
            spec.artifact.readiness_sha256,
            _ZERO_SHA256_HEX,
        ),
        "OMNIGENT_SAAS_PREVIEW_ROOT_DOMAIN": (
            spec.preview.root_domain,
            "replace-preview-root.example.net",
        ),
        "OMNIGENT_SAAS_PREVIEW_RELAY_TRUST_BUNDLE_VERSIONS": (
            ",".join(spec.preview.relay_trust_bundle_versions),
            "replace-with-preview-relay-trust-bundle-version",
        ),
        "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS": (
            spec.preview.pod_cidr,
            "replace-with-cluster-pod-cidr",
        ),
        "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_CIDRS": (
            spec.preview.service_cidr,
            "replace-with-cluster-service-cidr",
        ),
    }
    for field, (rendered, expected) in production_values.items():
        _set_exact(production_data, field, rendered, expected=expected, name=field)

    bindings_text = _service_bindings_text(spec)
    template_bindings_text = _template_service_bindings_text()
    for document in (migration, production):
        bindings = _resource(document, kind="ConfigMap", data_key="service-role-bindings.json")
        bindings_data = _nested_mapping(bindings, "data")
        _set_exact(
            bindings_data,
            "service-role-bindings.json",
            bindings_text,
            expected=template_bindings_text,
            name="service-role bindings",
        )

    server = _resource(production, kind="Deployment", name="omnigent-saas-server")
    server_annotations = _nested_mapping(server, "spec", "template", "metadata", "annotations")
    for field, rendered in {
        "omnigent.io/artifact-credential-revision": spec.artifact.credential_revision,
        "omnigent.io/artifact-admission-receipt-revision": receipt_value,
        "omnigent.io/release-incarnation": spec.release_incarnation,
    }.items():
        expected = _TEMPLATE_RELEASE_INCARNATION if field.endswith("incarnation") else _ZERO_DIGEST
        _set_exact(
            server_annotations,
            field,
            rendered,
            expected=expected,
            name=f"server annotation {field}",
        )

    source_replicas = {
        "omnigent-saas-server": 2,
        "omnigent-saas-worker": 2,
        "omnigent-saas-runner-agent-a": 0,
        "omnigent-saas-runner-agent-b": 0,
        "omnigent-saas-preview-edge": 2,
        "omnigent-saas-preview-owner": 1,
    }
    final_replicas = {
        **source_replicas,
        "omnigent-saas-runner-agent-a": 1,
        "omnigent-saas-runner-agent-b": 1,
    }
    for deployment_name, source_count in source_replicas.items():
        deployment = _resource(production, kind="Deployment", name=deployment_name)
        deployment_spec = _nested_mapping(deployment, "spec")
        rendered_count = 0 if spec.mode == "stage" else final_replicas[deployment_name]
        _set_exact(
            deployment_spec,
            "replicas",
            rendered_count,
            expected=source_count,
            name=f"{deployment_name} replica gate",
        )

    for slot in ("a", "b"):
        runner_spec = spec.runners[slot]
        deployment = _resource(
            production,
            kind="Deployment",
            name=f"omnigent-saas-runner-agent-{slot}",
        )
        deployment_annotations = _nested_mapping(deployment, "metadata", "annotations")
        annotations = _nested_mapping(deployment, "spec", "template", "metadata", "annotations")
        fleet_phase = "admission" if spec.mode == "stage" else "runtime"
        _set_exact(
            deployment_annotations,
            "omnigent.io/runner-fleet-phase",
            fleet_phase,
            expected="admission",
            name=f"Runner {slot} fleet metadata phase",
        )
        blocker_field = "omnigent.io/production-blocker"
        if deployment_annotations.get(blocker_field) != "runner-fleet-admission-pending":
            raise ReleaseRenderError(f"Runner {slot} fleet blocker is not canonical")
        if spec.mode == "final":
            del deployment_annotations[blocker_field]
        _set_exact(
            annotations,
            "omnigent.io/runner-recovery-artifact-credential-revision",
            runner_spec.recovery_credential_revision,
            expected=_ZERO_DIGEST,
            name=f"Runner {slot} recovery annotation",
        )
        fleet_receipt_sha256 = (
            _ZERO_DIGEST if spec.mode == "stage" else spec.runner_fleet.receipt_sha256
        )
        fleet_receipt_signature_sha256 = (
            _ZERO_DIGEST if spec.mode == "stage" else spec.runner_fleet.receipt_signature_sha256
        )
        fleet_annotations = {
            "omnigent.io/runner-fleet-phase": fleet_phase,
            "omnigent.io/runner-database-fleet-namespace": spec.runner_fleet.namespace,
            "omnigent.io/runner-database-fleet-admission-epoch": str(
                spec.runner_fleet.admission_epoch
            ),
            "omnigent.io/runner-database-fleet-sha256": spec.runner_fleet.fleet_sha256,
            "omnigent.io/runner-database-fleet-context-sha256": (
                spec.runner_fleet.evidence_context_sha256
            ),
            "omnigent.io/runner-database-fleet-trust-pins-sha256": (
                spec.runner_fleet.trust_pins_sha256
            ),
            "omnigent.io/runner-database-fleet-attestation-issuer": (
                spec.runner_fleet.attestation_issuer
            ),
            "omnigent.io/runner-database-fleet-attestation-key-id": (
                spec.runner_fleet.attestation_key_id
            ),
            "omnigent.io/runner-database-fleet-attestation-public-key-sha256": (
                spec.runner_fleet.attestation_public_key_sha256
            ),
            "omnigent.io/runner-database-fleet-attestation-sha256": (
                spec.runner_fleet.attestation_sha256
            ),
            "omnigent.io/runner-database-fleet-attestation-signature-sha256": (
                spec.runner_fleet.attestation_signature_sha256
            ),
            "omnigent.io/runner-database-fleet-receipt-issuer": (spec.runner_fleet.receipt_issuer),
            "omnigent.io/runner-database-fleet-receipt-key-id": (spec.runner_fleet.receipt_key_id),
            "omnigent.io/runner-database-fleet-receipt-public-key-sha256": (
                spec.runner_fleet.receipt_public_key_sha256
            ),
            "omnigent.io/runner-database-fleet-receipt-sha256": fleet_receipt_sha256,
            "omnigent.io/runner-database-fleet-receipt-signature-sha256": (
                fleet_receipt_signature_sha256
            ),
        }
        fleet_annotation_templates = {
            "omnigent.io/runner-fleet-phase": "admission",
            "omnigent.io/runner-database-fleet-namespace": ("replace-with-runner-fleet-namespace"),
            "omnigent.io/runner-database-fleet-admission-epoch": "0",
            "omnigent.io/runner-database-fleet-sha256": _ZERO_DIGEST,
            "omnigent.io/runner-database-fleet-context-sha256": _ZERO_DIGEST,
            "omnigent.io/runner-database-fleet-trust-pins-sha256": _ZERO_DIGEST,
            "omnigent.io/runner-database-fleet-attestation-issuer": (
                "replace-with-runner-fleet-attestation-issuer"
            ),
            "omnigent.io/runner-database-fleet-attestation-key-id": (
                "replace-with-runner-fleet-attestation-key-id"
            ),
            "omnigent.io/runner-database-fleet-attestation-public-key-sha256": (_ZERO_DIGEST),
            "omnigent.io/runner-database-fleet-attestation-sha256": _ZERO_DIGEST,
            "omnigent.io/runner-database-fleet-attestation-signature-sha256": (_ZERO_DIGEST),
            "omnigent.io/runner-database-fleet-receipt-issuer": (
                "replace-with-runner-fleet-receipt-issuer"
            ),
            "omnigent.io/runner-database-fleet-receipt-key-id": (
                "replace-with-runner-fleet-receipt-key-id"
            ),
            "omnigent.io/runner-database-fleet-receipt-public-key-sha256": _ZERO_DIGEST,
            "omnigent.io/runner-database-fleet-receipt-sha256": _ZERO_DIGEST,
            "omnigent.io/runner-database-fleet-receipt-signature-sha256": _ZERO_DIGEST,
        }
        if set(fleet_annotations) != set(fleet_annotation_templates):
            raise ReleaseRenderError("internal Runner fleet annotation schema diverged")
        for field, rendered in fleet_annotations.items():
            _set_exact(
                annotations,
                field,
                rendered,
                expected=fleet_annotation_templates[field],
                name=f"Runner {slot} fleet annotation {field}",
            )
        for field, rendered, expected in (
            ("omnigent.io/runner-repository-slot", slot, slot),
            (
                "omnigent.io/runner-repository-credential-revision",
                runner_spec.repository_credential_revision,
                _ZERO_DIGEST,
            ),
            (
                "omnigent.io/runner-repository-spec-sha256",
                runner_spec.repository_spec_sha256,
                _ZERO_DIGEST,
            ),
            (
                "omnigent.io/runner-repository-bindings-sha256",
                runner_spec.repository_bindings_sha256,
                _ZERO_DIGEST,
            ),
            (
                "omnigent.io/runner-repository-receipt-sha256",
                runner_spec.repository_receipt_sha256,
                _ZERO_DIGEST,
            ),
        ):
            _set_exact(
                annotations,
                field,
                rendered,
                expected=expected,
                name=f"Runner {slot} repository annotation {field}",
            )
        pod_spec = _nested_mapping(deployment, "spec", "template", "spec")
        container = _named_row(
            pod_spec.get("containers"), name="runner-agent", row_type="container"
        )
        env = container.get("env")
        runner_fields = {
            "OMNIGENT_SAAS_RUNNER_ID": (
                runner_spec.runner_id,
                f"replace-with-runner-{slot}-uuid",
            ),
            "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": (
                str(runner_spec.connection_generation),
                "1",
            ),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI": (
                runner_spec.recovery_artifact_uri,
                f"{_TEMPLATE_ARTIFACT_STORE_URI}/runtime-recovery/runner/"
                f"replace-with-runner-{slot}-uuid/generation/1",
            ),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_ENDPOINT_URL": (
                spec.artifact.endpoint_url,
                _TEMPLATE_ARTIFACT_ENDPOINT,
            ),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_REGION": (
                spec.artifact.region,
                _TEMPLATE_ARTIFACT_REGION,
            ),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE": (
                runner_spec.recovery_credentials_profile,
                f"runner-replace-with-runner-{slot}-uuid-g1",
            ),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION": (
                runner_spec.recovery_credential_revision,
                _ZERO_DIGEST,
            ),
        }
        for field, (rendered, expected) in runner_fields.items():
            row = _named_row(env, name=field, row_type="environment entry")
            _set_exact(
                row,
                "value",
                rendered,
                expected=expected,
                name=f"Runner {slot} {field}",
            )
        fleet_environment = {
            "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_SHA256": (
                spec.runner_fleet.fleet_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_EVIDENCE_CONTEXT_SHA256": (
                spec.runner_fleet.evidence_context_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256": (
                spec.runner_fleet.trust_pins_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_NAMESPACE": spec.runner_fleet.namespace,
        }
        for field, rendered in fleet_environment.items():
            row = _named_row(env, name=field, row_type="environment entry")
            expected = (
                "replace-with-runner-fleet-namespace"
                if field.endswith("_NAMESPACE")
                else _ZERO_SHA256_HEX
            )
            _set_exact(
                row,
                "value",
                rendered,
                expected=expected,
                name=f"Runner {slot} {field}",
            )
        repository_environment = {
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RUNNER_SLOT": slot,
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_SPEC_SHA256": (
                runner_spec.repository_spec_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_BINDINGS_SHA256": (
                runner_spec.repository_bindings_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RECEIPT_SHA256": (
                runner_spec.repository_receipt_sha256.removeprefix("sha256:")
            ),
        }
        for field, rendered in repository_environment.items():
            row = _named_row(env, name=field, row_type="environment entry")
            expected = slot if field.endswith("_SLOT") else _ZERO_SHA256_HEX
            _set_exact(
                row,
                "value",
                rendered,
                expected=expected,
                name=f"Runner {slot} {field}",
            )
        database_volume = _named_row(
            pod_spec.get("volumes"),
            name="runner-database-source",
            row_type="volume",
        )
        database_secret = _nested_mapping(database_volume, "secret")
        _set_exact(
            database_secret,
            "secretName",
            f"omnigent-saas-runner-agent-{slot}-database-g{runner_spec.connection_generation}",
            expected=f"omnigent-saas-runner-agent-{slot}-database-g1",
            name=f"Runner {slot} database Secret",
        )
        credential_volume = _named_row(
            pod_spec.get("volumes"),
            name="artifact-credentials-source",
            row_type="volume",
        )
        credential_secret = _nested_mapping(credential_volume, "secret")
        _set_exact(
            credential_secret,
            "secretName",
            runner_spec.recovery_credential_secret_name,
            expected=f"omnigent-runner-{slot}-recovery-replace-g1-v1",
            name=f"Runner {slot} recovery credential Secret",
        )
        fleet_volume = _named_row(
            pod_spec.get("volumes"), name="runner-fleet-source", row_type="volume"
        )
        fleet_secret = _nested_mapping(fleet_volume, "secret")
        if fleet_secret.get("defaultMode") != 0o400 or fleet_secret.get("items") != [
            {"key": key, "path": path} for key, path in _RUNNER_FLEET_SECRET_ITEMS
        ]:
            raise ReleaseRenderError(
                f"Runner {slot} fleet Secret projection must contain the exact public files"
            )
        _set_exact(
            fleet_secret,
            "secretName",
            spec.runner_fleet.secret_name,
            expected="omnigent-saas-runner-database-fleet-replace-fleetpins12",
            name=f"Runner {slot} immutable fleet Secret",
        )
        repository_spec_volume = _named_row(
            pod_spec.get("volumes"),
            name="runner-repository-spec-source",
            row_type="volume",
        )
        _set_exact(
            _nested_mapping(repository_spec_volume, "secret"),
            "secretName",
            runner_spec.repository_spec_secret_name,
            expected=(f"omnigent-saas-runner-{slot}-repository-provisioning-replace-repospec12"),
            name=f"Runner {slot} immutable repository spec Secret",
        )
        repository_credentials_volume = _named_row(
            pod_spec.get("volumes"),
            name="runner-repository-credentials-source",
            row_type="volume",
        )
        _set_exact(
            _nested_mapping(repository_credentials_volume, "secret"),
            "secretName",
            runner_spec.repository_credentials_secret_name,
            expected=(f"omnigent-saas-runner-{slot}-repository-credentials-replace-repocreds12"),
            name=f"Runner {slot} immutable repository credential Secret",
        )

    preview_owner = _resource(production, kind="Deployment", name="omnigent-saas-preview-owner")
    owner_annotations = _nested_mapping(
        preview_owner, "spec", "template", "metadata", "annotations"
    )
    _set_exact(
        owner_annotations,
        "omnigent.io/preview-owner-incarnation",
        spec.preview.owner_incarnation,
        expected="replace-with-preview-owner-incarnation",
        name="Preview owner incarnation",
    )
    owner_pod_spec = _nested_mapping(preview_owner, "spec", "template", "spec")
    owner_container = _named_row(
        owner_pod_spec.get("containers"), name="preview-owner", row_type="container"
    )
    gateway = _named_row(
        owner_container.get("env"),
        name="OMNIGENT_SAAS_PREVIEW_GATEWAY_INSTANCE_ID",
        row_type="environment entry",
    )
    _set_exact(
        gateway,
        "value",
        spec.preview.gateway_instance_id,
        expected="replace-with-preview-gateway-instance-id",
        name="Preview Gateway instance",
    )

    final_image = f"{_IMAGE_REPOSITORY}@{spec.image_digest}"
    image_counts = {
        name: _replace_images(document, final_image) for name, document in documents.items()
    }
    if (
        image_counts["kubernetes.migration.yaml"] <= 0
        or image_counts["kubernetes.artifact-admission.yaml"] <= 0
        or image_counts["kubernetes.production.yaml"] <= 0
        or image_counts["kubernetes.network-policy.yaml"] != 0
    ):
        raise ReleaseRenderError("source image projection is incomplete")

    suffixes = {
        "release": spec.release_incarnation[:12],
        "credential": spec.artifact.credential_revision.removeprefix("sha256:")[:12],
        "bindings": hashlib.sha256(bindings_text.encode("ascii")).hexdigest()[:12],
        "owner": hashlib.sha256(spec.preview.owner_incarnation.encode("ascii")).hexdigest()[:12],
    }
    resource_token_projections = (
        (
            _resource(
                migration,
                kind="ConfigMap",
                name="omnigent-saas-migration-release-replace-release12",
            ),
            "replace-release12",
            suffixes["release"],
            1,
            "migration release ConfigMap",
        ),
        (
            _resource(
                migration,
                kind="ConfigMap",
                name="omnigent-saas-service-role-bindings-replace-bindings12",
            ),
            "replace-bindings12",
            suffixes["bindings"],
            1,
            "migration bindings ConfigMap",
        ),
        (
            _resource(migration, kind="Job", name="omnigent-saas-postgresql-migration"),
            "replace-release12",
            suffixes["release"],
            1,
            "migration Job release reference",
        ),
        (
            _resource(migration, kind="Job", name="omnigent-saas-postgresql-migration"),
            "replace-bindings12",
            suffixes["bindings"],
            1,
            "migration Job bindings reference",
        ),
        (
            _resource(
                artifact_admission,
                kind="ConfigMap",
                name="omnigent-artifact-release-replace-release12",
            ),
            "replace-release12",
            suffixes["release"],
            1,
            "artifact release ConfigMap",
        ),
        (
            _resource(
                artifact_admission,
                kind="Job",
                name="omnigent-artifact-admit-replace-release12",
            ),
            "replace-release12",
            suffixes["release"],
            2,
            "artifact admission Job release projection",
        ),
        (
            _resource(
                artifact_admission,
                kind="Job",
                name="omnigent-artifact-admit-replace-release12",
            ),
            "replace-credential12",
            suffixes["credential"],
            1,
            "artifact admission Job credential projection",
        ),
        (
            _resource(
                production,
                kind="ConfigMap",
                name="omnigent-saas-release-replace-release12",
            ),
            "replace-release12",
            suffixes["release"],
            1,
            "production release ConfigMap",
        ),
        (
            _resource(
                production,
                kind="ConfigMap",
                name="omnigent-saas-service-role-bindings-replace-bindings12",
            ),
            "replace-bindings12",
            suffixes["bindings"],
            1,
            "production bindings ConfigMap",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-server"),
            "replace-release12",
            suffixes["release"],
            2,
            "Server release projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-server"),
            "replace-credential12",
            suffixes["credential"],
            1,
            "Server credential projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-server"),
            "replace-bindings12",
            suffixes["bindings"],
            1,
            "Server bindings projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-worker"),
            "replace-release12",
            suffixes["release"],
            2,
            "Worker release projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-worker"),
            "replace-bindings12",
            suffixes["bindings"],
            1,
            "Worker bindings projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-runner-agent-a"),
            "replace-release12",
            suffixes["release"],
            1,
            "Runner A release projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-runner-agent-b"),
            "replace-release12",
            suffixes["release"],
            1,
            "Runner B release projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-preview-edge"),
            "replace-release12",
            suffixes["release"],
            1,
            "Preview Edge release projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-preview-edge"),
            "replace-bindings12",
            suffixes["bindings"],
            1,
            "Preview Edge bindings projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-preview-owner"),
            "replace-release12",
            suffixes["release"],
            1,
            "Preview Owner release projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-preview-owner"),
            "replace-bindings12",
            suffixes["bindings"],
            1,
            "Preview Owner bindings projection",
        ),
        (
            _resource(production, kind="Deployment", name="omnigent-saas-preview-owner"),
            "replace-owner12",
            suffixes["owner"],
            3,
            "Preview Owner Secret projection",
        ),
    )
    for resource, token, replacement, count, projection_name in resource_token_projections:
        _replace_exact_resource_token(
            resource,
            token=token,
            replacement=replacement,
            expected_count=count,
            name=projection_name,
        )

    network_token_projections = (
        (
            "omnigent-saas-artifact-admission",
            "replace-with-artifact-endpoint-cidr",
            spec.artifact.endpoint_cidr,
        ),
        (
            "omnigent-saas-server",
            "replace-with-artifact-endpoint-cidr",
            spec.artifact.endpoint_cidr,
        ),
        (
            "omnigent-saas-worker",
            "replace-with-artifact-endpoint-cidr",
            spec.artifact.endpoint_cidr,
        ),
        (
            "omnigent-saas-runner-agent",
            "replace-with-artifact-endpoint-cidr",
            spec.artifact.endpoint_cidr,
        ),
        (
            "omnigent-saas-runner-agent",
            "replace-with-repository-endpoint-cidr",
            spec.repository_endpoint_cidr,
        ),
        (
            "omnigent-saas-server",
            "replace-with-ingress-namespace",
            spec.ingress_namespace,
        ),
        (
            "omnigent-saas-preview-edge",
            "replace-with-ingress-namespace",
            spec.ingress_namespace,
        ),
        (
            "omnigent-saas-server",
            "replace-with-ingress-workload",
            spec.ingress_workload,
        ),
        (
            "omnigent-saas-preview-edge",
            "replace-with-ingress-workload",
            spec.ingress_workload,
        ),
    )
    for resource_name, token, replacement in network_token_projections:
        _replace_exact_resource_token(
            _resource(network, kind="NetworkPolicy", name=resource_name),
            token=token,
            replacement=replacement,
            expected_count=1,
            name=f"NetworkPolicy {resource_name}",
        )
    return documents, suffixes


def _scalar_changes(
    source: Any,
    rendered: Any,
    *,
    name: str,
    path: tuple[str | int, ...] = (),
) -> list[tuple[tuple[str | int, ...], Any, Any]]:
    if isinstance(source, dict):
        if not isinstance(rendered, dict) or set(rendered) - set(source):
            raise ReleaseRenderError(f"{name}: renderer changed mapping structure")
        changes: list[tuple[tuple[str | int, ...], Any, Any]] = []
        for key, value in source.items():
            if key not in rendered:
                changes.append(((*path, key), value, _MISSING))
                continue
            changes.extend(_scalar_changes(value, rendered[key], name=name, path=(*path, key)))
        return changes
    if isinstance(source, list):
        if not isinstance(rendered, list) or len(source) != len(rendered):
            raise ReleaseRenderError(f"{name}: renderer changed list structure")
        changes = []
        for index, (before, after) in enumerate(zip(source, rendered, strict=True)):
            changes.extend(_scalar_changes(before, after, name=name, path=(*path, index)))
        return changes
    if type(source) is not type(rendered):
        raise ReleaseRenderError(f"{name}: renderer changed scalar type")
    return [] if source == rendered else [(path, source, rendered)]


def _value_at_path(value: Any, path: tuple[str | int, ...]) -> Any:
    current = value
    for part in path:
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                raise ReleaseRenderError("release change audit path is invalid")
            current = current[part]
        else:
            if not isinstance(current, dict) or part not in current:
                raise ReleaseRenderError("release change audit path is invalid")
            current = current[part]
    return current


def _authorized_release_change(
    *,
    manifest_name: str,
    source_item: Mapping[str, Any],
    relative_path: tuple[str | int, ...],
    before: Any,
    after: Any,
    spec: KubernetesReleaseSpec,
    suffixes: Mapping[str, str],
) -> bool:
    kind = source_item.get("kind")
    metadata = source_item.get("metadata")
    if not isinstance(kind, str) or not isinstance(metadata, dict):
        return False
    resource_name = metadata.get("name")
    if not isinstance(resource_name, str):
        return False

    final_image = f"{_IMAGE_REPOSITORY}@{spec.image_digest}"
    if relative_path and relative_path[-1] == "image":
        return before == _TEMPLATE_IMAGE and after == final_image

    metadata_names = {
        (
            "kubernetes.migration.yaml",
            "ConfigMap",
            "omnigent-saas-migration-release-replace-release12",
        ): f"omnigent-saas-migration-release-{suffixes['release']}",
        (
            "kubernetes.migration.yaml",
            "ConfigMap",
            "omnigent-saas-service-role-bindings-replace-bindings12",
        ): f"omnigent-saas-service-role-bindings-{suffixes['bindings']}",
        (
            "kubernetes.artifact-admission.yaml",
            "ConfigMap",
            "omnigent-artifact-release-replace-release12",
        ): f"omnigent-artifact-release-{suffixes['release']}",
        (
            "kubernetes.artifact-admission.yaml",
            "Job",
            "omnigent-artifact-admit-replace-release12",
        ): f"omnigent-artifact-admit-{suffixes['release']}",
        (
            "kubernetes.production.yaml",
            "ConfigMap",
            "omnigent-saas-release-replace-release12",
        ): f"omnigent-saas-release-{suffixes['release']}",
        (
            "kubernetes.production.yaml",
            "ConfigMap",
            "omnigent-saas-service-role-bindings-replace-bindings12",
        ): f"omnigent-saas-service-role-bindings-{suffixes['bindings']}",
    }
    identity = (manifest_name, kind, resource_name)
    if relative_path == ("metadata", "name"):
        return metadata_names.get(identity) == after

    source_replica_counts = {
        "omnigent-saas-server": 2,
        "omnigent-saas-worker": 2,
        "omnigent-saas-runner-agent-a": 0,
        "omnigent-saas-runner-agent-b": 0,
        "omnigent-saas-preview-edge": 2,
        "omnigent-saas-preview-owner": 1,
    }
    if (
        manifest_name == "kubernetes.production.yaml"
        and kind == "Deployment"
        and relative_path == ("spec", "replicas")
        and resource_name in source_replica_counts
    ):
        expected_after = 0 if spec.mode == "stage" else source_replica_counts[resource_name]
        if spec.mode == "final" and resource_name in {
            "omnigent-saas-runner-agent-a",
            "omnigent-saas-runner-agent-b",
        }:
            expected_after = 1
        return before == source_replica_counts[resource_name] and after == expected_after

    if relative_path == ("metadata", "annotations", "omnigent.io/production-blocker"):
        return (
            identity
            in {
                (
                    "kubernetes.production.yaml",
                    "Deployment",
                    "omnigent-saas-runner-agent-a",
                ),
                (
                    "kubernetes.production.yaml",
                    "Deployment",
                    "omnigent-saas-runner-agent-b",
                ),
            }
            and spec.mode == "final"
            and before == "runner-fleet-admission-pending"
            and after is _MISSING
        )

    if len(relative_path) == 2 and relative_path[0] == "data":
        field = relative_path[1]
        receipt_value = _ZERO_DIGEST if spec.mode == "stage" else spec.artifact.receipt_revision
        data_pairs = {
            (
                "kubernetes.migration.yaml",
                "omnigent-saas-migration-release-replace-release12",
            ): {
                "OMNIGENT_SAAS_PRODUCT_REVISION": (_ZERO_GIT_SHA, spec.product_revision),
                "OMNIGENT_SAAS_SOURCE_SHA": (_ZERO_GIT_SHA, spec.source_revision),
            },
            (
                "kubernetes.migration.yaml",
                "omnigent-saas-service-role-bindings-replace-bindings12",
            ): {
                "service-role-bindings.json": (
                    _template_service_bindings_text(),
                    _service_bindings_text(spec),
                )
            },
            (
                "kubernetes.artifact-admission.yaml",
                "omnigent-artifact-release-replace-release12",
            ): {
                "OMNIGENT_SAAS_PRODUCT_REVISION": (_ZERO_GIT_SHA, spec.product_revision),
                "OMNIGENT_SAAS_SOURCE_SHA": (_ZERO_GIT_SHA, spec.source_revision),
                "OMNIGENT_SAAS_IMAGE_DIGEST": (_ZERO_DIGEST, spec.image_digest),
                "OMNIGENT_SAAS_RELEASE_INCARNATION": (
                    _TEMPLATE_RELEASE_INCARNATION,
                    spec.release_incarnation,
                ),
                "OMNIGENT_SAAS_ARTIFACT_STORE_URI": (
                    _TEMPLATE_ARTIFACT_STORE_URI,
                    spec.artifact.store_uri,
                ),
                "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL": (
                    _TEMPLATE_ARTIFACT_ENDPOINT,
                    spec.artifact.endpoint_url,
                ),
                "OMNIGENT_SAAS_ARTIFACT_REGION": (
                    _TEMPLATE_ARTIFACT_REGION,
                    spec.artifact.region,
                ),
                "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE": (
                    "omnigent-saas-artifacts",
                    spec.artifact.credentials_profile,
                ),
                "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION": (
                    _ZERO_DIGEST,
                    spec.artifact.credential_revision,
                ),
            },
            (
                "kubernetes.production.yaml",
                "omnigent-saas-release-replace-release12",
            ): {
                "OMNIGENT_SAAS_PRODUCT_REVISION": (_ZERO_GIT_SHA, spec.product_revision),
                "OMNIGENT_SAAS_SOURCE_SHA": (_ZERO_GIT_SHA, spec.source_revision),
                "OMNIGENT_SAAS_UPSTREAM_REVISION": (_ZERO_GIT_SHA, spec.upstream_revision),
                "OMNIGENT_SAAS_IMAGE_DIGEST": (_ZERO_DIGEST, spec.image_digest),
                "OMNIGENT_SAAS_RELEASE_INCARNATION": (
                    _TEMPLATE_RELEASE_INCARNATION,
                    spec.release_incarnation,
                ),
                "OMNIGENT_SAAS_RUNTIME_VERSION": (
                    "replace-with-runtime-version",
                    spec.runtime_version,
                ),
                "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": (
                    "replace-with-official-schema-head",
                    spec.official_schema_revision,
                ),
                "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": (
                    _CONTROL_PLANE_SCHEMA_REVISION,
                    spec.control_plane_schema_revision,
                ),
                "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION": (
                    "replace-with-adapter-contract",
                    spec.adapter_contract_version,
                ),
                "OMNIGENT_SAAS_PUBLIC_ORIGIN": (
                    "https://next.jxhh.com",
                    spec.public_origin,
                ),
                "OMNIGENT_SAAS_ARTIFACT_STORE_URI": (
                    _TEMPLATE_ARTIFACT_STORE_URI,
                    spec.artifact.store_uri,
                ),
                "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL": (
                    _TEMPLATE_ARTIFACT_ENDPOINT,
                    spec.artifact.endpoint_url,
                ),
                "OMNIGENT_SAAS_ARTIFACT_REGION": (
                    _TEMPLATE_ARTIFACT_REGION,
                    spec.artifact.region,
                ),
                "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE": (
                    "omnigent-saas-artifacts",
                    spec.artifact.credentials_profile,
                ),
                "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION": (
                    _ZERO_DIGEST,
                    spec.artifact.credential_revision,
                ),
                "OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION": (
                    _ZERO_DIGEST,
                    receipt_value,
                ),
                "OMNIGENT_SAAS_ARTIFACT_READINESS_KEY": (
                    "readiness/omnigent-saas-canary-v1",
                    spec.artifact.readiness_key,
                ),
                "OMNIGENT_SAAS_ARTIFACT_READINESS_SHA256": (
                    _ZERO_SHA256_HEX,
                    spec.artifact.readiness_sha256,
                ),
                "OMNIGENT_SAAS_PREVIEW_ROOT_DOMAIN": (
                    "replace-preview-root.example.net",
                    spec.preview.root_domain,
                ),
                "OMNIGENT_SAAS_PREVIEW_RELAY_TRUST_BUNDLE_VERSIONS": (
                    "replace-with-preview-relay-trust-bundle-version",
                    ",".join(spec.preview.relay_trust_bundle_versions),
                ),
                "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS": (
                    "replace-with-cluster-pod-cidr",
                    spec.preview.pod_cidr,
                ),
                "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_CIDRS": (
                    "replace-with-cluster-service-cidr",
                    spec.preview.service_cidr,
                ),
            },
            (
                "kubernetes.production.yaml",
                "omnigent-saas-service-role-bindings-replace-bindings12",
            ): {
                "service-role-bindings.json": (
                    _template_service_bindings_text(),
                    _service_bindings_text(spec),
                )
            },
        }
        resource_pairs = data_pairs.get((manifest_name, resource_name), {})
        expected_pair = resource_pairs.get(field) if isinstance(field, str) else None
        return expected_pair is not None and (before, after) == expected_pair

    if kind == "NetworkPolicy" and manifest_name == "kubernetes.network-policy.yaml":
        network_pairs = {
            (
                "omnigent-saas-artifact-admission",
                "replace-with-artifact-endpoint-cidr",
                spec.artifact.endpoint_cidr,
                "cidr",
            ),
            (
                "omnigent-saas-server",
                "replace-with-artifact-endpoint-cidr",
                spec.artifact.endpoint_cidr,
                "cidr",
            ),
            (
                "omnigent-saas-worker",
                "replace-with-artifact-endpoint-cidr",
                spec.artifact.endpoint_cidr,
                "cidr",
            ),
            (
                "omnigent-saas-runner-agent",
                "replace-with-artifact-endpoint-cidr",
                spec.artifact.endpoint_cidr,
                "cidr",
            ),
            (
                "omnigent-saas-runner-agent",
                "replace-with-repository-endpoint-cidr",
                spec.repository_endpoint_cidr,
                "cidr",
            ),
            (
                "omnigent-saas-server",
                "replace-with-ingress-namespace",
                spec.ingress_namespace,
                "kubernetes.io/metadata.name",
            ),
            (
                "omnigent-saas-preview-edge",
                "replace-with-ingress-namespace",
                spec.ingress_namespace,
                "kubernetes.io/metadata.name",
            ),
            (
                "omnigent-saas-server",
                "replace-with-ingress-workload",
                spec.ingress_workload,
                "app.kubernetes.io/name",
            ),
            (
                "omnigent-saas-preview-edge",
                "replace-with-ingress-workload",
                spec.ingress_workload,
                "app.kubernetes.io/name",
            ),
        }
        return (
            bool(relative_path)
            and (resource_name, before, after, relative_path[-1]) in network_pairs
        )

    if len(relative_path) >= 2 and relative_path[-2] == "annotations":
        field = relative_path[-1]
        if not isinstance(field, str):
            return False
        receipt_value = _ZERO_DIGEST if spec.mode == "stage" else spec.artifact.receipt_revision
        annotation_pairs: dict[str, tuple[Any, Any]] = {}
        if identity == (
            "kubernetes.artifact-admission.yaml",
            "Job",
            "omnigent-artifact-admit-replace-release12",
        ):
            annotation_pairs = {
                "omnigent.io/artifact-credential-revision": (
                    _ZERO_DIGEST,
                    spec.artifact.credential_revision,
                ),
                "omnigent.io/release-incarnation": (
                    _TEMPLATE_RELEASE_INCARNATION,
                    spec.release_incarnation,
                ),
            }
        elif identity == (
            "kubernetes.production.yaml",
            "Deployment",
            "omnigent-saas-server",
        ):
            annotation_pairs = {
                "omnigent.io/artifact-credential-revision": (
                    _ZERO_DIGEST,
                    spec.artifact.credential_revision,
                ),
                "omnigent.io/artifact-admission-receipt-revision": (
                    _ZERO_DIGEST,
                    receipt_value,
                ),
                "omnigent.io/release-incarnation": (
                    _TEMPLATE_RELEASE_INCARNATION,
                    spec.release_incarnation,
                ),
            }
        elif (
            resource_name
            in {
                "omnigent-saas-runner-agent-a",
                "omnigent-saas-runner-agent-b",
            }
            and manifest_name == "kubernetes.production.yaml"
        ):
            slot = resource_name[-1]
            runner_spec = spec.runners[slot]
            fleet_phase = "admission" if spec.mode == "stage" else "runtime"
            fleet_receipt_sha256 = (
                _ZERO_DIGEST if spec.mode == "stage" else spec.runner_fleet.receipt_sha256
            )
            fleet_receipt_signature_sha256 = (
                _ZERO_DIGEST
                if spec.mode == "stage"
                else spec.runner_fleet.receipt_signature_sha256
            )
            annotation_pairs = {
                "omnigent.io/runner-recovery-artifact-credential-revision": (
                    _ZERO_DIGEST,
                    runner_spec.recovery_credential_revision,
                ),
                "omnigent.io/runner-fleet-phase": ("admission", fleet_phase),
                "omnigent.io/runner-database-fleet-namespace": (
                    "replace-with-runner-fleet-namespace",
                    spec.runner_fleet.namespace,
                ),
                "omnigent.io/runner-database-fleet-admission-epoch": (
                    "0",
                    str(spec.runner_fleet.admission_epoch),
                ),
                "omnigent.io/runner-database-fleet-sha256": (
                    _ZERO_DIGEST,
                    spec.runner_fleet.fleet_sha256,
                ),
                "omnigent.io/runner-database-fleet-context-sha256": (
                    _ZERO_DIGEST,
                    spec.runner_fleet.evidence_context_sha256,
                ),
                "omnigent.io/runner-database-fleet-trust-pins-sha256": (
                    _ZERO_DIGEST,
                    spec.runner_fleet.trust_pins_sha256,
                ),
                "omnigent.io/runner-database-fleet-attestation-issuer": (
                    "replace-with-runner-fleet-attestation-issuer",
                    spec.runner_fleet.attestation_issuer,
                ),
                "omnigent.io/runner-database-fleet-attestation-key-id": (
                    "replace-with-runner-fleet-attestation-key-id",
                    spec.runner_fleet.attestation_key_id,
                ),
                "omnigent.io/runner-database-fleet-attestation-public-key-sha256": (
                    _ZERO_DIGEST,
                    spec.runner_fleet.attestation_public_key_sha256,
                ),
                "omnigent.io/runner-database-fleet-attestation-sha256": (
                    _ZERO_DIGEST,
                    spec.runner_fleet.attestation_sha256,
                ),
                "omnigent.io/runner-database-fleet-attestation-signature-sha256": (
                    _ZERO_DIGEST,
                    spec.runner_fleet.attestation_signature_sha256,
                ),
                "omnigent.io/runner-database-fleet-receipt-issuer": (
                    "replace-with-runner-fleet-receipt-issuer",
                    spec.runner_fleet.receipt_issuer,
                ),
                "omnigent.io/runner-database-fleet-receipt-key-id": (
                    "replace-with-runner-fleet-receipt-key-id",
                    spec.runner_fleet.receipt_key_id,
                ),
                "omnigent.io/runner-database-fleet-receipt-public-key-sha256": (
                    _ZERO_DIGEST,
                    spec.runner_fleet.receipt_public_key_sha256,
                ),
                "omnigent.io/runner-database-fleet-receipt-sha256": (
                    _ZERO_DIGEST,
                    fleet_receipt_sha256,
                ),
                "omnigent.io/runner-database-fleet-receipt-signature-sha256": (
                    _ZERO_DIGEST,
                    fleet_receipt_signature_sha256,
                ),
                "omnigent.io/runner-repository-credential-revision": (
                    _ZERO_DIGEST,
                    runner_spec.repository_credential_revision,
                ),
                "omnigent.io/runner-repository-spec-sha256": (
                    _ZERO_DIGEST,
                    runner_spec.repository_spec_sha256,
                ),
                "omnigent.io/runner-repository-bindings-sha256": (
                    _ZERO_DIGEST,
                    runner_spec.repository_bindings_sha256,
                ),
                "omnigent.io/runner-repository-receipt-sha256": (
                    _ZERO_DIGEST,
                    runner_spec.repository_receipt_sha256,
                ),
            }
        elif identity == (
            "kubernetes.production.yaml",
            "Deployment",
            "omnigent-saas-preview-owner",
        ):
            annotation_pairs = {
                "omnigent.io/preview-owner-incarnation": (
                    "replace-with-preview-owner-incarnation",
                    spec.preview.owner_incarnation,
                )
            }
        expected_pair = annotation_pairs.get(field)
        return expected_pair is not None and (before, after) == expected_pair

    if (
        len(relative_path) >= 3
        and relative_path[-3] == "env"
        and isinstance(relative_path[-2], int)
        and relative_path[-1] == "value"
    ):
        row = _value_at_path(source_item, relative_path[:-1])
        env_name = row.get("name") if isinstance(row, dict) else None
        container = _value_at_path(source_item, relative_path[:-3])
        container_name = container.get("name") if isinstance(container, dict) else None
        if (
            resource_name
            in {
                "omnigent-saas-runner-agent-a",
                "omnigent-saas-runner-agent-b",
            }
            and container_name == "runner-agent"
        ):
            slot = resource_name[-1]
            runner_spec = spec.runners[slot]
            runner_env_pairs = {
                "OMNIGENT_SAAS_RUNNER_ID": (
                    f"replace-with-runner-{slot}-uuid",
                    runner_spec.runner_id,
                ),
                "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": (
                    "1",
                    str(runner_spec.connection_generation),
                ),
                "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI": (
                    f"{_TEMPLATE_ARTIFACT_STORE_URI}/runtime-recovery/runner/"
                    f"replace-with-runner-{slot}-uuid/generation/1",
                    runner_spec.recovery_artifact_uri,
                ),
                "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_ENDPOINT_URL": (
                    _TEMPLATE_ARTIFACT_ENDPOINT,
                    spec.artifact.endpoint_url,
                ),
                "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_REGION": (
                    _TEMPLATE_ARTIFACT_REGION,
                    spec.artifact.region,
                ),
                "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE": (
                    f"runner-replace-with-runner-{slot}-uuid-g1",
                    runner_spec.recovery_credentials_profile,
                ),
                "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION": (
                    _ZERO_DIGEST,
                    runner_spec.recovery_credential_revision,
                ),
                "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_SHA256": (
                    _ZERO_SHA256_HEX,
                    spec.runner_fleet.fleet_sha256.removeprefix("sha256:"),
                ),
                "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_EVIDENCE_CONTEXT_SHA256": (
                    _ZERO_SHA256_HEX,
                    spec.runner_fleet.evidence_context_sha256.removeprefix("sha256:"),
                ),
                "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256": (
                    _ZERO_SHA256_HEX,
                    spec.runner_fleet.trust_pins_sha256.removeprefix("sha256:"),
                ),
                "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_NAMESPACE": (
                    "replace-with-runner-fleet-namespace",
                    spec.runner_fleet.namespace,
                ),
                "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_SPEC_SHA256": (
                    _ZERO_SHA256_HEX,
                    runner_spec.repository_spec_sha256.removeprefix("sha256:"),
                ),
                "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_BINDINGS_SHA256": (
                    _ZERO_SHA256_HEX,
                    runner_spec.repository_bindings_sha256.removeprefix("sha256:"),
                ),
                "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RECEIPT_SHA256": (
                    _ZERO_SHA256_HEX,
                    runner_spec.repository_receipt_sha256.removeprefix("sha256:"),
                ),
            }
            expected_pair = runner_env_pairs.get(env_name) if isinstance(env_name, str) else None
            return expected_pair is not None and (before, after) == expected_pair
        return (
            resource_name == "omnigent-saas-preview-owner"
            and container_name == "preview-owner"
            and env_name == "OMNIGENT_SAAS_PREVIEW_GATEWAY_INSTANCE_ID"
            and before == "replace-with-preview-gateway-instance-id"
            and after == spec.preview.gateway_instance_id
        )

    if isinstance(before, str) and isinstance(after, str):
        token_pairs = {
            "replace-release12": suffixes["release"],
            "replace-credential12": suffixes["credential"],
            "replace-bindings12": suffixes["bindings"],
            "replace-owner12": suffixes["owner"],
        }
        for token, replacement in token_pairs.items():
            if token not in before or after != before.replace(token, replacement):
                continue
            if relative_path[-2:] == ("configMapRef", "name"):
                return token == "replace-release12"
            if relative_path[-2:] == ("configMap", "name"):
                return token == "replace-bindings12"
            if relative_path[-2:] == ("secret", "secretName"):
                return token in {
                    "replace-release12",
                    "replace-credential12",
                    "replace-owner12",
                }

    if relative_path[-2:] == ("secret", "secretName"):
        if resource_name not in {
            "omnigent-saas-runner-agent-a",
            "omnigent-saas-runner-agent-b",
        }:
            return False
        volume = _value_at_path(source_item, relative_path[:-2])
        volume_name = volume.get("name") if isinstance(volume, dict) else None
        slot = resource_name[-1]
        runner_spec = spec.runners[slot]
        secret_pairs = {
            "runner-database-source": (
                f"omnigent-saas-runner-agent-{slot}-database-g1",
                f"omnigent-saas-runner-agent-{slot}-database-g{runner_spec.connection_generation}",
            ),
            "artifact-credentials-source": (
                f"omnigent-runner-{slot}-recovery-replace-g1-v1",
                runner_spec.recovery_credential_secret_name,
            ),
            "runner-fleet-source": (
                "omnigent-saas-runner-database-fleet-replace-fleetpins12",
                spec.runner_fleet.secret_name,
            ),
            "runner-repository-spec-source": (
                f"omnigent-saas-runner-{slot}-repository-provisioning-replace-repospec12",
                runner_spec.repository_spec_secret_name,
            ),
            "runner-repository-credentials-source": (
                f"omnigent-saas-runner-{slot}-repository-credentials-replace-repocreds12",
                runner_spec.repository_credentials_secret_name,
            ),
        }
        expected_pair = secret_pairs.get(volume_name) if isinstance(volume_name, str) else None
        return expected_pair is not None and (before, after) == expected_pair
    return False


def _assert_authorized_release_changes(
    source: dict[str, Any],
    rendered: dict[str, Any],
    *,
    name: str,
    spec: KubernetesReleaseSpec,
    suffixes: Mapping[str, str],
) -> None:
    changes = _scalar_changes(source, rendered, name=name)
    source_items = _items(source, name=name)
    for path, before, after in changes:
        if len(path) < 3 or path[0] != "items" or not isinstance(path[1], int):
            raise ReleaseRenderError(f"{name}: renderer changed an unauthorized document scalar")
        item_index = path[1]
        if item_index >= len(source_items) or not _authorized_release_change(
            manifest_name=name,
            source_item=source_items[item_index],
            relative_path=path[2:],
            before=before,
            after=after,
            spec=spec,
            suffixes=suffixes,
        ):
            raise ReleaseRenderError(f"{name}: renderer changed an unauthorized scalar")


def _dump_document(document: Mapping[str, Any]) -> bytes:
    return yaml.safe_dump(
        dict(document),
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
        width=4096,
    ).encode("ascii")


def _walk_strings(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                values.append(key)
            values.extend(_walk_strings(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_walk_strings(child))
    elif isinstance(value, str):
        values.append(value)
    return values


def _audit_no_sentinels(
    documents: Mapping[str, dict[str, Any]],
    spec: KubernetesReleaseSpec,
    suffixes: Mapping[str, str],
) -> None:
    receipt_zero_count = sum(
        value.count(_ZERO_DIGEST)
        for document in documents.values()
        for value in _walk_strings(document)
    )
    expected_zero_count = 6 if spec.mode == "stage" else 0
    if receipt_zero_count != expected_zero_count:
        raise ReleaseRenderError(
            f"{spec.mode} release must contain exactly {expected_zero_count} "
            "pending receipt sentinel(s)"
        )
    audited = copy.deepcopy(documents)
    production = audited["kubernetes.production.yaml"]
    release_name = f"omnigent-saas-release-{suffixes['release']}"
    release_config = _resource(production, kind="ConfigMap", name=release_name)
    release_data = _nested_mapping(release_config, "data")
    server = _resource(production, kind="Deployment", name="omnigent-saas-server")
    annotations = _nested_mapping(server, "spec", "template", "metadata", "annotations")
    receipt_field = "OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION"
    annotation_field = "omnigent.io/artifact-admission-receipt-revision"
    expected = _ZERO_DIGEST if spec.mode == "stage" else spec.artifact.receipt_revision
    if (
        release_data.get(receipt_field) != expected
        or annotations.get(annotation_field) != expected
    ):
        raise ReleaseRenderError("artifact receipt projection is incomplete")
    if spec.mode == "stage":
        release_data[receipt_field] = f"sha256:{'f' * 64}"
        annotations[annotation_field] = f"sha256:{'f' * 64}"

    fleet_receipt_sha256 = (
        _ZERO_DIGEST if spec.mode == "stage" else spec.runner_fleet.receipt_sha256
    )
    fleet_receipt_signature_sha256 = (
        _ZERO_DIGEST if spec.mode == "stage" else spec.runner_fleet.receipt_signature_sha256
    )
    for slot in ("a", "b"):
        runner = _resource(
            production,
            kind="Deployment",
            name=f"omnigent-saas-runner-agent-{slot}",
        )
        runner_annotations = _nested_mapping(runner, "spec", "template", "metadata", "annotations")
        fleet_receipt_field = "omnigent.io/runner-database-fleet-receipt-sha256"
        fleet_signature_field = "omnigent.io/runner-database-fleet-receipt-signature-sha256"
        if (
            runner_annotations.get(fleet_receipt_field) != fleet_receipt_sha256
            or runner_annotations.get(fleet_signature_field) != fleet_receipt_signature_sha256
        ):
            raise ReleaseRenderError(f"Runner {slot} fleet receipt projection is incomplete")
        if spec.mode == "stage":
            runner_annotations[fleet_receipt_field] = f"sha256:{'f' * 64}"
            runner_annotations[fleet_signature_field] = f"sha256:{'f' * 64}"

    for name, document in audited.items():
        for value in _walk_strings(document):
            if _SENTINEL.search(value):
                raise ReleaseRenderError(
                    f"{name}: unresolved or unknown template sentinel remains"
                )
            if _DEFAULT_ROUTE.search(value):
                raise ReleaseRenderError(f"{name}: default-route CIDR is forbidden")


def _audit_projection(
    documents: Mapping[str, dict[str, Any]],
    spec: KubernetesReleaseSpec,
    suffixes: Mapping[str, str],
) -> None:
    for manifest_name, resources in _PUBLIC_CA_SECRET_PROJECTIONS.items():
        document = documents[manifest_name]
        for resource_name, projections in resources.items():
            resource = _resource(
                document,
                kind="Job" if manifest_name == "kubernetes.migration.yaml" else "Deployment",
                name=resource_name,
            )
            pod_spec = _nested_mapping(resource, "spec", "template", "spec")
            for volume_name, secret_name in projections.items():
                volume = _named_row(pod_spec.get("volumes"), name=volume_name, row_type="volume")
                if _nested_mapping(volume, "secret") != {
                    "secretName": secret_name,
                    "defaultMode": 0o400,
                    "items": [{"key": "ca.crt", "path": "ca.crt"}],
                }:
                    raise ReleaseRenderError(
                        f"{resource_name} public CA Secret projection diverged"
                    )
    final_image = f"{_IMAGE_REPOSITORY}@{spec.image_digest}"
    for name, document in documents.items():
        for item in _items(document, name=name):
            metadata = _mapping(item.get("metadata"), name=f"{name} metadata")
            if metadata.get("namespace") != TARGET_NAMESPACE:
                raise ReleaseRenderError(f"{name}: target namespace projection is incomplete")
        for value in _walk_strings(document):
            if value.startswith(f"{_IMAGE_REPOSITORY}@") and value != final_image:
                raise ReleaseRenderError(f"{name}: image digest projection is inconsistent")

    production = documents["kubernetes.production.yaml"]
    release = _resource(
        production,
        kind="ConfigMap",
        name=f"omnigent-saas-release-{suffixes['release']}",
    )
    data = _nested_mapping(release, "data")
    expected_release_values = {
        "OMNIGENT_SAAS_PRODUCT_REVISION": spec.product_revision,
        "OMNIGENT_SAAS_SOURCE_SHA": spec.source_revision,
        "OMNIGENT_SAAS_UPSTREAM_REVISION": spec.upstream_revision,
        "OMNIGENT_SAAS_IMAGE_DIGEST": spec.image_digest,
        "OMNIGENT_SAAS_RELEASE_INCARNATION": spec.release_incarnation,
        "OMNIGENT_SAAS_RUNTIME_VERSION": spec.runtime_version,
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": spec.official_schema_revision,
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": spec.control_plane_schema_revision,
        "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION": spec.adapter_contract_version,
        "OMNIGENT_SAAS_PUBLIC_ORIGIN": spec.public_origin,
        "OMNIGENT_SAAS_ARTIFACT_STORE_URI": spec.artifact.store_uri,
        "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL": spec.artifact.endpoint_url,
        "OMNIGENT_SAAS_ARTIFACT_REGION": spec.artifact.region,
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE": spec.artifact.credentials_profile,
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION": spec.artifact.credential_revision,
        "OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION": (
            _ZERO_DIGEST if spec.mode == "stage" else spec.artifact.receipt_revision
        ),
        "OMNIGENT_SAAS_ARTIFACT_READINESS_KEY": spec.artifact.readiness_key,
        "OMNIGENT_SAAS_ARTIFACT_READINESS_SHA256": spec.artifact.readiness_sha256,
        "OMNIGENT_SAAS_PREVIEW_ROOT_DOMAIN": spec.preview.root_domain,
        "OMNIGENT_SAAS_PREVIEW_RELAY_TRUST_BUNDLE_VERSIONS": ",".join(
            spec.preview.relay_trust_bundle_versions
        ),
        "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS": spec.preview.pod_cidr,
        "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_CIDRS": spec.preview.service_cidr,
    }
    if any(data.get(key) != value for key, value in expected_release_values.items()):
        raise ReleaseRenderError("production release facts are not bound consistently")

    binding_text = _service_bindings_text(spec)
    for manifest_name in ("kubernetes.migration.yaml", "kubernetes.production.yaml"):
        config = _resource(
            documents[manifest_name], kind="ConfigMap", data_key="service-role-bindings.json"
        )
        if _nested_mapping(config, "data").get("service-role-bindings.json") != binding_text:
            raise ReleaseRenderError("service-role bindings diverged across manifests")

    source_replicas = {
        "omnigent-saas-server": 2,
        "omnigent-saas-worker": 2,
        "omnigent-saas-runner-agent-a": 0,
        "omnigent-saas-runner-agent-b": 0,
        "omnigent-saas-preview-edge": 2,
        "omnigent-saas-preview-owner": 1,
    }
    for deployment_name, source_count in source_replicas.items():
        deployment = _resource(production, kind="Deployment", name=deployment_name)
        expected_replicas = 0 if spec.mode == "stage" else source_count
        if spec.mode == "final" and deployment_name in {
            "omnigent-saas-runner-agent-a",
            "omnigent-saas-runner-agent-b",
        }:
            expected_replicas = 1
        if _nested_mapping(deployment, "spec").get("replicas") != expected_replicas:
            raise ReleaseRenderError(
                f"{deployment_name}: {spec.mode} replica gate is inconsistent"
            )

    for slot in ("a", "b"):
        runner_spec = spec.runners[slot]
        deployment = _resource(
            production,
            kind="Deployment",
            name=f"omnigent-saas-runner-agent-{slot}",
        )
        fleet_phase = "admission" if spec.mode == "stage" else "runtime"
        deployment_annotations = _nested_mapping(deployment, "metadata", "annotations")
        if deployment_annotations.get("omnigent.io/runner-fleet-phase") != fleet_phase:
            raise ReleaseRenderError(f"Runner {slot} fleet phase projection diverged")
        blocker = deployment_annotations.get("omnigent.io/production-blocker", _MISSING)
        expected_blocker = "runner-fleet-admission-pending" if spec.mode == "stage" else _MISSING
        if blocker != expected_blocker:
            raise ReleaseRenderError(f"Runner {slot} fleet blocker projection diverged")
        annotations = _nested_mapping(deployment, "spec", "template", "metadata", "annotations")
        fleet_receipt_sha256 = (
            _ZERO_DIGEST if spec.mode == "stage" else spec.runner_fleet.receipt_sha256
        )
        fleet_receipt_signature_sha256 = (
            _ZERO_DIGEST if spec.mode == "stage" else spec.runner_fleet.receipt_signature_sha256
        )
        expected_annotations = {
            "omnigent.io/runner-repository-expected-binding-keys": "primary",
            "omnigent.io/runner-repository-slot": slot,
            "omnigent.io/runner-repository-credential-revision": (
                runner_spec.repository_credential_revision
            ),
            "omnigent.io/runner-repository-spec-sha256": runner_spec.repository_spec_sha256,
            "omnigent.io/runner-repository-bindings-sha256": (
                runner_spec.repository_bindings_sha256
            ),
            "omnigent.io/runner-repository-receipt-sha256": (
                runner_spec.repository_receipt_sha256
            ),
            "omnigent.io/runner-recovery-artifact-credential-revision": (
                runner_spec.recovery_credential_revision
            ),
            "omnigent.io/runner-fleet-phase": fleet_phase,
            "omnigent.io/runner-database-fleet-namespace": spec.runner_fleet.namespace,
            "omnigent.io/runner-database-fleet-admission-epoch": str(
                spec.runner_fleet.admission_epoch
            ),
            "omnigent.io/runner-database-fleet-sha256": spec.runner_fleet.fleet_sha256,
            "omnigent.io/runner-database-fleet-context-sha256": (
                spec.runner_fleet.evidence_context_sha256
            ),
            "omnigent.io/runner-database-fleet-trust-pins-sha256": (
                spec.runner_fleet.trust_pins_sha256
            ),
            "omnigent.io/runner-database-fleet-attestation-issuer": (
                spec.runner_fleet.attestation_issuer
            ),
            "omnigent.io/runner-database-fleet-attestation-key-id": (
                spec.runner_fleet.attestation_key_id
            ),
            "omnigent.io/runner-database-fleet-attestation-public-key-sha256": (
                spec.runner_fleet.attestation_public_key_sha256
            ),
            "omnigent.io/runner-database-fleet-attestation-sha256": (
                spec.runner_fleet.attestation_sha256
            ),
            "omnigent.io/runner-database-fleet-attestation-signature-sha256": (
                spec.runner_fleet.attestation_signature_sha256
            ),
            "omnigent.io/runner-database-fleet-receipt-issuer": (spec.runner_fleet.receipt_issuer),
            "omnigent.io/runner-database-fleet-receipt-key-id": (spec.runner_fleet.receipt_key_id),
            "omnigent.io/runner-database-fleet-receipt-public-key-sha256": (
                spec.runner_fleet.receipt_public_key_sha256
            ),
            "omnigent.io/runner-database-fleet-receipt-sha256": fleet_receipt_sha256,
            "omnigent.io/runner-database-fleet-receipt-signature-sha256": (
                fleet_receipt_signature_sha256
            ),
        }
        if any(annotations.get(field) != value for field, value in expected_annotations.items()):
            raise ReleaseRenderError(f"Runner {slot} fleet annotations diverged")
        pod_spec = _nested_mapping(deployment, "spec", "template", "spec")
        container = _named_row(
            pod_spec.get("containers"), name="runner-agent", row_type="container"
        )
        expected_env = {
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RUNNER_SLOT": slot,
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_SPEC_SHA256": (
                runner_spec.repository_spec_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_BINDINGS_SHA256": (
                runner_spec.repository_bindings_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RECEIPT_SHA256": (
                runner_spec.repository_receipt_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_MIRROR_ROOT": (f"/repository/state/mirrors/{slot}"),
            "OMNIGENT_SAAS_RUNNER_ID": runner_spec.runner_id,
            "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": str(runner_spec.connection_generation),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI": (runner_spec.recovery_artifact_uri),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_ENDPOINT_URL": (spec.artifact.endpoint_url),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_REGION": spec.artifact.region,
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE": (
                runner_spec.recovery_credentials_profile
            ),
            "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION": (
                runner_spec.recovery_credential_revision
            ),
            "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_SHA256": (
                spec.runner_fleet.fleet_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_EVIDENCE_CONTEXT_SHA256": (
                spec.runner_fleet.evidence_context_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256": (
                spec.runner_fleet.trust_pins_sha256.removeprefix("sha256:")
            ),
            "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_NAMESPACE": spec.runner_fleet.namespace,
        }
        for field, value in expected_env.items():
            row = _named_row(container.get("env"), name=field, row_type="environment entry")
            if row.get("value") != value:
                raise ReleaseRenderError(f"Runner {slot} release binding diverged")
        expected_secrets = {
            "runner-database-source": (
                f"omnigent-saas-runner-agent-{slot}-database-g{runner_spec.connection_generation}"
            ),
            "artifact-credentials-source": runner_spec.recovery_credential_secret_name,
            "runner-fleet-source": spec.runner_fleet.secret_name,
            "runner-repository-spec-source": runner_spec.repository_spec_secret_name,
            "runner-repository-credentials-source": (
                runner_spec.repository_credentials_secret_name
            ),
        }
        for volume_name, expected_secret in expected_secrets.items():
            volume = _named_row(pod_spec.get("volumes"), name=volume_name, row_type="volume")
            if _nested_mapping(volume, "secret").get("secretName") != expected_secret:
                raise ReleaseRenderError(f"Runner {slot} immutable Secret binding diverged")
        fleet_secret = _nested_mapping(
            _named_row(pod_spec.get("volumes"), name="runner-fleet-source", row_type="volume"),
            "secret",
        )
        if fleet_secret.get("defaultMode") != 0o400 or fleet_secret.get("items") != [
            {"key": key, "path": path} for key, path in _RUNNER_FLEET_SECRET_ITEMS
        ]:
            raise ReleaseRenderError(
                f"Runner {slot} fleet Secret projection must contain the exact public files"
            )
        init_container = _named_row(
            pod_spec.get("initContainers"),
            name="stage-runner-identity",
            row_type="init container",
        )
        repository_secret_volumes = {
            "runner-repository-spec-source",
            "runner-repository-credentials-source",
        }
        init_mounts = {
            row.get("name"): row
            for row in init_container.get("volumeMounts", [])
            if isinstance(row, dict) and isinstance(row.get("name"), str)
        }
        main_mounts = {
            row.get("name"): row
            for row in container.get("volumeMounts", [])
            if isinstance(row, dict) and isinstance(row.get("name"), str)
        }
        if not repository_secret_volumes.issubset(init_mounts.keys()) or (
            repository_secret_volumes & main_mounts.keys()
        ):
            raise ReleaseRenderError(f"Runner {slot} repository Secrets must remain init-only")
        if any(
            init_mounts[name].get("readOnly") is not True for name in repository_secret_volumes
        ):
            raise ReleaseRenderError(f"Runner {slot} repository Secrets must be read-only")
        repository_spec_secret = _nested_mapping(
            _named_row(
                pod_spec.get("volumes"),
                name="runner-repository-spec-source",
                row_type="volume",
            ),
            "secret",
        )
        if repository_spec_secret != {
            "secretName": runner_spec.repository_spec_secret_name,
            "defaultMode": 0o400,
            "items": [
                {
                    "key": "repository-provisioning.json",
                    "path": "repository-provisioning.json",
                }
            ],
        }:
            raise ReleaseRenderError(f"Runner {slot} repository spec Secret projection diverged")
        repository_credential_secret = _nested_mapping(
            _named_row(
                pod_spec.get("volumes"),
                name="runner-repository-credentials-source",
                row_type="volume",
            ),
            "secret",
        )
        if repository_credential_secret != {
            "secretName": runner_spec.repository_credentials_secret_name,
            "defaultMode": 0o400,
            "items": [{"key": "primary.credential", "path": "primary.credential"}],
        }:
            raise ReleaseRenderError(
                f"Runner {slot} repository credential Secret projection diverged"
            )
        init_args = init_container.get("args")
        expected_provision_command = (
            "omnigent-saas-provision-runner-repositories --spec "
            "/provisioning-private/spec/repository-provisioning.json "
            "--expected-binding-key primary"
        )
        provision_lines = (
            [
                line.strip()
                for line in init_args[0].splitlines()
                if line.strip().startswith("omnigent-saas-provision-runner-repositories")
            ]
            if isinstance(init_args, list)
            and len(init_args) == 1
            and isinstance(init_args[0], str)
            else []
        )
        if provision_lines != [expected_provision_command]:
            raise ReleaseRenderError(f"Runner {slot} repository exact-primary init gate diverged")
        expected_main_mounts = {
            "runtime-secrets": {
                "name": "runtime-secrets",
                "mountPath": "/runtime",
                "readOnly": True,
            },
            "repository-state": {"name": "repository-state", "mountPath": "/repository"},
            "work": {"name": "work", "mountPath": "/work"},
            "preview-socket": {"name": "preview-socket", "mountPath": "/preview/socket"},
            "preview-log": {"name": "preview-log", "mountPath": "/preview/log"},
            "temp": {"name": "temp", "mountPath": "/tmp"},
        }
        if main_mounts != expected_main_mounts:
            raise ReleaseRenderError(f"Runner {slot} main volume mount projection diverged")
        for mounts in (init_mounts, main_mounts):
            state_mount = mounts.get("repository-state")
            if (
                not isinstance(state_mount, dict)
                or state_mount.get("mountPath") != "/repository"
                or state_mount.get("readOnly") is True
            ):
                raise ReleaseRenderError(
                    f"Runner {slot} repository state must be shared read-write"
                )
        main_work = main_mounts.get("work")
        if not isinstance(main_work, dict) or main_work.get("mountPath") != "/work":
            raise ReleaseRenderError(f"Runner {slot} work mount projection diverged")

    network_values = set(_walk_strings(documents["kubernetes.network-policy.yaml"]))
    for value in (
        spec.artifact.endpoint_cidr,
        spec.repository_endpoint_cidr,
        spec.ingress_namespace,
        spec.ingress_workload,
    ):
        if value not in network_values:
            raise ReleaseRenderError("NetworkPolicy release binding is incomplete")
    _audit_no_sentinels(documents, spec, suffixes)


def _prepare_output_directory(source_dir: Path, output_dir: Path) -> None:
    try:
        source_resolved = source_dir.resolve(strict=True)
        output_resolved = output_dir.resolve(strict=False)
    except OSError as error:
        raise ReleaseRenderError("source or output directory cannot be resolved") from error
    if output_resolved == source_resolved or output_resolved.is_relative_to(source_resolved):
        raise ReleaseRenderError("output directory must be outside the source directory")
    if output_dir.exists() or output_dir.is_symlink():
        try:
            metadata = output_dir.lstat()
            has_entries = any(output_dir.iterdir())
        except OSError as error:
            raise ReleaseRenderError("output directory cannot be inspected") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ReleaseRenderError("output directory must be a real mode-0700 directory")
        if has_entries:
            raise ReleaseRenderError("output directory must be empty")
        return
    try:
        output_dir.mkdir(mode=0o700)
        output_dir.chmod(0o700)
    except OSError as error:
        raise ReleaseRenderError("output directory cannot be created") from error


def _write_exclusive(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        with suppress(OSError):
            path.unlink()
        raise ReleaseRenderError(f"{path.name}: output cannot be written") from error


def _load_rendered_manifest(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
        document = yaml.safe_load(raw.decode("ascii"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ReleaseRenderError(f"{path.name}: rendered manifest cannot be audited") from error
    return raw, _mapping(document, name=f"{path.name} rendered manifest")


def render_kubernetes_release(
    spec_file: Path, source_dir: Path, output_dir: Path
) -> dict[str, Any]:
    """Render four manifests and one canonical secret-free evidence document."""

    spec = load_public_release_spec(spec_file)
    sources = _load_source_manifests(source_dir)
    release_documents, suffixes = _render_release_documents(sources, spec)
    release_bytes: dict[str, bytes] = {}
    for name in MANIFEST_NAMES:
        _assert_authorized_release_changes(
            sources[name].document,
            release_documents[name],
            name=name,
            spec=spec,
            suffixes=suffixes,
        )
        release_bytes[name] = _dump_document(release_documents[name])

    final_bytes: dict[str, bytes] = {}
    final_documents: dict[str, dict[str, Any]] = {}
    namespace_summary: dict[str, Any]
    namespace_evidence: dict[str, Any]
    try:
        with tempfile.TemporaryDirectory(prefix="omnigent-release-render-") as temporary:
            temporary_root = Path(temporary)
            temporary_root.chmod(0o700)
            release_source = temporary_root / "release"
            release_source.mkdir(mode=0o700)
            namespace_output = temporary_root / "namespace"
            for name in MANIFEST_NAMES:
                _write_exclusive(release_source / name, release_bytes[name])
            try:
                namespace_summary = render_namespace_manifests(release_source, namespace_output)
            except NamespaceRenderError as error:
                raise ReleaseRenderError(
                    f"namespace renderer rejected release: {error}"
                ) from error
            namespace_evidence_path = namespace_output / "namespace-render-evidence.json"
            namespace_evidence_raw = namespace_evidence_path.read_bytes()
            namespace_evidence_value = json.loads(namespace_evidence_raw.decode("ascii"))
            namespace_evidence = _mapping(
                namespace_evidence_value, name="namespace render evidence"
            )
            if namespace_evidence_raw != _canonical_json(namespace_evidence):
                raise ReleaseRenderError("namespace renderer evidence is not canonical")
            for name in MANIFEST_NAMES:
                raw, document = _load_rendered_manifest(namespace_output / name)
                final_bytes[name] = raw
                final_documents[name] = document
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseRenderError("namespace renderer output cannot be audited") from error

    _audit_projection(final_documents, spec, suffixes)
    file_rows = [
        {
            "name": name,
            "source_sha256": _sha256(sources[name].raw),
            "release_rendered_sha256": _sha256(release_bytes[name]),
            "rendered_sha256": _sha256(final_bytes[name]),
        }
        for name in MANIFEST_NAMES
    ]
    rendered_set_sha256 = _sha256(
        _canonical_json(
            {
                "files": [
                    {"name": row["name"], "rendered_sha256": row["rendered_sha256"]}
                    for row in file_rows
                ]
            }
        )
    )
    receipt_state = "pending" if spec.mode == "stage" else "bound"
    evidence: dict[str, Any] = {
        "artifact": {
            "credential_revision": spec.artifact.credential_revision,
            "credentials_profile": spec.artifact.credentials_profile,
            "endpoint_url_sha256": _sha256(spec.artifact.endpoint_url.encode("ascii")),
            "region": spec.artifact.region,
            "readiness_sha256": spec.artifact.readiness_sha256,
            "receipt_revision": (None if spec.mode == "stage" else spec.artifact.receipt_revision),
            "receipt_state": receipt_state,
            "store_uri_sha256": _sha256(spec.artifact.store_uri.encode("ascii")),
        },
        "files": file_rows,
        "image_digest": spec.image_digest,
        "manifest_count": len(file_rows),
        "mode": spec.mode,
        "namespace_render": {
            "evidence_sha256": namespace_summary["evidence_sha256"],
            "rendered_set_sha256": namespace_summary["rendered_set_sha256"],
            "source_namespace": namespace_evidence["source_namespace"],
            "target_namespace": namespace_evidence["target_namespace"],
        },
        "product_revision": spec.product_revision,
        "release_contract": {
            "adapter_contract_version": spec.adapter_contract_version,
            "control_plane_schema_revision": spec.control_plane_schema_revision,
            "official_schema_revision": spec.official_schema_revision,
            "runtime_version": spec.runtime_version,
        },
        "release_incarnation": spec.release_incarnation,
        "rendered_set_sha256": rendered_set_sha256,
        "runner_fleet": {
            "admission_epoch": spec.runner_fleet.admission_epoch,
            "attestation": {
                "document_sha256": spec.runner_fleet.attestation_sha256,
                "issuer": spec.runner_fleet.attestation_issuer,
                "key_id": spec.runner_fleet.attestation_key_id,
                "public_key_sha256": spec.runner_fleet.attestation_public_key_sha256,
                "signature_sha256": spec.runner_fleet.attestation_signature_sha256,
            },
            "evidence_context_sha256": spec.runner_fleet.evidence_context_sha256,
            "fleet_sha256": spec.runner_fleet.fleet_sha256,
            "namespace": spec.runner_fleet.namespace,
            "phase": "admission" if spec.mode == "stage" else "runtime",
            "receipt": {
                "document_sha256": spec.runner_fleet.receipt_sha256,
                "issuer": spec.runner_fleet.receipt_issuer,
                "key_id": spec.runner_fleet.receipt_key_id,
                "public_key_sha256": spec.runner_fleet.receipt_public_key_sha256,
                "signature_sha256": spec.runner_fleet.receipt_signature_sha256,
                "state": "pending" if spec.mode == "stage" else "bound",
            },
            "secret_name": spec.runner_fleet.secret_name,
            "trust_pins_sha256": spec.runner_fleet.trust_pins_sha256,
        },
        "runners": {
            slot: {
                "connection_generation": spec.runners[slot].connection_generation,
                "recovery_artifact_uri_sha256": _sha256(
                    spec.runners[slot].recovery_artifact_uri.encode("ascii")
                ),
                "recovery_credential_revision": (spec.runners[slot].recovery_credential_revision),
                "recovery_credential_secret_name": (
                    spec.runners[slot].recovery_credential_secret_name
                ),
                "recovery_credentials_profile": (spec.runners[slot].recovery_credentials_profile),
                "repository_pre_provisioning_expectations": {
                    "bindings_sha256": spec.runners[slot].repository_bindings_sha256,
                    "credential_revision": (spec.runners[slot].repository_credential_revision),
                    "credentials_secret_name": (
                        spec.runners[slot].repository_credentials_secret_name
                    ),
                    "final_init_requirement": "must-reproduce-exact-digests",
                    "receipt_sha256": spec.runners[slot].repository_receipt_sha256,
                    "source": "owner-sealed-pre-provisioning-rehearsal",
                    "spec_secret_name": spec.runners[slot].repository_spec_secret_name,
                    "spec_sha256": spec.runners[slot].repository_spec_sha256,
                },
                "replicas": 0 if spec.mode == "stage" else 1,
                "runner_id": spec.runners[slot].runner_id,
            }
            for slot in ("a", "b")
        },
        "schema_version": 1,
        "service_role_bindings_sha256": hashlib.sha256(
            _service_bindings_text(spec).encode("ascii")
        ).hexdigest(),
        "spec_sha256": spec.source_sha256,
        "source_revision": spec.source_revision,
        "status": "pass",
        "upstream_revision": spec.upstream_revision,
    }
    evidence_bytes = _canonical_json(evidence)

    _prepare_output_directory(source_dir, output_dir)
    created: list[Path] = []
    try:
        for name in MANIFEST_NAMES:
            path = output_dir / name
            _write_exclusive(path, final_bytes[name])
            created.append(path)
        evidence_path = output_dir / EVIDENCE_FILE_NAME
        _write_exclusive(evidence_path, evidence_bytes)
        created.append(evidence_path)
    except ReleaseRenderError:
        for path in created:
            with suppress(OSError):
                path.unlink()
        raise

    return {
        "evidence_file": EVIDENCE_FILE_NAME,
        "evidence_sha256": _sha256(evidence_bytes),
        "manifest_count": len(file_rows),
        "mode": spec.mode,
        "receipt_state": receipt_state,
        "rendered_set_sha256": rendered_set_sha256,
        "status": "pass",
    }


def _default_source_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "deployment" / "server"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Render one canonical public release spec into the exact four next-beta "
            "Kubernetes manifests."
        )
    )
    parser.add_argument("--spec-file", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, default=_default_source_dir())
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = render_kubernetes_release(
            arguments.spec_file, arguments.source_dir, arguments.output_dir
        )
    except ReleaseRenderError as error:
        print(
            json.dumps(
                {"error": str(error), "status": "fail"},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EVIDENCE_FILE_NAME",
    "KubernetesReleaseSpec",
    "ReleaseRenderError",
    "load_public_release_spec",
    "main",
    "render_kubernetes_release",
]
