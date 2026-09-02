"""Fail-closed contract for the exact production Runner database fleet."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import sqlalchemy as sa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import Connection, Engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent, RuntimePlacementRecord
from saas.control_plane.scheduling_models import (
    CapabilityTokenRecord,
    RunnerPoolRecord,
    RunnerRegistrationRecord,
)
from saas.production.admission import admission_signature_payload

RUNNER_DATABASE_FLEET_FILE_ENV = "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_FILE"
RUNNER_DATABASE_FLEET_SHA256_ENV = "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_SHA256"
RUNNER_DATABASE_FLEET_CONTEXT_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_EVIDENCE_CONTEXT_FILE"
)
RUNNER_DATABASE_FLEET_CONTEXT_SHA256_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_EVIDENCE_CONTEXT_SHA256"
)
RUNNER_DATABASE_FLEET_ADMIN_URL_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_ADMIN_DATABASE_URL_FILE"
)
RUNNER_DATABASE_FLEET_NAMESPACE_ENV = "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_NAMESPACE"
RUNNER_DATABASE_FLEET_STAGE_FILE_ENV = "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_STAGE_FILE"
RUNNER_DATABASE_FLEET_STAGE_SHA256_ENV = "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_STAGE_SHA256"
RUNNER_DATABASE_FLEET_STAGE_TOKEN_OUTPUT_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_STAGE_TOKEN_OUTPUT_FILE"
)
RUNNER_DATABASE_FLEET_STAGE_DATABASE_HOST_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_STAGE_DATABASE_HOST"
)
RUNNER_DATABASE_FLEET_STAGE_DATABASE_PORT_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_STAGE_DATABASE_PORT"
)
RUNNER_DATABASE_FLEET_STAGE_DATABASE_NAME_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_STAGE_DATABASE_NAME"
)
RUNNER_DATABASE_FLEET_TRUST_PINS_FILE_ENV = "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_TRUST_PINS_FILE"
RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256"
)
RUNNER_DATABASE_FLEET_ATTESTATION_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_ENVIRONMENT_ATTESTATION_FILE"
)
RUNNER_DATABASE_FLEET_ATTESTATION_SIGNATURE_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_ENVIRONMENT_ATTESTATION_SIGNATURE_FILE"
)
RUNNER_DATABASE_FLEET_ATTESTATION_PUBLIC_KEY_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_ENVIRONMENT_ATTESTATION_PUBLIC_KEY_FILE"
)
RUNNER_DATABASE_FLEET_RECEIPT_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_ADMISSION_RECEIPT_FILE"
)
RUNNER_DATABASE_FLEET_RECEIPT_SIGNATURE_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_ADMISSION_RECEIPT_SIGNATURE_FILE"
)
RUNNER_DATABASE_FLEET_RECEIPT_PUBLIC_KEY_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_ADMISSION_RECEIPT_PUBLIC_KEY_FILE"
)
RUNNER_DATABASE_FLEET_RECEIPT_PRIVATE_KEY_FILE_ENV = (
    "OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_ADMISSION_RECEIPT_PRIVATE_KEY_FILE"
)

_SCHEMA_REVISION = "p0s000000011"
_RUNNER_BASE_ROLE = "saas_runner_agent"
_RUNNER_ROLE_PATTERN = r"^runner_[0-9a-f]{32}_g[1-9][0-9]*$"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RELEASE_INCARNATION = re.compile(r"^[0-9a-f]{32}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_DATABASE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_RESOURCE_VERSION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_INSTANCE_KEY = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_FAILURE_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9.-]{0,126}[a-z0-9]$")
_ADAPTER_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_ISSUER = re.compile(r"^[a-z0-9][a-z0-9./:_-]{2,255}$")
_MAX_DOCUMENT_BYTES = 64 * 1024
_MAX_DATABASE_URL_BYTES = 16 * 1024
_MAX_KEY_BYTES = 16 * 1024
_EXPECTED_SLOTS = ("a", "b")
_ATTESTATION_PAYLOAD_TYPE = (
    "application/vnd.omnigent.runner-database-fleet-environment-attestation.v1+json"
)
_RECEIPT_PAYLOAD_TYPE = "application/vnd.omnigent.runner-database-fleet-admission-receipt.v1+json"
_ATTESTATION_AUDIENCE = "omnigent.runner-database-fleet.owner-admission"
_RECEIPT_AUDIENCE = "omnigent.runner-database-fleet.promotion-and-runtime"
_MAX_ATTESTATION_TTL = timedelta(minutes=10)
_MAX_RECEIPT_TTL = timedelta(minutes=5)
_EXPECTED_SOURCE_HASH_KEYS = frozenset(
    {
        "cluster_sql",
        "roles_sql",
        "runner_database_fleet",
        "runner_executor",
        "verify_runner_database_fleet",
    }
)
_ALLOWED_ADMIN_URL_QUERY_KEYS = frozenset(
    {
        "application_name",
        "connect_timeout",
        "sslcert",
        "sslkey",
        "sslmode",
        "sslrootcert",
        "target_session_attrs",
    }
)
_LIBPQ_ENVIRONMENTS = frozenset(
    {
        "PGAPPNAME",
        "PGCHANNELBINDING",
        "PGCLIENTENCODING",
        "PGCONNECT_TIMEOUT",
        "PGDATABASE",
        "PGGSSENCMODE",
        "PGHOST",
        "PGHOSTADDR",
        "PGOPTIONS",
        "PGPASSFILE",
        "PGPASSWORD",
        "PGPORT",
        "PGREQUIRESSL",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGSSLCERT",
        "PGSSLCRL",
        "PGSSLCRLDIR",
        "PGSSLKEY",
        "PGSSLMODE",
        "PGSSLROOTCERT",
        "PGTARGETSESSIONATTRS",
        "PGUSER",
    }
)


class RunnerDatabaseFleetError(RuntimeError):
    """Stable rejection for a malformed or unsafe Runner database fleet."""


def runner_database_fleet_source_sha256s() -> dict[str, str]:
    """Hash every installed SQL/Python source that makes the signed decision."""

    try:
        control_plane = files("saas.control_plane")
        production = files("saas.production")
        scripts = files("saas.scripts")
        sources = {
            "cluster_sql": control_plane.joinpath(
                "postgresql_runner_agent_cluster.sql"
            ).read_bytes(),
            "roles_sql": control_plane.joinpath("postgresql_roles.sql").read_bytes(),
            "runner_database_fleet": Path(__file__).read_bytes(),
            "runner_executor": production.joinpath("runner_executor.py").read_bytes(),
            "verify_runner_database_fleet": scripts.joinpath(
                "verify_runner_database_fleet.py"
            ).read_bytes(),
        }
    except OSError:
        raise RunnerDatabaseFleetError("Runner fleet admission sources are unavailable") from None
    return {name: hashlib.sha256(value).hexdigest() for name, value in sources.items()}


@dataclass(frozen=True, slots=True)
class RunnerDatabaseFleetMember:
    """One immutable Runner incarnation and its direct-login generation."""

    runner_id: UUID
    connection_generation: int

    @property
    def login(self) -> str:
        return f"runner_{self.runner_id.hex}_g{self.connection_generation}"


@dataclass(frozen=True, slots=True)
class RunnerDatabaseFleet:
    """The exact two-member fleet loaded from one canonical owner-only file."""

    path: Path
    sha256: str
    runners: tuple[RunnerDatabaseFleetMember, ...]


@dataclass(frozen=True, slots=True)
class RunnerDatabaseFleetStageSpec:
    """Owner-only desired registration facts for one pre-Pod incarnation."""

    runner_id: UUID
    pool_id: UUID
    placement_id: UUID
    instance_key: str
    failure_domain: str
    protocol_version: int
    source_revision: str
    schema_revision: str
    adapter_contract_version: str
    capabilities: tuple[str, ...]
    max_concurrency: int


@dataclass(frozen=True, slots=True)
class StagedRunnerDatabaseFleetMember:
    """One staged identity; the raw token is returned once to the external Secret writer."""

    runner_id: UUID
    connection_generation: int
    connection_token: str
    status: str


@dataclass(frozen=True, slots=True)
class RunnerDatabaseFleetEvidenceMember:
    """Secret-free Kubernetes identity evidence for one fleet member."""

    slot: str
    runner_id: UUID
    connection_generation: int
    pool_id: UUID
    placement_id: UUID
    instance_key: str
    failure_domain: str
    protocol_version: int
    source_revision: str
    schema_revision: str
    adapter_contract_version: str
    capabilities: tuple[str, ...]
    capabilities_sha256: str
    max_concurrency: int
    deployment_name: str
    deployment_uid: UUID
    deployment_template_sha256: str
    deployment_yaml_sha256: str
    database_secret_name: str
    database_secret_uid: UUID
    database_secret_resource_version: str


@dataclass(frozen=True, slots=True)
class RunnerDatabaseFleetEvidenceContext:
    """Canonical external facts that the database receipt must bind."""

    path: Path
    sha256: str
    product_revision: str
    image_digest: str
    schema_revision: str
    namespace: str
    release_incarnation: str
    admission_epoch: int
    cnpg_cluster_namespace: str
    cnpg_cluster_name: str
    cnpg_cluster_uid: UUID
    cnpg_cluster_resource_version: str
    cnpg_postgresql_major: int
    database: str
    database_oid: int
    database_system_identifier: str
    database_service_name: str
    database_service_uid: UUID
    database_service_resource_version: str
    database_service_dns: str
    database_service_port: int
    database_service_cluster_ip: str
    database_service_selector_sha256: str
    database_endpoint_slices_sha256: str
    runners: tuple[RunnerDatabaseFleetEvidenceMember, ...]


@dataclass(frozen=True, slots=True)
class RunnerDatabaseFleetTrustPins:
    """GitOps-rendered trust roots and exact artifact hashes pinned by Pod annotation."""

    path: Path
    sha256: str
    stage: str
    admission_epoch: int
    product_revision: str
    schema_revision: str
    fleet_sha256: str
    evidence_context_sha256: str
    attestation_issuer: str
    attestation_key_id: str
    attestation_public_key_sha256: str
    attestation_sha256: str
    attestation_signature_sha256: str
    receipt_issuer: str
    receipt_key_id: str
    receipt_public_key_sha256: str
    receipt_sha256: str | None
    receipt_signature_sha256: str | None


@dataclass(frozen=True, slots=True)
class VerifiedRunnerDatabaseFleetAttestation:
    """Canonical environment attestation accepted under a pinned Ed25519 key."""

    document: dict[str, object]
    sha256: str
    signature_sha256: str
    public_key_sha256: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedRunnerDatabaseFleetAdmission:
    """Signed DB receipt revalidated inside the locked promotion transaction."""

    document: dict[str, object]
    receipt_sha256: str
    signature_sha256: str
    public_key_sha256: str
    admission_epoch: int
    issued_at: datetime
    expires_at: datetime
    fleet_sha256: str
    evidence_context_sha256: str
    environment_attestation_sha256: str
    catalog_projection_sha256: str
    registration_projection_sha256: str
    online_registration_projection_sha256: str
    product_revision: str
    schema_revision: str


@dataclass(frozen=True, slots=True)
class SignedRunnerDatabaseFleetAdmission:
    """Canonical receipt and detached signature emitted without private-key material."""

    receipt: str
    receipt_sha256: str
    signature: str
    signature_sha256: str


@dataclass(frozen=True, slots=True)
class RunnerDatabaseRoleProjection:
    """Non-secret role flags used by owner-side admission."""

    name: str
    can_login: bool
    is_superuser: bool
    can_create_database: bool
    can_create_role: bool
    can_replicate: bool
    bypasses_rls: bool
    inherits_roles: bool
    connection_limit: int
    role_config_is_null: bool
    valid_until_is_null: bool


@dataclass(frozen=True, slots=True)
class RunnerDatabaseMembershipProjection:
    """One PostgreSQL 18 role-membership edge and all grant options."""

    member: str
    granted_role: str
    admin_option: bool
    inherit_option: bool
    set_option: bool


@dataclass(frozen=True, slots=True)
class RunnerDatabaseRegistrationProjection:
    """Only the non-secret registration fields needed for fleet admission."""

    runner_id: UUID
    pool_id: UUID
    placement_id: UUID
    instance_key: str
    failure_domain: str
    connection_generation: int
    status: str
    connection_token_sha256: str
    protocol_version: int
    source_revision: str
    schema_revision: str
    adapter_contract_version: str
    capabilities: tuple[str, ...]
    capabilities_sha256: str
    max_concurrency: int
    active_leases: int


@dataclass(frozen=True, slots=True)
class RunnerDatabaseIdentityProjection:
    """Stable, non-secret identity of the inspected PostgreSQL database."""

    operator: str
    session_user: str
    database: str
    database_oid: int
    server_version_num: int
    system_identifier: str
    in_recovery: bool
    tls: bool
    transaction_read_only: bool
    operator_is_superuser: bool


@dataclass(frozen=True, slots=True)
class RunnerDatabaseFleetCatalogProjection:
    """Complete read-only fleet projection used to make one admission decision."""

    identity: RunnerDatabaseIdentityProjection
    schema_revision: str
    cluster_settings: tuple[tuple[str, str, str, bool, str], ...]
    prepared_transaction_count: int
    roles: tuple[RunnerDatabaseRoleProjection, ...]
    memberships: tuple[RunnerDatabaseMembershipProjection, ...]
    direct_acl_count: int
    owned_object_count: int
    role_setting_count: int
    user_mapping_count: int
    direct_policy_count: int
    registrations: tuple[RunnerDatabaseRegistrationProjection, ...]


def _canonical_json(document: object) -> str:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    )


def _canonical_uuid(value: object, *, field: str) -> UUID:
    if not isinstance(value, str):
        raise RunnerDatabaseFleetError(f"{field} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except ValueError:
        raise RunnerDatabaseFleetError(f"{field} must be a canonical UUID") from None
    if parsed.int == 0 or str(parsed) != value:
        raise RunnerDatabaseFleetError(f"{field} must be a canonical UUID")
    return parsed


def _generation(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63 - 1:
        raise RunnerDatabaseFleetError(f"{field} must be a positive bigint")
    return value


def _nonzero_match(value: object, pattern: re.Pattern[str], *, field: str) -> str:
    if (
        not isinstance(value, str)
        or pattern.fullmatch(value) is None
        or set(value.removeprefix("sha256:")) == {"0"}
    ):
        raise RunnerDatabaseFleetError(f"{field} is invalid")
    return value


def _dns_label(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _DNS_LABEL.fullmatch(value) is None:
        raise RunnerDatabaseFleetError(f"{field} must be a DNS label")
    return value


def _read_owner_only_file(
    source: Mapping[str, str],
    name: str,
    *,
    maximum: int,
) -> tuple[Path, bytes]:
    value = source.get(name)
    if value is None or not value or value != value.strip() or "\x00" in value:
        raise RunnerDatabaseFleetError(f"{name} is required")
    path = Path(value)
    if not path.is_absolute():
        raise RunnerDatabaseFleetError(f"{name} must be an absolute path")
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened_before = os.fstat(descriptor)
        after_open = path.lstat()
        identity = (opened_before.st_dev, opened_before.st_ino)
        metadata = (
            opened_before.st_mode,
            opened_before.st_uid,
            opened_before.st_size,
            opened_before.st_mtime_ns,
            opened_before.st_ctime_ns,
        )
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened_before.st_mode)
            or (before.st_dev, before.st_ino) != identity
            or (after_open.st_dev, after_open.st_ino) != identity
            or opened_before.st_uid != os.geteuid()
            or stat.S_IMODE(opened_before.st_mode) != 0o400
            or not 0 < opened_before.st_size <= maximum
        ):
            raise RunnerDatabaseFleetError(
                f"{name} must be an owner-readable, owner-only, read-only regular file"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        after_read = path.lstat()
        if (
            len(raw) != opened_before.st_size
            or len(raw) > maximum
            or (opened_after.st_dev, opened_after.st_ino) != identity
            or (after_read.st_dev, after_read.st_ino) != identity
            or (
                opened_after.st_mode,
                opened_after.st_uid,
                opened_after.st_size,
                opened_after.st_mtime_ns,
                opened_after.st_ctime_ns,
            )
            != metadata
        ):
            raise RunnerDatabaseFleetError(f"{name} changed while it was being read")
        return path, raw
    except RunnerDatabaseFleetError:
        raise
    except OSError:
        raise RunnerDatabaseFleetError(f"{name} cannot be inspected or read") from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _expected_sha256(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RunnerDatabaseFleetError(f"{name} must be a lowercase SHA256")
    return value


def _read_canonical_document(
    source: Mapping[str, str],
    *,
    file_environment: str,
    sha256_environment: str,
) -> tuple[Path, str, dict[str, object], str]:
    path, raw_bytes = _read_owner_only_file(
        source,
        file_environment,
        maximum=_MAX_DOCUMENT_BYTES,
    )
    expected_sha256 = _expected_sha256(source, sha256_environment)
    try:
        raw = raw_bytes.decode("ascii")
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise RunnerDatabaseFleetError(f"{file_environment} cannot be loaded") from None
    observed_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if not hmac.compare_digest(observed_sha256, expected_sha256):
        raise RunnerDatabaseFleetError(f"{file_environment} SHA256 does not match")
    if not isinstance(document, dict):
        raise RunnerDatabaseFleetError(f"{file_environment} must contain a JSON object")
    return path, observed_sha256, cast(dict[str, object], document), raw


def _format_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RunnerDatabaseFleetError("Runner fleet time must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RunnerDatabaseFleetError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise RunnerDatabaseFleetError(f"{field} is invalid") from None
    if parsed.tzinfo is None or _format_time(parsed) != value:
        raise RunnerDatabaseFleetError(f"{field} is invalid")
    return parsed.astimezone(UTC)


def _validate_signature_window(
    *,
    issued_at: datetime,
    expires_at: datetime,
    now: datetime,
    maximum_ttl: timedelta,
    subject: str,
) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise RunnerDatabaseFleetError("Runner fleet verifier clock is invalid")
    checked_at = now.astimezone(UTC)
    if (
        issued_at > checked_at
        or checked_at >= expires_at
        or expires_at <= issued_at
        or expires_at - issued_at > maximum_ttl
    ):
        raise RunnerDatabaseFleetError(f"Runner fleet {subject} is expired or not yet valid")


def _public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _load_pinned_public_key(
    source: Mapping[str, str],
    *,
    file_environment: str,
    expected_sha256: str,
) -> Ed25519PublicKey:
    _path, raw = _read_owner_only_file(source, file_environment, maximum=_MAX_KEY_BYTES)
    try:
        loaded = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError):
        raise RunnerDatabaseFleetError("Runner fleet public key is invalid") from None
    if not isinstance(loaded, Ed25519PublicKey) or not hmac.compare_digest(
        _public_key_fingerprint(loaded), expected_sha256
    ):
        raise RunnerDatabaseFleetError("Runner fleet public key does not match trust pins")
    return loaded


def _load_pinned_private_key(
    source: Mapping[str, str],
    *,
    expected_public_key_sha256: str,
) -> Ed25519PrivateKey:
    _path, raw = _read_owner_only_file(
        source,
        RUNNER_DATABASE_FLEET_RECEIPT_PRIVATE_KEY_FILE_ENV,
        maximum=_MAX_KEY_BYTES,
    )
    try:
        loaded = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError):
        raise RunnerDatabaseFleetError("Runner fleet receipt signing key is invalid") from None
    if not isinstance(loaded, Ed25519PrivateKey) or not hmac.compare_digest(
        _public_key_fingerprint(loaded.public_key()), expected_public_key_sha256
    ):
        raise RunnerDatabaseFleetError(
            "Runner fleet receipt signing key does not match trust pins"
        )
    return loaded


def _load_detached_signature(
    source: Mapping[str, str],
    *,
    file_environment: str,
    expected_sha256: str,
) -> bytes:
    _path, raw = _read_owner_only_file(source, file_environment, maximum=1024)
    try:
        encoded = raw.decode("ascii")
        signature = base64.b64decode(encoded, validate=True)
    except (UnicodeError, binascii.Error):
        raise RunnerDatabaseFleetError("Runner fleet detached signature is invalid") from None
    if (
        encoded != encoded.strip()
        or len(signature) != 64
        or not hmac.compare_digest(hashlib.sha256(signature).hexdigest(), expected_sha256)
    ):
        raise RunnerDatabaseFleetError("Runner fleet detached signature does not match trust pins")
    return signature


def _trust_pins_document(pins: RunnerDatabaseFleetTrustPins) -> dict[str, object]:
    return {
        "admission_epoch": pins.admission_epoch,
        "attestation_issuer": pins.attestation_issuer,
        "attestation_key_id": pins.attestation_key_id,
        "attestation_public_key_sha256": pins.attestation_public_key_sha256,
        "attestation_sha256": pins.attestation_sha256,
        "attestation_signature_sha256": pins.attestation_signature_sha256,
        "evidence_context_sha256": pins.evidence_context_sha256,
        "fleet_sha256": pins.fleet_sha256,
        "product_revision": pins.product_revision,
        "receipt_issuer": pins.receipt_issuer,
        "receipt_key_id": pins.receipt_key_id,
        "receipt_public_key_sha256": pins.receipt_public_key_sha256,
        "receipt_sha256": pins.receipt_sha256,
        "receipt_signature_sha256": pins.receipt_signature_sha256,
        "schema_revision": pins.schema_revision,
        "schema_version": 1,
        "stage": pins.stage,
    }


def render_runner_database_fleet_trust_pins(pins: RunnerDatabaseFleetTrustPins) -> str:
    """Render trust pins whose SHA is projected from the immutable Pod annotation."""

    _validate_trust_pins(pins)
    return _canonical_json(_trust_pins_document(pins))


def _validate_trust_pins(pins: RunnerDatabaseFleetTrustPins) -> None:
    if pins.stage not in {"admission", "runtime"}:
        raise RunnerDatabaseFleetError("Runner fleet trust-pin stage is invalid")
    _generation(pins.admission_epoch, field="admission_epoch")
    _nonzero_match(pins.product_revision, _FULL_GIT_SHA, field="product_revision")
    if pins.schema_revision != _SCHEMA_REVISION:
        raise RunnerDatabaseFleetError("Runner fleet trust-pin schema is invalid")
    for field, value in (
        ("fleet_sha256", pins.fleet_sha256),
        ("evidence_context_sha256", pins.evidence_context_sha256),
        ("attestation_public_key_sha256", pins.attestation_public_key_sha256),
        ("attestation_sha256", pins.attestation_sha256),
        ("attestation_signature_sha256", pins.attestation_signature_sha256),
        ("receipt_public_key_sha256", pins.receipt_public_key_sha256),
    ):
        _nonzero_match(value, _SHA256, field=field)
    if (
        _ISSUER.fullmatch(pins.attestation_issuer) is None
        or _KEY_ID.fullmatch(pins.attestation_key_id) is None
    ):
        raise RunnerDatabaseFleetError("Runner fleet attestation signer identity is invalid")
    if (
        _ISSUER.fullmatch(pins.receipt_issuer) is None
        or _KEY_ID.fullmatch(pins.receipt_key_id) is None
    ):
        raise RunnerDatabaseFleetError("Runner fleet receipt signer identity is invalid")
    if pins.stage == "admission":
        if pins.receipt_sha256 is not None or pins.receipt_signature_sha256 is not None:
            raise RunnerDatabaseFleetError("Admission trust pins cannot preclaim receipt hashes")
    elif pins.receipt_sha256 is None or pins.receipt_signature_sha256 is None:
        raise RunnerDatabaseFleetError("Runtime trust pins must pin the signed receipt")
    else:
        _nonzero_match(pins.receipt_sha256, _SHA256, field="receipt_sha256")
        _nonzero_match(
            pins.receipt_signature_sha256,
            _SHA256,
            field="receipt_signature_sha256",
        )


def load_runner_database_fleet_trust_pins(
    source: Mapping[str, str],
    *,
    fleet: RunnerDatabaseFleet,
    context: RunnerDatabaseFleetEvidenceContext,
) -> RunnerDatabaseFleetTrustPins:
    """Load trust pins and bind them to fleet/context and the Pod annotation SHA."""

    path, sha256, document, raw = _read_canonical_document(
        source,
        file_environment=RUNNER_DATABASE_FLEET_TRUST_PINS_FILE_ENV,
        sha256_environment=RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV,
    )
    fields = {
        "schema_version",
        "stage",
        "admission_epoch",
        "product_revision",
        "schema_revision",
        "fleet_sha256",
        "evidence_context_sha256",
        "attestation_issuer",
        "attestation_key_id",
        "attestation_public_key_sha256",
        "attestation_sha256",
        "attestation_signature_sha256",
        "receipt_issuer",
        "receipt_key_id",
        "receipt_public_key_sha256",
        "receipt_sha256",
        "receipt_signature_sha256",
    }
    if set(document) != fields or document.get("schema_version") != 1:
        raise RunnerDatabaseFleetError("Runner fleet trust-pin document shape is invalid")
    string_fields = fields - {
        "schema_version",
        "admission_epoch",
        "receipt_sha256",
        "receipt_signature_sha256",
    }
    if not all(isinstance(document.get(field), str) for field in string_fields):
        raise RunnerDatabaseFleetError("Runner fleet trust-pin values are invalid")
    if document.get("receipt_sha256") is not None and not isinstance(
        document.get("receipt_sha256"), str
    ):
        raise RunnerDatabaseFleetError("Runner fleet receipt SHA pin is invalid")
    if document.get("receipt_signature_sha256") is not None and not isinstance(
        document.get("receipt_signature_sha256"), str
    ):
        raise RunnerDatabaseFleetError("Runner fleet receipt signature pin is invalid")
    pins = RunnerDatabaseFleetTrustPins(
        path=path,
        sha256=sha256,
        stage=cast(str, document["stage"]),
        admission_epoch=_generation(document.get("admission_epoch"), field="admission_epoch"),
        product_revision=cast(str, document["product_revision"]),
        schema_revision=cast(str, document["schema_revision"]),
        fleet_sha256=cast(str, document["fleet_sha256"]),
        evidence_context_sha256=cast(str, document["evidence_context_sha256"]),
        attestation_issuer=cast(str, document["attestation_issuer"]),
        attestation_key_id=cast(str, document["attestation_key_id"]),
        attestation_public_key_sha256=cast(str, document["attestation_public_key_sha256"]),
        attestation_sha256=cast(str, document["attestation_sha256"]),
        attestation_signature_sha256=cast(str, document["attestation_signature_sha256"]),
        receipt_issuer=cast(str, document["receipt_issuer"]),
        receipt_key_id=cast(str, document["receipt_key_id"]),
        receipt_public_key_sha256=cast(str, document["receipt_public_key_sha256"]),
        receipt_sha256=cast(str | None, document["receipt_sha256"]),
        receipt_signature_sha256=cast(str | None, document["receipt_signature_sha256"]),
    )
    _validate_trust_pins(pins)
    if (
        pins.fleet_sha256 != fleet.sha256
        or pins.evidence_context_sha256 != context.sha256
        or pins.admission_epoch != context.admission_epoch
        or pins.product_revision != context.product_revision
        or pins.schema_revision != context.schema_revision
    ):
        raise RunnerDatabaseFleetError("Runner fleet trust pins do not match fleet/context")
    if raw != render_runner_database_fleet_trust_pins(pins):
        raise RunnerDatabaseFleetError("Runner fleet trust pins must contain canonical JSON")
    return pins


def _fleet_document(runners: tuple[RunnerDatabaseFleetMember, ...]) -> dict[str, object]:
    ordered = tuple(sorted(runners, key=lambda runner: str(runner.runner_id)))
    return {
        "runners": [
            {
                "connection_generation": runner.connection_generation,
                "runner_id": str(runner.runner_id),
            }
            for runner in ordered
        ],
        "schema_version": 1,
    }


def render_runner_database_fleet(runners: tuple[RunnerDatabaseFleetMember, ...]) -> str:
    """Render the only admitted byte representation of the exact A/B fleet."""

    _validate_fleet_members(runners)
    return _canonical_json(_fleet_document(runners))


def _validate_fleet_members(runners: tuple[RunnerDatabaseFleetMember, ...]) -> None:
    if len(runners) != 2:
        raise RunnerDatabaseFleetError("Runner database fleet must contain exactly two members")
    identities: set[UUID] = set()
    logins: set[str] = set()
    for runner in runners:
        if not isinstance(runner, RunnerDatabaseFleetMember) or runner.runner_id.int == 0:
            raise RunnerDatabaseFleetError("Runner database fleet member is invalid")
        _generation(runner.connection_generation, field="connection_generation")
        if len(runner.login.encode("ascii")) > 63:
            raise RunnerDatabaseFleetError("Runner database login exceeds PostgreSQL limits")
        identities.add(runner.runner_id)
        logins.add(runner.login)
    if len(identities) != 2 or len(logins) != 2:
        raise RunnerDatabaseFleetError("Runner database fleet members must be unique")


def load_runner_database_fleet(source: Mapping[str, str]) -> RunnerDatabaseFleet:
    """Load and hash one canonical exact-two fleet manifest."""

    path, sha256, document, raw = _read_canonical_document(
        source,
        file_environment=RUNNER_DATABASE_FLEET_FILE_ENV,
        sha256_environment=RUNNER_DATABASE_FLEET_SHA256_ENV,
    )
    if (
        set(document) != {"schema_version", "runners"}
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
    ):
        raise RunnerDatabaseFleetError("Runner database fleet document shape is invalid")
    rows = document.get("runners")
    if not isinstance(rows, list):
        raise RunnerDatabaseFleetError("Runner database fleet members are invalid")
    parsed: list[RunnerDatabaseFleetMember] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"runner_id", "connection_generation"}:
            raise RunnerDatabaseFleetError("Runner database fleet member shape is invalid")
        parsed.append(
            RunnerDatabaseFleetMember(
                runner_id=_canonical_uuid(row.get("runner_id"), field="runner_id"),
                connection_generation=_generation(
                    row.get("connection_generation"), field="connection_generation"
                ),
            )
        )
    runners = tuple(sorted(parsed, key=lambda runner: str(runner.runner_id)))
    _validate_fleet_members(runners)
    if raw != render_runner_database_fleet(runners):
        raise RunnerDatabaseFleetError("Runner database fleet must contain canonical JSON")
    return RunnerDatabaseFleet(path=path, sha256=sha256, runners=runners)


def _capabilities_sha256(capabilities: tuple[str, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            list(capabilities),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _validate_stage_specs(
    specs: tuple[RunnerDatabaseFleetStageSpec, RunnerDatabaseFleetStageSpec],
) -> None:
    if len(specs) != 2 or specs != tuple(sorted(specs, key=lambda item: str(item.runner_id))):
        raise RunnerDatabaseFleetError("Runner fleet stage specs must be exact sorted A/B")
    if len({spec.runner_id for spec in specs}) != 2 or any(
        spec.runner_id.int == 0 for spec in specs
    ):
        raise RunnerDatabaseFleetError("Runner fleet stage identities are invalid")
    if (
        len({spec.pool_id for spec in specs}) != 1
        or len({spec.placement_id for spec in specs}) != 1
    ):
        raise RunnerDatabaseFleetError("Runner fleet stage must use one pool and placement")
    if len({spec.instance_key for spec in specs}) != 2:
        raise RunnerDatabaseFleetError("Runner fleet stage instance keys must be unique")
    for spec in specs:
        if spec.pool_id.int == 0 or spec.placement_id.int == 0:
            raise RunnerDatabaseFleetError("Runner fleet stage pool binding is invalid")
        if _INSTANCE_KEY.fullmatch(spec.instance_key) is None:
            raise RunnerDatabaseFleetError("Runner fleet stage instance key is invalid")
        if _FAILURE_DOMAIN.fullmatch(spec.failure_domain) is None:
            raise RunnerDatabaseFleetError("Runner fleet stage failure domain is invalid")
        if type(spec.protocol_version) is not int or spec.protocol_version <= 0:
            raise RunnerDatabaseFleetError("Runner fleet stage protocol is invalid")
        _nonzero_match(spec.source_revision, _FULL_GIT_SHA, field="source_revision")
        if spec.schema_revision != _SCHEMA_REVISION:
            raise RunnerDatabaseFleetError("Runner fleet stage schema is invalid")
        if _ADAPTER_VERSION.fullmatch(spec.adapter_contract_version) is None:
            raise RunnerDatabaseFleetError("Runner fleet stage adapter contract is invalid")
        if (
            not spec.capabilities
            or spec.capabilities != tuple(sorted(set(spec.capabilities)))
            or any(_CAPABILITY.fullmatch(value) is None for value in spec.capabilities)
        ):
            raise RunnerDatabaseFleetError("Runner fleet stage capabilities are invalid")
        if type(spec.max_concurrency) is not int or not 1 <= spec.max_concurrency <= 1024:
            raise RunnerDatabaseFleetError("Runner fleet stage max concurrency is invalid")


def _stage_spec_document(spec: RunnerDatabaseFleetStageSpec) -> dict[str, object]:
    return {
        "adapter_contract_version": spec.adapter_contract_version,
        "capabilities": list(spec.capabilities),
        "failure_domain": spec.failure_domain,
        "instance_key": spec.instance_key,
        "max_concurrency": spec.max_concurrency,
        "placement_id": str(spec.placement_id),
        "pool_id": str(spec.pool_id),
        "protocol_version": spec.protocol_version,
        "runner_id": str(spec.runner_id),
        "schema_revision": spec.schema_revision,
        "source_revision": spec.source_revision,
    }


def render_runner_database_fleet_stage_specs(
    specs: tuple[RunnerDatabaseFleetStageSpec, RunnerDatabaseFleetStageSpec],
) -> str:
    """Render canonical owner-only stage input without any token or DSN."""

    _validate_stage_specs(specs)
    return _canonical_json(
        {
            "runners": [_stage_spec_document(spec) for spec in specs],
            "schema_version": 1,
        }
    )


def load_runner_database_fleet_stage_specs(
    source: Mapping[str, str],
) -> tuple[RunnerDatabaseFleetStageSpec, RunnerDatabaseFleetStageSpec]:
    """Load exact A/B stage specs from one owner-only canonical file."""

    _path, _sha256, document, raw = _read_canonical_document(
        source,
        file_environment=RUNNER_DATABASE_FLEET_STAGE_FILE_ENV,
        sha256_environment=RUNNER_DATABASE_FLEET_STAGE_SHA256_ENV,
    )
    rows = document.get("runners")
    fields = {
        "runner_id",
        "pool_id",
        "placement_id",
        "instance_key",
        "failure_domain",
        "protocol_version",
        "source_revision",
        "schema_revision",
        "adapter_contract_version",
        "capabilities",
        "max_concurrency",
    }
    if set(document) != {"schema_version", "runners"} or document.get("schema_version") != 1:
        raise RunnerDatabaseFleetError("Runner fleet stage document shape is invalid")
    if not isinstance(rows, list) or len(rows) != 2:
        raise RunnerDatabaseFleetError("Runner fleet stage must contain exact A/B")
    parsed: list[RunnerDatabaseFleetStageSpec] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise RunnerDatabaseFleetError("Runner fleet stage member shape is invalid")
        capabilities = row.get("capabilities")
        string_fields = {
            "instance_key",
            "failure_domain",
            "source_revision",
            "schema_revision",
            "adapter_contract_version",
        }
        if not all(isinstance(row.get(field), str) for field in string_fields) or any(
            type(row.get(field)) is not int for field in ("protocol_version", "max_concurrency")
        ):
            raise RunnerDatabaseFleetError("Runner fleet stage member values are invalid")
        if not isinstance(capabilities, list) or not all(
            isinstance(value, str) for value in capabilities
        ):
            raise RunnerDatabaseFleetError("Runner fleet stage capabilities are invalid")
        parsed.append(
            RunnerDatabaseFleetStageSpec(
                runner_id=_canonical_uuid(row.get("runner_id"), field="runner_id"),
                pool_id=_canonical_uuid(row.get("pool_id"), field="pool_id"),
                placement_id=_canonical_uuid(row.get("placement_id"), field="placement_id"),
                instance_key=cast(str, row.get("instance_key")),
                failure_domain=cast(str, row.get("failure_domain")),
                protocol_version=cast(int, row.get("protocol_version")),
                source_revision=cast(str, row.get("source_revision")),
                schema_revision=cast(str, row.get("schema_revision")),
                adapter_contract_version=cast(str, row.get("adapter_contract_version")),
                capabilities=tuple(cast(list[str], capabilities)),
                max_concurrency=cast(int, row.get("max_concurrency")),
            )
        )
    specs = cast(
        tuple[RunnerDatabaseFleetStageSpec, RunnerDatabaseFleetStageSpec],
        tuple(parsed),
    )
    _validate_stage_specs(specs)
    if raw != render_runner_database_fleet_stage_specs(specs):
        raise RunnerDatabaseFleetError("Runner fleet stage specs must contain canonical JSON")
    return specs


def _require_postgresql_fleet_table_lock(db: Session) -> datetime:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        raise RunnerDatabaseFleetError("Runner fleet lifecycle requires PostgreSQL")
    db.execute(sa.text("LOCK TABLE public.saas_runner_registrations IN SHARE ROW EXCLUSIVE MODE"))
    database_now = db.scalar(sa.text("SELECT clock_timestamp()"))
    if not isinstance(database_now, datetime) or database_now.tzinfo is None:
        raise RunnerDatabaseFleetError("Runner fleet database clock is invalid")
    return database_now.astimezone(UTC)


def _stage_runner_database_fleet_in_transaction(
    db: Session,
    *,
    specs: tuple[RunnerDatabaseFleetStageSpec, RunnerDatabaseFleetStageSpec],
    staged_at: datetime,
) -> tuple[StagedRunnerDatabaseFleetMember, StagedRunnerDatabaseFleetMember]:
    """Internal mutation after the caller holds the registration table lock."""

    _validate_stage_specs(specs)
    if staged_at.tzinfo is None:
        raise RunnerDatabaseFleetError("Runner fleet stage time is invalid")
    runner_ids = tuple(spec.runner_id for spec in specs)
    active_before = tuple(
        db.scalars(
            sa.select(RunnerRegistrationRecord)
            .where(
                sa.or_(
                    RunnerRegistrationRecord.status.in_(("online", "draining")),
                    RunnerRegistrationRecord.active_leases != 0,
                )
            )
            .order_by(RunnerRegistrationRecord.id)
            .with_for_update()
        )
    )
    if any(row.id not in runner_ids for row in active_before):
        raise RunnerDatabaseFleetError("Runner fleet stage found a third active registration")
    pool = db.scalar(
        sa.select(RunnerPoolRecord)
        .where(RunnerPoolRecord.id == specs[0].pool_id)
        .with_for_update()
    )
    placement = db.scalar(
        sa.select(RuntimePlacementRecord)
        .where(RuntimePlacementRecord.id == specs[0].placement_id)
        .with_for_update()
    )
    if (
        pool is None
        or placement is None
        or pool.status != "active"
        or placement.status != "active"
        or pool.placement_id != placement.id
        or pool.capacity_slots < sum(spec.max_concurrency for spec in specs)
    ):
        raise RunnerDatabaseFleetError("Runner fleet stage pool or placement is unavailable")
    if any(
        spec.pool_id != pool.id
        or spec.placement_id != placement.id
        or spec.failure_domain != pool.failure_domain
        or spec.failure_domain != placement.failure_domain
        or spec.protocol_version != pool.protocol_version
        or spec.source_revision != pool.source_revision
        or spec.schema_revision != pool.schema_revision
        or spec.schema_revision != placement.official_schema_revision
        or spec.adapter_contract_version != pool.adapter_contract_version
        for spec in specs
    ):
        raise RunnerDatabaseFleetError("Runner fleet stage compatibility facts are not approved")
    collisions = tuple(
        db.scalars(
            sa.select(RunnerRegistrationRecord).where(
                RunnerRegistrationRecord.pool_id == pool.id,
                RunnerRegistrationRecord.instance_key.in_(
                    tuple(spec.instance_key for spec in specs)
                ),
                RunnerRegistrationRecord.id.not_in(runner_ids),
            )
        )
    )
    if collisions:
        raise RunnerDatabaseFleetError("Runner fleet stage instance key is already registered")
    existing = {
        row.id: row
        for row in db.scalars(
            sa.select(RunnerRegistrationRecord)
            .where(RunnerRegistrationRecord.id.in_(runner_ids))
            .order_by(RunnerRegistrationRecord.id)
            .with_for_update()
        )
    }
    staged: list[StagedRunnerDatabaseFleetMember] = []
    for spec in specs:
        row = existing.get(spec.runner_id)
        if row is not None and (row.status not in {"draining", "offline"} or row.active_leases):
            raise RunnerDatabaseFleetError(
                "Runner fleet stage can only fence a drained or offline incarnation"
            )
        generation = 1 if row is None else row.connection_generation + 1
        token = secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest()
        capabilities = list(spec.capabilities)
        if row is None:
            row = RunnerRegistrationRecord(
                id=spec.runner_id,
                pool_id=pool.id,
                placement_id=placement.id,
                instance_key=spec.instance_key,
                failure_domain=spec.failure_domain,
                status="draining",
                connection_generation=generation,
                connection_token_hash=token_sha256,
                protocol_version=spec.protocol_version,
                source_revision=spec.source_revision,
                schema_revision=spec.schema_revision,
                adapter_contract_version=spec.adapter_contract_version,
                capabilities=capabilities,
                capabilities_hash=_capabilities_sha256(spec.capabilities),
                max_concurrency=spec.max_concurrency,
                active_leases=0,
                last_heartbeat_at=staged_at,
                registered_at=staged_at,
            )
            db.add(row)
        else:
            row.pool_id = pool.id
            row.placement_id = placement.id
            row.instance_key = spec.instance_key
            row.failure_domain = spec.failure_domain
            row.status = "draining"
            row.connection_generation = generation
            row.connection_token_hash = token_sha256
            row.protocol_version = spec.protocol_version
            row.source_revision = spec.source_revision
            row.schema_revision = spec.schema_revision
            row.adapter_contract_version = spec.adapter_contract_version
            row.capabilities = capabilities
            row.capabilities_hash = _capabilities_sha256(spec.capabilities)
            row.max_concurrency = spec.max_concurrency
            row.last_heartbeat_at = staged_at
            row.registered_at = staged_at
            db.execute(
                sa.update(CapabilityTokenRecord)
                .where(
                    CapabilityTokenRecord.runner_id == row.id,
                    CapabilityTokenRecord.revoked_at.is_(None),
                )
                .values(
                    revoked_at=staged_at,
                    revocation_reason="runner_fleet_restaged",
                )
            )
        staged.append(
            StagedRunnerDatabaseFleetMember(
                runner_id=spec.runner_id,
                connection_generation=generation,
                connection_token=token,
                status="draining",
            )
        )
    db.flush()
    active_after = tuple(
        db.scalars(
            sa.select(RunnerRegistrationRecord)
            .where(
                sa.or_(
                    RunnerRegistrationRecord.status.in_(("online", "draining")),
                    RunnerRegistrationRecord.active_leases != 0,
                )
            )
            .order_by(RunnerRegistrationRecord.id)
            .with_for_update()
        )
    )
    if tuple(row.id for row in active_after) != runner_ids or any(
        row.status != "draining" or row.active_leases != 0 for row in active_after
    ):
        raise RunnerDatabaseFleetError("Runner fleet stage active projection is not exact A/B")
    return cast(
        tuple[StagedRunnerDatabaseFleetMember, StagedRunnerDatabaseFleetMember],
        tuple(staged),
    )


def stage_runner_database_fleet(
    session_factory: sessionmaker[Session],
    *,
    specs: tuple[RunnerDatabaseFleetStageSpec, RunnerDatabaseFleetStageSpec],
) -> tuple[StagedRunnerDatabaseFleetMember, StagedRunnerDatabaseFleetMember]:
    """Atomically create/fence exact A/B directly into ``draining`` with no online window."""

    _validate_stage_specs(specs)
    try:
        with session_factory.begin() as db:
            staged_at = _require_postgresql_fleet_table_lock(db)
            return _stage_runner_database_fleet_in_transaction(
                db,
                specs=specs,
                staged_at=staged_at,
            )
    except RunnerDatabaseFleetError:
        raise
    except sa.exc.SQLAlchemyError:
        raise RunnerDatabaseFleetError("Runner fleet stage transaction failed") from None


def _registration_projection_from_record(
    record: RunnerRegistrationRecord,
) -> RunnerDatabaseRegistrationProjection:
    capabilities = record.capabilities
    if not isinstance(capabilities, list) or not all(
        isinstance(value, str) for value in capabilities
    ):
        raise RunnerDatabaseFleetError("Runner fleet registration capabilities are malformed")
    return RunnerDatabaseRegistrationProjection(
        runner_id=record.id,
        pool_id=record.pool_id,
        placement_id=record.placement_id,
        instance_key=record.instance_key,
        failure_domain=record.failure_domain,
        connection_generation=record.connection_generation,
        status=record.status,
        connection_token_sha256=record.connection_token_hash,
        protocol_version=record.protocol_version,
        source_revision=record.source_revision,
        schema_revision=record.schema_revision,
        adapter_contract_version=record.adapter_contract_version,
        capabilities=tuple(capabilities),
        capabilities_sha256=record.capabilities_hash,
        max_concurrency=record.max_concurrency,
        active_leases=record.active_leases,
    )


def _locked_active_runner_registrations(db: Session) -> tuple[RunnerRegistrationRecord, ...]:
    return tuple(
        db.scalars(
            sa.select(RunnerRegistrationRecord)
            .where(
                sa.or_(
                    RunnerRegistrationRecord.status.in_(("online", "draining")),
                    RunnerRegistrationRecord.active_leases != 0,
                )
            )
            .order_by(RunnerRegistrationRecord.id)
            .with_for_update()
        )
    )


def promote_runner_database_fleet_after_admission(
    session_factory: sessionmaker[Session],
    source: Mapping[str, str],
) -> tuple[UUID, UUID]:
    """Verify signed evidence after the table lock, then atomically promote exact A/B."""

    fleet = load_runner_database_fleet(source)
    context = load_runner_database_fleet_evidence_context(source, fleet=fleet)
    trust_pins = load_runner_database_fleet_trust_pins(
        source,
        fleet=fleet,
        context=context,
    )
    if trust_pins.stage != "runtime":
        raise RunnerDatabaseFleetError("Runner fleet promotion requires runtime trust pins")
    runner_ids = tuple(runner.runner_id for runner in fleet.runners)
    aggregate_key = ":".join(str(runner_id) for runner_id in runner_ids)
    try:
        with session_factory.begin() as db:
            database_now = _require_postgresql_fleet_table_lock(db)
            environment_attestation = (
                load_and_verify_runner_database_fleet_environment_attestation(
                    source,
                    fleet=fleet,
                    context=context,
                    pins=trust_pins,
                    now=database_now,
                )
            )
            admission = load_and_verify_runner_database_fleet_admission_receipt(
                source,
                fleet=fleet,
                context=context,
                trust_pins=trust_pins,
                environment_attestation=environment_attestation,
                now=database_now,
            )
            active_rows = _locked_active_runner_registrations(db)
            registrations = tuple(
                _registration_projection_from_record(record) for record in active_rows
            )
            observed_registration_sha256 = validate_runner_database_fleet_registration_projection(
                fleet=fleet,
                context=context,
                registrations=registrations,
                expected_status="draining",
            )
            if not hmac.compare_digest(
                observed_registration_sha256,
                admission.registration_projection_sha256,
            ):
                raise RunnerDatabaseFleetError(
                    "Runner fleet registration projection differs from the signed receipt"
                )
            pool_ids = {record.pool_id for record in active_rows}
            placement_ids = {record.placement_id for record in active_rows}
            pools = tuple(
                db.scalars(
                    sa.select(RunnerPoolRecord)
                    .where(RunnerPoolRecord.id.in_(pool_ids))
                    .order_by(RunnerPoolRecord.id)
                    .with_for_update()
                )
            )
            placements = tuple(
                db.scalars(
                    sa.select(RuntimePlacementRecord)
                    .where(RuntimePlacementRecord.id.in_(placement_ids))
                    .order_by(RuntimePlacementRecord.id)
                    .with_for_update()
                )
            )
            if (
                len(pools) != 1
                or len(placements) != 1
                or pools[0].status != "active"
                or placements[0].status != "active"
                or pools[0].placement_id != placements[0].id
            ):
                raise RunnerDatabaseFleetError(
                    "Runner fleet pool or placement changed after admission"
                )
            prior_epochs: list[int] = []
            for payload in db.scalars(
                sa.select(ControlPlaneOutboxEvent.payload).where(
                    ControlPlaneOutboxEvent.aggregate_type == "runner_fleet",
                    ControlPlaneOutboxEvent.aggregate_key == aggregate_key,
                    ControlPlaneOutboxEvent.event_type == "runner.fleet.promoted",
                )
            ):
                epoch = payload.get("admission_epoch") if isinstance(payload, dict) else None
                if type(epoch) is not int or not 1 <= epoch <= 2**63 - 1:
                    raise RunnerDatabaseFleetError("Runner fleet promotion history is malformed")
                prior_epochs.append(epoch)
            if prior_epochs and admission.admission_epoch <= max(prior_epochs):
                raise RunnerDatabaseFleetError("Runner fleet admission epoch is not monotonic")
            for record in active_rows:
                record.status = "online"
            db.flush()
            online_rows = _locked_active_runner_registrations(db)
            online_registrations = tuple(
                _registration_projection_from_record(record) for record in online_rows
            )
            online_registration_sha256 = validate_runner_database_fleet_registration_projection(
                fleet=fleet,
                context=context,
                registrations=online_registrations,
                expected_status="online",
            )
            if not hmac.compare_digest(
                online_registration_sha256,
                admission.online_registration_projection_sha256,
            ):
                raise RunnerDatabaseFleetError(
                    "Runner fleet online projection differs from the signed transition"
                )
            event_payload: dict[str, object] = {
                "admission_epoch": admission.admission_epoch,
                "catalog_projection_sha256": admission.catalog_projection_sha256,
                "environment_attestation_sha256": admission.environment_attestation_sha256,
                "evidence_context_sha256": admission.evidence_context_sha256,
                "fleet_sha256": admission.fleet_sha256,
                "online_registration_projection_sha256": online_registration_sha256,
                "product_revision": admission.product_revision,
                "promoted_at": _format_time(database_now),
                "receipt_public_key_sha256": admission.public_key_sha256,
                "receipt_sha256": admission.receipt_sha256,
                "receipt_signature_sha256": admission.signature_sha256,
                "runners": [
                    {
                        "connection_generation": runner.connection_generation,
                        "runner_id": str(runner.runner_id),
                    }
                    for runner in fleet.runners
                ],
                "schema_revision": admission.schema_revision,
            }
            event_hash = hashlib.sha256(_canonical_json(event_payload).encode("ascii")).hexdigest()
            db.add(
                ControlPlaneOutboxEvent(
                    tenant_id=None,
                    aggregate_type="runner_fleet",
                    aggregate_key=aggregate_key,
                    event_type="runner.fleet.promoted",
                    payload=event_payload,
                    idempotency_key=f"runner-fleet-promote:{event_hash}",
                    request_hash=event_hash,
                    attempt_count=0,
                    available_at=database_now,
                )
            )
            db.flush()
            return cast(tuple[UUID, UUID], runner_ids)
    except RunnerDatabaseFleetError:
        raise
    except sa.exc.SQLAlchemyError:
        raise RunnerDatabaseFleetError("Runner fleet promotion transaction failed") from None


def _evidence_member_document(member: RunnerDatabaseFleetEvidenceMember) -> dict[str, object]:
    return {
        "adapter_contract_version": member.adapter_contract_version,
        "capabilities": list(member.capabilities),
        "capabilities_sha256": member.capabilities_sha256,
        "connection_generation": member.connection_generation,
        "database_secret_name": member.database_secret_name,
        "database_secret_resource_version": member.database_secret_resource_version,
        "database_secret_uid": str(member.database_secret_uid),
        "deployment_name": member.deployment_name,
        "deployment_template_sha256": member.deployment_template_sha256,
        "deployment_uid": str(member.deployment_uid),
        "deployment_yaml_sha256": member.deployment_yaml_sha256,
        "failure_domain": member.failure_domain,
        "instance_key": member.instance_key,
        "max_concurrency": member.max_concurrency,
        "placement_id": str(member.placement_id),
        "pool_id": str(member.pool_id),
        "protocol_version": member.protocol_version,
        "runner_id": str(member.runner_id),
        "schema_revision": member.schema_revision,
        "slot": member.slot,
        "source_revision": member.source_revision,
    }


def _evidence_context_document(
    context: RunnerDatabaseFleetEvidenceContext,
) -> dict[str, object]:
    return {
        "cnpg_cluster_name": context.cnpg_cluster_name,
        "cnpg_cluster_namespace": context.cnpg_cluster_namespace,
        "cnpg_cluster_resource_version": context.cnpg_cluster_resource_version,
        "cnpg_cluster_uid": str(context.cnpg_cluster_uid),
        "cnpg_postgresql_major": context.cnpg_postgresql_major,
        "database": context.database,
        "database_endpoint_slices_sha256": context.database_endpoint_slices_sha256,
        "database_oid": context.database_oid,
        "database_service_cluster_ip": context.database_service_cluster_ip,
        "database_service_dns": context.database_service_dns,
        "database_service_name": context.database_service_name,
        "database_service_port": context.database_service_port,
        "database_service_resource_version": context.database_service_resource_version,
        "database_service_selector_sha256": context.database_service_selector_sha256,
        "database_service_uid": str(context.database_service_uid),
        "database_system_identifier": context.database_system_identifier,
        "image_digest": context.image_digest,
        "namespace": context.namespace,
        "product_revision": context.product_revision,
        "release_incarnation": context.release_incarnation,
        "admission_epoch": context.admission_epoch,
        "runners": [
            _evidence_member_document(member)
            for member in sorted(context.runners, key=lambda item: item.slot)
        ],
        "schema_revision": context.schema_revision,
        "schema_version": 2,
    }


def render_runner_database_fleet_evidence_context(
    context: RunnerDatabaseFleetEvidenceContext,
) -> str:
    """Render the strict secret-free evidence context bound into the receipt."""

    _validate_evidence_context(context)
    return _canonical_json(_evidence_context_document(context))


def runner_database_fleet_environment_attestation_document(
    *,
    fleet: RunnerDatabaseFleet,
    context: RunnerDatabaseFleetEvidenceContext,
    issuer: str,
    key_id: str,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, object]:
    """Build the canonical secret-free Kubernetes/CNPG attestation payload."""

    _validate_fleet_members(fleet.runners)
    _validate_evidence_context(context)
    if _ISSUER.fullmatch(issuer) is None or _KEY_ID.fullmatch(key_id) is None:
        raise RunnerDatabaseFleetError("Runner fleet attestation signer identity is invalid")
    return {
        "admission_epoch": context.admission_epoch,
        "audience": _ATTESTATION_AUDIENCE,
        "environment": _evidence_context_document(context),
        "evidence_context_sha256": context.sha256,
        "expires_at": _format_time(expires_at),
        "fleet_sha256": fleet.sha256,
        "issued_at": _format_time(issued_at),
        "issuer": issuer,
        "key_id": key_id,
        "payload_type": _ATTESTATION_PAYLOAD_TYPE,
        "product_revision": context.product_revision,
        "schema_revision": context.schema_revision,
        "schema_version": 1,
    }


def load_and_verify_runner_database_fleet_environment_attestation(
    source: Mapping[str, str],
    *,
    fleet: RunnerDatabaseFleet,
    context: RunnerDatabaseFleetEvidenceContext,
    pins: RunnerDatabaseFleetTrustPins,
    now: datetime,
    enforce_expiry: bool = True,
) -> VerifiedRunnerDatabaseFleetAttestation:
    """Verify the independently signed environment projection against GitOps pins."""

    _path, raw = _read_owner_only_file(
        source,
        RUNNER_DATABASE_FLEET_ATTESTATION_FILE_ENV,
        maximum=_MAX_DOCUMENT_BYTES,
    )
    try:
        text = raw.decode("ascii")
        document = json.loads(text)
    except (UnicodeError, json.JSONDecodeError):
        raise RunnerDatabaseFleetError("Runner fleet environment attestation is invalid") from None
    if not isinstance(document, dict):
        raise RunnerDatabaseFleetError("Runner fleet environment attestation must be an object")
    observed_sha256 = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(observed_sha256, pins.attestation_sha256):
        raise RunnerDatabaseFleetError("Runner fleet environment attestation SHA is untrusted")
    issued_at = _parse_time(document.get("issued_at"), field="attestation issued_at")
    expires_at = _parse_time(document.get("expires_at"), field="attestation expires_at")
    if enforce_expiry:
        _validate_signature_window(
            issued_at=issued_at,
            expires_at=expires_at,
            now=now,
            maximum_ttl=_MAX_ATTESTATION_TTL,
            subject="environment attestation",
        )
    elif (
        issued_at > now.astimezone(UTC)
        or expires_at <= issued_at
        or expires_at - issued_at > _MAX_ATTESTATION_TTL
    ):
        raise RunnerDatabaseFleetError("Runner fleet environment attestation window is invalid")
    expected = runner_database_fleet_environment_attestation_document(
        fleet=fleet,
        context=context,
        issuer=pins.attestation_issuer,
        key_id=pins.attestation_key_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    if cast(dict[str, object], document) != expected or text != _canonical_json(expected):
        raise RunnerDatabaseFleetError(
            "Runner fleet environment attestation is not canonical or exact"
        )
    public_key = _load_pinned_public_key(
        source,
        file_environment=RUNNER_DATABASE_FLEET_ATTESTATION_PUBLIC_KEY_FILE_ENV,
        expected_sha256=pins.attestation_public_key_sha256,
    )
    signature = _load_detached_signature(
        source,
        file_environment=RUNNER_DATABASE_FLEET_ATTESTATION_SIGNATURE_FILE_ENV,
        expected_sha256=pins.attestation_signature_sha256,
    )
    try:
        public_key.verify(signature, admission_signature_payload(expected))
    except InvalidSignature:
        raise RunnerDatabaseFleetError(
            "Runner fleet environment attestation signature is invalid"
        ) from None
    return VerifiedRunnerDatabaseFleetAttestation(
        document=expected,
        sha256=observed_sha256,
        signature_sha256=hashlib.sha256(signature).hexdigest(),
        public_key_sha256=_public_key_fingerprint(public_key),
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _validate_evidence_member(member: RunnerDatabaseFleetEvidenceMember) -> None:
    if member.slot not in _EXPECTED_SLOTS:
        raise RunnerDatabaseFleetError("Runner evidence slot is invalid")
    if member.runner_id.int == 0:
        raise RunnerDatabaseFleetError("Runner evidence identity is invalid")
    _generation(member.connection_generation, field="connection_generation")
    if member.pool_id.int == 0 or member.placement_id.int == 0:
        raise RunnerDatabaseFleetError("Runner control-plane binding is invalid")
    if _INSTANCE_KEY.fullmatch(member.instance_key) is None:
        raise RunnerDatabaseFleetError("Runner instance key is invalid")
    if _FAILURE_DOMAIN.fullmatch(member.failure_domain) is None:
        raise RunnerDatabaseFleetError("Runner failure domain is invalid")
    if type(member.protocol_version) is not int or member.protocol_version <= 0:
        raise RunnerDatabaseFleetError("Runner protocol version is invalid")
    _nonzero_match(member.source_revision, _FULL_GIT_SHA, field="Runner source_revision")
    if member.schema_revision != _SCHEMA_REVISION:
        raise RunnerDatabaseFleetError("Runner schema revision is invalid")
    if _ADAPTER_VERSION.fullmatch(member.adapter_contract_version) is None:
        raise RunnerDatabaseFleetError("Runner adapter contract version is invalid")
    if (
        not member.capabilities
        or member.capabilities != tuple(sorted(set(member.capabilities)))
        or any(_CAPABILITY.fullmatch(value) is None for value in member.capabilities)
    ):
        raise RunnerDatabaseFleetError("Runner capabilities are invalid")
    expected_capabilities_sha256 = hashlib.sha256(
        json.dumps(
            list(member.capabilities),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    if not hmac.compare_digest(member.capabilities_sha256, expected_capabilities_sha256):
        raise RunnerDatabaseFleetError("Runner capabilities SHA256 is invalid")
    if type(member.max_concurrency) is not int or not 1 <= member.max_concurrency <= 1024:
        raise RunnerDatabaseFleetError("Runner max concurrency is invalid")
    expected_deployment = f"omnigent-saas-runner-agent-{member.slot}"
    expected_secret = f"{expected_deployment}-database-g{member.connection_generation}"
    if member.deployment_name != expected_deployment:
        raise RunnerDatabaseFleetError("Runner evidence deployment name is invalid")
    if member.deployment_uid.int == 0:
        raise RunnerDatabaseFleetError("Runner evidence Deployment UID is invalid")
    _nonzero_match(
        member.deployment_template_sha256,
        _SHA256,
        field="deployment_template_sha256",
    )
    if member.database_secret_name != expected_secret:
        raise RunnerDatabaseFleetError("Runner evidence database Secret name is invalid")
    _nonzero_match(
        member.deployment_yaml_sha256,
        _SHA256,
        field="deployment_yaml_sha256",
    )
    if member.database_secret_uid.int == 0:
        raise RunnerDatabaseFleetError("Runner database Secret UID is invalid")
    if _RESOURCE_VERSION.fullmatch(member.database_secret_resource_version) is None:
        raise RunnerDatabaseFleetError("Runner database Secret resourceVersion is invalid")


def _validate_evidence_context(context: RunnerDatabaseFleetEvidenceContext) -> None:
    _nonzero_match(context.product_revision, _FULL_GIT_SHA, field="product_revision")
    _nonzero_match(context.image_digest, _IMAGE_DIGEST, field="image_digest")
    if context.schema_revision != _SCHEMA_REVISION:
        raise RunnerDatabaseFleetError("schema_revision must be p0s000000011")
    _dns_label(context.namespace, field="namespace")
    _nonzero_match(
        context.release_incarnation,
        _RELEASE_INCARNATION,
        field="release_incarnation",
    )
    _generation(context.admission_epoch, field="admission_epoch")
    _dns_label(context.cnpg_cluster_namespace, field="cnpg_cluster_namespace")
    _dns_label(context.cnpg_cluster_name, field="cnpg_cluster_name")
    if context.cnpg_cluster_uid.int == 0:
        raise RunnerDatabaseFleetError("CNPG Cluster UID is invalid")
    if _RESOURCE_VERSION.fullmatch(context.cnpg_cluster_resource_version) is None:
        raise RunnerDatabaseFleetError("CNPG Cluster resourceVersion is invalid")
    if context.cnpg_postgresql_major != 18:
        raise RunnerDatabaseFleetError("CNPG PostgreSQL major must be 18")
    if _DATABASE_NAME.fullmatch(context.database) is None:
        raise RunnerDatabaseFleetError("database is invalid")
    if not 1 <= context.database_oid <= 2**32 - 1:
        raise RunnerDatabaseFleetError("database OID is invalid")
    if (
        not context.database_system_identifier.isdecimal()
        or int(context.database_system_identifier) <= 0
        or len(context.database_system_identifier) > 20
    ):
        raise RunnerDatabaseFleetError("database system identifier is invalid")
    _dns_label(context.database_service_name, field="database_service_name")
    if context.database_service_uid.int == 0:
        raise RunnerDatabaseFleetError("database Service UID is invalid")
    if _RESOURCE_VERSION.fullmatch(context.database_service_resource_version) is None:
        raise RunnerDatabaseFleetError("database Service resourceVersion is invalid")
    expected_service_dns = f"{context.database_service_name}.{context.cnpg_cluster_namespace}.svc"
    if context.database_service_dns != expected_service_dns:
        raise RunnerDatabaseFleetError("database Service DNS is invalid")
    if context.database_service_port != 5432:
        raise RunnerDatabaseFleetError("database Service port must be 5432")
    try:
        cluster_ip = ipaddress.ip_address(context.database_service_cluster_ip)
    except ValueError:
        raise RunnerDatabaseFleetError("database Service cluster IP is invalid") from None
    if cluster_ip.version != 4 or not cluster_ip.is_private:
        raise RunnerDatabaseFleetError("database Service cluster IP is invalid")
    _nonzero_match(
        context.database_service_selector_sha256,
        _SHA256,
        field="database_service_selector_sha256",
    )
    _nonzero_match(
        context.database_endpoint_slices_sha256,
        _SHA256,
        field="database_endpoint_slices_sha256",
    )
    if tuple(member.slot for member in context.runners) != _EXPECTED_SLOTS:
        raise RunnerDatabaseFleetError("Runner evidence must contain exact sorted A/B slots")
    for member in context.runners:
        _validate_evidence_member(member)
        if (
            member.source_revision != context.product_revision
            or member.schema_revision != context.schema_revision
        ):
            raise RunnerDatabaseFleetError("Runner revisions do not match the release")
    pairs = {(member.runner_id, member.connection_generation) for member in context.runners}
    if (
        len(pairs) != 2
        or len({member.runner_id for member in context.runners}) != 2
        or len({member.pool_id for member in context.runners}) != 1
        or len({member.placement_id for member in context.runners}) != 1
        or len({member.instance_key for member in context.runners}) != 2
        or len({member.deployment_uid for member in context.runners}) != 2
        or len({member.database_secret_uid for member in context.runners}) != 2
    ):
        raise RunnerDatabaseFleetError("Runner evidence identities must be unique")


def _parse_evidence_member(row: object) -> RunnerDatabaseFleetEvidenceMember:
    fields = {
        "slot",
        "runner_id",
        "connection_generation",
        "pool_id",
        "placement_id",
        "instance_key",
        "failure_domain",
        "protocol_version",
        "source_revision",
        "schema_revision",
        "adapter_contract_version",
        "capabilities",
        "capabilities_sha256",
        "max_concurrency",
        "deployment_name",
        "deployment_uid",
        "deployment_template_sha256",
        "deployment_yaml_sha256",
        "database_secret_name",
        "database_secret_uid",
        "database_secret_resource_version",
    }
    if not isinstance(row, dict) or set(row) != fields:
        raise RunnerDatabaseFleetError("Runner evidence member shape is invalid")
    string_fields = fields - {
        "connection_generation",
        "protocol_version",
        "capabilities",
        "max_concurrency",
    }
    if not all(isinstance(row.get(field), str) for field in string_fields):
        raise RunnerDatabaseFleetError("Runner evidence member values are invalid")
    raw_capabilities = row.get("capabilities")
    if not isinstance(raw_capabilities, list) or not all(
        isinstance(value, str) for value in raw_capabilities
    ):
        raise RunnerDatabaseFleetError("Runner evidence capabilities are invalid")
    return RunnerDatabaseFleetEvidenceMember(
        slot=cast(str, row["slot"]),
        runner_id=_canonical_uuid(row.get("runner_id"), field="runner_id"),
        connection_generation=_generation(
            row.get("connection_generation"), field="connection_generation"
        ),
        pool_id=_canonical_uuid(row.get("pool_id"), field="pool_id"),
        placement_id=_canonical_uuid(row.get("placement_id"), field="placement_id"),
        instance_key=cast(str, row["instance_key"]),
        failure_domain=cast(str, row["failure_domain"]),
        protocol_version=cast(int, row["protocol_version"]),
        source_revision=cast(str, row["source_revision"]),
        schema_revision=cast(str, row["schema_revision"]),
        adapter_contract_version=cast(str, row["adapter_contract_version"]),
        capabilities=tuple(cast(list[str], raw_capabilities)),
        capabilities_sha256=cast(str, row["capabilities_sha256"]),
        max_concurrency=cast(int, row["max_concurrency"]),
        deployment_name=cast(str, row["deployment_name"]),
        deployment_uid=_canonical_uuid(row.get("deployment_uid"), field="deployment_uid"),
        deployment_template_sha256=cast(str, row["deployment_template_sha256"]),
        deployment_yaml_sha256=cast(str, row["deployment_yaml_sha256"]),
        database_secret_name=cast(str, row["database_secret_name"]),
        database_secret_uid=_canonical_uuid(
            row.get("database_secret_uid"), field="database_secret_uid"
        ),
        database_secret_resource_version=cast(str, row["database_secret_resource_version"]),
    )


def load_runner_database_fleet_evidence_context(
    source: Mapping[str, str],
    *,
    fleet: RunnerDatabaseFleet,
) -> RunnerDatabaseFleetEvidenceContext:
    """Load the canonical Kubernetes/CNPG evidence context for one fleet."""

    path, sha256, document, raw = _read_canonical_document(
        source,
        file_environment=RUNNER_DATABASE_FLEET_CONTEXT_FILE_ENV,
        sha256_environment=RUNNER_DATABASE_FLEET_CONTEXT_SHA256_ENV,
    )
    expected_fields = {
        "schema_version",
        "admission_epoch",
        "product_revision",
        "image_digest",
        "schema_revision",
        "namespace",
        "release_incarnation",
        "cnpg_cluster_namespace",
        "cnpg_cluster_name",
        "cnpg_cluster_uid",
        "cnpg_cluster_resource_version",
        "cnpg_postgresql_major",
        "database",
        "database_oid",
        "database_system_identifier",
        "database_service_name",
        "database_service_uid",
        "database_service_resource_version",
        "database_service_dns",
        "database_service_port",
        "database_service_cluster_ip",
        "database_service_selector_sha256",
        "database_endpoint_slices_sha256",
        "runners",
    }
    if (
        set(document) != expected_fields
        or type(document.get("schema_version")) is not int
        or (document.get("schema_version") != 2)
    ):
        raise RunnerDatabaseFleetError("Runner fleet evidence context shape is invalid")
    rows = document.get("runners")
    if not isinstance(rows, list):
        raise RunnerDatabaseFleetError("Runner fleet evidence members are invalid")
    top_level_strings = expected_fields - {
        "schema_version",
        "admission_epoch",
        "cnpg_postgresql_major",
        "database_oid",
        "database_service_port",
        "runners",
    }
    if not all(isinstance(document.get(field), str) for field in top_level_strings):
        raise RunnerDatabaseFleetError("Runner fleet evidence context values are invalid")
    context = RunnerDatabaseFleetEvidenceContext(
        path=path,
        sha256=sha256,
        product_revision=cast(str, document["product_revision"]),
        image_digest=cast(str, document["image_digest"]),
        schema_revision=cast(str, document["schema_revision"]),
        namespace=cast(str, document["namespace"]),
        release_incarnation=cast(str, document["release_incarnation"]),
        admission_epoch=_generation(document.get("admission_epoch"), field="admission_epoch"),
        cnpg_cluster_namespace=cast(str, document["cnpg_cluster_namespace"]),
        cnpg_cluster_name=cast(str, document["cnpg_cluster_name"]),
        cnpg_cluster_uid=_canonical_uuid(
            document.get("cnpg_cluster_uid"), field="cnpg_cluster_uid"
        ),
        cnpg_cluster_resource_version=cast(str, document["cnpg_cluster_resource_version"]),
        cnpg_postgresql_major=cast(int, document["cnpg_postgresql_major"]),
        database=cast(str, document["database"]),
        database_oid=cast(int, document["database_oid"]),
        database_system_identifier=cast(str, document["database_system_identifier"]),
        database_service_name=cast(str, document["database_service_name"]),
        database_service_uid=_canonical_uuid(
            document.get("database_service_uid"), field="database_service_uid"
        ),
        database_service_resource_version=cast(str, document["database_service_resource_version"]),
        database_service_dns=cast(str, document["database_service_dns"]),
        database_service_port=cast(int, document["database_service_port"]),
        database_service_cluster_ip=cast(str, document["database_service_cluster_ip"]),
        database_service_selector_sha256=cast(str, document["database_service_selector_sha256"]),
        database_endpoint_slices_sha256=cast(str, document["database_endpoint_slices_sha256"]),
        runners=tuple(_parse_evidence_member(row) for row in rows),
    )
    _validate_evidence_context(context)
    fleet_pairs = {(runner.runner_id, runner.connection_generation) for runner in fleet.runners}
    evidence_pairs = {
        (runner.runner_id, runner.connection_generation) for runner in context.runners
    }
    if evidence_pairs != fleet_pairs:
        raise RunnerDatabaseFleetError("Runner fleet evidence does not match the fleet manifest")
    if raw != render_runner_database_fleet_evidence_context(context):
        raise RunnerDatabaseFleetError("Runner fleet evidence context must contain canonical JSON")
    return context


def verify_runner_database_fleet_release_facts(
    source: Mapping[str, str],
    context: RunnerDatabaseFleetEvidenceContext,
) -> None:
    """Bind the context to the immutable release facts visible to this Job."""

    expected = {
        "OMNIGENT_SAAS_PRODUCT_REVISION": context.product_revision,
        "OMNIGENT_SAAS_SOURCE_SHA": context.product_revision,
        "OMNIGENT_SAAS_IMAGE_DIGEST": context.image_digest,
        "OMNIGENT_SAAS_RELEASE_INCARNATION": context.release_incarnation,
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": context.schema_revision,
        RUNNER_DATABASE_FLEET_NAMESPACE_ENV: context.namespace,
    }
    if any(source.get(name) != value for name, value in expected.items()):
        raise RunnerDatabaseFleetError("Runner fleet evidence does not match release facts")


def verify_installed_runner_database_fleet_lineage(
    context: RunnerDatabaseFleetEvidenceContext,
) -> None:
    """Reject an admission image whose installed code is not the context source."""

    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError):
        raise RunnerDatabaseFleetError("Runner fleet build lineage is unavailable") from None
    if not isinstance(installed_revision, str) or not hmac.compare_digest(
        installed_revision, context.product_revision
    ):
        raise RunnerDatabaseFleetError("Runner fleet build lineage does not match")


def _reject_ambient_database_authority(source: Mapping[str, str]) -> None:
    for name, value in source.items():
        if not value.strip() or name == RUNNER_DATABASE_FLEET_ADMIN_URL_FILE_ENV:
            continue
        if (
            name in {"DATABASE_URL", "OMNIGENT_SAAS_DB_URL"}
            or name in _LIBPQ_ENVIRONMENTS
            or name.endswith(("_DATABASE_URL", "_DATABASE_URL_FILE"))
        ):
            raise RunnerDatabaseFleetError(
                "Runner fleet admission received forbidden ambient database authority"
            )


def _load_runner_database_fleet_admin_database_url_for_target(
    source: Mapping[str, str],
    *,
    database_service_dns: str,
    database_service_port: int,
    database: str,
) -> tuple[str, URL, Path]:
    _reject_ambient_database_authority(source)
    path, raw_bytes = _read_owner_only_file(
        source,
        RUNNER_DATABASE_FLEET_ADMIN_URL_FILE_ENV,
        maximum=_MAX_DATABASE_URL_BYTES,
    )
    try:
        raw = raw_bytes.decode("utf-8").rstrip("\r\n")
    except UnicodeError:
        raise RunnerDatabaseFleetError("Runner fleet admin database URL cannot be read") from None
    if not raw or raw != raw.strip() or "\x00" in raw or "\n" in raw or "\r" in raw:
        raise RunnerDatabaseFleetError("Runner fleet admin database URL is malformed")
    try:
        parsed = make_url(raw)
    except Exception:  # noqa: BLE001 - parser exceptions can echo secret-adjacent input.
        raise RunnerDatabaseFleetError("Runner fleet admin database URL is malformed") from None
    if (
        parsed.drivername != "postgresql+psycopg"
        or not parsed.username
        or parsed.password is None
        or parsed.host != database_service_dns
        or parsed.port != database_service_port
        or parsed.database != database
    ):
        raise RunnerDatabaseFleetError("Runner fleet admin database URL is incomplete")
    query = {str(key): value for key, value in parsed.query.items()}
    if set(query) - _ALLOWED_ADMIN_URL_QUERY_KEYS:
        raise RunnerDatabaseFleetError("Runner fleet admin database URL query is unsafe")
    if query.get("sslmode") != "verify-full":
        raise RunnerDatabaseFleetError("Runner fleet admin database URL must require TLS")
    if query.get("target_session_attrs") != "read-write":
        raise RunnerDatabaseFleetError(
            "Runner fleet admin database URL must target the read-write primary"
        )
    sslrootcert = query.get("sslrootcert")
    if not isinstance(sslrootcert, str) or not Path(sslrootcert).is_absolute():
        raise RunnerDatabaseFleetError("Runner fleet admin database URL must pin a root CA")
    sslcert = query.get("sslcert")
    sslkey = query.get("sslkey")
    if (sslcert is None) != (sslkey is None) or any(
        not isinstance(value, str) or not Path(value).is_absolute()
        for value in (sslcert, sslkey)
        if value is not None
    ):
        raise RunnerDatabaseFleetError("Runner fleet admin client certificate paths are unsafe")
    return raw, parsed, path


def load_runner_database_fleet_admin_database_url(
    source: Mapping[str, str],
    *,
    context: RunnerDatabaseFleetEvidenceContext,
) -> tuple[str, URL, Path]:
    """Load the sole managed-admin DSN from an exact 0400 file bound to evidence."""

    return _load_runner_database_fleet_admin_database_url_for_target(
        source,
        database_service_dns=context.database_service_dns,
        database_service_port=context.database_service_port,
        database=context.database,
    )


def load_runner_database_fleet_stage_admin_database_url(
    source: Mapping[str, str],
) -> tuple[str, URL, Path]:
    """Load the stage DSN bound to explicit, secret-free GitOps database facts."""

    host = source.get(RUNNER_DATABASE_FLEET_STAGE_DATABASE_HOST_ENV)
    port_text = source.get(RUNNER_DATABASE_FLEET_STAGE_DATABASE_PORT_ENV)
    database = source.get(RUNNER_DATABASE_FLEET_STAGE_DATABASE_NAME_ENV)
    if (
        not isinstance(host, str)
        or not host
        or len(host) > 253
        or any(_DNS_LABEL.fullmatch(label) is None for label in host.split("."))
        or not isinstance(port_text, str)
        or not port_text.isascii()
        or not port_text.isdecimal()
        or len(port_text) > 5
        or str(int(port_text)) != port_text
        or not 1 <= int(port_text) <= 65535
        or not isinstance(database, str)
        or _DATABASE_NAME.fullmatch(database) is None
    ):
        raise RunnerDatabaseFleetError("Runner fleet stage database target is invalid")
    return _load_runner_database_fleet_admin_database_url_for_target(
        source,
        database_service_dns=host,
        database_service_port=int(port_text),
        database=database,
    )


def _role_projection(row: Any) -> RunnerDatabaseRoleProjection:
    return RunnerDatabaseRoleProjection(
        name=str(row[0]),
        can_login=bool(row[1]),
        is_superuser=bool(row[2]),
        can_create_database=bool(row[3]),
        can_create_role=bool(row[4]),
        can_replicate=bool(row[5]),
        bypasses_rls=bool(row[6]),
        inherits_roles=bool(row[7]),
        connection_limit=int(row[8]),
        role_config_is_null=bool(row[9]),
        valid_until_is_null=bool(row[10]),
    )


def inspect_runner_database_fleet_projection(
    connection: Connection,
    *,
    fleet: RunnerDatabaseFleet,
) -> RunnerDatabaseFleetCatalogProjection:
    """Read the complete owner-side fleet projection without mutating PostgreSQL."""

    identity_row = connection.execute(
        sa.text(
            "SELECT current_user::text, session_user::text, current_database()::text, "
            "database.oid::bigint, current_setting('server_version_num')::integer, "
            "control.system_identifier::text, pg_is_in_recovery(), "
            "COALESCE(ssl.ssl, false), "
            "current_setting('transaction_read_only') = 'on', role.rolsuper "
            "FROM pg_database AS database "
            "JOIN pg_roles AS role ON role.rolname = current_user "
            "CROSS JOIN LATERAL pg_control_system() AS control "
            "LEFT JOIN pg_stat_ssl AS ssl ON ssl.pid = pg_backend_pid() "
            "WHERE database.datname = current_database()"
        )
    ).one()
    identity = RunnerDatabaseIdentityProjection(
        operator=str(identity_row[0]),
        session_user=str(identity_row[1]),
        database=str(identity_row[2]),
        database_oid=int(identity_row[3]),
        server_version_num=int(identity_row[4]),
        system_identifier=str(identity_row[5]),
        in_recovery=bool(identity_row[6]),
        tls=bool(identity_row[7]),
        transaction_read_only=bool(identity_row[8]),
        operator_is_superuser=bool(identity_row[9]),
    )
    schema_revision = str(
        connection.scalar(sa.text("SELECT version_num FROM public.saas_alembic_version"))
    )
    cluster_settings = tuple(
        (str(row[0]), str(row[1]), str(row[2]), bool(row[3]), str(row[4]))
        for row in connection.execute(
            sa.text(
                "SELECT name, setting, context, pending_restart, source FROM pg_settings "
                "WHERE name IN ('max_notify_queue_pages', 'max_prepared_transactions') "
                "ORDER BY name"
            )
        ).all()
    )
    prepared_transaction_count = int(
        connection.scalar(sa.text("SELECT count(*) FROM pg_prepared_xacts"))
    )
    roles = tuple(
        _role_projection(row)
        for row in connection.execute(
            sa.text(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit, rolconnlimit, "
                "rolconfig IS NULL, rolvaliduntil IS NULL FROM pg_roles "
                "WHERE rolname = :base_role OR rolname ~ :runner_pattern ORDER BY rolname"
            ),
            {"base_role": _RUNNER_BASE_ROLE, "runner_pattern": _RUNNER_ROLE_PATTERN},
        ).all()
    )
    memberships = tuple(
        RunnerDatabaseMembershipProjection(
            member=str(row[0]),
            granted_role=str(row[1]),
            admin_option=bool(row[2]),
            inherit_option=bool(row[3]),
            set_option=bool(row[4]),
        )
        for row in connection.execute(
            sa.text(
                "SELECT member.rolname, granted.rolname, membership.admin_option, "
                "membership.inherit_option, membership.set_option "
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "WHERE member.rolname = :base_role OR granted.rolname = :base_role "
                "OR member.rolname ~ :runner_pattern OR granted.rolname ~ :runner_pattern "
                "ORDER BY member.rolname, granted.rolname"
            ),
            {"base_role": _RUNNER_BASE_ROLE, "runner_pattern": _RUNNER_ROLE_PATTERN},
        ).all()
    )
    direct_acl_count = int(
        connection.scalar(
            sa.text(
                "WITH principals AS (SELECT oid FROM pg_roles WHERE rolname ~ :runner_pattern), "
                "observed AS ("
                "SELECT 1 FROM pg_database object "
                "CROSS JOIN LATERAL aclexplode(object.datacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_namespace object "
                "CROSS JOIN LATERAL aclexplode(object.nspacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_class object CROSS JOIN LATERAL aclexplode(object.relacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_attribute object "
                "CROSS JOIN LATERAL aclexplode(object.attacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_proc object CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_type object CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_language object "
                "CROSS JOIN LATERAL aclexplode(object.lanacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_largeobject_metadata object "
                "CROSS JOIN LATERAL aclexplode(object.lomacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_foreign_data_wrapper object "
                "CROSS JOIN LATERAL aclexplode(object.fdwacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_foreign_server object "
                "CROSS JOIN LATERAL aclexplode(object.srvacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_tablespace object "
                "CROSS JOIN LATERAL aclexplode(object.spcacl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_parameter_acl object "
                "CROSS JOIN LATERAL aclexplode(object.paracl) acl "
                "JOIN principals ON principals.oid = acl.grantee UNION ALL "
                "SELECT 1 FROM pg_default_acl object "
                "CROSS JOIN LATERAL aclexplode(object.defaclacl) acl "
                "JOIN principals ON principals.oid = acl.grantee) "
                "SELECT count(*) FROM observed"
            ),
            {"runner_pattern": _RUNNER_ROLE_PATTERN},
        )
    )
    owned_object_count = int(
        connection.scalar(
            sa.text(
                "WITH principals AS (SELECT oid FROM pg_roles WHERE rolname ~ :runner_pattern), "
                "owned AS ("
                "SELECT 1 FROM pg_database object "
                "JOIN principals ON object.datdba = principals.oid "
                "UNION ALL SELECT 1 FROM pg_namespace object "
                "JOIN principals ON object.nspowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_class object "
                "JOIN principals ON object.relowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_proc object "
                "JOIN principals ON object.proowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_type object "
                "JOIN principals ON object.typowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_language object "
                "JOIN principals ON object.lanowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_largeobject_metadata object "
                "JOIN principals ON object.lomowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_tablespace object "
                "JOIN principals ON object.spcowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_foreign_data_wrapper object "
                "JOIN principals ON object.fdwowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_foreign_server object "
                "JOIN principals ON object.srvowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_extension object "
                "JOIN principals ON object.extowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_event_trigger object "
                "JOIN principals ON object.evtowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_publication object "
                "JOIN principals ON object.pubowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_subscription object "
                "JOIN principals ON object.subowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_default_acl object "
                "JOIN principals ON object.defaclrole = principals.oid "
                "UNION ALL SELECT 1 FROM pg_collation object "
                "JOIN principals ON object.collowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_conversion object "
                "JOIN principals ON object.conowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_operator object "
                "JOIN principals ON object.oprowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_opclass object "
                "JOIN principals ON object.opcowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_opfamily object "
                "JOIN principals ON object.opfowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_ts_dict object "
                "JOIN principals ON object.dictowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_ts_config object "
                "JOIN principals ON object.cfgowner = principals.oid "
                "UNION ALL SELECT 1 FROM pg_statistic_ext object "
                "JOIN principals ON object.stxowner = principals.oid) "
                "SELECT count(*) FROM owned"
            ),
            {"runner_pattern": _RUNNER_ROLE_PATTERN},
        )
    )
    role_setting_count = int(
        connection.scalar(
            sa.text(
                "SELECT count(*) FROM pg_db_role_setting setting "
                "JOIN pg_roles role ON role.oid = setting.setrole "
                "WHERE role.rolname ~ :runner_pattern"
            ),
            {"runner_pattern": _RUNNER_ROLE_PATTERN},
        )
    )
    user_mapping_count = int(
        connection.scalar(
            sa.text(
                "SELECT count(*) FROM pg_user_mappings mapping "
                "JOIN pg_roles role ON role.oid = mapping.umuser "
                "WHERE role.rolname ~ :runner_pattern"
            ),
            {"runner_pattern": _RUNNER_ROLE_PATTERN},
        )
    )
    direct_policy_count = int(
        connection.scalar(
            sa.text(
                "SELECT count(*) FROM pg_policy policy "
                "CROSS JOIN LATERAL unnest(policy.polroles) role_oid "
                "JOIN pg_roles role ON role.oid = role_oid "
                "WHERE role.rolname ~ :runner_pattern"
            ),
            {"runner_pattern": _RUNNER_ROLE_PATTERN},
        )
    )
    runner_ids = [str(runner.runner_id) for runner in fleet.runners]
    registrations = tuple(
        RunnerDatabaseRegistrationProjection(
            runner_id=UUID(str(row[0])),
            pool_id=UUID(str(row[1])),
            placement_id=UUID(str(row[2])),
            instance_key=str(row[3]),
            failure_domain=str(row[4]),
            connection_generation=int(row[5]),
            status=str(row[6]),
            connection_token_sha256=str(row[7]),
            protocol_version=int(row[8]),
            source_revision=str(row[9]),
            schema_revision=str(row[10]),
            adapter_contract_version=str(row[11]),
            capabilities=tuple(str(value) for value in row[12]),
            capabilities_sha256=str(row[13]),
            max_concurrency=int(row[14]),
            active_leases=int(row[15]),
        )
        for row in connection.execute(
            sa.text(
                "SELECT id::text, pool_id::text, placement_id::text, instance_key, "
                "failure_domain, connection_generation, status, connection_token_hash, "
                "protocol_version, source_revision, schema_revision, "
                "adapter_contract_version, capabilities, capabilities_hash, "
                "max_concurrency, active_leases "
                "FROM public.saas_runner_registrations "
                "WHERE id = ANY(CAST(:runner_ids AS uuid[])) "
                "OR status IN ('online', 'draining') OR active_leases <> 0 "
                "ORDER BY id"
            ),
            {"runner_ids": runner_ids},
        ).all()
    )
    return RunnerDatabaseFleetCatalogProjection(
        identity=identity,
        schema_revision=schema_revision,
        cluster_settings=cluster_settings,
        prepared_transaction_count=prepared_transaction_count,
        roles=roles,
        memberships=memberships,
        direct_acl_count=direct_acl_count,
        owned_object_count=owned_object_count,
        role_setting_count=role_setting_count,
        user_mapping_count=user_mapping_count,
        direct_policy_count=direct_policy_count,
        registrations=registrations,
    )


def _expected_roles(fleet: RunnerDatabaseFleet) -> tuple[RunnerDatabaseRoleProjection, ...]:
    common = {
        "is_superuser": False,
        "can_create_database": False,
        "can_create_role": False,
        "can_replicate": False,
        "bypasses_rls": False,
        "inherits_roles": True,
        "role_config_is_null": True,
        "valid_until_is_null": True,
    }
    roles = [
        RunnerDatabaseRoleProjection(
            name=_RUNNER_BASE_ROLE,
            can_login=False,
            connection_limit=-1,
            **common,
        )
    ]
    roles.extend(
        RunnerDatabaseRoleProjection(
            name=runner.login,
            can_login=True,
            connection_limit=8,
            **common,
        )
        for runner in fleet.runners
    )
    return tuple(sorted(roles, key=lambda role: role.name))


def _projection_document(projection: RunnerDatabaseFleetCatalogProjection) -> dict[str, object]:
    return {
        "direct_acl_count": projection.direct_acl_count,
        "direct_policy_count": projection.direct_policy_count,
        "memberships": [
            {
                "admin_option": membership.admin_option,
                "granted_role": membership.granted_role,
                "inherit_option": membership.inherit_option,
                "member": membership.member,
                "set_option": membership.set_option,
            }
            for membership in projection.memberships
        ],
        "owned_object_count": projection.owned_object_count,
        "role_setting_count": projection.role_setting_count,
        "roles": [
            {
                "bypasses_rls": role.bypasses_rls,
                "can_create_database": role.can_create_database,
                "can_create_role": role.can_create_role,
                "can_login": role.can_login,
                "can_replicate": role.can_replicate,
                "connection_limit": role.connection_limit,
                "inherits_roles": role.inherits_roles,
                "is_superuser": role.is_superuser,
                "name": role.name,
                "role_config_is_null": role.role_config_is_null,
                "valid_until_is_null": role.valid_until_is_null,
            }
            for role in projection.roles
        ],
        "user_mapping_count": projection.user_mapping_count,
    }


def _registration_document(
    registrations: tuple[RunnerDatabaseRegistrationProjection, ...],
) -> dict[str, object]:
    return {
        "registrations": [
            {
                "active_leases": registration.active_leases,
                "adapter_contract_version": registration.adapter_contract_version,
                "capabilities": list(registration.capabilities),
                "capabilities_sha256": registration.capabilities_sha256,
                "connection_generation": registration.connection_generation,
                "connection_token_sha256": registration.connection_token_sha256,
                "failure_domain": registration.failure_domain,
                "instance_key": registration.instance_key,
                "max_concurrency": registration.max_concurrency,
                "placement_id": str(registration.placement_id),
                "pool_id": str(registration.pool_id),
                "protocol_version": registration.protocol_version,
                "runner_id": str(registration.runner_id),
                "schema_revision": registration.schema_revision,
                "source_revision": registration.source_revision,
                "status": registration.status,
            }
            for registration in registrations
        ]
    }


def _redacted_registration_document(
    registrations: tuple[RunnerDatabaseRegistrationProjection, ...],
) -> dict[str, object]:
    return {
        "registrations": [
            {
                "active_leases": registration.active_leases,
                "connection_generation": registration.connection_generation,
                "runner_id": str(registration.runner_id),
                "status": registration.status,
            }
            for registration in registrations
        ]
    }


def validate_runner_database_fleet_registration_projection(
    *,
    fleet: RunnerDatabaseFleet,
    context: RunnerDatabaseFleetEvidenceContext,
    registrations: tuple[RunnerDatabaseRegistrationProjection, ...],
    expected_status: str,
) -> str:
    """Validate every durable registration fact and return its canonical digest."""

    if expected_status not in {"draining", "online"}:
        raise RunnerDatabaseFleetError("Runner fleet expected registration status is invalid")
    fleet_pairs = {(runner.runner_id, runner.connection_generation) for runner in fleet.runners}
    context_pairs = {
        (runner.runner_id, runner.connection_generation) for runner in context.runners
    }
    if fleet_pairs != context_pairs:
        raise RunnerDatabaseFleetError("Runner fleet registration context is inconsistent")
    expected_registrations = tuple(
        sorted(
            (
                RunnerDatabaseRegistrationProjection(
                    runner_id=runner.runner_id,
                    pool_id=runner.pool_id,
                    placement_id=runner.placement_id,
                    instance_key=runner.instance_key,
                    failure_domain=runner.failure_domain,
                    connection_generation=runner.connection_generation,
                    status=expected_status,
                    connection_token_sha256="",
                    protocol_version=runner.protocol_version,
                    source_revision=runner.source_revision,
                    schema_revision=runner.schema_revision,
                    adapter_contract_version=runner.adapter_contract_version,
                    capabilities=runner.capabilities,
                    capabilities_sha256=runner.capabilities_sha256,
                    max_concurrency=runner.max_concurrency,
                    active_leases=0,
                )
                for runner in context.runners
            ),
            key=lambda registration: str(registration.runner_id),
        )
    )
    if len(registrations) != 2 or any(
        registration.connection_token_sha256 == ""
        or _SHA256.fullmatch(registration.connection_token_sha256) is None
        or registration.connection_token_sha256 == "0" * 64
        or replace(registration, connection_token_sha256="") != expected
        for registration, expected in zip(registrations, expected_registrations, strict=True)
    ):
        raise RunnerDatabaseFleetError(
            f"Runner fleet registrations are not exact, {expected_status}, and fully drained"
        )
    return hashlib.sha256(
        _canonical_json(_registration_document(registrations)).encode("ascii")
    ).hexdigest()


def validate_runner_database_fleet_projection(
    *,
    fleet: RunnerDatabaseFleet,
    context: RunnerDatabaseFleetEvidenceContext,
    projection: RunnerDatabaseFleetCatalogProjection,
) -> str:
    """Validate an observed projection and return its canonical role/ACL digest."""

    identity = projection.identity
    if (
        identity.operator != identity.session_user
        or _ROLE_NAME.fullmatch(identity.operator) is None
        or not identity.operator_is_superuser
        or identity.database != context.database
        or identity.database_oid != context.database_oid
        or identity.server_version_num // 10_000 != 18
        or identity.system_identifier != context.database_system_identifier
        or identity.in_recovery
        or not identity.tls
        or not identity.transaction_read_only
    ):
        raise RunnerDatabaseFleetError("Runner fleet database identity is unsafe")
    if projection.schema_revision != context.schema_revision or (
        projection.schema_revision != _SCHEMA_REVISION
    ):
        raise RunnerDatabaseFleetError("Runner fleet schema revision is unsafe")
    expected_settings = (
        ("max_notify_queue_pages", "64", "postmaster", False, "configuration file"),
        ("max_prepared_transactions", "0", "postmaster", False, "configuration file"),
    )
    if projection.cluster_settings != expected_settings or projection.prepared_transaction_count:
        raise RunnerDatabaseFleetError("Runner fleet PostgreSQL settings are unsafe")
    if projection.roles != _expected_roles(fleet):
        raise RunnerDatabaseFleetError("Runner fleet role flags or role set are unsafe")
    expected_memberships = tuple(
        RunnerDatabaseMembershipProjection(
            member=runner.login,
            granted_role=_RUNNER_BASE_ROLE,
            admin_option=False,
            inherit_option=True,
            set_option=False,
        )
        for runner in sorted(fleet.runners, key=lambda item: item.login)
    )
    if projection.memberships != expected_memberships:
        raise RunnerDatabaseFleetError("Runner fleet membership graph is unsafe")
    if any(
        value != 0
        for value in (
            projection.direct_acl_count,
            projection.owned_object_count,
            projection.role_setting_count,
            projection.user_mapping_count,
            projection.direct_policy_count,
        )
    ):
        raise RunnerDatabaseFleetError("Runner fleet has direct database authority")
    validate_runner_database_fleet_registration_projection(
        fleet=fleet,
        context=context,
        registrations=projection.registrations,
        expected_status="draining",
    )
    rendered = _canonical_json(_projection_document(projection)).encode("ascii")
    return hashlib.sha256(rendered).hexdigest()


def run_runner_database_fleet_admission(
    *,
    engine: Engine,
    fleet: RunnerDatabaseFleet,
    context: RunnerDatabaseFleetEvidenceContext,
    trust_pins: RunnerDatabaseFleetTrustPins,
    environment_attestation: VerifiedRunnerDatabaseFleetAttestation,
    source_sha256s: Mapping[str, str],
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    """Run a read-only, repeatable-read fleet admission and build an unsigned receipt."""

    if engine.dialect.name != "postgresql":
        raise RunnerDatabaseFleetError("Runner fleet admission requires PostgreSQL")
    if trust_pins.stage != "admission":
        raise RunnerDatabaseFleetError(
            "Runner fleet owner admission requires admission trust pins"
        )
    if (
        environment_attestation.sha256 != trust_pins.attestation_sha256
        or environment_attestation.public_key_sha256 != trust_pins.attestation_public_key_sha256
    ):
        raise RunnerDatabaseFleetError("Runner fleet environment attestation is not trusted")
    if set(source_sha256s) != _EXPECTED_SOURCE_HASH_KEYS or any(
        _SHA256.fullmatch(value) is None for value in source_sha256s.values()
    ):
        raise RunnerDatabaseFleetError("Runner fleet source hashes are invalid")
    try:
        from saas.production.runner_executor import (
            _verify_runner_agent_database_authority,
        )

        with engine.connect() as connection, connection.begin():
            connection.exec_driver_sql(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            projection = inspect_runner_database_fleet_projection(connection, fleet=fleet)
            projection_sha256 = validate_runner_database_fleet_projection(
                fleet=fleet,
                context=context,
                projection=projection,
            )
            runtime_contract_sha256s: list[str] = []
            for runner in fleet.runners:
                connection.exec_driver_sql(f"SET LOCAL SESSION AUTHORIZATION '{runner.login}'")
                try:
                    runtime_contract_sha256s.append(
                        _verify_runner_agent_database_authority(
                            connection,
                            runner_id=runner.runner_id,
                            connection_generation=runner.connection_generation,
                            fleet_members=cast(
                                tuple[tuple[UUID, int], tuple[UUID, int]],
                                tuple(
                                    (member.runner_id, member.connection_generation)
                                    for member in fleet.runners
                                ),
                            ),
                            required_registration_status="draining",
                        )
                    )
                finally:
                    connection.exec_driver_sql("RESET SESSION AUTHORIZATION")
            if len(set(runtime_contract_sha256s)) != 1:
                raise RunnerDatabaseFleetError(
                    "Runner fleet runtime catalog contracts are inconsistent"
                )
    except RunnerDatabaseFleetError:
        raise
    except sa.exc.SQLAlchemyError:
        raise RunnerDatabaseFleetError("Runner fleet database inspection failed") from None
    verified_at = now()
    if verified_at.tzinfo is None or verified_at.utcoffset() is None:
        raise RunnerDatabaseFleetError("Runner fleet verification time is invalid")
    verified_at = verified_at.astimezone(UTC).replace(microsecond=0)
    expires_at = verified_at + _MAX_RECEIPT_TTL
    identity = projection.identity
    registration_document = _registration_document(projection.registrations)
    redacted_registrations = _redacted_registration_document(projection.registrations)
    registration_sha256 = hashlib.sha256(
        _canonical_json(registration_document).encode("ascii")
    ).hexdigest()
    online_registrations = tuple(
        replace(registration, status="online") for registration in projection.registrations
    )
    online_registration_sha256 = validate_runner_database_fleet_registration_projection(
        fleet=fleet,
        context=context,
        registrations=online_registrations,
        expected_status="online",
    )
    catalog_projection_sha256 = hashlib.sha256(
        _canonical_json(
            {
                "role_acl_projection_sha256": projection_sha256,
                "runtime_authority_contract_sha256": runtime_contract_sha256s[0],
                "runner_executor_source_sha256": source_sha256s["runner_executor"],
            }
        ).encode("ascii")
    ).hexdigest()
    return {
        "admission_epoch": context.admission_epoch,
        "audience": _RECEIPT_AUDIENCE,
        "catalog_projection_sha256": catalog_projection_sha256,
        "database_identity": {
            "database": identity.database,
            "database_oid": identity.database_oid,
            "server_version_num": identity.server_version_num,
            "system_identifier": identity.system_identifier,
        },
        "environment_attestation_public_key_sha256": (environment_attestation.public_key_sha256),
        "environment_attestation_sha256": environment_attestation.sha256,
        "evidence_context_sha256": context.sha256,
        "expires_at": _format_time(expires_at),
        "image_digest": context.image_digest,
        "issued_at": _format_time(verified_at),
        "issuer": trust_pins.receipt_issuer,
        "key_id": trust_pins.receipt_key_id,
        "operator": identity.operator,
        "payload_type": _RECEIPT_PAYLOAD_TYPE,
        "product_revision": context.product_revision,
        "role_acl_projection_sha256": projection_sha256,
        "runner_database_fleet_sha256": fleet.sha256,
        "runner_registration_projection_sha256": registration_sha256,
        "runner_registration_online_projection_sha256": online_registration_sha256,
        "runner_registrations": redacted_registrations["registrations"],
        "schema_revision": context.schema_revision,
        "schema_version": 1,
        "source_sha256s": dict(sorted(source_sha256s.items())),
        "status": "pass",
        "admission_trust_pins_sha256": trust_pins.sha256,
        "verified_at": verified_at.isoformat().replace("+00:00", "Z"),
    }


def sign_runner_database_fleet_admission_receipt(
    source: Mapping[str, str],
    *,
    receipt: Mapping[str, object],
    trust_pins: RunnerDatabaseFleetTrustPins,
) -> SignedRunnerDatabaseFleetAdmission:
    """Sign one canonical admission receipt with an external owner-only Ed25519 key."""

    if trust_pins.stage != "admission":
        raise RunnerDatabaseFleetError("Runner fleet receipt signing requires admission pins")
    if (
        receipt.get("issuer") != trust_pins.receipt_issuer
        or receipt.get("key_id") != trust_pins.receipt_key_id
        or receipt.get("payload_type") != _RECEIPT_PAYLOAD_TYPE
    ):
        raise RunnerDatabaseFleetError("Runner fleet receipt signer binding is invalid")
    private_key = _load_pinned_private_key(
        source,
        expected_public_key_sha256=trust_pins.receipt_public_key_sha256,
    )
    document = cast(dict[str, object], dict(receipt))
    raw = _canonical_json(document)
    signature = private_key.sign(admission_signature_payload(document))
    return SignedRunnerDatabaseFleetAdmission(
        receipt=raw,
        receipt_sha256=hashlib.sha256(raw.encode("ascii")).hexdigest(),
        signature=base64.b64encode(signature).decode("ascii"),
        signature_sha256=hashlib.sha256(signature).hexdigest(),
    )


def load_and_verify_runner_database_fleet_admission_receipt(
    source: Mapping[str, str],
    *,
    fleet: RunnerDatabaseFleet,
    context: RunnerDatabaseFleetEvidenceContext,
    trust_pins: RunnerDatabaseFleetTrustPins,
    environment_attestation: VerifiedRunnerDatabaseFleetAttestation,
    now: datetime,
    enforce_promotion_deadline: bool = True,
) -> VerifiedRunnerDatabaseFleetAdmission:
    """Verify exact canonical receipt bytes and detached signature at the use boundary."""

    if trust_pins.stage != "runtime":
        raise RunnerDatabaseFleetError("Runner fleet receipt verification requires runtime pins")
    if trust_pins.receipt_sha256 is None or trust_pins.receipt_signature_sha256 is None:
        raise RunnerDatabaseFleetError("Runner fleet runtime pins are incomplete")
    _path, raw = _read_owner_only_file(
        source,
        RUNNER_DATABASE_FLEET_RECEIPT_FILE_ENV,
        maximum=_MAX_DOCUMENT_BYTES,
    )
    try:
        text = raw.decode("ascii")
        document = json.loads(text)
    except (UnicodeError, json.JSONDecodeError):
        raise RunnerDatabaseFleetError("Runner fleet admission receipt is invalid") from None
    if not isinstance(document, dict):
        raise RunnerDatabaseFleetError("Runner fleet admission receipt must be an object")
    receipt = cast(dict[str, object], document)
    receipt_sha256 = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(receipt_sha256, trust_pins.receipt_sha256):
        raise RunnerDatabaseFleetError("Runner fleet admission receipt SHA is untrusted")
    if text != _canonical_json(receipt):
        raise RunnerDatabaseFleetError("Runner fleet admission receipt must be canonical JSON")
    fields = {
        "schema_version",
        "payload_type",
        "audience",
        "issuer",
        "key_id",
        "status",
        "admission_epoch",
        "issued_at",
        "expires_at",
        "verified_at",
        "runner_database_fleet_sha256",
        "evidence_context_sha256",
        "environment_attestation_sha256",
        "environment_attestation_public_key_sha256",
        "admission_trust_pins_sha256",
        "catalog_projection_sha256",
        "role_acl_projection_sha256",
        "runner_registration_projection_sha256",
        "runner_registration_online_projection_sha256",
        "runner_registrations",
        "database_identity",
        "product_revision",
        "image_digest",
        "schema_revision",
        "source_sha256s",
        "operator",
    }
    if set(receipt) != fields or receipt.get("schema_version") != 1:
        raise RunnerDatabaseFleetError("Runner fleet admission receipt shape is invalid")
    issued_at = _parse_time(receipt.get("issued_at"), field="receipt issued_at")
    expires_at = _parse_time(receipt.get("expires_at"), field="receipt expires_at")
    if receipt.get("verified_at") != _format_time(issued_at):
        raise RunnerDatabaseFleetError("Runner fleet receipt verification time is inconsistent")
    if enforce_promotion_deadline:
        _validate_signature_window(
            issued_at=issued_at,
            expires_at=expires_at,
            now=now,
            maximum_ttl=_MAX_RECEIPT_TTL,
            subject="admission receipt",
        )
    elif (
        issued_at > now.astimezone(UTC)
        or expires_at <= issued_at
        or expires_at - issued_at > _MAX_RECEIPT_TTL
    ):
        raise RunnerDatabaseFleetError("Runner fleet receipt validity window is invalid")
    public_key = _load_pinned_public_key(
        source,
        file_environment=RUNNER_DATABASE_FLEET_RECEIPT_PUBLIC_KEY_FILE_ENV,
        expected_sha256=trust_pins.receipt_public_key_sha256,
    )
    signature = _load_detached_signature(
        source,
        file_environment=RUNNER_DATABASE_FLEET_RECEIPT_SIGNATURE_FILE_ENV,
        expected_sha256=trust_pins.receipt_signature_sha256,
    )
    try:
        public_key.verify(signature, admission_signature_payload(receipt))
    except InvalidSignature:
        raise RunnerDatabaseFleetError(
            "Runner fleet admission receipt signature is invalid"
        ) from None
    expected_registrations = [
        {
            "active_leases": 0,
            "connection_generation": runner.connection_generation,
            "runner_id": str(runner.runner_id),
            "status": "draining",
        }
        for runner in sorted(fleet.runners, key=lambda item: str(item.runner_id))
    ]
    database_identity = receipt.get("database_identity")
    expected_database_identity = {
        "database": context.database,
        "database_oid": context.database_oid,
        "server_version_num": context.cnpg_postgresql_major * 10_000,
        "system_identifier": context.database_system_identifier,
    }
    if not isinstance(database_identity, dict) or any(
        database_identity.get(field) != value
        for field, value in expected_database_identity.items()
        if field != "server_version_num"
    ):
        raise RunnerDatabaseFleetError("Runner fleet receipt database identity is invalid")
    server_version_num = database_identity.get("server_version_num")
    if type(server_version_num) is not int or server_version_num // 10_000 != 18:
        raise RunnerDatabaseFleetError("Runner fleet receipt PostgreSQL major is invalid")
    hashes = (
        receipt.get("catalog_projection_sha256"),
        receipt.get("role_acl_projection_sha256"),
        receipt.get("runner_registration_projection_sha256"),
        receipt.get("runner_registration_online_projection_sha256"),
        receipt.get("admission_trust_pins_sha256"),
    )
    if any(not isinstance(value, str) or _SHA256.fullmatch(value) is None for value in hashes):
        raise RunnerDatabaseFleetError("Runner fleet receipt projection hashes are invalid")
    source_hashes = receipt.get("source_sha256s")
    if (
        not isinstance(source_hashes, dict)
        or set(source_hashes) != _EXPECTED_SOURCE_HASH_KEYS
        or any(
            not isinstance(value, str) or _SHA256.fullmatch(value) is None
            for value in source_hashes.values()
        )
    ):
        raise RunnerDatabaseFleetError("Runner fleet receipt source hashes are invalid")
    if (
        receipt.get("payload_type") != _RECEIPT_PAYLOAD_TYPE
        or receipt.get("audience") != _RECEIPT_AUDIENCE
        or receipt.get("issuer") != trust_pins.receipt_issuer
        or receipt.get("key_id") != trust_pins.receipt_key_id
        or receipt.get("status") != "pass"
        or receipt.get("admission_epoch") != trust_pins.admission_epoch
        or receipt.get("admission_epoch") != context.admission_epoch
        or receipt.get("runner_database_fleet_sha256") != fleet.sha256
        or receipt.get("evidence_context_sha256") != context.sha256
        or receipt.get("environment_attestation_sha256") != environment_attestation.sha256
        or receipt.get("environment_attestation_sha256") != trust_pins.attestation_sha256
        or receipt.get("environment_attestation_public_key_sha256")
        != trust_pins.attestation_public_key_sha256
        or receipt.get("runner_registrations") != expected_registrations
        or receipt.get("product_revision") != context.product_revision
        or receipt.get("image_digest") != context.image_digest
        or receipt.get("schema_revision") != context.schema_revision
        or not isinstance(receipt.get("operator"), str)
        or _ROLE_NAME.fullmatch(cast(str, receipt["operator"])) is None
    ):
        raise RunnerDatabaseFleetError("Runner fleet admission receipt binding is invalid")
    return VerifiedRunnerDatabaseFleetAdmission(
        document=receipt,
        receipt_sha256=receipt_sha256,
        signature_sha256=hashlib.sha256(signature).hexdigest(),
        public_key_sha256=_public_key_fingerprint(public_key),
        admission_epoch=cast(int, receipt["admission_epoch"]),
        issued_at=issued_at,
        expires_at=expires_at,
        fleet_sha256=fleet.sha256,
        evidence_context_sha256=context.sha256,
        environment_attestation_sha256=environment_attestation.sha256,
        catalog_projection_sha256=cast(str, receipt["catalog_projection_sha256"]),
        registration_projection_sha256=cast(str, receipt["runner_registration_projection_sha256"]),
        online_registration_projection_sha256=cast(
            str, receipt["runner_registration_online_projection_sha256"]
        ),
        product_revision=context.product_revision,
        schema_revision=context.schema_revision,
    )


def verify_runner_database_fleet_runtime_admission(
    source: Mapping[str, str],
    *,
    runner_id: UUID,
    connection_generation: int,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[
    VerifiedRunnerDatabaseFleetAdmission,
    tuple[tuple[UUID, int], tuple[UUID, int]],
]:
    """Reverify immutable signed artifacts at startup/each claim without TTL self-destruction."""

    fleet = load_runner_database_fleet(source)
    context = load_runner_database_fleet_evidence_context(source, fleet=fleet)
    verify_runner_database_fleet_release_facts(source, context)
    verify_installed_runner_database_fleet_lineage(context)
    pins = load_runner_database_fleet_trust_pins(
        source,
        fleet=fleet,
        context=context,
    )
    if pins.stage != "runtime":
        raise RunnerDatabaseFleetError("Runner fleet runtime requires runtime trust pins")
    checked_at = now()
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise RunnerDatabaseFleetError("Runner fleet runtime clock is invalid")
    attestation = load_and_verify_runner_database_fleet_environment_attestation(
        source,
        fleet=fleet,
        context=context,
        pins=pins,
        now=checked_at,
        enforce_expiry=False,
    )
    admission = load_and_verify_runner_database_fleet_admission_receipt(
        source,
        fleet=fleet,
        context=context,
        trust_pins=pins,
        environment_attestation=attestation,
        now=checked_at,
        enforce_promotion_deadline=False,
    )
    observed_sources = runner_database_fleet_source_sha256s()
    if admission.document.get("source_sha256s") != observed_sources:
        raise RunnerDatabaseFleetError("Runner fleet runtime source lineage is stale")
    members = cast(
        tuple[tuple[UUID, int], tuple[UUID, int]],
        tuple((member.runner_id, member.connection_generation) for member in fleet.runners),
    )
    if (runner_id, connection_generation) not in members:
        raise RunnerDatabaseFleetError("Runner identity is not in the signed exact A/B fleet")
    return admission, members


def verify_runner_database_fleet_runtime_catalog_binding(
    admission: VerifiedRunnerDatabaseFleetAdmission,
    *,
    runtime_authority_contract_sha256: str,
) -> None:
    """Bind the live full-catalog verifier result to the exact signed receipt."""

    _nonzero_match(
        runtime_authority_contract_sha256,
        _SHA256,
        field="runtime_authority_contract_sha256",
    )
    role_acl_sha256 = admission.document.get("role_acl_projection_sha256")
    source_hashes = admission.document.get("source_sha256s")
    if not isinstance(role_acl_sha256, str) or not isinstance(source_hashes, dict):
        raise RunnerDatabaseFleetError("Runner fleet signed catalog binding is invalid")
    runner_executor_sha256 = source_hashes.get("runner_executor")
    if not isinstance(runner_executor_sha256, str):
        raise RunnerDatabaseFleetError("Runner fleet executor source binding is invalid")
    observed = hashlib.sha256(
        _canonical_json(
            {
                "role_acl_projection_sha256": role_acl_sha256,
                "runtime_authority_contract_sha256": runtime_authority_contract_sha256,
                "runner_executor_source_sha256": runner_executor_sha256,
            }
        ).encode("ascii")
    ).hexdigest()
    if not hmac.compare_digest(observed, admission.catalog_projection_sha256):
        raise RunnerDatabaseFleetError("Runner fleet live catalog differs from signed admission")


__all__ = [
    "RUNNER_DATABASE_FLEET_ADMIN_URL_FILE_ENV",
    "RUNNER_DATABASE_FLEET_ATTESTATION_FILE_ENV",
    "RUNNER_DATABASE_FLEET_ATTESTATION_PUBLIC_KEY_FILE_ENV",
    "RUNNER_DATABASE_FLEET_ATTESTATION_SIGNATURE_FILE_ENV",
    "RUNNER_DATABASE_FLEET_CONTEXT_FILE_ENV",
    "RUNNER_DATABASE_FLEET_CONTEXT_SHA256_ENV",
    "RUNNER_DATABASE_FLEET_FILE_ENV",
    "RUNNER_DATABASE_FLEET_NAMESPACE_ENV",
    "RUNNER_DATABASE_FLEET_RECEIPT_FILE_ENV",
    "RUNNER_DATABASE_FLEET_RECEIPT_PRIVATE_KEY_FILE_ENV",
    "RUNNER_DATABASE_FLEET_RECEIPT_PUBLIC_KEY_FILE_ENV",
    "RUNNER_DATABASE_FLEET_RECEIPT_SIGNATURE_FILE_ENV",
    "RUNNER_DATABASE_FLEET_SHA256_ENV",
    "RUNNER_DATABASE_FLEET_STAGE_DATABASE_HOST_ENV",
    "RUNNER_DATABASE_FLEET_STAGE_DATABASE_NAME_ENV",
    "RUNNER_DATABASE_FLEET_STAGE_DATABASE_PORT_ENV",
    "RUNNER_DATABASE_FLEET_STAGE_FILE_ENV",
    "RUNNER_DATABASE_FLEET_STAGE_SHA256_ENV",
    "RUNNER_DATABASE_FLEET_STAGE_TOKEN_OUTPUT_FILE_ENV",
    "RUNNER_DATABASE_FLEET_TRUST_PINS_FILE_ENV",
    "RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV",
    "RunnerDatabaseFleet",
    "RunnerDatabaseFleetCatalogProjection",
    "RunnerDatabaseFleetError",
    "RunnerDatabaseFleetEvidenceContext",
    "RunnerDatabaseFleetEvidenceMember",
    "RunnerDatabaseFleetMember",
    "RunnerDatabaseFleetStageSpec",
    "RunnerDatabaseFleetTrustPins",
    "RunnerDatabaseIdentityProjection",
    "RunnerDatabaseMembershipProjection",
    "RunnerDatabaseRegistrationProjection",
    "RunnerDatabaseRoleProjection",
    "SignedRunnerDatabaseFleetAdmission",
    "StagedRunnerDatabaseFleetMember",
    "VerifiedRunnerDatabaseFleetAdmission",
    "VerifiedRunnerDatabaseFleetAttestation",
    "inspect_runner_database_fleet_projection",
    "load_and_verify_runner_database_fleet_admission_receipt",
    "load_and_verify_runner_database_fleet_environment_attestation",
    "load_runner_database_fleet",
    "load_runner_database_fleet_admin_database_url",
    "load_runner_database_fleet_evidence_context",
    "load_runner_database_fleet_stage_admin_database_url",
    "load_runner_database_fleet_stage_specs",
    "load_runner_database_fleet_trust_pins",
    "promote_runner_database_fleet_after_admission",
    "render_runner_database_fleet",
    "render_runner_database_fleet_evidence_context",
    "render_runner_database_fleet_stage_specs",
    "render_runner_database_fleet_trust_pins",
    "run_runner_database_fleet_admission",
    "runner_database_fleet_environment_attestation_document",
    "runner_database_fleet_source_sha256s",
    "sign_runner_database_fleet_admission_receipt",
    "stage_runner_database_fleet",
    "validate_runner_database_fleet_projection",
    "validate_runner_database_fleet_registration_projection",
    "verify_installed_runner_database_fleet_lineage",
    "verify_runner_database_fleet_release_facts",
    "verify_runner_database_fleet_runtime_admission",
    "verify_runner_database_fleet_runtime_catalog_binding",
]
