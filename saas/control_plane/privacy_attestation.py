"""DSSE verification boundary for append-only privacy execution evidence."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from types import MappingProxyType
from typing import NoReturn, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from saas.control_plane.platform_security import PlatformSecurityError

PRIVACY_DSSE_PAYLOAD_TYPE = "application/vnd.omnigent.privacy-evidence.v1+json"
PRIVACY_DSSE_KEY_PURPOSE = "privacy-surface-evidence"

_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "subject_kind",
        "manifest_id",
        "work_item_id",
        "attempt_id",
        "surface",
        "phase",
        "target_locator_hmac",
        "disposition",
        "outcome",
        "evidence_sha256",
        "remaining_item_count",
        "runtime_accessible",
        "direct_identifiers_remaining",
        "retention_until",
        "retention_basis",
        "tombstone_sha256",
        "product_revision",
        "upstream_revision",
        "schema_revision",
        "adapter_contract_version",
        "policy_version",
        "workflow_identity",
        "artifact_uri",
        "immutability_receipt_sha256",
        "kms_audit_receipt_sha256",
        "observed_at",
        "issued_at",
        "expires_at",
    }
)
_SUBJECT_KINDS = frozenset(
    {"surface_attempt", "backup_purge", "manifest_attestation", "production_admission"}
)
_ATTESTOR_ROLES = frozenset({"privacy", "security", "data_owner"})
_EXPECTED_CLAIM_FIELDS = _PAYLOAD_FIELDS - {"observed_at", "issued_at", "expires_at"}
_VERIFIER_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "attestation_id",
        "manifest_id",
        "target_type",
        "target_id",
        "subject_kind",
        "subject_id",
        "execution_attempt_id",
        "attempt_number",
        "lease_generation",
        "replay_generation",
        "surface",
        "payload_sha256",
        "envelope_sha256",
        "artifact_uri",
        "immutability_receipt_sha256",
        "kms_audit_receipt_sha256",
        "signer_key_id",
        "workflow_identity",
        "observed_at",
        "signed_at",
        "verified_at",
        "verifier_policy_version",
    }
)


def canonical_json(value: object) -> bytes:
    """Return deterministic UTF-8 JSON used for hashes and signatures."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Build DSSE v1 pre-authentication encoding without ambiguous concatenation."""

    encoded_type = payload_type.encode("utf-8")
    return b" ".join(
        (
            b"DSSEv1",
            str(len(encoded_type)).encode("ascii"),
            encoded_type,
            str(len(payload)).encode("ascii"),
            payload,
        )
    )


def privacy_verifier_receipt_sha256(facts: Mapping[str, object]) -> str:
    """Hash the exact immutable facts written only by the independent verifier role."""

    if set(facts) != _VERIFIER_RECEIPT_FIELDS or facts.get("schema_version") != 1:
        raise PlatformSecurityError(
            "platform_privacy_attestation_invalid",
            "privacy verifier receipt fields do not match the schema",
        )
    return sha256(canonical_json(dict(facts))).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise PlatformSecurityError(
            "platform_privacy_attestation_invalid",
            "privacy attestation time must include a timezone",
        )
    return value.astimezone(timezone.utc)


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise PlatformSecurityError("platform_privacy_attestation_invalid", f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PlatformSecurityError(
            "platform_privacy_attestation_invalid", f"{field} is invalid"
        ) from error
    return _utc(parsed)


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PlatformSecurityError("platform_privacy_attestation_invalid", f"{field} is invalid")
    return value


def _revision(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PlatformSecurityError("platform_privacy_attestation_invalid", f"{field} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class PrivacyAttestationTrustKey:
    """Public verification authority; signing material remains outside the app."""

    key_id: str
    public_key_pem: bytes
    workflow_identity: str
    purpose: str
    not_before: datetime
    not_after: datetime
    revocation_checked_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if (
            not self.key_id.strip()
            or not self.workflow_identity.strip()
            or self.purpose != PRIVACY_DSSE_KEY_PURPOSE
            or _utc(self.not_after) <= _utc(self.not_before)
            or _utc(self.revocation_checked_at) < _utc(self.not_before)
        ):
            raise ValueError("privacy attestation trust key is invalid")
        if self.revoked_at is not None and _utc(self.revoked_at) < _utc(self.not_before):
            raise ValueError("privacy attestation key revocation predates activation")


@dataclass(frozen=True, slots=True)
class PrivacyDsseEnvelope:
    """External DSSE envelope plus immutable-storage receipts."""

    envelope: Mapping[str, object]
    artifact_uri: str
    immutability_receipt_sha256: str
    kms_audit_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPrivacyAttestation:
    """Content-blind metadata safe to persist after cryptographic verification."""

    payload_type: str
    payload: Mapping[str, object]
    payload_sha256: str
    envelope_sha256: str
    artifact_uri: str
    immutability_receipt_sha256: str
    kms_audit_receipt_sha256: str
    signature_algorithm: str
    key_id: str
    workflow_identity: str
    subject_kind: str
    observed_at: datetime
    issued_at: datetime
    expires_at: datetime
    verified_at: datetime


class PrivacyAttestationVerifier:
    """Verify exact-purpose Ed25519 DSSE envelopes against a rotating trust set."""

    def __init__(
        self,
        keys: tuple[PrivacyAttestationTrustKey, ...],
        *,
        max_observation_age: timedelta = timedelta(hours=24),
        max_verification_delay: timedelta = timedelta(hours=1),
        max_clock_skew: timedelta = timedelta(minutes=2),
        max_revocation_staleness: timedelta = timedelta(minutes=15),
    ) -> None:
        if len({key.key_id for key in keys}) != len(keys):
            raise ValueError("privacy attestation key identities must be unique")
        if any(
            value <= timedelta(0)
            for value in (
                max_observation_age,
                max_verification_delay,
                max_clock_skew,
                max_revocation_staleness,
            )
        ):
            raise ValueError("privacy attestation verification windows must be positive")
        self._keys = MappingProxyType({key.key_id: key for key in keys})
        self._max_observation_age = max_observation_age
        self._max_verification_delay = max_verification_delay
        self._max_clock_skew = max_clock_skew
        self._max_revocation_staleness = max_revocation_staleness

    def verify(
        self,
        value: PrivacyDsseEnvelope,
        *,
        expected_claims: Mapping[str, object],
        now: datetime,
    ) -> VerifiedPrivacyAttestation:
        checked_at = _utc(now)
        envelope = value.envelope
        if set(envelope) != {"payloadType", "payload", "signatures"}:
            self._invalid("DSSE envelope fields do not match the schema")
        payload_type = envelope.get("payloadType")
        encoded_payload = envelope.get("payload")
        signatures = envelope.get("signatures")
        if payload_type != PRIVACY_DSSE_PAYLOAD_TYPE:
            self._invalid("DSSE payload type is invalid")
        if not isinstance(encoded_payload, str) or not isinstance(signatures, list):
            self._invalid("DSSE payload or signatures are invalid")
        if len(signatures) != 1 or not isinstance(signatures[0], Mapping):
            self._invalid("DSSE envelope must contain one signature")
        signature_entry = cast(Mapping[str, object], signatures[0])
        if set(signature_entry) != {"keyid", "sig"}:
            self._invalid("DSSE signature fields do not match the schema")
        key_id = signature_entry.get("keyid")
        signature_value = signature_entry.get("sig")
        if not isinstance(key_id, str) or not isinstance(signature_value, str):
            self._invalid("DSSE signature identity is invalid")
        key = self._keys.get(key_id)
        if key is None:
            self._invalid("DSSE signer is not trusted")
        try:
            payload_bytes = base64.b64decode(encoded_payload.encode("ascii"), validate=True)
            signature = base64.b64decode(signature_value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as error:
            raise PlatformSecurityError(
                "platform_privacy_attestation_invalid",
                "DSSE payload or signature is not canonical base64",
            ) from error
        if (
            base64.b64encode(payload_bytes).decode("ascii") != encoded_payload
            or base64.b64encode(signature).decode("ascii") != signature_value
        ):
            self._invalid("DSSE payload or signature is not canonical base64")
        try:
            loaded = serialization.load_pem_public_key(key.public_key_pem)
        except ValueError as error:
            raise PlatformSecurityError(
                "platform_privacy_attestation_unavailable",
                "privacy evidence public key cannot be loaded",
            ) from error
        if not isinstance(loaded, Ed25519PublicKey):
            self._invalid("privacy evidence public key algorithm is invalid")
        try:
            loaded.verify(signature, dsse_pae(cast(str, payload_type), payload_bytes))
        except InvalidSignature as error:
            raise PlatformSecurityError(
                "platform_privacy_attestation_invalid", "DSSE signature is invalid"
            ) from error
        try:
            raw_payload = json.loads(payload_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PlatformSecurityError(
                "platform_privacy_attestation_invalid", "DSSE payload is not canonical JSON"
            ) from error
        if not isinstance(raw_payload, dict) or canonical_json(raw_payload) != payload_bytes:
            self._invalid("DSSE payload is not canonical JSON")
        payload = cast(dict[str, object], raw_payload)
        if set(payload) != _PAYLOAD_FIELDS:
            self._invalid("privacy evidence payload fields do not match the schema")
        if payload.get("schema_version") != 1 or payload.get("subject_kind") not in _SUBJECT_KINDS:
            self._invalid("privacy evidence subject is invalid")
        if set(expected_claims) != _EXPECTED_CLAIM_FIELDS:
            self._invalid("privacy evidence expected claims are incomplete")
        for field, expected in expected_claims.items():
            if field not in _PAYLOAD_FIELDS or payload.get(field) != expected:
                self._invalid(f"privacy evidence {field} does not match")
        for field in ("target_locator_hmac", "evidence_sha256", "tombstone_sha256"):
            if payload.get(field) is not None:
                _sha256(payload[field], field)
        for field in ("product_revision", "upstream_revision"):
            _revision(payload.get(field), field)
        observed_at = _parse_time(payload.get("observed_at"), "observed_at")
        issued_at = _parse_time(payload.get("issued_at"), "issued_at")
        expires_at = _parse_time(payload.get("expires_at"), "expires_at")
        if (
            observed_at > issued_at
            or issued_at > checked_at + self._max_clock_skew
            or checked_at < observed_at
            or issued_at - observed_at > self._max_observation_age
            or checked_at - issued_at > self._max_verification_delay
            or expires_at <= issued_at
            or checked_at >= expires_at
        ):
            self._invalid("privacy evidence validity window is invalid")
        if payload.get("workflow_identity") != key.workflow_identity:
            self._invalid("privacy evidence workflow identity is invalid")
        if issued_at < _utc(key.not_before) or expires_at > _utc(key.not_after):
            self._invalid("privacy evidence was issued outside key validity")
        revocation_checked_at = _utc(key.revocation_checked_at)
        if (
            revocation_checked_at < checked_at - self._max_revocation_staleness
            or revocation_checked_at > checked_at + self._max_clock_skew
        ):
            raise PlatformSecurityError(
                "platform_privacy_attestation_unavailable",
                "privacy evidence key revocation status is stale or unavailable",
            )
        if key.revoked_at is not None and checked_at >= _utc(key.revoked_at):
            self._invalid("privacy evidence signer was revoked")
        if not value.artifact_uri.startswith("https://") or len(value.artifact_uri) > 2048:
            self._invalid("privacy evidence artifact URI is invalid")
        immutability_hash = _sha256(
            value.immutability_receipt_sha256, "immutability_receipt_sha256"
        )
        kms_hash = _sha256(value.kms_audit_receipt_sha256, "kms_audit_receipt_sha256")
        if (
            payload.get("artifact_uri") != value.artifact_uri
            or payload.get("immutability_receipt_sha256") != immutability_hash
            or payload.get("kms_audit_receipt_sha256") != kms_hash
        ):
            self._invalid("privacy evidence does not bind its immutable artifact receipts")
        return VerifiedPrivacyAttestation(
            payload_type=cast(str, payload_type),
            payload=MappingProxyType(payload),
            payload_sha256=sha256(payload_bytes).hexdigest(),
            envelope_sha256=sha256(canonical_json(envelope)).hexdigest(),
            artifact_uri=value.artifact_uri,
            immutability_receipt_sha256=immutability_hash,
            kms_audit_receipt_sha256=kms_hash,
            signature_algorithm="ed25519",
            key_id=key.key_id,
            workflow_identity=key.workflow_identity,
            subject_kind=cast(str, payload["subject_kind"]),
            observed_at=observed_at,
            issued_at=issued_at,
            expires_at=expires_at,
            verified_at=checked_at,
        )

    @staticmethod
    def _invalid(message: str) -> NoReturn:
        raise PlatformSecurityError("platform_privacy_attestation_invalid", message)


def validate_manifest_attestors(
    attestations: tuple[Mapping[str, object], ...],
    *,
    expected_record_sha256: str,
) -> None:
    """Require three distinct human authorities over one exact manifest record."""

    _sha256(expected_record_sha256, "record_sha256")
    roles: set[str] = set()
    actors: set[str] = set()
    for value in attestations:
        role = value.get("attestor_role")
        actor_hash = value.get("actor_id_hmac")
        record_hash = value.get("record_sha256")
        if (
            role not in _ATTESTOR_ROLES
            or not isinstance(actor_hash, str)
            or len(actor_hash) != 64
            or record_hash != expected_record_sha256
        ):
            raise PlatformSecurityError(
                "platform_privacy_attestation_invalid",
                "manifest attestation does not match its authority or record",
            )
        roles.add(cast(str, role))
        actors.add(actor_hash)
    if roles != _ATTESTOR_ROLES or len(actors) != 3 or len(attestations) != 3:
        raise PlatformSecurityError(
            "platform_privacy_attestation_invalid",
            "privacy, security, and data-owner attestations must use distinct actors",
        )
