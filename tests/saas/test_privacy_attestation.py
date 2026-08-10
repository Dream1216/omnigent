from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saas.control_plane.platform_security import PlatformSecurityError
from saas.control_plane.privacy_attestation import (
    PRIVACY_DSSE_KEY_PURPOSE,
    PRIVACY_DSSE_PAYLOAD_TYPE,
    PrivacyAttestationTrustKey,
    PrivacyAttestationVerifier,
    PrivacyDsseEnvelope,
    canonical_json,
    dsse_pae,
    validate_manifest_attestors,
)

NOW = datetime(2026, 8, 10, 5, 0, tzinfo=timezone.utc)


def _payload(*, workflow: str = "spiffe://prod/privacy-worker") -> dict[str, object]:
    return {
        "schema_version": 1,
        "subject_kind": "surface_attempt",
        "manifest_id": str(uuid4()),
        "work_item_id": str(uuid4()),
        "attempt_id": str(uuid4()),
        "surface": "object_and_artifact_store",
        "phase": "primary_erasure",
        "target_locator_hmac": "1" * 64,
        "disposition": "erase",
        "outcome": "succeeded",
        "evidence_sha256": "2" * 64,
        "remaining_item_count": 0,
        "runtime_accessible": False,
        "direct_identifiers_remaining": False,
        "retention_until": None,
        "retention_basis": None,
        "tombstone_sha256": None,
        "product_revision": "3" * 40,
        "upstream_revision": "4" * 40,
        "schema_revision": "pc5b00000003",
        "adapter_contract_version": "privacy-adapter.v1",
        "policy_version": "2026-08-10.p1-privacy-execution",
        "workflow_identity": workflow,
        "artifact_uri": "https://evidence.example.test/privacy/immutable-envelope.json",
        "immutability_receipt_sha256": "5" * 64,
        "kms_audit_receipt_sha256": "6" * 64,
        "observed_at": NOW.isoformat(),
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=15)).isoformat(),
    }


def _envelope(
    private_key: Ed25519PrivateKey,
    payload: dict[str, object],
    *,
    key_id: str = "privacy-prod-2026-08",
) -> PrivacyDsseEnvelope:
    encoded = canonical_json(payload)
    signature = private_key.sign(dsse_pae(PRIVACY_DSSE_PAYLOAD_TYPE, encoded))
    return PrivacyDsseEnvelope(
        envelope={
            "payloadType": PRIVACY_DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(encoded).decode("ascii"),
            "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}],
        },
        artifact_uri="https://evidence.example.test/privacy/immutable-envelope.json",
        immutability_receipt_sha256="5" * 64,
        kms_audit_receipt_sha256="6" * 64,
    )


def _expected(payload: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in payload.items()
        if key not in {"observed_at", "issued_at", "expires_at"}
    }


def _verifier(
    private_key: Ed25519PrivateKey,
    *,
    workflow: str = "spiffe://prod/privacy-worker",
    revoked_at: datetime | None = None,
) -> PrivacyAttestationVerifier:
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return PrivacyAttestationVerifier(
        (
            PrivacyAttestationTrustKey(
                key_id="privacy-prod-2026-08",
                public_key_pem=public_pem,
                workflow_identity=workflow,
                purpose=PRIVACY_DSSE_KEY_PURPOSE,
                not_before=NOW - timedelta(days=1),
                not_after=NOW + timedelta(days=30),
                revocation_checked_at=NOW,
                revoked_at=revoked_at,
            ),
        )
    )


def test_privacy_dsse_verifies_exact_claims_and_external_receipts() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    verified = _verifier(private_key).verify(
        _envelope(private_key, payload),
        expected_claims=_expected(payload),
        now=NOW + timedelta(seconds=1),
    )

    assert verified.subject_kind == "surface_attempt"
    assert verified.signature_algorithm == "ed25519"
    assert verified.key_id == "privacy-prod-2026-08"
    assert verified.payload_sha256
    assert verified.envelope_sha256
    assert verified.immutability_receipt_sha256 == "5" * 64
    assert verified.kms_audit_receipt_sha256 == "6" * 64


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda payload: payload.update(surface="wrong"), "surface does not match"),
        (
            lambda payload: payload.update(workflow_identity="spiffe://attacker"),
            "workflow identity is invalid",
        ),
    ],
)
def test_privacy_dsse_rejects_claim_or_workflow_drift(mutation, message: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    mutation(payload)
    with pytest.raises(PlatformSecurityError, match=message):
        _verifier(private_key).verify(
            _envelope(private_key, payload),
            expected_claims=_expected({**payload, "surface": "object_and_artifact_store"}),
            now=NOW + timedelta(seconds=1),
        )


def test_privacy_dsse_rejects_tamper_and_revoked_key() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    value = _envelope(private_key, payload)
    tampered = dict(value.envelope)
    tampered["payload"] = base64.b64encode(
        canonical_json({**payload, "remaining_item_count": 1})
    ).decode("ascii")
    with pytest.raises(PlatformSecurityError, match="signature is invalid"):
        _verifier(private_key).verify(
            PrivacyDsseEnvelope(
                envelope=tampered,
                artifact_uri=value.artifact_uri,
                immutability_receipt_sha256=value.immutability_receipt_sha256,
                kms_audit_receipt_sha256=value.kms_audit_receipt_sha256,
            ),
            expected_claims=_expected(payload),
            now=NOW + timedelta(seconds=1),
        )

    with pytest.raises(PlatformSecurityError, match="signer was revoked"):
        _verifier(private_key, revoked_at=NOW).verify(
            value,
            expected_claims=_expected(payload),
            now=NOW + timedelta(seconds=1),
        )


def test_privacy_dsse_requires_complete_authoritative_claim_binding() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    with pytest.raises(PlatformSecurityError, match="expected claims are incomplete"):
        _verifier(private_key).verify(
            _envelope(private_key, payload),
            expected_claims={"manifest_id": payload["manifest_id"]},
            now=NOW + timedelta(seconds=1),
        )


def test_privacy_dsse_binds_external_receipts_and_enforces_time_windows() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = _payload()
    value = _envelope(private_key, payload)
    with pytest.raises(PlatformSecurityError, match="immutable artifact receipts"):
        _verifier(private_key).verify(
            PrivacyDsseEnvelope(
                envelope=value.envelope,
                artifact_uri=value.artifact_uri,
                immutability_receipt_sha256="7" * 64,
                kms_audit_receipt_sha256=value.kms_audit_receipt_sha256,
            ),
            expected_claims=_expected(payload),
            now=NOW + timedelta(seconds=1),
        )

    invalid_time = {
        **payload,
        "observed_at": (NOW + timedelta(seconds=2)).isoformat(),
        "issued_at": NOW.isoformat(),
    }
    with pytest.raises(PlatformSecurityError, match="validity window"):
        _verifier(private_key).verify(
            _envelope(private_key, invalid_time),
            expected_claims=_expected(invalid_time),
            now=NOW + timedelta(seconds=3),
        )


def test_privacy_dsse_fails_closed_when_revocation_status_is_stale() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier = PrivacyAttestationVerifier(
        (
            PrivacyAttestationTrustKey(
                key_id="privacy-prod-2026-08",
                public_key_pem=public_pem,
                workflow_identity="spiffe://prod/privacy-worker",
                purpose=PRIVACY_DSSE_KEY_PURPOSE,
                not_before=NOW - timedelta(days=1),
                not_after=NOW + timedelta(days=30),
                revocation_checked_at=NOW - timedelta(hours=1),
            ),
        )
    )
    payload = _payload()
    with pytest.raises(PlatformSecurityError, match="revocation status is stale"):
        verifier.verify(
            _envelope(private_key, payload),
            expected_claims=_expected(payload),
            now=NOW + timedelta(seconds=1),
        )


def test_manifest_attestations_require_three_distinct_authorities() -> None:
    record_hash = "a" * 64
    values = tuple(
        {
            "attestor_role": role,
            "actor_id_hmac": character * 64,
            "record_sha256": record_hash,
        }
        for role, character in (
            ("privacy", "b"),
            ("security", "c"),
            ("data_owner", "d"),
        )
    )
    validate_manifest_attestors(values, expected_record_sha256=record_hash)

    duplicate_actor = (*values[:2], {**values[2], "actor_id_hmac": "b" * 64})
    with pytest.raises(PlatformSecurityError, match="distinct actors"):
        validate_manifest_attestors(duplicate_actor, expected_record_sha256=record_hash)
