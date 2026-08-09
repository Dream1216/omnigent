from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from saas.production.deletion import (
    canonical_deletion_attestation_subject_sha256,
    canonical_deletion_record_sha256,
    load_deletion_evidence,
    validate_deletion_readiness,
)

_NOW = datetime(2026, 8, 5, 12, tzinfo=UTC)
_PRODUCT_REVISION = "a" * 40


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _policy() -> dict[str, object]:
    return json.loads(
        (_repo() / "saas/production/deletion-policy.json").read_text(encoding="utf-8")
    )


def _hash(seed: str) -> str:
    return (seed.encode("utf-8").hex() + "0" * 64)[:64]


def _evidence_artifact(
    name: str,
    payload_sha256: str,
    *,
    verified_at: str = "2026-08-05T09:00:00Z",
) -> dict[str, object]:
    return {
        "payload_sha256": payload_sha256,
        "dsse_envelope_sha256": _hash(f"dsse-{name}"),
        "immutability_receipt_sha256": _hash(f"immutability-{name}"),
        "kms_receipt_sha256": _hash(f"kms-{name}"),
        "signature_algorithm": "ed25519",
        "signing_key_id": "deletion-evidence-production-key-01",
        "signing_key_purpose": "production-tenant-deletion-evidence",
        "workflow_identity": "spiffe://omnigent/deletion-evidence",
        "verified_at": verified_at,
    }


def _outcome(name: str, requirement: dict[str, object]) -> dict[str, object]:
    disposition = requirement["disposition"]
    evidence_sha256 = _hash(f"evidence-{name}")
    common: dict[str, object] = {
        "disposition": disposition,
        "evidence_sha256": evidence_sha256,
        "runtime_accessible": False,
        "direct_identifiers_remaining": False,
        "purge_due_at": None,
        "retention_basis": None,
        "tombstone_sha256": None,
        "artifact": _evidence_artifact(name, evidence_sha256),
    }
    if disposition in {"erase", "cryptographic_erase"}:
        return {**common, "status": "erased", "remaining_item_count": 0}
    if disposition == "redact_and_retain":
        return {
            **common,
            "status": "retained",
            "remaining_item_count": 8,
            "purge_due_at": "2026-09-01T08:30:00Z",
            "retention_basis": "operational-security-retention",
        }
    if disposition == "anonymize_and_retain":
        return {
            **common,
            "status": "retained",
            "remaining_item_count": 12,
            "purge_due_at": "2030-08-05T08:30:00Z",
            "retention_basis": "audit-and-financial-record-retention",
        }
    if disposition == "tombstone_then_expire":
        return {
            **common,
            "status": "pending_retention",
            "remaining_item_count": 3,
            "direct_identifiers_remaining": True,
            "purge_due_at": "2026-09-01T08:30:00Z",
            "retention_basis": "immutable-backup-retention",
            "tombstone_sha256": _hash("backup-tombstone"),
        }
    raise AssertionError(f"unsupported test disposition {disposition}")


def _record() -> dict[str, object]:
    policy = _policy()
    surfaces = policy["required_surfaces"]
    assert isinstance(surfaces, dict)
    record: dict[str, object] = {
        "schema_version": 2,
        "evidence_id": "tenant-deletion-20260805",
        "evidence_kind": "production_tenant_deletion",
        "tenant_id_hash": _hash("tenant"),
        "requested_at": "2026-08-05T08:00:00Z",
        "quiesced_at": "2026-08-05T08:05:00Z",
        "completed_at": "2026-08-05T08:30:00Z",
        "product_revision": _PRODUCT_REVISION,
        "revision_contract": policy["revision_contract"],
        "request": {
            "operation_id_hash": _hash("operation"),
            "idempotency_key_hash": _hash("idempotency"),
            "authorization_decision_sha256": _hash("authorization"),
            "export_decision": "completed",
            "export_artifact_sha256": _hash("export"),
            "legal_hold": False,
            "legal_hold_decision_sha256": _hash("legal-hold"),
            "deletion_reason_code": "customer_tenant_closure",
        },
        "preconditions": dict.fromkeys(
            policy["required_preconditions"],  # type: ignore[arg-type]
            True,
        ),
        "surface_outcomes": {
            name: _outcome(name, requirement) for name, requirement in surfaces.items()
        },
        "checks": dict.fromkeys(
            policy["required_checks"],  # type: ignore[arg-type]
            True,
        ),
        "artifact": {
            "uri": "s3://deletion-evidence/report.json",
            "sha256": _hash("artifact"),
            "dsse_envelope_uri": "s3://deletion-evidence/report.dsse.json",
            **_evidence_artifact("record", _hash("artifact")),
        },
        "attestations": [],
    }
    subject_sha256 = canonical_deletion_attestation_subject_sha256(record)
    record["attestations"] = [
        {
            "role": role,
            "actor_id_hmac": _hash(f"actor-{role}"),
            "attested_at": "2026-08-05T09:30:00Z",
            "product_revision": _PRODUCT_REVISION,
            "record_subject_sha256": subject_sha256,
        }
        for role in policy["required_attestation_roles"]  # type: ignore[union-attr]
    ]
    record["record_sha256"] = canonical_deletion_record_sha256(record)
    return record


def _resign(record: dict[str, object]) -> None:
    subject_sha256 = canonical_deletion_attestation_subject_sha256(record)
    attestations = record.get("attestations")
    if isinstance(attestations, list):
        for attestation in attestations:
            if isinstance(attestation, dict):
                attestation["record_subject_sha256"] = subject_sha256
    record["record_sha256"] = canonical_deletion_record_sha256(record)


def test_empty_deletion_evidence_is_structurally_valid_but_production_blocked() -> None:
    report = validate_deletion_readiness(_repo(), _policy(), [], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["blockers"] == ["no current qualifying production tenant deletion evidence"]
    assert report["metrics"] == {
        "evidence_record_count": 0,
        "qualified_record_count": 0,
        "required_surface_count": 15,
        "violation_count": 0,
        "readiness_blocker_count": 1,
    }


def test_exact_production_tenant_deletion_satisfies_the_contract() -> None:
    report = validate_deletion_readiness(
        _repo(),
        _policy(),
        [_record()],
        now=_NOW,
        expected_product_revision=_PRODUCT_REVISION,
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["violations"] == []
    assert report["blockers"] == []


def test_deletion_record_tampering_is_a_structural_failure() -> None:
    record = _record()
    record["completed_at"] = "2026-08-05T08:31:00Z"

    report = validate_deletion_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "fail"
    assert any("record_sha256" in violation for violation in report["violations"])


def test_missing_surface_and_ci_evidence_cannot_count_as_production_proof() -> None:
    record = _record()
    record["evidence_kind"] = "ci_contract"
    record["raw_tenant_id"] = "tenant-customer-visible-id"
    record["surface_outcomes"].pop("queues_and_dlq")  # type: ignore[union-attr]
    _resign(record)

    report = validate_deletion_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "fail"
    assert any("evidence_kind" in violation for violation in report["violations"])
    assert any("record fields" in violation for violation in report["violations"])
    assert any("complete inventory" in violation for violation in report["violations"])


def test_legal_hold_identifier_retention_and_overdue_backup_block_completion() -> None:
    record = _record()
    record["request"]["legal_hold"] = True  # type: ignore[index]
    outcomes = record["surface_outcomes"]  # type: ignore[assignment]
    outcomes["logs_and_traces"]["direct_identifiers_remaining"] = True
    outcomes["backups_and_snapshots"]["purge_due_at"] = "2026-08-05T10:00:00Z"
    _resign(record)

    report = validate_deletion_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert (
        "tenant-deletion-20260805: unresolved legal hold blocks deletion completion"
        in report["blockers"]
    )
    assert (
        "tenant-deletion-20260805: surface logs_and_traces retains direct identifiers"
        in report["blockers"]
    )
    assert (
        "tenant-deletion-20260805: surface backups_and_snapshots retention deadline passed "
        "without erasure" in report["blockers"]
    )


def test_stale_or_different_release_deletion_is_rejected_for_promotion() -> None:
    record = _record()
    record["requested_at"] = "2026-04-01T08:00:00Z"
    record["quiesced_at"] = "2026-04-01T08:05:00Z"
    record["completed_at"] = "2026-04-01T08:30:00Z"
    outcomes = record["surface_outcomes"]  # type: ignore[assignment]
    outcomes["logs_and_traces"]["purge_due_at"] = "2026-04-20T08:30:00Z"
    outcomes["immutable_audit_and_ledger"]["purge_due_at"] = "2030-04-01T08:30:00Z"
    outcomes["backups_and_snapshots"] = {
        **outcomes["backups_and_snapshots"],
        "status": "erased",
        "remaining_item_count": 0,
        "direct_identifiers_remaining": False,
        "purge_due_at": None,
        "retention_basis": None,
    }
    for outcome in outcomes.values():
        outcome["artifact"]["verified_at"] = "2026-04-01T09:00:00Z"
    record["artifact"]["verified_at"] = "2026-04-01T09:00:00Z"  # type: ignore[index]
    record["attestations"] = [
        {**attestation, "attested_at": "2026-04-01T09:30:00Z"}
        for attestation in record["attestations"]  # type: ignore[union-attr]
    ]
    _resign(record)

    report = validate_deletion_readiness(
        _repo(),
        _policy(),
        [record],
        now=_NOW,
        expected_product_revision="b" * 40,
    )

    assert "tenant-deletion-20260805: deletion evidence is older than policy" in report["blockers"]
    assert (
        "tenant-deletion-20260805: product revision does not match the release candidate"
        in report["blockers"]
    )


def test_policy_drift_and_unsafe_evidence_directory_fail_closed(tmp_path: Path) -> None:
    policy = copy.deepcopy(_policy())
    policy["revision_contract"]["control_plane_schema_revision"] = "stale"  # type: ignore[index]
    policy["evidence_directory"] = "../outside"

    report = validate_deletion_readiness(_repo(), policy, [], now=_NOW)

    assert report["status"] == "fail"
    assert (
        "deletion policy revision_contract must match production baseline" in report["violations"]
    )
    assert "evidence_directory must be a safe repository-relative path" in report["violations"]

    unsafe = copy.deepcopy(_policy())
    unsafe["evidence_directory"] = str(tmp_path)
    try:
        load_deletion_evidence(_repo(), unsafe)
    except ValueError as error:
        assert "escapes the repository" in str(error)
    else:
        raise AssertionError("absolute evidence directory was not rejected")


def test_duplicate_evidence_ids_and_incomplete_attestations_fail_closed() -> None:
    first = _record()
    second = copy.deepcopy(first)
    second["attestations"] = second["attestations"][:-1]  # type: ignore[index]
    _resign(second)

    report = validate_deletion_readiness(_repo(), _policy(), [first, second], now=_NOW)

    assert report["status"] == "fail"
    assert "duplicate deletion evidence_id tenant-deletion-20260805" in report["violations"]
    assert (
        "tenant-deletion-20260805: independent attestations are incomplete" in report["blockers"]
    )


def test_uri_only_or_control_plane_completion_cannot_qualify_as_production_proof() -> None:
    record = _record()
    outcomes = record["surface_outcomes"]  # type: ignore[assignment]
    outcomes["control_plane_database"].pop("artifact")
    record["artifact"] = {
        "uri": "s3://deletion-evidence/report.json",
        "sha256": _hash("artifact"),
        "dsse_envelope_uri": "s3://deletion-evidence/report.dsse.json",
    }
    _resign(record)

    report = validate_deletion_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"
    assert report["metrics"]["qualified_record_count"] == 0
    assert any(
        "surface control_plane_database artifact proof is required" in violation
        for violation in report["violations"]
    )
    assert any("artifact fields do not match the schema" in item for item in report["violations"])


def test_surface_backup_and_global_artifact_proofs_are_fail_closed() -> None:
    record = _record()
    outcomes = record["surface_outcomes"]  # type: ignore[assignment]
    outcomes["control_plane_database"]["artifact"]["payload_sha256"] = _hash("wrong")
    outcomes["backups_and_snapshots"]["artifact"].pop("kms_receipt_sha256")
    outcomes["runtime_database"]["artifact"]["workflow_identity"] = "spiffe://untrusted/job"
    outcomes["logs_and_traces"]["artifact"]["signing_key_id"] = "untrusted-key-01"
    record["artifact"]["signing_key_purpose"] = "general-purpose"  # type: ignore[index]
    _resign(record)

    report = validate_deletion_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "fail"
    assert any("does not bind the evidence payload" in item for item in report["violations"])
    assert any("kms_receipt_sha256 must be SHA-256" in item for item in report["violations"])
    assert any("workflow identity is not trusted" in item for item in report["violations"])
    assert any("signing_key_id is not trusted" in item for item in report["violations"])
    assert any(
        "signing key purpose does not match policy" in item for item in report["violations"]
    )


def test_attestors_are_distinct_and_bind_the_same_record_and_revision() -> None:
    record = _record()
    attestations = record["attestations"]  # type: ignore[assignment]
    attestations[1]["actor_id_hmac"] = attestations[0]["actor_id_hmac"]
    attestations[1]["record_subject_sha256"] = _hash("wrong-subject")
    attestations[2]["product_revision"] = "b" * 40
    record["record_sha256"] = canonical_deletion_record_sha256(record)

    report = validate_deletion_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "fail"
    assert any("actors must be pairwise distinct" in item for item in report["violations"])
    assert any(
        "does not bind the canonical record subject" in item for item in report["violations"]
    )
    assert any(
        "attestation revision does not match evidence" in item for item in report["violations"]
    )


def test_evidence_verification_and_approval_times_are_bounded() -> None:
    record = _record()
    outcomes = record["surface_outcomes"]  # type: ignore[assignment]
    outcomes["control_plane_database"]["artifact"]["verified_at"] = "2026-08-05T08:00:00Z"
    record["artifact"]["verified_at"] = "2026-08-05T13:00:00Z"  # type: ignore[index]
    for attestation in record["attestations"]:  # type: ignore[union-attr]
        attestation["attested_at"] = "2026-08-05T09:30:00Z"
    _resign(record)

    report = validate_deletion_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "fail"
    assert any(
        "verified_at must follow completion and not be in the future" in item
        for item in report["violations"]
    )
    assert any(
        "attestation time must follow evidence verification and not be future" in item
        for item in report["violations"]
    )
