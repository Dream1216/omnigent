from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saas.production.admission import (
    admission_signature_payload,
    validate_evidence_admission,
)

_KINDS = (
    "baseline",
    "image",
    "deployment",
    "recovery",
    "slo_capacity",
    "deletion",
    "commercial",
    "enterprise",
)
_REVISION = "a" * 40
_NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _fixture(tmp_path: Path) -> tuple[dict[str, object], Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    sources: list[dict[str, object]] = []
    evidence_paths: dict[str, Path] = {}
    for kind in _KINDS:
        if kind in {"baseline", "image"}:
            relative = Path("evidence") / f"{kind}.json"
            sources.append(
                {
                    "kind": kind,
                    "path": relative.as_posix(),
                    "directory": None,
                    "pattern": None,
                }
            )
        else:
            directory = Path("evidence") / kind
            relative = directory / "record.json"
            sources.append(
                {
                    "kind": kind,
                    "path": None,
                    "directory": directory.as_posix(),
                    "pattern": "*.json",
                }
            )
        _write_json(tmp_path / relative, {"evidence_kind": kind, "value": 1})
        evidence_paths[kind] = relative
    policy: dict[str, object] = {
        "schema_version": 1,
        "policy_id": "test-production-evidence-admission",
        "reviewed_at": "2026-08-09",
        "payload_type": "application/vnd.omnigent.production-evidence-admission.v1+json",
        "signature_algorithm": "ed25519",
        "maximum_receipt_age_days": 31,
        "trusted_key_registry": "admission/keys.json",
        "receipt_directory": "admission/receipts",
        "evidence_sources": sources,
    }
    _write_json(
        tmp_path / "admission/keys.json",
        {
            "schema_version": 1,
            "keys": [
                {
                    "key_id": "production-admission-2026-01",
                    "algorithm": "ed25519",
                    "purpose": "production-evidence-admission",
                    "workflow_identity": "spiffe://omnigent/production-evidence-admission",
                    "public_key_pem": public_pem,
                    "not_before": "2026-08-01T00:00:00Z",
                    "not_after": "2026-09-01T00:00:00Z",
                    "revoked_at": None,
                }
            ],
        },
    )
    (tmp_path / "admission/receipts").mkdir(parents=True)
    for kind, relative in evidence_paths.items():
        digest = hashlib.sha256((tmp_path / relative).read_bytes()).hexdigest()
        receipt: dict[str, object] = {
            "schema_version": 1,
            "receipt_id": f"receipt-{kind}",
            "evidence_kind": kind,
            "evidence_path": relative.as_posix(),
            "evidence_sha256": digest,
            "product_revision": _REVISION,
            "workflow_identity": "spiffe://omnigent/production-evidence-admission",
            "issued_at": "2026-08-09T11:00:00Z",
            "expires_at": "2026-08-10T11:00:00Z",
            "signer_key_id": "production-admission-2026-01",
            "payload_type": policy["payload_type"],
            "signature": "",
        }
        receipt["signature"] = base64.b64encode(
            private_key.sign(admission_signature_payload(receipt))
        ).decode("ascii")
        _write_json(tmp_path / f"admission/receipts/{kind}.json", receipt)
    return policy, private_key


def test_current_bootstrap_policy_is_structurally_valid_and_fail_closed() -> None:
    policy = json.loads(
        (_repo() / "saas/production/evidence-admission-policy.json").read_text(encoding="utf-8")
    )

    report = validate_evidence_admission(_repo(), policy, now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["violations"] == []
    assert report["metrics"]["active_trusted_key_count"] == 0
    assert report["metrics"]["ready_kind_count"] == 0
    assert report["kinds"]["baseline"]["evidence_document_count"] == 1
    assert any(
        "no active trusted production evidence admission key" in blocker
        for blocker in report["kinds"]["baseline"]["blockers"]
    )


def test_valid_ed25519_receipts_admit_exact_evidence_bytes(tmp_path: Path) -> None:
    policy, _ = _fixture(tmp_path)

    report = validate_evidence_admission(
        tmp_path,
        policy,
        expected_product_revision=_REVISION,
        now=_NOW,
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["metrics"] == {
        "required_kind_count": 8,
        "ready_kind_count": 8,
        "evidence_document_count": 8,
        "admitted_document_count": 8,
        "active_trusted_key_count": 1,
        "receipt_count": 8,
    }


def test_evidence_byte_tampering_invalidates_admission(tmp_path: Path) -> None:
    policy, _ = _fixture(tmp_path)
    path = tmp_path / "evidence/baseline.json"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    report = validate_evidence_admission(tmp_path, policy, now=_NOW)

    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"
    assert any("admitted evidence bytes have changed" in item for item in report["violations"])
    assert report["kinds"]["baseline"]["admitted_document_count"] == 0


def test_workflow_identity_and_signature_cannot_be_relabelled(tmp_path: Path) -> None:
    policy, _ = _fixture(tmp_path)
    path = tmp_path / "admission/receipts/deployment.json"
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["workflow_identity"] = "spiffe://attacker/forged-workflow"
    _write_json(path, receipt)

    report = validate_evidence_admission(tmp_path, policy, now=_NOW)

    assert report["status"] == "fail"
    assert any(
        "workflow identity does not match signer key" in item for item in report["violations"]
    )
    assert any("admission signature is invalid" in item for item in report["violations"])


def test_expired_receipts_block_without_reclassifying_policy_as_invalid(
    tmp_path: Path,
) -> None:
    policy, _ = _fixture(tmp_path)

    report = validate_evidence_admission(
        tmp_path,
        policy,
        now=datetime(2026, 8, 11, 12, 0, tzinfo=UTC),
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["violations"] == []
    assert any("admission receipt is expired" in item for item in report["blockers"])


def test_receipt_for_undeclared_path_fails_closed(tmp_path: Path) -> None:
    policy, private_key = _fixture(tmp_path)
    path = tmp_path / "admission/receipts/commercial.json"
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["evidence_path"] = "evidence/enterprise/record.json"
    receipt["signature"] = base64.b64encode(
        private_key.sign(admission_signature_payload(receipt))
    ).decode("ascii")
    _write_json(path, receipt)

    report = validate_evidence_admission(tmp_path, policy, now=_NOW)

    assert report["status"] == "fail"
    assert any(
        "evidence_path is not declared for commercial" in item for item in report["violations"]
    )


def test_receipt_signature_cannot_be_reused_for_another_revision(tmp_path: Path) -> None:
    policy, _ = _fixture(tmp_path)
    path = tmp_path / "admission/receipts/image.json"
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["product_revision"] = "b" * 40
    _write_json(path, receipt)

    report = validate_evidence_admission(
        tmp_path,
        policy,
        expected_product_revision="b" * 40,
        now=_NOW,
    )

    assert report["status"] == "fail"
    assert any("admission signature is invalid" in item for item in report["violations"])


def test_exact_candidate_revision_mismatch_blocks_valid_receipt(tmp_path: Path) -> None:
    policy, _ = _fixture(tmp_path)

    report = validate_evidence_admission(
        tmp_path,
        policy,
        expected_product_revision="b" * 40,
        now=_NOW,
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any(
        "product revision does not match the release candidate" in item
        for item in report["blockers"]
    )


def test_receipt_must_be_issued_during_signer_key_validity(tmp_path: Path) -> None:
    policy, private_key = _fixture(tmp_path)
    path = tmp_path / "admission/receipts/recovery.json"
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["issued_at"] = "2026-07-31T23:00:00Z"
    receipt["expires_at"] = "2026-08-01T23:00:00Z"
    receipt["signature"] = base64.b64encode(
        private_key.sign(admission_signature_payload(receipt))
    ).decode("ascii")
    _write_json(path, receipt)

    report = validate_evidence_admission(
        tmp_path,
        policy,
        now=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
    )

    assert report["status"] == "fail"
    assert any(
        "receipt was issued outside signer key validity" in item for item in report["violations"]
    )


def test_revoked_key_cannot_admit_receipts(tmp_path: Path) -> None:
    policy, _ = _fixture(tmp_path)
    key_path = tmp_path / "admission/keys.json"
    registry = json.loads(key_path.read_text(encoding="utf-8"))
    registry["keys"][0]["revoked_at"] = "2026-08-09T11:30:00Z"
    _write_json(key_path, registry)

    report = validate_evidence_admission(tmp_path, policy, now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["metrics"]["active_trusted_key_count"] == 0
    assert any("trusted admission key is not active" in item for item in report["blockers"])


def test_duplicate_receipt_id_and_evidence_claim_fail_closed(tmp_path: Path) -> None:
    policy, private_key = _fixture(tmp_path)
    source = tmp_path / "admission/receipts/baseline.json"
    receipt = json.loads(source.read_text(encoding="utf-8"))
    duplicate = copy.deepcopy(receipt)
    duplicate["signature"] = base64.b64encode(
        private_key.sign(admission_signature_payload(duplicate))
    ).decode("ascii")
    _write_json(tmp_path / "admission/receipts/baseline-duplicate.json", duplicate)

    report = validate_evidence_admission(tmp_path, policy, now=_NOW)

    assert report["status"] == "fail"
    assert any("duplicate admission receipt_id" in item for item in report["violations"])
    assert any("duplicate admission receipt claim" in item for item in report["violations"])


def test_symlinked_receipt_directory_is_rejected(tmp_path: Path) -> None:
    policy, _ = _fixture(tmp_path)
    policy["receipt_directory"] = "admission/receipts-link"
    (tmp_path / "admission/receipts-link").symlink_to(
        tmp_path / "admission/receipts",
        target_is_directory=True,
    )

    report = validate_evidence_admission(tmp_path, policy, now=_NOW)

    assert report["status"] == "fail"
    assert any(
        "receipt_directory must be a regular directory" in item for item in report["violations"]
    )
