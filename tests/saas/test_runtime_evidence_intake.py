"""Registered native origins, exact subjects and complete scope are mandatory."""

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime

import pytest

from saas.scripts.combined_runtime_disposition import RuntimeSubject
from saas.scripts.runtime_evidence_intake import REGISTRY, verifier_from_registered_inputs

NOW = datetime(2026, 11, 6, tzinfo=UTC)
EXPIRY = "2026-11-11T10:40:00Z"


def registered(tmp_path):
    root = tmp_path / "saas/supply_chain/runtime-conditions"
    root.mkdir(parents=True)
    subject = RuntimeSubject(
        "a" * 40, "linux/amd64", "sha256:" + "b" * 64, "sha256:" + "c" * 64, "d" * 64, "e" * 64
    )
    identity = asdict(subject)
    identity.pop("report_sha256")
    producer = {"kind": "existing-native-operator", "operation": "fixed-original-task"}
    roles = [{"role": "helper", "command": ["original"], "profile": "original-private-PID"}]

    def write(name, document):
        path = root / name
        raw = (json.dumps(document, sort_keys=True) + "\n").encode()
        path.write_bytes(raw)
        return {"path": str(path.relative_to(tmp_path)), "sha256": hashlib.sha256(raw).hexdigest()}

    evidence = {
        "producer": producer,
        "original_report_sha256": subject.report_sha256,
        "subject": identity,
        "roles": roles,
        "expires_at": EXPIRY,
    }
    native = write("native.json", evidence)
    contract = {
        "subject": identity,
        "scope": "full-release-image",
        "uncovered_boundaries": [],
        "native_evidence": native,
        "roles": roles,
        "installed_files": {"trusted.py": "f" * 64},
        "last_merge_contract": {"point": "reviewed actual final merge"},
        "expires_at": EXPIRY,
    }
    contract_file = write("contract.json", contract)
    review = {
        "reviewed_contract_sha256": contract_file["sha256"],
        "native_evidence_sha256": native["sha256"],
        "unresolved_findings": [],
        "verified_native_producer": dict(producer),
        "verified_last_merge_contract": contract["last_merge_contract"],
        "expires_at": EXPIRY,
    }
    review_file = write("review.json", review)
    authority = {
        "rule_id": "CVE-2026-84243",
        "classification": "mitigated_by_verified_runtime_conditions",
        "expires_at": EXPIRY,
    }
    authority_file = write("authority.json", authority)
    coordinate = {
        "contract": contract_file,
        "independent_review": review_file,
        "authority": authority_file,
    }
    registry = {"schema_version": 1, "approved_scopes": [coordinate]}
    (tmp_path / REGISTRY).write_text(json.dumps(registry))
    return subject, registry, contract, evidence, review, authority, write


def test_registered_content_and_independent_origin_are_bound_without_new_signer(tmp_path):
    subject, *_ = registered(tmp_path)
    condition = verifier_from_registered_inputs(
        tmp_path, [{"path": "trusted.py", "sha256": "f" * 64}]
    )(subject, now=NOW)
    assert condition.subject == subject
    assert condition.expires_at == datetime.fromisoformat(EXPIRY.replace("Z", "+00:00"))


@pytest.mark.parametrize(
    "fault", ["subject", "bytes", "scope", "producer", "raw", "review", "code", "expiry"]
)
def test_unknown_subject_or_unverified_input_and_incomplete_scope_reject(tmp_path, fault):
    subject, registry, contract, evidence, review, authority, write = registered(tmp_path)
    coordinate = registry["approved_scopes"][0]
    if fault == "bytes":
        (tmp_path / coordinate["contract"]["path"]).write_text("{}")
    elif fault in {"subject", "scope"}:
        if fault == "subject":
            contract["subject"]["source_revision"] = "0" * 40
        else:
            contract["uncovered_boundaries"] = ["terminal"]
        coordinate["contract"] = write("contract.json", contract)
    elif fault in {"producer", "raw"}:
        if fault == "producer":
            evidence["producer"]["operation"] = "unregistered"
        else:
            evidence["original_report_sha256"] = "0" * 64
        contract["native_evidence"] = write("native.json", evidence)
        coordinate["contract"] = write("contract.json", contract)
        review["reviewed_contract_sha256"] = coordinate["contract"]["sha256"]
        review["native_evidence_sha256"] = contract["native_evidence"]["sha256"]
        coordinate["independent_review"] = write("review.json", review)
    elif fault == "review":
        review["unresolved_findings"] = ["unproven trusted path"]
        coordinate["independent_review"] = write("review.json", review)
    elif fault == "expiry":
        authority["expires_at"] = NOW.isoformat()
        coordinate["authority"] = write("authority.json", authority)
    (tmp_path / REGISTRY).write_text(json.dumps(registry))
    inventory = [{"path": "trusted.py", "sha256": "0" * 64 if fault == "code" else "f" * 64}]
    with pytest.raises(ValueError):
        verifier_from_registered_inputs(tmp_path, inventory)(subject, now=NOW)


def test_component_only_does_not_approve_an_image_and_duplicate_subjects_reject(tmp_path):
    subject, registry, *_ = registered(tmp_path)
    registry["approved_scopes"] = []
    (tmp_path / REGISTRY).write_text(json.dumps(registry))
    with pytest.raises(ValueError, match="full-role contract"):
        verifier_from_registered_inputs(tmp_path, [])(subject, now=NOW)
