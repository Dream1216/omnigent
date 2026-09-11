from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saas.scripts.check_acceptance_manifest import validate_manifest


def test_current_acceptance_manifest_is_consistent_and_no_go() -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (repo / "saas/acceptance/p0-p6-evidence.json").read_text(encoding="utf-8")
    )

    assert validate_manifest(repo, manifest) == []
    assert manifest["release_decision"] == "NO-GO"
    assert [phase["status"] for phase in manifest["phases"]] == [
        "in_progress",
        "complete",
        "complete",
        "complete",
        "in_progress",
        "in_progress",
        "in_progress",
    ]


def test_acceptance_manifest_rejects_premature_go() -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (repo / "saas/acceptance/p0-p6-evidence.json").read_text(encoding="utf-8")
    )
    manifest["release_decision"] = "GO"

    assert "release_decision cannot be GO before every phase is complete" in validate_manifest(
        repo, manifest
    )


def test_acceptance_manifest_rejects_stale_adr_approval_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (repo / "saas/acceptance/p0-p6-evidence.json").read_text(encoding="utf-8")
    )
    gate = next(
        gate
        for phase in manifest["phases"]
        for gate in phase["gates"]
        if gate["id"] == "p0-approved-production-adrs-and-owners"
    )
    gate["status"] = "passed"
    monkeypatch.setattr(
        "saas.scripts.check_acceptance_manifest._adr_bundle_is_approved",
        lambda _repo: False,
    )

    assert (
        "p0-approved-production-adrs-and-owners cannot pass before the current ADR "
        "bundle is approved"
    ) in validate_manifest(repo, manifest)


def test_current_adr_gate_reopens_for_exact_upstream_sync_candidate() -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (repo / "saas/acceptance/p0-p6-evidence.json").read_text(encoding="utf-8")
    )
    gate = next(
        gate
        for phase in manifest["phases"]
        for gate in phase["gates"]
        if gate["id"] == "p0-approved-production-adrs-and-owners"
    )
    approval_path = (
        "saas/production/adr-approvals/"
        "omnigent-saas-p0s12-platform-smtp-2026-09-05-8457cc9758444570.json"
    )
    baseline = json.loads((repo / "saas/production/baseline.json").read_text(encoding="utf-8"))
    candidate = json.loads(
        (repo / "saas/production/adr-approval-candidate.json").read_text(encoding="utf-8")
    )

    assert gate["status"] == "pending"
    assert baseline["approval"]["state"] == "review_required"
    assert baseline["approval"]["approved_control_plane_schema_revision"] == ("p0s000000012")
    assert baseline["approval"]["record"] is None
    assert all(adr["status"] == "proposed" for adr in baseline["adrs"])
    assert candidate["upstream_revision"] == ("06c33aeae701d521a3cfacd2daf99441b6d64492")
    assert candidate["implementation_revision"] == ("e68d77142db8767e2c75297237082a328ca140d7")
    assert candidate["evidence_revision"] == candidate["implementation_revision"]

    # The previous approval remains immutable historical evidence, but cannot
    # authorize a candidate whose upstream and implementation revisions changed.
    assert approval_path in gate["evidence"]
    historical_evidence_path = "saas/acceptance/p0-adr-approval-evidence-ci-33975479868.json"
    assert historical_evidence_path in gate["evidence"]
    historical_evidence = json.loads((repo / historical_evidence_path).read_text(encoding="utf-8"))
    assert (
        hashlib.sha256((repo / approval_path).read_bytes()).hexdigest()
        == (historical_evidence["adr_approval"]["approval_record_sha256"])
    )
