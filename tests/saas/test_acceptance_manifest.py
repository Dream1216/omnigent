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


def test_current_adr_gate_is_closed_by_exact_p0s12_successor_ci() -> None:
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
    evidence_path = "saas/acceptance/p0-adr-approval-evidence-ci-33975479868.json"

    baseline = json.loads((repo / "saas/production/baseline.json").read_text(encoding="utf-8"))

    assert gate["status"] == "passed"
    assert baseline["approval"]["state"] == "approved"
    assert baseline["approval"]["approved_control_plane_schema_revision"] == ("p0s000000012")
    assert baseline["approval"]["record"] == approval_path
    assert approval_path in gate["evidence"]
    assert evidence_path in gate["evidence"]

    evidence = json.loads((repo / evidence_path).read_text(encoding="utf-8"))
    assert evidence["source_revision"] == ("249c34c1e1dd10cc463e976e0422cebf8ea7afea")
    assert evidence["source_tree"] == evidence["tested_pull_request_merge_tree"]
    assert evidence["github_actions"]["workflow_sha256"] == (
        "e16f3107bb8759a97f8ed7a168cfa864bd08e4dce892b32ca5161cbf305b51d4"
    )
    assert evidence["github_actions"]["exact_source_push"]["run_id"] == 33975451216
    assert evidence["github_actions"]["exact_source_push"]["conclusion"] == "success"
    assert evidence["github_actions"]["exact_source_push"]["artifact"] == {
        "id": 9972414339,
        "name": "upstream-delta-report",
        "size_in_bytes": 14881,
        "archive_sha256": ("2e680be3001288af59f42f25786e6cfc59cd1ba3d526917bc6c2ed475a8e8167"),
    }
    assert evidence["github_actions"]["run_id"] == 33975479868
    assert evidence["github_actions"]["job_id"] == 101331305838
    assert evidence["github_actions"]["conclusion"] == "success"
    assert evidence["github_actions"]["pull_request_head_sha"] == (evidence["source_revision"])
    assert (
        evidence["github_actions"]["temporary_merge_revision"]
        == (evidence["tested_pull_request_merge_revision"])
    )
    assert evidence["github_actions"]["temporary_merge_tree"] == (evidence["source_tree"])
    assert evidence["github_actions"]["temporary_merge_parents"] == [
        evidence["base_revision"],
        evidence["source_revision"],
    ]
    assert evidence["github_actions"]["artifact"] == {
        "id": 9972495008,
        "name": "upstream-delta-report",
        "size_in_bytes": 14880,
        "archive_sha256": ("e4a460c6a58796be276b5b5688b813a80831f4426bb22e2b984e33afe2cd7b11"),
    }
    assert evidence["adr_approval"]["approval_record"] == approval_path
    assert evidence["additional_exact_head_gates"] == {
        "n1_push": {"run_id": 33975451264, "conclusion": "success"},
        "n1_pull_request": {"run_id": 33975479899, "conclusion": "success"},
        "ci_regression": {
            "run_id": 33975480019,
            "run_attempt": 2,
            "conclusion": "success",
            "note": (
                "The failed misc timing test from attempt 1 passed without a source "
                "change in attempt 2."
            ),
        },
    }
    assert evidence["acceptance_ledger"] == {
        "closed_gate": "p0-approved-production-adrs-and-owners",
        "passed_gate_count_before": 40,
        "passed_gate_count_after": 41,
        "pending_gate_count_after": 10,
        "p0_status": "in_progress",
        "release_decision": "NO-GO",
    }
    assert (
        hashlib.sha256((repo / approval_path).read_bytes()).hexdigest()
        == (evidence["adr_approval"]["approval_record_sha256"])
    )
