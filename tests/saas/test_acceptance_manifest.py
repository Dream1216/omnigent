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


def test_current_adr_gate_waits_for_successor_ci_after_current_bundle_approval() -> None:
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
    prior_approval_path = (
        "saas/production/adr-approvals/"
        "omnigent-saas-upstream-sync-3369b36c-2026-08-31-2500a820699ccb24.json"
    )
    approval_path = (
        "saas/production/adr-approvals/"
        "omnigent-saas-p0s11-production-runtime-2026-09-02-42167426f3706279.json"
    )
    evidence_path = "saas/acceptance/p0-adr-approval-evidence-ci-33468247922.json"

    baseline = json.loads((repo / "saas/production/baseline.json").read_text(encoding="utf-8"))

    assert gate["status"] == "pending"
    assert baseline["approval"]["state"] == "approved"
    assert baseline["approval"]["approved_control_plane_schema_revision"] == ("p0s000000011")
    assert baseline["approval"]["record"] == approval_path
    assert prior_approval_path in gate["evidence"]
    assert approval_path in gate["evidence"]
    assert evidence_path in gate["evidence"]

    evidence = json.loads((repo / evidence_path).read_text(encoding="utf-8"))
    assert evidence["source_revision"] == ("e6172495448f8c1c70ee433aac10d9d8d0fbc7b6")
    assert evidence["source_tree"] == evidence["tested_pull_request_merge_tree"]
    assert evidence["github_actions"]["workflow_sha256"] == (
        "9877b3f78ca924f09d4b605002c1218be62c37746e56921168c381f067ff720e"
    )
    assert evidence["github_actions"]["exact_source_push"]["run_id"] == 33468201793
    assert evidence["github_actions"]["exact_source_push"]["conclusion"] == "success"
    assert evidence["github_actions"]["exact_source_push"]["artifact"] == {
        "id": 9785864359,
        "name": "upstream-delta-report",
        "archive_sha256": ("aeea57427485c99b073f834231fd3fe3ba85c1c21d40f28168607da655fab7df"),
    }
    assert evidence["github_actions"]["run_id"] == 33468247922
    assert evidence["github_actions"]["job_id"] == 99732483988
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
        "id": 9785898142,
        "name": "upstream-delta-report",
        "display_size": "13.2 KB",
        "archive_sha256": ("daf74fe80dbcb33211d122e091fc28418d22ad1e53936210a09663f454f9079c"),
    }
    assert evidence["adr_approval"]["approval_record"] == prior_approval_path
    assert evidence["acceptance_ledger"] == {
        "closed_gate": "p0-approved-production-adrs-and-owners",
        "passed_gate_count_before": 40,
        "passed_gate_count_after": 41,
        "pending_gate_count_after": 10,
        "p0_status": "in_progress",
        "release_decision": "NO-GO",
    }
    assert (
        hashlib.sha256((repo / prior_approval_path).read_bytes()).hexdigest()
        == (evidence["adr_approval"]["approval_record_sha256"])
    )
