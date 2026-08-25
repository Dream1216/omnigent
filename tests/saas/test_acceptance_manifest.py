from __future__ import annotations

import json
from pathlib import Path

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


def test_acceptance_manifest_rejects_stale_adr_approval_status() -> None:
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

    assert (
        "p0-approved-production-adrs-and-owners cannot pass before the current ADR "
        "bundle is approved"
    ) in validate_manifest(repo, manifest)
