from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

from saas.production.readiness import (
    derive_gate_results,
    validate_candidate_revision,
    validate_consecutive_upstream_syncs,
    validate_gate_ledger,
    validate_production_readiness,
)
from tests.saas._approval_history import require_current_approval_history


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _manifest() -> dict[str, object]:
    return json.loads(
        (_repo() / "saas/acceptance/p0-p6-evidence.json").read_text(encoding="utf-8")
    )


def _report(ready: bool, blocker: str = "missing evidence") -> dict[str, object]:
    return {
        "status": "pass",
        "production_readiness": "ready" if ready else "blocked",
        "violations": [],
        "blockers": [] if ready else [blocker],
    }


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _admission_reports(ready: bool = True) -> dict[str, dict[str, object]]:
    return {
        f"{kind}_admission": _report(ready, f"{kind} admission missing")
        for kind in (
            "baseline",
            "image",
            "deployment",
            "recovery",
            "slo_capacity",
            "deletion",
            "commercial",
            "enterprise",
        )
    }


def test_current_consecutive_upstream_sync_contract_is_ready() -> None:
    report = validate_consecutive_upstream_syncs(_repo())

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["violations"] == []


def test_consecutive_upstream_sync_digest_drift_fails_closed(tmp_path: Path) -> None:
    for relative in (
        "saas/production/upstream-sync-policy.json",
        "saas/acceptance/p6-upstream-sync-ci-31011047850.json",
        "saas/acceptance/p6-upstream-sync-ci-31019511803.json",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_repo() / relative, destination)
    first = tmp_path / "saas/acceptance/p6-upstream-sync-ci-31011047850.json"
    first.write_text(first.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    report = validate_consecutive_upstream_syncs(tmp_path)

    assert report["status"] == "fail"
    assert any("digest drifted" in item for item in report["violations"])


def test_gate_derivation_requires_every_named_verifier() -> None:
    reports = {
        "candidate_revision": _report(True),
        "baseline": _report(True),
        "image": _report(True),
        "deployment": _report(True),
        "recovery": _report(True),
        "slo_capacity": _report(True),
        "deletion": _report(True),
        "commercial": _report(False, "real provider invoice missing"),
        "enterprise": _report(True),
        "upstream_sync": _report(True),
        **_admission_reports(),
    }

    gates = derive_gate_results(reports)

    assert len(gates) == 10
    assert gates["p5-production-foundation-gate"]["ready"] is True
    assert gates["p6-billing-ledger-entitlement-quota-subscription"]["ready"] is False
    assert gates["p6-two-consecutive-upstream-syncs-and-commercial-gate"]["ready"] is False
    assert any(
        "real provider invoice missing" in item
        for item in gates["p6-two-consecutive-upstream-syncs-and-commercial-gate"]["blockers"]
    )


def test_manual_pass_cannot_override_a_blocked_derived_gate() -> None:
    manifest = copy.deepcopy(_manifest())
    reports = {
        "candidate_revision": _report(True),
        "baseline": _report(False),
        "image": _report(False),
        "deployment": _report(False),
        "recovery": _report(False),
        "slo_capacity": _report(False),
        "deletion": _report(False),
        "commercial": _report(False),
        "enterprise": _report(False),
        "upstream_sync": _report(True),
        **_admission_reports(False),
    }
    phases = manifest["phases"]
    assert isinstance(phases, list)
    p0 = phases[0]
    assert isinstance(p0, dict)
    gates = p0["gates"]
    assert isinstance(gates, list)
    image_gate = next(
        gate
        for gate in gates
        if isinstance(gate, dict)
        and gate.get("id") == "p0-reproducible-official-image-and-oss-regression"
    )
    image_gate["status"] = "passed"

    violations = validate_gate_ledger(manifest, derive_gate_results(reports))

    assert (
        "aggregate gate p0-reproducible-official-image-and-oss-regression is passed "
        "without qualifying evidence"
    ) in violations


def test_current_overall_readiness_is_structurally_valid_and_no_go() -> None:
    require_current_approval_history(_repo())
    report = validate_production_readiness(_repo())

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["release_decision"] == "NO-GO"
    assert report["violations"] == []
    assert report["metrics"] == {
        "aggregate_gate_count": 10,
        "derived_ready_gate_count": 0,
        "ledger_passed_gate_count": 0,
        "structural_violation_count": 0,
    }
    assert report["verifiers"]["upstream_sync"]["production_readiness"] == "ready"
    assert report["verifiers"]["candidate_revision"]["production_readiness"] == "blocked"
    assert report["verifiers"]["deployment"]["production_readiness"] == "blocked"
    assert report["verifiers"]["baseline_admission"]["production_readiness"] == "blocked"
    assert any(
        "no active trusted production evidence admission key" in blocker
        for blocker in report["verifiers"]["baseline_admission"]["blockers"]
    )


def test_release_candidate_revision_is_an_explicit_common_gate() -> None:
    assert validate_candidate_revision(None)["production_readiness"] == "blocked"
    assert validate_candidate_revision("short")["status"] == "fail"
    assert validate_candidate_revision("a" * 40)["production_readiness"] == "ready"


def test_candidate_lineage_allows_only_committed_evidence_after_candidate(
    tmp_path: Path,
) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    source = tmp_path / "saas/runtime.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "candidate")
    candidate = _git(tmp_path, "rev-parse", "HEAD")

    evidence = tmp_path / "saas/production/deployment-evidence/drill.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "add evidence")

    assert validate_candidate_revision(candidate, tmp_path)["production_readiness"] == "ready"

    source.write_text("value = 2\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "code drift")

    report = validate_candidate_revision(candidate, tmp_path)
    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("non-evidence paths" in item for item in report["blockers"])


def test_candidate_lineage_rejects_uncommitted_evidence(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    tracked = tmp_path / "README.md"
    tracked.write_text("candidate\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "candidate")
    candidate = _git(tmp_path, "rev-parse", "HEAD")
    evidence = tmp_path / "saas/production/recovery-evidence/drill.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")

    report = validate_candidate_revision(candidate, tmp_path)

    assert report["production_readiness"] == "blocked"
    assert any("clean repository" in item for item in report["blockers"])


def test_candidate_lineage_rejects_trust_registry_changes(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    registry = tmp_path / "saas/production/evidence-admission-keys.json"
    registry.parent.mkdir(parents=True)
    registry.write_text('{"keys": []}\n', encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "candidate")
    candidate = _git(tmp_path, "rev-parse", "HEAD")
    registry.write_text('{"keys": [{"key_id": "unreviewed"}]}\n', encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "replace trust root")

    report = validate_candidate_revision(candidate, tmp_path)

    assert report["production_readiness"] == "blocked"
    assert any("non-evidence paths" in item for item in report["blockers"])
