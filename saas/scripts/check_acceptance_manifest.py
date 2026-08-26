"""Validate the P0-P6 progress ledger and its repository evidence paths."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_PHASES = tuple(f"P{index}" for index in range(7))
_PHASE_STATUSES = {"not_started", "in_progress", "complete"}
_GATE_STATUSES = {"pending", "passed"}
_ADR_APPROVAL_GATE = "p0-approved-production-adrs-and-owners"


def _adr_bundle_is_approved(repo: Path) -> bool:
    baseline_path = repo / "saas/production/baseline.json"
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(baseline, dict):
        return False
    approval = baseline.get("approval")
    adrs = baseline.get("adrs")
    return (
        isinstance(approval, dict)
        and approval.get("state") == "approved"
        and isinstance(adrs, list)
        and len(adrs) == 11
        and all(isinstance(adr, dict) and adr.get("status") == "accepted" for adr in adrs)
    )


def validate_manifest(repo: Path, manifest: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    phases = manifest.get("phases")
    if not isinstance(phases, list):
        return ["phases must be a list"]
    phase_ids = tuple(phase.get("id") for phase in phases if isinstance(phase, dict))
    if phase_ids != _PHASES:
        violations.append(f"phase order must be {_PHASES}")

    all_complete = True
    for phase in phases:
        if not isinstance(phase, dict):
            violations.append("phase entries must be objects")
            all_complete = False
            continue
        phase_id = phase.get("id")
        status = phase.get("status")
        if status not in _PHASE_STATUSES:
            violations.append(f"{phase_id} has invalid status {status}")
        all_complete = all_complete and status == "complete"
        gates = phase.get("gates")
        if not isinstance(gates, list) or not gates:
            violations.append(f"{phase_id} must declare at least one gate")
            continue
        gate_ids: set[str] = set()
        pending = False
        for gate in gates:
            if not isinstance(gate, dict):
                violations.append(f"{phase_id} contains a non-object gate")
                pending = True
                continue
            gate_id = gate.get("id")
            if not isinstance(gate_id, str) or not gate_id:
                violations.append(f"{phase_id} contains a gate without an id")
                continue
            if gate_id in gate_ids:
                violations.append(f"{phase_id} repeats gate {gate_id}")
            gate_ids.add(gate_id)
            gate_status = gate.get("status")
            if gate_status not in _GATE_STATUSES:
                violations.append(f"{gate_id} has invalid status {gate_status}")
            if (
                gate_id == _ADR_APPROVAL_GATE
                and gate_status == "passed"
                and not _adr_bundle_is_approved(repo)
            ):
                violations.append(
                    f"{gate_id} cannot pass before the current ADR bundle is approved"
                )
            pending = pending or gate_status != "passed"
            evidence = gate.get("evidence")
            if not isinstance(evidence, list):
                violations.append(f"{gate_id} evidence must be a list")
                continue
            if gate_status == "passed" and not evidence:
                violations.append(f"passed gate {gate_id} has no evidence")
            for evidence_path in evidence:
                if not isinstance(evidence_path, str) or not (repo / evidence_path).is_file():
                    violations.append(f"{gate_id} references missing evidence {evidence_path}")
        if status == "complete" and pending:
            violations.append(f"{phase_id} is complete while gates remain pending")
        if status == "not_started" and not pending:
            violations.append(f"{phase_id} is not_started but all gates passed")

    decision = manifest.get("release_decision")
    if decision not in {"GO", "NO-GO"}:
        violations.append("release_decision must be GO or NO-GO")
    if decision == "GO" and not all_complete:
        violations.append("release_decision cannot be GO before every phase is complete")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default="saas/acceptance/p0-p6-evidence.json",
        help="acceptance manifest path",
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads((repo / args.manifest).read_text(encoding="utf-8"))
    violations = validate_manifest(repo, manifest)
    if violations:
        print(json.dumps({"status": "fail", "violations": violations}, indent=2))
        return 1
    pending = [
        gate["id"]
        for phase in manifest["phases"]
        for gate in phase["gates"]
        if gate["status"] != "passed"
    ]
    print(
        json.dumps(
            {
                "status": "pass",
                "release_decision": manifest["release_decision"],
                "pending_gate_count": len(pending),
                "pending_gates": pending,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
