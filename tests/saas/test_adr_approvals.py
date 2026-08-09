from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

from saas.scripts.check_adr_approvals import (
    compute_decision_bundle,
    validate_approval_contract,
)
from saas.scripts.finalize_adr_approval import _assign_distinct_signers, build_record


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _baseline() -> dict[str, object]:
    return json.loads((_repo() / "saas/production/baseline.json").read_text(encoding="utf-8"))


def test_current_adr_contract_is_approved_by_explicit_degraded_waiver() -> None:
    report = validate_approval_contract(_repo(), _baseline())

    assert report["status"] == "pass"
    assert report["approval_readiness"] == "approved"
    assert report["metrics"] == {
        "approval_mode": "sole-owner-risk-waiver",
        "governance_classification": "degraded",
        "decision_file_count": 11,
        "required_signing_role_count": 4,
        "configured_authority_role_count": 8,
        "signature_count": 1,
        "technical_owner_confirmation_count": 11,
    }
    assert report["blockers"] == []


def test_approved_architecture_schema_is_separate_from_current_implementation_head() -> None:
    baseline = _baseline()

    assert baseline["approval"]["approved_control_plane_schema_revision"] == "pc5a00000003"  # type: ignore[index]
    assert baseline["revision_contract"]["control_plane_schema_revision"] == "pc5b00000001"  # type: ignore[index]
    assert validate_approval_contract(_repo(), baseline)["status"] == "pass"


def test_decision_bundle_detects_document_tampering(tmp_path: Path) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    candidate_path = tmp_path / "saas/production/adr-approval-candidate.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    before = compute_decision_bundle(tmp_path, candidate)
    adr = tmp_path / candidate["decision_files"][0]
    adr.write_text(adr.read_text(encoding="utf-8") + "\nmaterial change\n", encoding="utf-8")

    assert compute_decision_bundle(tmp_path, candidate) != before


def test_distinct_signer_assignment_rejects_one_human_for_four_roles() -> None:
    roles = ["product-owner", "platform-architecture", "security", "site-reliability"]
    authorities = {role: {"same-human"} for role in roles}
    reviews = {"same-human": {"state": "APPROVED"}}

    assert _assign_distinct_signers(roles, authorities, reviews, "pr-author") is None


def test_standard_four_party_mode_remains_available(tmp_path: Path) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    baseline["approval"]["state"] = "review_required"  # type: ignore[index]
    baseline["approval"]["record"] = None  # type: ignore[index]
    baseline["approval"]["mode"] = "four-party-github-reviews"  # type: ignore[index]
    baseline["approval"]["governance_classification"] = "independent"  # type: ignore[index]
    for adr in baseline["adrs"]:  # type: ignore[index]
        adr["status"] = "proposed"
    policy_path = tmp_path / str(baseline["approval"]["policy"])  # type: ignore[index]
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["active_mode"] = "four-party-github-reviews"
    policy["governance_classification"] = "independent"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    authorities_path = tmp_path / str(baseline["approval"]["authorities"])  # type: ignore[index]
    authorities = json.loads(authorities_path.read_text(encoding="utf-8"))
    authorities["governance_mode"] = "four-party-github-reviews"
    authorities["governance_classification"] = "independent"
    for index, (role, value) in enumerate(authorities["roles"].items(), start=1):
        value["github_logins"] = [f"owner-{index}"]
    authorities_path.write_text(json.dumps(authorities), encoding="utf-8")

    report = validate_approval_contract(tmp_path, baseline)

    assert report["status"] == "pass"
    assert report["approval_readiness"] == "blocked"
    assert report["metrics"]["configured_authority_role_count"] == 8
    assert report["blockers"] == ["no immutable ADR approval record is referenced"]


def test_approved_waiver_requires_exact_owner_identity_merge_and_ci(tmp_path: Path) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    candidate_path = tmp_path / str(baseline["approval"]["candidate"])  # type: ignore[index]
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    commit = "a" * 40
    evidence = {
        "pull_request": {
            "number": 1,
            "html_url": "https://github.com/Dream1216/omnigent/pull/1",
            "merged_at": "2026-08-09T11:00:00Z",
            "merge_commit_sha": "b" * 40,
            "head": {"sha": commit},
            "user": {"login": "Dream1216"},
            "merged_by": {"login": "Dream1216"},
        },
        "reviews": [],
        "waiver_actor": {"login": "Dream1216", "id": 39821512, "type": "User"},
        "waiver_actor_permission": {"permission": "admin"},
        "check_runs": [
            {
                "id": 500,
                "name": "compatibility-gate",
                "head_sha": commit,
                "status": "completed",
                "conclusion": "success",
                "html_url": "https://github.com/Dream1216/omnigent/actions/runs/1/job/500",
            }
        ],
    }
    record = build_record(tmp_path, baseline, evidence)
    record_name = f"{candidate['candidate_id']}-{record['decision_bundle_sha256'][:16]}.json"
    record_path = tmp_path / "saas/production/adr-approvals" / record_name
    record_path.write_text(json.dumps(record), encoding="utf-8")
    for adr in baseline["adrs"]:  # type: ignore[index]
        adr["status"] = "accepted"
    baseline["approval"]["state"] = "approved"  # type: ignore[index]
    baseline["approval"]["record"] = f"saas/production/adr-approvals/{record_name}"  # type: ignore[index]

    report = validate_approval_contract(tmp_path, baseline, github_evidence=evidence)
    assert report["status"] == "pass"
    assert report["approval_readiness"] == "approved"

    evidence["waiver_actor_permission"] = {"permission": "write"}
    downgraded = validate_approval_contract(tmp_path, baseline, github_evidence=evidence)
    assert downgraded["status"] == "fail"
    assert "live sole-owner repository permission is not admin" in downgraded["violations"]
