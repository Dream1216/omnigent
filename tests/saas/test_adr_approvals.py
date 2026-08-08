from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

from saas.scripts.check_adr_approvals import (
    authority_bundle_sha256,
    compute_decision_bundle,
    validate_approval_contract,
)
from saas.scripts.finalize_adr_approval import _assign_distinct_signers


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _baseline() -> dict[str, object]:
    return json.loads((_repo() / "saas/production/baseline.json").read_text(encoding="utf-8"))


def test_adr_contract_is_structurally_valid_but_human_approval_is_not_faked() -> None:
    report = validate_approval_contract(_repo(), _baseline())

    assert report["status"] == "pass"
    assert report["approval_readiness"] == "blocked"
    assert report["metrics"] == {
        "decision_file_count": 11,
        "required_signing_role_count": 4,
        "configured_authority_role_count": 0,
        "signature_count": 0,
        "technical_owner_confirmation_count": 0,
    }
    assert any("approval authorities are not active" in value for value in report["blockers"])
    assert "no immutable ADR approval record is referenced" in report["blockers"]


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


def test_approved_record_requires_authorized_exact_commit_live_reviews(tmp_path: Path) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    authorities_path = tmp_path / str(baseline["approval"]["authorities"])  # type: ignore[index]
    authorities = json.loads(authorities_path.read_text(encoding="utf-8"))
    role_logins = {
        "product-owner": "product-human",
        "platform-architecture": "architecture-human",
        "security": "security-human",
        "site-reliability": "sre-human",
        "runtime-compatibility": "runtime-human",
        "control-plane": "control-human",
        "execution-platform": "execution-human",
        "billing-platform": "billing-human",
    }
    authorities["state"] = "active"
    authorities["reviewed_at"] = "2026-08-09"
    for role, login in role_logins.items():
        authorities["roles"][role]["github_logins"] = [login]
    authorities_path.write_text(json.dumps(authorities), encoding="utf-8")
    candidate_path = tmp_path / str(baseline["approval"]["candidate"])  # type: ignore[index]
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    commit = "a" * 40

    live_reviews: list[dict[str, object]] = []
    review_id = 100

    def review_fields(role: str) -> dict[str, object]:
        nonlocal review_id
        review_id += 1
        login = role_logins[role]
        live = {
            "id": review_id,
            "user": {"login": login},
            "state": "APPROVED",
            "submitted_at": "2026-08-09T10:00:00Z",
            "commit_id": commit,
            "html_url": f"https://github.com/Dream1216/omnigent/pull/1#pullrequestreview-{review_id}",
        }
        live_reviews.append(live)
        return {
            "login": login,
            "review_id": review_id,
            "submitted_at": live["submitted_at"],
            "commit_sha": commit,
            "state": "APPROVED",
            "review_url": live["html_url"],
        }

    signing_roles = list(baseline["approval"]["required_roles"])  # type: ignore[index]
    signatures = [{"role": role, **review_fields(role)} for role in signing_roles]
    confirmations = []
    for adr in baseline["adrs"]:  # type: ignore[index]
        owner = adr["owner"]
        confirmations.append({"adr_id": adr["id"], "owner_role": owner, **review_fields(owner)})
        adr["status"] = "accepted"
    record = {
        "schema_version": 1,
        "state": "approved",
        "candidate_id": candidate["candidate_id"],
        "decision_bundle_sha256": compute_decision_bundle(tmp_path, candidate),
        "decision_registry_sha256": candidate["decision_registry_sha256"],
        "authority_bundle_sha256": authority_bundle_sha256(authorities),
        **{
            field: candidate[field]
            for field in (
                "implementation_revision",
                "evidence_revision",
                "upstream_revision",
                "adapter_contract_version",
                "control_plane_schema_revision",
                "deployment_scope",
            )
        },
        "repository": "Dream1216/omnigent",
        "pull_request": 1,
        "pull_request_url": "https://github.com/Dream1216/omnigent/pull/1",
        "pull_request_author": "pr-author",
        "reviewed_commit_sha": commit,
        "merge_commit_sha": "b" * 40,
        "merged_at": "2026-08-09T11:00:00Z",
        "generated_at": "2026-08-09T11:01:00Z",
        "signatures": signatures,
        "technical_owner_confirmations": confirmations,
    }
    record_name = f"{candidate['candidate_id']}-{record['decision_bundle_sha256'][:16]}.json"
    record_path = tmp_path / "saas/production/adr-approvals" / record_name
    record_path.write_text(json.dumps(record), encoding="utf-8")
    baseline["approval"]["state"] = "approved"  # type: ignore[index]
    baseline["approval"]["record"] = f"saas/production/adr-approvals/{record_name}"  # type: ignore[index]
    evidence = {
        "pull_request": {
            "number": 1,
            "html_url": "https://github.com/Dream1216/omnigent/pull/1",
            "merged_at": "2026-08-09T11:00:00Z",
            "merge_commit_sha": "b" * 40,
            "head": {"sha": commit},
            "user": {"login": "pr-author"},
        },
        "reviews": live_reviews,
    }

    report = validate_approval_contract(tmp_path, baseline, github_evidence=evidence)
    assert report["status"] == "pass"
    assert report["approval_readiness"] == "approved"

    live_reviews[0]["state"] = "DISMISSED"
    dismissed = validate_approval_contract(tmp_path, baseline, github_evidence=evidence)
    assert dismissed["status"] == "fail"
    assert any("state no longer matches" in value for value in dismissed["violations"])
