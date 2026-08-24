from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from saas.scripts.check_adr_approvals import (
    _validate_append_only_history,
    compute_decision_bundle,
    validate_approval_contract,
)
from saas.scripts.finalize_adr_approval import _assign_distinct_signers, build_record
from tests.saas._approval_history import require_current_approval_history


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _baseline() -> dict[str, object]:
    return json.loads((_repo() / "saas/production/baseline.json").read_text(encoding="utf-8"))


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _refresh_candidate_digest(repo: Path) -> None:
    candidate_path = repo / "saas/production/adr-approval-candidate.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate["decision_bundle_sha256"] = compute_decision_bundle(repo, candidate)
    candidate_path.write_text(
        json.dumps(candidate, indent=2) + "\n",
        encoding="utf-8",
    )


def _commit_decision_tree(repo: Path) -> tuple[str, str]:
    baseline_path = repo / "saas/production/baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    approval = baseline["approval"]
    active_record = approval.pop("record", None)
    approval["state"] = "review_required"
    for adr in baseline["adrs"]:
        adr["status"] = "proposed"
    baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    if isinstance(active_record, str):
        (repo / active_record).unlink(missing_ok=True)
    _refresh_candidate_digest(repo)
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "adr-test@example.test")
    _git(repo, "config", "user.name", "ADR Test")
    _git(repo, "commit", "--allow-empty", "-m", "base")
    _git(repo, "switch", "-c", "decision")
    _git(repo, "add", "saas/production")
    _git(repo, "commit", "-m", "decision tree")
    reviewed_commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "switch", "main")
    _git(repo, "merge", "--no-ff", "decision", "-m", "merge decision")
    return reviewed_commit, _git(repo, "rev-parse", "HEAD")


def _waiver_evidence(commit: str, merge_commit: str) -> dict[str, object]:
    return {
        "pull_request": {
            "number": 1,
            "html_url": "https://github.com/Dream1216/omnigent/pull/1",
            "merged_at": "2026-08-09T11:00:00Z",
            "merge_commit_sha": merge_commit,
            "head": {"sha": commit},
            "base": {
                "ref": "main",
                "repo": {"full_name": "Dream1216/omnigent"},
            },
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


def _approved_baseline_with_record(
    repo: Path,
    baseline: dict[str, object],
    evidence: dict[str, object],
) -> dict[str, object]:
    candidate_path = repo / str(baseline["approval"]["candidate"])  # type: ignore[index]
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    record = build_record(repo, baseline, evidence)
    record_name = f"{candidate['candidate_id']}-{record['decision_bundle_sha256'][:16]}.json"
    record_path = repo / "saas/production/adr-approvals" / record_name
    record_path.write_text(json.dumps(record), encoding="utf-8")
    for adr in baseline["adrs"]:  # type: ignore[index]
        adr["status"] = "accepted"
    baseline["approval"]["state"] = "approved"  # type: ignore[index]
    baseline["approval"]["record"] = (  # type: ignore[index]
        f"saas/production/adr-approvals/{record_name}"
    )
    return record


def test_current_adr_contract_has_consistent_degraded_waiver_state() -> None:
    require_current_approval_history(_repo())
    baseline = _baseline()
    report = validate_approval_contract(_repo(), baseline)
    approved = baseline["approval"]["state"] == "approved"  # type: ignore[index]

    assert report["status"] == "pass"
    assert report["approval_readiness"] == ("approved" if approved else "blocked")
    assert report["metrics"] == {
        "approval_mode": "sole-owner-risk-waiver",
        "governance_classification": "degraded",
        "decision_file_count": 11,
        "required_signing_role_count": 4,
        "configured_authority_role_count": 8,
        "signature_count": 1 if approved else 0,
        "technical_owner_confirmation_count": 11 if approved else 0,
    }
    assert report["blockers"] == (
        [] if approved else ["no immutable ADR approval record is referenced"]
    )


def test_approved_architecture_schema_matches_current_implementation_head() -> None:
    require_current_approval_history(_repo())
    baseline = _baseline()

    assert baseline["approval"]["approved_control_plane_schema_revision"] == "pc5a00000005"  # type: ignore[index]
    assert baseline["revision_contract"]["control_plane_schema_revision"] == "pc5a00000005"  # type: ignore[index]
    assert validate_approval_contract(_repo(), baseline)["status"] == "pass"


def test_decision_bundle_detects_document_tampering(tmp_path: Path) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    candidate_path = tmp_path / "saas/production/adr-approval-candidate.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    before = compute_decision_bundle(tmp_path, candidate)
    adr = tmp_path / candidate["decision_files"][0]
    adr.write_text(adr.read_text(encoding="utf-8") + "\nmaterial change\n", encoding="utf-8")

    assert compute_decision_bundle(tmp_path, candidate) != before


def test_append_only_history_distinguishes_a_similar_new_record_from_a_rewrite(
    tmp_path: Path,
) -> None:
    record_directory = "saas/production/adr-approvals"
    records = tmp_path / record_directory
    records.mkdir(parents=True)
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "adr-test@example.test")
    _git(tmp_path, "config", "user.name", "ADR Test")
    first = records / "candidate-a-1111111111111111.json"
    first.write_text(
        json.dumps({"candidate": "a", "state": "approved", "facts": list(range(24))}),
        encoding="utf-8",
    )
    _git(tmp_path, "add", record_directory)
    _git(tmp_path, "commit", "-m", "first immutable record")

    second = records / "candidate-b-2222222222222222.json"
    second.write_text(
        json.dumps({"candidate": "b", "state": "approved", "facts": list(range(24))}),
        encoding="utf-8",
    )
    _git(tmp_path, "add", record_directory)
    _git(tmp_path, "commit", "-m", "second immutable record")

    violations: list[str] = []
    _validate_append_only_history(tmp_path, record_directory, violations)
    assert violations == []

    first.write_text(first.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    _git(tmp_path, "add", str(first.relative_to(tmp_path)))
    _git(tmp_path, "commit", "-m", "tamper with first record")
    violations = []
    _validate_append_only_history(tmp_path, record_directory, violations)
    assert (
        f"approval record was changed after creation: {first.relative_to(tmp_path)}" in violations
    )


def test_append_only_history_rejects_a_pure_record_rename(tmp_path: Path) -> None:
    record_directory = "saas/production/adr-approvals"
    records = tmp_path / record_directory
    records.mkdir(parents=True)
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "adr-test@example.test")
    _git(tmp_path, "config", "user.name", "ADR Test")
    original = records / "candidate-a-1111111111111111.json"
    renamed = records / "candidate-a-renamed-1111111111111111.json"
    original.write_text(json.dumps({"candidate": "a", "state": "approved"}), encoding="utf-8")
    _git(tmp_path, "add", record_directory)
    _git(tmp_path, "commit", "-m", "immutable record")
    _git(tmp_path, "mv", str(original.relative_to(tmp_path)), str(renamed.relative_to(tmp_path)))
    _git(tmp_path, "commit", "-m", "rename immutable record")

    violations: list[str] = []
    _validate_append_only_history(tmp_path, record_directory, violations)

    assert "an immutable approval record was deleted from Git history" in violations


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
    _refresh_candidate_digest(tmp_path)

    report = validate_approval_contract(tmp_path, baseline)

    assert report["status"] == "pass"
    assert report["approval_readiness"] == "blocked"
    assert report["metrics"]["configured_authority_role_count"] == 8
    assert report["blockers"] == ["no immutable ADR approval record is referenced"]


def test_approved_waiver_requires_exact_owner_identity_merge_and_ci(tmp_path: Path) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    commit, merge_commit = _commit_decision_tree(tmp_path)
    evidence = _waiver_evidence(commit, merge_commit)
    record = _approved_baseline_with_record(tmp_path, baseline, evidence)

    assert record["target_repository"] == "Dream1216/omnigent"
    assert record["target_branch"] == "main"
    assert record["merge_strategy"] == "merge-commit"

    report = validate_approval_contract(tmp_path, baseline, github_evidence=evidence)
    assert report["status"] == "pass"
    assert report["approval_readiness"] == "approved"

    evidence["waiver_actor_permission"] = {"permission": "write"}
    downgraded = validate_approval_contract(tmp_path, baseline, github_evidence=evidence)
    assert downgraded["status"] == "fail"
    assert "live sole-owner repository permission is not admin" in downgraded["violations"]


@pytest.mark.parametrize(
    ("drift", "expected"),
    [
        ("missing-base", "decision PR base repository metadata is missing"),
        ("wrong-repository", "decision PR base repository does not match approval policy"),
        ("wrong-branch", "decision PR base branch does not match approval policy"),
    ],
)
def test_finalizer_and_live_checker_reject_wrong_pr_target(
    tmp_path: Path,
    drift: str,
    expected: str,
) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    commit, merge_commit = _commit_decision_tree(tmp_path)
    evidence = _waiver_evidence(commit, merge_commit)
    _approved_baseline_with_record(tmp_path, baseline, evidence)
    drifted = copy.deepcopy(evidence)
    pull = drifted["pull_request"]
    assert isinstance(pull, dict)
    if drift == "missing-base":
        pull.pop("base")
    else:
        base = pull["base"]
        assert isinstance(base, dict)
        if drift == "wrong-repository":
            base["repo"] = {"full_name": "attacker/omnigent"}
        else:
            base["ref"] = "release"

    with pytest.raises(ValueError) as raised:
        build_record(tmp_path, baseline, drifted)
    assert expected in str(raised.value)

    report = validate_approval_contract(tmp_path, baseline, github_evidence=drifted)
    assert report["status"] == "fail"
    assert expected in report["violations"]


def test_finalizer_and_live_checker_reject_non_ancestor_merge(tmp_path: Path) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    commit, merge_commit = _commit_decision_tree(tmp_path)
    evidence = _waiver_evidence(commit, merge_commit)
    _approved_baseline_with_record(tmp_path, baseline, evidence)

    root = _git(tmp_path, "rev-list", "--max-parents=0", "HEAD")
    _git(tmp_path, "switch", "-c", "unmerged", root)
    _git(tmp_path, "commit", "--allow-empty", "-m", "unmerged commit")
    unmerged = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "switch", "main")
    drifted = copy.deepcopy(evidence)
    pull = drifted["pull_request"]
    assert isinstance(pull, dict)
    pull["merge_commit_sha"] = unmerged

    with pytest.raises(ValueError) as raised:
        build_record(tmp_path, baseline, drifted)
    assert "decision PR merge commit is not an ancestor of current HEAD" in str(raised.value)

    report = validate_approval_contract(tmp_path, baseline, github_evidence=drifted)
    assert report["status"] == "fail"
    assert "decision PR merge commit is not an ancestor of current HEAD" in report["violations"]


def test_finalizer_rejects_worktree_drift_from_reviewed_pr_commit(tmp_path: Path) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    commit, merge_commit = _commit_decision_tree(tmp_path)
    candidate_path = tmp_path / str(baseline["approval"]["candidate"])  # type: ignore[index]
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    adr = tmp_path / candidate["decision_files"][0]
    adr.write_text(adr.read_text(encoding="utf-8") + "\nunreviewed change\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"decision file .* bytes differ from reviewed commit"):
        build_record(tmp_path, baseline, _waiver_evidence(commit, merge_commit))


@pytest.mark.parametrize(
    ("source", "expected_violation"),
    [
        (
            "saas/production/adr-approval-candidate.json",
            "approval.candidate bytes differ from reviewed commit",
        ),
        (
            "saas/production/adr-approval-policy.json",
            "approval.policy bytes differ from reviewed commit",
        ),
        (
            "saas/production/adr-approval-authorities.json",
            "approval.authorities bytes differ from reviewed commit",
        ),
        (
            "saas/production/adrs/ADR-001-postgresql-topology-and-transactions.md",
            "decision file saas/production/adrs/ADR-001-postgresql-topology-and-transactions.md "
            "bytes differ from reviewed commit",
        ),
    ],
)
def test_successor_decision_source_drift_fails_closed(
    tmp_path: Path,
    source: str,
    expected_violation: str,
) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    commit, merge_commit = _commit_decision_tree(tmp_path)
    evidence = _waiver_evidence(commit, merge_commit)
    _approved_baseline_with_record(tmp_path, baseline, evidence)

    path = tmp_path / source
    path.write_bytes(path.read_bytes() + b"\n")
    _git(tmp_path, "add", source)
    _git(tmp_path, "commit", "-m", "unreviewed successor drift")

    report = validate_approval_contract(tmp_path, baseline, github_evidence=evidence)

    assert report["status"] == "fail"
    assert any(expected_violation in violation for violation in report["violations"])


@pytest.mark.parametrize(
    "drift",
    ["candidate-path", "adr-registry", "revision-contract", "approved-schema"],
)
def test_successor_baseline_decision_material_drift_fails_closed(
    tmp_path: Path,
    drift: str,
) -> None:
    shutil.copytree(_repo() / "saas/production", tmp_path / "saas/production")
    baseline = copy.deepcopy(_baseline())
    commit, merge_commit = _commit_decision_tree(tmp_path)
    evidence = _waiver_evidence(commit, merge_commit)
    _approved_baseline_with_record(tmp_path, baseline, evidence)

    if drift == "candidate-path":
        baseline["approval"]["candidate"] = (  # type: ignore[index]
            "saas/production/adr-approval-policy.json"
        )
    elif drift == "adr-registry":
        baseline["adrs"][0]["decision"] += " unreviewed"  # type: ignore[index]
    elif drift == "revision-contract":
        baseline["revision_contract"]["adapter_contract_version"] = "unreviewed"  # type: ignore[index]
    else:
        baseline["approval"]["approved_control_plane_schema_revision"] = (  # type: ignore[index]
            "unreviewed"
        )

    report = validate_approval_contract(tmp_path, baseline, github_evidence=evidence)

    assert report["status"] == "fail"
    assert any(
        "baseline decision material differs from reviewed commit" in violation
        for violation in report["violations"]
    )
