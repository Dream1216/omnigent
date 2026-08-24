"""Generate an immutable ADR approval record from a merged GitHub decision PR."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts.check_adr_approvals import (
    _REQUIRED_WAIVER_RISKS,
    _STANDARD_MODE,
    _WAIVER_MODE,
    _read_json,
    authority_bundle_sha256,
    decision_registry_sha256,
    fetch_github_evidence,
    reviewed_decision_sources,
    validate_pull_target_and_ancestry,
)


def _latest_approved_reviews(
    evidence: dict[str, Any], commit_sha: str
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    reviews = evidence.get("reviews")
    if not isinstance(reviews, list):
        return result
    for review in sorted(
        (item for item in reviews if isinstance(item, dict)),
        key=lambda item: str(item.get("submitted_at") or ""),
    ):
        user = review.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        if (
            isinstance(login, str)
            and review.get("state") == "APPROVED"
            and review.get("commit_id") == commit_sha
        ):
            result[login.lower()] = review
    return result


def _assign_distinct_signers(
    roles: list[str],
    authority_logins: dict[str, set[str]],
    reviews: dict[str, dict[str, Any]],
    author: str,
) -> dict[str, str] | None:
    assigned: dict[str, str] = {}

    def visit(index: int, used: set[str]) -> bool:
        if index == len(roles):
            return True
        role = roles[index]
        choices = sorted(authority_logins.get(role, set()) & set(reviews))
        for login in choices:
            if login in used or login == author.lower():
                continue
            assigned[role] = login
            if visit(index + 1, used | {login}):
                return True
            assigned.pop(role, None)
        return False

    return assigned if visit(0, set()) else None


def _review_record(review: dict[str, Any], *, role_field: str, role: str) -> dict[str, Any]:
    user = review.get("user")
    return {
        role_field: role,
        "login": user.get("login") if isinstance(user, dict) else None,
        "review_id": review.get("id"),
        "submitted_at": review.get("submitted_at"),
        "commit_sha": review.get("commit_id"),
        "state": review.get("state"),
        "review_url": review.get("html_url"),
    }


def _build_waiver_record(
    baseline: dict[str, Any],
    evidence: dict[str, Any],
    policy: dict[str, Any],
    authorities: dict[str, Any],
    candidate: dict[str, Any],
    pull: dict[str, Any],
    commit_sha: str,
    author: str,
    decision_bundle_sha256: str,
) -> dict[str, Any]:
    waiver_policy = policy.get("sole_owner_risk_waiver")
    sole_owner = authorities.get("sole_owner")
    if not isinstance(waiver_policy, dict) or not isinstance(sole_owner, dict):
        raise ValueError("sole-owner waiver policy and authority are required")
    login = sole_owner.get("github_login")
    user_id = sole_owner.get("github_user_id")
    merged_by = pull.get("merged_by")
    merged_login = merged_by.get("login") if isinstance(merged_by, dict) else None
    if not isinstance(login, str) or author != login or merged_login != login:
        raise ValueError("the sole owner must author and merge the exact decision PR")
    actor = evidence.get("waiver_actor")
    permission = evidence.get("waiver_actor_permission")
    if (
        not isinstance(actor, dict)
        or actor.get("login") != login
        or actor.get("id") != user_id
        or actor.get("type") != "User"
    ):
        raise ValueError("live GitHub sole-owner identity does not match the authority")
    if not isinstance(permission, dict) or permission.get("permission") != "admin":
        raise ValueError("the sole owner must retain repository admin permission")
    check_name = waiver_policy.get("require_exact_head_ci")
    check_runs = evidence.get("check_runs")
    matches = (
        [
            item
            for item in check_runs
            if isinstance(item, dict)
            and item.get("name") == check_name
            and item.get("head_sha") == commit_sha
            and item.get("status") == "completed"
            and item.get("conclusion") == "success"
            and isinstance(item.get("id"), int)
            and isinstance(item.get("html_url"), str)
        ]
        if isinstance(check_runs, list)
        else []
    )
    if not matches:
        raise ValueError("the exact decision PR head has no successful compatibility-gate")
    check_run = max(matches, key=lambda item: int(item["id"]))
    adrs = baseline.get("adrs")
    if not isinstance(adrs, list) or len(adrs) != 11:
        raise ValueError("baseline must contain eleven ADRs")
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": 2,
        "state": "approved",
        "approval_mode": _WAIVER_MODE,
        "governance_classification": "degraded",
        "candidate_id": candidate["candidate_id"],
        "decision_bundle_sha256": decision_bundle_sha256,
        "decision_registry_sha256": candidate["decision_registry_sha256"],
        "authority_bundle_sha256": authority_bundle_sha256(authorities),
        "implementation_revision": candidate["implementation_revision"],
        "evidence_revision": candidate["evidence_revision"],
        "upstream_revision": candidate["upstream_revision"],
        "adapter_contract_version": candidate["adapter_contract_version"],
        "control_plane_schema_revision": candidate["control_plane_schema_revision"],
        "deployment_scope": candidate["deployment_scope"],
        "repository": policy["repository"],
        "target_repository": policy["repository"],
        "target_branch": policy["target_branch"],
        "merge_strategy": policy["merge_strategy"],
        "pull_request": pull["number"],
        "pull_request_url": pull["html_url"],
        "pull_request_author": author,
        "merged_by": merged_login,
        "reviewed_commit_sha": commit_sha,
        "merge_commit_sha": pull.get("merge_commit_sha"),
        "merged_at": pull["merged_at"],
        "generated_at": generated_at,
        "waiver_signature": {
            "login": login,
            "github_user_id": user_id,
            "github_actor_type": "User",
            "repository_permission": "admin",
            "authorization_source": waiver_policy["authorization_source"],
            "authorized_at": waiver_policy["authorized_at"],
            "review_due_at": waiver_policy["review_due_at"],
            "commit_sha": commit_sha,
            "ci_name": check_name,
            "check_run_id": check_run["id"],
            "check_run_url": check_run["html_url"],
            "risk_acceptance": _REQUIRED_WAIVER_RISKS,
        },
        "technical_owner_acceptances": [
            {
                "adr_id": adr.get("id"),
                "owner_role": adr.get("owner"),
                "login": login,
                "acceptance_mode": _WAIVER_MODE,
                "commit_sha": commit_sha,
            }
            for adr in adrs
            if isinstance(adr, dict)
        ],
    }


def build_record(
    repo: Path,
    baseline: dict[str, Any],
    evidence: dict[str, Any],
    *,
    baseline_path: str = "saas/production/baseline.json",
) -> dict[str, Any]:
    pull = evidence.get("pull_request")
    if not isinstance(pull, dict) or pull.get("merged_at") is None:
        raise ValueError("the ADR decision pull request must be merged")
    head = pull.get("head")
    commit_sha = head.get("sha") if isinstance(head, dict) else None
    author_value = pull.get("user")
    author = author_value.get("login") if isinstance(author_value, dict) else None
    if not isinstance(commit_sha, str) or not isinstance(author, str):
        raise ValueError("the GitHub pull request is missing head or author metadata")
    sources = reviewed_decision_sources(
        repo,
        baseline,
        commit_sha,
        baseline_path=baseline_path,
    )
    policy = sources["policy"]
    authorities = sources["authorities"]
    candidate = sources["candidate"]
    decision_bundle_sha256 = sources["decision_bundle_sha256"]
    validated_head, _ = validate_pull_target_and_ancestry(repo, pull, policy)
    if validated_head != commit_sha:
        raise ValueError("validated decision PR head does not match GitHub evidence")
    if authorities.get("state") != "active":
        raise ValueError("approval authorities must be active before finalization")
    if candidate.get("decision_registry_sha256") != decision_registry_sha256(baseline):
        raise ValueError("candidate and baseline ADR registry content do not match")
    if candidate.get("decision_bundle_sha256") != decision_bundle_sha256:
        raise ValueError("candidate decision digest does not match the reviewed Git commit")
    if policy.get("active_mode") == _WAIVER_MODE:
        return _build_waiver_record(
            baseline,
            evidence,
            policy,
            authorities,
            candidate,
            pull,
            commit_sha,
            author,
            decision_bundle_sha256,
        )

    roles_value = authorities.get("roles")
    if not isinstance(roles_value, dict):
        raise ValueError("approval authorities roles must be an object")
    authority_logins: dict[str, set[str]] = {}
    for role, value in roles_value.items():
        logins = value.get("github_logins") if isinstance(value, dict) else None
        if not isinstance(logins, list):
            raise ValueError(f"authority role {role} must contain github_logins")
        authority_logins[role] = {login.lower() for login in logins if isinstance(login, str)}
    reviews = _latest_approved_reviews(evidence, commit_sha)
    signing_roles = list(policy["required_signing_roles"])
    signers = _assign_distinct_signers(signing_roles, authority_logins, reviews, author)
    if signers is None:
        raise ValueError(
            "four distinct authorized non-author signers have not approved the exact PR head"
        )

    adrs = baseline.get("adrs")
    if not isinstance(adrs, list):
        raise ValueError("baseline ADR registry is missing")
    confirmations: list[dict[str, Any]] = []
    for adr in adrs:
        if not isinstance(adr, dict):
            raise ValueError("baseline ADR registry contains a non-object")
        owner = str(adr.get("owner"))
        candidates = sorted(authority_logins.get(owner, set()) & set(reviews))
        if not candidates:
            raise ValueError(f"{adr.get('id')} has no authorized exact-commit owner approval")
        item = _review_record(reviews[candidates[0]], role_field="owner_role", role=owner)
        item = {"adr_id": adr.get("id"), **item}
        confirmations.append(item)

    return {
        "schema_version": 1,
        "state": "approved",
        "approval_mode": _STANDARD_MODE,
        "candidate_id": candidate["candidate_id"],
        "decision_bundle_sha256": decision_bundle_sha256,
        "decision_registry_sha256": candidate["decision_registry_sha256"],
        "authority_bundle_sha256": authority_bundle_sha256(authorities),
        "implementation_revision": candidate["implementation_revision"],
        "evidence_revision": candidate["evidence_revision"],
        "upstream_revision": candidate["upstream_revision"],
        "adapter_contract_version": candidate["adapter_contract_version"],
        "control_plane_schema_revision": candidate["control_plane_schema_revision"],
        "deployment_scope": candidate["deployment_scope"],
        "repository": policy["repository"],
        "target_repository": policy["repository"],
        "target_branch": policy["target_branch"],
        "merge_strategy": policy["merge_strategy"],
        "pull_request": pull["number"],
        "pull_request_url": pull["html_url"],
        "pull_request_author": author,
        "reviewed_commit_sha": commit_sha,
        "merge_commit_sha": pull.get("merge_commit_sha"),
        "merged_at": pull["merged_at"],
        "generated_at": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "signatures": [
            _review_record(reviews[signers[role]], role_field="role", role=role)
            for role in signing_roles
        ],
        "technical_owner_confirmations": confirmations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request", required=True, type=int)
    parser.add_argument("--baseline", default="saas/production/baseline.json")
    parser.add_argument("--output")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    baseline = _read_json(repo / args.baseline)
    authorities = _read_json(repo / baseline["approval"]["authorities"])
    sole_owner = authorities.get("sole_owner")
    actor_login = sole_owner.get("github_login") if isinstance(sole_owner, dict) else None
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", "")
    evidence = fetch_github_evidence(
        args.repository,
        args.pull_request,
        token=token,
        actor_login=actor_login if isinstance(actor_login, str) else None,
    )
    record = build_record(repo, baseline, evidence, baseline_path=args.baseline)
    candidate = _read_json(repo / baseline["approval"]["candidate"])
    digest = record["decision_bundle_sha256"]
    output = (
        repo / args.output
        if args.output
        else repo
        / "saas/production/adr-approvals"
        / f"{candidate['candidate_id']}-{digest[:16]}.json"
    )
    if output.exists():
        raise SystemExit(f"refusing to overwrite immutable approval record: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output.relative_to(repo))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
