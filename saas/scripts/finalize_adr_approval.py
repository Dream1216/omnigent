"""Generate an immutable ADR approval record from a merged GitHub decision PR."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts.check_adr_approvals import (
    _read_json,
    authority_bundle_sha256,
    compute_decision_bundle,
    decision_registry_sha256,
    fetch_github_evidence,
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


def build_record(
    repo: Path,
    baseline: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    approval = baseline["approval"]
    policy = _read_json(repo / approval["policy"])
    authorities = _read_json(repo / approval["authorities"])
    candidate = _read_json(repo / approval["candidate"])
    if authorities.get("state") != "active":
        raise ValueError("approval authorities must be active before finalization")
    if candidate.get("decision_registry_sha256") != decision_registry_sha256(baseline):
        raise ValueError("candidate and baseline ADR registry content do not match")
    pull = evidence.get("pull_request")
    if not isinstance(pull, dict) or pull.get("merged_at") is None:
        raise ValueError("the ADR decision pull request must be merged")
    head = pull.get("head")
    commit_sha = head.get("sha") if isinstance(head, dict) else None
    author_value = pull.get("user")
    author = author_value.get("login") if isinstance(author_value, dict) else None
    if not isinstance(commit_sha, str) or not isinstance(author, str):
        raise ValueError("the GitHub pull request is missing head or author metadata")

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
        "candidate_id": candidate["candidate_id"],
        "decision_bundle_sha256": compute_decision_bundle(repo, candidate),
        "decision_registry_sha256": candidate["decision_registry_sha256"],
        "authority_bundle_sha256": authority_bundle_sha256(authorities),
        "implementation_revision": candidate["implementation_revision"],
        "evidence_revision": candidate["evidence_revision"],
        "upstream_revision": candidate["upstream_revision"],
        "adapter_contract_version": candidate["adapter_contract_version"],
        "control_plane_schema_revision": candidate["control_plane_schema_revision"],
        "deployment_scope": candidate["deployment_scope"],
        "repository": policy["repository"],
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
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", "")
    evidence = fetch_github_evidence(args.repository, args.pull_request, token=token)
    record = build_record(repo, baseline, evidence)
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
