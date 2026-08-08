"""Validate the P0 ADR decision bundle and immutable human approval evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_STANDARD_MODE = "four-party-github-reviews"
_WAIVER_MODE = "sole-owner-risk-waiver"
_DEGRADED = "degraded"
_CANDIDATE_REVISION_FIELDS = (
    "upstream_revision",
    "adapter_contract_version",
    "control_plane_schema_revision",
    "deployment_scope",
)
_REQUIRED_RULES = {
    "review_source": "github_pull_request_review",
    "required_review_state": "APPROVED",
    "require_merged_decision_pr": True,
    "require_exact_reviewed_commit": True,
    "require_distinct_signing_humans": True,
    "forbid_pull_request_author_as_signer": True,
    "require_every_adr_technical_owner": True,
    "allow_one_human_to_confirm_multiple_technical_owner_roles": True,
    "record_is_append_only": True,
    "record_hash_algorithm": "sha256",
    "authority_identity_namespace": "github-login",
}
_REQUIRED_INVALIDATION = {
    "decision_file_change": "invalidate",
    "candidate_revision_change": "invalidate",
    "authority_mapping_change": "require-new-record",
    "github_review_dismissed": "invalidate",
    "github_review_commit_mismatch": "invalidate",
    "approval_record_modified_or_deleted": "reject",
}
_REQUIRED_WAIVER_RISKS = [
    "independent product architecture security and SRE review is waived",
    "separation of duties is not present",
    "single-person error or compromise can approve all eleven ADRs",
    "production verification gates remain independent and are not waived",
]


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _repo_file(repo: Path, value: object) -> Path | None:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return None
    path = (repo / value).resolve()
    try:
        path.relative_to(repo.resolve())
    except ValueError:
        return None
    return path


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def authority_bundle_sha256(authorities: dict[str, Any]) -> str:
    """Bind a record to the exact role-to-person authority snapshot."""

    snapshot = {
        "schema_version": authorities.get("schema_version"),
        "state": authorities.get("state"),
        "governance_mode": authorities.get("governance_mode"),
        "governance_classification": authorities.get("governance_classification"),
        "reviewed_at": authorities.get("reviewed_at"),
        "review_due_at": authorities.get("review_due_at"),
        "sole_owner": authorities.get("sole_owner"),
        "roles": authorities.get("roles"),
    }
    return _canonical_sha256(snapshot)


def decision_registry_sha256(baseline: dict[str, Any]) -> str:
    """Hash material ADR registry fields while allowing status to advance."""

    adrs = baseline.get("adrs")
    if not isinstance(adrs, list):
        raise ValueError("baseline.adrs must be a list")
    snapshot = [
        {
            field: item.get(field)
            for field in ("id", "title", "owner", "decision", "verification_gate")
        }
        for item in adrs
        if isinstance(item, dict)
    ]
    return _canonical_sha256(snapshot)


def compute_decision_bundle(repo: Path, candidate: dict[str, Any]) -> str:
    """Hash candidate lineage and the byte-exact ordered ADR documents."""

    lineage = {
        "schema_version": candidate.get("schema_version"),
        "candidate_id": candidate.get("candidate_id"),
        "implementation_revision": candidate.get("implementation_revision"),
        "evidence_revision": candidate.get("evidence_revision"),
        "decision_registry_sha256": candidate.get("decision_registry_sha256"),
        **{field: candidate.get(field) for field in _CANDIDATE_REVISION_FIELDS},
    }
    digest = hashlib.sha256(b"omnigent-saas-adr-bundle-v1\0")
    digest.update(json.dumps(lineage, sort_keys=True, separators=(",", ":")).encode())
    files = candidate.get("decision_files")
    if not isinstance(files, list):
        raise ValueError("candidate.decision_files must be a list")
    for value in files:
        path = _repo_file(repo, value)
        if path is None or not path.is_file():
            raise ValueError(f"invalid or missing decision file: {value}")
        encoded = str(value).encode()
        payload = path.read_bytes()
        digest.update(b"\0" + len(encoded).to_bytes(4, "big") + encoded)
        digest.update(len(payload).to_bytes(8, "big") + payload)
    return digest.hexdigest()


def fetch_github_evidence(
    repository: str,
    pull_request: int,
    *,
    token: str,
    actor_login: str | None = None,
    api_url: str = "https://api.github.com",
) -> dict[str, Any]:
    """Fetch PR and paginated Review metadata from GitHub's REST API."""

    if not token:
        raise ValueError("a GitHub token is required for live Review verification")

    def request_json(url: str) -> tuple[Any, dict[str, str]]:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "omnigent-saas-adr-approval-verifier",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                return json.loads(response.read()), headers
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            raise ValueError(f"GitHub API {error.code}: {detail}") from error

    base = api_url.rstrip("/")
    pull, _ = request_json(f"{base}/repos/{repository}/pulls/{pull_request}")
    reviews: list[dict[str, Any]] = []
    page = 1
    while True:
        batch, _ = request_json(
            f"{base}/repos/{repository}/pulls/{pull_request}/reviews?per_page=100&page={page}"
        )
        if not isinstance(batch, list):
            raise ValueError("GitHub Reviews response must be a list")
        reviews.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < 100:
            break
        page += 1
    result: dict[str, Any] = {"pull_request": pull, "reviews": reviews}
    if actor_login:
        actor, _ = request_json(f"{base}/users/{actor_login}")
        permission, _ = request_json(
            f"{base}/repos/{repository}/collaborators/{actor_login}/permission"
        )
        head = pull.get("head") if isinstance(pull, dict) else None
        head_sha = head.get("sha") if isinstance(head, dict) else None
        checks: list[dict[str, Any]] = []
        if isinstance(head_sha, str) and _SHA1.fullmatch(head_sha):
            payload, _ = request_json(
                f"{base}/repos/{repository}/commits/{head_sha}/check-runs?per_page=100"
            )
            values = payload.get("check_runs") if isinstance(payload, dict) else None
            if isinstance(values, list):
                checks = [item for item in values if isinstance(item, dict)]
        result.update(
            {
                "waiver_actor": actor,
                "waiver_actor_permission": permission,
                "check_runs": checks,
            }
        )
    return result


def _review_fields_valid(review: object) -> bool:
    if not isinstance(review, dict):
        return False
    return (
        isinstance(review.get("review_id"), int)
        and review["review_id"] > 0
        and isinstance(review.get("login"), str)
        and _GITHUB_LOGIN.fullmatch(review["login"]) is not None
        and review.get("state") == "APPROVED"
        and _iso_timestamp(review.get("submitted_at"))
        and isinstance(review.get("review_url"), str)
        and review["review_url"].startswith("https://github.com/")
        and isinstance(review.get("commit_sha"), str)
        and _SHA1.fullmatch(review["commit_sha"]) is not None
    )


def _iso_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _validate_live_review(
    item: dict[str, Any], live_reviews: dict[int, dict[str, Any]], violations: list[str]
) -> None:
    review_id = item.get("review_id")
    live = live_reviews.get(review_id) if isinstance(review_id, int) else None
    if live is None:
        violations.append(f"GitHub Review {review_id} is missing")
        return
    user = live.get("user")
    live_login = user.get("login") if isinstance(user, dict) else None
    expected = {
        "login": live_login,
        "state": live.get("state"),
        "submitted_at": live.get("submitted_at"),
        "commit_sha": live.get("commit_id"),
        "review_url": live.get("html_url"),
    }
    for field, value in expected.items():
        if item.get(field) != value:
            violations.append(f"GitHub Review {review_id} {field} no longer matches")


def _validate_append_only_history(
    repo: Path, record_directory: str, violations: list[str]
) -> None:
    """Reject approval JSON that was modified, renamed, or deleted after creation."""

    probe = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        return
    pathspec = f":(glob){record_directory}/*.json"
    tracked = subprocess.run(
        ["git", "ls-files", pathspec],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if tracked.returncode != 0:
        violations.append(f"cannot list immutable approval records: {tracked.stderr.strip()}")
        return
    for value in tracked.stdout.splitlines():
        history = subprocess.run(
            ["git", "log", "--format=%H", "--follow", "--", value],
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
        )
        if history.returncode != 0:
            violations.append(f"cannot inspect approval record history: {value}")
        elif len(history.stdout.splitlines()) != 1:
            violations.append(f"approval record was changed after creation: {value}")
    deleted = subprocess.run(
        ["git", "log", "--format=", "--name-only", "--diff-filter=D", "--", pathspec],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if deleted.returncode != 0:
        violations.append(f"cannot inspect deleted approval records: {deleted.stderr.strip()}")
    elif deleted.stdout.strip():
        violations.append("an immutable approval record was deleted from Git history")


def validate_approval_contract(
    repo: Path,
    baseline: dict[str, Any],
    *,
    github_evidence: dict[str, Any] | None = None,
    base_ref: str | None = None,
) -> dict[str, Any]:
    """Return structural violations and explicit ADR-approval blockers."""

    violations: list[str] = []
    blockers: list[str] = []
    approval = baseline.get("approval")
    if not isinstance(approval, dict):
        return {
            "status": "fail",
            "approval_readiness": "blocked",
            "violations": ["baseline.approval must be an object"],
            "blockers": [],
            "metrics": {},
        }

    loaded: dict[str, dict[str, Any]] = {}
    for name in ("policy", "authorities", "candidate"):
        path = _repo_file(repo, approval.get(name))
        if path is None or not path.is_file():
            violations.append(f"approval.{name} must reference a repository file")
            continue
        try:
            loaded[name] = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            violations.append(f"cannot read approval.{name}: {error}")

    policy = loaded.get("policy", {})
    authorities = loaded.get("authorities", {})
    candidate = loaded.get("candidate", {})
    if policy.get("schema_version") != 2:
        violations.append("approval policy schema_version must be 2")
    if authorities.get("schema_version") != 2:
        violations.append("approval authorities schema_version must be 2")
    if candidate.get("schema_version") != 1:
        violations.append("approval candidate schema_version must be 1")
    if policy.get("repository") != "Dream1216/omnigent":
        violations.append("approval policy must bind the Dream1216/omnigent repository")
    if policy.get("candidate_path") != approval.get("candidate"):
        violations.append("approval policy candidate_path does not match baseline")
    if policy.get("authority_path") != approval.get("authorities"):
        violations.append("approval policy authority_path does not match baseline")
    if policy.get("record_directory") != "saas/production/adr-approvals":
        violations.append("approval records must remain in the governed append-only directory")
    if policy.get("rules") != _REQUIRED_RULES:
        violations.append("standard approval policy rules do not match the mandatory contract")
    if policy.get("invalidation") != _REQUIRED_INVALIDATION:
        violations.append("approval invalidation rules do not match the mandatory contract")

    approval_mode = approval.get("mode")
    if approval_mode not in {_STANDARD_MODE, _WAIVER_MODE}:
        violations.append("baseline approval mode is invalid")
    if policy.get("active_mode") != approval_mode:
        violations.append("baseline and policy active approval modes must match")
    if approval_mode == _WAIVER_MODE:
        if approval.get("governance_classification") != _DEGRADED:
            violations.append("sole-owner waiver must be classified as degraded governance")
        if policy.get("governance_classification") != _DEGRADED:
            violations.append("waiver policy must be classified as degraded governance")
        waiver_policy = policy.get("sole_owner_risk_waiver")
        if not isinstance(waiver_policy, dict) or waiver_policy.get("enabled") is not True:
            violations.append("sole-owner risk waiver must be explicitly enabled")
            waiver_policy = {}
        expected_waiver = {
            "required_repository_permission": "admin",
            "authorization_source": "authenticated-repository-owner-directive",
            "require_merged_decision_pr": True,
            "require_exact_head_ci": "compatibility-gate",
            "require_pull_request_author_and_merger_match_owner": True,
            "require_all_technical_roles_assumed_by_owner": True,
            "require_append_only_waiver_record": True,
            "risk_acceptance": _REQUIRED_WAIVER_RISKS,
        }
        for field, expected in expected_waiver.items():
            if waiver_policy.get(field) != expected:
                violations.append(f"sole-owner waiver {field} does not match the contract")
        waiver_login = waiver_policy.get("authorized_login")
        waiver_user_id = waiver_policy.get("authorized_github_user_id")
        if not isinstance(waiver_login, str) or _GITHUB_LOGIN.fullmatch(waiver_login) is None:
            violations.append("sole-owner waiver authorized_login is invalid")
        if not isinstance(waiver_user_id, int) or waiver_user_id <= 0:
            violations.append("sole-owner waiver authorized_github_user_id is invalid")
        for field in ("authorized_at", "review_due_at"):
            if not _iso_timestamp(waiver_policy.get(field)):
                violations.append(f"sole-owner waiver {field} must be ISO-8601")
        if _iso_timestamp(waiver_policy.get("review_due_at")):
            review_due = datetime.fromisoformat(
                str(waiver_policy["review_due_at"]).replace("Z", "+00:00")
            )
            if review_due <= datetime.now(UTC):
                blockers.append("sole-owner risk waiver governance review is overdue")
    else:
        waiver_policy = {}
        waiver_login = None
        waiver_user_id = None

    required_roles = approval.get("required_roles")
    policy_roles = policy.get("required_signing_roles")
    if not isinstance(required_roles, list) or required_roles != policy_roles:
        violations.append("baseline and policy required signing roles must match in order")
        required_roles = []
    if len(set(required_roles)) != 4:
        violations.append("exactly four distinct signing roles are required")

    revision = baseline.get("revision_contract")
    if isinstance(revision, dict):
        for field in _CANDIDATE_REVISION_FIELDS:
            if candidate.get(field) != revision.get(field):
                violations.append(f"candidate.{field} does not match baseline revision contract")
    implementation_revision = candidate.get("implementation_revision")
    evidence_revision = candidate.get("evidence_revision")
    if (
        not isinstance(implementation_revision, str)
        or _SHA1.fullmatch(implementation_revision) is None
    ):
        violations.append("candidate.implementation_revision must be a full Git SHA")
    if not isinstance(evidence_revision, str) or _SHA1.fullmatch(evidence_revision) is None:
        violations.append("candidate.evidence_revision must be a full Git SHA")

    decision_files = candidate.get("decision_files")
    if not isinstance(decision_files, list) or len(decision_files) != 11:
        violations.append("candidate must contain exactly eleven decision files")
    elif len(set(decision_files)) != 11:
        violations.append("candidate decision files must be unique")
    try:
        computed_digest = compute_decision_bundle(repo, candidate)
    except (OSError, ValueError) as error:
        computed_digest = ""
        violations.append(str(error))
    declared_digest = candidate.get("decision_bundle_sha256")
    if not isinstance(declared_digest, str) or _SHA256.fullmatch(declared_digest) is None:
        violations.append("candidate.decision_bundle_sha256 must be a SHA-256 digest")
    elif declared_digest != computed_digest:
        violations.append("candidate decision bundle digest does not match its files")

    adrs = baseline.get("adrs")
    adr_items = [item for item in adrs if isinstance(item, dict)] if isinstance(adrs, list) else []
    declared_registry_digest = candidate.get("decision_registry_sha256")
    computed_registry_digest = decision_registry_sha256(baseline)
    if declared_registry_digest != computed_registry_digest:
        violations.append("candidate decision registry digest does not match baseline ADR content")
    if isinstance(decision_files, list):
        file_ids = {
            Path(value).name[:7]
            for value in decision_files
            if isinstance(value, str) and re.match(r"^ADR-[0-9]{3}-", Path(value).name)
        }
        registry_ids = {str(item.get("id")) for item in adr_items}
        if file_ids != registry_ids:
            violations.append("candidate ADR document IDs do not match the baseline registry")
    technical_roles = {str(item.get("owner")) for item in adr_items}
    authority_roles = authorities.get("roles")
    expected_authority_roles = set(required_roles) | technical_roles
    if not isinstance(authority_roles, dict):
        violations.append("approval authorities roles must be an object")
        authority_roles = {}
    elif set(authority_roles) != expected_authority_roles:
        violations.append(
            "approval authorities must enumerate every signer and technical owner role"
        )

    normalized_authorities: dict[str, set[str]] = {}
    missing_authority_roles: list[str] = []
    for role in sorted(expected_authority_roles):
        value = authority_roles.get(role)
        logins = value.get("github_logins") if isinstance(value, dict) else None
        if not isinstance(logins, list):
            violations.append(f"authority role {role} github_logins must be a list")
            continue
        if len({login.lower() for login in logins if isinstance(login, str)}) != len(logins):
            violations.append(f"authority role {role} contains duplicate GitHub identities")
        invalid = [
            login
            for login in logins
            if not isinstance(login, str) or _GITHUB_LOGIN.fullmatch(login) is None
        ]
        if invalid:
            violations.append(f"authority role {role} contains invalid GitHub identities")
        normalized_authorities[role] = {
            login.lower()
            for login in logins
            if isinstance(login, str) and _GITHUB_LOGIN.fullmatch(login)
        }
        if not normalized_authorities[role]:
            missing_authority_roles.append(role)
    if authorities.get("state") != "active" or missing_authority_roles:
        blockers.append(
            f"approval authorities are not active; missing roles: {missing_authority_roles}"
        )
    if not isinstance(authorities.get("reviewed_at"), str) or not authorities.get("reviewed_at"):
        if authorities.get("state") == "active":
            violations.append("active approval authorities require reviewed_at")
    elif authorities.get("state") == "active" and not _iso_timestamp(authorities["reviewed_at"]):
        violations.append("active approval authorities reviewed_at must be ISO-8601")
    if approval_mode == _WAIVER_MODE:
        sole_owner = authorities.get("sole_owner")
        if not isinstance(sole_owner, dict):
            violations.append("waiver authorities require a sole_owner object")
            sole_owner = {}
        if authorities.get("governance_mode") != _WAIVER_MODE:
            violations.append("waiver authorities governance_mode does not match")
        if authorities.get("governance_classification") != _DEGRADED:
            violations.append("waiver authorities must be classified as degraded")
        if authorities.get("review_due_at") != waiver_policy.get("review_due_at"):
            violations.append("waiver authority and policy review_due_at must match")
        expected_owner = {
            "github_login": waiver_login,
            "github_user_id": waiver_user_id,
            "github_actor_type": "User",
            "repository_permission": "admin",
            "authorization_source": waiver_policy.get("authorization_source"),
            "authorized_at": waiver_policy.get("authorized_at"),
        }
        for field, expected in expected_owner.items():
            if sole_owner.get(field) != expected:
                violations.append(f"waiver sole_owner {field} does not match policy")
        normalized_owner = waiver_login.lower() if isinstance(waiver_login, str) else ""
        for role in sorted(expected_authority_roles):
            if normalized_authorities.get(role) != {normalized_owner}:
                violations.append(
                    f"waiver authority role {role} must be assumed only by {waiver_login}"
                )

    record_value = approval.get("record")
    record: dict[str, Any] | None = None
    record_path = _repo_file(repo, record_value)
    record_directory = policy.get("record_directory")
    if isinstance(record_directory, str):
        _validate_append_only_history(repo, record_directory, violations)
    if record_value is None:
        blockers.append("no immutable ADR approval record is referenced")
    elif record_path is None or not record_path.is_file():
        violations.append("approval.record must reference an existing repository file")
    else:
        record_dir = policy.get("record_directory")
        if not isinstance(record_dir, str) or not str(record_path).startswith(
            str((repo / record_dir).resolve()) + os.sep
        ):
            violations.append("approval.record must be inside the policy record directory")
        try:
            record = _read_json(record_path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            violations.append(f"cannot read approval.record: {error}")

    if base_ref and isinstance(policy.get("record_directory"), str):
        result = subprocess.run(
            [
                "git",
                "diff",
                "--name-status",
                f"{base_ref}...HEAD",
                "--",
                policy["record_directory"],
            ],
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            violations.append(
                f"cannot verify append-only approval records: {result.stderr.strip()}"
            )
        for line in result.stdout.splitlines():
            status = line.split("\t", 1)[0]
            if status.startswith(("M", "D", "R", "C", "T")):
                violations.append(
                    "approval records are append-only and cannot be modified or deleted"
                )

    if record is not None:
        expected_record_schema = 2 if approval_mode == _WAIVER_MODE else 1
        if (
            record.get("schema_version") != expected_record_schema
            or record.get("state") != "approved"
        ):
            violations.append(
                f"approval record must be schema version {expected_record_schema} and approved"
            )
        if record.get("approval_mode") != approval_mode:
            violations.append("approval record mode does not match baseline")
        if approval_mode == _WAIVER_MODE and record.get("governance_classification") != _DEGRADED:
            violations.append("waiver approval record must declare degraded governance")
        if record.get("candidate_id") != candidate.get("candidate_id"):
            violations.append("approval record candidate_id does not match")
        if record.get("decision_bundle_sha256") != computed_digest:
            violations.append("approval record decision digest does not match")
        if record.get("decision_registry_sha256") != computed_registry_digest:
            violations.append("approval record decision registry digest does not match")
        if record.get("authority_bundle_sha256") != authority_bundle_sha256(authorities):
            violations.append("approval record authority digest does not match")
        for field in ("implementation_revision", "evidence_revision", *_CANDIDATE_REVISION_FIELDS):
            if record.get(field) != candidate.get(field):
                violations.append(f"approval record {field} does not match candidate")
        if record.get("repository") != policy.get("repository"):
            violations.append("approval record repository does not match policy")
        if not isinstance(record.get("pull_request"), int) or record["pull_request"] <= 0:
            violations.append("approval record pull_request must be positive")
        expected_url = (
            f"https://github.com/{policy.get('repository')}/pull/{record.get('pull_request')}"
        )
        if record.get("pull_request_url") != expected_url:
            violations.append("approval record pull_request_url does not match")
        merge_commit = record.get("merge_commit_sha")
        if not isinstance(merge_commit, str) or _SHA1.fullmatch(merge_commit) is None:
            violations.append("approval record merge_commit_sha must be a full Git SHA")
        for field in ("generated_at", "merged_at"):
            if not _iso_timestamp(record.get(field)):
                violations.append(f"approval record {field} must be an ISO-8601 timestamp")
        reviewed_commit = record.get("reviewed_commit_sha")
        if not isinstance(reviewed_commit, str) or _SHA1.fullmatch(reviewed_commit) is None:
            violations.append("approval record reviewed_commit_sha must be a full Git SHA")
        author = record.get("pull_request_author")
        if not isinstance(author, str) or _GITHUB_LOGIN.fullmatch(author) is None:
            violations.append("approval record pull_request_author is invalid")
        if record_path is not None:
            expected_name = f"{candidate.get('candidate_id')}-{computed_digest[:16]}.json"
            if record_path.name != expected_name:
                violations.append("approval record filename does not bind candidate and digest")

        signature_items: list[dict[str, Any]] = []
        confirmation_items: list[dict[str, Any]] = []
        if approval_mode == _WAIVER_MODE:
            waiver_signature = record.get("waiver_signature")
            if not isinstance(waiver_signature, dict):
                violations.append("waiver approval record requires waiver_signature")
                waiver_signature = {}
            expected_signature = {
                "login": waiver_login,
                "github_user_id": waiver_user_id,
                "github_actor_type": "User",
                "repository_permission": "admin",
                "authorization_source": waiver_policy.get("authorization_source"),
                "authorized_at": waiver_policy.get("authorized_at"),
                "review_due_at": waiver_policy.get("review_due_at"),
                "commit_sha": reviewed_commit,
                "ci_name": waiver_policy.get("require_exact_head_ci"),
                "risk_acceptance": _REQUIRED_WAIVER_RISKS,
            }
            for field, expected in expected_signature.items():
                if waiver_signature.get(field) != expected:
                    violations.append(f"waiver signature {field} does not match policy")
            check_run_id = waiver_signature.get("check_run_id")
            check_run_url = waiver_signature.get("check_run_url")
            if not isinstance(check_run_id, int) or check_run_id <= 0:
                violations.append("waiver signature check_run_id must be positive")
            if not isinstance(check_run_url, str) or not check_run_url.startswith(
                "https://github.com/"
            ):
                violations.append("waiver signature check_run_url is invalid")
            acceptances = record.get("technical_owner_acceptances")
            confirmation_items = acceptances if isinstance(acceptances, list) else []
            if not isinstance(acceptances, list):
                violations.append("waiver record technical_owner_acceptances must be a list")
            by_adr = {
                item.get("adr_id"): item for item in confirmation_items if isinstance(item, dict)
            }
            if set(by_adr) != {item.get("id") for item in adr_items}:
                violations.append("waiver must accept every ADR exactly once")
            if len(by_adr) != len(confirmation_items):
                violations.append("waiver technical-owner acceptances contain duplicate ADR IDs")
            for adr in adr_items:
                item = by_adr.get(adr.get("id"))
                expected_acceptance = {
                    "adr_id": adr.get("id"),
                    "owner_role": adr.get("owner"),
                    "login": waiver_login,
                    "acceptance_mode": _WAIVER_MODE,
                    "commit_sha": reviewed_commit,
                }
                if not isinstance(item, dict):
                    continue
                for field, expected in expected_acceptance.items():
                    if item.get(field) != expected:
                        violations.append(
                            f"{adr.get('id')} waiver acceptance {field} does not match"
                        )
        else:
            signatures = record.get("signatures")
            signature_items = signatures if isinstance(signatures, list) else []
            if not isinstance(signatures, list):
                violations.append("approval record signatures must be a list")
            signature_roles = [
                item.get("role") for item in signature_items if isinstance(item, dict)
            ]
            if signature_roles != required_roles:
                violations.append(
                    "approval record signatures must cover the four roles in policy order"
                )
            signing_logins: list[str] = []
            signing_review_ids: list[int] = []
            for item in signature_items:
                if not isinstance(item, dict) or not _review_fields_valid(item):
                    violations.append("approval record contains an invalid signing Review")
                    continue
                role = item.get("role")
                login = str(item["login"]).lower()
                signing_logins.append(login)
                signing_review_ids.append(int(item["review_id"]))
                if login not in normalized_authorities.get(str(role), set()):
                    violations.append(f"{item['login']} is not authorized for signing role {role}")
                if item.get("commit_sha") != reviewed_commit:
                    violations.append(f"signing role {role} did not approve the reviewed commit")
            if len(signing_logins) != len(set(signing_logins)):
                violations.append("the four signing roles require four distinct human identities")
            if len(signing_review_ids) != len(set(signing_review_ids)):
                violations.append("the four signing roles require four distinct GitHub Reviews")
            if isinstance(author, str) and author.lower() in signing_logins:
                violations.append("the pull request author cannot be a four-party signer")

            confirmations = record.get("technical_owner_confirmations")
            confirmation_items = confirmations if isinstance(confirmations, list) else []
            if not isinstance(confirmations, list):
                violations.append("approval record technical_owner_confirmations must be a list")
            by_adr = {
                item.get("adr_id"): item for item in confirmation_items if isinstance(item, dict)
            }
            if set(by_adr) != {item.get("id") for item in adr_items}:
                violations.append("every ADR requires exactly one technical-owner confirmation")
            if len(by_adr) != len(confirmation_items):
                violations.append("technical-owner confirmations contain duplicate ADR IDs")
            for adr in adr_items:
                item = by_adr.get(adr.get("id"))
                if not isinstance(item, dict) or not _review_fields_valid(item):
                    violations.append(f"{adr.get('id')} has an invalid technical-owner Review")
                    continue
                owner_role = adr.get("owner")
                login = str(item["login"]).lower()
                if item.get("owner_role") != owner_role:
                    violations.append(f"{adr.get('id')} technical-owner role does not match")
                if login not in normalized_authorities.get(str(owner_role), set()):
                    violations.append(f"{item['login']} is not authorized for {owner_role}")
                if item.get("commit_sha") != reviewed_commit:
                    violations.append(f"{adr.get('id')} owner did not approve the reviewed commit")

        if github_evidence is not None:
            pull = github_evidence.get("pull_request")
            reviews = github_evidence.get("reviews")
            if not isinstance(pull, dict) or not isinstance(reviews, list):
                violations.append("live GitHub evidence is malformed")
            else:
                if pull.get("merged_at") is None:
                    violations.append("the ADR decision pull request is not merged")
                head = pull.get("head")
                head_sha = head.get("sha") if isinstance(head, dict) else None
                if head_sha != reviewed_commit:
                    violations.append(
                        "the merged decision PR head differs from reviewed_commit_sha"
                    )
                pull_user = pull.get("user")
                pull_login = pull_user.get("login") if isinstance(pull_user, dict) else None
                if pull_login != author:
                    violations.append("the decision PR author no longer matches the record")
                if pull.get("number") != record.get("pull_request"):
                    violations.append("the live decision PR number does not match the record")
                if pull.get("html_url") != record.get("pull_request_url"):
                    violations.append("the live decision PR URL does not match the record")
                if pull.get("merge_commit_sha") != record.get("merge_commit_sha"):
                    violations.append(
                        "the live decision PR merge commit does not match the record"
                    )
                if pull.get("merged_at") != record.get("merged_at"):
                    violations.append("the live decision PR merge time does not match the record")
                if approval_mode == _WAIVER_MODE:
                    merged_by = pull.get("merged_by")
                    merged_login = merged_by.get("login") if isinstance(merged_by, dict) else None
                    if pull_login != waiver_login or merged_login != waiver_login:
                        violations.append(
                            "waiver decision PR author and merger must match the sole owner"
                        )
                    actor = github_evidence.get("waiver_actor")
                    permission = github_evidence.get("waiver_actor_permission")
                    if not isinstance(actor, dict) or not isinstance(permission, dict):
                        violations.append("live sole-owner identity evidence is missing")
                    else:
                        if actor.get("login") != waiver_login:
                            violations.append("live sole-owner login does not match")
                        if actor.get("id") != waiver_user_id or actor.get("type") != "User":
                            violations.append("live sole-owner GitHub identity does not match")
                        if permission.get("permission") != "admin":
                            violations.append("live sole-owner repository permission is not admin")
                    check_runs = github_evidence.get("check_runs")
                    matching_checks = (
                        [
                            item
                            for item in check_runs
                            if isinstance(item, dict)
                            and item.get("name") == waiver_policy.get("require_exact_head_ci")
                            and item.get("head_sha") == reviewed_commit
                            and item.get("status") == "completed"
                            and item.get("conclusion") == "success"
                        ]
                        if isinstance(check_runs, list)
                        else []
                    )
                    waiver_signature = record.get("waiver_signature")
                    expected_check_id = (
                        waiver_signature.get("check_run_id")
                        if isinstance(waiver_signature, dict)
                        else None
                    )
                    expected_check_url = (
                        waiver_signature.get("check_run_url")
                        if isinstance(waiver_signature, dict)
                        else None
                    )
                    if not any(
                        item.get("id") == expected_check_id
                        and item.get("html_url") == expected_check_url
                        for item in matching_checks
                    ):
                        violations.append(
                            "live exact-head compatibility-gate does not match waiver record"
                        )
                else:
                    live_reviews = {
                        item["id"]: item
                        for item in reviews
                        if isinstance(item, dict) and isinstance(item.get("id"), int)
                    }
                    for item in signature_items + confirmation_items:
                        if isinstance(item, dict):
                            _validate_live_review(item, live_reviews, violations)

    state = approval.get("state")
    adr_statuses = {item.get("status") for item in adr_items}
    if record is None:
        if state != "review_required":
            violations.append("baseline approval must remain review_required without a record")
        if adr_statuses - {"proposed", "superseded"}:
            violations.append("ADRs cannot be accepted before an immutable approval record exists")
    else:
        if state != "approved":
            blockers.append("baseline approval state is not approved")
        if adr_statuses != {"accepted"}:
            blockers.append("all eleven ADR registry entries are not accepted")

    ready = not violations and not blockers and record is not None
    return {
        "status": "pass" if not violations else "fail",
        "approval_readiness": "approved" if ready else "blocked",
        "violations": sorted(set(violations)),
        "blockers": sorted(set(blockers)),
        "metrics": {
            "approval_mode": approval_mode,
            "governance_classification": approval.get("governance_classification"),
            "decision_file_count": len(decision_files) if isinstance(decision_files, list) else 0,
            "required_signing_role_count": len(required_roles),
            "configured_authority_role_count": len(expected_authority_roles)
            - len(missing_authority_roles),
            "signature_count": (
                1
                if isinstance(record, dict)
                and approval_mode == _WAIVER_MODE
                and isinstance(record.get("waiver_signature"), dict)
                else len(record.get("signatures", []))
                if isinstance(record, dict) and isinstance(record.get("signatures"), list)
                else 0
            ),
            "technical_owner_confirmation_count": (
                len(record.get("technical_owner_acceptances", []))
                if isinstance(record, dict)
                and approval_mode == _WAIVER_MODE
                and isinstance(record.get("technical_owner_acceptances"), list)
                else len(record.get("technical_owner_confirmations", []))
                if isinstance(record, dict)
                and isinstance(record.get("technical_owner_confirmations"), list)
                else 0
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="saas/production/baseline.json")
    parser.add_argument("--output")
    parser.add_argument("--base-ref", help="reject modified/deleted approval records in this diff")
    parser.add_argument(
        "--verify-github",
        action="store_true",
        help="re-fetch the referenced merged PR and Review states from GitHub",
    )
    parser.add_argument(
        "--require-approved",
        action="store_true",
        help="fail until the four-party and technical-owner approval record is valid",
    )
    parser.add_argument(
        "--require-approved-if-declared",
        action="store_true",
        help="fail when baseline declares approved but the immutable record is not valid",
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    baseline = _read_json(repo / args.baseline)
    github_evidence = None
    if args.verify_github and isinstance(baseline.get("approval"), dict):
        approval = baseline["approval"]
        record_path = _repo_file(repo, approval.get("record"))
        if record_path is not None and record_path.is_file():
            record = _read_json(record_path)
            policy_path = _repo_file(repo, approval.get("policy"))
            policy = _read_json(policy_path) if policy_path is not None else {}
            authorities_path = _repo_file(repo, approval.get("authorities"))
            authorities = _read_json(authorities_path) if authorities_path is not None else {}
            repository = policy.get("repository")
            pull_request = record.get("pull_request")
            sole_owner = authorities.get("sole_owner")
            actor_login = sole_owner.get("github_login") if isinstance(sole_owner, dict) else None
            if isinstance(repository, str) and isinstance(pull_request, int):
                github_evidence = fetch_github_evidence(
                    repository,
                    pull_request,
                    token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", ""),
                    actor_login=actor_login if isinstance(actor_login, str) else None,
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                )
    report = validate_approval_contract(
        repo,
        baseline,
        github_evidence=github_evidence,
        base_ref=args.base_ref,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = repo / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["status"] != "pass":
        return 1
    declared_approved = baseline.get("approval", {}).get("state") == "approved"
    require_approved = args.require_approved or (
        args.require_approved_if_declared and declared_approved
    )
    return 1 if require_approved and report["approval_readiness"] != "approved" else 0


if __name__ == "__main__":
    raise SystemExit(main())
