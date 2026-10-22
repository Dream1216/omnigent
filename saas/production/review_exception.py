"""Validate an explicit, candidate-bound sole-owner production review exception."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

from saas.production.admission import _regular_repo_file
from saas.scripts.check_adr_approvals import _validate_append_only_history

MODE = "sole-owner-risk-waiver"
POLICY_PATH = "saas/production/review-exception-policy.json"
RECORD_DIRECTORY = "saas/production/review-exception-evidence"
RELEASE_ID = "omnigent-saas-v0.19.0.dev20261020-3db749d7"
WORKFLOW_IDENTITY = (
    "Dream1216/omnigent/.github/workflows/saas-production-admission.yml@refs/heads/main"
)
_WORKFLOW_PATH = ".github/workflows/saas-production-admission.yml"
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VALID_FROM = "2026-10-21T00:00:00Z"
_EXPIRES_AT = "2026-12-20T00:00:00Z"
_FACT_CACHE: ContextVar[dict[int, dict[str, Any]] | None] = ContextVar(
    "release_review_facts", default=None
)
_Parameters = ParamSpec("_Parameters")
_Result = TypeVar("_Result")
_REVISION_CONTRACT = {
    "upstream_revision": "3db749d784ff044304473939acaae3a65c0fec61",
    "adapter_contract_version": "0.2.0",
    "control_plane_schema_revision": "p0s000000018",
}
_DOMAIN_ROLES = {
    "image": {"release-engineering", "security", "site-reliability"},
    "deployment": {"site-reliability", "security", "release-engineering"},
    "recovery": {"site-reliability", "security", "data-owner"},
    "slo_capacity": {"site-reliability", "product-owner", "service-owner"},
    "deletion": {"privacy", "security", "data_owner"},
    "commercial": {"finance", "product-owner", "service-owner", "customer-success"},
    "enterprise": {"identity-owner", "security", "privacy", "customer-admin"},
}
_POLICY_FIELDS = {
    "schema_version",
    "release_id",
    "mode",
    "governance_classification",
    "revision_contract",
    "authorized_login",
    "authorized_github_user_id",
    "valid_from",
    "expires_at",
    "authorization_reference_sha256",
    "record_directory",
    "domain_roles",
    "risks_accepted",
    "technical_gates_waived",
}
_RECORD_FIELDS = {
    "schema_version",
    "release_id",
    "mode",
    "governance_classification",
    "product_revision",
    "evidence_revision",
    "revision_contract",
    "authorized_login",
    "authorized_github_user_id",
    "attestor_commitment",
    "issued_at",
    "expires_at",
    "authorization_reference_sha256",
    "domains",
    "native_approval",
}
_APPROVAL_FIELDS = {
    "workflow_run_id",
    "workflow_head_sha",
    "workflow_identity",
    "environment",
    "approval_facts_sha256",
    "authorization_manifest_sha256",
    "authorization_artifact_id",
    "authorization_artifact_digest",
    "product_revision",
    "attestor_commitment",
    "expires_at",
    "authorization_reference_sha256",
}
_RISKS = [
    "independent production review separation of duties is absent for this release",
    "one compromised or mistaken owner can approve all production evidence domains",
    "all technical tests measurements signatures and release gates remain mandatory",
]


def review_verification_scope(
    function: Callable[_Parameters, _Result],
) -> Callable[_Parameters, _Result]:
    """Share native facts inside one check and discard them before the next check."""

    @wraps(function)
    def scoped(*args: _Parameters.args, **kwargs: _Parameters.kwargs) -> _Result:
        if _FACT_CACHE.get() is not None:
            return function(*args, **kwargs)
        token = _FACT_CACHE.set({})
        try:
            return function(*args, **kwargs)
        finally:
            _FACT_CACHE.reset(token)

    return scoped


def canonical_review_record(document: Mapping[str, Any]) -> bytes:
    """Render the only accepted representation for append-only exception records."""

    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("review exception timestamps must be UTC")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)


def _object(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("review exception JSON contains duplicate members")
            document[key] = value
        return document

    if len(raw) > 131072:
        raise ValueError("review exception document is oversized")
    document = json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")),
    )
    if not isinstance(document, dict):
        raise ValueError("review exception document must be an object")
    return document


def governed_review_record(repo: Path, relative: str) -> dict[str, Any] | None:
    """Accept canonical governed JSON only; never whitelist an arbitrary directory."""

    path = Path(relative)
    if path.parent.as_posix() != RECORD_DIRECTORY:
        return None
    source = _regular_repo_file(repo, path)
    if source is None:
        return None
    try:
        raw = source.read_bytes()
        record = _object(raw)
        product = record.get("product_revision")
        evidence = record.get("evidence_revision")
        proof = record.get("native_approval")
        if (
            set(record) != _RECORD_FIELDS
            or record.get("schema_version") != 1
            or record.get("release_id") != RELEASE_ID
            or record.get("mode") != MODE
            or record.get("governance_classification") != "degraded"
            or record.get("revision_contract") != _REVISION_CONTRACT
            or record.get("authorized_login") != "Dream1216"
            or record.get("authorized_github_user_id") != 39821512
            or not isinstance(product, str)
            or _REVISION.fullmatch(product) is None
            or not isinstance(evidence, str)
            or _REVISION.fullmatch(evidence) is None
            or not isinstance(record.get("attestor_commitment"), str)
            or _SHA256.fullmatch(record["attestor_commitment"]) is None
            or not isinstance(record.get("authorization_reference_sha256"), str)
            or _SHA256.fullmatch(record["authorization_reference_sha256"]) is None
            or record.get("domains") != sorted(_DOMAIN_ROLES)
            or not isinstance(proof, dict)
            or set(proof) != _APPROVAL_FIELDS
            or type(proof.get("workflow_run_id")) is not int
            or proof["workflow_run_id"] <= 0
            or proof.get("workflow_head_sha") != evidence
            or proof.get("workflow_identity") != WORKFLOW_IDENTITY
            or proof.get("environment") != "production-evidence"
            or not isinstance(proof.get("approval_facts_sha256"), str)
            or _SHA256.fullmatch(proof["approval_facts_sha256"]) is None
            or proof.get("product_revision") != product
            or proof.get("attestor_commitment") != record.get("attestor_commitment")
            or proof.get("expires_at") != record.get("expires_at")
            or type(proof.get("authorization_artifact_id")) is not int
            or proof["authorization_artifact_id"] <= 0
            or not isinstance(proof.get("authorization_artifact_digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", proof["authorization_artifact_digest"]) is None
            or not isinstance(proof.get("authorization_manifest_sha256"), str)
            or _SHA256.fullmatch(proof["authorization_manifest_sha256"]) is None
            or path.name != f"{RELEASE_ID}-{product}.json"
            or raw != canonical_review_record(record)
        ):
            return None
        if (
            not _time(_VALID_FROM)
            <= _time(record["issued_at"])
            < _time(record["expires_at"])
            <= _time(_EXPIRES_AT)
        ):
            return None
        return record
    except (OSError, ValueError, TypeError):
        return None


def _load_policy(repo: Path) -> dict[str, Any]:
    path = _regular_repo_file(repo, Path(POLICY_PATH))
    if path is None:
        raise ValueError("release review exception policy is missing")
    policy = _object(path.read_bytes())
    if (
        set(policy) != _POLICY_FIELDS
        or policy.get("schema_version") != 1
        or policy.get("release_id") != RELEASE_ID
        or policy.get("mode") != MODE
        or policy.get("governance_classification") != "degraded"
        or policy.get("revision_contract") != _REVISION_CONTRACT
        or policy.get("authorized_login") != "Dream1216"
        or policy.get("authorized_github_user_id") != 39821512
        or policy.get("record_directory") != RECORD_DIRECTORY
        or policy.get("domain_roles")
        != {key: sorted(value) for key, value in _DOMAIN_ROLES.items()}
        or policy.get("risks_accepted") != _RISKS
        or policy.get("technical_gates_waived") != []
        or policy.get("valid_from") != _VALID_FROM
        or policy.get("expires_at") != _EXPIRES_AT
        or not isinstance(policy.get("authorization_reference_sha256"), str)
        or _SHA256.fullmatch(policy["authorization_reference_sha256"]) is None
    ):
        raise ValueError("release review exception policy scope is invalid")
    return policy


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise ValueError("GitHub review verification redirects are forbidden")


def _github_json(path: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "omnigent-release-review",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    request = urllib.request.Request("https://api.github.com/" + path, headers=headers)
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError("GitHub review metadata is oversized")
        return json.loads(raw)
    except (OSError, urllib.error.URLError, ValueError) as error:
        raise ValueError("live GitHub review facts could not be verified") from error


def _github_artifact_zip(artifact_id: int) -> bytes:
    """Follow one native signed download URL without forwarding the API token."""

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "omnigent-release-review",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    url = f"https://api.github.com/repos/Dream1216/omnigent/actions/artifacts/{artifact_id}/zip"

    # Handle the single API redirect explicitly; no credential leaves api.github.com.
    class NoFollow(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoFollow(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        try:
            opener.open(urllib.request.Request(url, headers=headers), timeout=15).close()
            raise ValueError("artifact API did not issue its expected signed redirect")
        except urllib.error.HTTPError as error:
            if error.code != 302:
                raise ValueError("native artifact download was denied") from error
            location = error.headers.get("Location", "")
        parsed = urllib.parse.urlsplit(location)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.port not in {None, 443}
            or not (
                (
                    host.startswith("productionresultssa")
                    and host.endswith(".blob.core.windows.net")
                )
                or host.endswith(".actions.githubusercontent.com")
            )
        ):
            raise ValueError("native artifact download host is not allowed")
        with opener.open(
            urllib.request.Request(location, headers={"User-Agent": "omnigent-release-review"}),
            timeout=15,
        ) as response:
            raw = response.read(4194305)
        if len(raw) > 4194304:
            raise ValueError("authorization artifact exceeds its size bound")
        return raw
    except (OSError, urllib.error.URLError) as error:
        raise ValueError("native artifact download could not be verified") from error


def native_authorization(run_id: int, evidence_revision: str) -> dict[str, Any]:
    inventory = _github_json(
        f"repos/Dream1216/omnigent/actions/runs/{run_id}/artifacts?per_page=2"
    )
    if not isinstance(inventory, dict) or inventory.get("total_count") != 1:
        raise ValueError("one unambiguous native authorization artifact is required")
    artifacts = inventory.get("artifacts")
    if (
        not isinstance(artifacts, list)
        or len(artifacts) != 1
        or not isinstance(artifacts[0], dict)
    ):
        raise ValueError("native authorization artifact inventory is invalid")
    artifact = artifacts[0]
    source = artifact.get("workflow_run", {})
    if (
        type(artifact.get("id")) is not int
        or artifact["id"] <= 0
        or artifact.get("name") != "production-review-authorization-" + evidence_revision
        or artifact.get("expired") is not False
        or not isinstance(source, dict)
        or source.get("id") != run_id
        or source.get("head_sha") != evidence_revision
        or type(artifact.get("size_in_bytes")) is not int
        or not 0 < artifact["size_in_bytes"] <= 4194304
        or not isinstance(artifact.get("digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]) is None
    ):
        raise ValueError("native authorization artifact metadata does not bind this run")
    raw = _github_artifact_zip(artifact["id"])
    if (
        len(raw) != artifact["size_in_bytes"]
        or "sha256:" + hashlib.sha256(raw).hexdigest() != artifact["digest"]
    ):
        raise ValueError("native authorization ZIP digest or size differs")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if (
                len(entries) != 1
                or entries[0].filename != "review-exception-authorization.json"
                or entries[0].file_size > 131072
                or entries[0].flag_bits & 1
                or (entries[0].external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise ValueError("native authorization artifact contents are invalid")
            payload = archive.read(entries[0])
    except (zipfile.BadZipFile, RuntimeError) as error:
        raise ValueError("native authorization artifact is not a valid bounded ZIP") from error
    document = _object(payload)
    fields = {
        "schema_version",
        "release_id",
        "mode",
        "product_revision",
        "evidence_revision",
        "attestor_commitment",
        "revision_contract",
        "authorization_reference_sha256",
        "workflow_identity",
        "expires_at",
    }
    if (
        set(document) != fields
        or document.get("schema_version") != 1
        or document.get("release_id") != RELEASE_ID
        or document.get("mode") != MODE
        or document.get("revision_contract") != _REVISION_CONTRACT
        or document.get("workflow_identity") != WORKFLOW_IDENTITY
        or document.get("evidence_revision") != evidence_revision
        or not isinstance(document.get("product_revision"), str)
        or _REVISION.fullmatch(document["product_revision"]) is None
        or not isinstance(document.get("attestor_commitment"), str)
        or _SHA256.fullmatch(document["attestor_commitment"]) is None
        or not isinstance(document.get("authorization_reference_sha256"), str)
        or _SHA256.fullmatch(document["authorization_reference_sha256"]) is None
        or payload != canonical_review_record(document)
    ):
        raise ValueError("native authorization manifest scope is invalid")
    if not _time(_VALID_FROM) < _time(document["expires_at"]) <= _time(_EXPIRES_AT):
        raise ValueError("native authorization manifest expiry is invalid")
    return {
        **document,
        "authorization_manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "authorization_artifact_id": artifact["id"],
        "authorization_artifact_digest": artifact["digest"],
    }


def native_review_facts(run_id: int) -> dict[str, Any]:
    """Fetch authority from native GitHub responses, never caller-supplied identities."""

    cache = _FACT_CACHE.get()
    if cache is not None and run_id in cache:
        if cache[run_id].get("verification_failed") is True:
            raise ValueError("native review facts failed earlier in this check")
        return dict(cache[run_id])
    if cache is not None and len(cache) >= 32:
        raise ValueError("too many distinct review runs in one check")
    if cache is not None:
        cache[run_id] = {"verification_failed": True}
    repository = _github_json("repos/Dream1216/omnigent")
    run = _github_json(f"repos/Dream1216/omnigent/actions/runs/{run_id}")
    approvals = _github_json(f"repos/Dream1216/omnigent/actions/runs/{run_id}/approvals")
    owner = repository.get("owner", {}) if isinstance(repository, dict) else {}
    source_repo = run.get("repository", {}) if isinstance(run, dict) else {}
    head_repo = run.get("head_repository", {}) if isinstance(run, dict) else {}
    if (
        not isinstance(run, dict)
        or not isinstance(approvals, list)
        or not isinstance(owner, dict)
        or not isinstance(source_repo, dict)
        or not isinstance(head_repo, dict)
        or owner.get("login") != "Dream1216"
        or owner.get("id") != 39821512
        or owner.get("type") != "User"
        or repository.get("default_branch") != "main"
        or run.get("id") != run_id
        or source_repo.get("full_name") != "Dream1216/omnigent"
        or head_repo.get("full_name") != "Dream1216/omnigent"
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != "main"
        or run.get("path")
        not in {_WORKFLOW_PATH, _WORKFLOW_PATH + "@main", _WORKFLOW_PATH + "@refs/heads/main"}
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("run_attempt") != 1
    ):
        raise ValueError("review run is not the approved production workflow")
    normalized = []
    for raw in approvals:
        if not isinstance(raw, dict):
            raise ValueError("GitHub review entry is invalid")
        user = raw.get("user", {})
        environments = raw.get("environments", [])
        if not isinstance(environments, list) or not isinstance(user, dict):
            raise ValueError("GitHub review environments are invalid")
        normalized.append(
            {
                "state": raw.get("state"),
                "login": user.get("login"),
                "user_id": user.get("id"),
                "actor_type": user.get("type"),
                "environments": sorted(
                    item.get("name", "") for item in environments if isinstance(item, dict)
                ),
            }
        )
    expected = {
        "state": "approved",
        "login": "Dream1216",
        "user_id": 39821512,
        "actor_type": "User",
        "environments": ["production-evidence"],
    }
    if normalized != [expected]:
        raise ValueError("one actual Dream1216 production Environment approval is required")
    evidence = run.get("head_sha")
    if not isinstance(evidence, str) or _REVISION.fullmatch(evidence) is None:
        raise ValueError("native approval head revision is invalid")
    authorization = native_authorization(run_id, evidence)
    facts = {
        key: authorization[key]
        for key in (
            "product_revision",
            "attestor_commitment",
            "expires_at",
            "authorization_reference_sha256",
            "authorization_manifest_sha256",
            "authorization_artifact_id",
            "authorization_artifact_digest",
        )
    }
    facts.update(
        {
            "workflow_run_id": run_id,
            "workflow_head_sha": run.get("head_sha"),
            "workflow_identity": WORKFLOW_IDENTITY,
            "environment": "production-evidence",
            "approval_facts_sha256": hashlib.sha256(
                canonical_review_record({"approvals": normalized})
            ).hexdigest(),
            "completed_at": run.get("updated_at"),
        }
    )
    if cache is not None:
        cache[run_id] = facts
    return dict(facts)


@dataclass(frozen=True)
class ReviewExceptionResult:
    attestations: object
    required_roles: set[str]
    violations: tuple[str, ...] = ()


def apply_review_exception(
    repo: Path | None,
    attestations: object,
    *,
    domain: str,
    required_roles: set[str],
    product_revision: object,
    now: datetime,
) -> ReviewExceptionResult:
    """Change only human role cardinality after complete, current waiver verification."""

    unchanged = ReviewExceptionResult(attestations, required_roles)
    if not isinstance(attestations, list) or not any(
        isinstance(item, dict) and item.get("role") == MODE for item in attestations
    ):
        return unchanged
    try:
        if repo is None or len(attestations) != 1 or domain not in _DOMAIN_ROLES:
            raise ValueError("review exception requires one named owner and an exact repository")
        policy = _load_policy(repo)
        baseline = _object((repo / "saas/production/baseline.json").read_bytes())
        current_revision = baseline.get("revision_contract", {})
        if (
            not isinstance(current_revision, dict)
            or {key: current_revision.get(key) for key in _REVISION_CONTRACT} != _REVISION_CONTRACT
        ):
            raise ValueError("review exception cannot authorize another upstream or schema")
        if required_roles != _DOMAIN_ROLES[domain] or not _time(
            policy["valid_from"]
        ) <= now < _time(policy["expires_at"]):
            raise ValueError("release review exception domain or validity does not match")
        item = attestations[0]
        reference = item.get("review_exception")
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise ValueError("single owner attestation must bind its immutable exception record")
        relative = reference["path"]
        if not isinstance(relative, str):
            raise ValueError("review exception record path is invalid")
        record = governed_review_record(repo, relative)
        if (
            record is None
            or hashlib.sha256((repo / relative).read_bytes()).hexdigest() != reference["sha256"]
        ):
            raise ValueError("canonical review exception record digest does not match")
        committed = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "blob", f"HEAD:{relative}"],
            capture_output=True,
            check=False,
        )
        if committed.returncode != 0 or committed.stdout != (repo / relative).read_bytes():
            raise ValueError("review exception record must match committed immutable bytes")
        if (
            record["product_revision"] != product_revision
            or record["revision_contract"] != policy["revision_contract"]
        ):
            raise ValueError("review exception is for another product or revision contract")
        if record["authorization_reference_sha256"] != policy["authorization_reference_sha256"]:
            raise ValueError("review exception does not bind the authorized human directive")
        if record["domains"] != sorted(_DOMAIN_ROLES) or not _time(policy["valid_from"]) <= _time(
            record["issued_at"]
        ) <= now < _time(record["expires_at"]) <= _time(policy["expires_at"]):
            raise ValueError("review exception record has invalid domain scope or expiry")
        commitment = item.get("actor_id_hash", item.get("actor_id_hmac"))
        if (
            not isinstance(commitment, str)
            or _SHA256.fullmatch(commitment) is None
            or commitment != record["attestor_commitment"]
        ):
            raise ValueError("single actor commitment differs from its approved record")
        proof = record["native_approval"]
        if (
            not isinstance(proof, dict)
            or set(proof) != _APPROVAL_FIELDS
            or type(proof["workflow_run_id"]) is not int
        ):
            raise ValueError("review exception native approval schema is invalid")
        actual = native_review_facts(proof["workflow_run_id"])
        if actual["authorization_reference_sha256"] != policy["authorization_reference_sha256"]:
            raise ValueError("native authorization does not bind the approved human directive")
        if (
            proof != {key: value for key, value in actual.items() if key != "completed_at"}
            or proof["workflow_head_sha"] != record["evidence_revision"]
            or _time(actual["completed_at"]) > _time(record["issued_at"])
        ):
            raise ValueError("live native review approval differs from the exception record")
        for ancestor, descendant in (
            (str(product_revision), record["evidence_revision"]),
            (record["evidence_revision"], "HEAD"),
        ):
            if (
                not isinstance(ancestor, str)
                or _REVISION.fullmatch(ancestor) is None
                or (
                    descendant != "HEAD"
                    and (
                        not isinstance(descendant, str) or _REVISION.fullmatch(descendant) is None
                    )
                )
            ):
                raise ValueError("review exception lineage has invalid revisions")
            result = subprocess.run(
                ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                raise ValueError("review exception approval is not in this candidate lineage")
        history_violations: list[str] = []
        _validate_append_only_history(repo, RECORD_DIRECTORY, history_violations)
        if history_violations:
            raise ValueError("review exception history is not append-only")
        normalized = {key: value for key, value in item.items() if key != "review_exception"}
        return ReviewExceptionResult([normalized], {MODE})
    except (OSError, ValueError, TypeError, KeyError) as error:
        return ReviewExceptionResult(
            attestations, required_roles, (f"release review exception: {error}",)
        )
