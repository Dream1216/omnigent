"""Admit one fixed product through an independently qualified CI-only controller."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from saas.scripts import oci_promotion
from saas.scripts.check_upstream_delta import _ordinary_m_candidate_matches
from saas.scripts.oci_promotion import (
    TRUSTED_REPOSITORY,
    TRUSTED_WORKFLOW,
    read_json,
    require,
    verify_promotion_controller,
)
from saas.scripts.resume_oci_promotion import (
    build_certificate_claims,
    build_promotion_predicate,
    verify_predicate,
)

MODE = "fixed-main16-ci-only"
PRODUCT = "16ab5ce0c7278205c2b4adebdaa49ed6e4cf8b45"
PRODUCT_TREE = "93d5425df20a4f42b9e3b37f8bfe8270493ceeea"
PRODUCT_EPOCH = 1794811061
SOURCE_RUN = 43818055404
SOURCE_ATTEMPT = 1
ARTIFACT = 14210895004
ZIP_SHA256 = "756131b12e619508dd6285b5be91590e9ecf67858dd0cfe4a3ce38a43b13c458"
SEAL_SHA256 = "d87424bdb17b2ed985df07d6dc3f03afc545285abbd16ef8973e20963ecb9023"
PROFILE_KEY = "fixed_main16_ci_promotion"
BUDGET_PATH = ".github/workflows/saas-controller-source-budget.json"
SCOPE_PATH = "saas/governance/ordinary-m-native-0142-source-scope.json"
GOVERNANCE_PATHS = frozenset(
    (
        BUDGET_PATH,
        SCOPE_PATH,
        "saas/upstream-baseline.json",
        "saas/scripts/check_upstream_delta.py",
        "tests/saas/test_upstream_delta.py",
    )
)
CI_ONLY_PATHS = GOVERNANCE_PATHS | frozenset(
    (
        TRUSTED_WORKFLOW,
        "saas/scripts/fixed_main16_ci_promotion.py",
        "saas/scripts/oci_promotion.py",
        "tests/saas/test_oci_promotion.py",
        "saas/scripts/check_image_supply_chain.py",
        "tests/saas/test_image_supply_chain.py",
        "tests/saas/test_scan_oci_candidates.py",
        "tests/saas/test_oci_candidate_build_capacity.py",
        "tests/saas/test_legacy_domain_discovery.py",
        "tests/saas/resources/native-domain-discovery-parent-hashes.json",
    )
)
PRODUCT_CORE = {
    ".github/workflows/ci.yml": 43818055697,
    ".github/workflows/lint.yml": 43818055437,
    ".github/workflows/saas-upstream-compat.yml": 43818055408,
    ".github/workflows/saas-n1-compat-image.yml": 43818055390,
    ".github/workflows/windows.yml": 43818055657,
    ".github/workflows/trivy.yml": 43818055535,
}


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=repo, text=True).strip()


def validate_ci_only_paths(changes: dict[str, str], registered: set[str]) -> None:
    """Reject runtime changes, deletions, renames and paths outside the reviewed scope."""
    require(
        bool(changes)
        and set(changes) <= CI_ONLY_PATHS
        and set(changes) <= registered
        and all(status in {"A", "M"} for status in changes.values()),
        "fixed controller diff is not the registered CI-only change",
    )


def _classify_clean_tree(repo: Path, revision: str) -> dict[str, Any]:
    require(_git(repo, "rev-parse", "HEAD") == revision, "controller checkout differs")
    budget = read_json(repo / BUDGET_PATH)
    profile = budget.get(PROFILE_KEY)
    if profile is None:
        return {"mode": "same-main", "product_revision": revision, "controller_revision": revision}
    require(
        profile == {"mode": MODE, "product_revision": PRODUCT} and revision != PRODUCT,
        "fixed controller profile differs",
    )
    require(_ordinary_m_candidate_matches(repo, budget), "fixed controller finite scope differs")
    require(
        _git(repo, "rev-parse", f"{PRODUCT}^{{tree}}") == PRODUCT_TREE,
        "fixed product tree differs",
    )
    _git(repo, "merge-base", "--is-ancestor", PRODUCT, revision)
    product_baseline = json.loads(_git(repo, "show", f"{PRODUCT}:saas/upstream-baseline.json"))
    controller_baseline = read_json(repo / "saas/upstream-baseline.json")
    for baseline in (product_baseline, controller_baseline):
        baseline.pop("ordinary_m_native_0142_finite_approval", None)
    require(product_baseline == controller_baseline, "product baseline controls differ")
    scope = read_json(repo / SCOPE_PATH)
    changes = {
        path: status
        for status, path in (
            row.split("\t")
            for row in _git(
                repo, "diff", "--no-renames", "--name-status", PRODUCT, revision
            ).splitlines()
        )
    }
    registered = {item["path"] for item in scope["files"]} | set(scope["governance_paths"])
    require(
        set(scope["governance_paths"]) == GOVERNANCE_PATHS,
        "fixed controller governance paths differ",
    )
    validate_ci_only_paths(changes, registered)
    postimages = []
    for path, status in sorted(changes.items()):
        target = repo / path
        require(
            target.is_file() and not target.is_symlink(), "controller postimage is not regular"
        )
        body = target.read_bytes()
        postimages.append(
            {
                "path": path,
                "status": status,
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    return {
        "mode": MODE,
        "product_revision": PRODUCT,
        "product_tree": PRODUCT_TREE,
        "controller_revision": revision,
        "controller_tree": _git(repo, "rev-parse", "HEAD^{tree}"),
        "controller_candidate_manifest_sha256": scope["candidate_manifest_sha256"],
        "controller_scope_sha256": hashlib.sha256((repo / SCOPE_PATH).read_bytes()).hexdigest(),
        "controller_changed_paths": postimages,
    }


def classify(repo: Path, revision: str) -> dict[str, Any]:
    """Check the complete finite scope in an owned clean view, even after downloads."""
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid controller revision")
    require(_git(repo, "rev-parse", "HEAD") == revision, "controller checkout differs")
    require(not _git(repo, "diff", "HEAD", "--"), "controller tracked checkout is modified")
    with tempfile.TemporaryDirectory(prefix="omnigent-fixed-controller-") as directory:
        view = Path(directory) / "controller"
        _git(repo, "worktree", "add", "--quiet", "--detach", str(view), revision)
        try:
            return _classify_clean_tree(view, revision)
        finally:
            _git(repo, "worktree", "remove", "--force", str(view))


def require_source_coordinates(
    *,
    revision: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    zip_sha256: str,
    manifest_sha256: str | None,
) -> None:
    require(
        (revision, run_id, run_attempt, artifact_id, zip_sha256, manifest_sha256)
        == (PRODUCT, SOURCE_RUN, SOURCE_ATTEMPT, ARTIFACT, ZIP_SHA256, SEAL_SHA256),
        "fixed original product/source/archive/seal coordinates differ",
    )


def _api(endpoint: str, *, paginate: bool = False) -> Any:
    arguments = ["gh", "api"]
    if paginate:
        arguments.extend(("--paginate", "--slurp"))
    return json.loads(subprocess.check_output([*arguments, endpoint], text=True))


def verify_core_ci(
    rows: list[dict[str, Any]],
    *,
    revision: str,
    repository_id: int,
    now: datetime,
) -> list[dict[str, Any]]:
    """Keep both six-run qualifications native, exact and under their original clocks."""
    require(
        len(rows) == 6 and {row["run"]["path"] for row in rows} == set(PRODUCT_CORE),
        "six own-Main CI workflows required",
    )
    result = []
    for row in sorted(rows, key=lambda value: value["run"]["path"]):
        run, jobs = row["run"], row["jobs"]
        require(
            type(run.get("id")) is int
            and run["id"] > 0
            and run.get("head_sha") == revision
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and run.get("run_attempt") == 1
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and all(
                run.get(key, {}).get("full_name") == TRUSTED_REPOSITORY
                and run[key].get("id") == repository_id
                for key in ("repository", "head_repository")
            )
            and (revision != PRODUCT or run["id"] == PRODUCT_CORE[run["path"]]),
            "own-Main CI identity, attempt or conclusion differs",
        )
        require(
            bool(jobs)
            and len({job.get("id") for job in jobs}) == len(jobs)
            and any(job.get("conclusion") == "success" for job in jobs)
            and all(
                type(job.get("id")) is int
                and job["id"] > 0
                and job.get("run_id") == run["id"]
                and job.get("run_attempt") == 1
                and job.get("head_sha") == revision
                and job.get("status") == "completed"
                and job.get("conclusion") in {"success", "skipped"}
                for job in jobs
            ),
            "own-Main CI native jobs differ",
        )
        clocks = [datetime.fromisoformat(run[key]) for key in ("created_at", "updated_at")]
        clocks += [
            datetime.fromisoformat(job["completed_at"])
            for job in jobs
            if job.get("completed_at") is not None
        ]
        require(
            all(
                clock.tzinfo is not None and clock <= now < clock + timedelta(hours=24)
                for clock in clocks
            )
            and clocks[0] <= clocks[1],
            "own-Main CI original normal24 clocks expired or differ",
        )
        run_keys = (
            "id",
            "path",
            "event",
            "head_sha",
            "head_branch",
            "run_attempt",
            "status",
            "conclusion",
            "created_at",
            "updated_at",
        )
        job_keys = (
            "id",
            "name",
            "run_id",
            "run_attempt",
            "head_sha",
            "status",
            "conclusion",
            "started_at",
            "completed_at",
        )
        run_facts = {key: run[key] for key in run_keys}
        for key in ("repository", "head_repository"):
            run_facts[key] = {field: run[key][field] for field in ("full_name", "id")}
        result.append(
            {
                "run": run_facts,
                "jobs": [
                    {key: job.get(key) for key in job_keys}
                    for job in sorted(jobs, key=lambda value: value["id"])
                ],
            }
        )
    return result


def _read_core(revision: str, repository_id: int) -> list[dict[str, Any]]:
    rows = []
    for path in PRODUCT_CORE:
        if revision == PRODUCT:
            identifier = PRODUCT_CORE[path]
        else:
            pages = _api(
                f"repos/{TRUSTED_REPOSITORY}/actions/workflows/{Path(path).name}/runs"
                f"?event=push&head_sha={revision}&per_page=100",
                paginate=True,
            )
            runs = [run for page in pages for run in page["workflow_runs"]]
            require(len(runs) == 1, "controller own-Main workflow run is missing or ambiguous")
            require(
                runs[0].get("run_attempt") == 1, "controller own-Main CI latest attempt differs"
            )
            identifier = runs[0]["id"]
        endpoint = f"repos/{TRUSTED_REPOSITORY}/actions/runs/{identifier}/attempts/1"
        run = _api(endpoint)
        pages = _api(endpoint + "/jobs?per_page=100", paginate=True)
        rows.append({"run": run, "jobs": [job for page in pages for job in page["jobs"]]})
    return verify_core_ci(
        rows, revision=revision, repository_id=repository_id, now=datetime.now(UTC)
    )


def controller_context(
    *,
    repository: str,
    revision: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    zip_sha256: str,
    manifest_sha256: str | None,
) -> tuple[int, dict[str, Any]]:
    require_source_coordinates(
        revision=revision,
        run_id=run_id,
        run_attempt=run_attempt,
        artifact_id=artifact_id,
        zip_sha256=zip_sha256,
        manifest_sha256=manifest_sha256,
    )
    controller = os.environ.get("GITHUB_SHA", "")
    repository_id = verify_promotion_controller(
        dict(os.environ), repository=repository, revision=controller
    )
    proof = classify(Path.cwd(), controller)
    require(proof["mode"] == MODE, "explicit fixed controller proof required")
    require(
        _api(f"repos/{repository}/git/ref/heads/main")["object"]["sha"] == controller,
        "controller is no longer actual Main",
    )
    proof["product_core"] = _read_core(PRODUCT, repository_id)
    proof["controller_core"] = _read_core(controller, repository_id)
    proof["repository_id"] = repository_id
    return repository_id, proof


def promotion_binding(source: dict[str, Any]) -> dict[str, Any]:
    context = source["controller_context"]
    require_source_coordinates(
        revision=source["product_revision"],
        run_id=source["source_run_id"],
        run_attempt=source["source_run_attempt"],
        artifact_id=source["artifact_id"],
        zip_sha256=source["artifact_sha256"],
        manifest_sha256=SEAL_SHA256,
    )
    require(
        source["repository"] == TRUSTED_REPOSITORY
        and context["mode"] == MODE
        and context["product_revision"] == PRODUCT
        and context["product_tree"] == PRODUCT_TREE,
        "fixed promotion source context differs",
    )
    now = datetime.now(UTC)
    for key, revision in (
        ("product_core", PRODUCT),
        ("controller_core", context["controller_revision"]),
    ):
        require(
            verify_core_ci(
                context[key], revision=revision, repository_id=context["repository_id"], now=now
            )
            == context[key],
            "promotion native CI facts are not canonical",
        )
    keys = (
        "repository",
        "product_revision",
        "source_run_id",
        "source_run_attempt",
        "source_producer_job_id",
        "artifact_id",
        "artifact_sha256",
    )
    return {
        "repository": TRUSTED_REPOSITORY,
        "product_revision": PRODUCT,
        "oci_artifact_id": ARTIFACT,
        "oci_artifact_sha256": ZIP_SHA256,
        "candidate_manifest_sha256": SEAL_SHA256,
        "source_proof": {key: source[key] for key in keys},
        "controller_context": context,
    }


def check_wheel(path: Path) -> None:
    """Inspect build metadata as data; never import the candidate package."""
    with zipfile.ZipFile(path) as archive:
        require(archive.testzip() is None, "wheel CRC failed")
        require(len(archive.namelist()) == len(set(archive.namelist())), "duplicate wheel member")
        tree = ast.parse(archive.read("omnigent/_build_info.py").decode())
        values = {
            node.target.id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        }
        require(
            values.get("COMMIT_SHA") == PRODUCT
            and type(values.get("BUILD_TIME_EPOCH")) is int
            and values["BUILD_TIME_EPOCH"] == PRODUCT_EPOCH,
            "wheel does not bind actual fixed product checkout and epoch",
        )
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        require(
            len(metadata) == 1
            and "\nVersion: 0.21.0.dev20261031\n" in archive.read(metadata[0]).decode(),
            "wheel target version differs",
        )


def resolve_trusted_main_source(
    *,
    repository: str,
    revision: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    zip_sha256: str,
    controller_profile: str = MODE,
    manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Keep fixed-controller intake outside the unchanged legacy OCI module."""
    require(controller_profile == MODE, "explicit fixed controller profile required")
    repository_id, context = controller_context(
        repository=repository,
        revision=revision,
        run_id=run_id,
        run_attempt=run_attempt,
        artifact_id=artifact_id,
        zip_sha256=zip_sha256,
        manifest_sha256=manifest_sha256,
    )
    endpoint = f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
    run = _api(endpoint)
    pages = _api(endpoint + "/jobs?per_page=100", paginate=True)
    artifact = _api(f"repos/{repository}/actions/artifacts/{artifact_id}")
    source = oci_promotion.verify_trusted_main_source(
        run,
        [job for page in pages for job in page["jobs"]],
        artifact,
        repository=repository,
        repository_id=repository_id,
        revision=revision,
        run_id=run_id,
        run_attempt=run_attempt,
        artifact_id=artifact_id,
        zip_sha256=zip_sha256,
    )
    source["controller_context"] = context
    return source


def trusted_main_intake(args: argparse.Namespace) -> None:
    """Reuse native source validation and transfer; never override signer identity."""
    require(
        args.root is not None
        and args.revision == PRODUCT
        and args.source_date_epoch == PRODUCT_EPOCH,
        "fixed intake requires the original product and epoch",
    )
    source = resolve_trusted_main_source(
        repository=args.repository,
        revision=args.revision,
        run_id=int(args.run_id),
        run_attempt=args.run_attempt,
        artifact_id=args.artifact_id,
        zip_sha256=args.artifact_sha256,
        manifest_sha256=args.manifest_sha256,
        controller_profile=args.controller_profile,
    )
    if args.command == "verify-trusted-main":
        print(json.dumps(source, sort_keys=True))
        return
    oci_promotion.download_artifact(
        f"repos/{args.repository}/actions/artifacts/{args.artifact_id}",
        args.root,
        zip_sha256=args.artifact_sha256,
    )
    manifest_path = args.root / oci_promotion.MANIFEST_NAME
    require(
        oci_promotion.file_sha256(manifest_path) == args.manifest_sha256,
        "candidate seal digest mismatch",
    )
    manifest = read_json(manifest_path)
    labels = oci_promotion.expected_labels(Path.cwd(), PRODUCT)
    require(
        manifest.get("product_revision") == PRODUCT
        and manifest.get("source_date_epoch") == PRODUCT_EPOCH
        and manifest.get("labels") == labels
        and set(manifest.get("images", {})) == set(oci_promotion.IMAGES)
        and all(
            set(manifest["images"][name]["facts"]["platforms"]) == set(oci_promotion.PLATFORMS)
            for name in oci_promotion.IMAGES
        ),
        "transferred candidate source or platform set differs",
    )
    source["candidate_manifest_sha256"] = args.manifest_sha256
    source["state"] = "trusted_source_transferred_requires_current_prepare"
    (args.root / "promotion-source.json").write_text(
        json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "classify",
            "predicate",
            "verify-predicate",
            "check-wheel",
            "download-trusted-main",
            "verify-trusted-main",
        ),
    )
    parser.add_argument("--candidate-revision")
    parser.add_argument("--source-proof", type=Path)
    parser.add_argument("--policy-revision")
    parser.add_argument("--run-id")
    parser.add_argument("--attempt")
    parser.add_argument("--subject")
    parser.add_argument(
        "--verification", "--verification-json", dest="verification_json", type=Path
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--artifact-sha256")
    parser.add_argument("--run-attempt", type=int)
    parser.add_argument("--repository")
    parser.add_argument("--controller-profile", choices=(MODE,), default=MODE)
    args = parser.parse_args()
    if args.command in {"download-trusted-main", "verify-trusted-main"}:
        trusted_main_intake(args)
        return 0
    if args.command == "classify":
        print(json.dumps(classify(Path.cwd(), args.candidate_revision), sort_keys=True))
        return 0
    if args.command == "check-wheel":
        check_wheel(args.wheel)
        print(json.dumps({"verified": True, "product_revision": PRODUCT}, sort_keys=True))
        return 0
    binding = promotion_binding(read_json(args.source_proof))
    controller = binding["controller_context"]["controller_revision"]
    require(
        args.policy_revision == controller, "explicit policy revision differs from source proof"
    )
    predicate = build_promotion_predicate(
        binding, TRUSTED_WORKFLOW, controller, args.run_id, args.attempt
    )
    if args.command == "predicate":
        serialized = json.dumps(predicate, sort_keys=True) + "\n"
        if args.output is not None:
            args.output.write_text(serialized, encoding="utf-8")
        else:
            print(serialized, end="")
    else:
        entries = json.loads(args.verification_json.read_text(encoding="utf-8"))
        verify_predicate(
            entries,
            subject=args.subject,
            predicate=predicate,
            predicate_type="https://slsa.dev/provenance/v1",
            claims=build_certificate_claims(
                TRUSTED_REPOSITORY, controller, TRUSTED_WORKFLOW, args.run_id, args.attempt
            ),
        )
        print(json.dumps({"verified": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
