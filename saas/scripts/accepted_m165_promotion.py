"""Sign the actual recovered M165 product under its separate protected controller."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import re
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts import accepted_m165_clean_context as clean
from saas.scripts import accepted_oci_recovery as recovery
from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.oci_promotion import (
    MANIFEST_NAME,
    expected_labels,
    extract_artifact,
    read_json,
    require,
    verify_candidate,
)
from saas.scripts.resume_oci_promotion import (
    PREDICATE_TYPE,
    build_certificate_claims,
    build_promotion_predicate,
    verify_predicate,
    verify_sbom,
)
from saas.scripts.scan_oci_candidates import file_sha256

PRODUCT = recovery.PRODUCT
EPOCH = recovery.EPOCH
REPOSITORY = recovery.REPOSITORY
WORKFLOW = ".github/workflows/saas-oci-promotion-accepted-m165.yml"
CI_PATHS = (
    ".github/workflows/saas-upstream-compat.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/saas-n1-compat-image.yml",
)


def api(endpoint: str) -> dict[str, Any]:
    return json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))


def producer_run_id() -> int:
    value = os.environ.get("OMNIGENT_M165_PRODUCER_RUN", "")
    require(
        re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None,
        "explicit actual producer run required",
    )
    return int(value)


def verify_controller_sources(controller: str, policy: str) -> dict[str, str]:
    require(
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", controller, policy],
            capture_output=True,
        ).returncode
        == 0,
        "producer controller is not an ancestor of the signing policy",
    )
    excluded = {"saas/scripts/accepted_m165_promotion.py", "saas/scripts/resume_oci_promotion.py"}
    trees = []
    for revision in (controller, policy):
        rows = subprocess.check_output(
            ["git", "ls-tree", "-r", revision, "--", "saas", recovery.WORKFLOW], text=True
        ).splitlines()
        require(
            any(row.endswith("\t" + recovery.WORKFLOW) for row in rows),
            "reviewed producer workflow is missing",
        )
        trees.append("\n".join(row for row in rows if row.split("\t", 1)[1] not in excluded))
    require(bool(trees[0]) and trees[0] == trees[1], "reviewed producer execution tree differs")
    return {"protected_execution_tree_sha256": hashlib.sha256(trees[0].encode()).hexdigest()}


def verify_policy_ci(run: dict[str, Any], path: str, policy: str) -> None:
    require(
        run.get("head_sha") == policy
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("path") == path
        and run.get("run_attempt") == 1
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "signing controller own Main CI is not successful",
    )


def verify_producer(run: dict[str, Any], job: dict[str, Any], builder: dict[str, Any]) -> None:
    require(
        run.get("id") == producer_run_id()
        and re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", "")) is not None
        and run.get("head_sha") != PRODUCT
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == recovery.WORKFLOW
        and run.get("run_attempt") == 1
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and type(job.get("id")) is int
        and job["id"] > 0
        and job.get("run_id") == producer_run_id()
        and job.get("run_attempt") == 1
        and job.get("name") == "scan-and-admit-same-oci"
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in job.get("labels", [])
        and type(builder.get("id")) is int
        and builder["id"] > 0
        and builder.get("run_id") == producer_run_id()
        and builder.get("run_attempt") == 1
        and builder.get("name") == "build-accepted-product"
        and builder.get("status") == "completed"
        and builder.get("conclusion") == "success"
        and builder.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in builder.get("labels", [])
        and all(
            any(
                step.get("name") == name and step.get("conclusion") == "success"
                for step in builder.get("steps", [])
            )
            for name in (
                "Authenticate retained failed parent and prove current frozen source "
                "on both architectures",
                "Independently build only Server without cache for the clean retained first",
                "Confirm actual independent Server pair and unchanged historical Host pair",
                "Preserve actual OCI before any fresh vulnerability scan",
            )
        ),
        "actual recovered producer and successful hosted scan/build jobs differ",
    )


def verify_artifact(metadata: dict[str, Any], name: str, maximum: int, *, controller: str) -> None:
    require(
        re.fullmatch(r"[0-9a-f]{40}", controller) is not None
        and type(metadata.get("id")) is int
        and metadata["id"] > 0
        and metadata.get("name") == name
        and metadata.get("expired") is False
        and re.fullmatch(r"sha256:[0-9a-f]{64}", metadata.get("digest", "")) is not None
        and metadata.get("workflow_run", {}).get("id") == producer_run_id()
        and metadata.get("workflow_run", {}).get("head_sha") == controller
        and type(metadata.get("size_in_bytes")) is int
        and 0 < metadata["size_in_bytes"] <= maximum,
        "recovered native artifact identity differs",
    )


def download_metadata(metadata: dict[str, Any], archive: Path, root: Path) -> None:
    digest = metadata["digest"].removeprefix("sha256:")
    download_artifact_bytes(
        metadata["id"], archive, expected_size=metadata["size_in_bytes"], expected_sha256=digest
    )
    extract_artifact(archive, root, zip_sha256=digest)


def report_binding(root: Path, completed_at: str) -> dict[str, Any]:
    """Authenticate reports; full OCI/component admission still happens after download."""
    manifest = read_json(root / MANIFEST_NAME)
    comparison = read_json(root / "saas-image-candidate.json")
    original = recovery.original_report(root / "original-report.zip")
    proof = read_json(root / "clean-context-first.json")
    detail = comparison.get("clean_context_reproducibility", {})
    unchanged = copy.deepcopy(original)
    unchanged["images"]["omnigent-saas-server"] = comparison["images"]["omnigent-saas-server"]
    unchanged["clean_context_reproducibility"] = detail
    repeated = comparison["images"]["omnigent-saas-server"]
    expected_detail = {
        **{key: value for key, value in proof.items() if key != "facts"},
        "first_proof_sha256": file_sha256(root / "clean-context-first.json"),
        "independent_Server_archive_sha256": detail.get("independent_Server_archive_sha256"),
        "Host_rebuilt_in_this_confirmation": False,
    }
    require(
        comparison == unchanged
        and proof.get("kind") == clean.KIND
        and proof.get("product_revision") == PRODUCT
        and proof.get("product_tree") == clean.TREE
        and proof.get("source_date_epoch") == EPOCH
        and proof.get("parent_raw_checkpoint") == clean.PARENT
        and proof.get("old_Server_byte_identity_claimed") is False
        and detail == expected_detail
        and re.fullmatch(r"[0-9a-f]{64}", detail.get("independent_Server_archive_sha256", ""))
        is not None
        and set(proof.get("source_proofs", {})) == {"linux/amd64", "linux/arm64"}
        and repeated.get("matching_platform_manifest_and_config") is True
        and repeated.get("history_created_by_equal") is True
        and repeated.get("first") == proof.get("facts", {}).get("server")
        and repeated.get("second", {}).get("platforms") == repeated["first"]["platforms"]
        and repeated.get("second", {}).get("attestations") == repeated["first"]["attestations"]
        and proof.get("facts", {}).get("host")
        == original["images"]["omnigent-saas-host"]["first"],
        "actual clean Server confirmation or historical Host identity differs",
    )
    completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    sealed = datetime.fromisoformat(manifest["sealed_at"])
    require(
        completed.tzinfo is not None
        and sealed.tzinfo is not None
        and sealed <= completed <= datetime.now(UTC)
        and manifest.get("schema_version") == 1
        and manifest.get("evidence_kind") == "immutable_oci_promotion_candidate"
        and manifest.get("product_revision") == PRODUCT
        and manifest.get("source_date_epoch") == EPOCH
        and manifest.get("labels") == expected_labels(Path.cwd(), PRODUCT)
        and manifest.get("comparison_sha256") == file_sha256(root / "saas-image-candidate.json")
        and set(manifest.get("images", {})) == {"server", "host"},
        "recovered seal source/time/labels differ",
    )
    scans = manifest["scans"]
    require(
        file_sha256(root / "grype/candidate-scan-summary.json") == scans["summary_sha256"]
        and set(scans["reports"])
        == {
            f"grype/{role}-{arch}-grype.json"
            for role in ("server", "host")
            for arch in ("amd64", "arm64")
        }
        and all(file_sha256(root / name) == digest for name, digest in scans["reports"].items()),
        "recovered original four raw reports differ",
    )
    for role, image in manifest["images"].items():
        require(
            image["facts"] == comparison["images"][f"omnigent-saas-{role}"]["first"]
            and re.fullmatch(r"sha256:[0-9a-f]{64}", image["index_digest"]) is not None,
            "recovered executable facts or actual index differs",
        )
    return manifest


def preflight(root: Path, policy: str) -> dict[str, Any]:
    require(
        re.fullmatch(r"[0-9a-f]{40}", policy) is not None and policy != PRODUCT,
        "explicit signing controller required",
    )
    prefix = f"repos/{REPOSITORY}/actions"
    policy_evidence = {}
    for path in CI_PATHS:
        runs = api(
            f"{prefix}/workflows/{path.rsplit('/', 1)[-1]}/runs"
            f"?head_sha={policy}&event=push&branch=main&per_page=100"
        )["workflow_runs"]
        require(bool(runs), "signing controller own Main CI is missing")
        latest = max(runs, key=lambda run: (run["id"], run["run_attempt"]))
        verify_policy_ci(latest, path, policy)
        policy_evidence[path] = latest["id"]
    product_ci = {}
    for identifier, path in recovery.CI.items():
        original_ci = api(f"{prefix}/runs/{identifier}")
        recovery.verify_product_ci(original_ci, identifier, path)
        product_ci[path] = {
            key: original_ci.get(key)
            for key in (
                "id",
                "head_sha",
                "head_branch",
                "event",
                "path",
                "run_attempt",
                "status",
                "conclusion",
            )
        }
    producer = producer_run_id()
    run = api(f"{prefix}/runs/{producer}")
    jobs = api(f"{prefix}/runs/{producer}/attempts/1/jobs?per_page=100")["jobs"]
    matching = [job for job in jobs if job.get("name") == "scan-and-admit-same-oci"]
    require(len(matching) == 1, "actual successful scan producer missing or ambiguous")
    job = matching[0]
    builders = [item for item in jobs if item.get("name") == "build-accepted-product"]
    require(len(builders) == 1, "actual raw builder missing or ambiguous")
    verify_producer(run, job, builders[0])
    controller = run["head_sha"]
    controller_sources = verify_controller_sources(controller, policy)
    artifacts = api(f"{prefix}/runs/{producer}/artifacts?per_page=100")["artifacts"]
    selected = {}
    for kind, name, maximum in (
        ("raw", f"accepted-raw-{PRODUCT}-{producer}", 16 * 1024**3),
        ("oci", f"saas-oci-promotion-{PRODUCT}", 16 * 1024**3),
        ("report", f"accepted-same-oci-scan-{producer}", 32 * 1024**2),
    ):
        rows = [item for item in artifacts if item.get("name") == name]
        require(len(rows) == 1, "actual recovered artifact missing or ambiguous")
        verify_artifact(rows[0], name, maximum, controller=controller)
        selected[kind] = rows[0]
    download_metadata(selected["report"], root.with_suffix(".zip"), root)
    original = root / "original-report.zip"
    if not original.exists():
        download_artifact_bytes(
            recovery.REPORT_ID,
            original,
            expected_size=recovery.REPORT_SIZE,
            expected_sha256=recovery.REPORT_SHA,
        )
    manifest = report_binding(root, job["completed_at"])
    result = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "product_revision": PRODUCT,
        "source_date_epoch": EPOCH,
        "candidate_run_id": producer,
        "candidate_run_attempt": 1,
        "candidate_controller_revision": controller,
        "candidate_build_job_id": builders[0]["id"],
        "candidate_build_completed_at": builders[0]["completed_at"],
        "candidate_manifest_sha256": file_sha256(root / MANIFEST_NAME),
        "native_run": {
            key: run.get(key)
            for key in (
                "id",
                "head_sha",
                "head_branch",
                "event",
                "path",
                "run_attempt",
                "status",
                "conclusion",
            )
        },
        "native_builder_job": {
            key: builders[0].get(key)
            for key in (
                "id",
                "run_id",
                "run_attempt",
                "name",
                "status",
                "conclusion",
                "labels",
                "runner_group_name",
            )
        },
        "native_scan_job": {
            key: job.get(key)
            for key in (
                "id",
                "run_id",
                "run_attempt",
                "name",
                "status",
                "conclusion",
                "labels",
                "runner_group_name",
            )
        },
        "accepted_product_main_ci": product_ci,
        "parent_raw_checkpoint": clean.PARENT,
        "comparison_profile": "clean-M165-server",
        "producer_control_equivalence": controller_sources,
        "clean_context_first_sha256": file_sha256(root / "clean-context-first.json"),
        "artifacts": selected,
        "images": {role: image["index_digest"] for role, image in manifest["images"].items()},
        "oci_artifact_id": selected["oci"]["id"],
        "oci_artifact_sha256": selected["oci"]["digest"].removeprefix("sha256:"),
        "rebuilt": True,
        "signing_rebuilt_oci": False,
        "production_authority": False,
    }
    binding_path().write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            stream.write(f"manifest-sha256={result['candidate_manifest_sha256']}\n")
            stream.write(f"oci-artifact-id={result['oci_artifact_id']}\n")
            stream.write(f"oci-artifact-sha256={result['oci_artifact_sha256']}\n")
    return {
        "state": "NATIVE_PRODUCER_AUTHENTICATED_FULL_OCI_ADMISSION_PENDING",
        "binding": result,
        "controller_own_Main_CI": policy_evidence,
    }


def binding_path() -> Path:
    require(bool(os.environ.get("OMNIGENT_M165_BINDING")), "explicit native binding path required")
    return Path(os.environ["OMNIGENT_M165_BINDING"])


def binding() -> dict[str, Any]:
    value = read_json(binding_path())
    require(
        value.get("schema_version") == 1
        and value.get("repository") == REPOSITORY
        and value.get("product_revision") == PRODUCT
        and value.get("source_date_epoch") == EPOCH
        and value.get("candidate_run_id") == producer_run_id()
        and value.get("candidate_run_attempt") == 1
        and value.get("candidate_controller_revision")
        == value.get("native_run", {}).get("head_sha")
        and re.fullmatch(r"[0-9a-f]{40}", value.get("candidate_controller_revision", ""))
        is not None
        and value.get("candidate_controller_revision") != PRODUCT
        and value.get("candidate_build_job_id") == value.get("native_builder_job", {}).get("id")
        and value.get("parent_raw_checkpoint") == clean.PARENT
        and value.get("comparison_profile") == "clean-M165-server"
        and value.get("rebuilt") is True
        and value.get("signing_rebuilt_oci") is False
        and value.get("production_authority") is False,
        "fixed recovered product binding differs",
    )
    return value


def download(root: Path) -> None:
    value = binding()
    metadata = api(f"repos/{REPOSITORY}/actions/artifacts/{value['oci_artifact_id']}")
    require(
        metadata == value["artifacts"]["oci"], "immutable OCI metadata changed after preflight"
    )
    verify_artifact(
        metadata,
        f"saas-oci-promotion-{PRODUCT}",
        16 * 1024**3,
        controller=value["candidate_controller_revision"],
    )
    download_metadata(metadata, root.with_suffix(".zip"), root)
    verify_candidate(
        root,
        manifest_sha256=value["candidate_manifest_sha256"],
        labels=expected_labels(Path.cwd(), PRODUCT),
        source_date_epoch=EPOCH,
    )
    require(
        file_sha256(root / "clean-context-first.json") == value["clean_context_first_sha256"]
        and clean.verify_first(root, Path.cwd()) == read_json(root / "clean-context-first.json"),
        "actual sealed OCI source or retained parent lineage differs",
    )


def predicate(policy: str, run: str, attempt: str, *, wheel: bool = False) -> dict[str, Any]:
    value = build_promotion_predicate(binding(), WORKFLOW, policy, run, attempt)
    value["buildDefinition"]["externalParameters"]["oci_rebuild_performed"] = False
    if wheel:
        value["buildDefinition"]["externalParameters"]["wheel_build_performed"] = True
    return value


def check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        require(archive.testzip() is None, "wheel CRC failed")
        tree = ast.parse(archive.read("omnigent/_build_info.py").decode())
        values = {
            node.target.id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        }
        require(
            values.get("COMMIT_SHA") == PRODUCT and values.get("BUILD_TIME_EPOCH") == EPOCH,
            "wheel does not bind actual product checkout and epoch",
        )
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        require(
            len(metadata) == 1
            and "\nVersion: 0.21.0.dev20261031\n" in archive.read(metadata[0]).decode(),
            "wheel target version differs",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "preflight",
            "download",
            "child",
            "predicate",
            "wheel-predicate",
            "check-wheel",
            "verify",
            "verify-wheel",
            "verify-sbom",
        ),
    )
    parser.add_argument("--root", type=Path)
    parser.add_argument("--policy-revision")
    parser.add_argument("--run-id")
    parser.add_argument("--attempt")
    parser.add_argument("--role", choices=("server", "host"))
    parser.add_argument("--architecture", choices=("amd64", "arm64"))
    parser.add_argument("--verification", type=Path)
    parser.add_argument("--subject")
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--wheel", type=Path)
    args = parser.parse_args()
    if args.command == "preflight":
        print(json.dumps(preflight(args.root, args.policy_revision)))
    elif args.command == "download":
        download(args.root)
    elif args.command == "check-wheel":
        check_wheel(args.wheel)
    elif args.command == "child":
        value = binding()
        manifest = read_json(args.root / MANIFEST_NAME)
        require(
            file_sha256(args.root / MANIFEST_NAME) == value["candidate_manifest_sha256"]
            and manifest["images"][args.role]["index_digest"] == value["images"][args.role],
            "child seal differs",
        )
        digest = manifest["images"][args.role]["facts"]["platforms"][f"linux/{args.architecture}"][
            "manifest_digest"
        ]
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None, "child digest differs")
        print(f"ghcr.io/dream1216/omnigent-saas-{args.role}@{digest}")
    elif args.command in ("predicate", "wheel-predicate"):
        print(
            json.dumps(
                predicate(
                    args.policy_revision,
                    args.run_id,
                    args.attempt,
                    wheel=args.command == "wheel-predicate",
                )
            )
        )
    else:
        entries = json.loads(args.verification.read_text())
        claims = build_certificate_claims(
            REPOSITORY, args.policy_revision, WORKFLOW, args.run_id, args.attempt
        )
        if args.command == "verify-sbom":
            verify_sbom(
                entries, subject=args.subject, predicate=read_json(args.sbom), claims=claims
            )
        else:
            if args.command == "verify":
                require(
                    args.subject in binding()["images"].values(),
                    "subject is not admitted image index",
                )
            verify_predicate(
                entries,
                subject=args.subject,
                predicate=predicate(
                    args.policy_revision,
                    args.run_id,
                    args.attempt,
                    wheel=args.command == "verify-wheel",
                ),
                predicate_type=PREDICATE_TYPE,
                claims=claims,
            )


if __name__ == "__main__":
    main()
