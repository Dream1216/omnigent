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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from saas.scripts import accepted_m165_clean_context as clean
from saas.scripts import accepted_oci_recovery as recovery
from saas.scripts import scan_oci_candidates as scan
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
from saas.scripts.scan_oci_candidates import (
    TEMPORARY_DATABASE_AGE,
    TEMPORARY_DATABASE_AGE_SHA256,
    file_sha256,
    parse_database_status,
)

PRODUCT = recovery.PRODUCT
EPOCH = recovery.EPOCH
PROFILE = "M165"
REPOSITORY = recovery.REPOSITORY
WORKFLOW = ".github/workflows/saas-oci-promotion-accepted-m165.yml"
CI_PATHS = (
    ".github/workflows/saas-upstream-compat.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/saas-n1-compat-image.yml",
)


def configure_product_profile(name: str) -> None:
    global PRODUCT, EPOCH, PROFILE
    require(
        name in {"M165", "M8c-retained-first", "M8c-clean-context"},
        "unapproved accepted product profile",
    )
    PROFILE = name
    PRODUCT, EPOCH = (
        (recovery.M8C_PRODUCT, recovery.M8C_EPOCH)
        if name != "M165"
        else (recovery.PRODUCT, recovery.EPOCH)
    )


def _m8c() -> bool:
    return PRODUCT == recovery.M8C_PRODUCT


def _m8c_clean() -> bool:
    return _m8c() and PROFILE == "M8c-clean-context"


def _comparison_profile() -> str:
    if _m8c_clean():
        return "clean-M8c-server-pair"
    return "retained-M8c-first-server" if _m8c() else "clean-M165-server"


def _original_m8c_server(*, promoted: bool) -> dict[str, Any]:
    return {
        "artifact": {
            "id": recovery.M8C_FIRST[0],
            "bytes": recovery.M8C_FIRST[1],
            "sha256": recovery.M8C_FIRST[2],
        },
        "archive_sha256": recovery.M8C_FIRST_SHA256,
        "index_digest": recovery.M8C_INDEX,
        **({"promoted": False} if not promoted else {"never_rebuilt": True}),
    }


def _m8c_recovery_scope() -> dict[str, Any]:
    if _m8c_clean():
        return {"builds_performed": 4, "server": 2, "host": 2, "original_Server_reused": False}
    return {"missing_builds_performed": 3, "first_Server_reused": True}


def _scan_job_name() -> str:
    return "scan-and-admit-m8c-same-oci" if _m8c() else "scan-and-admit-same-oci"


def _build_job_name() -> str:
    return "complete-m8c-first-server" if _m8c() else "build-accepted-product"


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
    if _m8c():
        recovery.verify_m8c_recovery_run(run, job, run.get("head_sha", ""), _scan_job_name())
        recovery.verify_m8c_recovery_run(run, builder, run.get("head_sha", ""), _build_job_name())
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
        and job.get("name") == _scan_job_name()
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in job.get("labels", [])
        and type(builder.get("id")) is int
        and builder["id"] > 0
        and builder.get("run_id") == producer_run_id()
        and builder.get("run_attempt") == 1
        and builder.get("name") == _build_job_name()
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
                (
                    "Build new clean M8c Server attempt 1",
                    "Verify new clean M8c Server SDK on both architectures",
                    "Prove clean M8c source and preflight before independent builds",
                    "Preserve cached original M8c Server as history only",
                    *(
                        "Authenticate and retain exact original M8c first Server",
                        "Complete original Server preflight before missing builds",
                        "Independently build only missing M8c Server attempt 2",
                        "Build only missing M8c Host attempt 1",
                        "Independently build only missing M8c Host attempt 2",
                        "Compare exact original M8c independent Server and Host pairs",
                        "Retain complete original M8c four OCI raw checkpoint",
                    ),
                )
                if _m8c_clean()
                else (
                    "Authenticate and retain exact original M8c first Server",
                    "Complete original Server preflight before missing builds",
                    "Independently build only missing M8c Server attempt 2",
                    "Build only missing M8c Host attempt 1",
                    "Independently build only missing M8c Host attempt 2",
                    "Compare exact original M8c independent Server and Host pairs",
                    "Retain complete original M8c four OCI raw checkpoint",
                )
                if _m8c()
                else (
                    "Authenticate retained failed parent and prove current frozen source "
                    "on both architectures",
                    "Independently build only Server without cache for the clean retained first",
                    "Confirm actual independent Server pair and unchanged historical Host pair",
                    "Preserve actual OCI before any fresh vulnerability scan",
                )
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
    if _m8c():
        proof = read_json(root / "m8c-retained-origin.json")
        raw = read_json(root / "unadmitted-build.json")
        require(
            proof.get("kind") == "accepted_M8c_original_Server/v1"
            and proof.get("product_revision") == PRODUCT
            and proof.get("product_tree") == recovery.M8C_TREE
            and proof.get("source_date_epoch") == EPOCH
            and proof.get("original_run_id") == recovery.M8C_RUN
            and proof.get("original_job_id") == recovery.M8C_JOB
            and proof.get("first_archive_sha256") == recovery.M8C_FIRST_SHA256
            and raw.get("kind")
            == (
                "accepted_M8c_complete_clean_context/v1"
                if _m8c_clean()
                else "accepted_M8c_complete_retained_first/v1"
            )
            and raw.get("original_first_archive_sha256") == recovery.M8C_FIRST_SHA256
            and (
                _m8c_clean()
                or (
                    manifest.get("images", {}).get("server", {}).get("archive_sha256")
                    == recovery.M8C_FIRST_SHA256
                    and manifest["images"]["server"]["index_digest"] == recovery.M8C_INDEX
                    and manifest["images"]["server"]["facts"] == proof.get("first_facts")
                )
            )
            and comparison.get("status") == "pass"
            and comparison.get("violations") == [],
            "M8c original parent, Server or complete comparison differs",
        )
        if _m8c_clean():
            first = read_json(root / "clean-context-first.json")
            require(
                first.get("kind") == "accepted_M8c_clean_context_first/v1"
                and first.get("product_revision") == PRODUCT
                and first.get("product_tree") == recovery.M8C_TREE
                and first.get("source_date_epoch") == EPOCH
                and first.get("host_bytecode_members") == 0
                and first.get("original_Server_promoted") is False
                and first.get("origin_sha256") == file_sha256(root / "m8c-retained-origin.json")
                and first.get("SDK_sha256") == file_sha256(root / "server-candidate-runtime.json")
                and first.get("archive_sha256")
                == manifest["images"]["server"]["archive_sha256"]
                != recovery.M8C_FIRST_SHA256
                and first.get("facts") == manifest["images"]["server"]["facts"]
                and set(first.get("source_proofs", {})) == {"linux/amd64", "linux/arm64"}
                and raw.get("clean_context_first_sha256")
                == file_sha256(root / "clean-context-first.json")
                and raw.get("original_Server_promoted") is False
                and raw.get("recovery_builds") == {"server": 2, "host": 2},
                "new clean M8c source, executable SDK or accurate recovery scope differs",
            )
        for role in ("server", "host"):
            repeated = comparison["images"][f"omnigent-saas-{role}"]
            require(
                repeated.get("matching_platform_manifest_and_config") is True
                and repeated.get("history_created_by_equal") is True,
                "M8c actual independent pair differs",
            )
            for attempt, name in ((1, "first"), (2, "second")):
                require(
                    raw["images"][f"{role}-{attempt}.tar"]["facts"] == repeated[name],
                    "M8c original four OCI raw proof differs",
                )
    else:
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
    summary = read_json(root / "grype/candidate-scan-summary.json")
    finite_reports = {}
    for row in summary.get("images", []):
        disposition = row.get("database_age_disposition")
        if disposition is None:
            continue
        role, platform = row["image"], row["platform"]
        relative = f"grype/{role}-{platform.split('/')[-1]}-grype.json"
        raw = read_json(root / relative)
        parse_database_status(
            raw["descriptor"]["db"]["status"],
            now=datetime.now(UTC),
            subject=raw["source"]["target"],
            database_age_disposition=disposition,
            report_sha256=file_sha256(root / relative),
        )
        subject, image = disposition["subject"], manifest["images"][role]
        require(
            subject["image"] == role
            and subject["platform"] == platform
            and subject["archive_sha256"] == image["archive_sha256"]
            and subject["index_digest"] == image["index_digest"],
            "small report database context differs from the actual sealed OCI coordinate",
        )
        require(relative not in finite_reports, "finite database scan coordinate is duplicated")
        finite_reports[relative] = disposition
    expected_age = None
    if finite_reports:
        require(
            set(finite_reports) == set(scans["reports"]), "finite database reports omit a platform"
        )
        expected_age = {
            "rule": TEMPORARY_DATABASE_AGE,
            "rule_sha256": TEMPORARY_DATABASE_AGE_SHA256,
            "reports": finite_reports,
        }
    require(
        scans.get("temporary_database_age") == expected_age,
        "finite database signed scan binding differs",
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
    for identifier, path in (recovery.M8C_CI if _m8c() else recovery.CI).items():
        original_ci = api(f"{prefix}/runs/{identifier}")
        if _m8c():
            recovery._verify_product_ci(original_ci, identifier, path, PRODUCT)
        else:
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
    matching = [job for job in jobs if job.get("name") == _scan_job_name()]
    require(len(matching) == 1, "actual successful scan producer missing or ambiguous")
    job = matching[0]
    builders = [item for item in jobs if item.get("name") == _build_job_name()]
    require(len(builders) == 1, "actual raw builder missing or ambiguous")
    verify_producer(run, job, builders[0])
    controller = run["head_sha"]
    controller_sources = verify_controller_sources(controller, policy)
    artifacts = api(f"{prefix}/runs/{producer}/artifacts?per_page=100")["artifacts"]
    selected = {}
    for kind, name, maximum in (
        ("raw", f"accepted-raw-{PRODUCT}-{producer}", 16 * 1024**3),
        ("oci", f"saas-oci-promotion-{PRODUCT}", 16 * 1024**3),
        (
            "report",
            f"saas-image-candidate-{PRODUCT}" if _m8c() else f"accepted-same-oci-scan-{producer}",
            64 * 1024**2 if _m8c() else 32 * 1024**2,
        ),
    ):
        rows = [item for item in artifacts if item.get("name") == name]
        require(len(rows) == 1, "actual recovered artifact missing or ambiguous")
        verify_artifact(rows[0], name, maximum, controller=controller)
        selected[kind] = rows[0]
    download_metadata(selected["report"], root.with_suffix(".zip"), root)
    original = root / "original-report.zip"
    if not _m8c() and not original.exists():
        download_artifact_bytes(
            recovery.REPORT_ID,
            original,
            expected_size=recovery.REPORT_SIZE,
            expected_sha256=recovery.REPORT_SHA,
        )
    manifest = report_binding(root, job["completed_at"])
    if _m8c():
        require(
            read_json(root / "m8c-retained-origin.json").get("controller_revision") == controller,
            "M8c original raw operator differs",
        )
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
        "parent_raw_checkpoint": (
            {
                "run_id": recovery.M8C_RUN,
                "attempt": 1,
                "job_id": recovery.M8C_JOB,
                "conclusion": "failure",
            }
            if _m8c()
            else clean.PARENT
        ),
        "comparison_profile": _comparison_profile(),
        "producer_control_equivalence": controller_sources,
        ("retained_origin_sha256" if _m8c() else "clean_context_first_sha256"): file_sha256(
            root / ("m8c-retained-origin.json" if _m8c() else "clean-context-first.json")
        ),
        "artifacts": selected,
        "images": {role: image["index_digest"] for role, image in manifest["images"].items()},
        "oci_artifact_id": selected["oci"]["id"],
        "oci_artifact_sha256": selected["oci"]["digest"].removeprefix("sha256:"),
        "rebuilt": not _m8c(),
        "signing_rebuilt_oci": False,
        "production_authority": False,
    }
    if _m8c():
        result.update(
            {
                "product_tree": recovery.M8C_TREE,
                "runtime_evidence_revision": recovery.M8C_DATA,
                (
                    "original_first_server" if _m8c_clean() else "retained_first_server"
                ): _original_m8c_server(promoted=not _m8c_clean()),
                "recovery": _m8c_recovery_scope(),
            }
        )
        if _m8c_clean():
            result["clean_context_first_sha256"] = file_sha256(root / "clean-context-first.json")
    if "temporary_database_age" in manifest["scans"]:
        result["temporary_database_age"] = manifest["scans"]["temporary_database_age"]
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
        and value.get("parent_raw_checkpoint")
        == (
            {
                "run_id": recovery.M8C_RUN,
                "attempt": 1,
                "job_id": recovery.M8C_JOB,
                "conclusion": "failure",
            }
            if _m8c()
            else clean.PARENT
        )
        and value.get("comparison_profile") == _comparison_profile()
        and value.get("rebuilt") is (not _m8c())
        and value.get("signing_rebuilt_oci") is False
        and value.get("production_authority") is False,
        "fixed recovered product binding differs",
    )
    if _m8c():
        require(
            value.get("product_tree") == recovery.M8C_TREE
            and value.get("runtime_evidence_revision") == recovery.M8C_DATA
            and value.get("original_first_server" if _m8c_clean() else "retained_first_server")
            == _original_m8c_server(promoted=not _m8c_clean())
            and value.get("recovery") == _m8c_recovery_scope()
            and re.fullmatch(r"[0-9a-f]{64}", value.get("retained_origin_sha256", "")) is not None,
            "M8c fixed runtime data, original Server or completion scope differs",
        )
        if _m8c_clean():
            require(
                "retained_first_server" not in value
                and re.fullmatch(r"[0-9a-f]{64}", value.get("clean_context_first_sha256", ""))
                is not None,
                "clean M8c binding cannot claim to promote the cached original Server",
            )
    if "temporary_database_age" in value:
        age = value["temporary_database_age"]
        require(
            isinstance(age, dict)
            and set(age) == {"rule", "rule_sha256", "reports"}
            and hashlib.sha256(
                json.dumps(age["rule"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            == TEMPORARY_DATABASE_AGE_SHA256
            and age["rule_sha256"] == TEMPORARY_DATABASE_AGE_SHA256
            and set(age["reports"])
            == {
                f"grype/{role}-{arch}-grype.json"
                for role in ("server", "host")
                for arch in ("amd64", "arm64")
            },
            "signed finite database age rule or report matrix differs",
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
        read_json(root / MANIFEST_NAME)["scans"].get("temporary_database_age")
        == value.get("temporary_database_age"),
        "downloaded finite database context differs from the signed producer binding",
    )
    if _m8c():
        origin = read_json(root / "m8c-retained-origin.json")
        require(
            file_sha256(root / "m8c-retained-origin.json") == value["retained_origin_sha256"]
            and origin.get("product_revision") == PRODUCT
            and origin.get("product_tree") == recovery.M8C_TREE
            and origin.get("original_run_id") == recovery.M8C_RUN
            and origin.get("first_archive_sha256") == recovery.M8C_FIRST_SHA256
            and (_m8c_clean() or file_sha256(root / "server-1.tar") == recovery.M8C_FIRST_SHA256),
            "M8c exact preserved Server or source lineage differs",
        )
        if _m8c_clean():
            require(
                file_sha256(root / "clean-context-first.json")
                == value["clean_context_first_sha256"]
                and clean.verify_m8c_first(root, Path.cwd())
                == read_json(root / "clean-context-first.json"),
                "new clean M8c sealed source or exact executable SDK proof differs",
            )
    else:
        require(
            file_sha256(root / "clean-context-first.json") == value["clean_context_first_sha256"]
            and clean.verify_first(root, Path.cwd())
            == read_json(root / "clean-context-first.json"),
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


def scan_registry_sbom(
    root: Path,
    image: Path,
    *,
    role: str,
    architecture: str,
    scanner: Path,
    report: Path,
    output: Path,
) -> None:
    """Bind each registry report to its actual OCI and approved database."""
    from saas.scripts.approved_disposition import inspect_approved_disposition
    from saas.scripts.sqlite_component_disposition import image_blobs

    value = binding()
    manifest = read_json(root / MANIFEST_NAME)
    require(
        file_sha256(root / MANIFEST_NAME) == value["candidate_manifest_sha256"]
        and manifest["images"][role]["index_digest"] == value["images"][role],
        "registry scan seal differs",
    )
    platform = f"linux/{architecture}"
    sealed = manifest["images"][role]
    expected = sealed["facts"]["platforms"][platform]
    with image_blobs(image) as blobs:
        digest, document = blobs.platform(platform)
        config_digest = document["config"]["digest"]
        config = blobs.document(config_digest)
        require(
            digest == expected["manifest_digest"]
            and config_digest == expected["config_digest"]
            and config.get("config", {}).get("Labels") == expected["labels"],
            "registry scan actual OCI subject differs",
        )
    subject = {
        "image": role,
        "platform": platform,
        "archive_sha256": sealed["archive_sha256"],
        "index_digest": sealed["index_digest"],
        "manifest_digest": digest,
        "config_digest": config_digest,
        "source_revision": PRODUCT,
        "product_tree": value["product_tree"],
    }
    now = datetime.now(UTC)
    latest = scan.official_database_latest()
    temporary = (
        scan.temporary_database_age_enabled()
        and scan.TEMPORARY_DATABASE_AGE["products"].get(PRODUCT) == value["product_tree"]
        and scan.approved_database_is_latest(latest)
        and datetime.fromisoformat(scan.TEMPORARY_DATABASE_AGE["built"].replace("Z", "+00:00"))
        + timedelta(hours=24)
        < now
        < datetime.fromisoformat(scan.TEMPORARY_DATABASE_AGE["expires_at"].replace("Z", "+00:00"))
    )
    database_root = root.parent / "sbom-grype-database"
    database_root.mkdir(mode=0o700, exist_ok=True)
    require(not database_root.is_symlink(), "registry database cache must be private")
    database_archive = database_root / "approved-database.tar.zst"
    config_path = database_root / "grype.json"
    config_path.write_text(
        json.dumps(
            {
                "db": {
                    "cache-dir": str(database_root / "cache"),
                    "auto-update": False,
                    "max-update-check-frequency": "0s",
                    "validate-by-hash-on-start": True,
                    "validate-age": True,
                    "max-allowed-built-age": "48h" if temporary else "24h",
                }
            }
        )
        + "\n"
    )
    command = [str(scanner), "-c", str(config_path)]
    if temporary:
        require(not database_archive.is_symlink(), "registry database archive is not trusted")
        if not database_archive.exists():
            scan.download_approved_database(database_archive)
        require(
            file_sha256(database_archive) == scan.TEMPORARY_DATABASE_AGE["archive_SHA256"],
            "registry database archive full SHA256 differs",
        )
        subprocess.run([*command, "db", "import", str(database_archive)], check=True)
    else:
        subprocess.run([*command, "db", "update"], check=True)
    status = json.loads(subprocess.check_output([*command, "db", "status", "-o", "json"]))
    if temporary:
        scan.validate_approved_database_status(status, now=datetime.now(UTC))
        latest = scan.official_database_latest()
        require(
            scan.approved_database_is_latest(latest)
            and file_sha256(database_archive) == scan.TEMPORARY_DATABASE_AGE["archive_SHA256"],
            "official latest or verified registry database changed before scan",
        )
    else:
        scan.parse_database_status(status, now=datetime.now(UTC))
    checked_at = datetime.now(UTC)
    result = subprocess.run(
        [
            *command,
            f"registry:ghcr.io/dream1216/omnigent-saas-{role}@{digest}",
            "--platform",
            platform,
            "--fail-on",
            "high",
            "-o",
            "json",
            "--file",
            str(report),
        ],
        check=False,
    )
    require(result.returncode in (0, 2) and report.is_file(), "registry Grype scan failed")
    raw = report.read_bytes()
    raw_report = json.loads(raw)
    parsed = scan.scan_report(raw_report)
    require(raw_report.get("ignoredMatches", []) == [], "registry scan omitted findings")
    descriptor = raw_report.get("descriptor", {})
    configuration = descriptor.get("configuration", {})
    require(
        descriptor.get("name") == "grype"
        and descriptor.get("version") == scan.GRYPE_VERSION
        and configuration.get("only-fixed") is False
        and configuration.get("only-notfixed") is False
        and configuration.get("exclude", []) == []
        and configuration.get("vex-documents", []) == [],
        "registry scanner or unfiltered report configuration differs",
    )
    disposition = (
        scan.make_database_age_disposition(
            raw_report["descriptor"]["db"]["status"],
            latest,
            subject,
            now=datetime.now(UTC),
            checked_at=checked_at,
            report_sha256=hashlib.sha256(raw).hexdigest(),
        )
        if temporary
        else None
    )
    scan.parse_database_status(
        raw_report["descriptor"]["db"]["status"],
        now=datetime.now(UTC),
        database_age_disposition=disposition,
        subject=raw_report.get("source", {}).get("target"),
        report_sha256=hashlib.sha256(raw).hexdigest(),
    )
    require(
        result.returncode != 2 or any(parsed["counts"].values()),
        "registry scanner exit and raw findings disagree",
    )
    proof = (
        inspect_approved_disposition(
            image,
            report,
            platform=platform,
            now=datetime.now(UTC),
            database_age_disposition=disposition,
        )
        if any(parsed["counts"].values())
        else None
    )
    output.write_text(
        json.dumps(
            {
                "raw_counts": parsed["counts"],
                "scanner_exit": result.returncode,
                "component_disposition": proof,
                "database_age_disposition": disposition,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def main() -> None:
    configure_product_profile(os.environ.get("OMNIGENT_ACCEPTED_PRODUCT_PROFILE", "M165"))
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
            "scan-registry-sbom",
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
    parser.add_argument("--image", type=Path)
    parser.add_argument("--scanner", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "preflight":
        print(json.dumps(preflight(args.root, args.policy_revision)))
    elif args.command == "download":
        download(args.root)
    elif args.command == "check-wheel":
        check_wheel(args.wheel)
    elif args.command == "scan-registry-sbom":
        scan_registry_sbom(
            args.root,
            args.image,
            role=args.role,
            architecture=args.architecture,
            scanner=args.scanner,
            report=args.report,
            output=args.output,
        )
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
