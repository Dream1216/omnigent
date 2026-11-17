"""Recover the exact four Main22 archives whose final scan failed before sealing."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from saas.scripts import accepted_oci_recovery as recovery
from saas.scripts.compare_oci_rebuilds import inspect_oci_archive
from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.oci_promotion import (
    MANIFEST_NAME,
    archive_index_digest,
    expected_labels,
    extract_artifact,
    read_json,
    require,
    seal_candidate,
)
from saas.scripts.scan_oci_candidates import file_sha256

PRODUCT = "22e237f61246ec0b041ddc604b8d41422804c7a8"
TREE = "72def792f42279fbf4d91cb756a6479ee3091be7"
EPOCH = 1794888040
PROFILE = "Main22e-retained-failed-scan/v1"
MODE = "exact_main22_retained_failed_scan_v1"
REPOSITORY = recovery.REPOSITORY
WORKFLOW = ".github/workflows/saas-main22-retained-scan-recovery.yml"
SOURCE_WORKFLOW = ".github/workflows/saas-image-candidate.yml"
PARENT = {"run_id": 44014148143, "attempt": 1, "job_id": 133810193394, "conclusion": "failure"}
RAW = (
    14306702318,
    10454943346,
    "3e227db21360bfe13161a9e171651dc78f27ae3e5e19627a6b1630ec6f7a6518",
)
REPORT = (14307445929, 364779, "184d277c21d7ab99cc810350da967a4f24cfb9e4b47903cad0c0450f3c9cfa5b")
ORIGIN = "main22-retained-origin.json"
MANIFEST = "saas/governance/main22-retained-recovery-controller.json"
CORE = {
    44014148322: ".github/workflows/lint.yml",
    44014148237: ".github/workflows/windows.yml",
    44014148283: ".github/workflows/saas-upstream-compat.yml",
    44014148043: ".github/workflows/trivy.yml",
    44014148061: ".github/workflows/saas-n1-compat-image.yml",
    44014148073: ".github/workflows/ci.yml",
}
CONTROLLER_CI = tuple(path for path in CORE.values() if "saas-n1-compat-image" not in path)
SOURCE_THREAD = "01a1bb0b-1a2b-75b3-bbb3-5e28a8a4271a"
HANDOFF = "cf1cf1f4850ebe2b6a70ab82d516be83f644b6520ffdf9ad4d921edf469d1e9e"
ARCHIVES = {f"{role}-{attempt}.tar" for role in ("server", "host") for attempt in (1, 2)}
CONTROL_PATHS = {
    WORKFLOW,
    SOURCE_WORKFLOW,
    ".github/workflows/saas-oci-promotion-accepted-m165.yml",
    ".github/workflows/saas-controller-source-budget.json",
    "saas/upstream-baseline.json",
    "saas/governance/ordinary-m-native-0142-source-scope.json",
    "saas/scripts/check_upstream_delta.py",
    "saas/scripts/check_image_supply_chain.py",
    "tests/saas/test_oci_promotion.py",
    "saas/scripts/main22_retained_recovery.py",
    "saas/scripts/accepted_m165_promotion.py",
    "tests/saas/test_main22_retained_recovery.py",
    "tests/saas/test_accepted_m165_promotion.py",
    "tests/saas/test_upstream_delta.py",
    MANIFEST,
}
RUN_FIELDS = (
    "id",
    "head_sha",
    "head_branch",
    "event",
    "path",
    "run_attempt",
    "status",
    "conclusion",
    "created_at",
)
JOB_FIELDS = (
    "id",
    "run_id",
    "run_attempt",
    "head_sha",
    "name",
    "status",
    "conclusion",
    "labels",
    "runner_group_name",
    "started_at",
    "completed_at",
)


def selected(value: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {key: value.get(key) for key in fields}


def instant(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "native timestamp must include timezone")
    return result


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def validate_control_changes(changes: dict[str, str], registered: set[str]) -> None:
    require(
        bool(changes)
        and set(changes) == registered
        and set(changes) <= CONTROL_PATHS
        and all(status in {"A", "M"} for status in changes.values()),
        "unregistered Main22 controller change, deletion or runtime change",
    )


def classify(repo: Path, revision: str) -> dict[str, Any]:
    """Only the complete finite registered controller may suppress another OCI build."""
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid controller revision")
    require(
        git(repo, "rev-parse", "HEAD") == revision and not git(repo, "diff", "HEAD", "--"),
        "controller checkout is modified or differs",
    )
    git(repo, "merge-base", "--is-ancestor", PRODUCT, revision)
    require(
        revision != PRODUCT and git(repo, "rev-parse", f"{PRODUCT}^{{tree}}") == TREE,
        "fixed Main22 product or tree differs",
    )
    manifest = read_json(repo / MANIFEST)
    require(
        manifest.get("recovery_profile") == PROFILE
        and manifest.get("product_revision") == PRODUCT
        and manifest.get("product_tree") == TREE,
        "Main22 controller registration differs",
    )
    changes = {
        path: status
        for status, path in (
            row.split("\t")
            for row in git(
                repo, "diff", "--no-renames", "--name-status", PRODUCT, revision
            ).splitlines()
        )
    }
    from saas.scripts.check_upstream_delta import _ordinary_m_candidate_matches

    require(
        _ordinary_m_candidate_matches(
            repo, read_json(repo / ".github/workflows/saas-controller-source-budget.json")
        ),
        "normal finite source budget qualification differs",
    )
    governance = set(
        read_json(repo / "saas/governance/ordinary-m-native-0142-source-scope.json")[
            "governance_paths"
        ]
    )
    rows = manifest["postimages"]
    registered = {item["path"] for item in rows} | {MANIFEST} | (set(changes) & governance)
    validate_control_changes(changes, registered)
    require(
        len(rows) == len({item["path"] for item in rows}),
        "duplicate registered controller postimage",
    )
    for item in rows:
        path = repo / item["path"]
        require(
            path.is_file()
            and not path.is_symlink()
            and len(path.read_bytes()) == item["bytes"]
            and file_sha256(path) == item["sha256"],
            "controller postimage differs",
        )
    return {
        "mode": MODE,
        "recovery_profile": PROFILE,
        "product_revision": PRODUCT,
        "product_tree": TREE,
        "controller_revision": revision,
        "controller_tree": git(repo, "rev-parse", "HEAD^{tree}"),
        "controller_registration_sha256": file_sha256(repo / MANIFEST),
    }


def artifact(
    metadata: dict[str, Any],
    name: str,
    controller: str,
    run_id: int,
    coordinate: tuple[int, int, str] | None = None,
) -> None:
    require(
        type(metadata.get("id")) is int
        and metadata["id"] > 0
        and metadata.get("name") == name
        and metadata.get("expired") is False
        and 0 < metadata.get("size_in_bytes", 0) <= 16 * 1024**3
        and re.fullmatch(r"sha256:[0-9a-f]{64}", metadata.get("digest", "")) is not None
        and metadata.get("workflow_run", {}).get("id") == run_id
        and metadata.get("workflow_run", {}).get("head_sha") == controller,
        "native artifact source, digest, size or expiry differs",
    )
    if coordinate:
        require(
            (metadata["id"], metadata["size_in_bytes"], metadata["digest"][7:]) == coordinate,
            "original immutable artifact coordinate differs",
        )


def hosted_job(
    job: dict[str, Any], run_id: int, controller: str, name: str, conclusion: str
) -> None:
    require(
        type(job.get("id")) is int
        and job["id"] > 0
        and job.get("run_id") == run_id
        and job.get("head_sha") == controller
        and job.get("run_attempt") == 1
        and job.get("name") == name
        and job.get("status") == "completed"
        and job.get("conclusion") == conclusion
        and job.get("labels") == ["ubuntu-24.04"]
        and job.get("runner_group_name") == "GitHub Actions",
        "native hosted job differs",
    )


def validate_parent(
    run: dict[str, Any], jobs: list[dict[str, Any]], raw: dict[str, Any], report: dict[str, Any]
) -> dict[str, Any]:
    require(
        run.get("id") == PARENT["run_id"]
        and run.get("head_sha") == PRODUCT
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("path") == SOURCE_WORKFLOW
        and run.get("run_attempt") == 1
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "original failed Main22 run differs",
    )
    by_id = {job["id"]: job for job in jobs}
    require(len(by_id) == len(jobs), "duplicate parent job")
    required = {
        133807912798: "source-context",
        133808078611: "verify-candidate-preflight",
        133808078759: "verify-production-migration-replay (postgres:18.",
        133808078896: "verify-production-migration-replay (postgres:16.",
    }
    for identifier, prefix in required.items():
        job = by_id.get(identifier, {})
        require(job.get("name", "").startswith(prefix), "original preflight or migration missing")
        hosted_job(job, PARENT["run_id"], PRODUCT, job["name"], "success")
    builder = by_id.get(PARENT["job_id"], {})
    hosted_job(builder, PARENT["run_id"], PRODUCT, "build-candidate", "failure")
    steps = builder.get("steps", [])
    require(
        [step["name"] for step in steps if step.get("conclusion") == "failure"]
        == ["Scan exact OCI candidates on both architectures"],
        "original failure was not scan-only",
    )
    required_steps = [
        "Run current-revision OSS and SaaS regressions",
        "Verify migrations and downstream compatibility",
        "Verify executable Server candidate SDK on both architectures",
        "Preflight scan exact server candidate on both architectures",
        "Compare repeated executable image facts",
        *[
            f"Build {role} candidate attempt {number}"
            for role in ("server", "host")
            for number in (1, 2)
        ],
        "Retain unqualified OCI after failed candidate build",
        "Upload candidate evidence",
    ]
    for name in required_steps:
        require(
            sum(step.get("name") == name and step.get("conclusion") == "success" for step in steps)
            == 1,
            "original accepted build, SDK, comparison or tests missing",
        )
    for name in (
        "Prepare immutable runtime evidence data for candidate",
        "Seal exact admitted OCI archives and raw scan evidence",
        "Upload immutable admitted OCI bytes",
    ):
        require(
            sum(step.get("name") == name and step.get("conclusion") == "skipped" for step in steps)
            == 1,
            "original overlay or admission state differs",
        )
    for metadata, coordinate, name, upload in (
        (
            raw,
            RAW,
            f"unqualified-oci-{PRODUCT}-{PARENT['run_id']}-1",
            "Retain unqualified OCI after failed candidate build",
        ),
        (report, REPORT, f"saas-image-candidate-{PRODUCT}", "Upload candidate evidence"),
    ):
        artifact(metadata, name, PRODUCT, PARENT["run_id"], coordinate)
        step = next(item for item in steps if item["name"] == upload)
        require(
            instant(step["started_at"])
            <= instant(metadata["created_at"])
            <= instant(step["completed_at"]),
            "original artifact was not uploaded by the original step",
        )
    return {
        "native_run": selected(run, RUN_FIELDS),
        "native_job": selected(builder, JOB_FIELDS),
        "native_prerequisites": [
            selected(by_id[identifier], JOB_FIELDS) for identifier in required
        ],
        "artifacts": {"raw": raw, "report": report},
    }


def hard_caps(parent: dict[str, Any], core: dict[str, Any]) -> dict[str, str]:
    deadlines = {
        "source_created_at_plus_24h": (
            instant(parent["native_run"]["created_at"]) + timedelta(hours=24)
        ).isoformat(),
        "native_completed_at_plus_24h": (
            instant(parent["native_job"]["completed_at"]) + timedelta(hours=24)
        ).isoformat(),
        "original_core_created_at_plus_24h": min(
            instant(row["created_at"]) + timedelta(hours=24) for row in core.values()
        ).isoformat(),
    }
    deadlines["effective_not_after"] = min(
        instant(value) for value in deadlines.values()
    ).isoformat()
    require(
        datetime.now(UTC) < instant(deadlines["effective_not_after"]),
        "original Main22 evidence deadline expired",
    )
    return deadlines


def native_origin() -> dict[str, Any]:
    prefix = f"repos/{REPOSITORY}/actions"
    run = recovery.api(f"{prefix}/runs/{PARENT['run_id']}")
    jobs = recovery.api(f"{prefix}/runs/{PARENT['run_id']}/attempts/1/jobs?per_page=100")["jobs"]
    raw, report = (
        recovery.api(f"{prefix}/artifacts/{identifier}") for identifier in (RAW[0], REPORT[0])
    )
    parent = validate_parent(run, jobs, raw, report)
    core = {}
    for identifier, path in CORE.items():
        evidence = recovery.api(f"{prefix}/runs/{identifier}")
        recovery._verify_product_ci(evidence, identifier, path, PRODUCT)
        core[path] = selected(evidence, RUN_FIELDS)
    deadlines = hard_caps(parent, core)
    return {
        "schema_version": 1,
        "recovery_profile": PROFILE,
        "producer_binding_mode": MODE,
        "product_revision": PRODUCT,
        "product_tree": TREE,
        "source_date_epoch": EPOCH,
        "failed_parent": parent,
        "original_Main_CI": core,
        "hard_caps": deadlines,
        "rebuilt": False,
        "source_thread": SOURCE_THREAD,
        "source_actor_handoff_sha256": HANDOFF,
    }


def transfer(metadata: dict[str, Any], destination: Path, *, retain_zip: bool = False) -> None:
    archive = destination.with_suffix(".zip")
    download_artifact_bytes(
        metadata["id"],
        archive,
        expected_size=metadata["size_in_bytes"],
        expected_sha256=metadata["digest"][7:],
    )
    with zipfile.ZipFile(archive) as bundle:
        require(bundle.testzip() is None, "native artifact ZIP CRC differs")
    extract_artifact(archive, destination, zip_sha256=metadata["digest"][7:])
    if not retain_zip:
        archive.unlink()


def verify_original_files(root: Path, *, all_four: bool) -> dict[str, Any]:
    comparison = read_json(root / "saas-image-candidate.json")
    require(
        comparison.get("candidate_evidence_version") == 3
        and comparison.get("status") == "pass"
        and comparison.get("violations") == []
        and comparison.get("product_revision") == PRODUCT
        and comparison.get("source_date_epoch") == EPOCH
        and comparison.get("label_profile") == "executable",
        "original Main22 reproducibility report differs",
    )
    labels = expected_labels(Path.cwd(), PRODUCT)
    images: dict[str, Any] = {}
    for role in ("server", "host"):
        repeated = comparison["images"][f"omnigent-saas-{role}"]
        require(
            repeated.get("matching_platform_manifest_and_config") is True
            and repeated.get("history_created_by_equal") is True,
            "original reproducibility mismatch",
        )
        for attempt in (1, 2) if all_four else (1,):
            name = f"{role}-{attempt}.tar"
            path = root / name
            require(path.is_file() and not path.is_symlink(), "missing original OCI archive")
            facts = inspect_oci_archive(path, label_profile="executable")
            require(
                facts == repeated["first" if attempt == 1 else "second"]
                and set(facts["platforms"]) == {"linux/amd64", "linux/arm64"}
                and all(row["labels"] == labels for row in facts["platforms"].values()),
                "original OCI bytes differ from the fixed comparison",
            )
            images[name] = {
                "archive_sha256": file_sha256(path),
                "index_digest": archive_index_digest(path),
                "facts": facts,
            }
    sdk = read_json(root / "server-candidate-runtime.json")
    first = images["server-1.tar"]
    require(
        sdk.get("schema_version") == 1
        and sdk.get("passed") is True
        and sdk.get("source_revision") == PRODUCT
        and sdk.get("e2b_version") == "2.31.0"
        and sdk.get("archive_sha256") == first["archive_sha256"]
        and sdk.get("root_digest") == first["index_digest"]
        and sdk.get("platforms")
        == [
            {
                "platform": platform,
                **{key: row[key] for key in ("config_digest", "manifest_digest")},
            }
            for platform, row in sorted(first["facts"]["platforms"].items())
        ],
        "original both-architecture executable SDK proof differs",
    )
    cases = ET.parse(root / "server-regressions.junit.xml").findall(".//testcase")
    counts = {
        "total": len(cases),
        "skipped": sum(case.find("skipped") is not None for case in cases),
        "failed": sum(
            case.find("failure") is not None or case.find("error") is not None for case in cases
        ),
    }
    require(
        counts == {"total": 8230, "skipped": 38, "failed": 0},
        "original native regression counts differ",
    )
    return {
        "archives": images,
        "SDK_sha256": file_sha256(root / "server-candidate-runtime.json"),
        "comparison_sha256": file_sha256(root / "saas-image-candidate.json"),
        "JUnit_sha256": file_sha256(root / "server-regressions.junit.xml"),
        "regressions": counts,
    }


def retain(root: Path) -> None:
    origin = native_origin()
    transfer(origin["failed_parent"]["artifacts"]["raw"], root)
    require(
        {path.name for path in root.iterdir()} == ARCHIVES,
        "original four-archive ZIP inventory differs",
    )
    report_root = root.with_name(root.name + "-original-report")
    transfer(origin["failed_parent"]["artifacts"]["report"], report_root)
    for name in (
        "saas-image-candidate.json",
        "server-candidate-runtime.json",
        "server-regressions.junit.xml",
    ):
        shutil.copy2(report_root / name, root / name)
    origin["retained_bytes"] = verify_original_files(root, all_four=True)
    (root / ORIGIN).write_text(json.dumps(origin, indent=2, sort_keys=True) + "\n")


def verify_origin(origin: dict[str, Any], fresh: dict[str, Any]) -> None:
    require(
        {key: value for key, value in origin.items() if key != "retained_bytes"} == fresh,
        "Main22 retained origin does not match native readback",
    )


def recovered_run(
    run: dict[str, Any], jobs: list[dict[str, Any]], controller: str, *, completed: bool
) -> dict[str, dict[str, Any]]:
    require(
        type(run.get("id")) is int
        and run["id"] > 0
        and run.get("head_sha") == controller
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW
        and run.get("run_attempt") == 1
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and (
            not completed
            or (run.get("status") == "completed" and run.get("conclusion") == "success")
        ),
        "successful recovery producer differs",
    )
    result = {}
    for name in (
        ("retain-original-four", "scan-and-admit-main22")
        if completed
        else ("retain-original-four",)
    ):
        matching = [job for job in jobs if job.get("name") == name]
        require(len(matching) == 1, "missing or duplicate recovery job")
        hosted_job(matching[0], run["id"], controller, name, "success")
        result[name] = matching[0]
    return result


def download_checkpoint(
    root: Path, controller: str, run_id: int, artifact_id: int, sha256: str
) -> None:
    classify(Path.cwd(), controller)
    prefix = f"repos/{REPOSITORY}/actions"
    run = recovery.api(f"{prefix}/runs/{run_id}")
    jobs = recovery.api(f"{prefix}/runs/{run_id}/attempts/1/jobs?per_page=100")["jobs"]
    recovered_run(run, jobs, controller, completed=False)
    metadata = recovery.api(f"{prefix}/artifacts/{artifact_id}")
    artifact(metadata, f"accepted-raw-{PRODUCT}-{run_id}", controller, run_id)
    require(metadata["digest"] == "sha256:" + sha256, "raw checkpoint SHA differs")
    transfer(metadata, root)
    origin = read_json(root / ORIGIN)
    verify_origin(origin, native_origin())
    require(
        verify_original_files(root, all_four=True) == origin["retained_bytes"],
        "retained four-archive proof differs",
    )


def report_binding(root: Path, scan_job: dict[str, Any]) -> dict[str, Any]:
    origin = read_json(root / ORIGIN)
    verify_origin(origin, native_origin())
    manifest = read_json(root / MANIFEST_NAME)
    sealed = instant(manifest["sealed_at"])
    require(
        instant(scan_job["started_at"])
        <= sealed
        <= instant(scan_job["completed_at"])
        <= datetime.now(UTC),
        "native recovery scan/seal interval differs",
    )
    require(
        manifest.get("product_revision") == PRODUCT
        and manifest.get("source_date_epoch") == EPOCH
        and manifest.get("comparison_sha256") == file_sha256(root / "saas-image-candidate.json")
        and "temporary_database_age" not in manifest.get("scans", {}),
        "Main22 seal or normal24 policy differs",
    )
    from saas.scripts.oci_promotion import validate_scans

    require(
        validate_scans(root, manifest["images"], now=sealed) == manifest["scans"],
        "four original raw scans differ",
    )
    for role in ("server", "host"):
        retained = origin["retained_bytes"]["archives"][f"{role}-1.tar"]
        image = manifest["images"][role]
        require(
            all(
                image[key] == retained[key] for key in ("archive_sha256", "index_digest", "facts")
            ),
            "sealed OCI is not the original retained first archive",
        )
    return manifest


def preflight(root: Path, policy: str, producer: int) -> dict[str, Any]:
    from saas.scripts import accepted_m165_promotion as promotion

    controller = classify(Path.cwd(), policy)
    prefix = f"repos/{REPOSITORY}/actions"
    policy_ci = {}
    for path in CONTROLLER_CI:
        rows = recovery.api(
            f"{prefix}/workflows/{path.rsplit('/', 1)[-1]}/runs"
            f"?head_sha={policy}&event=push&branch=main&per_page=100"
        )["workflow_runs"]
        require(bool(rows), "recovery controller own Main CI missing")
        listed = max(rows, key=lambda row: (row["id"], row["run_attempt"]))
        promotion.verify_policy_ci(listed, path, policy)
        run = recovery.api(f"{prefix}/runs/{listed['id']}")
        promotion.verify_policy_ci(run, path, policy)
        require(run["run_attempt"] == listed["run_attempt"], "controller CI attempt changed")
        policy_ci[path] = selected(run, RUN_FIELDS)
    run = recovery.api(f"{prefix}/runs/{producer}")
    jobs = recovery.api(f"{prefix}/runs/{producer}/attempts/1/jobs?per_page=100")["jobs"]
    native = recovered_run(run, jobs, policy, completed=True)
    artifacts = recovery.api(f"{prefix}/runs/{producer}/artifacts?per_page=100")["artifacts"]
    chosen = {}
    for kind, name in (
        ("raw", f"accepted-raw-{PRODUCT}-{producer}"),
        ("oci", f"saas-oci-promotion-{PRODUCT}"),
        ("report", f"main22-retained-scan-{producer}"),
    ):
        matches = [item for item in artifacts if item.get("name") == name]
        require(len(matches) == 1, "missing or duplicate recovered artifact")
        artifact(matches[0], name, policy, producer)
        chosen[kind] = matches[0]
    transfer(chosen["report"], root, retain_zip=True)
    scan_job = native["scan-and-admit-main22"]
    manifest = report_binding(root, scan_job)
    origin = read_json(root / ORIGIN)
    result = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "recovery_profile": PROFILE,
        "producer_binding_mode": MODE,
        "product_revision": PRODUCT,
        "product_tree": TREE,
        "source_date_epoch": EPOCH,
        "candidate_run_id": producer,
        "candidate_run_attempt": 1,
        "candidate_controller_revision": policy,
        "controller_tree": controller["controller_tree"],
        "controller_own_Main_CI": policy_ci,
        "accepted_product_main_ci": origin["original_Main_CI"],
        "candidate_build_job_id": native["retain-original-four"]["id"],
        "candidate_build_completed_at": native["retain-original-four"]["completed_at"],
        "candidate_manifest_sha256": file_sha256(root / MANIFEST_NAME),
        "native_run": selected(run, RUN_FIELDS),
        "native_builder_job": selected(native["retain-original-four"], JOB_FIELDS),
        "native_scan_job": selected(scan_job, JOB_FIELDS),
        "parent_raw_checkpoint": PARENT,
        "recovery_source_qualification": origin,
        "retained_origin_sha256": file_sha256(root / ORIGIN),
        "producer_control_equivalence": controller,
        "artifacts": chosen,
        "images": {role: image["index_digest"] for role, image in manifest["images"].items()},
        "oci_artifact_id": chosen["oci"]["id"],
        "oci_artifact_sha256": chosen["oci"]["digest"][7:],
        "rebuilt": False,
        "signing_rebuilt_oci": False,
        "production_authority": False,
    }
    validate_binding(result, producer)
    promotion.binding_path().write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            for output, key in (
                ("manifest-sha256", "candidate_manifest_sha256"),
                ("oci-artifact-id", "oci_artifact_id"),
                ("oci-artifact-sha256", "oci_artifact_sha256"),
            ):
                stream.write(f"{output}={result[key]}\n")
    return {"state": "NATIVE_PRODUCER_AUTHENTICATED_FULL_OCI_ADMISSION_PENDING", "binding": result}


def validate_binding(value: dict[str, Any], producer: int) -> None:
    require(
        value.get("schema_version") == 1
        and value.get("repository") == REPOSITORY
        and value.get("recovery_profile") == PROFILE
        and value.get("producer_binding_mode") == MODE
        and value.get("product_revision") == PRODUCT
        and value.get("product_tree") == TREE
        and value.get("source_date_epoch") == EPOCH
        and value.get("candidate_run_id") == producer
        and value.get("candidate_run_attempt") == 1
        and value.get("parent_raw_checkpoint") == PARENT
        and value.get("candidate_controller_revision") != PRODUCT
        and re.fullmatch(r"[0-9a-f]{40}", value.get("candidate_controller_revision", ""))
        is not None
        and value.get("rebuilt") is False
        and value.get("signing_rebuilt_oci") is False
        and value.get("production_authority") is False
        and "temporary_database_age" not in value,
        "exact Main22 recovery binding differs",
    )
    origin = value["recovery_source_qualification"]
    require(
        origin.get("recovery_profile") == PROFILE
        and origin.get("producer_binding_mode") == MODE
        and origin.get("product_revision") == PRODUCT
        and origin.get("product_tree") == TREE
        and origin.get("failed_parent", {}).get("native_run", {}).get("conclusion") == "failure"
        and origin.get("source_thread") == SOURCE_THREAD
        and origin.get("source_actor_handoff_sha256") == HANDOFF,
        "Main22 original failure, Source issuer or product differs",
    )
    require(set(origin["original_Main_CI"]) == set(CORE.values()), "original Core6 set differs")
    for identifier, path in CORE.items():
        recovery._verify_product_ci(
            {**origin["original_Main_CI"][path], "repository": {"full_name": REPOSITORY}},
            identifier,
            path,
            PRODUCT,
        )
    require(
        origin["hard_caps"] == hard_caps(origin["failed_parent"], origin["original_Main_CI"]),
        "original evidence cap expired or extended",
    )
    recovered_run(
        {**value["native_run"], "repository": {"full_name": REPOSITORY}},
        [value["native_builder_job"], value["native_scan_job"]],
        value["candidate_controller_revision"],
        completed=True,
    )
    require(
        value["candidate_build_job_id"] == value["native_builder_job"]["id"]
        and value["native_run"]["id"] == producer,
        "recovery native identity differs",
    )


def download(root: Path, value: dict[str, Any]) -> None:
    metadata = recovery.api(f"repos/{REPOSITORY}/actions/artifacts/{value['oci_artifact_id']}")
    require(metadata == value["artifacts"]["oci"], "admitted OCI metadata changed")
    transfer(metadata, root)
    require(
        file_sha256(root / MANIFEST_NAME) == value["candidate_manifest_sha256"]
        and file_sha256(root / ORIGIN) == value["retained_origin_sha256"],
        "transferred seal or retained origin differs",
    )
    manifest = report_binding(root, value["native_scan_job"])
    require(
        seal_candidate(
            root,
            labels=expected_labels(Path.cwd(), PRODUCT),
            source_date_epoch=EPOCH,
            now=instant(manifest["sealed_at"]),
        )
        == manifest,
        "exact original sealed OCI differs",
    )
    facts = verify_original_files(root, all_four=False)
    original = value["recovery_source_qualification"]["retained_bytes"]
    require(
        all(
            facts[key] == original[key]
            for key in ("SDK_sha256", "comparison_sha256", "JUnit_sha256", "regressions")
        )
        and all(row == original["archives"][name] for name, row in facts["archives"].items()),
        "original SDK, regressions or first archives differ",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("classify", "retain", "checkpoint"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--candidate-revision")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--sha256")
    args = parser.parse_args()
    if args.command == "classify":
        print(json.dumps(classify(Path.cwd(), args.candidate_revision)))
    elif args.command == "retain":
        classify(Path.cwd(), os.environ["GITHUB_SHA"])
        retain(args.root)
    else:
        download_checkpoint(
            args.root, os.environ["GITHUB_SHA"], args.run_id, args.artifact_id, args.sha256
        )


if __name__ == "__main__":
    main()
