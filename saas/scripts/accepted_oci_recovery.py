"""Recover one accepted product without confusing its source with build policy."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from saas.scripts.compare_oci_rebuilds import inspect_oci_archive
from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.oci_promotion import archive_index_digest, extract_artifact, require
from saas.scripts.scan_oci_candidates import file_sha256

PRODUCT = "165cebe8585a1a5fa8588e2a55f37505f89f3e55"
EPOCH = 1794108147
REPOSITORY = "Dream1216/omnigent"
WORKFLOW = ".github/workflows/saas-accepted-oci-recovery.yml"
REPORT_ID = 13607590461
REPORT_SIZE = 360565
REPORT_SHA = "b5ae6a581813650bd810082348df65a39bfa3e84e868b9fef311797077732057"
ORIGINAL_RUN = 42447484107
ORIGINAL_JOB = 128630408304
CI = {
    42444609846: ".github/workflows/saas-upstream-compat.yml",
    42444609890: ".github/workflows/ci.yml",
    42444609835: ".github/workflows/saas-n1-compat-image.yml",
}
M8C_PRODUCT = "8c851bdd12829340b2a327cf7542fe4de84d9132"
M8C_TREE = "694a997f3e74999f968f4341851ebaf0765d50aa"
M8C_EPOCH = 1794205060
M8C_DATA = "1da1acd35a63ab3c14a14dff030f0061e1f74314"
M8C_RUN = 42579035292
M8C_JOB = 129035564337
M8C_FIRST = (
    13658323260,
    540859547,
    "a60985c24490319274730129d48eb26f2cb6f0ed8f01b2ae3f4d4b7fd22a9d97",
)
M8C_REPORT = (
    13657869858,
    132566,
    "583a9e20c9fa935977c2d3c90c0fde9b993d6db21a162f32a8c7260587eb99d4",
)
M8C_FIRST_SHA256 = "cbbfd8bb80ca748d887ecaec36925da6bd770810f417cc3d92a0869b166c3cf4"
M8C_INDEX = "sha256:ac5abc35b3456a3e1c03c75d1dfaaf9ffec47f1ab002e471f255d3f2987cf0bd"
M8C_CI = {
    42575743497: ".github/workflows/saas-upstream-compat.yml",
    42575743501: ".github/workflows/ci.yml",
    42575743243: ".github/workflows/saas-n1-compat-image.yml",
}
_M8C_COMPLETED_JOBS = {129033169293, 129033168963, 129033169296}
_M8C_REUSED_STEPS = (
    "Run current-revision OSS and SaaS regressions",
    "Verify migrations and downstream compatibility",
    "Build React 18 login export",
    "Resolve immutable build materials",
    "Build server candidate attempt 1",
    "Verify executable Server candidate SDK on both architectures",
    "Retain failed Server preflight OCI for diagnosis",
    "Upload candidate evidence",
)


def api(endpoint: str) -> dict[str, Any]:
    return json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))


def _verify_product_ci(run: dict[str, Any], identifier: int, path: str, product: str) -> None:
    require(
        run.get("id") == identifier
        and run.get("head_sha") == product
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("path") == path
        and run.get("run_attempt") == 1
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "accepted product own Main CI differs",
    )


def verify_product_ci(run: dict[str, Any], identifier: int, path: str) -> None:
    _verify_product_ci(run, identifier, path, PRODUCT)


def verify_m8c_parent(run, jobs, first, report) -> None:
    require(
        run.get("id") == M8C_RUN
        and run.get("head_sha") == M8C_PRODUCT
        and run.get("head_branch") == "main"
        and run.get("path") == ".github/workflows/saas-image-candidate.yml"
        and run.get("event") == "workflow_dispatch"
        and run.get("run_attempt") == 1
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "M8c original failed producer differs",
    )
    indexed = {job.get("id"): job for job in jobs}
    require(len(indexed) == len(jobs), "M8c native job inventory is duplicated")
    for identifier in _M8C_COMPLETED_JOBS | {M8C_JOB}:
        job = indexed.get(identifier, {})
        require(
            job.get("run_id") == M8C_RUN
            and job.get("run_attempt") == 1
            and job.get("head_sha") == M8C_PRODUCT
            and job.get("status") == "completed"
            and job.get("conclusion") == ("failure" if identifier == M8C_JOB else "success")
            and job.get("runner_group_name") == "GitHub Actions"
            and job.get("labels") == ["ubuntu-24.04"],
            "M8c reused original job differs",
        )
    builder = indexed[M8C_JOB]
    require(builder.get("name") == "build-candidate", "M8c original builder differs")
    steps = builder.get("steps", [])
    require(
        [step["name"] for step in steps if step.get("conclusion") == "failure"]
        == ["Preflight scan exact server candidate on both architectures"]
        and all(
            len(
                [
                    step
                    for step in steps
                    if step.get("name") == name and step.get("conclusion") == "success"
                ]
            )
            == 1
            for name in _M8C_REUSED_STEPS
        ),
        "M8c completed inputs or original failure stage differs",
    )
    for metadata, coordinate, name, upload in (
        (
            first,
            M8C_FIRST,
            f"failed-server-preflight-oci-{M8C_PRODUCT}-{M8C_RUN}-1",
            "Retain failed Server preflight OCI for diagnosis",
        ),
        (report, M8C_REPORT, f"saas-image-candidate-{M8C_PRODUCT}", "Upload candidate evidence"),
    ):
        require(
            metadata.get("id") == coordinate[0]
            and metadata.get("size_in_bytes") == coordinate[1]
            and metadata.get("digest") == "sha256:" + coordinate[2]
            and metadata.get("name") == name
            and metadata.get("expired") is False
            and metadata.get("workflow_run", {}).get("id") == M8C_RUN
            and metadata.get("workflow_run", {}).get("head_sha") == M8C_PRODUCT,
            "M8c exact preserved artifact differs",
        )
        from saas.scripts.legacy_source_ci import _instant

        step = next(step for step in steps if step["name"] == upload)
        from datetime import timedelta

        require(
            _instant(step["started_at"])
            <= _instant(metadata.get("created_at"))
            < _instant(step["completed_at"]) + timedelta(seconds=1),
            "M8c preserved artifact upload window differs",
        )


def prepare_m8c_first(root: Path, github_env: Path) -> None:
    control = Path.cwd()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{WORKFLOW}@refs/heads/main"
        and os.environ.get("GITHUB_SHA") == revision
        and os.environ.get("GITHUB_WORKFLOW_SHA") == revision,
        "M8c recovery needs the exact native protected Main controller",
    )
    prefix = f"repos/{REPOSITORY}/actions"
    run = api(f"{prefix}/runs/{M8C_RUN}")
    inventory = api(f"{prefix}/runs/{M8C_RUN}/attempts/1/jobs?per_page=100")
    jobs = inventory.get("jobs", [])
    require(inventory.get("total_count") == len(jobs) < 100, "M8c native jobs are incomplete")
    first = api(f"{prefix}/artifacts/{M8C_FIRST[0]}")
    report = api(f"{prefix}/artifacts/{M8C_REPORT[0]}")
    verify_m8c_parent(run, jobs, first, report)
    for identifier, workflow in M8C_CI.items():
        _verify_product_ci(api(f"{prefix}/runs/{identifier}"), identifier, workflow, M8C_PRODUCT)
    require(
        subprocess.check_output(
            ["git", "rev-parse", M8C_PRODUCT + "^{tree}"], cwd=control, text=True
        ).strip()
        == M8C_TREE
        and int(
            subprocess.check_output(
                ["git", "show", "-s", "--format=%ct", M8C_PRODUCT], cwd=control, text=True
            )
        )
        == M8C_EPOCH,
        "M8c frozen source tree or epoch differs",
    )
    root.mkdir(parents=True, exist_ok=False)
    first_zip = root / "original-first-server.zip"
    report_zip = root / "original-report.zip"
    for coordinate, destination in ((M8C_FIRST, first_zip), (M8C_REPORT, report_zip)):
        download_artifact_bytes(
            coordinate[0], destination, expected_size=coordinate[1], expected_sha256=coordinate[2]
        )
    names = {"_temp/server-1.tar", "omnigent/omnigent/artifacts/server-candidate-runtime.json"}
    with zipfile.ZipFile(first_zip) as bundle, zipfile.ZipFile(report_zip) as original:
        require(
            len(bundle.namelist()) == len(names)
            and set(bundle.namelist()) == names
            and bundle.testzip() is None,
            "M8c first Server original ZIP members or CRC differ",
        )
        runtime = bundle.read("omnigent/omnigent/artifacts/server-candidate-runtime.json")
        require(
            original.testzip() is None
            and runtime == original.read("server-candidate-runtime.json"),
            "M8c original native SDK receipts differ",
        )
        with (
            bundle.open("_temp/server-1.tar") as source,
            (root / "server-1.tar").open("xb") as destination,
        ):
            shutil.copyfileobj(source, destination, 1024 * 1024)
    require(
        file_sha256(root / "server-1.tar") == M8C_FIRST_SHA256
        and archive_index_digest(root / "server-1.tar") == M8C_INDEX,
        "M8c original Server tar or index differs",
    )
    sdk = json.loads(runtime)
    facts = inspect_oci_archive(root / "server-1.tar", label_profile="executable")
    require(
        sdk.get("source_revision") == M8C_PRODUCT
        and sdk.get("root_digest") == M8C_INDEX
        and sdk.get("passed") is True
        and sdk.get("e2b_version") == "2.31.0",
        "M8c original Server SDK identity differs",
    )
    expected = {row["platform"]: row for row in sdk["platforms"]}
    require(
        set(facts["platforms"]) == set(expected) == {"linux/amd64", "linux/arm64"},
        "M8c original Server platforms differ",
    )
    for platform, actual in facts["platforms"].items():
        require(
            all(
                actual[key] == expected[platform][key]
                for key in ("manifest_digest", "config_digest")
            )
            and actual["labels"]["org.opencontainers.image.revision"] == M8C_PRODUCT,
            "M8c original Server manifest, config or source differs",
        )
    require(
        api(f"{prefix}/runs/{M8C_RUN}") == run
        and api(f"{prefix}/artifacts/{M8C_FIRST[0]}") == first
        and api(f"{prefix}/artifacts/{M8C_REPORT[0]}") == report,
        "M8c original native producer changed during retention",
    )
    first_zip.unlink()
    (root / "original-server-runtime.json").write_bytes(runtime)
    (root / "m8c-retained-origin.json").write_text(
        json.dumps(
            {
                "kind": "accepted_M8c_original_Server/v1",
                "product_revision": M8C_PRODUCT,
                "product_tree": M8C_TREE,
                "source_date_epoch": M8C_EPOCH,
                "controller_revision": revision,
                "original_run_id": M8C_RUN,
                "original_job_id": M8C_JOB,
                "first_artifact": first,
                "report_artifact": report,
                "first_archive_sha256": M8C_FIRST_SHA256,
                "SDK": sdk,
                "first_facts": facts,
                "raw_checkpoint_only": True,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    with github_env.open("a") as output:
        for key, value in {
            "PRODUCT_REVISION": M8C_PRODUCT,
            "SOURCE_REVISION": M8C_PRODUCT,
            "SOURCE_DATE_EPOCH": str(M8C_EPOCH),
        }.items():
            output.write(f"{key}={value}\n")


def verify_m8c_complete(root: Path) -> dict[str, Any]:
    require(
        subprocess.check_output(["git", "rev-parse", M8C_PRODUCT + "^{tree}"], text=True).strip()
        == M8C_TREE,
        "M8c completion source tree differs",
    )
    origin = json.loads((root / "m8c-retained-origin.json").read_text())
    require(
        origin.get("product_revision") == M8C_PRODUCT
        and origin.get("product_tree") == M8C_TREE
        and origin.get("original_run_id") == M8C_RUN
        and origin.get("original_job_id") == M8C_JOB
        and origin.get("first_archive_sha256") == M8C_FIRST_SHA256
        and file_sha256(root / "server-1.tar") == M8C_FIRST_SHA256,
        "M8c retained original Server identity changed",
    )
    report = json.loads((root / "saas-image-candidate.json").read_text())
    require(
        report.get("product_revision") == M8C_PRODUCT
        and report.get("source_date_epoch") == M8C_EPOCH
        and report.get("status") == "pass"
        and report.get("violations") == []
        and set(report.get("images", {})) == {"omnigent-saas-server", "omnigent-saas-host"},
        "M8c original complete independent comparison failed",
    )
    images = {}
    for role in ("server", "host"):
        comparison = report["images"][f"omnigent-saas-{role}"]
        require(
            comparison.get("matching_platform_manifest_and_config") is True
            and comparison.get("history_created_by_equal") is True,
            "M8c independent executable comparison differs",
        )
        for attempt, name in ((1, "first"), (2, "second")):
            path = root / f"{role}-{attempt}.tar"
            facts = inspect_oci_archive(path, label_profile="executable")
            require(
                facts == comparison[name], "M8c actual completed OCI differs from its comparison"
            )
            require(
                all(
                    row["labels"]["org.opencontainers.image.revision"] == M8C_PRODUCT
                    for row in facts["platforms"].values()
                ),
                "M8c completed OCI source differs",
            )
            images[path.name] = {"archive_sha256": file_sha256(path), "facts": facts}
    require(
        images["server-1.tar"]["facts"] == origin["first_facts"],
        "M8c original first Server facts changed",
    )
    receipt = {
        "kind": "accepted_M8c_complete_retained_first/v1",
        "product_revision": M8C_PRODUCT,
        "product_tree": M8C_TREE,
        "original_first_archive_sha256": M8C_FIRST_SHA256,
        "images": images,
        "origin_sha256": file_sha256(root / "m8c-retained-origin.json"),
        "raw_checkpoint_only": True,
        "fresh_scans_passed": False,
        "signed_or_production_admitted": False,
    }
    (root / "unadmitted-build.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n"
    )
    return receipt


def verify_m8c_recovery_run(run, job, policy: str, name: str, *, active: bool = False) -> None:
    require(
        re.fullmatch(r"[0-9a-f]{40}", policy) is not None
        and policy != M8C_PRODUCT
        and type(run.get("id")) is int
        and run["id"] > 0
        and run.get("head_sha") == policy
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW
        and run.get("run_attempt") == 1
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and (
            (run.get("status") == "completed" and run.get("conclusion") == "success")
            or (active and run.get("status") == "in_progress" and run.get("conclusion") is None)
        )
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == 1
        and job.get("head_sha") == policy
        and job.get("name") == name
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_group_name") == "GitHub Actions"
        and job.get("labels") == ["ubuntu-24.04"],
        "M8c recovery producer is not the exact successful protected operator",
    )


def download_m8c_raw(root: Path, run_id: int, artifact_id: int, sha: str, policy: str) -> None:
    prefix = f"repos/{REPOSITORY}/actions"
    run = api(f"{prefix}/runs/{run_id}")
    inventory = api(f"{prefix}/runs/{run_id}/attempts/1/jobs?per_page=100")
    jobs = inventory.get("jobs", [])
    require(inventory.get("total_count") == len(jobs) < 100, "M8c recovery jobs are incomplete")
    matching = [job for job in jobs if job.get("name") == "complete-m8c-first-server"]
    require(len(matching) == 1, "M8c completion builder is missing or duplicated")
    verify_m8c_recovery_run(run, matching[0], policy, "complete-m8c-first-server", active=True)
    metadata = api(f"{prefix}/artifacts/{artifact_id}")
    require(
        metadata.get("id") == artifact_id
        and metadata.get("name") == f"accepted-raw-{M8C_PRODUCT}-{run_id}"
        and metadata.get("digest") == "sha256:" + sha
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == run_id
        and metadata.get("workflow_run", {}).get("head_sha") == policy
        and type(metadata.get("size_in_bytes")) is int
        and 0 < metadata["size_in_bytes"] <= 16 * 1024**3,
        "M8c exact complete raw artifact differs",
    )
    archive = root.with_suffix(".zip")
    download_artifact_bytes(
        artifact_id, archive, expected_size=metadata["size_in_bytes"], expected_sha256=sha
    )
    extract_artifact(archive, root, zip_sha256=sha)
    archive.unlink()
    origin = json.loads((root / "m8c-retained-origin.json").read_text())
    require(origin.get("controller_revision") == policy, "M8c raw operator differs")
    verify_m8c_complete(root)
    require(api(f"{prefix}/artifacts/{artifact_id}") == metadata, "M8c raw artifact changed")


def original_report(archive: Path) -> dict[str, Any]:
    require(
        archive.is_file()
        and not archive.is_symlink()
        and archive.stat().st_size == REPORT_SIZE
        and file_sha256(archive) == REPORT_SHA,
        "original comparison artifact bytes differ",
    )
    with zipfile.ZipFile(archive) as bundle:
        require(bundle.testzip() is None, "original comparison artifact CRC failed")
        report = json.loads(bundle.read("saas-image-candidate.json"))
    require(
        report.get("candidate_evidence_version") == 3
        and report.get("status") == "pass"
        and report.get("violations") == []
        and report.get("product_revision") == PRODUCT
        and report.get("source_date_epoch") == EPOCH
        and report.get("label_profile") == "executable"
        and set(report.get("images", {})) == {"omnigent-saas-server", "omnigent-saas-host"},
        "original comparison does not bind accepted product",
    )
    return report


def prepare(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    root = f"repos/{REPOSITORY}"
    for identifier, path in CI.items():
        verify_product_ci(api(f"{root}/actions/runs/{identifier}"), identifier, path)
    job = api(f"{root}/actions/jobs/{ORIGINAL_JOB}")
    steps = {step["name"]: step for step in job.get("steps", [])}
    require(
        job.get("run_id") == ORIGINAL_RUN
        and job.get("run_attempt") == 1
        and job.get("name") == "build-candidate"
        and job.get("status") == "completed"
        and job.get("conclusion") == "failure"
        and all(
            steps.get(name, {}).get("conclusion") == "success"
            for name in (
                "Build server candidate attempt 1",
                "Build server candidate attempt 2",
                "Build host candidate attempt 1",
                "Build host candidate attempt 2",
                "Compare repeated executable image facts",
            )
        )
        and [step["name"] for step in steps.values() if step.get("conclusion") == "failure"]
        == ["Scan exact OCI candidates on both architectures"],
        "original builds/comparison are not the accepted completed steps",
    )
    metadata = api(f"{root}/actions/artifacts/{REPORT_ID}")
    require(
        metadata.get("id") == REPORT_ID
        and metadata.get("name") == f"saas-image-candidate-{PRODUCT}"
        and metadata.get("digest") == f"sha256:{REPORT_SHA}"
        and metadata.get("size_in_bytes") == REPORT_SIZE
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == ORIGINAL_RUN
        and metadata.get("workflow_run", {}).get("head_sha") == PRODUCT,
        "original native comparison metadata differs",
    )
    archive = directory / "original-report.zip"
    download_artifact_bytes(
        REPORT_ID, archive, expected_size=REPORT_SIZE, expected_sha256=REPORT_SHA
    )
    original_report(archive)


def verify_raw(directory: Path) -> dict[str, Any]:
    report = original_report(directory / "original-report.zip")
    images = {}
    for role in ("server", "host"):
        archive = directory / f"{role}-1.tar"
        require(archive.is_file() and not archive.is_symlink(), "missing regular recovered OCI")
        facts = inspect_oci_archive(archive, label_profile="executable")
        repeated = report["images"][f"omnigent-saas-{role}"]
        require(
            repeated.get("matching_platform_manifest_and_config") is True
            and repeated.get("history_created_by_equal") is True
            and repeated.get("first") == facts
            and repeated.get("second", {}).get("platforms") == facts["platforms"]
            and repeated.get("second", {}).get("attestations") == facts["attestations"],
            "recovered OCI differs from original independent comparison",
        )
        images[role] = {"archive_sha256": file_sha256(archive), "facts": facts}
    (directory / "saas-image-candidate.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    result = {
        "schema_version": 1,
        "product_revision": PRODUCT,
        "source_date_epoch": EPOCH,
        "rebuilt": True,
        "original_comparison_artifact_id": REPORT_ID,
        "original_comparison_artifact_sha256": REPORT_SHA,
        "images": images,
        "raw_checkpoint_only": True,
        "fresh_scans_passed": False,
        "signed_or_production_admitted": False,
    }
    (directory / "unadmitted-build.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def download_raw(
    run_id: int,
    artifact_id: int,
    sha: str,
    policy: str,
    root: Path,
    *,
    comparison_profile: str = "historical",
) -> None:
    require(
        comparison_profile in {"historical", "clean-M165-server"}, "unknown comparison profile"
    )
    prefix = f"repos/{REPOSITORY}"
    run = api(f"{prefix}/actions/runs/{run_id}")
    require(
        run.get("id") == run_id
        and run.get("run_attempt") == 1
        and run.get("head_sha") == policy
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "raw checkpoint native producer differs",
    )
    jobs = api(f"{prefix}/actions/runs/{run_id}/attempts/1/jobs?per_page=100")["jobs"]
    builders = [job for job in jobs if job.get("name") == "build-accepted-product"]
    require(
        len(builders) == 1
        and builders[0].get("run_id") == run_id
        and builders[0].get("run_attempt") == 1
        and builders[0].get("status") == "completed"
        and builders[0].get("conclusion") == "success"
        and builders[0].get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in builders[0].get("labels", []),
        "raw checkpoint has no successful hosted builder",
    )
    metadata = api(f"{prefix}/actions/artifacts/{artifact_id}")
    require(
        metadata.get("id") == artifact_id
        and metadata.get("name") == f"accepted-raw-{PRODUCT}-{run_id}"
        and metadata.get("digest") == f"sha256:{sha}"
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == run_id
        and metadata.get("workflow_run", {}).get("head_sha") == policy
        and type(metadata.get("size_in_bytes")) is int
        and 0 < metadata["size_in_bytes"] <= 16 * 1024**3,
        "raw checkpoint artifact differs",
    )
    archive = root.with_suffix(".zip")
    download_artifact_bytes(
        artifact_id, archive, expected_size=metadata["size_in_bytes"], expected_sha256=sha
    )
    extract_artifact(archive, root, zip_sha256=sha)
    if comparison_profile == "historical":
        verify_raw(root)
    else:
        from saas.scripts.accepted_m165_clean_context import verify_complete

        archive.unlink()
        verify_complete(root, Path.cwd())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("prepare", "verify", "download", "m8c-prepare", "m8c-verify", "m8c-download"),
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--sha256")
    parser.add_argument("--policy")
    parser.add_argument("--github-env", type=Path)
    parser.add_argument(
        "--comparison-profile", choices=("historical", "clean-M165-server"), default="historical"
    )
    args = parser.parse_args()
    if args.command == "m8c-download":
        require(
            bool(args.run_id and args.artifact_id and args.sha256 and args.policy),
            "M8c exact raw coordinates required",
        )
        download_m8c_raw(args.root, args.run_id, args.artifact_id, args.sha256, args.policy)
    elif args.command == "m8c-prepare":
        require(args.github_env is not None, "M8c native environment output is required")
        prepare_m8c_first(args.root, args.github_env)
    elif args.command == "m8c-verify":
        verify_m8c_complete(args.root)
    elif args.command == "prepare":
        prepare(args.root)
    elif args.command == "verify":
        verify_raw(args.root)
    else:
        require(
            bool(args.run_id and args.artifact_id and args.sha256 and args.policy),
            "exact raw checkpoint coordinates required",
        )
        download_raw(
            args.run_id,
            args.artifact_id,
            args.sha256,
            args.policy,
            args.root,
            comparison_profile=args.comparison_profile,
        )


if __name__ == "__main__":
    main()
