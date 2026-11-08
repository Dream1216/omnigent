"""Recover one accepted product without confusing its source with build policy."""

from __future__ import annotations

import argparse
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from saas.scripts.compare_oci_rebuilds import inspect_oci_archive
from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.oci_promotion import extract_artifact, require
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


def api(endpoint: str) -> dict[str, Any]:
    return json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))


def verify_product_ci(run: dict[str, Any], identifier: int, path: str) -> None:
    require(
        run.get("id") == identifier
        and run.get("head_sha") == PRODUCT
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("path") == path
        and run.get("run_attempt") == 1
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "accepted product own Main CI differs",
    )


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


def download_raw(run_id: int, artifact_id: int, sha: str, policy: str, root: Path) -> None:
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
    verify_raw(root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "download"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--sha256")
    parser.add_argument("--policy")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.root)
    elif args.command == "verify":
        verify_raw(args.root)
    else:
        require(
            bool(args.run_id and args.artifact_id and args.sha256 and args.policy),
            "exact raw checkpoint coordinates required",
        )
        download_raw(args.run_id, args.artifact_id, args.sha256, args.policy, args.root)


if __name__ == "__main__":
    main()
