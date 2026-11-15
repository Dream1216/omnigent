"""Seal, transfer and verify the exact OCI bytes admitted by candidate CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from saas.scripts.compare_oci_rebuilds import inspect_oci_archive
from saas.scripts.scan_oci_candidates import (
    GRYPE_VERSION,
    TEMPORARY_DATABASE_AGE,
    TEMPORARY_DATABASE_AGE_SHA256,
    file_sha256,
    parse_database_status,
    scan_report,
)

IMAGES = ("server", "host")
PLATFORMS = ("linux/amd64", "linux/arm64")
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_NAME = "oci-promotion-manifest.json"
TRUSTED_REPOSITORY = "Dream1216/omnigent"
TRUSTED_WORKFLOW = ".github/workflows/saas-image-candidate.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "missing regular evidence file")
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "evidence must be an object")
    return value


def expected_labels(repo: Path, revision: str) -> dict[str, str]:
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid source revision")
    upstream = read_json(repo / "saas/upstream-baseline.json")
    baseline = read_json(repo / "saas/production/baseline.json")
    return {
        "org.opencontainers.image.revision": revision,
        "ai.omnigent.upstream.revision": upstream["upstream_revision"],
        "ai.omnigent.saas.schema-revision": baseline["revision_contract"][
            "control_plane_schema_revision"
        ],
        "ai.omnigent.saas.adapter-contract-version": upstream["adapter_contract_version"],
    }


def archive_index_digest(archive_path: Path) -> str:
    with tarfile.open(archive_path) as archive:
        index_file = archive.extractfile("index.json")
        require(index_file is not None, "OCI archive lacks index.json")
        assert index_file is not None
        index = json.load(index_file)
        descriptors = index.get("manifests", [])
        require(len(descriptors) == 1, "OCI layout must select exactly one image index")
        descriptor = descriptors[0]
        digest = descriptor.get("digest", "")
        require(
            descriptor.get("mediaType") == INDEX_TYPE
            and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
            "OCI root descriptor must be a sha256 image index",
        )
        member = archive.getmember("blobs/sha256/" + digest.removeprefix("sha256:"))
        stream = archive.extractfile(member)
        require(member.isfile() and stream is not None, "OCI root index is not a file")
        assert stream is not None
        body = stream.read()
        require(
            len(body) == descriptor.get("size")
            and hashlib.sha256(body).hexdigest() == digest.removeprefix("sha256:"),
            "OCI root index digest or size mismatch",
        )
        return digest


def validate_scans(
    root: Path, images: dict[str, Any], *, now: datetime, archive_root: Path | None = None
) -> dict[str, Any]:
    summary_path = root / "grype/candidate-scan-summary.json"
    summary = read_json(summary_path)
    require(
        summary.get("scanner") == f"grype {GRYPE_VERSION}" and summary.get("exceptions") == [],
        "candidate scan policy differs",
    )
    rows = summary.get("images", [])
    require(isinstance(rows, list) and len(rows) == 4, "four raw scans are required")
    seen: set[tuple[str, str]] = set()
    reports: dict[str, str] = {}
    database_age_reports: dict[str, Any] = {}
    verified_archives: dict[str, Path] = {}
    for row in rows:
        name, platform = row.get("image"), row.get("platform")
        require(name in IMAGES and platform in PLATFORMS, "unexpected scan coordinate")
        require((name, platform) not in seen, "duplicate scan coordinate")
        seen.add((name, platform))
        relative = f"grype/{name}-{platform.split('/')[-1]}-grype.json"
        report_path = root / relative
        report = read_json(report_path)
        descriptor = report.get("descriptor", {})
        require(
            descriptor.get("name") == "grype" and descriptor.get("version") == GRYPE_VERSION,
            "raw scanner identity differs",
        )
        database_age = row.get("database_age_disposition")
        database_built = parse_database_status(
            descriptor["db"]["status"],
            now=now,
            database_age_disposition=database_age,
            subject=report.get("source", {}).get("target"),
            report_sha256=file_sha256(report_path),
        )
        require(database_built == summary.get("database_built_at"), "scan database differs")
        config = descriptor.get("configuration", {})
        require(
            config.get("only-fixed") is False
            and config.get("only-notfixed") is False
            and config.get("exclude", []) == []
            and config.get("vex-documents", []) == [],
            "raw scan must not filter findings",
        )
        parsed = scan_report(report)
        if any(parsed["counts"].values()):
            from saas.scripts.sqlite_component_disposition import validate_disposition

            if name not in verified_archives:
                archive = (archive_root or root) / images[name]["archive"]
                require(
                    file_sha256(archive) == images[name]["archive_sha256"],
                    "actual component OCI archive differs",
                )
                verified_archives[name] = archive
            validate_disposition(
                report_path,
                row.get("component_disposition"),
                image=verified_archives[name],
                now=now,
                database_age_disposition=database_age,
            )
            require(row.get("scanner_exit") == 2, "original High scanner exit is required")
        else:
            require(row.get("component_disposition") is None, "unexpected component disposition")
        facts = images[name]["facts"]["platforms"][platform]
        target = report.get("source", {}).get("target", {})
        require(
            target.get("manifestDigest") == facts["manifest_digest"]
            and target.get("imageID") == facts["config_digest"]
            and target.get("os") == "linux"
            and target.get("architecture") == platform.split("/")[-1]
            and target.get("labels") == facts["labels"],
            "raw scan does not bind the exact OCI platform",
        )
        sha = file_sha256(report_path)
        require(
            row.get("archive_sha256") == images[name]["archive_sha256"]
            and row.get("report_sha256") == sha
            and row.get("critical") == parsed["counts"]["Critical"]
            and row.get("high") == parsed["counts"]["High"]
            and row.get("findings") == parsed["findings"],
            "scan summary does not bind original archive and report",
        )
        reports[relative] = sha
        if database_age is not None:
            bound = database_age["subject"]
            require(
                bound["image"] == name
                and bound["platform"] == platform
                and bound["archive_sha256"] == images[name]["archive_sha256"]
                and bound["index_digest"] == images[name]["index_digest"],
                "finite database age does not bind the actual OCI archive and index",
            )
            database_age_reports[relative] = database_age
    result: dict[str, Any] = {"summary_sha256": file_sha256(summary_path), "reports": reports}
    if database_age_reports:
        require(
            len(database_age_reports) == 4, "finite database age requires all four bound reports"
        )
        result["temporary_database_age"] = {
            "rule": TEMPORARY_DATABASE_AGE,
            "rule_sha256": TEMPORARY_DATABASE_AGE_SHA256,
            "reports": database_age_reports,
        }
    return result


def seal_candidate(
    root: Path, *, labels: dict[str, str], source_date_epoch: int, now: datetime
) -> dict[str, Any]:
    revision = labels["org.opencontainers.image.revision"]
    comparison_path = root / "saas-image-candidate.json"
    comparison = read_json(comparison_path)
    require(
        comparison.get("candidate_evidence_version") == 3
        and comparison.get("status") == "pass"
        and comparison.get("violations") == []
        and comparison.get("product_revision") == revision
        and comparison.get("source_date_epoch") == source_date_epoch
        and comparison.get("label_profile") == "executable"
        and comparison.get("upstream_revision") == labels["ai.omnigent.upstream.revision"]
        and comparison.get("adapter_contract_version")
        == labels["ai.omnigent.saas.adapter-contract-version"]
        and set(comparison.get("images", {})) == {"omnigent-saas-server", "omnigent-saas-host"},
        "reproducibility evidence does not bind the final source",
    )
    images: dict[str, Any] = {}
    for name in IMAGES:
        archive = root / f"{name}-1.tar"
        require(archive.is_file() and not archive.is_symlink(), "missing candidate OCI")
        facts = inspect_oci_archive(archive, label_profile="executable")
        for platform in PLATFORMS:
            require(facts["platforms"][platform]["labels"] == labels, "OCI source labels differ")
        repeated = comparison["images"][f"omnigent-saas-{name}"]
        require(
            repeated.get("matching_platform_manifest_and_config") is True
            and repeated.get("history_created_by_equal") is True
            and repeated.get("first") == facts
            and repeated.get("second", {}).get("platforms") == facts["platforms"]
            and repeated.get("second", {}).get("attestations") == facts["attestations"],
            "archive differs from accepted reproducibility evidence",
        )
        images[name] = {
            "archive": f"{name}-1.tar",
            "archive_sha256": file_sha256(archive),
            "index_digest": archive_index_digest(archive),
            "facts": facts,
        }
    return {
        "schema_version": 1,
        "evidence_kind": "immutable_oci_promotion_candidate",
        "product_revision": revision,
        "source_date_epoch": source_date_epoch,
        "sealed_at": now.isoformat(),
        "labels": labels,
        "comparison_sha256": file_sha256(comparison_path),
        "scans": validate_scans(root, images, now=now),
        "images": images,
    }


def verify_candidate(
    root: Path,
    *,
    manifest_sha256: str,
    labels: dict[str, str],
    source_date_epoch: int,
    current_scan_root: Path | None = None,
) -> dict[str, Any]:
    path = root / MANIFEST_NAME
    require(file_sha256(path) == manifest_sha256, "candidate seal digest mismatch")
    manifest = read_json(path)
    sealed_at = datetime.fromisoformat(manifest["sealed_at"])
    now = datetime.now(UTC)
    require(sealed_at.tzinfo is not None and sealed_at <= now, "candidate seal time is invalid")
    actual = seal_candidate(
        root, labels=labels, source_date_epoch=source_date_epoch, now=sealed_at
    )
    require(actual == manifest, "candidate seal does not bind transferred OCI bytes")
    validate_scans(current_scan_root or root, manifest["images"], now=now, archive_root=root)
    return manifest


def verify_artifact_metadata(
    metadata: dict[str, Any], *, artifact_id: int, zip_sha256: str, revision: str, run_id: int
) -> None:
    require(
        metadata.get("id") == artifact_id
        and metadata.get("name") == f"saas-oci-promotion-{revision}"
        and metadata.get("expired") is False
        and metadata.get("digest") == f"sha256:{zip_sha256}"
        and metadata.get("workflow_run", {}).get("id") == run_id
        and metadata.get("workflow_run", {}).get("head_sha") == revision,
        "OCI artifact does not bind this exact workflow run and source",
    )


def verify_promotion_controller(
    environment: dict[str, str], *, repository: str, revision: str
) -> int:
    """Permit cross-run intake only from the exact protected Main controller."""
    require(
        repository == TRUSTED_REPOSITORY
        and environment.get("GITHUB_ACTIONS") == "true"
        and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and environment.get("GITHUB_REPOSITORY") == repository
        and environment.get("GITHUB_REF") == "refs/heads/main"
        and environment.get("GITHUB_SHA") == revision
        and re.fullmatch(r"[0-9a-f]{40}", revision) is not None
        and environment.get("GITHUB_WORKFLOW_REF")
        == f"{repository}/{TRUSTED_WORKFLOW}@refs/heads/main"
        and environment.get("GITHUB_WORKFLOW_SHA") == revision
        and re.fullmatch(r"[1-9][0-9]*", environment.get("GITHUB_REPOSITORY_ID", "")) is not None,
        "cross-run promotion requires the registered exact Main controller",
    )
    return int(environment["GITHUB_REPOSITORY_ID"])


def verify_trusted_main_source(
    run: dict[str, Any],
    jobs: list[dict[str, Any]],
    artifact: dict[str, Any],
    *,
    repository: str,
    repository_id: int,
    revision: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    zip_sha256: str,
) -> dict[str, Any]:
    """Bind an admitted artifact to its actual successful Main producer attempt."""
    require(
        repository == TRUSTED_REPOSITORY
        and type(repository_id) is int
        and repository_id > 0
        and type(run_id) is int
        and run_id > 0
        and type(run_attempt) is int
        and run_attempt > 0
        and run.get("id") == run_id
        and run.get("run_attempt") == run_attempt
        and run.get("path") == TRUSTED_WORKFLOW
        and run.get("event") in {"push", "workflow_dispatch"}
        and run.get("status") == "completed"
        and run.get("head_sha") == revision
        and run.get("head_branch") == "main"
        and all(
            run.get(key, {}).get("full_name") == repository
            and run.get(key, {}).get("id") == repository_id
            for key in ("repository", "head_repository")
        ),
        "source is not the registered completed Main workflow and attempt",
    )
    verify_artifact_metadata(
        artifact,
        artifact_id=artifact_id,
        zip_sha256=zip_sha256,
        revision=revision,
        run_id=run_id,
    )
    require(
        artifact.get("workflow_run", {}).get("repository_id") == repository_id
        and artifact.get("workflow_run", {}).get("head_repository_id") == repository_id
        and artifact.get("workflow_run", {}).get("head_branch") == "main",
        "artifact repository or Main source differs",
    )
    by_name = {job.get("name"): job for job in jobs}
    require(len(by_name) == len(jobs), "duplicate source job names")
    migrations = [
        job
        for name, job in by_name.items()
        if isinstance(name, str) and name.startswith("verify-production-migration-replay (")
    ]
    require(
        len(migrations) == 2
        and all(
            sum(job["name"].startswith(prefix) for job in migrations) == 1
            for prefix in (
                "verify-production-migration-replay (postgres:16.14-",
                "verify-production-migration-replay (postgres:18.6-",
            )
        ),
        "both registered production migration replays are required",
    )
    required_jobs = [
        by_name.get(name, {}) for name in ("verify-candidate-preflight", "build-candidate")
    ]
    required_jobs.extend(migrations)
    require(
        len({job.get("id") for job in required_jobs}) == len(required_jobs)
        and all(
            type(job.get("id")) is int
            and job["id"] > 0
            and job.get("run_id") == run_id
            and job.get("run_attempt") == run_attempt
            and job.get("head_sha") == revision
            and job.get("status") == "completed"
            and job.get("conclusion") == "success"
            for job in required_jobs
        ),
        "source producer and prerequisites must pass for this exact attempt",
    )
    producer = by_name["build-candidate"]
    uploads = [
        step
        for step in producer.get("steps", [])
        if step.get("name") == "Upload immutable admitted OCI bytes"
    ]
    require(
        len(uploads) == 1
        and uploads[0].get("status") == "completed"
        and uploads[0].get("conclusion") == "success",
        "source producer did not complete the admitted OCI upload",
    )
    try:
        started, created, completed = [
            datetime.fromisoformat(value)
            for value in (
                uploads[0]["started_at"],
                artifact["created_at"],
                uploads[0]["completed_at"],
            )
        ]
        require(
            all(value.tzinfo is not None for value in (started, created, completed))
            and started <= created <= completed <= datetime.now(UTC),
            "artifact creation does not bind the producer upload attempt",
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("artifact creation does not bind the producer upload attempt") from exc
    return {
        "repository": repository,
        "product_revision": revision,
        "source_run_id": run_id,
        "source_run_attempt": run_attempt,
        "source_producer_job_id": producer["id"],
        "artifact_id": artifact_id,
        "artifact_sha256": zip_sha256,
    }


def download_artifact(endpoint: str, root: Path, *, zip_sha256: str) -> None:
    """Transfer the immutable original once and retain the existing ZIP checks."""
    with tempfile.TemporaryDirectory(prefix="omnigent-promotion-download-") as temporary:
        archive = Path(temporary) / "candidate.zip"
        with archive.open("wb") as stream:
            subprocess.run(["gh", "api", endpoint + "/zip"], stdout=stream, check=True)
        extract_artifact(archive, root, zip_sha256=zip_sha256)


def extract_artifact(archive: Path, root: Path, *, zip_sha256: str) -> None:
    require(file_sha256(archive) == zip_sha256, "original artifact ZIP digest mismatch")
    root.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as bundle:
        seen: set[str] = set()
        for item in bundle.infolist():
            path = PurePosixPath(item.filename)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and "\\" not in item.filename
                and item.filename not in seen
                and (item.external_attr >> 16) & 0o170000 != 0o120000,
                "unsafe or duplicate artifact ZIP entry",
            )
            seen.add(item.filename)
        bundle.extractall(root)


def extract_layout(archive: Path, root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as bundle:
        seen: set[str] = set()
        for member in bundle.getmembers():
            path = PurePosixPath(member.name)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and "\\" not in member.name
                and (member.isfile() or member.isdir())
                and member.name not in seen,
                "unsafe or duplicate OCI archive entry",
            )
            seen.add(member.name)
        bundle.extractall(root, filter="data")


def verify_readback(archive: Path, expected: dict[str, Any]) -> None:
    require(archive_index_digest(archive) == expected["index_digest"], "registry index differs")
    require(
        inspect_oci_archive(archive, label_profile="executable") == expected["facts"],
        "registry executable or attestation facts differ from accepted candidate",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("seal", "download", "download-trusted-main", "prepare", "readback")
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--artifact-sha256")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--run-attempt", type=int)
    parser.add_argument("--repository")
    parser.add_argument("--layout-root", type=Path)
    parser.add_argument("--current-scans", type=Path)
    parser.add_argument("--discard-transferred-archives", action="store_true")
    parser.add_argument("--server", type=Path)
    parser.add_argument("--host", type=Path)
    args = parser.parse_args()
    labels = expected_labels(Path.cwd(), args.revision)
    if args.command in {"download", "download-trusted-main"}:
        require(
            args.artifact_id is not None
            and args.run_id is not None
            and args.repository is not None
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) is not None
            and args.artifact_sha256 is not None
            and re.fullmatch(r"[0-9a-f]{64}", args.artifact_sha256) is not None,
            "immutable artifact coordinates are required",
        )
        endpoint = f"repos/{args.repository}/actions/artifacts/{args.artifact_id}"
        repository_id = None
        if args.command == "download-trusted-main":
            repository_id = verify_promotion_controller(
                dict(os.environ), repository=args.repository, revision=args.revision
            )
            require(args.run_attempt is not None, "the original source attempt is required")
        metadata = json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))
        verify_artifact_metadata(
            metadata,
            artifact_id=args.artifact_id,
            zip_sha256=args.artifact_sha256,
            revision=args.revision,
            run_id=args.run_id,
        )
        source = None
        if repository_id is not None:
            run_endpoint = (
                f"repos/{args.repository}/actions/runs/{args.run_id}/attempts/{args.run_attempt}"
            )
            run = json.loads(subprocess.check_output(["gh", "api", run_endpoint], text=True))
            pages = json.loads(
                subprocess.check_output(
                    ["gh", "api", "--paginate", "--slurp", run_endpoint + "/jobs?per_page=100"],
                    text=True,
                )
            )
            source = verify_trusted_main_source(
                run,
                [job for page in pages for job in page["jobs"]],
                metadata,
                repository=args.repository,
                repository_id=repository_id,
                revision=args.revision,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                artifact_id=args.artifact_id,
                zip_sha256=args.artifact_sha256,
            )
            require(args.manifest_sha256 is not None, "expected candidate seal is required")
        download_artifact(endpoint, args.root, zip_sha256=args.artifact_sha256)
        if source is not None:
            require(
                file_sha256(args.root / MANIFEST_NAME) == args.manifest_sha256,
                "candidate seal digest mismatch",
            )
            manifest = read_json(args.root / MANIFEST_NAME)
            require(
                manifest.get("product_revision") == args.revision
                and manifest.get("source_date_epoch") == args.source_date_epoch
                and manifest.get("labels") == labels
                and set(manifest.get("images", {})) == set(IMAGES)
                and all(
                    set(manifest["images"][name]["facts"]["platforms"]) == set(PLATFORMS)
                    for name in IMAGES
                ),
                "transferred candidate source or platform set differs",
            )
            source["candidate_manifest_sha256"] = args.manifest_sha256
            source["state"] = "trusted_source_transferred_requires_current_prepare"
            (args.root / "promotion-source.json").write_text(
                json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        return 0
    if args.command == "seal":
        manifest = seal_candidate(
            args.root,
            labels=labels,
            source_date_epoch=args.source_date_epoch,
            now=datetime.now(UTC),
        )
        path = args.root / MANIFEST_NAME
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"manifest-sha256={file_sha256(path)}")
    elif args.command == "prepare":
        require(args.manifest_sha256 is not None, "expected candidate seal is required")
        manifest = verify_candidate(
            args.root,
            manifest_sha256=args.manifest_sha256,
            labels=labels,
            source_date_epoch=args.source_date_epoch,
            current_scan_root=args.current_scans,
        )
        require(args.layout_root is not None, "layout destination is required")
        for name in IMAGES:
            extract_layout(
                args.root / manifest["images"][name]["archive"], args.layout_root / name
            )
        if args.discard_transferred_archives:
            for name in IMAGES:
                (args.root / manifest["images"][name]["archive"]).unlink()
    else:
        path = args.root / MANIFEST_NAME
        require(file_sha256(path) == args.manifest_sha256, "readback candidate seal differs")
        manifest = read_json(path)
        require(
            manifest.get("product_revision") == args.revision
            and manifest.get("source_date_epoch") == args.source_date_epoch
            and manifest.get("labels") == labels,
            "readback candidate source differs",
        )
        require(
            args.server is not None and args.host is not None,
            "both registry archives are required",
        )
        for name in IMAGES:
            verify_readback(getattr(args, name), manifest["images"][name])
        print(
            json.dumps(
                {
                    "status": "pass",
                    "product_revision": args.revision,
                    "candidate_manifest_sha256": args.manifest_sha256,
                    "images": {name: manifest["images"][name]["index_digest"] for name in IMAGES},
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
