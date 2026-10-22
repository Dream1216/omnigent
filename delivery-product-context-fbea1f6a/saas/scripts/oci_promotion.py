"""Seal, transfer and verify the exact OCI bytes admitted by candidate CI."""

from __future__ import annotations

import argparse
import hashlib
import json
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
    file_sha256,
    parse_database_status,
    scan_report,
)

IMAGES = ("server", "host")
PLATFORMS = ("linux/amd64", "linux/arm64")
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_NAME = "oci-promotion-manifest.json"


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


def validate_scans(root: Path, images: dict[str, Any], *, now: datetime) -> dict[str, Any]:
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
        database_built = parse_database_status(descriptor["db"]["status"], now=now)
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
        require(not any(parsed["counts"].values()), "Critical or High finding blocks promotion")
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
            and row.get("critical") == 0
            and row.get("high") == 0
            and row.get("findings") == [],
            "scan summary does not bind original archive and report",
        )
        reports[relative] = sha
    return {"summary_sha256": file_sha256(summary_path), "reports": reports}


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
    validate_scans(current_scan_root or root, manifest["images"], now=now)
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
    parser.add_argument("command", choices=("seal", "download", "prepare", "readback"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--artifact-sha256")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--repository")
    parser.add_argument("--layout-root", type=Path)
    parser.add_argument("--current-scans", type=Path)
    parser.add_argument("--discard-transferred-archives", action="store_true")
    parser.add_argument("--server", type=Path)
    parser.add_argument("--host", type=Path)
    args = parser.parse_args()
    labels = expected_labels(Path.cwd(), args.revision)
    if args.command == "download":
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
        metadata = json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))
        verify_artifact_metadata(
            metadata,
            artifact_id=args.artifact_id,
            zip_sha256=args.artifact_sha256,
            revision=args.revision,
            run_id=args.run_id,
        )
        with tempfile.TemporaryDirectory(prefix="omnigent-promotion-download-") as temporary:
            archive = Path(temporary) / "candidate.zip"
            with archive.open("wb") as stream:
                subprocess.run(["gh", "api", endpoint + "/zip"], stdout=stream, check=True)
            extract_artifact(archive, args.root, zip_sha256=args.artifact_sha256)
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
