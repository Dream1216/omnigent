"""Bind an advisory scan and registry readback to an unchanged Aliyun Host OCI."""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts.compare_oci_rebuilds import inspect_oci_archive
from saas.scripts.oci_promotion import archive_index_digest, extract_layout, read_json, require
from saas.scripts.scan_oci_candidates import (
    GRYPE_VERSION,
    file_sha256,
    parse_database_status,
    scan_report,
)

PROFILE = "aliyun-host-minimal"


def select_candidate_artifacts(
    run: dict[str, Any],
    jobs: dict[str, Any],
    artifacts: dict[str, Any],
    *,
    revision: str,
    run_id: int,
) -> list[dict[str, Any]]:
    """Select both native archives from a successful, source-bound Gen2 build."""
    repository = "Dream1216/omnigent"
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid source revision")
    require(
        run_id > 0
        and run.get("id") == run_id
        and run.get("head_sha") == revision
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
        and run.get("head_branch") == "codex/aliyun-sandbox-p1-p5-20261031"
        and run.get("path") == ".github/workflows/saas-aliyun-host-candidate.yml"
        and run.get("event") in {"push", "workflow_dispatch"}
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "original run must be a successful Gen2 build from the expected repository and branch",
    )
    attempt = run.get("run_attempt")
    require(type(attempt) is int and attempt > 0, "invalid original run attempt")
    require(jobs.get("total_count") == len(jobs.get("jobs", [])), "incomplete original jobs")
    for name in ("verify", "build (1)", "build (2)", "compare-and-scan"):
        matching = [job for job in jobs["jobs"] if job.get("name") == name]
        require(
            len(matching) == 1
            and matching[0].get("status") == "completed"
            and matching[0].get("conclusion") == "success",
            f"original {name} job did not succeed",
        )
    require(
        artifacts.get("total_count") == len(artifacts.get("artifacts", [])),
        "incomplete original artifacts",
    )
    selected = []
    for number, destination in ((1, "first"), (2, "second")):
        name = f"aliyun-host-{revision}-{attempt}-{number}"
        matching = [item for item in artifacts["artifacts"] if item.get("name") == name]
        require(len(matching) == 1, "missing or duplicate original archive")
        item = matching[0]
        require(
            type(item.get("id")) is int
            and item["id"] > 0
            and item.get("expired") is False
            and re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest", "")) is not None
            and item.get("workflow_run", {}).get("id") == run_id
            and item.get("workflow_run", {}).get("head_sha") == revision,
            "original archive identity or digest mismatch",
        )
        selected.append(
            {"destination": destination, "artifact_id": item["id"], "digest": item["digest"]}
        )
    require(selected[0]["artifact_id"] != selected[1]["artifact_id"], "duplicate archive identity")
    return selected


def prepare(archive: Path, revision: str, scans: Path, layout: Path) -> dict[str, Any]:
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid source revision")
    facts = inspect_oci_archive(archive, label_profile=PROFILE)
    require(set(facts["platforms"]) == {"linux/amd64"}, "Aliyun Host must be Linux amd64")
    platform = facts["platforms"]["linux/amd64"]
    require(platform["labels"]["org.opencontainers.image.revision"] == revision, "source mismatch")
    digest = file_sha256(archive)
    summary = read_json(scans / "aliyun-host-scan-summary.json")
    require(
        summary.get("scope") == "aliyun-host"
        and summary.get("vulnerability_policy") == "advisory"
        and summary.get("scanner") == f"grype {GRYPE_VERSION}"
        and summary.get("exceptions") == [],
        "unexpected Aliyun advisory scan policy",
    )
    rows = summary.get("images", [])
    require(len(rows) == 1, "one exact Aliyun Host scan is required")
    row = rows[0]
    raw = scans / "host-amd64-grype.json"
    require(
        row.get("image") == "host"
        and row.get("platform") == "linux/amd64"
        and row.get("archive_sha256") == digest
        and row.get("report_sha256") == file_sha256(raw)
        and row.get("scanner_returncode") in (0, 2),
        "scan archive or report binding mismatch",
    )
    report = read_json(raw)
    parsed = scan_report(report)
    require(
        row.get("critical") == parsed["counts"]["Critical"]
        and row.get("high") == parsed["counts"]["High"]
        and row.get("findings") == parsed["findings"],
        "raw scan counts or findings mismatch",
    )
    built = parse_database_status(report["descriptor"]["db"]["status"], now=datetime.now(UTC))
    require(built == summary.get("database_built_at"), "database identity mismatch")
    target = report["source"]["target"]
    require(
        target.get("manifestDigest") == platform["manifest_digest"]
        and target.get("imageID") == platform["config_digest"]
        and target.get("architecture") == "amd64"
        and target.get("os") == "linux"
        and target.get("labels") == platform["labels"],
        "raw scanner image identity mismatch",
    )
    index_digest = archive_index_digest(archive)
    extract_layout(archive, layout)
    return {
        "source_revision": revision,
        "archive_sha256": digest,
        "index_digest": index_digest,
        "facts": facts,
        "scan": summary,
        "scan_summary_sha256": file_sha256(scans / "aliyun-host-scan-summary.json"),
        "qualification": "private-cloud-validation-candidate",
        "production_ready": False,
    }


def verify_readback(archive: Path, receipt: dict[str, Any]) -> None:
    require(archive_index_digest(archive) == receipt["index_digest"], "registry index changed")
    require(
        inspect_oci_archive(archive, label_profile=PROFILE) == receipt["facts"],
        "registry executable bytes or attestations changed",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    selection_parser = commands.add_parser("select")
    selection_parser.add_argument("--evidence", type=Path, required=True)
    selection_parser.add_argument("--revision", required=True)
    selection_parser.add_argument("--run-id", type=int, required=True)
    selection_parser.add_argument("--receipt", type=Path, required=True)
    promotion = commands.add_parser("prepare")
    promotion.add_argument("--archive", type=Path, required=True)
    promotion.add_argument("--revision", required=True)
    promotion.add_argument("--scans", type=Path, required=True)
    promotion.add_argument("--layout", type=Path, required=True)
    promotion.add_argument("--receipt", type=Path, required=True)
    readback = commands.add_parser("readback")
    readback.add_argument("--archive", type=Path, required=True)
    readback.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "select":
        selection = select_candidate_artifacts(
            read_json(args.evidence / "run.json"),
            read_json(args.evidence / "jobs.json"),
            read_json(args.evidence / "artifacts.json"),
            revision=args.revision,
            run_id=args.run_id,
        )
        args.receipt.write_text(json.dumps(selection, indent=2) + "\n")
    elif args.command == "prepare":
        receipt = prepare(args.archive, args.revision, args.scans, args.layout)
        args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    else:
        verify_readback(args.archive, read_json(args.receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
