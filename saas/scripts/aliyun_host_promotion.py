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
    if args.command == "prepare":
        receipt = prepare(args.archive, args.revision, args.scans, args.layout)
        args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    else:
        verify_readback(args.archive, read_json(args.receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
