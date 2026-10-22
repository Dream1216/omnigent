"""Scan both platforms of exact OCI candidate archives with a fresh Grype DB."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict

GRYPE_VERSION = "0.120.1"
GRYPE_SHA256 = "0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d"
PLATFORMS = ("linux/amd64", "linux/arm64")
SEVERITIES = ("Critical", "High")
SCAN_SCOPES = {"complete": {"server", "host"}, "server-preflight": {"server"}}


class ScanReport(TypedDict):
    counts: dict[str, int]
    findings: list[dict[str, object]]


def parse_database_status(data: dict[str, object], *, now: datetime) -> str:
    built = data.get("built")
    if data.get("valid") is not True or not isinstance(built, str):
        raise ValueError("Grype vulnerability database is invalid")
    built_at = datetime.fromisoformat(built.replace("Z", "+00:00"))
    if built_at.tzinfo is None:
        raise ValueError("Grype database timestamp lacks a timezone")
    if not timedelta(0) <= now - built_at <= timedelta(hours=24):
        raise ValueError("Grype vulnerability database is older than 24 hours")
    schema = data.get("schemaVersion")
    if not isinstance(schema, str) or not schema.startswith("v6."):
        raise ValueError("unexpected Grype database schema")
    return built


def scan_report(data: dict[str, object]) -> ScanReport:
    matches = data.get("matches")
    ignored = data.get("ignoredMatches", [])
    if not isinstance(matches, list) or ignored != []:
        raise ValueError("Grype report is incomplete or contains ignored findings")
    counts = dict.fromkeys(SEVERITIES, 0)
    findings: list[dict[str, object]] = []
    for match in matches:
        if not isinstance(match, dict):
            raise ValueError("Grype match is malformed")
        vulnerability = match.get("vulnerability")
        artifact = match.get("artifact")
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            raise ValueError("Grype match lacks vulnerability or package identity")
        severity = vulnerability.get("severity")
        if severity in counts:
            counts[severity] += 1
            findings.append(
                {
                    "id": vulnerability.get("id"),
                    "severity": severity,
                    "package": artifact.get("name"),
                    "version": artifact.get("version"),
                }
            )
    return {"counts": counts, "findings": findings}


def validate_image_scope(images: dict[str, Path], scope: str) -> None:
    expected = SCAN_SCOPES[scope]
    if set(images) != expected:
        raise ValueError(f"{scope} scan requires exactly: {', '.join(sorted(expected))}")


def install_grype(destination: Path) -> Path:
    url = (
        f"https://github.com/anchore/grype/releases/download/v{GRYPE_VERSION}/"
        f"grype_{GRYPE_VERSION}_linux_amd64.tar.gz"
    )
    archive = destination / "grype.tar.gz"
    with urllib.request.urlopen(url, timeout=120) as response, archive.open("wb") as stream:
        digest = hashlib.sha256()
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            stream.write(chunk)
    if digest.hexdigest() != GRYPE_SHA256:
        archive.unlink(missing_ok=True)
        raise ValueError("Grype release archive hash mismatch")
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(destination), "grype"], check=True)
    binary = destination / "grype"
    version = subprocess.check_output([str(binary), "version"], text=True)
    if re.search(rf"(?m)^Version:\s+{re.escape(GRYPE_VERSION)}\s*$", version) is None:
        raise ValueError("Grype binary version mismatch")
    return binary


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", action="append", required=True, metavar="NAME=OCI_ARCHIVE")
    parser.add_argument("--scope", choices=tuple(SCAN_SCOPES), default="complete")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    images = {}
    for item in args.image:
        name, separator, path = item.partition("=")
        if separator != "=" or name not in {"server", "host"} or name in images:
            parser.error("images must be unique server= and host= OCI archives")
        archive = Path(path)
        if not archive.is_file():
            parser.error(f"OCI archive is missing: {archive}")
        images[name] = archive
    try:
        validate_image_scope(images, args.scope)
    except ValueError as error:
        parser.error(str(error))

    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="omnigent-grype-") as temporary:
        scanner_root = Path(temporary)
        scanner = install_grype(scanner_root)
        config = scanner_root / "grype.yaml"
        config.write_text(
            "ignore: []\nvex-documents: []\ndb:\n"
            f"  cache-dir: {scanner_root / 'grype-db'}\n"
            "  auto-update: true\n  validate-age: true\n"
            "  max-allowed-built-age: 24h\n"
        )
        subprocess.run([str(scanner), "-c", str(config), "db", "update"], check=True)
        status = json.loads(
            subprocess.check_output(
                [str(scanner), "-c", str(config), "db", "status", "-o", "json"], text=True
            )
        )
        database_built_at = parse_database_status(status, now=datetime.now(UTC))
        summaries = []
        blocked = False
        for name, archive in sorted(images.items()):
            archive_digest = file_sha256(archive)
            for platform in PLATFORMS:
                output = args.output / f"{name}-{platform.split('/')[-1]}-grype.json"
                result = subprocess.run(
                    [
                        str(scanner),
                        "-c",
                        str(config),
                        f"oci-archive:{archive}",
                        "--platform",
                        platform,
                        "--fail-on",
                        "high",
                        "-o",
                        "json",
                        "--file",
                        str(output),
                    ],
                    check=False,
                )
                if result.returncode not in (0, 2) or not output.is_file():
                    raise RuntimeError(f"Grype failed to scan {name} {platform}")
                parsed = scan_report(json.loads(output.read_text()))
                counts = parsed["counts"]
                blocked |= result.returncode == 2 or any(counts.values())
                summaries.append(
                    {
                        "image": name,
                        "platform": platform,
                        "archive_sha256": archive_digest,
                        "report_sha256": file_sha256(output),
                        "critical": counts["Critical"],
                        "high": counts["High"],
                        "findings": parsed["findings"],
                    }
                )
    receipt = {
        "scanner": f"grype {GRYPE_VERSION}",
        "database_built_at": database_built_at,
        "exceptions": [],
        "images": summaries,
    }
    summary_name = (
        "server-preflight-scan-summary.json"
        if args.scope == "server-preflight"
        else "candidate-scan-summary.json"
    )
    (args.output / summary_name).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 2 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
