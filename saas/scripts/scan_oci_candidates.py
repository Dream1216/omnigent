"""Scan exact OCI archives; Aliyun Host findings are advisory, other scopes block."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict

GRYPE_VERSION = "0.120.1"
GRYPE_SHA256 = "0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d"
GRYPE_ASSET_ID = 616618032
GRYPE_ARCHIVE_BYTES = 32270829
PLATFORMS = ("linux/amd64", "linux/arm64")
SEVERITIES = ("Critical", "High")
SCAN_SCOPES = {
    "complete": {"server", "host"},
    "server-preflight": {"server"},
    "aliyun-host": {"host"},
}
OFFICIAL_DATABASE_LATEST = "https://grype.anchore.io/databases/v6/latest.json"
TEMPORARY_DATABASE_AGE: dict[str, Any] = {
    "kind": "temporary_official_grype_database_age/v1",
    "id": "OmniAgent021-20261109-official-DB48",
    "default_maximum_age_hours": 24,
    "maximum_age_hours": 48,
    "schemaVersion": "v6.1.10",
    "built": "2026-11-08T06:19:57Z",
    "archive_URL": "https://grype.anchore.io/databases/v6/"
    "vulnerability-db_v6.1.10_2026-11-08T00:22:04Z_1794118797.tar.zst",
    "archive_SHA256": "dcca24722e16c2bcf4a542a3f7fdd2147baf9215c17b973f5a7d4243fbddacea",
    "expires_at": "2026-11-10T06:19:57Z",
    "approval_sha256": "b4f07121624844ad7b83eab092a48d17440eafc2a223b3eb861e6b3420677875",
    "approval_path": "saas/supply_chain/temporary-official-db-age-approval.json",
    "products": {
        "8c851bdd12829340b2a327cf7542fe4de84d9132": "694a997f3e74999f968f4341851ebaf0765d50aa",
        "27503d14973b751a2031c6febf12a581b42b06d1": "a02ea9f17664bd0290eb5025f864672c0025075c",
    },
}
TEMPORARY_DATABASE_AGE_SHA256 = hashlib.sha256(
    json.dumps(TEMPORARY_DATABASE_AGE, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


def temporary_database_age_enabled(repo: Path | None = None) -> bool:
    root = repo or Path(__file__).resolve().parents[2]
    policy = root / "saas/supply_chain/release-policy.json"
    approval = root / str(TEMPORARY_DATABASE_AGE["approval_path"])
    if any(not path.is_file() or path.is_symlink() for path in (policy, approval)):
        return False
    value = json.loads(policy.read_text()).get("vulnerability_policy", {})
    return (
        type(value.get("maximum_scanner_database_age_hours")) is int
        and value.get("maximum_scanner_database_age_hours") == 24
        and hashlib.sha256(
            json.dumps(
                value.get("temporary_database_age"), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        == TEMPORARY_DATABASE_AGE_SHA256
        and file_sha256(approval) == TEMPORARY_DATABASE_AGE["approval_sha256"]
    )


def official_database_latest() -> dict[str, Any]:
    request = urllib.request.Request(
        OFFICIAL_DATABASE_LATEST, headers={"User-Agent": "omnigent-finite-db-age"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError("official database latest metadata exceeds its bound")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("official database latest metadata is not an object")
    return value


def approved_database_is_latest(value: dict[str, Any]) -> bool:
    return (
        isinstance(value, dict)
        and value.get("status") == "active"
        and value.get("schemaVersion") == TEMPORARY_DATABASE_AGE["schemaVersion"]
        and value.get("built") == TEMPORARY_DATABASE_AGE["built"]
        and value.get("path")
        in (
            TEMPORARY_DATABASE_AGE["archive_URL"],
            str(TEMPORARY_DATABASE_AGE["archive_URL"]).rsplit("/", 1)[-1],
        )
        and value.get("checksum") == "sha256:" + str(TEMPORARY_DATABASE_AGE["archive_SHA256"])
    )


def download_approved_database(destination: Path) -> None:
    if restore_release_cache(destination, str(TEMPORARY_DATABASE_AGE["archive_SHA256"])):
        return
    request = urllib.request.Request(
        str(TEMPORARY_DATABASE_AGE["archive_URL"]),
        headers={"User-Agent": "omnigent-finite-db-age"},
    )
    digest, size = hashlib.sha256(), 0
    with (
        urllib.request.urlopen(request, timeout=120) as response,
        destination.open("xb") as output,
    ):
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > 2 * 1024**3:
                raise ValueError("official database archive exceeds its finite bound")
            digest.update(chunk)
            output.write(chunk)
    if size == 0 or digest.hexdigest() != TEMPORARY_DATABASE_AGE["archive_SHA256"]:
        raise ValueError("official database archive full SHA256 differs")
    save_release_cache(destination, str(TEMPORARY_DATABASE_AGE["archive_SHA256"]))


def temporary_database_subjects(
    images: dict[str, Path], *, scope: str, now: datetime
) -> dict[str, dict[str, Any]]:
    """Read actual OCI metadata; unknown subjects retain the original 24h path."""
    if (
        scope == "aliyun-host"
        or not temporary_database_age_enabled()
        or not (
            datetime.fromisoformat(str(TEMPORARY_DATABASE_AGE["built"]).replace("Z", "+00:00"))
            + timedelta(hours=24)
            < now
            < datetime.fromisoformat(
                str(TEMPORARY_DATABASE_AGE["expires_at"]).replace("Z", "+00:00")
            )
        )
    ):
        return {}
    from saas.scripts.sqlite_component_disposition import image_blobs

    result = {}
    try:
        for name, archive in images.items():
            with image_blobs(archive) as blobs:
                with blobs.member("index.json") as stream:
                    descriptors = json.load(stream)["manifests"]
                if len(descriptors) != 1:
                    return {}
                index_digest = descriptors[0]["digest"]
                blobs.document(index_digest)
                archive_digest = file_sha256(archive)
                targets = {}
                for platform in PLATFORMS:
                    manifest_digest, manifest = blobs.platform(platform)
                    config_digest = manifest["config"]["digest"]
                    config = blobs.document(config_digest)
                    revision = (
                        config.get("config", {})
                        .get("Labels", {})
                        .get("org.opencontainers.image.revision")
                    )
                    products = TEMPORARY_DATABASE_AGE["products"]
                    if not isinstance(products, dict) or revision not in products:
                        return {}
                    targets[platform] = {
                        "image": name,
                        "platform": platform,
                        "archive_sha256": archive_digest,
                        "index_digest": index_digest,
                        "manifest_digest": manifest_digest,
                        "config_digest": config_digest,
                        "source_revision": revision,
                        "product_tree": products[revision],
                    }
                result[name] = targets
        if (
            len(
                {row["source_revision"] for targets in result.values() for row in targets.values()}
            )
            != 1
        ):
            return {}
    except (KeyError, ValueError, OSError, tarfile.TarError):
        return {}
    return result


def validate_database_age_disposition(
    data: dict[str, Any],
    receipt: object,
    *,
    subject: dict[str, Any] | None,
    now: datetime,
    repo: Path | None = None,
    report_sha256: str | None = None,
) -> None:
    """Only the exact human-approved DB and an actual bound subject can use 48h."""
    if not isinstance(receipt, dict) or set(receipt) != {
        "rule_sha256",
        "approval_sha256",
        "maximum_age_hours",
        "expires_at",
        "database_sha256",
        "database_schema",
        "database_built_at",
        "official_latest",
        "official_latest_checked_at",
        "subject",
        "report_sha256",
    }:
        raise ValueError("finite database age receipt fields differ")
    bound = receipt.get("subject")
    if not isinstance(bound, dict) or set(bound) != {
        "image",
        "platform",
        "archive_sha256",
        "index_digest",
        "manifest_digest",
        "config_digest",
        "source_revision",
        "product_tree",
    }:
        raise ValueError("finite database age OCI subject is incomplete")
    products = TEMPORARY_DATABASE_AGE["products"]
    built = datetime.fromisoformat(str(data.get("built", "")).replace("Z", "+00:00"))
    checked = datetime.fromisoformat(
        str(receipt["official_latest_checked_at"]).replace("Z", "+00:00")
    )
    if (
        not temporary_database_age_enabled(repo)
        or data.get("valid") is not True
        or receipt["rule_sha256"] != TEMPORARY_DATABASE_AGE_SHA256
        or receipt["approval_sha256"] != TEMPORARY_DATABASE_AGE["approval_sha256"]
        or re.fullmatch(r"[0-9a-f]{64}", str(receipt["report_sha256"])) is None
        or receipt["report_sha256"] != report_sha256
        or type(receipt["maximum_age_hours"]) is not int
        or receipt["maximum_age_hours"] != 48
        or receipt["expires_at"] != TEMPORARY_DATABASE_AGE["expires_at"]
        or now >= datetime.fromisoformat(str(receipt["expires_at"]).replace("Z", "+00:00"))
        or receipt["database_sha256"] != TEMPORARY_DATABASE_AGE["archive_SHA256"]
        or receipt["database_schema"] != data.get("schemaVersion")
        or data.get("schemaVersion") != TEMPORARY_DATABASE_AGE["schemaVersion"]
        or receipt["database_built_at"] != data.get("built")
        or built
        != datetime.fromisoformat(str(TEMPORARY_DATABASE_AGE["built"]).replace("Z", "+00:00"))
        or built.tzinfo is None
        or now.tzinfo is None
        or checked.tzinfo is None
        or not timedelta(0) <= now - built <= timedelta(hours=48)
        or not built <= checked <= now
        or not approved_database_is_latest(receipt["official_latest"])
        or bound["image"] not in {"server", "host"}
        or bound["platform"] not in PLATFORMS
        or not isinstance(products, dict)
        or products.get(bound["source_revision"]) != bound["product_tree"]
        or re.fullmatch(r"[0-9a-f]{64}", str(bound["archive_sha256"])) is None
        or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", str(bound[key])) is None
            for key in ("index_digest", "manifest_digest", "config_digest")
        )
        or not isinstance(subject, dict)
        or subject.get("manifestDigest") != bound["manifest_digest"]
        or subject.get("imageID") != bound["config_digest"]
        or subject.get("os") != "linux"
        or subject.get("architecture") != bound["platform"].split("/")[1]
        or subject.get("labels", {}).get("org.opencontainers.image.revision")
        != bound["source_revision"]
    ):
        raise ValueError("finite database age approval, original DB, time or actual OCI differs")


def make_database_age_disposition(
    status: dict[str, Any],
    latest: dict[str, Any],
    subject: dict[str, Any],
    *,
    now: datetime,
    report_sha256: str,
    checked_at: datetime,
) -> dict[str, Any]:
    receipt = {
        "rule_sha256": TEMPORARY_DATABASE_AGE_SHA256,
        "approval_sha256": TEMPORARY_DATABASE_AGE["approval_sha256"],
        "maximum_age_hours": 48,
        "expires_at": TEMPORARY_DATABASE_AGE["expires_at"],
        "database_sha256": TEMPORARY_DATABASE_AGE["archive_SHA256"],
        "database_schema": status["schemaVersion"],
        "database_built_at": status["built"],
        "official_latest": latest,
        "official_latest_checked_at": checked_at.isoformat(),
        "subject": subject,
        "report_sha256": report_sha256,
    }
    target = {
        "manifestDigest": subject["manifest_digest"],
        "imageID": subject["config_digest"],
        "os": "linux",
        "architecture": subject["platform"].split("/")[1],
        "labels": {"org.opencontainers.image.revision": subject["source_revision"]},
    }
    validate_database_age_disposition(
        status, receipt, subject=target, now=now, report_sha256=report_sha256
    )
    return receipt


def validate_approved_database_status(status: dict[str, Any], *, now: datetime) -> None:
    built = datetime.fromisoformat(str(status.get("built", "")).replace("Z", "+00:00"))
    if (
        status.get("valid") is not True
        or status.get("schemaVersion") != TEMPORARY_DATABASE_AGE["schemaVersion"]
        or built
        != datetime.fromisoformat(str(TEMPORARY_DATABASE_AGE["built"]).replace("Z", "+00:00"))
        or now.tzinfo is None
        or built.tzinfo is None
        or not timedelta(0) <= now - built <= timedelta(hours=48)
        or now
        >= datetime.fromisoformat(str(TEMPORARY_DATABASE_AGE["expires_at"]).replace("Z", "+00:00"))
    ):
        raise ValueError("approved database validity, original built time or hard expiry differs")


def database_age_disposition_for_report(scan: dict[str, Any], raw: bytes) -> dict[str, Any] | None:
    digest = hashlib.sha256(raw).hexdigest()
    rows = scan.get("database_age_dispositions", [])
    matches = [
        row.get("receipt")
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("receipt"), dict)
        and row["receipt"].get("report_sha256") == digest
    ]
    if len(matches) > 1:
        raise ValueError("database age receipt is duplicated")
    return matches[0] if matches else None


def validate_release_database_age(
    repo: Path, image: dict[str, Any], scan: dict[str, Any], *, now: datetime
) -> None:
    bundle = scan.get("database_age_dispositions")
    if not isinstance(bundle, list) or len(bundle) != 2:
        raise ValueError("finite release database age requires both original platform reports")
    seen = set()
    for row in bundle:
        if not isinstance(row, dict) or set(row) != {"raw_report", "receipt"}:
            raise ValueError("finite release database age report bundle differs")
        if not isinstance(row["raw_report"], str):
            raise ValueError("finite release database report must preserve original JSON text")
        raw = row["raw_report"].encode()
        report, receipt = json.loads(raw), row["receipt"]
        target = report.get("source", {}).get("target")
        descriptor = report.get("descriptor", {})
        if descriptor.get("name") != "grype" or descriptor.get("version") != GRYPE_VERSION:
            raise ValueError("finite release database scanner differs")
        configuration = descriptor.get("configuration", {})
        if (
            configuration.get("only-fixed") is not False
            or configuration.get("only-notfixed") is not False
            or configuration.get("exclude", []) != []
            or configuration.get("vex-documents", []) != []
        ):
            raise ValueError("finite database age cannot authorize filtered raw reports")
        validate_database_age_disposition(
            descriptor["db"]["status"],
            receipt,
            subject=target,
            now=now,
            repo=repo,
            report_sha256=hashlib.sha256(raw).hexdigest(),
        )
        subject = receipt["subject"]
        platform = subject["platform"]
        if (
            platform in seen
            or subject["index_digest"] != image.get("manifest_digest")
            or subject["manifest_digest"] != image.get("platform_digests", {}).get(platform)
            or subject["config_digest"] != image.get("config_digests", {}).get(platform)
            or subject["source_revision"]
            != image.get("labels", {}).get("org.opencontainers.image.revision")
            or str(image.get("name", "")).rsplit("/", 1)[-1] != "omnigent-saas-" + subject["image"]
            or datetime.fromisoformat(receipt["database_built_at"].replace("Z", "+00:00"))
            != datetime.fromisoformat(
                str(scan.get("scanner_database_updated_at", "")).replace("Z", "+00:00")
            )
            or datetime.fromisoformat(receipt["official_latest_checked_at"].replace("Z", "+00:00"))
            > datetime.fromisoformat(str(scan.get("scan_completed_at", "")).replace("Z", "+00:00"))
        ):
            raise ValueError("finite release database receipt belongs to another actual OCI")
        parsed = scan_report(report)
        if "component_dispositions" not in scan and any(parsed["counts"].values()):
            raise ValueError("finite database age cannot authorize raw Critical or High findings")
        seen.add(platform)
    if seen != set(PLATFORMS):
        raise ValueError("finite release database receipts omit a platform")
    if "component_dispositions" not in scan and hashlib.sha256(
        json.dumps(bundle, sort_keys=True).encode()
    ).hexdigest() != scan.get("report_sha256"):
        raise ValueError("finite release database original report bundle digest differs")


def scan_platforms(scope: str) -> tuple[str, ...]:
    if scope not in SCAN_SCOPES:
        raise ValueError("Unsupported scan scope")
    return ("linux/amd64",) if scope == "aliyun-host" else PLATFORMS


class ScanReport(TypedDict):
    counts: dict[str, int]
    findings: list[dict[str, object]]


def parse_database_status(
    data: dict[str, Any],
    *,
    now: datetime,
    database_age_disposition: object = None,
    subject: dict[str, Any] | None = None,
    report_sha256: str | None = None,
) -> str:
    built = data.get("built")
    if data.get("valid") is not True or not isinstance(built, str):
        raise ValueError("Grype vulnerability database is invalid")
    built_at = datetime.fromisoformat(built.replace("Z", "+00:00"))
    if built_at.tzinfo is None:
        raise ValueError("Grype database timestamp lacks a timezone")
    if database_age_disposition is not None:
        validate_database_age_disposition(
            data, database_age_disposition, subject=subject, now=now, report_sha256=report_sha256
        )
    elif not timedelta(0) <= now - built_at <= timedelta(hours=24):
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


def restore_release_cache(destination: Path, digest: str, *, size: int | None = None) -> bool:
    """Cache only complete hash-verified archives; qualification never comes from a cache."""
    root = os.environ.get("OMNIGENT_RELEASE_TOOL_CACHE")
    if not root:
        return False
    cached = Path(root) / digest
    if (
        not cached.is_file()
        or cached.is_symlink()
        or (size is not None and cached.stat().st_size != size)
        or file_sha256(cached) != digest
    ):
        return False
    shutil.copyfile(cached, destination)
    if file_sha256(destination) != digest:
        destination.unlink()
        raise ValueError("cached release archive changed during transfer")
    return True


def save_release_cache(source: Path, digest: str) -> None:
    root = os.environ.get("OMNIGENT_RELEASE_TOOL_CACHE")
    if not root:
        return
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream:
        temporary = Path(stream.name)
    try:
        shutil.copyfile(source, temporary)
        if file_sha256(temporary) != digest:
            raise ValueError("release archive changed before caching")
        temporary.replace(directory / digest)
    finally:
        temporary.unlink(missing_ok=True)


def install_grype(destination: Path) -> Path:
    request = urllib.request.Request(
        f"https://api.github.com/repos/anchore/grype/releases/assets/{GRYPE_ASSET_ID}",
        headers={"Accept": "application/octet-stream", "User-Agent": "omnigent-grype-supply"},
    )
    if token := os.environ.get("GH_TOKEN"):
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    archive = destination / "grype.tar.gz"
    if not restore_release_cache(archive, GRYPE_SHA256, size=GRYPE_ARCHIVE_BYTES):
        with (
            urllib.request.urlopen(request, timeout=120) as response,
            archive.open("wb") as stream,
        ):
            digest = hashlib.sha256()
            downloaded = 0
            while chunk := response.read(1024 * 1024):
                downloaded += len(chunk)
                if downloaded > GRYPE_ARCHIVE_BYTES:
                    raise ValueError("Grype release archive size mismatch")
                digest.update(chunk)
                stream.write(chunk)
        if downloaded != GRYPE_ARCHIVE_BYTES or digest.hexdigest() != GRYPE_SHA256:
            archive.unlink(missing_ok=True)
            raise ValueError("Grype release archive size or hash mismatch")
        save_release_cache(archive, GRYPE_SHA256)
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
    subjects = temporary_database_subjects(images, scope=args.scope, now=datetime.now(UTC))
    latest = official_database_latest() if subjects else {}
    temporary_database = bool(subjects and approved_database_is_latest(latest))
    with tempfile.TemporaryDirectory(prefix="omnigent-grype-") as temporary:
        scanner_root = Path(temporary)
        scanner = install_grype(scanner_root)
        config = scanner_root / "grype.yaml"
        config.write_text(
            "ignore: []\nvex-documents: []\ndb:\n"
            f"  cache-dir: {scanner_root / 'grype-db'}\n"
            f"  auto-update: {'false' if temporary_database else 'true'}\n  validate-age: true\n"
            f"  max-allowed-built-age: {48 if temporary_database else 24}h\n"
        )
        database_archive = scanner_root / "official-db.tar.zst"
        if temporary_database:
            download_approved_database(database_archive)
            subprocess.run(
                [str(scanner), "-c", str(config), "db", "import", str(database_archive)],
                check=True,
            )
        else:
            subprocess.run([str(scanner), "-c", str(config), "db", "update"], check=True)
        status = json.loads(
            subprocess.check_output(
                [str(scanner), "-c", str(config), "db", "status", "-o", "json"], text=True
            )
        )
        if temporary_database:
            validate_approved_database_status(status, now=datetime.now(UTC))
            database_built_at = status["built"]
        else:
            database_built_at = parse_database_status(status, now=datetime.now(UTC))
        summaries = []
        findings_present = False
        blocked = False
        for name, archive in sorted(images.items()):
            archive_digest = file_sha256(archive)
            for platform in scan_platforms(args.scope):
                database_age_disposition = None
                latest_checked_at = datetime.now(UTC)
                if temporary_database:
                    latest = official_database_latest()
                    if (
                        not approved_database_is_latest(latest)
                        or file_sha256(database_archive)
                        != TEMPORARY_DATABASE_AGE["archive_SHA256"]
                    ):
                        raise ValueError(
                            "official latest or full verified database changed before scan"
                        )
                    latest_checked_at = datetime.now(UTC)
                    validate_approved_database_status(status, now=latest_checked_at)
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
                raw_report = json.loads(output.read_text())
                if temporary_database:
                    database_age_disposition = make_database_age_disposition(
                        raw_report["descriptor"]["db"]["status"],
                        latest,
                        subjects[name][platform],
                        now=datetime.now(UTC),
                        checked_at=latest_checked_at,
                        report_sha256=file_sha256(output),
                    )
                    parse_database_status(
                        raw_report["descriptor"]["db"]["status"],
                        now=datetime.now(UTC),
                        database_age_disposition=database_age_disposition,
                        subject=raw_report.get("source", {}).get("target"),
                        report_sha256=file_sha256(output),
                    )
                    raw_built = raw_report["descriptor"]["db"]["status"]["built"]
                    if summaries and raw_built != database_built_at:
                        raise ValueError("raw platform reports disagree on their DB timestamp")
                    database_built_at = raw_built
                parsed = scan_report(raw_report)
                counts = parsed["counts"]
                present = result.returncode == 2 or any(counts.values())
                findings_present |= present
                disposition = None
                if args.scope != "aliyun-host" and any(counts.values()) and result.returncode == 2:
                    from saas.scripts.approved_disposition import inspect_approved_disposition

                    try:
                        disposition = inspect_approved_disposition(
                            archive,
                            output,
                            platform=platform,
                            now=datetime.now(UTC),
                            **(
                                {"database_age_disposition": database_age_disposition}
                                if database_age_disposition is not None
                                else {}
                            ),
                        )
                    except ValueError as error:
                        print(f"Component disposition rejected: {error}")
                blocked |= present and disposition is None
                summaries.append(
                    {
                        "image": name,
                        "platform": platform,
                        "archive_sha256": archive_digest,
                        "report_sha256": file_sha256(output),
                        "scanner_returncode": result.returncode,
                        "critical": counts["Critical"],
                        "high": counts["High"],
                        "findings": parsed["findings"],
                        **(
                            {"database_age_disposition": database_age_disposition}
                            if database_age_disposition is not None
                            else {}
                        ),
                        **(
                            {
                                "component_disposition": disposition,
                                "scanner_exit": result.returncode,
                            }
                            if disposition is not None
                            else {}
                        ),
                    }
                )
    advisory = args.scope == "aliyun-host"
    receipt = {
        "scope": args.scope,
        "vulnerability_policy": "advisory" if advisory else "blocking",
        "vulnerability_findings_present": findings_present,
        "scanner": f"grype {GRYPE_VERSION}",
        "database_built_at": database_built_at,
        "exceptions": [],
        "images": summaries,
    }
    summary_name = {
        "complete": "candidate-scan-summary.json",
        "server-preflight": "server-preflight-scan-summary.json",
        "aliyun-host": "aliyun-host-scan-summary.json",
    }[args.scope]
    (args.output / summary_name).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    if advisory and findings_present:
        print(
            "::warning::Aliyun Host vulnerability findings are advisory; "
            "original reports, counts and scanner exit codes are retained."
        )
    return 2 if blocked and not advisory else 0


if __name__ == "__main__":
    raise SystemExit(main())
