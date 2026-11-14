"""Refresh only vulnerability evidence for the fixed, already signed M2c OCI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.oci_promotion import (
    MANIFEST_NAME,
    extract_artifact,
    read_json,
    require,
    validate_scans,
    verify_candidate,
)
from saas.scripts.resume_oci_promotion import (
    api,
    build_certificate_claims,
    build_promotion_predicate,
    verify_predicate,
)
from saas.scripts.scan_oci_candidates import official_database_latest, scan_report

ORIGIN_FILE = Path(".github/actions/compat-smoke-m2c-evidence-renewal/origin.json")
WORKFLOW = ".github/workflows/saas-m2c-evidence-renewal.yml"
PRODUCT = "2c34fd412118b806156b42de767dc2315e25cbd1"


def origin() -> dict:
    value = read_json(ORIGIN_FILE)
    require(
        value["product_revision"] == PRODUCT
        and value["product_tree"] == "0589ca4ed27b94691dae61db48dd84e4777401bc"
        and value["run_id"] == 43535964651
        and value["attempt"] == 1
        and value["workflow"] == ".github/workflows/saas-image-candidate.yml"
        and value["rebuilt"] is False,
        "fixed original signed M identity differs",
    )
    return value


def instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() == timedelta(0), "UTC timestamp required")
    return parsed


def verify_origin(run: dict, jobs: dict, tree: dict, artifacts: dict) -> None:
    value = origin()
    require(
        run["id"] == value["run_id"]
        and run["run_attempt"] == value["attempt"]
        and run["head_sha"] == PRODUCT
        and run["head_branch"] == "main"
        and run["path"] == value["workflow"]
        and run["event"] == "workflow_dispatch"
        and run["status"] == "completed"
        and run["conclusion"] == "success"
        and run["repository"]["full_name"] == value["repository"]
        and tree["sha"] == PRODUCT
        and tree["tree"]["sha"] == value["product_tree"],
        "original native source or signing invocation differs",
    )
    by_id = {job["id"]: job for job in jobs["jobs"]}
    for job_id in value["required_jobs"]:
        job = by_id[job_id]
        require(
            job["run_id"] == value["run_id"]
            and job["run_attempt"] == value["attempt"]
            and job["status"] == "completed"
            and job["conclusion"] == "success"
            and job["runner_group_name"] == "GitHub Actions"
            and "ubuntu-24.04" in job["labels"],
            "original required hosted job differs",
        )
    actual = {item["id"]: item for item in artifacts["artifacts"]}
    for expected in value["artifacts"].values():
        item = actual[expected["id"]]
        require(
            item["name"] == expected["name"]
            and item["size_in_bytes"] == expected["bytes"]
            and item["digest"] == "sha256:" + expected["sha256"]
            and item["expired"] is False
            and item["workflow_run"]["id"] == value["run_id"]
            and item["workflow_run"]["head_sha"] == PRODUCT,
            "original immutable artifact differs or expired",
        )


def download_origin(destination: Path) -> None:
    value = origin()
    prefix = f"repos/{value['repository']}"
    native = {
        "run": api(f"{prefix}/actions/runs/{value['run_id']}/attempts/{value['attempt']}"),
        "jobs": api(
            f"{prefix}/actions/runs/{value['run_id']}/attempts/{value['attempt']}/jobs?per_page=100"
        ),
        "tree": api(f"{prefix}/git/commits/{PRODUCT}"),
        "artifacts": api(f"{prefix}/actions/runs/{value['run_id']}/artifacts?per_page=100"),
    }
    verify_origin(**native)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "native-origin.json").write_text(json.dumps(native, sort_keys=True) + "\n")
    for role, target in (("oci", "sealed"), ("signed", "signed-origin")):
        item = value["artifacts"][role]
        archive = destination / f"{role}.zip"
        download_artifact_bytes(
            item["id"], archive, expected_size=item["bytes"], expected_sha256=item["sha256"]
        )
        extract_artifact(archive, destination / target, zip_sha256=item["sha256"])
        archive.unlink()
    require(
        digest(destination / "sealed" / MANIFEST_NAME) == value["manifest_sha256"],
        "retained OCI seal differs",
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def promotion_predicate(policy: str, run: str, attempt: str) -> dict:
    value = origin()
    binding = {
        **value,
        "oci_artifact_id": value["artifacts"]["oci"]["id"],
        "oci_artifact_sha256": value["artifacts"]["oci"]["sha256"],
    }
    return build_promotion_predicate(binding, WORKFLOW, policy, run, attempt)


def verify_signature(entries: list, subject: str, *, policy: str, run: str, attempt: str) -> None:
    value = origin()
    verify_predicate(
        entries,
        subject="sha256:" + subject,
        predicate=promotion_predicate(policy, run, attempt),
        predicate_type="https://slsa.dev/provenance/v1",
        claims=build_certificate_claims(value["repository"], policy, WORKFLOW, run, attempt),
    )


def qualify(
    sealed: Path, scans: Path, *, policy: str, run: str, attempt: str, started: str
) -> dict:
    value = origin()
    require(
        re.fullmatch(r"[0-9a-f]{40}", policy) is not None
        and policy != PRODUCT
        and re.fullmatch(r"[1-9][0-9]*", run) is not None
        and re.fullmatch(r"[1-9][0-9]*", attempt) is not None,
        "actual distinct controller and invocation required",
    )
    current = datetime.now(UTC)
    beginning = instant(started)
    require(beginning <= current, "scan start cannot be in the future")
    manifest = read_json(sealed / MANIFEST_NAME)
    manifest = verify_candidate(
        sealed,
        manifest_sha256=value["manifest_sha256"],
        labels=manifest["labels"],
        source_date_epoch=value["source_date_epoch"],
        current_scan_root=scans,
    )
    require(
        manifest["product_revision"] == PRODUCT
        and {role: row["index_digest"] for role, row in manifest["images"].items()}
        == value["images"],
        "fresh evidence cannot change source or OCI subjects",
    )
    latest = official_database_latest()
    checked = datetime.now(UTC)
    summary = read_json(scans / "grype/candidate-scan-summary.json")
    require(
        all(
            row.get("database_age_disposition") is None
            and row.get("component_disposition") is None
            for row in summary["images"]
        ),
        "renewal accepts no age or component exception",
    )
    qualified = validate_scans(scans, manifest["images"], now=checked)
    require("temporary_database_age" not in qualified, "normal24 only")
    built = instant(summary["database_built_at"])
    expiry = min(built + timedelta(hours=24), checked + timedelta(hours=24))
    require(
        latest["status"] == "active"
        and instant(latest["built"]) == built
        and beginning <= checked < expiry
        and checked - built < timedelta(hours=24),
        "current official database or time bound differs",
    )
    reports = {}
    for role in ("server", "host"):
        for arch in ("amd64", "arm64"):
            coordinate = f"{role}-{arch}"
            path = scans / f"grype/{coordinate}-grype.json"
            raw = read_json(path)
            descriptor = raw["descriptor"]
            config = descriptor["configuration"]
            db = config["db"]
            require(
                scan_report(raw)["counts"] == {"Critical": 0, "High": 0}
                and raw.get("ignoredMatches", []) == []
                and config["fail-on-severity"] == "high"
                and db["validate-age"] is True
                and db["validate-by-hash-on-start"] is True
                and db["max-allowed-built-age"] == 86400000000000
                and descriptor["db"]["status"]["schemaVersion"] == latest["schemaVersion"]
                and parse_qs(urlsplit(descriptor["db"]["status"]["from"]).query).get("checksum")
                == [latest["checksum"]],
                "raw findings, official DB hash or normal24 policy differs",
            )
            reports[coordinate] = {
                "sha256": digest(path),
                "manifest_digest": manifest["images"][role]["facts"]["platforms"][f"linux/{arch}"][
                    "manifest_digest"
                ],
                "config_digest": manifest["images"][role]["facts"]["platforms"][f"linux/{arch}"][
                    "config_digest"
                ],
            }
    return {
        "schema_version": 1,
        "kind": "same_signed_M2c_current_scan_evidence",
        "origin": value,
        "signing_policy_revision": policy,
        "run_id": run,
        "run_attempt": attempt,
        "workflow": WORKFLOW,
        "scan_started_at": beginning.isoformat(),
        "scan_qualified_at": checked.isoformat(),
        "official_latest_checked_at": checked.isoformat(),
        "official_latest": latest,
        "database_built_at": built.isoformat(),
        "expires_at": expiry.isoformat(),
        "reports": reports,
        "scan_summary_sha256": qualified["summary_sha256"],
        "product_source_or_OCI_rebuilt": False,
        "production_deployment_receipt": None,
    }


def verify_current(payload: dict, scans: Path, *, policy: str, run: str, attempt: str) -> None:
    value = origin()
    now = datetime.now(UTC)
    require(
        payload["origin"] == value
        and payload["kind"] == "same_signed_M2c_current_scan_evidence"
        and payload["signing_policy_revision"] == policy
        and payload["run_id"] == run
        and payload["run_attempt"] == attempt
        and payload["workflow"] == WORKFLOW
        and payload["product_source_or_OCI_rebuilt"] is False
        and payload["production_deployment_receipt"] is None
        and instant(payload["scan_started_at"]) <= instant(payload["scan_qualified_at"]) <= now
        and now
        < instant(payload["expires_at"])
        <= instant(payload["database_built_at"]) + timedelta(hours=24),
        "current signed evidence identity or hard expiry differs",
    )
    manifest = read_json(scans / MANIFEST_NAME)
    require(digest(scans / MANIFEST_NAME) == value["manifest_sha256"], "independent seal differs")
    require(
        validate_scans(scans, manifest["images"], now=now)["summary_sha256"]
        == payload["scan_summary_sha256"],
        "independent current raw scan validation differs",
    )
    summary = read_json(scans / "grype/candidate-scan-summary.json")
    require(
        all(
            row.get("component_disposition") is None
            and row.get("database_age_disposition") is None
            for row in summary["images"]
        ),
        "independent renewal accepts no exception",
    )
    require(
        payload["official_latest"]["status"] == "active"
        and instant(payload["official_latest"]["built"]) == instant(payload["database_built_at"]),
        "independent official input binding differs",
    )
    for coordinate, reference in payload["reports"].items():
        raw = read_json(scans / f"grype/{coordinate}-grype.json")
        config = raw["descriptor"]["configuration"]
        db = config["db"]
        require(
            scan_report(raw)["counts"] == {"Critical": 0, "High": 0}
            and raw.get("ignoredMatches", []) == []
            and config["fail-on-severity"] == "high"
            and db["validate-age"] is True
            and db["validate-by-hash-on-start"] is True
            and db["max-allowed-built-age"] == 86400000000000
            and instant(raw["descriptor"]["db"]["status"]["built"])
            == instant(payload["database_built_at"])
            and parse_qs(urlsplit(raw["descriptor"]["db"]["status"]["from"]).query).get("checksum")
            == [payload["official_latest"]["checksum"]],
            "independent raw findings or normal official policy differs",
        )
        facts = value["platforms"][coordinate]
        require(
            reference["sha256"] == digest(scans / f"grype/{coordinate}-grype.json")
            and reference["manifest_digest"] == facts["manifest_digest"]
            and reference["config_digest"] == facts["config_digest"],
            "current exact four report subjects differ",
        )
    require(
        set(payload["reports"]) == set(value["platforms"]), "four current coordinates required"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "action", choices=("origin", "qualify", "verify", "origin-signatures", "predicate")
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scans", type=Path)
    parser.add_argument("--policy")
    parser.add_argument("--run")
    parser.add_argument("--attempt")
    parser.add_argument("--started")
    args = parser.parse_args()
    if args.action == "origin":
        download_origin(args.root)
    elif args.action == "predicate":
        print(json.dumps(promotion_predicate(args.policy, args.run, args.attempt), sort_keys=True))
    elif args.action == "origin-signatures":
        value = origin()
        claims = build_certificate_claims(
            value["repository"],
            PRODUCT,
            value["workflow"],
            str(value["run_id"]),
            str(value["attempt"]),
        )
        for role, subject in value["images"].items():
            entries = json.loads((args.root / f"{role}-origin-signature.json").read_text())
            require(
                any(
                    all(
                        e["verificationResult"]["signature"]["certificate"].get(k) == v
                        for k, v in claims.items()
                    )
                    and e["verificationResult"]["statement"].get("predicateType")
                    == "https://slsa.dev/provenance/v1"
                    and any(
                        s.get("digest", {}).get("sha256") == subject.removeprefix("sha256:")
                        for s in e["verificationResult"]["statement"]["subject"]
                    )
                    for e in entries
                ),
                "original signed image must bind the actual original invocation",
            )
        print(json.dumps({"state": "EXACT_ORIGIN_IMAGE_SIGNATURES_PASS"}))
    elif args.action == "qualify":
        value = qualify(
            args.root,
            args.scans,
            policy=args.policy,
            run=args.run,
            attempt=args.attempt,
            started=args.started,
        )
        print(json.dumps(value, sort_keys=True))
    else:
        payload_path = args.root / "current-scan-evidence.json"
        payload = read_json(payload_path)
        verify_signature(
            json.loads((args.root / "current-signature.json").read_text()),
            digest(payload_path),
            policy=args.policy,
            run=args.run,
            attempt=args.attempt,
        )
        verify_current(payload, args.root, policy=args.policy, run=args.run, attempt=args.attempt)
        print(
            json.dumps(
                {
                    "state": "CURRENT_EVIDENCE_SIGNATURE_RAW_AND_CLOCK_PASS",
                    "payload_sha256": digest(payload_path),
                    "expires_at": payload["expires_at"],
                    "production_deployment_receipt": None,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
