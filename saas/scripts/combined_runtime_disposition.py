"""Finite raw-two-High composition, pending a protected native-evidence intake.

No existing caller uses this module and the current policy does not enable its
rule. A protected caller must supply a native verifier with authenticated
producer/independent-review/authorization and whole-role/last-override coverage.
Parsing a candidate-provided JSON claim is not an implementation of that verifier.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from saas.scripts import sqlite_component_disposition as sqlite
from saas.scripts.scan_oci_candidates import GRYPE_VERSION, parse_database_status, scan_report

RUNTIME_RULE: dict[str, Any] = {
    "id": "CVE-2026-84243",
    "package": "glibc-2.44",
    "version": "2.44-r8",
    "classification": "mitigated_by_verified_runtime_conditions",
    "expires_at": "2026-11-11T10:40:00Z",
    "libc_sha256": {
        "linux/amd64": "ff446e3fa632b252be608349a210f1b4142f30e97d9735d2c3a95d35a9b37ea8",
        "linux/arm64": "98c931a2f98dfceb54e1bf580e7e552f3a33fdc2ee50df4e81051532082dc90f",
    },
}


@dataclass(frozen=True)
class RuntimeSubject:
    source_revision: str
    platform: str
    manifest_digest: str
    config_digest: str
    libc_sha256: str
    report_sha256: str


@dataclass(frozen=True)
class VerifiedRuntimeCondition:
    """Result of a protected verifier, never a deserialized candidate assertion."""

    subject: RuntimeSubject
    role_contract_sha256: str
    native_evidence_sha256: str
    independent_review_sha256: str
    authority_reference_sha256: str
    expires_at: datetime


class NativeRuntimeVerifier(Protocol):
    def __call__(self, subject: RuntimeSubject, *, now: datetime) -> VerifiedRuntimeCondition:
        """Verify C-family messages throughout the approved trusted role lifecycle.

        Authenticate actual native producer/origin, exact final subject or an
        independently accepted byte/component/entry bridge, role/command/env
        sources, last lower-trust merges, effective libc state, whole permitted
        lifetime, independent review, authority and expiry. Reject an unknown
        path or applicable unmitigated risk; hashes/expected digests alone do
        not prove these properties. This intake is not supplied by this module.
        """
        ...


def runtime_rule_enabled() -> bool:
    policy = json.loads(
        (Path(__file__).resolve().parents[1] / "supply_chain/release-policy.json").read_text()
    )
    return policy.get("vulnerability_policy", {}).get("runtime_mitigation") == RUNTIME_RULE


def _unexpired(value: datetime, expiry: str) -> bool:
    return value.tzinfo is not None and value < datetime.fromisoformat(
        expiry.replace("Z", "+00:00")
    )


def _exact_two_findings(report: dict[str, Any], *, now: datetime) -> None:
    parsed = scan_report(report)
    if parsed["counts"] != {"Critical": 0, "High": 2}:
        raise ValueError("finite combination requires exactly the two original High findings")
    configuration = report.get("descriptor", {}).get("configuration", {})
    if (
        configuration.get("only-fixed") is not False
        or configuration.get("only-notfixed") is not False
        or configuration.get("exclude", []) != []
        or configuration.get("vex-documents", []) != []
    ):
        raise ValueError("finite combination requires complete unfiltered raw findings")
    wanted = {
        (rule["id"], rule["package"], rule["version"]) for rule in (sqlite.RULE, RUNTIME_RULE)
    }
    seen = set()
    for item in report["matches"]:
        vulnerability, artifact = item["vulnerability"], item["artifact"]
        if vulnerability.get("severity") != "High":
            continue
        key = (vulnerability.get("id"), artifact.get("name"), artifact.get("version"))
        details = item.get("matchDetails")
        if (
            key not in wanted
            or key in seen
            or vulnerability.get("namespace") != "nvd:cpe"
            or artifact.get("type") != "apk"
            or not isinstance(details, list)
            or len(details) != 1
            or not isinstance(details[0], dict)
            or details[0].get("matcher") != "apk-matcher"
            or details[0].get("type") != "cpe-match"
        ):
            raise ValueError("unknown, duplicated or changed finite finding identity")
        seen.add(key)
    if seen != wanted:
        raise ValueError("finite finding set differs")
    descriptor = report.get("descriptor", {})
    if descriptor.get("name") != "grype" or descriptor.get("version") != GRYPE_VERSION:
        raise ValueError("finite combination scanner differs")
    parse_database_status(descriptor["db"]["status"], now=now)


def inspect_combined_disposition(
    image: Path,
    report_path: Path,
    *,
    platform: str,
    now: datetime,
    scanner_exit: int,
    verify_runtime: NativeRuntimeVerifier | None = None,
) -> dict[str, Any]:
    """Compose independent component facts and authenticated runtime conditions.

    Both policy and a protected verifier are mandatory. Existing sole-SQLite
    APIs remain strict raw0C1H. This path never produces a filtered report.
    """
    repo = Path(__file__).resolve().parents[2]
    if verify_runtime is None:
        from saas.scripts.runtime_evidence_intake import registered_inventory_paths

        extra_paths = registered_inventory_paths(repo)
    else:
        extra_paths = frozenset({"usr/lib/libc.so.6"})
    if (
        not runtime_rule_enabled()
        or not sqlite.rule_enabled()
        or not _unexpired(now, RUNTIME_RULE["expires_at"])
        or not _unexpired(now, sqlite.RULE["expires_at"])
        or platform not in RUNTIME_RULE["libc_sha256"]
        or type(scanner_exit) is not int
        or scanner_exit != 2
    ):
        raise ValueError("finite runtime rule or protected native verifier is unavailable")
    raw = report_path.read_bytes()
    report = json.loads(raw)
    _exact_two_findings(report, now=now)
    target = report.get("source", {}).get("target", {})
    with sqlite.image_blobs(image) as blobs:
        digest, manifest = blobs.platform(platform)
        config_digest = manifest["config"]["digest"]
        config = blobs.document(config_digest)
        revision = (
            config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision")
        )
        if (
            target.get("manifestDigest") != digest
            or target.get("imageID") != config_digest
            or target.get("os") != "linux"
            or target.get("architecture") != platform.split("/")[1]
            or target.get("labels") != config.get("config", {}).get("Labels")
            or config.get("os") != "linux"
            or config.get("architecture") != platform.split("/")[1]
            or re.fullmatch(r"[0-9a-f]{40}", str(revision)) is None
        ):
            raise ValueError("finite runtime evidence does not bind the actual OCI subject")
        inventory = sqlite.component_inventory(blobs, manifest, additional_paths=extra_paths)
    if verify_runtime is None:
        from saas.scripts.runtime_evidence_intake import verifier_from_registered_inputs

        verify_runtime = verifier_from_registered_inputs(repo, inventory)
    return disposition_receipt(
        raw,
        inventory,
        platform=platform,
        now=now,
        scanner_exit=scanner_exit,
        verify_runtime=verify_runtime,
    )


def disposition_receipt(
    raw: bytes,
    inventory: list[dict[str, Any]],
    *,
    platform: str,
    now: datetime,
    scanner_exit: int,
    verify_runtime: NativeRuntimeVerifier | None = None,
) -> dict[str, Any]:
    """Recheck original report and authenticated inventory without rewriting either."""
    if (
        not runtime_rule_enabled()
        or not sqlite.rule_enabled()
        or not _unexpired(now, RUNTIME_RULE["expires_at"])
        or not _unexpired(now, sqlite.RULE["expires_at"])
        or verify_runtime is None
        or platform not in RUNTIME_RULE["libc_sha256"]
        or type(scanner_exit) is not int
        or scanner_exit != 2
    ):
        raise ValueError("finite runtime rule or protected native verifier is unavailable")
    report = json.loads(raw)
    _exact_two_findings(report, now=now)
    target = report.get("source", {}).get("target", {})
    revision = target.get("labels", {}).get("org.opencontainers.image.revision")
    digest, config_digest = target.get("manifestDigest"), target.get("imageID")
    if (
        target.get("os") != "linux"
        or target.get("architecture") != platform.split("/")[1]
        or re.fullmatch(r"[0-9a-f]{40}", str(revision)) is None
        or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", str(value)) is None
            for value in (digest, config_digest)
        )
    ):
        raise ValueError("finite runtime subject identity is incomplete")
    component = sqlite.sqlite_component_facts(inventory, platform=platform)
    libc = [row for row in inventory if row["path"] == "usr/lib/libc.so.6"]
    if (
        len(libc) != 1
        or libc[0]["type"] != "0"
        or libc[0].get("sha256") != RUNTIME_RULE["libc_sha256"][platform]
    ):
        raise ValueError("actual OCI libc bytes differ from the finite rule")
    subject = RuntimeSubject(
        source_revision=revision,
        platform=platform,
        manifest_digest=digest,
        config_digest=config_digest,
        libc_sha256=libc[0]["sha256"],
        report_sha256=hashlib.sha256(raw).hexdigest(),
    )
    condition = verify_runtime(subject, now=now)
    if not isinstance(condition, VerifiedRuntimeCondition) or condition.subject != subject:
        raise ValueError("protected runtime proof belongs to a different exact subject")
    maximum_expiry = min(
        datetime.fromisoformat(rule["expires_at"].replace("Z", "+00:00"))
        for rule in (RUNTIME_RULE, sqlite.RULE)
    )
    if (
        not isinstance(condition.expires_at, datetime)
        or condition.expires_at.tzinfo is None
        or not now < condition.expires_at <= maximum_expiry
    ):
        raise ValueError("finite runtime proof is expired or extends an approved expiry")
    for value in (
        condition.role_contract_sha256,
        condition.native_evidence_sha256,
        condition.independent_review_sha256,
        condition.authority_reference_sha256,
    ):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("protected runtime proof lacks an authenticated input identity")
    return {
        "classification": RUNTIME_RULE["classification"],
        **asdict(subject),
        "raw_critical": 0,
        "raw_high": 2,
        "scanner_exit": 2,
        "sqlite_rule_sha256": sqlite.RULE_SHA256,
        "sqlite_component": component,
        "runtime_rule_sha256": hashlib.sha256(
            json.dumps(RUNTIME_RULE, sort_keys=True).encode()
        ).hexdigest(),
        "runtime_condition": {
            **asdict(condition),
            "expires_at": condition.expires_at.isoformat(),
        },
        "inventory": inventory,
    }


def validate_combined_disposition(
    image: Path,
    report_path: Path,
    proof: object,
    *,
    platform: str,
    now: datetime,
    scanner_exit: int,
    verify_runtime: NativeRuntimeVerifier | None = None,
) -> dict[str, Any]:
    """Every downstream intake recomputes the same subject and condition."""
    if not isinstance(proof, dict) or any(
        type(proof.get(field)) is not int or proof[field] != value
        for field, value in (("raw_critical", 0), ("raw_high", 2), ("scanner_exit", 2))
    ):
        raise ValueError("finite combination requires exact integer raw counts and scanner exit")
    expected = inspect_combined_disposition(
        image,
        report_path,
        platform=platform,
        now=now,
        scanner_exit=scanner_exit,
        verify_runtime=verify_runtime,
    )
    try:
        actual_json = json.dumps(proof, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("finite combination proof is not strict JSON") from error
    expected_json = json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if actual_json != expected_json:
        raise ValueError("finite combination differs from original raw, OCI or native proof")
    return expected
