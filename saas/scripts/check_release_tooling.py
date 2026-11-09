"""Fail before OCI builds when the official vulnerability database is unusable."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from saas.scripts.scan_oci_candidates import (
    TEMPORARY_DATABASE_AGE,
    approved_database_is_latest,
    official_database_latest,
    temporary_database_age_enabled,
)

ROOT = Path(__file__).resolve().parents[2]


def check_database(
    repo: Path, *, revision: str, tree: str, latest: dict[str, Any], now: datetime
) -> dict[str, Any]:
    policy_path = repo / "saas/supply_chain/release-policy.json"
    policy = json.loads(policy_path.read_text())
    maximum_hours = policy["vulnerability_policy"]["maximum_scanner_database_age_hours"]
    violations: list[str] = []
    age_hours: float | None = None
    finite = False
    try:
        built = datetime.fromisoformat(latest["built"].replace("Z", "+00:00"))
        if (
            now.tzinfo is None
            or built.tzinfo is None
            or latest.get("status") != "active"
            or not str(latest.get("schemaVersion", "")).startswith("v6.")
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(latest.get("checksum", ""))) is None
            or not isinstance(latest.get("path"), str)
            or not latest["path"]
            or not isinstance(maximum_hours, int)
            or maximum_hours != 24
        ):
            raise ValueError("official database metadata or policy is invalid")
        age = now - built
        age_hours = round(age.total_seconds() / 3600, 3)
        if not timedelta(0) <= age <= timedelta(hours=maximum_hours):
            finite = (
                TEMPORARY_DATABASE_AGE["products"].get(revision) == tree
                and temporary_database_age_enabled(repo)
                and approved_database_is_latest(latest)
                and timedelta(0)
                <= age
                <= timedelta(hours=TEMPORARY_DATABASE_AGE["maximum_age_hours"])
                and now
                < datetime.fromisoformat(
                    TEMPORARY_DATABASE_AGE["expires_at"].replace("Z", "+00:00")
                )
            )
            if not finite:
                violations.append(
                    "official vulnerability database exceeds the product's 24-hour bound"
                )
    except (KeyError, TypeError, ValueError) as error:
        violations.append(f"official database metadata is unusable: {error}")
    return {
        "schema_version": 1,
        "product_revision": revision,
        "product_tree": tree,
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "official_database_built": latest.get("built"),
        "official_database_checksum": latest.get("checksum"),
        "age_hours": age_hours,
        "maximum_age_hours": maximum_hours,
        "registered_finite_subject_precheck": finite,
        "actual_oci_subject_scan_required": True,
        "production_authority": False,
        "status": "blocked" if violations else "pass",
        "violations": violations,
    }


def main() -> int:
    output = ROOT / "artifacts/release-tooling.json"
    try:
        revision, tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=ROOT, text=True
        ).splitlines()
        result = check_database(
            ROOT,
            revision=revision,
            tree=tree,
            latest=official_database_latest(),
            now=datetime.now(UTC),
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        result = {"status": "blocked", "production_authority": False, "violations": [str(error)]}
    output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    output.write_text(rendered)
    print(rendered, end="")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
