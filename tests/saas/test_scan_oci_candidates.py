"""Safety checks for exact OCI candidate scan receipts."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from saas.scripts.scan_oci_candidates import parse_database_status, scan_report


def test_database_must_be_fresh_and_timezone_bound() -> None:
    now = datetime(2026, 10, 9, 0, 0, tzinfo=UTC)
    current = {"valid": True, "schemaVersion": "v6.1.10", "built": "2026-10-08T06:00:00Z"}
    assert parse_database_status(current, now=now) == current["built"]
    with pytest.raises(ValueError, match="older than 24 hours"):
        parse_database_status(
            {**current, "built": (now - timedelta(hours=25)).isoformat()}, now=now
        )
    with pytest.raises(ValueError, match="timezone"):
        parse_database_status({**current, "built": "2026-10-08T06:00:00"}, now=now)
    with pytest.raises(ValueError, match="invalid"):
        parse_database_status({**current, "valid": False}, now=now)


def test_report_keeps_each_high_finding_and_rejects_ignores() -> None:
    match = {
        "vulnerability": {"id": "CVE-2026-19931", "severity": "Critical"},
        "artifact": {"name": "curl", "version": "8.14.1-2+deb13u5"},
    }
    result = scan_report({"matches": [match], "ignoredMatches": []})
    assert result["counts"] == {"Critical": 1, "High": 0}
    assert result["findings"] == [
        {
            "id": "CVE-2026-19931",
            "severity": "Critical",
            "package": "curl",
            "version": "8.14.1-2+deb13u5",
        }
    ]
    with pytest.raises(ValueError, match="ignored"):
        scan_report({"matches": [], "ignoredMatches": [match]})
    with pytest.raises(ValueError, match="incomplete"):
        scan_report({"matches": "not-a-list"})


def test_signed_release_checks_raw_findings_before_signing() -> None:
    workflow_path = (
        Path(__file__).resolve().parents[2] / ".github/workflows/saas-image-candidate.yml"
    )
    workflow = yaml.load(workflow_path.read_text(), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["publish-signed"]["steps"]
    names = [step["name"] for step in steps]
    scan_index = names.index("Generate per-architecture SBOMs and check raw findings")
    sign_index = names.index("Sign server image provenance with GitHub OIDC")
    assert scan_index < sign_index
    command = steps[scan_index]["run"]
    assert "${prefix}.raw.grype.json" in command
    assert ".ignoredMatches // []) == []" in command
    assert "--vex" not in command
    assert "admitted.grype.json" not in command
