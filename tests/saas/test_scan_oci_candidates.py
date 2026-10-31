"""Safety checks for exact OCI candidate scan receipts."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from saas.scripts.scan_oci_candidates import (
    parse_database_status,
    scan_report,
    validate_image_scope,
    validate_scan_configuration,
)


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


def _current_scan_configuration() -> dict[str, object]:
    return {
        "ignore": [],
        "exclude": [],
        "vex-documents": [],
        "vex-add": [],
        "ignore-wontfix": "",
        "only-fixed": False,
        "only-notfixed": False,
        "match-upstream-kernel-headers": True,
        "fail-on-severity": "high",
        "db": {"validate-age": True, "max-allowed-built-age": 86_400_000_000_000},
    }


@pytest.mark.parametrize(
    "override",
    [
        {"ignore": [{"package": {"name": "kernel-headers"}}]},
        {"exclude": ["/usr/lib/**"]},
        {"vex-documents": ["exception.json"]},
        {"vex-add": ["fixed"]},
        {"ignore-wontfix": "all"},
        {"only-fixed": True},
        {"only-notfixed": True},
        {"match-upstream-kernel-headers": False},
        {"fail-on-severity": "critical"},
        {"db": {"validate-age": False, "max-allowed-built-age": 86_400_000_000_000}},
        {"db": {"validate-age": True, "max-allowed-built-age": 604_800_000_000_000}},
    ],
)
def test_current_scan_rejects_inactive_ignores_and_policy_relaxation(
    override: dict[str, object],
) -> None:
    configuration = _current_scan_configuration()
    report: dict[str, object] = {
        "matches": [],
        "ignoredMatches": [],
        "descriptor": {"configuration": configuration},
    }
    validate_scan_configuration(report)
    configuration.update(override)
    with pytest.raises(ValueError, match="raw scan configuration"):
        validate_scan_configuration(report)


def test_current_scan_requires_raw_configuration() -> None:
    with pytest.raises(ValueError, match="configuration is incomplete"):
        validate_scan_configuration({"matches": [], "ignoredMatches": []})


def test_preflight_scope_cannot_replace_complete_four_report_scan() -> None:
    server = Path("server.tar")
    host = Path("host.tar")
    validate_image_scope({"server": server}, "server-preflight")
    validate_image_scope({"server": server, "host": host}, "complete")
    with pytest.raises(ValueError, match="requires exactly: host, server"):
        validate_image_scope({"server": server}, "complete")
    with pytest.raises(ValueError, match="requires exactly: server"):
        validate_image_scope({"server": server, "host": host}, "server-preflight")


def test_preflight_blocks_rebuilds_but_keeps_final_scan() -> None:
    workflow_path = (
        Path(__file__).resolve().parents[2] / ".github/workflows/saas-image-candidate.yml"
    )
    workflow = yaml.load(workflow_path.read_text(), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["build-candidate"]["steps"]
    names = [step["name"] for step in steps]
    preflight = names.index("Preflight scan exact server candidate on both architectures")
    assert names.index("Build server candidate attempt 1") < preflight
    assert preflight < names.index("Build server candidate attempt 2")
    assert preflight < names.index("Build host candidate attempt 1")
    assert names.index("Compare repeated executable image facts") < names.index(
        "Scan exact OCI candidates on both architectures"
    )
    assert "--scope server-preflight" in steps[preflight]["run"]
    final_scan = steps[names.index("Scan exact OCI candidates on both architectures")]["run"]
    assert "--scope server-preflight" not in final_scan
    assert "--image server=" in final_scan and "--image host=" in final_scan
    upload = steps[names.index("Upload candidate evidence")]["with"]["path"]
    assert "artifacts/grype-preflight/*.json" in upload
    assert "artifacts/grype/*.json" in upload


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
    assert "'match-upstream-kernel-headers: true'" in command
    assert "--fail-on high" in command
    assert ".descriptor.configuration.ignore == []" in command
    assert '.descriptor.configuration."match-upstream-kernel-headers" == true' in command
    assert '.descriptor.configuration.db."max-allowed-built-age" == 86400000000000' in command
    assert "--vex" not in command
    assert "admitted.grype.json" not in command
