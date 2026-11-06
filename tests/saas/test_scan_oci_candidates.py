"""Safety checks for exact OCI candidate scan receipts."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from saas.scripts.scan_oci_candidates import (
    parse_database_status,
    scan_report,
    validate_image_scope,
)


def test_database_must_be_fresh_and_timezone_bound() -> None:
    now = datetime(2026, 10, 9, 0, 0, tzinfo=UTC)
    current: dict[str, Any] = {
        "valid": True,
        "schemaVersion": "v6.1.10",
        "built": "2026-10-08T06:00:00Z",
    }
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
    diagnostic_index = names.index("Retain failed Server preflight OCI for diagnosis")
    diagnostic = steps[diagnostic_index]
    assert preflight < diagnostic_index < names.index("Build server candidate attempt 2")
    assert steps[preflight]["id"] == "server_preflight"
    assert "continue-on-error" not in steps[preflight]
    assert "failure()" in diagnostic["if"]
    assert "!cancelled()" in diagnostic["if"]
    for required in (
        "steps.first_server_build.outcome == 'success'",
        "steps.server_preflight.outcome == 'failure'",
        "github.event.pull_request.head.repo.full_name == github.repository",
        "github.ref == 'refs/heads/main'",
    ):
        assert required in diagnostic["if"]
    assert diagnostic["timeout-minutes"] == "10"
    assert diagnostic["with"]["retention-days"] == "1"
    assert diagnostic["with"]["compression-level"] == "0"
    assert diagnostic["with"]["if-no-files-found"] == "error"
    assert diagnostic["with"]["name"].startswith("failed-server-preflight-oci-")
    assert diagnostic["with"]["path"].splitlines() == [
        "${{ runner.temp }}/server-1.tar",
        "artifacts/grype-preflight/*.json",
    ]
    for name in (
        "Build server candidate attempt 2",
        "Build host candidate attempt 1",
        "Build host candidate attempt 2",
        "Seal exact admitted OCI archives and raw scan evidence",
    ):
        assert "if" not in steps[names.index(name)]
        assert "continue-on-error" not in steps[names.index(name)]
    assert "artifacts/grype/*.json" in upload


def test_fixed_host_diagnostic_cannot_enter_release_or_hide_raw_failures() -> None:
    repo = Path(__file__).resolve().parents[2]
    workflow = yaml.load(
        (repo / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    diagnostic = workflow["jobs"]["diagnostic-host-only"]
    flag = workflow["on"]["workflow_dispatch"]["inputs"]["diagnostic_host_only"]
    assert flag["default"] == "false" and flag["type"] == "boolean"
    for name in ("verify-candidate-preflight", "verify-production-migration-replay"):
        assert workflow["jobs"][name]["if"] == "${{ !inputs.diagnostic_host_only }}"
    for name in ("publish-signed", "verify-published-source"):
        assert "!inputs.diagnostic_host_only &&" in workflow["jobs"][name]["if"]
    assert diagnostic["permissions"] == {"contents": "read", "actions": "read"}
    assert "environment" not in diagnostic and "services" not in diagnostic
    assert (
        "workflow_dispatch" in diagnostic["if"]
        and "inputs.diagnostic_host_only" in diagnostic["if"]
    )
    fixed = "514a2ce1ae703869260c0e1eccf5a06767e7e4e3"
    assert diagnostic["env"]["SOURCE_REVISION"] == fixed
    assert diagnostic["env"]["CANDIDATE_REVISION"] == fixed
    steps = diagnostic["steps"]
    assert '[[ "$PUBLISH_SIGNED" == "false" ]]' in steps[0]["run"]
    assert '[[ "$GITHUB_RUN_ATTEMPT" == "1" ]]' in steps[0]["run"]
    builds = [s for s in steps if "build-oci-candidate@" in s.get("uses", "")]
    assert len(builds) == 1
    assert builds[0]["uses"] == "Dream1216/omnigent/saas/actions/build-oci-candidate@" + fixed
    assert builds[0]["with"] == {"artifact": "host", "target": "host", "attempt": "1"}
    scans = [s for s in steps if "python -m saas.scripts.scan_oci_candidates" in s.get("run", "")]
    assert len(scans) == 1 and "--scope" not in scans[0]["run"]
    assert '--image "server=' in scans[0]["run"] and '--image "host=' in scans[0]["run"]
    assert "continue-on-error" not in scans[0]
    retained = steps[-2]
    assert (
        "always()" in retained["if"] and "diagnostic-host.outcome == 'success'" in retained["if"]
    )
    assert retained["with"]["name"].startswith("diagnostic-only-host-")
    assert "host-1.tar" in retained["with"]["path"]
    assert "diagnostic-host-grype/*.json" in retained["with"]["path"]
    assert "always()" in steps[-1]["if"] and "exit 1" in steps[-1]["run"]
    assert not any("continue-on-error" in step for step in steps)


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
    assert command.count("--from registry") == 2
    retained = steps[names.index("Retain original published-runtime scan evidence")]
    assert retained["if"] == "always()"
    assert retained["with"]["path"] == "artifacts/supply-chain/"
    assert names.index(retained["name"]) < sign_index


@pytest.mark.parametrize(
    "workflow",
    [
        "saas-image-candidate.yml",
        "saas-oci-promotion-resume.yml",
        "saas-oci-promotion-token-renewal.yml",
        "saas-oci-promotion-model-renewal.yml",
    ],
)
def test_component_classification_keeps_its_real_input_until_complete(workflow: str) -> None:
    path = Path(__file__).resolve().parents[2] / ".github/workflows" / workflow
    document = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    steps = next(
        job["steps"]
        for job in document["jobs"].values()
        if any(
            step.get("name") == "Generate per-architecture SBOMs and check raw findings"
            for step in job.get("steps", [])
        )
    )
    commands = "\n".join(step.get("run", "") for step in steps)
    classify = commands.index("python -m saas.scripts.sqlite_component_disposition")
    cleanup = commands.index('rm -r -- "${RUNNER_TEMP:?}/admitted-layouts/server"')
    assert classify < cleanup
    assert commands.index('"${prefix}.raw.grype.json"') < commands.index(
        "grype_exit=$?", classify - 400
    )
    assert '--scanner-exit "$grype_exit"' in commands
    assert '--image "${RUNNER_TEMP}/admitted-layouts/${artifact}"' in commands
