"""Safety checks for exact OCI candidate scan receipts."""

import copy
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from saas.scripts import scan_oci_candidates
from saas.scripts.scan_oci_candidates import (
    parse_database_status,
    scan_platforms,
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


def test_aliyun_scan_is_explicitly_host_only_and_does_not_reduce_existing_scopes() -> None:
    validate_image_scope({"host": Path("aliyun.tar")}, "aliyun-host")
    assert scan_platforms("aliyun-host") == ("linux/amd64",)
    for scope in ("complete", "server-preflight"):
        assert scan_platforms(scope) == ("linux/amd64", "linux/arm64")
    with pytest.raises(ValueError, match="requires exactly: host"):
        validate_image_scope({"server": Path("server.tar")}, "aliyun-host")
    with pytest.raises(ValueError, match="Unsupported"):
        scan_platforms("unknown")


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
        "steps.first_server_sdk.outcome == 'success'",
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
        "artifacts/server-candidate-runtime.json",
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


@pytest.fixture
def run_scan_cli(monkeypatch, tmp_path):
    """Exercise the CLI boundary with Grype's original JSON and exit protocol."""

    def run(scope, *, returncode=2, ignored=False, missing_report=False, stale=False):
        output = tmp_path / scope
        images = ["host"] if scope == "aliyun-host" else ["server"]
        if scope == "complete":
            images.append("host")
        argv = ["scan", "--scope", scope, "--output", str(output)]
        for name in images:
            archive = tmp_path / f"{name}.tar"
            archive.write_bytes(f"exact-{name}-archive".encode())
            argv += ["--image", f"{name}={archive}"]
        monkeypatch.setattr("sys.argv", argv)
        monkeypatch.setattr(scan_oci_candidates, "install_grype", lambda root: root / "grype")
        built = datetime.now(UTC) - timedelta(hours=25 if stale else 1)
        monkeypatch.setattr(
            scan_oci_candidates.subprocess,
            "check_output",
            lambda *a, **kw: json.dumps(
                {"valid": True, "schemaVersion": "v6.1.10", "built": built.isoformat()}
            ),
        )

        def grype(command, **kwargs):
            if command[-2:] == ["db", "update"]:
                return subprocess.CompletedProcess(command, 0)
            assert command[command.index("--fail-on") + 1] == "high"
            if not missing_report:
                matches = [
                    {
                        "vulnerability": {"id": f"CVE-test-{severity}", "severity": severity},
                        "artifact": {"name": "system-package", "version": "1.0"},
                    }
                    for severity in ("Critical", "High")
                ]
                Path(command[-1]).write_text(
                    json.dumps({"matches": matches, "ignoredMatches": matches if ignored else []})
                )
            return subprocess.CompletedProcess(command, returncode)

        monkeypatch.setattr(scan_oci_candidates.subprocess, "run", grype)
        return scan_oci_candidates.main(), output

    return run


@pytest.mark.parametrize(
    ("scope", "exit_code", "policy", "reports"),
    [
        ("aliyun-host", 0, "advisory", 1),
        ("server-preflight", 2, "blocking", 2),
        ("complete", 2, "blocking", 4),
    ],
)
def test_cli_findings_policy_keeps_raw_reports(
    run_scan_cli, capsys, scope, exit_code, policy, reports
):
    actual, output = run_scan_cli(scope)
    assert actual == exit_code
    summary = json.loads(next(output.glob("*summary.json")).read_text())
    assert summary["vulnerability_policy"] == policy
    assert summary["vulnerability_findings_present"] is True
    assert summary["exceptions"] == []
    assert len(summary["images"]) == reports
    for image in summary["images"]:
        report = output / f"{image['image']}-{image['platform'].split('/')[-1]}-grype.json"
        assert image["report_sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()
        assert image["critical"] == image["high"] == 1
        assert image["scanner_returncode"] == 2
        assert len(image["findings"]) == 2
    assert ("::warning::" in capsys.readouterr().out) == (policy == "advisory")


@pytest.mark.parametrize("failure", ["scanner", "missing", "ignored", "stale"])
def test_advisory_policy_still_rejects_invalid_scan_evidence(run_scan_cli, failure):
    options = {
        "scanner": {"returncode": 1},
        "missing": {"missing_report": True},
        "ignored": {"ignored": True},
        "stale": {"stale": True},
    }
    with pytest.raises((RuntimeError, ValueError)):
        run_scan_cli("aliyun-host", **options[failure])


def test_aliyun_workflow_does_not_hide_scanner_errors():
    path = Path(__file__).resolve().parents[2] / ".github/workflows/saas-aliyun-host-candidate.yml"
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["compare-and-scan"]["steps"]
    scan = next(step for step in steps if "scan_oci_candidates" in step.get("run", ""))
    assert "--scope aliyun-host" in scan["run"]
    assert "continue-on-error" not in scan
    assert "|| true" not in scan["run"]
    assert "set -euo pipefail" in scan["run"]


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


@pytest.mark.parametrize(
    ("scope", "shell", "exit_code", "reports"),
    [
        ("complete", False, 0, 4),
        ("server-preflight", False, 0, 2),
        ("complete", True, 2, 4),
        ("server-preflight", True, 2, 2),
        ("aliyun-host", True, 0, 1),
    ],
)
def test_policy_composition_preserves_original_high_and_finite_scope(
    tmp_path, monkeypatch, scope, shell, exit_code, reports
):
    from saas.scripts import sqlite_component_disposition as component
    from tests.saas.test_sqlite_component_disposition import NOW, candidate

    image, _, original = candidate(
        tmp_path,
        monkeypatch,
        extra={"usr/bin/sqlite3": b"#!/bin/sh\n.recover\n"} if shell else None,
    )

    class Clock(datetime):
        @classmethod
        def now(cls, timezone=None):
            return NOW

    monkeypatch.setattr(scan_oci_candidates, "datetime", Clock)
    output = tmp_path / "scan-output"
    argv = ["scan", "--scope", scope, "--output", str(output)]
    names = ["host"] if scope == "aliyun-host" else ["server"]
    if scope == "complete":
        names.append("host")
    for name in names:
        argv += ["--image", f"{name}={image}"]
    monkeypatch.setattr("sys.argv", argv)
    monkeypatch.setattr(scan_oci_candidates, "install_grype", lambda root: root / "grype")
    monkeypatch.setattr(
        scan_oci_candidates.subprocess,
        "check_output",
        lambda *args, **kwargs: json.dumps(
            {"valid": True, "schemaVersion": "v6.1.10", "built": NOW.isoformat()}
        ),
    )
    original_reports = {}

    def scanner(command, **kwargs):
        if command[-2:] == ["db", "update"]:
            return subprocess.CompletedProcess(command, 0)
        platform = command[command.index("--platform") + 1]
        report = copy.deepcopy(original)
        with component.image_blobs(image) as blobs:
            digest, manifest = blobs.platform(platform)
            config = blobs.document(manifest["config"]["digest"])
        report["source"]["target"].update(
            manifestDigest=digest,
            imageID=manifest["config"]["digest"],
            architecture=platform.split("/")[1],
            labels=config["config"]["Labels"],
        )
        path = Path(command[-1])
        raw = (json.dumps(report) + "\n").encode()
        path.write_bytes(raw)
        original_reports[path] = raw
        return subprocess.CompletedProcess(command, 2)

    monkeypatch.setattr(scan_oci_candidates.subprocess, "run", scanner)
    if scope == "aliyun-host":

        def unrelated_disposition_must_not_run(*args, **kwargs):
            raise AssertionError("Aliyun advisory path entered generic component classification")

        monkeypatch.setattr(component, "inspect_disposition", unrelated_disposition_must_not_run)

    assert scan_oci_candidates.main() == exit_code
    summary = json.loads(next(output.glob("*summary.json")).read_text())
    assert summary["scope"] == scope
    assert summary["vulnerability_policy"] == (
        "advisory" if scope == "aliyun-host" else "blocking"
    )
    assert summary["vulnerability_findings_present"] is True
    assert summary["exceptions"] == []
    assert len(summary["images"]) == reports
    for row in summary["images"]:
        path = output / f"{row['image']}-{row['platform'].split('/')[1]}-grype.json"
        assert path.read_bytes() == original_reports[path]
        assert row["report_sha256"] == hashlib.sha256(original_reports[path]).hexdigest()
        assert row["critical"] == 0 and row["high"] == 1
        assert row["scanner_returncode"] == 2 and len(row["findings"]) == 1
        assert ("component_disposition" in row) == (not shell and scope != "aliyun-host")
        if "component_disposition" in row:
            assert row["scanner_exit"] == 2
