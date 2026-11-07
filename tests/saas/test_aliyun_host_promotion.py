"""An advisory finding cannot weaken original-image and registry-byte checks."""

from __future__ import annotations

import json
import re
import tarfile
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from packaging.specifiers import SpecifierSet

from saas.scripts.aliyun_host_promotion import prepare, select_candidate_artifacts, verify_readback
from saas.scripts.compare_oci_rebuilds import inspect_oci_archive
from saas.scripts.scan_oci_candidates import GRYPE_VERSION, file_sha256, scan_report
from tests.saas.test_image_supply_chain import _write_oci

REVISION = "a" * 40


@pytest.mark.parametrize(
    ("branch", "event"),
    [
        ("codex/aliyun-sandbox-p1-p5-20261031", "push"),
        ("codex/aliyun-sandbox-p1-p5-20261031", "workflow_dispatch"),
        ("main", "workflow_dispatch"),
    ],
)
@pytest.mark.parametrize(
    "failure",
    [
        None,
        "source",
        "repository",
        "branch",
        "event",
        "workflow",
        "run",
        "job",
        "attempt",
        "expired",
        "digest",
        "artifact_source",
        "duplicate",
        "truncated",
    ],
)
def test_promotion_only_selects_both_archives_from_a_successful_native_run(branch, event, failure):
    run = {
        "id": 123,
        "head_sha": REVISION,
        "repository": {"full_name": "Dream1216/omnigent"},
        "head_repository": {"full_name": "Dream1216/omnigent"},
        "head_branch": branch,
        "path": ".github/workflows/saas-aliyun-host-candidate.yml",
        "event": event,
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 2,
    }
    jobs = {
        "total_count": 4,
        "jobs": [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in ("verify", "build (1)", "build (2)", "compare-and-scan")
        ],
    }
    artifacts = {
        "total_count": 2,
        "artifacts": [
            {
                "id": number,
                "name": f"aliyun-host-{REVISION}-2-{number}",
                "digest": "sha256:" + str(number) * 64,
                "expired": False,
                "workflow_run": {"id": 123, "head_sha": REVISION},
            }
            for number in (1, 2)
        ],
    }
    first = artifacts["artifacts"][0]
    if failure == "source":
        run["head_sha"] = "b" * 40
    elif failure == "repository":
        run["head_repository"] = {"full_name": "untrusted/omnigent"}
    elif failure == "branch":
        run["head_branch"] = "other-branch"
    elif failure == "event":
        run["event"] = "push" if branch == "main" else "pull_request"
    elif failure == "workflow":
        run["path"] = ".github/workflows/other.yml"
    elif failure == "run":
        run["conclusion"] = "failure"
    elif failure == "job":
        jobs["jobs"][-1]["conclusion"] = "skipped"
    elif failure == "attempt":
        run["run_attempt"] = 1
    elif failure == "expired":
        first["expired"] = True
    elif failure == "digest":
        first["digest"] = "not-a-digest"
    elif failure == "artifact_source":
        first["workflow_run"]["head_sha"] = "b" * 40
    elif failure == "duplicate":
        artifacts["artifacts"][1]["id"] = first["id"]
    elif failure == "truncated":
        artifacts["total_count"] = 3
    if failure is not None:
        with pytest.raises(ValueError):
            select_candidate_artifacts(run, jobs, artifacts, revision=REVISION, run_id=123)
    else:
        selected = select_candidate_artifacts(run, jobs, artifacts, revision=REVISION, run_id=123)
        assert selected == [
            {"destination": name, "artifact_id": number, "digest": "sha256:" + str(number) * 64}
            for number, name in ((1, "first"), (2, "second"))
        ]


def test_gen2_builder_meets_the_repository_uv_requirement():
    repo = Path(__file__).resolve().parents[2]
    dockerfile = (repo / "saas/deployment/aliyun/Dockerfile.host").read_text()
    pinned = re.search(r"^ARG UV_VERSION=(\S+)$", dockerfile, re.MULTILINE)
    assert pinned is not None
    required = tomllib.loads((repo / "uv.toml").read_text())["required-version"]
    assert SpecifierSet(required).contains(pinned.group(1)), (
        "Gen2 builder uv must satisfy the repository security and lockfile requirement"
    )


@pytest.fixture
def candidate(tmp_path):
    archive = tmp_path / "host.tar"
    _write_oci(archive, revision=REVISION, label_profile="aliyun-host-minimal", nested=True)
    layout = tmp_path / "host-layout"
    index = json.loads((layout / "index.json").read_text())
    descriptor = index["manifests"][0]
    descriptor["size"] = (layout / "blobs/sha256" / descriptor["digest"][7:]).stat().st_size
    (layout / "index.json").write_text(json.dumps(index))
    with tarfile.open(archive, "w") as stream:
        for member in sorted(layout.rglob("*")):
            stream.add(member, arcname=member.relative_to(layout), recursive=False)
    facts = inspect_oci_archive(archive, label_profile="aliyun-host-minimal")
    platform = facts["platforms"]["linux/amd64"]
    built = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    report = {
        "descriptor": {"db": {"status": {"valid": True, "built": built, "schemaVersion": "v6.1"}}},
        "source": {
            "target": {
                "manifestDigest": platform["manifest_digest"],
                "imageID": platform["config_digest"],
                "architecture": "amd64",
                "os": "linux",
                "labels": platform["labels"],
            }
        },
        "matches": [
            {
                "vulnerability": {"id": "CVE-test", "severity": "High"},
                "artifact": {"name": "system-package", "version": "1"},
            }
        ],
        "ignoredMatches": [],
    }
    scans = tmp_path / "scan"
    scans.mkdir()
    raw = scans / "host-amd64-grype.json"
    raw.write_text(json.dumps(report))
    summary = {
        "scope": "aliyun-host",
        "vulnerability_policy": "advisory",
        "scanner": f"grype {GRYPE_VERSION}",
        "exceptions": [],
        "database_built_at": built,
        "images": [
            {
                "image": "host",
                "platform": "linux/amd64",
                "archive_sha256": file_sha256(archive),
                "report_sha256": file_sha256(raw),
                "scanner_returncode": 2,
                "critical": 0,
                "high": 1,
                "findings": scan_report(report)["findings"],
            }
        ],
    }
    (scans / "aliyun-host-scan-summary.json").write_text(json.dumps(summary))
    return archive, scans, report, summary


def test_advisory_candidate_preserves_source_findings_and_exact_readback(candidate, tmp_path):
    archive, scans, _, _ = candidate
    receipt = prepare(archive, REVISION, scans, tmp_path / "promote")
    assert receipt["source_revision"] == REVISION
    assert receipt["scan"]["images"][0]["high"] == 1
    assert receipt["qualification"] == "private-cloud-validation-candidate"
    assert receipt["production_ready"] is False
    verify_readback(archive, receipt)
    changed = tmp_path / "changed.tar"
    _write_oci(
        changed,
        revision=REVISION,
        label_profile="aliyun-host-minimal",
        nested=True,
        layer_payload=b"different runtime bytes",
    )
    with pytest.raises(ValueError):
        verify_readback(changed, receipt)


@pytest.mark.parametrize(
    "failure",
    [
        "revision",
        "archive",
        "report",
        "counts",
        "scanner",
        "policy",
        "database",
        "target",
        "ignored",
    ],
)
def test_findings_are_advisory_but_mismatched_evidence_is_rejected(candidate, tmp_path, failure):
    archive, scans, report, summary = candidate
    revision = REVISION
    row = summary["images"][0]
    if failure == "revision":
        revision = "b" * 40
    elif failure == "archive":
        row["archive_sha256"] = "0" * 64
    elif failure == "report":
        row["report_sha256"] = "0" * 64
    elif failure == "counts":
        row["high"] = 0
    elif failure == "scanner":
        row["scanner_returncode"] = 1
    elif failure == "policy":
        summary["vulnerability_policy"] = "blocking"
    elif failure == "database":
        report["descriptor"]["db"]["status"]["built"] = (
            datetime.now(UTC) - timedelta(hours=25)
        ).isoformat()
    elif failure == "target":
        report["source"]["target"]["manifestDigest"] = "sha256:" + "0" * 64
    elif failure == "ignored":
        report["ignoredMatches"] = report["matches"]
    raw = scans / "host-amd64-grype.json"
    raw.write_text(json.dumps(report))
    if failure != "report":
        row["report_sha256"] = file_sha256(raw)
    (scans / "aliyun-host-scan-summary.json").write_text(json.dumps(summary))
    with pytest.raises(ValueError):
        prepare(archive, revision, scans, tmp_path / "promote")
    assert not (tmp_path / "promote").exists()


def test_private_promotion_transfers_original_bytes_and_signs_after_readback():
    path = Path(__file__).resolve().parents[2] / ".github/workflows/saas-aliyun-host-candidate.yml"
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    job = workflow["jobs"]["promote-reviewed-gen2"]
    assert "workflow_dispatch" in job["if"]
    assert "codex/aliyun-sandbox-p1-p5-20261031" in job["if"]
    steps = job["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "docker build" not in commands and "buildx build" not in commands
    assert "extract_artifact" in commands and "compare_oci_rebuilds" in commands
    assert "aliyun_host_promotion select" in commands
    assert job["env"]["ORIGINAL_REVISION"] == "${{ inputs.source_revision }}"
    assert job["env"]["ORIGINAL_RUN"] == "${{ inputs.source_run }}"
    assert "--scope aliyun-host" in commands
    assert "--source-digest" in commands and "--deny-self-hosted-runners" in commands
    publish = next(step["run"] for step in steps if "crane push" in step.get("run", ""))
    assert publish.index("--jq .visibility)") < publish.index("crane push")
    assert publish.count('--jq .visibility)" == private ]]') == 2
    readback = next(
        i
        for i, step in enumerate(steps)
        if "aliyun_host_promotion readback" in step.get("run", "")
    )
    signature = next(
        i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/attest@")
    )
    assert readback < signature
    assert all("continue-on-error" not in step for step in steps)
