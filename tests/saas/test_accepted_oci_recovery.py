"""Accepted source reuse authenticates actual CI and checks real OCI bytes."""

import hashlib
import json
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from saas.scripts import accepted_oci_recovery as recovery
from tests.saas.test_oci_promotion import EPOCH, REVISION, candidate


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "id",
        "head_sha",
        "head_branch",
        "event",
        "path",
        "run_attempt",
        "status",
        "conclusion",
        "repository",
    ],
)
def test_product_uses_only_its_own_successful_main_ci(fault):
    identifier, path = next(iter(recovery.CI.items()))
    run = {
        "id": identifier,
        "head_sha": recovery.PRODUCT,
        "head_branch": "main",
        "event": "push",
        "path": path,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": recovery.REPOSITORY},
    }
    if fault is None:
        recovery.verify_product_ci(run, identifier, path)
    else:
        run[fault] = {"full_name": "foreign/repo"} if fault == "repository" else "wrong"
        with pytest.raises(ValueError, match="own Main CI"):
            recovery.verify_product_ci(run, identifier, path)


@pytest.mark.parametrize("fault", [None, "archive", "source", "epoch", "comparison", "platform"])
def test_recovery_rechecks_actual_oci_and_original_comparison(tmp_path, monkeypatch, fault):
    candidate(tmp_path)
    report = json.loads((tmp_path / "saas-image-candidate.json").read_text())
    monkeypatch.setattr(recovery, "PRODUCT", REVISION)
    monkeypatch.setattr(recovery, "EPOCH", EPOCH)
    if fault == "source":
        report["product_revision"] = "b" * 40
    elif fault == "epoch":
        report["source_date_epoch"] += 1
    elif fault == "comparison":
        report["status"] = "failure"
    elif fault == "platform":
        report["images"]["omnigent-saas-host"]["second"]["platforms"] = {}
    archive = tmp_path / "original-report.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("saas-image-candidate.json", json.dumps(report))
    monkeypatch.setattr(recovery, "REPORT_SIZE", archive.stat().st_size)
    monkeypatch.setattr(recovery, "REPORT_SHA", hashlib.sha256(archive.read_bytes()).hexdigest())
    if fault == "archive":
        (tmp_path / "host-1.tar").write_bytes(b"not the authenticated OCI")
    if fault:
        with pytest.raises((ValueError, KeyError, OSError, tarfile.ReadError)):
            recovery.verify_raw(tmp_path)
    else:
        result = recovery.verify_raw(tmp_path)
        assert result["rebuilt"] is True
        assert result["raw_checkpoint_only"] is True
        assert result["fresh_scans_passed"] is False
        assert result["signed_or_production_admitted"] is False
        assert set(result["images"]) == {"server", "host"}


def test_workflow_keeps_fixed_product_and_preserves_before_scan():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.load((root / recovery.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    assert workflow["env"]["PRODUCT_REVISION"] == recovery.PRODUCT
    assert workflow["env"]["SOURCE_REVISION"] == recovery.PRODUCT
    assert workflow["env"]["SOURCE_DATE_EPOCH"] == str(recovery.EPOCH)
    build = workflow["jobs"]["build-accepted-product"]
    assert "inputs.policy_revision == github.sha" in build["if"]
    assert "github.ref == 'refs/heads/main'" in build["if"]
    assert "packages" not in build["permissions"]
    steps = build["steps"]
    actual_builds = [
        step for step in steps if step.get("uses") == "./saas/actions/build-oci-candidate"
    ]
    assert {(step["with"]["artifact"], step["with"]["attempt"]) for step in actual_builds} == {
        ("server", "1"),
        ("host", "1"),
    }
    stage_index = next(
        index for index, step in enumerate(steps) if "Stage actual OCI" in step.get("name", "")
    )
    cleanup_index = next(
        index for index, step in enumerate(steps) if "Reclaim only" in step.get("name", "")
    )
    compare_index = next(index for index, step in enumerate(steps) if step.get("id") == "compare")
    assert stage_index < cleanup_index < compare_index
    assert "mv " not in steps[compare_index]["run"]
    preserve = next(step for step in steps if step.get("id") == "raw")
    assert "always()" in preserve["if"]
    assert preserve["with"]["retention-days"] == "30"
    scan = workflow["jobs"]["scan-and-admit-same-oci"]
    assert "build-accepted-product" in scan["needs"]
    assert any("accepted_oci_recovery download" in step.get("run", "") for step in scan["steps"])
    assert not any("build-oci-candidate" in step.get("uses", "") for step in scan["steps"])
    assert any("scan_oci_candidates" in step.get("run", "") for step in scan["steps"])
    assert any(step.get("if") == "always()" for step in scan["steps"])


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "producer-source",
        "producer-path",
        "producer-event",
        "producer-repo",
        "job-failed",
        "job-missing",
        "artifact-source",
        "artifact-run",
        "artifact-name",
        "artifact-digest",
        "artifact-expired",
    ],
)
def test_raw_resume_authenticates_native_producer_and_exact_bytes(tmp_path, monkeypatch, fault):
    original = tmp_path / "original"
    original.mkdir()
    candidate(original)
    with zipfile.ZipFile(original / "original-report.zip", "w") as bundle:
        bundle.write(original / "saas-image-candidate.json", "saas-image-candidate.json")
    report = original / "original-report.zip"
    monkeypatch.setattr(recovery, "PRODUCT", REVISION)
    monkeypatch.setattr(recovery, "EPOCH", EPOCH)
    monkeypatch.setattr(recovery, "REPORT_SIZE", report.stat().st_size)
    monkeypatch.setattr(recovery, "REPORT_SHA", hashlib.sha256(report.read_bytes()).hexdigest())
    source = tmp_path / "checkpoint.zip"
    with zipfile.ZipFile(source, "w") as bundle:
        for name in ("original-report.zip", "server-1.tar", "host-1.tar"):
            bundle.write(original / name, name)
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    policy, run_id, artifact_id = "b" * 40, 71, 19
    run = {
        "id": run_id,
        "run_attempt": 1,
        "head_sha": policy,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": recovery.WORKFLOW,
        "repository": {"full_name": recovery.REPOSITORY},
    }
    job = {
        "name": "build-accepted-product",
        "run_id": run_id,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-24.04"],
    }
    metadata = {
        "id": artifact_id,
        "name": f"accepted-raw-{REVISION}-{run_id}",
        "digest": f"sha256:{sha}",
        "expired": False,
        "size_in_bytes": source.stat().st_size,
        "workflow_run": {"id": run_id, "head_sha": policy},
    }
    if fault == "producer-source":
        run["head_sha"] = "c" * 40
    elif fault == "producer-path":
        run["path"] = "unreviewed.yml"
    elif fault == "producer-event":
        run["event"] = "pull_request"
    elif fault == "producer-repo":
        run["repository"] = {"full_name": "foreign/repo"}
    elif fault == "job-failed":
        job["conclusion"] = "failure"
    elif fault == "artifact-source":
        metadata["workflow_run"]["head_sha"] = "c" * 40
    elif fault == "artifact-run":
        metadata["workflow_run"]["id"] = 72
    elif fault == "artifact-name":
        metadata["name"] = "arbitrary"
    elif fault == "artifact-digest":
        metadata["digest"] = "sha256:" + "0" * 64
    elif fault == "artifact-expired":
        metadata["expired"] = True

    def api(endpoint):
        if "/artifacts/" in endpoint:
            return metadata
        if "/jobs?" in endpoint:
            return {"jobs": [] if fault == "job-missing" else [job]}
        return run

    monkeypatch.setattr(recovery, "api", api)
    monkeypatch.setattr(
        recovery,
        "download_artifact_bytes",
        lambda _id, destination, **_kw: shutil.copyfile(source, destination),
    )
    if fault:
        with pytest.raises(ValueError):
            recovery.download_raw(run_id, artifact_id, sha, policy, tmp_path / "downloaded")
    else:
        recovery.download_raw(run_id, artifact_id, sha, policy, tmp_path / "downloaded")
        assert (tmp_path / "downloaded/unadmitted-build.json").is_file()
