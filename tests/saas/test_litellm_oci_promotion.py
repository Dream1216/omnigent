"""The separate model runtime must satisfy the same exact-byte release boundary."""

from __future__ import annotations

import copy
import json
import re
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from saas.scripts.litellm_oci_promotion import (
    ARTIFACT_PREFIX,
    COMPARISON_NAME,
    seal_runtime,
    validate_runtime_release_contract,
    verify_runtime,
    verify_runtime_readback,
)
from saas.scripts.oci_promotion import MANIFEST_NAME, seal_candidate, verify_artifact_metadata
from saas.scripts.scan_oci_candidates import file_sha256, validate_image_scope
from tests.saas.test_oci_promotion import EPOCH, REVISION, candidate, write_json

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("event", ["pull_request", "push"])
def test_runtime_only_changes_trigger_the_formal_candidate(event: str) -> None:
    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert "saas/deployment/litellm/**" in workflow["on"][event]["paths"]


def test_runtime_gate_rejects_missing_runtime_only_trigger() -> None:
    workflow = (ROOT / ".github/workflows/saas-image-candidate.yml").read_text()
    action = (ROOT / "saas/actions/build-oci-candidate/action.yml").read_text()
    changed = workflow.replace('      - "saas/deployment/litellm/**"\n', "", 1)
    assert (
        "LiteLLM runtime changes must trigger the formal candidate: pull_request"
        in validate_runtime_release_contract(ROOT, changed, action)
    )


def test_runtime_release_shell_steps_parse_after_github_expression_binding() -> None:
    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    count = 0
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "LiteLLM" not in step.get("name", "") or "run" not in step:
                continue
            script = re.sub(r"\$\{\{.*?\}\}", "bound-ci-coordinate", step["run"])
            result = subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True)
            assert result.returncode == 0, step["name"] + ": " + result.stderr
            count += 1
    assert count >= 10


def test_runtime_workflow_preserves_application_and_runtime_boundaries() -> None:
    workflow = (ROOT / ".github/workflows/saas-image-candidate.yml").read_text()
    action = (ROOT / "saas/actions/build-oci-candidate/action.yml").read_text()
    assert validate_runtime_release_contract(ROOT, workflow, action) == []
    parsed = yaml.load(workflow, Loader=yaml.BaseLoader)
    publish = parsed["jobs"]["publish-signed"]
    assert publish["environment"] == "production-image"
    assert "inputs.publish_signed" in publish["if"] and "refs/heads/main" in publish["if"]
    builds = parsed["jobs"]["build-candidate"]["steps"]
    runtime_builds = [step for step in builds if step.get("with", {}).get("artifact") == "litellm"]
    assert [step["with"]["attempt"] for step in runtime_builds] == ["1", "2"]
    assert all(step["with"]["target"] == "runtime" for step in runtime_builds)
    assert "--image server=" in workflow and "--image host=" in workflow


@pytest.mark.parametrize(
    "step_name",
    [
        "Scan exact LiteLLM candidates on both architectures",
        "Seal exact admitted LiteLLM OCI and scan evidence",
        "Download and validate admitted LiteLLM OCI",
        "Verify published LiteLLM runtime on both architectures",
        "Sign LiteLLM image provenance with GitHub OIDC",
        "Verify signed LiteLLM digest and source",
        "Read back signed LiteLLM OCI",
        "Independently verify LiteLLM runtime digest and source",
    ],
)
def test_runtime_release_rejects_missing_required_step(step_name: str) -> None:
    workflow = (ROOT / ".github/workflows/saas-image-candidate.yml").read_text()
    action = (ROOT / "saas/actions/build-oci-candidate/action.yml").read_text()
    changed = workflow.replace(
        "      - name: " + step_name + "\n", "      - name: omitted runtime gate\n", 1
    )
    assert any(
        step_name in error for error in validate_runtime_release_contract(ROOT, changed, action)
    )


def test_runtime_build_cannot_use_application_dockerfile() -> None:
    workflow = (ROOT / ".github/workflows/saas-image-candidate.yml").read_text()
    action = (ROOT / "saas/actions/build-oci-candidate/action.yml").read_text()
    changed = action.replace("'saas/deployment/litellm/Dockerfile'", "'deploy/docker/Dockerfile'")
    assert (
        "LiteLLM composite build must use the admitted runtime and base"
        in validate_runtime_release_contract(ROOT, workflow, changed)
    )


@pytest.mark.parametrize(
    "relative",
    ["saas", "saas/deployment", "saas/deployment/litellm", "saas/deployment/litellm/Dockerfile"],
)
def test_runtime_gate_rejects_symlinked_deployment_materials(
    tmp_path: Path, relative: str
) -> None:
    repo = tmp_path / "repo"
    link = repo / relative
    link.parent.mkdir(parents=True)
    link.symlink_to(ROOT / relative)
    workflow = (ROOT / ".github/workflows/saas-image-candidate.yml").read_text()
    action = (ROOT / "saas/actions/build-oci-candidate/action.yml").read_text()
    assert (
        "LiteLLM runtime must carry exact source and OSS profile labels"
        in validate_runtime_release_contract(repo, workflow, action)
    )


def test_litellm_candidate_seal_and_exact_readback(tmp_path: Path) -> None:
    labels, now = candidate(tmp_path, images=("litellm",), label_profile="litellm")
    manifest = seal_runtime(tmp_path, labels=labels, source_date_epoch=EPOCH, now=now)
    write_json(tmp_path / MANIFEST_NAME, manifest)
    digest = file_sha256(tmp_path / MANIFEST_NAME)
    assert (
        verify_runtime(tmp_path, manifest_sha256=digest, labels=labels, source_date_epoch=EPOCH)
        == manifest
    )
    result = verify_runtime_readback(
        tmp_path,
        tmp_path / "litellm-1.tar",
        manifest_sha256=digest,
        labels=labels,
        source_date_epoch=EPOCH,
        current_scan_root=tmp_path,
    )
    assert result["status"] == "pass" and result["current_scans"] == manifest["scans"]
    assert result["production_deployment_receipt"] is None


@pytest.mark.parametrize(
    "mutation", ["source", "ignored", "high", "missing_arch", "archive", "stale_db", "comparison"]
)
def test_litellm_candidate_rejects_incomplete_or_changed_evidence(
    tmp_path: Path, mutation: str
) -> None:
    labels, now = candidate(tmp_path, images=("litellm",), label_profile="litellm")
    if mutation == "source":
        labels = {**labels, "io.omnigent.integration.revision": "b" * 40}
    elif mutation == "archive":
        (tmp_path / "litellm-1.tar").unlink()
    elif mutation == "comparison":
        path = tmp_path / COMPARISON_NAME
        document = json.loads(path.read_text())
        document["images"]["omnigent-litellm"]["history_created_by_equal"] = False
        write_json(path, document)
    elif mutation == "missing_arch":
        path = tmp_path / "grype/candidate-scan-summary.json"
        document = json.loads(path.read_text())
        document["images"].pop()
        write_json(path, document)
    else:
        path = tmp_path / "grype/litellm-arm64-grype.json"
        document = json.loads(path.read_text())
        finding = {
            "vulnerability": {"id": "CVE-test", "severity": "High"},
            "artifact": {"name": "test-package", "version": "1"},
        }
        if mutation == "ignored":
            document["ignoredMatches"] = [finding]
        elif mutation == "high":
            document["matches"] = [finding]
        else:
            document["descriptor"]["db"]["status"]["built"] = (
                now - timedelta(hours=25)
            ).isoformat()
        write_json(path, document)
    with pytest.raises(ValueError):
        seal_runtime(tmp_path, labels=labels, source_date_epoch=EPOCH, now=now)


def test_litellm_runtime_cannot_replace_application_or_preflight_scan(tmp_path: Path) -> None:
    labels, now = candidate(tmp_path, images=("litellm",), label_profile="litellm")
    validate_image_scope({"litellm": tmp_path / "litellm-1.tar"}, "litellm-runtime")
    with pytest.raises(ValueError, match="requires exactly: host, server"):
        validate_image_scope({"litellm": tmp_path / "litellm-1.tar"}, "complete")
    with pytest.raises(ValueError, match="requires exactly: litellm"):
        validate_image_scope({"server": tmp_path / "litellm-1.tar"}, "litellm-runtime")
    application_comparison = copy.deepcopy(json.loads((tmp_path / COMPARISON_NAME).read_text()))
    write_json(tmp_path / "saas-image-candidate.json", application_comparison)
    with pytest.raises(ValueError, match="does not bind the final source"):
        seal_candidate(tmp_path, labels=labels, source_date_epoch=EPOCH, now=now)


@pytest.mark.parametrize("wrong_binding", ["prefix", "source", "run", "expired"])
def test_runtime_artifact_is_bound_to_exact_name_source_and_run(wrong_binding: str) -> None:
    metadata: dict[str, Any] = {
        "id": 12,
        "name": ARTIFACT_PREFIX + REVISION,
        "expired": False,
        "digest": "sha256:" + "c" * 64,
        "workflow_run": {"id": 34, "head_sha": REVISION},
    }
    verify_artifact_metadata(
        metadata,
        artifact_id=12,
        zip_sha256="c" * 64,
        revision=REVISION,
        run_id=34,
        artifact_prefix=ARTIFACT_PREFIX,
    )
    if wrong_binding == "prefix":
        metadata["name"] = "saas-oci-promotion-" + REVISION
    elif wrong_binding == "source":
        metadata["workflow_run"]["head_sha"] = "b" * 40
    elif wrong_binding == "run":
        metadata["workflow_run"]["id"] = 35
    else:
        metadata["expired"] = True
    with pytest.raises(ValueError, match="exact workflow run and source"):
        verify_artifact_metadata(
            metadata,
            artifact_id=12,
            zip_sha256="c" * 64,
            revision=REVISION,
            run_id=34,
            artifact_prefix=ARTIFACT_PREFIX,
        )


def test_application_artifact_rejects_runtime_name() -> None:
    metadata = {
        "id": 12,
        "name": ARTIFACT_PREFIX + REVISION,
        "expired": False,
        "digest": "sha256:" + "c" * 64,
        "workflow_run": {"id": 34, "head_sha": REVISION},
    }
    with pytest.raises(ValueError, match="exact workflow run and source"):
        verify_artifact_metadata(
            metadata, artifact_id=12, zip_sha256="c" * 64, revision=REVISION, run_id=34
        )
