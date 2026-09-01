from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import yaml

from saas.scripts.run_production_admission import (
    _output_directory,
    _render,
    build_production_admission_bundle,
)

_NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _head() -> str:
    return subprocess.run(
        ("git", "-C", str(_repo()), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_current_candidate_generates_hash_bound_fail_closed_bundle() -> None:
    revision = _head()

    reports = build_production_admission_bundle(
        _repo(),
        product_revision=revision,
        evidence_revision=revision,
        now=_NOW,
    )

    bundle = reports["bundle"]
    assert bundle["status"] == "pass"
    assert bundle["production_readiness"] == "blocked"
    assert bundle["release_decision"] == "NO-GO"
    assert bundle["violations"] == []
    assert bundle["metrics"] == {
        "ready_evidence_kind_count": 0,
        "required_evidence_kind_count": 8,
        "derived_ready_gate_count": 0,
        "aggregate_gate_count": 10,
        "ledger_passed_gate_count": 0,
    }
    assert (
        bundle["reports"]["evidence_admission"]["sha256"]
        == hashlib.sha256(_render(reports["admission"])).hexdigest()
    )
    assert (
        bundle["reports"]["production_readiness"]["sha256"]
        == hashlib.sha256(_render(reports["readiness"])).hexdigest()
    )


def test_evidence_revision_must_equal_checked_out_head() -> None:
    reports = build_production_admission_bundle(
        _repo(),
        product_revision=_head(),
        evidence_revision="b" * 40,
        now=_NOW,
    )

    assert reports["bundle"]["status"] == "fail"
    assert reports["bundle"]["production_readiness"] == "blocked"
    assert "checked-out HEAD does not match evidence_revision" in reports["bundle"]["violations"]


def test_product_revision_must_be_an_exact_lowercase_sha() -> None:
    reports = build_production_admission_bundle(
        _repo(),
        product_revision="not-a-revision",
        evidence_revision=_head(),
        now=_NOW,
    )

    assert reports["bundle"]["status"] == "fail"
    assert reports["bundle"]["production_readiness"] == "blocked"
    assert "product_revision must be a full lowercase Git SHA" in reports["bundle"]["violations"]


def test_output_directory_rejects_escape_and_symlink(tmp_path: Path) -> None:
    for unsafe in (".", "../outside", "/tmp/outside"):
        try:
            _output_directory(tmp_path, unsafe)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe output path was accepted: {unsafe}")
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    try:
        _output_directory(tmp_path, "link")
    except ValueError:
        pass
    else:
        raise AssertionError("symbolic-link output directory was accepted")
    nested = tmp_path / "nested"
    nested.symlink_to(target, target_is_directory=True)
    try:
        _output_directory(tmp_path, "nested/reports")
    except ValueError:
        pass
    else:
        raise AssertionError("nested symbolic-link output directory was accepted")


def test_production_workflow_is_manual_protected_and_fail_closed() -> None:
    path = _repo() / ".github/workflows/saas-production-admission.yml"
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {"workflow_dispatch"}
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"product_revision", "evidence_revision", "receipt_request_json"}
    job = workflow["jobs"]["production-admission"]
    assert job["environment"] == "production-evidence"
    assert workflow["permissions"] == {"contents": "read"}
    preflight = next(
        step["run"]
        for step in job["steps"]
        if step.get("name") == "Validate immutable revision inputs"
    )
    assert "refs/heads/main" in preflight
    assert '"$EVIDENCE_REVISION" == "$TRUSTED_REF_REVISION"' in preflight
    checkout = next(step for step in job["steps"] if "actions/checkout@" in step.get("uses", ""))
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["fetch-depth"] == "0"
    assert checkout["with"]["persist-credentials"] == "false"
    command = next(
        step["run"]
        for step in job["steps"]
        if "saas.scripts.run_production_admission" in step.get("run", "")
    )
    assert "--require-ready" in command
    assert "--product-revision" in command
    assert "--evidence-revision" in command
    upload = next(
        step for step in job["steps"] if "actions/upload-artifact@" in step.get("uses", "")
    )
    assert upload["if"] == "always()"
    assert upload["with"]["retention-days"] == "90"

    candidate_path = _repo() / ".github/workflows/saas-image-candidate.yml"
    candidate = yaml.load(candidate_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert ".github/workflows/saas-production-admission.yml" in candidate["on"]["push"]["paths"]


def test_image_candidate_composite_preserves_reproducible_build_contract() -> None:
    path = _repo() / "saas/actions/build-oci-candidate/action.yml"
    action = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert set(action["inputs"]) == {"artifact", "target", "attempt"}
    assert action["runs"]["using"] == "composite"
    build = next(
        step
        for step in action["runs"]["steps"]
        if "docker/build-push-action@" in step.get("uses", "")
    )
    options = build["with"]
    assert options["platforms"] == "linux/amd64,linux/arm64"
    assert options["provenance"] == "mode=max"
    assert options["sbom"] == "true"
    assert options["outputs"].endswith(",rewrite-timestamp=true")
    assert options["no-cache"] == "${{ inputs.attempt == '2' }}"
    assert "inputs.attempt == '1'" in options["cache-from"]
    assert "inputs.attempt == '1'" in options["cache-to"]
    for name in (
        "PYTHON_IMAGE",
        "NODE_IMAGE",
        "SOURCE_DATE_EPOCH",
        "SOURCE_REVISION",
        "UPSTREAM_REVISION",
        "CONTROL_PLANE_SCHEMA_REVISION",
        "ADAPTER_CONTRACT_VERSION",
    ):
        assert f"{name}=${{{{ env.{name} }}}}" in options["build-args"]
