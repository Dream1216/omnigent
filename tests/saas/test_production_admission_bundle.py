from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
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
    assert set(inputs) == {
        "product_revision",
        "evidence_revision",
        "receipt_request_json",
        "review_exception_request_json",
        "runtime_evidence_revision",
    }
    assert inputs["runtime_evidence_revision"]["required"] == "false"
    job = workflow["jobs"]["production-admission"]
    assert job["environment"] == "production-evidence"
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}
    assert job["env"]["GH_TOKEN"] == "${{ github.token }}"
    preflight = next(
        step["run"]
        for step in job["steps"]
        if step.get("name") == "Validate immutable revision inputs"
    )
    assert "refs/heads/main" in preflight
    assert '"$EVIDENCE_REVISION" == "$TRUSTED_REF_REVISION"' in preflight
    assert (
        '[[ -z "$RUNTIME_EVIDENCE_REVISION" || -z "$REVIEW_EXCEPTION_REQUEST_JSON" ]]' in preflight
    )
    context = next(
        step
        for step in job["steps"]
        if step.get("uses") == "./saas/actions/runtime-evidence-context"
    )
    assert (
        context["if"]
        == "inputs.runtime_evidence_revision != '' && inputs.review_exception_request_json == ''"
    )
    assert context["with"] == {
        "product-revision": "${{ inputs.product_revision }}",
        "evidence-revision": "${{ inputs.runtime_evidence_revision }}",
    }
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
    assert '--controller-revision "$TRUSTED_REF_REVISION"' in command
    assert '--evidence-revision "${RUNTIME_EVIDENCE_REVISION:-$EVIDENCE_REVISION}"' in command
    assert '--evidence-repo "${OMNIGENT_RUNTIME_EVIDENCE_REPO:-$GITHUB_WORKSPACE}"' in command
    upload = next(
        step for step in job["steps"] if step.get("name") == "Upload immutable admission reports"
    )
    assert upload["if"] == "always() && inputs.review_exception_request_json == ''"
    assert '[[ -z "$REVIEW_EXCEPTION_REQUEST_JSON" || -z "$RECEIPT_REQUEST_JSON" ]]' in preflight
    waiver_upload = next(
        step
        for step in job["steps"]
        if step.get("name") == "Upload immutable review authorization"
    )
    assert waiver_upload["if"] == "inputs.review_exception_request_json != ''"
    assert (
        waiver_upload["with"]["name"]
        == "production-review-authorization-${{ inputs.evidence_revision }}"
    )
    assert upload["with"]["retention-days"] == "90"

    candidate_path = _repo() / ".github/workflows/saas-image-candidate.yml"
    candidate = yaml.load(candidate_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert candidate["on"]["push"]["branches"] == ["main"]
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
        "RUNTIME_IMAGE",
        "NODE_IMAGE",
        "GO_IMAGE",
        "SOURCE_DATE_EPOCH",
        "SOURCE_REVISION",
        "UPSTREAM_REVISION",
        "CONTROL_PLANE_SCHEMA_REVISION",
        "ADAPTER_CONTRACT_VERSION",
    ):
        assert f"{name}=${{{{ env.{name} }}}}" in options["build-args"]


@pytest.mark.parametrize("fault", [None, "controller", "source", "dirty", "evidence"])
def test_final_admission_separates_controller_product_and_immutable_data(
    tmp_path, monkeypatch, fault
):
    from saas.scripts import run_production_admission as runner
    from saas.scripts.runtime_evidence_intake import ADMISSION_POLICY
    from tests.saas import test_evidence_admission as signed
    from tests.saas.test_production_readiness import _git

    controller, data = tmp_path / "controller", tmp_path / "data"
    controller.mkdir()
    policy, _ = signed._fixture(controller)
    path = controller / ADMISSION_POLICY
    path.parent.mkdir(parents=True)
    image_path = "saas/acceptance/p0-production-image-evidence.json"
    next(row for row in policy["evidence_sources"] if row["kind"] == "image")["path"] = image_path
    path.write_text(json.dumps(policy))
    image = controller / image_path
    image.parent.mkdir(parents=True)
    image.write_text("{}")
    for args in (
        ("init",),
        ("config", "user.email", "test@example.invalid"),
        ("config", "user.name", "Test"),
        ("add", "."),
        ("commit", "-m", "product"),
    ):
        _git(controller, *args)
    product = _git(controller, "rev-parse", "HEAD")
    image.write_text('{"data_only": true}')
    if fault == "source":
        (controller / "runtime.py").write_text("raise RuntimeError('data must never execute')")
    _git(controller, "add", ".")
    _git(controller, "commit", "-m", "data")
    evidence = _git(controller, "rev-parse", "HEAD")
    _git(controller, "worktree", "add", "--detach", str(data), evidence)
    _git(controller, "checkout", "--detach", product)
    (controller / "control.py").write_text("# independent protected controller increment\n")
    _git(controller, "add", ".")
    _git(controller, "commit", "-m", "controller")
    control = _git(controller, "rev-parse", "HEAD")
    if fault == "dirty":
        (data / image_path).write_text("{}")
    calls = []

    def verify(root, *args, **kwargs):
        calls.append(root)
        return {"status": "pass", "production_readiness": "blocked", "violations": []}

    monkeypatch.setattr(runner, "validate_evidence_admission", verify)
    monkeypatch.setattr(runner, "validate_production_readiness", verify)
    arguments = {
        "product_revision": product,
        "evidence_revision": "b" * 40 if fault == "evidence" else evidence,
        "controller_revision": "b" * 40 if fault == "controller" else control,
        "evidence_repo": data,
        "now": _NOW,
    }
    if fault in {"source", "dirty"}:
        with pytest.raises(ValueError, match="dirty lineage"):
            runner.build_production_admission_bundle(controller, **arguments)
        assert calls == []
    else:
        bundle = runner.build_production_admission_bundle(controller, **arguments)["bundle"]
        assert calls == [data, data]
        assert bundle["product_revision"] == product
        assert bundle["controller_revision"] == arguments["controller_revision"]
        assert bundle["evidence_revision"] == arguments["evidence_revision"]
        assert bundle["status"] == ("pass" if fault is None else "fail")
        assert bundle["release_decision"] == "NO-GO"
        assert _git(controller, "rev-parse", "HEAD") == control
        assert image.read_text() == "{}"
