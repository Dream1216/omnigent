"""Only the new controller bindings; OCI mechanics use existing small fixtures."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from tests.saas.test_oci_promotion import EPOCH, REVISION, candidate, seal, write_json

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("m2c_renewal_controller", HERE / "renewal.py")
assert spec and spec.loader
renewal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renewal)
POLICY = "b" * 40


@pytest.fixture(params=["m2c", "main4cb"])
def _fixed_release(request, monkeypatch):
    for name in (
        "PRODUCT",
        "_FIXED_TREE",
        "_FIXED_RUN",
        "ORIGIN_FILE",
        "WORKFLOW",
        "_EVIDENCE_KIND",
    ):
        monkeypatch.setattr(renewal, name, getattr(renewal, name))
    renewal.select_release(request.param)
    return request.param


@pytest.fixture
def native_origin(_fixed_release):
    value = renewal.origin()
    run = {
        "id": value["run_id"],
        "run_attempt": 1,
        "head_sha": renewal.PRODUCT,
        "head_branch": "main",
        "path": value["workflow"],
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": value["repository"]},
    }
    jobs = {
        "jobs": [
            {
                "id": job,
                "run_id": value["run_id"],
                "run_attempt": 1,
                "status": "completed",
                "conclusion": "success",
                "runner_group_name": "GitHub Actions",
                "labels": ["ubuntu-24.04"],
            }
            for job in value["required_jobs"]
        ]
    }
    artifacts = {
        "artifacts": [
            {
                "id": row["id"],
                "name": row["name"],
                "size_in_bytes": row["bytes"],
                "digest": "sha256:" + row["sha256"],
                "expired": False,
                "workflow_run": {"id": value["run_id"], "head_sha": renewal.PRODUCT},
            }
            for row in value["artifacts"].values()
        ]
    }
    return {
        "run": run,
        "jobs": jobs,
        "artifacts": artifacts,
        "tree": {"sha": renewal.PRODUCT, "tree": {"sha": value["product_tree"]}},
    }


def test_actual_fixed_origin_native_bindings(native_origin):
    renewal.verify_origin(**native_origin)


@pytest.mark.parametrize("fault", ["source", "attempt", "job", "artifact", "expired", "tree"])
def test_origin_rejects_other_material_or_borrowed_success(native_origin, fault):
    if fault == "source":
        native_origin["run"]["head_sha"] = POLICY
    elif fault == "attempt":
        native_origin["run"]["run_attempt"] = 2
    elif fault == "job":
        native_origin["jobs"]["jobs"][0]["conclusion"] = "failure"
    elif fault == "artifact":
        native_origin["artifacts"]["artifacts"][0]["digest"] = "sha256:" + "0" * 64
    elif fault == "expired":
        native_origin["artifacts"]["artifacts"][0]["expired"] = True
    else:
        native_origin["tree"]["tree"]["sha"] = POLICY
    with pytest.raises(ValueError):
        renewal.verify_origin(**native_origin)


@pytest.fixture
def current(tmp_path, monkeypatch, _fixed_release):
    sealed = tmp_path / "sealed"
    labels, _ = candidate(sealed)
    summary = json.loads((sealed / "grype/candidate-scan-summary.json").read_text())
    checksum = "sha256:" + "d" * 64
    for row in summary["images"]:
        path = sealed / f"grype/{row['image']}-{row['platform'].split('/')[-1]}-grype.json"
        raw = json.loads(path.read_text())
        raw["descriptor"]["configuration"].update(
            {
                "fail-on-severity": "high",
                "db": {
                    "validate-age": True,
                    "validate-by-hash-on-start": True,
                    "max-allowed-built-age": 86400000000000,
                },
            }
        )
        raw["descriptor"]["db"]["status"]["from"] = (
            "https://grype.anchore.io/db?checksum=" + checksum
        )
        write_json(path, raw)
        row["report_sha256"] = renewal.digest(path)
    write_json(sealed / "grype/candidate-scan-summary.json", summary)
    manifest = seal(sealed, labels, datetime.now(UTC))
    write_json(sealed / renewal.MANIFEST_NAME, manifest)
    value = copy.deepcopy(renewal.origin())
    value.update(
        product_revision=REVISION,
        source_date_epoch=EPOCH,
        manifest_sha256=renewal.digest(sealed / renewal.MANIFEST_NAME),
        images={role: row["index_digest"] for role, row in manifest["images"].items()},
        platforms={
            f"{role}-{arch}": {
                "manifest_digest": row["facts"]["platforms"][f"linux/{arch}"]["manifest_digest"],
                "config_digest": row["facts"]["platforms"][f"linux/{arch}"]["config_digest"],
            }
            for role, row in manifest["images"].items()
            for arch in ("amd64", "arm64")
        },
    )
    if "original_main_ci" in value:
        value["original_main_ci"]["expires_at"] = (
            datetime.now(UTC) + timedelta(hours=2)
        ).isoformat()
    monkeypatch.setattr(renewal, "origin", lambda: copy.deepcopy(value))
    monkeypatch.setattr(renewal, "PRODUCT", REVISION)
    monkeypatch.setattr(
        renewal,
        "official_database_latest",
        lambda: {
            "status": "active",
            "built": summary["database_built_at"],
            "schemaVersion": "v6.1.10",
            "checksum": checksum,
        },
    )
    scans = tmp_path / "current"
    shutil.copytree(sealed / "grype", scans / "grype")
    shutil.copy2(sealed / renewal.MANIFEST_NAME, scans / renewal.MANIFEST_NAME)
    payload = renewal.qualify(
        sealed,
        scans,
        policy=POLICY,
        run="42",
        attempt="1",
        started=(datetime.now(UTC) - timedelta(seconds=10)).isoformat(),
    )
    return payload, scans


def test_fresh_current_reports_keep_original_product_and_immutable_subjects(current):
    payload, scans = current
    renewal.verify_current(payload, scans, policy=POLICY, run="42", attempt="1")
    assert payload["origin"] == renewal.origin()
    assert payload["product_source_or_OCI_rebuilt"] is False
    assert len(payload["reports"]) == 4


@pytest.mark.parametrize(
    "fault", ["equality-expiry", "controller", "attempt", "missing-report", "policy"]
)
def test_current_clock_and_scope_cannot_be_borrowed(current, fault):
    payload, scans = current
    if fault == "equality-expiry":
        payload["expires_at"] = datetime.now(UTC).isoformat()
    elif fault == "controller":
        payload["signing_policy_revision"] = "c" * 40
    elif fault == "attempt":
        payload["run_attempt"] = "2"
    elif fault == "missing-report":
        payload["reports"].pop("host-arm64")
    else:
        path = scans / "grype/host-amd64-grype.json"
        raw = json.loads(path.read_text())
        raw["descriptor"]["configuration"]["db"]["validate-age"] = False
        write_json(path, raw)
    with pytest.raises(ValueError):
        renewal.verify_current(payload, scans, policy=POLICY, run="42", attempt="1")


def test_current_evidence_signature_requires_its_actual_native_controller_and_subject(
    _fixed_release,
):
    claims = renewal.build_certificate_claims(
        renewal.origin()["repository"],
        POLICY,
        renewal.WORKFLOW,
        "42",
        "1",
    )
    subject = "e" * 64
    entry = {
        "verificationResult": {
            "signature": {"certificate": claims},
            "statement": {
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"digest": {"sha256": subject}}],
                "predicate": renewal.promotion_predicate(POLICY, "42", "1"),
            },
        }
    }
    renewal.verify_signature([entry], subject, policy=POLICY, run="42", attempt="1")
    with pytest.raises(ValueError):
        renewal.verify_signature([entry], "f" * 64, policy=POLICY, run="42", attempt="1")
    with pytest.raises(ValueError):
        renewal.verify_signature([entry], subject, policy=POLICY, run="43", attempt="1")


@pytest.mark.parametrize("fault", ["Source-q", "Main-CI", "normal-environment"])
def test_profile_does_not_borrow_another_origin_or_renew_its_authority(
    _fixed_release, monkeypatch, fault
):
    value = copy.deepcopy(renewal.origin())
    if fault == "Source-q":
        value["source_qualification_sha256"] = "0" * 64
    elif fault == "Main-CI":
        value.setdefault("original_main_ci", {})["expires_at"] = "2099-01-01T00:00:00Z"
    else:
        value.setdefault("original_environment_review", {})["run"] = 1
    monkeypatch.setattr(renewal, "read_json", lambda _: value)
    with pytest.raises(ValueError):
        renewal.origin()


def test_unregistered_release_does_not_accept_an_arbitrary_origin_path():
    with pytest.raises(ValueError):
        renewal.select_release("/tmp/untrusted-origin.json")


def test_current_security_expiry_is_bounded_by_original_Main_CI(current, monkeypatch):
    payload, scans = current
    value = copy.deepcopy(renewal.origin())
    if "original_main_ci" not in value:
        # The historical M2c profile keeps its original contract unchanged.
        assert "original_main_ci" not in payload["origin"]
        return
    assert renewal.instant(payload["expires_at"]) <= renewal.instant(
        value["original_main_ci"]["expires_at"]
    )
    value["original_main_ci"]["expires_at"] = datetime.now(UTC).isoformat()
    payload["origin"] = value
    monkeypatch.setattr(renewal, "origin", lambda: copy.deepcopy(value))
    with pytest.raises(ValueError, match="cannot renew original Main CI"):
        renewal.verify_current(payload, scans, policy=POLICY, run="42", attempt="1")


def test_protected_workflow_signs_only_new_evidence_for_its_fixed_origin(_fixed_release):
    workflow = yaml.safe_load(Path(renewal.WORKFLOW).read_text())
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["sign-current-evidence"]
    assert job["environment"] == "production-image"
    assert job["permissions"]["packages"] == "read"
    assert job["permissions"]["id-token"] == job["permissions"]["attestations"] == "write"
    assert "github.ref == 'refs/heads/main'" in job["if"]
    assert "inputs.policy_revision == github.sha" in job["if"]
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert f"git merge-base --is-ancestor {renewal.PRODUCT} HEAD" in commands
    assert "--source-digest " + renewal.PRODUCT in commands
    assert "'.images[$role]' " + renewal.ORIGIN_FILE.as_posix() + ")" in commands
    assert '--image "server=$RUNNER_TEMP/origin/sealed/server-1.tar"' in commands
    assert '--image "host=$RUNNER_TEMP/origin/sealed/host-1.tar"' in commands
    signing = [
        step
        for step in job["steps"]
        if step.get("name") == "Sign only new current evidence subject"
    ]
    assert len(signing) == 1
    assert signing[0]["with"]["subject-path"] == "evidence/current-scan-evidence.json"
    independent = workflow["jobs"]["independent-current-readback"]
    assert independent["needs"] == "sign-current-evidence"
    assert all(access == "read" for access in independent["permissions"].values())
    verification = "\n".join(step.get("run", "") for step in independent["steps"])
    assert renewal.WORKFLOW in verification
    assert commands.count("--release main4cb") == (4 if _fixed_release == "main4cb" else 0)
    assert verification.count("--release main4cb") == (1 if _fixed_release == "main4cb" else 0)
