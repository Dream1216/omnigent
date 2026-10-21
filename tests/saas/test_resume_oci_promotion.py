"""Recovery must retain original bytes and distinguish product from signer source."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from saas.scripts import resume_oci_promotion as resume
from tests.saas.test_oci_promotion import (
    EPOCH,
    REVISION,
    candidate,
    refresh_scan_time,
    seal,
    verify_candidate,
    write_json,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY = "b" * 40
RUN = "43"


@pytest.mark.parametrize(
    ("profile", "path", "workflow", "revision"),
    [
        (
            "f440",
            "saas/supply_chain/oci-promotion-resume-f440.json",
            ".github/workflows/saas-oci-promotion-resume.yml",
            "f4404d47f705c7a3c0745c38ccd1a9be125c31ad",
        ),
        (
            "token-renewal-c90a079c",
            "saas/supply_chain/oci-promotion-token-renewal-c90a079c.json",
            ".github/workflows/saas-oci-promotion-token-renewal.yml",
            "c90a079cb6e3c6cadda35ee1ea3121083e86d8fa",
        ),
        (
            "model-renewal-7cea0940",
            "saas/supply_chain/oci-promotion-model-renewal-7cea0940.json",
            ".github/workflows/saas-oci-promotion-model-renewal.yml",
            "7cea09404d49fc965ce053e51803688a5be5fe53",
        ),
    ],
)
def test_release_profile_binds_exact_product_lock_and_signer(
    monkeypatch: pytest.MonkeyPatch, profile: str, path: str, workflow: str, revision: str
) -> None:
    for name in ("LOCK_PATH", "WORKFLOW", "_SELECTED_PRODUCT_REVISION"):
        monkeypatch.setattr(resume, name, getattr(resume, name))
    resume.configure_release_profile(profile)
    assert Path(path) == resume.LOCK_PATH
    assert workflow == resume.WORKFLOW
    assert revision == resume._SELECTED_PRODUCT_REVISION
    binding: dict[str, Any] = {
        "schema_version": 1,
        "repository": "Dream1216/omnigent",
        "product_revision": revision,
        "rebuilt": False,
        "production_authority": False,
    }
    monkeypatch.setattr(resume, "read_json", lambda _value: copy.deepcopy(binding))
    assert resume.lock() == binding
    for field, value in (
        ("product_revision", POLICY),
        ("repository", "other/omnigent"),
        ("schema_version", 2),
        ("rebuilt", True),
        ("production_authority", True),
    ):
        original = binding[field]
        binding[field] = value
        with pytest.raises(ValueError, match="immutable material scope"):
            resume.lock()
        binding[field] = original


@pytest.mark.parametrize(
    "profile", ["unreviewed", "token-renewal-4dd4f670", "token-renewal-6b51036e"]
)
def test_release_profile_rejects_unreviewed_selection(profile: str) -> None:
    original = (resume.LOCK_PATH, resume.WORKFLOW, resume._SELECTED_PRODUCT_REVISION)
    with pytest.raises(ValueError, match="unapproved release profile"):
        resume.configure_release_profile(profile)
    assert original == (resume.LOCK_PATH, resume.WORKFLOW, resume._SELECTED_PRODUCT_REVISION)


def test_f440_recovery_workflow_is_bound_to_the_actual_retained_materials() -> None:
    binding = resume.lock()
    workflow = yaml.load((ROOT / resume.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    assert binding["product_revision"] == "f4404d47f705c7a3c0745c38ccd1a9be125c31ad"
    assert binding["candidate_run_id"] == 38427634877
    assert binding["candidate_build_job_id"] == 115409178450
    assert binding["candidate_build_completed_at"] == "2026-10-13T18:39:43Z"
    assert binding["rebuilt"] is False
    assert binding["production_authority"] is False
    assert workflow["env"]["PRODUCT_REVISION"] == binding["product_revision"]
    assert workflow["env"]["SOURCE_DATE_EPOCH"] == str(binding["source_date_epoch"])
    assert workflow["env"]["ORIGINAL_CANDIDATE_RUN_ID"] == str(binding["candidate_run_id"])
    outputs = workflow["jobs"]["admit-original"]["outputs"]
    assert outputs["manifest-sha256"] == binding["candidate_manifest_sha256"]
    assert outputs["oci-artifact-id"] == str(binding["oci_artifact_id"])
    assert outputs["oci-artifact-sha256"] == binding["oci_artifact_sha256"]
    publish = workflow["jobs"]["publish-signed"]
    assert publish["environment"] == "production-image"
    assert "run: docker build" not in (ROOT / resume.WORKFLOW).read_text()


def test_token_renewal_recovery_binds_actual_candidate_and_original_wheel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("LOCK_PATH", "WORKFLOW", "_SELECTED_PRODUCT_REVISION"):
        monkeypatch.setattr(resume, name, getattr(resume, name))
    resume.configure_release_profile("token-renewal-c90a079c")
    binding = resume.lock()
    assert binding == {
        "schema_version": 1,
        "repository": "Dream1216/omnigent",
        "product_revision": "c90a079cb6e3c6cadda35ee1ea3121083e86d8fa",
        "source_date_epoch": 1792091272,
        "candidate_run_id": 38792121089,
        "candidate_run_attempt": 1,
        "candidate_run_conclusion": "failure",
        "candidate_build_job_id": 116620710153,
        "candidate_build_completed_at": "2026-10-15T20:58:01Z",
        "candidate_manifest_sha256": (
            "60220221724dc74390549701a1d8b7ca554c75b9205cec887c11bca0f9cf4812"
        ),
        "oci_artifact_id": 12005794203,
        "oci_artifact_sha256": "32a7d9038d3d0b418a0c29e868156bbef96a1eaa9a5d3adafe71e4fbfab6ca19",
        "report_artifact_id": 12005554352,
        "report_artifact_sha256": (
            "d3ce25b380ed77544d8c190b834e515ddb7fab539bd1adcd0ff70e4597d62db6"
        ),
        "wheel_artifact_id": 12006543176,
        "wheel_artifact_sha256": (
            "7bb61ecc0caf198ab2344189d9133521058baa34a726985dfcf105fd920433ea"
        ),
        "wheel_sha256": "d8943d62d0329d87899c2d475b06d440c11d1ff3e483746e8f1936da59803b8e",
        "images": {
            "server": "sha256:d309604af931bf454ec76c3fa098e27afe663433bdda73f454e69abc03571fe5",
            "host": "sha256:237ac333db58abcad813747c85b4b0cf4dcff173b5c9d5955e055149a19c12e8",
        },
        "rebuilt": False,
        "production_authority": False,
    }
    predicate = resume.promotion_predicate(POLICY, RUN, "1")
    external = predicate["buildDefinition"]["externalParameters"]
    assert external["original_candidate"] == binding
    assert external["product_source_revision"] == binding["product_revision"]
    assert external["signing_policy_revision"] == POLICY
    assert external["workflow"]["path"] == resume.WORKFLOW
    workflow_text = (ROOT / resume.WORKFLOW).read_text()
    workflow = yaml.load(workflow_text, Loader=yaml.BaseLoader)
    assert workflow["env"]["PRODUCT_REVISION"] == binding["product_revision"]
    assert workflow["env"]["SOURCE_DATE_EPOCH"] == str(binding["source_date_epoch"])
    assert workflow["env"]["ORIGINAL_CANDIDATE_RUN_ID"] == str(binding["candidate_run_id"])
    assert workflow["jobs"]["admit-original"]["outputs"] == {
        "manifest-sha256": binding["candidate_manifest_sha256"],
        "oci-artifact-id": str(binding["oci_artifact_id"]),
        "oci-artifact-sha256": binding["oci_artifact_sha256"],
    }
    publish = workflow["jobs"]["publish-signed"]
    assert publish["environment"] == "production-image"
    for job_name in ("admit-original", "publish-signed", "verify-published-source"):
        condition = workflow["jobs"][job_name]["if"]
        assert "github.event_name == 'workflow_dispatch'" in condition
        assert "inputs.policy_revision == github.sha" in condition
        assert "github.ref == 'refs/heads/main'" in condition
    helper = "python -m saas.scripts.resume_oci_promotion"
    assert workflow_text.count(helper) >= 10
    assert workflow_text.count(helper) == workflow_text.count(
        helper + " --release token-renewal-c90a079c "
    )
    assert "docker build" not in workflow_text and "uv build" not in workflow_text
    steps = {step.get("name"): step for step in publish["steps"]}
    scans = steps["Generate per-architecture SBOMs and check raw findings"]["run"]
    assert "for arch in amd64 arm64; do" in scans
    assert helper + " --release token-renewal-c90a079c child" in scans
    assert '--role "$artifact" --architecture "$arch"' in scans
    assert "(.ignoredMatches // []) == []" in scans
    for role in ("server", "host"):
        for arch in ("amd64", "arm64"):
            step = steps[f"Sign {role} {arch} explicit SPDX subject"]
            assert step["with"]["subject-digest"] == (
                "${{ steps.coordinates.outputs." + f"{role}-{arch}" + " }}"
            )
            assert step["with"]["sbom-path"] == f"artifacts/supply-chain/{role}-{arch}.spdx.json"
    facts = steps["Record signed candidate facts"]
    assert facts["env"]["WHEEL_ATTESTATION"] == (
        "https://github.com/Dream1216/omnigent/attestations/56434357"
    )
    assert "original_candidate_run_id: 38792121089" in facts["run"]
    for event in ("pull_request", "push"):
        assert resume.WORKFLOW in workflow["on"][event]["paths"]
        assert str(resume.LOCK_PATH) in workflow["on"][event]["paths"]


@pytest.fixture
def report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    labels, now = candidate(tmp_path)
    manifest = seal(tmp_path, labels, now)
    write_json(tmp_path / resume.MANIFEST_NAME, manifest)
    binding = copy.deepcopy(resume.lock())
    binding.update(
        product_revision=REVISION,
        source_date_epoch=EPOCH,
        candidate_build_completed_at=manifest["sealed_at"],
        candidate_manifest_sha256=hashlib.sha256(
            (tmp_path / resume.MANIFEST_NAME).read_bytes()
        ).hexdigest(),
        images={role: value["index_digest"] for role, value in manifest["images"].items()},
    )
    monkeypatch.setattr(resume, "lock", lambda: copy.deepcopy(binding))
    monkeypatch.setattr(resume, "expected_labels", lambda repo, revision: labels)
    return tmp_path


def signed_entry(subject: str) -> dict[str, Any]:
    repository = "https://github.com/Dream1216/omnigent"
    workflow = f"{repository}/{resume.WORKFLOW}@refs/heads/main"
    return {
        "verificationResult": {
            "signature": {
                "certificate": {
                    "issuer": "https://token.actions.githubusercontent.com",
                    "sourceRepositoryURI": repository,
                    "sourceRepositoryRef": "refs/heads/main",
                    "sourceRepositoryDigest": POLICY,
                    "buildSignerDigest": POLICY,
                    "buildConfigDigest": POLICY,
                    "runnerEnvironment": "github-hosted",
                    "subjectAlternativeName": workflow,
                    "runInvocationURI": f"{repository}/actions/runs/{RUN}/attempts/1",
                }
            },
            "statement": {
                "subject": [{"name": "image", "digest": {"sha256": subject[7:]}}],
                "predicateType": resume.PREDICATE_TYPE,
                "predicate": resume.promotion_predicate(POLICY, RUN, "1"),
            },
        }
    }


def test_original_report_still_satisfies_unchanged_raw_and_repeat_gates(report: Path) -> None:
    assert resume.check_report(report)["product_revision"] == REVISION


def test_historical_original_admission_still_requires_fresh_promotion_scans(
    report: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    now = datetime.now(UTC)
    labels = resume.expected_labels(ROOT, REVISION)
    refresh_scan_time(report, now - timedelta(hours=26))
    manifest = seal(report, labels, now - timedelta(hours=25))
    write_json(report / resume.MANIFEST_NAME, manifest)
    binding = resume.lock()
    binding["candidate_manifest_sha256"] = resume.file_sha256(report / resume.MANIFEST_NAME)
    binding["candidate_build_completed_at"] = (
        now - timedelta(hours=25) + timedelta(minutes=1)
    ).isoformat()
    monkeypatch.setattr(resume, "lock", lambda: copy.deepcopy(binding))
    assert resume.check_report(report) == manifest
    parameters = {
        "manifest_sha256": binding["candidate_manifest_sha256"],
        "labels": labels,
        "source_date_epoch": EPOCH,
    }
    with pytest.raises(ValueError, match="older than 24 hours"):
        verify_candidate(report, **parameters)
    current = tmp_path / "fresh-current"
    shutil.copytree(report / "grype", current / "grype")
    with pytest.raises(ValueError, match="older than 24 hours"):
        verify_candidate(report, current_scan_root=current, **parameters)
    refresh_scan_time(current, now)
    assert verify_candidate(report, current_scan_root=current, **parameters) == manifest
    assert (
        resume.file_sha256(report / resume.MANIFEST_NAME) == binding["candidate_manifest_sha256"]
    )


@pytest.mark.parametrize("invalid", ["before-seal", "future", "no-timezone"])
def test_original_completion_time_cannot_be_moved_to_waive_scan_freshness(
    report: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    binding = resume.lock()
    sealed_at = datetime.fromisoformat(
        json.loads((report / resume.MANIFEST_NAME).read_text())["sealed_at"]
    )
    completion = {
        "before-seal": sealed_at - timedelta(seconds=1),
        "future": datetime.now(UTC) + timedelta(hours=1),
        "no-timezone": sealed_at.replace(tzinfo=None),
    }[invalid]
    binding["candidate_build_completed_at"] = completion.isoformat()
    monkeypatch.setattr(resume, "lock", lambda: copy.deepcopy(binding))
    with pytest.raises(ValueError, match="completion time"):
        resume.check_report(report)


@pytest.mark.parametrize("role", ["server", "host"])
@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_probe_reference_is_child_not_multiarch_index(
    report: Path, role: str, architecture: str
) -> None:
    reference = resume.child_reference(report, role, architecture)
    manifest = json.loads((report / resume.MANIFEST_NAME).read_text())
    assert reference.endswith(
        "@"
        + manifest["images"][role]["facts"]["platforms"][f"linux/{architecture}"][
            "manifest_digest"
        ]
    )
    assert not reference.endswith("@" + manifest["images"][role]["index_digest"])


def test_changed_child_or_index_fails_seal_validation(report: Path) -> None:
    path = report / resume.MANIFEST_NAME
    manifest = json.loads(path.read_text())
    manifest["images"]["server"]["facts"]["platforms"]["linux/amd64"]["manifest_digest"] = (
        "sha256:" + "f" * 64
    )
    write_json(path, manifest)
    with pytest.raises(ValueError, match="admitted index"):
        resume.child_reference(report, "server", "amd64")


@pytest.mark.parametrize("coordinate", ["source", "repeat", "raw-scan"])
def test_original_report_tampering_still_blocks_admission(report: Path, coordinate: str) -> None:
    path = report / "saas-image-candidate.json"
    if coordinate == "raw-scan":
        path = report / "grype/server-amd64-grype.json"
    value = json.loads(path.read_text())
    if coordinate == "source":
        value["product_revision"] = POLICY
    elif coordinate == "repeat":
        value["images"]["omnigent-saas-server"]["matching_platform_manifest_and_config"] = False
    else:
        value["ignoredMatches"] = [{"reason": "not permitted"}]
    write_json(path, value)
    with pytest.raises(ValueError):
        resume.check_report(report)


def test_explicit_two_bindings_are_required_not_forged_product_certificate(report: Path) -> None:
    subject = resume.lock()["images"]["server"]
    resume.verify_signature(
        [signed_entry(subject)], subject=subject, policy_revision=POLICY, run_id=RUN, attempt="1"
    )
    predicate = resume.promotion_predicate(POLICY, RUN, "1")
    parameters = predicate["buildDefinition"]["externalParameters"]
    assert parameters["product_source_revision"] == REVISION
    assert parameters["signing_policy_revision"] == POLICY
    assert parameters["rebuild_performed"] is False


def test_promotion_uses_supported_github_workflow_buildtype_without_relabeling_source(
    report: Path,
) -> None:
    predicate = resume.promotion_predicate(POLICY, RUN, "1")
    definition = predicate["buildDefinition"]
    assert definition["buildType"] == "https://actions.github.io/buildtypes/workflow/v1"
    assert definition["externalParameters"]["workflow"] == {
        "path": resume.WORKFLOW,
        "ref": "refs/heads/main",
        "repository": "https://github.com/Dream1216/omnigent",
    }
    assert definition["internalParameters"]["github"] == {
        "event_name": "workflow_dispatch",
        "repository_id": "1319241251",
        "repository_owner_id": "39821512",
        "runner_environment": "github-hosted",
    }
    assert definition["externalParameters"]["original_candidate"]["product_revision"] == REVISION
    dependencies = definition["resolvedDependencies"]
    assert dependencies == [
        {
            "uri": "git+https://github.com/Dream1216/omnigent@refs/heads/main",
            "digest": {"gitCommit": POLICY},
        },
        {
            "uri": f"git+https://github.com/Dream1216/omnigent@{REVISION}",
            "digest": {"gitCommit": REVISION},
        },
        {
            "uri": "https://github.com/Dream1216/omnigent/actions/artifacts/"
            + str(resume.lock()["oci_artifact_id"]),
            "digest": {"sha256": resume.lock()["oci_artifact_sha256"]},
        },
    ]


@pytest.mark.parametrize("field", ["order", "signer-source", "original-product", "archive"])
def test_primary_workflow_source_and_every_original_material_are_required(
    report: Path, field: str
) -> None:
    subject = resume.lock()["images"]["server"]
    entry = signed_entry(subject)
    dependencies = entry["verificationResult"]["statement"]["predicate"]["buildDefinition"][
        "resolvedDependencies"
    ]
    if field == "order":
        dependencies[0], dependencies[1] = dependencies[1], dependencies[0]
    elif field == "signer-source":
        dependencies[0]["digest"]["gitCommit"] = REVISION
    elif field == "original-product":
        dependencies[1]["digest"]["gitCommit"] = POLICY
    else:
        dependencies[2]["digest"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="explicit original-product"):
        resume.verify_signature(
            [entry], subject=subject, policy_revision=POLICY, run_id=RUN, attempt="1"
        )


@pytest.mark.parametrize("field", ["build-type", "workflow", "repository-id", "owner-id"])
def test_unsupported_or_forged_github_build_context_is_rejected(report: Path, field: str) -> None:
    subject = resume.lock()["images"]["server"]
    entry = signed_entry(subject)
    definition = entry["verificationResult"]["statement"]["predicate"]["buildDefinition"]
    if field == "build-type":
        definition["buildType"] = "https://github.com/Dream1216/omnigent/oci-promotion/v1"
    elif field == "workflow":
        definition["externalParameters"]["workflow"]["ref"] = "refs/heads/untrusted"
    else:
        key = "repository_id" if field == "repository-id" else "repository_owner_id"
        definition["internalParameters"]["github"][key] = "0"
    with pytest.raises(ValueError, match="explicit original-product"):
        resume.verify_signature(
            [entry], subject=subject, policy_revision=POLICY, run_id=RUN, attempt="1"
        )


@pytest.mark.parametrize(
    "field",
    [
        "sourceRepositoryDigest",
        "buildSignerDigest",
        "buildConfigDigest",
        "sourceRepositoryRef",
        "subjectAlternativeName",
        "runInvocationURI",
        "runnerEnvironment",
        "issuer",
    ],
)
def test_untrusted_signer_or_old_run_certificate_is_rejected(report: Path, field: str) -> None:
    subject = resume.lock()["images"]["server"]
    entry = signed_entry(subject)
    entry["verificationResult"]["signature"]["certificate"][field] = "not-exact-approved-policy"
    with pytest.raises(ValueError, match="explicit original-product"):
        resume.verify_signature(
            [entry], subject=subject, policy_revision=POLICY, run_id=RUN, attempt="1"
        )


@pytest.mark.parametrize(
    "field", ["product", "artifact", "rebuilt", "boolean", "subject", "builder"]
)
def test_signed_policy_cannot_substitute_original_product_materials(
    report: Path, field: str
) -> None:
    subject = resume.lock()["images"]["server"]
    entry = signed_entry(subject)
    statement = entry["verificationResult"]["statement"]
    parameters = statement["predicate"]["buildDefinition"]["externalParameters"]
    if field == "product":
        parameters["product_source_revision"] = POLICY
    elif field == "artifact":
        parameters["original_candidate"]["oci_artifact_id"] += 1
    elif field == "rebuilt":
        parameters["rebuild_performed"] = True
    elif field == "boolean":
        parameters["rebuild_performed"] = 0
    elif field == "builder":
        statement["predicate"]["runDetails"]["builder"]["id"] = "untrusted"
    else:
        statement["subject"] = []
    with pytest.raises(ValueError):
        resume.verify_signature(
            [entry], subject=subject, policy_revision=POLICY, run_id=RUN, attempt="1"
        )


def test_default_new_workflow_provenance_alone_is_insufficient(report: Path) -> None:
    subject = resume.lock()["images"]["server"]
    entry = signed_entry(subject)
    entry["verificationResult"]["statement"]["predicate"]["buildDefinition"].pop(
        "externalParameters"
    )
    with pytest.raises(ValueError):
        resume.verify_signature(
            [entry], subject=subject, policy_revision=POLICY, run_id=RUN, attempt="1"
        )


@pytest.mark.parametrize("field", ["id", "head_sha", "expired", "digest", "name"])
def test_original_artifact_metadata_is_not_replaceable(field: str) -> None:
    binding = resume.lock()
    metadata = {
        "id": binding["report_artifact_id"],
        "name": f"saas-image-candidate-{binding['product_revision']}",
        "expired": False,
        "digest": "sha256:" + binding["report_artifact_sha256"],
        "workflow_run": {
            "id": binding["candidate_run_id"],
            "head_sha": binding["product_revision"],
        },
    }
    resume.check_artifact(metadata, "report", "saas-image-candidate")
    if field == "head_sha":
        metadata["workflow_run"]["head_sha"] = POLICY
    else:
        metadata[field] = "changed"
    with pytest.raises(ValueError, match="artifact identity"):
        resume.check_artifact(metadata, "report", "saas-image-candidate")


@pytest.mark.parametrize(
    "field",
    ["head_sha", "run_attempt", "conclusion", "runner_group_name", "job-id", "completed_at"],
)
def test_failed_publisher_does_not_authorize_untrusted_candidate_job(field: str) -> None:
    binding = resume.lock()
    run: dict[str, Any] = {
        "id": binding["candidate_run_id"],
        "run_attempt": 1,
        "head_sha": binding["product_revision"],
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": ".github/workflows/saas-image-candidate.yml",
        "status": "completed",
        "conclusion": "failure",
        "repository": {"full_name": binding["repository"]},
    }
    job = {
        "id": binding["candidate_build_job_id"],
        "run_id": binding["candidate_run_id"],
        "run_attempt": 1,
        "name": "build-candidate",
        "status": "completed",
        "conclusion": "success",
        "completed_at": binding["candidate_build_completed_at"],
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-latest"],
    }
    resume.check_original_run(run, job)
    if field in ("head_sha", "run_attempt"):
        run[field] = "different"
    elif field == "job-id":
        job["id"] += 1
    else:
        job[field] = "different"
    with pytest.raises(ValueError, match="candidate job"):
        resume.check_original_run(run, job)


@pytest.mark.parametrize("conclusion", ["success", "failure"])
def test_explicit_completed_run_still_requires_exact_successful_candidate(
    monkeypatch: pytest.MonkeyPatch, conclusion: str
) -> None:
    binding = copy.deepcopy(resume.lock())
    binding["candidate_run_conclusion"] = conclusion
    monkeypatch.setattr(resume, "lock", lambda: copy.deepcopy(binding))
    run = {
        "id": binding["candidate_run_id"],
        "run_attempt": binding["candidate_run_attempt"],
        "head_sha": binding["product_revision"],
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": ".github/workflows/saas-image-candidate.yml",
        "status": "completed",
        "conclusion": conclusion,
        "repository": {"full_name": binding["repository"]},
    }
    job = {
        "id": binding["candidate_build_job_id"],
        "run_id": binding["candidate_run_id"],
        "run_attempt": binding["candidate_run_attempt"],
        "name": "build-candidate",
        "status": "completed",
        "conclusion": "success",
        "completed_at": binding["candidate_build_completed_at"],
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-latest"],
    }
    resume.check_original_run(run, job)
    for changed in (
        {"conclusion": "failure"},
        {"status": "in_progress"},
        {"runner_group_name": "self-hosted"},
        {"id": binding["candidate_build_job_id"] + 1},
        {"run_id": binding["candidate_run_id"] + 1},
        {"completed_at": "2099-01-01T00:00:00Z"},
    ):
        with pytest.raises(ValueError, match="candidate job"):
            resume.check_original_run(run, {**job, **changed})
    for changed in (
        {"conclusion": "cancelled"},
        {"conclusion": "failure" if conclusion == "success" else "success"},
        {"head_sha": POLICY},
        {"status": "in_progress"},
    ):
        with pytest.raises(ValueError, match="candidate job"):
            resume.check_original_run({**run, **changed}, job)


@pytest.mark.parametrize("conclusion", [None, "cancelled", "skipped", "timed_out", ""])
def test_resume_cannot_lock_a_nonterminal_or_unadmitted_original_run(
    monkeypatch: pytest.MonkeyPatch, conclusion: object
) -> None:
    binding = copy.deepcopy(resume.lock())
    binding["candidate_run_conclusion"] = conclusion
    monkeypatch.setattr(resume, "lock", lambda: copy.deepcopy(binding))
    with pytest.raises(ValueError, match="unapproved original run conclusion"):
        resume.check_original_run({}, {})


def test_resume_workflow_never_builds_or_relabels_oci_and_keeps_all_gates() -> None:
    workflow = yaml.load((ROOT / resume.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    publish = workflow["jobs"]["publish-signed"]
    independent = workflow["jobs"]["verify-published-source"]
    assert publish["environment"] == "production-image"
    assert publish["needs"] == "admit-original"
    assert independent["needs"] == ["admit-original", "publish-signed"]
    for job in (publish, independent):
        source = json.dumps(job)
        assert "build-push-action" not in source
        assert "docker build" not in source
        assert "uv build" not in source
        assert "--deny-self-hosted-runners" in source
        assert '--source-digest \\"$SIGNING_POLICY_REVISION\\"' in source
        assert "oci_promotion readback" in source
        assert "resume_oci_promotion verify" in source
    run = "\n".join(step.get("run", "") for step in publish["steps"])
    assert "child \\\n" in run
    assert '--run-id "$ORIGINAL_CANDIDATE_RUN_ID"' in run
    assert "scan_oci_candidates" in run
    assert "resume_oci_promotion predicate" in run
    assert "rebuild" not in run.replace("--deny-self-hosted-runners", "")
    attestations = [s for s in publish["steps"] if s.get("uses", "").startswith("actions/attest@")]
    assert len(attestations) == 8
    assert len([s for s in attestations if "sbom-path" in s["with"]]) == 4
    assert len([s for s in attestations if "predicate-path" in s["with"]]) == 2


@pytest.mark.parametrize(
    "field",
    [
        "none",
        "subject",
        "certificate",
        "packages",
        "unversioned",
        "predicate-version",
        "document-version",
        "empty-inventory",
    ],
)
def test_spdx_attestation_requires_explicit_child_and_exact_generated_sbom(
    report: Path, field: str
) -> None:
    subject = "sha256:" + "d" * 64
    sbom = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "python"}]}
    entry = signed_entry(subject)
    statement = entry["verificationResult"]["statement"]
    statement["predicateType"] = "https://spdx.dev/Document/v2.3"
    statement["predicate"] = copy.deepcopy(sbom)
    if field == "subject":
        statement["subject"] = []
    elif field == "certificate":
        entry["verificationResult"]["signature"]["certificate"]["buildSignerDigest"] = REVISION
    elif field == "packages":
        statement["predicate"]["packages"] = []
    elif field == "unversioned":
        statement["predicateType"] = "https://spdx.dev/Document"
    elif field == "predicate-version":
        statement["predicateType"] = "https://spdx.dev/Document/v2.2"
    elif field == "document-version":
        sbom["spdxVersion"] = statement["predicate"]["spdxVersion"] = "SPDX-2.2"
    elif field == "empty-inventory":
        sbom["packages"] = statement["predicate"]["packages"] = []
    parameters = {
        "subject": subject,
        "predicate": sbom,
        "claims": resume.certificate_claims(POLICY, resume.WORKFLOW, RUN, "1"),
    }
    if field == "none":
        resume.verify_sbom([entry], **parameters)
    else:
        with pytest.raises(ValueError):
            resume.verify_sbom([entry], **parameters)
