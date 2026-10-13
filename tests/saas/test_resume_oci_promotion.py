"""Recovery must retain original bytes and distinguish product from signer source."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from saas.scripts import resume_oci_promotion as resume
from tests.saas.test_oci_promotion import EPOCH, REVISION, candidate, seal, write_json

ROOT = Path(__file__).resolve().parents[2]
POLICY = "b" * 40
RUN = "43"


@pytest.fixture
def report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    labels, now = candidate(tmp_path)
    manifest = seal(tmp_path, labels, now)
    write_json(tmp_path / resume.MANIFEST_NAME, manifest)
    binding = copy.deepcopy(resume.lock())
    binding.update(
        product_revision=REVISION,
        source_date_epoch=EPOCH,
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
            "uri": "https://github.com/Dream1216/omnigent/actions/artifacts/11767146798",
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
    "field", ["head_sha", "run_attempt", "conclusion", "runner_group_name", "job-id"]
)
def test_failed_publisher_does_not_authorize_untrusted_candidate_job(field: str) -> None:
    binding = resume.lock()
    run = {
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


@pytest.mark.parametrize("field", ["none", "subject", "certificate", "packages"])
def test_spdx_attestation_requires_explicit_child_and_exact_generated_sbom(
    report: Path, field: str
) -> None:
    subject = "sha256:" + "d" * 64
    sbom = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "python"}]}
    entry = signed_entry(subject)
    statement = entry["verificationResult"]["statement"]
    statement["predicateType"] = "https://spdx.dev/Document"
    statement["predicate"] = copy.deepcopy(sbom)
    if field == "subject":
        statement["subject"] = []
    elif field == "certificate":
        entry["verificationResult"]["signature"]["certificate"]["buildSignerDigest"] = REVISION
    elif field == "packages":
        statement["predicate"]["packages"] = []
    parameters = {
        "subject": subject,
        "predicate": sbom,
        "predicate_type": "https://spdx.dev/Document",
        "claims": resume.certificate_claims(POLICY, resume.WORKFLOW, RUN, "1"),
    }
    if field == "none":
        resume.verify_predicate([entry], **parameters)
    else:
        with pytest.raises(ValueError):
            resume.verify_predicate([entry], **parameters)
