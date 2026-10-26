"""Local contracts; native API/signature positives are explicit test mocks only."""

from __future__ import annotations

import base64
import copy
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from saas.production import legacy_publication as admission
from saas.scripts import legacy_publication_reader as reader
from saas.scripts.check_image_supply_chain import validate_release
from saas.scripts.run_production_admission import build_production_admission_bundle
from tests.saas import test_image_supply_chain as image
from tests.saas.test_legacy_build_controller import product as product
from tests.saas.test_legacy_initial_publisher import publication_data as publication_data

ROOT = Path(__file__).resolve().parents[2]
MAIN = "2c5a9a45f1a576439fc9c5aa0a91022d461389ab"


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def envelope(evidence):
    return {
        "kind": "production_release_with_legacy_fallback/v1",
        "product_revision": evidence["product_revision"],
        "release_evidence": evidence,
        "legacy_fallback": {"publication_id": "fixture-Core", "full_stack_rollback": {}},
    }


@pytest.fixture
def registration(publication_data, tmp_path, monkeypatch):
    """Registry shape unit fixture; dummy CI/PG stores cannot pass native consumption."""
    data = publication_data
    profile = data["profile"]
    monkeypatch.setitem(
        admission.validate_profile.__globals__["BASELINES"], "Core", profile["baseline_revision"]
    )
    source = data["admission"]["source_qualification"]["result"]
    source["complete_domain_discovery"] = True
    data["admission"]["source_qualification"]["sha256"] = reader.publisher.digest(source)
    row = {
        "input_variant": reader.publisher.VARIANT,
        "profile": profile,
        "producer": {**data["context"], "control_tree": "b" * 40, "workflow_sha256": "e" * 64},
        "admission": data["admission"],
        "predicate_sha256": "a" * 64,
        "stage_artifacts": {
            role: {
                "job_id": 100 + index,
                "artifact_id": 200 + index,
                "zip_size": 100,
                "zip_sha256": str(index) * 64,
                "artifact_name": reader.publisher.artifact_name(role, profile, data["context"]),
            }
            for index, role in enumerate(
                ("preparation", "publication", "runtime", "signatures"), 1
            )
        },
        "deployment_roles": {"control-plane": "server"},
    }
    for name in reader.TRUSTED_STORES:
        key = "inputs" if "original-inputs" in name else "profiles"
        selected = profile if "build-profiles" in name else {"fixture_only": True}
        write(
            tmp_path / "saas/supply_chain" / name, {"schema_version": 1, key: {"Core": selected}}
        )
    write(
        tmp_path / admission.REGISTRY, {"schema_version": 1, "publications": {"fixture-Core": row}}
    )
    return tmp_path, row


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "v1",
        "unknown",
        "missing_domain",
        "domain_false",
        "domain_truthy",
        "blocked_domain",
        "mixed_tree",
        "same_artifact",
        "stage_hash",
        "stage_job_bool",
        "empty_current_store",
    ],
)
def test_exact_registration_denies_unapproved_variants_and_incomplete_discovery(
    registration, fault
):
    repo, row = registration
    source = row["admission"]["source_qualification"]["result"]
    if fault == "v1":
        row["input_variant"] = "original_pr_oci_and_fresh_control_wheel/v1"
    elif fault == "unknown":
        row["input_variant"] = "protected_legacy_initial_publication/v99"
    elif fault == "missing_domain":
        source.pop("complete_domain_discovery")
    elif fault in {"domain_false", "domain_truthy", "blocked_domain"}:
        source["complete_domain_discovery"] = 1 if fault == "domain_truthy" else False
        if fault == "blocked_domain":
            source.update(status="blocked-domain-discovery", source_ci_pass=False)
    elif fault == "mixed_tree":
        row["admission"]["fresh_control_wheel"]["product_tree"] = "0" * 40
    elif fault == "same_artifact":
        row["stage_artifacts"]["runtime"]["artifact_id"] = row["stage_artifacts"]["publication"][
            "artifact_id"
        ]
    elif fault == "stage_hash":
        row["stage_artifacts"]["runtime"]["zip_sha256"] = "bad"
    elif fault == "stage_job_bool":
        row["stage_artifacts"]["runtime"]["job_id"] = True
    elif fault == "empty_current_store":
        write(
            repo / "saas/supply_chain/legacy-security-pg-profiles.json",
            {"schema_version": 1, "profiles": {}},
        )
    write(repo / admission.REGISTRY, {"schema_version": 1, "publications": {"fixture-Core": row}})
    if fault:
        with pytest.raises(ValueError):
            admission.registered_publication(repo, "fixture-Core")
    else:
        assert admission.registered_publication(repo, "fixture-Core") == row


@pytest.mark.parametrize(
    "fault", [None, "active", "failed", "actor", "attempt", "tree", "workflow_bytes"]
)
def test_historical_context_reads_real_objects_and_native_API_without_GHA_impersonation(
    tmp_path, monkeypatch, fault
):
    """Only native API responses are mocked; these commits belong to this fixture."""
    control = tmp_path / "control"
    workflow = control / reader.publisher.WORKFLOW
    workflow.parent.mkdir(parents=True)
    workflow.write_bytes((ROOT / reader.publisher.WORKFLOW).read_bytes())
    for arguments in (
        ("init", "-q"),
        ("config", "user.name", "Historical reader fixture"),
        ("config", "user.email", "fixture@example.invalid"),
        ("config", "commit.gpgsign", "false"),
        ("add", "."),
        ("commit", "-qm", "fixture owned workflow objects"),
    ):
        subprocess.run(["git", *arguments], cwd=control, check=True, capture_output=True)
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=control, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=control, text=True
    ).strip()
    producer = reader.HistoricalProducer(
        revision, tree, reader.publisher.file_sha256(workflow), 42, 1, "fixture"
    )
    run = {
        "id": 42,
        "run_attempt": 1,
        "head_sha": revision,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": reader.publisher.WORKFLOW,
        "repository": {"full_name": reader.publisher.REPOSITORY},
        "head_repository": {"full_name": reader.publisher.REPOSITORY},
        "actor": {"login": "fixture"},
        "triggering_actor": {"login": "fixture"},
        "status": "completed",
        "conclusion": "success",
    }
    if fault == "active":
        run.update(status="in_progress", conclusion=None)
    elif fault == "failed":
        run["conclusion"] = "failure"
    elif fault == "actor":
        run["triggering_actor"]["login"] = "other"
    elif fault == "attempt":
        run["run_attempt"] = 2
    body = workflow.read_bytes() + (b"changed" if fault == "workflow_bytes" else b"")
    calls = []

    def native(endpoint):
        calls.append(endpoint)
        if "/contents/" in endpoint:
            return {
                "path": reader.publisher.WORKFLOW,
                "encoding": "base64",
                "size": len(body),
                "content": base64.b64encode(body).decode(),
            }
        if "/git/commits/" in endpoint:
            return {"sha": revision, "tree": {"sha": "0" * 40 if fault == "tree" else tree}}
        return copy.deepcopy(run)

    monkeypatch.setattr(reader.publisher, "api", native)
    for name in (
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_EVENT_NAME",
        "GITHUB_WORKFLOW_SHA",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_JOB",
    ):
        monkeypatch.delenv(name, raising=False)
    if fault:
        with pytest.raises(ValueError):
            producer.verify(control, revision)
    else:
        with reader.object_view(control, revision, tmp_path / "view") as view:
            producer.verify(view, revision)
        assert any("/attempts/1" in call for call in calls)
        assert any("/git/commits/" in call for call in calls)
    with pytest.raises(ValueError, match="protected native main context"):
        reader.publisher.control_context(control, revision)


def test_original_generic_reader_stays_exact_and_empty_registry_denies_v2():
    evidence = image._valid_evidence()
    report = validate_release(
        ROOT,
        image._policy(),
        evidence,
        now=image._NOW,
        expected_product_revision=evidence["product_revision"],
    )
    assert report["production_readiness"] == "ready"
    report = validate_release(
        ROOT,
        image._policy(),
        envelope(evidence),
        now=image._NOW,
        expected_product_revision=evidence["product_revision"],
    )
    assert report["production_readiness"] == "blocked"
    assert (
        "legacy fallback: single-publication fallback cannot qualify the complete "
        "Core/Gateway/Model stack" in report["blockers"]
    )
    unknown = {**evidence, "kind": "production_release_with_legacy_fallback/v99"}
    assert (
        validate_release(ROOT, image._policy(), unknown, now=image._NOW)["production_readiness"]
        == "blocked"
    )


def test_single_publication_envelope_cannot_claim_three_service_fallback(registration):
    repo, _row = registration
    with pytest.raises(ValueError, match="single-publication fallback"):
        admission.validate_legacy_fallback(
            repo,
            envelope(image._valid_evidence()),
            now=image._NOW,
            expected_product_revision="a" * 40,
        )


def test_real_final_production_entry_rejects_unregistered_v2_with_all_original_gates(tmp_path):
    """Current Root entry with same-source contracts and no verifier or policy mocks."""
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    with reader.object_view(ROOT, revision, tmp_path / "evidence") as repo:
        policy = image._policy()
        material_paths = {
            "saas/upstream-baseline.json",
            "saas/production/baseline.json",
            "saas/production/evidence-admission-keys.json",
            "saas/production/evidence-admission-policy.json",
            "saas/supply_chain/release-policy.json",
            policy["dockerfile"],
            *policy["reproducibility"]["dependency_locks"],
        }
        assert all(
            (repo / path).read_bytes() == (ROOT / path).read_bytes() for path in material_paths
        )
        evidence = image._valid_evidence()

        def bind(value):
            if isinstance(value, dict):
                return {key: bind(item) for key, item in value.items()}
            if isinstance(value, list):
                return [bind(item) for item in value]
            return revision if value == "a" * 40 else value

        evidence = bind(evidence)
        image._resign(evidence)
        generic = validate_release(
            repo, policy, evidence, now=image._NOW, expected_product_revision=revision
        )
        assert generic["status"] == "pass"
        assert generic["production_readiness"] == "ready"
        assert generic["violations"] == [] and generic["blockers"] == []
        wrapped = {
            "kind": admission.VARIANT,
            "product_revision": revision,
            "release_evidence": evidence,
            "legacy_fallback": {
                "stack_id": "fixture-stack",
                "publication_ids": {},
                "original_publication_ids": {},
                "full_stack_rollback": {},
            },
        }
        write(repo / "saas/acceptance/p0-production-image-evidence.json", wrapped)
        write(
            repo / "saas/supply_chain/legacy-production-stacks.json",
            {"schema_version": 1, "stacks": {}},
        )
        write(repo / admission.REGISTRY, {"schema_version": 1, "publications": {}})
        result = build_production_admission_bundle(
            repo, product_revision=revision, evidence_revision=revision, now=image._NOW
        )
        assert result["bundle"]["production_readiness"] == "blocked"
        assert result["bundle"]["release_decision"] == "NO-GO"
        assert "complete legacy stack is not registered" in json.dumps(result["readiness"])
        assert result["admission"]["metrics"]["required_kind_count"] == 8
        assert result["admission"]["metrics"]["ready_kind_count"] == 0
        assert result["readiness"]["metrics"]["aggregate_gate_count"] == 10
        assert result["readiness"]["metrics"]["derived_ready_gate_count"] == 0


def test_production_workflow_has_only_read_native_permissions_and_existing_protection():
    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-production-admission.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    job = workflow["jobs"]["production-admission"]
    assert job["environment"] == "production-evidence"
    assert set(job["permissions"].values()) == {"read"}
    assert {"actions", "checks", "statuses", "pull-requests", "packages", "attestations"} <= set(
        job["permissions"]
    )
    assert all(
        "@" not in step.get("uses", "") or len(step["uses"].split("@")[1]) == 40
        for step in job["steps"]
    )
