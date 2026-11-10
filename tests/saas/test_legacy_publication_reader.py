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
from saas.scripts import legacy_publication_renewal as renewal
from saas.scripts.check_image_supply_chain import validate_release
from saas.scripts.run_production_admission import build_production_admission_bundle
from tests.saas import test_image_supply_chain as image
from tests.saas._legacy_frozen_compatibility import frozen_entries
from tests.saas.test_compat018_recovered_input import native_origin as native_origin
from tests.saas.test_compat018_recovered_input import recovered_admission as recovered_admission
from tests.saas.test_legacy_build_controller import product as product
from tests.saas.test_legacy_initial_publisher import publication_data as publication_data

ROOT = Path(__file__).resolve().parents[2]
MAIN = "2c5a9a45f1a576439fc9c5aa0a91022d461389ab"


@pytest.mark.parametrize("fault", [None, "variant", "historical", "tree", "raw", "sealed"])
def test_recovered_reader_selection_comes_from_exact_admission_not_ambient_env(
    recovered_admission, monkeypatch, fault
):
    body, _ = recovered_admission
    body = copy.deepcopy(body)
    selected = body["recovered_compat018_oci"]
    if fault == "variant":
        body["kind"] = reader.publisher.VARIANT
    elif fault == "historical":
        body["historical_pr_oci_registration"]["run_id"] += 1
    elif fault == "tree":
        body["profile"]["product_tree"] = "0" * 40
    elif fault in {"raw", "sealed"}:
        selected["producer"]["raw_checkpoint" if fault == "raw" else "sealed_oci"]["run_id"] = 0
    monkeypatch.setenv("COMPAT018_RAW_RUN_ID", "999")
    monkeypatch.setenv("COMPAT018_SEALED_RUN_ID", "888")
    row = {"profile": body["profile"], "admission": body}
    if fault:
        with pytest.raises(ValueError):
            reader.recovered_publication_selection(row)
    else:
        assert reader.recovered_publication_selection(row) == (101, 202)
        assert __import__("os").environ["COMPAT018_RAW_RUN_ID"] == "999"


@pytest.mark.parametrize(
    "fault", [None, "variant", "nonstring-variant", "mixed-input", "same-raw-artifact"]
)
def test_registry_accepts_typed_recovered_C2_and_keeps_distinct_native_roles(
    recovered_admission, tmp_path, monkeypatch, fault
):
    """Registry shape only; profile/source positives are explicit fixture seams."""
    body, _ = recovered_admission
    body = copy.deepcopy(body)
    row = {
        "input_variant": reader.publisher.c2_recovered.VARIANT,
        "profile": body["profile"],
        "producer": {
            **{k: body["control"][k] for k in ("control_revision", "run_id", "attempt", "actor")},
            "control_tree": "b" * 40,
            "workflow_sha256": body["control"]["workflow_sha256"],
        },
        "admission": body,
        "predicate_sha256": "a" * 64,
        "stage_artifacts": {
            role: {
                "job_id": 600 + index,
                "artifact_id": 700 + index,
                "zip_size": 100,
                "zip_sha256": str(index) * 64,
                "artifact_name": reader.publisher.artifact_name(
                    role, body["profile"], body["control"]
                ),
            }
            for index, role in enumerate(
                ("preparation", "publication", "runtime", "signatures"), 1
            )
        },
        "deployment_roles": {"compat-server": "server", "compat-host": "host"},
    }
    monkeypatch.setattr(admission, "validate_profile", lambda *_: None)
    monkeypatch.setattr(
        admission,
        "trusted_entries",
        lambda *_: {
            "legacy-security-build-profiles.json": body["profile"],
        },
    )
    monkeypatch.setattr(admission, "require_publication_source_origin", lambda *_a, **_k: None)
    if fault == "variant":
        row["input_variant"] = reader.publisher.VARIANT
    elif fault == "nonstring-variant":
        row["input_variant"] = []
    elif fault == "mixed-input":
        body["original_pr_oci"] = body["recovered_compat018_oci"]
    elif fault == "same-raw-artifact":
        row["stage_artifacts"]["runtime"]["artifact_id"] = body["recovered_compat018_oci"][
            "producer"
        ]["raw_checkpoint"]["artifact_id"]
    write(tmp_path / admission.REGISTRY, {"schema_version": 1, "publications": {"current": row}})
    if fault:
        with pytest.raises(ValueError):
            admission.registered_publication(tmp_path, "current")
    else:
        assert admission.registered_publication(tmp_path, "current") == row


@pytest.mark.parametrize("source_reuse", [False, True])
@pytest.mark.parametrize("fault", [None, "context", "changed-source"])
def test_historical_recovered_reader_rejoins_actual_native_inputs(
    recovered_admission, native_origin, tmp_path, monkeypatch, source_reuse, fault
):
    """Mock source/PG/wheel I/O; recovered OCI uses the original native fixture collector."""
    body, _ = recovered_admission
    body = copy.deepcopy(body)
    control, _, _, _, downloads, _ = native_origin
    source = body["source_qualification"]["result"]
    if source_reuse:
        body["source_qualification"]["native_producer"] = {"artifact_id": 504}
    row = {"profile": body["profile"], "admission": body}
    producer = reader.HistoricalProducer(
        **{
            key: body["control"][key] for key in ("control_revision", "run_id", "attempt", "actor")
        },
        control_tree="b" * 40,
        workflow_sha256=body["control"]["workflow_sha256"],
    )
    verified, qualifications = [], []
    monkeypatch.setattr(
        reader.HistoricalProducer, "verify", lambda self, *args: verified.append(args)
    )
    monkeypatch.setattr(reader.publisher, "load_profile", lambda *_: row["profile"])
    monkeypatch.setattr(reader.publisher, "verify_source_delta", lambda *_: None)
    monkeypatch.setattr(reader, "require_publication_source_origin", lambda *_: None)

    def qualify(root, product, component, historical, destination, *, recovered_selection):
        assert root == control and historical is producer
        assert recovered_selection == (101, 202)
        qualifications.append(destination)
        return {**source, **({"changed": True} if fault == "changed-source" else {})}

    monkeypatch.setattr(reader, "qualify_historical_source", qualify)

    def qualified(root, product, profile, context, destination, *, source_qualifier):
        assert context == producer.context
        result = source_qualifier(
            root,
            product,
            profile["component"],
            "0" * 40 if fault == "context" else producer.control_revision,
            destination,
        )
        return result, body["source_qualification"]["native_producer"]

    monkeypatch.setattr(reader.publisher, "collect_qualified_source", qualified)
    monkeypatch.setattr(
        reader, "_collect_pg_receipts", lambda *_a, **_k: body["native_product_pg"]["result"]
    )
    monkeypatch.setattr(
        reader.publisher,
        "load_original_inputs",
        lambda *_: body["historical_pr_oci_registration"],
    )
    monkeypatch.setattr(
        reader.publisher,
        "load_transfer_profile",
        lambda *_: body["historical_pr_transfer_profile"],
    )
    wheel = tmp_path / "fresh.whl"
    wheel.write_bytes(b"explicit mocked wheel input")
    monkeypatch.setattr(
        reader.publisher,
        "collect_fresh_wheel",
        lambda *_: (body["fresh_control_wheel"], wheel),
    )
    monkeypatch.setattr(
        reader.publisher,
        "collect_original_input",
        lambda *_: pytest.fail("typed recovered input must not use historical PR OCI collection"),
    )
    destination = tmp_path / "historical-read"
    if fault == "changed-source" or (fault == "context" and source_reuse):
        with pytest.raises(ValueError):
            reader.collect_historical_inputs(control, control, row, producer, destination)
    else:
        actual, archive, actual_wheel = reader.collect_historical_inputs(
            control, control, row, producer, destination
        )
        assert actual == body and actual_wheel == wheel and archive.is_file()
        assert archive == destination / "original/download/original-oci.zip"
        assert len(qualifications) == 1 and verified
        assert downloads[-1] == 502


@pytest.mark.parametrize("selection", [None, (101, 202)])
def test_historical_qualification_preserves_producer_context_and_exact_selection(
    tmp_path, monkeypatch, selection
):
    producer = reader.HistoricalProducer("c" * 40, "b" * 40, "d" * 64, 303, 1, "fixture")
    verified = []
    monkeypatch.setattr(
        reader.HistoricalProducer, "verify", lambda self, *args: verified.append(args)
    )

    def qualify(control, product, component, revision, destination, evidence, **kwargs):
        assert revision == producer.control_revision
        assert kwargs.get("recovered_selection") == selection
        kwargs["context_verifier"](control, revision)
        with pytest.raises(ValueError, match="historical source context differs"):
            kwargs["context_verifier"](control, "0" * 40)
        return {"explicit_fixture": True}

    monkeypatch.setattr(reader, "_qualify_source_ci", qualify)
    assert reader.qualify_historical_source(
        tmp_path,
        tmp_path,
        "Compatibility018",
        producer,
        tmp_path / "historical-source",
        recovered_selection=selection,
    ) == {"explicit_fixture": True}
    assert verified == [(tmp_path, producer.control_revision)] * 2


@pytest.mark.parametrize("fault", [None, "OCI", "wheel"])
def test_recovered_publication_renewal_keeps_actual_OCI_and_wheel_identity(
    recovered_admission, fault
):
    body, _ = recovered_admission
    original = {
        "profile": body["profile"],
        "admission": copy.deepcopy(body),
        "producer": {"run_id": 303},
        "predicate_sha256": "a" * 64,
        "stage_artifacts": {"runtime": {"artifact_id": 700}},
    }
    current = copy.deepcopy(original)
    current["producer"]["run_id"] = 404
    current["predicate_sha256"] = "b" * 64
    current["stage_artifacts"]["runtime"]["artifact_id"] = 800
    current["admission"]["fresh_control_wheel"]["artifact_id"] += 1
    if fault == "OCI":
        current["admission"]["recovered_compat018_oci"]["zip_sha256"] = "0" * 64
    elif fault == "wheel":
        current["admission"]["fresh_control_wheel"]["wheel_sha256"] = "0" * 64
    if fault:
        with pytest.raises(ValueError):
            renewal.verify_renewal_identity(original, current)
    else:
        renewal.verify_renewal_identity(original, current)


@pytest.mark.parametrize("fault", [None, *reader.TRUSTED_STORES])
def test_frozen_c2_data_registration_requires_all_six_exact_original_rows(tmp_path, fault):
    before = {}
    frozen = frozen_entries()
    for name in reader.TRUSTED_STORES:
        key = "inputs" if name == "legacy-security-original-inputs.json" else "profiles"
        row = copy.deepcopy(frozen[name])
        row.pop("bootstrap_positive_origin", None)
        if name == fault:
            row["unreviewed_change"] = True
        path = tmp_path / "saas/supply_chain" / name
        write(path, {"schema_version": 1, key: {"Compatibility018": row}})
        before[path] = path.read_bytes()
    if fault:
        entries = reader.trusted_entries(tmp_path, "Compatibility018")
        assert (
            "bootstrap_positive_origin" not in entries["legacy-source-qualification-profiles.json"]
        )
        with pytest.raises(ValueError, match="bootstrap origin registration fields differ"):
            reader.require_publication_source_origin(
                tmp_path,
                entries["legacy-security-build-profiles.json"],
                {
                    "domain_qualification_kind": reader.BOOTSTRAP_KIND,
                    "complete_domain_discovery": False,
                },
                entries=entries,
            )
    else:
        assert reader.trusted_entries(tmp_path, "Compatibility018") == frozen
    assert all(path.read_bytes() == raw for path, raw in before.items())


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
