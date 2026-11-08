"""Recovered product, real producer and signer identities remain independently bound."""

import copy
import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from saas.scripts import accepted_m165_clean_context as clean
from saas.scripts import accepted_m165_promotion as promotion
from saas.scripts import accepted_oci_recovery as recovery
from saas.scripts.oci_promotion import MANIFEST_NAME, seal_candidate
from saas.scripts.resume_oci_promotion import (
    PREDICATE_TYPE,
    build_certificate_claims,
    verify_predicate,
)
from tests.saas.test_oci_promotion import EPOCH, REVISION, candidate, write_json

POLICY = "b" * 40
PRODUCER_RUN = 71
PRODUCER_CONTROLLER = "c" * 40
PRODUCER_BUILD_JOB = 82


@pytest.fixture(autouse=True)
def explicit_actual_producer(monkeypatch):
    monkeypatch.setenv("OMNIGENT_M165_PRODUCER_RUN", str(PRODUCER_RUN))


@pytest.mark.parametrize("value", [None, "", "0", "-1", "71/attempts/2", "71\n", "x" * 40])
def test_producer_input_must_be_a_real_positive_run_coordinate(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("OMNIGENT_M165_PRODUCER_RUN", raising=False)
    else:
        monkeypatch.setenv("OMNIGENT_M165_PRODUCER_RUN", value)
    with pytest.raises(ValueError, match="actual producer run"):
        promotion.producer_run_id()


@pytest.mark.parametrize(
    "fault", [None, "unrelated-controller", "changed-scanner", "changed-policy"]
)
def test_dynamic_producer_still_requires_exact_reviewed_execution_tree(monkeypatch, fault):
    monkeypatch.setattr(
        promotion.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1 if fault == "unrelated-controller" else 0
        ),
    )
    shared = "100644 blob " + "a" * 40 + "\tsaas/scripts/scan_oci_candidates.py\n"
    shared += "100644 blob " + "a" * 40 + "\t" + recovery.WORKFLOW + "\n"

    def tree(command, **_kwargs):
        result = shared
        if command[3] == POLICY:
            if fault == "changed-scanner":
                result = result.replace("a" * 40, "d" * 40)
            elif fault == "changed-policy":
                result += "100644 blob " + "d" * 40 + "\tsaas/supply_chain/runtime-policy.json\n"
            result += "100644 blob " + "e" * 40 + "\tsaas/scripts/accepted_m165_promotion.py\n"
        result += (
            "100644 blob "
            + ("f" * 40 if command[3] == POLICY else "a" * 40)
            + "\tsaas/scripts/resume_oci_promotion.py\n"
        )
        return result

    monkeypatch.setattr(promotion.subprocess, "check_output", tree)
    if fault:
        with pytest.raises(ValueError):
            promotion.verify_controller_sources(PRODUCER_CONTROLLER, POLICY)
    else:
        assert promotion.verify_controller_sources(PRODUCER_CONTROLLER, POLICY)[
            "protected_execution_tree_sha256"
        ]


def producer_records():
    run = {
        "id": PRODUCER_RUN,
        "head_sha": PRODUCER_CONTROLLER,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": recovery.WORKFLOW,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": promotion.REPOSITORY},
    }
    scan = {
        "id": 81,
        "run_id": PRODUCER_RUN,
        "run_attempt": 1,
        "name": "scan-and-admit-same-oci",
        "status": "completed",
        "conclusion": "success",
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-24.04"],
        "completed_at": datetime.now(UTC).isoformat(),
    }
    builder = {
        **scan,
        "id": PRODUCER_BUILD_JOB,
        "name": "build-accepted-product",
        "steps": [
            {"name": name, "conclusion": "success"}
            for name in (
                "Authenticate retained failed parent and prove current frozen source "
                "on both architectures",
                "Independently build only Server without cache for the clean retained first",
                "Confirm actual independent Server pair and unchanged historical Host pair",
                "Preserve actual OCI before any fresh vulnerability scan",
            )
        ],
    }
    return run, scan, builder


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "head_sha",
        "head_branch",
        "event",
        "path",
        "run_attempt",
        "status",
        "conclusion",
        "repository",
        "builder-failed",
        "scan-failed",
        "builder-id",
        "self-hosted",
    ],
)
def test_actual_native_build_scan_and_controller_are_required(fault):
    run, scan, builder = producer_records()
    if fault == "builder-failed":
        builder["conclusion"] = "failure"
    elif fault == "scan-failed":
        scan["conclusion"] = "skipped"
    elif fault == "builder-id":
        builder["id"] = 0
    elif fault == "self-hosted":
        builder["labels"] = ["self-hosted"]
    elif fault:
        run[fault] = {"full_name": "foreign/repo"} if fault == "repository" else "wrong"
    if fault:
        with pytest.raises(ValueError, match="actual recovered producer"):
            promotion.verify_producer(run, scan, builder)
    else:
        promotion.verify_producer(run, scan, builder)


@pytest.mark.parametrize(
    "fault",
    [
        None,
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
def test_signer_must_have_its_own_successful_main_ci(fault):
    path = promotion.CI_PATHS[0]
    run = {
        "id": 39,
        "head_sha": POLICY,
        "head_branch": "main",
        "event": "push",
        "path": path,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": promotion.REPOSITORY},
    }
    if fault:
        run[fault] = {"full_name": "foreign/repo"} if fault == "repository" else "wrong"
    if fault:
        with pytest.raises(ValueError, match="own Main CI"):
            promotion.verify_policy_ci(run, path, POLICY)
    else:
        promotion.verify_policy_ci(run, path, POLICY)


@pytest.fixture
def recovered(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    labels, now = candidate(source)
    monkeypatch.setattr(promotion, "expected_labels", lambda _repo, _revision: labels)
    monkeypatch.setattr(promotion, "PRODUCT", REVISION)
    monkeypatch.setattr(promotion, "EPOCH", EPOCH)
    monkeypatch.setattr(recovery, "PRODUCT", REVISION)
    monkeypatch.setattr(recovery, "EPOCH", EPOCH)
    original = tmp_path / "original.zip"
    with zipfile.ZipFile(original, "w") as bundle:
        bundle.write(source / "saas-image-candidate.json", "saas-image-candidate.json")
    monkeypatch.setattr(recovery, "REPORT_SIZE", original.stat().st_size)
    monkeypatch.setattr(recovery, "REPORT_SHA", hashlib.sha256(original.read_bytes()).hexdigest())
    historical = json.loads((source / "saas-image-candidate.json").read_text())
    first = {
        "kind": clean.KIND,
        "product_revision": REVISION,
        "product_tree": clean.TREE,
        "source_date_epoch": EPOCH,
        "parent_raw_checkpoint": clean.PARENT,
        "old_Server_byte_identity_claimed": False,
        "facts": {
            role: historical["images"][f"omnigent-saas-{role}"]["first"]
            for role in ("server", "host")
        },
        "source_proofs": {
            platform: {"tracked_inputs": 2064} for platform in ("linux/amd64", "linux/arm64")
        },
        "archive_sha256": {
            role: hashlib.sha256((source / f"{role}-1.tar").read_bytes()).hexdigest()
            for role in ("server", "host")
        },
    }
    write_json(source / "clean-context-first.json", first)
    historical["clean_context_reproducibility"] = {
        **{key: value for key, value in first.items() if key != "facts"},
        "first_proof_sha256": hashlib.sha256(
            (source / "clean-context-first.json").read_bytes()
        ).hexdigest(),
        "independent_Server_archive_sha256": first["archive_sha256"]["server"],
        "Host_rebuilt_in_this_confirmation": False,
    }
    write_json(source / "saas-image-candidate.json", historical)
    shutil.copyfile(original, source / "original-report.zip")
    manifest = seal_candidate(source, labels=labels, source_date_epoch=EPOCH, now=now)
    write_json(source / MANIFEST_NAME, manifest)
    monkeypatch.setattr(clean, "verify_first", lambda _root, _repo: copy.deepcopy(first))
    archives = {}
    for kind in ("report", "oci"):
        path = tmp_path / f"fixture-{kind}.zip"
        with zipfile.ZipFile(path, "w") as bundle:
            files = [
                source / MANIFEST_NAME,
                source / "saas-image-candidate.json",
                source / "clean-context-first.json",
                source / "original-report.zip",
                *sorted((source / "grype").glob("*.json")),
            ]
            if kind == "oci":
                files += [source / "server-1.tar", source / "host-1.tar"]
            for file in files:
                bundle.write(file, file.relative_to(source))
        archives[kind] = path
    metadata = []
    for identifier, kind, name in (
        (11, "raw", f"accepted-raw-{REVISION}-{PRODUCER_RUN}"),
        (12, "oci", f"saas-oci-promotion-{REVISION}"),
        (13, "report", f"accepted-same-oci-scan-{PRODUCER_RUN}"),
    ):
        archive = archives.get(kind, original)
        metadata.append(
            {
                "id": identifier,
                "name": name,
                "expired": False,
                "size_in_bytes": archive.stat().st_size,
                "digest": "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(),
                "workflow_run": {
                    "id": PRODUCER_RUN,
                    "head_sha": PRODUCER_CONTROLLER,
                },
            }
        )
    run, scan, builder = producer_records()
    scan["completed_at"] = datetime.now(UTC).isoformat()

    def api(endpoint):
        if "/workflows/" in endpoint:
            filename = endpoint.split("/workflows/")[1].split("/runs")[0]
            return {
                "workflow_runs": [
                    {
                        "id": 99,
                        "run_attempt": 1,
                        "head_sha": POLICY,
                        "head_branch": "main",
                        "event": "push",
                        "status": "completed",
                        "conclusion": "success",
                        "path": ".github/workflows/" + filename,
                        "repository": {"full_name": promotion.REPOSITORY},
                    }
                ]
            }
        if endpoint.endswith("/jobs?per_page=100"):
            return {"jobs": [scan, builder]}
        if endpoint.endswith("/artifacts?per_page=100"):
            return {"artifacts": metadata}
        if "/artifacts/" in endpoint:
            return next(row for row in metadata if row["id"] == int(endpoint.rsplit("/", 1)[1]))
        identifier = int(endpoint.rsplit("/", 1)[-1])
        if identifier in recovery.CI:
            return {
                "id": identifier,
                "head_sha": promotion.PRODUCT,
                "head_branch": "main",
                "event": "push",
                "path": recovery.CI[identifier],
                "run_attempt": 1,
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": promotion.REPOSITORY},
            }
        return run

    def download(identifier, destination, **kwargs):
        file = (
            original
            if identifier == recovery.REPORT_ID
            else archives["report" if identifier == 13 else "oci"]
        )
        shutil.copyfile(file, destination)

    monkeypatch.setattr(promotion, "api", api)
    monkeypatch.setattr(
        promotion,
        "verify_controller_sources",
        lambda _controller, _policy: {"protected_execution_tree_sha256": "d" * 64},
    )
    monkeypatch.setattr(promotion, "download_artifact_bytes", download)
    monkeypatch.setenv("OMNIGENT_M165_BINDING", str(tmp_path / "binding.json"))
    return {
        "root": tmp_path,
        "source": source,
        "metadata": metadata,
        "run": run,
        "scan": scan,
        "builder": builder,
    }


@pytest.mark.parametrize(
    "fault",
    [None, "expired", "name", "digest", "run", "head", "size-zero", "size-bool", "size-large"],
)
def test_artifact_coordinates_and_bounded_size_are_required(recovered, fault):
    row = copy.deepcopy(recovered["metadata"][1])
    name = row["name"]
    if fault in ("expired", "name", "digest"):
        row[fault] = True if fault == "expired" else "wrong"
    elif fault == "run":
        row["workflow_run"]["id"] += 1
    elif fault == "head":
        row["workflow_run"]["head_sha"] = POLICY
    elif fault:
        row["size_in_bytes"] = {"size-zero": 0, "size-bool": True, "size-large": 17 * 1024**3}[
            fault
        ]
    if fault:
        with pytest.raises(ValueError, match="artifact identity"):
            promotion.verify_artifact(row, name, 16 * 1024**3, controller=PRODUCER_CONTROLLER)
    else:
        promotion.verify_artifact(row, name, 16 * 1024**3, controller=PRODUCER_CONTROLLER)


def test_native_preflight_uses_actual_coordinates_then_rechecks_full_oci(recovered):
    root = recovered["root"]
    result = promotion.preflight(root / "report", POLICY)
    assert result["state"] == "NATIVE_PRODUCER_AUTHENTICATED_FULL_OCI_ADMISSION_PENDING"
    bound = promotion.binding()
    assert bound["oci_artifact_id"] == 12 and bound["artifacts"]["raw"]["id"] == 11
    assert bound["rebuilt"] is True and bound["signing_rebuilt_oci"] is False
    assert bound["production_authority"] is False
    promotion.download(root / "downloaded")
    assert (root / "downloaded/server-1.tar").is_file()
    assert bound["candidate_build_job_id"] == PRODUCER_BUILD_JOB
    assert bound["native_scan_job"]["id"] != bound["candidate_build_job_id"]


@pytest.mark.parametrize(
    "fault",
    [
        "parent",
        "old-Server-claim",
        "Host-rebuilt",
        "proof-hash",
        "source-architecture",
        "Server-second",
        "Host-history",
        "product",
    ],
)
def test_small_report_authentication_rejects_lineage_and_comparison_substitution(recovered, fault):
    root = recovered["source"]
    report = json.loads((root / "saas-image-candidate.json").read_text())
    proof = json.loads((root / "clean-context-first.json").read_text())
    if fault == "parent":
        proof["parent_raw_checkpoint"]["job_conclusion"] = "success"
    elif fault == "old-Server-claim":
        proof["old_Server_byte_identity_claimed"] = True
    elif fault == "source-architecture":
        proof["source_proofs"].pop("linux/arm64")
    elif fault == "product":
        proof["product_revision"] = POLICY
    elif fault == "Server-second":
        report["images"]["omnigent-saas-server"]["second"]["platforms"] = {}
    elif fault == "Host-history":
        report["images"]["omnigent-saas-host"]["history_created_by_equal"] = False
    write_json(root / "clean-context-first.json", proof)
    detail = report["clean_context_reproducibility"]
    report["clean_context_reproducibility"] = {
        **{key: value for key, value in proof.items() if key != "facts"},
        "first_proof_sha256": "0" * 64
        if fault == "proof-hash"
        else hashlib.sha256((root / "clean-context-first.json").read_bytes()).hexdigest(),
        "independent_Server_archive_sha256": detail["independent_Server_archive_sha256"],
        "Host_rebuilt_in_this_confirmation": fault == "Host-rebuilt",
    }
    write_json(root / "saas-image-candidate.json", report)
    with pytest.raises(ValueError, match="confirmation or historical Host"):
        promotion.report_binding(root, recovered["scan"]["completed_at"])


@pytest.mark.parametrize(
    "field",
    [
        "product_revision",
        "candidate_controller_revision",
        "candidate_run_id",
        "rebuilt",
        "production_authority",
    ],
)
def test_binding_cannot_replace_accepted_product_or_recovery_origin(recovered, field):
    promotion.preflight(recovered["root"] / "report", POLICY)
    path = promotion.binding_path()
    value = json.loads(path.read_text())
    value[field] = "wrong"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="binding differs"):
        promotion.binding()


def test_product_and_signer_are_distinct_in_image_and_new_wheel_predicates(recovered):
    promotion.preflight(recovered["root"] / "report", POLICY)
    image = promotion.predicate(POLICY, "91", "1")
    wheel = promotion.predicate(POLICY, "91", "1", wheel=True)
    params = image["buildDefinition"]["externalParameters"]
    assert params["product_source_revision"] == REVISION
    assert params["signing_policy_revision"] == POLICY
    assert params["original_candidate"]["candidate_controller_revision"] == PRODUCER_CONTROLLER
    assert (
        params["original_candidate"]["rebuilt"] is True
        and params["oci_rebuild_performed"] is False
    )
    assert wheel["buildDefinition"]["externalParameters"]["wheel_build_performed"] is True


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "certificate-product",
        "workflow",
        "run",
        "product",
        "recovery",
        "subject",
        "wheel-not-built",
    ],
)
def test_signed_wheel_requires_actual_controller_and_complete_product_materials(recovered, fault):
    promotion.preflight(recovered["root"] / "report", POLICY)
    expected = promotion.predicate(POLICY, "91", "1", wheel=True)
    claims = build_certificate_claims(promotion.REPOSITORY, POLICY, promotion.WORKFLOW, "91", "1")
    subject = "sha256:" + "c" * 64
    certificate = copy.deepcopy(claims)
    signed = copy.deepcopy(expected)
    actual_subject = subject
    if fault == "certificate-product":
        certificate["sourceRepositoryDigest"] = REVISION
    elif fault == "workflow":
        certificate["subjectAlternativeName"] = "foreign/workflow"
    elif fault == "run":
        certificate["runInvocationURI"] += "0"
    elif fault == "product":
        signed["buildDefinition"]["externalParameters"]["product_source_revision"] = POLICY
    elif fault == "recovery":
        signed["buildDefinition"]["externalParameters"]["original_candidate"][
            "candidate_controller_revision"
        ] = POLICY
    elif fault == "subject":
        actual_subject = "sha256:" + "d" * 64
    elif fault == "wheel-not-built":
        signed["buildDefinition"]["externalParameters"]["wheel_build_performed"] = False
    entries = [
        {
            "verificationResult": {
                "signature": {"certificate": certificate},
                "statement": {
                    "subject": [{"digest": {"sha256": actual_subject[7:]}}],
                    "predicateType": PREDICATE_TYPE,
                    "predicate": signed,
                },
            }
        }
    ]
    if fault:
        with pytest.raises(ValueError):
            verify_predicate(
                entries,
                subject=subject,
                predicate=expected,
                predicate_type=PREDICATE_TYPE,
                claims=claims,
            )
    else:
        verify_predicate(
            entries,
            subject=subject,
            predicate=expected,
            predicate_type=PREDICATE_TYPE,
            claims=claims,
        )


@pytest.mark.parametrize("fault", [None, "commit", "epoch", "version"])
def test_new_wheel_must_contain_exact_product_identity_and_target_version(tmp_path, fault):
    commit = POLICY if fault == "commit" else promotion.PRODUCT
    epoch = promotion.EPOCH + 1 if fault == "epoch" else promotion.EPOCH
    version = "0.18.0" if fault == "version" else "0.21.0.dev20261031"
    wheel = tmp_path / "product.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "omnigent/_build_info.py",
            f"COMMIT_SHA: str = {commit!r}\nBUILD_TIME_EPOCH: int = {epoch}\n",
        )
        archive.writestr(
            "omnigent.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: omnigent\nVersion: {version}\n",
        )
    if fault:
        with pytest.raises(ValueError):
            promotion.check_wheel(wheel)
    else:
        promotion.check_wheel(wheel)


def test_workflow_has_no_borrowed_wheel_or_future_static_artifact_coordinates():
    root = Path(__file__).resolve().parents[2]
    text = (root / promotion.WORKFLOW).read_text()
    value = yaml.load(text, Loader=yaml.BaseLoader)
    assert value["env"]["PRODUCT_REVISION"] == promotion.PRODUCT
    assert value["env"]["ORIGINAL_CANDIDATE_RUN_ID"] == "${{ inputs.candidate_run_id }}"
    assert value["env"]["OMNIGENT_M165_PRODUCER_RUN"] == "${{ inputs.candidate_run_id }}"
    assert value["on"]["workflow_dispatch"]["inputs"]["candidate_run_id"]["required"] == "true"
    assert '--argjson original_candidate_run_id "$ORIGINAL_CANDIDATE_RUN_ID"' in text
    assert "12344292161" not in text and "58194115" not in text and "7cea0940" not in text
    outputs = value["jobs"]["admit-original"]["outputs"]
    assert all("steps.accepted.outputs." in field for field in outputs.values())
    for name in ("admit-original", "publish-signed", "verify-published-source"):
        job = value["jobs"][name]
        assert job["permissions"]["actions"] == "read"
        assert any(
            step.get("uses") == "./saas/actions/runtime-evidence-context" for step in job["steps"]
        )
        assert any(
            "accepted_m165_promotion preflight" in step.get("run", "") for step in job["steps"]
        )
    publisher = value["jobs"]["publish-signed"]
    assert publisher["environment"] == "production-image"
    assert any(
        step.get("working-directory") == "wheel-product"
        and "uv build --wheel" in step.get("run", "")
        for step in publisher["steps"]
    )
    assert not any("build-push-action" in step.get("uses", "") for step in publisher["steps"])
    assert "wheel-provenance.json" in text and "independent-wheel-signatures.json" in text
    assert "rebuilt: true, signing_rebuilt_oci: false" in text


def test_signed_facts_shell_binds_actual_dynamic_producer_without_publishing(tmp_path):
    root = Path(__file__).resolve().parents[2]
    value = yaml.load((root / promotion.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    step = next(
        step
        for step in value["jobs"]["publish-signed"]["steps"]
        if step.get("name") == "Record signed candidate facts"
    )
    environment = {**os.environ, **dict.fromkeys(step["env"], "unit-test-only")}
    environment.update(
        PRODUCT_REVISION=promotion.PRODUCT,
        SIGNING_POLICY_REVISION=POLICY,
        GITHUB_RUN_ID="91",
        GITHUB_RUN_ATTEMPT="1",
        ORIGINAL_CANDIDATE_RUN_ID=str(PRODUCER_RUN),
        GITHUB_WORKFLOW_REF="unit-test-only-workflow",
        CANDIDATE_MANIFEST_SHA256="d" * 64,
        OMNIGENT_M165_BINDING=str(tmp_path / "binding.json"),
    )
    (tmp_path / "binding.json").write_text('{"unit_test_only":true}')
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    facts = json.loads((tmp_path / "artifacts/signed-release-candidate.json").read_text())
    assert facts["original_candidate_run_id"] == PRODUCER_RUN
    assert facts["signing_policy_revision"] == POLICY
    assert facts["promotion"]["signing_rebuilt_oci"] is False
