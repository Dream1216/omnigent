"""Recovered product, real producer and signer identities remain independently bound."""

import ast
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
        "old-product",
        "old-scan",
        "old-builder",
        "missing-preflight",
        "missing-Host2",
        "foreign-job-head",
        "failed-scan",
        "attempt",
    ],
)
@pytest.mark.parametrize("clean_context", [False, True])
def test_current_M8c_uses_its_actual_complete_producer_and_preserved_first(
    monkeypatch, fault, clean_context
):
    monkeypatch.setattr(promotion, "PRODUCT", recovery.M8C_PRODUCT)
    monkeypatch.setattr(promotion, "EPOCH", recovery.M8C_EPOCH)
    run, scan, builder = producer_records()
    scan.update(name="scan-and-admit-m8c-same-oci", head_sha=PRODUCER_CONTROLLER)
    builder.update(
        name="complete-m8c-first-server",
        head_sha=PRODUCER_CONTROLLER,
        steps=[
            {"name": name, "conclusion": "success"}
            for name in (
                "Authenticate and retain exact original M8c first Server",
                "Complete original Server preflight before missing builds",
                "Independently build only missing M8c Server attempt 2",
                "Build only missing M8c Host attempt 1",
                "Independently build only missing M8c Host attempt 2",
                "Compare exact original M8c independent Server and Host pairs",
                "Retain complete original M8c four OCI raw checkpoint",
            )
        ],
    )
    if clean_context:
        monkeypatch.setattr(promotion, "PROFILE", "M8c-clean-context")
        builder["steps"] += [
            {"name": name, "conclusion": "success"}
            for name in (
                "Build new clean M8c Server attempt 1",
                "Verify new clean M8c Server SDK on both architectures",
                "Prove clean M8c source and preflight before independent builds",
                "Preserve cached original M8c Server as history only",
            )
        ]
    if fault == "old-product":
        run["head_sha"] = recovery.PRODUCT
        scan["head_sha"] = builder["head_sha"] = recovery.PRODUCT
        scan["name"] = "scan-and-admit-same-oci"
    elif fault == "old-scan":
        scan["name"] = "scan-and-admit-same-oci"
    elif fault == "old-builder":
        builder["name"] = "build-accepted-product"
    elif fault in {"missing-preflight", "missing-Host2"}:
        index = 1 if fault == "missing-preflight" else 4
        builder["steps"][index]["conclusion"] = "skipped"
    elif fault == "foreign-job-head":
        scan["head_sha"] = POLICY
    elif fault == "failed-scan":
        scan["conclusion"] = "failure"
    elif fault == "attempt":
        run["run_attempt"] = 2
    if fault is None:
        promotion.verify_producer(run, scan, builder)
    else:
        with pytest.raises(ValueError):
            promotion.verify_producer(run, scan, builder)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "tree",
        "parent",
        "first-bytes",
        "first-facts",
        "second-facts",
        "comparison",
        "report-bytes",
    ],
)
def test_M8c_report_preserves_original_first_and_all_actual_independent_facts(
    tmp_path, monkeypatch, fault
):
    labels, now = candidate(tmp_path)
    manifest = seal_candidate(tmp_path, labels=labels, source_date_epoch=EPOCH, now=now)
    write_json(tmp_path / MANIFEST_NAME, manifest)
    first_sha = manifest["images"]["server"]["archive_sha256"]
    monkeypatch.setattr(recovery, "M8C_PRODUCT", REVISION)
    monkeypatch.setattr(recovery, "M8C_EPOCH", EPOCH)
    monkeypatch.setattr(recovery, "M8C_FIRST_SHA256", first_sha)
    monkeypatch.setattr(recovery, "M8C_INDEX", manifest["images"]["server"]["index_digest"])
    monkeypatch.setattr(promotion, "PRODUCT", REVISION)
    monkeypatch.setattr(promotion, "EPOCH", EPOCH)
    monkeypatch.setattr(promotion, "expected_labels", lambda *_: labels)
    comparison = json.loads((tmp_path / "saas-image-candidate.json").read_text())
    proof = {
        "kind": "accepted_M8c_original_Server/v1",
        "product_revision": REVISION,
        "product_tree": recovery.M8C_TREE,
        "source_date_epoch": EPOCH,
        "original_run_id": recovery.M8C_RUN,
        "original_job_id": recovery.M8C_JOB,
        "first_archive_sha256": first_sha,
        "first_facts": manifest["images"]["server"]["facts"],
    }
    raw = {
        "kind": "accepted_M8c_complete_retained_first/v1",
        "original_first_archive_sha256": first_sha,
        "images": {
            f"{role}-{attempt}.tar": {"facts": comparison["images"][f"omnigent-saas-{role}"][name]}
            for role in ("server", "host")
            for attempt, name in ((1, "first"), (2, "second"))
        },
    }
    if fault == "tree":
        proof["product_tree"] = "f" * 40
    elif fault == "parent":
        proof["original_run_id"] += 1
    elif fault == "first-bytes":
        proof["first_archive_sha256"] = "f" * 64
    elif fault == "first-facts":
        proof["first_facts"] = {}
    elif fault == "second-facts":
        raw["images"]["host-2.tar"]["facts"] = {}
    elif fault == "comparison":
        comparison["status"] = "fail"
        write_json(tmp_path / "saas-image-candidate.json", comparison)
    elif fault == "report-bytes":
        path = tmp_path / "grype/server-amd64-grype.json"
        path.write_bytes(path.read_bytes() + b" ")
    write_json(tmp_path / "m8c-retained-origin.json", proof)
    write_json(tmp_path / "unadmitted-build.json", raw)
    if fault:
        with pytest.raises(ValueError):
            promotion.report_binding(tmp_path, datetime.now(UTC).isoformat())
    else:
        assert promotion.report_binding(tmp_path, datetime.now(UTC).isoformat()) == manifest


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
        "archives": archives,
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


@pytest.mark.parametrize("clean_context", [False, True])
def test_M8c_complete_preflight_and_download_need_only_its_original_proof(
    recovered, monkeypatch, clean_context
):
    source = recovered["source"]
    manifest = json.loads((source / MANIFEST_NAME).read_text())
    comparison = json.loads((source / "saas-image-candidate.json").read_text())
    comparison.pop("clean_context_reproducibility")
    write_json(source / "saas-image-candidate.json", comparison)
    manifest["comparison_sha256"] = hashlib.sha256(
        (source / "saas-image-candidate.json").read_bytes()
    ).hexdigest()
    write_json(source / MANIFEST_NAME, manifest)
    monkeypatch.setattr(recovery, "M8C_PRODUCT", REVISION)
    monkeypatch.setattr(recovery, "M8C_EPOCH", EPOCH)
    monkeypatch.setattr(recovery, "M8C_CI", recovery.CI)
    monkeypatch.setattr(
        recovery,
        "M8C_FIRST_SHA256",
        "f" * 64 if clean_context else manifest["images"]["server"]["archive_sha256"],
    )
    monkeypatch.setattr(recovery, "M8C_INDEX", manifest["images"]["server"]["index_digest"])
    proof = {
        "kind": "accepted_M8c_original_Server/v1",
        "controller_revision": PRODUCER_CONTROLLER,
        "product_revision": REVISION,
        "product_tree": recovery.M8C_TREE,
        "source_date_epoch": EPOCH,
        "original_run_id": recovery.M8C_RUN,
        "original_job_id": recovery.M8C_JOB,
        "first_archive_sha256": recovery.M8C_FIRST_SHA256,
        "first_facts": manifest["images"]["server"]["facts"],
    }
    write_json(source / "m8c-retained-origin.json", proof)
    write_json(
        source / "unadmitted-build.json",
        {
            "kind": "accepted_M8c_complete_retained_first/v1",
            "original_first_archive_sha256": recovery.M8C_FIRST_SHA256,
            "images": {
                f"{role}-{attempt}.tar": {
                    "facts": comparison["images"][f"omnigent-saas-{role}"][name]
                }
                for role in ("server", "host")
                for attempt, name in ((1, "first"), (2, "second"))
            },
        },
    )
    if clean_context:
        monkeypatch.setattr(promotion, "PROFILE", "M8c-clean-context")
        write_json(source / "server-candidate-runtime.json", {"own-new-executable-SDK": True})
        first = {
            "kind": "accepted_M8c_clean_context_first/v1",
            "product_revision": REVISION,
            "product_tree": recovery.M8C_TREE,
            "source_date_epoch": EPOCH,
            "host_bytecode_members": 0,
            "original_Server_promoted": False,
            "origin_sha256": hashlib.sha256(
                (source / "m8c-retained-origin.json").read_bytes()
            ).hexdigest(),
            "SDK_sha256": hashlib.sha256(
                (source / "server-candidate-runtime.json").read_bytes()
            ).hexdigest(),
            "archive_sha256": manifest["images"]["server"]["archive_sha256"],
            "facts": manifest["images"]["server"]["facts"],
            "source_proofs": {
                platform: {"tracked_inputs": 2064} for platform in ("linux/amd64", "linux/arm64")
            },
        }
        write_json(source / "clean-context-first.json", first)
        monkeypatch.setattr(clean, "verify_m8c_first", lambda _root, _repo: copy.deepcopy(first))
        raw = json.loads((source / "unadmitted-build.json").read_text())
        raw.update(
            kind="accepted_M8c_complete_clean_context/v1",
            clean_context_first_sha256=hashlib.sha256(
                (source / "clean-context-first.json").read_bytes()
            ).hexdigest(),
            original_Server_promoted=False,
            recovery_builds={"server": 2, "host": 2},
        )
        write_json(source / "unadmitted-build.json", raw)
    else:
        (source / "clean-context-first.json").unlink()
    workflow = yaml.safe_load(Path(recovery.WORKFLOW).read_text())
    recovered["scan"].update(name="scan-and-admit-m8c-same-oci", head_sha=PRODUCER_CONTROLLER)
    recovered["builder"].update(
        name="complete-m8c-first-server",
        head_sha=PRODUCER_CONTROLLER,
        steps=[
            {"name": step["name"], "conclusion": "success"}
            for step in workflow["jobs"]["complete-m8c-first-server"]["steps"]
            if "name" in step
        ],
    )
    for kind, archive in recovered["archives"].items():
        with zipfile.ZipFile(archive, "w") as bundle:
            for file in sorted(source.rglob("*")):
                if file.is_file() and (kind == "oci" or file.suffix != ".tar"):
                    bundle.write(file, file.relative_to(source))
        row = next(
            item
            for item in recovered["metadata"]
            if item["id"] == (13 if kind == "report" else 12)
        )
        row.update(
            size_in_bytes=archive.stat().st_size,
            digest="sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(),
        )
        if kind == "report":
            row["name"] = f"saas-image-candidate-{REVISION}"
    root = recovered["root"]
    promotion.preflight(root / "report", POLICY)
    bound = promotion.binding()
    assert (
        bound["retained_origin_sha256"]
        == hashlib.sha256((source / "m8c-retained-origin.json").read_bytes()).hexdigest()
    )
    if clean_context:
        assert bound["original_first_server"]["promoted"] is False
        assert "retained_first_server" not in bound
        assert bound["clean_context_first_sha256"] == raw["clean_context_first_sha256"]
        assert bound["comparison_profile"] == "clean-M8c-server-pair"
        assert bound["recovery"] == {
            "builds_performed": 4,
            "server": 2,
            "host": 2,
            "original_Server_reused": False,
        }
    else:
        assert "clean_context_first_sha256" not in bound
        assert bound["recovery"]["missing_builds_performed"] == 3
    assert bound["rebuilt"] is False
    promotion.download(root / "downloaded")
    assert (root / "downloaded/server-1.tar").read_bytes() == (
        source / "server-1.tar"
    ).read_bytes()
    assert (root / "downloaded/clean-context-first.json").exists() is clean_context


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
    assert '(.rebuilt | type) == "boolean"' in text
    assert '--argjson promotion_rebuilt "$promotion_rebuilt"' in text
    assert "rebuilt: $promotion_rebuilt, signing_rebuilt_oci: false" in text
    assert ".promotion.rebuilt == $binding[0].rebuilt" in text
    # The signer must use the same strict component versions as product admission.
    policy = ast.parse((root / "saas/scripts/check_image_supply_chain.py").read_text())
    runtime_guards = {
        node.value
        for node in ast.walk(policy)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith(("pyexpat.EXPAT_VERSION == ", "zlib.ZLIB_RUNTIME_VERSION == "))
    }
    assert len(runtime_guards) == 2
    assert all(guard in text for guard in runtime_guards)
    steps = publisher["steps"]
    scan = next(
        s
        for s in steps
        if s.get("name") == "Generate per-architecture SBOMs and check raw findings"
    )
    assert 'supply-chain-tools/syft" "registry:$image"' in scan["run"]
    assert 'supply-chain-tools/grype" "registry:$image"' in scan["run"]
    assert "|| grype_exit=$?" in scan["run"]
    retention = next(s for s in steps if s.get("name") == "Upload exact signed-image scan reports")
    assert retention["if"] == "always()"
    assert "artifacts/supply-chain/*.json" in retention["with"]["path"].splitlines()
    preflight = value["jobs"]["verify-resume-contract"]["steps"]
    assert any("OCI_PROMOTION_TEST_GRYPE=" in s.get("run", "") for s in preflight)
    reports = next(
        s
        for s in preflight
        if s.get("name") == "Preserve original native registry subject preflight reports"
    )
    assert reports["if"] == "always()"
    assert reports["with"]["path"] == "artifacts/registry-subject-preflight/"


@pytest.mark.parametrize("rebuilt", [True, False, None])
def test_signed_facts_shell_binds_actual_dynamic_producer_without_publishing(tmp_path, rebuilt):
    root = Path(__file__).resolve().parents[2]
    value = yaml.load((root / promotion.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    step = next(
        step
        for step in value["jobs"]["publish-signed"]["steps"]
        if step.get("name") == "Record signed candidate facts"
    )
    environment = {**os.environ, **dict.fromkeys(step["env"], "unit-test-only")}
    environment.update(
        OMNIGENT_ACCEPTED_PRODUCT_PROFILE="M165",
        PRODUCT_REVISION=promotion.PRODUCT,
        OMNIGENT_ACCEPTED_PRODUCT_PROFILE="M165",
        SIGNING_POLICY_REVISION=POLICY,
        GITHUB_RUN_ID="91",
        GITHUB_RUN_ATTEMPT="1",
        ORIGINAL_CANDIDATE_RUN_ID=str(PRODUCER_RUN),
        GITHUB_WORKFLOW_REF="unit-test-only-workflow",
        CANDIDATE_MANIFEST_SHA256="d" * 64,
        OMNIGENT_M165_BINDING=str(tmp_path / "binding.json"),
    )
    value = {"unit_test_only": True, **({"rebuilt": rebuilt} if rebuilt is not None else {})}
    (tmp_path / "binding.json").write_text(json.dumps(value))
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
    )
    if rebuilt is None:
        assert result.returncode != 0
        assert not (tmp_path / "artifacts/signed-release-candidate.json").exists()
        return
    assert result.returncode == 0, result.stderr
    facts = json.loads((tmp_path / "artifacts/signed-release-candidate.json").read_text())
    assert facts["original_candidate_run_id"] == PRODUCER_RUN
    assert facts["signing_policy_revision"] == POLICY
    assert facts["promotion"]["signing_rebuilt_oci"] is False
    assert facts["promotion"]["rebuilt"] is rebuilt


@pytest.mark.parametrize(
    "fault", [None, "parent", "tree", "data", "archive", "missing-builds", "promotion-rebuilt"]
)
def test_M8c_binding_and_predicate_keep_exact_original_materials(tmp_path, monkeypatch, fault):
    monkeypatch.setattr(promotion, "PRODUCT", recovery.M8C_PRODUCT)
    monkeypatch.setattr(promotion, "EPOCH", recovery.M8C_EPOCH)
    path = tmp_path / "binding.json"
    monkeypatch.setenv("OMNIGENT_M165_BINDING", str(path))
    value = {
        "schema_version": 1,
        "repository": promotion.REPOSITORY,
        "product_revision": recovery.M8C_PRODUCT,
        "source_date_epoch": recovery.M8C_EPOCH,
        "candidate_run_id": PRODUCER_RUN,
        "candidate_run_attempt": 1,
        "candidate_controller_revision": PRODUCER_CONTROLLER,
        "native_run": {"head_sha": PRODUCER_CONTROLLER},
        "native_builder_job": {"id": PRODUCER_BUILD_JOB},
        "candidate_build_job_id": PRODUCER_BUILD_JOB,
        "parent_raw_checkpoint": {
            "run_id": recovery.M8C_RUN,
            "attempt": 1,
            "job_id": recovery.M8C_JOB,
            "conclusion": "failure",
        },
        "comparison_profile": "retained-M8c-first-server",
        "rebuilt": False,
        "signing_rebuilt_oci": False,
        "production_authority": False,
        "product_tree": recovery.M8C_TREE,
        "runtime_evidence_revision": recovery.M8C_DATA,
        "retained_first_server": {
            "artifact": {
                "id": recovery.M8C_FIRST[0],
                "bytes": recovery.M8C_FIRST[1],
                "sha256": recovery.M8C_FIRST[2],
            },
            "archive_sha256": recovery.M8C_FIRST_SHA256,
            "index_digest": recovery.M8C_INDEX,
            "never_rebuilt": True,
        },
        "recovery": {"missing_builds_performed": 3, "first_Server_reused": True},
        "retained_origin_sha256": "d" * 64,
        "oci_artifact_id": 12,
        "oci_artifact_sha256": "e" * 64,
    }
    if fault == "parent":
        value["parent_raw_checkpoint"]["conclusion"] = "success"
    elif fault == "tree":
        value["product_tree"] = "f" * 40
    elif fault == "data":
        value["runtime_evidence_revision"] = "f" * 40
    elif fault == "archive":
        value["retained_first_server"]["archive_sha256"] = "f" * 64
    elif fault == "missing-builds":
        value["recovery"]["missing_builds_performed"] = 2
    elif fault == "promotion-rebuilt":
        value["rebuilt"] = True
    write_json(path, value)
    if fault:
        with pytest.raises(ValueError):
            promotion.binding()
    else:
        assert promotion.binding() == value
        for wheel in (False, True):
            params = promotion.predicate(POLICY, "91", "1", wheel=wheel)["buildDefinition"][
                "externalParameters"
            ]
            assert params["product_source_revision"] == recovery.M8C_PRODUCT
            assert (
                params["signing_policy_revision"] == POLICY
                and params["original_candidate"] == value
            )
            assert params["oci_rebuild_performed"] is False
            if wheel:
                assert params["wheel_build_performed"] is True


def test_M8c_workflows_only_complete_missing_builds_and_use_fixed_profile():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.load((root / recovery.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    builder = workflow["jobs"]["complete-m8c-first-server"]
    assert "inputs.phase == 'complete-m8c'" in builder["if"]
    assert "inputs.policy_revision == github.sha" in builder["if"]
    assert builder["timeout-minutes"] == "240"
    builds = [
        s["with"]
        for s in builder["steps"]
        if s.get("uses") == "./saas/actions/build-oci-candidate"
        and s.get("if") != "inputs.phase == 'build-clean-m8c'"
    ]
    assert builds == [
        {"artifact": "server", "target": "runtime", "attempt": "2"},
        {"artifact": "host", "target": "host", "attempt": "1"},
        {"artifact": "host", "target": "host", "attempt": "2"},
    ]
    names = [s.get("name") for s in builder["steps"]]
    assert names.index("Complete original Server preflight before missing builds") < names.index(
        "Independently build only missing M8c Server attempt 2"
    )
    scan = workflow["jobs"]["scan-and-admit-m8c-same-oci"]
    assert "complete-m8c-first-server" in scan["needs"]
    assert scan["env"]["PRODUCT_REVISION"] == recovery.M8C_PRODUCT
    assert not any(s.get("uses") == "./saas/actions/build-oci-candidate" for s in scan["steps"])
    assert any(
        s.get("with", {}).get("evidence-revision") == recovery.M8C_DATA for s in scan["steps"]
    )
    signer = yaml.load((root / promotion.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    profile = signer["on"]["workflow_dispatch"]["inputs"]["product_profile"]
    assert profile["default"] == "M165" and set(profile["options"]) == {
        "M165",
        "M8c-retained-first",
        "M8c-clean-context",
    }
    for job in signer["jobs"].values():
        selectors = [
            s
            for s in job["steps"]
            if s.get("name") == "Select only the exact retained M8c product profile"
        ]
        assert len(selectors) == 1 and selectors[0]["if"] == (
            "(inputs.product_profile == 'M8c-retained-first' "
            "|| inputs.product_profile == 'M8c-clean-context')"
        )
        assert (
            recovery.M8C_PRODUCT in selectors[0]["run"]
            and str(recovery.M8C_EPOCH) in selectors[0]["run"]
        )


def test_clean_M8c_workflow_preflights_exact_new_source_before_expensive_independent_builds():
    workflow = yaml.load(Path(recovery.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    builder = workflow["jobs"]["complete-m8c-first-server"]
    assert builder["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    steps = builder["steps"]
    new_first = next(s for s in steps if s.get("name") == "Build new clean M8c Server attempt 1")
    assert new_first["if"] == "inputs.phase == 'build-clean-m8c'"
    assert new_first["with"] == {"artifact": "server", "target": "runtime", "attempt": "1"}
    names = [s.get("name") for s in steps]
    assert names.index("Complete original Server preflight before missing builds") < names.index(
        new_first["name"]
    )
    assert names.index(new_first["name"]) < names.index(
        "Verify new clean M8c Server SDK on both architectures"
    )
    assert names.index(
        "Prove clean M8c source and preflight before independent builds"
    ) < names.index("Independently build only missing M8c Server attempt 2")
    verify = next(
        s
        for s in steps
        if s.get("name") == "Prove clean M8c source and preflight before independent builds"
    )
    assert verify["env"]["PYTHONPATH"] == "${{ runner.temp }}/accepted-m8c-control"
    assert "m8c-clean-first" in verify["run"] and "server-preflight" in verify["run"]
    scan = workflow["jobs"]["scan-and-admit-m8c-same-oci"]
    download = next(s for s in scan["steps"] if "m8c-download" in s.get("run", ""))
    assert "--clean-context" in download["env"]["CLEAN_CONTEXT"]
    for step in scan["steps"]:
        if "upload-artifact" in step.get("uses", ""):
            assert "clean-context-first.json" in step["with"]["path"]
            assert "server-candidate-runtime.json" in step["with"]["path"]
            assert "unadmitted-build.json" in step["with"]["path"]

    publisher = yaml.load(Path(promotion.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    publish_steps = publisher["jobs"]["publish-signed"]["steps"]
    upload = next(
        s for s in publish_steps if s.get("name") == "Upload signed release candidate facts"
    )
    for name in (
        "clean-context-first.json",
        "server-candidate-runtime.json",
        "m8c-retained-origin.json",
    ):
        assert "artifacts/" + name in upload["with"]["path"]
        assert any(
            '"$RUNNER_TEMP/admitted-oci/' + name + '"' in s.get("run", "") for s in publish_steps
        )


@pytest.mark.parametrize(
    "missing",
    [
        "Build new clean M8c Server attempt 1",
        "Verify new clean M8c Server SDK on both architectures",
        "Prove clean M8c source and preflight before independent builds",
        "Preserve cached original M8c Server as history only",
    ],
)
def test_clean_profile_cannot_borrow_a_retained_producer_with_missing_new_proof(
    monkeypatch, missing
):
    monkeypatch.setattr(promotion, "PRODUCT", recovery.M8C_PRODUCT)
    monkeypatch.setattr(promotion, "PROFILE", "M8c-clean-context")
    run, scan, builder = producer_records()
    scan.update(name="scan-and-admit-m8c-same-oci", head_sha=PRODUCER_CONTROLLER)
    workflow = yaml.safe_load(Path(recovery.WORKFLOW).read_text())
    builder.update(
        name="complete-m8c-first-server",
        head_sha=PRODUCER_CONTROLLER,
        steps=[
            {
                "name": step["name"],
                "conclusion": "skipped" if step["name"] == missing else "success",
            }
            for step in workflow["jobs"]["complete-m8c-first-server"]["steps"]
            if "name" in step
        ],
    )
    with pytest.raises(ValueError):
        promotion.verify_producer(run, scan, builder)


def test_clean_SDK_step_prepares_report_destination_in_empty_runner_workspace(tmp_path):
    workflow = yaml.load(Path(recovery.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["complete-m8c-first-server"]["steps"]
    sdk = next(
        step
        for step in steps
        if step.get("name") == "Verify new clean M8c Server SDK on both architectures"
    )
    # Substitute only the expensive probe process; execute the real shell setup and heredoc.
    shell = "python() { test -d artifacts; };\n" + sdk["run"]
    result = subprocess.run(["bash", "-c", shell], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "artifacts").is_dir()


def test_post_checkout_launcher_uses_reviewed_controller_instead_of_frozen_product(tmp_path):
    import sys

    repo = Path(__file__).resolve().parents[2]
    product = tmp_path / "frozen-product"
    selected = [
        "saas/__init__.py",
        "saas/scripts/__init__.py",
        "saas/scripts/accepted_oci_recovery.py",
        "saas/scripts/scan_oci_candidates.py",
        "saas/scripts/compare_oci_rebuilds.py",
    ]
    for name in selected:
        destination = product / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        # This directory models the product's regular package boundary. Keep the
        # CI regression self-contained: shallow checkouts do not carry old Git
        # blobs. The exact frozen-8c proof is preserved separately by Source.
        destination.write_text("" if name.endswith("__init__.py") else "PROFILE = 'product'\n")
    environment = {**os.environ, "PYTHONPATH": str(repo), "PYTHONDONTWRITEBYTECODE": "1"}
    environment.pop("PYTHONSAFEPATH", None)
    probe = """
import ast,importlib.util,json
result={}
for name in ('accepted_oci_recovery','scan_oci_candidates','compare_oci_rebuilds'):
    path=importlib.util.find_spec('saas.scripts.'+name).origin
    source=ast.parse(open(path).read())
    commands=[n.value for n in ast.walk(source) if isinstance(n,ast.Constant)]
    result[name]={'path':path,'new_command':'m8c-clean-first' in commands}
print(json.dumps(result))
"""
    for safe in (False, True):
        command = [sys.executable, *(["-P"] if safe else []), "-c", probe]
        result = subprocess.run(
            command, cwd=product, env=environment, text=True, capture_output=True, timeout=30
        )
        assert result.returncode == 0, result.stderr
        facts = json.loads(result.stdout)
        for name, fact in facts.items():
            assert Path(fact["path"]) == (repo if safe else product) / "saas/scripts" / (
                name + ".py"
            )
        assert facts["accepted_oci_recovery"]["new_command"] is safe
    workflow = yaml.load((repo / recovery.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["complete-m8c-first-server"]["steps"]
    control_steps = [s for s in steps if "PYTHONPATH" in s.get("env", {})]
    assert len(control_steps) == 3
    for step in control_steps:
        assert step["env"]["PYTHONPATH"] == "${{ runner.temp }}/accepted-m8c-control"
        commands = [
            line.strip()
            for line in step["run"].splitlines()
            if line.strip().startswith(".venv/bin/python")
        ]
        assert commands and all(line.startswith(".venv/bin/python -P ") for line in commands)
    result = subprocess.run(
        [sys.executable, "-P", "-m", "saas.scripts.accepted_oci_recovery", "--help"],
        cwd=product,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0 and "m8c-clean-first" in result.stdout, result.stderr
