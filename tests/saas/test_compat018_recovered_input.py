"""Finite C2 origin contracts using synthetic bytes and native API fixtures only.

The nearby publisher's unchanged Core scenario covers the old default lifecycle;
these cases isolate the new fixed-product origin and native refusal boundaries.
No live API, dispatch, OCI build, credential, signing, or admission is performed.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import importlib.util
import inspect
import json
import shutil
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    qualified = "saas.scripts." + name
    path = ROOT / "saas/scripts" / (name + ".py")
    old = sys.modules.get(qualified)
    if old is not None and Path(old.__file__) == path:
        return old
    spec = importlib.util.spec_from_file_location(qualified, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified] = module
    spec.loader.exec_module(module)
    setattr(importlib.import_module("saas.scripts"), name, module)
    return module


recovery = load("compat018_oci_recovery")
load("compat018_clean_context")
m = load("compat018_recovered_input")
publisher = load("legacy_initial_publisher")
PROFILE = {
    "component": m.COMPONENT,
    "product_revision": recovery.PRODUCT,
    "product_tree": recovery.TREE,
    "source_date_epoch": recovery.EPOCH,
}


@pytest.mark.parametrize(
    "raw,sealed,component,expected",
    [
        ("", "", "Core", None),
        ("", "", m.COMPONENT, None),
        ("101", "", m.COMPONENT, (101, 101)),
        ("101", "202", m.COMPONENT, (101, 202)),
        ("", "202", m.COMPONENT, False),
        ("101", "202", "Core", False),
        ("0101", "", m.COMPONENT, False),
        ("1/2", "", m.COMPONENT, False),
        ("101", "-1", m.COMPONENT, False),
        (str(m.HISTORICAL["run_id"]), "", m.COMPONENT, False),
    ],
)
def test_only_two_finite_actual_dispatch_ids(raw, sealed, component, expected):
    profile = {**PROFILE, "component": component}
    env = {"COMPAT018_RAW_RUN_ID": raw, "COMPAT018_SEALED_RUN_ID": sealed}
    if expected is False:
        with pytest.raises(ValueError):
            m.dispatch_selection(profile, env)
    else:
        assert m.dispatch_selection(profile, env) == expected


@pytest.fixture
def native_origin(tmp_path, monkeypatch):
    """Two bounded native job/artifact fixtures; bytes are explicit tiny test inputs."""
    control = tmp_path / "control"
    for name in m.SOURCES:
        path = control / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    archive = tmp_path / "fixture.zip"
    bodies = dict.fromkeys(m.SEALED_FILES, b"unit-test-only\n")
    bodies["saas-image-candidate.json"] = json.dumps(
        {"clean_context_reproducibility": {"comparison_profile": "clean-C2-server"}}
    ).encode()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        for name, body in sorted(bodies.items()):
            bundle.writestr(name, body)
    native = {}
    endpoints = []
    prefix = f"repos/{recovery.REPOSITORY}/actions/"
    first_steps = [
        "Recover Server using its existing first-attempt build cache",
        "Recover Host using its existing first-attempt build cache",
        "Audit actual fixed C2 source, UI, and historical Host",
        "Independently build only C2 Server without cache",
        "Confirm exact C2 comparison profile",
        "Preserve actual OCI before any fresh vulnerability scan",
    ]
    scan_steps = [
        "Download and independently recheck the same real raw checkpoint",
        "Fresh scan and seal without rebuilding or relaxing any gate",
        "Retain actually admitted immutable OCI",
    ]
    for run_id, job_id, artifact_id, names, job_name in (
        (101, 301, 501, first_steps, "build-compat018-product"),
        (202, 302, 502, scan_steps, "scan-and-seal-same-oci"),
    ):
        revision = ("a" if run_id == 101 else "b") * 40
        run = {
            "id": run_id,
            "run_attempt": 1,
            "head_sha": revision,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": recovery.WORKFLOW,
            "repository": {"full_name": recovery.REPOSITORY},
            "status": "completed",
            "conclusion": "success",
            "actor": {"login": "fixture-actor"},
        }
        job = {
            "id": job_id,
            "run_id": run_id,
            "run_attempt": 1,
            "head_sha": revision,
            "name": job_name,
            "status": "completed",
            "conclusion": "success",
            "runner_group_name": "GitHub Actions",
            "labels": ["ubuntu-24.04"],
            "steps": [
                {
                    "name": name,
                    "number": i + 1,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": "2026-11-08T10:00:00Z",
                    "completed_at": "2026-11-08T10:00:02Z",
                }
                for i, name in enumerate(names)
            ],
        }
        metadata = {
            "id": artifact_id,
            "name": f"compat018-raw-{recovery.PRODUCT}-{run_id}"
            if run_id == 101
            else f"saas-oci-promotion-{recovery.PRODUCT}",
            "size_in_bytes": archive.stat().st_size,
            "digest": "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(),
            "expired": False,
            "workflow_run": {"id": run_id, "head_sha": revision},
            "created_at": "2026-11-08T10:00:01Z",
        }
        native[prefix + f"runs/{run_id}"] = run
        native[prefix + f"jobs/{job_id}"] = job
        native[prefix + f"artifacts/{artifact_id}"] = metadata
        native[prefix + f"runs/{run_id}/attempts/1/jobs?per_page=100"] = {
            "total_count": 1,
            "jobs": [job],
        }
        native[prefix + f"runs/{run_id}/artifacts?per_page=100"] = {
            "total_count": 1,
            "artifacts": [metadata],
        }
        tree_sha = ("c" if run_id == 101 else "d") * 40
        git_prefix = f"repos/{recovery.REPOSITORY}/git/"
        native[f"{git_prefix}commits/{revision}"] = {"sha": revision, "tree": {"sha": tree_sha}}
        entries = []
        for name in m.SOURCES:
            path = control / name
            body = path.read_bytes()
            entries.append(
                {
                    "path": name,
                    "type": "blob",
                    "mode": "100755" if path.stat().st_mode & 0o111 else "100644",
                    "size": len(body),
                    "sha": hashlib.sha1(
                        b"blob " + str(len(body)).encode() + b"\0" + body
                    ).hexdigest(),
                }
            )
        native[f"{git_prefix}trees/{tree_sha}?recursive=1"] = {
            "sha": tree_sha,
            "truncated": False,
            "tree": entries,
        }

    def api(endpoint):
        endpoints.append(endpoint)
        return copy.deepcopy(native[endpoint])

    downloaded = []

    def download(artifact_id, destination, *, expected_size, expected_sha256):
        downloaded.append(artifact_id)
        assert artifact_id == 502
        m.require(
            expected_size == archive.stat().st_size
            and expected_sha256 == hashlib.sha256(archive.read_bytes()).hexdigest(),
            "fixture download full bytes differ",
        )
        shutil.copyfile(archive, destination)

    monkeypatch.setattr(m, "api", api)
    monkeypatch.setattr(m, "download_artifact_bytes", download)
    return control, archive, native, endpoints, downloaded, prefix


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "run-failed",
        "branch",
        "attempt",
        "self-hosted",
        "missing-step",
        "step-order",
        "expired",
        "duplicate-name",
        "partial-listing",
        "source-bytes",
        "upload-time",
        "digest",
        "changed-after-download",
    ],
)
def test_native_origin_derives_unique_actual_coordinates_and_refuses_faults(
    native_origin, tmp_path, monkeypatch, fault
):
    control, _archive, data, _calls, downloaded, prefix = native_origin
    run = data[prefix + "runs/202"]
    job = data[prefix + "jobs/302"]
    meta = data[prefix + "artifacts/502"]
    if fault == "run-failed":
        run["conclusion"] = "failure"
    if fault == "branch":
        run["head_branch"] = "feature"
    if fault == "attempt":
        run["run_attempt"] = 2
    if fault == "self-hosted":
        job["labels"].append("self-hosted")
    if fault == "missing-step":
        job["steps"][1]["conclusion"] = "skipped"
    if fault == "step-order":
        job["steps"][0]["number"] = 99
    if fault == "expired":
        meta["expired"] = True
    if fault == "duplicate-name":
        listing = data[prefix + "runs/202/artifacts?per_page=100"]
        listing["artifacts"].append(copy.deepcopy(meta))
        listing["total_count"] = 2
    if fault == "partial-listing":
        data[prefix + "runs/202/artifacts?per_page=100"]["total_count"] = 101
    if fault == "source-bytes":
        (control / m.SOURCES[0]).write_bytes(b"different reviewed control")
    if fault == "upload-time":
        meta["created_at"] = "2026-11-08T10:00:10Z"
    if fault == "digest":
        meta["digest"] = "sha256:" + "0" * 64
    if fault == "changed-after-download":
        original = m.api
        count = 0

        def changed(endpoint):
            nonlocal count
            result = original(endpoint)
            if endpoint == prefix + "runs/101":
                count += 1
                if count > 2:
                    result["conclusion"] = "cancelled"
            return result

        monkeypatch.setattr(m, "api", changed)
    if fault:
        with pytest.raises(ValueError):
            m.collect(control, PROFILE, (101, 202), m.HISTORICAL, tmp_path / "download")
        return
    result = m.collect(control, PROFILE, (101, 202), m.HISTORICAL, tmp_path / "download")
    assert downloaded == [502] and result["run_id"] == 202 and result["job_id"] == 302
    assert result["producer"]["raw_checkpoint"]["artifact_id"] == 501
    assert result["seal_sha256"] == hashlib.sha256(b"unit-test-only\n").hexdigest()
    assert result["producer"]["comparison_profile"] == "clean-C2-server"
    assert result["controller_sources"]["raw"] == result["controller_sources"]["sealed"]
    assert result["kind"] != "legacy_pr_sealed_oci/v1"
    assert result["sealed_zip_full_CRC_verified"] is True


@pytest.mark.parametrize("extra", ["future.json", "../escape", "grype/extra.json"])
def test_exact_nine_plus_two_zip_refuses_additional_files(native_origin, extra):
    _, archive, *_ = native_origin
    with zipfile.ZipFile(archive, "a") as bundle:
        bundle.writestr(extra, b"no")
    with pytest.raises(ValueError):
        m.verify_sealed_zip(archive, archive.stat().st_size, crc=True)


def test_new_dispatch_values_do_not_change_original_profile_or_protected_execution():
    workflow = yaml.load((ROOT / publisher.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]["workflow_dispatch"]["inputs"]) == {
        "component",
        "compat018_raw_run_id",
        "compat018_sealed_run_id",
    }
    assert set(workflow["env"]) == {"COMPAT018_RAW_RUN_ID", "COMPAT018_SEALED_RUN_ID"}
    assert workflow["env"]["COMPAT018_RAW_RUN_ID"] == "${{ inputs.compat018_raw_run_id }}"
    assert workflow["env"]["COMPAT018_SEALED_RUN_ID"] == "${{ inputs.compat018_sealed_run_id }}"
    assert not (ROOT / "saas/supply_chain/compat018-recovered-oci-input.json").exists()


@pytest.fixture
def recovered_admission(native_origin, tmp_path):
    control, archive, *_ = native_origin
    origin = m.collect(control, PROFILE, (101, 202), m.HISTORICAL, tmp_path / "origin")
    context = {
        "control_revision": "c" * 40,
        "run_id": 303,
        "attempt": 1,
        "actor": "fixture-actor",
        "workflow_path": publisher.WORKFLOW,
        "workflow_sha256": "d" * 64,
    }
    source = {
        "kind": "legacy_source_qualification/v1",
        "status": "pass",
        "source_ci_pass": True,
        "technical_source_ci": "pass",
        "control_revision": context["control_revision"],
        **{k: PROFILE[k] for k in ("component", "product_revision", "product_tree")},
    }
    pg = {"native_PG_receipts_pass": True}
    admission = {
        "kind": m.VARIANT,
        "control": context,
        "profile": copy.deepcopy(PROFILE),
        "recovered_compat018_oci": origin,
        "historical_pr_oci_registration": copy.deepcopy(m.HISTORICAL),
        "historical_pr_transfer_profile": {
            "component": m.COMPONENT,
            "actor": "Dream1216",
            "base_ref": "codex/p18-a7-validation-base-20261102",
            "pull_number": 223,
            "workflow_sha256": "9a42ad4fff59764287f673a5798b742b7be63afd41c3edf53b97dff84aba3707",
        },
        "fresh_control_wheel": {
            **{k: context[k] for k in ("control_revision", "run_id", "attempt", "actor")},
            "job_id": 403,
            "artifact_id": 503,
            "zip_size": 100,
            "product_revision": recovery.PRODUCT,
            "product_tree": recovery.TREE,
            "zip_sha256": "e" * 64,
            "wheel_sha256": "f" * 64,
            "source_facts_sha256": "a" * 64,
        },
        "source_qualification": {"result": source, "sha256": publisher.digest(source)},
        "native_product_pg": {"result": pg, "sha256": publisher.digest(pg)},
        "rebuild_in_publisher": False,
    }
    return admission, archive


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "old-kind",
        "old-field",
        "foreign-product",
        "old-registration",
        "transfer",
        "actor",
        "raw-conflation",
        "sealed-conflation",
        "bad-wheel-hash",
        "source-false",
        "pg-false",
        "source-digest",
        "pg-digest",
        "stage-conflation",
    ],
)
def test_new_typed_origin_keeps_historical_registration_and_actual_producer_distinct(
    recovered_admission, fault
):
    admission, _ = recovered_admission
    if fault == "old-kind":
        admission["kind"] = publisher.VARIANT
    if fault == "old-field":
        admission["original_pr_oci"] = {}
    if fault == "foreign-product":
        admission["profile"]["product_revision"] = "0" * 40
    if fault == "old-registration":
        admission["historical_pr_oci_registration"]["run_id"] = 101
    if fault == "transfer":
        admission["historical_pr_transfer_profile"]["pull_number"] = 999
    if fault == "actor":
        admission["fresh_control_wheel"]["actor"] = "someone-else"
    if fault == "raw-conflation":
        admission["fresh_control_wheel"]["run_id"] = 101
        admission["control"]["run_id"] = 101
    if fault == "sealed-conflation":
        admission["fresh_control_wheel"]["artifact_id"] = 502
    if fault == "bad-wheel-hash":
        admission["fresh_control_wheel"]["wheel_sha256"] = "x" * 64
    if fault == "source-false":
        admission["source_qualification"]["result"]["source_ci_pass"] = False
    if fault == "pg-false":
        admission["native_product_pg"]["result"]["native_PG_receipts_pass"] = False
    if fault == "source-digest":
        admission["source_qualification"]["sha256"] = "0" * 64
    if fault == "pg-digest":
        admission["native_product_pg"]["sha256"] = "0" * 64
    coordinates = {}
    for index, role in enumerate(("preparation", "publication", "runtime")):
        coordinates[role + "_artifact"] = {
            "job_id": 410 + index,
            "artifact_id": 510 + index,
            "artifact_name": publisher.artifact_name(
                role, admission["profile"], admission["control"]
            ),
            "zip_size": 100,
            "zip_sha256": str(index + 1) * 64,
        }
    if fault == "stage-conflation":
        coordinates["runtime_artifact"]["artifact_id"] = 501
    publication = {"admission_sha256": publisher.digest(admission)}
    runtime = {
        "admission_sha256": publisher.digest(admission),
        "publication_sha256": publisher.digest(publication),
    }
    if fault:
        with pytest.raises(ValueError):
            publisher.typed_provenance(admission, publication, runtime, **coordinates)
        return
    statement = publisher.typed_provenance(admission, publication, runtime, **coordinates)
    parameters = statement["buildDefinition"]["externalParameters"]
    assert parameters["input_variant"] == m.VARIANT
    assert "original_pr_oci" not in parameters
    assert parameters["historical_pr_oci_registration"] == m.HISTORICAL
    assert parameters["recovered_compat018_oci"]["kind"] == m.ORIGIN
    deps = statement["buildDefinition"]["resolvedDependencies"]
    ids = {item["uri"].rsplit("/", 1)[-1] for item in deps if "/actions/artifacts/" in item["uri"]}
    assert ids == {"501", "502", "503", "510", "511", "512"}
    assert str(m.HISTORICAL["artifact_id"]) not in ids


def test_only_recovered_zip_accepts_exact_two_proofs_and_requires_product(
    recovered_admission, tmp_path, monkeypatch
):
    admission, archive = recovered_admission
    origin = admission["recovered_compat018_oci"]
    calls = []
    monkeypatch.setattr(
        m,
        "verify_payload",
        lambda root, descriptor, product: calls.append((root, descriptor, product)),
    )
    with pytest.raises(ValueError, match="actual frozen Git product"):
        publisher.unpack_original(archive, origin, tmp_path / "no-product")
    publisher.unpack_original(
        archive, origin, tmp_path / "new", product=tmp_path / "fixed-product"
    )
    assert (
        len(calls) == 1
        and {
            p.relative_to(tmp_path / "new").as_posix()
            for p in (tmp_path / "new").rglob("*")
            if p.is_file()
        }
        == m.SEALED_FILES
    )
    with pytest.raises(ValueError, match="exact sealed"):
        publisher.unpack_original(
            archive,
            {k: origin[k] for k in ("zip_size", "zip_sha256")},
            tmp_path / "old",
        )


def test_collect_original_branches_only_for_explicit_c2_ids(
    recovered_admission, tmp_path, monkeypatch
):
    from contextlib import nullcontext

    admission, _ = recovered_admission
    monkeypatch.setenv("COMPAT018_RAW_RUN_ID", "101")
    monkeypatch.setenv("COMPAT018_SEALED_RUN_ID", "202")
    monkeypatch.setattr(publisher, "preserve_native_evidence", lambda *_a, **_k: nullcontext())
    monkeypatch.setattr(publisher, "load_original_inputs", lambda *_a: copy.deepcopy(m.HISTORICAL))
    calls = []
    monkeypatch.setattr(
        m,
        "collect",
        lambda *args: (calls.append(args), admission["recovered_compat018_oci"])[1],
    )
    result = publisher.collect_original_input(tmp_path, PROFILE, tmp_path / "branch")
    assert result["kind"] == m.ORIGIN and calls[0][2] == (101, 202)
    monkeypatch.setattr(
        publisher,
        "download_original_oci",
        lambda *_a, **_k: pytest.fail("must refuse before legacy transfer"),
    )
    with pytest.raises(ValueError):
        publisher.collect_original_input(
            tmp_path, {**PROFILE, "component": "Core"}, tmp_path / "foreign"
        )


@pytest.mark.parametrize(
    "fault", [None, "raw-identity", "proof-hash", "host", "server", "old-claim", "seal"]
)
def test_sealed_proofs_bind_actual_raw_builder_host_server_and_seal(
    recovered_admission, tmp_path, monkeypatch, fault
):
    clean = importlib.import_module("saas.scripts.compat018_clean_context")
    admission, _ = recovered_admission
    descriptor = admission["recovered_compat018_oci"]
    root = tmp_path / "proofs"
    root.mkdir()
    server_facts = {
        "platforms": {"linux/amd64": {"manifest": "fixture"}},
        "attestations": {},
    }
    first = {
        "facts": {"server": server_facts},
        "historical_comparison": {"artifact_id": recovery.REPORT_ID},
        "historical_Server_facts_equal": False,
    }
    native = {
        "workflow_path": recovery.WORKFLOW,
        "controller_revision": "a" * 40,
        "run_id": 101,
        "attempt": 1,
        "job_name": "build-compat018-product",
        "actor": "fixture-actor",
    }
    stored = {**copy.deepcopy(first), "native_builder": copy.deepcopy(native)}
    if fault == "raw-identity":
        stored["native_builder"]["run_id"] = 999
    (root / "clean-context-first.json").write_text(json.dumps(stored))
    (root / "oci-promotion-manifest.json").write_bytes(b"fixture-seal")
    seal = recovery.sha256(root / "oci-promotion-manifest.json")
    descriptor["seal_sha256"] = descriptor["producer"]["sealed_oci"]["seal_sha256"] = seal
    host = {"fixture": "unchanged historical Host pair"}
    proof = {
        "kind": clean.KIND,
        "comparison_profile": "clean-C2-server",
        "native_builder": native,
        "product_revision": recovery.PRODUCT,
        "product_tree": recovery.TREE,
        "source_date_epoch": recovery.EPOCH,
        "historical_comparison": first["historical_comparison"],
        "first_proof_sha256": recovery.sha256(root / "clean-context-first.json"),
        "independent_Server_archive_sha256": "c" * 64,
        "old_Server_byte_identity_claimed": False,
        "new_Host_matches_historical_independent_pair": True,
    }
    server = {
        "first": server_facts,
        "second": copy.deepcopy(server_facts),
        "matching_platform_manifest_and_config": True,
        "history_created_by_equal": True,
    }
    candidate = {
        "clean_context_reproducibility": proof,
        "product_revision": recovery.PRODUCT,
        "source_date_epoch": recovery.EPOCH,
        "upstream_revision": recovery.UPSTREAM,
        "status": "pass",
        "violations": [],
        "images": {
            "omnigent-saas-host": copy.deepcopy(host),
            "omnigent-saas-server": server,
        },
    }
    if fault == "proof-hash":
        proof["first_proof_sha256"] = "0" * 64
    if fault == "host":
        candidate["images"]["omnigent-saas-host"] = {"fixture": "changed"}
    if fault == "server":
        server["second"]["platforms"] = {}
    if fault == "old-claim":
        proof["old_Server_byte_identity_claimed"] = True
    if fault == "seal":
        (root / "oci-promotion-manifest.json").write_bytes(b"tampered-seal")
    (root / "saas-image-candidate.json").write_text(json.dumps(candidate))
    monkeypatch.setattr(clean, "verify_first", lambda *_a: copy.deepcopy(first))
    monkeypatch.setattr(
        m.recovery,
        "original_evidence",
        lambda *_a: ({"images": {"omnigent-saas-host": host}}, None, None),
    )
    if fault:
        with pytest.raises(ValueError):
            m.verify_payload(root, descriptor, tmp_path)
    else:
        m.verify_payload(root, descriptor, tmp_path)


def test_sealed_run_defaults_to_actual_same_producer_without_conflating_artifacts(
    native_origin, tmp_path
):
    control, _archive, data, _calls, downloaded, prefix = native_origin
    job = data[prefix + "jobs/302"]
    job.update(run_id=101, head_sha="a" * 40)
    artifact = data[prefix + "artifacts/502"]
    artifact["workflow_run"] = {"id": 101, "head_sha": "a" * 40}
    data[prefix + "runs/101/attempts/1/jobs?per_page=100"] = {
        "total_count": 2,
        "jobs": [data[prefix + "jobs/301"], job],
    }
    data[prefix + "runs/101/artifacts?per_page=100"] = {
        "total_count": 2,
        "artifacts": [data[prefix + "artifacts/501"], artifact],
    }
    result = m.collect(control, PROFILE, (101, 101), m.HISTORICAL, tmp_path / "same-run")
    assert result["run_id"] == result["producer"]["raw_checkpoint"]["run_id"] == 101
    assert (
        result["artifact_id"] == 502 and result["producer"]["raw_checkpoint"]["artifact_id"] == 501
    )
    assert downloaded == [502]


@pytest.mark.parametrize("role", ["raw", "sealed"])
@pytest.mark.parametrize(
    "dependency",
    [
        "saas/scripts/compare_oci_rebuilds.py",
        "saas/scripts/scan_oci_candidates.py",
        "saas/scripts/oci_promotion.py",
        "saas/scripts/legacy_artifact_download.py",
        "saas/scripts/approved_disposition.py",
        "saas/scripts/sqlite_component_disposition.py",
        "saas/scripts/combined_runtime_disposition.py",
        "saas/scripts/legacy_native_evidence.py",
        "saas/actions/runtime-evidence-context/action.yml",
        "saas/supply_chain/release-policy.json",
    ],
)
def test_shared_execution_dependency_drift_rejected_with_identical_wrappers(
    native_origin, tmp_path, role, dependency
):
    control, _, data, _, downloaded, _ = native_origin
    wrappers = [
        recovery.WORKFLOW,
        "saas/scripts/compat018_oci_recovery.py",
        "saas/scripts/compat018_clean_context.py",
    ]
    before = {name: (control / name).read_bytes() for name in wrappers}
    tree_sha = ("c" if role == "raw" else "d") * 40
    tree = data[f"repos/{recovery.REPOSITORY}/git/trees/{tree_sha}?recursive=1"]
    next(row for row in tree["tree"] if row["path"] == dependency)["sha"] = "0" * 40
    with pytest.raises(ValueError, match="execution source differs"):
        m.collect(control, PROFILE, (101, 202), m.HISTORICAL, tmp_path / "refused")
    assert before == {name: (control / name).read_bytes() for name in wrappers}
    assert downloaded == []


@pytest.mark.parametrize("fault", ["truncated", "missing", "duplicate", "mode", "size"])
def test_incomplete_or_changed_git_execution_metadata_is_rejected(native_origin, fault):
    control, _, data, _, _, _ = native_origin
    tree = data[f"repos/{recovery.REPOSITORY}/git/trees/{'c' * 40}?recursive=1"]
    if fault == "truncated":
        tree["truncated"] = True
    elif fault == "missing":
        tree["tree"].pop()
    elif fault == "duplicate":
        tree["tree"].append(copy.deepcopy(tree["tree"][0]))
    elif fault == "mode":
        tree["tree"][0]["mode"] = "120000"
    else:
        tree["tree"][0]["size"] += 1
    with pytest.raises(ValueError):
        m._code(control, "a" * 40)


def test_finite_identity_inventory_covers_existing_static_import_dependencies():
    bound = set(m.SOURCES)
    for name in m.SOURCES:
        if not name.endswith(".py"):
            continue
        path = ROOT / name
        module = name[:-3].replace("/", ".")
        package = (
            module.removesuffix(".__init__")
            if path.name == "__init__.py"
            else module.rpartition(".")[0]
        )
        for node in ast.walk(ast.parse(path.read_text())):
            imports = []
            if isinstance(node, ast.Import):
                imports = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = (
                    importlib.util.resolve_name("." * node.level + (node.module or ""), package)
                    if node.level
                    else node.module
                )
                if base:
                    imports = [base, *[base + "." + alias.name for alias in node.names]]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                imports = [node.args[0].value]
            for imported in imports:
                if imported != "saas" and not imported.startswith("saas."):
                    continue
                parts = imported.split(".")
                for count in range(1, len(parts) + 1):
                    relative = "/".join(parts[:count])
                    for candidate in (relative + ".py", relative + "/__init__.py"):
                        if (ROOT / candidate).is_file():
                            assert candidate in bound, (name, candidate)


def test_publisher_component_equalities_match_the_canonical_security_contract():
    canonical = ast.parse((ROOT / "saas/scripts/check_image_supply_chain.py").read_text())
    fragments = [
        node.value
        for node in ast.walk(canonical)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith(("pyexpat.EXPAT_VERSION == ", "zlib.ZLIB_RUNTIME_VERSION == "))
    ]
    expected = {}
    for fragment in fragments:
        compare = ast.parse(fragment, mode="eval").body
        assert isinstance(compare, ast.Compare)
        expected[ast.unparse(compare.left)] = ast.literal_eval(compare.comparators[0])
    assert len(expected) == 2
    function = ast.parse(inspect.getsource(publisher.execute_runtime))
    script = next(
        node.value
        for node in ast.walk(function)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("import sys; from omnigent import _build_info;")
    )
    actual = {
        ast.unparse(node.left): ast.literal_eval(node.comparators[0])
        for node in ast.walk(ast.parse(script))
        if isinstance(node, ast.Compare) and ast.unparse(node.left) in expected
    }
    assert actual == expected


def test_finite_identity_inventory_covers_controller_owned_local_actions():
    for name in m.SOURCES:
        if not name.endswith((".yml", ".yaml")):
            continue
        value = yaml.load((ROOT / name).read_text(), Loader=yaml.BaseLoader)
        groups = list(value.get("jobs", {}).values())
        if "runs" in value:
            groups.append(value["runs"])
        for group in groups:
            fixed_product_checkout = False
            for step in group.get("steps", []):
                action = step.get("uses", "")
                options = step.get("with", {})
                if action.startswith("actions/checkout@") and not options.get("path"):
                    ref = options.get("ref")
                    fixed_product_checkout = not step.get("if") and (
                        ref == recovery.PRODUCT
                        or (
                            ref == "${{ env.PRODUCT_REVISION }}"
                            and value.get("env", {}).get("PRODUCT_REVISION") == recovery.PRODUCT
                        )
                    )
                if action.startswith("./saas/"):
                    if fixed_product_checkout:
                        # This action is covered by the pinned product tree.
                        assert action == "./saas/actions/build-oci-candidate"
                    else:
                        assert action[2:] + "/action.yml" in m.SOURCES, (name, action)
