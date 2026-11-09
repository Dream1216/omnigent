"""Local contracts only: native APIs, signing and registry processes are mocked."""

from __future__ import annotations

import base64
import copy
import json
import re
import shutil
import stat
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from saas.scripts import legacy_initial_publisher as publisher
from saas.scripts import protected_legacy_initial_build as core
from saas.scripts.oci_promotion import file_sha256
from tests.saas import test_oci_promotion as oci
from tests.saas.test_legacy_build_controller import CONTROL, controller, make_wheel
from tests.saas.test_legacy_build_controller import product as product

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def publication_data(product, tmp_path, monkeypatch):
    source, profile = product
    # The reused OUT test loaders retain several verifier module instances.
    # Give each actual verifier this fixture's owned immutable baseline.
    verifiers = (
        publisher.verify_source_delta,
        controller.verify_source_delta,
        publisher.transfer_provenance.__globals__["provenance"],
        publisher.verify_wheel_bundle.__globals__["wheel_source_facts"].__globals__[
            "verify_source_delta"
        ],
    )
    for verifier in verifiers:
        monkeypatch.setitem(
            verifier.__globals__["BASELINES"], "Core", profile["baseline_revision"]
        )
    monkeypatch.setattr(oci, "REVISION", profile["product_revision"])
    monkeypatch.setattr(oci, "EPOCH", profile["source_date_epoch"])
    candidate = tmp_path / "candidate"
    labels, now = oci.candidate(candidate)
    manifest = oci.seal(candidate, labels, now)
    publisher.write_json(candidate / "oci-promotion-manifest.json", manifest)
    archive = tmp_path / "original.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        for item in sorted(candidate.rglob("*")):
            if item.is_file() and "-layout" not in str(item.relative_to(candidate)):
                bundle.write(item, str(item.relative_to(candidate)))
    wheel = make_wheel(tmp_path / "dist", profile)
    facts = controller.wheel_source_facts(source, wheel, profile, CONTROL)
    context = {"control_revision": CONTROL, "run_id": 42, "attempt": 1, "actor": "Dream1216"}
    transfer = {
        "component": "Core",
        "pull_number": 9001,
        "base_ref": "codex/legacy-validation-core-dc1e9a97",
        "workflow_sha256": "f" * 64,
        "actor": "Dream1216",
    }
    original = {
        "kind": "legacy_pr_sealed_oci/v1",
        "component": "Core",
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "baseline_revision": profile["baseline_revision"],
        **transfer,
        "merge_revision": "d" * 40,
        "workflow_path": ".github/workflows/saas-image-candidate.yml",
        "run_id": 41,
        "attempt": 2,
        "job_id": 81,
        "artifact_id": 121,
        "zip_size": archive.stat().st_size,
        "zip_sha256": file_sha256(archive),
        "seal_sha256": file_sha256(candidate / "oci-promotion-manifest.json"),
    }
    fresh = {
        **context,
        "job_id": 82,
        "artifact_id": 122,
        "artifact_name": f"legacy-initial-Core-{profile['product_revision']}-{CONTROL}-42-1",
        "zip_size": 500,
        "zip_sha256": "a" * 64,
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "wheel_filename": wheel.name,
        "wheel_sha256": file_sha256(wheel),
        "source_facts_sha256": publisher.digest(facts),
    }
    source_result = {
        "kind": "legacy_source_qualification/v1",
        "component": "Core",
        "control_revision": CONTROL,
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "technical_source_ci": "pass",
        "status": "pass",
        "source_ci_pass": True,
    }
    pg_result = {
        "kind": "legacy_native_exact_product_PG_receipts/v1",
        "native_PG_receipts_pass": True,
    }
    admission = {
        "kind": publisher.VARIANT,
        "profile": profile,
        "transfer_profile": transfer,
        "control": {**context, "workflow_path": publisher.WORKFLOW, "workflow_sha256": "e" * 64},
        "original_pr_oci": original,
        "fresh_control_wheel": fresh,
        "source_qualification": {
            "sha256": publisher.digest(source_result),
            "result": source_result,
        },
        "native_product_pg": {"sha256": publisher.digest(pg_result), "result": pg_result},
        "rebuild_in_publisher": False,
    }
    monkeypatch.setattr(publisher, "expected_labels", lambda _product, _revision: labels)
    return {
        "source": source,
        "profile": profile,
        "candidate": candidate,
        "manifest": manifest,
        "archive": archive,
        "wheel": wheel,
        "context": context,
        "admission": admission,
    }


@pytest.mark.parametrize(
    "fault", [None, "blocked", "false", "truthy", "product", "control", "tree", "technical"]
)
def test_source_interface_requires_strict_exact_qualification(publication_data, fault):
    data = publication_data
    result = copy.deepcopy(data["admission"]["source_qualification"]["result"])
    changes = {
        "blocked": ("status", "blocked-governance"),
        "false": ("source_ci_pass", False),
        "truthy": ("source_ci_pass", 1),
        "product": ("product_revision", "0" * 40),
        "control": ("control_revision", "0" * 40),
        "tree": ("product_tree", "0" * 40),
        "technical": ("technical_source_ci", "blocked"),
    }
    if fault:
        key, value = changes[fault]
        result[key] = value
        with pytest.raises(ValueError, match="strict pass"):
            publisher.strict_qualification(result, data["profile"], CONTROL)
    else:
        publisher.strict_qualification(result, data["profile"], CONTROL)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "changed",
        "changed_listing",
        "changed_blocked",
        "no_etag",
        "original_component",
        "rate_limit",
        "incomplete",
        "record_boundary",
        "record_limit",
        "empty_records",
        "source_block",
        "wrong_control",
        "wrong_product",
        "response_hash",
        "response_size",
        "response_path",
        "duplicate_path",
        "foreign_endpoint",
        "failed_http",
        "bad_etag",
        "advisory_observed",
        "advisory_unknown",
        "rate_response",
        "missing_native_response",
        "historical_callback",
    ],
)
def test_same_attempt_source_reuse_requires_current_native_origin(
    publication_data, tmp_path, monkeypatch, fault
):
    from saas.scripts import legacy_native_evidence as native

    assert publisher._MAX_RESPONSES == native._MAX_RESPONSES == 32768
    data = publication_data
    if fault == "original_component":
        calls = []
        original = data["admission"]["source_qualification"]["result"]
        monkeypatch.setattr(
            publisher, "qualify_source_ci", lambda *args: (calls.append(args), original)[1]
        )
        monkeypatch.setattr(
            publisher,
            "collect_job_export",
            lambda *_a, **_k: pytest.fail("other components must retain the original qualifier"),
        )
        qualified, provenance = publisher.collect_qualified_source(
            data["source"], data["source"], data["profile"], data["context"], tmp_path / "source"
        )
        assert qualified == original and len(calls) == 1
        assert provenance == {"mode": "original-full-source-qualification"}
        return
    data["profile"]["component"] = publisher.COMPATIBILITY_COMPONENT
    result = copy.deepcopy(data["admission"]["source_qualification"]["result"])
    result["component"] = publisher.COMPATIBILITY_COMPONENT
    if fault == "source_block":
        result["source_ci_pass"] = False
    if fault == "wrong_control":
        result["control_revision"] = "0" * 40
    if fault == "wrong_product":
        result["product_revision"] = "0" * 40
    root = tmp_path / "qualified-native-export"
    (root / "native-api").mkdir(parents=True)
    publisher.write_json(root / "source-qualification.json", result)
    endpoint = publisher.PREFIX + "/actions/runs/91"
    if fault == "foreign_endpoint":
        endpoint = "repos/foreign/repository/actions/runs/91"
    etag = None if fault == "no_etag" else '"qualified"'
    if fault == "bad_etag":
        etag = '"qualified"\r\nInjected: value'
    old = {"id": 91, "status": "completed", "conclusion": "success"}
    if fault == "changed_listing":
        endpoint = publisher.PREFIX + "/actions/workflows/saas-n1-merge-gate.yml/runs?page=1"
        old = {"total_count": 1, "workflow_runs": [{"id": 91}]}
    records = []
    for number in (1, 2):
        path = root / "native-api" / f"response-{number:06d}.json"
        response = {
            "endpoint": endpoint,
            "response": old,
            "http_observation": {
                "status": 403 if fault == "failed_http" else 200,
                "headers": {"etag": etag} if etag is not None else {},
            },
        }
        if number == 1 and fault in {"advisory_observed", "advisory_unknown"}:
            response = {
                "endpoint": "rate_limit",
                "advisory": (
                    {"status": "OBSERVED_ADVISORY_ONLY", "core": {"remaining": 0}}
                    if fault == "advisory_observed"
                    else {"status": "UNKNOWN", "reason": "unrecognized-rate-fields"}
                ),
            }
        elif number == 1 and fault == "rate_response":
            response["endpoint"] = "rate_limit"
        elif number == 1 and fault == "missing_native_response":
            del response["response"]
        publisher.write_json(path, response)
        records.append(
            {"path": path.name, "bytes": path.stat().st_size, "sha256": file_sha256(path)}
        )
    receipt = {
        "kind": "legacy_native_api_evidence_receipt/v1",
        "stage": "pass",
        "invocation_raised": False,
        "capture_failed": False,
        "pin_errors": [],
        "records": records,
    }
    if fault == "incomplete":
        receipt["capture_failed"] = True
    if fault in {"record_boundary", "record_limit"}:
        monkeypatch.setattr(publisher, "_MAX_RESPONSES", 2 if fault == "record_boundary" else 1)
    if fault == "empty_records":
        receipt["records"] = []
    if fault == "response_hash":
        records[0]["sha256"] = "0" * 64
    if fault == "response_size":
        records[0]["bytes"] += 1
    if fault == "response_path":
        records[0]["path"] = "../response-000001.json"
    if fault == "duplicate_path":
        records.append(copy.deepcopy(records[0]))
    publisher.write_json(root / "native-api/receipt.json", receipt)
    coordinate = {"artifact_id": 902, "job_id": 901, "zip_sha256": "a" * 64}
    monkeypatch.setattr(publisher, "collect_job_export", lambda *_a, **_k: (root, coordinate))
    calls, recalculations = [], []

    def fresh(command, **kwargs):
        assert kwargs == {"capture_output": True, "timeout": 60}
        calls.append(command)
        if fault == "rate_limit":
            return subprocess.CompletedProcess(
                command, 1, b"HTTP/1.1 403 Forbidden\r\nX-Ratelimit-Remaining: 0\r\n\r\n{}", b""
            )
        if fault in {
            "changed",
            "changed_listing",
            "changed_blocked",
            "no_etag",
            "historical_callback",
        }:
            value = old if fault == "no_etag" else {**old, "conclusion": "failure"}
            if fault == "changed_listing":
                value = {"total_count": 2, "workflow_runs": [{"id": 92}, {"id": 91}]}
            return subprocess.CompletedProcess(
                command, 0, b"HTTP/1.1 200 OK\r\n\r\n" + json.dumps(value).encode(), b""
            )
        return subprocess.CompletedProcess(
            command, 1, b'HTTP/1.1 304 Not Modified\r\nEtag: "qualified"\r\n\r\n', b""
        )

    def recalculate(*args):
        recalculations.append(args)
        return {
            **result,
            "fresh_full_qualification": True,
            "source_ci_pass": fault != "changed_blocked",
        }

    monkeypatch.setattr(native.subprocess, "run", fresh)
    monkeypatch.setattr(publisher, "qualify_source_ci", recalculate)
    if fault == "historical_callback":
        monkeypatch.setattr(
            publisher,
            "qualify_source_ci",
            lambda *_: pytest.fail("historical revalidation must retain its read-only context"),
        )

    def collect():
        return publisher.collect_qualified_source(
            data["source"],
            data["source"],
            data["profile"],
            data["context"],
            tmp_path / "source-revalidation",
            **({"source_qualifier": recalculate} if fault == "historical_callback" else {}),
        )

    if fault not in {
        None,
        "changed",
        "changed_listing",
        "no_etag",
        "record_boundary",
        "advisory_observed",
        "advisory_unknown",
        "rate_response",
        "historical_callback",
    }:
        with pytest.raises(ValueError if fault != "rate_limit" else native.NativeEvidenceFailure):
            collect()
        assert bool(recalculations) is (fault == "changed_blocked")
        assert len(calls) == (1 if fault in {"rate_limit", "changed_blocked"} else 0)
    else:
        qualified, provenance = collect()
        assert len(calls) == 1  # Both recorded checkpoints have the same native endpoint.
        assert calls[0][:4] == ["gh", "api", "--include", endpoint]
        assert ("-H" in calls[0]) is (fault != "no_etag")
        assert provenance["artifact_id"] == 902
        changed = fault in {"changed", "changed_listing", "historical_callback"}
        assert provenance["current_inputs_required_full_requalification"] is changed
        assert bool(recalculations) is changed
        assert qualified == ({**result, "fresh_full_qualification": True} if changed else result)
        audit = json.loads(
            (tmp_path / "source-revalidation/revalidation-api/receipt.json").read_text()
        )
        assert audit["native_requests_started"] == 1 and audit["capture_failed"] is False
        if fault != "no_etag":
            seed = json.loads(
                (
                    tmp_path / "source-revalidation/revalidation-api/response-000001.json"
                ).read_text()
            )
            assert "http_observation" not in seed
            assert seed["verified_producer_input"] == {
                "producer": coordinate,
                "record": records[-1],
            }
            refreshed = json.loads(
                (
                    tmp_path / "source-revalidation/revalidation-api/response-000002.json"
                ).read_text()
            )
            if not changed:
                assert refreshed["http_observation"]["status"] == 304
                assert refreshed["response"] == old
                assert (
                    refreshed["http_observation"]["validated_source_record"]
                    == "response-000001.json"
                )


@pytest.mark.parametrize("source_ci", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "traversal",
        "alias",
        "symlink",
        "special",
        "duplicate",
        "expansion",
        "many_members",
        "capacity_boundary",
        "too_many_members",
    ],
)
def test_publication_zip_checks_all_members_before_extracting(tmp_path, fault, source_ci):
    archive = tmp_path / "export.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        if source_ci:
            for name in (
                "source-qualification.json",
                "native-api/receipt.json",
                "native-api/response-000001.json",
                "native-api/http-000001.PRIVATE.response",
            ):
                bundle.writestr(name, b"{}")
        name = (
            "../escape"
            if fault == "traversal"
            else "./file.json"
            if fault == "alias"
            else "file.json"
        )
        entry = zipfile.ZipInfo(name)
        if fault in {"symlink", "special"}:
            entry.external_attr = (stat.S_IFLNK if fault == "symlink" else stat.S_IFIFO) << 16
        bundle.writestr(entry, b"{}")
        if fault == "duplicate":
            with pytest.warns(UserWarning):
                bundle.writestr(entry, b"{}")
        if fault in {"many_members", "capacity_boundary", "too_many_members"}:
            # Same shape/count as the actual successful qualification artifact.
            bound = 2 * publisher._MAX_RESPONSES + 8192 if source_ci else 8192
            members = 35865 if fault == "many_members" else bound + (fault == "too_many_members")
            for number in range(members - 1 - (4 if source_ci else 0)):
                bundle.writestr(f"unneeded-ci/record-{number:06d}.json", b"{}")
    target = tmp_path / "extract"
    if fault and fault != "capacity_boundary" and not (source_ci and fault == "many_members"):
        with pytest.raises(ValueError):
            publisher.safe_extract(
                archive,
                target,
                max_bytes=1 if fault == "expansion" else 1024 * 1024,
                source_ci=source_ci,
            )
        assert not target.exists()
    else:
        publisher.safe_extract(archive, target, max_bytes=1024 * 1024, source_ci=source_ci)
        if source_ci:
            assert sorted(
                str(p.relative_to(target)) for p in target.rglob("*") if p.is_file()
            ) == [
                "native-api/http-000001.PRIVATE.response",
                "native-api/receipt.json",
                "native-api/response-000001.json",
                "source-qualification.json",
            ]
        else:
            assert (target / "file.json").read_bytes() == b"{}"


@pytest.mark.parametrize(
    "fault", [None, "attempt", "actor", "failure", "workflow", "source", "size"]
)
def test_native_control_uses_current_run_and_actual_workflow_bytes(tmp_path, monkeypatch, fault):
    control = tmp_path / "control"
    path = control / publisher.WORKFLOW
    path.parent.mkdir(parents=True)
    path.write_bytes(b"trusted exact control workflow\n")
    context = {"control_revision": CONTROL, "run_id": 42, "attempt": 1, "actor": "Dream1216"}
    run = {
        "id": 42,
        "run_attempt": 1,
        "head_sha": CONTROL,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": publisher.WORKFLOW,
        "repository": {"full_name": publisher.REPOSITORY},
        "head_repository": {"full_name": publisher.REPOSITORY},
        "actor": {"login": "Dream1216"},
        "triggering_actor": {"login": "Dream1216"},
        "status": "in_progress",
        "conclusion": None,
    }
    body = path.read_bytes()
    if fault == "attempt":
        run["run_attempt"] = 2
    if fault == "actor":
        run["triggering_actor"]["login"] = "different"
    if fault == "failure":
        run.update(status="completed", conclusion="failure")
    if fault == "workflow":
        run["path"] = ".github/workflows/other.yml"
    if fault == "source":
        body += b"changed"
    source = {
        "path": publisher.WORKFLOW,
        "encoding": "base64",
        "size": len(body),
        "content": base64.b64encode(body).decode(),
    }
    if fault == "size":
        source["size"] += 1
    monkeypatch.setattr(
        publisher,
        "api",
        lambda endpoint: copy.deepcopy(source if "/contents/" in endpoint else run),
    )
    if fault:
        with pytest.raises(ValueError):
            publisher.verify_native_control(control, context)
    else:
        assert publisher.verify_native_control(control, context) == run


@pytest.fixture
def native_export(publication_data, tmp_path, monkeypatch, request):
    data = publication_data
    data["control"] = tmp_path / "native-control"
    workflow = data["control"] / publisher.WORKFLOW
    workflow.parent.mkdir(parents=True)
    workflow.write_bytes((ROOT / publisher.WORKFLOW).read_bytes())
    context, profile = data["context"], data["profile"]
    root = tmp_path / "native-payload"
    root.mkdir()
    job_name, role = getattr(request, "param", ("publish-exact-oci", "publication"))
    if role == "source-ci":
        publisher.write_json(
            root / "source-qualification.json", data["admission"]["source_qualification"]["result"]
        )
        (root / "native-api").mkdir()
        publisher.write_json(root / "native-api/receipt.json", {"kind": "fixture"})
    else:
        publisher.write_json(root / "admission.json", data["admission"])
        publisher.write_json(root / "publication.json", {})
    archive = tmp_path / "native-export.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path in root.rglob("*"):
            if path.is_file():
                bundle.write(path, path.relative_to(root))
    job = {
        "id": 901,
        "name": job_name,
        "run_id": 42,
        "run_attempt": 1,
        "head_sha": CONTROL,
        "status": "completed",
        "conclusion": "success",
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-24.04"],
        "steps": [],
    }
    stamp = datetime(2026, 10, 25, 1, tzinfo=UTC)
    lines = []
    for number, name in enumerate(publisher.RUN_STEPS[job["name"]], 3):
        start = stamp + timedelta(seconds=number * 10)
        step = {
            "number": number,
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "started_at": start.isoformat(),
            "completed_at": (start + timedelta(seconds=2)).isoformat(),
        }
        job["steps"].append(step)
        checkout_names = (publisher.RUN_STEPS[job_name][0], publisher.RUN_STEPS[job_name][2])
        if name in checkout_names:
            revision = CONTROL if name == checkout_names[0] else profile["product_revision"]
            lines.extend(
                f"{start.isoformat()} {text}"
                for text in (
                    "##[group]Run actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                    "[command]/usr/bin/git log -1 --format=%H",
                    revision,
                )
            )
    metadata = {
        "id": 902,
        "name": publisher.artifact_name(role, profile, context),
        "size_in_bytes": archive.stat().st_size,
        "digest": "sha256:" + file_sha256(archive),
        "expired": False,
        "created_at": job["steps"][-1]["started_at"],
        "workflow_run": {"id": 42, "head_sha": CONTROL},
    }
    run = {
        "id": 42,
        "run_attempt": 1,
        "head_sha": CONTROL,
        "repository": {"full_name": publisher.REPOSITORY},
    }
    state = {"job": job, "metadata": metadata, "log": "\n".join(lines), "run": run, "role": role}
    monkeypatch.setattr(
        publisher, "verify_native_control", lambda *_args: copy.deepcopy(state["run"])
    )
    monkeypatch.setattr(publisher, "_job_pages", lambda *_args: [copy.deepcopy(state["job"])])
    monkeypatch.setattr(publisher, "_pages", lambda *_args: [copy.deepcopy(state["metadata"])])
    monkeypatch.setattr(
        publisher,
        "api",
        lambda endpoint: copy.deepcopy(
            state["metadata"] if "/artifacts/" in endpoint else state["job"]
        ),
    )
    monkeypatch.setattr(
        publisher, "download_job_log", lambda _job, path: path.write_text(state["log"])
    )
    monkeypatch.setattr(
        publisher,
        "download_artifact_bytes",
        lambda _id, path, **_kw: shutil.copyfile(archive, path),
    )
    return data, state


def _add_completion_second_overlap(state, first_checkout, product_checkout):
    steps = state["job"]["steps"]
    first = next(step for step in steps if step["name"] == first_checkout)
    product = next(step for step in steps if step["name"] == product_checkout)
    first_index = steps.index(first)
    selection = steps[first_index + 1]
    ended = datetime.fromisoformat(first["completed_at"])
    first_start = first["started_at"]
    previous_start = product["started_at"]
    for step in steps:
        if step["number"] > first["number"]:
            step["number"] += 1
    selection.update(started_at=ended.isoformat(), completed_at=ended.isoformat())
    product.update(
        started_at=ended.isoformat(), completed_at=(ended + timedelta(seconds=1)).isoformat()
    )
    steps.insert(
        first_index + 1,
        dict(
            first,
            number=first["number"] + 1,
            name="Set up Python",
            started_at=ended.isoformat(),
            completed_at=ended.isoformat(),
        ),
    )
    lines = (
        state["log"]
        .replace(previous_start + " ", (ended + timedelta(seconds=0.8)).isoformat() + " ")
        .splitlines()
    )
    lines = [
        line.replace(first_start + " ", (ended + timedelta(seconds=0.05)).isoformat() + " ")
        if line.startswith(first_start + " ") and "##[group]Run " not in line
        else line
        for line in lines
    ]
    lines.append(
        f"{(ended + timedelta(seconds=0.1)).isoformat()} "
        "##[group]Run actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"
    )
    state["log"] = "\n".join(
        sorted(lines, key=lambda line: datetime.fromisoformat(line.partition(" ")[0]))
    )


@pytest.mark.parametrize(
    "native_export",
    [("publish-exact-oci", "publication"), ("qualify-source", "source-ci")],
    indirect=True,
)
@pytest.mark.parametrize("overlap", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "head",
        "attempt",
        "runner",
        "runner_label",
        "step",
        "order",
        "checkout",
        "checkout_header",
        "checkout_command",
        "expired",
        "upload_time",
        "zip_hash",
        "refresh",
    ],
)
def test_cross_job_transfer_binds_native_job_checkout_upload_and_zip(
    native_export, tmp_path, monkeypatch, fault, overlap
):
    data, state = native_export
    job, metadata = state["job"], state["metadata"]
    checkout_names = (publisher.RUN_STEPS[job["name"]][0], publisher.RUN_STEPS[job["name"]][2])
    if overlap:
        _add_completion_second_overlap(state, *checkout_names)
    execution = next(
        step for step in job["steps"] if step["name"] == publisher.RUN_STEPS[job["name"]][3]
    )
    if fault == "head":
        job["head_sha"] = "0" * 40
    if fault == "attempt":
        job["run_attempt"] = 2
    if fault == "runner":
        job["labels"].append("self-hosted")
    if fault == "runner_label":
        job["labels"] = ["ubuntu-latest"]
    if fault == "step":
        execution["conclusion"] = "skipped"
    if fault == "order":
        execution["number"] = 1
    if fault == "checkout":
        state["log"] = state["log"].replace(data["profile"]["product_revision"], "0" * 40)
    if fault in {"checkout_header", "checkout_command"}:
        marker = (
            "##[group]Run actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
            if fault == "checkout_header"
            else "[command]/usr/bin/git log -1 --format=%H"
        )
        line = next(line for line in state["log"].splitlines() if marker in line)
        state["log"] = state["log"].replace(line, line + "\n" + line, 1)
    if fault == "expired":
        metadata["expired"] = True
    if fault == "upload_time":
        metadata["created_at"] = "2026-10-24T00:00:00+00:00"
    if fault == "zip_hash":
        metadata["digest"] = "sha256:" + "0" * 64
    if fault == "refresh":
        counts = {"artifact": 0}

        def changed(endpoint):
            result = copy.deepcopy(metadata if "/artifacts/" in endpoint else job)
            if "/artifacts/" in endpoint:
                counts["artifact"] += 1
                if counts["artifact"] > 1:
                    result["expired"] = True
            return result

        monkeypatch.setattr(publisher, "api", changed)
    destination = tmp_path / "collected"

    def collect():
        return publisher.collect_job_export(
            data["control"],
            data["source"],
            data["profile"],
            data["context"],
            job_name=job["name"],
            role=state["role"],
            destination=destination,
        )

    if fault:
        with pytest.raises(ValueError):
            collect()
        assert json.loads((destination / "native-api/receipt.json").read_text())[
            "invocation_raised"
        ]
    else:
        root, coordinate = collect()
        assert root.joinpath(
            "source-qualification.json" if state["role"] == "source-ci" else "admission.json"
        ).is_file()
        assert coordinate["artifact_id"] == 902 and coordinate["job_id"] == 901
        assert coordinate["zip_sha256"] == metadata["digest"][7:]


@pytest.mark.parametrize("overlap", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "control_checkout",
        "product_checkout",
        "checkout_header",
        "checkout_command",
        "upload_time",
        "post_job",
    ],
)
def test_fresh_wheel_binds_separate_native_job_actor_size_and_static_product(
    native_export, tmp_path, monkeypatch, fault, overlap
):
    data, state = native_export
    stage = tmp_path / "fresh-stage"
    controller.stage_wheel(data["source"], data["wheel"].parent, stage, data["profile"], CONTROL)
    archive = tmp_path / "fresh-native.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path in stage.iterdir():
            bundle.write(path, path.name)
    job = state["job"]
    job["name"] = "build-initial"
    stamp = datetime(2026, 10, 25, 1, tzinfo=UTC)
    job["steps"] = []
    lines = []
    for number, name in enumerate(publisher.FRESH_STEPS, 3):
        start = stamp + timedelta(seconds=number * 10)
        job["steps"].append(
            {
                "name": name,
                "number": number,
                "status": "completed",
                "conclusion": "success",
                "started_at": start.isoformat(),
                "completed_at": (start + timedelta(seconds=1)).isoformat(),
            }
        )
        if name in (publisher.FRESH_STEPS[0], publisher.FRESH_STEPS[2]):
            revision = (
                CONTROL
                if name == publisher.FRESH_STEPS[0]
                else data["profile"]["product_revision"]
            )
            if (fault == "control_checkout" and name == publisher.FRESH_STEPS[0]) or (
                fault == "product_checkout" and name == publisher.FRESH_STEPS[2]
            ):
                revision = "0" * 40
            lines.extend(
                f"{start.isoformat()} {line}"
                for line in (
                    "##[group]Run actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                    "[command]/usr/bin/git log -1 --format=%H",
                    revision,
                )
            )
    state["log"] = "\n".join(lines)
    if overlap:
        _add_completion_second_overlap(state, publisher.FRESH_STEPS[0], publisher.FRESH_STEPS[2])
    if fault in {"checkout_header", "checkout_command"}:
        marker = (
            "##[group]Run actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
            if fault == "checkout_header"
            else "[command]/usr/bin/git log -1 --format=%H"
        )
        line = next(line for line in state["log"].splitlines() if marker in line)
        state["log"] = state["log"].replace(line, line + "\n" + line, 1)
    metadata = state["metadata"]
    metadata.update(
        name=f"legacy-initial-Core-{data['profile']['product_revision']}-{CONTROL}-42-1",
        size_in_bytes=archive.stat().st_size,
        digest="sha256:" + file_sha256(archive),
        created_at=job["steps"][-1]["started_at"],
    )
    if fault == "upload_time":
        metadata["created_at"] = "2026-10-24T00:00:00+00:00"

    def download(profile, **coordinates):
        assert profile == data["profile"] and coordinates["actor"] == "Dream1216"
        assert coordinates["job_id"] == job["id"]
        assert coordinates["zip_size"] == archive.stat().st_size
        destination = coordinates["destination"]
        destination.mkdir()
        shutil.copyfile(archive, destination / "fresh-wheel.zip")
        if fault == "post_job":
            job["conclusion"] = "failure"
        return {"native_run": state["run"], "native_artifact": copy.deepcopy(metadata)}

    monkeypatch.setattr(publisher, "download_fresh_wheel", download)
    if fault:
        with pytest.raises(ValueError):
            publisher.collect_fresh_wheel(
                data["control"],
                data["source"],
                data["profile"],
                data["context"],
                tmp_path / "collected-fresh",
            )
    else:
        coordinate, wheel = publisher.collect_fresh_wheel(
            data["control"],
            data["source"],
            data["profile"],
            data["context"],
            tmp_path / "collected-fresh",
        )
        assert coordinate["actor"] == "Dream1216" and coordinate["job_id"] == job["id"]
        assert coordinate["zip_size"] == archive.stat().st_size
        assert wheel.read_bytes() == data["wheel"].read_bytes()


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "source_block",
        "pg_block",
        "same_run",
        "same_job",
        "same_artifact",
        "blocked_domain_discovery",
    ],
)
def test_native_input_join_requires_all_independent_gates(
    publication_data, tmp_path, monkeypatch, fault
):
    data = publication_data
    source_result = copy.deepcopy(data["admission"]["source_qualification"]["result"])
    pg_result = copy.deepcopy(data["admission"]["native_product_pg"]["result"])
    fresh = copy.deepcopy(data["admission"]["fresh_control_wheel"])
    original = data["admission"]["original_pr_oci"]
    effects = []
    if fault == "source_block":
        source_result["status"] = "blocked-governance"
    if fault == "blocked_domain_discovery":
        receipt = {
            "kind": "legacy_main_domain_not_applicable/v1",
            "workflow": ".github/workflows/saas-n1-merge-gate.yml",
            "run_id": 8001,
            "attempt": 1,
            "job_id": 8801,
            "check_id": 8803,
            "check_revision": data["profile"]["product_revision"],
            "check_suite_id": 8802,
            "app_id": 15368,
            "source_head": data["profile"]["product_revision"],
            "validation_pr": 9001,
            "validation_base_ref": data["admission"]["transfer_profile"]["base_ref"],
            "original_conclusion": "failure",
            "evaluated_PG_authority": False,
            "technical_gate_waiver": False,
            "main_targeting_PR_permission": False,
            "production_admission": False,
        }
        source_result.update(
            status="blocked-domain-discovery",
            source_ci_pass=False,
            complete_domain_discovery=False,
            all_apps={
                "governance_refusals": [],
                "original_informational_checks": [],
                "all_original_governance_clear": True,
                "verified_main_domain_refusals": [receipt],
            },
        )
        assert source_result["technical_source_ci"] == "pass"
    if fault == "pg_block":
        pg_result["native_PG_receipts_pass"] = False
    for name, key in (
        ("same_run", "run_id"),
        ("same_job", "job_id"),
        ("same_artifact", "artifact_id"),
    ):
        if fault == name:
            fresh[key] = original[key]
    monkeypatch.setattr(publisher, "load_profile", lambda *_a: data["profile"])
    monkeypatch.setattr(
        publisher, "load_transfer_profile", lambda *_a: data["admission"]["transfer_profile"]
    )
    monkeypatch.setattr(
        publisher, "collect_qualified_source", lambda *_a: (source_result, {"artifact_id": 123})
    )

    def pg(*_args, **_kwargs):
        effects.append("PG")
        return pg_result

    def original_input(*_args):
        effects.append("original")
        return original

    def fresh_input(*_args):
        effects.append("fresh")
        return fresh, data["wheel"]

    def forbidden(*_args, **_kwargs):
        effects.append("publish-or-sign")
        raise AssertionError("blocked source reached a privileged operation")

    monkeypatch.setattr(publisher, "collect_pg_receipts", pg)
    monkeypatch.setattr(publisher, "collect_original_input", original_input)
    monkeypatch.setattr(publisher, "collect_fresh_wheel", fresh_input)
    monkeypatch.setattr(publisher, "publish_exact", forbidden)
    monkeypatch.setattr(publisher, "verify_signatures", forbidden)
    monkeypatch.setattr(publisher, "verify_native_control", lambda *_a: {})
    control = tmp_path / "input-control"
    path = control / publisher.WORKFLOW
    path.parent.mkdir(parents=True)
    path.write_text("trusted control workflow")

    def collect():
        if fault == "blocked_domain_discovery":
            return publisher.stage(
                "publish",
                control,
                data["source"],
                "Core",
                data["context"],
                tmp_path / "blocked-publication",
            )
        return publisher.collect_inputs(
            control, data["source"], "Core", data["context"], tmp_path / "joined-inputs"
        )

    if fault:
        with pytest.raises(ValueError):
            collect()
        if fault in {"source_block", "blocked_domain_discovery"}:
            assert effects == []
    else:
        admission, archive, wheel = collect()
        assert admission["fresh_control_wheel"] == fresh
        assert admission["source_qualification"]["sha256"] == publisher.digest(source_result)
        assert admission["native_product_pg"]["sha256"] == publisher.digest(pg_result)
        assert archive.name == "original-oci.zip" and wheel == data["wheel"]


@pytest.mark.parametrize("fault", [None, "upload_time", "job_refresh", "zip_bytes"])
def test_original_PR_OCI_requires_original_producer_upload_interval_and_bytes(
    native_export, tmp_path, monkeypatch, fault
):
    data, state = native_export
    original = data["admission"]["original_pr_oci"]
    job = state["job"]
    job.update(
        id=original["job_id"],
        name="build-candidate",
        run_id=41,
        run_attempt=2,
        head_sha=data["profile"]["product_revision"],
    )
    job["steps"][-1]["name"] = publisher.UPLOAD_STEP
    metadata = state["metadata"]
    metadata.update(
        id=original["artifact_id"],
        name="original-reviewed-pr-oci",
        size_in_bytes=data["archive"].stat().st_size,
        digest="sha256:" + file_sha256(data["archive"]),
        workflow_run={"id": 41, "head_sha": data["profile"]["product_revision"]},
    )
    state["run"].update(id=41, run_attempt=2, head_sha=data["profile"]["product_revision"])
    if fault == "upload_time":
        metadata["created_at"] = "2026-10-24T00:00:00+00:00"

    def download(_control, _component, *, destination):
        destination.mkdir()
        shutil.copyfile(data["archive"], destination / "original-oci.zip")
        result = {
            "original_oci": original,
            "native_jobs": [copy.deepcopy(job)],
            "native_run": copy.deepcopy(state["run"]),
            "native_artifact": copy.deepcopy(metadata),
        }
        if fault == "zip_bytes":
            (destination / "original-oci.zip").write_bytes(b"changed")
        if fault == "job_refresh":
            job["conclusion"] = "failure"
        return result

    monkeypatch.setattr(publisher, "load_original_inputs", lambda *_a: {})
    monkeypatch.setattr(publisher, "download_original_oci", download)
    if fault:
        with pytest.raises(ValueError):
            publisher.collect_original_input(
                data["source"], data["profile"], tmp_path / "original-collected"
            )
    else:
        assert (
            publisher.collect_original_input(
                data["source"], data["profile"], tmp_path / "original-collected"
            )
            == original
        )


def _native_verified(predicate, subject, context):
    repository = f"https://github.com/{publisher.REPOSITORY}"
    return [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "issuer": "https://token.actions.githubusercontent.com",
                        "sourceRepositoryURI": repository,
                        "sourceRepositoryRef": "refs/heads/main",
                        "sourceRepositoryDigest": CONTROL,
                        "buildSignerDigest": CONTROL,
                        "buildConfigDigest": CONTROL,
                        "runnerEnvironment": "github-hosted",
                        "subjectAlternativeName": (
                            f"{repository}/{publisher.WORKFLOW}@refs/heads/main"
                        ),
                        "runInvocationURI": (
                            f"{repository}/actions/runs/{context['run_id']}/"
                            f"attempts/{context['attempt']}"
                        ),
                    }
                },
                "statement": {
                    "predicate": predicate,
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "subject": [{"digest": {"sha256": subject}}],
                },
            }
        }
    ]


def test_complete_local_pipeline_preserves_original_bytes_and_separates_privileges(
    publication_data, tmp_path, monkeypatch
):
    """Real Git/wheel/OCI parsers, fake native APIs/processes; no real signature."""
    data = publication_data
    admission, manifest = data["admission"], data["manifest"]
    source = data["source"]
    calls = []
    exports = {}
    original_run = publisher.subprocess.run

    def inputs(_control, _product, _component, _context, destination):
        destination.mkdir(parents=True)
        archive = destination / "original.zip"
        shutil.copyfile(data["archive"], archive)
        return copy.deepcopy(admission), archive, data["wheel"]

    def current_scan(_control, _oci, destination):
        shutil.copytree(data["candidate"] / "grype", destination / "grype")

    def native_export(_control, _product, _profile, _context, *, job_name, role, destination):
        calls.append(("native", job_name))
        coordinate = {
            "job_id": 1000 + len(exports),
            "artifact_id": {
                "preparation": 2001,
                "publication": 2002,
                "runtime": 2003,
                "signatures": 2004,
            }[role],
            "artifact_name": publisher.artifact_name(role, data["profile"], data["context"]),
            "zip_size": 123,
            "zip_sha256": {
                "preparation": "1",
                "publication": "2",
                "runtime": "3",
                "signatures": "4",
            }[role]
            * 64,
        }
        # Job identity is stable across readers, as it is in native GitHub APIs.
        coordinate["job_id"] = coordinate["artifact_id"] + 100
        return exports[role], coordinate

    def process(command, **kwargs):
        if command[0] == "git":
            return original_run(command, **kwargs)
        calls.append(tuple(command))
        if command[:2] == ["crane", "digest"]:
            return subprocess.CompletedProcess(command, 1, "", "MANIFEST_UNKNOWN")
        if command[:2] == ["crane", "pull"]:
            role = "server" if "server@" in command[-2] else "host"
            shutil.copytree(data["candidate"] / f"{role}-1-layout", command[-1])
        if command[0] == "fake-syft":
            for value in command:
                if value.startswith("spdx-json="):
                    publisher.write_json(
                        Path(value.partition("=")[2]),
                        {
                            "spdxVersion": "SPDX-2.3",
                            "SPDXID": "SPDXRef-DOCUMENT",
                            "creationInfo": {"creators": [f"Tool: syft-{publisher.SYFT_VERSION}"]},
                            "packages": [{"name": "fixture"}],
                        },
                    )
                if value.startswith("cyclonedx-json="):
                    publisher.write_json(
                        Path(value.partition("=")[2]),
                        {"bomFormat": "CycloneDX", "components": [{"name": "fixture"}]},
                    )
        return subprocess.CompletedProcess(command, 0, "", "")

    def command_output(command, **kwargs):
        calls.append(tuple(command))
        if command[:2] == ["crane", "digest"]:
            role = "server" if "server:" in command[-1] else "host"
            return manifest["images"][role]["index_digest"] + "\n"
        if command[:3] == ["gh", "attestation", "verify"]:
            predicate = json.loads((exports["attest"] / "provenance.json").read_text())
            subject = (
                admission["fresh_control_wheel"]["wheel_sha256"]
                if not command[3].startswith("oci://")
                else command[3].split("sha256:")[1]
            )
            if command[command.index("--predicate-type") + 1] == publisher.SPDX_PREDICATE_TYPE:
                runtime = publisher.read_json(exports["attest"] / "runtime.json")
                name = next(
                    name
                    for name, facts in runtime["sboms"].items()
                    if "oci://" + facts["image"] == command[3]
                )
                predicate = publisher.read_json(exports["attest"] / "sbom" / f"{name}.spdx.json")
                entries = _native_verified(predicate, subject, data["context"])
                entries[0]["verificationResult"]["statement"]["predicateType"] = (
                    publisher.SPDX_PREDICATE_TYPE
                )
                return json.dumps(entries)
            return json.dumps(_native_verified(predicate, subject, data["context"]))
        raise AssertionError(command)

    monkeypatch.setattr(publisher, "collect_inputs", inputs)
    monkeypatch.setattr(publisher, "collect_job_export", native_export)
    monkeypatch.setattr(publisher, "verify_native_control", lambda *_args: {})
    monkeypatch.setattr(publisher, "scan", current_scan)
    monkeypatch.setattr(publisher, "install_syft", lambda _root: Path("fake-syft"))
    monkeypatch.setattr(publisher.subprocess, "run", process)
    original_output = publisher.subprocess.check_output

    def dispatch(command, **kwargs):
        return (
            original_output(command, **kwargs)
            if command[0] == "git"
            else command_output(command, **kwargs)
        )

    monkeypatch.setattr(publisher.subprocess, "check_output", dispatch)
    for command, role in (
        ("prepare", "preparation"),
        ("publish", "publication"),
        ("runtime", "runtime"),
        ("attest-inputs", "attest"),
        ("consume", "consumer"),
    ):
        monkeypatch.setenv(
            "GITHUB_JOB",
            "verify-published-runtime" if command == "runtime" else "owned-local-contract",
        )
        destination = tmp_path / command
        destination.mkdir()
        values = publisher.stage(command, source, source, "Core", data["context"], destination)
        exports[role] = destination / "export"
        if command == "attest-inputs":
            exports["signatures"] = destination / "signature-export"
            exports["signatures"].mkdir()
            signature = publisher.verify_signatures(exports[role], admission, data["wheel"])
            publisher.write_json(exports["signatures"] / "native-signatures.json", signature)
        assert values["admission_sha256"] == publisher.digest(admission)
        assert (
            file_sha256(destination / "inputs/original.zip")
            == admission["original_pr_oci"]["zip_sha256"]
        )
    predicate = json.loads((exports["attest"] / "provenance.json").read_text())
    params = predicate["buildDefinition"]["externalParameters"]
    assert params["input_variant"] == publisher.VARIANT
    assert params["fresh_control_wheel"]["run_id"] != params["original_pr_oci"]["run_id"]
    assert params["fresh_control_wheel"]["job_id"] != params["original_pr_oci"]["job_id"]
    assert params["rebuild_in_publisher"] is False
    containers = [call for call in calls if call[:2] == ("docker", "run")]
    assert len(containers) == 8 and {
        call[call.index("--platform") + 1] for call in containers
    } == set(publisher.PLATFORMS)
    assert all(
        "--network" in call and "none" in call and "--env" not in call for call in containers
    )
    gh_calls = [call for call in calls if call[:3] == ("gh", "attestation", "verify")]
    assert len(gh_calls) == 14 and all(
        "--source-digest" in call and "--deny-self-hosted-runners" in call for call in gh_calls
    )
    assert not any("build" in str(call[0]) or call[0] == "uv" for call in calls)


@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "fresh_job",
        "fresh_actor",
        "fresh_size",
        "oci_run",
        "oci_artifact",
        "source_digest",
        "pg_digest",
    ],
)
def test_typed_publication_rejects_input_conflation_and_evidence_tampering(
    publication_data, fault
):
    admission = copy.deepcopy(publication_data["admission"])
    if fault == "source":
        admission["profile"]["product_tree"] = "0" * 40
    if fault == "fresh_job":
        admission["fresh_control_wheel"]["job_id"] = admission["original_pr_oci"]["job_id"]
    if fault == "fresh_actor":
        admission["fresh_control_wheel"]["actor"] = "other"
    if fault == "fresh_size":
        admission["fresh_control_wheel"]["zip_size"] = True
    if fault == "oci_run":
        admission["original_pr_oci"]["run_id"] = admission["control"]["run_id"]
    if fault == "oci_artifact":
        admission["original_pr_oci"]["artifact_id"] = admission["fresh_control_wheel"][
            "artifact_id"
        ]
    if fault == "source_digest":
        admission["source_qualification"]["sha256"] = "0" * 64
    if fault == "pg_digest":
        admission["native_product_pg"]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        publisher.typed_provenance(
            admission,
            {},
            {},
            preparation_artifact={},
            publication_artifact={},
            runtime_artifact={},
        )


@pytest.mark.parametrize(
    "fault", ["bad_signature", "wrong_claim", "wrong_subject", "old_predicate", "cli_failure"]
)
def test_real_native_verifier_is_required_and_artifact_owned_json_has_no_input(
    publication_data, tmp_path, monkeypatch, fault
):
    data = publication_data
    predicate = {"typed": publisher.VARIANT}
    digest = data["admission"]["fresh_control_wheel"]["wheel_sha256"]
    entries = _native_verified(predicate, digest, data["context"])
    command_seen = []
    if fault == "wrong_claim":
        entries[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"] = (
            data["profile"]["product_revision"]
        )
    if fault == "wrong_subject":
        entries[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
    if fault == "old_predicate":
        entries[0]["verificationResult"]["statement"]["predicate"] = {
            "input_variant": "original_pr_oci_and_fresh_control_wheel/v1"
        }

    def verify(command, **_kwargs):
        command_seen.append(command)
        if fault in {"bad_signature", "cli_failure"}:
            raise subprocess.CalledProcessError(1, command)
        return json.dumps(entries)

    monkeypatch.setattr(core.subprocess, "check_output", verify)
    (tmp_path / "artifact-owned-verification.json").write_text(
        json.dumps(_native_verified(predicate, digest, data["context"]))
    )
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        core.verify_native_statement(
            str(data["wheel"]),
            digest="sha256:" + digest,
            predicate=predicate,
            control_revision=CONTROL,
            run_id=42,
            attempt=1,
        )
    assert command_seen and command_seen[0][:3] == ["gh", "attestation", "verify"]
    assert "--source-digest" in command_seen[0]


def test_complete_workflow_keeps_product_execution_out_of_protected_jobs():
    workflow = yaml.load((ROOT / publisher.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    jobs = workflow["jobs"]
    protected = {name for name, job in jobs.items() if "environment" in job}
    assert protected == {"publish-exact-oci", "attest-exact-inputs"}
    assert jobs["publish-exact-oci"]["permissions"]["packages"] == "write"
    assert "id-token" not in jobs["publish-exact-oci"]["permissions"]
    assert jobs["attest-exact-inputs"]["permissions"]["id-token"] == "write"
    assert jobs["verify-published-runtime"]["needs"] == "publish-exact-oci"
    assert jobs["attest-exact-inputs"]["needs"] == "verify-published-runtime"
    assert jobs["independent-readback"]["needs"] == "attest-exact-inputs"
    for name, job in jobs.items():
        assert job["runs-on"] == "ubuntu-24.04"
        assert "refs/heads/main" in job["if"]
        if name not in protected:
            assert set(job["permissions"].values()) == {"read"}
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r".+@[0-9a-f]{40}", step["uses"])
            if name in protected and "run" in step:
                assert step["working-directory"] == "control"
                assert not any(
                    command in step["run"]
                    for command in ("uv build", "pip install", "docker run", "npm", "cd product")
                )
            if name in publisher.RUN_STEPS and step["name"] == publisher.UPLOAD_NAMES[name]:
                assert step["with"]["retention-days"] == "90"
    assert all(jobs[name]["environment"] == "production-image" for name in protected)
    attest_steps = [
        step
        for step in jobs["attest-exact-inputs"]["steps"]
        if step.get("uses", "").startswith("actions/attest@")
    ]
    assert len(attest_steps) == 7
    assert all("predicate-path" in step["with"] for step in attest_steps)
    assert "verify-signatures" in json.dumps(jobs["attest-exact-inputs"])


def test_runtime_entrypoint_cannot_execute_from_a_protected_job(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_JOB", "attest-exact-inputs")
    with pytest.raises(ValueError, match="isolated unprivileged"):
        publisher.execute_runtime(tmp_path, {}, {}, {}, tmp_path, tmp_path, tmp_path)
