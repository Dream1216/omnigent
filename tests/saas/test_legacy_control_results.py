"""Bind both native PG matrix jobs without changing completed source-CI rules."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import shutil
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.saas.test_legacy_pg_contract import pg, result_xml
from tests.saas.test_legacy_pg_contract import scenario as scenario

ROOT = Path(__file__).resolve().parents[2]
key = "saas.scripts.legacy_control_results"
spec = importlib.util.spec_from_file_location(key, ROOT / "saas/scripts/legacy_control_results.py")
assert spec and spec.loader
consumer = importlib.util.module_from_spec(spec)
sys.modules[key] = consumer
spec.loader.exec_module(consumer)
capture = sys.modules["saas.scripts.legacy_native_evidence"]
reader = sys.modules["saas.scripts.legacy_pytest_results"]


@pytest.fixture
def pg_native(scenario, tmp_path, monkeypatch):
    control, product, control_sha = (
        scenario["control"],
        scenario["product"],
        scenario["control_sha"],
    )
    profile = scenario["profile"]
    source = pg.verify_pg_source(control, product, "Core", control_sha)
    run = {
        "id": 6001,
        "run_attempt": 1,
        "head_sha": control_sha,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": consumer.WORKFLOW,
        "repository": {"full_name": consumer.REPOSITORY},
        "head_repository": {"full_name": consumer.REPOSITORY},
        "actor": {"login": "reviewed-actor"},
        "triggering_actor": {"login": "reviewed-actor"},
        "status": "in_progress",
        "conclusion": None,
    }
    jobs, artifacts, archives, logs = [], [], {}, {}
    stamp = datetime(2026, 10, 24, 14, 0, tzinfo=UTC)
    for major in (16, 18):
        job = {
            "id": 7000 + major,
            "run_id": run["id"],
            "run_attempt": 1,
            "head_sha": control_sha,
            "name": f"legacy-pg ({major})",
            "status": "completed",
            "conclusion": "success",
            "runner_group_name": "GitHub Actions",
            "labels": ["ubuntu-latest"],
            "steps": [],
        }
        lines = []
        for number, name in enumerate(consumer._PG_STEPS, 3):
            start = stamp + timedelta(seconds=number * 10)
            step = {
                "number": number,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": start.isoformat(),
                "completed_at": (start + timedelta(seconds=1)).isoformat(),
            }
            job["steps"].append(step)
            payload = []
            if name in {"Checkout exact main PG verifier", "Checkout exact PG product"}:
                checkout = (
                    control_sha
                    if name == "Checkout exact main PG verifier"
                    else profile["product_revision"]
                )
                payload = [
                    "##[group]Run actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                    "[command]/usr/bin/git log -1 --format=%H",
                    checkout,
                ]
            if name == "Execute original exact-source PostgreSQL contracts":
                cases = sorted(pg.expected_cases(major))
                payload = [f"collecting ... collected {len(cases)} items"] + [
                    f"{classname.replace('.', '/')}.py::{test} PASSED [100%]"
                    for classname, test in cases
                ]
            lines.extend(f"{start.isoformat()} {line}" for line in payload)
        logs[job["id"]] = "\n".join(lines)
        major_source = {
            **source,
            "postgresql_major": major,
            "service_image": pg.PG_IMAGES[major],
            "production_admission": False,
        }
        xml = result_xml(major)
        version = "160014" if major == 16 else "180006"
        result = pg.verify_pg_results(xml, major=major, observed_version=version)
        payloads = {
            "legacy-pg-source.json": json.dumps(major_source),
            "legacy-pg-version.txt": version,
            "legacy-pg.xml": xml,
            "legacy-pg-result.json": json.dumps({**major_source, "result": result}),
        }
        archive = tmp_path / f"fixture-{major}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
            for name, payload in payloads.items():
                bundle.writestr(name, payload)
        identifier = 8000 + major
        artifacts.append(
            {
                "id": identifier,
                "name": (
                    f"legacy-pg-Core-{major}-{profile['product_revision']}-{control_sha}-6001-1"
                ),
                "expired": False,
                "size_in_bytes": archive.stat().st_size,
                "digest": "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(),
                "created_at": job["steps"][-1]["started_at"],
                "workflow_run": {"id": run["id"], "head_sha": control_sha},
            }
        )
        archives[identifier] = archive
        jobs.append(job)
    state = {
        "run": run,
        "jobs": jobs,
        "artifacts": artifacts,
        "archives": archives,
        "logs": logs,
        "downloads": 0,
        "fault": None,
    }
    workflow = (control / consumer.WORKFLOW).read_bytes()

    def api(endpoint):
        value = None
        if "/contents/" in endpoint:
            value = {
                "path": consumer.WORKFLOW,
                "encoding": "base64",
                "size": len(workflow),
                "content": base64.b64encode(workflow).decode(),
            }
        elif "/jobs?" in endpoint:
            value = {"total_count": len(jobs), "jobs": jobs}
        elif endpoint.endswith("/artifacts?per_page=100&page=1"):
            value = {"total_count": len(artifacts), "artifacts": artifacts}
        elif "/actions/artifacts/" in endpoint:
            value = next(row for row in artifacts if row["id"] == int(endpoint.rsplit("/", 1)[1]))
        elif "/actions/jobs/" in endpoint:
            value = next(row for row in jobs if row["id"] == int(endpoint.rsplit("/", 1)[1]))
        elif "/actions/runs/" in endpoint:
            value = run
        else:
            raise AssertionError(endpoint)
        value = copy.deepcopy(value)
        if state["fault"] == "changed_attempt" and state["downloads"]:
            if value.get("id") == run["id"]:
                value["run_attempt"] = 2
        if (
            state["fault"] == "expired_after_download"
            and state["downloads"]
            and "/actions/artifacts/" in endpoint
        ):
            value["expired"] = True
        return value

    def download(identifier, path, *, expected_size, expected_sha256):
        source_zip = archives[identifier]
        assert source_zip.stat().st_size == expected_size
        assert hashlib.sha256(source_zip.read_bytes()).hexdigest() == expected_sha256
        shutil.copyfile(source_zip, path)
        state["downloads"] += 1

    monkeypatch.setattr(capture, "_native_api", api)
    monkeypatch.setattr(
        consumer, "download_job_log", lambda identifier, path: path.write_text(logs[identifier])
    )
    monkeypatch.setattr(consumer, "download_artifact_bytes", download)
    state["invoke"] = lambda: consumer.collect_pg_receipts(
        control,
        product,
        "Core",
        control_sha,
        run_id=6001,
        attempt=1,
        actor="reviewed-actor",
        destination=tmp_path / "native-results",
    )
    return state


@pytest.mark.parametrize(
    "scenario", [{"pg_inputs": True, "control_workflow": True}], indirect=True
)
def test_exact_PG16_and_PG18_jobs_bind_active_control_and_different_product(pg_native, tmp_path):
    result = pg_native["invoke"]()
    assert result["native_PG_receipts_pass"] is True
    assert result["complete_source_image_signature_production_admission"] is False
    assert result["control_revision"] != result["product_revision"]
    assert [row["XML_result"]["tests"] for row in result["PG16_and_PG18"]] == [4, 7]
    assert pg_native["downloads"] == 2
    assert (
        len(
            json.loads((tmp_path / "native-results/native-api/receipt.json").read_text())[
                "records"
            ]
        )
        > 10
    )


@pytest.mark.parametrize(
    "scenario", [{"pg_inputs": True, "control_workflow": True}], indirect=True
)
@pytest.mark.parametrize(
    "fault",
    [
        "attempt",
        "actor",
        "conflated_sha",
        "failed_run",
        "missing_matrix",
        "failed_job",
        "skipped_step",
        "checkout",
        "artifact_attempt",
        "expired_artifact",
        "wrong_artifact_head",
        "upload_time",
        "extra_ZIP_member",
        "wrong_source_receipt",
        "wrong_version",
        "missing_XML_case",
        "changed_attempt",
        "expired_after_download",
    ],
)
def test_native_PG_denies_source_attempt_job_artifact_and_result_faults(
    pg_native, scenario, tmp_path, fault
):
    state = pg_native
    run, jobs, artifacts = state["run"], state["jobs"], state["artifacts"]
    if fault == "attempt":
        run["run_attempt"] = 2
    elif fault == "actor":
        run["triggering_actor"]["login"] = "other"
    elif fault == "conflated_sha":
        run["head_sha"] = scenario["profile"]["product_revision"]
    elif fault == "failed_run":
        run.update(status="completed", conclusion="failure")
    elif fault == "missing_matrix":
        jobs.pop()
    elif fault == "failed_job":
        jobs[0]["conclusion"] = "failure"
    elif fault == "skipped_step":
        jobs[0]["steps"][-2]["conclusion"] = "skipped"
    elif fault == "checkout":
        state["logs"][jobs[0]["id"]] = state["logs"][jobs[0]["id"]].replace(
            scenario["profile"]["product_revision"], scenario["control_sha"]
        )
    elif fault == "artifact_attempt":
        artifacts[0]["name"] += "-old-attempt"
    elif fault == "expired_artifact":
        artifacts[0]["expired"] = True
    elif fault == "wrong_artifact_head":
        artifacts[0]["workflow_run"]["head_sha"] = scenario["profile"]["product_revision"]
    elif fault == "upload_time":
        artifacts[0]["created_at"] = "2026-10-23T00:00:00Z"
    elif fault in {"changed_attempt", "expired_after_download"}:
        state["fault"] = fault
    else:
        archive = state["archives"][artifacts[0]["id"]]
        with zipfile.ZipFile(archive) as bundle:
            payloads = {name: bundle.read(name) for name in bundle.namelist()}
        if fault == "extra_ZIP_member":
            payloads["unreviewed"] = b"extra"
        elif fault == "wrong_source_receipt":
            payloads["legacy-pg-source.json"] = b"{}"
        elif fault == "wrong_version":
            payloads["legacy-pg-version.txt"] = b"180006"
        elif fault == "missing_XML_case":
            payloads["legacy-pg.xml"] = result_xml(16, fault="missing")
        with zipfile.ZipFile(archive, "w") as bundle:
            for name, payload in payloads.items():
                bundle.writestr(name, payload)
        artifacts[0]["size_in_bytes"] = archive.stat().st_size
        artifacts[0]["digest"] = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        state["invoke"]()
    receipt = json.loads((tmp_path / "native-results/native-api/receipt.json").read_text())
    assert receipt["invocation_raised"] and receipt["source_ci_admission"] is False
    assert not (tmp_path / "native-results/native-PG-results.json").exists()


def test_original_source_artifact_entrypoint_still_rejects_active_runs():
    with pytest.raises(ValueError, match="successful exact-source"):
        reader.verify_pytest_artifact_identity(
            {},
            {"status": "in_progress", "conclusion": None},
            {},
            revision="a" * 40,
            artifact_name="original",
            upload_step={},
            archive=Path("not-read"),
        )


def test_PG_receipt_job_depends_on_both_original_matrix_results_and_has_no_publish_privilege():
    import yaml

    workflow = yaml.load((ROOT / consumer.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
    original = workflow["jobs"]["verify-product-pg"]
    assert tuple(step["name"] for step in original["steps"]) == consumer._PG_STEPS
    job = workflow["jobs"]["collect-product-pg"]
    assert job["needs"] == "verify-product-pg"
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert "environment" not in job
    steps = {step["name"]: step for step in job["steps"]}
    execution = steps["Collect exact native PG16 and PG18 jobs and original artifacts"]
    assert execution["working-directory"] == "control"
    assert "python -B -m saas.scripts.legacy_control_results" in execution["run"]
    assert "uv " not in execution["run"] and "pip " not in execution["run"]
    upload = steps["Retain original native PG receipts and refusal evidence"]
    assert upload["if"] == "always()" and upload["with"]["retention-days"] == "90"
    assert job["env"]["CONTROL_REVISION"] == "${{ github.sha }}"
