"""Keep the fixed main-only refusal separate from technical and policy failures."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.saas.test_legacy_source_qualification import ROOT, invoke, qualifier
from tests.saas.test_legacy_source_qualification import scenario as scenario

domain = sys.modules["saas.scripts.legacy_domain_eligibility"]


@pytest.fixture
def native_domain(scenario, monkeypatch):
    profile, identity = scenario["profile"], scenario["identity"]
    attachment = profile["product_revision"]
    prefix = f"https://api.github.com/repos/{domain.REPOSITORY}/actions/runs/8001"
    run = {
        "id": 8001,
        "created_at": "2026-10-24T15:00:00Z",
        "run_attempt": 1,
        "path": domain.MAIN_WORKFLOW,
        "name": "SaaS N-1 merge gate",
        "event": "pull_request_target",
        "head_sha": attachment,
        "workflow_id": 8801,
        "check_suite_id": 8802,
        "repository": {"full_name": domain.REPOSITORY},
        "head_repository": {"full_name": domain.REPOSITORY},
        "status": "completed",
        "conclusion": "failure",
        "pull_requests": [],
        "jobs_url": prefix + "/attempts/1/jobs",
        "logs_url": prefix + "/attempts/1/logs",
    }
    job = {
        "id": 8803,
        "run_id": 8001,
        "run_attempt": 1,
        "head_sha": attachment,
        "name": "evaluate",
        "status": "completed",
        "conclusion": "failure",
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-latest"],
        "check_run_url": f"https://api.github.com/repos/{domain.REPOSITORY}/check-runs/8804",
        "steps": [],
    }
    stamp = datetime(2026, 10, 24, 15, tzinfo=UTC)
    lines = []
    names = (
        ("Check out trusted gate", "success"),
        ("Resolve current PR head", "failure"),
        ("Evaluate exact PostgreSQL N-1 authority", "skipped"),
        ("Mark non-completed N-1 run pending", "skipped"),
        ("Post exact-head gate status", "skipped"),
    )
    for number, (name, conclusion) in enumerate(names, 2):
        start = stamp + timedelta(seconds=number * 10)
        job["steps"].append(
            {
                "number": number,
                "name": name,
                "status": "completed",
                "conclusion": conclusion,
                "started_at": start.isoformat(),
                "completed_at": (start + timedelta(seconds=1)).isoformat(),
            }
        )
        bodies = []
        if number == 2:
            bodies = [
                "##[group]Run actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                "[command]/usr/bin/git log -1 --format=%H",
                scenario["control_sha"],
            ]
        if number == 3:
            bodies = [
                "##[group]Run set -euo pipefail",
                "env:",
                f"  REPO: {domain.REPOSITORY}",
                "  EVENT_NAME: pull_request_target",
                f"  EVENT_PR: {identity['validation_pr']}",
                f"  EVENT_HEAD_SHA: {profile['product_revision']}",
                "  WORKFLOW_HEAD_SHA: ",
                "  WORKFLOW_PRS: null",
                "##[endgroup]",
                domain._ERROR,
                "##[error]Process completed with exit code 1.",
            ]
        for index, body in enumerate(bodies):
            lines.append((start + timedelta(milliseconds=index * 50)).isoformat() + " " + body)
    check = {
        "id": 8804,
        "name": "evaluate",
        "head_sha": attachment,
        "app": {"id": 15368},
        "check_suite": {"id": 8802},
        "status": "completed",
        "conclusion": "failure",
    }
    gate = b"#!/bin/bash\n# original fixture gate; never executed\n"
    data = {"run": run, "job": job, "check": check, "log": "\n".join(lines) + "\n", "gate": gate}

    def refresh_rule():
        rule = {
            "kind": "legacy_original_main_domain_refusal/v2",
            "workflow_sha256": domain.MAIN_WORKFLOW_SHA256,
            "product_revision": profile["product_revision"],
            "product_tree": profile["product_tree"],
            "validation_pr": identity["validation_pr"],
            "validation_base_ref": identity["validation_base_ref"],
            "attachment_revision": run["head_sha"],
            "run_id": run["id"],
            "attempt": run["run_attempt"],
            "job_id": job["id"],
            "check_id": check["id"],
            "run_sha256": domain.native_digest(run),
            "job_sha256": domain.native_digest(job),
            "check_sha256": domain.native_digest(check),
            "job_log_sha256": hashlib.sha256(data["log"].encode()).hexdigest(),
            "trusted_checkout_revision": scenario["control_sha"],
            "trusted_gate_sha256": hashlib.sha256(gate).hexdigest(),
        }
        data["rule"] = rule
        scenario["policy"]["domain_not_applicable"] = {domain.MAIN_WORKFLOW: [rule]}
        return rule

    scenario["policy"]["workflow_catalog"][domain.MAIN_WORKFLOW]["disposition"] = (
        "original-domain-not-applicable"
    )
    refresh_rule()
    data["refresh_rule"] = refresh_rule

    scenario["pull"]["created_at"] = "2026-10-23T00:00:00Z"
    data["runs"] = [run]
    data["jobs"] = {run["id"]: [job]}
    data["checks"] = {check["id"]: check}
    data["logs"] = {job["id"]: lambda: data["log"]}
    data["calls"] = []

    def api(endpoint):
        data["calls"].append(endpoint)
        root = f"repos/{domain.REPOSITORY}"
        if endpoint == root + f"/pulls/{identity['validation_pr']}":
            return copy.deepcopy(scenario["pull"])
        if "/git/commits/" in endpoint:
            return copy.deepcopy(scenario["commit"])
        if "/actions/workflows/" in endpoint:
            query = parse_qs(urlsplit(endpoint).query)
            assert "exclude_pull_requests" not in query
            rows = []
            for item in data["runs"]:
                if item["event"] == query["event"][0]:
                    row = copy.deepcopy(item)
                    prefix = f"https://api.github.com/repos/{domain.REPOSITORY}/actions/runs/{item['id']}"
                    row.update(jobs_url=prefix + "/jobs", logs_url=prefix + "/logs")
                    rows.append(row)
            return {"total_count": len(rows), "workflow_runs": rows}
        if "/actions/runs/" in endpoint:
            suffix = endpoint.split("/actions/runs/", 1)[1].split("/")
            item = next(item for item in data["runs"] if item["id"] == int(suffix[0]))
            if len(suffix) > 1:
                return copy.deepcopy(
                    data.get("attempts", {}).get((item["id"], int(suffix[2])), item)
                )
            latest = copy.deepcopy(item)
            prefix = f"https://api.github.com/repos/{domain.REPOSITORY}/actions/runs/{item['id']}"
            latest.update(jobs_url=prefix + "/jobs", logs_url=prefix + "/logs")
            return latest
        if "/check-runs/" in endpoint:
            return copy.deepcopy(data["checks"][int(endpoint.rsplit("/", 1)[1])])
        if endpoint.startswith(root + "/contents/"):
            path, _, revision = endpoint.removeprefix(root + "/contents/").partition("?ref=")
            body = (
                (ROOT / "tests/saas/resources/main-domain-merge-gate.yml").read_bytes()
                if path == domain.MAIN_WORKFLOW
                else data["gate"]
            )
            if revision not in {item["head_sha"] for item in data["runs"]} | {
                scenario["control_sha"]
            }:
                raise ValueError("native fixture revision is unavailable")
            return {
                "type": "file",
                "path": path,
                "encoding": "base64",
                "size": len(body),
                "content": base64.b64encode(body).decode(),
            }
        raise AssertionError(endpoint)

    def jobs(run_id, attempt):
        return copy.deepcopy(
            data.get("attempt_jobs", {}).get((run_id, attempt), data["jobs"][run_id])
        )

    def log(job_id, path):
        path.write_bytes(data["logs"][job_id]().encode())

    monkeypatch.setattr(domain, "api", api)
    monkeypatch.setattr(domain, "_job_pages", jobs)
    monkeypatch.setattr(domain, "download_job_log", log)
    reader = domain.discover_main_domain.__globals__
    monkeypatch.setitem(reader, "api", api)
    monkeypatch.setitem(reader, "_job_pages", jobs)
    monkeypatch.setitem(reader, "download_job_log", log)
    monkeypatch.setattr(reader["history"], "api", api)
    monkeypatch.setattr(reader["domain"], "api", api)
    monkeypatch.setitem(
        reader["verify_pr_tree"].__globals__["BASELINES"], "Core", profile["baseline_revision"]
    )
    monkeypatch.setattr(qualifier, "load_qualification_policy", lambda *_: scenario["policy"])
    return data


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("attachment", ["head", "base", "default"])
def test_native_domain_preserves_head_failure_and_rejects_unsupported_attachments(
    scenario, native_domain, tmp_path, attachment
):
    data = native_domain
    revision = {
        "head": scenario["profile"]["product_revision"],
        "base": scenario["profile"]["baseline_revision"],
        "default": "a" * 40,
    }[attachment]
    for row in (data["run"], data["job"], data["check"]):
        row["head_sha"] = revision
    data["refresh_rule"]()
    if attachment == "head":
        scenario["snapshots"]["head"]["runs"].append(data["run"])
        scenario["snapshots"]["head"]["checks"].append(data["check"])
        scenario["policy"]["other_checks"] = [
            {
                "role": "head",
                "app_id": 15368,
                "suite_id": 8802,
                "name": "evaluate",
                "scope": "original-domain-not-applicable",
                "expected_conclusion": None,
                "reason": "Frozen validation PR is outside this original main-merge guard",
            }
        ]
    result = invoke(scenario, tmp_path)
    receipt = result["all_apps"]["verified_main_domain_refusals"][0]
    assert result["status"] == "pass" and result["source_ci_pass"] is True
    assert result["complete_domain_discovery"] is True
    assert receipt["check_revision"] == revision and receipt["original_conclusion"] == "failure"
    assert receipt["technical_gate_waiver"] is False and result["exact_product_PG_pass"] is False
    assert (tmp_path / "qualified/main-domain/job-8803.log").read_bytes() == data["log"].encode()


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "main_base",
        "unknown_base",
        "catalog_hash",
        "other_workflow",
        "generic_information",
        "policy_failure",
        "technical_failure",
        "wrong_event",
        "wrong_provider",
        "wrong_suite",
        "wrong_attempt",
        "wrong_checkout",
        "wrong_source",
        "wrong_PR",
        "wrong_error",
        "extra_error",
        "executed_PG",
        "stale_hash",
        "changed_native_after",
        "changed_gate",
        "missing_rule",
        "not_triggered",
        "unobserved_governance",
    ],
)
def test_domain_rule_cannot_waive_policy_technical_unknown_or_stale_native_evidence(
    scenario, native_domain, tmp_path, monkeypatch, fault
):
    data = native_domain
    run, job, check = data["run"], data["job"], data["check"]
    if fault in {"main_base", "unknown_base"}:
        scenario["identity"]["validation_base_ref"] = "main" if fault == "main_base" else "other"
        with pytest.raises(ValueError, match="frozen validation route"):
            domain.validate_domain_rules(scenario["policy"], scenario["identity"])
        return
    if fault == "catalog_hash":
        scenario["policy"]["workflow_catalog"][domain.MAIN_WORKFLOW]["sha256"] = "0" * 64
    elif fault == "other_workflow":
        run["path"] = ".github/workflows/ci.yml"
    elif fault == "generic_information":
        scenario["policy"]["workflow_catalog"][domain.MAIN_WORKFLOW]["disposition"] = (
            "original-informational"
        )
    elif fault in {"not_triggered", "unobserved_governance"}:
        scenario["policy"]["workflow_catalog"][domain.MAIN_WORKFLOW]["disposition"] = (
            "original-not-triggered" if fault == "not_triggered" else "original-governance"
        )
    elif fault == "policy_failure":
        job["steps"][1]["conclusion"] = "success"
        job["steps"][2]["conclusion"] = "failure"
    elif fault == "technical_failure":
        job["steps"][0]["conclusion"] = "failure"
    elif fault == "executed_PG":
        job["steps"][2]["conclusion"] = "success"
    elif fault == "wrong_event":
        run["event"] = "push"
    elif fault == "wrong_provider":
        check["app"]["id"] = 999
    elif fault == "wrong_suite":
        check["check_suite"]["id"] += 1
    elif fault == "wrong_attempt":
        job["run_attempt"] += 1
    elif fault == "wrong_checkout":
        data["log"] = data["log"].replace(scenario["control_sha"], "f" * 40)
    elif fault == "wrong_source":
        data["log"] = data["log"].replace(scenario["profile"]["product_revision"], "f" * 40)
    elif fault == "wrong_PR":
        data["log"] = data["log"].replace("EVENT_PR: 9001", "EVENT_PR: 9002")
    elif fault == "wrong_error":
        data["log"] = data["log"].replace(domain._ERROR, "##[error]real technical failure")
    elif fault == "extra_error":
        data["log"] = data["log"].replace(
            domain._ERROR,
            domain._ERROR + "\n2026-10-24T15:00:30.500+00:00 ##[error]another failure",
        )
    elif fault == "changed_native_after":
        initial = domain.api
        calls = []

        def api(endpoint):
            value = initial(endpoint)
            if endpoint.endswith("/actions/runs/8001"):
                calls.append(endpoint)
                if len(calls) > 1:
                    value["run_attempt"] += 1
            return value

        monkeypatch.setattr(domain, "api", api)
        monkeypatch.setitem(domain.discover_main_domain.__globals__, "api", api)
    elif fault == "changed_gate":
        data["gate"] += b"changed\n"
    if fault not in {"stale_hash", "changed_gate", "missing_rule"}:
        data["refresh_rule"]()
    if fault == "stale_hash":
        check["conclusion"] = "success"
    if fault in {"missing_rule", "not_triggered", "unobserved_governance"}:
        scenario["policy"]["domain_not_applicable"] = {}
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_workflow_run_needs_native_trigger_PR_and_original_source_binding(
    scenario, native_domain, tmp_path
):
    data = native_domain
    for row in (data["run"], data["job"], data["check"]):
        row["head_sha"] = scenario["profile"]["product_revision"]
    data["run"]["event"] = "workflow_run"
    repository_url = f"https://api.github.com/repos/{domain.REPOSITORY}"
    pull = {
        "number": 9001,
        "url": repository_url + "/pulls/9001",
        "head": {"sha": scenario["profile"]["product_revision"], "repo": {"url": repository_url}},
        "base": {"sha": scenario["profile"]["baseline_revision"], "repo": {"url": repository_url}},
    }
    data["log"] = (
        data["log"]
        .replace("EVENT_NAME: pull_request_target", "EVENT_NAME: workflow_run")
        .replace("EVENT_PR: 9001", "EVENT_PR: ")
        .replace("EVENT_HEAD_SHA: " + scenario["profile"]["product_revision"], "EVENT_HEAD_SHA: ")
        .replace(
            "WORKFLOW_HEAD_SHA: ", "WORKFLOW_HEAD_SHA: " + scenario["profile"]["product_revision"]
        )
        .replace("WORKFLOW_PRS: null", "WORKFLOW_PRS: " + json.dumps([pull]))
    )
    data["refresh_rule"]()
    result = domain.collect_domain_eligibility(
        scenario["profile"], scenario["identity"], scenario["policy"], tmp_path / "trigger-only"
    )
    assert result.refusals[0]["original_conclusion"] == "failure"
    data["log"] = data["log"].replace(json.dumps([pull]), "[]")
    data["refresh_rule"]()
    with pytest.raises(ValueError, match="incomplete"):
        domain.collect_domain_eligibility(
            scenario["profile"],
            scenario["identity"],
            scenario["policy"],
            tmp_path / "invalid-trigger",
        )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_original_governance_cannot_be_relabelled_as_generic_information(scenario, native_domain):
    data = native_domain
    for row in (data["run"], data["job"], data["check"]):
        row["head_sha"] = scenario["profile"]["product_revision"]
    scenario["snapshots"]["head"]["runs"].append(data["run"])
    scenario["snapshots"]["head"]["checks"].append(data["check"])
    scenario["policy"]["workflow_catalog"][domain.MAIN_WORKFLOW]["disposition"] = (
        "original-governance"
    )
    scenario["policy"]["domain_not_applicable"] = {}
    scenario["policy"]["other_checks"] = [
        {
            "role": "head",
            "app_id": 15368,
            "suite_id": 8802,
            "name": "evaluate",
            "scope": "original-informational",
            "expected_conclusion": None,
            "reason": "This must not turn a policy refusal into successful source qualification",
        }
    ]
    with pytest.raises(ValueError, match="bypasses its original governance"):
        qualifier.assess_all_app_policy(
            scenario["snapshots"], scenario["observations"], scenario["policy"]
        )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_new_unregistered_head_domain_run_cannot_hide_behind_older_registered_ID(
    scenario, native_domain, tmp_path
):
    data = native_domain
    for row in (data["run"], data["job"], data["check"]):
        row["head_sha"] = scenario["profile"]["product_revision"]
    data["refresh_rule"]()
    later_run, later_check = copy.deepcopy(data["run"]), copy.deepcopy(data["check"])
    later_run.update(id=8002, check_suite_id=8805)
    later_check.update(id=8806, check_suite={"id": 8805})
    head = scenario["snapshots"]["head"]
    head["runs"].extend([data["run"], later_run])
    head["checks"].extend([data["check"], later_check])
    scenario["policy"]["other_checks"] = [
        {
            "role": "head",
            "app_id": 15368,
            "suite_id": 8802,
            "name": "evaluate",
            "scope": "original-domain-not-applicable",
            "expected_conclusion": None,
            "reason": "Older exact native domain refusal remains registered",
        }
    ]
    with pytest.raises(ValueError, match="main-domain check has no exact native refusal evidence"):
        invoke(scenario, tmp_path)
    assert not (tmp_path / "qualified/source-qualification.json").exists()
    observed = json.loads((tmp_path / "qualified/native-checks-before.json").read_text())
    assert later_run["id"] in [row["id"] for row in observed["head"]["runs"]]


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("attachment", ["base", "default"])
def test_registered_head_evidence_never_qualifies_with_undiscovered_later_domain_run(
    scenario, native_domain, tmp_path, monkeypatch, attachment
):
    data = native_domain
    head = scenario["snapshots"]["head"]
    head["runs"].append(data["run"])
    head["checks"].append(data["check"])
    scenario["policy"]["other_checks"] = [
        {
            "role": "head",
            "app_id": 15368,
            "suite_id": 8802,
            "name": "evaluate",
            "scope": "original-domain-not-applicable",
            "expected_conclusion": None,
            "reason": "Only the exact native head refusal has been registered",
        }
    ]
    later = copy.deepcopy(data["run"])
    repository_url = f"https://api.github.com/repos/{domain.REPOSITORY}"
    later.update(
        id=8002,
        event="workflow_run",
        check_suite_id=8805,
        head_sha=(
            scenario["profile"]["baseline_revision"]
            if attachment == "base"
            else scenario["control_sha"]
        ),
        pull_requests=[
            {
                "number": 9001,
                "url": repository_url + "/pulls/9001",
                "head": {
                    "sha": scenario["profile"]["product_revision"],
                    "repo": {"url": repository_url},
                },
                "base": {
                    "sha": scenario["profile"]["baseline_revision"],
                    "repo": {"url": repository_url},
                },
            }
        ],
    )
    data["runs"].append(later)
    data["refresh_rule"]()
    with pytest.raises(ValueError, match="incomplete"):
        invoke(scenario, tmp_path)
    receipt = json.loads(
        (tmp_path / "qualified/main-domain/discovery-before/domain-discovery.json").read_text()
    )
    assert later["id"] in receipt["discovered_run_ids"]
    assert receipt["complete_discovery"] is False
    assert receipt["source_ci_pass"] is False
