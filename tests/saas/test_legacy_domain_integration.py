"""Only complete native discovery and exact original refusals qualify legacy."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from datetime import timedelta

import pytest

from tests.saas.test_legacy_domain_discovery import discovery, framed_log, reviewed_source_bytes
from tests.saas.test_legacy_domain_discovery import discovery_case as discovery_case
from tests.saas.test_legacy_domain_eligibility import domain
from tests.saas.test_legacy_domain_eligibility import native_domain as native_domain
from tests.saas.test_legacy_source_qualification import invoke, qualifier
from tests.saas.test_legacy_source_qualification import scenario as scenario


def refusal_log(data, scenario, event="pull_request_target", source=None):
    log = framed_log(data, scenario, event, source=source)
    start = discovery._instant(data["job"]["steps"][1]["started_at"])
    for milliseconds, body in [
        (500, domain._ERROR),
        (550, "##[error]Process completed with exit code 1."),
    ]:
        log += (start + timedelta(milliseconds=milliseconds)).isoformat() + " " + body + "\n"
    return log


def current_refusal(scenario, data, attachment="head", event="pull_request_target"):
    revision = {
        "head": scenario["profile"]["product_revision"],
        "base": scenario["profile"]["baseline_revision"],
        "default": scenario["control_sha"],
        "merge": scenario["pull"]["merge_commit_sha"],
    }[attachment]
    for row in (data["run"], data["job"], data["check"]):
        row["head_sha"] = revision
    data["run"]["event"] = event
    data["log"] = refusal_log(data, scenario, event)
    data["refresh_rule"]()
    role = "head" if attachment == "head" else "merge" if attachment == "merge" else None
    if role is not None:
        scenario["snapshots"][role]["runs"].append(data["run"])
        scenario["snapshots"][role]["checks"].append(data["check"])
        scenario["policy"]["other_checks"] = [
            {
                "role": role,
                "app_id": 15368,
                "suite_id": 8802,
                "name": "evaluate",
                "scope": "original-domain-not-applicable",
                "expected_conclusion": None,
                "reason": "Exact frozen legacy original main-domain refusal",
            }
        ]


def add_run(scenario, data, attachment, *, source=None, event="workflow_run", other_PR=None):
    run, job, check = (copy.deepcopy(data[key]) for key in ("run", "job", "check"))
    revision = (
        scenario["profile"]["baseline_revision"]
        if attachment == "base"
        else scenario["control_sha"]
    )
    run.update(id=8002, check_suite_id=8902, event=event, head_sha=revision)
    prefix = f"{discovery._REPO_URL}/actions/runs/8002/attempts/1"
    run.update(jobs_url=prefix + "/jobs", logs_url=prefix + "/logs")
    job.update(
        id=8903,
        run_id=8002,
        head_sha=revision,
        check_run_url=discovery._REPO_URL + "/check-runs/8904",
    )
    check.update(id=8904, head_sha=revision, check_suite={"id": 8902})
    log = refusal_log(data, scenario, event, source=source)
    if other_PR is not None:
        run["pull_requests"] = [
            {"number": other_PR, "url": discovery._REPO_URL + f"/pulls/{other_PR}"}
        ]
    data["runs"].append(run)
    data["jobs"][8002] = [job]
    data["checks"][8904] = check
    data["logs"][8903] = lambda: log
    return run, job, check


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("attachment", ["head", "base", "default", "merge"])
@pytest.mark.parametrize("event", ["pull_request_target", "workflow_run"])
def test_exact_typed_native_refusal_can_qualify_only_legacy_source(
    scenario, discovery_case, tmp_path, attachment, event
):
    data = discovery_case
    current_refusal(scenario, data, attachment, event)
    result = invoke(scenario, tmp_path)
    assert result["status"] == "pass" and result["source_ci_pass"] is True
    assert result["domain_qualification_kind"] == "legacy_authenticated_domain_eligibility/v2"
    assert result["complete_domain_discovery"] is True and result["domain_discovery_sha256"]
    proof = result["all_apps"]["verified_main_domain_refusals"][0]
    assert proof["kind"] == "legacy_main_domain_not_applicable/v2"
    assert proof["original_event_source_revision"] == scenario["profile"]["product_revision"]
    assert proof["attachment_revision"] == data["run"]["head_sha"]
    assert proof["trusted_checkout_revision"] == scenario["control_sha"]
    assert proof["original_conclusion"] == "failure" and proof["evaluated_PG_authority"] is False
    assert (
        result["production_admission"]
        is result["exact_product_PG_pass"]
        is result["image_admission"]
        is False
    )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "unknown-PR",
        "empty-PR-search-fallback",
        "source0",
        "cancelled",
        "skipped",
        "empty-jobs",
        "technical-failure-after-Resolve",
        "unregistered-base",
        "unregistered-default",
        "wrong-kind",
        "wrong-attachment",
        "wrong-product",
        "wrong-tree",
        "wrong-PR",
        "claimed-checkout",
        "changed-log",
        "changed-gate",
        "mutable-head-only",
        "mutable-head-old-exclusion",
        "forged-json-flag",
        "env-bypass",
        "later-run-during-refusal",
        "log-changes-during-refusal",
    ],
)
def test_incomplete_or_nonrefusal_never_qualifies(
    scenario, discovery_case, tmp_path, monkeypatch, fault
):
    data = discovery_case
    current_refusal(scenario, data, "default", "workflow_run")
    if fault == "unknown-PR":
        data["log"] = data["log"].replace('"number": 9001', '"number": 0')
    elif fault == "empty-PR-search-fallback":
        data["log"] = re.sub(r"(WORKFLOW_PRS: )\[.*?\n\]", r"\1[]", data["log"], flags=re.S)
    elif fault == "source0":
        data["log"] = data["log"].replace(
            "WORKFLOW_HEAD_SHA: " + scenario["profile"]["product_revision"], "WORKFLOW_HEAD_SHA: 0"
        )
    elif fault == "cancelled":
        data["run"]["conclusion"] = "cancelled"
    elif fault == "skipped":
        data["job"]["steps"][1]["conclusion"] = "skipped"
    elif fault == "empty-jobs":
        data["jobs"][8001] = []
    elif fault == "technical-failure-after-Resolve":
        data["job"]["steps"][1]["conclusion"] = "success"
        data["job"]["steps"][2]["conclusion"] = "failure"
    elif fault in {"unregistered-base", "unregistered-default", "env-bypass"}:
        add_run(scenario, data, "base" if fault == "unregistered-base" else "default")
        monkeypatch.setenv("ALLOW_HISTORICAL", "true")
        monkeypatch.setenv("LEGACY_ALLOW_DOMAIN", "true")
    elif fault == "mutable-head-only":
        data["run"]["pull_requests"] = [
            {
                "number": 9001,
                "url": discovery._REPO_URL + "/pulls/9001",
                "head": {"sha": scenario["profile"]["product_revision"]},
            }
        ]
        data["log"] = data["log"].replace('"number": 9001', '"number": 0')
    elif fault == "mutable-head-old-exclusion":
        data["run"]["pull_requests"] = [
            {"number": 9001, "url": discovery._REPO_URL + "/pulls/9001", "head": {"sha": "b" * 40}}
        ]
    elif fault in {"later-run-during-refusal", "log-changes-during-refusal"}:
        original = domain.verify_main_domain_refusal

        def changing(*args):
            result = original(*args)
            if fault == "later-run-during-refusal":
                add_run(scenario, data, "default")
            else:
                data["log"] += "changed\n"
            return result

        monkeypatch.setattr(domain, "verify_main_domain_refusal", changing)
    if fault not in {"changed-log", "changed-gate"}:
        data["refresh_rule"]()
    rule = data["rule"]
    if fault == "wrong-kind":
        rule["kind"] = "legacy_original_main_domain_refusal/v1"
    elif fault == "wrong-attachment":
        rule["attachment_revision"] = scenario["profile"]["product_revision"]
    elif fault == "wrong-product":
        rule["product_revision"] = "f" * 40
    elif fault == "wrong-tree":
        rule["product_tree"] = "f" * 40
    elif fault == "wrong-PR":
        rule["validation_pr"] += 1
    elif fault == "claimed-checkout":
        rule["trusted_checkout_revision"] = "f" * 40
    elif fault == "changed-log":
        data["log"] += "changed\n"
    elif fault == "changed-gate":
        data["gate"] += b"changed\n"
    elif fault == "forged-json-flag":
        rule["complete_discovery"] = True
    elif fault == "mutable-head-old-exclusion":
        rule["run_id"] = 8002
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)
    assert not (tmp_path / "qualified/source-qualification.json").exists()


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("excluded", ["authenticated-old-source", "other-PR-cancelled"])
def test_authenticated_history_keeps_original_failure_without_becoming_current_success(
    scenario, discovery_case, tmp_path, excluded
):
    data = discovery_case
    current_refusal(scenario, data, "default", "workflow_run")
    run, job, check = add_run(
        scenario,
        data,
        "default",
        source="b" * 40,
        other_PR=187 if excluded == "other-PR-cancelled" else None,
    )
    if excluded == "other-PR-cancelled":
        run["conclusion"] = "cancelled"
    else:
        job["steps"][1]["conclusion"] = "success"
        job["steps"][2]["conclusion"] = "failure"
        data["logs"][8903] = lambda: framed_log(data, scenario, "workflow_run", source="b" * 40)
    result = invoke(scenario, tmp_path)
    assert result["source_ci_pass"] is True and result["production_admission"] is False
    refusals = result["all_apps"]["verified_main_domain_refusals"]
    assert len(refusals) == 1 and refusals[0]["run_id"] == 8001
    observed = json.loads(
        (tmp_path / "qualified/main-domain/discovery-before/domain-discovery.json").read_text()
    )
    record = next(row for row in observed["records"] if row["run_id"] == 8002)
    assert record["classification"] == (
        "other-pr" if excluded == "other-PR-cancelled" else "old-source"
    )
    assert record["original_run_conclusion"] == run["conclusion"]
    assert record["technical_gate_waiver"] is False and check["conclusion"] == "failure"


def test_source_qualifier_rejects_artifact_boolean_instead_of_typed_native_proof(
    scenario, tmp_path, monkeypatch
):
    monkeypatch.setattr(
        qualifier,
        "collect_domain_eligibility",
        lambda *_: {"source_ci_pass": True, "complete_domain_discovery": True, "status": "pass"},
    )
    with pytest.raises(ValueError, match="typed native domain proof"):
        invoke(scenario, tmp_path)


def test_shared_multiline_parser_keeps_original_generic_source_parser_bytes():
    from pathlib import Path

    resource = Path(__file__).parent / "resources/native-domain-discovery-parent-hashes.json"
    expected = json.loads(resource.read_text())["saas/scripts/legacy_source_ci.py"]
    root = Path(__file__).resolve().parents[2]
    body = reviewed_source_bytes(root, "saas/scripts/legacy_source_ci.py", expected)
    assert hashlib.sha256(body).hexdigest() == (
        expected if isinstance(expected, str) else expected["combined_sha256"]
    )
    if isinstance(expected, dict):
        text = body.decode()
        functions = {
            node.name: node
            for node in ast.parse(text).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for name, digest in {
            **expected["preserved_functions"],
            **expected["approved_functions"],
        }.items():
            node = functions[name]
            function = "\n".join(text.splitlines()[node.lineno - 1 : node.end_lineno]).encode()
            assert hashlib.sha256(function).hexdigest() == digest
    assert discovery.trigger_environment is domain.native.trigger_environment


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("inconsistent_origin", [False, True])
def test_every_native_attempt_needs_its_own_exact_refusal_and_original_event(
    scenario, discovery_case, tmp_path, inconsistent_origin
):
    data = discovery_case
    current_refusal(scenario, data)
    if inconsistent_origin:
        data["log"] = refusal_log(data, scenario, source="b" * 40)
    first = copy.deepcopy(data["run"])
    rule1 = copy.deepcopy(data["refresh_rule"]())
    data["run"]["run_attempt"] = 2
    prefix = f"{discovery._REPO_URL}/actions/runs/8001/attempts/2"
    data["run"].update(jobs_url=prefix + "/jobs", logs_url=prefix + "/logs")
    second_job, second_check = copy.deepcopy(data["job"]), copy.deepcopy(data["check"])
    second_job.update(
        id=8903, run_attempt=2, check_run_url=discovery._REPO_URL + "/check-runs/8904"
    )
    second_check["id"] = 8904
    data["attempts"] = {(8001, 1): first, (8001, 2): data["run"]}
    data["attempt_jobs"] = {(8001, 1): [data["job"]], (8001, 2): [second_job]}
    data["checks"][8904] = second_check
    second_log = (
        refusal_log(data, scenario, source="c" * 40) if inconsistent_origin else data["log"]
    )
    data["logs"][8903] = lambda: second_log
    scenario["snapshots"]["head"]["checks"][-1] = second_check
    rule2 = dict(
        rule1,
        attempt=2,
        job_id=8903,
        check_id=8904,
        run_sha256=domain.native_digest(data["run"]),
        job_sha256=domain.native_digest(second_job),
        check_sha256=domain.native_digest(second_check),
        job_log_sha256=hashlib.sha256(second_log.encode()).hexdigest(),
    )
    scenario["policy"]["domain_not_applicable"][domain.MAIN_WORKFLOW] = [rule1, rule2]
    if inconsistent_origin:
        with pytest.raises(ValueError, match="incomplete"):
            invoke(scenario, tmp_path)
        observed = json.loads(
            (tmp_path / "qualified/main-domain/discovery-before/domain-discovery.json").read_text()
        )
        assert "rerun original sources or PRs differ" in observed["records"][0]["reason"]
    else:
        result = invoke(scenario, tmp_path)
        proofs = result["all_apps"]["verified_main_domain_refusals"]
        assert [(row["attempt"], row["job_id"], row["check_id"]) for row in proofs] == [
            (1, 8803, 8804),
            (2, 8903, 8904),
        ]
        assert result["source_ci_pass"] is True and result["production_admission"] is False


def test_native_request_omits_optional_flag_and_retains_real_PR_association(monkeypatch):
    from datetime import UTC, datetime
    from pathlib import Path
    from urllib.parse import parse_qs, urlsplit

    fixture = json.loads(
        (
            Path(__file__).parent / "resources/native-domain-list-pr-association-shape.json"
        ).read_text()
    )
    shapes = fixture["scenarios"]
    actual = shapes["native-get-known-boundary"]["rows"][0]
    calls = []

    def api(endpoint):
        calls.append(endpoint)
        query = parse_qs(urlsplit(endpoint).query)
        key = "explicit-false" if "exclude_pull_requests" in query else "omitted"
        rows = copy.deepcopy(shapes[key]["rows"])
        for row in rows:
            row["created_at"] = "2026-10-23T00:00:00Z"
        return {"total_count": len(rows), "workflow_runs": rows}

    monkeypatch.setattr(discovery, "api", api)
    monkeypatch.setattr(discovery.history, "api", api)
    monkeypatch.setattr(discovery, "_run_shape", lambda *_: None)
    rows = discovery._list_event(
        "workflow_run", datetime(2026, 10, 23, tzinfo=UTC), datetime(2026, 10, 25, tzinfo=UTC)
    )
    observed = next(row for row in rows if row["id"] == actual["id"])
    assert (
        discovery._pr_numbers(observed["pull_requests"])
        == discovery._pr_numbers(actual["pull_requests"])
        == [187]
    )
    assert all("exclude_pull_requests" not in urlsplit(endpoint).query for endpoint in calls)
    assert all(row["pull_requests"] == [] for row in shapes["explicit-false"]["rows"])
    assert fixture["not_original_event_source_evidence"] is True
