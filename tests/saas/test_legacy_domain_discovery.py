"""Native domain discovery remains evidence-only, including complete fixtures."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from saas.scripts import legacy_domain_discovery as discovery
from tests.saas.test_legacy_domain_eligibility import domain
from tests.saas.test_legacy_domain_eligibility import native_domain as native_domain
from tests.saas.test_legacy_source_qualification import scenario as scenario

RESOURCE = Path(__file__).parent / "resources/native-domain-workflow-prs-excerpt.json"


def framed_log(data, scenario, event="pull_request_target", number=None, source=None):
    """Extend the nearest native job fixture with runner environment framing."""
    number = number or scenario["identity"]["validation_pr"]
    source = source or scenario["profile"]["product_revision"]
    step = data["job"]["steps"][1]
    start = discovery._instant(step["started_at"])
    prefix = (
        "\n".join(
            line
            for line in data["log"].splitlines()
            if (match := discovery._STAMP.fullmatch(line)) and discovery._instant(match[1]) < start
        )
        + "\n"
    )
    pulls = [
        {
            "number": number,
            "url": f"{discovery._REPO_URL}/pulls/{number}",
            "head": {"sha": source, "repo": {"url": discovery._REPO_URL}},
            "base": {"repo": {"url": discovery._REPO_URL}},
        }
    ]
    values = {
        "REPO": discovery.REPOSITORY,
        "EVENT_NAME": event,
        "EVENT_PR": str(number) if event == "pull_request_target" else "",
        "EVENT_HEAD_SHA": source if event == "pull_request_target" else "",
        "WORKFLOW_HEAD_SHA": source if event == "workflow_run" else "",
        "WORKFLOW_PRS": json.dumps(pulls, indent=2) if event == "workflow_run" else "null",
    }
    bodies = ["##[group]Run set -euo pipefail", "shell: /usr/bin/bash -e {0}", "env:"]
    bodies += [f"  {key}: {value}" for key, value in values.items()]
    bodies += ["##[endgroup]"]
    return (
        prefix
        + "\n".join(
            (start + timedelta(milliseconds=10 * index)).isoformat() + " " + body
            for index, body in enumerate(bodies)
        )
        + "\n"
    )


@pytest.fixture
def discovery_case(scenario, native_domain, monkeypatch):
    data = native_domain
    data["run"]["created_at"] = "2026-10-24T15:00:00Z"
    scenario["pull"]["created_at"] = "2026-10-23T00:00:00Z"
    data["log"] = framed_log(data, scenario)
    data["runs"] = [data["run"]]
    data["jobs"] = {data["run"]["id"]: [data["job"]]}
    data["checks"] = {data["check"]["id"]: data["check"]}
    data["logs"] = {data["job"]["id"]: lambda: data["log"]}
    data["calls"] = []

    def latest(row):
        result = copy.deepcopy(row)
        prefix = f"{discovery._REPO_URL}/actions/runs/{row['id']}"
        result.update(jobs_url=prefix + "/jobs", logs_url=prefix + "/logs")
        return result

    def api(endpoint):
        data["calls"].append(endpoint)
        if endpoint == discovery._ROOT + f"/pulls/{scenario['identity']['validation_pr']}":
            return copy.deepcopy(scenario["pull"])
        if "/git/commits/" in endpoint:
            return copy.deepcopy(scenario["commit"])
        if "/actions/workflows/" in endpoint:
            query = parse_qs(urlsplit(endpoint).query)
            assert "exclude_pull_requests" not in query
            assert "head_sha" not in query
            rows = [latest(row) for row in data["runs"] if row["event"] == query["event"][0]]
            return {"total_count": len(rows), "workflow_runs": rows}
        if "/actions/runs/" in endpoint:
            suffix = endpoint.split("/actions/runs/", 1)[1].split("/")
            row = next(row for row in data["runs"] if row["id"] == int(suffix[0]))
            return (
                copy.deepcopy(data.get("attempts", {}).get((row["id"], int(suffix[2])), row))
                if len(suffix) > 1
                else latest(row)
            )
        if "/check-runs/" in endpoint:
            return copy.deepcopy(data["checks"][int(endpoint.rsplit("/", 1)[1])])
        if "/contents/" in endpoint:
            path, _, revision = endpoint.split("/contents/", 1)[1].partition("?ref=")
            body = (
                (Path(__file__).parent / "resources/main-domain-merge-gate.yml").read_bytes()
                if path == domain.MAIN_WORKFLOW
                else data["gate"]
            )
            assert revision in {row["head_sha"] for row in data["runs"]} | {
                scenario["control_sha"]
            }
            return {
                "path": path,
                "type": "file",
                "encoding": "base64",
                "size": len(body),
                "content": base64.b64encode(body).decode(),
            }
        raise AssertionError(endpoint)

    monkeypatch.setattr(discovery, "api", api)
    monkeypatch.setattr(discovery.history, "api", api)
    monkeypatch.setattr(discovery.domain, "api", api)
    monkeypatch.setattr(
        discovery,
        "_job_pages",
        lambda run, attempt: copy.deepcopy(
            data.get("attempt_jobs", {}).get((run, attempt), data["jobs"][run])
        ),
    )
    monkeypatch.setattr(
        discovery, "download_job_log", lambda job, path: path.write_text(data["logs"][job]())
    )
    # Earlier historical tests load several verifier module copies; each function
    # must receive this owned fixture's baseline in its own module globals.
    monkeypatch.setitem(
        discovery.verify_pr_tree.__globals__["BASELINES"],
        "Core",
        scenario["profile"]["baseline_revision"],
    )
    data["latest"] = latest
    return data


def invoke(scenario, data, tmp_path, rules=None):
    path = tmp_path / "discovery"
    path.mkdir()
    if rules is None:
        rules = [data["refresh_rule"]()]
    return discovery.discover_main_domain(scenario["profile"], scenario["identity"], rules, path)


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("event", ["pull_request_target", "workflow_run"])
@pytest.mark.parametrize("attachment", ["head", "base", "default"])
def test_complete_discovery_binds_original_event_without_enabling_admission(
    scenario, discovery_case, tmp_path, event, attachment
):
    data = discovery_case
    data["run"]["event"] = event
    source = scenario["profile"]["product_revision"]
    target = {
        "head": source,
        "base": scenario["profile"]["baseline_revision"],
        "default": "a" * 40,
    }[attachment]
    for row in (data["run"], data["job"], data["check"]):
        row["head_sha"] = target
    data["log"] = framed_log(data, scenario, event)
    # This current native API association may show a later mutable PR head.
    data["run"]["pull_requests"] = [
        {"number": 9001, "url": discovery._REPO_URL + "/pulls/9001", "head": {"sha": "b" * 40}}
    ]
    result = invoke(scenario, data, tmp_path)
    assert result["complete_discovery"] is True and result["status"] == "complete-evidence-only"
    assert (
        result["source_ci_pass"]
        is result["admission_enabled"]
        is result["domain_eligibility"]
        is False
    )
    attempt = result["records"][0]["attempts"][0]
    assert attempt["original_event_source_revision"] == source
    assert attempt["attachment_revision"] == target
    assert attempt["trusted_checkout_revision"] == scenario["control_sha"]
    assert result["technical_gate_waiver"] is False
    assert all("created=" in call for call in data["calls"] if "/actions/workflows/" in call)


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "unregistered",
        "orphaned",
        "duplicate",
        "new-default",
        "changed-PR",
        "skipped",
        "cancelled",
        "missing-log",
        "wrong-provider",
        "wrong-check-source",
        "wrong-attempt",
        "changed-native",
        "wrong-workflow-bytes",
        "no-trigger-PR",
        "contradictory-PR",
        "rerun",
        "stale-proof",
        "empty-jobs",
        "pending-run",
        "run-cancelled",
        "step-order",
        "late-native-change",
        "late-log-change",
    ],
)
def test_incomplete_or_unregistered_evidence_is_closed(
    scenario, discovery_case, tmp_path, monkeypatch, fault
):
    data = discovery_case
    rules = [data["rule"]]
    if fault == "unregistered":
        rules = []
    elif fault == "orphaned":
        rules = [dict(data["rule"], run_id=8002)]
    elif fault == "duplicate":
        rules *= 2
    elif fault == "skipped":
        data["job"]["steps"][1]["conclusion"] = "skipped"
    elif fault == "cancelled":
        data["run"]["status"] = "completed"
        data["job"]["conclusion"] = "cancelled"
    elif fault == "missing-log":
        data["logs"][data["job"]["id"]] = lambda: ""
    elif fault == "wrong-provider":
        data["check"]["app"]["id"] = 999
    elif fault == "wrong-check-source":
        data["check"]["head_sha"] = "f" * 40
    elif fault == "wrong-attempt":
        data["job"]["run_attempt"] = 2
    elif fault == "wrong-workflow-bytes":
        monkeypatch.setattr(discovery.domain, "_native_file", lambda *_: b"changed")
    elif fault == "no-trigger-PR":
        data["run"]["event"] = "workflow_run"
        data["log"] = framed_log(data, scenario, "workflow_run").replace(
            json.dumps([{"number": 9001}], indent=2), "[]"
        )
        data["log"] = data["log"].replace('"number": 9001', '"number": 0')
    elif fault == "contradictory-PR":
        data["run"]["pull_requests"] = [
            {"number": 9001, "url": discovery._REPO_URL + "/pulls/9001"}
        ]
        data["log"] = framed_log(data, scenario, number=9002)
    elif fault == "rerun":
        data["run"]["run_attempt"] = 2
    elif fault == "empty-jobs":
        data["jobs"][8001] = []
    elif fault == "pending-run":
        data["run"]["status"] = "in_progress"
    elif fault == "run-cancelled":
        data["run"]["conclusion"] = "cancelled"
    elif fault == "step-order":
        data["job"]["steps"][1]["number"] = 1
    elif fault == "late-log-change":
        calls = []

        def log_content():
            calls.append(1)
            return data["log"] if len(calls) == 1 else data["log"] + "changed\n"

        data["logs"][8803] = log_content
    elif fault in {"new-default", "changed-PR", "changed-native", "late-native-change"}:
        original = discovery.api
        counts = {}

        def changing(endpoint):
            response = original(endpoint)
            counts[endpoint] = counts.get(endpoint, 0) + 1
            if fault == "changed-native" and "/check-runs/" in endpoint and counts[endpoint] > 1:
                response["conclusion"] = "success"
            if (
                fault == "late-native-change"
                and "/check-runs/" in endpoint
                and counts[endpoint] > 2
            ):
                response["conclusion"] = "success"
            if fault == "changed-PR" and "/pulls/" in endpoint and counts[endpoint] > 1:
                response["head"]["sha"] = "f" * 40
            if (
                fault == "new-default"
                and "/actions/workflows/" in endpoint
                and counts[endpoint] > 3
            ):
                response["workflow_runs"] = []
                response["total_count"] = 0
            return response

        monkeypatch.setattr(discovery, "api", changing)
        monkeypatch.setattr(discovery.history, "api", changing)
    if fault == "duplicate":
        with pytest.raises(ValueError, match="duplicated"):
            invoke(scenario, data, tmp_path, rules)
        return
    if fault not in {"unregistered", "orphaned", "stale-proof"}:
        rules = [data["refresh_rule"]()]
    result = invoke(scenario, data, tmp_path, rules)
    assert result["status"] == "incomplete-closed" and result["complete_discovery"] is False
    assert result["blockers"] and result["source_ci_pass"] is False
    expected_reason = {
        "new-default": "discovery sets changed",
        "changed-PR": "PR changed",
        "stale-proof": "proof bytes differ",
        "late-log-change": "job log changed after",
        "late-native-change": "check changed after",
        "step-order": "step order differs",
        "run-cancelled": "no execution exemption",
        "empty-jobs": "job set differs",
    }.get(fault)
    if expected_reason:
        assert any(expected_reason in row["reason"] for row in result["blockers"])


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("attachment", ["base", "default"])
def test_new_unregistered_same_source_nonhead_run_is_discovered(
    scenario, discovery_case, tmp_path, attachment
):
    data = discovery_case
    registered = [data["refresh_rule"]()]
    run, job, check = (copy.deepcopy(data[key]) for key in ("run", "job", "check"))
    run.update(id=8002, check_suite_id=8902, event="workflow_run")
    revision = scenario["profile"]["baseline_revision"] if attachment == "base" else "a" * 40
    run["head_sha"] = job["head_sha"] = check["head_sha"] = revision
    prefix = f"{discovery._REPO_URL}/actions/runs/8002/attempts/1"
    run.update(jobs_url=prefix + "/jobs", logs_url=prefix + "/logs")
    job.update(id=8903, run_id=8002, check_run_url=discovery._REPO_URL + "/check-runs/8904")
    check.update(id=8904, check_suite={"id": 8902})
    data["runs"].append(run)
    data["jobs"][8002] = [job]
    data["checks"][8904] = check
    data["logs"][8903] = lambda: framed_log(data, scenario, "workflow_run")
    result = invoke(scenario, data, tmp_path, registered)
    assert result["discovered_run_ids"] == [8001, 8002]
    assert result["unregistered_related_coordinates"] == [(8002, 1, 8903, 8904)]
    assert result["records"][1]["classification"] == "related"
    assert result["complete_discovery"] is result["source_ci_pass"] is False


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("classification", ["other-pr", "old-source", "unknown-cancelled"])
def test_unrelated_default_failures_are_not_global_technical_gates(
    scenario, discovery_case, tmp_path, classification
):
    data = discovery_case
    if classification == "other-pr":
        data["run"]["pull_requests"] = [{"number": 185, "url": discovery._REPO_URL + "/pulls/185"}]
        data["run"]["conclusion"] = "cancelled"
    elif classification == "old-source":
        data["log"] = framed_log(data, scenario, source="a" * 40)
    else:
        data["job"]["conclusion"] = data["check"]["conclusion"] = "cancelled"
    result = invoke(scenario, data, tmp_path, rules=[])
    assert result["records"][0]["classification"] == (
        "unassignable" if classification == "unknown-cancelled" else classification
    )
    assert result["complete_discovery"] is (classification != "unknown-cancelled")
    assert result["source_ci_pass"] is result["technical_gate_waiver"] is False


def test_real_native_multiline_excerpt_preserves_original_main_source_and_stays_ineligible():
    fixture = json.loads(RESOURCE.read_text())
    environment = discovery.trigger_environment(fixture["selected_log"], fixture["step"])
    number, source = discovery.trigger_identity(environment, "workflow_run")
    assert number == 185 and source == "a3020c625fd14c083337329b2031582fd8f14161"
    assert fixture["step"]["conclusion"] == "success"  # A later technical failure is not N/A.
    with pytest.raises(ValueError, match="main-targeting"):
        domain.verify_main_domain_refusal(
            {"component": "Core"},
            {"validation_base_ref": "main"},
            {},
            {},
            {},
            {},
            fixture["selected_log"],
        )
    assert fixture["N_A_qualification"] is False and "GH_TOKEN" not in fixture["selected_log"]


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_other_PR_outcome_change_does_not_become_a_product_technical_gate(
    scenario, discovery_case, tmp_path, monkeypatch
):
    data = discovery_case
    data["run"]["pull_requests"] = [{"number": 185, "url": discovery._REPO_URL + "/pulls/185"}]
    original = discovery.api
    calls = []

    def changing(endpoint):
        response = original(endpoint)
        if "/actions/workflows/" in endpoint:
            calls.append(endpoint)
            if len(calls) > 6:
                for row in response["workflow_runs"]:
                    row["status"], row["conclusion"] = "in_progress", None
        return response

    monkeypatch.setattr(discovery, "api", changing)
    monkeypatch.setattr(discovery.history, "api", changing)
    result = invoke(scenario, data, tmp_path, rules=[])
    assert result["complete_discovery"] is True and result["stable_discovery_sets"] is True
    assert result["source_ci_pass"] is result["technical_gate_waiver"] is False
    assert result["records"][0]["original_run_conclusion"] == "failure"


@pytest.mark.parametrize(
    "fault",
    [
        "missing-end",
        "bad-json",
        "oversize-json",
        "outside-step",
        "duplicate-env",
        "stray-line",
        "missing-group",
        "skip-step",
        "cancel-step",
        "duplicate-key",
        "trailing-json",
        "second-group",
        "wrong-repository",
        "reversed-time",
        "duplicate-json-key",
        "oversize-log",
        "line-limit",
    ],
)
def test_multiline_parser_requires_native_framing_boundaries_and_size(fault):
    fixture = json.loads(RESOURCE.read_text())
    log, step = fixture["selected_log"], fixture["step"]
    if fault == "missing-end":
        log = log.rsplit("2026-10-24T14:42:59.3763618Z", 1)[0]
    elif fault == "bad-json":
        log = log.replace('"number": 185', '"number": invalid')
    elif fault == "oversize-json":
        log = log.replace('"number": 185', '"padding": "' + "x" * 65536 + '", "number": 185')
    elif fault == "outside-step":
        log = log.replace("14:42:59.3763618Z", "14:43:01.3763618Z")
    elif fault == "duplicate-env":
        log = log.replace("env:", "env:\n2026-10-24T14:42:59.3756Z env:")
    elif fault == "stray-line":
        log = log.replace("env:", "env:\nunframed")
    elif fault == "missing-group":
        log = log.replace("##[group]Run set -euo pipefail", "unframed")
    elif fault == "skip-step":
        step["conclusion"] = "skipped"
    elif fault == "cancel-step":
        step["conclusion"] = "cancelled"
    elif fault == "duplicate-key":
        log = log.replace("  REPO: ", "  EVENT_NAME: ")
    elif fault == "trailing-json":
        log = log.replace("\n]\n", "\n] trailing\n")
    elif fault == "second-group":
        log += log
    elif fault == "wrong-repository":
        log = log.replace("  REPO: Dream1216/omnigent", "  REPO: other/repository")
    elif fault == "reversed-time":
        step["started_at"] = "2026-10-24T15:00:00Z"
    elif fault == "duplicate-json-key":
        log = log.replace('"number": 185', '"number": 184, "number": 185')
    elif fault == "oversize-log":
        log += "x" * (12 * 1024 * 1024)
    elif fault == "line-limit":
        log += "\n" * 200001
    with pytest.raises(ValueError):
        discovery.trigger_environment(log, step)


@pytest.mark.parametrize(
    "fault", ["wrong-event", "missing-source", "ambiguous-PR", "empty-PR", "PR-source-swap"]
)
def test_workflow_event_identity_does_not_guess_from_current_PR_or_search(fault):
    fixture = json.loads(RESOURCE.read_text())
    environment = discovery.trigger_environment(fixture["selected_log"], fixture["step"])
    if fault == "wrong-event":
        environment["EVENT_NAME"] = "pull_request_target"
    elif fault == "missing-source":
        environment["WORKFLOW_HEAD_SHA"] = ""
    elif fault == "ambiguous-PR":
        environment["WORKFLOW_PRS"] *= 2
    elif fault == "empty-PR":
        environment["WORKFLOW_PRS"] = []
    elif fault == "PR-source-swap":
        environment["WORKFLOW_PRS"][0]["head"]["sha"] = "f" * 40
    with pytest.raises(ValueError):
        discovery.trigger_identity(environment, "workflow_run")


@pytest.mark.parametrize(
    "fault", [None, "cap-single-second", "duplicate-page", "truncated", "total-changed"]
)
def test_complete_native_pagination_partitions_search_cap_and_rejects_gaps(monkeypatch, fault):
    created = datetime(2026, 10, 23, tzinfo=UTC)
    rows = [
        {"id": index + 1, "created_at": (created + timedelta(seconds=index // 600)).isoformat()}
        for index in range(1200)
    ]
    if fault == "cap-single-second":
        for row in rows:
            row["created_at"] = created.isoformat()
    calls = []

    def api(endpoint):
        query = parse_qs(urlsplit(endpoint).query)
        window = query["created"][0]
        selected = rows
        if ".." in window:
            lower, upper = (discovery._instant(part) for part in window.split(".."))
            selected = [
                row for row in rows if lower <= discovery._instant(row["created_at"]) <= upper
            ]
        page = int(query["page"][0])
        calls.append(endpoint)
        total = len(selected)
        if fault == "total-changed" and page > 1:
            total += 1
        start = (page - 1) * 100
        if fault == "duplicate-page" and page > 1:
            start = 0
        chunk = selected[start : start + 100]
        if fault == "truncated" and page > 1:
            chunk = []
        return {"total_count": total, "workflow_runs": chunk}

    monkeypatch.setattr(discovery, "api", api)
    monkeypatch.setattr(discovery.history, "api", api)
    monkeypatch.setattr(discovery, "_run_shape", lambda *_: None)
    if fault is not None:
        with pytest.raises(ValueError):
            discovery._list_event("workflow_run", created, created + timedelta(seconds=2))
    else:
        result = discovery._list_event("workflow_run", created, created + timedelta(seconds=2))
        assert len(result) == 1200 and len({row["id"] for row in result}) == 1200
        assert any("page=6" in endpoint for endpoint in calls)
        assert all("head_sha=" not in endpoint for endpoint in calls)


def reviewed_source_bytes(root, relative, expected):
    """Restore only exact reviewed corrections before checking original guard bytes."""
    body = (root / relative).read_bytes()
    if isinstance(expected, str):
        return body
    correction = expected.get("type_and_context_correction")
    if correction is not None:
        assert hashlib.sha256(body).hexdigest() == correction["corrected_sha256"]
        for fragment in correction["inverse_fragments"]:
            before, after = fragment["before"].encode(), fragment["after"].encode()
            assert before != after and body.count(after) == 1
            body = body.replace(after, before)
    return body


def test_existing_source_qualifier_hard_closure_and_generic_parser_are_unchanged():
    parent = json.loads(
        (RESOURCE.parent / "native-domain-discovery-parent-hashes.json").read_text()
    )
    root = Path(__file__).resolve().parents[2]
    for relative, expected in parent.items():
        body = (
            (root / relative).read_bytes()
            if isinstance(expected, str)
            else reviewed_source_bytes(root, relative, expected)
        )
        if isinstance(expected, str):
            assert hashlib.sha256(body).hexdigest() == expected
            continue
        assert hashlib.sha256(body).hexdigest() == expected["combined_sha256"]
        if "retention_fragment" in expected:
            fragment = expected["retention_fragment"].encode()
            assert body.count(fragment) == 1
            restored = body.replace(
                fragment, fragment.replace(b"retention-days: 90", b"retention-days: 30")
            )
            assert hashlib.sha256(restored).hexdigest() == expected["parent_sha256"]
            continue
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


@pytest.mark.parametrize("failure", [False, True])
def test_cli_remains_nonzero_for_complete_or_failed_discovery(
    monkeypatch, tmp_path, capsys, failure
):
    import sys
    from contextlib import contextmanager

    @contextmanager
    def evidence(*_args, **_kwargs):
        yield type("Evidence", (), {"stage": ""})()

    monkeypatch.setattr(discovery, "preserve_native_evidence", evidence)
    monkeypatch.setattr(discovery, "control_context", lambda *_: None)
    monkeypatch.setattr(discovery, "load_profile", lambda *_: {})
    monkeypatch.setattr(discovery, "verify_source_delta", lambda *_: None)
    monkeypatch.setattr(discovery, "_load_contract", lambda *_: {})
    monkeypatch.setattr(
        discovery, "load_qualification_policy", lambda *_: {"domain_not_applicable": {}}
    )

    def discover(*_args):
        if failure:
            raise ValueError("native discovery is incomplete")
        return {"complete_discovery": True, "source_ci_pass": False, "admission_enabled": False}

    monkeypatch.setattr(discovery, "discover_main_domain", discover)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "discovery",
            "--control",
            str(tmp_path),
            "--product",
            str(tmp_path),
            "--component",
            "Core",
            "--control-revision",
            "a" * 40,
            "--destination",
            str(tmp_path / "cli"),
        ],
    )
    assert discovery.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["source_ci_pass"] is False
    if failure:
        assert result["status"] == "incomplete-closed" and result["complete_discovery"] is False
