"""Portable unit fixtures for bounded native audit types; no native CI credit."""

from __future__ import annotations

import copy
import io
import json
import zipfile
from pathlib import Path

import pytest

from saas.scripts import legacy_domain_non_execution as audit
from tests.saas.test_legacy_unattributed_zero_execution import (
    audit_case as audit_case,
)
from tests.saas.test_legacy_unattributed_zero_execution import (
    discovery,
    domain,
    invoke,
)
from tests.saas.test_legacy_unattributed_zero_execution import (
    discovery_case as discovery_case,
)
from tests.saas.test_legacy_unattributed_zero_execution import (
    native_domain as native_domain,
)
from tests.saas.test_legacy_unattributed_zero_execution import (
    scenario as scenario,
)
from tests.saas.test_legacy_unattributed_zero_execution import (
    unattributed_case as unattributed_case,
)

SCHEMAS = json.loads(
    (Path(__file__).parent / "resources/native-bootstrap-audit-unit-schemas.json").read_text()
)
STAMP = "2026-10-24T15:00:00.1000000Z "


def zip_members(members):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        for name, text in members.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0
            archive.writestr(info, text.encode())
            archive.filelist[-1].external_attr = 0
    return raw.getvalue()


def unit_members(schema, runner):
    return {
        name: "\n".join(
            STAMP
            + body.replace("WORKER_UUID", "11111111-2222-3333-4444-555555555555")
            .replace("TEMP_UUID", "11111111-2222-3333-4444-555555555555")
            .replace("RUNNER_NAME", runner)
            for body in bodies
        )
        + ("\n" if name == "0_evaluate.txt" else "")
        for name, bodies in SCHEMAS[schema]["members"].items()
    }


@pytest.fixture
def native_audit_case(scenario, discovery_case, unattributed_case, monkeypatch):
    case = unattributed_case
    run, job, check = (case[k] for k in ("run", "job", "check"))
    run["run_started_at"] = run["created_at"]
    job.update(started_at=run["created_at"], completed_at="2026-10-24T15:00:02Z")
    suite = {
        "id": run["check_suite_id"],
        "url": f"{discovery._REPO_URL}/check-suites/{run['check_suite_id']}",
        "repository": {"full_name": discovery.REPOSITORY},
        "app": {"id": 15368},
        "head_sha": run["head_sha"],
        "status": "completed",
        "conclusion": "cancelled",
        "pull_requests": [],
        "latest_check_runs_count": 0,
    }
    suite["check_runs_url"] = suite["url"] + "/check-runs"
    case.update(suite=suite, checks={"total_count": 0, "check_runs": []})
    prior = discovery.api

    def api(endpoint):
        if endpoint == f"{discovery._ROOT}/check-suites/{run['check_suite_id']}":
            return copy.deepcopy(case["suite"])
        if endpoint == (
            f"{discovery._ROOT}/check-suites/{run['check_suite_id']}/check-runs"
            "?filter=all&per_page=100&page=1"
        ):
            return copy.deepcopy(case["checks"])
        if (
            endpoint
            == f"{discovery._ROOT}/actions/runs/{run['id']}/attempts/1/jobs?per_page=100&page=1"
        ):
            jobs = discovery_case["jobs"][run["id"]]
            return copy.deepcopy({"total_count": len(jobs), "jobs": jobs})
        if (
            endpoint
            == f"{discovery._ROOT}/check-runs/{check['id']}/annotations?per_page=100&page=1"
        ):
            return copy.deepcopy(case["annotations"])
        return prior(endpoint)

    case["download_bounds"] = []

    def bounded_transport(run_id, attempt, path, bound):
        assert (run_id, attempt) == (run["id"], run["run_attempt"])
        case["download_bounds"].append(bound)
        assert len(case["logs"]) <= bound
        path.write_bytes(case["logs"])

    monkeypatch.setattr(audit, "_download_run_logs", bounded_transport)
    monkeypatch.setattr(discovery, "api", api)
    monkeypatch.setattr(audit, "api", api)
    monkeypatch.setattr(audit.native, "api", api)
    return case


def make_bootstrap(scenario, case, schema):
    policy = {**case["unattributed_policy"], "kind": audit.BOOTSTRAP_POLICY_KIND}
    scenario["policy"]["domain_unattributed_bootstrap_cancellation"] = {
        domain.MAIN_WORKFLOW: policy
    }
    case["bootstrap_policy"] = policy
    job = case["job"]
    job.update(
        runner_id=12345, runner_name="GitHub Actions 12345", runner_group_name="GitHub Actions"
    )
    shape = SCHEMAS[schema]["shape"]
    steps = (
        audit._INFRASTRUCTURE_STEPS if shape == "checkout" else ((1, "Set up job", "cancelled"),)
    )
    job["steps"] = [
        {
            "number": n,
            "name": name,
            "status": "completed",
            "conclusion": result,
            "started_at": job["started_at"],
            "completed_at": job["completed_at"],
        }
        for n, name, result in steps
    ]
    line = audit._BOOTSTRAP_SCHEMAS[schema]["operation_annotation_line"]
    message = case["annotations"][0]["message"]
    case["annotations"] = [
        audit._annotation(case["run"], "failure", message),
        audit._annotation(case["run"], "failure", "The operation was canceled.", line),
        audit._annotation(case["run"], "notice", audit._UBUNTU26_NOTICE),
    ]
    case["check"]["output"]["annotations_count"] = 3
    case["members"] = unit_members(schema, job["runner_name"])
    case["logs"] = zip_members(case["members"])


def verify_bootstrap(scenario, c):
    return audit.verify_bootstrap_cancellation(
        scenario["profile"],
        scenario["identity"],
        c["bootstrap_policy"],
        c["run"],
        c["job"],
        c["check"],
        c["annotations"],
        c["logs"],
    )


def no_job(scenario, case, data):
    data["jobs"][case["run"]["id"]] = []
    return audit.verify_no_job_execution(
        scenario["profile"],
        scenario["identity"],
        case["unattributed_policy"],
        case["run"],
        {"total_count": 0, "jobs": []},
        case["suite"],
        case["checks"],
        case["logs"],
    )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("schema", ["no-job", *SCHEMAS])
def test_full_reader_distinguishes_empty_native_set_and_assigned_bootstrap(
    scenario,
    discovery_case,
    native_audit_case,
    tmp_path,
    schema,
):
    case = native_audit_case
    if schema == "no-job":
        no_job(scenario, case, discovery_case)
        field, cls = (
            "unattributed_no_job_observations",
            audit.UnattributedNoJobExecutionObservation,
        )
    else:
        make_bootstrap(scenario, case, schema)
        field, cls = (
            "unattributed_bootstrap_observations",
            audit.UnattributedBootstrapCancellationObservation,
        )
    result = invoke(scenario, tmp_path)
    assert result["complete_domain_discovery"] is True
    if schema != "no-job":
        assert case["download_bounds"] and set(case["download_bounds"]) == {4096}
    assert result["production_admission"] is result["exact_product_PG_pass"] is False
    raw = json.loads(
        (tmp_path / "qualified/main-domain/discovery-before/domain-discovery.json").read_text()
    )
    assert (
        raw["unattributed_expected_attempts"]
        == raw["unattributed_verified_attempts"]
        == [[8002, 1]]
    )
    assert len(raw[field]) == 1 and raw["unattributed_zero_execution_observations"] == []
    row = raw[field][0]
    assert row["original_conclusion"] == "cancelled" and row["source_classification"] == "UNKNOWN"
    assert (
        row["source_proof"]
        is row["guard_refusal"]
        is row["technical_gate_waiver"]
        is row["production_admission"]
        is False
    )
    assert row["original_event_source_revision"] is row["trusted_checkout_revision"] is None
    assert not audit.typed_observation(cls(row))
    eligibility = json.loads(
        (tmp_path / "qualified/main-domain/domain-eligibility.json").read_text()
    )
    assert (
        eligibility[field] == [row]
        and eligibility["unattributed_zero_execution_observations"] == []
    )
    assert result["all_apps"]["verified_main_domain_zero_execution"] == []


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "count",
        "job",
        "check-count",
        "check",
        "suite-count",
        "suite-app",
        "suite-head",
        "suite-id",
        "suite-url",
        "suite-status",
        "suite-PR",
        "nonempty-ZIP",
        "wrong-source",
        "wrong-base",
        "wrong-kind",
        "extra-field",
    ],
)
def test_no_job_complete_absence_requires_every_native_count_and_binding(
    scenario,
    discovery_case,
    native_audit_case,
    fault,
):
    c = native_audit_case
    jobs = {"total_count": 0, "jobs": []}
    if fault == "count":
        jobs["total_count"] = 1
    elif fault == "job":
        jobs["jobs"] = [c["job"]]
    elif fault == "check-count":
        c["checks"]["total_count"] = 1
    elif fault == "check":
        c["checks"]["check_runs"] = [c["check"]]
    elif fault == "suite-count":
        c["suite"]["latest_check_runs_count"] = 1
    elif fault == "suite-app":
        c["suite"]["app"]["id"] = 1
    elif fault == "suite-head":
        c["suite"]["head_sha"] = "f" * 40
    elif fault == "suite-id":
        c["suite"]["id"] += 1
    elif fault == "suite-url":
        c["suite"]["check_runs_url"] += "/bad"
    elif fault == "suite-status":
        c["suite"]["conclusion"] = "success"
    elif fault == "suite-PR":
        c["suite"]["pull_requests"] = [{"number": 192, "url": discovery._REPO_URL + "/pulls/192"}]
    elif fault == "nonempty-ZIP":
        c["logs"] += b"x"
    elif fault == "wrong-source":
        c["unattributed_policy"]["product_revision"] = "f" * 40
    elif fault == "wrong-base":
        c["unattributed_policy"]["validation_base_ref"] = "main"
    elif fault == "wrong-kind":
        c["unattributed_policy"]["kind"] = audit.BOOTSTRAP_POLICY_KIND
    elif fault == "extra-field":
        c["unattributed_policy"]["allow"] = True
    with pytest.raises(ValueError):
        audit.verify_no_job_execution(
            scenario["profile"],
            scenario["identity"],
            c["unattributed_policy"],
            c["run"],
            jobs,
            c["suite"],
            c["checks"],
            c["logs"],
        )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "Resolve-ran",
        "Evaluate-ran",
        "pending-ran",
        "unknown-step",
        "reordered-step",
        "runner-zero",
        "runner-name",
        "wrong-App",
        "wrong-check",
        "job-head",
        "run-success",
        "wrong-policy",
        "wrong-base",
        "unknown-annotation",
        "notice-change",
        "annotation-count",
        "annotation-order",
        "unknown-command",
        "unknown-header",
        "extra-member",
        "ZIP-trailer",
        "bare-CR",
        "unicode-newline",
        "double-BOM",
        "bad-timestamp",
        "outside-window",
        "wrong-system-runner",
        "system-terminator",
        "aggregate-no-terminator",
    ],
)
def test_bootstrap_is_a_bounded_schema_and_never_executed_governance(
    scenario,
    native_audit_case,
    fault,
):
    c = native_audit_case
    make_bootstrap(scenario, c, "checkout-before-format")
    if fault.endswith("-ran"):
        n = {"Resolve-ran": 3, "Evaluate-ran": 4, "pending-ran": 5}[fault]
        next(s for s in c["job"]["steps"] if s["number"] == n)["conclusion"] = "success"
    elif fault == "unknown-step":
        c["job"]["steps"].append(copy.deepcopy(c["job"]["steps"][0]))
    elif fault == "reordered-step":
        c["job"]["steps"].reverse()
    elif fault == "runner-zero":
        c["job"]["runner_id"] = 0
    elif fault == "runner-name":
        c["job"]["runner_name"] = "other"
    elif fault == "wrong-App":
        c["check"]["app"]["id"] = 1
    elif fault == "wrong-check":
        c["check"]["id"] += 1
    elif fault == "job-head":
        c["job"]["head_sha"] = "f" * 40
    elif fault == "run-success":
        c["run"]["conclusion"] = "success"
    elif fault == "wrong-policy":
        c["bootstrap_policy"]["kind"] = audit.UNATTRIBUTED_POLICY_KIND
    elif fault == "wrong-base":
        c["bootstrap_policy"]["validation_base_ref"] = "main"
    elif fault == "unknown-annotation":
        c["annotations"][0]["message"] += "x"
    elif fault == "notice-change":
        c["annotations"][2]["message"] += "x"
    elif fault == "annotation-count":
        c["check"]["output"]["annotations_count"] -= 1
    elif fault == "annotation-order":
        c["annotations"].reverse()
    else:
        m = c["members"]
        name = "0_evaluate.txt"
        if fault == "unknown-command":
            m[name] += STAMP + "[command]/usr/bin/git fetch\n"
        elif fault == "unknown-header":
            m[name] = m[name].replace("2.338.0", "2.338.1")
        elif fault == "extra-member":
            m["evaluate/unknown.txt"] = "x"
        elif fault == "bare-CR":
            m[name] = m[name].replace("\n", "\r", 1)
        elif fault == "unicode-newline":
            m[name] = m[name].replace("\n", "\u2028", 1)
        elif fault == "double-BOM":
            m[name] = "\ufeff\ufeff" + m[name]
        elif fault == "bad-timestamp":
            m[name] = m[name].replace("2026-", "bad-", 1)
        elif fault == "outside-window":
            m[name] = m[name].replace("15:00:00.", "16:00:00.", 1)
        elif fault == "wrong-system-runner":
            m["evaluate/system.txt"] = m["evaluate/system.txt"].replace(
                "GitHub Actions 12345", "GitHub Actions 1"
            )
        elif fault == "system-terminator":
            m["evaluate/system.txt"] += "\n"
        elif fault == "aggregate-no-terminator":
            m[name] = m[name].rstrip("\n")
        c["logs"] = zip_members(m)
        if fault == "ZIP-trailer":
            c["logs"] += b"x"
    with pytest.raises(ValueError):
        verify_bootstrap(scenario, c)


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("kind", ["no-job", "bootstrap"])
@pytest.mark.parametrize(
    "fault", ["no-policy", "no-refusal", "changed-native", "forged-JSON", "missing-proof"]
)
def test_new_audits_require_independent_current_refusal_and_full_native_rereads(
    scenario,
    discovery_case,
    native_audit_case,
    tmp_path,
    monkeypatch,
    kind,
    fault,
):
    c = native_audit_case
    if kind == "no-job":
        no_job(scenario, c, discovery_case)
        key = "domain_unattributed_zero_execution"
    else:
        make_bootstrap(scenario, c, "setup-central")
        scenario["policy"].pop("domain_unattributed_zero_execution")
        key = "domain_unattributed_bootstrap_cancellation"
    if fault == "no-policy":
        scenario["policy"].pop(key)
    elif fault == "no-refusal":
        scenario["policy"]["domain_not_applicable"] = {}
    elif fault == "changed-native":
        original = audit.collect_unattributed_audit
        count = 0

        def changed(*args):
            nonlocal count
            p = original(*args)
            count += 1
            if count > 1:
                p.receipt["run_sha256"] = "f" * 64
            return p

        monkeypatch.setattr(audit, "collect_unattributed_audit", changed)
    else:
        original = domain.discover_main_domain

        def forged(*args):
            p = original(*args)
            if fault == "forged-JSON":
                return dict(p)
            p.unattributed_observations = ()
            return p

        monkeypatch.setattr(domain, "discover_main_domain", forged)
    with pytest.raises((ValueError, AttributeError)):
        invoke(scenario, tmp_path)
    assert not (tmp_path / "qualified/source-qualification.json").exists()


def other_pr_fixture(scenario, data, case):
    # Native job/check/suite payloads are unit fixtures; no source/admission claim.
    job = case["job"]
    job.update(
        runner_id=12345, runner_name="GitHub Actions 12345", runner_group_name="GitHub Actions"
    )
    job["steps"] = [
        {
            "number": 2,
            "name": "Check out trusted gate",
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-10-24T15:00:00Z",
            "completed_at": "2026-10-24T15:00:01Z",
        },
        {
            "number": 3,
            "name": "Resolve current PR head",
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-10-24T15:00:01Z",
            "completed_at": "2026-10-24T15:00:01Z",
        },
    ]
    prefix = "2026-10-24T15:00:00.1000000Z "
    checkout = (
        "\n".join(
            prefix + x
            for x in [
                "##[group]Run actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                "[command]/usr/bin/git log -1 --format=%H",
                scenario["control_sha"],
            ]
        )
        + "\n"
    )
    pulls = [
        {
            "number": 192,
            "url": discovery._REPO_URL + "/pulls/192",
            "head": {"sha": "b" * 40, "repo": {"url": discovery._REPO_URL}},
            "base": {"repo": {"url": discovery._REPO_URL}},
        }
    ]
    bodies = [
        "##[group]Run set -euo pipefail",
        "env:",
        "  REPO: Dream1216/omnigent",
        "  EVENT_NAME: workflow_run",
        "  EVENT_PR: ",
        "  EVENT_HEAD_SHA: ",
        "  WORKFLOW_HEAD_SHA: " + "b" * 40,
        "  WORKFLOW_PRS: " + json.dumps(pulls, indent=2),
        "##[endgroup]",
    ]
    trigger = "\n".join("2026-10-24T15:00:01.1000000Z " + x for x in bodies) + "\n"
    pending = (
        "\n".join(
            "2026-10-24T15:00:01.8000000Z " + x
            for x in [
                "##[group]Run set -euo pipefail",
                "env:",
                "  REPO: Dream1216/omnigent",
                "  PR: 192",
                "##[endgroup]",
            ]
        )
        + "\n"
    )
    case.update(checkout_log=checkout, trigger_log=trigger, pending_log=pending)
    case["text"] = checkout + trigger + pending
    data["logs"][job["id"]] = lambda: case["text"]


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_other_pr_cancelled_reader_uses_original_env_amid_same_second_next_step(
    scenario,
    discovery_case,
    native_audit_case,
    tmp_path,
):
    c = native_audit_case
    other_pr_fixture(scenario, discovery_case, c)
    scenario["policy"].pop("domain_unattributed_zero_execution")
    result = invoke(scenario, tmp_path)
    assert result["complete_domain_discovery"] is True and result["production_admission"] is False
    raw = json.loads(
        (tmp_path / "qualified/main-domain/discovery-before/domain-discovery.json").read_text()
    )
    row = next(r for r in raw["records"] if r["run_id"] == 8002)
    assert row["classification"] == "other-pr"
    observed = row["attempts"][0]
    assert (
        observed["original_PR"] == 192 and observed["original_event_source_revision"] == "b" * 40
    )
    assert (
        observed["original_run_conclusion"] == observed["original_job_conclusion"] == "cancelled"
    )
    assert (
        observed["technical_gate_waiver"] is False and raw["unattributed_verified_attempts"] == []
    )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "same-PR",
        "checkout-cancelled",
        "Resolve-failed",
        "duplicate-group",
        "missing-group",
        "unterminated",
        "outside-window",
        "duplicate-key",
        "wrong-repo",
        "snapshot-mismatch",
        "wrong-App",
        "wrong-suite",
        "step-order",
        "native-suite-other-PR",
    ],
)
def test_cancelled_other_pr_requires_native_success_and_unambiguous_original_trigger(
    scenario,
    discovery_case,
    native_audit_case,
    tmp_path,
    fault,
):
    c = native_audit_case
    other_pr_fixture(scenario, discovery_case, c)
    text = c["text"]
    if fault == "same-PR":
        text = text.replace("192", str(scenario["identity"]["validation_pr"]))
    elif fault == "checkout-cancelled":
        c["job"]["steps"][0]["conclusion"] = "cancelled"
    elif fault == "Resolve-failed":
        c["job"]["steps"][1]["conclusion"] = "failure"
    elif fault == "duplicate-group":
        text += c["trigger_log"]
    elif fault == "missing-group":
        text = c["checkout_log"] + c["pending_log"]
    elif fault == "unterminated":
        text = (
            c["checkout_log"]
            + c["trigger_log"].rsplit("2026-10-24T15:00:01.1000000Z ##[endgroup]", 1)[0]
        )
    elif fault == "outside-window":
        text = text.replace("15:00:01.1000000Z", "15:01:01.1000000Z")
    elif fault == "duplicate-key":
        text = text.replace(
            "  EVENT_NAME: workflow_run",
            "  EVENT_NAME: workflow_run\n2026-10-24T15:00:01.1000000Z   EVENT_NAME: workflow_run",
        )
    elif fault == "wrong-repo":
        text = text.replace("  REPO: Dream1216/omnigent", "  REPO: other/repo")
    elif fault == "snapshot-mismatch":
        text = text.replace('"sha": "' + "b" * 40, '"sha": "' + "c" * 40)
    elif fault == "wrong-App":
        c["check"]["app"]["id"] = 1
    elif fault == "wrong-suite":
        c["suite"]["id"] += 1
    elif fault == "step-order":
        c["job"]["steps"][0]["number"] = 4
    elif fault == "native-suite-other-PR":
        c["suite"]["pull_requests"] = [{"number": 193, "url": discovery._REPO_URL + "/pulls/193"}]
    c["text"] = text
    with pytest.raises(ValueError):
        discovery._cancelled_other_pr_attempt(
            c["run"], [c["job"]], scenario["identity"]["validation_pr"], tmp_path
        )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_a_native_audit_attempt_cannot_be_hidden_by_a_later_authenticated_source(
    scenario,
    discovery_case,
    native_audit_case,
    tmp_path,
    monkeypatch,
):
    c = native_audit_case
    old_run, old_job, old_check = (copy.deepcopy(c[k]) for k in ("run", "job", "check"))
    old_job["id"] = 9905
    old_job["check_run_url"] = discovery._REPO_URL + "/check-runs/9906"
    old_check.update(
        id=9906, details_url="https://github.com/Dream1216/omnigent/actions/runs/8002/job/9905"
    )
    old_check["output"]["annotations_url"] = discovery._REPO_URL + "/check-runs/9906/annotations"
    discovery_case["checks"][9906] = old_check
    c["run"].update(
        run_attempt=2,
        jobs_url=discovery._REPO_URL + "/actions/runs/8002/attempts/2/jobs",
        logs_url=discovery._REPO_URL + "/actions/runs/8002/attempts/2/logs",
    )
    c["job"]["run_attempt"] = 2
    other_pr_fixture(scenario, discovery_case, c)
    discovery_case["attempts"] = {(8002, 1): old_run}
    prior_jobs = discovery._job_pages

    def jobs(run, attempt):
        return (
            [copy.deepcopy(old_job)] if (run, attempt) == (8002, 1) else prior_jobs(run, attempt)
        )

    monkeypatch.setattr(discovery, "_job_pages", jobs)
    prior_api = audit.api

    def api(endpoint):
        if endpoint == discovery._ROOT + "/check-runs/9906/annotations?per_page=100&page=1":
            return copy.deepcopy(c["annotations"])
        return prior_api(endpoint)

    monkeypatch.setattr(audit, "api", api)
    rules = scenario["policy"]["domain_not_applicable"][domain.MAIN_WORKFLOW]
    result = discovery.discover_main_domain(
        scenario["profile"],
        scenario["identity"],
        rules,
        tmp_path,
        unattributed_policy=c["unattributed_policy"],
    )
    assert result["complete_discovery"] is False
    assert any(
        "cannot mix with source-authenticated" in row["reason"] for row in result["blockers"]
    )
    assert result["source_ci_pass"] is result["production_admission"] is False
