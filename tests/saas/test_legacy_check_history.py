"""Keep same-named native checks separate and reject stale green attempts."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for name in ("legacy_native_evidence", "protected_legacy_initial_build", "legacy_check_history"):
    key = "saas.scripts." + name
    if name == "legacy_native_evidence" and key in sys.modules:
        continue
    spec = importlib.util.spec_from_file_location(key, ROOT / "saas/scripts" / (name + ".py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    spec.loader.exec_module(module)
history = sys.modules["saas.scripts.legacy_check_history"]


@pytest.fixture
def native():
    data = json.loads(
        (ROOT / "tests/saas/resources/native_all_app/retained-old018-checks.json").read_text()
    )
    snapshot = {
        "revision": data["head"],
        "checks": data["checks"],
        "statuses": data["statuses"],
        "runs": data["runs"],
    }
    run = next(row for row in data["runs"] if row["id"] == 40102636888)
    return snapshot, [{"run": run, "jobs": data["actual_lint_jobs"]}]


def test_actual_native_all_app_inventory_keeps_nine_same_named_gates_and_real_failures(
    native,
):
    snapshot, observations = native
    result = history.result_inventory(snapshot)
    assert result["original_checks"] == 97 and result["original_statuses"] == 3
    assert result["original_workflow_runs"] == 26
    assert (
        len([row for row in result["latest_checks"] if row["name"] == "gate / Security Gate"]) == 9
    )
    assert {row["name"] for row in result["unresolved_checks"]} == {
        "Pytest (server-rest)",
        "build-candidate",
        "evaluate",
        "Pinned callers match tested action",
    }
    history.verify_required_job_bindings(snapshot, observations)
    assert result["complete_required_source_CI_PG_test_selection_production_admission"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "new_workflow",
        "new_attempt",
        "new_failed_check",
        "wrong_app",
        "wrong_suite",
        "wrong_name",
        "failed_run",
    ],
)
def test_current_job_binding_refuses_stale_green_or_foreign_native_identity(native, fault):
    snapshot, observations = native
    run = observations[0]["run"]
    if fault == "new_workflow":
        newer = copy.deepcopy(run)
        newer.update(
            id=run["id"] + 100000,
            check_suite_id=run["check_suite_id"] + 100000,
            status="queued",
            conclusion=None,
        )
        snapshot["runs"].append(newer)
    if fault == "new_attempt":
        selected = next(row for row in snapshot["runs"] if row["id"] == run["id"])
        selected["run_attempt"] += 1
        observations[0]["run"] = copy.deepcopy(run) | {"run_attempt": 1}
    job = observations[0]["jobs"][-1]
    check = next(row for row in snapshot["checks"] if row["id"] == job["id"])
    if fault == "new_failed_check":
        snapshot["checks"].append(
            copy.deepcopy(check) | {"id": check["id"] + 100000, "conclusion": "failure"}
        )
    if fault == "wrong_app":
        check["app"]["id"] = 555
    if fault == "wrong_suite":
        check["check_suite"]["id"] += 123
    if fault == "wrong_name":
        check["name"] = "Another check"
    if fault == "failed_run":
        run["conclusion"] = "failure"
    with pytest.raises(ValueError):
        history.verify_required_job_bindings(snapshot, observations)


def test_external_provider_and_latest_creator_are_not_hidden_by_github_green(native):
    snapshot, _ = native
    original = copy.deepcopy(snapshot["checks"][0])
    snapshot["checks"].append(
        original | {"id": original["id"] + 100000, "app": {"id": 888}, "conclusion": "failure"}
    )
    statuses = snapshot["statuses"]
    original_status = max(statuses, key=lambda row: row["id"])
    statuses.append(
        copy.deepcopy(original_status)
        | {"id": original_status["id"] + 100, "state": "error", "creator": {"id": 999}}
    )
    result = history.result_inventory(snapshot)
    assert any(row["app_id"] == 888 for row in result["unresolved_checks"])
    assert any(
        row["creator_id"] == 999 and row["state"] == "error" for row in result["latest_statuses"]
    )


@pytest.mark.parametrize("fault", [None, "duplicate", "total_drift", "partial"])
def test_complete_native_pagination_rejects_duplicates_drift_and_missing_rows(monkeypatch, fault):
    first = [{"id": index} for index in range(1, 101)]
    second = [{"id": 101}]
    pages = [
        {"total_count": 101, "check_runs": first},
        {"total_count": 101, "check_runs": second},
    ]
    if fault == "duplicate":
        pages[1]["check_runs"] = [{"id": 1}]
    if fault == "total_drift":
        pages[1]["total_count"] = 102
    if fault == "partial":
        pages[1]["check_runs"] = []
    calls = []

    def native(endpoint):
        calls.append(endpoint)
        return pages[len(calls) - 1]

    monkeypatch.setattr(history, "api", native)
    if fault:
        with pytest.raises(ValueError):
            history._pages("fixed-native-endpoint?filter=all", "check_runs")
    else:
        assert len(history._pages("fixed-native-endpoint?filter=all", "check_runs")) == 101
        assert calls[1].endswith("&per_page=100&page=2")


@pytest.mark.parametrize("fault", [None, "new_check", "changed_result", "new_attempt"])
def test_two_native_snapshots_refuse_new_or_changed_results(native, tmp_path, monkeypatch, fault):
    snapshot, _ = native
    reads = []

    def collect(revision):
        assert revision == snapshot["revision"]
        reads.append(revision)
        value = copy.deepcopy(snapshot)
        if len(reads) == 2:
            if fault == "new_check":
                value["checks"].append(copy.deepcopy(value["checks"][0]) | {"id": 999999999999})
            if fault == "changed_result":
                value["checks"][0]["conclusion"] = "failure"
            if fault == "new_attempt":
                value["runs"][0]["run_attempt"] += 1
        return value

    monkeypatch.setattr(history, "collect_snapshot", collect)
    if fault:
        with pytest.raises(ValueError, match="changed during"):
            history.collect_stable_history(snapshot["revision"], tmp_path / "observed")
        assert (tmp_path / "observed/before.json").exists() and (
            tmp_path / "observed/after.json"
        ).exists()
    else:
        result = history.collect_stable_history(snapshot["revision"], tmp_path / "observed")
        assert result["unresolved_checks"] and len(reads) == 2


def test_collect_snapshot_reads_every_provider_and_rejects_foreign_head(native, monkeypatch):
    snapshot, _ = native
    rows = copy.deepcopy(snapshot)

    def api(endpoint):
        if "/check-runs?" in endpoint:
            return {"total_count": len(rows["checks"]), "check_runs": rows["checks"]}
        if "/statuses?" in endpoint:
            return rows["statuses"]
        return {"total_count": len(rows["runs"]), "workflow_runs": rows["runs"]}

    monkeypatch.setattr(history, "api", api)
    assert len(history.collect_snapshot(snapshot["revision"])["checks"]) == 97
    rows["checks"][0]["head_sha"] = "f" * 40
    with pytest.raises(ValueError, match="another source"):
        history.collect_snapshot(snapshot["revision"])
