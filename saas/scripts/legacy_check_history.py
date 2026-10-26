"""Observe all native check providers and bind source jobs to latest attempts.

This module does not infer which original workflows or tests are required. The
reviewed source-CI contract supplies that inventory; unknown and failed records
remain visible and cannot become an implicit release pass.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from saas.scripts.legacy_native_evidence import api
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import REPOSITORY

GITHUB_ACTIONS_APP_ID = 15368


def _pages(endpoint: str, field: str | None) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    expected_total = None
    for number in range(1, 102):
        joiner = "&" if "?" in endpoint else "?"
        payload = api(f"{endpoint}{joiner}per_page=100&page={number}")
        if field is None:
            rows = payload
        else:
            require(
                isinstance(payload, dict)
                and type(payload.get("total_count")) is int
                and 0 <= payload["total_count"] <= 10000,
                "native check history total is invalid",
            )
            total = payload["total_count"]
            require(
                expected_total is None or expected_total == total,
                "native check history changed during pagination",
            )
            expected_total = total
            rows = payload.get(field)
        require(
            isinstance(rows, list)
            and len(rows) <= 100
            and all(
                isinstance(row, dict) and type(row.get("id")) is int and row["id"] > 0
                for row in rows
            ),
            "native check history page is malformed",
        )
        rows = cast(list[dict[str, Any]], rows)
        result.extend(rows)
        ids = [row["id"] for row in result]
        require(
            len(ids) == len(set(ids)) and len(ids) <= 10000,
            "native check history has duplicate or excess records",
        )
        if len(rows) < 100:
            require(
                expected_total is None or len(result) == expected_total,
                "native check history pagination is incomplete",
            )
            return result
        if expected_total is not None and len(result) == expected_total:
            return result
    raise ValueError("native check history pagination limit exceeded")


def collect_snapshot(revision: str) -> dict[str, Any]:
    require(
        isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
        "native check history requires a complete source SHA",
    )
    prefix = f"repos/{REPOSITORY}"
    checks = _pages(f"{prefix}/commits/{revision}/check-runs?filter=all", "check_runs")
    statuses = _pages(f"{prefix}/commits/{revision}/statuses", None)
    runs = _pages(f"{prefix}/actions/runs?head_sha={revision}", "workflow_runs")
    require(
        all(row.get("head_sha") == revision for row in [*checks, *runs]),
        "native check history contains another source revision",
    )
    status_url = f"https://api.github.com/repos/{REPOSITORY}/statuses/{revision}"
    require(
        all(row.get("url") == status_url for row in statuses),
        "native commit status belongs to another source",
    )
    return {"revision": revision, "checks": checks, "statuses": statuses, "runs": runs}


def _run_key(row: dict[str, Any]) -> tuple[Any, ...]:
    require(
        type(row.get("workflow_id")) is int
        and row["workflow_id"] > 0
        and isinstance(row.get("path"), str)
        and isinstance(row.get("event"), str),
        "native workflow identity is missing",
    )
    pulls = row.get("pull_requests")
    require(
        isinstance(pulls, list)
        and all(
            isinstance(pull, dict) and type(pull.get("number")) is int and pull["number"] > 0
            for pull in pulls
        ),
        "native workflow PR associations are malformed",
    )
    pulls = cast(list[dict[str, Any]], pulls)
    numbers = [pull["number"] for pull in pulls]
    require(len(numbers) == len(set(numbers)), "native workflow repeats its PR association")
    return row["workflow_id"], row["path"], row["event"], tuple(sorted(numbers))


def latest_workflow_runs(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    selected: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in snapshot["runs"]:
        require(
            row.get("head_sha") == snapshot["revision"]
            and type(row.get("run_attempt")) is int
            and row["run_attempt"] > 0,
            "native workflow source or attempt differs",
        )
        key = _run_key(row)
        if key not in selected or row["id"] > selected[key]["id"]:
            selected[key] = row
    return sorted(selected.values(), key=lambda row: row["id"])


def latest_check_runs(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Never collapse same-named jobs from separate workflow suites or Apps."""
    latest_suites = {row["check_suite_id"] for row in latest_workflow_runs(snapshot)}
    all_action_suites = {row["check_suite_id"] for row in snapshot["runs"]}
    selected: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in snapshot["checks"]:
        app, suite = row.get("app", {}), row.get("check_suite", {})
        require(
            type(app.get("id")) is int
            and app["id"] > 0
            and type(suite.get("id")) is int
            and suite["id"] > 0
            and isinstance(row.get("name"), str)
            and bool(row["name"])
            and row.get("head_sha") == snapshot["revision"],
            "native check provider, suite, name or source is missing",
        )
        if (
            app["id"] == GITHUB_ACTIONS_APP_ID
            and suite["id"] in all_action_suites
            and suite["id"] not in latest_suites
        ):
            continue
        key = app["id"], suite["id"], row["name"]
        if key not in selected or row["id"] > selected[key]["id"]:
            selected[key] = row
    return sorted(selected.values(), key=lambda row: row["id"])


def latest_statuses(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for row in snapshot["statuses"]:
        context = row.get("context")
        require(
            isinstance(context, str)
            and bool(context)
            and type(row.get("creator", {}).get("id")) is int
            and row["creator"]["id"] > 0,
            "native status provider or context is missing",
        )
        # Keep the actual latest creator; a different App cannot mask an older
        # trusted result by being silently merged into its identity.
        if context not in selected or row["id"] > selected[context]["id"]:
            selected[context] = row
    return sorted(selected.values(), key=lambda row: row["id"])


def verify_required_job_bindings(
    snapshot: dict[str, Any], observations: list[dict[str, Any]]
) -> None:
    """Cross-bind the source reader's jobs to native checks and latest runs."""
    require(bool(observations), "no required original source workflows supplied")
    latest_runs = {row["id"]: row for row in latest_workflow_runs(snapshot)}
    checks = {row["id"]: row for row in latest_check_runs(snapshot)}
    for observation in observations:
        run = observation["run"]
        current = latest_runs.get(run["id"])
        require(
            current is not None
            and all(
                current.get(key) == run.get(key)
                for key in (
                    "run_attempt",
                    "head_sha",
                    "path",
                    "event",
                    "workflow_id",
                    "check_suite_id",
                )
            )
            and current.get("status") == "completed"
            and current.get("conclusion") == "success",
            "required source workflow is not its latest successful native execution",
        )
        current = cast(dict[str, Any], current)
        for job in observation["jobs"]:
            link = job.get("check_run_url", "")
            pattern = rf"https://api\.github\.com/repos/{REPOSITORY}/check-runs/([0-9]+)"
            match = re.fullmatch(pattern, link)
            require(match is not None, "native job check-run identity is missing")
            match = cast(re.Match[str], match)
            check = checks.get(int(match.group(1)))
            require(
                check is not None
                and check["app"]["id"] == GITHUB_ACTIONS_APP_ID
                and check["check_suite"]["id"] == current["check_suite_id"]
                and check["name"] == job["name"]
                and check["head_sha"] == job["head_sha"] == snapshot["revision"]
                and check["status"] == job["status"] == "completed"
                and check["conclusion"] == job["conclusion"],
                "required source job is not its latest same-provider native check",
            )


def result_inventory(snapshot: dict[str, Any]) -> dict[str, Any]:
    checks, statuses, runs = (
        latest_check_runs(snapshot),
        latest_statuses(snapshot),
        latest_workflow_runs(snapshot),
    )

    def compact_check(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "app_id": row["app"]["id"],
            "suite_id": row["check_suite"]["id"],
            "name": row["name"],
            "status": row["status"],
            "conclusion": row.get("conclusion"),
        }

    return {
        "revision": snapshot["revision"],
        "original_checks": len(snapshot["checks"]),
        "original_statuses": len(snapshot["statuses"]),
        "original_workflow_runs": len(snapshot["runs"]),
        "latest_checks": [compact_check(row) for row in checks],
        "latest_statuses": [
            {
                "id": row["id"],
                "context": row["context"],
                "state": row["state"],
                "creator_id": row["creator"]["id"],
            }
            for row in statuses
        ],
        "unresolved_checks": [
            compact_check(row)
            for row in checks
            if row["status"] != "completed"
            or row.get("conclusion") not in {"success", "skipped", "neutral"}
        ],
        "non_success_statuses": [row["id"] for row in statuses if row["state"] != "success"],
        "latest_run_ids": [row["id"] for row in runs],
        "complete_required_source_CI_PG_test_selection_production_admission": False,
        "conditional_and_neutral_records_are_not_technical_passes": True,
    }


def _stable_projection(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "revision": snapshot["revision"],
        "checks": sorted(
            (
                {
                    key: row.get(key)
                    for key in (
                        "id",
                        "head_sha",
                        "name",
                        "status",
                        "conclusion",
                        "check_suite",
                        "details_url",
                    )
                }
                | {"app_id": row.get("app", {}).get("id")}
                for row in snapshot["checks"]
            ),
            key=lambda row: row["id"],
        ),
        "statuses": sorted(
            (
                {
                    key: row.get(key)
                    for key in (
                        "id",
                        "context",
                        "state",
                        "target_url",
                        "created_at",
                        "updated_at",
                    )
                }
                | {"creator_id": row.get("creator", {}).get("id")}
                for row in snapshot["statuses"]
            ),
            key=lambda row: row["id"],
        ),
        "runs": sorted(
            (
                {
                    key: row.get(key)
                    for key in (
                        "id",
                        "run_attempt",
                        "head_sha",
                        "path",
                        "event",
                        "workflow_id",
                        "check_suite_id",
                        "status",
                        "conclusion",
                    )
                }
                for row in snapshot["runs"]
            ),
            key=lambda row: row["id"],
        ),
    }


def collect_stable_history(revision: str, destination: Path) -> dict[str, Any]:
    """Two authenticated reads detect added checks and newer or failed attempts."""
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = collect_snapshot(revision)
    (destination / "before.json").write_text(json.dumps(before, indent=2) + "\n")
    after = collect_snapshot(revision)
    (destination / "after.json").write_text(json.dumps(after, indent=2) + "\n")
    require(
        _stable_projection(before) == _stable_projection(after),
        "native all-App results changed during collection",
    )
    inventory = result_inventory(after)
    inventory["native_snapshot_sha256"] = hashlib.sha256(
        json.dumps(after, sort_keys=True).encode()
    ).hexdigest()
    (destination / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    return inventory
