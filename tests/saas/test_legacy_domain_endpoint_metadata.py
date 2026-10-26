"""Portable endpoint-shape examples, not native qualification or source proofs."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tests.saas.test_legacy_domain_discovery import discovery, invoke
from tests.saas.test_legacy_domain_discovery import discovery_case as discovery_case
from tests.saas.test_legacy_domain_eligibility import native_domain as native_domain
from tests.saas.test_legacy_source_qualification import scenario as scenario

RESOURCE = Path(__file__).parent / "resources/native-domain-endpoint-metadata.json"
EXAMPLES = json.loads(RESOURCE.read_text())["examples"]


def endpoint_pair(example):
    prefix = f"{discovery._REPO_URL}/actions/runs/{example['id']}"
    latest = {
        "id": example["id"],
        "run_attempt": 1,
        "workflow_id": 343249704,
        "check_suite_id": 123,
        "head_sha": "2c5a9a45f1a576439fc9c5aa0a91022d461389ab",
        "status": "completed",
        "conclusion": example["conclusion"],
        "event": "workflow_run",
        "path": discovery.domain.MAIN_WORKFLOW,
        "pull_requests": [],
        "created_at": example["latest_created_at"],
        "updated_at": example["latest_updated_at"],
        "run_started_at": example["run_started_at"],
        "jobs_url": prefix + "/jobs",
        "logs_url": prefix + "/logs",
    }
    attempt = {
        **latest,
        "created_at": example["attempt_created_at"],
        "updated_at": example["attempt_updated_at"],
        "jobs_url": prefix + "/attempts/1/jobs",
        "logs_url": prefix + "/attempts/1/logs",
    }
    return latest, attempt


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda row: str(row["id"]))
def test_seven_original_endpoint_shapes_keep_distinct_dates_and_full_digest(example):
    latest, attempt = endpoint_pair(example)
    before = copy.deepcopy((latest, attempt))
    assert discovery.domain._latest_matches_attempt(latest, attempt) is True
    assert (latest, attempt) == before
    assert discovery.domain.native_digest(latest) != discovery.domain.native_digest(attempt)
    assert latest["conclusion"] == attempt["conclusion"] == example["conclusion"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 42),
        ("run_attempt", 2),
        ("head_sha", "b" * 40),
        ("workflow_id", 42),
        ("check_suite_id", 42),
        ("status", "in_progress"),
        ("conclusion", "success"),
        ("event", "push"),
        ("path", ".github/workflows/ci.yml"),
        ("pull_requests", [{"number": 192}]),
        ("run_started_at", "2026-10-25T20:43:43Z"),
        ("unexpected_identity", "new"),
        ("jobs_url", "https://unit.invalid/jobs"),
        ("logs_url", "https://unit.invalid/logs"),
    ],
)
def test_endpoint_metadata_compatibility_never_ignores_identity_or_terminal(field, value):
    latest, attempt = endpoint_pair(EXAMPLES[0])
    attempt[field] = value
    try:
        result = discovery.domain._latest_matches_attempt(latest, attempt)
    except ValueError:
        result = False
    assert result is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("created_at", "2026-02-30T20:43:42Z"),
        ("created_at", "2026-10-25T20:43:42+00:00"),
        ("created_at", "2099-01-01T00:00:00Z"),
        ("created_at", None),
        ("updated_at", "2026-10-25T20:43:41Z"),
        ("updated_at", "2099-01-01T00:00:00Z"),
        ("updated_at", "2026-10-25T20:44:04"),
    ],
)
def test_changed_endpoint_dates_require_valid_UTC_and_nonfuture_chronology(field, value):
    latest, attempt = endpoint_pair(EXAMPLES[0])
    attempt[field] = value
    with pytest.raises(ValueError):
        discovery.domain._latest_matches_attempt(latest, attempt)


def test_endpoint_metadata_schema_must_still_match():
    latest, attempt = endpoint_pair(EXAMPLES[0])
    del attempt["updated_at"]
    with pytest.raises(ValueError):
        discovery.domain._latest_matches_attempt(latest, attempt)


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("fault", [None, "before-listed", "future", "changed-digest"])
def test_discovery_keeps_attempt_window_and_exact_reviewed_digest(
    scenario, discovery_case, tmp_path, fault
):
    data = discovery_case
    data["run"].update(updated_at="2026-10-24T15:01:00Z", run_started_at="2026-10-24T15:00:00Z")
    attempt = copy.deepcopy(data["run"])
    attempt.update(created_at="2026-10-24T15:00:01Z", updated_at="2026-10-24T15:01:01Z")
    data["attempts"] = {(attempt["id"], 1): attempt}
    rule = data["refresh_rule"]()
    rule["run_sha256"] = discovery.domain.native_digest(attempt)
    if fault == "before-listed":
        attempt["created_at"] = "2026-10-24T14:59:59Z"
    elif fault == "future":
        attempt["created_at"] = "2099-01-01T00:00:00Z"
    elif fault == "changed-digest":
        attempt["updated_at"] = "2026-10-24T15:01:02Z"
    result = invoke(scenario, data, tmp_path, rules=[rule])
    if fault is None:
        assert result["complete_discovery"] is True
        assert result["records"][0]["attempts"][0]["run_sha256"] == rule["run_sha256"]
    else:
        assert result["complete_discovery"] is False
        assert result["blockers"]
        if fault == "changed-digest":
            assert result["changed_registered_proof_coordinates"]
    assert result["source_ci_pass"] is result["admission_enabled"] is False
