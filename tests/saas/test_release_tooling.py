"""Official database readiness fails before image work without widening exceptions."""

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from saas.scripts.check_release_tooling import check_database
from saas.scripts.scan_oci_candidates import TEMPORARY_DATABASE_AGE

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 9, 20, tzinfo=UTC)


@pytest.fixture
def policy_repo(tmp_path):
    for relative in (
        "saas/supply_chain/release-policy.json",
        TEMPORARY_DATABASE_AGE["approval_path"],
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    return tmp_path


@pytest.mark.parametrize(
    "fault,passed",
    [
        ("fresh", True),
        ("new-product-stale", False),
        ("registered-product", True),
        ("wrong-tree", False),
        ("expired", False),
        ("future", False),
        ("inactive", False),
        ("schema", False),
        ("timestamp", False),
        ("approval", False),
        ("checksum", False),
        ("archive", False),
    ],
)
def test_precheck_binds_finite_age_to_exact_existing_source_and_approval(
    policy_repo, fault, passed
):
    revision, tree = next(iter(TEMPORARY_DATABASE_AGE["products"].items()))
    latest = {
        "status": "active",
        "built": TEMPORARY_DATABASE_AGE["built"],
        "schemaVersion": TEMPORARY_DATABASE_AGE["schemaVersion"],
        "path": TEMPORARY_DATABASE_AGE["archive_URL"],
        "checksum": "sha256:" + TEMPORARY_DATABASE_AGE["archive_SHA256"],
    }
    now = NOW
    if fault == "fresh":
        revision = "a" * 40
        latest["built"] = (NOW - timedelta(hours=12)).isoformat()
    elif fault == "new-product-stale":
        revision = "a" * 40
    elif fault == "wrong-tree":
        tree = "b" * 40
    elif fault == "expired":
        now += timedelta(days=1)
    elif fault == "future":
        latest["built"] = (NOW + timedelta(hours=1)).isoformat()
    elif fault == "inactive":
        latest["status"] = "inactive"
    elif fault == "schema":
        latest["schemaVersion"] = "v7.0"
    elif fault == "timestamp":
        latest["built"] = "invalid"
    elif fault == "approval":
        (policy_repo / TEMPORARY_DATABASE_AGE["approval_path"]).write_text("{}")
    elif fault == "checksum":
        latest["checksum"] = "missing"
    elif fault == "archive":
        del latest["path"]
    result = check_database(policy_repo, revision=revision, tree=tree, latest=latest, now=now)
    assert (result["status"] == "pass") is passed
    assert bool(result["violations"]) is not passed
    assert result["production_authority"] is False
    assert result["actual_oci_subject_scan_required"] is True
    assert result["registered_finite_subject_precheck"] is (fault == "registered-product")


def test_external_precheck_blocks_all_builds_and_retains_the_failure():
    workflow = yaml.safe_load((ROOT / ".github/workflows/saas-image-candidate.yml").read_text())
    preflight = workflow["jobs"]["verify-candidate-preflight"]
    step = next(s for s in preflight["steps"] if "gate --stage tooling" in s.get("run", ""))
    assert not {"if", "continue-on-error"} & step.keys()
    assert "verify-candidate-preflight" in workflow["jobs"]["build-server-preflight"]["needs"]
    retained = next(
        s for s in preflight["steps"] if s.get("name") == "Retain external tooling readiness"
    )
    assert retained["if"] == "always()"
    assert retained["with"]["path"] == "artifacts/release-tooling.json"
    settings = json.loads((ROOT / ".github/release-pipeline.json").read_text())
    assert settings["gates"]["tooling"] == ["check_release_tooling"]
