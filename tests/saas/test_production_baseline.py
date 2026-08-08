from __future__ import annotations

import copy
import json
from pathlib import Path

from saas.scripts.check_production_baseline import validate_baseline


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _baseline() -> dict[str, object]:
    return json.loads((_repo() / "saas/production/baseline.json").read_text(encoding="utf-8"))


def test_production_baseline_is_complete_content_but_not_falsely_ready() -> None:
    report = validate_baseline(_repo(), _baseline())

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["metrics"] == {
        "adr_count": 11,
        "service_count": 7,
        "slo_count": 6,
        "data_class_count": 3,
        "threat_count": 12,
        "readiness_blocker_count": 10,
    }
    assert "ADR-001 is not accepted" not in report["blockers"]
    assert "T0 RPO/RTO is not business-approved" in report["blockers"]
    assert (
        "no immutable tenant or regional recovery drill evidence is recorded" in report["blockers"]
    )


def test_production_baseline_rejects_missing_ownership_and_threat_coverage() -> None:
    baseline = copy.deepcopy(_baseline())
    baseline["service_catalog"][0]["code_owner"] = "all teams"  # type: ignore[index]
    baseline["threat_model"]["threats"][0]["stride"] = "T"  # type: ignore[index]

    report = validate_baseline(_repo(), baseline)

    assert "control-plane.code_owner must be a stable role identifier" in report["violations"]
    assert "threat model must cover every STRIDE category" in report["violations"]


def test_production_baseline_rejects_revision_drift() -> None:
    baseline = copy.deepcopy(_baseline())
    baseline["revision_contract"]["control_plane_schema_revision"] = "stale"  # type: ignore[index]

    report = validate_baseline(_repo(), baseline)

    assert any(
        violation.startswith("control_plane_schema_revision must be the only migration head")
        for violation in report["violations"]
    )
