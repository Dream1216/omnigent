from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from saas.scripts.check_production_baseline import _migration_heads, validate_baseline
from tests.saas._approval_history import require_current_approval_history


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _baseline() -> dict[str, object]:
    return json.loads((_repo() / "saas/production/baseline.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _full_approval_history() -> None:
    require_current_approval_history(_repo())


def test_production_baseline_is_complete_content_but_not_falsely_ready() -> None:
    baseline = _baseline()
    report = validate_baseline(_repo(), baseline)
    approved = baseline["approval"]["state"] == "approved"  # type: ignore[index]

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["metrics"] == {
        "adr_count": 11,
        "service_count": 7,
        "slo_count": 6,
        "data_class_count": 3,
        "threat_count": 12,
        "readiness_blocker_count": 10 if approved else 22,
    }
    assert ("ADR-001 is not accepted" in report["blockers"]) is not approved
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


def test_production_baseline_tracks_typed_and_untyped_alembic_revisions() -> None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(_repo() / "saas/control_plane/alembic.ini"))
    config.set_main_option("script_location", str(_repo() / "saas/control_plane/migrations"))
    assert _migration_heads(_repo()) == set(ScriptDirectory.from_config(config).get_heads())


def test_migration_graph_tracks_typed_and_untyped_revisions(tmp_path: Path) -> None:
    versions = tmp_path / "saas/control_plane/migrations/versions"
    versions.mkdir(parents=True)
    (versions / "typed.py").write_text(
        'revision: str = "first"\ndown_revision: str | None = None\n'
    )
    (versions / "untyped.py").write_text('revision = "second"\ndown_revision = "first"\n')
    assert _migration_heads(tmp_path) == {"second"}


def test_production_baseline_rejects_unrelated_approved_schema_lineage() -> None:
    baseline = copy.deepcopy(_baseline())
    baseline["approval"]["approved_control_plane_schema_revision"] = "not-a-revision"  # type: ignore[index]

    report = validate_baseline(_repo(), baseline)

    assert (
        "approved control-plane schema revision must be an ancestor of the current head"
        in report["violations"]
    )
