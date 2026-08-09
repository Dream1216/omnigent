from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from saas.production.slo_capacity import (
    canonical_slo_capacity_record_sha256,
    load_slo_capacity_evidence,
    validate_slo_capacity_readiness,
)

_NOW = datetime(2026, 8, 5, 12, tzinfo=UTC)
_PRODUCT_REVISION = "a" * 40
_METRICS = {
    "SLO-AUTH": ("availability_percent", 99.95, None),
    "SLO-RESOLVE": ("p99_seconds", 0.08, None),
    "SLO-ADMISSION": ("p99_seconds", 1.5, None),
    "SLO-REVOCATION": ("revocation_seconds", 0.0, 45.0),
    "SLO-OUTBOX": ("p99_seconds", 45.0, None),
    "SLO-RUN-EVENT": ("loss_count", 0.0, None),
}


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _load(name: str) -> dict[str, object]:
    return json.loads((_repo() / name).read_text(encoding="utf-8"))


def _policy() -> dict[str, object]:
    return _load("saas/production/slo-capacity-policy.json")


def _active_baseline() -> dict[str, object]:
    baseline = _load("saas/production/baseline.json")
    for slo in baseline["slos"]:  # type: ignore[union-attr]
        slo["dashboard_state"] = "active"
    return baseline


def _hash(seed: str) -> str:
    return (seed.encode("utf-8").hex() + "0" * 64)[:64]


def _record() -> dict[str, object]:
    policy = _policy()
    baseline = _active_baseline()
    services = baseline["service_catalog"]
    slos = baseline["slos"]
    record: dict[str, object] = {
        "schema_version": 1,
        "evidence_id": "slo-capacity-20260805",
        "evidence_kind": "production_slo_capacity_observation",
        "window_started_at": "2026-07-01T08:30:00Z",
        "window_completed_at": "2026-08-05T08:30:00Z",
        "product_revision": _PRODUCT_REVISION,
        "revision_contract": policy["revision_contract"],
        "production_observation": {
            "environment": "production",
            "region": "region-a",
            "failure_domains": ["az-a", "az-b"],
            "traffic_profile_sha256": _hash("traffic-profile"),
            "cardinality_snapshot_sha256": _hash("cardinality"),
            "tenant_count": 100,
            "eligible_request_count": 1_000_000,
        },
        "slo_outcomes": {
            slo["id"]: {
                "objective": slo["objective"],
                "measurement_kind": _METRICS[slo["id"]][0],
                "primary_value": _METRICS[slo["id"]][1],
                "secondary_value": _METRICS[slo["id"]][2],
                "eligible_event_count": 100_000,
                "excluded_event_count": 100,
                "error_budget_consumed_percent": 20.0,
                "max_burn_rate_1h": 1.0,
                "max_burn_rate_6h": 0.5,
                "dashboard_uri": f"https://observe.example.test/d/{slo['id'].lower()}",
                "dashboard_sha256": _hash(f"dashboard-{slo['id']}"),
                "measurement_query_sha256": _hash(f"query-{slo['id']}"),
                "alert_policy_sha256": _hash(f"alert-{slo['id']}"),
            }
            for slo in slos  # type: ignore[union-attr]
        },
        "capacity_test": {
            "environment": "isolated_production_like",
            "production_traffic_enabled": False,
            "dataset_profile_sha256": _hash("capacity-dataset"),
            "service_outcomes": {
                service["id"]: {
                    "owner": service["code_owner"],
                    "capacity_model_sha256": _hash(f"model-{service['id']}"),
                    "scenarios": {
                        scenario: {
                            "passed": True,
                            "offered_work_units": 10_000,
                            "completed_work_units": 9_900,
                            "controlled_rejections": 100,
                            "unexpected_errors": 0,
                            "max_saturation_percent": 70.0,
                            "minimum_headroom_percent": 30.0,
                            "tenant_fairness_ratio": 0.95,
                            "evidence_sha256": _hash(f"scenario-{service['id']}-{scenario}"),
                        }
                        for scenario in policy["required_capacity_scenarios"]  # type: ignore[union-attr]
                    },
                }
                for service in services  # type: ignore[union-attr]
            },
            "dimension_checks": {
                dimension: {
                    "passed": True,
                    "evidence_sha256": _hash(f"dimension-{dimension}"),
                }
                for dimension in policy["required_capacity_dimensions"]  # type: ignore[union-attr]
            },
        },
        "alert_drills": {
            alert: {
                "fired": True,
                "routed_to_oncall": True,
                "acknowledged_seconds": 120,
                "evidence_sha256": _hash(f"alert-drill-{alert}"),
            }
            for alert in policy["required_alert_drills"]  # type: ignore[union-attr]
        },
        "artifact": {
            "uri": "s3://slo-capacity-evidence/report.json",
            "sha256": _hash("artifact"),
            "immutability_receipt_sha256": _hash("object-lock-receipt"),
            "dsse_envelope_uri": "s3://slo-capacity-evidence/report.dsse.json",
            "dsse_subject_sha256": _hash("subject"),
            "verified_workflow_identity": "spiffe://omnigent/slo-capacity-evidence",
        },
        "attestations": [
            {
                "role": role,
                "actor_id_hash": _hash(f"actor-{role}"),
                "attested_at": "2026-08-05T09:00:00Z",
                "product_revision": _PRODUCT_REVISION,
            }
            for role in policy["required_attestation_roles"]  # type: ignore[union-attr]
        ],
    }
    record["record_sha256"] = canonical_slo_capacity_record_sha256(record)
    return record


def _resign(record: dict[str, object]) -> None:
    record["record_sha256"] = canonical_slo_capacity_record_sha256(record)


def test_empty_evidence_and_planned_dashboards_block_production() -> None:
    report = validate_slo_capacity_readiness(_repo(), _policy(), [], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert len(report["blockers"]) == 7
    assert "SLO-AUTH dashboard is not active in production baseline" in report["blockers"]
    assert "no current qualifying production SLO and capacity evidence" in report["blockers"]
    assert report["metrics"] == {
        "evidence_record_count": 0,
        "qualified_record_count": 0,
        "required_service_count": 7,
        "required_slo_count": 6,
        "required_capacity_scenario_count": 5,
        "violation_count": 0,
        "readiness_blocker_count": 7,
    }


def test_exact_production_slo_and_capacity_evidence_satisfies_contract() -> None:
    report = validate_slo_capacity_readiness(
        _repo(),
        _policy(),
        [_record()],
        now=_NOW,
        expected_product_revision=_PRODUCT_REVISION,
        baseline=_active_baseline(),
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["violations"] == []
    assert report["blockers"] == []


def test_a_record_cannot_replace_inactive_production_dashboards() -> None:
    report = validate_slo_capacity_readiness(_repo(), _policy(), [_record()], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["metrics"]["qualified_record_count"] == 1
    assert len(report["blockers"]) == 6
    assert all("dashboard is not active" in blocker for blocker in report["blockers"])


def test_slo_capacity_record_tampering_is_a_structural_failure() -> None:
    record = _record()
    record["window_completed_at"] = "2026-08-05T08:31:00Z"

    report = validate_slo_capacity_readiness(
        _repo(), _policy(), [record], now=_NOW, baseline=_active_baseline()
    )

    assert report["status"] == "fail"
    assert any("record_sha256" in violation for violation in report["violations"])


def test_slo_capacity_and_alert_threshold_failures_block_promotion() -> None:
    record = _record()
    slo_outcomes = record["slo_outcomes"]
    assert isinstance(slo_outcomes, dict)
    auth_outcome = slo_outcomes["SLO-AUTH"]
    assert isinstance(auth_outcome, dict)
    auth_outcome["primary_value"] = 99.8
    auth_outcome["error_budget_consumed_percent"] = 101.0
    scenario = record["capacity_test"]["service_outcomes"]["control-plane"][  # type: ignore[index]
        "scenarios"
    ]["hot_tenant"]
    scenario["max_saturation_percent"] = 90.0
    scenario["minimum_headroom_percent"] = 10.0
    scenario["tenant_fairness_ratio"] = 0.8
    alert = record["alert_drills"]["queue_age"]  # type: ignore[index]
    alert["fired"] = False
    alert["acknowledged_seconds"] = 301
    _resign(record)

    report = validate_slo_capacity_readiness(
        _repo(), _policy(), [record], now=_NOW, baseline=_active_baseline()
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("objective was missed" in blocker for blocker in report["blockers"])
    assert any("error budget is exhausted" in blocker for blocker in report["blockers"])
    assert any("saturation exceeds policy" in blocker for blocker in report["blockers"])
    assert any("headroom is below policy" in blocker for blocker in report["blockers"])
    assert any("tenant fairness is below policy" in blocker for blocker in report["blockers"])
    assert any("did not fire and route" in blocker for blocker in report["blockers"])
    assert any("acknowledgement exceeded" in blocker for blocker in report["blockers"])


def test_ci_kind_missing_service_and_raw_field_cannot_count_as_proof() -> None:
    record = _record()
    record["evidence_kind"] = "ci_benchmark"
    record["raw_tenant_id"] = "tenant-customer-visible-id"
    record["capacity_test"]["service_outcomes"].pop("runner-sandbox")  # type: ignore[index]
    _resign(record)

    report = validate_slo_capacity_readiness(
        _repo(), _policy(), [record], now=_NOW, baseline=_active_baseline()
    )

    assert report["status"] == "fail"
    assert any("evidence_kind" in violation for violation in report["violations"])
    assert any("record fields" in violation for violation in report["violations"])
    assert any("seven-service catalog" in violation for violation in report["violations"])


def test_stale_or_different_release_evidence_is_rejected() -> None:
    record = _record()
    record["window_started_at"] = "2026-05-01T08:30:00Z"
    record["window_completed_at"] = "2026-06-01T08:30:00Z"
    record["attestations"] = [
        {**attestation, "attested_at": "2026-06-01T09:00:00Z"}
        for attestation in record["attestations"]  # type: ignore[union-attr]
    ]
    _resign(record)

    report = validate_slo_capacity_readiness(
        _repo(),
        _policy(),
        [record],
        now=_NOW,
        expected_product_revision="b" * 40,
        baseline=_active_baseline(),
    )

    assert any("older than policy" in blocker for blocker in report["blockers"])
    assert any("does not match the release candidate" in blocker for blocker in report["blockers"])


def test_policy_drift_malformed_thresholds_and_unsafe_directory_fail_closed(
    tmp_path: Path,
) -> None:
    policy = copy.deepcopy(_policy())
    policy["revision_contract"]["control_plane_schema_revision"] = "stale"  # type: ignore[index]
    policy["thresholds"] = {}
    policy["evidence_directory"] = "../outside"

    report = validate_slo_capacity_readiness(
        _repo(), policy, [_record()], now=_NOW, baseline=_active_baseline()
    )

    assert report["status"] == "fail"
    assert any("revision_contract" in violation for violation in report["violations"])
    assert any("safe repository-relative" in violation for violation in report["violations"])
    assert any("threshold" in violation for violation in report["violations"])

    unsafe = copy.deepcopy(_policy())
    unsafe["evidence_directory"] = str(tmp_path)
    try:
        load_slo_capacity_evidence(_repo(), unsafe)
    except ValueError as error:
        assert "escapes the repository" in str(error)
    else:
        raise AssertionError("absolute evidence directory was not rejected")

    evidence_directory = tmp_path / "evidence"
    evidence_directory.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (evidence_directory / "escaped.json").symlink_to(outside)
    symlink_policy = copy.deepcopy(_policy())
    symlink_policy["evidence_directory"] = "evidence"
    try:
        load_slo_capacity_evidence(tmp_path, symlink_policy)
    except ValueError as error:
        assert "symbolic links" in str(error)
    else:
        raise AssertionError("symbolic-link evidence record was not rejected")


def test_duplicate_ids_and_incomplete_attestations_fail_closed() -> None:
    first = _record()
    second = copy.deepcopy(first)
    second["attestations"] = second["attestations"][:-1]  # type: ignore[index]
    _resign(second)

    report = validate_slo_capacity_readiness(
        _repo(), _policy(), [first, second], now=_NOW, baseline=_active_baseline()
    )

    assert report["status"] == "fail"
    assert "duplicate SLO capacity evidence_id slo-capacity-20260805" in report["violations"]
    assert any(
        "independent attestations are incomplete" in blocker for blocker in report["blockers"]
    )


def test_untrusted_workflow_and_reused_attestor_identity_fail_closed() -> None:
    record = _record()
    record["artifact"]["verified_workflow_identity"] = "spiffe://untrusted/job"  # type: ignore[index]
    attestations = record["attestations"]
    assert isinstance(attestations, list)
    assert isinstance(attestations[0], dict)
    assert isinstance(attestations[1], dict)
    attestations[1]["actor_id_hash"] = attestations[0]["actor_id_hash"]
    _resign(record)

    report = validate_slo_capacity_readiness(
        _repo(), _policy(), [record], now=_NOW, baseline=_active_baseline()
    )

    assert report["status"] == "fail"
    assert any("workflow identity is not trusted" in item for item in report["violations"])
    assert any("actors must be independent" in item for item in report["violations"])
