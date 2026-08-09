from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from saas.production.recovery import (
    canonical_record_sha256,
    load_recovery_evidence,
    validate_recovery_readiness,
)

_NOW = datetime(2026, 8, 5, 12, tzinfo=UTC)
_PRODUCT_REVISION = "a" * 40


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _policy() -> dict[str, object]:
    return json.loads(
        (_repo() / "saas/production/recovery-policy.json").read_text(encoding="utf-8")
    )


def _hash(seed: str) -> str:
    return (seed.encode("utf-8").hex() + "0" * 64)[:64]


def _record(scope: str) -> dict[str, object]:
    policy = _policy()
    boundaries = {
        name: {
            "source_hash": _hash(f"source-{name}"),
            "restore_hash": _hash(f"restore-{name}"),
        }
        for name in policy["required_isolation_boundaries"]  # type: ignore[union-attr]
    }
    record: dict[str, object] = {
        "schema_version": 1,
        "evidence_id": f"drill-{scope}-20260805",
        "evidence_kind": "production_drill",
        "drill_scope": scope,
        "tenant_id_hash": _hash("tenant") if scope == "tenant" else None,
        "started_at": "2026-08-05T08:00:00Z",
        "completed_at": "2026-08-05T08:30:00Z",
        "product_revision": _PRODUCT_REVISION,
        "revision_contract": policy["revision_contract"],
        "source": {
            "environment": "production",
            "region": "region-a",
            "failure_domains": ["az-a", "az-b"],
        },
        "backup": {
            "backup_id_hash": _hash("backup-id"),
            "manifest_sha256": _hash("manifest"),
            "wal_chain_sha256": _hash("wal"),
            "object_versions_sha256": _hash("objects"),
            "kms_key_version_hash": _hash("key"),
            "encrypted": True,
            "deletion_protected": True,
            "storage_failure_domain": "archive-c",
        },
        "isolation": {
            "shared_environment": False,
            "production_traffic_enabled_during_validation": False,
            "boundaries": boundaries,
        },
        "checks": dict.fromkeys(
            policy["required_checks"],  # type: ignore[arg-type]
            True,
        ),
        "data_class_outcomes": {
            "T0": {"achieved_rpo_seconds": 120, "achieved_rto_seconds": 1800},
            "T1": {"achieved_rpo_seconds": 300, "achieved_rto_seconds": 3600},
            "T2": {
                "achieved_rpo_mode": "latest_durable_recovery_point",
                "achieved_rto_seconds": 7200,
            },
        },
        "artifact": {
            "uri": f"s3://recovery-evidence/{scope}/report.json",
            "sha256": _hash("artifact"),
            "dsse_envelope_uri": f"s3://recovery-evidence/{scope}/report.dsse.json",
            "dsse_subject_sha256": _hash("subject"),
            "verified_workflow_identity": "spiffe://omnigent/recovery-evidence",
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
    record["record_sha256"] = canonical_record_sha256(record)
    return record


def _resign(record: dict[str, object]) -> None:
    record["record_sha256"] = canonical_record_sha256(record)


def test_empty_evidence_is_structurally_valid_but_production_blocked() -> None:
    report = validate_recovery_readiness(_repo(), _policy(), [], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["blockers"] == [
        "no current qualifying cluster recovery drill evidence",
        "no current qualifying tenant recovery drill evidence",
    ]
    assert report["metrics"] == {
        "evidence_record_count": 0,
        "qualified_scope_count": 0,
        "required_scope_count": 2,
        "violation_count": 0,
        "readiness_blocker_count": 2,
    }


def test_exact_tenant_and_cluster_drills_satisfy_the_contract() -> None:
    report = validate_recovery_readiness(
        _repo(),
        _policy(),
        [_record("tenant"), _record("cluster")],
        now=_NOW,
        expected_product_revision=_PRODUCT_REVISION,
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["violations"] == []
    assert report["blockers"] == []


def test_recovery_record_tampering_is_a_structural_failure() -> None:
    tenant = _record("tenant")
    tenant["completed_at"] = "2026-08-05T08:31:00Z"

    report = validate_recovery_readiness(_repo(), _policy(), [tenant], now=_NOW)

    assert report["status"] == "fail"
    assert any("record_sha256" in violation for violation in report["violations"])


def test_shared_boundary_and_exceeded_objectives_cannot_count_as_proof() -> None:
    tenant = _record("tenant")
    boundaries = tenant["isolation"]["boundaries"]  # type: ignore[index]
    boundaries["kms"]["restore_hash"] = boundaries["kms"]["source_hash"]  # type: ignore[index]
    tenant["data_class_outcomes"]["T0"]["achieved_rpo_seconds"] = 301  # type: ignore[index]
    _resign(tenant)

    report = validate_recovery_readiness(_repo(), _policy(), [tenant], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert "drill-tenant-20260805: isolation kms was reused" in report["blockers"]
    assert "drill-tenant-20260805: T0 RPO exceeds policy" in report["blockers"]


def test_stale_or_different_release_evidence_is_rejected_for_promotion() -> None:
    tenant = _record("tenant")
    tenant["completed_at"] = "2026-04-01T08:30:00Z"
    tenant["started_at"] = "2026-04-01T08:00:00Z"
    tenant["attestations"] = [
        {**attestation, "attested_at": "2026-04-01T09:00:00Z"}
        for attestation in tenant["attestations"]  # type: ignore[union-attr]
    ]
    _resign(tenant)

    report = validate_recovery_readiness(
        _repo(),
        _policy(),
        [tenant],
        now=_NOW,
        expected_product_revision="b" * 40,
    )

    assert "drill-tenant-20260805: recovery evidence is older than policy" in report["blockers"]
    assert (
        "drill-tenant-20260805: product revision does not match the release candidate"
        in report["blockers"]
    )


def test_policy_drift_and_unsafe_evidence_directory_fail_closed(tmp_path: Path) -> None:
    policy = copy.deepcopy(_policy())
    policy["revision_contract"]["control_plane_schema_revision"] = "stale"  # type: ignore[index]
    policy["evidence_directory"] = "../outside"

    report = validate_recovery_readiness(_repo(), policy, [], now=_NOW)

    assert report["status"] == "fail"
    assert (
        "recovery policy revision_contract must match production baseline" in report["violations"]
    )
    assert "evidence_directory must be a safe repository-relative path" in report["violations"]

    unsafe = copy.deepcopy(_policy())
    unsafe["evidence_directory"] = str(tmp_path)
    try:
        load_recovery_evidence(_repo(), unsafe)
    except ValueError as error:
        assert "escapes the repository" in str(error)
    else:
        raise AssertionError("absolute evidence directory was not rejected")
