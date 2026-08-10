from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saas.production.business import (
    canonical_business_record_sha256,
    load_business_evidence,
    validate_business_readiness,
)

_NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)
_PRODUCT_REVISION = "a" * 40
_POLICIES = ("commercial-policy.json", "enterprise-policy.json")


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _policy(name: str) -> dict[str, object]:
    return json.loads((_repo() / "saas/production" / name).read_text(encoding="utf-8"))


def _hash(seed: str) -> str:
    return (seed.encode("utf-8").hex() + "0" * 64)[:64]


def _record(policy_name: str) -> dict[str, object]:
    policy = _policy(policy_name)
    required_integrations = policy["required_integrations"]
    required_checks = policy["required_checks"]
    required_scenarios = policy["required_scenarios"]
    zero_metrics = policy["required_zero_metrics"]
    positive_metrics = policy["required_positive_metrics"]
    roles = policy["required_attestation_roles"]
    assert isinstance(required_integrations, dict)
    assert isinstance(required_checks, list)
    assert isinstance(required_scenarios, list)
    assert isinstance(zero_metrics, list)
    assert isinstance(positive_metrics, list)
    assert isinstance(roles, list)
    evidence_kind = str(policy["evidence_kind"])
    record: dict[str, object] = {
        "schema_version": 1,
        "evidence_id": f"{evidence_kind}-20260809",
        "evidence_kind": evidence_kind,
        "started_at": "2026-08-09T08:00:00Z",
        "completed_at": "2026-08-09T09:00:00Z",
        "product_revision": _PRODUCT_REVISION,
        "revision_contract": policy["revision_contract"],
        "environment": "production",
        "subject_hashes": [_hash("tenant-a")],
        "integrations": {
            name: {
                "provider_id_hash": _hash(f"provider-{name}"),
                "account_id_hash": _hash(f"account-{name}"),
                "environment": "production",
                "checks": dict.fromkeys(checks, True),
                "evidence_sha256": _hash(f"integration-{name}"),
            }
            for name, checks in required_integrations.items()
        },
        "checks": dict.fromkeys(required_checks, True),
        "scenarios": {
            name: {
                "result": "passed",
                "evidence_sha256": _hash(f"scenario-{name}"),
            }
            for name in required_scenarios
        },
        "metrics": {
            **dict.fromkeys(zero_metrics, 0),
            **dict.fromkeys(positive_metrics, 1),
        },
        "customer_acceptances": [
            {
                "tenant_id_hash": _hash("tenant-a"),
                "acceptance_id_hash": _hash("customer-acceptance-a"),
                "accepted_at": "2026-08-09T08:45:00Z",
                "evidence_sha256": _hash("customer-acceptance-evidence-a"),
            }
        ],
        "artifact": {
            "uri": f"s3://business-evidence/{evidence_kind}.json",
            "sha256": _hash("artifact"),
            "dsse_envelope_uri": f"s3://business-evidence/{evidence_kind}.dsse.json",
            "dsse_subject_sha256": _hash("dsse-subject"),
            "verified_workflow_identity": policy["verified_workflow_identities"][0],  # type: ignore[index]
        },
        "attestations": [
            {
                "role": role,
                "actor_id_hash": _hash(f"actor-{role}"),
                "attested_at": "2026-08-09T09:15:00Z",
                "product_revision": _PRODUCT_REVISION,
            }
            for role in roles
        ],
    }
    record["record_sha256"] = canonical_business_record_sha256(record)
    return record


def _resign(record: dict[str, object]) -> None:
    record["record_sha256"] = canonical_business_record_sha256(record)


@pytest.mark.parametrize("policy_name", _POLICIES)
def test_empty_business_evidence_is_structurally_valid_but_blocked(
    policy_name: str,
) -> None:
    policy = _policy(policy_name)
    report = validate_business_readiness(_repo(), policy, [], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["blockers"] == [f"no current qualifying {policy['evidence_kind']} evidence"]
    assert report["metrics"]["required_integration_count"] == len(
        policy["required_integrations"]
    )


@pytest.mark.parametrize("policy_name", _POLICIES)
def test_exact_production_business_evidence_satisfies_contract(
    policy_name: str,
) -> None:
    report = validate_business_readiness(
        _repo(),
        _policy(policy_name),
        [_record(policy_name)],
        now=_NOW,
        expected_product_revision=_PRODUCT_REVISION,
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["violations"] == []
    assert report["blockers"] == []


def test_sandbox_integration_cannot_replace_production_evidence() -> None:
    record = _record("commercial-policy.json")
    integrations = record["integrations"]
    assert isinstance(integrations, dict)
    assert isinstance(integrations["payment_processor"], dict)
    integrations["payment_processor"]["environment"] = "test"
    _resign(record)

    report = validate_business_readiness(
        _repo(), _policy("commercial-policy.json"), [record], now=_NOW
    )

    assert report["status"] == "fail"
    assert any("integration must be production" in item for item in report["violations"])


def test_failed_checks_scenarios_and_metrics_block_promotion() -> None:
    record = _record("commercial-policy.json")
    integrations = record["integrations"]
    checks = record["checks"]
    scenarios = record["scenarios"]
    metrics = record["metrics"]
    assert isinstance(integrations, dict)
    assert isinstance(integrations["provider_usage"], dict)
    assert isinstance(integrations["provider_usage"]["checks"], dict)
    assert isinstance(checks, dict)
    assert isinstance(scenarios, dict)
    assert isinstance(scenarios["unknown_provider_outcome"], dict)
    assert isinstance(metrics, dict)
    integrations["provider_usage"]["checks"]["native_receipt_recovery"] = False
    checks["provider_invoice_reconciled"] = False
    scenarios["unknown_provider_outcome"]["result"] = "failed"
    metrics["unresolved_unknown_outcome_count"] = 1
    metrics["provider_receipt_count"] = 0
    _resign(record)

    report = validate_business_readiness(
        _repo(), _policy("commercial-policy.json"), [record], now=_NOW
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("integration checks did not all pass" in item for item in report["blockers"])
    assert any("aggregate checks failed" in item for item in report["blockers"])
    assert any("scenario did not pass" in item for item in report["blockers"])
    assert any("must be zero" in item for item in report["blockers"])
    assert any("must be positive" in item for item in report["blockers"])


def test_record_tampering_and_raw_identity_fields_fail_closed() -> None:
    record = _record("enterprise-policy.json")
    record["raw_customer_domain"] = "customer.example"

    report = validate_business_readiness(
        _repo(), _policy("enterprise-policy.json"), [record], now=_NOW
    )

    assert report["status"] == "fail"
    assert any("record fields" in item for item in report["violations"])
    assert any("record_sha256" in item for item in report["violations"])


def test_policy_drift_and_symbolic_link_evidence_fail_closed(tmp_path: Path) -> None:
    policy = copy.deepcopy(_policy("commercial-policy.json"))
    revision = policy["revision_contract"]
    assert isinstance(revision, dict)
    revision["control_plane_schema_revision"] = "stale"
    policy["evidence_directory"] = "../outside"

    report = validate_business_readiness(_repo(), policy, [], now=_NOW)

    assert report["status"] == "fail"
    assert any("revision_contract" in item for item in report["violations"])
    assert any("safe repository-relative" in item for item in report["violations"])

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (evidence / "escaped.json").symlink_to(outside)
    symlink_policy = copy.deepcopy(_policy("commercial-policy.json"))
    symlink_policy["evidence_directory"] = "evidence"
    try:
        load_business_evidence(tmp_path, symlink_policy)
    except ValueError as error:
        assert "symbolic links" in str(error)
    else:
        raise AssertionError("symbolic-link business evidence was not rejected")


def test_untrusted_workflow_and_reused_attestor_fail_closed() -> None:
    record = _record("enterprise-policy.json")
    artifact = record["artifact"]
    attestations = record["attestations"]
    assert isinstance(artifact, dict)
    assert isinstance(attestations, list)
    assert isinstance(attestations[0], dict)
    assert isinstance(attestations[1], dict)
    artifact["verified_workflow_identity"] = "spiffe://untrusted/workflow"
    attestations[1]["actor_id_hash"] = attestations[0]["actor_id_hash"]
    _resign(record)

    report = validate_business_readiness(
        _repo(), _policy("enterprise-policy.json"), [record], now=_NOW
    )

    assert report["status"] == "fail"
    assert any("workflow identity is not trusted" in item for item in report["violations"])
    assert any("actors must be distinct" in item for item in report["violations"])
