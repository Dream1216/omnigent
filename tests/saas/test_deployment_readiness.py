from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from saas.production.deployment import (
    canonical_deployment_record_sha256,
    load_deployment_evidence,
    validate_deployment_readiness,
)

_NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)
_PRODUCT_REVISION = "a" * 40


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _policy() -> dict[str, object]:
    return json.loads(
        (_repo() / "saas/production/deployment-policy.json").read_text(encoding="utf-8")
    )


def _hash(seed: str) -> str:
    return (seed.encode("utf-8").hex() + "0" * 64)[:64]


def _component(name: str) -> dict[str, object]:
    return {
        "desired_replicas": 2,
        "ready_replicas": 2,
        "digest_pinned_image": f"registry.example/{name}@sha256:{_hash(f'image-{name}')}",
        "placements": [
            {
                "pod_uid_hash": _hash(f"{name}-pod-a"),
                "node_uid_hash": _hash("node-a"),
                "physical_host_hash": _hash("host-a"),
                "failure_domain_hash": _hash("failure-domain-a"),
            },
            {
                "pod_uid_hash": _hash(f"{name}-pod-b"),
                "node_uid_hash": _hash("node-b"),
                "physical_host_hash": _hash("host-b"),
                "failure_domain_hash": _hash("failure-domain-b"),
            },
        ],
        "pdb_min_available": 1,
        "topology_spread_max_skew": 1,
        "anti_affinity_required": True,
        "dedicated_service_account": True,
        "host_network": False,
        "host_pid": False,
        "host_ipc": False,
        "privileged": False,
        "allow_privilege_escalation": False,
        "read_only_root_filesystem": True,
        "seccomp_profile": "RuntimeDefault",
        "dropped_capabilities": ["ALL"],
    }


def _record() -> dict[str, object]:
    policy = _policy()
    components = policy["required_components"]
    network_controls = policy["required_network_controls"]
    drills = policy["required_drills"]
    roles = policy["required_attestation_roles"]
    assert isinstance(components, dict)
    assert isinstance(network_controls, list)
    assert isinstance(drills, list)
    assert isinstance(roles, list)
    record: dict[str, object] = {
        "schema_version": 1,
        "evidence_id": "production-deployment-20260809",
        "evidence_kind": "production_deployment_drill",
        "started_at": "2026-08-09T08:00:00Z",
        "completed_at": "2026-08-09T09:00:00Z",
        "product_revision": _PRODUCT_REVISION,
        "revision_contract": policy["revision_contract"],
        "cluster": {
            "environment": "production",
            "provider": "test-cloud",
            "region": "test-region-1",
            "cluster_uid_hash": _hash("cluster"),
            "failure_domains": [
                {
                    "id_hash": _hash("failure-domain-a"),
                    "zone": "test-region-1a",
                    "physical_host_hashes": [_hash("host-a")],
                },
                {
                    "id_hash": _hash("failure-domain-b"),
                    "zone": "test-region-1b",
                    "physical_host_hashes": [_hash("host-b")],
                },
            ],
        },
        "components": {name: _component(name) for name in components},
        "network_controls": dict.fromkeys(network_controls, True),
        "drills": {
            name: {
                "result": "passed",
                "started_at": "2026-08-09T08:10:00Z",
                "completed_at": "2026-08-09T08:20:00Z",
                "evidence_sha256": _hash(f"drill-{name}"),
            }
            for name in drills
        },
        "artifact": {
            "uri": "s3://production-deployment-evidence/report.json",
            "sha256": _hash("artifact"),
            "dsse_envelope_uri": "s3://production-deployment-evidence/report.dsse.json",
            "dsse_subject_sha256": _hash("dsse-subject"),
            "verified_workflow_identity": ("spiffe://omnigent/production-deployment-evidence"),
        },
        "attestations": [
            {
                "role": role,
                "actor_id_hash": _hash(f"actor-{role}"),
                "attested_at": "2026-08-09T08:30:00Z",
                "product_revision": _PRODUCT_REVISION,
            }
            for role in roles
        ],
    }
    record["record_sha256"] = canonical_deployment_record_sha256(record)
    return record


def _resign(record: dict[str, object]) -> None:
    record["record_sha256"] = canonical_deployment_record_sha256(record)


def test_empty_deployment_evidence_is_structurally_valid_but_blocked() -> None:
    report = validate_deployment_readiness(_repo(), _policy(), [], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["blockers"] == ["no current qualifying production deployment evidence"]
    assert report["metrics"] == {
        "evidence_record_count": 0,
        "qualified_record_count": 0,
        "required_component_count": 5,
        "required_network_control_count": 10,
        "required_drill_count": 10,
        "violation_count": 0,
        "readiness_blocker_count": 1,
    }


def test_exact_two_zone_physical_deployment_evidence_satisfies_contract() -> None:
    report = validate_deployment_readiness(
        _repo(),
        _policy(),
        [_record()],
        now=_NOW,
        expected_product_revision=_PRODUCT_REVISION,
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["violations"] == []
    assert report["blockers"] == []


def test_logical_nodes_on_one_physical_host_cannot_prove_failure_domains() -> None:
    record = _record()
    cluster = record["cluster"]
    assert isinstance(cluster, dict)
    domains = cluster["failure_domains"]
    assert isinstance(domains, list)
    assert isinstance(domains[1], dict)
    domains[1]["physical_host_hashes"] = [_hash("host-a")]
    _resign(record)

    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("one physical host appears" in item for item in report["blockers"])
    assert any("does not prove two physical hosts" in item for item in report["blockers"])


def test_replica_hardening_network_and_drill_failures_block_promotion() -> None:
    record = _record()
    components = record["components"]
    network = record["network_controls"]
    drills = record["drills"]
    assert isinstance(components, dict)
    assert isinstance(components["runner"], dict)
    assert isinstance(network, dict)
    assert isinstance(drills, dict)
    assert isinstance(drills["n_minus_one_rollback"], dict)
    components["runner"]["ready_replicas"] = 1
    components["runner"]["privileged"] = True
    network["metadata_endpoint_denied"] = False
    drills["n_minus_one_rollback"]["result"] = "failed"
    drills["n_minus_one_rollback"]["completed_at"] = "2026-08-09T08:25:01Z"
    _resign(record)

    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("required ready replicas" in item for item in report["blockers"])
    assert any("forbidden host or privilege" in item for item in report["blockers"])
    assert any("containment controls failed" in item for item in report["blockers"])
    assert any("n_minus_one_rollback drill did not pass" in item for item in report["blockers"])
    assert any("rollback exceeded policy" in item for item in report["blockers"])


def test_tampering_and_raw_fields_are_structural_failures() -> None:
    record = _record()
    record["raw_node_name"] = "customer-visible-node"

    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "fail"
    assert any("record fields" in item for item in report["violations"])
    assert any("record_sha256" in item for item in report["violations"])


def test_policy_drift_and_unsafe_evidence_directory_fail_closed(tmp_path: Path) -> None:
    policy = copy.deepcopy(_policy())
    revision = policy["revision_contract"]
    assert isinstance(revision, dict)
    revision["control_plane_schema_revision"] = "stale"
    policy["evidence_directory"] = "../outside"

    report = validate_deployment_readiness(_repo(), policy, [], now=_NOW)

    assert report["status"] == "fail"
    assert any("revision_contract" in item for item in report["violations"])
    assert any("safe repository-relative" in item for item in report["violations"])

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (evidence / "escaped.json").symlink_to(outside)
    symlink_policy = copy.deepcopy(_policy())
    symlink_policy["evidence_directory"] = "evidence"
    try:
        load_deployment_evidence(tmp_path, symlink_policy)
    except ValueError as error:
        assert "symbolic links" in str(error)
    else:
        raise AssertionError("symbolic-link deployment evidence was not rejected")


def test_untrusted_workflow_and_reused_attestor_fail_closed() -> None:
    record = _record()
    artifact = record["artifact"]
    attestations = record["attestations"]
    assert isinstance(artifact, dict)
    assert isinstance(attestations, list)
    assert isinstance(attestations[0], dict)
    assert isinstance(attestations[1], dict)
    artifact["verified_workflow_identity"] = "spiffe://untrusted/workflow"
    attestations[1]["actor_id_hash"] = attestations[0]["actor_id_hash"]
    _resign(record)

    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "fail"
    assert any("workflow identity is not trusted" in item for item in report["violations"])
    assert any("actors must be distinct" in item for item in report["violations"])
