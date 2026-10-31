from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

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
    database_controls = policy["required_database_controls"]
    drills = policy["required_drills"]
    roles = policy["required_attestation_roles"]
    assert isinstance(components, dict)
    assert isinstance(network_controls, list)
    assert isinstance(database_controls, list)
    assert isinstance(drills, list)
    assert isinstance(roles, list)
    record: dict[str, object] = {
        "schema_version": policy["schema_version"],
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
        "database_controls": dict.fromkeys(database_controls, True),
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
    runner = record["components"]["runner"]
    runner["seccomp_profile"] = "Localhost"
    for placement in runner["placements"]:
        placement["seccomp"] = _seccomp_observation(placement, runner["digest_pinned_image"])
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
        "required_database_control_count": 4,
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
    database = record["database_controls"]
    drills = record["drills"]
    assert isinstance(components, dict)
    assert isinstance(components["runner"], dict)
    assert isinstance(network, dict)
    assert isinstance(database, dict)
    assert isinstance(drills, dict)
    assert isinstance(drills["n_minus_one_rollback"], dict)
    components["runner"]["ready_replicas"] = 1
    components["runner"]["privileged"] = True
    network["metadata_endpoint_denied"] = False
    database["runner_transition_rpc_or_trigger_only"] = False
    drills["n_minus_one_rollback"]["result"] = "failed"
    drills["n_minus_one_rollback"]["completed_at"] = "2026-08-09T08:25:01Z"
    _resign(record)

    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("required ready replicas" in item for item in report["blockers"])
    assert any("forbidden host or privilege" in item for item in report["blockers"])
    assert any("containment controls failed" in item for item in report["blockers"])
    assert any("Runner database controls failed" in item for item in report["blockers"])
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


def _seccomp_observation(placement: dict, image: str) -> dict:
    """Synthetic unit facts only; never an actual node/CRI collector receipt."""

    return {
        "container_name": "runner-agent",
        "container_id_hash": _hash(str(placement["pod_uid_hash"]) + "container"),
        "image": image,
        "product_revision": _PRODUCT_REVISION,
        "node_uid_hash": placement["node_uid_hash"],
        "pod_uid_hash": placement["pod_uid_hash"],
        "effective_profile": {
            "type": "Localhost",
            "localhostProfile": "omnigent/bubblewrap-v3.json",
        },
        "pod_profile": {"type": "RuntimeDefault"},
        "init_profiles": {"stage-runner-identity": {"type": "RuntimeDefault"}},
        "node_file": {
            "path": "omnigent/bubblewrap-v3.json",
            "sha256": "c500aa5e6862ba7d50e54dcff65bf39120eb6f5300e548fc6e599bc58fcba363",
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": "0644",
            "nlink": 1,
            "type": "regular_nofollow",
            "device": 1,
            "inode": 42,
        },
        "runtime": {
            "platform": "linux/amd64",
            "runtime_class": "omnigent-runner",
            "kernel_release": "6.8.0-test",
            "container_runtime_version": "containerd://2.3.2-k3s2",
            "pid_namespace_hash": _hash("runner-pid"),
            "host_pid_namespace_hash": _hash("host-pid"),
        },
        "process": {
            "uid": 65532,
            "gid": 65532,
            "no_new_privileges": True,
            "seccomp_mode": 2,
            "effective_capabilities": 0,
            "host_pid": False,
            "share_process_namespace": False,
            "root_read_only": True,
            "sandbox_backend": "kubernetes",
        },
        "observed_at": "2026-08-09T08:15:00Z",
        "raw_evidence_sha256": _hash("raw-" + str(placement["pod_uid_hash"])),
    }


def _v2_record() -> dict:
    record = _record()
    record["schema_version"] = 2
    runner = record["components"]["runner"]
    runner["seccomp_profile"] = "RuntimeDefault"
    for placement in runner["placements"]:
        del placement["seccomp"]
    _resign(record)
    return record


def test_v2_record_bytes_and_runtime_default_semantics_are_preserved() -> None:
    policy = _policy()
    policy["schema_version"] = 2
    del policy["runner_seccomp"]
    record = _v2_record()
    assert (
        record["record_sha256"]
        == "5966eecda7061c10edc8ab9b916b370334dfd51e18d0cd51aaeddebe477da014"
    )
    assert (
        hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        == "2365e3fd4fc5afbfbfde6d19dcdb07a8e36289e264a47a036be0cae0fed18aab"
    )
    report = validate_deployment_readiness(_repo(), policy, [record], now=_NOW)
    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    record["components"]["runner"]["seccomp_profile"] = "Localhost"
    _resign(record)
    report = validate_deployment_readiness(_repo(), policy, [record], now=_NOW)
    assert report["production_readiness"] == "blocked"
    assert any("does not use RuntimeDefault" in item for item in report["blockers"])


@pytest.mark.parametrize("policy_version,record_version", [(2, 3), (3, 2), (3, True)])
def test_record_cannot_be_rebased_across_seccomp_schema_versions(
    policy_version, record_version
) -> None:
    policy = _policy()
    policy["schema_version"] = policy_version
    if policy_version == 2:
        del policy["runner_seccomp"]
    record = _record()
    record["schema_version"] = record_version
    _resign(record)
    report = validate_deployment_readiness(_repo(), policy, [record], now=_NOW)
    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"
    assert any("schema_version" in item for item in report["violations"])


@pytest.mark.parametrize(
    "path,value",
    [
        (("container_name",), "stage-runner-identity"),
        (("container_id_hash",), None),
        (("container_id_hash",), "0" * 64),
        (("image",), "registry.example/other@sha256:" + "f" * 64),
        (("product_revision",), "b" * 40),
        (("node_uid_hash",), _hash("other-node")),
        (("pod_uid_hash",), _hash("other-pod")),
        (("effective_profile", "type"), "RuntimeDefault"),
        (("effective_profile", "localhostProfile"), "other/profile.json"),
        (("pod_profile", "type"), "Localhost"),
        (("init_profiles", "stage-runner-identity", "type"), "Localhost"),
        (("node_file", "sha256"), "f" * 64),
        (("node_file", "path"), "../bubblewrap-v3.json"),
        (("node_file", "owner_uid"), 10001),
        (("node_file", "owner_gid"), True),
        (("node_file", "mode"), "0664"),
        (("node_file", "type"), "symlink"),
        (("node_file", "nlink"), 2),
        (("node_file", "inode"), 0),
        (("runtime", "platform"), "linux/arm64"),
        (("runtime", "runtime_class"), "untrusted"),
        (("runtime", "kernel_release"), "UNKNOWN"),
        (("runtime", "kernel_release"), "6.8"),
        (("runtime", "container_runtime_version"), "containerd://2.3.3-k3s1"),
        (("runtime", "container_runtime_version"), None),
        (("runtime", "pid_namespace_hash"), _hash("host-pid")),
        (("process", "uid"), 10001),
        (("process", "effective_capabilities"), True),
        (("process", "no_new_privileges"), False),
        (("process", "seccomp_mode"), 0),
        (("process", "host_pid"), True),
        (("process", "share_process_namespace"), True),
        (("process", "root_read_only"), False),
        (("process", "sandbox_backend"), "none"),
        (("observed_at",), "2026-08-09T07:59:59Z"),
        (("observed_at",), "2026-08-09T09:00:01Z"),
        (("raw_evidence_sha256",), "0" * 64),
        (("raw_evidence_sha256",), hashlib.sha256(b"").hexdigest()),
    ],
)
def test_v3_runner_observation_rejects_missing_or_cross_bound_facts(path, value) -> None:
    record = _record()
    target = record["components"]["runner"]["placements"][0]["seccomp"]
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = value
    _resign(record)
    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)
    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"
    assert any("runner seccomp" in item for item in report["violations"])


@pytest.mark.parametrize("replacement", [None, {}, {"node_label": "c500aa5e6862ba7d"}])
def test_v3_runner_requires_full_observation_not_node_labels(replacement) -> None:
    record = _record()
    record["components"]["runner"]["placements"][0]["seccomp"] = replacement
    _resign(record)
    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)
    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"


@pytest.mark.parametrize(
    "component", ["control-plane", "queue-worker", "preview-gateway", "egress-proxy"]
)
def test_v3_does_not_allow_localhost_for_other_components(component) -> None:
    record = _record()
    record["components"][component]["seccomp_profile"] = "Localhost"
    _resign(record)
    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)
    assert report["production_readiness"] == "blocked"
    assert any("does not use RuntimeDefault" in item for item in report["blockers"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("profile_sha256", "f" * 64),
        ("localhost_profile", "other/profile.json"),
        ("container_name", "other"),
        ("run_as_uid", 10001),
    ],
)
def test_v3_policy_cannot_expand_the_reviewed_runner_contract(field, value) -> None:
    policy = _policy()
    policy["runner_seccomp"][field] = value
    report = validate_deployment_readiness(_repo(), policy, [_record()], now=_NOW)
    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"
    assert any("exact reviewed v3 contract" in item for item in report["violations"])


@pytest.mark.parametrize("field", ["container_id_hash", "raw_evidence_sha256"])
def test_v3_distinct_pods_cannot_reuse_one_execution_or_raw_observation(field) -> None:
    record = _record()
    placements = record["components"]["runner"]["placements"]
    assert placements[0]["node_uid_hash"] != placements[1]["node_uid_hash"]
    assert placements[0]["pod_uid_hash"] != placements[1]["pod_uid_hash"]
    placements[1]["seccomp"][field] = placements[0]["seccomp"][field]
    _resign(record)
    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)
    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"
    assert any(f"repeats {field}" in item for item in report["violations"])


def test_v3_one_node_cannot_claim_two_physical_hosts_and_failure_domains() -> None:
    record = _record()
    placements = record["components"]["runner"]["placements"]
    assert placements[0]["physical_host_hash"] != placements[1]["physical_host_hash"]
    assert placements[0]["failure_domain_hash"] != placements[1]["failure_domain_hash"]
    assert placements[0]["pod_uid_hash"] != placements[1]["pod_uid_hash"]
    assert (
        placements[0]["seccomp"]["container_id_hash"]
        != placements[1]["seccomp"]["container_id_hash"]
    )
    assert (
        placements[0]["seccomp"]["raw_evidence_sha256"]
        != placements[1]["seccomp"]["raw_evidence_sha256"]
    )
    placements[1]["node_uid_hash"] = placements[0]["node_uid_hash"]
    placements[1]["seccomp"]["node_uid_hash"] = placements[0]["node_uid_hash"]
    _resign(record)
    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)
    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"
    assert any("repeats node_uid_hash" in item for item in report["violations"])


@pytest.mark.parametrize(
    "field", ["node_uid_hash", "pod_uid_hash", "pid_namespace_hash", "host_pid_namespace_hash"]
)
@pytest.mark.parametrize(
    "digest", ["0" * 64, hashlib.sha256(b"").hexdigest()], ids=["zero", "empty"]
)
def test_v3_identity_hashes_reject_missing_observation_sentinels(field, digest) -> None:
    record = _record()
    placement = record["components"]["runner"]["placements"][0]
    observation = placement["seccomp"]
    if field in {"node_uid_hash", "pod_uid_hash"}:
        placement[field] = digest
        observation[field] = digest
    else:
        observation["runtime"][field] = digest
    _resign(record)
    report = validate_deployment_readiness(_repo(), _policy(), [record], now=_NOW)
    assert report["status"] == "fail"
    assert report["production_readiness"] == "blocked"
    assert any("runner seccomp" in item for item in report["violations"])
