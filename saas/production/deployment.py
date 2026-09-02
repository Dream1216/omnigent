"""Validate immutable production deployment and failure-domain evidence.

The contract deliberately distinguishes logical Kubernetes objects from physical
failure domains. A record qualifies only when every required component is spread over
distinct physical hosts in at least two zones, all containment and Runner database
controls are live, and the complete failure matrix has independently attested
immutable evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_RECORD_FIELDS = {
    "schema_version",
    "evidence_id",
    "evidence_kind",
    "started_at",
    "completed_at",
    "product_revision",
    "revision_contract",
    "cluster",
    "components",
    "network_controls",
    "database_controls",
    "drills",
    "artifact",
    "attestations",
    "record_sha256",
}
_CLUSTER_FIELDS = {
    "environment",
    "provider",
    "region",
    "cluster_uid_hash",
    "failure_domains",
}
_FAILURE_DOMAIN_FIELDS = {"id_hash", "zone", "physical_host_hashes"}
_COMPONENT_FIELDS = {
    "desired_replicas",
    "ready_replicas",
    "digest_pinned_image",
    "placements",
    "pdb_min_available",
    "topology_spread_max_skew",
    "anti_affinity_required",
    "dedicated_service_account",
    "host_network",
    "host_pid",
    "host_ipc",
    "privileged",
    "allow_privilege_escalation",
    "read_only_root_filesystem",
    "seccomp_profile",
    "dropped_capabilities",
}
_PLACEMENT_FIELDS = {
    "pod_uid_hash",
    "node_uid_hash",
    "physical_host_hash",
    "failure_domain_hash",
}
_DRILL_FIELDS = {"result", "started_at", "completed_at", "evidence_sha256"}
_ARTIFACT_FIELDS = {
    "uri",
    "sha256",
    "dsse_envelope_uri",
    "dsse_subject_sha256",
    "verified_workflow_identity",
}
_ATTESTATION_FIELDS = {"role", "actor_id_hash", "attested_at", "product_revision"}


def canonical_deployment_record_sha256(record: Mapping[str, Any]) -> str:
    """Hash a record without its self-authenticating digest field."""

    payload = {key: value for key, value in record.items() if key != "record_sha256"}
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return set()
    return set(value)


def _artifact_uri(value: object, schemes: set[str]) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return parsed.scheme in schemes and bool(parsed.netloc) and bool(parsed.path)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def load_deployment_evidence(repo: Path, policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Load non-symlink evidence records from the policy-owned directory."""

    relative = policy.get("evidence_directory")
    if not isinstance(relative, str):
        raise ValueError("evidence_directory must be a repository-relative path")
    directory = (repo / relative).resolve()
    try:
        directory.relative_to(repo.resolve())
    except ValueError as error:
        raise ValueError("evidence_directory escapes the repository") from error
    if not directory.is_dir():
        raise ValueError("evidence_directory does not exist")
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        if path.is_symlink():
            raise ValueError("deployment evidence cannot contain symbolic links")
        records.append(_load_json(path))
    return records


def _validate_policy(
    repo: Path,
    policy: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> list[str]:
    violations: list[str] = []
    if policy.get("schema_version") != 2:
        violations.append("deployment policy schema_version must be 2")
    if not _nonempty(policy.get("policy_id")):
        violations.append("deployment policy_id is required")
    if _parse_time(f"{policy.get('reviewed_at')}T00:00:00Z") is None:
        violations.append("deployment policy reviewed_at must be an ISO date")

    baseline_revision = _mapping(baseline.get("revision_contract")) or {}
    expected_revision = {
        key: baseline_revision.get(key)
        for key in (
            "upstream_revision",
            "adapter_contract_version",
            "control_plane_schema_revision",
        )
    }
    if _mapping(policy.get("revision_contract")) != expected_revision:
        violations.append("deployment policy revision_contract must match production baseline")

    directory = policy.get("evidence_directory")
    if (
        not isinstance(directory, str)
        or Path(directory).is_absolute()
        or ".." in Path(directory).parts
    ):
        violations.append("evidence_directory must be a safe repository-relative path")
    elif not (repo / directory).is_dir():
        violations.append("evidence_directory must exist")

    max_age = policy.get("max_evidence_age_days")
    if not isinstance(max_age, int) or isinstance(max_age, bool) or not 1 <= max_age <= 30:
        violations.append("max_evidence_age_days must be between 1 and 30")
    for field in ("minimum_failure_domains", "minimum_physical_hosts"):
        value = policy.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 2:
            violations.append(f"{field} must be at least 2")

    components = _mapping(policy.get("required_components"))
    if components is None or set(components) != {
        "control-plane",
        "queue-worker",
        "runner",
        "preview-gateway",
        "egress-proxy",
    }:
        violations.append("required_components must match the production execution path")
    else:
        for name, requirement in components.items():
            item = _mapping(requirement)
            replicas = item.get("minimum_replicas") if item is not None else None
            if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas < 2:
                violations.append(f"{name}.minimum_replicas must be at least 2")

    network_controls = _string_set(policy.get("required_network_controls"))
    if len(network_controls) < 10:
        violations.append("required_network_controls must contain the complete containment set")
    database_controls = _string_set(policy.get("required_database_controls"))
    if database_controls != {
        "runner_target_database_connect_only",
        "runner_no_database_create_or_temporary",
        "runner_catalog_drift_fail_closed",
        "runner_transition_rpc_or_trigger_only",
    }:
        violations.append(
            "required_database_controls must match the complete Runner database boundary"
        )
    drills = _string_set(policy.get("required_drills"))
    required_drills = {
        "failure_domain_loss",
        "network_partition",
        "control_plane_replica_loss",
        "runner_loss",
        "preview_gateway_loss",
        "egress_bypass",
        "metadata_access",
        "secret_exfiltration",
        "stale_fencing",
        "n_minus_one_rollback",
    }
    if drills != required_drills:
        violations.append("required_drills must match the complete production failure matrix")
    rollback = policy.get("maximum_n_minus_one_rollback_seconds")
    if not isinstance(rollback, int) or isinstance(rollback, bool) or rollback > 900:
        violations.append("maximum_n_minus_one_rollback_seconds cannot exceed 900")

    roles = _string_set(policy.get("required_attestation_roles"))
    if roles != {"site-reliability", "security", "release-engineering"}:
        violations.append("deployment evidence requires the three independent approval roles")
    schemes = _string_set(policy.get("artifact_uri_schemes"))
    if not schemes or any(value not in {"s3", "gs", "az", "oci"} for value in schemes):
        violations.append("artifact_uri_schemes contains an unapproved scheme")
    workflows = _string_set(policy.get("verified_workflow_identities"))
    if not workflows:
        violations.append("verified_workflow_identities must not be empty")
    return violations


def _validate_cluster(
    record: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    label: str,
) -> tuple[list[str], list[str], set[str], set[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    failure_domain_hashes: set[str] = set()
    physical_host_hashes: set[str] = set()
    cluster = _mapping(record.get("cluster"))
    if cluster is None or set(cluster) != _CLUSTER_FIELDS:
        violations.append(f"{label}: cluster facts do not match schema")
        return violations, blockers, failure_domain_hashes, physical_host_hashes
    if cluster.get("environment") != "production":
        violations.append(f"{label}: cluster environment must be production")
    for field in ("provider", "region"):
        if not _nonempty(cluster.get(field)):
            violations.append(f"{label}: cluster.{field} is required")
    if not _sha256(cluster.get("cluster_uid_hash")):
        violations.append(f"{label}: cluster_uid_hash must be SHA-256")

    domains = cluster.get("failure_domains")
    zones: set[str] = set()
    if not isinstance(domains, list):
        violations.append(f"{label}: failure_domains must be a list")
        return violations, blockers, failure_domain_hashes, physical_host_hashes
    for raw in domains:
        domain = _mapping(raw)
        if domain is None or set(domain) != _FAILURE_DOMAIN_FIELDS:
            violations.append(f"{label}: failure-domain facts do not match schema")
            continue
        domain_hash = domain.get("id_hash")
        zone = domain.get("zone")
        hosts = domain.get("physical_host_hashes")
        if (
            not isinstance(domain_hash, str)
            or not _sha256(domain_hash)
            or domain_hash in failure_domain_hashes
        ):
            violations.append(f"{label}: failure-domain hashes must be unique SHA-256 values")
        else:
            failure_domain_hashes.add(domain_hash)
        if not isinstance(zone, str) or not _nonempty(zone) or zone in zones:
            blockers.append(f"{label}: failure domains do not prove distinct availability zones")
        else:
            zones.add(zone)
        if not isinstance(hosts, list) or not hosts:
            violations.append(f"{label}: each failure domain requires physical hosts")
            continue
        for host in hosts:
            if not _sha256(host):
                violations.append(f"{label}: physical host identities must be SHA-256")
            elif host in physical_host_hashes:
                blockers.append(f"{label}: one physical host appears in multiple failure domains")
            else:
                physical_host_hashes.add(host)
    if len(failure_domain_hashes) < int(policy.get("minimum_failure_domains", 2)):
        blockers.append(f"{label}: cluster does not prove two physical failure domains")
    if len(physical_host_hashes) < int(policy.get("minimum_physical_hosts", 2)):
        blockers.append(f"{label}: cluster does not prove two physical hosts")
    return violations, blockers, failure_domain_hashes, physical_host_hashes


def _validate_components(
    record: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    label: str,
    failure_domains: set[str],
    physical_hosts: set[str],
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    expected = _mapping(policy.get("required_components")) or {}
    components = _mapping(record.get("components"))
    if components is None or set(components) != set(expected):
        violations.append(f"{label}: components do not match policy")
        return violations, blockers
    for name, raw in components.items():
        component = _mapping(raw)
        if component is None or set(component) != _COMPONENT_FIELDS:
            violations.append(f"{label}: {name} facts do not match schema")
            continue
        requirement = _mapping(expected[name]) or {}
        minimum = int(requirement.get("minimum_replicas", 2))
        desired = component.get("desired_replicas")
        ready = component.get("ready_replicas")
        if (
            not isinstance(desired, int)
            or isinstance(desired, bool)
            or not isinstance(ready, int)
            or isinstance(ready, bool)
            or desired < minimum
            or ready < desired
        ):
            blockers.append(f"{label}: {name} does not have the required ready replicas")
        if not _nonempty(component.get("digest_pinned_image")) or "@sha256:" not in str(
            component.get("digest_pinned_image")
        ):
            violations.append(f"{label}: {name} image is not digest-pinned")
        pdb = component.get("pdb_min_available")
        if not isinstance(pdb, int) or isinstance(pdb, bool) or pdb < 1:
            blockers.append(f"{label}: {name} has no effective disruption budget")
        max_skew = component.get("topology_spread_max_skew")
        if not isinstance(max_skew, int) or isinstance(max_skew, bool) or max_skew > 1:
            blockers.append(f"{label}: {name} topology spread is not strict")

        true_controls = {
            "anti_affinity_required",
            "dedicated_service_account",
            "read_only_root_filesystem",
        }
        false_controls = {
            "host_network",
            "host_pid",
            "host_ipc",
            "privileged",
            "allow_privilege_escalation",
        }
        if any(component.get(field) is not True for field in true_controls):
            blockers.append(f"{label}: {name} is missing a required workload hardening control")
        if any(component.get(field) is not False for field in false_controls):
            blockers.append(f"{label}: {name} enables a forbidden host or privilege control")
        if component.get("seccomp_profile") != "RuntimeDefault":
            blockers.append(f"{label}: {name} does not use RuntimeDefault seccomp")
        if _string_set(component.get("dropped_capabilities")) != {"ALL"}:
            blockers.append(f"{label}: {name} does not drop all Linux capabilities")

        placements = component.get("placements")
        component_domains: set[str] = set()
        component_hosts: set[str] = set()
        pod_hashes: set[str] = set()
        if not isinstance(placements, list):
            violations.append(f"{label}: {name} placements must be a list")
            continue
        for raw_placement in placements:
            placement = _mapping(raw_placement)
            if placement is None or set(placement) != _PLACEMENT_FIELDS:
                violations.append(f"{label}: {name} placement facts do not match schema")
                continue
            for field in _PLACEMENT_FIELDS:
                if not _sha256(placement.get(field)):
                    violations.append(f"{label}: {name} placement {field} must be SHA-256")
            pod = placement.get("pod_uid_hash")
            if isinstance(pod, str) and pod in pod_hashes:
                violations.append(f"{label}: {name} repeats a Pod identity")
            elif isinstance(pod, str):
                pod_hashes.add(pod)
            domain = placement.get("failure_domain_hash")
            host = placement.get("physical_host_hash")
            if isinstance(domain, str):
                component_domains.add(domain)
            if isinstance(host, str):
                component_hosts.add(host)
        if len(placements) < minimum:
            blockers.append(f"{label}: {name} has too few scheduled placements")
        if not component_domains <= failure_domains or len(component_domains) < 2:
            blockers.append(f"{label}: {name} is not spread across two failure domains")
        if not component_hosts <= physical_hosts or len(component_hosts) < 2:
            blockers.append(f"{label}: {name} is not spread across two physical hosts")
    return violations, blockers


def _validate_record(
    record: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    now: datetime,
    expected_product_revision: str | None,
) -> tuple[list[str], list[str], bool]:
    violations: list[str] = []
    blockers: list[str] = []
    evidence_id = record.get("evidence_id")
    label = (
        evidence_id
        if isinstance(evidence_id, str) and _nonempty(evidence_id)
        else "unknown-evidence"
    )
    if set(record) != _RECORD_FIELDS:
        violations.append(f"{label}: record fields do not match schema")
    if record.get("schema_version") != 2:
        violations.append(f"{label}: schema_version must be 2")
    if not _nonempty(evidence_id):
        violations.append("deployment evidence_id is required")
    if record.get("evidence_kind") != "production_deployment_drill":
        violations.append(f"{label}: evidence_kind must be production_deployment_drill")

    started = _parse_time(record.get("started_at"))
    completed = _parse_time(record.get("completed_at"))
    if started is None or completed is None or completed < started or completed > now:
        violations.append(f"{label}: evidence timestamps are invalid")
    elif now - completed > timedelta(days=int(policy.get("max_evidence_age_days", 0))):
        blockers.append(f"{label}: deployment evidence is older than policy")

    revision = record.get("product_revision")
    if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
        violations.append(f"{label}: product_revision must be a full Git SHA")
    elif expected_product_revision is not None and revision != expected_product_revision:
        blockers.append(f"{label}: product revision does not match the release candidate")
    if _mapping(record.get("revision_contract")) != _mapping(policy.get("revision_contract")):
        blockers.append(f"{label}: revision contract does not match current policy")

    cluster_violations, cluster_blockers, domains, hosts = _validate_cluster(
        record, policy, label=label
    )
    violations.extend(cluster_violations)
    blockers.extend(cluster_blockers)
    component_violations, component_blockers = _validate_components(
        record,
        policy,
        label=label,
        failure_domains=domains,
        physical_hosts=hosts,
    )
    violations.extend(component_violations)
    blockers.extend(component_blockers)

    expected_network = _string_set(policy.get("required_network_controls"))
    network = _mapping(record.get("network_controls"))
    if network is None or set(network) != expected_network:
        violations.append(f"{label}: network controls do not match policy")
    elif any(network[name] is not True for name in expected_network):
        blockers.append(f"{label}: one or more containment controls failed")

    expected_database = _string_set(policy.get("required_database_controls"))
    database = _mapping(record.get("database_controls"))
    if database is None or set(database) != expected_database:
        violations.append(f"{label}: database controls do not match policy")
    elif any(database[name] is not True for name in expected_database):
        blockers.append(f"{label}: one or more Runner database controls failed")

    expected_drills = _string_set(policy.get("required_drills"))
    drills = _mapping(record.get("drills"))
    latest_drill: datetime | None = None
    if drills is None or set(drills) != expected_drills:
        violations.append(f"{label}: drills do not match policy")
    else:
        for name, raw in drills.items():
            drill = _mapping(raw)
            if drill is None or set(drill) != _DRILL_FIELDS:
                violations.append(f"{label}: {name} drill facts do not match schema")
                continue
            drill_started = _parse_time(drill.get("started_at"))
            drill_completed = _parse_time(drill.get("completed_at"))
            if (
                drill_started is None
                or drill_completed is None
                or drill_completed < drill_started
                or started is None
                or completed is None
                or drill_started < started
                or drill_completed > completed
            ):
                violations.append(f"{label}: {name} drill timestamps are invalid")
            elif latest_drill is None or drill_completed > latest_drill:
                latest_drill = drill_completed
            if drill.get("result") != "passed":
                blockers.append(f"{label}: {name} drill did not pass")
            if not _sha256(drill.get("evidence_sha256")):
                violations.append(f"{label}: {name} evidence_sha256 must be SHA-256")
            if name == "n_minus_one_rollback" and drill_started and drill_completed:
                maximum = int(policy.get("maximum_n_minus_one_rollback_seconds", 900))
                if (drill_completed - drill_started).total_seconds() > maximum:
                    blockers.append(f"{label}: N-1 rollback exceeded policy")

    schemes = _string_set(policy.get("artifact_uri_schemes"))
    artifact = _mapping(record.get("artifact"))
    if artifact is None or set(artifact) != _ARTIFACT_FIELDS:
        violations.append(f"{label}: artifact facts do not match schema")
    else:
        for field in ("uri", "dsse_envelope_uri"):
            if not _artifact_uri(artifact.get(field), schemes):
                violations.append(f"{label}: artifact.{field} is not an approved immutable URI")
        for field in ("sha256", "dsse_subject_sha256"):
            if not _sha256(artifact.get(field)):
                violations.append(f"{label}: artifact.{field} must be SHA-256")
        if artifact.get("verified_workflow_identity") not in _string_set(
            policy.get("verified_workflow_identities")
        ):
            violations.append(f"{label}: artifact workflow identity is not trusted")

    required_roles = _string_set(policy.get("required_attestation_roles"))
    attestations = record.get("attestations")
    roles: set[str] = set()
    actors: set[str] = set()
    if not isinstance(attestations, list):
        violations.append(f"{label}: attestations must be a list")
    else:
        for raw in attestations:
            attestation = _mapping(raw)
            if attestation is None or set(attestation) != _ATTESTATION_FIELDS:
                violations.append(f"{label}: attestation fields do not match schema")
                continue
            role = attestation.get("role")
            actor = attestation.get("actor_id_hash")
            if not isinstance(role, str) or role in roles:
                violations.append(f"{label}: attestation roles must be unique")
            else:
                roles.add(role)
            if not isinstance(actor, str) or not _sha256(actor) or actor in actors:
                violations.append(
                    f"{label}: attestation actors must be distinct SHA-256 identities"
                )
            else:
                actors.add(actor)
            attested_at = _parse_time(attestation.get("attested_at"))
            if (
                attested_at is None
                or latest_drill is None
                or completed is None
                or attested_at < latest_drill
                or attested_at > completed
            ):
                violations.append(f"{label}: attestation time is outside the approval window")
            if attestation.get("product_revision") != revision:
                violations.append(f"{label}: attestation product revision does not match")
    if roles != required_roles:
        blockers.append(f"{label}: independent attestations are incomplete")

    if not _sha256(record.get("record_sha256")) or record.get(
        "record_sha256"
    ) != canonical_deployment_record_sha256(record):
        violations.append(f"{label}: record_sha256 does not authenticate the canonical record")
    qualifies = not violations and not blockers
    return violations, blockers, qualifies


def validate_deployment_readiness(
    repo: Path,
    policy: Mapping[str, Any],
    records: list[dict[str, Any]],
    *,
    now: datetime | None = None,
    expected_product_revision: str | None = None,
    baseline: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return structural validity separately from production readiness."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if baseline is None:
        baseline = _load_json(repo / "saas/production/baseline.json")
    violations = _validate_policy(repo, policy, baseline)
    blockers: list[str] = []
    ids: set[str] = set()
    qualified = 0
    for record in records:
        evidence_id = record.get("evidence_id")
        if isinstance(evidence_id, str) and evidence_id in ids:
            violations.append(f"duplicate deployment evidence_id {evidence_id}")
        elif isinstance(evidence_id, str):
            ids.add(evidence_id)
        record_violations, record_blockers, record_qualifies = _validate_record(
            record,
            policy,
            now=current,
            expected_product_revision=expected_product_revision,
        )
        violations.extend(record_violations)
        blockers.extend(record_blockers)
        qualified += int(record_qualifies)
    if not records or (qualified == 0 and not blockers):
        blockers.append("no current qualifying production deployment evidence")
    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": (
            "ready" if not violations and not blockers and qualified > 0 else "blocked"
        ),
        "violations": sorted(set(violations)),
        "blockers": sorted(set(blockers)),
        "metrics": {
            "evidence_record_count": len(records),
            "qualified_record_count": qualified,
            "required_component_count": len(_mapping(policy.get("required_components")) or {}),
            "required_network_control_count": len(
                _string_set(policy.get("required_network_controls"))
            ),
            "required_database_control_count": len(
                _string_set(policy.get("required_database_controls"))
            ),
            "required_drill_count": len(_string_set(policy.get("required_drills"))),
            "violation_count": len(set(violations)),
            "readiness_blocker_count": len(set(blockers)),
        },
    }
