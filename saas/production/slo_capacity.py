"""Validate production SLO observation and capacity-test evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_CODE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{1,95}$")
_EVIDENCE_KIND = "production_slo_capacity_observation"
_SLO_IDS = {
    "SLO-AUTH",
    "SLO-RESOLVE",
    "SLO-ADMISSION",
    "SLO-REVOCATION",
    "SLO-OUTBOX",
    "SLO-RUN-EVENT",
}
_SERVICE_IDS = {
    "control-plane",
    "compatibility-adapter",
    "queue-worker",
    "runner-sandbox",
    "billing-metering",
    "audit",
    "admin",
}
_SCENARIOS = {
    "steady_state",
    "hot_tenant",
    "dependency_degraded",
    "backlog_recovery",
    "failure_reserve",
}
_DIMENSIONS = {
    "api_replicas",
    "postgresql_connections",
    "queue_depth_and_oldest_age",
    "worker_concurrency",
    "runner_cpu_and_memory",
    "runner_disk_and_inodes",
    "network_egress",
    "object_and_audit_storage",
    "tenant_fairness",
    "retry_budget_and_dlq",
}
_ALERTS = {
    "error_budget_exhaustion",
    "queue_age",
    "postgresql_pool_saturation",
    "runner_capacity",
    "storage_growth",
    "dependency_degradation",
}
_SLO_METRICS = {
    "SLO-AUTH": ("availability_percent", "minimum", 99.9, None),
    "SLO-RESOLVE": ("p99_seconds", "maximum", 0.1, None),
    "SLO-ADMISSION": ("p99_seconds", "maximum", 2.0, None),
    "SLO-REVOCATION": ("revocation_seconds", "maximum", 0.0, 60.0),
    "SLO-OUTBOX": ("p99_seconds", "maximum", 60.0, None),
    "SLO-RUN-EVENT": ("loss_count", "maximum", 0.0, None),
}
_POLICY_FIELDS = {
    "schema_version",
    "policy_id",
    "reviewed_at",
    "revision_contract",
    "evidence_directory",
    "max_evidence_age_days",
    "required_slo_ids",
    "required_service_ids",
    "required_capacity_scenarios",
    "required_capacity_dimensions",
    "required_alert_drills",
    "thresholds",
    "required_attestation_roles",
    "artifact_uri_schemes",
    "verified_workflow_identities",
}
_RECORD_FIELDS = {
    "schema_version",
    "evidence_id",
    "evidence_kind",
    "window_started_at",
    "window_completed_at",
    "product_revision",
    "revision_contract",
    "production_observation",
    "slo_outcomes",
    "capacity_test",
    "alert_drills",
    "artifact",
    "attestations",
    "record_sha256",
}
_OBSERVATION_FIELDS = {
    "environment",
    "region",
    "failure_domains",
    "traffic_profile_sha256",
    "cardinality_snapshot_sha256",
    "tenant_count",
    "eligible_request_count",
}
_SLO_OUTCOME_FIELDS = {
    "objective",
    "measurement_kind",
    "primary_value",
    "secondary_value",
    "eligible_event_count",
    "excluded_event_count",
    "error_budget_consumed_percent",
    "max_burn_rate_1h",
    "max_burn_rate_6h",
    "dashboard_uri",
    "dashboard_sha256",
    "measurement_query_sha256",
    "alert_policy_sha256",
}
_CAPACITY_TEST_FIELDS = {
    "environment",
    "production_traffic_enabled",
    "dataset_profile_sha256",
    "service_outcomes",
    "dimension_checks",
}
_SERVICE_OUTCOME_FIELDS = {"owner", "capacity_model_sha256", "scenarios"}
_SCENARIO_FIELDS = {
    "passed",
    "offered_work_units",
    "completed_work_units",
    "controlled_rejections",
    "unexpected_errors",
    "max_saturation_percent",
    "minimum_headroom_percent",
    "tenant_fairness_ratio",
    "evidence_sha256",
}
_BINARY_EVIDENCE_FIELDS = {"passed", "evidence_sha256"}
_ALERT_FIELDS = {
    "fired",
    "routed_to_oncall",
    "acknowledged_seconds",
    "evidence_sha256",
}
_ARTIFACT_FIELDS = {
    "uri",
    "sha256",
    "immutability_receipt_sha256",
    "dsse_envelope_uri",
    "dsse_subject_sha256",
    "verified_workflow_identity",
}
_ATTESTATION_FIELDS = {"role", "actor_id_hash", "attested_at", "product_revision"}


def canonical_slo_capacity_record_sha256(record: Mapping[str, Any]) -> str:
    """Hash a record without its self-authenticating field."""

    payload = {key: value for key, value in record.items() if key != "record_sha256"}
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _integer(value: object, *, positive: bool = False) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < (1 if positive else 0):
        return None
    return value


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return set()
    return set(value)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def load_slo_capacity_evidence(
    repo: Path, policy: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Load records only from the safe policy-owned evidence directory."""

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
            raise ValueError("evidence records cannot be symbolic links")
        try:
            path.resolve().relative_to(directory)
        except ValueError as error:
            raise ValueError("evidence record escapes the evidence directory") from error
        records.append(_load_json(path))
    return records


def _baseline_maps(
    baseline: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    service_catalog = baseline.get("service_catalog")
    slo_catalog = baseline.get("slos")
    services = {
        item["id"]: item
        for item in (service_catalog if isinstance(service_catalog, list) else [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    slos = {
        item["id"]: item
        for item in (slo_catalog if isinstance(slo_catalog, list) else [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    return services, slos


def _validate_policy(
    repo: Path,
    policy: Mapping[str, Any],
    *,
    baseline: Mapping[str, Any],
) -> list[str]:
    violations: list[str] = []
    if set(policy) != _POLICY_FIELDS:
        violations.append("SLO capacity policy fields do not match the schema")
    if policy.get("schema_version") != 1:
        violations.append("SLO capacity policy schema_version must be 1")
    if not _nonempty(policy.get("policy_id")):
        violations.append("SLO capacity policy_id is required")
    if _parse_time(f"{policy.get('reviewed_at')}T00:00:00Z") is None:
        violations.append("SLO capacity policy reviewed_at must be an ISO date")
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
        violations.append("SLO capacity revision_contract must match production baseline")
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
    if (
        not isinstance(max_age, int)
        or isinstance(max_age, bool)
        or max_age < 30
        or max_age > 35
    ):
        violations.append("max_evidence_age_days must be between 30 and 35")
    services, slos = _baseline_maps(baseline)
    required_services = policy.get("required_service_ids")
    if (
        set(services) != _SERVICE_IDS
        or _string_set(required_services) != set(services)
        or not isinstance(required_services, list)
        or len(required_services) != len(_SERVICE_IDS)
    ):
        violations.append("required_service_ids must match the seven-service catalog")
    required_slos = policy.get("required_slo_ids")
    if (
        set(slos) != _SLO_IDS
        or _string_set(required_slos) != set(slos)
        or not isinstance(required_slos, list)
        or len(required_slos) != len(_SLO_IDS)
    ):
        violations.append("required_slo_ids must match the six-SLO baseline")
    if _string_set(policy.get("required_capacity_scenarios")) != _SCENARIOS:
        violations.append("required_capacity_scenarios must match the load matrix")
    if _string_set(policy.get("required_capacity_dimensions")) != _DIMENSIONS:
        violations.append("required_capacity_dimensions must match the resource matrix")
    if _string_set(policy.get("required_alert_drills")) != _ALERTS:
        violations.append("required_alert_drills must match the operational matrix")
    thresholds = _mapping(policy.get("thresholds")) or {}
    expected_thresholds = {
        "minimum_headroom_percent": 20.0,
        "maximum_saturation_percent": 80.0,
        "minimum_tenant_fairness_ratio": 0.9,
        "maximum_burn_rate_1h": 14.4,
        "maximum_burn_rate_6h": 6.0,
        "maximum_alert_acknowledgement_seconds": 300,
    }
    if thresholds != expected_thresholds:
        violations.append("capacity and alert thresholds must match the approved contract")
    if _string_set(policy.get("required_attestation_roles")) != {
        "site-reliability",
        "product-owner",
        "service-owner",
    }:
        violations.append("SRE, product-owner, and service-owner attestations are required")
    schemes = _string_set(policy.get("artifact_uri_schemes"))
    if not schemes or any(scheme not in {"s3", "gs", "az", "oci"} for scheme in schemes):
        violations.append("artifact_uri_schemes must contain only immutable-store schemes")
    workflow_identities = policy.get("verified_workflow_identities")
    if (
        not isinstance(workflow_identities, list)
        or len(workflow_identities) != 1
        or workflow_identities != ["spiffe://omnigent/slo-capacity-evidence"]
    ):
        violations.append("verified_workflow_identities must match the trusted workflow")
    return violations


def _validate_observation(
    value: Mapping[str, Any] | None, *, label: str
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    if value is None:
        return [f"{label}: production_observation is required"], blockers
    if set(value) != _OBSERVATION_FIELDS:
        violations.append(f"{label}: production observation fields do not match the schema")
    if value.get("environment") != "production":
        violations.append(f"{label}: SLO observation environment must be production")
    if not _nonempty(value.get("region")):
        violations.append(f"{label}: production observation region is required")
    failure_domains = _string_set(value.get("failure_domains"))
    if len(failure_domains) < 2:
        blockers.append(f"{label}: production observation lacks two failure domains")
    for field in ("traffic_profile_sha256", "cardinality_snapshot_sha256"):
        if not _sha256(value.get(field)):
            violations.append(f"{label}: production_observation.{field} must be SHA-256")
    for field in ("tenant_count", "eligible_request_count"):
        if _integer(value.get(field), positive=True) is None:
            violations.append(f"{label}: production_observation.{field} must be positive")
    return violations, blockers


def _validate_slo_outcome(
    slo_id: str,
    outcome: Mapping[str, Any] | None,
    *,
    baseline_slo: Mapping[str, Any],
    policy: Mapping[str, Any],
    label: str,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    prefix = f"{label}: {slo_id}"
    if outcome is None:
        return [f"{prefix} outcome is required"], blockers
    if set(outcome) != _SLO_OUTCOME_FIELDS:
        violations.append(f"{prefix} fields do not match the schema")
    metric_contract = _SLO_METRICS.get(slo_id)
    if metric_contract is None:
        return [f"{prefix} is not part of the approved SLO contract"], blockers
    metric, direction, threshold, secondary_threshold = metric_contract
    if outcome.get("objective") != baseline_slo.get("objective"):
        violations.append(f"{prefix} objective does not match production baseline")
    if outcome.get("measurement_kind") != metric:
        violations.append(f"{prefix} measurement_kind is invalid")
    primary = _number(outcome.get("primary_value"))
    if primary is None or primary < 0:
        violations.append(f"{prefix} primary_value is invalid")
    elif (direction == "minimum" and primary < threshold) or (
        direction == "maximum" and primary > threshold
    ):
        blockers.append(f"{prefix} objective was missed")
    if metric == "availability_percent" and primary is not None and primary > 100:
        violations.append(f"{prefix} availability_percent cannot exceed 100")
    secondary = outcome.get("secondary_value")
    if secondary_threshold is None:
        if secondary is not None:
            violations.append(f"{prefix} cannot declare a secondary_value")
    else:
        secondary_number = _number(secondary)
        if secondary_number is None or secondary_number < 0:
            violations.append(f"{prefix} secondary_value is invalid")
        elif secondary_number > secondary_threshold:
            blockers.append(f"{prefix} degraded objective was missed")
    eligible = _integer(outcome.get("eligible_event_count"), positive=True)
    excluded = _integer(outcome.get("excluded_event_count"))
    if eligible is None or excluded is None or excluded > eligible:
        violations.append(f"{prefix} eligible or excluded event counts are invalid")
    budget = _number(outcome.get("error_budget_consumed_percent"))
    if budget is None or budget < 0:
        violations.append(f"{prefix} error budget consumption is invalid")
    elif budget > 100:
        blockers.append(f"{prefix} error budget is exhausted")
    thresholds = _mapping(policy.get("thresholds")) or {}
    for field, limit_key in (
        ("max_burn_rate_1h", "maximum_burn_rate_1h"),
        ("max_burn_rate_6h", "maximum_burn_rate_6h"),
    ):
        rate = _number(outcome.get(field))
        limit = _number(thresholds.get(limit_key))
        if rate is None or rate < 0 or limit is None:
            violations.append(f"{prefix} {field} is invalid")
        elif rate > limit:
            blockers.append(f"{prefix} {field} exceeds policy")
    dashboard = outcome.get("dashboard_uri")
    parsed = urlsplit(dashboard) if isinstance(dashboard, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        violations.append(f"{prefix} dashboard_uri must be a secret-free HTTPS URI")
    for field in ("dashboard_sha256", "measurement_query_sha256", "alert_policy_sha256"):
        if not _sha256(outcome.get(field)):
            violations.append(f"{prefix} {field} must be SHA-256")
    return violations, blockers


def _validate_scenarios(
    scenarios: Mapping[str, Any] | None,
    *,
    policy: Mapping[str, Any],
    prefix: str,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    if scenarios is None or set(scenarios) != _SCENARIOS:
        return [f"{prefix} scenarios do not match the capacity matrix"], blockers
    thresholds = _mapping(policy.get("thresholds")) or {}
    maximum_saturation = _number(thresholds.get("maximum_saturation_percent"))
    minimum_headroom = _number(thresholds.get("minimum_headroom_percent"))
    minimum_fairness = _number(thresholds.get("minimum_tenant_fairness_ratio"))
    if None in (maximum_saturation, minimum_headroom, minimum_fairness):
        violations.append(f"{prefix} policy thresholds are invalid")
    for name in _SCENARIOS:
        item = _mapping(scenarios.get(name))
        item_prefix = f"{prefix} scenario {name}"
        if item is None:
            violations.append(f"{item_prefix} is required")
            continue
        if set(item) != _SCENARIO_FIELDS:
            violations.append(f"{item_prefix} fields do not match the schema")
        offered = _integer(item.get("offered_work_units"), positive=True)
        completed = _integer(item.get("completed_work_units"))
        rejected = _integer(item.get("controlled_rejections"))
        unexpected = _integer(item.get("unexpected_errors"))
        if (
            offered is None
            or completed is None
            or rejected is None
            or completed + rejected != offered
        ):
            violations.append(f"{item_prefix} work-unit accounting is invalid")
        elif completed == 0:
            blockers.append(f"{item_prefix} completed no work units")
        if unexpected is None:
            violations.append(f"{item_prefix} unexpected_errors is invalid")
        elif unexpected != 0:
            blockers.append(f"{item_prefix} had unexpected errors")
        if item.get("passed") is not True:
            blockers.append(f"{item_prefix} did not pass")
        saturation = _number(item.get("max_saturation_percent"))
        headroom = _number(item.get("minimum_headroom_percent"))
        fairness = _number(item.get("tenant_fairness_ratio"))
        if saturation is None or not 0 <= saturation <= 100:
            violations.append(f"{item_prefix} max_saturation_percent is invalid")
        elif maximum_saturation is not None and saturation > maximum_saturation:
            blockers.append(f"{item_prefix} saturation exceeds policy")
        if headroom is None or not 0 <= headroom <= 100:
            violations.append(f"{item_prefix} minimum_headroom_percent is invalid")
        elif minimum_headroom is not None and headroom < minimum_headroom:
            blockers.append(f"{item_prefix} headroom is below policy")
        if fairness is None or not 0 <= fairness <= 1:
            violations.append(f"{item_prefix} tenant_fairness_ratio is invalid")
        elif minimum_fairness is not None and fairness < minimum_fairness:
            blockers.append(f"{item_prefix} tenant fairness is below policy")
        if not _sha256(item.get("evidence_sha256")):
            violations.append(f"{item_prefix} evidence_sha256 is invalid")
    return violations, blockers


def _validate_capacity_test(
    value: Mapping[str, Any] | None,
    *,
    policy: Mapping[str, Any],
    baseline_services: Mapping[str, Mapping[str, Any]],
    label: str,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    if value is None:
        return [f"{label}: capacity_test is required"], blockers
    if set(value) != _CAPACITY_TEST_FIELDS:
        violations.append(f"{label}: capacity_test fields do not match the schema")
    if value.get("environment") != "isolated_production_like":
        violations.append(
            f"{label}: capacity test must use an isolated production-like environment"
        )
    if value.get("production_traffic_enabled") is not False:
        blockers.append(f"{label}: capacity test enabled production traffic")
    if not _sha256(value.get("dataset_profile_sha256")):
        violations.append(f"{label}: capacity dataset profile SHA-256 is required")
    service_outcomes = _mapping(value.get("service_outcomes"))
    if service_outcomes is None or set(service_outcomes) != set(baseline_services):
        violations.append(f"{label}: service outcomes do not match the seven-service catalog")
    else:
        for service_id, baseline_service in baseline_services.items():
            item = _mapping(service_outcomes.get(service_id))
            prefix = f"{label}: service {service_id}"
            if item is None:
                violations.append(f"{prefix} outcome is required")
                continue
            if set(item) != _SERVICE_OUTCOME_FIELDS:
                violations.append(f"{prefix} fields do not match the schema")
            if item.get("owner") != baseline_service.get("code_owner"):
                violations.append(f"{prefix} owner does not match the service catalog")
            if not _sha256(item.get("capacity_model_sha256")):
                violations.append(f"{prefix} capacity_model_sha256 is invalid")
            item_violations, item_blockers = _validate_scenarios(
                _mapping(item.get("scenarios")), policy=policy, prefix=prefix
            )
            violations.extend(item_violations)
            blockers.extend(item_blockers)
    dimensions = _mapping(value.get("dimension_checks"))
    if dimensions is None or set(dimensions) != _DIMENSIONS:
        violations.append(f"{label}: capacity dimensions do not match the resource matrix")
    else:
        for name in _DIMENSIONS:
            item = _mapping(dimensions.get(name))
            if item is None or set(item) != _BINARY_EVIDENCE_FIELDS:
                violations.append(f"{label}: capacity dimension {name} fields are invalid")
                continue
            if item.get("passed") is not True:
                blockers.append(f"{label}: capacity dimension {name} failed")
            if not _sha256(item.get("evidence_sha256")):
                violations.append(f"{label}: capacity dimension {name} evidence is invalid")
    return violations, blockers


def _validate_alerts(
    value: Mapping[str, Any] | None,
    *,
    policy: Mapping[str, Any],
    label: str,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    if value is None or set(value) != _ALERTS:
        return [f"{label}: alert drills do not match the operational matrix"], blockers
    threshold = _integer(
        (_mapping(policy.get("thresholds")) or {}).get(
            "maximum_alert_acknowledgement_seconds"
        ),
        positive=True,
    )
    if threshold is None:
        violations.append(f"{label}: alert acknowledgement policy threshold is invalid")
    for name in _ALERTS:
        item = _mapping(value.get(name))
        prefix = f"{label}: alert {name}"
        if item is None or set(item) != _ALERT_FIELDS:
            violations.append(f"{prefix} fields do not match the schema")
            continue
        if item.get("fired") is not True or item.get("routed_to_oncall") is not True:
            blockers.append(f"{prefix} did not fire and route to on-call")
        acknowledged = _integer(item.get("acknowledged_seconds"))
        if acknowledged is None:
            violations.append(f"{prefix} acknowledgement time is invalid")
        elif threshold is not None and acknowledged > threshold:
            blockers.append(f"{prefix} acknowledgement exceeded policy")
        if not _sha256(item.get("evidence_sha256")):
            violations.append(f"{prefix} evidence_sha256 is invalid")
    return violations, blockers


def _validate_artifact(
    value: Mapping[str, Any] | None,
    *,
    policy: Mapping[str, Any],
    label: str,
) -> list[str]:
    if value is None:
        return [f"{label}: immutable SLO capacity artifact is required"]
    violations: list[str] = []
    if set(value) != _ARTIFACT_FIELDS:
        violations.append(f"{label}: artifact fields do not match the schema")
    schemes = _string_set(policy.get("artifact_uri_schemes"))
    for field in ("uri", "dsse_envelope_uri"):
        raw = value.get(field)
        parsed = urlsplit(raw) if isinstance(raw, str) else None
        if (
            parsed is None
            or parsed.scheme not in schemes
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.query)
            or bool(parsed.fragment)
        ):
            violations.append(f"{label}: artifact.{field} URI is invalid")
    for field in ("sha256", "immutability_receipt_sha256", "dsse_subject_sha256"):
        if not _sha256(value.get(field)):
            violations.append(f"{label}: artifact.{field} must be SHA-256")
    identity = value.get("verified_workflow_identity")
    if identity not in _string_set(policy.get("verified_workflow_identities")):
        violations.append(f"{label}: verified workflow identity is not trusted")
    return violations


def _validate_attestations(
    value: object,
    *,
    policy: Mapping[str, Any],
    label: str,
    completed: datetime | None,
    product_revision: object,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    required_roles = _string_set(policy.get("required_attestation_roles"))
    roles: set[str] = set()
    actors: set[str] = set()
    if not isinstance(value, list):
        return [f"{label}: attestations must be a list"], blockers
    for raw in value:
        item = _mapping(raw)
        if item is None:
            violations.append(f"{label}: attestation entries must be objects")
            continue
        if set(item) != _ATTESTATION_FIELDS:
            violations.append(f"{label}: attestation fields do not match the schema")
        role = item.get("role")
        if not isinstance(role, str):
            violations.append(f"{label}: attestation role is required")
        elif role in roles:
            violations.append(f"{label}: duplicate attestation role {role}")
        else:
            roles.add(role)
        if not _sha256(item.get("actor_id_hash")):
            violations.append(f"{label}: attestation actor_id_hash is invalid")
        elif item["actor_id_hash"] in actors:
            violations.append(f"{label}: attestation actors must be independent")
        else:
            actors.add(item["actor_id_hash"])
        attested_at = _parse_time(item.get("attested_at"))
        if completed is not None and (attested_at is None or attested_at < completed):
            violations.append(f"{label}: attestation time precedes observation completion")
        if item.get("product_revision") != product_revision:
            violations.append(f"{label}: attestation revision does not match evidence")
    if roles != required_roles:
        blockers.append(f"{label}: independent attestations are incomplete")
    return violations, blockers


def _validate_record(
    record: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
    baseline: Mapping[str, Any],
    now: datetime,
    expected_product_revision: str | None,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    evidence_id = record.get("evidence_id")
    label = evidence_id if isinstance(evidence_id, str) else "unknown-evidence"
    if set(record) != _RECORD_FIELDS:
        violations.append(f"{label}: record fields do not match the schema")
    if record.get("schema_version") != 1:
        violations.append(f"{label}: schema_version must be 1")
    if not isinstance(evidence_id, str) or _CODE.fullmatch(evidence_id) is None:
        violations.append("SLO capacity evidence_id must be a bounded code")
    if record.get("evidence_kind") != _EVIDENCE_KIND:
        violations.append(f"{label}: evidence_kind must be {_EVIDENCE_KIND}")
    started = _parse_time(record.get("window_started_at"))
    completed = _parse_time(record.get("window_completed_at"))
    _, baseline_slos = _baseline_maps(baseline)
    window_days = [
        value
        for slo in baseline_slos.values()
        if (value := _integer(slo.get("window_days"), positive=True)) is not None
    ]
    required_window_days = max(window_days, default=30)
    max_evidence_age_days = _integer(policy.get("max_evidence_age_days"), positive=True)
    if started is None or completed is None or completed < started or completed > now:
        violations.append(f"{label}: observation window is invalid")
    elif completed - started < timedelta(days=required_window_days):
        blockers.append(f"{label}: observation window is shorter than the SLO baseline")
    elif (
        max_evidence_age_days is not None
        and (now - completed).total_seconds() > max_evidence_age_days * 86400
    ):
        blockers.append(f"{label}: observation evidence is older than policy")
    product_revision = record.get("product_revision")
    if not isinstance(product_revision, str) or _REVISION.fullmatch(product_revision) is None:
        violations.append(f"{label}: product_revision must be a full Git SHA")
    elif expected_product_revision is not None and product_revision != expected_product_revision:
        blockers.append(f"{label}: product revision does not match the release candidate")
    if _mapping(record.get("revision_contract")) != _mapping(policy.get("revision_contract")):
        blockers.append(f"{label}: revision contract does not match current policy")
    item_violations, item_blockers = _validate_observation(
        _mapping(record.get("production_observation")), label=label
    )
    violations.extend(item_violations)
    blockers.extend(item_blockers)
    slo_outcomes = _mapping(record.get("slo_outcomes"))
    if slo_outcomes is None or set(slo_outcomes) != set(baseline_slos):
        violations.append(f"{label}: SLO outcomes do not match the six-SLO baseline")
    else:
        for slo_id, baseline_slo in baseline_slos.items():
            item_violations, item_blockers = _validate_slo_outcome(
                slo_id,
                _mapping(slo_outcomes.get(slo_id)),
                baseline_slo=baseline_slo,
                policy=policy,
                label=label,
            )
            violations.extend(item_violations)
            blockers.extend(item_blockers)
    baseline_services, _ = _baseline_maps(baseline)
    item_violations, item_blockers = _validate_capacity_test(
        _mapping(record.get("capacity_test")),
        policy=policy,
        baseline_services=baseline_services,
        label=label,
    )
    violations.extend(item_violations)
    blockers.extend(item_blockers)
    item_violations, item_blockers = _validate_alerts(
        _mapping(record.get("alert_drills")), policy=policy, label=label
    )
    violations.extend(item_violations)
    blockers.extend(item_blockers)
    violations.extend(
        _validate_artifact(_mapping(record.get("artifact")), policy=policy, label=label)
    )
    item_violations, item_blockers = _validate_attestations(
        record.get("attestations"),
        policy=policy,
        label=label,
        completed=completed,
        product_revision=product_revision,
    )
    violations.extend(item_violations)
    blockers.extend(item_blockers)
    record_hash = record.get("record_sha256")
    if not _sha256(record_hash) or record_hash != canonical_slo_capacity_record_sha256(record):
        violations.append(f"{label}: record_sha256 does not authenticate the canonical record")
    return violations, blockers


def validate_slo_capacity_readiness(
    repo: Path,
    policy: Mapping[str, Any],
    records: Collection[Mapping[str, Any]],
    *,
    now: datetime | None = None,
    expected_product_revision: str | None = None,
    baseline: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the policy and evidence without manufacturing production proof."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    current_baseline = (
        baseline
        if baseline is not None
        else _load_json(repo / "saas/production/baseline.json")
    )
    violations = _validate_policy(repo, policy, baseline=current_baseline)
    blockers: list[str] = []
    _, baseline_slos = _baseline_maps(current_baseline)
    for slo_id, slo in baseline_slos.items():
        if slo.get("dashboard_state") != "active":
            blockers.append(f"{slo_id} dashboard is not active in production baseline")
    qualified = 0
    evidence_ids: set[str] = set()
    for record in records:
        evidence_id = record.get("evidence_id")
        if isinstance(evidence_id, str):
            if evidence_id in evidence_ids:
                violations.append(f"duplicate SLO capacity evidence_id {evidence_id}")
            evidence_ids.add(evidence_id)
        record_violations, record_blockers = _validate_record(
            record,
            policy=policy,
            baseline=current_baseline,
            now=current,
            expected_product_revision=expected_product_revision,
        )
        violations.extend(record_violations)
        blockers.extend(record_blockers)
        if not record_violations and not record_blockers:
            qualified += 1
    if qualified == 0:
        blockers.append("no current qualifying production SLO and capacity evidence")
    unique_violations = sorted(set(violations))
    unique_blockers = sorted(set(blockers))
    return {
        "status": "pass" if not unique_violations else "fail",
        "production_readiness": (
            "ready" if not unique_violations and not unique_blockers else "blocked"
        ),
        "violations": unique_violations,
        "blockers": unique_blockers,
        "metrics": {
            "evidence_record_count": len(records),
            "qualified_record_count": qualified,
            "required_service_count": len(_SERVICE_IDS),
            "required_slo_count": len(_SLO_IDS),
            "required_capacity_scenario_count": len(_SCENARIOS),
            "violation_count": len(unique_violations),
            "readiness_blocker_count": len(unique_blockers),
        },
    }
