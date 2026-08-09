"""Validate immutable commercial and enterprise production-acceptance evidence."""

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
    "environment",
    "subject_hashes",
    "integrations",
    "checks",
    "scenarios",
    "metrics",
    "customer_acceptances",
    "artifact",
    "attestations",
    "record_sha256",
}
_INTEGRATION_FIELDS = {
    "provider_id_hash",
    "account_id_hash",
    "environment",
    "checks",
    "evidence_sha256",
}
_SCENARIO_FIELDS = {"result", "evidence_sha256"}
_ACCEPTANCE_FIELDS = {
    "tenant_id_hash",
    "acceptance_id_hash",
    "accepted_at",
    "evidence_sha256",
}
_ARTIFACT_FIELDS = {
    "uri",
    "sha256",
    "dsse_envelope_uri",
    "dsse_subject_sha256",
    "verified_workflow_identity",
}
_ATTESTATION_FIELDS = {"role", "actor_id_hash", "attested_at", "product_revision"}


def canonical_business_record_sha256(record: Mapping[str, Any]) -> str:
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


def load_business_evidence(repo: Path, policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Load non-symlink evidence records from a policy-owned directory."""

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
            raise ValueError("business evidence cannot contain symbolic links")
        records.append(_load_json(path))
    return records


def _validate_policy(
    repo: Path,
    policy: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> list[str]:
    violations: list[str] = []
    if policy.get("schema_version") != 1:
        violations.append("business policy schema_version must be 1")
    for field in ("policy_id", "evidence_kind"):
        if not _nonempty(policy.get(field)):
            violations.append(f"business policy {field} is required")
    if _parse_time(f"{policy.get('reviewed_at')}T00:00:00Z") is None:
        violations.append("business policy reviewed_at must be an ISO date")

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
        violations.append("business policy revision_contract must match production baseline")

    directory = policy.get("evidence_directory")
    if (
        not isinstance(directory, str)
        or Path(directory).is_absolute()
        or ".." in Path(directory).parts
    ):
        violations.append("evidence_directory must be a safe repository-relative path")
    elif not (repo / directory).is_dir():
        violations.append("evidence_directory must exist")
    age = policy.get("max_evidence_age_days")
    if not isinstance(age, int) or isinstance(age, bool) or not 1 <= age <= 31:
        violations.append("max_evidence_age_days must be between 1 and 31")

    integrations = _mapping(policy.get("required_integrations"))
    if integrations is None or len(integrations) < 4:
        violations.append("at least four production integrations are required")
    else:
        for name, checks in integrations.items():
            if not _nonempty(name) or len(_string_set(checks)) < 3:
                violations.append(f"integration {name} requires at least three checks")
    if len(_string_set(policy.get("required_checks"))) < 10:
        violations.append("business policy requires at least ten aggregate checks")
    if len(_string_set(policy.get("required_scenarios"))) < 10:
        violations.append("business policy requires at least ten failure scenarios")
    zeros = _string_set(policy.get("required_zero_metrics"))
    positives = _string_set(policy.get("required_positive_metrics"))
    if not zeros or not positives or zeros & positives:
        violations.append("zero and positive metric sets must be non-empty and disjoint")
    minimum = policy.get("minimum_customer_acceptances")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
        violations.append("minimum_customer_acceptances must be positive")
    if len(_string_set(policy.get("required_attestation_roles"))) < 4:
        violations.append("at least four independent attestation roles are required")
    schemes = _string_set(policy.get("artifact_uri_schemes"))
    if not schemes or any(value not in {"s3", "gs", "az", "oci"} for value in schemes):
        violations.append("artifact_uri_schemes contains an unapproved scheme")
    if not _string_set(policy.get("verified_workflow_identities")):
        violations.append("verified_workflow_identities must not be empty")
    return violations


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
    if record.get("schema_version") != 1:
        violations.append(f"{label}: schema_version must be 1")
    if not _nonempty(evidence_id):
        violations.append("business evidence_id is required")
    if record.get("evidence_kind") != policy.get("evidence_kind"):
        violations.append(f"{label}: evidence_kind does not match policy")
    if record.get("environment") != "production":
        violations.append(f"{label}: environment must be production")

    started = _parse_time(record.get("started_at"))
    completed = _parse_time(record.get("completed_at"))
    if started is None or completed is None or completed < started or completed > now:
        violations.append(f"{label}: evidence timestamps are invalid")
    elif now - completed > timedelta(days=int(policy.get("max_evidence_age_days", 0))):
        blockers.append(f"{label}: evidence is older than policy")

    revision = record.get("product_revision")
    if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
        violations.append(f"{label}: product_revision must be a full Git SHA")
    elif expected_product_revision is not None and revision != expected_product_revision:
        blockers.append(f"{label}: product revision does not match the release candidate")
    if _mapping(record.get("revision_contract")) != _mapping(policy.get("revision_contract")):
        blockers.append(f"{label}: revision contract does not match current policy")

    subject_hashes = record.get("subject_hashes")
    if (
        not isinstance(subject_hashes, list)
        or not subject_hashes
        or any(not _sha256(value) for value in subject_hashes)
        or len(subject_hashes) != len(set(subject_hashes))
    ):
        violations.append(f"{label}: subject_hashes must be unique SHA-256 values")

    required_integrations = _mapping(policy.get("required_integrations")) or {}
    integrations = _mapping(record.get("integrations"))
    if integrations is None or set(integrations) != set(required_integrations):
        violations.append(f"{label}: integrations do not match policy")
    else:
        for name, raw in integrations.items():
            integration = _mapping(raw)
            if integration is None or set(integration) != _INTEGRATION_FIELDS:
                violations.append(f"{label}: {name} integration facts do not match schema")
                continue
            for field in ("provider_id_hash", "account_id_hash", "evidence_sha256"):
                if not _sha256(integration.get(field)):
                    violations.append(f"{label}: {name}.{field} must be SHA-256")
            if integration.get("environment") != "production":
                violations.append(f"{label}: {name} integration must be production")
            expected_checks = _string_set(required_integrations[name])
            actual_checks = _mapping(integration.get("checks"))
            if actual_checks is None or set(actual_checks) != expected_checks:
                violations.append(f"{label}: {name} checks do not match policy")
            elif any(actual_checks[check] is not True for check in expected_checks):
                blockers.append(f"{label}: {name} integration checks did not all pass")

    expected_checks = _string_set(policy.get("required_checks"))
    checks = _mapping(record.get("checks"))
    if checks is None or set(checks) != expected_checks:
        violations.append(f"{label}: aggregate checks do not match policy")
    elif any(checks[name] is not True for name in expected_checks):
        blockers.append(f"{label}: one or more aggregate checks failed")

    expected_scenarios = _string_set(policy.get("required_scenarios"))
    scenarios = _mapping(record.get("scenarios"))
    if scenarios is None or set(scenarios) != expected_scenarios:
        violations.append(f"{label}: scenarios do not match policy")
    else:
        for name, raw in scenarios.items():
            scenario = _mapping(raw)
            if scenario is None or set(scenario) != _SCENARIO_FIELDS:
                violations.append(f"{label}: {name} scenario facts do not match schema")
                continue
            if scenario.get("result") != "passed":
                blockers.append(f"{label}: {name} scenario did not pass")
            if not _sha256(scenario.get("evidence_sha256")):
                violations.append(f"{label}: {name} evidence_sha256 must be SHA-256")

    zero_metrics = _string_set(policy.get("required_zero_metrics"))
    positive_metrics = _string_set(policy.get("required_positive_metrics"))
    metrics = _mapping(record.get("metrics"))
    if metrics is None or set(metrics) != zero_metrics | positive_metrics:
        violations.append(f"{label}: metrics do not match policy")
    else:
        for name in zero_metrics:
            value = metrics[name]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                violations.append(f"{label}: metric {name} must be a non-negative integer")
            elif value != 0:
                blockers.append(f"{label}: metric {name} must be zero")
        for name in positive_metrics:
            value = metrics[name]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                violations.append(f"{label}: metric {name} must be a non-negative integer")
            elif value <= 0:
                blockers.append(f"{label}: metric {name} must be positive")

    acceptances = record.get("customer_acceptances")
    accepted_hashes: set[str] = set()
    if not isinstance(acceptances, list):
        violations.append(f"{label}: customer_acceptances must be a list")
    else:
        for raw in acceptances:
            acceptance = _mapping(raw)
            if acceptance is None or set(acceptance) != _ACCEPTANCE_FIELDS:
                violations.append(f"{label}: customer acceptance facts do not match schema")
                continue
            for field in ("tenant_id_hash", "acceptance_id_hash", "evidence_sha256"):
                if not _sha256(acceptance.get(field)):
                    violations.append(f"{label}: customer acceptance {field} must be SHA-256")
            acceptance_hash = acceptance.get("acceptance_id_hash")
            if isinstance(acceptance_hash, str) and acceptance_hash in accepted_hashes:
                violations.append(f"{label}: customer acceptance identities must be unique")
            elif isinstance(acceptance_hash, str):
                accepted_hashes.add(acceptance_hash)
            accepted_at = _parse_time(acceptance.get("accepted_at"))
            if (
                accepted_at is None
                or started is None
                or completed is None
                or accepted_at < started
                or accepted_at > completed
            ):
                violations.append(f"{label}: customer acceptance time is outside evidence")
        minimum = int(policy.get("minimum_customer_acceptances", 1))
        if len(acceptances) < minimum:
            blockers.append(f"{label}: customer acceptance count is below policy")

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
                or completed is None
                or attested_at < completed
                or attested_at > now
            ):
                violations.append(f"{label}: attestation time is outside the approval window")
            if attestation.get("product_revision") != revision:
                violations.append(f"{label}: attestation product revision does not match")
    if roles != required_roles:
        blockers.append(f"{label}: independent attestations are incomplete")

    if not _sha256(record.get("record_sha256")) or record.get(
        "record_sha256"
    ) != canonical_business_record_sha256(record):
        violations.append(f"{label}: record_sha256 does not authenticate the canonical record")
    qualifies = not violations and not blockers
    return violations, blockers, qualifies


def validate_business_readiness(
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
            violations.append(f"duplicate business evidence_id {evidence_id}")
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
    kind = str(policy.get("evidence_kind", "business"))
    if not records or (qualified == 0 and not blockers):
        blockers.append(f"no current qualifying {kind} evidence")
    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": (
            "ready" if not violations and not blockers and qualified > 0 else "blocked"
        ),
        "evidence_kind": kind,
        "violations": sorted(set(violations)),
        "blockers": sorted(set(blockers)),
        "metrics": {
            "evidence_record_count": len(records),
            "qualified_record_count": qualified,
            "required_integration_count": len(_mapping(policy.get("required_integrations")) or {}),
            "required_check_count": len(_string_set(policy.get("required_checks"))),
            "required_scenario_count": len(_string_set(policy.get("required_scenarios"))),
            "violation_count": len(set(violations)),
            "readiness_blocker_count": len(set(blockers)),
        },
    }
