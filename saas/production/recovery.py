"""Validate immutable tenant and cluster recovery-drill evidence.

The validator separates a structurally complete recovery policy from production
readiness. A backup job, local restore, or CI fixture can test this contract but
cannot satisfy it: only exact-revision, independently attested production-drill
records from both required scopes count toward readiness.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DATA_CLASSES = {"T0", "T1", "T2"}
_SCOPES = {"tenant", "cluster"}


def canonical_record_sha256(record: Mapping[str, Any]) -> str:
    """Hash a record without its self-authenticating ``record_sha256`` field."""

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


def load_recovery_evidence(repo: Path, policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Load production evidence records from the policy-owned directory."""

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
    return [_load_json(path) for path in sorted(directory.glob("*.json"))]


def _validate_policy(
    repo: Path,
    policy: Mapping[str, Any],
    *,
    baseline: Mapping[str, Any],
) -> list[str]:
    violations: list[str] = []
    if policy.get("schema_version") != 1:
        violations.append("recovery policy schema_version must be 1")
    if not _nonempty(policy.get("policy_id")):
        violations.append("recovery policy_id is required")
    if _parse_time(f"{policy.get('reviewed_at')}T00:00:00Z") is None:
        violations.append("recovery policy reviewed_at must be an ISO date")

    revision = _mapping(policy.get("revision_contract"))
    baseline_revision = _mapping(baseline.get("revision_contract")) or {}
    expected_revision = {
        key: baseline_revision.get(key)
        for key in (
            "upstream_revision",
            "adapter_contract_version",
            "control_plane_schema_revision",
        )
    }
    if revision != expected_revision:
        violations.append("recovery policy revision_contract must match production baseline")

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
    if not isinstance(max_age, int) or max_age <= 0 or max_age > 90:
        violations.append("max_evidence_age_days must be between 1 and 90")
    domains = policy.get("minimum_source_failure_domains")
    if not isinstance(domains, int) or domains < 2:
        violations.append("minimum_source_failure_domains must be at least 2")
    if _string_set(policy.get("required_drill_scopes")) != _SCOPES:
        violations.append("required_drill_scopes must be tenant and cluster")

    boundaries = _string_set(policy.get("required_isolation_boundaries"))
    if len(boundaries) < 6:
        violations.append("at least six isolation boundaries are required")
    roles = _string_set(policy.get("required_attestation_roles"))
    if len(roles) < 3:
        violations.append("at least three independent attestation roles are required")
    checks = _string_set(policy.get("required_checks"))
    required_checks = {
        "backup_integrity",
        "restore_completed",
        "source_schema_exact",
        "source_revision_exact",
        "forced_rls_control_plane_88",
        "forced_rls_runtime_17",
        "cross_tenant_negative",
        "tombstone_replay",
        "revocation_replay",
        "machine_credential_revocation_replay",
        "binding_generation_fence",
        "active_binding_uniqueness",
        "ledger_conservation",
        "object_reference_integrity",
        "kms_decryptability",
        "canary_authorization",
        "traffic_disabled_until_validation",
    }
    if checks != required_checks:
        violations.append("required_checks must match the complete recovery safety matrix")
    schemes = _string_set(policy.get("artifact_uri_schemes"))
    if not schemes or any(scheme not in {"s3", "gs", "az", "oci"} for scheme in schemes):
        violations.append("artifact_uri_schemes must contain only immutable-store schemes")

    classes = policy.get("data_classes")
    if (
        not isinstance(classes, list)
        or {item.get("id") for item in classes if isinstance(item, dict)} != _DATA_CLASSES
    ):
        violations.append("recovery policy must contain T0, T1, and T2 objectives")
    return violations


def _validate_record(
    record: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
    now: datetime,
    expected_product_revision: str | None,
) -> tuple[list[str], list[str], str | None]:
    violations: list[str] = []
    blockers: list[str] = []
    evidence_id = record.get("evidence_id")
    label = evidence_id if _nonempty(evidence_id) else "unknown-evidence"
    if record.get("schema_version") != 1:
        violations.append(f"{label}: schema_version must be 1")
    if not _nonempty(evidence_id):
        violations.append("recovery evidence_id is required")
    if record.get("evidence_kind") != "production_drill":
        violations.append(f"{label}: evidence_kind must be production_drill")
    scope = record.get("drill_scope")
    if scope not in _SCOPES:
        violations.append(f"{label}: drill_scope must be tenant or cluster")
        scope = None
    tenant_hash = record.get("tenant_id_hash")
    if scope == "tenant" and not _sha256(tenant_hash):
        violations.append(f"{label}: tenant drill requires tenant_id_hash")
    if scope == "cluster" and tenant_hash is not None:
        violations.append(f"{label}: cluster drill cannot declare tenant_id_hash")

    started = _parse_time(record.get("started_at"))
    completed = _parse_time(record.get("completed_at"))
    if started is None or completed is None or completed < started or completed > now:
        violations.append(f"{label}: drill timestamps are invalid")
    elif (now - completed).total_seconds() > int(policy.get("max_evidence_age_days", 0)) * 86400:
        blockers.append(f"{label}: recovery evidence is older than policy")

    product_revision = record.get("product_revision")
    if not isinstance(product_revision, str) or _REVISION.fullmatch(product_revision) is None:
        violations.append(f"{label}: product_revision must be a full Git SHA")
    elif expected_product_revision is not None and product_revision != expected_product_revision:
        blockers.append(f"{label}: product revision does not match the release candidate")
    if _mapping(record.get("revision_contract")) != _mapping(policy.get("revision_contract")):
        blockers.append(f"{label}: revision contract does not match current policy")

    source = _mapping(record.get("source"))
    minimum_domains = int(policy.get("minimum_source_failure_domains", 2))
    if source is None:
        violations.append(f"{label}: source is required")
    else:
        if source.get("environment") != "production":
            violations.append(f"{label}: source environment must be production")
        if not _nonempty(source.get("region")):
            violations.append(f"{label}: source region is required")
        domains = _string_set(source.get("failure_domains"))
        if len(domains) < minimum_domains:
            blockers.append(f"{label}: source does not prove two failure domains")

    backup = _mapping(record.get("backup"))
    if backup is None:
        violations.append(f"{label}: backup facts are required")
    else:
        for field in (
            "backup_id_hash",
            "manifest_sha256",
            "wal_chain_sha256",
            "object_versions_sha256",
            "kms_key_version_hash",
        ):
            if not _sha256(backup.get(field)):
                violations.append(f"{label}: backup.{field} must be SHA-256")
        if backup.get("encrypted") is not True or backup.get("deletion_protected") is not True:
            blockers.append(f"{label}: backup is not encrypted and deletion-protected")
        if not _nonempty(backup.get("storage_failure_domain")):
            violations.append(f"{label}: backup storage failure domain is required")
        elif source is not None and backup.get("storage_failure_domain") in _string_set(
            source.get("failure_domains")
        ):
            blockers.append(f"{label}: backup is not stored in another failure domain")

    isolation = _mapping(record.get("isolation"))
    required_boundaries = _string_set(policy.get("required_isolation_boundaries"))
    if isolation is None:
        violations.append(f"{label}: isolation facts are required")
    else:
        if isolation.get("shared_environment") is not False:
            blockers.append(f"{label}: restore target is shared")
        if isolation.get("production_traffic_enabled_during_validation") is not False:
            blockers.append(f"{label}: traffic was enabled before validation completed")
        boundaries = _mapping(isolation.get("boundaries")) or {}
        if set(boundaries) != required_boundaries:
            violations.append(f"{label}: isolation boundaries do not match policy")
        for boundary in required_boundaries:
            pair = _mapping(boundaries.get(boundary))
            if (
                pair is None
                or not _sha256(pair.get("source_hash"))
                or not _sha256(pair.get("restore_hash"))
            ):
                violations.append(f"{label}: isolation {boundary} hashes are invalid")
            elif pair["source_hash"] == pair["restore_hash"]:
                blockers.append(f"{label}: isolation {boundary} was reused")

    checks = _mapping(record.get("checks"))
    required_checks = _string_set(policy.get("required_checks"))
    if checks is None or set(checks) != required_checks:
        violations.append(f"{label}: recovery checks do not match policy")
    elif any(checks[name] is not True for name in required_checks):
        blockers.append(f"{label}: one or more recovery checks failed")

    objectives = {
        item["id"]: item
        for item in policy.get("data_classes", [])
        if isinstance(item, dict) and item.get("id") in _DATA_CLASSES
    }
    outcomes = _mapping(record.get("data_class_outcomes"))
    if outcomes is None or set(outcomes) != _DATA_CLASSES:
        violations.append(f"{label}: data_class_outcomes must contain T0, T1, and T2")
    else:
        for class_id, objective in objectives.items():
            outcome = _mapping(outcomes.get(class_id))
            if outcome is None:
                continue
            rto = outcome.get("achieved_rto_seconds")
            if not isinstance(rto, int) or rto < 0:
                violations.append(f"{label}: {class_id} achieved_rto_seconds is invalid")
            elif rto > objective["rto_seconds"]:
                blockers.append(f"{label}: {class_id} RTO exceeds policy")
            if class_id == "T2":
                if outcome.get("achieved_rpo_mode") != objective.get("rpo_mode"):
                    blockers.append(f"{label}: T2 did not restore the latest durable point")
            else:
                rpo = outcome.get("achieved_rpo_seconds")
                if not isinstance(rpo, int) or rpo < 0:
                    violations.append(f"{label}: {class_id} achieved_rpo_seconds is invalid")
                elif rpo > objective["rpo_seconds"]:
                    blockers.append(f"{label}: {class_id} RPO exceeds policy")

    artifact = _mapping(record.get("artifact"))
    if artifact is None:
        violations.append(f"{label}: immutable artifact is required")
    else:
        uri = artifact.get("uri")
        envelope = artifact.get("dsse_envelope_uri")
        schemes = _string_set(policy.get("artifact_uri_schemes"))
        if not isinstance(uri, str) or urlsplit(uri).scheme not in schemes:
            violations.append(f"{label}: artifact URI scheme is not allowed")
        if not isinstance(envelope, str) or urlsplit(envelope).scheme not in schemes:
            violations.append(f"{label}: DSSE envelope URI scheme is not allowed")
        for field in ("sha256", "dsse_subject_sha256"):
            if not _sha256(artifact.get(field)):
                violations.append(f"{label}: artifact.{field} must be SHA-256")
        if not _nonempty(artifact.get("verified_workflow_identity")):
            violations.append(f"{label}: verified workflow identity is required")

    required_roles = _string_set(policy.get("required_attestation_roles"))
    attestations = record.get("attestations")
    attested_roles: set[str] = set()
    if not isinstance(attestations, list):
        violations.append(f"{label}: attestations must be a list")
    else:
        for attestation in attestations:
            item = _mapping(attestation)
            if item is None:
                violations.append(f"{label}: attestation entries must be objects")
                continue
            role = item.get("role")
            if role in attested_roles:
                violations.append(f"{label}: duplicate attestation role {role}")
            if isinstance(role, str):
                attested_roles.add(role)
            if not _sha256(item.get("actor_id_hash")):
                violations.append(f"{label}: attestation actor_id_hash is invalid")
            attested_at = _parse_time(item.get("attested_at"))
            if completed is not None and (attested_at is None or attested_at < completed):
                violations.append(f"{label}: attestation time precedes drill completion")
            if item.get("product_revision") != product_revision:
                violations.append(f"{label}: attestation revision does not match evidence")
        if attested_roles != required_roles:
            blockers.append(f"{label}: independent attestations are incomplete")

    record_hash = record.get("record_sha256")
    if not _sha256(record_hash) or record_hash != canonical_record_sha256(record):
        violations.append(f"{label}: record_sha256 does not authenticate the canonical record")
    return violations, blockers, scope if isinstance(scope, str) else None


def validate_recovery_readiness(
    repo: Path,
    policy: Mapping[str, Any],
    records: Collection[Mapping[str, Any]],
    *,
    now: datetime | None = None,
    expected_product_revision: str | None = None,
) -> dict[str, Any]:
    """Validate policy/evidence and report readiness without manufacturing proof."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    baseline = _load_json(repo / "saas/production/baseline.json")
    violations = _validate_policy(repo, policy, baseline=baseline)
    blockers: list[str] = []
    qualified_scopes: set[str] = set()
    for record in records:
        record_violations, record_blockers, scope = _validate_record(
            record,
            policy=policy,
            now=current,
            expected_product_revision=expected_product_revision,
        )
        violations.extend(record_violations)
        blockers.extend(record_blockers)
        if not record_violations and not record_blockers and scope is not None:
            qualified_scopes.add(scope)
    missing = _string_set(policy.get("required_drill_scopes")) - qualified_scopes
    for scope in sorted(missing):
        blockers.append(f"no current qualifying {scope} recovery drill evidence")
    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": ("ready" if not violations and not blockers else "blocked"),
        "violations": sorted(set(violations)),
        "blockers": sorted(set(blockers)),
        "metrics": {
            "evidence_record_count": len(records),
            "qualified_scope_count": len(qualified_scopes),
            "required_scope_count": len(_string_set(policy.get("required_drill_scopes"))),
            "violation_count": len(set(violations)),
            "readiness_blocker_count": len(set(blockers)),
        },
    }
