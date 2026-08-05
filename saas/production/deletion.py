"""Validate immutable production tenant-deletion manifests.

The contract distinguishes a complete deletion policy from operational proof. A CI
fixture can validate the schema and negative matrix, but only a current,
exact-revision, independently attested production deletion record can satisfy the
readiness result.
"""

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
_CODE = re.compile(r"^[a-z][a-z0-9_-]{1,95}$")
_EVIDENCE_KIND = "production_tenant_deletion"
_RECORD_FIELDS = {
    "schema_version",
    "evidence_id",
    "evidence_kind",
    "tenant_id_hash",
    "requested_at",
    "quiesced_at",
    "completed_at",
    "product_revision",
    "revision_contract",
    "request",
    "preconditions",
    "surface_outcomes",
    "checks",
    "artifact",
    "attestations",
    "record_sha256",
}
_REQUEST_FIELDS = {
    "operation_id_hash",
    "idempotency_key_hash",
    "authorization_decision_sha256",
    "export_decision",
    "export_artifact_sha256",
    "legal_hold",
    "legal_hold_decision_sha256",
    "deletion_reason_code",
}
_OUTCOME_FIELDS = {
    "disposition",
    "status",
    "evidence_sha256",
    "remaining_item_count",
    "runtime_accessible",
    "direct_identifiers_remaining",
    "purge_due_at",
    "retention_basis",
    "tombstone_sha256",
}
_ARTIFACT_FIELDS = {
    "uri",
    "sha256",
    "dsse_envelope_uri",
    "dsse_subject_sha256",
    "verified_workflow_identity",
}
_ATTESTATION_FIELDS = {"role", "actor_id_hash", "attested_at", "product_revision"}
_DISPOSITIONS = {
    "erase",
    "cryptographic_erase",
    "redact_and_retain",
    "anonymize_and_retain",
    "tombstone_then_expire",
}
_REQUIRED_PRECONDITIONS = {
    "tenant_pending_deletion",
    "new_admission_disabled",
    "active_runs_terminal_or_quarantined",
    "sessions_api_credentials_and_grants_revoked",
    "memberships_removed",
    "deletion_request_persisted_in_outbox",
}
_REQUIRED_CHECKS = {
    "control_plane_rls_zero_visible_rows",
    "runtime_rls_zero_visible_rows",
    "cross_tenant_canary_unchanged",
    "objects_and_artifacts_enumerated_zero",
    "search_and_vector_enumerated_zero",
    "cache_namespaces_invalidated",
    "queue_and_dlq_payloads_cleared",
    "webhook_endpoints_disabled_and_secrets_destroyed",
    "service_accounts_suspended_or_deleted_and_keys_revoked",
    "provider_and_connector_access_revoked",
    "runner_worktree_and_recovery_material_destroyed",
    "kms_grants_and_data_keys_revoked",
    "backup_tombstone_replay_verified",
    "restore_does_not_resurrect_deleted_tenant",
    "audit_and_ledger_direct_identifiers_removed",
    "retention_and_legal_hold_decisions_recorded",
    "customer_export_completed_or_waived",
}
_REQUIRED_SURFACES = {
    "control_plane_database": ("erase", 0),
    "runtime_database": ("erase", 0),
    "object_and_artifact_store": ("erase", 0),
    "vector_and_search_indexes": ("erase", 0),
    "caches": ("erase", 0),
    "queues_and_dlq": ("erase", 0),
    "provider_and_connector_state": ("erase", 0),
    "runner_worktree_and_recovery_material": ("erase", 0),
    "webhook_state": ("erase", 0),
    "secret_and_kms_references": ("cryptographic_erase", 0),
    "logs_and_traces": ("redact_and_retain", 30),
    "immutable_audit_and_ledger": ("anonymize_and_retain", 2555),
    "backups_and_snapshots": ("tombstone_then_expire", 35),
}


def canonical_deletion_record_sha256(record: Mapping[str, Any]) -> str:
    """Hash a manifest without its self-authenticating record hash."""

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


def load_deletion_evidence(repo: Path, policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Load only records from the safe policy-owned production directory."""

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


def _surface_policy(policy: Mapping[str, Any]) -> dict[str, tuple[str, int]]:
    requirements = _mapping(policy.get("required_surfaces")) or {}
    parsed: dict[str, tuple[str, int]] = {}
    for name, raw in requirements.items():
        item = _mapping(raw)
        if not isinstance(name, str) or item is None:
            continue
        disposition = item.get("disposition")
        retention = item.get("max_retention_days")
        if (
            isinstance(disposition, str)
            and isinstance(retention, int)
            and not isinstance(retention, bool)
        ):
            parsed[name] = (disposition, retention)
    return parsed


def _validate_policy(
    repo: Path,
    policy: Mapping[str, Any],
    *,
    baseline: Mapping[str, Any],
) -> list[str]:
    violations: list[str] = []
    if policy.get("schema_version") != 1:
        violations.append("deletion policy schema_version must be 1")
    if not _nonempty(policy.get("policy_id")):
        violations.append("deletion policy_id is required")
    if _parse_time(f"{policy.get('reviewed_at')}T00:00:00Z") is None:
        violations.append("deletion policy reviewed_at must be an ISO date")

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
        violations.append("deletion policy revision_contract must match production baseline")

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
        or max_age <= 0
        or max_age > 90
    ):
        violations.append("max_evidence_age_days must be between 1 and 90")
    if _string_set(policy.get("required_preconditions")) != _REQUIRED_PRECONDITIONS:
        violations.append("required_preconditions must match the deletion safety matrix")
    if _string_set(policy.get("required_checks")) != _REQUIRED_CHECKS:
        violations.append("required_checks must match the deletion reconciliation matrix")
    surfaces = _surface_policy(policy)
    if surfaces != _REQUIRED_SURFACES:
        violations.append("required_surfaces must match the complete deletion inventory")
    elif any(
        disposition not in _DISPOSITIONS or retention < 0
        for disposition, retention in surfaces.values()
    ):
        violations.append("required_surfaces contain an invalid disposition or retention")
    if _string_set(policy.get("required_attestation_roles")) != {
        "privacy",
        "security",
        "data-owner",
    }:
        violations.append("privacy, security, and data-owner attestations are required")
    schemes = _string_set(policy.get("artifact_uri_schemes"))
    if not schemes or any(scheme not in {"s3", "gs", "az", "oci"} for scheme in schemes):
        violations.append("artifact_uri_schemes must contain only immutable-store schemes")
    return violations


def _validate_request(
    request: Mapping[str, Any] | None,
    *,
    label: object,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    if request is None:
        return [f"{label}: deletion request facts are required"], blockers
    if set(request) != _REQUEST_FIELDS:
        violations.append(f"{label}: deletion request fields do not match the schema")
    for field in (
        "operation_id_hash",
        "idempotency_key_hash",
        "authorization_decision_sha256",
        "legal_hold_decision_sha256",
    ):
        if not _sha256(request.get(field)):
            violations.append(f"{label}: request.{field} must be SHA-256")
    if request.get("export_decision") not in {"completed", "waived"}:
        violations.append(f"{label}: export_decision must be completed or waived")
    export_sha = request.get("export_artifact_sha256")
    if request.get("export_decision") == "completed" and not _sha256(export_sha):
        violations.append(f"{label}: completed export requires an artifact SHA-256")
    if request.get("export_decision") == "waived" and export_sha is not None:
        violations.append(f"{label}: waived export cannot declare an artifact")
    if request.get("legal_hold") is not False:
        blockers.append(f"{label}: unresolved legal hold blocks deletion completion")
    reason = request.get("deletion_reason_code")
    if not isinstance(reason, str) or _CODE.fullmatch(reason) is None:
        violations.append(f"{label}: deletion_reason_code must be a bounded code")
    return violations, blockers


def _validate_surface_outcome(
    label: object,
    name: str,
    outcome: Mapping[str, Any] | None,
    *,
    disposition: str,
    max_retention_days: int,
    completed: datetime | None,
    now: datetime,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    prefix = f"{label}: surface {name}"
    if outcome is None:
        return [f"{prefix} outcome is required"], blockers
    if set(outcome) != _OUTCOME_FIELDS:
        violations.append(f"{prefix} fields do not match the schema")
    if outcome.get("disposition") != disposition:
        violations.append(f"{prefix} disposition does not match policy")
    if not _sha256(outcome.get("evidence_sha256")):
        violations.append(f"{prefix} evidence_sha256 is invalid")
    remaining = outcome.get("remaining_item_count")
    if not isinstance(remaining, int) or isinstance(remaining, bool) or remaining < 0:
        violations.append(f"{prefix} remaining_item_count is invalid")
        remaining = -1
    if outcome.get("runtime_accessible") is not False:
        blockers.append(f"{prefix} remains runtime-accessible")

    status = outcome.get("status")
    purge_due = _parse_time(outcome.get("purge_due_at"))
    retention_basis = outcome.get("retention_basis")
    tombstone = outcome.get("tombstone_sha256")
    if disposition in {"erase", "cryptographic_erase"}:
        if status != "erased" or remaining != 0:
            blockers.append(f"{prefix} is not completely erased")
        if outcome.get("direct_identifiers_remaining") is not False:
            blockers.append(f"{prefix} retains direct identifiers")
        if purge_due is not None or retention_basis is not None or tombstone is not None:
            violations.append(f"{prefix} cannot declare retention or tombstone facts")
        return violations, blockers

    if disposition in {"redact_and_retain", "anonymize_and_retain"}:
        if status != "retained":
            blockers.append(f"{prefix} is not in the required retained state")
        if outcome.get("direct_identifiers_remaining") is not False:
            blockers.append(f"{prefix} retains direct identifiers")
        if not isinstance(retention_basis, str) or _CODE.fullmatch(retention_basis) is None:
            violations.append(f"{prefix} retention_basis must be a bounded code")
        if purge_due is None or completed is None or purge_due < completed:
            violations.append(f"{prefix} purge_due_at is invalid")
        elif purge_due > completed + timedelta(days=max_retention_days):
            blockers.append(f"{prefix} retention exceeds policy")
        elif purge_due < now and remaining > 0:
            blockers.append(f"{prefix} retention deadline passed without erasure")
        if tombstone is not None:
            violations.append(f"{prefix} cannot declare a backup tombstone")
        return violations, blockers

    if disposition == "tombstone_then_expire":
        if status not in {"pending_retention", "erased"}:
            blockers.append(f"{prefix} has an invalid backup-retention state")
        if not _sha256(tombstone):
            violations.append(f"{prefix} tombstone_sha256 is required")
        if status == "erased":
            if remaining != 0 or outcome.get("direct_identifiers_remaining") is not False:
                blockers.append(f"{prefix} erased state retains backup data")
            if purge_due is not None or retention_basis is not None:
                violations.append(f"{prefix} erased state cannot retain a purge deadline")
        else:
            if not isinstance(retention_basis, str) or _CODE.fullmatch(retention_basis) is None:
                violations.append(f"{prefix} retention_basis must be a bounded code")
            if purge_due is None or completed is None or purge_due < completed:
                violations.append(f"{prefix} purge_due_at is invalid")
            elif purge_due > completed + timedelta(days=max_retention_days):
                blockers.append(f"{prefix} retention exceeds policy")
            elif purge_due < now and remaining > 0:
                blockers.append(f"{prefix} retention deadline passed without erasure")
        return violations, blockers

    violations.append(f"{prefix} has an unsupported disposition")
    return violations, blockers


def _validate_artifact(
    artifact: Mapping[str, Any] | None,
    *,
    label: object,
    policy: Mapping[str, Any],
) -> list[str]:
    if artifact is None:
        return [f"{label}: immutable deletion artifact is required"]
    violations: list[str] = []
    if set(artifact) != _ARTIFACT_FIELDS:
        violations.append(f"{label}: artifact fields do not match the schema")
    schemes = _string_set(policy.get("artifact_uri_schemes"))
    for field in ("uri", "dsse_envelope_uri"):
        value = artifact.get(field)
        parsed = urlsplit(value) if isinstance(value, str) else None
        if (
            parsed is None
            or parsed.scheme not in schemes
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.query)
            or bool(parsed.fragment)
        ):
            violations.append(f"{label}: artifact.{field} scheme is not allowed")
    for field in ("sha256", "dsse_subject_sha256"):
        if not _sha256(artifact.get(field)):
            violations.append(f"{label}: artifact.{field} must be SHA-256")
    if not _nonempty(artifact.get("verified_workflow_identity")):
        violations.append(f"{label}: verified workflow identity is required")
    return violations


def _validate_attestations(
    attestations: object,
    *,
    label: object,
    policy: Mapping[str, Any],
    completed: datetime | None,
    product_revision: object,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    required_roles = _string_set(policy.get("required_attestation_roles"))
    roles: set[str] = set()
    if not isinstance(attestations, list):
        return [f"{label}: attestations must be a list"], blockers
    for raw in attestations:
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
        attested_at = _parse_time(item.get("attested_at"))
        if completed is not None and (attested_at is None or attested_at < completed):
            violations.append(f"{label}: attestation time precedes deletion completion")
        if item.get("product_revision") != product_revision:
            violations.append(f"{label}: attestation revision does not match evidence")
    if roles != required_roles:
        blockers.append(f"{label}: independent attestations are incomplete")
    return violations, blockers


def _validate_record(
    record: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
    now: datetime,
    expected_product_revision: str | None,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    evidence_id = record.get("evidence_id")
    label = evidence_id if _nonempty(evidence_id) else "unknown-evidence"
    if set(record) != _RECORD_FIELDS:
        violations.append(f"{label}: record fields do not match the schema")
    if record.get("schema_version") != 1:
        violations.append(f"{label}: schema_version must be 1")
    if not isinstance(evidence_id, str) or _CODE.fullmatch(evidence_id) is None:
        violations.append("deletion evidence_id must be a bounded code")
    if record.get("evidence_kind") != _EVIDENCE_KIND:
        violations.append(f"{label}: evidence_kind must be {_EVIDENCE_KIND}")
    if not _sha256(record.get("tenant_id_hash")):
        violations.append(f"{label}: tenant_id_hash must be SHA-256")

    requested = _parse_time(record.get("requested_at"))
    quiesced = _parse_time(record.get("quiesced_at"))
    completed = _parse_time(record.get("completed_at"))
    if (
        requested is None
        or quiesced is None
        or completed is None
        or not requested <= quiesced <= completed <= now
    ):
        violations.append(f"{label}: deletion timestamps are invalid")
    elif (now - completed).total_seconds() > int(policy.get("max_evidence_age_days", 0)) * 86400:
        blockers.append(f"{label}: deletion evidence is older than policy")

    product_revision = record.get("product_revision")
    if not isinstance(product_revision, str) or _REVISION.fullmatch(product_revision) is None:
        violations.append(f"{label}: product_revision must be a full Git SHA")
    elif expected_product_revision is not None and product_revision != expected_product_revision:
        blockers.append(f"{label}: product revision does not match the release candidate")
    if _mapping(record.get("revision_contract")) != _mapping(policy.get("revision_contract")):
        blockers.append(f"{label}: revision contract does not match current policy")

    request_violations, request_blockers = _validate_request(
        _mapping(record.get("request")), label=label
    )
    violations.extend(request_violations)
    blockers.extend(request_blockers)
    preconditions = _mapping(record.get("preconditions"))
    if preconditions is None or set(preconditions) != _REQUIRED_PRECONDITIONS:
        violations.append(f"{label}: preconditions do not match policy")
    elif any(preconditions[name] is not True for name in _REQUIRED_PRECONDITIONS):
        blockers.append(f"{label}: one or more deletion preconditions failed")

    outcomes = _mapping(record.get("surface_outcomes"))
    surface_policy = _surface_policy(policy)
    if outcomes is None or set(outcomes) != set(surface_policy):
        violations.append(f"{label}: surface outcomes do not match the complete inventory")
    else:
        for name, (disposition, retention_days) in surface_policy.items():
            item_violations, item_blockers = _validate_surface_outcome(
                label,
                name,
                _mapping(outcomes.get(name)),
                disposition=disposition,
                max_retention_days=retention_days,
                completed=completed,
                now=now,
            )
            violations.extend(item_violations)
            blockers.extend(item_blockers)

    checks = _mapping(record.get("checks"))
    if checks is None or set(checks) != _REQUIRED_CHECKS:
        violations.append(f"{label}: deletion checks do not match policy")
    elif any(checks[name] is not True for name in _REQUIRED_CHECKS):
        blockers.append(f"{label}: one or more deletion checks failed")

    violations.extend(
        _validate_artifact(_mapping(record.get("artifact")), label=label, policy=policy)
    )
    attestation_violations, attestation_blockers = _validate_attestations(
        record.get("attestations"),
        label=label,
        policy=policy,
        completed=completed,
        product_revision=product_revision,
    )
    violations.extend(attestation_violations)
    blockers.extend(attestation_blockers)
    record_hash = record.get("record_sha256")
    if not _sha256(record_hash) or record_hash != canonical_deletion_record_sha256(record):
        violations.append(f"{label}: record_sha256 does not authenticate the canonical record")
    return violations, blockers


def validate_deletion_readiness(
    repo: Path,
    policy: Mapping[str, Any],
    records: Collection[Mapping[str, Any]],
    *,
    now: datetime | None = None,
    expected_product_revision: str | None = None,
) -> dict[str, Any]:
    """Validate policy and evidence without manufacturing production proof."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    baseline = _load_json(repo / "saas/production/baseline.json")
    violations = _validate_policy(repo, policy, baseline=baseline)
    blockers: list[str] = []
    qualified = 0
    evidence_ids: set[str] = set()
    for record in records:
        evidence_id = record.get("evidence_id")
        if isinstance(evidence_id, str):
            if evidence_id in evidence_ids:
                violations.append(f"duplicate deletion evidence_id {evidence_id}")
            evidence_ids.add(evidence_id)
        record_violations, record_blockers = _validate_record(
            record,
            policy=policy,
            now=current,
            expected_product_revision=expected_product_revision,
        )
        violations.extend(record_violations)
        blockers.extend(record_blockers)
        if not record_violations and not record_blockers:
            qualified += 1
    if qualified == 0:
        blockers.append("no current qualifying production tenant deletion evidence")
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
            "required_surface_count": len(_REQUIRED_SURFACES),
            "violation_count": len(unique_violations),
            "readiness_blocker_count": len(unique_blockers),
        },
    }
