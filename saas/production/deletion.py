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
_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_EVIDENCE_KIND = "production_tenant_deletion"
_POLICY_FIELDS = {
    "schema_version",
    "policy_id",
    "reviewed_at",
    "revision_contract",
    "evidence_directory",
    "max_evidence_age_days",
    "required_preconditions",
    "required_surfaces",
    "required_checks",
    "required_attestation_roles",
    "artifact_uri_schemes",
    "required_signature_algorithm",
    "required_signing_key_purpose",
    "trusted_signing_key_ids",
    "trusted_workflow_identities",
}
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
    "artifact",
}
_EVIDENCE_ARTIFACT_FIELDS = {
    "payload_sha256",
    "dsse_envelope_sha256",
    "immutability_receipt_sha256",
    "kms_receipt_sha256",
    "signature_algorithm",
    "signing_key_id",
    "signing_key_purpose",
    "workflow_identity",
    "verified_at",
}
_ARTIFACT_FIELDS = {
    "uri",
    "sha256",
    "dsse_envelope_uri",
    *_EVIDENCE_ARTIFACT_FIELDS,
}
_ATTESTATION_FIELDS = {
    "role",
    "actor_id_hmac",
    "attested_at",
    "product_revision",
    "record_subject_sha256",
}
_REQUIRED_ATTESTATION_ROLES = {"privacy", "security", "data_owner"}
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
    "scim_directory_tokens_revoked_and_hashes_destroyed",
    "scim_subject_mappings_erased",
    "scim_receipts_anonymized_without_replay_resurrection",
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
    "enterprise_identity_provisioning_state": ("erase", 0),
    "enterprise_identity_event_receipts": ("anonymize_and_retain", 2555),
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


def canonical_deletion_attestation_subject_sha256(record: Mapping[str, Any]) -> str:
    """Hash the deletion facts independently of attestations and the final self-hash.

    Attestors bind this digest, which avoids a circular dependency between their
    signatures and ``record_sha256`` while still binding every request, surface,
    check, artifact, timestamp, and revision fact in the record.
    """

    payload = {
        key: value for key, value in record.items() if key not in {"attestations", "record_sha256"}
    }
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
    if set(policy) != _POLICY_FIELDS:
        violations.append("deletion policy fields do not match the v2 schema")
    if policy.get("schema_version") != 2:
        violations.append("deletion policy schema_version must be 2")
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
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0 or max_age > 90:
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
    if _string_set(policy.get("required_attestation_roles")) != _REQUIRED_ATTESTATION_ROLES:
        violations.append("privacy, security, and data_owner attestations are required")
    schemes = _string_set(policy.get("artifact_uri_schemes"))
    if not schemes or any(scheme not in {"s3", "gs", "az", "oci"} for scheme in schemes):
        violations.append("artifact_uri_schemes must contain only immutable-store schemes")
    if policy.get("required_signature_algorithm") != "ed25519":
        violations.append("deletion evidence requires the ed25519 signature algorithm")
    if policy.get("required_signing_key_purpose") != "production-tenant-deletion-evidence":
        violations.append("deletion evidence signing key purpose is invalid")
    key_ids = _string_set(policy.get("trusted_signing_key_ids"))
    if not key_ids or any(_KEY_ID.fullmatch(value) is None for value in key_ids):
        violations.append("trusted_signing_key_ids must contain bounded key identifiers")
    identities = _string_set(policy.get("trusted_workflow_identities"))
    if not identities or any(not value.strip() or len(value) > 512 for value in identities):
        violations.append("trusted_workflow_identities must contain bounded identities")
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
    policy: Mapping[str, Any],
) -> tuple[list[str], list[str], datetime | None]:
    violations: list[str] = []
    blockers: list[str] = []
    prefix = f"{label}: surface {name}"
    if outcome is None:
        return [f"{prefix} outcome is required"], blockers, None
    if set(outcome) != _OUTCOME_FIELDS:
        violations.append(f"{prefix} fields do not match the schema")
    if outcome.get("disposition") != disposition:
        violations.append(f"{prefix} disposition does not match policy")
    evidence_sha256 = outcome.get("evidence_sha256")
    if not _sha256(evidence_sha256):
        violations.append(f"{prefix} evidence_sha256 is invalid")
    artifact_violations, artifact_verified_at = _validate_evidence_artifact(
        _mapping(outcome.get("artifact")),
        prefix=f"{prefix} artifact",
        policy=policy,
        completed=completed,
        now=now,
        expected_payload_sha256=evidence_sha256,
    )
    violations.extend(artifact_violations)
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
        return violations, blockers, artifact_verified_at

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
        return violations, blockers, artifact_verified_at

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
        return violations, blockers, artifact_verified_at

    violations.append(f"{prefix} has an unsupported disposition")
    return violations, blockers, artifact_verified_at


def _validate_evidence_artifact(
    artifact: Mapping[str, Any] | None,
    *,
    prefix: str,
    policy: Mapping[str, Any],
    completed: datetime | None,
    now: datetime,
    expected_payload_sha256: object,
) -> tuple[list[str], datetime | None]:
    """Validate a fail-closed DSSE/KMS/immutability proof bundle."""

    if artifact is None:
        return [f"{prefix} proof is required"], None
    violations: list[str] = []
    if set(artifact) != _EVIDENCE_ARTIFACT_FIELDS:
        violations.append(f"{prefix} fields do not match the v2 schema")
    for field in (
        "payload_sha256",
        "dsse_envelope_sha256",
        "immutability_receipt_sha256",
        "kms_receipt_sha256",
    ):
        if not _sha256(artifact.get(field)):
            violations.append(f"{prefix}.{field} must be SHA-256")
    if (
        _sha256(expected_payload_sha256)
        and artifact.get("payload_sha256") != expected_payload_sha256
    ):
        violations.append(f"{prefix}.payload_sha256 does not bind the evidence payload")

    signature_algorithm = artifact.get("signature_algorithm")
    if signature_algorithm != policy.get("required_signature_algorithm"):
        violations.append(f"{prefix} signature algorithm does not match policy")
    signing_key_id = artifact.get("signing_key_id")
    if not isinstance(signing_key_id, str) or _KEY_ID.fullmatch(signing_key_id) is None:
        violations.append(f"{prefix}.signing_key_id must be a bounded key identifier")
    elif signing_key_id not in _string_set(policy.get("trusted_signing_key_ids")):
        violations.append(f"{prefix}.signing_key_id is not trusted")
    if artifact.get("signing_key_purpose") != policy.get("required_signing_key_purpose"):
        violations.append(f"{prefix} signing key purpose does not match policy")
    if artifact.get("workflow_identity") not in _string_set(
        policy.get("trusted_workflow_identities")
    ):
        violations.append(f"{prefix} workflow identity is not trusted")

    verified_at = _parse_time(artifact.get("verified_at"))
    if verified_at is None:
        violations.append(f"{prefix}.verified_at must be an ISO UTC timestamp")
    elif completed is None or verified_at < completed or verified_at > now:
        violations.append(f"{prefix}.verified_at must follow completion and not be in the future")
    return violations, verified_at


def _validate_artifact(
    artifact: Mapping[str, Any] | None,
    *,
    label: object,
    policy: Mapping[str, Any],
    completed: datetime | None,
    now: datetime,
) -> tuple[list[str], datetime | None]:
    if artifact is None:
        return [f"{label}: immutable deletion artifact is required"], None
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
    artifact_sha256 = artifact.get("sha256")
    if not _sha256(artifact_sha256):
        violations.append(f"{label}: artifact.sha256 must be SHA-256")
    proof = {field: artifact.get(field) for field in _EVIDENCE_ARTIFACT_FIELDS}
    proof_violations, verified_at = _validate_evidence_artifact(
        proof,
        prefix=f"{label}: artifact",
        policy=policy,
        completed=completed,
        now=now,
        expected_payload_sha256=artifact_sha256,
    )
    violations.extend(proof_violations)
    return violations, verified_at


def _validate_attestations(
    attestations: object,
    *,
    label: object,
    policy: Mapping[str, Any],
    completed: datetime | None,
    product_revision: object,
    record_subject_sha256: str,
    verification_floor: datetime | None,
    now: datetime,
) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    required_roles = _string_set(policy.get("required_attestation_roles"))
    roles: set[str] = set()
    actor_id_hmacs: set[str] = set()
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
        elif role not in required_roles:
            violations.append(f"{label}: unsupported attestation role {role}")
        elif role in roles:
            violations.append(f"{label}: duplicate attestation role {role}")
        else:
            roles.add(role)
        actor_id_hmac = item.get("actor_id_hmac")
        if not isinstance(actor_id_hmac, str) or not _sha256(actor_id_hmac):
            violations.append(f"{label}: attestation actor_id_hmac is invalid")
        elif actor_id_hmac in actor_id_hmacs:
            violations.append(f"{label}: attestation actors must be pairwise distinct")
        else:
            actor_id_hmacs.add(actor_id_hmac)
        attested_at = _parse_time(item.get("attested_at"))
        minimum_time = verification_floor or completed
        if attested_at is None:
            violations.append(f"{label}: attestation time is invalid")
        elif minimum_time is None or attested_at < minimum_time or attested_at > now:
            violations.append(
                f"{label}: attestation time must follow evidence verification and not be future"
            )
        if item.get("product_revision") != product_revision:
            violations.append(f"{label}: attestation revision does not match evidence")
        if item.get("record_subject_sha256") != record_subject_sha256:
            violations.append(f"{label}: attestation does not bind the canonical record subject")
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
    if record.get("schema_version") != 2:
        violations.append(f"{label}: schema_version must be 2")
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
    verification_times: list[datetime] = []
    if outcomes is None or set(outcomes) != set(surface_policy):
        violations.append(f"{label}: surface outcomes do not match the complete inventory")
    else:
        for name, (disposition, retention_days) in surface_policy.items():
            item_violations, item_blockers, verified_at = _validate_surface_outcome(
                label,
                name,
                _mapping(outcomes.get(name)),
                disposition=disposition,
                max_retention_days=retention_days,
                completed=completed,
                now=now,
                policy=policy,
            )
            violations.extend(item_violations)
            blockers.extend(item_blockers)
            if verified_at is not None:
                verification_times.append(verified_at)

    checks = _mapping(record.get("checks"))
    if checks is None or set(checks) != _REQUIRED_CHECKS:
        violations.append(f"{label}: deletion checks do not match policy")
    elif any(checks[name] is not True for name in _REQUIRED_CHECKS):
        blockers.append(f"{label}: one or more deletion checks failed")

    artifact_violations, artifact_verified_at = _validate_artifact(
        _mapping(record.get("artifact")),
        label=label,
        policy=policy,
        completed=completed,
        now=now,
    )
    violations.extend(artifact_violations)
    if artifact_verified_at is not None:
        verification_times.append(artifact_verified_at)
    record_subject_sha256 = canonical_deletion_attestation_subject_sha256(record)
    attestation_violations, attestation_blockers = _validate_attestations(
        record.get("attestations"),
        label=label,
        policy=policy,
        completed=completed,
        product_revision=product_revision,
        record_subject_sha256=record_subject_sha256,
        verification_floor=max(verification_times) if verification_times else None,
        now=now,
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
