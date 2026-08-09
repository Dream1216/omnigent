"""Cryptographically admit production evidence before aggregate gates consume it.

Domain validators prove that an evidence document has the expected shape and facts.
This module proves a separate property: the exact bytes were admitted by a trusted
production workflow key.  A claimed DSSE URI or workflow identity inside an evidence
document is not sufficient on its own.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_REQUIRED_KINDS = {
    "baseline",
    "image",
    "deployment",
    "recovery",
    "slo_capacity",
    "deletion",
    "commercial",
    "enterprise",
}
_POLICY_FIELDS = {
    "schema_version",
    "policy_id",
    "reviewed_at",
    "payload_type",
    "signature_algorithm",
    "maximum_receipt_age_days",
    "trusted_key_registry",
    "receipt_directory",
    "evidence_sources",
}
_SOURCE_FIELDS = {"kind", "path", "directory", "pattern"}
_KEY_REGISTRY_FIELDS = {"schema_version", "keys"}
_KEY_FIELDS = {
    "key_id",
    "algorithm",
    "purpose",
    "workflow_identity",
    "public_key_pem",
    "not_before",
    "not_after",
    "revoked_at",
}
_RECEIPT_FIELDS = {
    "schema_version",
    "receipt_id",
    "evidence_kind",
    "evidence_path",
    "evidence_sha256",
    "product_revision",
    "workflow_identity",
    "issued_at",
    "expires_at",
    "signer_key_id",
    "payload_type",
    "signature",
}


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the canonical JSON representation used by admission signatures."""

    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def admission_signature_payload(receipt: Mapping[str, Any]) -> bytes:
    """Build DSSE PAE bytes for a receipt without its detached signature."""

    payload_type = receipt.get("payload_type")
    if not isinstance(payload_type, str) or not payload_type:
        raise ValueError("receipt payload_type is required")
    unsigned = {key: value for key, value in receipt.items() if key != "signature"}
    payload = canonical_json_bytes(unsigned)
    type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        (
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        )
    )


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _safe_relative(value: object) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _regular_repo_file(repo: Path, relative: Path) -> Path | None:
    candidate = repo / relative
    if candidate.is_symlink() or not candidate.is_file():
        return None
    try:
        candidate.resolve().relative_to(repo.resolve())
    except (OSError, ValueError):
        return None
    return candidate


def _load_policy_files(
    repo: Path, policy: Mapping[str, Any]
) -> tuple[dict[str, list[Path]], list[str]]:
    violations: list[str] = []
    files: dict[str, list[Path]] = {kind: [] for kind in _REQUIRED_KINDS}
    sources = policy.get("evidence_sources")
    if not isinstance(sources, list):
        return files, ["admission evidence_sources must be a list"]
    seen: set[str] = set()
    for index, raw in enumerate(sources):
        source = _mapping(raw)
        label = f"evidence_sources[{index}]"
        if source is None or set(source) != _SOURCE_FIELDS:
            violations.append(f"{label} fields do not match the schema")
            continue
        kind = source.get("kind")
        if kind not in _REQUIRED_KINDS or not isinstance(kind, str):
            violations.append(f"{label}.kind is invalid")
            continue
        if kind in seen:
            violations.append(f"duplicate admission evidence kind: {kind}")
            continue
        seen.add(kind)
        path_value = source.get("path")
        directory_value = source.get("directory")
        pattern = source.get("pattern")
        has_path = path_value is not None
        has_directory = directory_value is not None
        if has_path == has_directory:
            violations.append(f"{label} must declare exactly one path or directory")
            continue
        if has_path:
            relative = _safe_relative(path_value)
            if relative is None or pattern is not None:
                violations.append(f"{label}.path is unsafe or combined with pattern")
                continue
            candidate = _regular_repo_file(repo, relative)
            if candidate is not None:
                files[kind].append(relative)
            elif (repo / relative).exists():
                violations.append(f"{label}.path is not a regular repository file")
        else:
            relative = _safe_relative(directory_value)
            if relative is None or not isinstance(pattern, str) or pattern != "*.json":
                violations.append(f"{label}.directory or pattern is invalid")
                continue
            directory = repo / relative
            if directory.is_symlink() or not directory.is_dir():
                violations.append(f"{label}.directory is not a regular directory")
                continue
            try:
                directory.resolve().relative_to(repo.resolve())
            except (OSError, ValueError):
                violations.append(f"{label}.directory escapes the repository")
                continue
            for candidate in sorted(directory.glob(pattern)):
                item = candidate.relative_to(repo)
                if _regular_repo_file(repo, item) is None:
                    violations.append(f"evidence file is not a regular repository file: {item}")
                else:
                    files[kind].append(item)
    missing = _REQUIRED_KINDS - seen
    if missing:
        violations.append(
            "admission evidence_sources omit required kinds: " + ", ".join(sorted(missing))
        )
    return files, violations


def _validate_policy(repo: Path, policy: Mapping[str, Any]) -> list[str]:
    violations: list[str] = []
    if set(policy) != _POLICY_FIELDS:
        violations.append("admission policy fields do not match the schema")
    if policy.get("schema_version") != 1:
        violations.append("admission policy schema_version must be 1")
    if not _nonempty(policy.get("policy_id")):
        violations.append("admission policy_id is required")
    if _parse_time(f"{policy.get('reviewed_at')}T00:00:00Z") is None:
        violations.append("admission policy reviewed_at must be an ISO date")
    if policy.get("signature_algorithm") != "ed25519":
        violations.append("admission signature_algorithm must be ed25519")
    if not _nonempty(policy.get("payload_type")):
        violations.append("admission payload_type is required")
    maximum_age = policy.get("maximum_receipt_age_days")
    if (
        not isinstance(maximum_age, int)
        or isinstance(maximum_age, bool)
        or not 1 <= maximum_age <= 90
    ):
        violations.append("maximum_receipt_age_days must be between 1 and 90")
    for field in ("trusted_key_registry", "receipt_directory"):
        relative = _safe_relative(policy.get(field))
        if relative is None:
            violations.append(f"admission {field} must be repository-relative")
            continue
        candidate = repo / relative
        if field == "trusted_key_registry":
            if _regular_repo_file(repo, relative) is None:
                violations.append("trusted_key_registry must be a regular repository file")
        elif candidate.is_symlink() or not candidate.is_dir():
            violations.append("receipt_directory must be a regular directory")
    return violations


def _load_keys(
    repo: Path, policy: Mapping[str, Any], *, now: datetime
) -> tuple[dict[str, tuple[Mapping[str, Any], Ed25519PublicKey]], list[str], list[str]]:
    violations: list[str] = []
    blockers: list[str] = []
    relative = _safe_relative(policy.get("trusted_key_registry"))
    if relative is None:
        return {}, ["trusted key registry path is invalid"], []
    path = _regular_repo_file(repo, relative)
    if path is None:
        return {}, ["trusted key registry cannot be loaded"], []
    registry = _load_json(path)
    if set(registry) != _KEY_REGISTRY_FIELDS or registry.get("schema_version") != 1:
        return {}, ["trusted key registry fields are invalid"], []
    raw_keys = registry.get("keys")
    if not isinstance(raw_keys, list):
        return {}, ["trusted key registry keys must be a list"], []
    keys: dict[str, tuple[Mapping[str, Any], Ed25519PublicKey]] = {}
    for index, raw in enumerate(raw_keys):
        key = _mapping(raw)
        label = f"trusted key {index}"
        if key is None or set(key) != _KEY_FIELDS:
            violations.append(f"{label} fields do not match the schema")
            continue
        key_id = key.get("key_id")
        if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
            violations.append(f"{label} key_id is invalid")
            continue
        if key_id in keys:
            violations.append(f"duplicate trusted key_id: {key_id}")
            continue
        if (
            key.get("algorithm") != "ed25519"
            or key.get("purpose") != "production-evidence-admission"
        ):
            violations.append(f"{key_id}: algorithm or purpose is invalid")
            continue
        if not _nonempty(key.get("workflow_identity")):
            violations.append(f"{key_id}: workflow_identity is required")
            continue
        not_before = _parse_time(key.get("not_before"))
        not_after = _parse_time(key.get("not_after"))
        revoked_at = key.get("revoked_at")
        revoked = _parse_time(revoked_at) if revoked_at is not None else None
        if not_before is None or not_after is None or not_after <= not_before:
            violations.append(f"{key_id}: key validity window is invalid")
            continue
        if revoked_at is not None and revoked is None:
            violations.append(f"{key_id}: revoked_at is invalid")
            continue
        pem = key.get("public_key_pem")
        try:
            loaded = serialization.load_pem_public_key(
                pem.encode("ascii") if isinstance(pem, str) else b""
            )
        except (TypeError, ValueError):
            violations.append(f"{key_id}: public_key_pem is invalid")
            continue
        if not isinstance(loaded, Ed25519PublicKey):
            violations.append(f"{key_id}: public key is not Ed25519")
            continue
        if now < not_before or now > not_after or (revoked is not None and revoked <= now):
            blockers.append(f"{key_id}: trusted admission key is not active")
            continue
        keys[key_id] = (key, loaded)
    if not keys:
        blockers.append("no active trusted production evidence admission key")
    return keys, violations, blockers


def _load_receipts(
    repo: Path, policy: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    violations: list[str] = []
    relative = _safe_relative(policy.get("receipt_directory"))
    if relative is None:
        return [], ["admission receipt directory path is invalid"]
    directory = repo / relative
    if directory.is_symlink() or not directory.is_dir():
        return [], ["admission receipt directory is not a regular directory"]
    try:
        directory.resolve().relative_to(repo.resolve())
    except (OSError, ValueError):
        return [], ["admission receipt directory escapes the repository"]
    receipts: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            violations.append("admission receipts cannot contain symbolic links")
            continue
        try:
            receipts.append(_load_json(path))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            violations.append(f"cannot load admission receipt {path.name}: {error}")
    return receipts, violations


def _verify_receipt(
    repo: Path,
    policy: Mapping[str, Any],
    receipt: Mapping[str, Any],
    keys: Mapping[str, tuple[Mapping[str, Any], Ed25519PublicKey]],
    declared_files: Mapping[str, list[Path]],
    *,
    expected_product_revision: str | None,
    now: datetime,
) -> tuple[list[str], list[str], tuple[str, Path] | None]:
    violations: list[str] = []
    blockers: list[str] = []
    receipt_id = receipt.get("receipt_id")
    label = receipt_id if _nonempty(receipt_id) else "unknown receipt"
    if set(receipt) != _RECEIPT_FIELDS:
        violations.append(f"{label}: receipt fields do not match the schema")
    if receipt.get("schema_version") != 1 or not _nonempty(receipt_id):
        violations.append(f"{label}: receipt identity is invalid")
    kind = receipt.get("evidence_kind")
    relative = _safe_relative(receipt.get("evidence_path"))
    if kind not in _REQUIRED_KINDS or not isinstance(kind, str):
        violations.append(f"{label}: evidence_kind is invalid")
        kind = None
    if relative is None:
        violations.append(f"{label}: evidence_path is unsafe")
    elif kind is not None and relative not in declared_files.get(kind, []):
        violations.append(f"{label}: evidence_path is not declared for {kind}")
    evidence_sha = receipt.get("evidence_sha256")
    if not isinstance(evidence_sha, str) or _SHA256.fullmatch(evidence_sha) is None:
        violations.append(f"{label}: evidence_sha256 is invalid")
    elif relative is not None:
        evidence_path = _regular_repo_file(repo, relative)
        if evidence_path is None:
            violations.append(f"{label}: evidence file is missing or unsafe")
        elif hashlib.sha256(evidence_path.read_bytes()).hexdigest() != evidence_sha:
            violations.append(f"{label}: admitted evidence bytes have changed")
    revision = receipt.get("product_revision")
    if not isinstance(revision, str) or _GIT_SHA.fullmatch(revision) is None:
        violations.append(f"{label}: product_revision must be a full Git SHA")
    elif expected_product_revision is not None and revision != expected_product_revision:
        blockers.append(f"{label}: product revision does not match the release candidate")
    issued = _parse_time(receipt.get("issued_at"))
    expires = _parse_time(receipt.get("expires_at"))
    maximum_age = int(policy.get("maximum_receipt_age_days", 0))
    if issued is None or expires is None or expires <= issued or issued > now:
        violations.append(f"{label}: receipt validity window is invalid")
    elif (expires - issued).total_seconds() > maximum_age * 86400:
        violations.append(f"{label}: receipt validity exceeds policy")
    elif now > expires:
        blockers.append(f"{label}: admission receipt is expired")
    if receipt.get("payload_type") != policy.get("payload_type"):
        violations.append(f"{label}: payload_type does not match policy")
    key_id = receipt.get("signer_key_id")
    key_entry = keys.get(key_id) if isinstance(key_id, str) else None
    if key_entry is None:
        blockers.append(f"{label}: signer key is not active and trusted")
    else:
        key, public_key = key_entry
        key_not_before = _parse_time(key.get("not_before"))
        key_not_after = _parse_time(key.get("not_after"))
        if issued is not None and (
            key_not_before is None
            or key_not_after is None
            or issued < key_not_before
            or issued >= key_not_after
        ):
            violations.append(f"{label}: receipt was issued outside signer key validity")
        if receipt.get("workflow_identity") != key.get("workflow_identity"):
            violations.append(f"{label}: workflow identity does not match signer key")
        signature_value = receipt.get("signature")
        try:
            signature = base64.b64decode(
                signature_value.encode("ascii") if isinstance(signature_value, str) else b"",
                validate=True,
            )
        except (ValueError, binascii.Error):
            violations.append(f"{label}: signature is not canonical base64")
        else:
            try:
                public_key.verify(signature, admission_signature_payload(receipt))
            except (InvalidSignature, ValueError):
                violations.append(f"{label}: admission signature is invalid")
    admitted = (kind, relative) if kind is not None and relative is not None else None
    return violations, blockers, admitted


def validate_evidence_admission(
    repo: Path,
    policy: Mapping[str, Any],
    *,
    expected_product_revision: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify trusted-key admission of every production evidence document."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    policy_violations = _validate_policy(repo, policy)
    declared_files, source_violations = _load_policy_files(repo, policy)
    keys, key_violations, key_blockers = _load_keys(repo, policy, now=current)
    receipts, receipt_load_violations = _load_receipts(repo, policy)
    violations = [
        *policy_violations,
        *source_violations,
        *key_violations,
        *receipt_load_violations,
    ]
    receipt_ids: set[str] = set()
    receipt_claims: set[tuple[str, Path]] = set()
    admitted: dict[str, set[Path]] = {kind: set() for kind in _REQUIRED_KINDS}
    kind_violations: dict[str, list[str]] = {kind: [] for kind in _REQUIRED_KINDS}
    kind_blockers: dict[str, list[str]] = {kind: list(key_blockers) for kind in _REQUIRED_KINDS}
    for receipt in receipts:
        receipt_id = receipt.get("receipt_id")
        if isinstance(receipt_id, str):
            if receipt_id in receipt_ids:
                violations.append(f"duplicate admission receipt_id: {receipt_id}")
            receipt_ids.add(receipt_id)
        kind = receipt.get("evidence_kind")
        relative = _safe_relative(receipt.get("evidence_path"))
        if isinstance(kind, str) and kind in _REQUIRED_KINDS and relative is not None:
            claim = (kind, relative)
            if claim in receipt_claims:
                violations.append(
                    f"duplicate admission receipt claim: {kind}:{relative.as_posix()}"
                )
            receipt_claims.add(claim)
        item_violations, item_blockers, admitted_item = _verify_receipt(
            repo,
            policy,
            receipt,
            keys,
            declared_files,
            expected_product_revision=expected_product_revision,
            now=current,
        )
        if isinstance(kind, str) and kind in _REQUIRED_KINDS:
            kind_violations[kind].extend(item_violations)
            kind_blockers[kind].extend(item_blockers)
        violations.extend(item_violations)
        if admitted_item is not None and not item_violations and not item_blockers:
            admitted[admitted_item[0]].add(admitted_item[1])
    kinds: dict[str, dict[str, Any]] = {}
    for kind in sorted(_REQUIRED_KINDS):
        files = set(declared_files[kind])
        missing = files - admitted[kind]
        if not files:
            kind_blockers[kind].append(f"no {kind} production evidence document exists")
        for relative in sorted(missing, key=str):
            kind_blockers[kind].append(
                f"no valid signed admission receipt for {relative.as_posix()}"
            )
        item_violations = sorted(set(kind_violations[kind]))
        item_blockers = sorted(set(kind_blockers[kind]))
        kinds[kind] = {
            "status": "pass" if not item_violations else "fail",
            "production_readiness": (
                "ready" if files and not item_violations and not item_blockers else "blocked"
            ),
            "violations": item_violations,
            "blockers": item_blockers,
            "evidence_document_count": len(files),
            "admitted_document_count": len(admitted[kind]),
        }
    unique_violations = sorted(set(violations))
    all_ready = all(item["production_readiness"] == "ready" for item in kinds.values())
    return {
        "status": "pass" if not unique_violations else "fail",
        "production_readiness": ("ready" if not unique_violations and all_ready else "blocked"),
        "violations": unique_violations,
        "blockers": sorted(
            {
                blocker
                for item in kinds.values()
                for blocker in item["blockers"]
                if isinstance(blocker, str)
            }
        ),
        "kinds": kinds,
        "metrics": {
            "required_kind_count": len(_REQUIRED_KINDS),
            "ready_kind_count": sum(
                item["production_readiness"] == "ready" for item in kinds.values()
            ),
            "evidence_document_count": sum(len(value) for value in declared_files.values()),
            "admitted_document_count": sum(len(value) for value in admitted.values()),
            "active_trusted_key_count": len(keys),
            "receipt_count": len(receipts),
        },
    }
