"""Consume independently registered native records through existing release trust.

The registry is a reviewed repository material, covered by the same protected
source and admitted-image evidence as release policy. Candidate-supplied paths,
callbacks, expected digests and unregistered operator JSON are never authority.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from saas.production.admission import _regular_repo_file
from saas.scripts.combined_runtime_disposition import RuntimeSubject, VerifiedRuntimeCondition

REGISTRY = "saas/supply_chain/runtime-condition-inputs.json"


def _material_file(repo: Path, relative: str) -> Path:
    coordinate = Path(relative)
    if coordinate.is_absolute() or ".." in coordinate.parts:
        raise ValueError("native input escaped the reviewed material root")
    anchor = repo.resolve(strict=True)
    candidate = anchor
    for part in coordinate.parts:
        candidate /= part
        if candidate.is_symlink():
            raise ValueError("native input cannot use a symbolic link")
    path = _regular_repo_file(anchor, coordinate)
    if path is None:
        raise ValueError("native input escaped the reviewed material root")
    return path


def _document(repo: Path, coordinate: dict[str, Any]) -> tuple[dict[str, Any], str]:
    relative, expected = coordinate.get("path"), coordinate.get("sha256")
    if not isinstance(relative, str) or not isinstance(expected, str):
        raise ValueError("native input lacks a registered identity")
    if not Path(relative).is_relative_to("saas/supply_chain/runtime-conditions"):
        raise ValueError("native input escaped the reviewed material root")
    path = _material_file(repo, relative)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("registered native input bytes changed")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("native input document is malformed")
    return value, expected


def verifier_from_registered_inputs(repo: Path, inventory: list[dict[str, Any]]):
    """Create the sole production verifier from reviewed, byte-bound materials.

    Actual image hashes in inventory come from the existing OCI CAS consumer.
    Final signed receipts additionally require existing evidence admission.
    A helper-only experiment remains usable evidence, but cannot authorize a
    full Server/Host subject; absence of complete approved coverage rejects it.
    """
    registry = json.loads(_material_file(repo, REGISTRY).read_text())
    if (
        type(registry.get("schema_version")) is not int
        or registry["schema_version"] != 1
        or not isinstance(registry.get("approved_scopes"), list)
    ):
        raise ValueError("native input registry schema differs")

    def verify(subject: RuntimeSubject, *, now: datetime) -> VerifiedRuntimeCondition:
        matches = []
        for coordinate in registry["approved_scopes"]:
            contract, contract_sha = _document(repo, coordinate["contract"])
            if contract.get("subject") == {
                "source_revision": subject.source_revision,
                "platform": subject.platform,
                "manifest_digest": subject.manifest_digest,
                "config_digest": subject.config_digest,
                "libc_sha256": subject.libc_sha256,
            }:
                matches.append((contract, contract_sha, coordinate))
        if len(matches) != 1:
            raise ValueError(
                "final subject has no unique independently approved full-role contract"
            )
        contract, contract_sha, coordinate = matches[0]
        if (
            contract.get("scope") != "full-release-image"
            or contract.get("uncovered_boundaries") != []
        ):
            raise ValueError(
                "native evidence does not cover the complete approved image role scope"
            )
        evidence, native_sha = _document(repo, contract["native_evidence"])
        review, review_sha = _document(repo, coordinate["independent_review"])
        authority, authority_sha = _document(repo, coordinate["authority"])
        if (
            review.get("reviewed_contract_sha256") != contract_sha
            or review.get("native_evidence_sha256") != native_sha
            or review.get("unresolved_findings") != []
            or authority.get("rule_id") != "CVE-2026-84243"
            or authority.get("classification") != "mitigated_by_verified_runtime_conditions"
        ):
            raise ValueError("native condition lacks exact independent review or authority")
        # Producer identity and original file digests are registered by the
        # existing independent operator/CI review, never asserted by a caller.
        producer = evidence.get("producer")
        if (
            not isinstance(producer, dict)
            or producer.get("kind") not in {"existing-native-operator", "github-actions"}
            or not isinstance(producer.get("operation"), str)
            or not producer["operation"]
            or producer != review.get("verified_native_producer")
        ):
            raise ValueError("native producer origin is not independently registered")
        if evidence.get("original_report_sha256") != subject.report_sha256:
            raise ValueError("native evidence belongs to a different original raw report")
        if evidence.get("subject") != contract["subject"]:
            raise ValueError("native producer did not bind this exact subject")
        if evidence.get("roles") != contract.get("roles") or not evidence.get("roles"):
            raise ValueError("native evidence role/command/factory/profile coverage differs")
        if (
            not isinstance(contract.get("last_merge_contract"), dict)
            or not contract["last_merge_contract"]
            or contract["last_merge_contract"] != review.get("verified_last_merge_contract")
        ):
            raise ValueError("trusted lifecycle and last-override contract differs")
        expected_modules = contract.get("installed_files")
        if not isinstance(expected_modules, dict) or not expected_modules:
            raise ValueError("native condition lacks exact installed code boundaries")
        observed = {row["path"]: row.get("sha256") for row in inventory}
        if any(observed.get(path) != sha for path, sha in expected_modules.items()):
            raise ValueError("actual image changed an approved runtime boundary")
        expiry = min(
            datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00"))
            for document in (contract, evidence, review, authority)
        )
        if now.tzinfo is None or expiry.tzinfo is None or not now < expiry:
            raise ValueError("native registered evidence is expired")
        return VerifiedRuntimeCondition(
            subject=subject,
            role_contract_sha256=contract_sha,
            native_evidence_sha256=native_sha,
            independent_review_sha256=review_sha,
            authority_reference_sha256=authority_sha,
            expires_at=expiry,
        )

    return verify


def registered_inventory_paths(repo: Path) -> frozenset[str]:
    registry = json.loads(_material_file(repo, REGISTRY).read_text())
    paths = {"usr/lib/libc.so.6"}
    for coordinate in registry["approved_scopes"]:
        contract, _ = _document(repo, coordinate["contract"])
        paths.update(contract.get("installed_files", {}))
    return frozenset(paths)
