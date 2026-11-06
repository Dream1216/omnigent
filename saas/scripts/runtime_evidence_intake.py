"""Authenticate the complete native record graph with existing image admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from saas.production.admission import _regular_repo_file
from saas.scripts.combined_runtime_disposition import RuntimeSubject, VerifiedRuntimeCondition

REGISTRY = "saas/supply_chain/runtime-condition-inputs.json"
ADMISSION_POLICY = "saas/production/evidence-admission-policy.json"


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


def _coordinate(coordinate: dict[str, Any]) -> tuple[str, str]:
    relative, expected = coordinate.get("path"), coordinate.get("sha256")
    if not isinstance(relative, str) or not isinstance(expected, str):
        raise ValueError("native input lacks a registered identity")
    if not Path(relative).is_relative_to("saas/supply_chain/runtime-conditions"):
        raise ValueError("native input escaped the reviewed material root")
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("native input escaped the reviewed material root")
    return relative, expected


def _document(graph: dict[str, Any], coordinate: dict[str, Any]) -> tuple[dict[str, Any], str]:
    relative, expected = _coordinate(coordinate)
    content = graph["documents"].get(relative)
    if not isinstance(content, str):
        raise ValueError("native input is missing from the authenticated graph")
    raw = content.encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("registered native input bytes changed")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("native input document is malformed")
    return value, expected


def authenticated_image_documents(
    repo: Path, *, product_revision: str, now: datetime, evidence_repo: Path | None = None
) -> list[dict[str, Any]]:
    """Read only data from an evidence checkout; trust policy and keys from product."""
    from saas.production import admission

    evidence_repo = evidence_repo or Path(os.environ.get("OMNIGENT_RUNTIME_EVIDENCE_REPO", repo))
    policy_raw = _material_file(repo, ADMISSION_POLICY).read_bytes()
    policy = json.loads(policy_raw)
    key_path = policy["trusted_key_registry"]
    if (
        _material_file(evidence_repo, ADMISSION_POLICY).read_bytes() != policy_raw
        or _material_file(evidence_repo, key_path).read_bytes()
        != _material_file(repo, key_path).read_bytes()
    ):
        raise ValueError("evidence checkout changed protected admission policy or keys")
    result = admission.validate_evidence_admission(
        evidence_repo,
        policy,
        now=now,
        expected_product_revision=product_revision,
        include_authenticated_documents=True,
    )
    _, key_violations, _ = admission._load_keys(repo, policy, now=now)
    if (
        admission._validate_policy(repo, policy)
        or key_violations
        or result["kinds"]["image"]["status"] != "pass"
        or result["kinds"]["image"]["production_readiness"] != "ready"
    ):
        raise ValueError("finite image inventory lacks trusted signed evidence admission")
    documents = []
    for relative, digest in result["authenticated_documents"]["image"].items():
        raw = _material_file(evidence_repo, relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("finite image inventory bytes changed after verified admission")
        documents.append(json.loads(raw))
    return documents


def authenticated_runtime_graph(
    repo: Path, *, product_revision: str, now: datetime
) -> dict[str, Any]:
    documents = authenticated_image_documents(repo, product_revision=product_revision, now=now)
    graphs = []
    for document in documents:
        body = document.get("release_evidence", document)
        if isinstance(body, dict) and "runtime_conditions" in body:
            graphs.append(body["runtime_conditions"])
    if len(graphs) != 1:
        raise ValueError("final subject lacks a unique authenticated runtime graph")
    graph = graphs[0]
    if (
        not isinstance(graph, dict)
        or set(graph) != {"schema_version", "product_revision", "registry", "documents"}
        or type(graph["schema_version"]) is not int
        or graph["schema_version"] != 1
        or graph["product_revision"] != product_revision
        or not isinstance(graph["documents"], dict)
    ):
        raise ValueError("authenticated runtime graph subject or schema differs")
    _registry(graph)
    return graph


def _registry(graph: dict[str, Any]) -> dict[str, Any]:
    registry = graph["registry"]
    if (
        not isinstance(registry, dict)
        or type(registry.get("schema_version")) is not int
        or registry["schema_version"] != 1
        or not isinstance(registry.get("approved_scopes"), list)
    ):
        raise ValueError("native input registry schema differs")
    return registry


def prepare_runtime_graph(repo: Path, *, product_revision: str) -> dict[str, Any]:
    """Package original bytes for existing admission; this does not authenticate them."""
    graph = {
        "schema_version": 1,
        "product_revision": product_revision,
        "registry": json.loads(_material_file(repo, REGISTRY).read_text()),
        "documents": {},
    }
    scopes = _registry(graph)["approved_scopes"]
    if not scopes:
        raise ValueError("final subject has no approved full-role contract to package")
    for scope in scopes:
        for coordinate in (scope["contract"], scope["independent_review"], scope["authority"]):
            relative, _ = _coordinate(coordinate)
            graph["documents"][relative] = (
                _material_file(repo, relative).read_bytes().decode("utf-8")
            )
            _document(graph, coordinate)
        contract, _ = _document(graph, scope["contract"])
        relative, _ = _coordinate(contract["native_evidence"])
        graph["documents"][relative] = _material_file(repo, relative).read_bytes().decode("utf-8")
        _document(graph, contract["native_evidence"])
        if contract["subject"]["source_revision"] != product_revision:
            raise ValueError("native contract belongs to another product revision")
    return graph


def verifier_from_registered_inputs(graph: dict[str, Any], inventory: list[dict[str, Any]]):
    """Check consistency only after the protected caller authenticates the graph."""
    registry = _registry(graph)

    def verify(subject: RuntimeSubject, *, now: datetime) -> VerifiedRuntimeCondition:
        matches = []
        for coordinate in registry["approved_scopes"]:
            contract, contract_sha = _document(graph, coordinate["contract"])
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
        evidence, native_sha = _document(graph, contract["native_evidence"])
        review, review_sha = _document(graph, coordinate["independent_review"])
        authority, authority_sha = _document(graph, coordinate["authority"])
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
            runtime_graph_sha256=hashlib.sha256(
                json.dumps(graph, sort_keys=True, allow_nan=False).encode()
            ).hexdigest(),
            expires_at=expiry,
        )

    return verify


def registered_inventory_paths(graph: dict[str, Any]) -> frozenset[str]:
    registry = _registry(graph)
    paths = {"usr/lib/libc.so.6"}
    for coordinate in registry["approved_scopes"]:
        contract, _ = _document(graph, coordinate["contract"])
        paths.update(contract.get("installed_files", {}))
    return frozenset(paths)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--materials-root", required=True, type=Path)
    parser.add_argument("--product-revision", required=True)
    parser.add_argument("--image-evidence", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    from saas.scripts.prepare_evidence_receipt import _safe_output

    repo = Path(__file__).resolve().parents[2]
    try:
        document = json.loads(_material_file(repo, args.image_evidence).read_bytes())
        body = document.get("release_evidence", document)
        if body.get("product_revision") != args.product_revision:
            raise ValueError("image evidence belongs to another product revision")
        body["runtime_conditions"] = prepare_runtime_graph(
            args.materials_root, product_revision=args.product_revision
        )
        _safe_output(repo, args.output).write_text(
            json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
