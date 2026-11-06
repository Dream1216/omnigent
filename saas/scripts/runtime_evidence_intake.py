"""Authenticate the complete native record graph with existing image admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from saas.production.admission import _regular_repo_file
from saas.scripts.combined_runtime_disposition import (
    RUNTIME_RULE,
    RuntimeSubject,
    VerifiedRuntimeCondition,
)

REGISTRY = "saas/supply_chain/runtime-condition-inputs.json"
ADMISSION_POLICY = "saas/production/evidence-admission-policy.json"
COMPONENT_BRIDGE = "same-platform-installed-component-and-entry/v1"


def _native_startup_evidence(
    record: dict[str, Any], *, original: dict[str, Any], review: dict[str, Any]
) -> dict[str, Any]:
    facts, subject = record["native_facts"], record["subject"]
    controls = record["actual_runtime_contract"]
    roles = ["server", "worker", "runner_control", "runner_agent", "preview_edge", "preview_owner"]
    clean = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LC_MESSAGES": "C.UTF-8",
        "LANGUAGE": None,
        "LOCPATH": None,
    }
    if (
        type(record.get("qualification_exit")) is not int
        or record["qualification_exit"] != 0
        or record.get("owned_container_absent") is not True
        or record.get("DB_credentials_shared_PVC_external_network") is not False
        or record.get("QEMU_used") is not False
        or record.get("host_architecture") != "aarch64"
        or record.get("control_attempt") != "1"
        or record.get("High_disposition") is not False
        or record.get("full_image_or_lifecycle_qualified") is not False
        or facts.get("source_revision") != record["source_revision"]
        or subject.get("source_revision") != record["source_revision"]
        or facts.get("platform") != subject.get("platform")
        or subject["platform"] != "linux/arm64"
        or facts.get("actual_loaded_libc", {}).get("sha256") != subject["libc_sha256"]
        or not facts.get("installed_files")
        or facts.get("uid") != 1000
        or facts.get("gid") != 1000
        or type(facts.get("pid")) is not int
        or facts["pid"] <= 0
        or re.fullmatch(r"pid:\[\d+\]", facts.get("pid_namespace", "")) is None
        or not str(facts.get("process_start_ticks", "")).isdigit()
        or facts.get("mocked_exec") is not False
        or facts.get("production_source_modified") is not False
        or facts.get("whole_service_lifecycle_qualified") is not False
        or facts.get("High_disposition") is not False
        or facts.get("expires_at") != RUNTIME_RULE["expires_at"]
        or controls.get("NetworkMode") != "none"
        or controls.get("Privileged") is not False
        or controls.get("ReadonlyRootfs") is not True
        or controls.get("CapDrop") != ["ALL"]
        or controls.get("CapAdd")
        or controls.get("PidMode") == "host"
        or "no-new-privileges:true" not in controls.get("SecurityOpt", [])
        or facts.get("actual_controls")
        != {
            "no_new_privileges": True,
            "all_capabilities_empty": True,
            "rootfs_readonly": True,
            "interfaces": ["lo"],
            "non_loopback_routes": 0,
        }
        or [entry.get("role") for entry in facts.get("entries", [])] != roles
        or any(
            entry.get("five_locale_inputs") != clean
            or entry.get("effective_LC_MESSAGES") not in {"C.UTF-8", "C.utf8"}
            or entry.get("effective_encoding", "").lower().replace("-", "") != "utf8"
            for entry in facts.get("entries", [])
        )
    ):
        raise ValueError("original native startup component receipt is incomplete or changed")
    return {
        "producer": {"kind": "github-actions", "operation": record["operation"]},
        "subject": dict(subject),
        "original_report_sha256": record["original_report_sha256"],
        "roles": roles,
        "expires_at": RUNTIME_RULE["expires_at"],
        "original_operator_record": original,
        "original_operator_review": review,
    }


def native_evidence_from_operator(
    record: dict[str, Any], *, original: dict[str, Any], review: dict[str, Any]
) -> dict[str, Any]:
    """Derive component facts from the existing operator's original safe receipt."""
    facts = record["native_facts"]
    if facts.get("kind") == "installed-production-startup-locale/v1":
        return _native_startup_evidence(record, original=original, review=review)
    image = record["actual_image"]
    native = facts["subject"]
    expected = native["expected_original_subject"]
    controls = record["actual_runtime_contract"]
    if (
        type(record.get("qualification_exit")) is not int
        or record["qualification_exit"] != 0
        or record.get("product_modules_modified") is not False
        or record.get("owned_task_container_absent") is not True
        or record.get("owned_network_namespace_absent") is not True
        or record.get("cleanup_errors") != []
        or record.get("DB_credentials_shared_PVC_external_network") is not False
        or facts.get("mocked_exec") is not False
        or facts.get("production_source_modified") is not False
        or facts.get("source") != record["source"]
        or image.get("all_selected_CAS_verified") is not True
        or image.get("resolved_manifest_digest") != expected["manifest_digest"]
        or image.get("resolved_config_digest") != expected["config_digest"]
        or native["loaded_libc"]["sha256"] != expected["libc_sha256"]
        or any(
            controls.get(key) is not True
            for key in (
                "nonroot",
                "no_new_privileges",
                "all_capabilities_empty",
                "rootfs_readonly",
            )
        )
        or record["network"] != {"interfaces": ["lo"], "non_loopback_routes": 0}
        or record["actual_task"]["id"] != record["operation"]
        or facts.get("requested_roles") != ["helper", "terminal"]
    ):
        raise ValueError("original operator component receipt is incomplete or changed")
    clean = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LC_MESSAGES": "C.UTF-8",
        "LANGUAGE": None,
        "LOCPATH": None,
    }
    process_env = {key: [] if value is None else [value] for key, value in clean.items()}
    for role, launchers in (
        ("helper", ("trusted_launcher_process",)),
        ("terminal", ("trusted_tmux_server_process", "pane_process")),
    ):
        child = facts[role]["actual_child"]
        if (
            child["five_locale_inputs"] != clean
            or child["effective_LC_MESSAGES"] not in {"C.UTF-8", "C.utf8"}
            or child["effective_encoding"].lower().replace("-", "") != "utf8"
        ):
            raise ValueError("actual native child locale is not constrained")
        for name in launchers:
            process = facts[role][name]
            if (
                type(process["pid"]) is not int
                or process["pid"] <= 0
                or not process["start_ticks"]
                or process["five_locale_inputs"] != process_env
            ):
                raise ValueError("actual native launcher identity or locale differs")
    return {
        "producer": {"kind": "existing-native-operator", "operation": record["operation"]},
        "subject": {
            "source_revision": record["source"],
            "platform": native["platform"],
            "manifest_digest": expected["manifest_digest"],
            "config_digest": expected["config_digest"],
            "libc_sha256": expected["libc_sha256"],
        },
        "original_report_sha256": expected["original_report_sha256"],
        "roles": facts["requested_roles"],
        "expires_at": RUNTIME_RULE["expires_at"],
        "original_operator_record": original,
        "original_operator_review": review,
    }


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


def prepare_evidence_context(
    repo: Path, *, product_revision: str, evidence_revision: str, destination: Path
) -> Path:
    """Fetch immutable data; execute only product code and preserve clean lineage."""
    if (
        any(
            re.fullmatch(r"[0-9a-f]{40}", value) is None
            for value in (product_revision, evidence_revision)
        )
        or not destination.is_absolute()
        or destination.exists()
    ):
        raise ValueError("evidence context requires exact revisions and a fresh directory")
    subprocess.run(
        [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "credential.helper=!gh auth git-credential",
            "fetch",
            "--no-tags",
            "origin",
            evidence_revision,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(destination), evidence_revision],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    validate_evidence_context(repo, destination, product_revision=product_revision)
    return destination


def validate_evidence_context(repo: Path, evidence_repo: Path, *, product_revision: str) -> None:
    from saas.production.readiness import validate_candidate_revision

    lineage = validate_candidate_revision(product_revision, evidence_repo)
    if lineage["status"] != "pass" or lineage["production_readiness"] != "ready":
        raise ValueError("runtime data revision changed product source or has dirty lineage")
    policy = json.loads(_material_file(repo, ADMISSION_POLICY).read_bytes())
    for relative in (ADMISSION_POLICY, policy["trusted_key_registry"]):
        if (
            _material_file(repo, relative).read_bytes()
            != _material_file(evidence_repo, relative).read_bytes()
        ):
            raise ValueError("runtime data changed protected admission policy or keys")
    for source in policy["evidence_sources"]:
        if source["kind"] == "image":
            _material_file(evidence_repo, source["path"])


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
    for scope in graph["registry"]["approved_scopes"]:
        contract, _ = _document(graph, scope["contract"])
        native, _ = _document(graph, contract["native_evidence"])
        original, review = (
            native.get("original_operator_record"),
            native.get("original_operator_review"),
        )
        if not isinstance(original, dict) or not isinstance(review, dict):
            raise ValueError("native producer lacks its registered original operator receipt")
        record, _ = _document(graph, original)
        _document(graph, review)
        boundaries = _registered_native_origin(repo, native).get("installed_files")
        if (
            not isinstance(boundaries, dict)
            or not boundaries
            or any(
                contract.get("installed_files", {}).get(path) != sha
                for path, sha in boundaries.items()
            )
        ):
            raise ValueError(
                "runtime contract omitted or changed a registered native code boundary"
            )
        expected = native_evidence_from_operator(record, original=original, review=review)
        if native != expected:
            raise ValueError("native wrapper differs from unchanged original operator facts")
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


def _registered_native_origin(repo: Path, native: dict[str, Any]) -> dict[str, Any]:
    catalog = json.loads(_material_file(repo, REGISTRY).read_bytes())
    registration = {
        "operation": native["producer"]["operation"],
        "native_record_sha256": native["original_operator_record"]["sha256"],
        "independent_review_sha256": native["original_operator_review"]["sha256"],
    }
    matches = [
        entry
        for entry in catalog.get("approved_native_observations", [])
        if all(entry.get(key) == value for key, value in registration.items())
    ]
    if len(matches) != 1:
        raise ValueError("native operator origin is not registered in protected product source")
    return matches[0]


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
        native, _ = _document(graph, contract["native_evidence"])
        for key in ("original_operator_record", "original_operator_review"):
            if key in native:
                relative, _ = _coordinate(native[key])
                graph["documents"][relative] = (
                    _material_file(repo, relative).read_bytes().decode("utf-8")
                )
                _document(graph, native[key])
        target = contract.get("component_bridge", {}).get("target", contract["subject"])
        if target["source_revision"] != product_revision:
            raise ValueError("native contract belongs to another product revision")
    return graph


def verifier_from_registered_inputs(graph: dict[str, Any], inventory: list[dict[str, Any]]):
    """Check consistency only after the protected caller authenticates the graph."""
    registry = _registry(graph)

    def verify(subject: RuntimeSubject, *, now: datetime) -> VerifiedRuntimeCondition:
        matches = []
        identity = {
            "source_revision": subject.source_revision,
            "platform": subject.platform,
            "manifest_digest": subject.manifest_digest,
            "config_digest": subject.config_digest,
            "libc_sha256": subject.libc_sha256,
        }
        for coordinate in registry["approved_scopes"]:
            contract, contract_sha = _document(graph, coordinate["contract"])
            bridge = contract.get("component_bridge")
            if contract.get("subject") == identity or (
                isinstance(bridge, dict)
                and bridge.get("kind") == COMPONENT_BRIDGE
                and bridge.get("target")
                == {key: identity[key] for key in ("source_revision", "platform", "libc_sha256")}
                and graph["product_revision"] == subject.source_revision
            ):
                matches.append((contract, contract_sha, coordinate))
        if len(matches) != 1:
            raise ValueError(
                "final subject has no unique independently approved full-role contract"
            )
        contract, contract_sha, coordinate = matches[0]
        roles = contract.get("roles")
        role_ids = (
            [
                role
                if isinstance(role, str)
                else role.get("role")
                if isinstance(role, dict)
                else None
                for role in roles
            ]
            if isinstance(roles, list)
            else []
        )
        if (
            contract.get("scope") != "full-release-image"
            or contract.get("uncovered_boundaries") != []
            or not role_ids
            or any(not isinstance(role, str) or not role.strip() for role in role_ids)
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
        bridge = contract.get("component_bridge")
        if bridge is not None and (
            not isinstance(bridge, dict)
            or bridge.get("kind") != COMPONENT_BRIDGE
            or bridge.get("target")
            != {key: identity[key] for key in ("source_revision", "platform", "libc_sha256")}
            or graph["product_revision"] != subject.source_revision
            or bridge.get("native_subject") != contract["subject"]
            or any(
                contract["subject"].get(key) != identity[key]
                for key in ("platform", "libc_sha256")
            )
            or bridge.get("native_report_sha256") != evidence.get("original_report_sha256")
            or bridge.get("current_scan") != "fresh-unfiltered-exact-two-findings-same-OCI"
            or bridge.get("native_roles") != evidence.get("roles")
            or bridge.get("approved_roles") != contract.get("roles")
            or review.get("verified_component_bridge") != bridge
            or authority.get("approved_component_bridge") != bridge
        ):
            raise ValueError(
                "native component bridge lacks exact review, authority or applicability"
            )
        if evidence.get("original_report_sha256") != subject.report_sha256 and bridge is None:
            raise ValueError("native evidence belongs to a different original raw report")
        if evidence.get("subject") != contract["subject"]:
            raise ValueError("native producer did not bind this exact subject")
        if (bridge is None and evidence.get("roles") != contract.get("roles")) or not evidence.get(
            "roles"
        ):
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
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--materials-root", type=Path)
    mode.add_argument("--evidence-revision")
    parser.add_argument("--evidence-directory", type=Path)
    parser.add_argument("--operator-record")
    parser.add_argument("--operator-review")
    parser.add_argument("--product-revision", required=True)
    parser.add_argument("--image-evidence")
    parser.add_argument("--output")
    args = parser.parse_args()
    from saas.scripts.prepare_evidence_receipt import _safe_output

    repo = Path(__file__).resolve().parents[2]
    try:
        if args.evidence_revision:
            if args.evidence_directory is None or args.output or args.image_evidence:
                raise ValueError("evidence context requires only a fresh evidence directory")
            prepare_evidence_context(
                repo,
                product_revision=args.product_revision,
                evidence_revision=args.evidence_revision,
                destination=args.evidence_directory,
            )
            return 0
        if args.operator_record or args.operator_review:
            if not args.operator_record or not args.operator_review or not args.output:
                raise ValueError("native producer requires both original records and an output")
            originals = []
            for relative in (args.operator_record, args.operator_review):
                raw = _material_file(args.materials_root, relative).read_bytes()
                originals.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest()})
            value = native_evidence_from_operator(
                json.loads(_material_file(args.materials_root, args.operator_record).read_bytes()),
                original=originals[0],
                review=originals[1],
            )
            _registered_native_origin(repo, value)
            _safe_output(args.materials_root, args.output).write_text(
                json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
            )
            return 0
        if not args.image_evidence or not args.output:
            raise ValueError("graph packaging requires the image evidence and output paths")
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
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
