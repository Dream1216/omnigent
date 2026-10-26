"""Bind three independently verified legacy publications to one physical drill."""

from __future__ import annotations

import json
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from saas.production.admission import validate_evidence_admission
from saas.production.deployment import (
    _parse_time,
    load_deployment_evidence,
    validate_deployment_readiness,
)
from saas.production.legacy_publication import registered_publication
from saas.scripts import legacy_initial_publisher as publisher
from saas.scripts.legacy_publication_reader import read_registered_publication
from saas.scripts.legacy_publication_renewal import (
    read_original_publication_anchor,
    verify_renewal_identity,
)
from saas.scripts.oci_promotion import require

VARIANT = "production_release_with_legacy_fallback/v2"
STACK_REGISTRY = "saas/supply_chain/legacy-production-stacks.json"
COMPONENTS = {"Core", "Gateway", "Model"}
PAIR_CHECKS = {"final_server_old_host", "old_server_final_host", "old_pair_recovery"}


def _hex(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _identifiers(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == COMPONENTS
        and all(
            isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", item)
            for item in value.values()
        )
        and len(set(value.values())) == len(COMPONENTS)
    )


def registered_stack(repo: Path, identifier: Any, policy: dict[str, Any]) -> dict[str, Any]:
    from saas.scripts.check_image_supply_chain import load_release_evidence

    require(
        isinstance(identifier, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", identifier),
        "legacy stack identifier is invalid",
    )
    store = load_release_evidence(repo, STACK_REGISTRY)
    require(
        isinstance(store, dict)
        and set(store) == {"schema_version", "stacks"}
        and type(store["schema_version"]) is int
        and store["schema_version"] == 1
        and isinstance(store["stacks"], dict),
        "legacy stack registry differs",
    )
    row = store["stacks"].get(identifier)
    require(isinstance(row, dict), "complete legacy stack is not registered")
    require(
        set(row)
        == {
            "kind",
            "publication_ids",
            "original_publication_ids",
            "source_contracts",
            "physical_inventory",
            "policy_bindings",
            "n_minus_one_pair",
            "rollback_sha256",
            "protocol_database_contract_sha256",
        }
        and row["kind"] == "protected_legacy_full_stack/v1"
        and _identifiers(row["publication_ids"])
        and _identifiers(row["original_publication_ids"])
        and isinstance(row["source_contracts"], dict)
        and set(row["source_contracts"]) == COMPONENTS
        and all(isinstance(value, dict) and value for value in row["source_contracts"].values())
        and _hex(row["rollback_sha256"])
        and _hex(row["protocol_database_contract_sha256"]),
        "complete legacy stack registration fields differ",
    )
    inventory = row["physical_inventory"]
    require(
        isinstance(inventory, dict)
        and set(inventory) == {"cluster_uid_hash", "workloads"}
        and _hex(inventory["cluster_uid_hash"])
        and isinstance(inventory["workloads"], dict)
        and inventory["workloads"],
        "legacy physical inventory is not registered",
    )
    seen = set()
    for identifier, workload in inventory["workloads"].items():
        require(
            isinstance(identifier, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", identifier)
            and isinstance(workload, dict)
            and set(workload)
            == {
                "kind",
                "namespace_uid_hash",
                "workload_uid_hash",
                "container_name",
                "component",
                "image_role",
            }
            and workload["kind"] in {"Deployment", "StatefulSet", "DaemonSet"}
            and _hex(workload["namespace_uid_hash"])
            and _hex(workload["workload_uid_hash"])
            and isinstance(workload["container_name"], str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", workload["container_name"])
            and workload["component"] in COMPONENTS
            and workload["image_role"] in publisher.IMAGES,
            "legacy physical workload identity differs",
        )
        coordinate = (
            workload["namespace_uid_hash"],
            workload["workload_uid_hash"],
            workload["container_name"],
        )
        require(coordinate not in seen, "legacy physical workload identity is duplicated")
        seen.add(coordinate)
    require(
        {workload["component"] for workload in inventory["workloads"].values()} == COMPONENTS,
        "legacy physical inventory omits a Core/Gateway/Model service",
    )
    require(
        {workload["image_role"] for workload in inventory["workloads"].values()}
        == set(publisher.IMAGES),
        "legacy physical inventory omits the paired Host/Server roles",
    )
    bindings = row["policy_bindings"]
    require(
        isinstance(bindings, dict) and set(bindings) == set(policy["required_components"]),
        "legacy policy-to-physical mapping is incomplete",
    )
    for values in bindings.values():
        require(
            isinstance(values, list)
            and values
            and all(isinstance(item, str) for item in values)
            and len(values) == len(set(values))
            and set(values) <= set(inventory["workloads"]),
            "legacy policy mapping references unknown or duplicate physical workloads",
        )
    require(
        set().union(*(set(values) for values in bindings.values())) == set(inventory["workloads"]),
        "legacy policy mapping omits a registered physical workload",
    )
    pair = row["n_minus_one_pair"]
    require(
        isinstance(pair, dict) and set(pair) == set(publisher.IMAGES),
        "legacy N-1 pair registration differs",
    )
    for role, workload_id in pair.items():
        require(
            isinstance(workload_id, str)
            and workload_id in inventory["workloads"]
            and inventory["workloads"][workload_id]["image_role"] == role,
            "legacy N-1 pair does not bind physical Host/Server workloads",
        )
    return row


def _validate_pairs(body, stack, primary, facts):
    pair = {}
    for role, identifier in stack["n_minus_one_pair"].items():
        workload = stack["physical_inventory"]["workloads"][identifier]
        pair[role] = facts[workload["component"]]["images"][role]
    expected = {
        "final_server_old_host": {"server": primary["server"], "host": pair["host"]},
        "old_server_final_host": {"server": pair["server"], "host": primary["host"]},
        "old_pair_recovery": pair,
    }
    checks = body["pair_checks"]
    require(
        isinstance(checks, dict) and set(checks) == PAIR_CHECKS,
        "complete Host/Server N-1 pair matrix is required",
    )
    start, end = _parse_time(body["started_at"]), _parse_time(body["completed_at"])
    require(
        start is not None and end is not None and start <= end,
        "legacy complete rollback window is invalid",
    )
    hashes = []
    for name, item in checks.items():
        require(
            isinstance(item, dict)
            and set(item)
            == {
                "drill_id",
                "images",
                "started_at",
                "completed_at",
                "result",
                "evidence_sha256",
                "protocol_database_contract_sha256",
            }
            and item["drill_id"] == body["drill_id"]
            and item["images"] == expected[name]
            and item["result"] == "passed"
            and _hex(item["evidence_sha256"])
            and item["protocol_database_contract_sha256"]
            == stack["protocol_database_contract_sha256"],
            "Host/Server N-1 evidence belongs to another pair, contract or drill",
        )
        observed_start, observed_end = (
            _parse_time(item["started_at"]),
            _parse_time(item["completed_at"]),
        )
        require(
            observed_start is not None
            and observed_end is not None
            and start <= observed_start <= observed_end <= end,
            "Host/Server N-1 evidence is outside the complete rollback window",
        )
        hashes.append(item["evidence_sha256"])
    require(len(set(hashes)) == len(PAIR_CHECKS), "Host/Server N-1 proofs are conflated")


def validate_stack_fallback(
    repo: Path, envelope: dict[str, Any], *, now: datetime, expected_product_revision: str | None
) -> dict[str, Any]:
    require(
        set(envelope) == {"kind", "product_revision", "release_evidence", "legacy_fallback"}
        and envelope["kind"] == VARIANT,
        "legacy complete-set envelope fields differ",
    )
    evidence = envelope["release_evidence"]
    require(
        isinstance(evidence, dict)
        and evidence.get("product_revision") == envelope["product_revision"]
        and (
            expected_product_revision is None
            or expected_product_revision == envelope["product_revision"]
        ),
        "legacy complete-set envelope does not bind the primary candidate",
    )
    fallback = envelope["legacy_fallback"]
    require(
        isinstance(fallback, dict)
        and set(fallback)
        == {"stack_id", "publication_ids", "original_publication_ids", "full_stack_rollback"},
        "legacy complete publication-set fields differ",
    )
    policy = json.loads((repo / "saas/production/deployment-policy.json").read_text())
    stack = registered_stack(repo, fallback["stack_id"], policy)
    require(
        fallback["publication_ids"] == stack["publication_ids"]
        and fallback["original_publication_ids"] == stack["original_publication_ids"],
        "legacy publication set differs from the complete trusted set",
    )
    current, original = {}, {}
    for component in sorted(COMPONENTS):
        current[component] = registered_publication(repo, stack["publication_ids"][component])
        original[component] = registered_publication(
            repo, stack["original_publication_ids"][component]
        )
        require(
            current[component]["profile"]["component"]
            == original[component]["profile"]["component"]
            == component,
            "legacy publication component/profile has been exchanged",
        )
        require(
            current[component]["profile"]["product_revision"] != envelope["product_revision"],
            "legacy fallback source cannot replace the primary candidate",
        )
        if stack["publication_ids"][component] != stack["original_publication_ids"][component]:
            verify_renewal_identity(original[component], current[component])
    for field in ("product_revision", "product_tree"):
        require(
            len({row["profile"][field] for row in current.values()}) == len(COMPONENTS),
            "one legacy source/tree cannot impersonate three services",
        )
    facts = {}
    with tempfile.TemporaryDirectory(prefix="omnigent-legacy-stack-") as temporary:
        for component in sorted(COMPONENTS):
            root = Path(temporary) / component
            facts[component] = read_registered_publication(
                repo, current[component], root / "current"
            )
            require(
                facts[component]["revision_contract"] == stack["source_contracts"][component],
                "legacy component schema/protocol source contract differs",
            )
            expected_roles = {
                identifier: workload["image_role"]
                for identifier, workload in stack["physical_inventory"]["workloads"].items()
                if workload["component"] == component
            }
            require(
                current[component]["deployment_roles"] == expected_roles,
                "publication profile does not cover its exact physical service boundary",
            )
            if stack["publication_ids"][component] != stack["original_publication_ids"][component]:
                read_original_publication_anchor(
                    repo,
                    original[component],
                    current[component],
                    facts[component],
                    root / "original",
                )
    bindings = {
        component: {
            "publication_id": stack["publication_ids"][component],
            "original_publication_id": stack["original_publication_ids"][component],
            "profile_sha256": publisher.digest(current[component]["profile"]),
            "source_revision": facts[component]["product_revision"],
            "source_tree": facts[component]["product_tree"],
            "wheel_sha256": facts[component]["wheel_sha256"],
            "images": facts[component]["images"],
            "revision_contract": facts[component]["revision_contract"],
            "original_predicate_sha256": original[component]["predicate_sha256"],
            "current_predicate_sha256": current[component]["predicate_sha256"],
            "original_producer": original[component]["producer"],
            "current_producer": current[component]["producer"],
        }
        for component in sorted(COMPONENTS)
    }
    body = fallback["full_stack_rollback"]
    require(
        isinstance(body, dict)
        and set(body)
        == {
            "kind",
            "product_revision",
            "drill_id",
            "started_at",
            "completed_at",
            "result",
            "publication_bindings",
            "cluster_uid_hash",
            "workloads",
            "pair_checks",
            "protocol_database_contract_sha256",
        }
        and body["kind"] == "production_legacy_full_stack_rollback/v2"
        and body["product_revision"] == envelope["product_revision"]
        and body["result"] == "passed"
        and isinstance(body["drill_id"], str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", body["drill_id"])
        and body["publication_bindings"] == bindings
        and body["cluster_uid_hash"] == stack["physical_inventory"]["cluster_uid_hash"]
        and body["protocol_database_contract_sha256"]
        == stack["protocol_database_contract_sha256"],
        "complete physical rollback does not bind all three exact publications",
    )
    primary = {}
    rollback_records = evidence.get("promotion", {}).get("images", [])
    require(
        isinstance(rollback_records, list) and len(rollback_records) == len(publisher.IMAGES),
        "complete fallback needs both original primary image rollback records",
    )
    for item in rollback_records:
        role = item.get("name", "").removeprefix("omnigent-saas-")
        require(
            role in publisher.IMAGES and role not in primary, "primary rollback image roles differ"
        )
        primary[role] = item["registry_ref"]
        selected = stack["physical_inventory"]["workloads"][stack["n_minus_one_pair"][role]]
        reference = facts[selected["component"]]["images"][role]
        rollback = item["n_minus_one_rollback"]
        require(
            rollback.get("to_registry_ref") == reference
            and rollback.get("to_digest") == reference.split("@", 1)[1]
            and all(
                rollback.get(field) == body[field]
                for field in ("started_at", "completed_at", "result")
            )
            and rollback.get("evidence_sha256") == publisher.digest(body),
            "primary N-1 record does not bind the same complete physical rollback",
        )
    expected_workloads = {
        identifier: {
            "identity_sha256": publisher.digest(workload),
            "component": workload["component"],
            "image_role": workload["image_role"],
            "from_registry_ref": primary[workload["image_role"]],
            "to_registry_ref": facts[workload["component"]]["images"][workload["image_role"]],
            "drill_id": body["drill_id"],
        }
        for identifier, workload in stack["physical_inventory"]["workloads"].items()
    }
    require(
        body["workloads"] == expected_workloads,
        "physical rollback omits or exchanges a workload/profile/drill",
    )
    _validate_pairs(body, stack, primary, facts)
    require(
        publisher.digest(body) == stack["rollback_sha256"],
        "physical rollback body is not exactly registered",
    )
    records = load_deployment_evidence(repo, policy)
    report = validate_deployment_readiness(
        repo, policy, records, now=now, expected_product_revision=envelope["product_revision"]
    )
    require(
        report["status"] == "pass" and report["production_readiness"] == "ready",
        "complete legacy fallback requires all existing deployment gates",
    )
    matches = [
        record
        for record in records
        if record.get("drills", {}).get("n_minus_one_rollback", {}).get("evidence_sha256")
        == publisher.digest(body)
    ]
    require(len(matches) == 1, "complete rollback needs one matching physical deployment record")
    record = matches[0]
    require(
        record["cluster"]["cluster_uid_hash"] == body["cluster_uid_hash"]
        and all(
            record["drills"]["n_minus_one_rollback"].get(field) == body[field]
            for field in ("started_at", "completed_at", "result")
        ),
        "physical deployment record belongs to another cluster/window/drill",
    )
    for component, identifiers in stack["policy_bindings"].items():
        expected = {
            primary[stack["physical_inventory"]["workloads"][identifier]["image_role"]]
            for identifier in identifiers
        }
        require(
            len(expected) == 1
            and record["components"][component]["digest_pinned_image"] in expected,
            "deployment policy role does not bind the registered physical primary inventory",
        )
    admission_policy = json.loads(
        (repo / "saas/production/evidence-admission-policy.json").read_text()
    )
    signed = validate_evidence_admission(
        repo, admission_policy, now=now, expected_product_revision=envelope["product_revision"]
    )
    require(
        signed["status"] == "pass"
        and signed["kinds"]["deployment"]["production_readiness"] == "ready",
        "complete physical rollback requires independently signed deployment admission",
    )
    require(
        registered_stack(repo, fallback["stack_id"], policy) == stack,
        "complete legacy stack registration changed during native verification",
    )
    for component in COMPONENTS:
        require(
            registered_publication(repo, stack["publication_ids"][component]) == current[component]
            and registered_publication(repo, stack["original_publication_ids"][component])
            == original[component],
            "legacy publication registration changed during native verification",
        )
    return evidence
