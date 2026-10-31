"""Three real baseline shapes; mocked native publications are NOT qualification."""

from __future__ import annotations

import base64
import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saas.production import legacy_stack as stack
from saas.production.admission import admission_signature_payload
from saas.scripts import legacy_publication_reader as reader
from saas.scripts import legacy_publication_renewal as renewal
from tests.saas import test_deployment_readiness as deployment
from tests.saas import test_evidence_admission as signatures
from tests.saas import test_image_supply_chain as image

ROOT = Path(__file__).resolve().parents[2]
BASELINES = {
    "Core": "dc1e9a9735d4c996b74e601ed7f4ecb49e83f9ec",
    "Gateway": "3319b59a5d75a411f339b294cbe6b4133bfb851a",
    "Model": "7cea09404d49fc965ce053e51803688a5be5fe53",
}
NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def publication(component, number, generation=2):
    """Actual baseline identities; unpublished source/digest values are fixture-only."""
    revision, tree = f"{number:040x}", f"{number + 10:040x}"
    profile = {
        "schema_version": 1,
        "repository": reader.publisher.REPOSITORY,
        "component": component,
        "baseline_revision": BASELINES[component],
        "product_revision": revision,
        "product_tree": tree,
        "source_date_epoch": 1785542400,
        "application_version": "0.18.0.dev20261006",
        "source_delta": [
            {
                "path": "uv.toml",
                "before": {"mode": "100644", "sha256": "1" * 64},
                "after": {"mode": "100644", "sha256": "2" * 64},
            }
        ],
    }
    context = {
        "control_revision": "c" * 40,
        "run_id": generation * 100 + number,
        "attempt": 1,
        "actor": "fixture",
    }
    transfer = {
        "component": component,
        "pull_number": 9000 + number,
        "base_ref": f"codex/legacy-validation-{component.lower()}-{BASELINES[component][:8]}",
        "workflow_sha256": "f" * 64,
        "actor": "fixture",
    }
    original = {
        "kind": "legacy_pr_sealed_oci/v1",
        "component": component,
        "product_revision": revision,
        "product_tree": tree,
        "baseline_revision": BASELINES[component],
        **transfer,
        "merge_revision": "d" * 40,
        "workflow_path": ".github/workflows/saas-image-candidate.yml",
        "run_id": number + 1000,
        "attempt": 1,
        "job_id": number + 2000,
        "artifact_id": number + 3000,
        "zip_size": 100,
        "zip_sha256": f"{number + 100:064x}",
        "seal_sha256": f"{number + 200:064x}",
    }
    fresh = {
        **context,
        "job_id": generation * 10000 + number,
        "artifact_id": generation * 2000 + number,
        "artifact_name": f"legacy-initial-{component}-{revision}-{'c' * 40}-{context['run_id']}-1",
        "zip_size": 100,
        "zip_sha256": f"{generation * 100 + number:064x}",
        "product_revision": revision,
        "product_tree": tree,
        "wheel_filename": "omnigent-fixture.whl",
        "wheel_sha256": f"{number + 300:064x}",
        "source_facts_sha256": f"{number + 400:064x}",
    }
    source = {
        "kind": "legacy_source_qualification/v1",
        "component": component,
        "product_revision": revision,
        "product_tree": tree,
        "control_revision": context["control_revision"],
        "technical_source_ci": "pass",
        "status": "pass",
        "source_ci_pass": True,
        "complete_domain_discovery": True,
    }
    pg = {"kind": "legacy_native_exact_product_PG_receipts/v1", "native_PG_receipts_pass": True}
    admission = {
        "kind": reader.publisher.VARIANT,
        "profile": profile,
        "transfer_profile": transfer,
        "control": {
            **context,
            "workflow_path": reader.publisher.WORKFLOW,
            "workflow_sha256": "e" * 64,
        },
        "original_pr_oci": original,
        "fresh_control_wheel": fresh,
        "source_qualification": {"sha256": reader.publisher.digest(source), "result": source},
        "native_product_pg": {"sha256": reader.publisher.digest(pg), "result": pg},
        "rebuild_in_publisher": False,
    }
    return {
        "input_variant": reader.publisher.VARIANT,
        "profile": profile,
        "producer": {**context, "control_tree": "b" * 40, "workflow_sha256": "e" * 64},
        "admission": admission,
        "predicate_sha256": f"{generation * 200 + number:064x}",
        "stage_artifacts": {
            role: {
                "job_id": generation * 3000 + number * 10 + index,
                "artifact_id": generation * 4000 + number * 10 + index,
                "artifact_name": reader.publisher.artifact_name(role, profile, context),
                "zip_size": 100,
                "zip_sha256": f"{generation * 1000 + number * 10 + index:064x}",
            }
            for index, role in enumerate(
                ("preparation", "publication", "runtime", "signatures"), 1
            )
        },
        "deployment_roles": {},
    }


@pytest.fixture
def complete_stack(tmp_path, monkeypatch):
    """Only publication native readback is doubled; original Ed25519 verification runs."""
    policy, key = signatures._fixture(tmp_path)
    for source in policy["evidence_sources"]:
        if source["kind"] == "deployment":
            source["directory"] = "saas/production/deployment-evidence"
    write(tmp_path / "saas/production/evidence-admission-policy.json", policy)
    deploy_policy = deployment._policy()
    write(tmp_path / "saas/production/deployment-policy.json", deploy_policy)
    write(
        tmp_path / "saas/production/baseline.json",
        json.loads((ROOT / "saas/production/baseline.json").read_text()),
    )
    rows = {
        component: publication(component, index)
        for index, component in enumerate(sorted(BASELINES), 1)
    }
    contracts = {
        component: {
            "upstream_manifest": "saas/upstream-baseline.json",
            "upstream_revision": "825f8500d7cc8e997e5562fa55694cd146165f3c",
            "adapter_contract_version": "0.2.0",
            "deployment_scope": "single-region-multi-az",
            "control_plane_schema_revision": "lm2t00000001"
            if component == "Gateway"
            else "p0s000000015",
        }
        for component in BASELINES
    }
    inventory = {
        name: {
            "kind": "Deployment",
            "namespace_uid_hash": "f" * 64,
            "workload_uid_hash": f"{index + 700:064x}",
            "container_name": name,
            "component": component,
            "image_role": role,
        }
        for index, (name, component, role) in enumerate(
            (
                ("fixture-core", "Core", "server"),
                ("fixture-host", "Core", "host"),
                ("fixture-gateway", "Gateway", "server"),
                ("fixture-model", "Model", "server"),
                ("fixture-model-admin", "Model", "server"),
            ),
            1,
        )
    }
    for component, row in rows.items():
        row["deployment_roles"] = {
            name: item["image_role"]
            for name, item in inventory.items()
            if item["component"] == component
        }
    publication_ids = {component: "fixture-" + component for component in BASELINES}
    facts = {
        component: {
            "product_revision": row["profile"]["product_revision"],
            "product_tree": row["profile"]["product_tree"],
            "wheel_sha256": row["admission"]["fresh_control_wheel"]["wheel_sha256"],
            "images": {
                role: f"ghcr.io/dream1216/omnigent-saas-{role}@sha256:{number:064x}"
                for role, number in (("server", index + 800), ("host", index + 900))
            },
            "revision_contract": contracts[component],
            "production_admission": False,
        }
        for index, (component, row) in enumerate(sorted(rows.items()), 1)
    }
    calls = []

    def native(_repo, row, _destination):
        component = row["profile"]["component"]
        calls.append(component)
        return copy.deepcopy(facts[component])

    monkeypatch.setattr(stack, "read_registered_publication", native)
    evidence = image._valid_evidence()
    primary = {
        item["name"].removeprefix("omnigent-saas-"): item["registry_ref"]
        for item in evidence["promotion"]["images"]
    }
    record = deployment._record()
    record["completed_at"] = "2026-08-09T10:30:00Z"
    for attestation in record["attestations"]:
        attestation["attested_at"] = "2026-08-09T10:00:00Z"
    registration = {
        "kind": "protected_legacy_full_stack/v1",
        "publication_ids": publication_ids,
        "original_publication_ids": publication_ids,
        "source_contracts": contracts,
        "physical_inventory": {
            "cluster_uid_hash": record["cluster"]["cluster_uid_hash"],
            "workloads": inventory,
        },
        "policy_bindings": {
            "control-plane": ["fixture-core", "fixture-model-admin"],
            "queue-worker": ["fixture-core"],
            "runner": ["fixture-host"],
            "preview-gateway": ["fixture-gateway"],
            "egress-proxy": ["fixture-model"],
        },
        "n_minus_one_pair": {"server": "fixture-core", "host": "fixture-host"},
        "rollback_sha256": "0" * 64,
        "protocol_database_contract_sha256": "a" * 64,
    }
    bindings = {
        component: {
            "publication_id": publication_ids[component],
            "original_publication_id": publication_ids[component],
            "profile_sha256": reader.publisher.digest(rows[component]["profile"]),
            "source_revision": facts[component]["product_revision"],
            "source_tree": facts[component]["product_tree"],
            "wheel_sha256": facts[component]["wheel_sha256"],
            "images": facts[component]["images"],
            "revision_contract": contracts[component],
            "original_predicate_sha256": rows[component]["predicate_sha256"],
            "current_predicate_sha256": rows[component]["predicate_sha256"],
            "original_producer": rows[component]["producer"],
            "current_producer": rows[component]["producer"],
        }
        for component in BASELINES
    }
    body = {
        "kind": "production_legacy_full_stack_rollback/v2",
        "product_revision": "a" * 40,
        "drill_id": "fixture-physical-rollback-one",
        "started_at": "2026-08-09T09:00:00Z",
        "completed_at": "2026-08-09T09:05:00Z",
        "result": "passed",
        "publication_bindings": bindings,
        "cluster_uid_hash": record["cluster"]["cluster_uid_hash"],
        "workloads": {
            name: {
                "identity_sha256": reader.publisher.digest(item),
                "component": item["component"],
                "image_role": item["image_role"],
                "from_registry_ref": primary[item["image_role"]],
                "to_registry_ref": facts[item["component"]]["images"][item["image_role"]],
                "drill_id": "fixture-physical-rollback-one",
            }
            for name, item in inventory.items()
        },
        "protocol_database_contract_sha256": "a" * 64,
        "pair_checks": {},
    }
    pair_refs = {
        "final_server_old_host": {
            "server": primary["server"],
            "host": facts["Core"]["images"]["host"],
        },
        "old_server_final_host": {
            "server": facts["Core"]["images"]["server"],
            "host": primary["host"],
        },
        "old_pair_recovery": facts["Core"]["images"],
    }
    for index, name in enumerate(sorted(stack.PAIR_CHECKS), 1):
        body["pair_checks"][name] = {
            "drill_id": body["drill_id"],
            "images": pair_refs[name],
            "started_at": body["started_at"],
            "completed_at": body["completed_at"],
            "result": "passed",
            "evidence_sha256": f"{index + 999:064x}",
            "protocol_database_contract_sha256": "a" * 64,
        }
    for role, identifiers in registration["policy_bindings"].items():
        record["components"][role]["digest_pinned_image"] = primary[
            inventory[identifiers[0]]["image_role"]
        ]
        if role == "runner":
            for placement in record["components"][role]["placements"]:
                placement["seccomp"]["image"] = record["components"][role]["digest_pinned_image"]
    return {
        "repo": tmp_path,
        "rows": rows,
        "facts": facts,
        "stack": registration,
        "body": body,
        "record": record,
        "evidence": evidence,
        "policy": policy,
        "key": key,
        "calls": calls,
    }


def persist(data, *, bad_signature=False):
    repo, row, body = data["repo"], data["stack"], data["body"]
    row["rollback_sha256"] = reader.publisher.digest(body)
    write(repo / stack.STACK_REGISTRY, {"schema_version": 1, "stacks": {"fixture-stack": row}})
    write(
        repo / "saas/supply_chain/legacy-production-publications.json",
        {
            "schema_version": 1,
            "publications": {
                "fixture-" + component: value for component, value in data["rows"].items()
            },
        },
    )
    for name in reader.TRUSTED_STORES:
        key = "inputs" if "original-inputs" in name else "profiles"
        write(
            repo / "saas/supply_chain" / name,
            {
                "schema_version": 1,
                key: {
                    component: value["profile"]
                    if "build-profiles" in name
                    else {"fixture_only": True}
                    for component, value in data["rows"].items()
                },
            },
        )
    for item in data["evidence"]["promotion"]["images"]:
        role = item["name"].removeprefix("omnigent-saas-")
        target = data["facts"]["Core"]["images"][role]
        item["n_minus_one_rollback"].update(
            to_registry_ref=target,
            to_digest=target.split("@", 1)[1],
            evidence_sha256=row["rollback_sha256"],
            **{key: body[key] for key in ("started_at", "completed_at", "result")},
        )
    data["record"]["drills"]["n_minus_one_rollback"].update(
        evidence_sha256=row["rollback_sha256"],
        **{key: body[key] for key in ("started_at", "completed_at", "result")},
    )
    deployment._resign(data["record"])
    record_path = repo / "saas/production/deployment-evidence/fixture.json"
    write(record_path, data["record"])
    receipt_path = repo / "admission/receipts/deployment.json"
    receipt = json.loads(receipt_path.read_text())
    receipt.update(
        evidence_path="saas/production/deployment-evidence/fixture.json",
        evidence_sha256=__import__("hashlib").sha256(record_path.read_bytes()).hexdigest(),
    )
    receipt["signature"] = base64.b64encode(
        data["key"].sign(admission_signature_payload(receipt))
    ).decode()
    if bad_signature:
        receipt["signature"] = base64.b64encode(b"invalid fixture signature").decode()
    write(receipt_path, receipt)
    return {
        "kind": stack.VARIANT,
        "product_revision": "a" * 40,
        "release_evidence": data["evidence"],
        "legacy_fallback": {
            "stack_id": "fixture-stack",
            "publication_ids": row["publication_ids"],
            "original_publication_ids": row["original_publication_ids"],
            "full_stack_rollback": body,
        },
    }


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing_service",
        "swapped_profile",
        "one_source_for_three",
        "missing_physical_service",
        "unmapped_physical_service",
        "different_workload_drill",
        "different_pair_drill",
        "missing_host_pair",
        "wrong_host_digest",
        "wrong_wheel",
        "wrong_schema",
        "different_cluster",
        "bad_deployment_signature",
        "replica_failure",
    ],
)
def test_complete_three_service_set_and_one_physical_drill(complete_stack, fault):
    data = complete_stack
    if fault == "missing_service":
        data["body"]["publication_bindings"].pop("Model")
    elif fault == "swapped_profile":
        selected = data["stack"]["publication_ids"]
        selected["Core"], selected["Gateway"] = selected["Gateway"], selected["Core"]
    elif fault == "one_source_for_three":

        def replace(value, before, after):
            if isinstance(value, dict):
                return {k: replace(v, before, after) for k, v in value.items()}
            if isinstance(value, list):
                return [replace(v, before, after) for v in value]
            return value.replace(before, after) if isinstance(value, str) else value

        core = data["rows"]["Core"]["profile"]
        for component in ("Gateway", "Model"):
            for field in ("product_revision", "product_tree"):
                data["rows"][component] = replace(
                    data["rows"][component], data["rows"][component]["profile"][field], core[field]
                )
    elif fault == "missing_physical_service":
        data["body"]["workloads"].pop("fixture-model-admin")
    elif fault == "unmapped_physical_service":
        data["stack"]["policy_bindings"]["control-plane"].remove("fixture-model-admin")
    elif fault == "different_workload_drill":
        data["body"]["workloads"]["fixture-gateway"]["drill_id"] = "another-drill"
    elif fault == "different_pair_drill":
        data["body"]["pair_checks"]["old_server_final_host"]["drill_id"] = "another-drill"
    elif fault == "missing_host_pair":
        data["body"]["pair_checks"].pop("final_server_old_host")
    elif fault == "wrong_host_digest":
        data["body"]["pair_checks"]["final_server_old_host"]["images"]["host"] = data["facts"][
            "Model"
        ]["images"]["host"]
    elif fault == "wrong_wheel":
        data["body"]["publication_bindings"]["Gateway"]["wheel_sha256"] = data["facts"]["Core"][
            "wheel_sha256"
        ]
    elif fault == "wrong_schema":
        data["stack"]["source_contracts"]["Gateway"] = data["stack"]["source_contracts"]["Core"]
    elif fault == "different_cluster":
        data["record"]["cluster"]["cluster_uid_hash"] = "0" * 64
    elif fault == "replica_failure":
        data["record"]["components"]["runner"]["ready_replicas"] = 0
    wrapped = persist(data, bad_signature=fault == "bad_deployment_signature")
    if fault:
        with pytest.raises(ValueError):
            stack.validate_stack_fallback(
                data["repo"], wrapped, now=NOW, expected_product_revision="a" * 40
            )
    else:
        assert (
            stack.validate_stack_fallback(
                data["repo"], wrapped, now=NOW, expected_product_revision="a" * 40
            )
            == data["evidence"]
        )
        assert set(data["calls"]) == stack.COMPONENTS and len(data["calls"]) == 3
        assert (
            data["stack"]["source_contracts"]["Gateway"]
            != data["stack"]["source_contracts"]["Core"]
        )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "source",
        "tree",
        "wheel",
        "original_OCI",
        "same_run",
        "same_predicate",
        "same_artifact",
    ],
)
def test_new_complete_publication_must_preserve_candidate_and_keep_native_coordinates_separate(
    fault,
):
    original, current = publication("Gateway", 2, 1), publication("Gateway", 2, 2)
    if fault in {"source", "tree"}:
        current["profile"]["product_revision" if fault == "source" else "product_tree"] = "0" * 40
    elif fault == "wheel":
        current["admission"]["fresh_control_wheel"]["wheel_sha256"] = "0" * 64
    elif fault == "original_OCI":
        current["admission"]["original_pr_oci"]["seal_sha256"] = "0" * 64
    elif fault == "same_run":
        current["producer"]["run_id"] = original["producer"]["run_id"]
    elif fault == "same_predicate":
        current["predicate_sha256"] = original["predicate_sha256"]
    elif fault == "same_artifact":
        current["stage_artifacts"]["runtime"]["artifact_id"] = original["stage_artifacts"][
            "runtime"
        ]["artifact_id"]
    if fault:
        with pytest.raises(ValueError):
            renewal.verify_renewal_identity(original, current)
    else:
        renewal.verify_renewal_identity(original, current)
