"""Typed scope fixtures exercise parsers, not actual C2 publication qualification."""

from __future__ import annotations

import copy
import json

import pytest

from saas.production import legacy_stack as stack
from saas.production import readiness
from saas.production.legacy_publication import registered_publication
from saas.scripts import check_image_supply_chain as generic
from saas.scripts import legacy_publication_reader as reader
from tests.saas import test_image_supply_chain as image
from tests.saas import test_legacy_stack as base
from tests.saas.test_legacy_stack import complete_stack as complete_stack


def substitute(value, replacements):
    if isinstance(value, dict):
        return {key: substitute(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, replacements) for item in value]
    if isinstance(value, str):
        for before, after in replacements:
            if value == before:
                return after
    return value


@pytest.fixture
def runtime_pair(complete_stack):
    data = complete_stack
    histories = {}
    for component, row in data["rows"].items():
        qualification = copy.deepcopy(row["admission"]["source_qualification"]["result"])
        histories[component] = {
            "source_only": True,
            "runtime_admission": False,
            "control_revision": qualification["control_revision"],
            "profile_sha256": reader.publisher.digest(row["profile"]),
            "qualification": qualification,
            "qualification_sha256": reader.publisher.digest(qualification),
        }
    profile = json.loads(
        (base.ROOT / "saas/supply_chain/legacy-security-build-profiles.json").read_text()
    )["profiles"]["Compatibility018"]
    original = data["rows"]["Core"]
    replacements = [
        (original["profile"]["product_revision"], profile["product_revision"]),
        (original["profile"]["product_tree"], profile["product_tree"]),
        (original["profile"]["baseline_revision"], profile["baseline_revision"]),
        ("Core", "Compatibility018"),
    ]
    selected = substitute(copy.deepcopy(original), replacements)
    selected["profile"] = copy.deepcopy(profile)
    selected["admission"]["profile"] = copy.deepcopy(profile)
    transfer = json.loads(
        (base.ROOT / "saas/supply_chain/legacy-security-transfer-profiles.json").read_text()
    )["profiles"]["Compatibility018"]
    selected["admission"]["transfer_profile"] = copy.deepcopy(transfer)
    selected["admission"]["original_pr_oci"].update(transfer)
    fresh = selected["admission"]["fresh_control_wheel"]
    fresh["artifact_name"] = (
        f"legacy-initial-Compatibility018-{profile['product_revision']}-"
        f"{selected['producer']['control_revision']}-{fresh['run_id']}-1"
    )
    for role, coordinate in selected["stage_artifacts"].items():
        coordinate["artifact_name"] = reader.publisher.artifact_name(
            role, profile, selected["producer"]
        )
    qualification = selected["admission"]["source_qualification"]
    qualification["sha256"] = reader.publisher.digest(qualification["result"])
    data["rows"]["Compatibility018"] = selected
    facts = copy.deepcopy(data["facts"]["Core"])
    facts.update(
        product_revision=profile["product_revision"], product_tree=profile["product_tree"]
    )
    facts["revision_contract"]["control_plane_schema_revision"] = "p0s000000018"
    data["facts"]["Compatibility018"] = facts
    inventory = {
        name: item
        for name, item in data["stack"]["physical_inventory"]["workloads"].items()
        if name in {"fixture-core", "fixture-host"}
    }
    for item in inventory.values():
        item["component"] = "Compatibility018"
    selected["deployment_roles"] = {name: item["image_role"] for name, item in inventory.items()}
    registration = data["stack"]
    registration.update(
        kind=stack.RUNTIME_PAIR_KIND,
        publication_ids={"Compatibility018": "fixture-Compatibility018"},
        original_publication_ids={"Compatibility018": "fixture-Compatibility018"},
        source_contracts={"Compatibility018": facts["revision_contract"]},
        historical_source_qualification=histories,
    )
    registration["physical_inventory"]["workloads"] = inventory
    registration["policy_bindings"] = {
        role: ["fixture-host" if role == "runner" else "fixture-core"]
        for role in registration["policy_bindings"]
    }
    binding = copy.deepcopy(data["body"]["publication_bindings"]["Core"])
    binding.update(
        publication_id="fixture-Compatibility018",
        original_publication_id="fixture-Compatibility018",
        profile_sha256=reader.publisher.digest(profile),
        source_revision=profile["product_revision"],
        source_tree=profile["product_tree"],
        images=facts["images"],
        revision_contract=facts["revision_contract"],
        original_producer=selected["producer"],
        current_producer=selected["producer"],
    )
    body = data["body"]
    body["pair_checks"] = copy.deepcopy(body["pair_checks"])
    body["kind"] = stack.RUNTIME_PAIR_ROLLBACK_KIND
    body["publication_bindings"] = {"Compatibility018": binding}
    body["workloads"] = {
        name: {
            **body["workloads"][name],
            "identity_sha256": reader.publisher.digest(item),
            "component": "Compatibility018",
        }
        for name, item in inventory.items()
    }
    return data


def persist(data):
    envelope = base.persist(data)
    envelope["kind"] = stack.RUNTIME_PAIR_VARIANT
    return envelope


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "unsigned",
        "wrong_baseline",
        "wrong_source",
        "missing_digest",
        "as_core",
        "historical_runtime",
        "extra_runtime",
        "wrong_schema",
        "missing_mix",
        "wrong_pair",
    ],
)
def test_actual_runtime_pair_scope_reuses_publication_guards(runtime_pair, monkeypatch, fault):
    data = runtime_pair
    selected = data["rows"]["Compatibility018"]
    if fault == "unsigned":

        def reject_unsigned(*_args):
            raise ValueError("native signature verification refused unsigned publication")

        monkeypatch.setattr(stack, "read_registered_publication", reject_unsigned)
    elif fault == "wrong_baseline":
        selected["profile"]["baseline_revision"] = base.BASELINES["Core"]
    elif fault == "wrong_source":
        selected["profile"]["product_revision"] = "0" * 40
    elif fault == "missing_digest":
        data["body"]["pair_checks"]["old_pair_recovery"]["images"].pop("host")
    elif fault == "as_core":
        selected["profile"]["component"] = "Core"
    elif fault == "historical_runtime":
        data["stack"]["historical_source_qualification"]["Gateway"]["runtime_admission"] = True
    elif fault == "extra_runtime":
        inventory = data["stack"]["physical_inventory"]["workloads"]
        inventory["extra-gateway"] = {
            **inventory["fixture-core"],
            "component": "Gateway",
            "workload_uid_hash": "8" * 64,
        }
    elif fault == "wrong_schema":
        data["stack"]["source_contracts"]["Compatibility018"]["control_plane_schema_revision"] = (
            "p0s000000015"
        )
    elif fault == "missing_mix":
        data["body"]["pair_checks"].pop("old_server_final_host")
    elif fault == "wrong_pair":
        data["body"]["pair_checks"]["old_server_final_host"]["images"]["server"] = (
            "ghcr.io/dream1216/omnigent-saas-server@sha256:" + "f" * 64
        )
    wrapped = persist(data)
    if fault:
        with pytest.raises((ValueError, KeyError)):
            stack.validate_stack_fallback(
                data["repo"], wrapped, now=base.NOW, expected_product_revision="a" * 40
            )
    else:
        assert (
            stack.validate_stack_fallback(
                data["repo"], wrapped, now=base.NOW, expected_product_revision="a" * 40
            )
            == data["evidence"]
        )
        assert data["calls"] == ["Compatibility018"]
        assert (
            registered_publication(data["repo"], "fixture-Compatibility018")["profile"]
            == selected["profile"]
        )


@pytest.mark.parametrize("envelope_kind", [stack.RUNTIME_PAIR_VARIANT, stack.VARIANT])
def test_runtime_pair_dispatch_reaches_native_scope_validation(
    runtime_pair, monkeypatch, envelope_kind
):
    wrapped = persist(runtime_pair)
    wrapped["kind"] = envelope_kind
    calls = []

    def marker(*args, **_kwargs):
        calls.append(args[1]["kind"])
        raise ValueError("fixture native boundary reached")

    monkeypatch.setattr("saas.production.legacy_publication.validate_legacy_fallback", marker)
    monkeypatch.setattr(generic, "_validate_policy", lambda *_args: [])
    monkeypatch.setattr(generic, "_validate_evidence", lambda *_args, **_kwargs: [])
    generic.validate_release(runtime_pair["repo"], image._policy(), wrapped, now=base.NOW)
    assert calls == [envelope_kind]


@pytest.mark.parametrize("typed", [False, True])
@pytest.mark.parametrize("cross_kind", [False, True])
def test_evidence_only_lineage_keeps_registered_typed_scope(
    runtime_pair, monkeypatch, typed, cross_kind
):
    data = runtime_pair
    wrapped = persist(data)
    if not typed:
        wrapped["kind"] = stack.VARIANT
        data["stack"]["kind"] = "protected_legacy_full_stack/v1"
        data["body"]["kind"] = "production_legacy_full_stack_rollback/v2"
    if cross_kind:
        wrapped["kind"] = stack.VARIANT if typed else stack.RUNTIME_PAIR_VARIANT
    data["stack"]["rollback_sha256"] = reader.publisher.digest(data["body"])
    base.write(
        data["repo"] / stack.STACK_REGISTRY,
        {"schema_version": 1, "stacks": {"fixture-stack": data["stack"]}},
    )
    base.write(data["repo"] / "saas/acceptance/p0-production-image-evidence.json", wrapped)
    # Isolate the evidence-only classifier; real stack registration and publication
    # guards are exercised above and by the unchanged v2 matrix.
    monkeypatch.setattr(stack, "registered_stack", lambda *_args: data["stack"])

    class Result:
        returncode = 0
        stdout = '{"schema_version":1,"stacks":{}}'

    monkeypatch.setattr(readiness, "_git", lambda *_args: Result())
    assert readiness._legacy_stack_evidence_only(
        data["repo"], "a" * 40, validate_publications=False
    ) is (not cross_kind)
