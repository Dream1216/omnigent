"""Exercise the actual three-service current reader, old anchors and native crypto parsers.

All native responses/gh verification results and registry transfers are owned
external-boundary fixtures. They grant no real native or physical qualification.
"""

from __future__ import annotations

import copy
import json
import shutil

import pytest

from saas.production import legacy_stack as stack
from saas.scripts import check_image_supply_chain as generic
from saas.scripts import legacy_publication_reader as reader
from saas.scripts import legacy_publication_renewal as renewal
from saas.scripts.check_image_supply_chain import validate_release
from tests.saas import test_image_supply_chain as image
from tests.saas import test_legacy_stack as base
from tests.saas.legacy_renewal_native_fixture import NativeRenewal, archive, init, write
from tests.saas.test_legacy_stack import complete_stack as complete_stack


@pytest.fixture(scope="module")
def native_template(tmp_path_factory):
    patch = pytest.MonkeyPatch()
    patch.setenv("GIT_AUTHOR_DATE", "2026-08-01T00:00:00Z")
    patch.setenv("GIT_COMMITTER_DATE", "2026-08-01T00:00:00Z")
    try:
        yield NativeRenewal(tmp_path_factory.mktemp("owned-native-renewal"), patch)
    finally:
        patch.undo()


@pytest.fixture
def native_stack(complete_stack, native_template, tmp_path, monkeypatch):
    native = copy.copy(native_template)
    values = copy.deepcopy(
        {
            key: value
            for key, value in vars(native).items()
            if key not in {"monkeypatch", "calls", "crypto_calls"}
        }
    )
    vars(native).update(values)
    native.monkeypatch = monkeypatch
    native.calls, native.crypto_calls = [], []
    native._install_boundaries()
    data = complete_stack
    monkeypatch.setattr(stack.tempfile, "tempdir", str(tmp_path))
    paths = (
        {value for key, value in generic._APPROVED_PATHS.items() if key != "production_evidence"}
        | generic._REQUIRED_LOCKFILES
        | generic._REQUIRED_OFFICIAL_SUITES
        | {"setup.py"}
    )
    for relative in paths:
        target = data["repo"] / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(base.ROOT / relative, target)
    contexts = (
        image._candidate_contract_repo(tmp_path / "candidate-context"),
        image._material_lock_repo(tmp_path / "material-context"),
    )
    for context in contexts:
        for source in context.rglob("*"):
            if source.is_file():
                target = data["repo"] / source.relative_to(context)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
    (data["repo"] / "tests/saas").mkdir(parents=True, exist_ok=True)

    def shift(value):
        if isinstance(value, dict):
            return {key: shift(item) for key, item in value.items()}
        if isinstance(value, list):
            return [shift(item) for item in value]
        if isinstance(value, str) and value.startswith("2026-08-05T"):
            return "2026-08-09T" + value.removeprefix("2026-08-05T")
        return value

    data["evidence"] = shift(data["evidence"])
    data["native"] = native
    data["rows"] = native.rows["current"]
    data["stack"]["publication_ids"] = {
        component: "current-" + component for component in stack.COMPONENTS
    }
    data["stack"]["original_publication_ids"] = {
        component: "original-" + component for component in stack.COMPONENTS
    }
    inventory = data["stack"]["physical_inventory"]["workloads"]
    for component, product in native.products.items():
        data["stack"]["source_contracts"][component] = product["contract"]
        roles = {
            name: row["image_role"]
            for name, row in inventory.items()
            if row["component"] == component
        }
        for generation in ("old", "current"):
            native.rows[generation][component]["deployment_roles"] = roles
        current, original = native.rows["current"][component], native.rows["old"][component]
        images = product["current"]["publication"]["images"]
        data["facts"][component] = {
            "images": images,
            "wheel_sha256": current["admission"]["fresh_control_wheel"]["wheel_sha256"],
            "product_revision": product["profile"]["product_revision"],
            "product_tree": product["profile"]["product_tree"],
            "revision_contract": product["contract"],
        }
        data["body"]["publication_bindings"][component] = {
            "publication_id": "current-" + component,
            "original_publication_id": "original-" + component,
            "profile_sha256": reader.publisher.digest(product["profile"]),
            "source_revision": product["profile"]["product_revision"],
            "source_tree": product["profile"]["product_tree"],
            "wheel_sha256": data["facts"][component]["wheel_sha256"],
            "images": images,
            "revision_contract": product["contract"],
            "original_predicate_sha256": original["predicate_sha256"],
            "current_predicate_sha256": current["predicate_sha256"],
            "original_producer": original["producer"],
            "current_producer": current["producer"],
        }
    for name, value in data["body"]["workloads"].items():
        item = inventory[name]
        value["to_registry_ref"] = data["facts"][item["component"]]["images"][item["image_role"]]
    pair = data["facts"]["Core"]["images"]
    data["body"]["pair_checks"]["final_server_old_host"]["images"]["host"] = pair["host"]
    data["body"]["pair_checks"]["old_server_final_host"]["images"]["server"] = pair["server"]
    data["body"]["pair_checks"]["old_pair_recovery"]["images"] = pair
    init(data["repo"])
    objects = [
        native.control / ".git/objects",
        *(p["path"] / ".git/objects" for p in native.products.values()),
    ]
    (data["repo"] / ".git/objects/info/alternates").write_text("\n".join(map(str, objects)) + "\n")
    # Replace the old test's facts double with wrappers that invoke the REAL readers.
    current_calls, anchor_calls = [], []

    def current(repo, registration, destination):
        current_calls.append(registration["profile"]["component"])
        return reader.read_registered_publication(repo, registration, destination)

    def anchor(repo, original, current, facts, destination):
        anchor_calls.append(original["profile"]["component"])
        return renewal.read_original_publication_anchor(
            repo, original, current, facts, destination
        )

    monkeypatch.setattr(stack, "read_registered_publication", current)
    monkeypatch.setattr(stack, "read_original_publication_anchor", anchor)
    data.update(current_calls=current_calls, anchor_calls=anchor_calls)
    return data


def persist(data):
    envelope = base.persist(data, bad_signature=data.get("bad_signature", False))
    image._resign(envelope["release_evidence"])
    native, repo = data["native"], data["repo"]
    rows = {
        generation + "-" + component: row
        for generation, values in (
            ("current", native.rows["current"]),
            ("original", native.rows["old"]),
        )
        for component, row in values.items()
    }
    write(
        repo / "saas/supply_chain/legacy-production-publications.json",
        {"schema_version": 1, "publications": rows},
    )
    for name in reader.TRUSTED_STORES:
        target = repo / "saas/supply_chain" / name
        target.write_bytes((native.control / "saas/supply_chain" / name).read_bytes())
    return envelope


def corrupt_current_scan(data, fault):
    native = data["native"]
    product = native.products["Gateway"]
    export = data["repo"] / "corrupted-preparation"
    shutil.copytree(product["current"]["exports"]["preparation"], export)
    if fault == "current_DB":
        from tests.saas.test_oci_promotion import refresh_scan_time

        refresh_scan_time(export / "scans", native.old)
    else:
        path = export / "scans/grype/server-amd64-grype.json"
        raw = json.loads(path.read_text())
        raw["matches"] = [
            {
                "vulnerability": {"id": "fixture-High", "severity": "High"},
                "artifact": {"name": "fixture-package", "version": "1"},
            }
        ]
        write(path, raw)
        summary_path = export / "scans/grype/candidate-scan-summary.json"
        summary = json.loads(summary_path.read_text())
        summary["images"][0]["report_sha256"] = reader.publisher.file_sha256(path)
        write(summary_path, summary)
    row = native.rows["current"]["Gateway"]
    coordinate = row["stage_artifacts"]["preparation"]
    path = data["repo"] / "corrupted-preparation.zip"
    native.archives[coordinate["artifact_id"]] = path
    archive(export, path)
    metadata = native.artifacts[coordinate["artifact_id"]]
    metadata.update(
        size_in_bytes=path.stat().st_size, digest="sha256:" + reader.publisher.file_sha256(path)
    )
    coordinate.update(zip_size=metadata["size_in_bytes"], zip_sha256=metadata["digest"][7:])


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "expired_original",
        "expired_old_wheel",
        "original_signature",
        "original_predicate",
        "same_id_pseudo_renewal",
        "current_DB",
        "current_High",
        "source",
        "digest",
        "wheel",
        "physical_drill",
        "independent_signature",
        "missing_anchor_Core",
        "missing_anchor_Gateway",
        "missing_anchor_Model",
    ],
)
def test_actual_three_service_dual_publication_reader_and_anchor(native_stack, fault):
    data = native_stack
    native = data["native"]
    if fault in {"current_DB", "current_High"}:
        corrupt_current_scan(data, fault)
    elif fault == "original_predicate":
        native.rows["old"]["Gateway"]["predicate_sha256"] = "0" * 64
    elif fault == "same_id_pseudo_renewal":
        data["stack"]["original_publication_ids"]["Gateway"] = "current-Gateway"
    elif fault == "source":
        data["body"]["publication_bindings"]["Gateway"]["source_revision"] = "0" * 40
    elif fault == "digest":
        data["body"]["workloads"]["fixture-gateway"]["to_registry_ref"] = data["facts"]["Core"][
            "images"
        ]["server"]
    elif fault == "wheel":
        data["body"]["publication_bindings"]["Model"]["wheel_sha256"] = data["facts"]["Core"][
            "wheel_sha256"
        ]
    elif fault == "physical_drill":
        data["body"]["pair_checks"]["old_pair_recovery"]["drill_id"] = "another-drill"
    elif fault == "independent_signature":
        data["bad_signature"] = True
    native.fault = fault
    envelope = persist(data)
    native.calls.clear()
    native.crypto_calls.clear()
    if fault:
        report = validate_release(
            data["repo"],
            image._policy(),
            envelope,
            now=base.NOW,
            expected_product_revision="a" * 40,
        )
        assert report["production_readiness"] == "blocked"
        assert any("legacy fallback" in item for item in report["blockers"])
        reasons = {
            "expired_original": "PR OCI artifact",
            "expired_old_wheel": "legacy artifact",
            "original_signature": "native-verified control/product statement",
            "original_predicate": "original signed predicate",
            "same_id_pseudo_renewal": "complete physical rollback",
            "current_DB": "older than 24 hours",
            "current_High": "High finding",
            "source": "complete physical rollback",
            "digest": "physical rollback omits",
            "wheel": "complete physical rollback",
            "physical_drill": "another pair, contract or drill",
            "independent_signature": "independently signed deployment",
        }
        expected = (
            "native publication artifact is missing"
            if fault.startswith("missing_anchor_")
            else reasons[fault]
        )
        assert any(expected in item for item in report["blockers"]), report
    else:
        report = validate_release(
            data["repo"],
            image._policy(),
            envelope,
            now=base.NOW,
            expected_product_revision="a" * 40,
        )
        assert report["production_readiness"] == "ready", report
        assert data["current_calls"] == ["Core", "Gateway", "Model"]
        assert data["anchor_calls"] == ["Core", "Gateway", "Model"]
        assert (
            len(native.crypto_calls) == 42
        )  # seven original native verifications per old/current run.
        for component in stack.COMPONENTS:
            old, current = native.rows["old"][component], native.rows["current"][component]
            assert old["producer"]["run_id"] != current["producer"]["run_id"]
            assert old["predicate_sha256"] != current["predicate_sha256"]
            assert renewal.candidate_identity(old) == renewal.candidate_identity(current)
            assert {c["artifact_id"] for c in old["stage_artifacts"].values()}.isdisjoint(
                {c["artifact_id"] for c in current["stage_artifacts"].values()}
            )
        assert all("--deny-self-hosted-runners" in command for command in native.crypto_calls)
    write(
        data["repo"] / "renewal-readback-coverage.json",
        {
            "fault": fault,
            "production_readiness": report["production_readiness"],
            "blockers": report["blockers"],
            "actual_current_reader_calls": data["current_calls"],
            "actual_original_anchor_calls": data["anchor_calls"],
            "actual_gh_verify_process_calls": len(native.crypto_calls),
            "publication_coordinates": {
                generation: {
                    component: {
                        "producer": row["producer"],
                        "stage_artifacts": row["stage_artifacts"],
                        "original_pr_oci": row["admission"]["original_pr_oci"],
                        "fresh_control_wheel": row["admission"]["fresh_control_wheel"],
                        "predicate_sha256": row["predicate_sha256"],
                    }
                    for component, row in rows.items()
                }
                for generation, rows in native.rows.items()
            },
            "original_scan_age_days": 35,
            "external_fixture_boundaries": [
                "authenticated API responses",
                "gh log/ZIP transport",
                "gh attestation verify JSON",
                "crane pull",
            ],
            "schema_policy_signature_claim_parsers_or_readers_replaced": False,
            "fixture_owned_Git_objects_and_source_profiles": True,
            "GHA_producer_environment_forged": False,
            (
                "real_native_crypto_or_physical_protocol_DB_no_loss_or_production_qualification"
            ): False,
        },
    )
