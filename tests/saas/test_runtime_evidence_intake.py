"""Registered native origins, exact subjects and complete scope are mandatory."""

import base64
import copy
import hashlib
import json
import shutil
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saas.scripts.combined_runtime_disposition import RuntimeSubject
from saas.scripts.runtime_evidence_intake import (
    REGISTRY,
    authenticated_runtime_graph,
    prepare_runtime_graph,
    verifier_from_registered_inputs,
)

NOW = datetime(2026, 11, 6, tzinfo=UTC)
EXPIRY = "2026-11-11T10:40:00Z"


def prepared_verifier(repo, inventory):
    return verifier_from_registered_inputs(
        prepare_runtime_graph(repo, product_revision="a" * 40), inventory
    )


def registered(tmp_path, *, subject=None, installed_files=None):
    root = tmp_path / "saas/supply_chain/runtime-conditions"
    root.mkdir(parents=True)
    subject = subject or RuntimeSubject(
        "a" * 40, "linux/amd64", "sha256:" + "b" * 64, "sha256:" + "c" * 64, "d" * 64, "e" * 64
    )
    identity = asdict(subject)
    identity.pop("report_sha256")
    producer = {"kind": "existing-native-operator", "operation": "fixed-original-task"}
    roles = [{"role": "helper", "command": ["original"], "profile": "original-private-PID"}]

    def write(name, document):
        path = root / name
        raw = (json.dumps(document, sort_keys=True) + "\n").encode()
        path.write_bytes(raw)
        return {"path": str(path.relative_to(tmp_path)), "sha256": hashlib.sha256(raw).hexdigest()}

    evidence = {
        "producer": producer,
        "original_report_sha256": subject.report_sha256,
        "subject": identity,
        "roles": roles,
        "expires_at": EXPIRY,
    }
    native = write("native.json", evidence)
    contract = {
        "subject": identity,
        "scope": "full-release-image",
        "uncovered_boundaries": [],
        "native_evidence": native,
        "roles": roles,
        "installed_files": installed_files or {"trusted.py": "f" * 64},
        "last_merge_contract": {"point": "reviewed actual final merge"},
        "expires_at": EXPIRY,
    }
    contract_file = write("contract.json", contract)
    review = {
        "reviewed_contract_sha256": contract_file["sha256"],
        "native_evidence_sha256": native["sha256"],
        "unresolved_findings": [],
        "verified_native_producer": dict(producer),
        "verified_last_merge_contract": contract["last_merge_contract"],
        "expires_at": EXPIRY,
    }
    review_file = write("review.json", review)
    authority = {
        "rule_id": "CVE-2026-84243",
        "classification": "mitigated_by_verified_runtime_conditions",
        "expires_at": EXPIRY,
    }
    authority_file = write("authority.json", authority)
    coordinate = {
        "contract": contract_file,
        "independent_review": review_file,
        "authority": authority_file,
    }
    registry = {"schema_version": 1, "approved_scopes": [coordinate]}
    (tmp_path / REGISTRY).write_text(json.dumps(registry))
    return subject, registry, contract, evidence, review, authority, write


def test_registered_content_and_independent_origin_are_bound_without_new_signer(tmp_path):
    subject, *_ = registered(tmp_path)
    condition = prepared_verifier(tmp_path, [{"path": "trusted.py", "sha256": "f" * 64}])(
        subject, now=NOW
    )
    assert condition.subject == subject
    assert condition.expires_at == datetime.fromisoformat(EXPIRY.replace("Z", "+00:00"))


@pytest.mark.parametrize(
    "fault", ["subject", "bytes", "scope", "producer", "raw", "review", "code", "expiry"]
)
def test_unknown_subject_or_unverified_input_and_incomplete_scope_reject(tmp_path, fault):
    subject, registry, contract, evidence, review, authority, write = registered(tmp_path)
    coordinate = registry["approved_scopes"][0]
    if fault == "bytes":
        (tmp_path / coordinate["contract"]["path"]).write_text("{}")
    elif fault in {"subject", "scope"}:
        if fault == "subject":
            contract["subject"]["source_revision"] = "0" * 40
        else:
            contract["uncovered_boundaries"] = ["terminal"]
        coordinate["contract"] = write("contract.json", contract)
    elif fault in {"producer", "raw"}:
        if fault == "producer":
            evidence["producer"]["operation"] = "unregistered"
        else:
            evidence["original_report_sha256"] = "0" * 64
        contract["native_evidence"] = write("native.json", evidence)
        coordinate["contract"] = write("contract.json", contract)
        review["reviewed_contract_sha256"] = coordinate["contract"]["sha256"]
        review["native_evidence_sha256"] = contract["native_evidence"]["sha256"]
        coordinate["independent_review"] = write("review.json", review)
    elif fault == "review":
        review["unresolved_findings"] = ["unproven trusted path"]
        coordinate["independent_review"] = write("review.json", review)
    elif fault == "expiry":
        authority["expires_at"] = NOW.isoformat()
        coordinate["authority"] = write("authority.json", authority)
    (tmp_path / REGISTRY).write_text(json.dumps(registry))
    inventory = [{"path": "trusted.py", "sha256": "0" * 64 if fault == "code" else "f" * 64}]
    with pytest.raises(ValueError):
        prepared_verifier(tmp_path, inventory)(subject, now=NOW)


def test_component_only_does_not_approve_an_image_and_duplicate_subjects_reject(tmp_path):
    subject, registry, *_ = registered(tmp_path)
    registry["approved_scopes"] = []
    (tmp_path / REGISTRY).write_text(json.dumps(registry))
    with pytest.raises(ValueError, match="full-role contract"):
        prepared_verifier(tmp_path, [])(subject, now=NOW)


@pytest.mark.parametrize("fault", ["leaf", "material-root", "ancestor", "registry"])
def test_registered_materials_and_their_anchor_reject_symbolic_links(tmp_path, fault):
    subject, registry, *_ = registered(tmp_path)
    if fault == "leaf":
        original = tmp_path / registry["approved_scopes"][0]["contract"]["path"]
    elif fault == "material-root":
        original = tmp_path / "saas/supply_chain/runtime-conditions"
    elif fault == "ancestor":
        original = tmp_path / "saas/supply_chain"
    else:
        original = tmp_path / REGISTRY
    destination = tmp_path.parent / (tmp_path.name + "-original")
    original.rename(destination)
    original.symlink_to(destination, target_is_directory=destination.is_dir())
    with pytest.raises(ValueError, match="symbolic link"):
        prepared_verifier(tmp_path, [{"path": "trusted.py", "sha256": "f" * 64}])(subject, now=NOW)


def admitted_graph(tmp_path, monkeypatch, *, subject=None, installed_files=None, bridge=False):
    from saas.production.admission import admission_signature_payload
    from saas.scripts.runtime_evidence_intake import ADMISSION_POLICY
    from tests.saas import test_evidence_admission as signed

    materials, product, evidence = (
        tmp_path / name for name in ("materials", "product", "admitted")
    )
    subject, registry, contract, _, review, authority, write = registered(
        materials, subject=subject, installed_files=installed_files
    )
    from saas.scripts.runtime_evidence_intake import native_evidence_from_operator

    observed = (
        replace(
            subject,
            source_revision="1" * 40,
            manifest_digest="sha256:" + "2" * 64,
            config_digest="sha256:" + "3" * 64,
            report_sha256="4" * 64,
        )
        if bridge
        else subject
    )
    original = write("operator-original.json", operator_record(observed))
    origin_review = write("operator-review.json", {"review": "fixture original custody accepted"})
    native = native_evidence_from_operator(
        operator_record(observed), original=original, review=origin_review
    )
    contract["native_evidence"] = write("native.json", native)
    contract["roles"] = native["roles"]
    if bridge:
        contract["subject"] = native["subject"]
        contract["component_bridge"] = {
            "kind": "same-platform-installed-component-and-entry/v1",
            "target": {
                "source_revision": subject.source_revision,
                "platform": subject.platform,
                "libc_sha256": subject.libc_sha256,
            },
            "native_subject": native["subject"],
            "native_report_sha256": native["original_report_sha256"],
            "native_roles": native["roles"],
            "approved_roles": contract["roles"],
            "current_scan": "fresh-unfiltered-exact-two-findings-same-OCI",
        }
        review["verified_component_bridge"] = copy.deepcopy(contract["component_bridge"])
        authority["approved_component_bridge"] = copy.deepcopy(contract["component_bridge"])
    coordinate = registry["approved_scopes"][0]
    coordinate["contract"] = write("contract.json", contract)
    review.update(
        reviewed_contract_sha256=coordinate["contract"]["sha256"],
        native_evidence_sha256=contract["native_evidence"]["sha256"],
        verified_native_producer=native["producer"],
    )
    coordinate["independent_review"] = write("review.json", review)
    coordinate["authority"] = write("authority.json", authority)
    (materials / REGISTRY).write_text(json.dumps(registry))
    product.mkdir()
    policy, private_key = signed._fixture(product)
    policy_path = product / ADMISSION_POLICY
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text(json.dumps(policy))
    catalog = product / REGISTRY
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "approved_scopes": [],
                "approved_native_observations": [
                    {
                        "operation": native["producer"]["operation"],
                        "native_record_sha256": original["sha256"],
                        "independent_review_sha256": origin_review["sha256"],
                        "installed_files": contract["installed_files"],
                    }
                ],
            }
        )
    )
    graph = prepare_runtime_graph(materials, product_revision=subject.source_revision)
    (product / "evidence/image.json").write_text(json.dumps({"runtime_conditions": graph}))

    def sign(root):
        receipt_path = root / "admission/receipts/image.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["evidence_sha256"] = hashlib.sha256(
            (root / "evidence/image.json").read_bytes()
        ).hexdigest()
        receipt["signature"] = base64.b64encode(
            private_key.sign(admission_signature_payload(receipt))
        ).decode()
        receipt_path.write_text(json.dumps(receipt))

    sign(product)
    shutil.copytree(product, evidence)
    (product / "evidence/image.json").unlink()
    monkeypatch.setenv("OMNIGENT_RUNTIME_EVIDENCE_REPO", str(evidence))
    return product, evidence, graph, sign, signed._NOW, subject


def operator_record(subject):
    clean = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LC_MESSAGES": "C.UTF-8",
        "LANGUAGE": None,
        "LOCPATH": None,
    }
    process = {
        "pid": 17,
        "start_ticks": "12345",
        "five_locale_inputs": {
            key: [] if value is None else [value] for key, value in clean.items()
        },
    }
    child = {
        "effective_LC_MESSAGES": "C.UTF-8",
        "effective_encoding": "UTF-8",
        "five_locale_inputs": clean,
    }
    return {
        "operation": "fixed-original-task",
        "source": subject.source_revision,
        "qualification_exit": 0,
        "product_modules_modified": False,
        "owned_task_container_absent": True,
        "owned_network_namespace_absent": True,
        "cleanup_errors": [],
        "DB_credentials_shared_PVC_external_network": False,
        "network": {"interfaces": ["lo"], "non_loopback_routes": 0},
        "actual_task": {"id": "fixed-original-task"},
        "actual_runtime_contract": dict.fromkeys(
            ("nonroot", "no_new_privileges", "all_capabilities_empty", "rootfs_readonly"), True
        ),
        "actual_image": {
            "all_selected_CAS_verified": True,
            "resolved_manifest_digest": subject.manifest_digest,
            "resolved_config_digest": subject.config_digest,
        },
        "native_facts": {
            "mocked_exec": False,
            "production_source_modified": False,
            "source": subject.source_revision,
            "requested_roles": ["helper", "terminal"],
            "subject": {
                "platform": subject.platform,
                "loaded_libc": {"sha256": subject.libc_sha256},
                "expected_original_subject": {
                    "manifest_digest": subject.manifest_digest,
                    "config_digest": subject.config_digest,
                    "libc_sha256": subject.libc_sha256,
                    "original_report_sha256": subject.report_sha256,
                },
            },
            "helper": {
                "trusted_launcher_process": copy.deepcopy(process),
                "actual_child": copy.deepcopy(child),
            },
            "terminal": {
                "trusted_tmux_server_process": copy.deepcopy(process),
                "pane_process": copy.deepcopy(process),
                "actual_child": copy.deepcopy(child),
            },
        },
    }


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "signature",
        "missing-receipt",
        "changed-graph",
        "rehash-only",
        "source",
        "policy",
        "keys",
        "graph-source",
        "unsigned-registry",
        "expired",
        "unregistered-native",
        "changed-native-original",
        "native-boundary",
    ],
)
def test_full_graph_requires_real_existing_ed25519_admission_from_pinned_product_trust(
    tmp_path, monkeypatch, fault
):
    product, evidence, graph, sign, now, subject = admitted_graph(tmp_path, monkeypatch)
    receipt_path = evidence / "admission/receipts/image.json"
    image_path = evidence / "evidence/image.json"
    receipt = json.loads(receipt_path.read_text())
    if fault == "signature":
        receipt["signature"] = base64.b64encode(b"false-signature").decode()
        receipt_path.write_text(json.dumps(receipt))
    elif fault == "missing-receipt":
        receipt_path.unlink()
    elif fault in {"changed-graph", "rehash-only", "graph-source"}:
        graph["product_revision"] = "0" * 40
        image_path.write_text(json.dumps({"runtime_conditions": graph}))
        if fault == "rehash-only":
            receipt["evidence_sha256"] = hashlib.sha256(image_path.read_bytes()).hexdigest()
            receipt_path.write_text(json.dumps(receipt))
        elif fault == "graph-source":
            sign(evidence)
    elif fault in {"policy", "keys"}:
        path = evidence / (
            "saas/production/evidence-admission-policy.json"
            if fault == "policy"
            else "admission/keys.json"
        )
        path.write_text(path.read_text() + " ")
    elif fault == "unsigned-registry":
        image_path.write_text("{}")
        sign(evidence)
        (product / REGISTRY).parent.mkdir(parents=True, exist_ok=True)
        (product / REGISTRY).write_text(json.dumps(graph["registry"]))
    elif fault in {"unregistered-native", "native-boundary"}:
        catalog = json.loads((product / REGISTRY).read_text())
        if fault == "unregistered-native":
            catalog["approved_native_observations"] = []
        else:
            catalog["approved_native_observations"][0]["installed_files"] = {
                "missing.py": "0" * 64
            }
        (product / REGISTRY).write_text(json.dumps(catalog))
    elif fault == "changed-native-original":
        path = "saas/supply_chain/runtime-conditions/operator-original.json"
        graph["documents"][path] += " "
        image_path.write_text(json.dumps({"runtime_conditions": graph}))
        sign(evidence)
    revision = "0" * 40 if fault == "source" else subject.source_revision
    if fault == "expired":
        from datetime import timedelta

        now += timedelta(days=2)
    if fault is None:
        authenticated = authenticated_runtime_graph(product, product_revision=revision, now=now)
        condition = verifier_from_registered_inputs(
            authenticated, [{"path": "trusted.py", "sha256": "f" * 64}]
        )(subject, now=now)
        assert condition.subject == subject
        assert (
            condition.runtime_graph_sha256
            == hashlib.sha256(
                json.dumps(graph, sort_keys=True, allow_nan=False).encode()
            ).hexdigest()
        )
    else:
        with pytest.raises(ValueError):
            authenticated_runtime_graph(product, product_revision=revision, now=now)


@pytest.mark.parametrize("bridge", [False, True])
def test_production_oci_and_receipt_revalidation_consume_authenticated_graph(
    tmp_path, monkeypatch, bridge
):
    from saas.scripts import combined_runtime_disposition as combined
    from saas.scripts import sqlite_component_disposition as sqlite
    from tests.saas import test_evidence_admission as signed
    from tests.saas.test_combined_runtime_disposition import LIBC, combination

    image, report_path, _, approved = combination(tmp_path, monkeypatch, database_time=signed._NOW)
    product, evidence, graph, sign, now, subject = admitted_graph(
        tmp_path,
        monkeypatch,
        subject=approved.subject,
        installed_files={"usr/lib/libc.so.6": hashlib.sha256(LIBC).hexdigest()},
        bridge=bridge,
    )
    # Policy and keys stay pinned to product; only signed data is selectable.
    from saas.scripts import runtime_evidence_intake as intake

    original = intake.authenticated_runtime_graph
    monkeypatch.setattr(
        intake,
        "authenticated_runtime_graph",
        lambda repo, **kwargs: original(product, **kwargs),
    )
    proof = combined.inspect_combined_disposition(
        image, report_path, platform=subject.platform, now=now, scanner_exit=2
    )
    assert proof["raw_high"] == 2
    assert proof["report_sha256"] == subject.report_sha256
    assert sqlite.validate_disposition(report_path, proof, image=image, now=now) == proof
    if bridge:
        original_raw = report_path.read_bytes()
        changed = json.loads(original_raw)
        changed["matches"].append(copy.deepcopy(changed["matches"][0]))
        report_path.write_text(json.dumps(changed))
        with pytest.raises(ValueError, match="exactly the two original High"):
            combined.inspect_combined_disposition(
                image, report_path, platform=subject.platform, now=now, scanner_exit=2
            )
        report_path.write_bytes(original_raw)
    graph["registry"]["pending_inputs"] = {"changed": True}
    (evidence / "evidence/image.json").write_text(json.dumps({"runtime_conditions": graph}))
    sign(evidence)
    with pytest.raises(ValueError, match="differs from unchanged raw"):
        sqlite.validate_disposition(report_path, proof, image=image, now=now)


@pytest.mark.parametrize("fault", [None, "source", "policy", "keys", "symlink", "dirty"])
def test_existing_product_code_fetches_only_clean_immutable_evidence_data(tmp_path, fault):
    from saas.scripts.runtime_evidence_intake import (
        ADMISSION_POLICY,
        prepare_evidence_context,
        validate_evidence_context,
    )
    from tests.saas import test_evidence_admission as signed
    from tests.saas.test_production_readiness import _git

    product, data = tmp_path / "product", tmp_path / "data"
    product.mkdir()
    policy, private_key = signed._fixture(product)
    p = product / ADMISSION_POLICY
    p.parent.mkdir(parents=True)
    image_relative = "saas/acceptance/p0-production-image-evidence.json"
    image = product / image_relative
    image.parent.mkdir(parents=True)
    image.write_text("{}")
    next(source for source in policy["evidence_sources"] if source["kind"] == "image")["path"] = (
        image_relative
    )
    p.write_text(json.dumps(policy))
    _git(product, "init")
    _git(product, "config", "user.email", "test@example.invalid")
    _git(product, "config", "user.name", "Test")
    _git(product, "add", ".")
    _git(product, "commit", "-m", "product")
    revision = _git(product, "rev-parse", "HEAD")
    image.write_text(json.dumps({"product_revision": revision, "independent_data": True}))
    if fault in {"source", "policy", "keys"}:
        path = (
            product
            / {"source": "runtime.py", "policy": ADMISSION_POLICY, "keys": "admission/keys.json"}[
                fault
            ]
        )
        path.write_text(
            path.read_text() + " " if path.exists() else "raise RuntimeError('never execute data')"
        )
    elif fault == "symlink":
        image.unlink()
        image.symlink_to(tmp_path / "outside")
    _git(product, "add", ".")
    _git(product, "commit", "-m", "evidence data")
    evidence_revision = _git(product, "rev-parse", "HEAD")
    _git(product, "checkout", "--detach", revision)
    _git(product, "remote", "add", "origin", str(product))
    if fault not in {None, "dirty"}:
        with pytest.raises(ValueError):
            prepare_evidence_context(
                product,
                product_revision=revision,
                evidence_revision=evidence_revision,
                destination=data,
            )
    else:
        assert (
            prepare_evidence_context(
                product,
                product_revision=revision,
                evidence_revision=evidence_revision,
                destination=data,
            )
            == data
        )
        assert _git(product, "rev-parse", "HEAD") == revision
        assert _git(data, "rev-parse", "HEAD") == evidence_revision
        assert (product / image_relative).read_text() == "{}"
        assert json.loads((data / image_relative).read_text())["product_revision"] == revision
        if fault is None:
            from saas.scripts.issue_evidence_receipt import process_evidence_receipt_request

            request = {
                "action": "prepare",
                "evidence_kind": "image",
                "evidence_path": image_relative,
                "signer_key_id": "production-admission-2026-01",
                "receipt_id": "runtime-image",
                "issued_at": "2026-08-09T11:00:00Z",
                "expires_at": "2026-08-10T11:00:00Z",
                "signature_base64": None,
            }

            def issue():
                return process_evidence_receipt_request(
                    product,
                    json.dumps(request),
                    product_revision=revision,
                    evidence_repo=data,
                    now=signed._NOW,
                    workflow_identity="spiffe://omnigent/production-evidence-admission",
                )

            report, result = issue()
            assert report["status"] == "pass" and result is not None
            preparation = result["preparation"]
            assert (
                preparation["receipt"]["evidence_sha256"]
                == hashlib.sha256((data / image_relative).read_bytes()).hexdigest()
            )
            request.update(
                action="finalize",
                signature_base64=base64.b64encode(
                    private_key.sign(base64.b64decode(preparation["signature_payload_base64"]))
                ).decode(),
            )
            report, result = issue()
            assert report["status"] == "pass" and result["receipt"]["product_revision"] == revision
            assert (product / image_relative).read_text() == "{}"
        if fault == "dirty":
            (data / image_relative).write_text("{}")
            with pytest.raises(ValueError, match="dirty lineage"):
                validate_evidence_context(product, data, product_revision=revision)


@pytest.mark.parametrize(
    "fault", [None, "exit", "libc", "launcher", "child", "cleanup", "permissions"]
)
def test_native_producer_uses_actual_operator_values_and_fixed_expiry(tmp_path, fault):
    from saas.scripts.runtime_evidence_intake import native_evidence_from_operator

    subject, *_ = registered(tmp_path)
    record = operator_record(subject)
    if fault == "exit":
        record["qualification_exit"] = False
    elif fault == "libc":
        record["native_facts"]["subject"]["loaded_libc"]["sha256"] = "0" * 64
    elif fault == "launcher":
        record["native_facts"]["terminal"]["pane_process"]["five_locale_inputs"]["LOCPATH"] = [
            "/workspace"
        ]
    elif fault == "child":
        record["native_facts"]["helper"]["actual_child"]["effective_LC_MESSAGES"] = "fr_FR.UTF-8"
    elif fault == "cleanup":
        record["owned_task_container_absent"] = False
    elif fault == "permissions":
        record["actual_runtime_contract"]["no_new_privileges"] = False

    def produce():
        return native_evidence_from_operator(
            record,
            original={"path": "original", "sha256": "1" * 64},
            review={"path": "review", "sha256": "2" * 64},
        )

    if fault is None:
        native = produce()
        assert native["subject"]["source_revision"] == record["source"]
        assert native["original_report_sha256"] == subject.report_sha256
        assert native["expires_at"] == EXPIRY
        assert native["roles"] == ["helper", "terminal"]
    else:
        with pytest.raises(ValueError):
            produce()


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "exit",
        "cleanup",
        "emulation",
        "source",
        "platform",
        "libc",
        "pid",
        "namespace",
        "roles",
        "locale",
        "encoding",
        "mocked",
        "lifecycle",
        "High",
        "expiry",
        "network",
        "privileges",
        "writable",
        "caps",
        "NNP",
    ],
)
def test_startup_producer_preserves_real_ARM_component_scope_and_rejects_changed_facts(fault):
    from saas.scripts.runtime_evidence_intake import native_evidence_from_operator

    raw = (Path(__file__).parent / "resources/native-arm-startup-operator.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "c32ec8564c416e90f268d8d2e7c0e3f6d59f1c8509627dc1e0ca0376310fcd6a"
    )
    record = json.loads(raw)
    facts, controls = record["native_facts"], record["actual_runtime_contract"]
    if fault in {"exit", "cleanup", "emulation"}:
        record[
            {
                "exit": "qualification_exit",
                "cleanup": "owned_container_absent",
                "emulation": "QEMU_used",
            }[fault]
        ] = fault == "emulation"
    elif fault == "source":
        facts["source_revision"] = "a" * 40
    elif fault == "platform":
        record["subject"]["platform"] = "linux/amd64"
    elif fault == "libc":
        facts["actual_loaded_libc"]["sha256"] = "a" * 64
    elif fault == "pid":
        facts["pid"] = False
    elif fault == "namespace":
        facts["pid_namespace"] = "host"
    elif fault == "roles":
        facts["entries"] = []
    elif fault == "locale":
        facts["entries"][0]["five_locale_inputs"]["LOCPATH"] = "/workspace"
    elif fault == "encoding":
        facts["entries"][0]["effective_encoding"] = "ASCII"
    elif fault in {"mocked", "lifecycle", "High"}:
        facts[
            {
                "mocked": "mocked_exec",
                "lifecycle": "whole_service_lifecycle_qualified",
                "High": "High_disposition",
            }[fault]
        ] = True
    elif fault == "expiry":
        facts["expires_at"] = "2026-11-12T10:40:00Z"
    elif fault in {"network", "privileges", "writable", "caps", "NNP"}:
        controls[
            {
                "network": "NetworkMode",
                "privileges": "Privileged",
                "writable": "ReadonlyRootfs",
                "caps": "CapDrop",
                "NNP": "SecurityOpt",
            }[fault]
        ] = {"network": "bridge", "privileges": True, "writable": False, "caps": [], "NNP": []}[
            fault
        ]

    def produce():
        return native_evidence_from_operator(
            record,
            original={"path": "original", "sha256": hashlib.sha256(raw).hexdigest()},
            review={"path": "review", "sha256": "2" * 64},
        )

    if fault is not None:
        with pytest.raises(ValueError, match="native startup component"):
            produce()
    else:
        native = produce()
        assert native["subject"] == record["subject"]
        assert native["original_report_sha256"] == record["original_report_sha256"]
        assert native["producer"] == {"kind": "github-actions", "operation": record["operation"]}
        assert native["expires_at"] == EXPIRY
        assert native["roles"] == [entry["role"] for entry in facts["entries"]]
        assert "helper" not in native["roles"] and "terminal" not in native["roles"]


@pytest.mark.parametrize("changed_review", [False, True])
def test_real_ARM_origin_registration_does_not_approve_a_full_role_scope(changed_review):
    from saas.scripts.runtime_evidence_intake import (
        _registered_native_origin,
        native_evidence_from_operator,
    )

    root = Path(__file__).resolve().parents[2]
    raw = (Path(__file__).parent / "resources/native-arm-startup-operator.json").read_bytes()
    record = json.loads(raw)
    native = native_evidence_from_operator(
        record,
        original={"path": "original", "sha256": hashlib.sha256(raw).hexdigest()},
        review={
            "path": "review",
            "sha256": "0" * 64
            if changed_review
            else "718d857daa3a13d04f584423dc9daaa22c5a35897ec8810d04d63eb714552dbb",
        },
    )
    if changed_review:
        with pytest.raises(ValueError, match="not registered"):
            _registered_native_origin(root, native)
    else:
        registered = _registered_native_origin(root, native)
        assert registered["installed_files"] == record["native_facts"]["installed_files"]
        assert registered["classification_scope"] == (
            "installed-production-startup-locale-component-only"
        )
        assert json.loads((root / REGISTRY).read_text())["approved_scopes"] == []


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "review",
        "authority",
        "platform",
        "libc",
        "target",
        "scan",
        "empty-roles",
        "invalid-role",
    ],
)
def test_old_native_subject_requires_an_explicit_independently_approved_component_bridge(
    tmp_path, fault
):
    from saas.scripts.runtime_evidence_intake import COMPONENT_BRIDGE

    subject, registry, contract, evidence, review, authority, write = registered(tmp_path)
    old_subject = {
        **contract["subject"],
        "source_revision": "1" * 40,
        "manifest_digest": "sha256:" + "2" * 64,
        "config_digest": "sha256:" + "3" * 64,
    }
    contract["subject"] = dict(old_subject)
    evidence["subject"] = dict(old_subject)
    evidence["original_report_sha256"] = "4" * 64
    native_roles = copy.deepcopy(evidence["roles"])
    contract["roles"] = [{"role": "reviewed-final-role-and-entry-contract"}]
    if fault == "empty-roles":
        contract["roles"] = []
    elif fault == "invalid-role":
        contract["roles"] = [""]
    bridge = {
        "kind": COMPONENT_BRIDGE,
        "target": {
            "source_revision": subject.source_revision,
            "platform": subject.platform,
            "libc_sha256": subject.libc_sha256,
        },
        "native_subject": dict(old_subject),
        "native_report_sha256": evidence["original_report_sha256"],
        "native_roles": native_roles,
        "approved_roles": contract["roles"],
        "current_scan": "fresh-unfiltered-exact-two-findings-same-OCI",
    }
    if fault == "platform":
        contract["subject"]["platform"] = "linux/arm64"
    elif fault == "libc":
        contract["subject"]["libc_sha256"] = "0" * 64
    elif fault == "target":
        bridge["target"]["source_revision"] = "0" * 40
    elif fault == "scan":
        bridge["current_scan"] = "ignore-the-current-raw"
    contract["component_bridge"] = bridge
    contract["native_evidence"] = write("native.json", evidence)
    coordinate = registry["approved_scopes"][0]
    coordinate["contract"] = write("contract.json", contract)
    review.update(
        reviewed_contract_sha256=coordinate["contract"]["sha256"],
        native_evidence_sha256=contract["native_evidence"]["sha256"],
    )
    if fault != "review":
        review["verified_component_bridge"] = copy.deepcopy(bridge)
    if fault != "authority":
        authority["approved_component_bridge"] = copy.deepcopy(bridge)
    coordinate["independent_review"] = write("review.json", review)
    coordinate["authority"] = write("authority.json", authority)
    (tmp_path / REGISTRY).write_text(json.dumps(registry))
    if fault is None:
        condition = prepared_verifier(tmp_path, [{"path": "trusted.py", "sha256": "f" * 64}])(
            subject, now=NOW
        )
        assert condition.subject == subject
        assert condition.subject.source_revision != evidence["subject"]["source_revision"]
        assert condition.subject.report_sha256 != evidence["original_report_sha256"]
    else:
        with pytest.raises(ValueError):
            prepared_verifier(tmp_path, [{"path": "trusted.py", "sha256": "f" * 64}])(
                subject, now=NOW
            )
