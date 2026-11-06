"""Registered native origins, exact subjects and complete scope are mandatory."""

import base64
import hashlib
import json
import shutil
from dataclasses import asdict
from datetime import UTC, datetime

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


def admitted_graph(tmp_path, monkeypatch, *, subject=None, installed_files=None):
    from saas.production.admission import admission_signature_payload
    from saas.scripts.runtime_evidence_intake import ADMISSION_POLICY
    from tests.saas import test_evidence_admission as signed

    materials, product, evidence = (
        tmp_path / name for name in ("materials", "product", "admitted")
    )
    subject, *_ = registered(materials, subject=subject, installed_files=installed_files)
    product.mkdir()
    policy, private_key = signed._fixture(product)
    policy_path = product / ADMISSION_POLICY
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text(json.dumps(policy))
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


def test_production_oci_and_receipt_revalidation_consume_authenticated_graph(
    tmp_path, monkeypatch
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
    )
    # Policy and keys stay pinned to product; only signed data is selectable.
    from saas.scripts import runtime_evidence_intake as intake

    original = intake.authenticated_image_documents
    monkeypatch.setattr(
        intake, "authenticated_image_documents", lambda repo, **kwargs: original(product, **kwargs)
    )
    proof = combined.inspect_combined_disposition(
        image, report_path, platform=subject.platform, now=now, scanner_exit=2
    )
    assert proof["raw_high"] == 2
    assert proof["report_sha256"] == subject.report_sha256
    assert sqlite.validate_disposition(report_path, proof, image=image, now=now) == proof
    graph["registry"]["pending_inputs"] = {"changed": True}
    (evidence / "evidence/image.json").write_text(json.dumps({"runtime_conditions": graph}))
    sign(evidence)
    with pytest.raises(ValueError, match="differs from unchanged raw"):
        sqlite.validate_disposition(report_path, proof, image=image, now=now)
