"""Verify immutable overlay bytes and signing boundaries before any registry write."""

from __future__ import annotations

import base64
import copy
import csv
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
import yaml

from saas.scripts import d0_legacy_pair_release as release
from tests.saas.test_d0_legacy_overlay import installed_base as installed_base

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "fault", [None, "extra", "link", "mode", "record", "identity", "base", "command"]
)
def test_exact_overlay_preserves_base_and_refuses_payload_drift(
    tmp_path, monkeypatch, installed_base, fault
):
    output = tmp_path / "overlay"
    installed_base.run(output)
    payload = {
        release.SITE
        + path.relative_to(output / "lib/python3.12/site-packages").as_posix(): path.read_bytes()
        for path in (output / "lib/python3.12/site-packages").rglob("*")
        if path.is_file()
    }
    materials = {
        "files": {
            name: {"patched_sha256": hashlib.sha256(content).hexdigest()}
            for name, content in installed_base.payload.items()
            if name != release.recipe.BUILD_INFO
        }
    }
    if fault == "extra":
        payload[release.SITE + "foreign.py"] = b"unexpected"
    if fault == "record":
        payload[release.SITE + release.recipe.RECORD] = b"wrong,sha256=bad,5\n"
    if fault == "identity":
        name = release.SITE + release.recipe.BUILD_INFO
        payload[name] = payload[name].replace(b'"2222', b'"3333')
        record = io.StringIO(newline="")
        rows = list(
            csv.reader(io.StringIO(payload[release.SITE + release.recipe.RECORD].decode()))
        )
        for row in rows:
            if row[0] == release.recipe.BUILD_INFO:
                row[1] = "sha256=" + base64.urlsafe_b64encode(
                    hashlib.sha256(payload[name]).digest()
                ).decode().rstrip("=")
        csv.writer(record, lineterminator="\n").writerows(rows)
        payload[release.SITE + release.recipe.RECORD] = record.getvalue().encode()
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as bundle:
        for ordinal, (name, content) in enumerate(payload.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mtime, entry.mode = len(content), 1234, 0o644
            if ordinal == 0 and fault == "mode":
                entry.mode = 0o666
            if ordinal == 0 and fault == "link":
                entry.type, entry.linkname = tarfile.SYMTYPE, "/outside"
            bundle.addfile(entry, io.BytesIO(content))
    raw_layer = layer.getvalue()
    compressed = gzip.compress(raw_layer, mtime=0)
    parent = {"layers": []}
    parent_config = {"rootfs": {"diff_ids": []}, "config": {"Cmd": ["original"], "Labels": {}}}
    monkeypatch.setattr(release, "base_config", lambda *args: (parent, parent_config))
    config = copy.deepcopy(parent_config)
    config["rootfs"]["diff_ids"] = ["sha256:" + hashlib.sha256(raw_layer).hexdigest()]
    if fault == "command":
        config["config"]["Cmd"] = ["foreign"]
    blobs = {}

    def blob(content):
        digest = hashlib.sha256(content).hexdigest()
        blobs[digest] = content
        return "sha256:" + digest

    manifest = {
        "config": {"digest": blob(json.dumps(config).encode())},
        "layers": [
            {
                "digest": blob(compressed),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }
        ],
    }
    if fault == "base":
        parent["layers"].append({"digest": "sha256:" + "f" * 64})
    facts = {
        "platforms": {
            "linux/amd64": {
                "manifest_digest": blob(json.dumps(manifest).encode()),
                "config_digest": manifest["config"]["digest"],
            }
        }
    }
    archive = tmp_path / "candidate.tar"
    with tarfile.open(archive, "w") as bundle:
        for digest, content in blobs.items():
            entry = tarfile.TarInfo("blobs/sha256/" + digest)
            entry.size = len(content)
            bundle.addfile(entry, io.BytesIO(content))
    if fault is None:
        release.verify_overlay(archive, facts, materials, tmp_path, "server", "2" * 40, 1234)
    else:
        with pytest.raises(ValueError):
            release.verify_overlay(archive, facts, materials, tmp_path, "server", "2" * 40, 1234)


def test_base_registry_json_must_match_the_signed_digest(tmp_path):
    path = tmp_path / "base.json"
    raw = b'{"manifests": []}'
    path.write_bytes(raw + b"\n")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    assert release.bound_json(path, digest) == {"manifests": []}
    path.write_bytes(raw.replace(b"[]", b"[{}]"))
    with pytest.raises(ValueError, match="signed digest"):
        release.bound_json(path, digest)


def test_provenance_binds_pair_and_fixed_payload_without_deployment_authority():
    materials = release.recipe.load_manifest(ROOT)
    manifest = {
        "product_revision": "a" * 40,
        "source_date_epoch": 1234,
        "materials": materials,
        "images": {"server": {"index_digest": "sha256:" + "b" * 64}},
    }
    value = release.predicate(manifest, "server", "17", "1")
    external = value["buildDefinition"]["externalParameters"]
    assert external["production_authority"] is external["runtime_semantics_qualification"] is False
    assert external["physical_restore_qualification"] is False
    assert len(value["buildDefinition"]["resolvedDependencies"]) == 15
    manifest["images"]["server"]["index_digest"] = "sha256:" + "c" * 64
    changed = release.predicate(manifest, "server", "17", "1")
    assert (
        external["pair_manifest_sha256"]
        != changed["buildDefinition"]["externalParameters"]["pair_manifest_sha256"]
    )


def test_pr_can_only_build_unsigned_and_protected_main_signs_without_rebuild():
    workflow = yaml.safe_load((ROOT / release.WORKFLOW).read_text())
    jobs = workflow["jobs"]
    assert set(jobs["verify-pair"]["permissions"].values()) == {"read"}
    builds = [
        step
        for step in jobs["verify-pair"]["steps"]
        if step.get("uses", "").startswith("docker/build-push-action@")
    ]
    assert len(builds) == 4
    for step in builds:
        assert step["with"]["platforms"] == "linux/amd64,linux/arm64"
        assert step["with"]["no-cache"] is step["with"]["pull"] is True
        assert step["with"]["push"] is False
        assert "rewrite-timestamp" not in step["with"]["outputs"]
    assert jobs["publish-pair"]["environment"] == "production-image"
    assert "inputs.product_revision == github.sha" in jobs["publish-pair"]["if"]
    assert "refs/heads/main" in jobs["publish-pair"]["if"]
    assert not any(
        step.get("uses", "").startswith("docker/build-push-action@")
        for step in jobs["publish-pair"]["steps"]
    )
    assert set(jobs["independent-readback"]["permissions"].values()) == {"read"}


@pytest.mark.parametrize("fault", [None, "certificate", "run", "source", "subject"])
def test_native_material_signature_requires_exact_source_run_and_subject(fault):
    revision, subject, workflow = "a" * 40, "sha256:" + "b" * 64, release.WORKFLOW
    claims = release.signatures.certificate_claims(revision, workflow, "17", "1")
    signed = {
        "buildDefinition": {
            "resolvedDependencies": [
                {
                    "uri": "git+https://github.com/" + release.REPOSITORY + "@refs/heads/main",
                    "digest": {"gitCommit": revision},
                }
            ]
        },
        "runDetails": {
            "builder": {"id": claims["subjectAlternativeName"]},
            "metadata": {"invocationId": claims["runInvocationURI"]},
        },
    }
    entry = {
        "verificationResult": {
            "signature": {"certificate": dict(claims)},
            "statement": {
                "subject": [{"digest": {"sha256": subject[7:]}}],
                "predicateType": release.signatures.PREDICATE_TYPE,
                "predicate": signed,
            },
        }
    }
    if fault == "certificate":
        entry["verificationResult"]["signature"]["certificate"]["buildSignerDigest"] = "c" * 40
    elif fault == "run":
        signed["runDetails"]["metadata"]["invocationId"] += "0"
    elif fault == "source":
        signed["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = "c" * 40
    elif fault == "subject":
        entry["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "c" * 64
    arguments = {
        "subject": subject,
        "revision": revision,
        "workflow": workflow,
        "run_id": "17",
        "attempt": "1",
    }
    if fault is None:
        release.verify_binding([entry], **arguments)
    else:
        with pytest.raises(ValueError, match="exact source/workflow/run/subject"):
            release.verify_binding([entry], **arguments)


@pytest.mark.parametrize("fault", [None, "missing-host", "host-high", "host-filter"])
def test_complete_pair_scan_cannot_drop_or_filter_host_findings(tmp_path, fault):
    from tests.saas.test_oci_promotion import candidate

    labels, _ = candidate(tmp_path)
    comparison = release.read(tmp_path / "saas-image-candidate.json")
    components = {
        role: {
            "facts": comparison["images"]["omnigent-saas-" + role]["first"],
            "labels": labels,
            "archive_sha256": release.scans.file_sha256(tmp_path / (role + "-1.tar")),
        }
        for role in release.ROLES
    }
    scans = tmp_path / "grype"
    summary = release.read(scans / "candidate-scan-summary.json")
    report = release.read(scans / "host-arm64-grype.json")
    if fault == "missing-host":
        summary["images"] = [row for row in summary["images"] if row["image"] != "host"]
    elif fault == "host-high":
        report["matches"] = [
            {
                "vulnerability": {"severity": "High", "id": "test-cve"},
                "artifact": {"name": "fixture", "version": "1"},
            }
        ]
    elif fault == "host-filter":
        report["descriptor"]["configuration"]["only-fixed"] = True
    if fault is not None:
        (scans / "candidate-scan-summary.json").write_text(json.dumps(summary))
        (scans / "host-arm64-grype.json").write_text(json.dumps(report))
        with pytest.raises(ValueError):
            release.shared.validate_component_scans(
                scans, components, summary_name="candidate-scan-summary.json"
            )
    else:
        result = release.shared.validate_component_scans(
            scans, components, summary_name="candidate-scan-summary.json"
        )
        assert len(result["reports"]) == 4
