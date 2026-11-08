"""Actual OCI component absence and finite raw-finding classification boundaries."""

import copy
import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from saas.scripts import sqlite_component_disposition as component
from tests.saas.test_image_supply_chain import _write_oci

NOW = datetime(2026, 11, 4, 11, tzinfo=UTC)
LIBRARY = b"\x7fELFfixed-test-SQLite-library-without-shell"


def candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    extra: dict[str, bytes] | None = None,
    database_time: datetime = NOW,
    config_os: str | None = None,
):
    monkeypatch.setattr(component, "rule_enabled", lambda: True)
    library_hash = hashlib.sha256(LIBRARY).hexdigest()
    monkeypatch.setitem(
        component.RULE,
        "library_sha256",
        dict.fromkeys(("linux/amd64", "linux/arm64"), library_hash),
    )
    files = {"usr/lib/libsqlite3.so.3.54.1": LIBRARY, **(extra or {})}
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            member.mode = 0o755 if name.startswith("usr/bin/") else 0o644
            archive.addfile(member, io.BytesIO(body))
    image = tmp_path / "candidate.tar"
    _write_oci(
        image,
        revision="a" * 40,
        label_profile="executable",
        nested=True,
        layer_payload=layer.getvalue(),
        config_os=config_os,
    )
    layout = tmp_path / "candidate-layout"
    with tarfile.open(image, "w") as archive:
        for member in sorted(layout.rglob("*")):
            archive.add(member, arcname=member.relative_to(layout), recursive=False)
    with component.image_blobs(image) as blobs:
        digest, manifest = blobs.platform("linux/amd64")
        config = blobs.document(manifest["config"]["digest"])
    report: dict[str, Any] = {
        "descriptor": {
            "name": "grype",
            "version": "0.120.1",
            "configuration": {"only-fixed": False, "only-notfixed": False},
            "db": {
                "status": {
                    "built": database_time.isoformat(),
                    "valid": True,
                    "schemaVersion": "v6.1.10",
                }
            },
        },
        "source": {
            "target": {
                "manifestDigest": digest,
                "imageID": manifest["config"]["digest"],
                "os": "linux",
                "architecture": "amd64",
                "labels": config["config"]["Labels"],
            }
        },
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2026-119586",
                    "severity": "High",
                    "namespace": "nvd:cpe",
                },
                "artifact": {"type": "apk", "name": "sqlite-libs", "version": "3.54.1-r0"},
                "matchDetails": [{"matcher": "apk-matcher", "type": "cpe-match"}],
            }
        ],
    }
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(report) + "\n")
    return image, path, report


def test_exact_library_only_oci_keeps_original_high_and_binds_every_subject(tmp_path, monkeypatch):
    image, path, _ = candidate(tmp_path, monkeypatch)
    original = path.read_bytes()
    proof = component.inspect_disposition(image, path, platform="linux/amd64", now=NOW)
    assert proof["raw_high"] == 1 and proof["raw_critical"] == 0
    assert proof["report_sha256"] == hashlib.sha256(original).hexdigest()
    assert proof["source_revision"] == "a" * 40
    assert component.validate_disposition(path, proof, image=image, now=NOW) == proof
    assert path.read_bytes() == original
    assert "ignoredMatches" not in json.loads(original)
    layout = tmp_path / "candidate-layout"
    assert component.inspect_disposition(layout, path, platform="linux/amd64", now=NOW) == proof


@pytest.mark.parametrize(
    "fault",
    [
        "other-high",
        "critical",
        "duplicate",
        "version",
        "package-type",
        "matcher",
        "ignore",
        "wrong-digest",
        "wrong-architecture",
        "stale-db",
        "expired",
    ],
)
def test_unqualified_raw_reports_cannot_use_component_disposition(tmp_path, monkeypatch, fault):
    image, path, report = candidate(tmp_path, monkeypatch)
    match = report["matches"][0]
    now = NOW
    if fault in {"other-high", "critical", "duplicate"}:
        other = copy.deepcopy(match)
        if fault != "duplicate":
            other["vulnerability"]["id"] = "CVE-UNRELATED"
        if fault == "critical":
            other["vulnerability"]["severity"] = "Critical"
        report["matches"].append(other)
    elif fault == "version":
        match["artifact"]["version"] = "3.53.4-r2"
    elif fault == "package-type":
        match["artifact"]["type"] = "binary"
    elif fault == "matcher":
        match["matchDetails"][0]["matcher"] = "unknown"
    elif fault == "ignore":
        report["ignoredMatches"] = [match]
    elif fault == "wrong-digest":
        report["source"]["target"]["manifestDigest"] = "sha256:" + "f" * 64
    elif fault == "wrong-architecture":
        report["source"]["target"]["architecture"] = "arm64"
    elif fault == "stale-db":
        report["descriptor"]["db"]["status"]["built"] = (NOW - timedelta(hours=25)).isoformat()
    elif fault == "expired":
        now += timedelta(days=8)
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        component.inspect_disposition(image, path, platform="linux/amd64", now=now)


@pytest.mark.parametrize(
    "path,body",
    [
        ("usr/bin/sqlite3", b"shell"),
        ("usr/bin/renamed-tool", b"\x7fELFsqlite> .recover"),
        ("usr/lib/libsqlite-recover.so", b"\x7fELFsqlite3_recover_init"),
        ("usr/lib/libsqlite3.so.3.54.1", LIBRARY + b"tamper"),
    ],
)
def test_actual_shell_recovery_code_or_changed_library_blocks(tmp_path, monkeypatch, path, body):
    image, report_path, _ = candidate(tmp_path, monkeypatch, extra={path: body})
    with pytest.raises(ValueError):
        component.inspect_disposition(image, report_path, platform="linux/amd64", now=NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("rule_sha256", "f" * 64),
        ("manifest_digest", "sha256:" + "f" * 64),
        ("config_digest", "sha256:" + "f" * 64),
        ("report_sha256", "f" * 64),
        ("library_sha256", "f" * 64),
        ("expires_at", "2099-01-01T00:00:00Z"),
        ("raw_high", 0),
    ],
)
def test_disposition_receipt_tampering_is_rejected(tmp_path, monkeypatch, field, value):
    image, path, _ = candidate(tmp_path, monkeypatch)
    proof = component.inspect_disposition(image, path, platform="linux/amd64", now=NOW)
    proof[field] = value
    with pytest.raises(ValueError):
        component.validate_disposition(path, proof, image=image, now=NOW)


@pytest.mark.parametrize("consumer", ["promotion", "core"])
@pytest.mark.parametrize(
    "fault",
    [None, "missing-proof", "fake-zero", "extra-high", "subject-swap", "forged-cli-inventory"],
)
def test_existing_consumers_recompute_raw_counts_and_subject_bindings(
    tmp_path, monkeypatch, consumer, fault
):
    from saas.scripts import core_f440_compat_release as core
    from saas.scripts import oci_promotion as promotion
    from saas.scripts.scan_oci_candidates import file_sha256, scan_report

    class Clock:
        @staticmethod
        def now(_timezone):
            return NOW

    monkeypatch.setattr(core, "datetime", Clock)
    image, _, original = candidate(
        tmp_path,
        monkeypatch,
        extra={"usr/bin/sqlite3": b"#!/bin/sh\n.recover\n"}
        if fault == "forged-cli-inventory"
        else None,
    )
    scan_root = tmp_path / "grype"
    scan_root.mkdir()
    rows, images = [], {}
    for role in ("server", "host"):
        facts = {}
        for platform in ("linux/amd64", "linux/arm64"):
            with component.image_blobs(image) as blobs:
                digest, manifest = blobs.platform(platform)
                config = blobs.document(manifest["config"]["digest"])
            raw = copy.deepcopy(original)
            raw["source"]["target"].update(
                manifestDigest=digest,
                imageID=manifest["config"]["digest"],
                architecture=platform.split("/")[1],
            )
            path = scan_root / f"{role}-{platform.split('/')[1]}-grype.json"
            path.write_text(json.dumps(raw))
            if fault == "forged-cli-inventory":
                inventory = [
                    {
                        "path": "usr/lib/libsqlite3.so.3.54.1",
                        "type": "0",
                        "link": "",
                        "mode": 0o644,
                        "sha256": hashlib.sha256(LIBRARY).hexdigest(),
                        "shell": False,
                        "recover": False,
                    }
                ]
                proof = component.disposition_receipt(path, inventory, platform=platform, now=NOW)
            else:
                proof = component.inspect_disposition(image, path, platform=platform, now=NOW)
            if role == "server" and platform == "linux/amd64":
                if fault == "missing-proof":
                    proof = None
                elif fault == "extra-high":
                    other = copy.deepcopy(raw["matches"][0])
                    other["vulnerability"]["id"] = "CVE-UNRELATED"
                    raw["matches"].append(other)
                    path.write_text(json.dumps(raw))
                elif fault == "subject-swap":
                    raw["source"]["target"]["manifestDigest"] = "sha256:" + "f" * 64
                    path.write_text(json.dumps(raw))
                    proof = component.disposition_receipt(
                        path, proof["inventory"], platform=platform, now=NOW
                    )
            parsed = scan_report(raw)
            row = {
                "image": role,
                "platform": platform,
                "archive_sha256": file_sha256(image),
                "report_sha256": file_sha256(path),
                "critical": parsed["counts"]["Critical"],
                "high": parsed["counts"]["High"],
                "findings": parsed["findings"],
                "component_disposition": proof,
                "scanner_exit": 2,
            }
            if fault == "fake-zero" and role == "server" and platform == "linux/amd64":
                row["high"] = 0
            rows.append(row)
            facts[platform] = {
                "manifest_digest": digest,
                "config_digest": manifest["config"]["digest"],
                "labels": config["config"]["Labels"],
            }
        images[role] = {
            "facts": {"platforms": facts},
            "archive_sha256": file_sha256(image),
            "archive": image.name,
            "labels": original["source"]["target"]["labels"],
        }
    summary = {
        "scanner": "grype 0.120.1",
        "exceptions": [],
        "database_built_at": NOW.isoformat(),
        "images": rows,
    }
    (scan_root / "candidate-scan-summary.json").write_text(json.dumps(summary))

    def validate():
        if consumer == "promotion":
            return promotion.validate_scans(tmp_path, images, now=NOW)
        return core.validate_component_scans(
            scan_root,
            images,
            summary_name="candidate-scan-summary.json",
            archives=dict.fromkeys(images, image),
        )

    if fault is None:
        assert len(validate()["reports"]) == 4
        assert all(row["high"] == 1 for row in rows)
    else:
        with pytest.raises(ValueError, match="High finding" if fault == "missing-proof" else None):
            validate()


def test_missing_explicit_rule_keeps_strict_default(tmp_path, monkeypatch):
    image, path, _ = candidate(tmp_path, monkeypatch)
    monkeypatch.setattr(component, "rule_enabled", lambda: False)
    with pytest.raises(ValueError, match="do not qualify"):
        component.inspect_disposition(image, path, platform="linux/amd64", now=NOW)


@pytest.mark.parametrize("fault", ["wrong-type", "second-detail"])
def test_only_the_one_reviewed_cpe_match_is_eligible(tmp_path, monkeypatch, fault):
    image, path, raw = candidate(tmp_path, monkeypatch)
    detail = raw["matches"][0]["matchDetails"][0]
    if fault == "wrong-type":
        detail["type"] = "exact-direct-match"
    else:
        raw["matches"][0]["matchDetails"].append(copy.deepcopy(detail))
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="do not qualify"):
        component.inspect_disposition(image, path, platform="linux/amd64", now=NOW)


def test_actual_checker_and_instructions_are_not_sqlite_shell_components(tmp_path, monkeypatch):
    image, path, _ = candidate(
        tmp_path,
        monkeypatch,
        extra={
            "build/saas/scripts/sqlite_component_disposition.py": Path(
                component.__file__
            ).read_bytes(),
            "opt/other-sqlite-audit.py": (
                b"#!/usr/bin/python\n# Audit .recover, sqlite> and "
                b"sqlite3_recover_init text only\n"
            ),
            "docs/sqlite3.md": b"Use the sqlite3 .recover command only in an isolated environment",
        },
    )
    original = path.read_bytes()
    proof = component.inspect_disposition(image, path, platform="linux/amd64", now=NOW)
    assert not any(item.get("shell") or item.get("recover") for item in proof["inventory"])
    assert component.validate_disposition(path, proof, image=image, now=NOW) == proof
    assert path.read_bytes() == original


def test_deleting_cli_from_self_reported_inventory_never_authenticates_it(tmp_path, monkeypatch):

    image, path, _raw = candidate(
        tmp_path, monkeypatch, extra={"usr/bin/sqlite3": b"#!/bin/sh\n.recover\n"}
    )
    forged_inventory = [
        {
            "path": "usr/lib/libsqlite3.so.3.54.1",
            "type": "0",
            "link": "",
            "mode": 0o644,
            "sha256": hashlib.sha256(LIBRARY).hexdigest(),
            "shell": False,
            "recover": False,
        }
    ]
    forged = component.disposition_receipt(path, forged_inventory, platform="linux/amd64", now=NOW)
    with pytest.raises(ValueError):
        component.validate_disposition(path, forged, image=image, now=NOW)
    with pytest.raises(ValueError, match="actual verified OCI"):
        component.validate_disposition(path, forged, now=NOW)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "fake-zero",
        "different-subject",
        "extended-expiry",
        "self-rehashed-inventory",
        "missing-admission",
        "document-swapped-after-verification",
    ],
)
def test_existing_release_image_validator_keeps_finite_raw_evidence(tmp_path, monkeypatch, fault):
    monkeypatch.setenv("OMNIGENT_RUNTIME_EVIDENCE_REPO", str(tmp_path))
    import base64

    from saas.production.admission import admission_signature_payload
    from saas.scripts.check_image_supply_chain import _validate_image
    from tests.saas import test_evidence_admission as signed
    from tests.saas.test_image_supply_chain import _policy, _valid_evidence

    _NOW = signed._NOW
    admission_policy, signing_key = signed._fixture(tmp_path)
    policy_path = tmp_path / "saas/production/evidence-admission-policy.json"
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text(json.dumps(admission_policy))

    evidence = cast(dict[str, Any], _valid_evidence())
    policy = cast(dict[str, Any], _policy())
    value = evidence["images"][0]
    database_time = _NOW.replace(hour=7)
    image, _, original = candidate(tmp_path, monkeypatch, database_time=database_time)
    bundle: list[dict[str, Any]] = []
    for platform in ("linux/amd64", "linux/arm64"):
        with component.image_blobs(image) as blobs:
            digest, manifest = blobs.platform(platform)
        raw = copy.deepcopy(original)
        raw["source"]["target"].update(
            manifestDigest=digest,
            imageID=manifest["config"]["digest"],
            architecture=platform.split("/")[1],
        )
        path = tmp_path / (platform.split("/")[1] + ".json")
        path.write_text(json.dumps(raw))
        proof = component.inspect_disposition(image, path, platform=platform, now=_NOW)
        bundle.append({"raw_report": path.read_text(), "proof": proof})
        value["platform_digests"][platform] = digest
        value["config_digests"][platform] = manifest["config"]["digest"]
    value["labels"] = original["source"]["target"]["labels"]
    evidence.update(
        upstream_revision=value["labels"]["ai.omnigent.upstream.revision"],
        control_plane_schema_revision=value["labels"]["ai.omnigent.saas.schema-revision"],
        adapter_contract_version=value["labels"]["ai.omnigent.saas.adapter-contract-version"],
    )
    scan = value["vulnerabilities"]
    scan.update(high=2, scanner="grype 0.120.1", component_dispositions=bundle)
    for field in ("scanner_database_updated_at", "scan_completed_at"):
        scan[field] = scan[field].replace("2026-08-05", "2026-08-09")
    value["admission_completed_at"] = value["admission_completed_at"].replace(
        "2026-08-05", "2026-08-09"
    )
    if fault == "fake-zero":
        scan["high"] = 0
    elif fault == "different-subject":
        value["platform_digests"]["linux/amd64"] = "sha256:" + "f" * 64
    elif fault == "extended-expiry":
        bundle[0]["proof"]["expires_at"] = "2099-01-01T00:00:00Z"
    scan["report_sha256"] = hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest()
    image_document = tmp_path / "evidence/image.json"
    image_document.write_text(json.dumps(evidence))
    receipt_path = tmp_path / "admission/receipts/image.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["evidence_sha256"] = hashlib.sha256(image_document.read_bytes()).hexdigest()
    receipt["signature"] = base64.b64encode(
        signing_key.sign(admission_signature_payload(receipt))
    ).decode()
    receipt_path.write_text(json.dumps(receipt))
    if fault == "self-rehashed-inventory":
        inventory = [
            *bundle[0]["proof"]["inventory"],
            {
                "path": "docs/sqlite-invented.txt",
                "type": "0",
                "link": "",
                "mode": 0o644,
                "sha256": "f" * 64,
                "shell": False,
                "recover": False,
            },
        ]
        bundle[0]["proof"] = component.disposition_receipt(
            bundle[0]["raw_report"].encode(), inventory, platform="linux/amd64", now=_NOW
        )
        scan["report_sha256"] = hashlib.sha256(
            json.dumps(bundle, sort_keys=True).encode()
        ).hexdigest()
        image_document.write_text(json.dumps(evidence))
        receipt["evidence_sha256"] = hashlib.sha256(image_document.read_bytes()).hexdigest()
        receipt_path.write_text(json.dumps(receipt))
    elif fault == "missing-admission":
        receipt_path.unlink()
    elif fault == "document-swapped-after-verification":
        from saas.production import admission

        forged = copy.deepcopy(evidence)
        forged_scan = forged["images"][0]["vulnerabilities"]
        forged_bundle = forged_scan["component_dispositions"]
        inventory = [
            *forged_bundle[0]["proof"]["inventory"],
            {
                "path": "docs/sqlite-false-inventory.txt",
                "type": "0",
                "link": "",
                "mode": 0o644,
                "sha256": "f" * 64,
                "shell": False,
                "recover": False,
            },
        ]
        forged_bundle[0]["proof"] = component.disposition_receipt(
            forged_bundle[0]["raw_report"].encode(), inventory, platform="linux/amd64", now=_NOW
        )
        forged_scan["report_sha256"] = hashlib.sha256(
            json.dumps(forged_bundle, sort_keys=True).encode()
        ).hexdigest()
        real_verify = admission.validate_evidence_admission

        def verify_then_replace(*args, **kwargs):
            result = real_verify(*args, **kwargs)
            assert result["kinds"]["image"]["production_readiness"] == "ready"
            image_document.write_text(json.dumps(forged))
            return result

        monkeypatch.setattr(admission, "validate_evidence_admission", verify_then_replace)
        evidence = forged
        value = forged["images"][0]
    violations, _ = _validate_image(
        policy,
        value,
        expected=policy["images"][0],
        product_revision="a" * 40,
        evidence=evidence,
        completed_at=_NOW,
        now=_NOW,
        repo=tmp_path,
    )
    if fault is None:
        assert violations == []
        assert scan["high"] == 2 and scan["exceptions"] == []
    else:
        assert any("finite component disposition" in message for message in violations)
