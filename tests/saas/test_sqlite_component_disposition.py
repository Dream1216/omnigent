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
            archive.addfile(member, io.BytesIO(body))
    image = tmp_path / "candidate.tar"
    _write_oci(
        image,
        revision="a" * 40,
        label_profile="executable",
        nested=True,
        layer_payload=layer.getvalue(),
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
                "matchDetails": [{"matcher": "apk-matcher"}],
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
    assert component.validate_disposition(path, proof, now=NOW) == proof
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
        ("usr/lib/sqlite3recover.c", b"sqlite3_recover_init"),
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
        component.validate_disposition(path, proof, now=NOW)


@pytest.mark.parametrize("consumer", ["promotion", "core"])
@pytest.mark.parametrize(
    "fault", [None, "missing-proof", "fake-zero", "extra-high", "subject-swap"]
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
    image, _, original = candidate(tmp_path, monkeypatch)
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
            scan_root, images, summary_name="candidate-scan-summary.json"
        )

    if fault is None:
        assert len(validate()["reports"]) == 4
        assert all(row["high"] == 1 for row in rows)
    else:
        with pytest.raises(ValueError):
            validate()


def test_missing_explicit_rule_keeps_strict_default(tmp_path, monkeypatch):
    image, path, _ = candidate(tmp_path, monkeypatch)
    monkeypatch.setattr(component, "rule_enabled", lambda: False)
    with pytest.raises(ValueError, match="do not qualify"):
        component.inspect_disposition(image, path, platform="linux/amd64", now=NOW)


@pytest.mark.parametrize("fault", [None, "fake-zero", "different-subject", "extended-expiry"])
def test_existing_release_image_validator_keeps_finite_raw_evidence(tmp_path, monkeypatch, fault):
    from saas.scripts.check_image_supply_chain import _validate_image
    from tests.saas.test_image_supply_chain import _NOW, _policy, _valid_evidence

    evidence = cast(dict[str, Any], _valid_evidence())
    policy = cast(dict[str, Any], _policy())
    value = evidence["images"][0]
    database_time = _NOW.replace(hour=7)
    image, _, original = candidate(tmp_path, monkeypatch, database_time=database_time)
    bundle = []
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
    if fault == "fake-zero":
        scan["high"] = 0
    elif fault == "different-subject":
        value["platform_digests"]["linux/amd64"] = "sha256:" + "f" * 64
    elif fault == "extended-expiry":
        bundle[0]["proof"]["expires_at"] = "2099-01-01T00:00:00Z"
    scan["report_sha256"] = hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest()
    violations, _ = _validate_image(
        policy,
        value,
        expected=policy["images"][0],
        product_revision="a" * 40,
        evidence=evidence,
        completed_at=_NOW,
        now=_NOW,
    )
    if fault is None:
        assert violations == []
        assert scan["high"] == 2 and scan["exceptions"] == []
    else:
        assert any("finite component disposition" in message for message in violations)
