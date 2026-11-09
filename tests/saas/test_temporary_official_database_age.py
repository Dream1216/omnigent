"""Finite original-DB bytes, actual OCI subjects and hard-expiry boundaries."""

import copy
import hashlib
import io
import json
import subprocess
import tarfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from saas.scripts import scan_oci_candidates as scan
from saas.scripts import sqlite_component_disposition as sqlite
from tests.saas.test_image_supply_chain import _write_oci

NOW = datetime(2026, 11, 9, 14, tzinfo=UTC)
BUILT = datetime(2026, 11, 8, 6, 19, 57, tzinfo=UTC)
PRODUCT = "8c851bdd12829340b2a327cf7542fe4de84d9132"
LATEST = {
    "status": "active",
    "schemaVersion": "v6.1.10",
    "built": "2026-11-08T06:19:57Z",
    "path": scan.TEMPORARY_DATABASE_AGE["archive_URL"],
    "checksum": "sha256:" + scan.TEMPORARY_DATABASE_AGE["archive_SHA256"],
}


def status():
    return {"valid": True, "schemaVersion": "v6.1.10", "built": "2026-11-08T06:19:57Z"}


def image(tmp_path, revision=PRODUCT):
    path = tmp_path / "subject.tar"
    _write_oci(path, revision=revision, label_profile="executable", nested=True)
    layout = tmp_path / "subject-layout"
    with tarfile.open(path, "w") as archive:
        for member in sorted(layout.rglob("*")):
            archive.add(member, arcname=member.relative_to(layout), recursive=False)
    return path


def raw_report(path, platform):
    with sqlite.image_blobs(path) as blobs:
        digest, manifest = blobs.platform(platform)
        config = blobs.document(manifest["config"]["digest"])
    return {
        "descriptor": {
            "name": "grype",
            "version": "0.120.1",
            "db": {"status": status()},
            "configuration": {"only-fixed": False, "only-notfixed": False},
        },
        "source": {
            "target": {
                "manifestDigest": digest,
                "imageID": manifest["config"]["digest"],
                "os": "linux",
                "architecture": platform.split("/")[1],
                "labels": config["config"]["Labels"],
            }
        },
        "matches": [],
        "ignoredMatches": [],
    }


def receipt(path, report, *, platform="linux/amd64"):
    subject = scan.temporary_database_subjects(
        {"server": path}, scope="server-preflight", now=NOW
    )["server"][platform]
    raw = json.dumps(report).encode()
    return scan.make_database_age_disposition(
        report["descriptor"]["db"]["status"],
        LATEST,
        subject,
        now=NOW,
        report_sha256=hashlib.sha256(raw).hexdigest(),
        checked_at=NOW - timedelta(seconds=1),
    )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing",
        "dict-extra",
        "checksum",
        "schema",
        "built",
        "expiry",
        "future-check",
        "new-latest",
        "wrong-index-format",
        "wrong-manifest",
        "wrong-config",
        "wrong-source",
        "wrong-tree",
        "wrong-platform",
        "wrong-report",
        "float-hours",
        "unapproved",
        "hard-expiry",
    ],
)
def test_original_DB_exception_requires_exact_receipt_and_actual_subject(
    tmp_path, monkeypatch, fault
):
    path = image(tmp_path)
    report = raw_report(path, "linux/amd64")
    proof = receipt(path, report)
    when = NOW
    if fault == "missing":
        proof = None
    elif fault == "dict-extra":
        proof["future"] = True
    elif fault in {"checksum", "schema", "built", "expiry", "future-check", "wrong-report"}:
        key, value = {
            "checksum": ("database_sha256", "e" * 64),
            "schema": ("database_schema", "v6.2.0"),
            "built": ("database_built_at", NOW.isoformat()),
            "expiry": ("expires_at", "2026-11-11T06:19:57Z"),
            "future-check": (
                "official_latest_checked_at",
                (NOW + timedelta(seconds=1)).isoformat(),
            ),
            "wrong-report": ("report_sha256", "e" * 64),
        }[fault]
        proof[key] = value
    elif fault == "new-latest":
        proof["official_latest"] = {**LATEST, "checksum": "sha256:" + "e" * 64}
    elif fault in {
        "wrong-index-format",
        "wrong-manifest",
        "wrong-config",
        "wrong-source",
        "wrong-tree",
        "wrong-platform",
    }:
        key, value = {
            "wrong-index-format": ("index_digest", "unknown"),
            "wrong-manifest": ("manifest_digest", "sha256:" + "e" * 64),
            "wrong-config": ("config_digest", "sha256:" + "e" * 64),
            "wrong-source": ("source_revision", "f" * 40),
            "wrong-tree": ("product_tree", "f" * 40),
            "wrong-platform": ("platform", "linux/arm64"),
        }[fault]
        proof["subject"][key] = value
    elif fault == "float-hours":
        proof["maximum_age_hours"] = 48.0
    elif fault == "unapproved":
        monkeypatch.setattr(scan, "temporary_database_age_enabled", lambda *_: False)
    elif fault == "hard-expiry":
        when = datetime(2026, 11, 10, 6, 19, 57, tzinfo=UTC)
    kwargs = {
        "now": when,
        "subject": report["source"]["target"],
        "database_age_disposition": proof,
        "report_sha256": hashlib.sha256(json.dumps(report).encode()).hexdigest(),
    }
    if fault:
        with pytest.raises(ValueError):
            scan.parse_database_status(status(), **kwargs)
    else:
        assert scan.parse_database_status(status(), **kwargs) == status()["built"]
        with pytest.raises(ValueError, match="older than 24"):
            scan.parse_database_status(status(), now=NOW)


@pytest.mark.parametrize("fault", [None, "short", "changed"])
def test_actual_official_archive_full_hash_is_required_before_import(tmp_path, monkeypatch, fault):
    body = b"exact entire official DB archive fixture"
    monkeypatch.setitem(
        scan.TEMPORARY_DATABASE_AGE, "archive_SHA256", hashlib.sha256(body).hexdigest()
    )

    def response(request, *, timeout):
        assert request.full_url == scan.TEMPORARY_DATABASE_AGE["archive_URL"]
        assert request.get_header("Authorization") is None and timeout == 120
        return io.BytesIO(
            body if fault is None else body[:-1] if fault == "short" else body + b"x"
        )

    monkeypatch.setattr(scan.urllib.request, "urlopen", response)
    if fault:
        with pytest.raises(ValueError, match="full SHA256"):
            scan.download_approved_database(tmp_path / "db.tar.zst")
    else:
        scan.download_approved_database(tmp_path / "db.tar.zst")
        assert (tmp_path / "db.tar.zst").read_bytes() == body


@pytest.mark.parametrize(
    "mode", ["finite", "new-official", "changed-before-scan", "corrupt-cache"]
)
def test_scan_cli_rechecks_latest_and_full_DB_before_each_original_platform(
    tmp_path, monkeypatch, mode
):
    path = image(tmp_path)
    output = tmp_path / "scans"
    monkeypatch.setattr(
        "sys.argv",
        [
            "scan",
            "--scope",
            "server-preflight",
            "--image",
            f"server={path}",
            "--output",
            str(output),
        ],
    )

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(scan, "datetime", Clock)
    latest_calls, hashes, commands = [], [], []

    def latest():
        latest_calls.append(True)
        if mode == "new-official" or (mode == "changed-before-scan" and len(latest_calls) > 1):
            return {**LATEST, "checksum": "sha256:" + "e" * 64}
        return copy.deepcopy(LATEST)

    monkeypatch.setattr(scan, "official_database_latest", latest)
    monkeypatch.setattr(scan, "install_grype", lambda p: p / "grype")
    monkeypatch.setattr(
        scan, "download_approved_database", lambda p: p.write_bytes(b"verified DB")
    )
    original_hash = scan.file_sha256

    def digest(p):
        if p.name == "official-db.tar.zst":
            hashes.append(True)
            return (
                "e" * 64
                if mode == "corrupt-cache"
                else scan.TEMPORARY_DATABASE_AGE["archive_SHA256"]
            )
        return original_hash(p)

    monkeypatch.setattr(scan, "file_sha256", digest)
    db_status = status() if mode != "new-official" else {**status(), "built": NOW.isoformat()}
    monkeypatch.setattr(scan.subprocess, "check_output", lambda *_a, **_k: json.dumps(db_status))

    def scanner(command, **kwargs):
        commands.append(command)
        config = Path(command[2]).read_text()
        assert f"max-allowed-built-age: {24 if mode == 'new-official' else 48}h" in config
        if "--platform" in command:
            report = raw_report(path, command[command.index("--platform") + 1])
            report["descriptor"]["db"]["status"] = db_status
            Path(command[-1]).write_text(json.dumps(report))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(scan.subprocess, "run", scanner)
    if mode in {"changed-before-scan", "corrupt-cache"}:
        with pytest.raises(ValueError, match="changed before scan"):
            scan.main()
        assert not any("--platform" in row for row in commands)
    else:
        assert scan.main() == 0
        summary = json.loads((output / "server-preflight-scan-summary.json").read_text())
        assert len(summary["images"]) == 2
        assert all(
            ("database_age_disposition" in row) is (mode == "finite") for row in summary["images"]
        )
        assert len(latest_calls) == (3 if mode == "finite" else 1)
        assert len(hashes) == (2 if mode == "finite" else 0)
        assert any("import" in row for row in commands) is (mode == "finite")


def test_other_product_advisory_and_expired_subjects_do_not_gain48h(tmp_path):
    path = image(tmp_path, "a" * 40)
    assert scan.temporary_database_subjects({"server": path}, scope="complete", now=NOW) == {}
    assert scan.temporary_database_subjects({"host": path}, scope="aliyun-host", now=NOW) == {}
    assert (
        scan.temporary_database_subjects(
            {"server": path}, scope="server-preflight", now=NOW + timedelta(days=1)
        )
        == {}
    )


@pytest.mark.parametrize("fault", [None, "archive", "index", "report", "missing-platform"])
def test_actual_four_report_OCI_seal_binds_finite_age_and_original_bytes(
    tmp_path, monkeypatch, fault
):
    from saas.scripts import oci_promotion as promotion
    from tests.saas import test_oci_promotion as fixture

    monkeypatch.setattr(fixture, "REVISION", PRODUCT)
    root = tmp_path / "candidate"
    labels, _ = fixture.candidate(root)
    summary_path = root / "grype/candidate-scan-summary.json"
    summary = json.loads(summary_path.read_text())
    subjects = scan.temporary_database_subjects(
        {role: root / f"{role}-1.tar" for role in ("server", "host")}, scope="complete", now=NOW
    )
    summary["database_built_at"] = status()["built"]
    for row in summary["images"]:
        role, platform = row["image"], row["platform"]
        path = root / f"grype/{role}-{platform.split('/')[-1]}-grype.json"
        report = json.loads(path.read_text())
        report["descriptor"]["db"]["status"] = status()
        path.write_text(json.dumps(report))
        row["report_sha256"] = scan.file_sha256(path)
        row["database_age_disposition"] = scan.make_database_age_disposition(
            status(),
            LATEST,
            subjects[role][platform],
            now=NOW,
            report_sha256=row["report_sha256"],
            checked_at=NOW - timedelta(seconds=1),
        )
    first = summary["images"][0]
    if fault in {"archive", "index"}:
        key = "archive_sha256" if fault == "archive" else "index_digest"
        first["database_age_disposition"]["subject"][key] = (
            "" if fault == "archive" else "sha256:"
        ) + "e" * 64
    elif fault == "report":
        first["database_age_disposition"]["report_sha256"] = "e" * 64
    elif fault == "missing-platform":
        summary["images"].pop()
    summary_path.write_text(json.dumps(summary))
    if fault:
        with pytest.raises(ValueError):
            promotion.seal_candidate(root, labels=labels, source_date_epoch=fixture.EPOCH, now=NOW)
    else:
        manifest = promotion.seal_candidate(
            root, labels=labels, source_date_epoch=fixture.EPOCH, now=NOW
        )
        age = manifest["scans"]["temporary_database_age"]
        assert (
            len(age["reports"]) == 4 and age["rule_sha256"] == scan.TEMPORARY_DATABASE_AGE_SHA256
        )
        assert age["rule"] == scan.TEMPORARY_DATABASE_AGE


def test_existing_SQLite_disposition_accepts_only_the_bound_DB_age_context(tmp_path, monkeypatch):
    from tests.saas import test_sqlite_component_disposition as fixture

    original = fixture._write_oci
    monkeypatch.setattr(
        fixture,
        "_write_oci",
        lambda path, **kwargs: original(path, **{**kwargs, "revision": PRODUCT}),
    )
    path, _, report = fixture.candidate(tmp_path, monkeypatch, database_time=BUILT)
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(json.dumps(report))
    proof = receipt(path, report)
    with pytest.raises(ValueError, match="older than 24"):
        sqlite.inspect_disposition(path, raw_path, platform="linux/amd64", now=NOW)
    accepted = sqlite.inspect_disposition(
        path, raw_path, platform="linux/amd64", now=NOW, database_age_disposition=proof
    )
    assert accepted["raw_critical"] == 0 and accepted["raw_high"] == 1
    sqlite.validate_disposition(
        raw_path, accepted, image=path, now=NOW, database_age_disposition=proof
    )


def test_existing_combined_disposition_preserves_two_raw_High_with_bound_DB(tmp_path, monkeypatch):
    from tests.saas import test_combined_runtime_disposition as combined_fixture
    from tests.saas import test_sqlite_component_disposition as sqlite_fixture

    original = sqlite_fixture._write_oci
    monkeypatch.setattr(
        sqlite_fixture,
        "_write_oci",
        lambda path, **kwargs: original(path, **{**kwargs, "revision": PRODUCT}),
    )
    path, raw_path, report, approved = combined_fixture.combination(
        tmp_path, monkeypatch, database_time=BUILT
    )
    raw_path.write_text(json.dumps(report))
    raw = raw_path.read_bytes()
    approved = replace(
        approved,
        subject=replace(
            approved.subject,
            source_revision=PRODUCT,
            report_sha256=hashlib.sha256(raw).hexdigest(),
        ),
        expires_at=NOW + timedelta(hours=2),
    )
    proof = receipt(path, report)
    with pytest.raises(ValueError, match="older than 24"):
        combined_fixture.inspect(path, raw_path, approved, now=NOW)
    accepted = combined_fixture.inspect(
        path, raw_path, approved, now=NOW, database_age_disposition=proof
    )
    assert accepted["raw_high"] == 2 and accepted["raw_critical"] == 0
    assert raw_path.read_bytes() == raw


@pytest.mark.parametrize(
    "fault", [None, "wrong-index", "wrong-report", "expired", "missing-platform", "raw-high"]
)
def test_final_release_age_validation_requires_real_two_platform_report_bundle(tmp_path, fault):
    path = image(tmp_path)
    subjects = scan.temporary_database_subjects(
        {"server": path}, scope="server-preflight", now=NOW
    )["server"]
    bundle = []
    for platform in scan.PLATFORMS:
        report = raw_report(path, platform)
        if fault == "raw-high":
            report["matches"] = [{"vulnerability": {"severity": "High", "id": "CVE-other"}}]
        raw = json.dumps(report)
        proof = scan.make_database_age_disposition(
            status(),
            LATEST,
            subjects[platform],
            now=NOW,
            report_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            checked_at=NOW - timedelta(seconds=1),
        )
        bundle.append({"raw_report": raw, "receipt": proof})
    evidence = {
        "name": "ghcr.io/dream1216/omnigent-saas-server",
        "labels": {"org.opencontainers.image.revision": PRODUCT},
        "manifest_digest": subjects["linux/amd64"]["index_digest"],
        "platform_digests": {p: s["manifest_digest"] for p, s in subjects.items()},
        "config_digests": {p: s["config_digest"] for p, s in subjects.items()},
    }
    when = NOW
    if fault == "wrong-index":
        evidence["manifest_digest"] = "sha256:" + "e" * 64
    elif fault == "wrong-report":
        bundle[0]["raw_report"] += " "
    elif fault == "expired":
        when = NOW + timedelta(days=1)
    elif fault == "missing-platform":
        bundle.pop()
    summary = {
        "database_age_dispositions": bundle,
        "scanner_database_updated_at": status()["built"],
        "scan_completed_at": NOW.isoformat(),
        "report_sha256": hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest(),
    }
    if fault:
        with pytest.raises(ValueError):
            scan.validate_release_database_age(
                Path(__file__).resolve().parents[2], evidence, summary, now=when
            )
    else:
        scan.validate_release_database_age(
            Path(__file__).resolve().parents[2], evidence, summary, now=when
        )


@pytest.mark.parametrize("include_proof", [False, True])
def test_existing_final_image_gate_keeps_default24_and_accepts_only_bound48(
    tmp_path, include_proof
):
    from saas.scripts import check_image_supply_chain as final
    from tests.saas.test_image_supply_chain import _policy, _valid_evidence

    path = image(tmp_path)
    subjects = scan.temporary_database_subjects(
        {"server": path}, scope="server-preflight", now=NOW
    )["server"]
    policy, evidence = _policy(), _valid_evidence()
    actual = copy.deepcopy(evidence["images"][0])
    old_digest = actual["manifest_digest"]
    index = subjects["linux/amd64"]["index_digest"]
    actual["manifest_digest"] = index
    actual["labels"]["org.opencontainers.image.revision"] = PRODUCT
    actual["platform_digests"] = {p: s["manifest_digest"] for p, s in subjects.items()}
    actual["config_digests"] = {p: s["config_digest"] for p, s in subjects.items()}
    for key in ("sbom", "provenance", "signature", "vulnerabilities", "licenses"):
        actual[key]["subject_digest"] = index
    for key in ("spdx_uri", "cyclonedx_uri"):
        actual["sbom"][key] = actual["sbom"][key].replace(old_digest, index)
    actual["provenance"]["source_revision"] = PRODUCT
    actual["admission_completed_at"] = NOW.isoformat().replace("+00:00", "Z")
    vulnerability = actual["vulnerabilities"]
    vulnerability.update(
        scanner="grype 0.120.1",
        scanner_database_updated_at=status()["built"],
        scan_completed_at=NOW.isoformat().replace("+00:00", "Z"),
    )
    bundle = []
    for platform in scan.PLATFORMS:
        report = raw_report(path, platform)
        report["descriptor"]["db"]["status"]["built"] = BUILT.isoformat()
        raw = json.dumps(report)
        proof = scan.make_database_age_disposition(
            report["descriptor"]["db"]["status"],
            LATEST,
            subjects[platform],
            now=NOW,
            report_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            checked_at=NOW - timedelta(seconds=1),
        )
        bundle.append({"raw_report": raw, "receipt": proof})
    if include_proof:
        vulnerability["database_age_dispositions"] = bundle
        vulnerability["report_sha256"] = hashlib.sha256(
            json.dumps(bundle, sort_keys=True).encode()
        ).hexdigest()
    violations, _ = final._validate_image(
        policy,
        actual,
        expected=policy["images"][0],
        product_revision=PRODUCT,
        evidence=evidence,
        completed_at=NOW,
        now=NOW,
        repo=Path(__file__).resolve().parents[2],
    )
    assert (
        not [row for row in violations if "database" in row]
        if include_proof
        else any("database is stale" in row for row in violations)
    ), violations
