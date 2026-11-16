"""Exact-OCI promotion and failure-path contracts, independent of trusted N-1 tests."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from saas.scripts import oci_promotion
from saas.scripts.check_image_supply_chain import validate_candidate_build_contract
from saas.scripts.compare_oci_rebuilds import compare_archives, inspect_oci_archive
from saas.scripts.oci_promotion import (
    MANIFEST_NAME,
    archive_index_digest,
    extract_artifact,
    extract_layout,
    seal_candidate,
    verify_artifact_metadata,
    verify_candidate,
    verify_promotion_controller,
    verify_readback,
    verify_trusted_main_source,
)
from saas.scripts.scan_oci_candidates import file_sha256
from tests.saas.test_image_supply_chain import _candidate_contract_repo, _write_oci

ROOT = Path(__file__).resolve().parents[2]
REVISION = "a" * 40
EPOCH = 1791756537


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def candidate(
    root: Path, *, layer_payload: bytes = b"stable-layer", config_os: str | None = None
) -> tuple[dict[str, str], datetime]:
    now = datetime.now(UTC)
    (root / "grype").mkdir(parents=True)
    comparisons, rows = {}, []
    labels: dict[str, str] = {}
    for name in ("server", "host"):
        archive = root / f"{name}-1.tar"
        _write_oci(
            archive,
            revision=REVISION,
            label_profile="executable",
            nested=True,
            layer_payload=layer_payload,
            config_os=config_os,
        )
        layout = root / f"{name}-1-layout"
        index = json.loads((layout / "index.json").read_text())
        descriptor = index["manifests"][0]
        inner = json.loads(
            (layout / "blobs/sha256" / descriptor["digest"].removeprefix("sha256:")).read_text()
        )
        inner["mediaType"] = "application/vnd.oci.image.index.v1+json"
        changed_manifests: dict[str, str] = {}
        for child in inner["manifests"]:
            child.setdefault("mediaType", "application/vnd.oci.image.manifest.v1+json")
            if child.get("platform", {}).get("os") == "linux":
                old_digest = child["digest"]
                document = json.loads(
                    (layout / "blobs/sha256" / old_digest.removeprefix("sha256:")).read_text()
                )
                config = document["config"]
                config["size"] = (
                    (layout / "blobs/sha256" / config["digest"].removeprefix("sha256:"))
                    .stat()
                    .st_size
                )
                config["mediaType"] = "application/vnd.oci.image.config.v1+json"
                if config_os is not None:
                    for layer in document["layers"]:
                        layer["mediaType"] = "application/vnd.oci.image.layer.v1.tar"
                document["mediaType"] = child["mediaType"]
                body = json.dumps(document, sort_keys=True).encode()
                digest = hashlib.sha256(body).hexdigest()
                (layout / "blobs/sha256" / digest).write_bytes(body)
                child["digest"], child["size"] = f"sha256:{digest}", len(body)
                changed_manifests[old_digest] = child["digest"]
        for child in inner["manifests"]:
            annotations = child.get("annotations", {})
            if "vnd.docker.reference.digest" in annotations:
                annotations["vnd.docker.reference.digest"] = changed_manifests[
                    annotations["vnd.docker.reference.digest"]
                ]
        body = json.dumps(inner, sort_keys=True).encode()
        digest = hashlib.sha256(body).hexdigest()
        (layout / "blobs/sha256" / digest).write_bytes(body)
        descriptor["digest"], descriptor["size"] = f"sha256:{digest}", len(body)
        write_json(layout / "index.json", index)
        with tarfile.open(archive, "w") as bundle:
            for member in sorted(layout.rglob("*")):
                bundle.add(member, arcname=member.relative_to(layout), recursive=False)
        comparisons[f"omnigent-saas-{name}"] = compare_archives(
            archive, archive, label_profile="executable"
        )
        facts = inspect_oci_archive(archive, label_profile="executable")
        for platform, item in facts["platforms"].items():
            labels = item["labels"]
            relative = f"grype/{name}-{platform.split('/')[-1]}-grype.json"
            report = root / relative
            write_json(
                report,
                {
                    "descriptor": {
                        "name": "grype",
                        "version": "0.120.1",
                        "db": {
                            "status": {
                                "built": now.isoformat(),
                                "schemaVersion": "v6.1.10",
                                "valid": True,
                            }
                        },
                        "configuration": {"only-fixed": False, "only-notfixed": False},
                    },
                    "source": {
                        "target": {
                            "manifestDigest": item["manifest_digest"],
                            "imageID": item["config_digest"],
                            "architecture": platform.split("/")[-1],
                            "os": "linux",
                            "labels": labels,
                        }
                    },
                    "matches": [],
                    "ignoredMatches": [],
                },
            )
            rows.append(
                {
                    "image": name,
                    "platform": platform,
                    "archive_sha256": file_sha256(archive),
                    "report_sha256": file_sha256(report),
                    "critical": 0,
                    "high": 0,
                    "findings": [],
                }
            )
    write_json(
        root / "saas-image-candidate.json",
        {
            "candidate_evidence_version": 3,
            "status": "pass",
            "violations": [],
            "product_revision": REVISION,
            "source_date_epoch": EPOCH,
            "upstream_revision": labels["ai.omnigent.upstream.revision"],
            "adapter_contract_version": labels["ai.omnigent.saas.adapter-contract-version"],
            "label_profile": "executable",
            "images": comparisons,
        },
    )
    write_json(
        root / "grype/candidate-scan-summary.json",
        {
            "scanner": "grype 0.120.1",
            "database_built_at": now.isoformat(),
            "exceptions": [],
            "images": rows,
        },
    )
    return labels, now


def seal(root: Path, labels: dict[str, str], now: datetime) -> dict[str, Any]:
    return seal_candidate(root, labels=labels, source_date_epoch=EPOCH, now=now)


def test_seal_transfer_prepare_and_readback_keep_original_digest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    labels, now = candidate(source)
    manifest = seal(source, labels, now)
    write_json(source / MANIFEST_NAME, manifest)
    sha = file_sha256(source / MANIFEST_NAME)
    zip_path = tmp_path / "candidate.zip"
    with zipfile.ZipFile(zip_path, "w") as bundle:
        for member in source.rglob("*"):
            if member.is_file() and "-layout" not in str(member.relative_to(source)):
                bundle.write(member, arcname=member.relative_to(source))
    transferred = tmp_path / "transferred"
    extract_artifact(zip_path, transferred, zip_sha256=file_sha256(zip_path))
    assert (
        verify_candidate(transferred, manifest_sha256=sha, labels=labels, source_date_epoch=EPOCH)
        == manifest
    )
    for name in ("server", "host"):
        extract_layout(transferred / f"{name}-1.tar", tmp_path / name)
        verify_readback(source / f"{name}-1.tar", manifest["images"][name])
        assert (
            archive_index_digest(source / f"{name}-1.tar")
            == manifest["images"][name]["index_digest"]
        )


@pytest.mark.parametrize(
    "field", ["product_revision", "source_date_epoch", "status", "violations"]
)
def test_seal_rejects_reproducibility_or_source_drift(tmp_path: Path, field: str) -> None:
    labels, now = candidate(tmp_path)
    path = tmp_path / "saas-image-candidate.json"
    evidence = json.loads(path.read_text())
    evidence[field] = "different"
    write_json(path, evidence)
    with pytest.raises(ValueError, match="final source"):
        seal(tmp_path, labels, now)


@pytest.mark.parametrize(
    "failure",
    [
        "high",
        "ignored",
        "only-fixed",
        "exclude",
        "vex",
        "config",
        "architecture",
        "hash",
        "duplicate",
    ],
)
def test_raw_scan_tampering_blocks_promotion(tmp_path: Path, failure: str) -> None:
    labels, now = candidate(tmp_path)
    path = tmp_path / "grype/server-amd64-grype.json"
    raw = json.loads(path.read_text())
    if failure in ("high", "ignored"):
        match = {
            "artifact": {"name": "package", "version": "1"},
            "vulnerability": {"severity": "High", "id": "CVE-test"},
        }
        raw["matches" if failure == "high" else "ignoredMatches"] = [match]
    elif failure in ("only-fixed", "exclude", "vex"):
        raw["descriptor"]["configuration"]["vex-documents" if failure == "vex" else failure] = (
            True if failure == "only-fixed" else ["filtered"]
        )
    elif failure in ("config", "architecture"):
        raw["source"]["target"]["imageID" if failure == "config" else "architecture"] = "different"
    write_json(path, raw)
    summary_path = tmp_path / "grype/candidate-scan-summary.json"
    summary = json.loads(summary_path.read_text())
    summary["images"][0]["report_sha256"] = file_sha256(path) if failure != "hash" else "0" * 64
    if failure == "duplicate":
        summary["images"][1] = copy.deepcopy(summary["images"][0])
    write_json(summary_path, summary)
    with pytest.raises(ValueError):
        seal(tmp_path, labels, now)


def test_stale_scan_database_blocks_promotion(tmp_path: Path) -> None:
    labels, now = candidate(tmp_path)
    with pytest.raises(ValueError, match="older than 24 hours"):
        seal(tmp_path, labels, now + timedelta(hours=25))


def refresh_scan_time(root: Path, built_at: datetime) -> None:
    summary_path = root / "grype/candidate-scan-summary.json"
    summary = json.loads(summary_path.read_text())
    summary["database_built_at"] = built_at.isoformat()
    for row in summary["images"]:
        path = root / f"grype/{row['image']}-{row['platform'].split('/')[-1]}-grype.json"
        raw = json.loads(path.read_text())
        raw["descriptor"]["db"]["status"]["built"] = built_at.isoformat()
        write_json(path, raw)
        row["report_sha256"] = file_sha256(path)
    write_json(summary_path, summary)


def test_expired_scans_require_fresh_reports_for_the_same_original_oci(tmp_path: Path) -> None:
    source = tmp_path / "source"
    labels, now = candidate(source)
    refresh_scan_time(source, now - timedelta(hours=26))
    manifest = seal(source, labels, now - timedelta(hours=25))
    write_json(source / MANIFEST_NAME, manifest)
    sha = file_sha256(source / MANIFEST_NAME)
    with pytest.raises(ValueError, match="older than 24 hours"):
        verify_candidate(source, manifest_sha256=sha, labels=labels, source_date_epoch=EPOCH)
    current = tmp_path / "current"
    shutil.copytree(source / "grype", current / "grype")
    refresh_scan_time(current, now)
    actual = verify_candidate(
        source,
        manifest_sha256=sha,
        labels=labels,
        source_date_epoch=EPOCH,
        current_scan_root=current,
    )
    assert actual == manifest
    for name in ("server", "host"):
        assert file_sha256(source / f"{name}-1.tar") == manifest["images"][name]["archive_sha256"]


def test_manifest_or_transferred_archive_tampering_blocks_promotion(tmp_path: Path) -> None:
    labels, now = candidate(tmp_path)
    write_json(tmp_path / MANIFEST_NAME, seal(tmp_path, labels, now))
    sha = file_sha256(tmp_path / MANIFEST_NAME)
    with pytest.raises(ValueError, match="seal digest"):
        verify_candidate(
            tmp_path, manifest_sha256="0" * 64, labels=labels, source_date_epoch=EPOCH
        )
    with (tmp_path / "server-1.tar").open("ab") as stream:
        stream.write(b"replacement")
    with pytest.raises(ValueError, match="original archive"):
        verify_candidate(tmp_path, manifest_sha256=sha, labels=labels, source_date_epoch=EPOCH)


def test_registry_drift_is_not_accepted_as_metadata_only(tmp_path: Path) -> None:
    labels, now = candidate(tmp_path)
    expected = seal(tmp_path, labels, now)["images"]["server"]
    with pytest.raises(ValueError, match="index differs"):
        verify_readback(
            tmp_path / "server-1.tar", {**expected, "index_digest": "sha256:" + "0" * 64}
        )
    changed = copy.deepcopy(expected)
    changed["facts"]["platforms"]["linux/amd64"]["config_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="facts differ"):
        verify_readback(tmp_path / "server-1.tar", changed)


@pytest.mark.parametrize(
    "field", ["id", "name", "validation-name", "expired", "digest", "run-id", "head-sha"]
)
def test_wrong_artifact_or_workflow_coordinates_are_rejected(field: str) -> None:
    metadata = {
        "id": 17,
        "name": f"saas-oci-promotion-{REVISION}",
        "expired": False,
        "digest": "sha256:" + "b" * 64,
        "workflow_run": {"id": 23, "head_sha": REVISION},
    }
    verify_artifact_metadata(
        metadata, artifact_id=17, zip_sha256="b" * 64, revision=REVISION, run_id=23
    )
    if field == "validation-name":
        metadata["name"] = f"saas-oci-validation-{REVISION}"
    elif field in ("run-id", "head-sha"):
        metadata["workflow_run"]["id" if field == "run-id" else "head_sha"] = "different"
    else:
        metadata[field] = "different"
    with pytest.raises(ValueError, match="exact workflow"):
        verify_artifact_metadata(
            metadata, artifact_id=17, zip_sha256="b" * 64, revision=REVISION, run_id=23
        )


@pytest.fixture
def main_producer() -> dict[str, Any]:
    now = datetime.now(UTC)
    repository = {"full_name": "Dream1216/omnigent", "id": 19}
    job = {
        "id": 31,
        "run_id": 23,
        "run_attempt": 2,
        "head_sha": REVISION,
        "status": "completed",
        "conclusion": "success",
    }
    jobs = [
        {**job, "name": name}
        for name in (
            "verify-candidate-preflight",
            "build-candidate",
            "verify-production-migration-replay (postgres:16.14-bookworm@sha256:fixed)",
            "verify-production-migration-replay (postgres:18.6-trixie@sha256:fixed)",
        )
    ]
    for index, item in enumerate(jobs, 31):
        item["id"] = index
    jobs[1]["steps"] = [
        {
            "name": "Upload immutable admitted OCI bytes",
            "status": "completed",
            "conclusion": "success",
            "started_at": (now - timedelta(minutes=3)).isoformat(),
            "completed_at": (now - timedelta(minutes=1)).isoformat(),
        },
        {"name": "Prepare immutable runtime evidence data for candidate", "conclusion": "skipped"},
    ]
    return {
        "controller": {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": repository["full_name"],
            "GITHUB_REPOSITORY_ID": "19",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": REVISION,
            "GITHUB_WORKFLOW_SHA": REVISION,
            "GITHUB_WORKFLOW_REF": (
                "Dream1216/omnigent/.github/workflows/saas-image-candidate.yml@refs/heads/main"
            ),
        },
        "run": {
            "id": 23,
            "run_attempt": 2,
            "path": oci_promotion.TRUSTED_WORKFLOW,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_sha": REVISION,
            "head_branch": "main",
            "repository": repository,
            "head_repository": dict(repository),
        },
        "jobs": jobs,
        "artifact": {
            "id": 17,
            "name": f"saas-oci-promotion-{REVISION}",
            "expired": False,
            "digest": "sha256:" + "b" * 64,
            "created_at": (now - timedelta(minutes=2)).isoformat(),
            "workflow_run": {
                "id": 23,
                "head_sha": REVISION,
                "head_branch": "main",
                "repository_id": 19,
                "head_repository_id": 19,
            },
        },
    }


@pytest.mark.parametrize(
    "field",
    [
        "GITHUB_ACTIONS",
        "GITHUB_EVENT_NAME",
        "GITHUB_REPOSITORY",
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_WORKFLOW_SHA",
        "GITHUB_WORKFLOW_REF",
    ],
)
def test_cross_run_requires_the_exact_main_controller(main_producer, field: str) -> None:
    environment = main_producer["controller"]
    assert (
        verify_promotion_controller(
            environment, repository="Dream1216/omnigent", revision=REVISION
        )
        == 19
    )
    environment[field] = "different"
    with pytest.raises(ValueError, match="Main controller"):
        verify_promotion_controller(
            environment, repository="Dream1216/omnigent", revision=REVISION
        )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "late-publisher-failure",
        "run",
        "attempt",
        "workflow",
        "event",
        "branch",
        "product",
        "repository",
        "fork",
        "artifact-run",
        "artifact-attempt-time",
        "artifact-expired",
        "artifact-repository",
        "producer-attempt",
        "producer-failed",
        "source-runtime-context",
        "preflight-failed",
        "missing-migration",
        "duplicate-job",
        "missing-upload",
        "upload-failed",
    ],
)
def test_cross_run_binds_the_actual_producer_and_upload_attempt(main_producer, fault) -> None:
    run, jobs, artifact = [main_producer[key] for key in ("run", "jobs", "artifact")]
    if fault == "late-publisher-failure":
        run["conclusion"] = "failure"
    elif fault in {"run", "attempt", "workflow", "event", "branch", "product"}:
        field = {
            "run": "id",
            "attempt": "run_attempt",
            "workflow": "path",
            "event": "event",
            "branch": "head_branch",
            "product": "head_sha",
        }[fault]
        run[field] = "different"
    elif fault in {"repository", "fork"}:
        run["repository" if fault == "repository" else "head_repository"]["id"] = 20
    elif fault == "artifact-run":
        artifact["workflow_run"]["id"] = 24
    elif fault == "artifact-attempt-time":
        artifact["created_at"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    elif fault == "artifact-expired":
        artifact["expired"] = True
    elif fault == "artifact-repository":
        artifact["workflow_run"]["head_repository_id"] = 20
    elif fault == "producer-attempt":
        jobs[1]["run_attempt"] = 1
    elif fault in {"producer-failed", "preflight-failed"}:
        jobs[1 if fault == "producer-failed" else 0]["conclusion"] = "failure"
    elif fault == "source-runtime-context":
        jobs[1]["steps"][-1]["conclusion"] = "success"
    elif fault == "missing-migration":
        jobs.pop()
    elif fault == "duplicate-job":
        jobs.append(copy.deepcopy(jobs[0]))
    elif fault == "missing-upload":
        jobs[1]["steps"] = []
    elif fault == "upload-failed":
        jobs[1]["steps"][0]["conclusion"] = "failure"

    def verify():
        return verify_trusted_main_source(
            run,
            jobs,
            artifact,
            repository="Dream1216/omnigent",
            repository_id=19,
            revision=REVISION,
            run_id=23,
            run_attempt=2,
            artifact_id=17,
            zip_sha256="b" * 64,
        )

    if fault in {None, "late-publisher-failure"}:
        result = verify()
        assert result["source_run_id"] == 23 and result["source_run_attempt"] == 2
        assert result["source_producer_job_id"] == 32
    else:
        with pytest.raises(ValueError):
            verify()


@pytest.mark.parametrize(
    ("command", "fault"),
    [
        ("download-trusted-main", fault)
        for fault in [None, "wrong-attempt", "tampered-zip", "missing-platform", "expired-scans"]
    ]
    + [("verify-trusted-main", None), ("verify-trusted-main", "wrong-attempt")],
)
def test_cross_run_download_reuses_original_oci_and_security_checks(
    tmp_path, monkeypatch, capsys, main_producer, command, fault
) -> None:
    source = tmp_path / "source"
    labels, now = candidate(source)
    if fault == "expired-scans":
        refresh_scan_time(source, now - timedelta(hours=26))
        now -= timedelta(hours=25)
    manifest = seal(source, labels, now)
    if fault == "missing-platform":
        del manifest["images"]["host"]["facts"]["platforms"]["linux/arm64"]
    write_json(source / MANIFEST_NAME, manifest)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        for member in source.rglob("*"):
            if member.is_file():
                bundle.write(member, member.relative_to(source))
    zip_bytes = archive.getvalue()
    zip_sha = hashlib.sha256(zip_bytes).hexdigest()
    main_producer["artifact"]["digest"] = "sha256:" + zip_sha
    if fault == "wrong-attempt":
        main_producer["jobs"][1]["run_attempt"] = 1
    for key, value in main_producer["controller"].items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(oci_promotion, "expected_labels", lambda repo, revision: labels)
    downloads = []

    def metadata(args, **kwargs):
        endpoint = args[-1]
        if endpoint.endswith("/jobs?per_page=100"):
            jobs = main_producer["jobs"]
            return json.dumps([{"jobs": jobs[:2]}, {"jobs": jobs[2:]}])
        return json.dumps(
            main_producer["artifact"] if "/artifacts/" in endpoint else main_producer["run"]
        )

    def transfer(args, *, stdout, check):
        assert args == ["gh", "api", "repos/Dream1216/omnigent/actions/artifacts/17/zip"]
        downloads.append(args)
        stdout.write(zip_bytes + (b"tamper" if fault == "tampered-zip" else b""))

    monkeypatch.setattr(oci_promotion.subprocess, "check_output", metadata)
    monkeypatch.setattr(oci_promotion.subprocess, "run", transfer)
    destination = tmp_path / "download"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "oci_promotion",
            command,
            "--root",
            str(destination),
            "--revision",
            REVISION,
            "--source-date-epoch",
            str(EPOCH),
            "--repository",
            "Dream1216/omnigent",
            "--run-id",
            "23",
            "--run-attempt",
            "2",
            "--artifact-id",
            "17",
            "--artifact-sha256",
            zip_sha,
            "--manifest-sha256",
            file_sha256(source / MANIFEST_NAME),
        ],
    )
    if fault not in {None, "expired-scans"}:
        with pytest.raises(ValueError):
            oci_promotion.main()
        assert not (destination / "promotion-source.json").exists()
        assert bool(downloads) == (fault != "wrong-attempt")
        return
    assert oci_promotion.main() == 0
    if command == "verify-trusted-main":
        receipt = json.loads(capsys.readouterr().out)
        assert receipt["source_run_id"] == 23 and receipt["source_run_attempt"] == 2
        assert receipt["artifact_sha256"] == zip_sha
        assert downloads == [] and not destination.exists()
        return
    assert len(downloads) == 1
    if fault == "expired-scans":
        with pytest.raises(ValueError, match="older than 24 hours"):
            verify_candidate(
                destination,
                manifest_sha256=file_sha256(source / MANIFEST_NAME),
                labels=labels,
                source_date_epoch=EPOCH,
            )
        return
    assert (
        verify_candidate(
            destination,
            manifest_sha256=file_sha256(source / MANIFEST_NAME),
            labels=labels,
            source_date_epoch=EPOCH,
        )
        == manifest
    )
    for name in ("server", "host"):
        assert (
            file_sha256(destination / f"{name}-1.tar")
            == manifest["images"][name]["archive_sha256"]
        )
        verify_readback(destination / f"{name}-1.tar", manifest["images"][name])
    receipt = json.loads((destination / "promotion-source.json").read_text())
    assert receipt["source_run_attempt"] == 2 and receipt["artifact_sha256"] == zip_sha


def test_zip_sha_and_path_traversal_fail_closed(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../outside", "not allowed")
    with pytest.raises(ValueError, match="ZIP digest"):
        extract_artifact(archive, tmp_path / "wrong-sha", zip_sha256="0" * 64)
    with pytest.raises(ValueError, match="unsafe"):
        extract_artifact(archive, tmp_path / "unsafe", zip_sha256=file_sha256(archive))
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("kind", ["symlink", "traversal", "duplicate"])
def test_oci_extraction_rejects_links_traversal_and_duplicates(tmp_path: Path, kind: str) -> None:
    archive = tmp_path / "unsafe.tar"
    with tarfile.open(archive, "w") as bundle:
        member = tarfile.TarInfo("../outside" if kind == "traversal" else "index.json")
        if kind == "symlink":
            member.type, member.linkname = tarfile.SYMTYPE, "../outside"
        else:
            member.size = 2
        bundle.addfile(member, None if kind == "symlink" else io.BytesIO(b"{}"))
        if kind == "duplicate":
            bundle.addfile(member, io.BytesIO(b"{}"))
    with pytest.raises(ValueError, match="unsafe or duplicate"):
        extract_layout(archive, tmp_path / "layout")
    assert not (tmp_path / "outside").exists()


def test_workflow_never_rebuilds_after_candidate_admission() -> None:
    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    build, publish = workflow["jobs"]["build-candidate"], workflow["jobs"]["publish-signed"]
    assert (
        len(
            [
                step
                for step in build["steps"]
                if step.get("uses") == "./saas/actions/build-oci-candidate"
            ]
        )
        == 4
    )
    assert all("build-push-action" not in step.get("uses", "") for step in publish["steps"])
    assert all("setup-buildx-action" not in step.get("uses", "") for step in publish["steps"])
    names = [step["name"] for step in publish["steps"]]
    assert names.index("Read back promoted OCI bytes before signing") < names.index(
        "Sign server image provenance with GitHub OIDC"
    )
    assert workflow["jobs"]["verify-published-source"]["needs"] == ["publish-signed"]
    assert publish["needs"] == ["source-context", "build-candidate"]
    assert "needs.source-context.result == 'success'" in publish["if"]
    assert "!cancelled() &&" in publish["if"]
    assert "needs.build-candidate.result == 'success'" in publish["if"]
    assert "needs.build-candidate.result == 'skipped'" in publish["if"]
    for name in [
        "verify-candidate-preflight",
        "verify-production-migration-replay",
        "build-candidate",
    ]:
        assert "inputs.promotion_source_run_id == ''" in workflow["jobs"][name]["if"]
        assert "needs.source-context.outputs.mode == 'same-main'" in workflow["jobs"][name]["if"]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "legacy",
        "ref",
        "revision",
        "promotion_source_run_id",
        "promotion_source_run_attempt",
        "promotion_artifact_id",
        "promotion_artifact_sha256",
        "promotion_manifest_sha256",
        "partial-legacy",
        "invalid-id",
        "invalid-sha",
        "runtime-evidence",
    ],
)
def test_protected_promotion_coordinates_fail_before_transfer(fault) -> None:
    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    step = workflow["jobs"]["publish-signed"]["steps"][0]
    coordinates = {
        "PROMOTION_SOURCE_RUN_ID": "23",
        "PROMOTION_SOURCE_RUN_ATTEMPT": "2",
        "PROMOTION_ARTIFACT_ID": "17",
        "PROMOTION_ARTIFACT_SHA256": "b" * 64,
        "PROMOTION_MANIFEST_SHA256": "c" * 64,
    }
    if fault == "legacy":
        coordinates = dict.fromkeys(coordinates, "")
    elif fault == "partial-legacy":
        coordinates["PROMOTION_SOURCE_RUN_ID"] = ""
    elif fault and fault.startswith("promotion_"):
        coordinates[fault.upper()] = ""
    elif fault == "invalid-id":
        coordinates["PROMOTION_SOURCE_RUN_ID"] = "0"
    elif fault == "invalid-sha":
        coordinates["PROMOTION_ARTIFACT_SHA256"] = "not-a-digest"
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        capture_output=True,
        text=True,
        env={
            **coordinates,
            "TRUSTED_REF": "refs/heads/topic" if fault == "ref" else "refs/heads/main",
            "TRUSTED_REVISION": REVISION,
            "PRODUCT_REVISION": "d" * 40 if fault == "revision" else REVISION,
            "PROMOTION_RUNTIME_EVIDENCE_REVISION": "d" * 40 if fault == "runtime-evidence" else "",
        },
    )
    assert (result.returncode == 0) == (fault in {None, "legacy"})


def test_policy_rejects_reintroduced_post_admission_builder(tmp_path: Path) -> None:
    repo = _candidate_contract_repo(tmp_path)
    workflow = repo / ".github/workflows/saas-image-candidate.yml"
    text = workflow.read_text()
    text = text.replace(
        "      - name: Promote admitted server OCI without rebuilding",
        "      - uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf\n"
        "      - name: Promote admitted server OCI without rebuilding",
    )
    workflow.write_text(text)
    assert (
        "protected release must promote the admitted OCI bytes without rebuilding"
        in validate_candidate_build_contract(repo)
    )


@pytest.mark.parametrize(
    "target",
    [
        (
            "!cancelled() &&\n      needs.source-context.result == 'success' &&\n"
            "      github.event_name == 'workflow_dispatch' &&"
        ),
        "inputs.promotion_source_run_id == '' && needs.build-candidate.result == 'success'",
        "inputs.promotion_source_run_id != '' && needs.build-candidate.result == 'skipped'",
        (
            "if: ${{ !inputs.diagnostic_host_only && inputs.promotion_source_run_id == '' "
            "&& needs.source-context.outputs.mode == 'same-main' }}"
        ),
        "python -m saas.scripts.oci_promotion download-trusted-main",
        '[[ "$PROMOTION_ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]]',
        (
            '[[ -z "$PROMOTION_SOURCE_RUN_ATTEMPT$PROMOTION_ARTIFACT_ID'
            '$PROMOTION_ARTIFACT_SHA256$PROMOTION_MANIFEST_SHA256" ]]'
        ),
        "needs: [publish-signed]",
        "python -m saas.scripts.oci_promotion verify-trusted-main",
        ".[0] == (.[1] | del(.state, .candidate_manifest_sha256))",
        ".promotion.source_proof_sha256 == $proof",
    ],
)
def test_cross_run_policy_rejects_bypassed_origin_binding(tmp_path, target) -> None:
    repo = _candidate_contract_repo(tmp_path)
    workflow = repo / ".github/workflows/saas-image-candidate.yml"
    source = workflow.read_text()
    assert target in source
    workflow.write_text(source.replace(target, "removed-origin-binding", 1))
    assert (
        "cross-run promotion must independently bind a qualified trusted Main producer"
        in validate_candidate_build_contract(repo)
    )


@pytest.mark.parametrize(
    ("step_name", "target"),
    [
        (
            "Classify exact product and controller inputs before any build",
            "fixed_main16_ci_promotion classify",
        ),
        (
            "Validate protected release coordinates",
            '[[ "$PROMOTION_ARTIFACT_ID" == "14210895004" ]] || exit 1',
        ),
        (
            "Validate protected release coordinates",
            '[[ "$PRODUCT_REVISION" == "$TRUSTED_REVISION" ]] || exit 1',
        ),
        ("Build and verify the SaaS wheel", "fixed_main16_ci_promotion check-wheel"),
        (
            "Download and validate original admitted OCI artifact",
            'cp "${RUNNER_TEMP}/admitted-oci/promotion-source.json" artifacts/',
        ),
        (
            "Verify wheel signature identity and revision",
            '--source-digest "$SIGNING_POLICY_REVISION"',
        ),
        (
            "Verify image signatures and protected workflow identity",
            "fixed_main16_ci_promotion verify-predicate",
        ),
        (
            "Independently verify fixed-product wheel and controller provenance",
            "fixed_main16_ci_promotion check-wheel",
        ),
        (
            "Independently verify registry digests, source labels and signatures",
            "fixed_main16_ci_promotion verify-predicate",
        ),
        (
            "Independently verify cross-run producer origin",
            ".controller_context == $origin[0].controller_context",
        ),
        (
            "Preflight scan exact server candidate on both architectures",
            "GH_TOKEN: ${{ github.token }}",
        ),
        ("Scan exact OCI candidates on both architectures", "GH_TOKEN: ${{ github.token }}"),
        ("Scan signed image digests on both architectures", "GH_TOKEN: ${{ github.token }}"),
        ("Stage signed wheel and bundle together", 'cp -- "$WHEEL_BUNDLE_PATH"'),
        ("Upload signed wheel and checksum", "path: ${{ runner.temp }}/signed-wheel/"),
        ("Install hash-pinned Syft and Grype", "GH_TOKEN: ${{ github.token }}"),
        ("Install hash-pinned Syft and Grype", "gh release download v1.54.1"),
        ("Install hash-pinned Syft and Grype", "gh release download v0.120.1"),
        ("Install hash-pinned Syft and Grype", "sha256sum --check --strict"),
    ],
)
def test_fixed_product_policy_rejects_erased_controller_boundary(tmp_path, step_name, target):
    repo = _candidate_contract_repo(tmp_path)
    path = repo / ".github/workflows/saas-image-candidate.yml"
    source = path.read_text()
    marker = f"      - name: {step_name}\n"
    before, tail = source.split(marker, 1)
    step, separator, after = tail.partition("\n      - name:")
    assert target in step
    path.write_text(
        before
        + marker
        + step.replace(target, "removed-controller-boundary", 1)
        + separator
        + after
    )
    assert (
        "fixed-product controller promotion must keep exact source, "
        "signatures and build classification" in validate_candidate_build_contract(repo)
    )


@pytest.mark.parametrize("fault", ["late", "duplicate", "early", "predicate-after-sign"])
def test_fixed_product_policy_requires_proof_before_its_consumers(tmp_path, fault):
    repo = _candidate_contract_repo(tmp_path)
    path = repo / ".github/workflows/saas-image-candidate.yml"
    source = path.read_text()
    transfer = (
        '          if [[ -n "$PROMOTION_SOURCE_RUN_ID" ]]; then\n'
        '            cp "${RUNNER_TEMP}/admitted-oci/promotion-source.json" artifacts/\n'
        "          fi\n"
    )
    assert source.count(transfer) == 1
    if fault in {"late", "duplicate"}:
        if fault == "late":
            source = source.replace(transfer, "", 1)
        anchor = (
            '          cp "${RUNNER_TEMP}/admitted-oci/oci-promotion-manifest.json" artifacts/\n'
        )
        source = source.replace(anchor, anchor + transfer, 1)
    elif fault == "early":
        source = source.replace(transfer, "", 1)
        anchor = '          source_epoch=$(git show -s --format=%ct "$PRODUCT_REVISION")\n'
        source = source.replace(anchor, anchor + transfer, 1)
    else:
        start = source.index(
            "      - name: Generate explicit fixed-product controller provenance\n"
        )
        end = source.index("      - name: Sign wheel provenance with GitHub OIDC\n", start)
        producer = source[start:end]
        source = source[:start] + source[end:]
        anchor = "      - name: Verify wheel signature identity and revision\n"
        source = source.replace(anchor, producer + anchor, 1)
    path.write_text(source)
    assert (
        "fixed-product controller promotion must keep exact source, "
        "signatures and build classification" in validate_candidate_build_contract(repo)
    )


@pytest.mark.parametrize("wheel_count", [0, 1, 2])
def test_signed_wheel_upload_stages_original_bytes_for_independent_consumer(tmp_path, wheel_count):
    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    publisher = {step.get("name"): step for step in workflow["jobs"]["publish-signed"]["steps"]}
    independent = {
        step.get("name"): step for step in workflow["jobs"]["verify-published-source"]["steps"]
    }
    dist = tmp_path / "dist"
    dist.mkdir()
    for index in range(wheel_count):
        (dist / f"original-{index}.whl").write_bytes(b"original-wheel-" + bytes([index]))
    (dist / "SHA256SUMS").write_bytes(b"original-checksum-bytes\n")
    bundle = tmp_path / "_temp/random-attestation-directory/attestation.json"
    bundle.parent.mkdir(parents=True)
    bundle.write_bytes(b'{"original":"attestation bytes"}\n')
    result = subprocess.run(
        ["bash", "-c", publisher["Stage signed wheel and bundle together"]["run"]],
        cwd=tmp_path,
        env={**os.environ, "RUNNER_TEMP": str(tmp_path), "WHEEL_BUNDLE_PATH": str(bundle)},
        capture_output=True,
        text=True,
    )
    if wheel_count != 1:
        assert result.returncode != 0
        assert not (tmp_path / "signed-wheel").exists()
        return
    assert result.returncode == 0, result.stderr
    assert publisher["Upload signed wheel and checksum"]["with"]["path"] == (
        "${{ runner.temp }}/signed-wheel/"
    )
    original = {
        "original-0.whl": (dist / "original-0.whl").read_bytes(),
        "SHA256SUMS": (dist / "SHA256SUMS").read_bytes(),
        "attestation.json": bundle.read_bytes(),
    }
    archive = tmp_path / "uploaded-wheel.zip"
    with zipfile.ZipFile(archive, "w") as output:
        for member in (tmp_path / "signed-wheel").iterdir():
            output.write(member, member.name)
    with zipfile.ZipFile(archive) as uploaded:
        assert uploaded.testzip() is None
        assert {name: uploaded.read(name) for name in uploaded.namelist()} == original
        uploaded.extractall(tmp_path / "independent-wheel")
    consumer = independent["Independently verify fixed-product wheel and controller provenance"]
    selection = consumer["run"].split(
        "python -m saas.scripts.fixed_main16_ci_promotion check-wheel"
    )[0]
    selected = subprocess.run(
        ["bash", "-c", selection + '\nprintf "%s" "$wheel"'],
        env={**os.environ, "RUNNER_TEMP": str(tmp_path)},
        capture_output=True,
        text=True,
    )
    assert selected.returncode == 0, selected.stderr
    assert Path(selected.stdout).read_bytes() == original["original-0.whl"]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "product",
        "controller",
        "context",
        "source",
        "attempt",
        "artifact",
        "zip",
        "seal",
        "runtime-evidence",
        "profile",
    ],
)
def test_fixed_product_header_rejects_mixed_coordinates_before_transfer(fault):
    from saas.scripts import fixed_main16_ci_promotion as fixed

    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    step = workflow["jobs"]["publish-signed"]["steps"][0]
    environment = {
        "TRUSTED_REF": "refs/heads/main",
        "TRUSTED_REVISION": "a" * 40,
        "PRODUCT_REVISION": fixed.PRODUCT,
        "PROMOTION_CONTROLLER_PROFILE": fixed.MODE,
        "SOURCE_CONTEXT_MODE": fixed.MODE,
        "PROMOTION_SOURCE_RUN_ID": str(fixed.SOURCE_RUN),
        "PROMOTION_SOURCE_RUN_ATTEMPT": "1",
        "PROMOTION_ARTIFACT_ID": str(fixed.ARTIFACT),
        "PROMOTION_ARTIFACT_SHA256": fixed.ZIP_SHA256,
        "PROMOTION_MANIFEST_SHA256": fixed.SEAL_SHA256,
        "PROMOTION_RUNTIME_EVIDENCE_REVISION": "",
    }
    key = {
        "product": "PRODUCT_REVISION",
        "context": "SOURCE_CONTEXT_MODE",
        "source": "PROMOTION_SOURCE_RUN_ID",
        "attempt": "PROMOTION_SOURCE_RUN_ATTEMPT",
        "artifact": "PROMOTION_ARTIFACT_ID",
        "zip": "PROMOTION_ARTIFACT_SHA256",
        "seal": "PROMOTION_MANIFEST_SHA256",
        "runtime-evidence": "PROMOTION_RUNTIME_EVIDENCE_REVISION",
        "profile": "PROMOTION_CONTROLLER_PROFILE",
    }.get(fault)
    if key:
        environment[key] = "different"
    elif fault == "controller":
        environment["TRUSTED_REVISION"] = fixed.PRODUCT
    result = subprocess.run(["bash", "-c", step["run"]], capture_output=True, env=environment)
    assert (result.returncode == 0) is (fault is None)


def test_crane_promotes_and_reads_back_original_oci_index(tmp_path: Path) -> None:
    crane = os.environ.get("OCI_PROMOTION_TEST_CRANE")
    if not crane:
        pytest.skip("real crane round-trip is enabled in candidate preflight")
    grype = os.environ.get("OCI_PROMOTION_TEST_GRYPE")
    options: dict[str, Any] = {}
    if grype:
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as archive:
            marker = b"registry subject contract\n"
            member = tarfile.TarInfo("opt/registry-subject.txt")
            member.size = len(marker)
            archive.addfile(member, io.BytesIO(marker))
        options = {"layer_payload": layer.getvalue(), "config_os": "linux"}
    labels, now = candidate(tmp_path / "candidate", **options)
    manifest = seal(tmp_path / "candidate", labels, now)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        address = f"127.0.0.1:{reservation.getsockname()[1]}"
    with (tmp_path / "registry.log").open("wb") as log:
        registry = subprocess.Popen(
            [crane, "registry", "serve", "--address", address], stdout=log, stderr=log
        )
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    with urllib.request.urlopen(f"http://{address}/v2/", timeout=1):
                        break
                except OSError:
                    assert registry.poll() is None
                    if time.monotonic() >= deadline:
                        raise AssertionError("temporary registry did not start") from None
                    time.sleep(0.05)
            for name in ("server", "host"):
                layout = tmp_path / name
                extract_layout(tmp_path / "candidate" / f"{name}-1.tar", layout)
                tag = f"{address}/omnigent-saas-{name}:candidate"
                subprocess.run([crane, "push", str(layout), tag], check=True, capture_output=True)
                digest = subprocess.check_output([crane, "digest", tag], text=True).strip()
                assert digest == manifest["images"][name]["index_digest"]
                if grype:
                    facts = inspect_oci_archive(
                        tmp_path / "candidate" / f"{name}-1.tar", label_profile="executable"
                    )
                    for platform, expected in facts["platforms"].items():
                        subject = f"{address}/omnigent-saas-{name}@{expected['manifest_digest']}"
                        reports = Path(
                            os.environ.get(
                                "OCI_PROMOTION_TEST_REPORT_DIRECTORY", tmp_path / "scanner-reports"
                            )
                        )
                        reports.mkdir(parents=True, exist_ok=True)
                        prefix = reports / f"{name}-{platform.split('/')[-1]}"
                        raw = prefix.with_suffix(".raw.grype.json")
                        with (
                            raw.open("wb") as output,
                            prefix.with_suffix(".stderr.txt").open("wb") as errors,
                        ):
                            subprocess.run(
                                [
                                    grype,
                                    f"registry:{subject}",
                                    "--platform",
                                    platform,
                                    "-o",
                                    "json",
                                ],
                                env={
                                    **os.environ,
                                    "GRYPE_REGISTRY_INSECURE_USE_HTTP": "true",
                                    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                                },
                                stdout=output,
                                stderr=errors,
                                timeout=180,
                                check=True,
                            )
                        report = json.loads(raw.read_bytes())
                        target = report["source"]["target"]
                        assert target["manifestDigest"] == expected["manifest_digest"]
                        assert target["imageID"] == expected["config_digest"]
                        assert target["architecture"] == platform.split("/")[-1]
                        assert target["os"] == "linux"
                        assert target["labels"] == expected["labels"]
                readback = tmp_path / f"{name}-readback.tar"
                readback_layout = tmp_path / f"{name}-readback-layout"
                subprocess.run(
                    [crane, "pull", "--format=oci", "--platform=all", tag, str(readback_layout)],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "tar",
                        "-cf",
                        str(readback),
                        "-C",
                        str(readback_layout),
                        "oci-layout",
                        "index.json",
                        "blobs",
                    ],
                    check=True,
                )
                verify_readback(readback, manifest["images"][name])
        finally:
            registry.terminate()
            registry.wait(timeout=5)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "runtime",
        "lock",
        "other-workflow",
        "other-helper",
        "unregistered",
        "deleted",
        "renamed",
        "type-change",
        "empty",
    ],
)
def test_fixed_main16_controller_paths_fail_closed(fault) -> None:
    from saas.scripts import fixed_main16_ci_promotion as fixed

    changes = {oci_promotion.TRUSTED_WORKFLOW: "M"}
    registered = set(fixed.CI_ONLY_PATHS)
    invalid_paths = {
        "runtime": "omnigent/inner/codex_native_executor.py",
        "lock": "saas/supply_chain/wolfi-runtime-lock.json",
        "other-workflow": ".github/workflows/ci.yml",
        "other-helper": "saas/scripts/resume_oci_promotion.py",
    }
    if fault in invalid_paths:
        changes[invalid_paths[fault]] = "M"
        registered.add(invalid_paths[fault])
    elif fault == "unregistered":
        registered.clear()
    elif fault in {"deleted", "renamed", "type-change"}:
        changes[oci_promotion.TRUSTED_WORKFLOW] = {
            "deleted": "D",
            "renamed": "R100",
            "type-change": "T",
        }[fault]
    elif fault == "empty":
        changes.clear()
    if fault is None:
        fixed.validate_ci_only_paths(changes, registered)
    else:
        with pytest.raises(ValueError, match="registered CI-only"):
            fixed.validate_ci_only_paths(changes, registered)


@pytest.mark.parametrize("fault", [None, "finite", "profile", "product-tree", "baseline"])
def test_fixed_main16_static_scope_keeps_full_guard(tmp_path, monkeypatch, fault) -> None:
    from saas.scripts import fixed_main16_ci_promotion as fixed

    revision = "c" * 40
    budget = {fixed.PROFILE_KEY: {"mode": fixed.MODE, "product_revision": fixed.PRODUCT}}
    if fault == "profile":
        budget[fixed.PROFILE_KEY]["product_revision"] = "d" * 40
    scope = {
        "candidate_manifest_sha256": "e" * 64,
        "files": [{"path": oci_promotion.TRUSTED_WORKFLOW}],
        "governance_paths": sorted(fixed.GOVERNANCE_PATHS),
    }
    for path, value in (
        (fixed.BUDGET_PATH, budget),
        (fixed.SCOPE_PATH, scope),
        ("saas/upstream-baseline.json", {"upstream_revision": "a" * 40}),
    ):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        write_json(target, value)
    workflow = tmp_path / oci_promotion.TRUSTED_WORKFLOW
    workflow.write_text("fixed workflow\n")
    calls = []

    def full_guard(repo, manifest):
        calls.append((repo, manifest))
        return fault != "finite"

    def git(repo, *arguments):
        if arguments == ("rev-parse", "HEAD"):
            return revision
        if arguments == ("rev-parse", f"{fixed.PRODUCT}^{{tree}}"):
            return "f" * 40 if fault == "product-tree" else fixed.PRODUCT_TREE
        if arguments[0] == "show":
            return json.dumps({"upstream_revision": "b" * 40 if fault == "baseline" else "a" * 40})
        if arguments[0] == "diff":
            return "M\t" + oci_promotion.TRUSTED_WORKFLOW
        if arguments == ("rev-parse", "HEAD^{tree}"):
            return "1" * 40
        assert arguments == ("merge-base", "--is-ancestor", fixed.PRODUCT, revision)
        return ""

    monkeypatch.setattr(fixed, "_ordinary_m_candidate_matches", full_guard)
    monkeypatch.setattr(fixed, "_git", git)
    if fault is None:
        proof = fixed._classify_clean_tree(tmp_path, revision)
        assert proof["product_revision"] == fixed.PRODUCT
        assert proof["controller_revision"] == revision
        assert proof["controller_changed_paths"][0]["sha256"] == file_sha256(workflow)
        assert calls == [(tmp_path, budget)]
    else:
        with pytest.raises(ValueError):
            fixed._classify_clean_tree(tmp_path, revision)
        if fault != "profile":
            assert calls == [(tmp_path, budget)]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "controller",
        "substitute-product-run",
        "mixed-head",
        "fork",
        "attempt",
        "expired-created-recent-updated",
        "future",
        "job-failed",
        "job-attempt",
        "skipped-only",
        "missing-workflow",
    ],
)
def test_fixed_main16_dual_core_uses_native_identity_and_clocks(main_producer, fault) -> None:
    from saas.scripts import fixed_main16_ci_promotion as fixed

    now = datetime.now(UTC)
    revision = "c" * 40 if fault == "controller" else fixed.PRODUCT
    rows = []
    for index, (path, identifier) in enumerate(fixed.PRODUCT_CORE.items()):
        if fault == "controller":
            identifier += 1000
        run = {
            **copy.deepcopy(main_producer["run"]),
            "id": identifier,
            "path": path,
            "head_sha": revision,
            "run_attempt": 1,
            "created_at": (now - timedelta(minutes=5)).isoformat(),
            "updated_at": (now - timedelta(minutes=1)).isoformat(),
        }
        job = {
            **copy.deepcopy(main_producer["jobs"][0]),
            "id": 1000 + index,
            "run_id": identifier,
            "run_attempt": 1,
            "head_sha": revision,
            "started_at": run["created_at"],
            "completed_at": run["updated_at"],
        }
        rows.append({"run": run, "jobs": [job]})
    run, job = rows[0]["run"], rows[0]["jobs"][0]
    if fault == "substitute-product-run":
        run["id"] += 1
        job["run_id"] = run["id"]
    elif fault == "mixed-head":
        run["head_sha"] = "c" * 40
    elif fault == "fork":
        run["head_repository"]["id"] = 20
    elif fault == "attempt":
        run["run_attempt"] = 2
    elif fault == "expired-created-recent-updated":
        run["created_at"] = (now - timedelta(hours=25)).isoformat()
    elif fault == "future":
        run["updated_at"] = (now + timedelta(minutes=1)).isoformat()
    elif fault == "job-failed":
        job["conclusion"] = "failure"
    elif fault == "job-attempt":
        job["run_attempt"] = 2
    elif fault == "skipped-only":
        job["conclusion"] = "skipped"
    elif fault == "missing-workflow":
        rows.pop()
    if fault in {None, "controller"}:
        result = fixed.verify_core_ci(rows, revision=revision, repository_id=19, now=now)
        assert result == fixed.verify_core_ci(
            list(reversed(rows)),
            revision=revision,
            repository_id=19,
            now=now + timedelta(seconds=1),
        )
        assert {row["run"]["head_sha"] for row in result} == {revision}
    else:
        with pytest.raises(ValueError):
            fixed.verify_core_ci(rows, revision=revision, repository_id=19, now=now)


@pytest.mark.parametrize(
    "field",
    [None, "revision", "run_id", "run_attempt", "artifact_id", "zip_sha256", "manifest_sha256"],
)
def test_fixed_main16_source_coordinates_are_not_generalized(field) -> None:
    from saas.scripts import fixed_main16_ci_promotion as fixed

    values = {
        "revision": fixed.PRODUCT,
        "run_id": fixed.SOURCE_RUN,
        "run_attempt": fixed.SOURCE_ATTEMPT,
        "artifact_id": fixed.ARTIFACT,
        "zip_sha256": fixed.ZIP_SHA256,
        "manifest_sha256": fixed.SEAL_SHA256,
    }
    if field is None:
        fixed.require_source_coordinates(**values)
    else:
        values[field] = 2 if type(values[field]) is int else "0" * len(values[field])
        with pytest.raises(ValueError, match="original product/source/archive/seal"):
            fixed.require_source_coordinates(**values)


@pytest.mark.parametrize("fault", [None, "source-head", "source-prerequisite", "upload-time"])
def test_fixed_controller_resolver_keeps_original_source_verifier(
    main_producer, monkeypatch, fault
):
    from saas.scripts import fixed_main16_ci_promotion as fixed

    run, jobs, artifact = (main_producer[key] for key in ("run", "jobs", "artifact"))
    run.update(id=fixed.SOURCE_RUN, run_attempt=1, head_sha=fixed.PRODUCT)
    for job in jobs:
        job.update(run_id=fixed.SOURCE_RUN, run_attempt=1, head_sha=fixed.PRODUCT)
    artifact.update(
        id=fixed.ARTIFACT,
        name=f"saas-oci-promotion-{fixed.PRODUCT}",
        digest="sha256:" + fixed.ZIP_SHA256,
    )
    artifact["workflow_run"].update(id=fixed.SOURCE_RUN, head_sha=fixed.PRODUCT)
    context = {"mode": fixed.MODE, "controller_revision": "c" * 40}
    monkeypatch.setattr(fixed, "controller_context", lambda **kwargs: (19, context))

    def native_metadata(arguments, **kwargs):
        endpoint = arguments[-1]
        if endpoint.endswith("/jobs?per_page=100"):
            return json.dumps([{"jobs": jobs}])
        return json.dumps(artifact if "/artifacts/" in endpoint else run)

    monkeypatch.setattr(oci_promotion.subprocess, "check_output", native_metadata)
    if fault == "source-head":
        run["head_sha"] = "c" * 40
    elif fault == "source-prerequisite":
        jobs[0]["conclusion"] = "failure"
    elif fault == "upload-time":
        artifact["created_at"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    values = {
        "repository": oci_promotion.TRUSTED_REPOSITORY,
        "revision": fixed.PRODUCT,
        "run_id": fixed.SOURCE_RUN,
        "run_attempt": 1,
        "artifact_id": fixed.ARTIFACT,
        "zip_sha256": fixed.ZIP_SHA256,
        "manifest_sha256": fixed.SEAL_SHA256,
        "controller_profile": fixed.MODE,
    }
    if fault is None:
        proof = fixed.resolve_trusted_main_source(**values)
        assert proof["controller_context"] == context
        assert proof["product_revision"] == fixed.PRODUCT
        assert proof["source_run_id"] == fixed.SOURCE_RUN
    else:
        with pytest.raises(ValueError):
            fixed.resolve_trusted_main_source(**values)


@pytest.mark.parametrize("fault", [None, "controller-commit", "epoch", "version"])
def test_fixed_main16_wheel_embeds_product_not_controller(tmp_path, fault):
    from saas.scripts import fixed_main16_ci_promotion as fixed

    revision = "c" * 40 if fault == "controller-commit" else fixed.PRODUCT
    epoch = fixed.PRODUCT_EPOCH + 1 if fault == "epoch" else fixed.PRODUCT_EPOCH
    version = "0.22.0" if fault == "version" else "0.21.0.dev20261031"
    wheel = tmp_path / "product.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "omnigent/_build_info.py",
            f"COMMIT_SHA: str = {revision!r}\nBUILD_TIME_EPOCH: int = {epoch}\n",
        )
        archive.writestr(
            "omnigent.dist-info/METADATA", f"Metadata-Version: 2.4\nVersion: {version}\n"
        )
    if fault is None:
        fixed.check_wheel(wheel)
    else:
        with pytest.raises(ValueError, match="wheel"):
            fixed.check_wheel(wheel)


def test_fixed_main16_predicate_keeps_both_revisions_and_stable_native_facts(
    main_producer, tmp_path, monkeypatch
):
    from saas.scripts import fixed_main16_ci_promotion as fixed

    controller = "c" * 40
    now = datetime.now(UTC)

    def native_core(revision):
        rows = []
        for index, (path, identifier) in enumerate(fixed.PRODUCT_CORE.items()):
            if revision == controller:
                identifier += 1000
            run = {
                **copy.deepcopy(main_producer["run"]),
                "id": identifier,
                "path": path,
                "head_sha": revision,
                "run_attempt": 1,
                "created_at": (now - timedelta(minutes=5)).isoformat(),
                "updated_at": (now - timedelta(minutes=1)).isoformat(),
            }
            job = {
                **copy.deepcopy(main_producer["jobs"][0]),
                "id": 1000 + index,
                "run_id": identifier,
                "run_attempt": 1,
                "head_sha": revision,
                "started_at": run["created_at"],
                "completed_at": run["updated_at"],
            }
            rows.append({"run": run, "jobs": [job]})
        return fixed.verify_core_ci(rows, revision=revision, repository_id=19, now=now)

    source = {
        "repository": oci_promotion.TRUSTED_REPOSITORY,
        "product_revision": fixed.PRODUCT,
        "source_run_id": fixed.SOURCE_RUN,
        "source_run_attempt": 1,
        "source_producer_job_id": 133136433428,
        "artifact_id": fixed.ARTIFACT,
        "artifact_sha256": fixed.ZIP_SHA256,
        "controller_context": {
            "mode": fixed.MODE,
            "product_revision": fixed.PRODUCT,
            "product_tree": fixed.PRODUCT_TREE,
            "controller_revision": controller,
            "controller_tree": "d" * 40,
            "repository_id": 19,
            "product_core": native_core(fixed.PRODUCT),
            "controller_core": native_core(controller),
        },
    }
    binding = fixed.promotion_binding(source)
    source["state"] = "trusted_source_transferred_requires_current_prepare"
    source["candidate_manifest_sha256"] = fixed.SEAL_SHA256
    assert binding == fixed.promotion_binding(source)
    predicate = fixed.build_promotion_predicate(
        binding, oci_promotion.TRUSTED_WORKFLOW, controller, "101", "1"
    )
    dependencies = predicate["buildDefinition"]["resolvedDependencies"]
    assert dependencies[0]["digest"] == {"gitCommit": controller}
    assert dependencies[1]["digest"] == {"gitCommit": fixed.PRODUCT}
    assert dependencies[2]["digest"] == {"sha256": fixed.ZIP_SHA256}
    claims = fixed.build_certificate_claims(
        oci_promotion.TRUSTED_REPOSITORY, controller, oci_promotion.TRUSTED_WORKFLOW, "101", "1"
    )
    assert claims["sourceRepositoryDigest"] == controller

    admitted = tmp_path / "admitted-oci"
    artifacts = tmp_path / "artifacts"
    admitted.mkdir()
    artifacts.mkdir()
    (admitted / "promotion-source.json").write_text(json.dumps(source))
    target = artifacts / "promotion-source.json"
    output = artifacts / "predicate.json"
    arguments = [
        "fixed-controller",
        "predicate",
        "--source-proof",
        str(target),
        "--policy-revision",
        controller,
        "--run-id",
        "101",
        "--attempt",
        "1",
        "--output",
        str(output),
    ]
    monkeypatch.setattr(sys, "argv", arguments)
    with pytest.raises(ValueError, match="missing regular evidence file"):
        fixed.main()
    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/saas-image-candidate.yml"
    ).read_text()
    marker = "      - name: Download and validate original admitted OCI artifact\n"
    intake = workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
    transfer = 'cp "${RUNNER_TEMP}/admitted-oci/promotion-source.json" artifacts/'
    assert intake.count(transfer) == workflow.count(transfer) == 1
    subprocess.run(
        ["bash", "-eu", "-c", transfer],
        cwd=tmp_path,
        env={**os.environ, "RUNNER_TEMP": str(tmp_path)},
        check=True,
    )
    assert target.read_bytes() == (admitted / "promotion-source.json").read_bytes()
    assert fixed.main() == 0
    assert json.loads(output.read_text()) == predicate


@pytest.mark.parametrize(
    ("command", "fault"),
    [
        ("download-trusted-main", None),
        ("verify-trusted-main", None),
        ("download-trusted-main", "seal"),
        ("download-trusted-main", "platform"),
        ("download-trusted-main", "epoch"),
    ],
)
def test_fixed_main16_explicit_intake_cli_reuses_original_transfer_guards(
    tmp_path, monkeypatch, capsys, command, fault
):
    from saas.scripts import fixed_main16_ci_promotion as fixed

    labels = {"fixture": "product-labels"}
    manifest = {
        "product_revision": fixed.PRODUCT,
        "source_date_epoch": fixed.PRODUCT_EPOCH,
        "labels": labels,
        "images": {
            name: {
                "facts": {
                    "platforms": {platform: {} for platform in ("linux/amd64", "linux/arm64")}
                }
            }
            for name in ("server", "host")
        },
    }
    original = json.dumps(manifest, sort_keys=True).encode()
    seal = hashlib.sha256(original).hexdigest()
    proof = {
        "repository": oci_promotion.TRUSTED_REPOSITORY,
        "product_revision": fixed.PRODUCT,
        "source_run_id": fixed.SOURCE_RUN,
        "source_run_attempt": 1,
        "source_producer_job_id": 133136433428,
        "artifact_id": fixed.ARTIFACT,
        "artifact_sha256": fixed.ZIP_SHA256,
        "controller_context": {"mode": fixed.MODE},
    }
    calls = []

    def native_source(**values):
        assert values == {
            "repository": oci_promotion.TRUSTED_REPOSITORY,
            "revision": fixed.PRODUCT,
            "run_id": fixed.SOURCE_RUN,
            "run_attempt": 1,
            "artifact_id": fixed.ARTIFACT,
            "zip_sha256": fixed.ZIP_SHA256,
            "manifest_sha256": seal,
            "controller_profile": fixed.MODE,
        }
        calls.append("verified-source")
        return copy.deepcopy(proof)

    def transfer(endpoint, destination, *, zip_sha256):
        assert (
            endpoint
            == f"repos/{oci_promotion.TRUSTED_REPOSITORY}/actions/artifacts/{fixed.ARTIFACT}"
        )
        assert zip_sha256 == fixed.ZIP_SHA256
        calls.append("original-transfer")
        destination.mkdir()
        body = original
        if fault == "seal":
            body += b" "
        elif fault == "platform":
            changed = copy.deepcopy(manifest)
            changed["images"]["host"]["facts"]["platforms"].pop("linux/arm64")
            body = json.dumps(changed, sort_keys=True).encode()
        (destination / oci_promotion.MANIFEST_NAME).write_bytes(body)

    if fault == "platform":
        changed = copy.deepcopy(manifest)
        changed["images"]["host"]["facts"]["platforms"].pop("linux/arm64")
        seal = hashlib.sha256(json.dumps(changed, sort_keys=True).encode()).hexdigest()
    monkeypatch.setattr(fixed, "resolve_trusted_main_source", native_source)
    monkeypatch.setattr(oci_promotion, "download_artifact", transfer)
    monkeypatch.setattr(oci_promotion, "expected_labels", lambda *_: labels)
    destination = tmp_path / "transferred"
    epoch = fixed.PRODUCT_EPOCH + (1 if fault == "epoch" else 0)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fixed-main16",
            command,
            "--root",
            str(destination),
            "--revision",
            fixed.PRODUCT,
            "--source-date-epoch",
            str(epoch),
            "--repository",
            oci_promotion.TRUSTED_REPOSITORY,
            "--run-id",
            str(fixed.SOURCE_RUN),
            "--run-attempt",
            "1",
            "--artifact-id",
            str(fixed.ARTIFACT),
            "--artifact-sha256",
            fixed.ZIP_SHA256,
            "--manifest-sha256",
            seal,
            "--controller-profile",
            fixed.MODE,
        ],
    )
    if fault is not None:
        with pytest.raises(ValueError):
            fixed.main()
        assert not (destination / "promotion-source.json").exists()
        if fault == "epoch":
            assert calls == []
    else:
        assert fixed.main() == 0
        if command == "verify-trusted-main":
            assert json.loads(capsys.readouterr().out) == proof
            assert calls == ["verified-source"] and not destination.exists()
        else:
            saved = json.loads((destination / "promotion-source.json").read_text())
            assert saved["controller_context"] == proof["controller_context"]
            assert saved["state"] == "trusted_source_transferred_requires_current_prepare"
            assert saved["candidate_manifest_sha256"] == seal
            assert calls == ["verified-source", "original-transfer"]
