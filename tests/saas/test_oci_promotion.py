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
import tarfile
import time
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

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
    verify_readback,
)
from saas.scripts.scan_oci_candidates import file_sha256
from tests.saas.test_image_supply_chain import _candidate_contract_repo, _write_oci

ROOT = Path(__file__).resolve().parents[2]
REVISION = "a" * 40
EPOCH = 1791756537


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def candidate(root: Path) -> tuple[dict[str, str], datetime]:
    now = datetime.now(UTC)
    (root / "grype").mkdir(parents=True)
    comparisons, rows = {}, []
    labels: dict[str, str] = {}
    for name in ("server", "host"):
        archive = root / f"{name}-1.tar"
        _write_oci(archive, revision=REVISION, label_profile="executable", nested=True)
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


@pytest.mark.parametrize("field", ["id", "name", "expired", "digest", "run-id", "head-sha"])
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
    if field in ("run-id", "head-sha"):
        metadata["workflow_run"]["id" if field == "run-id" else "head_sha"] = "different"
    else:
        metadata[field] = "different"
    with pytest.raises(ValueError, match="exact workflow"):
        verify_artifact_metadata(
            metadata, artifact_id=17, zip_sha256="b" * 64, revision=REVISION, run_id=23
        )


def test_isolated_pr_oci_export_preserves_protected_publication_boundary() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/saas-image-candidate.yml").read_text())
    build = workflow["jobs"]["build-candidate"]
    steps = build["steps"]
    export = next(
        step for step in steps if step["name"] == "Upload unsigned OCI for isolated PR validation"
    )
    assert " ".join(export["if"].split()) == (
        "success() && github.event_name == 'pull_request' && "
        "github.event.pull_request.head.repo.full_name == github.repository"
    )
    assert export["uses"] == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    assert export["with"] == {
        "name": "saas-oci-validation-${{ env.CANDIDATE_REVISION }}",
        "path": "artifacts/promotion/",
        "compression-level": 0,
        "if-no-files-found": "error",
        "retention-days": 3,
    }
    seal = next(step for step in steps if step.get("id") == "seal")
    scan = next(
        step for step in steps if step["name"] == "Scan exact OCI candidates on both architectures"
    )
    compare = next(step for step in steps if step.get("id") == "compare")
    assert steps.index(compare) < steps.index(scan) < steps.index(seal) < steps.index(export)
    protected = next(step for step in steps if step.get("id") == "upload-oci")
    assert " ".join(protected["if"].split()) == (
        "github.event_name == 'workflow_dispatch' && "
        "inputs.publish_signed && github.ref == 'refs/heads/main'"
    )
    assert protected["with"]["name"] == "saas-oci-promotion-${{ env.CANDIDATE_REVISION }}"
    assert build["outputs"]["oci-artifact-id"] == "${{ steps.upload-oci.outputs.artifact-id }}"
    assert workflow["permissions"] == {"contents": "read"}


def test_unsigned_pr_oci_metadata_is_rejected_for_production_promotion() -> None:
    with pytest.raises(ValueError, match="exact workflow"):
        verify_artifact_metadata(
            {
                "id": 17,
                "name": f"saas-oci-validation-{REVISION}",
                "expired": False,
                "digest": "sha256:" + "b" * 64,
                "workflow_run": {"id": 23, "head_sha": REVISION},
            },
            artifact_id=17,
            zip_sha256="b" * 64,
            revision=REVISION,
            run_id=23,
        )


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
    assert workflow["jobs"]["verify-published-source"]["needs"] == [
        "build-candidate",
        "publish-signed",
    ]


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


def test_crane_promotes_and_reads_back_original_oci_index(tmp_path: Path) -> None:
    crane = os.environ.get("OCI_PROMOTION_TEST_CRANE")
    if not crane:
        pytest.skip("real crane round-trip is enabled in candidate preflight")
    labels, now = candidate(tmp_path / "candidate")
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
