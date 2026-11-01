from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import zipfile
from types import SimpleNamespace

import pytest

from saas.scripts import download_oci_validation as validation
from saas.scripts.oci_promotion import MANIFEST_NAME, verify_artifact_metadata

REVISION = "a" * 40
REPOSITORY = "example/product"
COORDINATES = {"repository": REPOSITORY, "revision": REVISION, "run_id": 123, "artifact_id": 456}


def native():
    artifact = {
        "id": 456,
        "name": f"saas-oci-validation-{REVISION}",
        "expired": False,
        "digest": "sha256:" + "b" * 64,
        "size_in_bytes": 100,
        "workflow_run": {"id": 123, "head_sha": REVISION},
    }
    run = {
        "id": 123,
        "head_sha": REVISION,
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_dispatch",
        "run_attempt": 1,
        "path": ".github/workflows/saas-image-candidate.yml",
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    }
    return artifact, run


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 457),
        ("name", f"saas-oci-promotion-{REVISION}"),
        ("expired", True),
        ("digest", None),
        ("digest", "sha256:" + "0" * 64),
        ("size_in_bytes", True),
        ("size_in_bytes", -1),
        ("workflow_run", {"id": 124, "head_sha": REVISION}),
        ("workflow_run", {"id": 123, "head_sha": "c" * 40}),
    ],
)
def test_artifact_coordinates_cannot_drift(field, value):
    artifact, run = native()
    artifact[field] = value
    with pytest.raises(ValueError):
        validation.verify_validation_coordinates(artifact, run, **COORDINATES)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 124),
        ("head_sha", "c" * 40),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("event", "push"),
        ("event", "pull_request"),
        ("run_attempt", 2),
        ("run_attempt", True),
        ("path", ".github/workflows/other.yml"),
        ("repository", {"full_name": "different/product"}),
        ("head_repository", {"full_name": "fork/product"}),
    ],
)
def test_only_successful_first_manual_candidate_is_eligible(field, value):
    artifact, run = native()
    run[field] = value
    with pytest.raises(ValueError):
        validation.verify_validation_coordinates(artifact, run, **COORDINATES)


def test_unsigned_transfer_does_not_widen_promotion_authority():
    artifact, run = native()
    validation.verify_validation_coordinates(artifact, run, **COORDINATES)
    with pytest.raises(ValueError):
        verify_artifact_metadata(
            artifact, artifact_id=456, zip_sha256="b" * 64, revision=REVISION, run_id=123
        )


def test_capacity_plan_has_both_copies_and_reserve_without_allocating(monkeypatch, tmp_path):
    artifact, _ = native()
    monkeypatch.setattr(validation.shutil, "disk_usage", lambda _: SimpleNamespace(free=399))
    plan = validation.transfer_plan(
        artifact, tmp_path, max_download=100, max_expanded=200, reserve=100
    )
    assert plan["status"] == "held_for_capacity"
    assert plan["required_free_bytes"] == 400
    monkeypatch.setattr(validation.shutil, "disk_usage", lambda _: SimpleNamespace(free=400))
    assert (
        validation.transfer_plan(
            artifact, tmp_path, max_download=99, max_expanded=200, reserve=100
        )["status"]
        == "held_for_capacity"
    )
    assert (
        validation.transfer_plan(
            artifact, tmp_path, max_download=100, max_expanded=200, reserve=100
        )["status"]
        == "transfer_capacity_available"
    )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("maximum", [0, -1, True])
def test_no_implicit_or_invalid_transfer_budget(tmp_path, maximum):
    artifact, _ = native()
    with pytest.raises(ValueError):
        validation.transfer_plan(
            artifact, tmp_path, max_download=maximum, max_expanded=100, reserve=100
        )


def emit(body):
    return [sys.executable, "-c", f"import os;os.write(1,bytes.fromhex('{body.hex()}'))"]


def test_stream_has_exact_size_digest_and_private_permissions(tmp_path):
    body = b"owned-validation-archive"
    path = tmp_path / "download.zip"
    validation.stream_archive(
        emit(body), path, size=len(body), digest=hashlib.sha256(body).hexdigest(), timeout=5
    )
    assert path.read_bytes() == body
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        validation.stream_archive(
            emit(body), path, size=len(body), digest=hashlib.sha256(body).hexdigest(), timeout=5
        )
    assert path.read_bytes() == body


@pytest.mark.parametrize("size,digest", [(2, "b" * 64), (4, "b" * 64), (3, "b" * 64)])
def test_size_or_digest_failure_never_writes_excess(tmp_path, size, digest):
    path = tmp_path / "bad.zip"
    with pytest.raises(ValueError):
        validation.stream_archive(emit(b"abc"), path, size=size, digest=digest, timeout=5)
    assert path.stat().st_size <= size


def test_stalled_download_is_terminated(tmp_path):
    with pytest.raises(ValueError, match="timed out"):
        validation.stream_archive(
            [sys.executable, "-c", "import time;time.sleep(10)"],
            tmp_path / "stalled.zip",
            size=3,
            digest="b" * 64,
            timeout=0.05,
        )


def bundle(tmp_path):
    archive = tmp_path / "candidate.zip"
    body = b'{"synthetic_transport_fixture":true}\n'
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
        stream.writestr(MANIFEST_NAME, body)
        stream.writestr("server-1.tar", b"s" * 2048)
    return (
        archive,
        hashlib.sha256(archive.read_bytes()).hexdigest(),
        hashlib.sha256(body).hexdigest(),
    )


def test_zip_expansion_and_independent_manifest_are_checked_before_output(tmp_path):
    archive, digest, manifest = bundle(tmp_path)
    for name, maximum, expected in (("expanded", 100, manifest), ("seal", 3000, "c" * 64)):
        with pytest.raises(ValueError):
            validation.extract_validation(
                archive,
                tmp_path / name,
                zip_digest=digest,
                manifest_digest=expected,
                max_expanded=maximum,
                reserve=1,
            )
        assert not (tmp_path / name).exists()
    count = validation.extract_validation(
        archive,
        tmp_path / "out",
        zip_digest=digest,
        manifest_digest=manifest,
        max_expanded=3000,
        reserve=1,
    )
    assert count > 2048
    assert (tmp_path / "out").stat().st_mode & 0o777 == 0o700


def arguments(tmp_path, command="inspect"):
    return [
        command,
        "--repository",
        REPOSITORY,
        "--revision",
        REVISION,
        "--run-id",
        "123",
        "--artifact-id",
        "456",
        "--output-dir",
        str(tmp_path / "out"),
        "--max-download-bytes",
        "3000",
        "--max-expanded-bytes",
        "3000",
        "--reserve-bytes",
        "1",
    ]


def install_native(monkeypatch, artifact, run):
    monkeypatch.setattr(
        validation,
        "_native_json",
        lambda endpoint: copy.deepcopy(artifact if "artifacts/" in endpoint else run),
    )


def test_inspect_and_capacity_hold_never_download(monkeypatch, tmp_path, capsys):
    artifact, run = native()
    install_native(monkeypatch, artifact, run)
    monkeypatch.setattr(validation, "stream_archive", lambda *_a, **_kw: pytest.fail("downloaded"))
    assert validation.main(arguments(tmp_path)) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "transfer_capacity_available"
    assert list(tmp_path.iterdir()) == []
    monkeypatch.setattr(validation.shutil, "disk_usage", lambda _: SimpleNamespace(free=1))
    assert validation.main(arguments(tmp_path, "download")) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "held_for_capacity"
    assert list(tmp_path.iterdir()) == []


def test_download_writes_transfer_receipt_without_claiming_oci_qualification(
    monkeypatch, tmp_path, capsys
):
    archive, digest, manifest = bundle(tmp_path)
    artifact, run = native()
    artifact.update(digest="sha256:" + digest, size_in_bytes=archive.stat().st_size)
    install_native(monkeypatch, artifact, run)

    def transfer(_command, output, **_kwargs):
        output.write_bytes(archive.read_bytes())

    monkeypatch.setattr(validation, "stream_archive", transfer)
    assert validation.main([*arguments(tmp_path, "download"), "--manifest-sha256", manifest]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["zip_sha256"] == digest
    assert receipt["production_qualification"] is False
    assert receipt["candidate_seal_verified"] is False
    assert receipt["runtime_qualified"] is False
    assert json.loads((tmp_path / "out/unsigned-validation-transfer.json").read_text()) == receipt
    assert not list(tmp_path.glob(".oci-validation-*"))


def test_native_failure_is_content_blind(monkeypatch, tmp_path, capsys):
    def fail(_endpoint):
        raise RuntimeError("private-native-url-and-credential")

    monkeypatch.setattr(validation, "_native_json", fail)
    assert validation.main(arguments(tmp_path)) == 1
    assert "private-native" not in capsys.readouterr().out


@pytest.mark.parametrize("digest", [None, "invalid", "0" * 64])
def test_manifest_input_is_required_before_downloading(monkeypatch, tmp_path, capsys, digest):
    artifact, run = native()
    install_native(monkeypatch, artifact, run)
    monkeypatch.setattr(validation, "stream_archive", lambda *_a, **_kw: pytest.fail("downloaded"))
    command = arguments(tmp_path, "download")
    if digest is not None:
        command.extend(["--manifest-sha256", digest])
    assert validation.main(command) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "rejected"
    assert list(tmp_path.iterdir()) == []


def test_bundle_cannot_supply_its_own_transfer_receipt(tmp_path):
    archive, _, manifest = bundle(tmp_path)
    with zipfile.ZipFile(archive, "a") as stream:
        stream.writestr("unsigned-validation-transfer.json", b'{"status":"transferred"}')
    with pytest.raises(ValueError, match="reserved"):
        validation.extract_validation(
            archive,
            tmp_path / "out",
            zip_digest=hashlib.sha256(archive.read_bytes()).hexdigest(),
            manifest_digest=manifest,
            max_expanded=3000,
            reserve=1,
        )
    assert not (tmp_path / "out").exists()


def test_changed_output_and_symlink_are_never_overwritten(monkeypatch, tmp_path, capsys):
    artifact, run = native()
    install_native(monkeypatch, artifact, run)
    target = tmp_path / "preserve"
    target.write_bytes(b"unique")
    os.symlink(target, tmp_path / "out")
    assert validation.main(arguments(tmp_path, "download")) == 1
    capsys.readouterr()
    assert target.read_bytes() == b"unique"
