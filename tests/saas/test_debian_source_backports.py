"""Source patch replay cannot stand in for compiled or production admission."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from saas.scripts.replay_debian_source_backports import replay


def source_archive(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


def source_bundle(tmp_path: Path, *, conflict: bool = False) -> tuple[Path, Path]:
    cache = tmp_path / "cache"
    cache.mkdir()
    data = {
        "upstream.tar.gz": source_archive({"curl-8.14.1/example": b"before\n"}),
        "upstream.asc": b"signature bytes are hash-bound, not PGP-verified by replay",
        "debian.tar.gz": source_archive({"debian/patches/series": b""}),
    }
    checksums = "".join(
        f" {hashlib.sha256(value).hexdigest()} {len(value)} {name}\n"
        for name, value in data.items()
    )
    data["source.dsc"] = (
        "Format: 3.0 (quilt)\nSource: curl\nVersion: 8.14.1-2+deb13u5\n"
        f"Checksums-Sha256:\n{checksums}Files:\n"
    ).encode()
    commit = "a" * 40
    old = "wrong" if conflict else "before"
    data["fix.patch"] = (
        f"From {commit} Mon Sep 17 00:00:00 2001\n"
        "Date: Thu, 1 Jan 2026 00:00:00 +0000\n"
        "diff --git a/example b/example\n--- a/example\n+++ b/example\n"
        f"@@ -1 +1 @@\n-{old}\n+after\n"
    ).encode()
    for name, value in data.items():
        (cache / name).write_bytes(value)
    roles = {
        "source.dsc": "dsc",
        "upstream.tar.gz": "upstream",
        "upstream.asc": "signature",
        "debian.tar.gz": "debian",
    }
    lock = {
        "schema_version": 1,
        "distribution": "debian",
        "codename": "trixie",
        "component": "curl",
        "source_version": "8.14.1-2+deb13u5",
        "source_root": "curl-8.14.1",
        "production_admission": False,
        "artifacts": [
            {"name": name, "role": role, "sha256": hashlib.sha256(data[name]).hexdigest()}
            for name, role in roles.items()
        ],
        "patches": [
            {
                "name": "fix.patch",
                "sha256": hashlib.sha256(data["fix.patch"]).hexdigest(),
                "commit": commit,
                "cve": "CVE-2026-19931",
            }
        ],
    }
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(json.dumps(lock))
    return lock_path, cache


def test_clean_replay_is_not_production_admission(tmp_path: Path) -> None:
    lock, cache = source_bundle(tmp_path)
    destination = tmp_path / "replay"
    report = replay(lock, cache, destination)
    assert report["status"] == "pass"
    assert report["production_admission"] is False
    assert report["required_followup"] == [
        "compiled-regression",
        "ABI-comparison",
        "full-image-admission",
    ]
    assert (destination / "curl-8.14.1/example").read_text() == "after\n"


def test_patch_conflict_is_a_failure_without_partial_application(tmp_path: Path) -> None:
    lock, cache = source_bundle(tmp_path, conflict=True)
    destination = tmp_path / "replay"
    report = replay(lock, cache, destination)
    assert report["status"] == "fail"
    assert report["backports"][0]["exit_code"] != 0
    assert (destination / "curl-8.14.1/example").read_text() == "before\n"


@pytest.mark.parametrize("case", ["hash", "commit", "admission", "distro", "boolean-schema"])
def test_invalid_binding_rejected_before_destination(tmp_path: Path, case: str) -> None:
    lock_path, cache = source_bundle(tmp_path)
    lock = json.loads(lock_path.read_text())
    if case == "hash":
        lock["artifacts"][0]["sha256"] = "0" * 64
    elif case == "commit":
        lock["patches"][0]["commit"] = "b" * 40
    elif case == "admission":
        lock["production_admission"] = True
    elif case == "distro":
        lock["codename"] = "forky"
    else:
        lock["schema_version"] = True
    lock_path.write_text(json.dumps(lock))
    destination = tmp_path / "replay"
    with pytest.raises(ValueError):
        replay(lock_path, cache, destination)
    assert not destination.exists()
