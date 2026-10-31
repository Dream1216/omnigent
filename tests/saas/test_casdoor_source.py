from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from saas.scripts import prepare_casdoor_source as source


def _archive(path: Path, member: str = "casdoor/version.txt") -> Path:
    with tarfile.open(path, "w:gz") as bundle:
        content = b"upstream\n"
        entry = tarfile.TarInfo(member)
        entry.size = len(content)
        bundle.addfile(entry, io.BytesIO(content))
    return path


def _supply(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, archive: Path) -> Path:
    supply = tmp_path / "supply"
    supply.mkdir()
    patch = b"--- a/version.txt\n+++ b/version.txt\n@@ -1 +1 @@\n-upstream\n+patched\n"
    (supply / "fix.patch").write_bytes(patch)
    (supply / "source-lock.json").write_text(
        json.dumps(
            {
                "source_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "patches": [{"path": "fix.patch", "sha256": hashlib.sha256(patch).hexdigest()}],
            }
        )
    )
    monkeypatch.setattr(source, "_SUPPLY_ROOT", supply)
    return supply


def test_source_is_verified_and_patched_without_overwriting_existing_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _archive(tmp_path / "source.tar.gz")
    _supply(tmp_path, monkeypatch, archive)
    output = tmp_path / "output"
    receipt = source.prepare_source(output, archive=archive)
    assert (output / "version.txt").read_text() == "patched\n"
    assert json.loads((output / "stbz-source-receipt.json").read_text()) == receipt
    with pytest.raises(ValueError, match="must not already exist"):
        source.prepare_source(output, archive=archive)
    assert (output / "version.txt").read_text() == "patched\n"


@pytest.mark.parametrize("tamper", ["archive", "patch"])
def test_tampered_supply_never_creates_an_output_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    archive = _archive(tmp_path / "source.tar.gz")
    supply = _supply(tmp_path, monkeypatch, archive)
    if tamper == "archive":
        archive.write_bytes(archive.read_bytes() + b"changed")
    else:
        (supply / "fix.patch").write_bytes(b"changed")
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="checksum mismatch"):
        source.prepare_source(output, archive=archive)
    assert not output.exists()


def test_archive_paths_cannot_escape_the_staging_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _archive(tmp_path / "source.tar.gz", "../../escaped.txt")
    _supply(tmp_path, monkeypatch, archive)
    with pytest.raises(tarfile.OutsideDestinationError):
        source.prepare_source(tmp_path / "output", archive=archive)
    assert not (tmp_path / "escaped.txt").exists()
    assert not (tmp_path / "output").exists()
