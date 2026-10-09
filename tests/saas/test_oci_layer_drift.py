from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from saas.scripts.diagnose_oci_layer_drift import diagnose_layer_pair


def _archive(
    path: Path, content: bytes, *, mtime: int = 1, declared_digest: str | None = None
) -> str:
    layer_data = io.BytesIO()
    with tarfile.open(fileobj=layer_data, mode="w:gz") as layer:
        entry = tarfile.TarInfo("etc/example.conf")
        entry.size = len(content)
        entry.mtime = mtime
        layer.addfile(entry, io.BytesIO(content))
    blob = layer_data.getvalue()
    digest = declared_digest or hashlib.sha256(blob).hexdigest()
    with tarfile.open(path, mode="w") as image:
        entry = tarfile.TarInfo(f"blobs/sha256/{digest}")
        entry.size = len(blob)
        image.addfile(entry, io.BytesIO(blob))
    return f"sha256:{digest}"


def test_layer_diagnostics_identify_changed_file_without_exposing_content(tmp_path: Path) -> None:
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    first_digest = _archive(first, b"private old value")
    second_digest = _archive(second, b"private new value")

    result = diagnose_layer_pair(first, second, first_digest, second_digest)

    assert result["changed_entry_count"] == 1
    assert result["truncated_entry_count"] == 0
    entry = result["changed_entries"][0]
    assert entry["path"] == "etc/example.conf"
    assert entry["first"]["sha256"] == hashlib.sha256(b"private old value").hexdigest()
    assert entry["second"]["sha256"] == hashlib.sha256(b"private new value").hexdigest()
    assert "private" not in str(result)


def test_layer_diagnostics_reject_blob_digest_mismatch(tmp_path: Path) -> None:
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    first_digest = _archive(first, b"first")
    second_digest = _archive(second, b"second", declared_digest=first_digest.removeprefix("sha256:"))

    with pytest.raises(ValueError, match="blob digest mismatch"):
        diagnose_layer_pair(first, second, first_digest, first_digest)
    assert first_digest == second_digest
