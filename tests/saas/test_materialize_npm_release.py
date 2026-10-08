"""Verify SaaS npm export admission before archive bytes reach the filesystem."""

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from saas.scripts.materialize_npm_release import materialize


def archive_bytes(extra: tarfile.TarInfo | None = None) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        payload = json.dumps({"name": "npm", "version": "12.2.0"}).encode()
        manifest = tarfile.TarInfo("package/package.json")
        manifest.size = len(payload)
        archive.addfile(manifest, io.BytesIO(payload))
        if extra is not None:
            archive.addfile(extra)
    return output.getvalue()


def integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def test_verified_manifest_is_exported(tmp_path: Path) -> None:
    data = archive_bytes()
    destination = tmp_path / "export"
    materialize(data, integrity=integrity(data), version="12.2.0", destination=destination)
    assert json.loads((destination / "package/package.json").read_text())["name"] == "npm"


@pytest.mark.parametrize("case", ["checksum", "version", "traversal", "symlink"])
def test_invalid_export_does_not_create_destination(tmp_path: Path, case: str) -> None:
    extra = None
    if case == "traversal":
        extra = tarfile.TarInfo("package/../../escape")
    elif case == "symlink":
        extra = tarfile.TarInfo("package/link")
        extra.type = tarfile.SYMTYPE
        extra.linkname = "/etc/passwd"
    data = archive_bytes(extra)
    destination = tmp_path / "export"
    with pytest.raises(ValueError):
        materialize(
            data,
            integrity=integrity(b"wrong") if case == "checksum" else integrity(data),
            version="12.1.0" if case == "version" else "12.2.0",
            destination=destination,
        )
    assert not destination.exists()
