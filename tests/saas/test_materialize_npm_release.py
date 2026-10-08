"""Verify SaaS npm export admission before archive bytes reach the filesystem."""

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from saas.scripts.check_image_supply_chain import validate_image_material_lock
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


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("ARG NPM_VERSION=12.2.0", "ARG NPM_VERSION=latest"),
        ("ARG NPM_INTEGRITY=sha512-", "ARG NPM_INTEGRITY=untrusted-"),
        (
            "COPY --from=npm-builder /opt/npm-export/package /usr/local/lib/node_modules/npm",
            "COPY --from=node-runtime /usr/local/lib/node_modules /usr/local/lib/node_modules",
        ),
    ],
)
def test_npm_material_policy_rejects_pin_or_export_drift(
    monkeypatch: pytest.MonkeyPatch, original: str, replacement: str
) -> None:
    repo = Path(__file__).resolve().parents[2]
    dockerfile = repo / "deploy/docker/Dockerfile"
    read_text = Path.read_text

    def mutated_read(path: Path, *args: object, **kwargs: object) -> str:
        content = read_text(path, *args, **kwargs)
        return content.replace(original, replacement) if path == dockerfile else content

    monkeypatch.setattr(Path, "read_text", mutated_read)
    assert "Host npm must use the normalized integrity-pinned release export" in (
        validate_image_material_lock(repo)
    )
