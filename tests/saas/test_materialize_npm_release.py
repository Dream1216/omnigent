"""Verify SaaS npm export admission before archive bytes reach the filesystem."""

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from saas.scripts.check_image_supply_chain import validate_image_material_lock
from saas.scripts.materialize_npm_release import (
    apply_security_overlays,
    download,
    materialize,
)


class _Response:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.data


def archive_bytes(
    extra: tarfile.TarInfo | None = None,
    *,
    name: str = "npm",
    version: str = "12.2.0",
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        payload = json.dumps({"name": name, "version": version}).encode()
        manifest = tarfile.TarInfo("package/package.json")
        manifest.size = len(payload)
        archive.addfile(manifest, io.BytesIO(payload))
        if extra is not None:
            archive.addfile(extra)
    return output.getvalue()


def integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def test_download_retries_transient_transport_errors_with_bounded_backoff() -> None:
    calls = 0
    delays: list[float] = []

    def opener(_url: str, *, timeout: int) -> _Response:
        nonlocal calls
        calls += 1
        assert timeout == 120
        if calls < 3:
            raise OSError("transient TLS EOF")
        return _Response(b"verified later by materialize")

    assert download("https://example.invalid/npm.tgz", opener=opener, sleeper=delays.append) == (
        b"verified later by materialize"
    )
    assert calls == 3
    assert delays == [1, 2]


def test_download_exhaustion_fails_closed() -> None:
    calls = 0

    def opener(_url: str, *, timeout: int) -> _Response:
        nonlocal calls
        calls += 1
        raise OSError("persistent TLS EOF")

    with pytest.raises(OSError, match="persistent TLS EOF"):
        download(
            "https://example.invalid/npm.tgz",
            attempts=3,
            opener=opener,
            sleeper=lambda _delay: None,
        )
    assert calls == 3


def test_verified_manifest_is_exported(tmp_path: Path) -> None:
    data = archive_bytes()
    destination = tmp_path / "export"
    materialize(data, integrity=integrity(data), version="12.2.0", destination=destination)
    assert json.loads((destination / "package/package.json").read_text())["name"] == "npm"


def test_verified_security_overlay_replaces_bundled_dependency(tmp_path: Path) -> None:
    npm_data = archive_bytes()
    destination = tmp_path / "export"
    materialize(npm_data, integrity=integrity(npm_data), version="12.2.0", destination=destination)
    bundled = destination / "package/node_modules/undici"
    bundled.mkdir(parents=True)
    (bundled / "package.json").write_text(
        json.dumps({"name": "undici", "version": "6.28.0"}), encoding="utf-8"
    )
    overlay_data = archive_bytes(name="undici", version="6.28.1")
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "npm_version": "12.2.0",
                "overlays": [
                    {
                        "name": "undici",
                        "version": "6.28.1",
                        "tarball": "https://registry.npmjs.org/undici/-/undici-6.28.1.tgz",
                        "integrity": integrity(overlay_data),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    apply_security_overlays(destination, lock, downloader=lambda _url: overlay_data)

    assert json.loads((bundled / "package.json").read_text())["version"] == "6.28.1"


@pytest.mark.parametrize("case", ["integrity", "manifest", "tarball", "missing-target"])
def test_invalid_security_overlay_fails_closed(tmp_path: Path, case: str) -> None:
    npm_data = archive_bytes()
    destination = tmp_path / "export"
    materialize(npm_data, integrity=integrity(npm_data), version="12.2.0", destination=destination)
    bundled = destination / "package/node_modules/undici"
    if case != "missing-target":
        bundled.mkdir(parents=True)
        (bundled / "package.json").write_text(
            json.dumps({"name": "undici", "version": "6.28.0"}), encoding="utf-8"
        )
    overlay_data = archive_bytes(
        name="wrong" if case == "manifest" else "undici", version="6.28.1"
    )
    tarball = (
        "https://example.invalid/undici.tgz"
        if case == "tarball"
        else ("https://registry.npmjs.org/undici/-/undici-6.28.1.tgz")
    )
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "npm_version": "12.2.0",
                "overlays": [
                    {
                        "name": "undici",
                        "version": "6.28.1",
                        "tarball": tarball,
                        "integrity": integrity(b"wrong")
                        if case == "integrity"
                        else integrity(overlay_data),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        apply_security_overlays(destination, lock, downloader=lambda _url: overlay_data)

    if bundled.exists():
        assert json.loads((bundled / "package.json").read_text())["version"] == "6.28.0"


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
        (
            "--security-lock /build/saas/supply_chain/npm-122-security-lock.json",
            "--security-lock /tmp/unreviewed.json",
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
