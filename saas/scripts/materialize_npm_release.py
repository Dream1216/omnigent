"""Materialize a complete npm release without resolving its bundled dependencies."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import shutil
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path, PurePosixPath

_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def download(
    url: str,
    *,
    attempts: int = 5,
    timeout: int = 120,
    opener: Callable[..., object] = urllib.request.urlopen,
    sleeper: Callable[[float], None] = time.sleep,
) -> bytes:
    """Download an immutable release with bounded retries."""

    if attempts < 1:
        raise ValueError("download attempts must be positive")
    for attempt in range(1, attempts + 1):
        try:
            with opener(url, timeout=timeout) as response:  # type: ignore[attr-defined]
                return response.read()  # type: ignore[no-any-return, attr-defined]
        except OSError:
            if attempt == attempts:
                raise
            sleeper(min(2 ** (attempt - 1), 8))
    raise AssertionError("unreachable")


def _verify_integrity(data: bytes, integrity: str) -> None:
    algorithm, expected = integrity.split("-", 1)
    if algorithm != "sha512":
        raise ValueError("npm release must be pinned with SHA-512 integrity")
    actual = hashlib.sha512(data).digest()
    if actual != base64.b64decode(expected, validate=True):
        raise ValueError("npm release integrity mismatch")


def _inspect_archive(data: bytes, *, name: str, version: str) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        seen: set[str] = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] != "package"
                or not (member.isfile() or member.isdir())
                or member.name in seen
            ):
                raise ValueError(f"unsafe npm archive member: {member.name}")
            seen.add(member.name)
        stream = archive.extractfile("package/package.json")
        if stream is None:
            raise ValueError("npm release manifest missing")
        manifest = json.load(stream)
        if manifest.get("name") != name or manifest.get("version") != version:
            raise ValueError("npm release manifest does not match pin")


def materialize(data: bytes, *, integrity: str, version: str, destination: Path) -> None:
    _verify_integrity(data, integrity)
    if destination.exists():
        raise ValueError("npm export destination must not already exist")
    _inspect_archive(data, name="npm", version=version)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        destination.mkdir(parents=True)
        archive.extractall(destination, filter="data")


def apply_security_overlays(
    destination: Path,
    lock_path: Path,
    *,
    downloader: Callable[[str], bytes] = download,
) -> None:
    """Replace vulnerable bundled npm dependencies with verified patch releases."""

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if set(lock) != {"schema_version", "npm_version", "overlays"}:
        raise ValueError("npm security overlay lock fields do not match schema")
    if lock["schema_version"] != 1 or not isinstance(lock["npm_version"], str):
        raise ValueError("npm security overlay lock metadata is invalid")
    npm_manifest = json.loads((destination / "package/package.json").read_text(encoding="utf-8"))
    if npm_manifest.get("name") != "npm" or npm_manifest.get("version") != lock["npm_version"]:
        raise ValueError("npm security overlay lock does not match materialized npm")
    overlays = lock["overlays"]
    if not isinstance(overlays, list) or not overlays:
        raise ValueError("npm security overlay lock must contain overlays")

    verified: list[tuple[str, bytes]] = []
    names: set[str] = set()
    for overlay in overlays:
        if not isinstance(overlay, dict) or set(overlay) != {
            "name",
            "version",
            "tarball",
            "integrity",
        }:
            raise ValueError("npm security overlay entry fields do not match schema")
        name = overlay["name"]
        version = overlay["version"]
        tarball = overlay["tarball"]
        integrity = overlay["integrity"]
        if (
            not isinstance(name, str)
            or not _PACKAGE_NAME.fullmatch(name)
            or name in names
            or not isinstance(version, str)
            or not version
            or tarball != f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
            or not isinstance(integrity, str)
        ):
            raise ValueError("npm security overlay entry is invalid")
        target = destination / "package/node_modules" / name
        if not target.is_dir():
            raise ValueError(f"npm security overlay target is missing: {name}")
        data = downloader(tarball)
        _verify_integrity(data, integrity)
        _inspect_archive(data, name=name, version=version)
        names.add(name)
        verified.append((name, data))

    for name, data in verified:
        target = destination / "package/node_modules" / name
        with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
            temporary_path = Path(temporary)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                archive.extractall(temporary_path, filter="data")
            shutil.rmtree(target)
            (temporary_path / "package").replace(target)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--integrity", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--security-lock", type=Path, required=True)
    args = parser.parse_args()
    if (
        not all(part.isdecimal() for part in args.version.split("."))
        or len(args.version.split(".")) != 3
    ):
        parser.error("version must be an exact numeric npm release")
    url = f"https://registry.npmjs.org/npm/-/npm-{args.version}.tgz"
    data = download(url)
    materialize(
        data,
        integrity=args.integrity,
        version=args.version,
        destination=args.destination,
    )
    apply_security_overlays(args.destination, args.security_lock)


if __name__ == "__main__":
    main()
