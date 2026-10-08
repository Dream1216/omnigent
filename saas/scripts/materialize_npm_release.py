"""Materialize a complete npm release without resolving its bundled dependencies."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath


def materialize(data: bytes, *, integrity: str, version: str, destination: Path) -> None:
    algorithm, expected = integrity.split("-", 1)
    if algorithm != "sha512":
        raise ValueError("npm release must be pinned with SHA-512 integrity")
    actual = hashlib.sha512(data).digest()
    if actual != base64.b64decode(expected, validate=True):
        raise ValueError("npm release integrity mismatch")
    if destination.exists():
        raise ValueError("npm export destination must not already exist")
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
        if manifest.get("name") != "npm" or manifest.get("version") != version:
            raise ValueError("npm release manifest does not match pin")
        destination.mkdir(parents=True)
        archive.extractall(destination, filter="data")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--integrity", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if (
        not all(part.isdecimal() for part in args.version.split("."))
        or len(args.version.split(".")) != 3
    ):
        parser.error("version must be an exact numeric npm release")
    url = f"https://registry.npmjs.org/npm/-/npm-{args.version}.tgz"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    materialize(
        data,
        integrity=args.integrity,
        version=args.version,
        destination=args.destination,
    )


if __name__ == "__main__":
    main()
