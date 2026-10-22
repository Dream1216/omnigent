"""Prefetch exact APT snapshot package inputs without changing dependency resolution."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import re
import shlex
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TypedDict


class AptPackageInput(TypedDict):
    uri: str
    name: str
    size: int
    sha256: str


def parse_inputs(text: str) -> list[AptPackageInput]:
    inputs: list[AptPackageInput] = []
    names: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("'"):
            continue
        fields = shlex.split(line)
        if len(fields) != 4:
            raise ValueError("APT package input must include URI, filename, size and hash")
        uri, name, size, digest = fields
        match = re.fullmatch(
            r"https://snapshot[.]debian[.]org/archive/(debian|debian-security)/"
            r"[0-9]{8}T[0-9]{6}Z/(pool/[A-Za-z0-9_./%+~:-]+[.]deb)",
            uri,
        )
        if (
            match is None
            or ".." in urllib.parse.unquote(match[2]).split("/")
            or not re.fullmatch(
                r"[A-Za-z0-9.+-]+_(?:[0-9]+%3[aA])?[A-Za-z0-9.+~:-]+_[A-Za-z0-9-]+[.]deb",
                name,
            )
            or urllib.parse.unquote(match[2]).rsplit("/", 1)[-1]
            != re.sub(r"_[0-9]+(?:%3[aA]|:)", "_", name, count=1)
            or name in names
            or not size.isascii()
            or not size.isdigit()
            or not 0 < int(size) <= 200_000_000
            or not re.fullmatch(r"SHA256:[a-f0-9]{64}", digest)
        ):
            raise ValueError("APT input is not a unique, SHA-256-pinned snapshot package")
        names.add(name)
        inputs.append({"uri": uri, "name": name, "size": int(size), "sha256": digest[7:]})
    if not inputs:
        raise ValueError("authenticated APT package input list is empty")
    return inputs


def fetch(item: AptPackageInput, output: Path) -> AptPackageInput:
    target = output / str(item["name"])
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file():
            raise ValueError("package cache target is not a regular file")
        if target.stat().st_size != item["size"] or (
            hashlib.sha256(target.read_bytes()).hexdigest() != item["sha256"]
        ):
            raise ValueError("existing package cache differs from authenticated APT input")
        return item
    # Dependency versions and hashes come from the signed snapshot indexes, not
    # from this mirror's current package index. APT verifies them again on install.
    uri = str(item["uri"])
    suffix = uri.split("/pool/", 1)[1]
    archive = "debian-security" if "/archive/debian-security/" in uri else "debian"
    urls = [f"https://deb.debian.org/{archive}/pool/{suffix}", uri]
    for index, url in enumerate(urls):
        try:
            with tempfile.TemporaryDirectory(dir=output, prefix=".package-") as temporary:
                tmp = Path(temporary) / "download"
                digest = hashlib.sha256()
                count = 0
                with tmp.open("wb") as stream, urllib.request.urlopen(url, timeout=45) as response:
                    while chunk := response.read(256 * 1024):
                        count += len(chunk)
                        if count > item["size"]:
                            raise ValueError("package download exceeds locked size")
                        digest.update(chunk)
                        stream.write(chunk)
                if count != item["size"] or digest.hexdigest() != item["sha256"]:
                    raise ValueError("package download does not match locked size/hash")
                tmp.replace(target)
                return item
        except (OSError, ValueError):
            if index == len(urls) - 1:
                raise
    raise AssertionError("package URLs exhausted")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inputs = parse_inputs(args.inputs.read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda item: fetch(item, args.output), inputs))
    print(json.dumps({"schema_version": 1, "production_admission": False, "packages": results}))


if __name__ == "__main__":
    main()
