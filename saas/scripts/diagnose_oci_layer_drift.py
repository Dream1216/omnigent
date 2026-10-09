"""Record bounded, content-free file diagnostics for changed OCI layers."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import tempfile
from pathlib import Path
from typing import Any

_MAX_REPORTED_ENTRIES = 200


def _hash_stream(stream: Any) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _layer_entries(archive_path: Path, digest: str) -> dict[str, dict[str, Any]]:
    algorithm, separator, value = digest.partition(":")
    if separator != ":" or algorithm != "sha256" or len(value) != 64:
        raise ValueError("invalid OCI layer digest")
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError("invalid OCI layer digest")
    with tempfile.TemporaryDirectory(prefix="omnigent-layer-drift-") as temp_name:
        blob = Path(temp_name) / "layer"
        with tarfile.open(archive_path) as image_archive:
            try:
                member = image_archive.getmember(f"blobs/sha256/{value}")
            except KeyError as error:
                raise ValueError("OCI layer blob is unavailable") from error
            source = image_archive.extractfile(member)
            if source is None:
                raise ValueError("OCI layer blob is unavailable")
            with source, blob.open("wb") as destination:
                checksum = hashlib.sha256()
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    destination.write(chunk)
                    checksum.update(chunk)
        if checksum.hexdigest() != value:
            raise ValueError("OCI layer blob digest mismatch")
        entries: dict[str, dict[str, Any]] = {}
        occurrences: dict[str, int] = {}
        with tarfile.open(blob) as layer_archive:
            for item in layer_archive:
                ordinal = occurrences.get(item.name, 0)
                occurrences[item.name] = ordinal + 1
                key = f"{item.name}#{ordinal}" if ordinal else item.name
                summary: dict[str, Any] = {
                    "type": item.type.decode("ascii", errors="replace"),
                    "size": item.size,
                    "mode": item.mode,
                    "uid": item.uid,
                    "gid": item.gid,
                    "mtime": item.mtime,
                    "uname": item.uname,
                    "gname": item.gname,
                    "linkname": item.linkname,
                    "pax_header_hashes": {
                        name: hashlib.sha256(value.encode()).hexdigest()
                        for name, value in sorted(item.pax_headers.items())
                    },
                }
                if item.isfile():
                    source = layer_archive.extractfile(item)
                    if source is None:
                        raise ValueError("OCI layer file is unavailable")
                    with source:
                        summary["sha256"] = _hash_stream(source)
                entries[key] = summary
        return entries


def diagnose_layer_pair(
    first_archive: Path, second_archive: Path, first_digest: str, second_digest: str
) -> dict[str, Any]:
    left = _layer_entries(first_archive, first_digest)
    right = _layer_entries(second_archive, second_digest)
    changed = [path for path in sorted(left.keys() | right.keys()) if left.get(path) != right.get(path)]
    return {
        "changed_entry_count": len(changed),
        "changed_entries": [
            {"path": path, "first": left.get(path), "second": right.get(path)}
            for path in changed[:_MAX_REPORTED_ENTRIES]
        ],
        "truncated_entry_count": max(0, len(changed) - _MAX_REPORTED_ENTRIES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--image", action="append", required=True, metavar="NAME=FIRST,SECOND")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    images: dict[str, Any] = {}
    for spec in args.image:
        name, paths = spec.split("=", 1)
        first, second = (Path(path) for path in paths.split(",", 1))
        comparison = report["images"].get(name)
        if comparison is None:
            continue
        changed_layers: dict[str, Any] = {}
        for platform in ("linux/amd64", "linux/arm64"):
            left = comparison["first"]["platforms"][platform]["layers"]
            right = comparison["second"]["platforms"][platform]["layers"]
            if len(left) != len(right):
                changed_layers[platform] = {"layer_count": [len(left), len(right)]}
                continue
            platform_diffs = {}
            for index, (left_layer, right_layer) in enumerate(zip(left, right)):
                if left_layer["digest"] == right_layer["digest"]:
                    continue
                platform_diffs[str(index)] = diagnose_layer_pair(
                    first, second, left_layer["digest"], right_layer["digest"]
                )
            if platform_diffs:
                changed_layers[platform] = platform_diffs
        if changed_layers:
            images[name] = changed_layers
    diagnostics = {
        "diagnostic_version": 1,
        "product_revision": report["product_revision"],
        "policy": "file paths, metadata, and content hashes only; no file contents",
        "images": images,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"images": {name: list(facts) for name, facts in images.items()}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
