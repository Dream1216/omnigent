"""Prepare a checksum-verified, patched Casdoor source tree for candidate builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

_SUPPLY_ROOT = Path(__file__).resolve().parents[1] / "production" / "casdoor"


def prepare_source(output: Path, *, archive: Path | None = None) -> dict[str, object]:
    lock = json.loads((_SUPPLY_ROOT / "source-lock.json").read_text())
    output = output.resolve()
    if output.exists():
        raise ValueError("source output must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="casdoor-source-", dir=output.parent) as scratch:
        staging = Path(scratch)
        source_archive = staging / "source.tar.gz"
        if archive is None:
            with (
                urlopen(lock["source_url"], timeout=120) as response,
                source_archive.open("wb") as destination,
            ):
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 100 * 1024 * 1024:
                        raise ValueError("source archive exceeds size limit")
                    destination.write(chunk)
        else:
            shutil.copyfile(archive, source_archive)
        with source_archive.open("rb") as archive_input:
            digest = hashlib.file_digest(archive_input, "sha256").hexdigest()
        if digest != lock["source_sha256"]:
            raise ValueError("Casdoor source checksum mismatch")
        for patch in lock["patches"]:
            patch_file = _SUPPLY_ROOT / patch["path"]
            if hashlib.sha256(patch_file.read_bytes()).hexdigest() != patch["sha256"]:
                raise ValueError("Casdoor patch checksum mismatch")
        with tarfile.open(source_archive, "r:gz") as bundle:
            bundle.extractall(staging / "unpacked", filter="data")
        unpacked = staging / "unpacked"
        roots = list(unpacked.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError("unexpected Casdoor source layout")
        tree = roots[0]
        for patch in lock["patches"]:
            with (_SUPPLY_ROOT / patch["path"]).open("rb") as patch_input:
                subprocess.run(
                    ["patch", "--batch", "--forward", "-p1"],
                    cwd=tree,
                    stdin=patch_input,
                    check=True,
                )
        receipt = {**lock, "status": "source_prepared"}
        (tree / "stbz-source-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        tree.rename(output)
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--archive", type=Path, help="optional previously downloaded source archive"
    )
    args = parser.parse_args()
    receipt = prepare_source(args.output, archive=args.archive)
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
