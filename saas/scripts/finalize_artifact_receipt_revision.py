"""Fail-closed finalization for the artifact-admission receipt revision."""

from __future__ import annotations

import argparse
import os
import re
import stat
import tempfile
from contextlib import suppress
from pathlib import Path

_ZERO_SHA256 = "sha256:" + ("0" * 64)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UNRESOLVED_SENTINEL = re.compile(r"0{32}|replace[._-]")
_RECEIPT_PREFIXES = (
    "      OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION: ",
    "            omnigent.io/artifact-admission-receipt-revision: ",
)


def _read_regular_file(path: Path) -> tuple[str, int]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("production manifest must be a regular file")
    return path.read_text(encoding="utf-8"), stat.S_IMODE(metadata.st_mode)


def _validate_pending_text(text: str) -> None:
    scrubbed = text
    for prefix in _RECEIPT_PREFIXES:
        needle = prefix + _ZERO_SHA256
        if text.count(needle) != 1:
            raise ValueError(f"pending receipt field must occur exactly once: {prefix.strip()}")
        scrubbed = scrubbed.replace(needle, prefix + "sha256:" + ("f" * 64), 1)
    if _UNRESOLVED_SENTINEL.search(scrubbed):
        raise ValueError("template sentinel remains outside the two pending receipt fields")


def validate_pending_manifest(path: Path) -> None:
    text, _mode = _read_regular_file(path)
    _validate_pending_text(text)


def finalize_manifest(path: Path, revision: str) -> None:
    if _SHA256.fullmatch(revision) is None or revision == _ZERO_SHA256:
        raise ValueError("receipt revision must be a nonzero sha256:<64 lowercase hex>")
    text, mode = _read_regular_file(path)
    _validate_pending_text(text)
    for prefix in _RECEIPT_PREFIXES:
        text = text.replace(prefix + _ZERO_SHA256, prefix + revision, 1)

    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    try:
        os.fchmod(file_descriptor, mode)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary_name)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("revision", nargs="?")
    parser.add_argument("--check-pending", action="store_true")
    arguments = parser.parse_args()
    if arguments.check_pending:
        if arguments.revision is not None:
            parser.error("revision is not accepted with --check-pending")
        validate_pending_manifest(arguments.manifest)
        return
    if arguments.revision is None:
        parser.error("revision is required unless --check-pending is used")
    finalize_manifest(arguments.manifest, arguments.revision)


if __name__ == "__main__":
    main()
