"""Normalize installer-created filesystem topology in the Host CLI tree."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
from pathlib import Path


def _regular_files(root: Path) -> list[Path]:
    """Return regular files in a stable order without following symlinks."""

    files: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda candidate: candidate.as_posix()):
        if path.is_symlink():
            continue
        metadata = path.stat(follow_symlinks=False)
        if stat.S_ISREG(metadata.st_mode):
            files.append(path)
    return files


def detach_hardlinked_regular_files(root: Path) -> int:
    """Replace every multiply-linked regular file with an independent inode.

    Some npm postinstall scripts use hard links as an installation optimization.
    BuildKit can serialize the resulting same-layer inode graph differently across
    otherwise identical builds.  Copying all but the last path of each hard-link
    group makes the final tree independent of inode allocation and traversal order.
    The replacement is atomic and the final scan fails closed if any regular file
    still has more than one link.
    """

    if not root.is_dir():
        raise ValueError(f"Host CLI root is not a directory: {root}")

    detached = 0
    for path in _regular_files(root):
        current = path.stat(follow_symlinks=False)
        if current.st_nlink <= 1:
            continue

        temporary = path.with_name(f".{path.name}.omnigent-detach")
        if os.path.lexists(temporary):
            raise RuntimeError(f"hard-link detachment temporary path exists: {temporary}")
        try:
            shutil.copy2(path, temporary, follow_symlinks=False)
            copied = temporary.stat(follow_symlinks=False)
            if not stat.S_ISREG(copied.st_mode) or copied.st_nlink != 1:
                raise RuntimeError(f"hard-link detachment did not create one inode: {path}")
            os.replace(temporary, path)
        finally:
            if os.path.lexists(temporary):
                temporary.unlink()
        detached += 1

    residual = [
        path.relative_to(root).as_posix()
        for path in _regular_files(root)
        if path.stat(follow_symlinks=False).st_nlink != 1
    ]
    if residual:
        raise RuntimeError(
            "hardlinked regular files remain after normalization: " + ", ".join(residual)
        )
    return detached


def normalize_tree_metadata(root: Path, *, source_date_epoch: int) -> int:
    """Normalize retained metadata and return a deterministic tree digest."""

    if source_date_epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be non-negative")
    entries = [root, *sorted(root.rglob("*"), key=lambda path: path.as_posix())]
    timestamp_ns = source_date_epoch * 1_000_000_000
    for path in entries:
        os.utime(path, ns=(timestamp_ns, timestamp_ns), follow_symlinks=False)

    digest = hashlib.sha256()
    for path in entries:
        metadata = path.stat(follow_symlinks=False)
        relative = "." if path == root else path.relative_to(root).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            kind = "symlink"
            payload = os.readlink(path).encode()
            payload_size = len(payload)
        elif stat.S_ISREG(metadata.st_mode):
            kind = "file"
            payload_digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    payload_digest.update(chunk)
            payload = payload_digest.digest()
            payload_size = metadata.st_size
        elif stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
            payload = b""
            payload_size = 0
        else:
            raise RuntimeError(f"unsupported Host CLI path type: {path}")
        record = (
            f"{relative}\0{kind}\0{stat.S_IMODE(metadata.st_mode):o}\0"
            f"{metadata.st_uid}\0{metadata.st_gid}\0{payload_size}\0"
            f"{metadata.st_mtime_ns}\0"
        ).encode()
        digest.update(record)
        digest.update(payload)
        digest.update(b"\0")
    for path in entries:
        os.utime(path, ns=(timestamp_ns, timestamp_ns), follow_symlinks=False)
    return int.from_bytes(digest.digest(), "big")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", action="append", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    args = parser.parse_args()
    detached = sum(detach_hardlinked_regular_files(root) for root in args.root)
    tree_digests = [
        normalize_tree_metadata(root, source_date_epoch=args.source_date_epoch)
        for root in args.root
    ]
    manifest = hashlib.sha256()
    for tree_digest in tree_digests:
        manifest.update(tree_digest.to_bytes(32, "big"))
    print(f"pnpm hardlinked regular files detached: {detached}")
    print(f"Host CLI normalized manifest sha256: {manifest.hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
