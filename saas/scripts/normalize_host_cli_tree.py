"""Normalize installer-created filesystem topology in the Host CLI tree."""

from __future__ import annotations

import argparse
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    detached = detach_hardlinked_regular_files(args.root)
    print(f"pnpm hardlinked regular files detached: {detached}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
