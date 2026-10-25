"""Release one ephemeral builder's cache without touching exported OCI inputs."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import stat
import subprocess
from pathlib import Path

ARCHIVES = ("server-1.tar", "server-2.tar", "host-1.tar", "host-2.tar")
LITELLM_ARCHIVES = ("litellm-1.tar", "litellm-2.tar")
HEADROOM_BYTES = 1024**3
BUILDER = re.compile(r"builder-[a-zA-Z0-9][a-zA-Z0-9_-]{1,90}")


def archive_snapshot(
    root: Path, *, archives: tuple[str, ...] = ARCHIVES
) -> dict[str, tuple[int, int, int, int]]:
    if archives not in (ARCHIVES, LITELLM_ARCHIVES):
        raise ValueError("unsupported candidate archive scope")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("candidate archive directory is invalid")
    result = {}
    for name in archives:
        metadata = (root / name).lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise ValueError(f"candidate archive is not a nonempty regular file: {name}")
        result[name] = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
    return result


def reclaim_build_cache(
    root: Path, builder: str, *, archives: tuple[str, ...] = ARCHIVES
) -> dict[str, object]:
    if BUILDER.fullmatch(builder) is None:
        raise ValueError("refusing anything except an explicitly named ephemeral builder")
    before = archive_snapshot(root, archives=archives)
    required = max(metadata[2] for metadata in before.values()) + HEADROOM_BYTES
    free_before = shutil.disk_usage(root).free
    subprocess.run(
        ["docker", "buildx", "prune", "--builder", builder, "--all", "--force"],
        check=True,
        timeout=300,
    )
    if archive_snapshot(root, archives=archives) != before:
        raise RuntimeError("exported candidate archives changed during cache reclamation")
    free_after = shutil.disk_usage(root).free
    if free_after < required:
        raise RuntimeError(
            f"insufficient OCI inspection space: {free_after} bytes free, {required} required"
        )
    return {
        "status": "pass",
        "builder": builder,
        "archive_sizes": {name: metadata[2] for name, metadata in before.items()},
        "exported_archive_metadata_unchanged": True,
        "free_bytes_before": free_before,
        "free_bytes_after": free_after,
        "required_inspection_bytes": required,
        "policy": "cache reclamation only; full OCI comparison and scan gates remain required",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--scope", choices=("application", "litellm"), default="application")
    args = parser.parse_args()
    archives = LITELLM_ARCHIVES if args.scope == "litellm" else ARCHIVES
    print(
        json.dumps(reclaim_build_cache(args.root, args.builder, archives=archives), sort_keys=True)
    )


if __name__ == "__main__":
    main()
