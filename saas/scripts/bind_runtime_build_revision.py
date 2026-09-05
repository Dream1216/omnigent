"""Bind immutable release coordinates into an installed Omnigent runtime."""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import re
import sys
from pathlib import Path

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def bind_runtime_build_revision(*, source_revision: str, source_date_epoch: int) -> Path:
    """Rewrite installed build metadata with validated, deterministic values."""

    if _FULL_GIT_SHA.fullmatch(source_revision) is None:
        raise ValueError("source revision must be a lowercase 40-character Git SHA")
    if source_date_epoch < 0:
        raise ValueError("source date epoch must be a non-negative integer")

    distribution = importlib.metadata.distribution("omnigent")
    prefix = Path(sys.prefix).resolve(strict=True)
    target = Path(str(distribution.locate_file("omnigent/_build_info.py")))
    if target.is_symlink() or not target.is_file():
        raise RuntimeError("installed Omnigent build metadata must be a regular file")
    resolved = target.resolve(strict=True)
    try:
        resolved.relative_to(prefix)
    except ValueError as error:
        raise RuntimeError(
            "installed Omnigent build metadata escapes the runtime prefix"
        ) from error

    content = (
        '"""Auto-generated for an immutable Omnigent runtime image; do not edit."""\n'
        "from __future__ import annotations\n\n"
        f"BUILD_TIME_EPOCH: int = {source_date_epoch}\n"
        f"COMMIT_SHA: str = {source_revision!r}\n"
    )
    temporary = resolved.with_name(f".{resolved.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.utime(temporary, (source_date_epoch, source_date_epoch))
    os.replace(temporary, resolved)

    namespace: dict[str, object] = {}
    exec(compile(resolved.read_text(encoding="utf-8"), str(resolved), "exec"), namespace)
    if namespace.get("COMMIT_SHA") != source_revision:
        raise RuntimeError("installed Omnigent runtime revision verification failed")
    if namespace.get("BUILD_TIME_EPOCH") != source_date_epoch:
        raise RuntimeError("installed Omnigent build epoch verification failed")
    return resolved


def main() -> int:
    """Parse immutable release inputs and update the installed runtime."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    arguments = parser.parse_args()
    target = bind_runtime_build_revision(
        source_revision=arguments.source_revision,
        source_date_epoch=arguments.source_date_epoch,
    )
    print(f"Bound installed runtime revision at {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
