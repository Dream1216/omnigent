"""Preserve Omni namespace flags in the fixed CLI's single bubblewrap launch."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def required_bwrap_argv(binary: Path, arguments: list[str]) -> list[str]:
    """Keep the native mount construction and add original UTS/IPC separation."""
    if arguments in (["--help"], ["--version"]):
        return [str(binary), *arguments]
    required = {
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--new-session",
        "--die-with-parent",
    }
    if "--" not in arguments:
        raise ValueError("Missing native bubblewrap command boundary")
    boundary = arguments.index("--")
    options = arguments[:boundary]
    if "--share-net" in options or "--share-user" in options:
        raise ValueError("Native executor attempted to share a required namespace")
    missing = sorted(required.difference(options))
    return [str(binary), "--unshare-uts", "--unshare-ipc", *missing, *arguments]


def main(binary: str) -> None:
    path = Path(binary)
    argv = required_bwrap_argv(path, sys.argv[1:])
    os.execv(path, argv)
