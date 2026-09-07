"""Prepare or bind the dedicated Platform-governance PostgreSQL login."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from saas.production.service_login_bootstrap import (
    ProductionServiceLoginBootstrapError,
    bind_platform_governance_service_login,
    prepare_platform_governance_service_login,
)

_MAX_PASSWORD_BYTES = 16 * 1024


def _password_path(parser: argparse.ArgumentParser, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        parser.error("--password-file must be absolute")
    try:
        metadata = path.lstat()
    except OSError:
        parser.error("--password-file cannot be inspected")
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or mode & 0o227
        or not mode & 0o440
        or not 0 < metadata.st_size <= _MAX_PASSWORD_BYTES
    ):
        parser.error("--password-file must be a bounded group-readable private file")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="create or rotate the bare login")
    prepare.add_argument("--password-file", required=True)
    commands.add_parser("bind", help="grant the sole base-role membership")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            path = _password_path(parser, args.password_file)
            with path.open("rb") as stream:
                receipt = prepare_platform_governance_service_login(
                    environ=os.environ,
                    password_stream=stream,
                )
        else:
            receipt = bind_platform_governance_service_login(environ=os.environ)
    except (OSError, ProductionServiceLoginBootstrapError) as error:
        code = getattr(error, "code", "password_file_unavailable")
        sys.stderr.write(f"Platform-governance service-login bootstrap rejected: {code}\n")
        return 1
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
