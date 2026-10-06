"""Create the first local-password Platform operator from a pinned legacy operator."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from saas.control_plane.platform_security import PlatformSecurityError
from saas.production.platform_admin import transition_local_operator

_MAX_USERNAME_BYTES = 256
_MAX_PASSWORD_BYTES = 2048


def _private_file(parser: argparse.ArgumentParser, value: str, *, maximum: int) -> Path:
    path = Path(value)
    if not path.is_absolute():
        parser.error("credential files must use absolute paths")
    try:
        metadata = path.lstat()
    except OSError:
        parser.error("credential file cannot be inspected")
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or mode & 0o077
        or not 0 < metadata.st_size <= maximum
    ):
        parser.error("credential file must be a bounded owner-only regular file")
    return path


def _read(path: Path) -> str:
    value = path.read_text(encoding="utf-8").rstrip("\r\n")
    if not value or value != value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("credential file is invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username-file", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--authorized-by-principal-id", required=True, type=UUID)
    parser.add_argument("--approval-ref", required=True)
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    username_path = _private_file(parser, args.username_file, maximum=_MAX_USERNAME_BYTES)
    password_path = _private_file(parser, args.password_file, maximum=_MAX_PASSWORD_BYTES)
    try:
        principal_id = transition_local_operator(
            os.environ,
            username=_read(username_path),
            password=_read(password_path),
            authorized_by_principal_id=args.authorized_by_principal_id,
            approval_ref=args.approval_ref,
            reason=args.reason,
        )
    except (OSError, UnicodeError, ValueError, PlatformSecurityError, SQLAlchemyError) as error:
        code = (
            error.code
            if isinstance(error, PlatformSecurityError)
            else "platform_transition_rejected"
        )
        sys.stderr.write(f"Local Platform operator transition rejected: {code}\n")
        return 1
    sys.stdout.write(
        json.dumps(
            {
                "schema_version": 1,
                "status": "pass",
                "production_authority": False,
                "principal_id": str(principal_id),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
