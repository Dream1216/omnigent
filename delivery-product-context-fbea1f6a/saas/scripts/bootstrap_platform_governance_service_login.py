"""Bootstrap a service login or converge the journal login posture."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from saas.production.service_login_bootstrap import (
    ProductionServiceLoginBootstrapError,
    bind_platform_admin_service_login,
    bind_platform_governance_service_login,
    bind_platform_model_service_login,
    converge_runtime_provider_journal_login_posture,
    prepare_platform_admin_service_login,
    prepare_platform_governance_service_login,
    prepare_platform_model_service_login,
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
    prepare_model = commands.add_parser(
        "prepare-platform-model",
        help="create or rotate one fixed Platform-model service login",
    )
    prepare_model.add_argument("--service", required=True, choices=("billing", "platform_app"))
    prepare_model.add_argument("--password-file", required=True)
    bind_model = commands.add_parser(
        "bind-platform-model",
        help="grant one fixed Platform-model service-role membership",
    )
    bind_model.add_argument("--service", required=True, choices=("billing", "platform_app"))
    prepare_admin = commands.add_parser(
        "prepare-platform-admin",
        help="create or rotate one fixed Platform Admin service login",
    )
    prepare_admin.add_argument("--service", required=True, choices=("platform_authenticator",))
    prepare_admin.add_argument("--password-file", required=True)
    bind_admin = commands.add_parser(
        "bind-platform-admin",
        help="grant one fixed Platform Admin service-role membership",
    )
    bind_admin.add_argument("--service", required=True, choices=("platform_authenticator",))
    commands.add_parser(
        "converge-runtime-journal-posture",
        help="pin the journal login search path through managed superuser authority",
    )
    args = parser.parse_args()
    try:
        if args.command in ("prepare", "prepare-platform-model", "prepare-platform-admin"):
            path = _password_path(parser, args.password_file)
            with path.open("rb") as stream:
                if args.command == "prepare":
                    receipt = prepare_platform_governance_service_login(
                        environ=os.environ,
                        password_stream=stream,
                    )
                elif args.command == "prepare-platform-model":
                    receipt = prepare_platform_model_service_login(
                        environ=os.environ,
                        service=args.service,
                        password_stream=stream,
                    )
                else:
                    receipt = prepare_platform_admin_service_login(
                        environ=os.environ,
                        service=args.service,
                        password_stream=stream,
                    )
        elif args.command == "bind":
            receipt = bind_platform_governance_service_login(environ=os.environ)
        elif args.command == "bind-platform-model":
            receipt = bind_platform_model_service_login(
                environ=os.environ,
                service=args.service,
            )
        elif args.command == "bind-platform-admin":
            receipt = bind_platform_admin_service_login(
                environ=os.environ,
                service=args.service,
            )
        else:
            receipt = converge_runtime_provider_journal_login_posture(environ=os.environ)
    except (OSError, ProductionServiceLoginBootstrapError) as error:
        code = getattr(error, "code", "password_file_unavailable")
        sys.stderr.write(f"Platform-governance service-login bootstrap rejected: {code}\n")
        return 1
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
