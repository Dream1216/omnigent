"""Run the four-authority production PostgreSQL migration boundary."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import stat
import sys
from contextlib import suppress
from pathlib import Path

from saas.production.postgresql_migration import (
    PostgreSqlMigrationError,
    ProductionPostgreSqlPlan,
    run_production_postgresql_migration,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_URL_ENVIRONMENTS = {
    "principal_operator_url": "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL_FILE",
    "database_owner_url": "OMNIGENT_SAAS_DATABASE_OWNER_DATABASE_URL_FILE",
    "official_owner_url": "OMNIGENT_SAAS_OFFICIAL_MIGRATION_DATABASE_URL_FILE",
    "saas_owner_url": "OMNIGENT_SAAS_CONTROL_PLANE_MIGRATION_DATABASE_URL_FILE",
}
_DIRECT_URL_ENVIRONMENTS = tuple(name.removesuffix("_FILE") for name in _URL_ENVIRONMENTS.values())
_MAX_URL_FILE_BYTES = 16 * 1024
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_UNRENDERED_GIT_SHA = "0" * 40


def _required_url_file(parser: argparse.ArgumentParser, name: str) -> str:
    path_value = os.environ.get(name, "")
    if not path_value or path_value != path_value.strip():
        parser.error(f"{name} is required")
    path = Path(path_value)
    if not path.is_absolute():
        parser.error(f"{name} must be an absolute path")
    try:
        metadata = path.lstat()
    except OSError:
        parser.error(f"{name} cannot be inspected")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not 0 < metadata.st_size <= _MAX_URL_FILE_BYTES
    ):
        parser.error(f"{name} must be an owner-only regular non-symlink file")
    try:
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError):
        parser.error(f"{name} cannot be read")
    if not value or value != value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        parser.error(f"{name} contains a malformed database URL")
    return value


def _write_exclusive(path: Path, rendered: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o400)
    except BaseException:
        with suppress(OSError):
            path.unlink()
        raise


def _verify_installed_build_revision(
    parser: argparse.ArgumentParser,
    expected_revision: str,
) -> None:
    """Reject an unrendered or wrong image before any authority file is read."""

    if expected_revision == _UNRENDERED_GIT_SHA:
        parser.error("the release revision template sentinel must be rendered")
    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError):
        parser.error("installed build revision is unavailable")
    if (
        not isinstance(installed_revision, str)
        or _FULL_GIT_SHA.fullmatch(installed_revision) is None
        or not hmac.compare_digest(installed_revision, expected_revision)
    ):
        parser.error("installed build revision does not match the release revision")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--product-revision",
        default=os.environ.get("OMNIGENT_SAAS_SOURCE_SHA"),
        help="exact 40-character product SHA; defaults to OMNIGENT_SAAS_SOURCE_SHA",
    )
    parser.add_argument(
        "--lock-timeout-seconds",
        type=float,
        default=30.0,
    )
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    if not args.product_revision:
        parser.error("--product-revision or OMNIGENT_SAAS_SOURCE_SHA is required")
    product_environment = os.environ.get("OMNIGENT_SAAS_PRODUCT_REVISION")
    source_environment = os.environ.get("OMNIGENT_SAAS_SOURCE_SHA")
    if product_environment is not None or source_environment is not None:
        if (
            product_environment is None
            or source_environment is None
            or _FULL_GIT_SHA.fullmatch(product_environment) is None
            or _FULL_GIT_SHA.fullmatch(source_environment) is None
            or product_environment != source_environment
            or args.product_revision != source_environment
        ):
            parser.error(
                "OMNIGENT_SAAS_PRODUCT_REVISION, OMNIGENT_SAAS_SOURCE_SHA, and "
                "--product-revision must be the same full Git SHA"
            )
    _verify_installed_build_revision(parser, args.product_revision)

    if any(os.environ.get(name, "").strip() for name in _DIRECT_URL_ENVIRONMENTS):
        parser.error("direct authority database URL environments are forbidden; use files")

    urls = {
        field: _required_url_file(parser, environment)
        for field, environment in _URL_ENVIRONMENTS.items()
    }
    try:
        service_role_bindings = load_production_service_role_bindings(os.environ)
    except ProductionServiceRoleBindingsError as error:
        parser.error(str(error))
    try:
        plan = ProductionPostgreSqlPlan.from_urls(
            product_revision=args.product_revision,
            lock_timeout_seconds=args.lock_timeout_seconds,
            principal_operator_url=urls["principal_operator_url"],
            database_owner_url=urls["database_owner_url"],
            official_owner_url=urls["official_owner_url"],
            saas_owner_url=urls["saas_owner_url"],
            service_role_bindings=service_role_bindings,
        )
        receipt = run_production_postgresql_migration(plan, verify_only=args.verify_only)
        rendered = json.dumps(receipt.to_dict(), indent=2, sort_keys=True) + "\n"
        if args.output:
            _write_exclusive(Path(args.output), rendered)
        else:
            sys.stdout.write(rendered)
    except PostgreSqlMigrationError as error:
        sys.stderr.write(f"{error}\n")
        return 1
    except OSError:
        sys.stderr.write("PostgreSQL migration receipt write failed\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
