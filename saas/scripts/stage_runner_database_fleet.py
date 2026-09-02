"""Atomically stage exact A/B Runner registrations without exposing their tokens."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from saas.production.runner_database_fleet import (
    RUNNER_DATABASE_FLEET_STAGE_TOKEN_OUTPUT_FILE_ENV,
    RunnerDatabaseFleetError,
    StagedRunnerDatabaseFleetMember,
    load_runner_database_fleet_stage_admin_database_url,
    load_runner_database_fleet_stage_specs,
    stage_runner_database_fleet,
)


def build_runner_database_fleet_stage_engine(database_url: str) -> Engine:
    """Build one owner-only stage connection without retaining a credential pool."""

    return sa.create_engine(database_url, poolclass=NullPool)


def _canonical_token_document(
    staged: tuple[StagedRunnerDatabaseFleetMember, StagedRunnerDatabaseFleetMember],
) -> bytes:
    document = {
        "runners": [
            {
                "connection_generation": member.connection_generation,
                "connection_token": member.connection_token,
                "runner_id": str(member.runner_id),
                "status": member.status,
            }
            for member in sorted(staged, key=lambda item: str(item.runner_id))
        ],
        "schema_version": 1,
    }
    return (
        json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def _reserve_owner_only_output(source: Mapping[str, str]) -> tuple[Path, int]:
    value = source.get(RUNNER_DATABASE_FLEET_STAGE_TOKEN_OUTPUT_FILE_ENV)
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise RunnerDatabaseFleetError("Runner fleet stage token output file is required")
    path = Path(value)
    if not path.is_absolute():
        raise RunnerDatabaseFleetError("Runner fleet stage token output file must be absolute")
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        parent = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise OSError
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o400,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        observed = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o400
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise OSError
    except OSError:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
            with suppress(OSError):
                os.unlink(path.name, dir_fd=parent_descriptor)
        raise RunnerDatabaseFleetError(
            "Runner fleet stage token output cannot be reserved"
        ) from None
    finally:
        if parent_descriptor >= 0:
            with suppress(OSError):
                os.close(parent_descriptor)
    return path, descriptor


def _write_reserved_output(path: Path, descriptor: int, raw: bytes) -> None:
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise OSError
            written += count
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        observed = path.lstat()
        if (
            after.st_size != len(raw)
            or stat.S_IMODE(after.st_mode) != 0o400
            or after.st_uid != os.geteuid()
            or (after.st_dev, after.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise OSError
    except OSError:
        raise RunnerDatabaseFleetError(
            "Runner fleet stage token output cannot be written"
        ) from None


def stage_exact_runner_database_fleet(
    source: Mapping[str, str],
    *,
    engine_factory: Callable[[str], Engine] = build_runner_database_fleet_stage_engine,
) -> tuple[tuple[str, int, str], tuple[str, int, str]]:
    """Stage exact A/B, then seal their one-time tokens in one new 0400 file."""

    specs = load_runner_database_fleet_stage_specs(source)
    database_url, _parsed, _path = load_runner_database_fleet_stage_admin_database_url(source)
    output_path, output_descriptor = _reserve_owner_only_output(source)
    engine = engine_factory(database_url)
    succeeded = False
    try:
        factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
        staged = stage_runner_database_fleet(factory, specs=specs)
        _write_reserved_output(output_path, output_descriptor, _canonical_token_document(staged))
        succeeded = True
        return cast(
            tuple[tuple[str, int, str], tuple[str, int, str]],
            tuple(
                (str(member.runner_id), member.connection_generation, member.status)
                for member in staged
            ),
        )
    finally:
        with suppress(OSError):
            os.close(output_descriptor)
        engine.dispose()
        if not succeeded:
            with suppress(OSError):
                output_path.unlink()


def main() -> int:
    """Emit only a secret-free result; tokens stay in the exclusive 0400 output."""

    try:
        staged = stage_exact_runner_database_fleet(os.environ)
    except Exception:  # noqa: BLE001 - never expose DSNs, tokens, or filesystem details.
        print(
            json.dumps(
                {
                    "code": "runner_database_fleet_stage_failed",
                    "schema_version": 1,
                    "status": "fail",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(
        json.dumps(
            {
                "runners": [
                    {
                        "connection_generation": generation,
                        "runner_id": runner_id,
                        "status": status,
                    }
                    for runner_id, generation, status in staged
                ],
                "schema_version": 1,
                "status": "pass",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "build_runner_database_fleet_stage_engine",
    "main",
    "stage_exact_runner_database_fleet",
]
