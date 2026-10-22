"""TLS 1.3 localhost readiness probe for the Runner control process."""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

from saas.production.runner_readiness import (
    RemoteTlsRunnerControlReadiness,
    RunnerReadinessError,
)

_INTERNAL_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value or value != value.strip() or "\x00" in value:
        raise RunnerReadinessError(f"{name} is invalid")
    return value


def _public_ca_path(source: Mapping[str, str]) -> Path:
    name = "OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE"
    path = Path(_required(source, name))
    if not path.is_absolute():
        raise RunnerReadinessError(f"{name} is invalid")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise RunnerReadinessError(f"{name} is invalid") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not 1 <= metadata.st_size <= 1_048_576
        ):
            raise RunnerReadinessError(f"{name} is invalid")
    finally:
        os.close(descriptor)
    return path


def load_local_runner_control_readiness(
    environ: Mapping[str, str] | None = None,
) -> RemoteTlsRunnerControlReadiness:
    """Bind the public identity to a loopback-only network connection."""

    source: Mapping[str, str] = os.environ if environ is None else environ
    raw_server_name = _required(source, "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_NAME")
    server_name = raw_server_name.lower()
    if (
        raw_server_name != server_name
        or _INTERNAL_HOST.fullmatch(server_name) is None
        or not server_name.endswith((".svc", ".svc.cluster.local"))
    ):
        raise RunnerReadinessError("Runner control readiness server name is invalid")
    try:
        port = int(_required(source, "OMNIGENT_SAAS_RUNNER_CONTROL_READINESS_PORT"))
        timeout_seconds = float(
            source.get("OMNIGENT_SAAS_RUNNER_CONTROL_READINESS_TIMEOUT_SECONDS", "2")
        )
    except ValueError as error:
        raise RunnerReadinessError("Runner control readiness endpoint is invalid") from error
    if not 1 <= port <= 65_535 or not 0.1 <= timeout_seconds <= 10.0:
        raise RunnerReadinessError("Runner control readiness endpoint is invalid")
    return RemoteTlsRunnerControlReadiness(
        connect_host="127.0.0.1",
        port=port,
        server_name=server_name,
        ca_certificate_path=_public_ca_path(source),
        timeout_seconds=timeout_seconds,
    )


def main() -> int:
    try:
        load_local_runner_control_readiness().assert_production_ready()
    except RunnerReadinessError:
        print("Runner control TLS readiness probe failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["load_local_runner_control_readiness", "main"]
