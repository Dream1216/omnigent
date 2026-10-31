"""Cloud Host entrypoint with server-mediated model access and file-only credentials."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from uuid import UUID

from omnigent.host import HOST_FATAL_EXIT_CODE
from omnigent.host.identity import (
    HOST_ID_ENV_VAR,
    HOST_NAME_ENV_VAR,
    HOST_TOKEN_ENV_VAR,
    HOST_TOKEN_FILE_ENV_VAR,
    HOST_WORKSPACE_ID_ENV_VAR,
)
from omnigent.host.runner_zygote import ZygoteRunnerProc
from saas.production.aliyun_model_client import (
    ALIYUN_MODEL_TOKEN_TTL_SECONDS,
    AliyunHostModelTokenIssuer,
    validated_server_origin,
)
from saas.production.platform_model_host import (
    PlatformModelHostProcess,
    run_host_with_model_issuer,
)
from saas.production.platform_model_relay import validated_model_gateway_url
from saas.production.tenant_model_keys import _read_file

SERVER_URL_ENV = "OMNIGENT_SAAS_SERVER_URL"
MODEL_LEASE_FILE_ENV = "OMNIGENT_SAAS_ALIYUN_MODEL_LEASE_FILE"
MODEL_GATEWAY_URL_ENV = "OMNIGENT_SAAS_ALIYUN_MODEL_GATEWAY_URL"
MODEL_TENANT_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID"
_SERVER_ONLY_ENV = (
    HOST_TOKEN_ENV_VAR,
    "E2B_API_KEY",
    "ALIBABA_CLOUD_ACCESS_KEY_ID",
    "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
    "ALIBABA_CLOUD_SECURITY_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE",
    "OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_FILE",
)


class AliyunHostConfigurationError(ValueError):
    """A cloud Host is missing a narrow, file-only launch authority."""


def configure_aliyun_runner_recovery(environment: dict[str, str]) -> None:
    """Keep a pending approval alive across the qualified 150-second outage."""

    environment["OMNIGENT_HOOK_MAX_RETRIES"] = "12"


class AliyunHostProcess(PlatformModelHostProcess):
    """Managed Host with a fixed, bounded approval recovery profile."""

    def _spawn_runner_proc(
        self,
        env: dict[str, str],
        session_slug: str,
        workspace: Path,
    ) -> tuple[subprocess.Popen[bytes] | ZygoteRunnerProc, Path]:
        configure_aliyun_runner_recovery(env)
        return super()._spawn_runner_proc(env, session_slug, workspace)


def prepare_aliyun_host_directory(private: Path, *, home: Path | None = None) -> None:
    """Create one fresh credential directory only below this Host's private HOME."""

    home = Path.home() if home is None else home
    if (
        not home.is_absolute()
        or home.is_symlink()
        or private.parent != home / ".omnigent" / "runtime"
        or re.fullmatch(r"aliyun-host-[0-9a-f]{32}-[0-9a-f]{24}", private.name) is None
    ):
        raise AliyunHostConfigurationError("Aliyun Host private directory is invalid")
    for directory in (home, home / ".omnigent", private.parent):
        if directory != home:
            directory.mkdir(mode=0o700, exist_ok=True)
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or directory.is_symlink()
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            raise AliyunHostConfigurationError("Aliyun Host private directory is invalid")
        if directory != home:
            directory.chmod(0o700)
    private.mkdir(mode=0o700)


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError("cloud Host configuration is invalid")
    return value


def build_aliyun_model_channel(
    source: Mapping[str, str],
) -> tuple[str, AliyunHostModelTokenIssuer, str]:
    """Validate launch authorities without starting a process or reading a model key."""

    try:
        if any(source.get(name) for name in _SERVER_ONLY_ENV):
            raise ValueError("server authority must not enter the cloud Host")
        server = validated_server_origin(_required(source, SERVER_URL_ENV))
        gateway = validated_model_gateway_url(_required(source, MODEL_GATEWAY_URL_ENV))
        if not gateway.startswith("https://"):
            raise ValueError("cloud model endpoint must use TLS")
        host_id = _required(source, HOST_ID_ENV_VAR)
        if UUID(host_id).int == 0 or UUID(host_id).hex != host_id:
            raise ValueError("Host identity must be canonical")
        name = _required(source, HOST_NAME_ENV_VAR)
        if not 1 <= len(name) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise ValueError("Host name is invalid")
        workspace = _required(source, HOST_WORKSPACE_ID_ENV_VAR)
        if not workspace.isascii() or not workspace.isdecimal() or workspace.startswith("0"):
            raise ValueError("Host workspace is invalid")
        tenant = _required(source, MODEL_TENANT_ENV)
        if str(UUID(tenant)) != tenant:
            raise ValueError("Host tenant must be canonical")
        token = (
            _read_file(Path(_required(source, HOST_TOKEN_FILE_ENV_VAR)), private=True, maximum=512)
            .rstrip(b"\r\n")
            .decode("ascii")
        )
        lease = (
            _read_file(Path(_required(source, MODEL_LEASE_FILE_ENV)), private=True, maximum=16384)
            .rstrip(b"\r\n")
            .decode("ascii")
        )
        issuer = AliyunHostModelTokenIssuer(
            server_url=server,
            host_id=host_id,
            workspace_id=int(workspace),
            tenant_id=UUID(tenant),
            host_token=token,
            lease=lease,
        )
    except (ValueError, OSError, TypeError, OverflowError):
        raise AliyunHostConfigurationError("Aliyun Host launch configuration is invalid") from None
    return server, issuer, gateway


def run_aliyun_host() -> None:
    server, issuer, gateway = build_aliyun_model_channel(os.environ)
    run_host_with_model_issuer(
        server,
        issuer,
        ALIYUN_MODEL_TOKEN_TTL_SECONDS,
        gateway_base_url=gateway,
        host_process_type=AliyunHostProcess,
    )


def main() -> None:
    try:
        run_aliyun_host()
    except AliyunHostConfigurationError:
        print("Aliyun Host launch configuration is invalid", file=sys.stderr)
        raise SystemExit(HOST_FATAL_EXIT_CODE) from None


if __name__ == "__main__":
    main()
