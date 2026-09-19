"""Production Host entrypoint for session-bound Platform model access."""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Mapping
from pathlib import Path
from uuid import UUID

from omnigent.debug_logging import PRIMARY_SESSION_ID_ENV_VAR
from omnigent.host.connect import HostProcess, run_host_process
from omnigent.host.daemon_lifecycle import DaemonLifecycleLock
from omnigent.host.frames import HarnessAvailability
from omnigent.host.identity import HostIdentity
from omnigent.host.runner_zygote import ZygoteRunnerProc
from omnigent.onboarding.provider_config import default_provider_for_harness, load_config
from saas.runner_adapter.platform_model_gateway import (
    PlatformModelGatewayTokenAuthority,
    inject_platform_model_gateway_token,
)
from saas.runner_adapter.platform_models import PLATFORM_MODEL_CREDENTIAL_ENV
from saas.runner_adapter.process_policy import activate_managed_host_environment

_SERVER_URL_ENV = "OMNIGENT_SAAS_SERVER_URL"
_TENANT_ID_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID"
_SIGNING_KEY_FILE_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE"
_TOKEN_TTL_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_TTL_SECONDS"


class PlatformModelHostConfigurationError(ValueError):
    """The managed Host composition is missing an immutable authority input."""


class PlatformModelHostProcess(HostProcess):
    """Official Host that injects a short-lived model token per Runner session."""

    def __init__(
        self,
        identity: HostIdentity,
        server_url: str,
        *,
        lifecycle_lock: DaemonLifecycleLock | None = None,
        interactive_shells: list[str] | None = None,
        token_authority: PlatformModelGatewayTokenAuthority,
        token_ttl_seconds: int,
    ) -> None:
        super().__init__(
            identity,
            server_url,
            lifecycle_lock=lifecycle_lock,
            interactive_shells=interactive_shells,
        )
        self._platform_model_tokens = token_authority
        self._platform_model_token_ttl = token_ttl_seconds

    async def _probe_configured_harnesses(
        self,
        *,
        startup: bool,
    ) -> dict[str, HarnessAvailability] | None:
        """Credit the managed Provider without pretending a missing CLI exists.

        Host-wide readiness runs before a per-session synthetic bearer exists.
        The official Codex readiness probe therefore sees the deliberately
        unresolved ``$OMNIGENT_PLATFORM_DEEPSEEK_KEY`` reference and reports
        ``needs-auth``, even though this Host injects that bearer into every
        Runner immediately before spawn. Promote only that auth-only state,
        and only when the pinned platform Provider is the Codex default. A
        missing or unsupported Codex binary remains unavailable.
        """

        configured = await super()._probe_configured_harnesses(startup=startup)
        if configured is None or not _platform_codex_provider_configured():
            return configured
        promoted = dict(configured)
        for harness in ("codex", "codex-native", "native-codex"):
            if promoted.get(harness) == "needs-auth":
                promoted[harness] = True
        return promoted

    def _spawn_runner_proc(
        self,
        env: dict[str, str],
        session_slug: str,
        workspace: Path,
    ) -> tuple[subprocess.Popen[bytes] | ZygoteRunnerProc, Path]:
        try:
            session_id = UUID(env[PRIMARY_SESSION_ID_ENV_VAR])
        except (KeyError, ValueError):
            raise OSError("Platform model Runner requires a canonical session identity") from None
        inject_platform_model_gateway_token(
            env,
            authority=self._platform_model_tokens,
            session_id=session_id,
            ttl_seconds=self._platform_model_token_ttl,
        )
        try:
            return super()._spawn_runner_proc(env, session_slug, workspace)
        finally:
            # Popen has copied the environment by this point. Keep the bearer
            # out of Host-side retained dictionaries and exception formatting.
            env.pop(PLATFORM_MODEL_CREDENTIAL_ENV, None)


def run_platform_model_host(environ: Mapping[str, str] = os.environ) -> None:
    """Validate all authorities, then run the official Host composition."""

    server_url = _required(environ, _SERVER_URL_ENV)
    try:
        tenant_id = UUID(_required(environ, _TENANT_ID_ENV))
        token_ttl = int(environ.get(_TOKEN_TTL_ENV, "3600"))
    except ValueError:
        raise PlatformModelHostConfigurationError(
            "Platform model Host identity is invalid"
        ) from None
    if tenant_id.int == 0 or not 60 <= token_ttl <= 8 * 60 * 60:
        raise PlatformModelHostConfigurationError("Platform model Host identity is invalid")
    signing_key = _secret_file(environ, _SIGNING_KEY_FILE_ENV)
    authority = PlatformModelGatewayTokenAuthority(
        signing_key=signing_key,
        tenant_id=tenant_id,
    )

    # The direct-spawn policy prevents a session bearer from ever entering a
    # long-lived forkserver snapshot.
    activate_managed_host_environment()

    def factory(
        identity: HostIdentity,
        resolved_server_url: str,
        *,
        lifecycle_lock: DaemonLifecycleLock | None = None,
        interactive_shells: list[str] | None = None,
    ) -> PlatformModelHostProcess:
        return PlatformModelHostProcess(
            identity,
            resolved_server_url,
            lifecycle_lock=lifecycle_lock,
            interactive_shells=interactive_shells,
            token_authority=authority,
            token_ttl_seconds=token_ttl,
        )

    run_host_process(server_url, host_factory=factory)


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise PlatformModelHostConfigurationError(f"{name} is invalid")
    return value


def _platform_codex_provider_configured() -> bool:
    """Return whether the immutable Host config routes Codex to our gateway."""

    try:
        provider = default_provider_for_harness(load_config(), "codex")
    except Exception:  # noqa: BLE001 - readiness must fail closed, never break Host startup.
        return False
    return (
        provider is not None
        and provider.name == "platform-deepseek"
        and provider.kind == "gateway"
    )


def _secret_file(source: Mapping[str, str], name: str) -> bytes:
    path = Path(_required(source, name))
    try:
        metadata = path.lstat()
        value = path.read_bytes().rstrip(b"\r\n")
    except OSError:
        raise PlatformModelHostConfigurationError(f"{name} is unavailable") from None
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not 32 <= len(value) <= 4096
        or b"\x00" in value
    ):
        raise PlatformModelHostConfigurationError(f"{name} is invalid")
    return value


def main() -> None:
    run_platform_model_host()


if __name__ == "__main__":
    main()


__all__ = [
    "PlatformModelHostConfigurationError",
    "PlatformModelHostProcess",
    "run_platform_model_host",
]
