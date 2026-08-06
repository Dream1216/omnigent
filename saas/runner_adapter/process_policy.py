"""Managed-SaaS process policy around the official Host/Runner launcher.

The official local Host may use a long-lived copy-on-write zygote to fork many
Runner processes.  That is a useful single-user optimization, but it is not a
safe default for a managed multi-tenant execution plane: the forkserver starts
from the Host environment and imported process image, while the SaaS Secret
Broker and containment contracts require one auditable process boundary per
Runner incarnation.

This adapter deliberately leaves the official local product unchanged.  A
managed Host entrypoint must build and activate this environment before it
constructs :class:`omnigent.host.connect.HostProcess`.  Until a separate
fork-safety review proves that cached credentials, file descriptors, native
library state, telemetry state, and tenant context are all reset after every
fork, managed modes use the official direct-``Popen`` fallback.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, MutableMapping
from pathlib import Path

from omnigent.host.connect import (
    HARNESS_CREDENTIAL_ENV_VARS,
    RUNNER_ENTRY_MODULE_ENV_VAR,
    RUNNER_ENV_PASSTHROUGH_ENV_VAR,
    HostProcess,
    run_host_process,
)
from omnigent.host.frames import HostLaunchRunnerFrame, HostLaunchRunnerResultFrame
from omnigent.host.identity import HostIdentity
from omnigent.host.runner_zygote import ZygoteRunnerProc
from omnigent.process_logging import env_truthy
from omnigent.runner._zygote import ZYGOTE_ENABLED_ENV_VAR
from omnigent.runner.identity import RUNNER_ID_ENV_VAR, token_bound_runner_id
from saas.runner_adapter.metering import (
    MANAGED_METERING_ENVELOPE_ENV_VAR,
    ManagedMeteringError,
    ManagedMeteringGrant,
    ManagedRunnerLaunchAuthority,
    managed_runner_entry_module,
    write_metering_envelope,
)

_CANONICAL_ZYGOTE_DISABLED = "0"
_METERING_LAUNCH_ERROR = "managed_metering_grant_denied"


class ManagedRunnerProcessPolicyError(RuntimeError):
    """A managed Host process environment violates the SaaS launch policy."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _ambient_credential_names(environment: Mapping[str, str]) -> tuple[str, ...]:
    """Return known non-empty credentials the official Host would forward.

    Values are never included in the result or an exception, so a deployment
    error cannot copy secret material into logs.
    """

    return tuple(
        sorted(
            name
            for name in HARNESS_CREDENTIAL_ENV_VARS
            if (value := environment.get(name)) is not None and value.strip()
        )
    )


def build_managed_host_environment(base: Mapping[str, str]) -> dict[str, str]:
    """Build a fail-closed environment for one managed SaaS Host process.

    The caller supplies a server-owned base environment.  Known provider/Git
    credentials and operator-selected passthrough variables are rejected: Run
    and Tool credentials must arrive through the mTLS Secret Broker after the
    launch grant is validated.  A truthy zygote override is also rejected
    instead of silently weakening an explicit operator setting.

    This function does not mutate ``base``.
    """

    credentials = _ambient_credential_names(base)
    if credentials:
        joined = ", ".join(credentials)
        raise ManagedRunnerProcessPolicyError(
            "managed_runner_ambient_credentials",
            f"managed Host environment contains forbidden credential variables: {joined}",
        )

    passthrough = base.get(RUNNER_ENV_PASSTHROUGH_ENV_VAR, "")
    passthrough_names = tuple(
        sorted(name.strip() for name in passthrough.split(",") if name.strip())
    )
    if passthrough_names:
        joined = ", ".join(passthrough_names)
        raise ManagedRunnerProcessPolicyError(
            "managed_runner_ambient_passthrough",
            f"managed Host environment requests forbidden credential passthrough: {joined}",
        )

    configured_zygote = base.get(ZYGOTE_ENABLED_ENV_VAR)
    if configured_zygote is not None and env_truthy(configured_zygote):
        raise ManagedRunnerProcessPolicyError(
            "managed_runner_zygote_enabled",
            "managed Host environment explicitly enables the upstream Runner zygote",
        )

    environment = dict(base)
    # Canonicalize every false spelling to the exact value used in deployment
    # evidence and ensure the upstream Host selects its direct-Popen path.
    environment[ZYGOTE_ENABLED_ENV_VAR] = _CANONICAL_ZYGOTE_DISABLED
    environment[RUNNER_ENTRY_MODULE_ENV_VAR] = managed_runner_entry_module()
    environment.pop(RUNNER_ENV_PASSTHROUGH_ENV_VAR, None)
    for name in HARNESS_CREDENTIAL_ENV_VARS:
        if not environment.get(name, "").strip():
            environment.pop(name, None)
    return environment


def require_managed_host_environment(environment: Mapping[str, str]) -> None:
    """Verify the exact environment contract immediately before Host startup."""

    if environment.get(ZYGOTE_ENABLED_ENV_VAR) != _CANONICAL_ZYGOTE_DISABLED:
        raise ManagedRunnerProcessPolicyError(
            "managed_runner_zygote_not_disabled",
            "managed Host must disable the upstream Runner zygote with the canonical value 0",
        )
    if environment.get(RUNNER_ENTRY_MODULE_ENV_VAR) != managed_runner_entry_module():
        raise ManagedRunnerProcessPolicyError(
            "managed_runner_entry_invalid",
            "managed Host must use the reviewed downstream Runner entrypoint",
        )
    credentials = _ambient_credential_names(environment)
    if credentials or environment.get(RUNNER_ENV_PASSTHROUGH_ENV_VAR, "").strip():
        raise ManagedRunnerProcessPolicyError(
            "managed_runner_ambient_credentials",
            "managed Host must receive Run and Tool credentials only from the Secret Broker",
        )


def activate_managed_host_environment(
    environment: MutableMapping[str, str] = os.environ,
) -> None:
    """Atomically validate and activate the managed policy in a process env."""

    prepared = build_managed_host_environment(environment)
    environment.clear()
    environment.update(prepared)
    require_managed_host_environment(environment)


class ManagedHostProcess(HostProcess):
    """Official Host with a one-time downstream metering envelope per launch."""

    def __init__(
        self,
        identity: HostIdentity,
        server_url: str,
        *,
        launch_authority: ManagedRunnerLaunchAuthority,
        envelope_directory: Path,
    ) -> None:
        super().__init__(identity, server_url)
        self._launch_authority = launch_authority
        self._envelope_directory = envelope_directory
        self._pending_metering: dict[str, ManagedMeteringGrant] = {}
        self._metering_envelopes: dict[str, Path] = {}

    async def _handle_launch(self, frame: HostLaunchRunnerFrame) -> HostLaunchRunnerResultFrame:
        runner_id = token_bound_runner_id(frame.binding_token)
        if frame.session_id is None:
            return HostLaunchRunnerResultFrame(
                request_id=frame.request_id,
                status="failed",
                error="managed launch requires a scheduler-bound session",
                error_code=_METERING_LAUNCH_ERROR,
            )
        try:
            grant = self._launch_authority.claim_metering_grant(
                session_id=frame.session_id,
                official_runner_id=runner_id,
            )
        except ManagedMeteringError:
            return HostLaunchRunnerResultFrame(
                request_id=frame.request_id,
                status="failed",
                error="managed launch metering authority denied the Runner",
                error_code=_METERING_LAUNCH_ERROR,
            )
        self._pending_metering[runner_id] = grant
        try:
            result = await super()._handle_launch(frame)
            if result.status != "launched":
                self._cleanup_metering_envelope(runner_id)
            return result
        finally:
            self._pending_metering.pop(runner_id, None)

    def _spawn_runner_proc(
        self, env: dict[str, str], session_slug: str
    ) -> tuple[subprocess.Popen[bytes] | ZygoteRunnerProc, Path]:
        runner_id = env.get(RUNNER_ID_ENV_VAR, "")
        grant = self._pending_metering.pop(runner_id, None)
        if grant is None:
            raise OSError("managed Runner metering grant is unavailable")
        try:
            envelope = write_metering_envelope(
                self._envelope_directory,
                grant=grant,
                official_runner_id=runner_id,
            )
        except ManagedMeteringError as exc:
            raise OSError("managed Runner metering envelope is unavailable") from exc
        env[MANAGED_METERING_ENVELOPE_ENV_VAR] = str(envelope)
        self._metering_envelopes[runner_id] = envelope
        try:
            return super()._spawn_runner_proc(env, session_slug)
        except BaseException:
            self._cleanup_metering_envelope(runner_id)
            raise

    async def _watch_runner(self, runner_id: str) -> None:
        try:
            await super()._watch_runner(runner_id)
        finally:
            self._cleanup_metering_envelope(runner_id)

    def _cleanup_metering_envelope(self, runner_id: str) -> None:
        path = self._metering_envelopes.pop(runner_id, None)
        if path is not None:
            path.unlink(missing_ok=True)


def run_managed_host_process(
    server_url: str,
    config_path: Path | None = None,
    *,
    launch_authority: ManagedRunnerLaunchAuthority,
    envelope_directory: Path,
) -> None:
    """Run the official Host behind the managed-SaaS process policy boundary."""

    activate_managed_host_environment()

    # HostProcess reads the zygote switch in its constructor, so activation
    # must precede the official composition root.
    def factory(identity: HostIdentity, resolved_server_url: str) -> ManagedHostProcess:
        return ManagedHostProcess(
            identity,
            resolved_server_url,
            launch_authority=launch_authority,
            envelope_directory=envelope_directory,
        )

    run_host_process(server_url, config_path, host_factory=factory)


__all__ = [
    "ManagedHostProcess",
    "ManagedRunnerProcessPolicyError",
    "activate_managed_host_environment",
    "build_managed_host_environment",
    "require_managed_host_environment",
    "run_managed_host_process",
]
