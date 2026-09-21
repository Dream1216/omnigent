"""Managed-sandbox Host entrypoint for Platform model access.

Kubernetes Secret volumes are projected through symlinks and are commonly
group-readable under a Pod ``fsGroup``.  The Platform Host intentionally
accepts only an owner-readable regular signing-key file.  This small entrypoint
copies the projected key into the sandbox's private HOME, makes it mode 0400,
then delegates to the existing production Host composition.
"""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Mapping, MutableMapping
from contextlib import suppress
from pathlib import Path

from omnigent.onboarding.sandboxes.kubernetes import MANAGED_SERVER_URL_ENV_VAR
from saas.production.platform_model_host import run_platform_model_host

_SOURCE_KEY = Path("/credentials/omnigent-platform-model/key")
_SERVER_URL_ENV = "OMNIGENT_SAAS_SERVER_URL"
_SIGNING_KEY_FILE_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_KEY_FILE"
_TOKEN_TTL_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TOKEN_TTL_SECONDS"


class PlatformModelSandboxHostConfigurationError(ValueError):
    """The managed sandbox is missing an immutable Host authority input."""


def stage_platform_model_key(
    environ: MutableMapping[str, str] = os.environ,
    *,
    source: Path = _SOURCE_KEY,
) -> Path:
    """Stage the projected signing key as an owner-only regular file."""

    server_url = environ.get(MANAGED_SERVER_URL_ENV_VAR, "")
    if (
        not server_url
        or server_url != server_url.strip()
        or "\x00" in server_url
        or not server_url.startswith(("http://", "https://"))
    ):
        raise PlatformModelSandboxHostConfigurationError(
            f"{MANAGED_SERVER_URL_ENV_VAR} is invalid"
        )
    try:
        metadata = source.stat()
        key = source.read_bytes().rstrip(b"\r\n")
    except OSError:
        raise PlatformModelSandboxHostConfigurationError(
            "platform model signing key projection is unavailable"
        ) from None
    if not stat.S_ISREG(metadata.st_mode) or not 32 <= len(key) <= 4096 or b"\x00" in key:
        raise PlatformModelSandboxHostConfigurationError(
            "platform model signing key projection is invalid"
        )

    home_value = environ.get("HOME", "")
    home = Path(home_value)
    if not home_value or not home.is_absolute() or "\x00" in home_value:
        raise PlatformModelSandboxHostConfigurationError("HOME is invalid")
    private_dir = home / ".omnigent" / "runtime"
    private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(private_dir, 0o700)
    target = private_dir / "platform-model-token-key"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".key-", dir=private_dir)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, target)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()

    environ[_SERVER_URL_ENV] = server_url
    environ[_SIGNING_KEY_FILE_ENV] = str(target)
    environ.setdefault(_TOKEN_TTL_ENV, "3600")
    return target


def run_platform_model_sandbox_host(
    environ: MutableMapping[str, str] = os.environ,
) -> None:
    """Stage sandbox-only authorities, then run the production Platform Host."""

    stage_platform_model_key(environ)
    run_platform_model_host(environ)


def main(source: Mapping[str, str] | None = None) -> None:
    if source is None:
        run_platform_model_sandbox_host()
        return
    environment = dict(source)
    run_platform_model_sandbox_host(environment)


if __name__ == "__main__":
    main()


__all__ = [
    "PlatformModelSandboxHostConfigurationError",
    "run_platform_model_sandbox_host",
    "stage_platform_model_key",
]
