"""Build-time Codex artifact receipt, consumed only inside a qualified Host image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

    from omnigent.harnesses.codex_native.execution import CodexPrivateRuntime
    from omnigent.runner.resource_registry import SessionResourceRegistry

ARTIFACT_PATH = Path("/usr/local/share/omnigent-native-codex.json")
HOST_LOCK_PATH = Path("/opt/omnigent-host-cli/pnpm-lock.yaml")
CODEX_VERSION = "0.142.0"


@dataclass(frozen=True)
class CodexRuntimeArtifact:
    binary: Path
    sha256: str
    source_revision: str


def installed_revision() -> str:
    from omnigent import _build_info

    value = _build_info.COMMIT_SHA
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{40}", value) is None:
        raise ValueError("Host has no installed source revision binding")
    return value


def _machine() -> str:
    value = platform.machine().lower()
    if value in {"x86_64", "amd64"}:
        return "x64"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    raise ValueError("Unsupported qualified Codex Host architecture")


def _elf(path: Path) -> None:
    with path.open("rb") as source:
        header = source.read(20)
    machine = 62 if _machine() == "x64" else 183
    if (
        len(header) != 20
        or header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != machine
    ):
        raise ValueError("Codex artifact is not the native Linux executable for this Host")


def native_binary(command: Path) -> Path:
    """Select the existing pinned native executable, avoiding another Node wrapper."""
    command = command.resolve(strict=True)
    with command.open("rb") as source:
        if source.read(4) == b"\x7fELF":
            _elf(command)
            return command
    package = command.parent.parent
    metadata = json.loads((package / "package.json").read_text())
    if metadata.get("name") != "@openai/codex" or metadata.get("version") != CODEX_VERSION:
        raise ValueError("Installed Codex package differs from the fixed CLI")
    binary_package = package.parent / ("codex-linux-" + _machine())
    roots = [package]
    if binary_package.is_dir():
        info = json.loads((binary_package / "package.json").read_text())
        if info.get("version") != CODEX_VERSION + "-linux-" + _machine():
            raise ValueError("Native Codex package differs from the fixed CLI")
        roots.insert(0, binary_package)
    matches = [path.resolve() for root in roots for path in root.glob("vendor/*/bin/codex")]
    if len(set(matches)) != 1:
        raise ValueError("Pinned native Codex executable is missing or ambiguous")
    binary = matches[0]
    _elf(binary)
    return binary


def record_installed_artifact(command: Path, destination: Path = ARTIFACT_PATH) -> None:
    """Run during the normal image build; this receipt is not a release PASS."""
    binary = native_binary(command)
    revision = installed_revision()
    response = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        check=True,
        timeout=10,
        env={"PATH": os.defpath},
        text=True,
    )
    if response.stdout.strip() != "codex-cli " + CODEX_VERSION:
        raise ValueError("Installed native Codex version does not match the pin")
    with binary.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    with HOST_LOCK_PATH.open("rb") as source:
        lock_digest = hashlib.file_digest(source, "sha256").hexdigest()
    payload = {
        "schema": 1,
        "source_revision": revision,
        "version": CODEX_VERSION,
        "architecture": _machine(),
        "binary": str(binary),
        "sha256": digest,
        "lock_path": str(HOST_LOCK_PATH),
        "lock_sha256": lock_digest,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x") as target:
        json.dump(payload, target, sort_keys=True)
        target.write("\n")
    destination.chmod(0o444)


def load_installed_artifact() -> CodexRuntimeArtifact:
    """Require the receipt carried by the same signed OCI and installed wheel."""
    path = ARTIFACT_PATH
    info = path.lstat()
    if path.is_symlink() or info.st_mode & 0o222:
        raise ValueError("Installed native artifact receipt is mutable")
    data = json.loads(path.read_text())
    if (
        not isinstance(data, dict)
        or data.get("schema") != 1
        or data.get("source_revision") != installed_revision()
        or data.get("version") != CODEX_VERSION
        or data.get("architecture") != _machine()
    ):
        raise ValueError("Installed native artifact receipt does not bind this Host")
    binary = Path(data["binary"])
    if not binary.is_absolute() or binary.resolve(strict=True) != binary:
        raise ValueError("Installed native Codex path is not canonical")
    _elf(binary)
    lock = Path(data["lock_path"])
    if lock != HOST_LOCK_PATH:
        raise ValueError("Installed CLI lock binding differs from the Host input")
    with lock.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != data.get("lock_sha256"):
            raise ValueError("Installed CLI lock bytes differ from the image receipt")
    with binary.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if re.fullmatch(r"[a-f0-9]{64}", str(data.get("sha256"))) is None or digest != data["sha256"]:
        raise ValueError("Installed native Codex bytes differ from the image receipt")
    return CodexRuntimeArtifact(binary, digest, data["source_revision"])


async def prepare_installed_executor(
    registry: SessionResourceRegistry,
    session_id: str,
    bridge: Path,
    server_client: httpx.AsyncClient,
) -> CodexPrivateRuntime:
    import asyncio

    try:
        artifact = await asyncio.to_thread(load_installed_artifact)
    except (ImportError, OSError, ValueError) as error:
        from omnigent.runner.policy import AgentStartPolicyError

        raise AgentStartPolicyError("server", "has no bound native Codex artifact") from error
    return await registry.prepare_native_executor(
        session_id,
        bridge,
        server_client,
        binary=artifact.binary,
        expected_sha256=artifact.sha256,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--command", type=Path)
    args = parser.parse_args()
    command = args.command or Path(shutil.which("codex") or "")
    if not str(command) or not command.is_file():
        raise ValueError("Installed pinned Codex command is unavailable")
    record_installed_artifact(command)


if __name__ == "__main__":
    main()
