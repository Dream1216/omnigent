"""Build/consumer receipt binding; synthetic ELF is never executed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from omnigent.harnesses.codex_native import executor_artifact as artifact


@pytest.mark.asyncio
async def test_artifact_receipt_binds_source_native_bytes_lock_and_normal_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = tmp_path / "@openai"
    package = scope / "codex"
    wrapper = package / "bin" / "codex.js"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("test wrapper, never executed")
    (package / "package.json").write_text(
        json.dumps({"name": "@openai/codex", "version": "0.142.0"})
    )
    native_package = scope / "codex-linux-x64"
    native = native_package / "vendor" / "x86_64-unknown-linux-musl" / "bin" / "codex"
    native.parent.mkdir(parents=True)
    header = bytearray(20)
    header[:6], header[18:20] = b"\x7fELF\x02\x01", (62).to_bytes(2, "little")
    native.write_bytes(header + b"synthetic metadata fixture, not executable")
    package_info = native_package / "package.json"
    package_info.write_text(json.dumps({"name": "@openai/codex", "version": "0.142.0-linux-x64"}))
    lock = tmp_path / "pnpm-lock.yaml"
    lock.write_text("fixed test lock input")
    manifest = tmp_path / "artifact.json"
    monkeypatch.setattr(artifact, "_machine", lambda: "x64")
    monkeypatch.setattr(artifact, "installed_revision", lambda: "a" * 40)
    monkeypatch.setattr(artifact, "HOST_LOCK_PATH", lock)
    monkeypatch.setattr(artifact, "ARTIFACT_PATH", manifest)

    def version(command, **kwargs):
        assert command == [str(native), "--version"]
        return SimpleNamespace(stdout="codex-cli 0.142.0\n")

    monkeypatch.setattr(artifact.subprocess, "run", version)
    artifact.record_installed_artifact(wrapper, manifest)
    installed = artifact.load_installed_artifact()
    assert installed.binary == native
    assert installed.sha256 == hashlib.sha256(native.read_bytes()).hexdigest()
    assert manifest.stat().st_mode & 0o222 == 0
    registry = Mock()
    registry.prepare_native_executor = AsyncMock(return_value="bound-runtime")
    server = Mock()
    assert (
        await artifact.prepare_installed_executor(registry, "session", tmp_path, server)
        == "bound-runtime"
    )
    registry.prepare_native_executor.assert_awaited_once_with(
        "session", tmp_path, server, binary=native, expected_sha256=installed.sha256
    )

    lock.write_text("different input")
    with pytest.raises(ValueError, match="lock bytes"):
        artifact.load_installed_artifact()
    lock.write_text("fixed test lock input")
    original = native.read_bytes()
    native.write_bytes(original + b"changed")
    with pytest.raises(ValueError, match="bytes differ"):
        artifact.load_installed_artifact()
    native.write_bytes(original)
    monkeypatch.setattr(artifact, "installed_revision", lambda: "b" * 40)
    with pytest.raises(ValueError, match="does not bind"):
        artifact.load_installed_artifact()
    monkeypatch.setattr(artifact, "installed_revision", lambda: "a" * 40)
    manifest.chmod(0o644)
    with pytest.raises(ValueError, match="mutable"):
        artifact.load_installed_artifact()
    from omnigent.runner.policy import AgentStartPolicyError

    registry.prepare_native_executor.reset_mock()
    with pytest.raises(AgentStartPolicyError, match="bound native Codex artifact"):
        await artifact.prepare_installed_executor(registry, "session", tmp_path, server)
    registry.prepare_native_executor.assert_not_awaited()
    manifest.chmod(0o444)
    package_info.write_text(json.dumps({"version": "0.143.0-linux-x64"}))
    with pytest.raises(ValueError, match="Native Codex package differs"):
        artifact.native_binary(wrapper)
