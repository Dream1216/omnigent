"""Sandbox-containment tests for the native Codex app-server spawn.

Covers the ordinary-M required-isolation contract: when a session's declared
``os_env`` resolves to an ACTIVE sandbox, the app-server must be spawned
through an omnigent sandbox launcher with codex's tool sandbox delegated via
the supported ``external-sandbox`` policy; ``None`` / ``type: none`` must
leave the launch exactly as before; containment + ``bypass_sandbox`` must
fail closed.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from omnigent.harnesses.codex_native import app_server as app_server_mod
from omnigent.harnesses.codex_native.app_server import (
    CodexNativeAppServer,
    build_codex_native_server,
)
from omnigent.inner.datamodel import OSEnvSandboxSpec, OSEnvSpec


def _server(**overrides: object) -> CodexNativeAppServer:
    base: dict[str, object] = {
        "codex_path": "/usr/local/bin/codex",
        "socket_path": Path("/tmp/test.sock"),
        "codex_home": Path("/tmp/test-codex-home"),
        "env": {},
        "config_overrides": [],
        "cwd": Path("/tmp"),
        "bridge_dir": Path("/tmp/test-bridge"),
    }
    base.update(overrides)
    return CodexNativeAppServer(**base)  # type: ignore[arg-type]


class _FakeWorkerLaunch:
    def __init__(self, *, sandboxed: bool) -> None:
        self.launch_path = "/tmp/fake-codex-launcher"
        self.sandboxed = sandboxed
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


def _active_os_env() -> OSEnvSpec:
    return OSEnvSpec(sandbox=OSEnvSandboxSpec(type="linux_bwrap"))


def _none_os_env() -> OSEnvSpec:
    return OSEnvSpec(sandbox=OSEnvSandboxSpec(type="none"))


def test_prepare_contained_launch_is_none_without_declared_os_env() -> None:
    server = _server(containment_os_env=None)
    assert server._prepare_contained_launch({}) is None


def test_prepare_contained_launch_is_none_for_type_none() -> None:
    # ``type: none`` must NOT carry external-sandbox onto an unsandboxed
    # app-server: the launch stays exactly as before.
    server = _server(containment_os_env=_none_os_env())
    assert server._prepare_contained_launch({}) is None


def test_prepare_contained_launch_fails_closed_when_sandbox_resolves_to_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsandboxed = _FakeWorkerLaunch(sandboxed=False)
    monkeypatch.setattr(app_server_mod, "prepare_codex_worker", lambda **_kwargs: unsandboxed)
    server = _server(containment_os_env=_active_os_env())
    with pytest.raises(OSError, match="refusing to launch"):
        server._prepare_contained_launch({})
    assert unsandboxed.close_calls == 1, "the rejected launch must be released"


def test_prepare_contained_launch_returns_launch_for_active_sandbox(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, object] = {}
    contained = _FakeWorkerLaunch(sandboxed=True)

    def _fake_prepare(**kwargs: object) -> _FakeWorkerLaunch:
        seen.update(kwargs)
        return contained

    monkeypatch.setattr(app_server_mod, "prepare_codex_worker", _fake_prepare)
    server = _server(
        codex_home=tmp_path / "home",
        cwd=tmp_path,
        containment_os_env=_active_os_env(),
    )
    proc_env = {"PATH": "/usr/bin"}
    launch = server._prepare_contained_launch(proc_env)
    assert launch is contained
    assert seen["codex_path"] == "/usr/local/bin/codex"
    assert seen["os_env"] is server.containment_os_env
    assert "PATH" in seen["spawn_env_names"]  # type: ignore[operator]


@pytest.mark.asyncio
async def test_contained_spawn_uses_launcher_and_external_sandbox(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    spawned: dict[str, object] = {}
    contained = _FakeWorkerLaunch(sandboxed=True)
    lock_path = tmp_path / "owner.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    lock_handle = app_server_mod.CodexNativeProcessOwnerLock(path=lock_path, fd=lock_fd)
    fake_proc = SimpleNamespace(pid=4242, stderr=None, returncode=None)

    async def _fake_exec(*args: object, **kwargs: object) -> object:
        spawned["argv"] = list(args)
        spawned["kwargs"] = kwargs
        return fake_proc

    async def _noop_stderr() -> None:
        await asyncio.sleep(0)

    monkeypatch.setattr(app_server_mod, "prepare_codex_worker", lambda **_k: contained)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(
        app_server_mod, "acquire_codex_native_process_owner_lock", lambda: lock_handle
    )
    monkeypatch.setattr(app_server_mod, "register_codex_native_process", lambda **_k: None)
    monkeypatch.setattr(app_server_mod, "_process_group_id", lambda _proc: 4242)

    server = _server(
        codex_home=tmp_path / "home",
        cwd=tmp_path,
        bridge_dir=tmp_path / "bridge",
        config_overrides=['model="gpt-5.4-mini"'],
        containment_os_env=_active_os_env(),
    )
    monkeypatch.setattr(server, "_stderr_loop", _noop_stderr)

    await server._spawn_app_server_process("ws://127.0.0.1:9")

    argv = spawned["argv"]  # type: ignore[index]
    kwargs = spawned["kwargs"]  # type: ignore[index]
    assert argv[0] == contained.launch_path, "spawn must go through the launcher"
    assert kwargs["executable"] == contained.launch_path
    assert 'sandbox_mode="external-sandbox"' in argv, (
        "codex's tool sandbox must be delegated to the outer sandbox via the "
        "supported external-sandbox policy"
    )
    assert "app-server" in argv and "--listen" in argv
    assert any(str(arg).startswith("omnigent-codex-native-tag:") for arg in argv) or any(
        "codex-native-" in str(arg) for arg in argv
    ), "the crash-reap tag must stay on the contained cmdline"
    assert server._worker_launch is contained
    assert server.process_owner_lock is lock_handle

    # Terminal teardown releases the owned launcher resources.
    fake_proc.returncode = 0  # already exited: close() skips process signaling
    await server.close()
    assert contained.close_calls == 1


@pytest.mark.asyncio
async def test_uncontained_spawn_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    spawned: dict[str, object] = {}
    fake_proc = SimpleNamespace(pid=99, stderr=None, returncode=None)

    async def _fake_exec(*args: object, **kwargs: object) -> object:
        spawned["argv"] = list(args)
        spawned["kwargs"] = kwargs
        return fake_proc

    async def _noop_stderr() -> None:
        await asyncio.sleep(0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(app_server_mod, "acquire_codex_native_process_owner_lock", lambda: None)
    monkeypatch.setattr(app_server_mod, "register_codex_native_process", lambda **_k: None)
    monkeypatch.setattr(app_server_mod, "_process_group_id", lambda _proc: 99)

    server = _server(
        codex_home=tmp_path / "home",
        cwd=tmp_path,
        bridge_dir=tmp_path / "bridge",
        containment_os_env=None,
    )
    monkeypatch.setattr(server, "_stderr_loop", _noop_stderr)

    await server._spawn_app_server_process("ws://127.0.0.1:9")

    argv = spawned["argv"]  # type: ignore[index]
    kwargs = spawned["kwargs"]  # type: ignore[index]
    assert "omnigent_crash_teardown_tag" in argv[0], "tagged argv0 preserved"
    assert kwargs["executable"] == "/usr/local/bin/codex"
    assert not any("external-sandbox" in str(arg) for arg in argv), (
        "no external-sandbox policy may appear on an uncontained launch"
    )
    assert server._worker_launch is None


def test_build_rejects_containment_with_bypass_sandbox(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="bypass_sandbox"):
        build_codex_native_server(
            socket_path=tmp_path / "s.sock",
            codex_home=tmp_path / "home",
            cwd=tmp_path,
            model=None,
            profile=None,
            bridge_dir=tmp_path / "bridge",
            bypass_sandbox=True,
            containment_os_env=_active_os_env(),
        )
