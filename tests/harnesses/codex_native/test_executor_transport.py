"""Private fixed-version executor transport; no CLI or kernel sandbox claim."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import tempfile
import threading
import tomllib
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest

from omnigent.harnesses.codex_native import execution
from omnigent.harnesses.codex_native.executor_transport import (
    SessionExecutorEndpoint,
    forward_stdio,
)
from omnigent.inner.bwrap_sandbox import BwrapSandboxBackend
from omnigent.inner.sandbox import SandboxPolicy
from omnigent.runner.identity import token_bound_runner_id
from omnigent.runner.session_channels import SessionRelayChannel


def test_rejected_executor_endpoint_allocates_no_runtime_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = Mock(spec=SessionRelayChannel)
    model.session_id, model.runner_id, model.generation = (
        str(uuid4()),
        "runner_token_test",
        "a" * 32,
    )
    policy = Mock(spec=SessionRelayChannel)
    policy.role, policy.generation = "policy", model.generation
    endpoint = Mock(spec=SessionExecutorEndpoint)
    endpoint.verify.side_effect = ValueError("stale executor endpoint")
    allocate = Mock(side_effect=AssertionError("Rejected endpoint allocated a directory"))
    monkeypatch.setattr(execution.tempfile, "mkdtemp", allocate)
    with pytest.raises(ValueError, match="stale executor"):
        execution.CodexPrivateRuntime.create(model, policy, Path("/unused"), executor=endpoint)
    allocate.assert_not_called()


def test_session_executor_projection_and_private_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with tempfile.TemporaryDirectory(prefix="om-exec-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        with contextlib.ExitStack() as stack:
            sockets = {}
            for role in ("model", "policy", "executor"):
                listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                listener.bind(str(root / (role + ".sock")))
                (root / (role + ".sock")).chmod(0o600)
                sockets[role] = listener
            session_id = str(uuid4())
            runner_id = token_bound_runner_id("test-executor-binding")
            channels = {}
            for role in ("model", "policy"):
                path = root / (role + ".sock")
                identity = path.lstat()
                channels[role] = SessionRelayChannel(
                    session_id,
                    runner_id,
                    "a" * 32,
                    str(path),
                    31401,
                    identity.st_dev,
                    identity.st_ino,
                    role,
                )
            path = root / "executor.sock"
            identity = path.lstat()
            endpoint = SessionExecutorEndpoint(
                session_id, runner_id, "a" * 32, path, identity.st_dev, identity.st_ino
            )
            bridge = tmp_path / "bridge"
            bridge.mkdir()
            (bridge / "tool_relay.json").write_text(
                json.dumps(
                    {
                        "url": "http://127.0.0.1:31401",
                        "token": "test-local-capability",
                        "session_id": session_id,
                        "generation": "a" * 32,
                        "socket_path": channels["policy"].socket_path,
                        "tools": [],
                    }
                )
            )
            monkeypatch.setattr(execution, "SYSTEM_CODEX_REQUIREMENTS", tmp_path / "absent")
            runtime = execution.CodexPrivateRuntime.create(
                channels["model"], channels["policy"], bridge, executor=endpoint
            )
            stack.callback(shutil.rmtree, runtime.root)
            config = tomllib.loads((runtime.home / "environments.toml").read_text())
            assert config["include_local"] is False
            assert len(config["environments"]) == 1
            assert config["environments"][0]["id"] == config["default"]
            assert "--socket" in config["environments"][0]["args"]
            requirements = tomllib.loads((runtime.root / "requirements.toml").read_text())
            assert requirements["features"]["use_legacy_landlock"] is False
            policy = runtime.apply(SandboxPolicy("linux_bwrap", True, [], [], [], False))
            policy = SandboxPolicy.from_jsonable(policy.to_jsonable())
            argv = BwrapSandboxBackend().wrap_launcher_argv(["/bin/true"], policy, tmp_path)
            mount = [
                "--ro-bind",
                str(runtime.root / "environments.toml"),
                str(runtime.home / "environments.toml"),
            ]
            assert any(argv[i : i + 3] == mount for i in range(len(argv) - 2))
            (runtime.root / "environments.toml").unlink()
            with pytest.raises(ValueError, match="executor configuration"):
                BwrapSandboxBackend().wrap_launcher_argv(["/bin/true"], policy, tmp_path)

            listener = sockets["executor"]
            listener.listen(1)
            input_read, input_write = os.pipe()
            output_read, output_write = os.pipe()
            for fd in (input_read, input_write, output_read, output_write):
                stack.callback(os.close, fd)
            failures = []

            def connect() -> None:
                try:
                    forward_stdio(
                        path,
                        device=identity.st_dev,
                        inode=identity.st_ino,
                        stdin=input_read,
                        stdout=output_write,
                    )
                except Exception as error:
                    failures.append(error)

            thread = threading.Thread(target=connect)
            thread.start()
            with listener.accept()[0] as peer:
                request = b'{"id":1,"method":"fs/writeFile","params":{}}\n'
                os.write(input_write, request)
                assert peer.recv(65536) == request
                response = b'{"id":1,"result":{}}\n'
                peer.sendall(response)
                assert os.read(output_read, 65536) == response
            thread.join(timeout=2)
            assert not thread.is_alive() and not failures
            with pytest.raises(ValueError, match="endpoint changed"):
                forward_stdio(
                    path,
                    device=identity.st_dev,
                    inode=identity.st_ino + 1,
                    stdin=input_read,
                    stdout=output_write,
                )

            from dataclasses import replace

            from omnigent.harnesses.codex_native.main import _find_codex_rollout
            from tests.harnesses.codex_native.session._support import _write_source_rollout

            thread_id = "019e96aa-0be2-7343-8d3b-6f914d60936b"
            saved = _write_source_rollout(
                codex_home=runtime.home, thread_id=thread_id, source_cwd=str(tmp_path)
            )
            (runtime.home / "auth.json").write_text('{"old_private_credential":"must-stay-old"}')
            runtime.close()
            refreshed = {
                role: replace(channel, generation="b" * 32) for role, channel in channels.items()
            }
            advertisement = json.loads((bridge / "tool_relay.json").read_text())
            advertisement["generation"] = "b" * 32
            (bridge / "tool_relay.json").write_text(json.dumps(advertisement))
            next_runtime = execution.CodexPrivateRuntime.create(
                refreshed["model"],
                refreshed["policy"],
                bridge,
                executor=replace(endpoint, generation="b" * 32),
            )
            stack.callback(shutil.rmtree, next_runtime.root)
            assert next_runtime.home != runtime.home and next_runtime.history == runtime.history
            restored = _find_codex_rollout(next_runtime.home, thread_id)
            assert restored is not None and restored.read_bytes() == saved.read_bytes()
            assert not (next_runtime.home / "auth.json").exists()
            assert (
                json.loads((next_runtime.bridge / "tool_relay.json").read_text())["generation"]
                == "b" * 32
            )
