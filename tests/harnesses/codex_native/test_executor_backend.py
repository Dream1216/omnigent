"""Required execution backend's policy/I/O contract; kernel executor is explicitly mocked."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest

from omnigent.harnesses.codex_native import executor_worker
from omnigent.harnesses.codex_native.executor_backend import SessionExecutorBackend
from omnigent.harnesses.codex_native.executor_bwrap import required_bwrap_argv
from omnigent.harnesses.codex_native.executor_policy import SessionExecutionPolicy
from omnigent.inner.sandbox import SandboxPolicy
from omnigent.runner.session_channels import SessionRelayChannel


@pytest.fixture
def authority(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with tempfile.TemporaryDirectory(prefix="om-authority-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        with contextlib.ExitStack() as cleanup:
            channels = []
            session = uuid4().hex
            for role in ("model", "policy"):
                listener = cleanup.enter_context(socket.socket(socket.AF_UNIX))
                path = root / (role + ".sock")
                listener.bind(str(path))
                path.chmod(0o600)
                info = path.lstat()
                channels.append(
                    SessionRelayChannel(
                        session,
                        "runner_test_bound",
                        "b" * 32,
                        str(path),
                        31401 if role == "model" else 31402,
                        info.st_dev,
                        info.st_ino,
                        role,
                    )
                )
            required = SandboxPolicy(
                "linux_bwrap",
                True,
                [workspace],
                [workspace],
                [],
                False,
                cwd_allow_hidden=["*"],
                env_passthrough=["APP_VALUE"],
            )
            bound = SessionExecutionPolicy.bind(
                channels[0],
                channels[1],
                workspace,
                required,
                {
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(workspace),
                    "APP_VALUE": "permitted",
                    "OPENAI_API_KEY": "must-never-pass",
                    "_OMNIGENT_RUNNER_TOKEN": "must-never-pass",
                },
            )
            yield bound, channels


def make_executor(monkeypatch: pytest.MonkeyPatch):
    """Keep the fixed executor/kernel mock visible; actual worker FS I/O remains real."""
    client = Mock()
    records, outputs = [], {}
    activated = []

    async def request(method, params):
        records.append((method, params))
        if method == "process/start":
            plan = json.loads(Path(params["argv"][-1]).read_text())
            assert params["sandbox"]["permissions"]["type"] == "managed"
            assert params["sandbox"]["permissions"]["network"] == "restricted"
            assert params["sandbox"]["useLegacyLandlock"] is False
            if plan["operation"].startswith("fs/") and plan["operation"] != "fs/open":
                with monkeypatch.context() as patch:
                    patch.setattr(executor_worker.sys, "platform", "linux")
                    patch.setattr(executor_worker.os, "chdir", lambda cwd: None)
                    patch.setattr(
                        executor_worker.BwrapSandboxBackend,
                        "activate",
                        lambda self, policy: activated.append(policy.backend_type),
                    )
                    result = executor_worker.run_plan(plan)
                outputs[params["processId"]] = json.dumps(result).encode()
            else:
                outputs[params["processId"]] = b""
            return {"result": {"processId": params["processId"]}}
        if method == "process/read":
            return {
                "result": {
                    "chunks": [
                        {
                            "seq": 1,
                            "stream": "stdout",
                            "chunk": base64.b64encode(outputs[params["processId"]]).decode(),
                        }
                    ],
                    "nextSeq": 1,
                    "exited": True,
                    "exitCode": 0,
                    "failure": None,
                }
            }
        if method == "process/terminate":
            return {"result": {"running": False}}
        if method == "environment/info":
            return {"result": {"shell": {"name": "sh", "path": "/bin/sh"}}}
        raise AssertionError(method)

    client.request = AsyncMock(side_effect=request)
    client.close = AsyncMock()
    return client, records, activated


@pytest.mark.asyncio
async def test_bound_backend_workspace_write_and_metadata_outside_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority,
) -> None:
    bound, channels = authority
    executor, records, activated = make_executor(monkeypatch)
    root = tmp_path / "backend"
    root.mkdir(mode=0o700)
    requests = []

    def allow(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        assert str(request.url).endswith(f"/v1/sessions/{bound.session_id}/policies/evaluate")
        return httpx.Response(200, json={"result": "POLICY_ACTION_ALLOW"})

    async with httpx.AsyncClient(
        base_url="https://original.test", transport=httpx.MockTransport(allow)
    ) as server:
        backend = SessionExecutorBackend(bound, *channels, server, executor, root)
        file = bound.cwd / "result.bin"
        await backend.dispatch(
            "fs/writeFile",
            {"path": file.as_uri(), "dataBase64": base64.b64encode(b"\0real-file").decode()},
        )
        assert file.read_bytes() == b"\0real-file"
        read = await backend.dispatch("fs/readFile", {"path": file.as_uri()})
        assert base64.b64decode(read["dataBase64"]) == b"\0real-file"
        assert activated == ["linux_bwrap", "linux_bwrap"]
        assert dict(bound.environment).get("APP_VALUE") == "permitted"
        assert "OPENAI_API_KEY" not in dict(bound.environment)
        for path in [
            *(bound.cwd / name / "new" for name in (".git", ".agents", ".codex")),
            tmp_path / "outside",
        ]:
            with pytest.raises(PermissionError):
                await backend.dispatch("fs/writeFile", {"path": path.as_uri(), "dataBase64": ""})
            assert not path.exists()
        assert len(requests) == 2
        assert not list(backend.plan_root.iterdir())
        await backend.close()
        executor.close.assert_awaited_once()
        assert not root.exists()
    assert len([method for method, _ in records if method == "process/start"]) == 2


@pytest.mark.asyncio
async def test_bound_backend_cancels_pending_start_and_private_disconnect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority,
) -> None:
    bound, channels = authority
    executor, records, _ = make_executor(monkeypatch)
    root = Path(tempfile.mkdtemp(prefix="om-owned-", dir="/tmp")).resolve()
    entered, parked, cancelled, closed = (asyncio.Event() for _ in range(4))

    async def allow(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": "POLICY_ACTION_ALLOW"})

    original_request = executor.request

    async def block_start(method, params):
        if method == "process/start":
            records.append((method, params))
            entered.set()
            await parked.wait()
        return await original_request(method, params)

    executor.request = AsyncMock(side_effect=block_start)

    async with httpx.AsyncClient(
        base_url="https://original.test", transport=httpx.MockTransport(allow)
    ) as server:
        backend = SessionExecutorBackend(bound, *channels, server, executor, root)
        params = {
            "processId": "pending",
            "argv": ["/bin/sh", "-c", "true"],
            "cwd": bound.cwd.as_uri(),
            "env": {},
            "tty": False,
        }
        task = asyncio.create_task(backend.dispatch("process/start", params))
        await asyncio.wait_for(entered.wait(), 1)
        internal = backend.processes["pending"]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert ("process/terminate", {"processId": internal}) in records
        assert not backend.processes and not list(backend.plan_root.iterdir())
        await backend.close()

    executor, records, _ = make_executor(monkeypatch)
    root = Path(tempfile.mkdtemp(prefix="om-owned-", dir="/tmp")).resolve()
    entered.clear()

    async def ask(request: httpx.Request) -> httpx.Response:
        entered.set()
        try:
            await parked.wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        raise AssertionError("Approval was never resolved")

    async def no_events():
        await parked.wait()
        yield {}

    async def close():
        closed.set()

    executor.iter_events = no_events
    executor.close = AsyncMock(side_effect=close)
    async with httpx.AsyncClient(
        base_url="https://original.test", transport=httpx.MockTransport(ask)
    ) as server:
        backend = SessionExecutorBackend(bound, *channels, server, executor, root)
        backend.server = await asyncio.start_unix_server(
            backend._serve, path=str(root / "exec.sock")
        )
        (root / "exec.sock").chmod(0o600)
        backend.endpoint().verify(channels[0])
        reader, writer = await asyncio.open_unix_connection(str(root / "exec.sock"))
        writer.write(
            json.dumps(
                {"id": 1, "method": "initialize", "params": {"clientName": "bound-test"}}
            ).encode()
            + b"\n"
        )
        await writer.drain()
        assert json.loads(await reader.readline())["result"]["sessionId"] == bound.generation
        file = bound.cwd / "must-not-execute-after-disconnect"
        writer.write(
            json.dumps(
                {
                    "id": 2,
                    "method": "fs/writeFile",
                    "params": {"path": file.as_uri(), "dataBase64": ""},
                }
            ).encode()
            + b"\n"
        )
        await writer.drain()
        await asyncio.wait_for(entered.wait(), 1)
        assert not file.exists() and not records
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(closed.wait(), 1)
        assert cancelled.is_set() and not file.exists()
        assert not root.exists()
        executor.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_bound_backend_preserves_parked_ask_deny_and_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority,
) -> None:
    bound, channels = authority
    executor, records, _ = make_executor(monkeypatch)
    root = tmp_path / "backend"
    root.mkdir(mode=0o700)
    entered, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()
    result = "POLICY_ACTION_ALLOW"

    async def evaluate(request: httpx.Request) -> httpx.Response:
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return httpx.Response(200, json={"result": result})

    async with httpx.AsyncClient(
        base_url="https://original.test", transport=httpx.MockTransport(evaluate)
    ) as server:
        backend = SessionExecutorBackend(bound, *channels, server, executor, root)
        path = bound.cwd / "approved"
        params = {"path": path.as_uri(), "dataBase64": base64.b64encode(b"yes").decode()}
        task = asyncio.create_task(backend.dispatch("fs/writeFile", params))
        await asyncio.wait_for(entered.wait(), 1)
        assert not path.exists() and not records
        release.set()
        await task
        assert path.read_bytes() == b"yes"
        for result in ("POLICY_ACTION_DENY", "POLICY_ACTION_ASK"):
            with pytest.raises(PermissionError):
                await backend.dispatch(
                    "fs/writeFile", {**params, "path": (bound.cwd / "denied").as_uri()}
                )
            assert not (bound.cwd / "denied").exists()
        release.clear()
        entered.clear()
        task = asyncio.create_task(backend.dispatch("fs/writeFile", params))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled.is_set()
        await backend.close()


@pytest.mark.asyncio
async def test_bound_backend_owns_process_cancel_and_client_restrictions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority,
) -> None:
    bound, channels = authority
    options = [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--new-session",
        "--die-with-parent",
        "--",
        "/bin/true",
    ]
    wrapped = required_bwrap_argv(Path("/usr/bin/bwrap"), options)
    assert wrapped == ["/usr/bin/bwrap", "--unshare-uts", "--unshare-ipc", *options]
    assert required_bwrap_argv(Path("/usr/bin/bwrap"), ["--help"]) == ["/usr/bin/bwrap", "--help"]
    advisory = required_bwrap_argv(Path("/usr/bin/bwrap"), ["--unshare-user", "--", "/bin/true"])
    assert "--unshare-pid" in advisory and "--unshare-net" in advisory
    with pytest.raises(ValueError, match="attempted to share"):
        required_bwrap_argv(Path("/usr/bin/bwrap"), ["--share-net", "--", "/bin/true"])
    executor, records, _ = make_executor(monkeypatch)
    root = tmp_path / "backend"
    root.mkdir(mode=0o700)
    async with httpx.AsyncClient(
        base_url="https://original.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"result": "POLICY_ACTION_ALLOW"})
        ),
    ) as server:
        backend = SessionExecutorBackend(bound, *channels, server, executor, root)
        params = {
            "processId": "owned",
            "argv": ["/bin/sh", "-c", "true"],
            "cwd": bound.cwd.as_uri(),
            "env": {},
            "tty": False,
        }
        await backend.dispatch("process/start", params)
        start = next(params for method, params in records if method == "process/start")
        assert start["processId"] != "owned"
        plan = json.loads(Path(start["argv"][-1]).read_text())
        assert plan["argv"] == params["argv"]
        assert "OPENAI_API_KEY" not in plan["env"]
        with pytest.raises(PermissionError, match="not owned"):
            await backend.dispatch("process/terminate", {"processId": "someone-else"})
        await backend.dispatch("process/terminate", {"processId": "owned"})
        assert records[-1] == ("process/terminate", {"processId": start["processId"]})
        assert not backend.processes and not list(backend.plan_root.iterdir())
        context = backend._context({})
        entries = context["permissions"]["file_system"]["entries"]
        readonly = {
            **context,
            "permissions": {
                **context["permissions"],
                "file_system": {
                    "type": "restricted",
                    "entries": [
                        {
                            **entry,
                            "access": "read" if entry["access"] == "write" else entry["access"],
                        }
                        for entry in entries
                    ],
                },
            },
        }
        with pytest.raises(PermissionError):
            await backend.dispatch(
                "fs/writeFile",
                {
                    "path": (bound.cwd / "restricted").as_uri(),
                    "dataBase64": "",
                    "sandbox": readonly,
                },
            )
        with pytest.raises(ValueError, match="disable or externalize"):
            backend._context({"sandbox": {"permissions": {"type": "disabled"}}})
        with pytest.raises(ValueError, match="environment exceeds"):
            await backend.dispatch(
                "process/start", {**params, "env": {"OPENAI_API_KEY": "forbidden"}}
            )
        assert not backend.processes
        await backend.close()


@pytest.mark.asyncio
async def test_registry_bootstrap_binds_executor_before_parent_and_retires_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority,
) -> None:
    import shutil

    from omnigent.harnesses.codex_native import execution
    from omnigent.inner.datamodel import OSEnvSandboxSpec, OSEnvSpec
    from omnigent.runner.resource_registry import SessionResourceRegistry

    bound, channels = authority
    executor, _, _ = make_executor(monkeypatch)
    root = Path(tempfile.mkdtemp(prefix="om-bootstrap-", dir="/tmp")).resolve()
    backend = SessionExecutorBackend(bound, *channels, Mock(), executor, root)
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(root / "exec.sock"))
        (root / "exec.sock").chmod(0o600)
        registry = SessionResourceRegistry(
            runner_workspace=bound.cwd, session_model_channel=channels[0]
        )
        registry.require_sandbox_binding()
        registry.bind_required_os_env(
            bound.session_id,
            OSEnvSpec(
                fork=False,
                cwd=str(bound.cwd),
                sandbox=OSEnvSandboxSpec(
                    type="linux_bwrap",
                    allow_network=False,
                    read_paths=[str(bound.cwd)],
                    write_paths=[str(bound.cwd)],
                    env_passthrough=[],
                ),
            ),
            require_native_channels=True,
        )
        registry.bind_native_policy_channel(
            bound.session_id, port=channels[1].relay_port, path=Path(channels[1].socket_path)
        )
        monkeypatch.setattr(
            "omnigent.inner.sandbox.resolve_sandbox", lambda spec, cwd: bound.required
        )
        start = AsyncMock(return_value=backend)
        monkeypatch.setattr(SessionExecutorBackend, "start", start)
        monkeypatch.setattr(execution, "SYSTEM_CODEX_REQUIREMENTS", tmp_path / "absent")
        bridge = tmp_path / "original-bridge"
        bridge.mkdir()
        (bridge / "tool_relay.json").write_text(
            json.dumps(
                {
                    "url": "http://127.0.0.1:31402",
                    "token": "only-test-local-capability",
                    "session_id": bound.session_id,
                    "generation": bound.generation,
                    "socket_path": channels[1].socket_path,
                    "tools": [],
                }
            )
        )
        runtime = await registry.prepare_native_executor(
            bound.session_id,
            bridge,
            Mock(),
            binary=Path("/qualified/codex"),
            expected_sha256="c" * 64,
        )
        assert start.await_count == 1
        assert runtime.executor == backend.endpoint()
        assert not registry.has_primary_env(bound.session_id)
        assert runtime.mcp_overrides is not None
        assert (
            "mcp_servers.omnigent.environment_id=" + json.dumps(backend.endpoint().environment_id)
            in runtime.mcp_overrides
        )
        assert backend._mcp is not None
        command, role, control = backend._mcp
        from dataclasses import replace

        configured_role = backend._mcp
        backend._mcp = None
        for change in (
            {"session_id": uuid4().hex},
            {"generation": "f" * 32},
            {"executor": None},
        ):
            with pytest.raises(ValueError, match="differs from its Session"):
                backend.bind_mcp(replace(runtime, **change))
        backend._mcp = configured_role
        assert role.required.session_relay_pairs() == [
            (channels[1].relay_port, channels[1].socket_path)
        ]
        assert runtime.bridge in role.required.write_roots and control in role.required.write_roots
        assert bound.required.session_relay_pairs() == []
        params = {
            "processId": "configured-mcp",
            "argv": list(command),
            "cwd": bound.cwd.as_uri(),
            "env": {},
            "envPolicy": {
                "inherit": "core",
                "ignoreDefaultExcludes": True,
                "exclude": [],
                "set": {},
                "includeOnly": [],
            },
            "tty": False,
            "pipeStdin": True,
            "arg0": None,
            "sandbox": None,
            "enforceManagedNetwork": False,
        }
        authorize = AsyncMock(side_effect=AssertionError("MCP startup re-entered Bash ASK"))
        backend._authorize = authorize
        await backend.dispatch("process/start", params)
        authorize.assert_not_called()
        plan = json.loads(backend.plans["configured-mcp"].read_text())
        assert plan["supervised"] is True
        first_control = Path(plan["env"]["OMNIGENT_HARNESS_TMP_PARENT"])
        assert first_control.parent == control and first_control.is_dir()
        await backend.dispatch("process/start", {**params, "processId": "second-mcp"})
        second_plan = json.loads(backend.plans["second-mcp"].read_text())
        second_control = Path(second_plan["env"]["OMNIGENT_HARNESS_TMP_PARENT"])
        assert second_control.parent == control and second_control != first_control
        assert second_control.is_dir()
        assert (
            not {
                "OPENAI_API_KEY",
                "_OMNIGENT_RUNNER_TOKEN",
                "OMNIGENT_PLATFORM_DEEPSEEK_KEY",
                "APP_VALUE",
            }
            & plan["env"].keys()
        )
        assert plan["required"]["allow_network"] is False
        assert plan["required"]["model_relay_socket_path"] is None
        for change in (
            {"env": {"PATH": "/mutable"}},
            {"cwd": (bound.cwd / "other").as_uri()},
            {"envPolicy": {"inherit": "all"}},
            {"sandbox": {}},
            {"role": "mcp"},
        ):
            with pytest.raises(ValueError, match="fixed Session role"):
                backend._mcp_authority({**params, **change})
        assert backend._mcp_authority({**params, "argv": [*command, "--foreign"]}) is None
        for write in (False, True):
            with pytest.raises(PermissionError):
                bound.check_path(backend._context(params), runtime.bridge, write=write)
        await backend.dispatch("process/terminate", {"processId": "configured-mcp"})
        assert not first_control.exists() and second_control.is_dir()
        await backend.dispatch("process/terminate", {"processId": "second-mcp"})
        assert not second_control.exists()
        snapshot = start.await_args.args[0]
        assert snapshot.required.session_relay_pairs() == []
        assert snapshot.required.write_roots == [bound.cwd]
        with pytest.raises(ValueError, match="must precede"):
            await registry.prepare_native_executor(
                bound.session_id,
                bridge,
                Mock(),
                binary=Path("/qualified/codex"),
                expected_sha256="c" * 64,
            )
        await registry.cleanup_session(bound.session_id)
        assert registry._native_executor is None and registry._native_runtime is None
        assert not root.exists()
        assert runtime.home.is_dir()
        shutil.rmtree(runtime.root)


@pytest.mark.asyncio
async def test_same_connection_terminate_cancels_parked_start_before_late_allow(
    monkeypatch: pytest.MonkeyPatch,
    authority,
) -> None:
    bound, channels = authority
    executor, records, _ = make_executor(monkeypatch)
    root = Path(tempfile.mkdtemp(prefix="om-cancel-", dir="/tmp")).resolve()
    entered, release, cancelled, closed = (asyncio.Event() for _ in range(4))

    async def evaluate(request: httpx.Request) -> httpx.Response:
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return httpx.Response(200, json={"result": "POLICY_ACTION_ALLOW"})

    async def no_events():
        await release.wait()
        if False:
            yield {}

    executor.iter_events = no_events
    executor.close = AsyncMock(side_effect=closed.set)
    async with httpx.AsyncClient(
        base_url="https://original.test", transport=httpx.MockTransport(evaluate)
    ) as server:
        backend = SessionExecutorBackend(bound, *channels, server, executor, root)
        backend.server = await asyncio.start_unix_server(
            backend._serve, path=str(root / "exec.sock")
        )
        reader, writer = await asyncio.open_unix_connection(str(root / "exec.sock"))

        async def send(request_id, method, params):
            writer.write(
                json.dumps({"id": request_id, "method": method, "params": params}).encode() + b"\n"
            )
            await writer.drain()

        await send(1, "initialize", {"clientName": "original-protocol-cancel"})
        assert json.loads(await asyncio.wait_for(reader.readline(), 1))["id"] == 1
        await send(
            2,
            "process/start",
            {
                "processId": "owned-pending",
                "argv": ["/bin/true"],
                "cwd": bound.cwd.as_uri(),
                "env": {},
                "tty": False,
            },
        )
        await asyncio.wait_for(entered.wait(), 1)
        await send(3, "process/terminate", {"processId": "owned-pending"})
        replies = [json.loads(await asyncio.wait_for(reader.readline(), 1)) for _ in range(2)]
        by_id = {reply["id"]: reply for reply in replies}
        assert by_id[2]["error"]["code"] == -32800
        assert by_id[3]["result"] == {"running": False}
        assert cancelled.is_set() and not records
        assert not backend.pending_starts and not backend.processes
        release.set()
        await send(4, "environment/info", {})
        assert (
            json.loads(await asyncio.wait_for(reader.readline(), 1))["result"]["shell"]["name"]
            == "sh"
        )
        assert not writer.is_closing() and not backend._closed
        assert not [record for record in records if record[0] == "process/start"]
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(closed.wait(), 1)


def test_read_handle_retains_open_inode_and_observes_updates(tmp_path: Path) -> None:
    import os
    import threading

    path = tmp_path / "source"
    path.write_bytes(b"before")
    input_read, input_write = os.pipe()
    output_read, output_write = os.pipe()
    failures = []

    def serve():
        try:
            with os.fdopen(input_read, "rb") as source, os.fdopen(output_write, "wb") as output:
                executor_worker.serve_read_handle(path, source, output)
        except Exception as error:
            failures.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with os.fdopen(input_write, "wb") as source, os.fdopen(output_read, "rb") as output:
        assert json.loads(output.readline()) == {"opened": True}
        path.write_bytes(b"updated")
        path.rename(tmp_path / "original-inode")
        path.write_bytes(b"replacement")
        source.write(b'{"offset":0,"len":32}\n')
        source.flush()
        reply = json.loads(output.readline())
        assert base64.b64decode(reply["chunk"]) == b"updated" and reply["eof"] is True
        source.write(b'{"close":true}\n')
        source.flush()
        assert json.loads(output.readline()) == {"closed": True}
    thread.join(timeout=1)
    assert not thread.is_alive() and not failures


def test_normal_fixed_client_special_paths_keep_server_grants(tmp_path: Path, authority) -> None:
    import sys

    bound, _ = authority
    entries = [
        {"path": {"type": "special", "value": {"kind": kind}}, "access": access}
        for kind, access in [
            ("root", "read"),
            ("project_roots", "write"),
            ("slash_tmp", "write"),
            ("tmpdir", "write"),
            ("minimal", "read"),
        ]
    ]
    client = {
        "permissions": {
            "type": "managed",
            "file_system": {"type": "restricted", "entries": entries},
            "network": "enabled",
        },
        "cwd": bound.cwd.as_uri(),
    }
    context = bound.prepare(
        client,
        worker=Path(sys.executable).parent.resolve() / Path(sys.executable).name,
        plan_root=tmp_path / "plans",
    )
    bound.check_path(context, bound.cwd / "allowed", write=True)
    assert context["permissions"]["network"] == "restricted"
    for path in (tmp_path / "outside", bound.cwd / ".git" / "config"):
        with pytest.raises(PermissionError):
            bound.check_path(context, path, write=True)
    assert not any(
        entry["path"].get("path") == "file:///tmp" and entry["access"] == "deny"
        for entry in context["permissions"]["file_system"]["entries"]
    )


@pytest.mark.asyncio
async def test_filesystem_response_limit_precedes_read_encoding_and_spool_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority,
) -> None:
    from omnigent.harnesses.codex_native import executor_backend as backend_module

    bound, channels = authority
    monkeypatch.setattr(executor_worker, "FS_RESPONSE_LIMIT_BYTES", 64)
    monkeypatch.setattr(backend_module, "FS_RESPONSE_LIMIT_BYTES", 64)
    file = bound.cwd / "bounded"
    file.write_bytes(b"x" * 33)
    encode = Mock(wraps=executor_worker.base64.b64encode)
    monkeypatch.setattr(executor_worker.base64, "b64encode", encode)
    result = executor_worker._read_file_response(file)
    assert base64.b64decode(result["dataBase64"]) == b"x" * 33
    assert len(json.dumps(result).encode()) <= 64
    file.write_bytes(b"x" * 34)
    with pytest.raises(ValueError, match="bounded filesystem stream"):
        executor_worker._read_file_response(file)
    assert encode.call_count == 1

    executor, _, _ = make_executor(monkeypatch)
    original_request = executor.request.side_effect

    async def split_output(method, params):
        response = await original_request(method, params)
        if method == "process/read":
            data = base64.b64decode(response["result"]["chunks"][0]["chunk"])
            start = params.get("afterSeq") or 0
            end = min(start + 32, len(data))
            return {
                "result": {
                    "chunks": [
                        {
                            "seq": end,
                            "stream": "stdout",
                            "chunk": base64.b64encode(data[start:end]).decode(),
                        }
                    ],
                    "nextSeq": end,
                    "exited": end == len(data),
                    "exitCode": 0,
                    "failure": None,
                }
            }
        return response

    executor.request.side_effect = split_output
    root = tmp_path / "backend"
    root.mkdir(mode=0o700)
    writes = []
    original_open = Path.open

    class BoundedSpool:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.file.close()

        def write(self, data):
            assert self.file.tell() + len(data) <= 64
            writes.append(len(data))
            return self.file.write(data)

    def open_file(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        return BoundedSpool(stream) if mode == "xb" and path.parent == root / "spools" else stream

    monkeypatch.setattr(Path, "open", open_file)
    async with httpx.AsyncClient(
        base_url="https://original.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"result": "POLICY_ACTION_ALLOW"})
        ),
    ) as server:
        backend = SessionExecutorBackend(bound, *channels, server, executor, root)
        with pytest.raises(ValueError, match="bounded filesystem stream"):
            await backend.dispatch("fs/readDirectory", {"path": bound.cwd.as_uri()})
        assert writes == [32, 32]
        assert not list(backend.spool_root.iterdir()) and not backend.processes
        await backend.close()


def test_configured_mcp_supervision_keeps_original_activation_until_child_exit(
    monkeypatch: pytest.MonkeyPatch,
    authority,
) -> None:
    bound, _ = authority
    active = []
    monkeypatch.setattr(executor_worker.sys, "platform", "linux")
    monkeypatch.setattr(executor_worker.os, "chdir", lambda cwd: None)
    monkeypatch.setattr(
        executor_worker.BwrapSandboxBackend,
        "activate",
        lambda self, policy: active.append(policy.backend_type),
    )
    command = ["/fixed/python", "-I", "-m", "fixed.bridge"]
    environment = {"PATH": "/fixed/bin"}
    child = Mock(return_value=23)

    def supervised(argv, **kwargs):
        assert active == ["linux_bwrap"]
        return child(argv, **kwargs)

    monkeypatch.setattr(executor_worker.subprocess, "call", supervised)
    with pytest.raises(SystemExit) as result:
        executor_worker.run_plan(
            {
                "required": bound.required.to_jsonable(),
                "cwd": str(bound.cwd),
                "operation": "process/start",
                "argv": command,
                "env": environment,
                "supervised": True,
            }
        )
    assert result.value.code == 23
    child.assert_called_once_with(command, env=environment)
