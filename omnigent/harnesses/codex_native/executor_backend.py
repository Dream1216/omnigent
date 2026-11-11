"""Session-bound required execution backend for the fixed native protocol."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import fnmatch
import hashlib
import json
import os
import shlex
import shutil
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

import httpx

from omnigent.harnesses.codex_native.app_server import CodexAppServerClient
from omnigent.harnesses.codex_native.executor_policy import (
    FS_RESPONSE_LIMIT_BYTES,
    SessionExecutionPolicy,
    native_path,
)
from omnigent.harnesses.codex_native.executor_transport import SessionExecutorEndpoint
from omnigent.inner import _proc
from omnigent.inner.sandbox import with_additional_write_roots
from omnigent.native.native_policy_hook import hook_payload_to_evaluation_request
from omnigent.runner.session_channels import SessionRelayChannel, session_ids_match

if TYPE_CHECKING:
    from omnigent.harnesses.codex_native.execution import CodexPrivateRuntime


@dataclass
class _ReadHandle:
    key: str
    after_seq: int = 0


@dataclass
class _PendingStart:
    task: asyncio.Task[Any] | None = None
    cancelled: bool = False


def _result(response: dict[str, object]) -> dict[str, Any]:
    value = response.get("result")
    if not isinstance(value, dict):
        raise ValueError("Malformed fixed executor result")
    return value


async def _probe(binary: Path, argument: str, env: dict[str, str]) -> bytes:
    process = await asyncio.create_subprocess_exec(
        str(binary),
        argument,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
        **_proc.spawn_kwargs(),
    )
    _proc.remember_process_group(process)
    try:
        assert process.stdout is not None
        output = await asyncio.wait_for(process.stdout.read(65537), 5)
        await asyncio.wait_for(process.wait(), 5)
        if process.returncode or len(output) > 65536:
            raise OSError("Qualified executor capability probe failed")
        return output
    finally:
        _proc.refresh_process_tree(process)
        _proc.terminate_tree(process)
        _proc.kill_tree(process)


class _ExecStdio:
    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self.process = process

    async def send(self, message: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(message.encode() + b"\n")
        await self.process.stdin.drain()

    def __aiter__(self) -> _ExecStdio:
        return self

    async def __anext__(self) -> str:
        assert self.process.stdout is not None
        line = await self.process.stdout.readline()
        if not line:
            raise StopAsyncIteration
        return line.decode()

    async def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()


class _FixedExecClient(CodexAppServerClient):
    """Reuse response/event dispatch for the fixed exec-server JSON-lines transport."""

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        super().__init__(socket_path=Path("/unused-exec-stdio"))
        self.process = process

    async def connect(self) -> None:
        self._ws = cast(Any, _ExecStdio(self.process))
        self._reader_task = asyncio.create_task(self._reader_loop())
        await self.request("initialize", {"clientName": "omnigent-session-executor"})
        await self.notify("initialized")

    async def close(self) -> None:
        try:
            await super().close()
        finally:
            _proc.refresh_process_tree(self.process)
            _proc.terminate_tree(self.process)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.process.wait(), 2)
            _proc.kill_tree(self.process)


class SessionExecutorBackend:
    """Own one trusted outside executor and only this Session's process handles."""

    def __init__(
        self,
        authority: SessionExecutionPolicy,
        model: SessionRelayChannel,
        policy: SessionRelayChannel,
        server_client: httpx.AsyncClient,
        executor: CodexAppServerClient,
        root: Path,
    ) -> None:
        self.authority, self.model, self.policy = authority, model, policy
        self.server_client, self.executor, self.root = server_client, executor, root
        self.plan_root = root / "plans"
        self.spool_root = root / "spools"
        self.plan_root.mkdir(mode=0o700)
        self.spool_root.mkdir(mode=0o700)
        self.launch_environment = dict(authority.environment)
        interpreter = Path(sys.executable)
        self.worker = interpreter.parent.resolve() / interpreter.name
        self.native_binary: Path | None = None
        self._mcp: tuple[tuple[str, ...], SessionExecutionPolicy, Path] | None = None
        self._mcp_controls: dict[str, tuple[Path, int, int]] = {}
        self.processes: dict[str, str] = {}
        self.pending_starts: dict[str, _PendingStart] = {}
        self.plans: dict[str, Path] = {}
        self.handles: dict[str, _ReadHandle] = {}
        self.server: asyncio.AbstractServer | None = None
        self._connection: asyncio.StreamWriter | None = None
        self._active_request: asyncio.Task[dict[str, Any]] | None = None
        self._closed = False
        info = root.lstat()
        self._root_identity = info.st_dev, info.st_ino

    @classmethod
    async def start(
        cls,
        authority: SessionExecutionPolicy,
        model: SessionRelayChannel,
        policy: SessionRelayChannel,
        server_client: httpx.AsyncClient,
        *,
        binary: Path,
        expected_sha256: str,
    ) -> SessionExecutorBackend:
        if not sys.platform.startswith("linux"):
            raise OSError("Required Session executor needs Linux")
        model.verify(session_id=authority.session_id, runner_id=authority.runner_id)
        policy.verify(session_id=authority.session_id, runner_id=authority.runner_id)
        if authority.generation != model.generation or authority.generation != policy.generation:
            raise ValueError("Executor authority generation is stale")
        if not binary.is_absolute() or binary.resolve() != binary:
            raise ValueError("Executor binary must be an authoritative canonical path")
        with binary.open("rb") as original:
            if hashlib.file_digest(original, "sha256").hexdigest() != expected_sha256:
                raise ValueError("Executor binary differs from its qualified artifact")
        environment = dict(authority.environment)
        if (await _probe(binary, "--version", environment)).strip() != b"codex-cli 0.142.0":
            raise ValueError("Session executor protocol is pinned to Codex 0.142.0")
        bwrap = shutil.which("bwrap", path=dict(authority.environment).get("PATH", os.defpath))
        if bwrap is None:
            raise OSError("Qualified Host has no bubblewrap binary")
        assert bwrap is not None
        bwrap_path = Path(bwrap).resolve(strict=True)
        if any(
            bwrap_path.is_relative_to(root.resolve()) for root in authority.required.write_roots
        ):
            raise ValueError("Bubblewrap binary is inside a tool write grant")
        if b"--perms" not in await _probe(bwrap_path, "--help", environment):
            raise OSError("System bubblewrap cannot preserve the pinned CLI's mount semantics")
        root = Path(tempfile.mkdtemp(prefix="om-executor-", dir="/tmp")).resolve()
        # No target business starts here. Only the qualified, fixed CLI may own tool namespaces.
        process = None
        launch_env = dict(authority.environment)
        try:
            wrapper = root / "launch" / "bwrap"
            wrapper.parent.mkdir(mode=0o700)
            wrapper.write_text(
                f"#!{sys.executable}\n"
                "from omnigent.harnesses.codex_native.executor_bwrap import main\n"
                f"main({str(bwrap_path)!r})\n"
            )
            wrapper.chmod(0o700)
            launch_env["PATH"] = (
                str(wrapper.parent) + os.pathsep + launch_env.get("PATH", os.defpath)
            )
            if b"--perms" not in await _probe(wrapper, "--help", launch_env):
                raise OSError("Required bubblewrap adapter is unavailable")
            process = await asyncio.create_subprocess_exec(
                str(binary),
                "exec-server",
                "--listen",
                "stdio",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=launch_env,
                limit=8 * 1024 * 1024,
                **_proc.spawn_kwargs(),
            )
        except BaseException:
            shutil.rmtree(root)
            raise
        assert process is not None
        _proc.remember_process_group(process)
        executor = _FixedExecClient(process)
        backend = None
        try:
            backend = cls(authority, model, policy, server_client, executor, root)
            backend.native_binary = binary
            backend.launch_environment = launch_env
            await asyncio.wait_for(executor.connect(), 15)
            backend.server = await asyncio.start_unix_server(
                backend._serve, path=str(root / "exec.sock"), limit=8 * 1024 * 1024
            )
            (root / "exec.sock").chmod(0o600)
            return backend
        except BaseException:
            if backend is not None:
                await backend.close()
            else:
                await executor.close()
                shutil.rmtree(root)
            raise

    def endpoint(self) -> SessionExecutorEndpoint:
        path = self.root / "exec.sock"
        info = path.lstat()
        return SessionExecutorEndpoint(
            self.authority.session_id,
            self.authority.runner_id,
            self.authority.generation,
            path,
            info.st_dev,
            info.st_ino,
        )

    def _verify(self) -> None:
        if self._closed:
            raise ConnectionError("Executor is closed")
        self.model.verify(session_id=self.authority.session_id, runner_id=self.authority.runner_id)
        self.policy.verify(
            session_id=self.authority.session_id, runner_id=self.authority.runner_id
        )
        if (
            self.model.generation != self.authority.generation
            or self.policy.generation != self.authority.generation
        ):
            raise ValueError("Executor Session generation changed")

    def bind_mcp(self, runtime: CodexPrivateRuntime) -> None:
        """Bind only the framework's exact bridge child, never a caller-selected role."""
        from omnigent.harnesses.codex_native.bridge import codex_mcp_config_overrides

        self._verify()
        if (
            self._mcp is not None
            or not session_ids_match(runtime.session_id, self.authority.session_id)
            or runtime.generation != self.authority.generation
            or runtime.executor != self.endpoint()
        ):
            raise ValueError("MCP runtime differs from its Session executor")
        control = runtime.root / "mcp"
        for directory in (runtime.root, runtime.bridge, control):
            info = directory.lstat()
            if (
                directory.is_symlink()
                or not directory.is_dir()
                or directory.resolve() != directory
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise ValueError("MCP runtime directory is not private")
        config = json.loads((runtime.bridge / "bridge.json").read_text())
        if set(config) != {"token"} or not isinstance(config["token"], str) or not config["token"]:
            raise ValueError("MCP bridge must expose only original relay tools")
        required = with_additional_write_roots(self.authority.required, [runtime.bridge, control])
        required = self.policy.apply(required, session_id=self.authority.session_id)
        scoped = replace(self.authority, policy_json=json.dumps(required.to_jsonable()))
        argv = (
            str(self.worker),
            "-I",
            "-m",
            "omnigent.harnesses.claude_native.bridge",
            "serve-mcp",
            "--bridge-dir",
            str(runtime.bridge),
        )
        self._mcp = argv, scoped, control
        runtime.mcp_overrides = (
            *codex_mcp_config_overrides(runtime.bridge, python_executable=str(self.worker)),
            "mcp_servers.omnigent.environment_id=" + json.dumps(self.endpoint().environment_id),
            "mcp_servers.omnigent.cwd=" + json.dumps(str(self.authority.cwd)),
        )

    def _mcp_authority(self, params: dict[str, Any]) -> SessionExecutionPolicy | None:
        if self._mcp is None or params.get("argv") != list(self._mcp[0]):
            return None
        expected_env = {
            "inherit": "core",
            "ignoreDefaultExcludes": True,
            "exclude": [],
            "set": {},
            "includeOnly": [],
        }
        if (
            params.get("cwd") != self.authority.cwd.as_uri()
            or params.get("env", {}) != {}
            or params.get("envPolicy") != expected_env
            or params.get("sandbox") is not None
            or params.get("tty") is not False
            or params.get("pipeStdin") is not True
            or params.get("arg0") is not None
            or params.get("enforceManagedNetwork") is not False
            or set(params)
            - {
                "processId",
                "argv",
                "cwd",
                "env",
                "envPolicy",
                "sandbox",
                "tty",
                "pipeStdin",
                "arg0",
                "enforceManagedNetwork",
            }
        ):
            raise ValueError("Configured MCP launch differs from its fixed Session role")
        return self._mcp[1]

    async def _authorize(self, method: str, params: dict[str, Any]) -> None:
        tool = (
            "Bash"
            if method == "process/start"
            else (
                "Write"
                if method in {"fs/writeFile", "fs/remove", "fs/copy", "fs/createDirectory"}
                else "Read"
            )
        )
        arguments = dict(params)
        arguments.pop("sandbox", None)
        arguments.pop("env", None)
        arguments.pop("envPolicy", None)
        if method == "process/start":
            arguments = {"command": shlex.join(params["argv"])}
        request = hook_payload_to_evaluation_request(
            "PreToolUse", {"tool_name": tool, "tool_input": arguments}
        )
        assert request is not None
        request["event"]["context"]["harness"] = "codex-native"
        response = await self.server_client.post(
            f"/v1/sessions/{self.authority.session_id}/policies/evaluate",
            json={**request, "_omnigent_elicitation_id": uuid4().hex},
            timeout=86400.0,
        )
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict) or result.get("result") != "POLICY_ACTION_ALLOW":
            raise PermissionError("Original Session policy did not allow this operation")

    def _context(
        self, params: dict[str, Any], authority: SessionExecutionPolicy | None = None
    ) -> dict[str, Any]:
        return (authority or self.authority).prepare(
            params.get("sandbox"),
            worker=self.worker,
            plan_root=self.plan_root,
            binary=self.native_binary,
        )

    def _tool_environment(self, params: dict[str, Any]) -> dict[str, str]:
        allowed = dict(self.authority.environment)
        policy = params.get("envPolicy")
        env = dict(allowed)
        if policy is not None:
            if not isinstance(policy, dict):
                raise ValueError("Malformed process environment policy")
            inherit = policy.get("inherit")
            if inherit == "none":
                env = {}
            elif inherit == "core":
                core = {
                    "HOME",
                    "LOGNAME",
                    "PATH",
                    "SHELL",
                    "USER",
                    "USERNAME",
                    "SYSTEMROOT",
                    "COMSPEC",
                }
                env = {name: value for name, value in env.items() if name.upper() in core}
            elif inherit != "all":
                raise ValueError("Unsupported process environment inheritance")
            exclude = policy.get("exclude", [])
            if not policy.get("ignoreDefaultExcludes", False):
                exclude = [*exclude, "*KEY*", "*SECRET*", "*TOKEN*"]
            env = {
                name: value
                for name, value in env.items()
                if not any(
                    fnmatch.fnmatchcase(name.upper(), pattern.upper()) for pattern in exclude
                )
            }
            requested = policy.get("set", {})
            if not isinstance(requested, dict) or any(name not in allowed for name in requested):
                raise ValueError("Client environment exceeds original grants")
            env.update(requested)
            include = policy.get("includeOnly", [])
            if include:
                env = {
                    name: value
                    for name, value in env.items()
                    if any(
                        fnmatch.fnmatchcase(name.upper(), pattern.upper()) for pattern in include
                    )
                }
        requested = params.get("env", {})
        if (
            not isinstance(requested, dict)
            or any(name not in allowed for name in requested)
            or any(not isinstance(value, str) for value in requested.values())
        ):
            raise ValueError("Client environment exceeds original grants")
        env.update(requested)
        return env

    async def _launch(
        self,
        method: str,
        params: dict[str, Any],
        *,
        key: str,
        context: dict[str, Any],
        authority: SessionExecutionPolicy | None = None,
    ) -> dict[str, Any]:
        scoped = authority or self.authority
        internal = uuid4().hex
        plan: dict[str, Any] = {
            "operation": method,
            "cwd": str(self.authority.cwd),
            "required": scoped.required.to_jsonable(),
            "params": params,
            "context": context,
        }
        if method == "process/start":
            cwd = native_path(params["cwd"]).resolve()
            scoped.check_path(context, cwd, write=False)
            argv = params.get("argv")
            if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
                raise ValueError("Process argv is invalid")
            if params.get("arg0") is not None:
                raise ValueError("Custom argv0 is not qualified for required execution")
            # Client values never affect the trusted Python bootstrap's import or activation.
            plan.update(argv=argv, cwd=str(cwd), env=self._tool_environment(params))
            if authority is not None:
                assert self._mcp is not None and authority is self._mcp[1]
                control = self._mcp[2] / internal
                control.mkdir(mode=0o700)
                info = control.lstat()
                self._mcp_controls[key] = control, info.st_dev, info.st_ino
                plan["env"]["OMNIGENT_HARNESS_TMP_PARENT"] = str(control)
                plan["supervised"] = True
        path = self.plan_root / (internal + ".json")
        self.plans[key] = path
        request: dict[str, Any] = {
            "processId": internal,
            "argv": [
                str(self.worker),
                "-I",
                "-m",
                "omnigent.harnesses.codex_native.executor_worker",
                str(path),
            ],
            "cwd": self.authority.cwd.as_uri(),
            "env": dict(self.launch_environment),
            "envPolicy": {
                "inherit": "none",
                "ignoreDefaultExcludes": False,
                "exclude": [],
                "set": {},
                "includeOnly": [],
            },
            "tty": bool(params.get("tty")) if method == "process/start" else False,
            "pipeStdin": bool(params.get("pipeStdin"))
            if method == "process/start"
            else method == "fs/open",
            "arg0": None,
            "sandbox": context,
            "enforceManagedNetwork": False,
        }
        try:
            with path.open("x") as output:
                os.chmod(path, 0o600)
                json.dump(plan, output)
            self.processes[key] = internal
            return await self.executor.request("process/start", request)
        except BaseException:
            await self._terminate(key)
            raise

    async def _terminate(self, key: str) -> None:
        internal = self.processes.get(key)
        if internal is not None:
            await self.executor.request("process/terminate", {"processId": internal})
        self.processes.pop(key, None)
        path = self.plans.pop(key, None)
        if path is not None:
            path.unlink(missing_ok=True)
        control = self._mcp_controls.pop(key, None)
        if control is not None:
            directory, device, inode = control
            with contextlib.suppress(FileNotFoundError):
                info = directory.lstat()
                if directory.is_symlink() or (info.st_dev, info.st_ino) != (device, inode):
                    raise ValueError("MCP control directory ownership changed")
                shutil.rmtree(directory)

    async def dispatch(
        self,
        method: str,
        params: dict[str, Any],
        *,
        pending: _PendingStart | None = None,
    ) -> dict[str, Any]:
        self._verify()
        if method == "process/start":
            key = params.get("processId")
            if (
                not isinstance(key, str)
                or not key
                or key in self.processes
                or (key in self.pending_starts and self.pending_starts[key] is not pending)
            ):
                raise ValueError("Process handle is missing or already owned")
            pending = pending or _PendingStart()
            self.pending_starts[key] = pending
            pending.task = asyncio.current_task()
            try:
                if pending.cancelled:
                    raise asyncio.CancelledError
                authority = self._mcp_authority(params)
                context = self._context(params, authority)
                # Configured bridge startup is infrastructure; its tool calls retain
                # the original MCP hook and Session relay policy decisions.
                if authority is None:
                    await self._authorize(method, params)
                if pending.cancelled:
                    raise asyncio.CancelledError
                await self._launch(method, params, key=key, context=context, authority=authority)
                return {"processId": key}
            finally:
                if self.pending_starts.get(key) is pending:
                    del self.pending_starts[key]
        if method in {"process/read", "process/write", "process/signal", "process/terminate"}:
            key = params.get("processId")
            if (
                method == "process/terminate"
                and isinstance(key, str)
                and key in self.pending_starts
            ):
                starting = self.pending_starts[key]
                starting.cancelled = True
                if starting.task is not None:
                    starting.task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await starting.task
                return {"running": False}
            if not isinstance(key, str) or key not in self.processes:
                raise PermissionError("Process handle is not owned by this Session connection")
            if method == "process/terminate":
                await self._terminate(key)
                return {"running": False}
            response = await self.executor.request(
                method, {**params, "processId": self.processes[key]}
            )
            return _result(response)
        if method.startswith("fs/"):
            return await self._filesystem(method, params)
        if method == "environment/info":
            response = await self.executor.request(method, {})
            return _result(response)
        raise ValueError("Unqualified executor method")

    async def _filesystem(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method in {"fs/readBlock", "fs/close"}:
            handle = params.get("handleId")
            if not isinstance(handle, str):
                raise ValueError("File handle is missing")
            owned = self.handles.get(handle)
            if owned is None:
                raise PermissionError("File handle is not owned by this connection")
            if method == "fs/close":
                await self._file_write(owned, {"close": True})
                reply = await self._file_reply(owned)
                if reply.get("closed") is not True:
                    raise OSError("File worker did not close its owned descriptor")
                await self._terminate(owned.key)
                del self.handles[handle]
                return {}
            offset, length = params.get("offset"), params.get("len")
            if (
                not isinstance(offset, int)
                or offset < 0
                or not isinstance(length, int)
                or not 0 <= length <= 1048576
            ):
                raise ValueError("Invalid bounded file read")
            await self._file_write(owned, {"offset": offset, "len": length})
            return await self._file_reply(owned)
        context = self._context(params)
        write = method in {"fs/writeFile", "fs/createDirectory", "fs/remove"}
        path = native_path(params.get("sourcePath") if method == "fs/copy" else params.get("path"))
        self.authority.check_path(context, path, write=write)
        if method == "fs/copy":
            self.authority.check_path(
                context, native_path(params.get("destinationPath")), write=True
            )
        await self._authorize(method, params)
        key = "fs-" + uuid4().hex
        if method == "fs/open":
            handle = params.get("handleId")
            if not isinstance(handle, str) or handle in self.handles:
                raise ValueError("File handle is missing or already owned")
            owned = _ReadHandle(key)
            try:
                await self._launch(method, params, key=key, context=context)
                reply = await self._file_reply(owned)
                if reply.get("opened") is not True:
                    raise OSError("File worker did not open its owned descriptor")
                self.handles[handle] = owned
                return {"handleId": handle}
            except BaseException:
                await self._terminate(key)
                raise
        spool = self.spool_root / (key + ".bytes")
        operation = "fs/open" if method == "fs/open" else method
        try:
            await self._launch(operation, params, key=key, context=context)
            after = 0
            output_bytes = 0
            with spool.open("xb") as output:
                os.chmod(spool, 0o600)
                while True:
                    response = await self.executor.request(
                        "process/read",
                        {
                            "processId": self.processes[key],
                            "afterSeq": after,
                            "maxBytes": 65536,
                            "waitMs": 1000,
                        },
                    )
                    result = _result(response)
                    for chunk in result["chunks"]:
                        if chunk["stream"] == "stdout":
                            data = base64.b64decode(chunk["chunk"], validate=True)
                            if len(data) > FS_RESPONSE_LIMIT_BYTES - output_bytes:
                                raise ValueError("Use the bounded filesystem stream for this file")
                            output.write(data)
                            output_bytes += len(data)
                    after = result["nextSeq"]
                    if result["exited"]:
                        if result["exitCode"] != 0 or result.get("failure"):
                            raise OSError("Sandboxed filesystem worker failed")
                        break
            return json.loads(spool.read_bytes())
        finally:
            try:
                await self._terminate(key)
            finally:
                spool.unlink(missing_ok=True)

    async def _file_write(self, owned: _ReadHandle, request: dict[str, Any]) -> None:
        response = await self.executor.request(
            "process/write",
            {
                "processId": self.processes[owned.key],
                "chunk": base64.b64encode(json.dumps(request).encode() + b"\n").decode(),
                "writeId": uuid4().hex,
            },
        )
        if _result(response).get("status") != "accepted":
            raise OSError("File worker is not accepting owned requests")

    async def _file_reply(self, owned: _ReadHandle) -> dict[str, Any]:
        output = bytearray()
        while True:
            response = await self.executor.request(
                "process/read",
                {
                    "processId": self.processes[owned.key],
                    "afterSeq": owned.after_seq,
                    "maxBytes": 65536,
                    "waitMs": 1000,
                },
            )
            result = _result(response)
            for chunk in result["chunks"]:
                if chunk["stream"] == "stdout":
                    output.extend(base64.b64decode(chunk["chunk"], validate=True))
            owned.after_seq = result["nextSeq"]
            if len(output) > 2 * 1048576:
                raise OSError("File worker response exceeded its bounded frame")
            if output.endswith(b"\n"):
                value = json.loads(output)
                if not isinstance(value, dict):
                    raise ValueError("Invalid file worker response")
                return value
            if result["exited"]:
                raise OSError("File worker exited before its reply")

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._connection is not None or self._closed:
            writer.close()
            return
        self._connection = writer
        initialized = False
        incoming: asyncio.Queue[tuple[dict[str, Any], _PendingStart | None]] = asyncio.Queue(
            maxsize=32
        )
        eof = asyncio.Event()

        async def receive() -> None:
            try:
                while line := await reader.readline():
                    request = json.loads(line)
                    method, params = request.get("method"), request.get("params", {})
                    key = params.get("processId")
                    if (
                        initialized
                        and method == "process/terminate"
                        and isinstance(key, str)
                        and key in self.pending_starts
                        and request.get("id") is not None
                    ):
                        result = await self.dispatch(method, params)
                        await emit({"id": request["id"], "result": result})
                        continue
                    pending = None
                    if (
                        method == "process/start"
                        and isinstance(key, str)
                        and key not in self.pending_starts
                        and key not in self.processes
                    ):
                        pending = _PendingStart()
                        self.pending_starts[key] = pending
                    incoming.put_nowait((request, pending))
            finally:
                eof.set()

        async def emit(message: dict[str, Any]) -> None:
            writer.write(json.dumps(message).encode() + b"\n")
            await writer.drain()

        async def notifications() -> None:
            async for event in self.executor.iter_events():
                params = event.get("params", {})
                if not isinstance(params, dict):
                    continue
                internal = params.get("processId")
                key = next(
                    (key for key, value in self.processes.items() if value == internal), None
                )
                if key is not None and not key.startswith("fs-"):
                    await emit({**event, "params": {**params, "processId": key}})

        events = asyncio.create_task(notifications())
        receiver = asyncio.create_task(receive())
        try:
            while not eof.is_set():
                next_line = asyncio.create_task(incoming.get())
                disconnected = asyncio.create_task(eof.wait())
                done, _ = await asyncio.wait(
                    (next_line, disconnected), return_when=asyncio.FIRST_COMPLETED
                )
                disconnected.cancel()
                if next_line not in done:
                    next_line.cancel()
                    break
                request, pending = next_line.result()
                method, params = request["method"], request.get("params", {})
                request_id = request.get("id")
                if method == "initialized" and request_id is None:
                    continue
                if request_id is None:
                    raise ValueError("Unqualified executor notification")
                try:
                    if method == "initialize" and not initialized:
                        if params.get("resumeSessionId") not in (None, self.authority.generation):
                            raise ValueError("Executor resume identity differs")
                        result = {"sessionId": self.authority.generation}
                        initialized = True
                    elif not initialized:
                        raise ValueError("Executor must initialize first")
                    else:
                        if eof.is_set():
                            break
                        task = asyncio.create_task(self.dispatch(method, params, pending=pending))
                        self._active_request = task
                        disconnected = asyncio.create_task(eof.wait())
                        # Requests are sequential in the pinned server; detect EOF while ASK parks.
                        done, _ = await asyncio.wait(
                            (task, disconnected), return_when=asyncio.FIRST_COMPLETED
                        )
                        if disconnected in done:
                            task.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await task
                            self._active_request = None
                            raise ConnectionError("Executor disconnected")
                        disconnected.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await disconnected
                        try:
                            result = task.result()
                        finally:
                            self._active_request = None
                    await emit({"id": request_id, "result": result})
                except asyncio.CancelledError:
                    if eof.is_set() or self._closed:
                        raise
                    await emit(
                        {
                            "id": request_id,
                            "error": {
                                "code": -32800,
                                "message": "Owned process start was cancelled",
                            },
                        }
                    )
                except (ValueError, PermissionError, OSError, httpx.HTTPError) as error:
                    await emit(
                        {"id": request_id, "error": {"code": -32602, "message": str(error)}}
                    )
        except (ConnectionError, OSError):
            pass
        finally:
            receiver.cancel()
            with contextlib.suppress(asyncio.CancelledError, asyncio.QueueFull):
                await receiver
            events.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await events
            writer.close()
            try:
                with contextlib.suppress(ConnectionError, OSError):
                    await writer.wait_closed()
            finally:
                self._connection = None
                await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for pending in self.pending_starts.values():
            pending.cancelled = True
        if self._active_request is not None:
            self._active_request.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._active_request
        if self._connection is not None:
            self._connection.close()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        try:
            for key in list(self.processes):
                with contextlib.suppress(ConnectionError, OSError):
                    await self._terminate(key)
        finally:
            await self.executor.close()
            info = self.root.lstat()
            if (info.st_dev, info.st_ino) != self._root_identity:
                raise ValueError("Executor temporary root ownership changed")
            shutil.rmtree(self.root)
