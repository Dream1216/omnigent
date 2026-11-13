"""Trusted bootstrap run only after the fixed Codex executor creates its sandbox."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, BinaryIO

from omnigent.harnesses.codex_native.executor_policy import (
    FS_RESPONSE_LIMIT_BYTES,
    SessionExecutionPolicy,
    native_path,
)
from omnigent.inner.bwrap_sandbox import BwrapSandboxBackend
from omnigent.inner.sandbox import SandboxPolicy


def serve_read_handle(path: Path, source: BinaryIO, output: BinaryIO) -> None:
    """Keep the actual file descriptor inside its original tool namespace."""

    def reply(value: dict[str, Any]) -> None:
        output.write(json.dumps(value).encode() + b"\n")
        output.flush()

    with path.open("rb") as file:
        reply({"opened": True})
        for line in source:
            request = json.loads(line)
            if request.get("close") is True:
                break
            offset, length = request.get("offset"), request.get("len")
            if (
                type(offset) is not int
                or offset < 0
                or type(length) is not int
                or not 0 <= length <= 1048576
            ):
                raise ValueError("Invalid bounded file read")
            file.seek(offset)
            chunk = file.read(length)
            reply(
                {
                    "chunk": base64.b64encode(chunk).decode(),
                    "eof": file.tell() >= os.fstat(file.fileno()).st_size,
                }
            )
    reply({"closed": True})


def _read_file_response(path: Path) -> dict[str, str]:
    overhead = len(json.dumps({"dataBase64": ""}).encode())
    maximum = max(0, (FS_RESPONSE_LIMIT_BYTES - overhead) // 4 * 3)
    if path.stat().st_size > maximum:
        raise ValueError("Use the bounded filesystem stream for this file")
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Use the bounded filesystem stream for this file")
    return {"dataBase64": base64.b64encode(data).decode("ascii")}


def run_plan(plan: dict[str, Any]) -> dict[str, Any] | None:
    """Apply original hardening before either process exec or filesystem access."""
    if not sys.platform.startswith("linux"):
        raise OSError("Required executor hardening needs Linux")
    required = SandboxPolicy.from_jsonable(plan["required"])
    if not required.active or required.backend_type != "linux_bwrap" or required.allow_network:
        raise ValueError("Missing required executor policy")
    BwrapSandboxBackend().activate(required)
    operation = plan["operation"]
    os.chdir(plan["cwd"])
    if operation == "process/start":
        argv = plan["argv"]
        if plan.get("supervised") is True:
            # The original relay threads must outlive this fixed MCP child.
            raise SystemExit(subprocess.call(argv, env=plan["env"]))
        os.execvpe(argv[0], argv, plan["env"])
    params, context = plan["params"], plan["context"]
    policy = SessionExecutionPolicy(
        "", "", "", Path(plan["cwd"]), json.dumps(plan["required"]), ()
    )
    write = operation in {"fs/writeFile", "fs/createDirectory", "fs/remove", "fs/copy"}
    path = native_path(params["sourcePath"] if operation == "fs/copy" else params["path"])
    policy.check_path(context, path, write=write and operation != "fs/copy")
    if operation == "fs/open":
        serve_read_handle(path, sys.stdin.buffer, sys.stdout.buffer)
        return None
    if operation == "fs/readFile":
        return _read_file_response(path)
    if operation == "fs/writeFile":
        path.write_bytes(base64.b64decode(params["dataBase64"], validate=True))
    elif operation == "fs/createDirectory":
        path.mkdir(parents=bool(params.get("recursive")), exist_ok=True)
    elif operation == "fs/getMetadata":
        info = path.lstat()
        return {
            "isDirectory": path.is_dir(),
            "isFile": path.is_file(),
            "isSymlink": path.is_symlink(),
            "size": info.st_size,
            "createdAtMs": int(info.st_ctime * 1000),
            "modifiedAtMs": int(info.st_mtime * 1000),
        }
    elif operation == "fs/canonicalize":
        return {"path": path.resolve(strict=True).as_uri()}
    elif operation == "fs/readDirectory":
        return {
            "entries": [
                {"fileName": child.name, "isDirectory": child.is_dir(), "isFile": child.is_file()}
                for child in path.iterdir()
            ]
        }
    elif operation == "fs/remove":
        if path.is_dir() and not path.is_symlink():
            if params.get("recursive"):
                shutil.rmtree(path)
            else:
                path.rmdir()
        else:
            path.unlink(missing_ok=bool(params.get("force")))
    elif operation == "fs/copy":
        destination = native_path(params["destinationPath"])
        policy.check_path(context, destination, write=True)
        if path.is_dir():
            if not params.get("recursive"):
                raise IsADirectoryError(str(path))
            shutil.copytree(path, destination, symlinks=True)
        else:
            shutil.copyfile(path, destination)
    else:
        raise ValueError("Unsupported executor filesystem operation")
    return {}


def main() -> None:
    if len(sys.argv) != 2:
        raise ValueError("Executor worker requires its immutable operation plan")
    plan_path = Path(sys.argv[1])
    info = plan_path.lstat()
    if plan_path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PermissionError("Executor operation plan is not private")
    result = run_plan(json.loads(plan_path.read_text()))
    if result is not None:
        sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()
