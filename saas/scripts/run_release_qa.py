"""Run pinned onsite QA operators through the release pipeline."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REGISTRY = Path(__file__).resolve().parents[2] / ".github/release-qa.json"
BOOTSTRAP = """import os, sys
path, descriptor = sys.argv[1:3]
source = os.fdopen(int(descriptor), 'rb').read()
sys.argv = [path, *sys.argv[3:]]
sys.path.insert(0, os.path.dirname(path))
__file__, __spec__, __package__ = path, None, None
exec(compile(source, path, 'exec'), globals())
"""


def require(value: Any, message: str) -> None:
    if not value:
        raise ValueError(message)


def verified_source(root: Path, entry: dict[str, Any]) -> tuple[Path, bytes]:
    relative = Path(entry["path"])
    require(not relative.is_absolute() and ".." not in relative.parts, "unsafe operator path")
    path = root / relative
    require(path.resolve().is_relative_to(root) and not path.is_symlink(), "escaped operator")
    metadata = path.stat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & 0o022,
        "operator must be an owner-controlled regular file",
    )
    require(0 < entry["bytes"] <= 1024 * 1024, "invalid operator size")
    body = path.read_bytes()
    require(
        len(body) == entry["bytes"] and hashlib.sha256(body).hexdigest() == entry["sha256"],
        "operator or dependency differs from the reviewed source",
    )
    compile(body, str(path), "exec")
    return path, body


def validate_arguments(arguments: list[str], entry: dict[str, Any]) -> None:
    require(
        isinstance(arguments, list) and all(isinstance(a, str) for a in arguments),
        "operator arguments must be a JSON string array",
    )
    seen: set[str] = set()
    actions: list[str] = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        require("\0" not in value, "invalid argument")
        if value.startswith("--"):
            require(value not in seen and value != "--execute", "duplicate or reserved argument")
            seen.add(value)
            require(value in entry["flags"] + entry["switches"], "unregistered operator argument")
            if value in entry["flags"]:
                index += 1
                require(
                    index < len(arguments) and not arguments[index].startswith("--"),
                    "operator argument has no value",
                )
        else:
            actions.append(value)
        index += 1
    require(set(entry["required"]) <= seen, "required operator arguments are missing")
    require(
        actions == []
        if not entry["actions"]
        else len(actions) == 1 and actions[0] in entry["actions"],
        "unregistered operator action",
    )


def write_record(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    with open(
        temporary, "w", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def run_operator(
    operator: str,
    arguments: list[str],
    *,
    execute: bool = False,
    operation_id: str | None = None,
    registry: Path = REGISTRY,
) -> dict[str, Any]:
    settings = json.loads(registry.read_text())
    require(settings["schema_version"] == 1, "unsupported QA registry")
    require(operator in settings["operators"], "unregistered QA operator")
    root_value = os.environ.get(settings["root_environment"])
    if not root_value:
        raise ValueError("configured onsite QA root environment is required")
    root = Path(root_value).resolve(strict=True)
    entry = settings["operators"][operator]
    path, source = verified_source(root, entry)
    for dependency in entry["dependencies"]:
        verified_source(root, dependency)
    validate_arguments(arguments, entry)
    result: dict[str, Any] = {
        "schema_version": 1,
        "operator": operator,
        "source_sha256": entry["sha256"],
        "status": "plan",
        "production_authority": False,
    }
    if not execute:
        return result
    require(os.environ.get("OMNIGENT_RELEASE_QA_DISABLED") != "1", "onsite QA execution disabled")
    require(
        operation_id and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}", operation_id),
        "a stable operation id is required for execution",
    )
    state = root / ".release-pipeline"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = state.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & 0o077,
        "QA state directory must be private and owned",
    )
    identity = hashlib.sha256(
        json.dumps([str(root), operator, entry, arguments], sort_keys=True).encode()
    ).hexdigest()
    record = state / f"{operation_id}.json"
    with open(
        state / "writer.lock", "a", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW, 0o600)
    ) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if record.exists():
            previous = json.loads(record.read_text())
            require(
                previous["identity_sha256"] == identity, "operation id belongs to different inputs"
            )
            require(
                previous["status"] == "completed",
                "operation requires explicit reconciliation; no replay",
            )
            return previous
        result.update(operation_id=operation_id, identity_sha256=identity, status="running")
        write_record(record, result)
        log = state / f"{operation_id}.log"
        started = time.monotonic()
        try:
            with (
                path.open("rb") as script,
                open(log, "xb", opener=lambda p, f: os.open(p, f, 0o600)) as output,
            ):
                require(script.read() == source, "operator changed before execution")
                script.seek(0)
                native_arguments = arguments + (
                    ["--execute"] if "--execute" in entry["switches"] else []
                )
                with subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        BOOTSTRAP,
                        str(path),
                        str(script.fileno()),
                        *native_arguments,
                    ],
                    pass_fds=(script.fileno(),),
                    stdout=output,
                    stderr=output,
                    start_new_session=True,
                ) as process:
                    try:
                        result["exit_code"] = process.wait(timeout=entry["timeout_seconds"])
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                        result["status"] = "unknown"
            verified_source(root, entry)
            for dependency in entry["dependencies"]:
                verified_source(root, dependency)
            if result["status"] != "unknown":
                result["status"] = "completed" if result["exit_code"] == 0 else "failed"
        except Exception:
            result["status"] = "unknown"
            raise
        finally:
            result["elapsed_seconds"] = round(time.monotonic() - started, 3)
            result["log_sha256"] = (
                hashlib.sha256(log.read_bytes()).hexdigest() if log.exists() else None
            )
            write_record(record, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--arguments-json", type=Path, required=True)
    parser.add_argument("--operation-id")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        result = run_operator(
            args.operator,
            json.loads(args.arguments_json.read_text()),
            execute=args.execute,
            operation_id=args.operation_id,
        )
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"plan", "completed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
