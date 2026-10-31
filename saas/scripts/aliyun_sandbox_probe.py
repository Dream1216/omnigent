"""Bounded live probe for the Aliyun E2B transport and Host prerequisites."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class ProbeConfig:
    api_key: str = field(repr=False)
    api_url: str
    domain: str
    template: str

    def sdk_options(self) -> dict[str, Any]:
        return {
            "api_key": self.api_key,
            "api_url": self.api_url,
            "domain": self.domain,
            "request_timeout": 45,
        }


def load_config(path: Path, template: str | None = None) -> ProbeConfig:
    """Read an owner-only dotenv without evaluating shell expressions."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Probe credential path must be absolute")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o077
                or not 0 < before.st_size <= 16384
            ):
                raise ValueError("Probe credentials require an owner-only regular file")
            raw = os.read(fd, 16385)
            after = os.fstat(fd)
            linked = path.lstat()
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if len(raw) != before.st_size or any(
                tuple(getattr(item, f) for f in fields)
                != tuple(getattr(before, f) for f in fields)
                for item in (after, linked)
            ):
                raise ValueError("Probe credential file changed while reading")
        finally:
            os.close(fd)
    except OSError:
        raise ValueError("Probe credential file is unavailable") from None
    values: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("Probe credential file must contain dotenv assignments")
        key, value = line.split("=", 1)
        if key in values:
            raise ValueError("Probe credential file contains duplicate assignments")
        values[key] = value
    key = values.get("E2B_API_KEY", "")
    if re.fullmatch(r"e2b_[A-Za-z0-9_-]{16,256}", key) is None:
        raise ValueError("Sandbox API key format is invalid")
    api = values.get("E2B_API_URL", "")
    domain = values.get("E2B_DOMAIN", "")
    if api != "https://api.cn-hangzhou.sandbox.aliyuncs.com" or domain != (
        "cn-hangzhou.sandbox.aliyuncs.com"
    ):
        raise ValueError("Probe accepts only the reviewed Hangzhou HTTPS endpoint")
    selected = template if template is not None else values.get("E2B_TEMPLATE_ID", "")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", selected) is None:
        raise ValueError("Sandbox template is invalid")
    return ProbeConfig(key, api, domain, selected)


def _safe_error(exc: Exception, config: ProbeConfig) -> str:
    message = str(exc).replace(config.api_key, "[REDACTED]")
    return re.sub(r"e2b_[A-Za-z0-9_-]+", "[REDACTED]", message)[:1500]


_INVENTORY_COMMAND = """python3 - <<'PY'
import importlib.util,json,os,platform,shutil,subprocess,sys
tools=['git','tmux','node','bwrap','curl','systemctl','sshd','sudo','chronyd','ossfs2']
node=None
if shutil.which('node'):
    node=subprocess.check_output(['node','--version']).decode().strip()
print(json.dumps({'python':platform.python_version(),'python_executable':sys.executable,
'uid':os.geteuid(),'tools':{k:shutil.which(k) for k in tools},
'node_version':node,
'omnigent_installed':importlib.util.find_spec('omnigent') is not None}))
PY"""


def host_prerequisites_ready(inventory: dict[str, Any]) -> bool:
    """Apply the actual Python/Node floors, not only executable presence."""
    try:
        python_version = tuple(int(x) for x in inventory["python"].split(".")[:2])
        node_version = tuple(
            int(x) for x in inventory["node_version"].removeprefix("v").split(".")
        )
    except (KeyError, AttributeError, TypeError, ValueError):
        return False
    uid = inventory.get("uid")
    return bool(
        inventory.get("omnigent_installed") is True
        and type(uid) is int
        and uid > 0
        and python_version >= (3, 12)
        and node_version >= (22, 13, 0)
        and all(inventory.get("tools", {}).get(k) for k in ("git", "tmux", "node", "bwrap"))
    )


def run_probe(config: ProbeConfig) -> dict[str, Any]:
    import httpx
    from e2b import Sandbox, SandboxNotFoundException
    from e2b.exceptions import AuthenticationException, SandboxException
    from e2b.sandbox.commands.command_handle import CommandExitException

    result: dict[str, Any] = {
        "schema_version": 1,
        "started_at": datetime.now(UTC).isoformat(),
        "run_id": "aliyun-integration-" + uuid4().hex,
        "sdk_version": version("e2b"),
        "template": config.template,
        "checks": {},
        "errors": {},
        "production_acceptance": False,
    }
    sandbox = None
    options = config.sdk_options()

    probe_errors = (
        AuthenticationException,
        SandboxException,
        httpx.HTTPError,
        OSError,
        ValueError,
        RuntimeError,
    )

    def check(name: str, operation: Callable[[], object]) -> None:
        try:
            operation()
            result["checks"][name] = True
        except probe_errors as exc:
            result["checks"][name] = False
            result["errors"][name] = {
                "type": type(exc).__name__,
                "message": _safe_error(exc, config),
            }

    try:
        start = time.monotonic()
        sandbox = Sandbox.create(
            template=config.template,
            timeout=240,
            metadata={"purpose": "omnigent-aliyun-integration", "probe_run": result["run_id"]},
            **options,
        )
        result["sandbox_id"] = sandbox.sandbox_id
        result["create_seconds"] = round(time.monotonic() - start, 3)
        result["checks"]["create"] = True

        def command_check() -> None:
            command = sandbox.commands.run("printf 'aliyun-sdk-ok\\n'", timeout=15)
            if command.exit_code != 0 or command.stdout.strip() != "aliyun-sdk-ok":
                raise RuntimeError("Command output does not match")

        def file_check() -> None:
            data = "阿里云接入验证\n" + result["run_id"]
            sandbox.files.write("/tmp/aliyun-probe.txt", data)
            if sandbox.files.read("/tmp/aliyun-probe.txt") != data:
                raise RuntimeError("Unicode roundtrip mismatch")
            binary = bytes(range(256)) * 4096
            sandbox.files.write("/tmp/aliyun-probe.bin", binary)
            if sandbox.files.read("/tmp/aliyun-probe.bin", format="bytes") != binary:
                raise RuntimeError("Binary roundtrip mismatch")

        def reconnect_check() -> None:
            attached = Sandbox.connect(sandbox.sandbox_id, **options)
            if attached.sandbox_id != sandbox.sandbox_id:
                raise RuntimeError("Connected to a different sandbox")
            if attached.commands.run("printf reconnect-ok", timeout=15).stdout != "reconnect-ok":
                raise RuntimeError("Reconnected command did not complete")

        def timeout_check() -> None:
            sandbox.set_timeout(240)
            sandbox.get_info()

        def nonzero_check() -> None:
            try:
                sandbox.commands.run("exit 7", timeout=15)
            except CommandExitException as exc:
                if exc.exit_code == 7:
                    return
                raise
            raise RuntimeError("Expected a nonzero exit status")

        def process_check() -> None:
            handle = sandbox.commands.run("sleep 120", background=True)
            listed = sandbox.commands.list()
            if not any(item.pid == handle.pid for item in listed):
                raise RuntimeError("Background process is not listed")
            handle.kill()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not any(item.pid == handle.pid for item in sandbox.commands.list()):
                    return
                time.sleep(0.2)
            raise RuntimeError("Killed process remained listed")

        def inventory_check() -> None:
            inventory = sandbox.commands.run(_INVENTORY_COMMAND, timeout=20)
            result["host_inventory"] = json.loads(inventory.stdout)

        check("command", command_check)
        check("unicode_and_1mib_binary_files", file_check)
        check("connect_and_command", reconnect_check)
        check("timeout_and_info", timeout_check)
        check("nonzero_exit", nonzero_check)
        check("background_list_kill", process_check)
        check("host_inventory", inventory_check)
    except probe_errors as exc:
        result["checks"].setdefault("create", False)
        result["errors"]["setup"] = {
            "type": type(exc).__name__,
            "message": _safe_error(exc, config),
        }
    finally:
        if sandbox is not None:
            check("kill_requested", sandbox.kill)

            def confirm_gone() -> None:
                try:
                    sandbox.get_info()
                except SandboxNotFoundException:
                    return
                raise RuntimeError("Sandbox remains queryable after termination")

            check("kill_confirmed", confirm_gone)
        result["transport_passed"] = len(result["checks"]) == 10 and all(result["checks"].values())
        inventory = result.get("host_inventory", {})
        result["host_prerequisites_ready"] = host_prerequisites_ready(inventory)
        result["finished_at"] = datetime.now(UTC).isoformat()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--template")
    args = parser.parse_args()
    config = load_config(args.env_file, args.template)
    result = run_probe(config)
    args.report_dir.mkdir(parents=True, exist_ok=True)
    report = args.report_dir / (result["run_id"] + ".json")
    fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({"report": str(report), **result}, ensure_ascii=False, indent=2))
    return 0 if result["transport_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
