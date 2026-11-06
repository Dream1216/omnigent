"""Observe installed production startup locale gates; never start real services."""

from __future__ import annotations

import ctypes
import hashlib
import importlib
import json
import locale
import os
import platform
import re
import sys
from pathlib import Path

KEYS = ("LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES", "LOCPATH")
POISON = {
    "LANG": "fr_FR.UTF-8",
    "LC_ALL": "fr_FR.UTF-8",
    "LC_MESSAGES": "fr_FR.UTF-8",
    "LANGUAGE": "../../workspace/catalog:fr",
    "LOCPATH": "/workspace/locale",
}
CLEAN = {key: None if key in {"LANGUAGE", "LOCPATH"} else "C.UTF-8" for key in KEYS}
ENTRIES = {
    "server": "ProductionServerConfigError",
    "worker": "ProductionWorkerConfigError",
    "runner_control": "RunnerControlError",
    "runner_agent": "RunnerControlError",
    "preview_edge": "ProductionPreviewEdgeError",
    "preview_owner": "ProductionPreviewRelayError",
}


def loaded_libc():
    paths = set()
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and re.fullmatch(
            r"libc(?:-[0-9.]+)?\.so(?:\.6)?", Path(fields[5]).name
        ):
            paths.add(Path(fields[5]).resolve(strict=True))
    if len(paths) != 1:
        raise RuntimeError("actual loaded libc identity is ambiguous or absent")
    path = paths.pop()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"target": str(path), "sha256": digest}


def observe_startup(bindings: dict) -> dict:
    if sys.platform != "linux" or platform.machine() != "aarch64":
        raise ValueError("requires actual Linux ARM64 userspace")
    if Path(sys.prefix).resolve() != Path("/opt/venv") or os.geteuid() == 0:
        raise ValueError("requires installed image virtualenv and a nonroot identity")
    if any(name.startswith("OMNIGENT_SAAS_") for name in os.environ):
        raise ValueError("diagnostic must not receive application configuration or credentials")
    from omnigent import _build_info

    if bindings["source_revision"] != _build_info.COMMIT_SHA:
        raise ValueError("installed source differs from the fixed subject")
    installed = {}
    for relative, expected in bindings["installed_files"].items():
        path = Path("/") / relative
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(Path("/opt/venv")):
            raise ValueError("installed boundary escaped the image virtualenv")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError("installed production boundary changed")
        installed[relative] = actual
    libc = loaded_libc()
    if libc["sha256"] != bindings["libc_sha256"]:
        raise ValueError("actual ARM64 libc differs")
    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
    )
    if status["NoNewPrivs"].strip() != "1" or any(
        int(status[key].strip(), 16) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    ):
        raise ValueError("actual process privileges are not constrained")
    if not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise ValueError("actual image root filesystem is not read-only")
    interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    if interfaces != ["lo"] or any(line.split()[0] != "lo" for line in routes if line.split()):
        raise ValueError("diagnostic has an external network interface or route")
    library = ctypes.CDLL(None)
    library.getenv.argtypes = [ctypes.c_char_p]
    library.getenv.restype = ctypes.c_char_p
    entries = []
    for role, error_name in ENTRIES.items():
        module = importlib.import_module(f"saas.production.{role}")
        errors = (
            importlib.import_module("saas.production.server_config")
            if role == "server"
            else module
        )
        expected_error = getattr(errors, error_name)
        locale.setlocale(locale.LC_ALL, "C")
        os.environ.update(POISON)
        try:
            module.main()
        except expected_error:
            pass
        else:
            raise ValueError("a real service started without required configuration")
        actual = {key: os.environ.get(key) for key in KEYS}
        native = {
            key: value.decode() if (value := library.getenv(key.encode())) is not None else None
            for key in KEYS
        }
        messages, encoding = locale.setlocale(locale.LC_MESSAGES), locale.getencoding()
        if actual != CLEAN or native != CLEAN or messages not in {"C.UTF-8", "C.utf8"}:
            raise ValueError("actual entry did not constrain libc messages and environment")
        if encoding.lower().replace("-", "") != "utf8":
            raise ValueError("actual entry encoding differs")
        entries.append(
            {
                "role": role,
                "expected_config_rejection": error_name,
                "five_locale_inputs": native,
                "effective_LC_MESSAGES": messages,
                "effective_encoding": encoding,
            }
        )
    return {
        "kind": "installed-production-startup-locale/v1",
        "source_revision": bindings["source_revision"],
        "platform": "linux/arm64",
        "actual_loaded_libc": libc,
        "installed_files": installed,
        "entries": entries,
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "pid": os.getpid(),
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
        "process_start_ticks": Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19],
        "actual_controls": {
            "no_new_privileges": True,
            "all_capabilities_empty": True,
            "rootfs_readonly": True,
            "interfaces": interfaces,
            "non_loopback_routes": 0,
        },
        "simulated_inputs": POISON,
        "mocked_exec": False,
        "production_source_modified": False,
        "whole_service_lifecycle_qualified": False,
        "High_disposition": False,
        "expires_at": "2026-11-11T10:40:00Z",
    }


if __name__ == "__main__":
    result = observe_startup(json.loads(Path(__file__).with_name("bindings.json").read_text()))
    Path("/evidence/native-startup.PUBLIC.json").write_text(json.dumps(result, indent=2) + "\n")
