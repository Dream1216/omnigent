"""Server-owned policy preparation for the fixed 0.142 execution protocol."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from omnigent.inner.bwrap_sandbox import BwrapSandboxBackend, _ensure_executable_visible
from omnigent.inner.os_env import (
    _assert_read_allowed,
    _assert_within_reach,
    _assert_write_allowed,
    build_helper_env,
)
from omnigent.inner.sandbox import SandboxPolicy
from omnigent.runner.session_channels import SessionRelayChannel

_ACCESS = {"deny": 0, "read": 1, "write": 2}
_METADATA = (".git", ".agents", ".codex")
FS_RESPONSE_LIMIT_BYTES = 8 * 1024 * 1024
_LINUX_MINIMAL_READ_ROOTS = (
    "/bin",
    "/sbin",
    "/usr",
    "/etc",
    "/lib",
    "/lib64",
    "/nix/store",
    "/run/current-system/sw",
)


def native_path(value: object) -> Path:
    """Accept only local absolute file URIs from the pinned protocol."""
    if not isinstance(value, str):
        raise ValueError("Expected a file URI")
    uri = urlsplit(value)
    if uri.scheme != "file" or uri.netloc or uri.query or uri.fragment:
        raise ValueError("Executor path must be a local file URI")
    path = Path(unquote(uri.path))
    if not path.is_absolute() or "\0" in str(path):
        raise ValueError("Executor path must be absolute")
    return path


def _access(entries: dict[Path, int], path: Path) -> int:
    matches = [
        (len(root.parts), access)
        for root, access in entries.items()
        if path == root or root in path.parents
    ]
    return max(matches, default=(0, 0))[1]


@dataclass(frozen=True)
class SessionExecutionPolicy:
    """Immutable authority copied from requiredSpec, never from executor RPC."""

    session_id: str
    runner_id: str
    generation: str
    cwd: Path
    policy_json: str
    environment: tuple[tuple[str, str], ...]

    @classmethod
    def bind(
        cls,
        model: SessionRelayChannel,
        policy: SessionRelayChannel,
        cwd: Path,
        required: SandboxPolicy,
        parent_env: Mapping[str, str],
    ) -> SessionExecutionPolicy:
        model.verify(session_id=model.session_id, runner_id=model.runner_id)
        policy.verify(session_id=model.session_id, runner_id=model.runner_id)
        if (
            model.role != "model"
            or policy.role != "policy"
            or policy.generation != model.generation
        ):
            raise ValueError("Executor channels do not share Session authority")
        if (
            not required.active
            or required.backend_type != "linux_bwrap"
            or required.allow_network
            or required.copy_on_write_roots
            or required.credential_proxy
            or required.git_ssh
            or required.session_relay_pairs()
            or required.egress_socket_path
            or required.codex_requirements_path
            or required.codex_environments_path
        ):
            raise ValueError("Executor requires the original, unexpanded linux_bwrap policy")
        resolved = cwd.resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError("Executor workspace is not a directory")
        return cls(
            model.session_id,
            model.runner_id,
            model.generation,
            resolved,
            json.dumps(required.to_jsonable(), sort_keys=True),
            tuple(sorted(build_helper_env(parent_env, required).items())),
        )

    @property
    def required(self) -> SandboxPolicy:
        return SandboxPolicy.from_jsonable(json.loads(self.policy_json))

    def _server_entries(
        self, worker: Path, plan_root: Path, binary: Path | None = None
    ) -> dict[Path, int]:
        required = self.required
        # Reuse the original mount/mask builder; unknown mount shapes fail closed.
        if any(not path.exists() for path in required.write_roots):
            raise ValueError("Declared write roots must already exist")
        argv = BwrapSandboxBackend().wrap_launcher_argv(
            [str(worker)],
            required,
            self.cwd,
            target=str(binary) if binary else None,
        )
        entries: dict[Path, int] = {Path("/"): 0}
        index = 1
        while index < len(argv) and argv[index] != "--":
            option = argv[index]
            if option in {"--bind", "--bind-try", "--ro-bind", "--ro-bind-try"}:
                source, target = Path(argv[index + 1]), Path(argv[index + 2])
                if source == Path("/dev/null") and source != target:
                    entries[target] = 0
                elif source != target:
                    if option.startswith("--ro-") and source.resolve() == target.resolve():
                        entries[target] = 1
                    else:
                        raise ValueError("Unsupported executor mount translation")
                elif source.exists():
                    entries[target] = 1 if option.startswith("--ro-") else 2
                index += 3
            elif option in {"--tmpfs", "--proc", "--dev", "--dir", "--chdir"}:
                target = Path(argv[index + 1])
                if option == "--tmpfs" and target != Path("/tmp"):
                    entries[target] = 0
                index += 2
            elif option == "--setenv":
                index += 3
            elif option in {
                "--unshare-net",
                "--unshare-pid",
                "--unshare-uts",
                "--unshare-ipc",
                "--die-with-parent",
                "--new-session",
            }:
                index += 1
            else:
                raise ValueError(f"Unsupported executor mount option: {option}")
        for path in (plan_root, worker):
            if any(path.is_relative_to(root.resolve()) for root in required.write_roots):
                raise ValueError("Trusted executor input overlaps tool write grants")
            entries[path] = 1
        for path in [
            *(required.credential_source_paths or []),
            *(required.deny_unix_socket_paths or []),
        ]:
            entries[path.resolve()] = 0
        for root in required.write_roots:
            for name in _METADATA:
                target = root.resolve() / name
                entries[target] = min(entries.get(target, 1), 1)
        return entries

    def prepare(
        self,
        client: object,
        *,
        worker: Path,
        plan_root: Path,
        binary: Path | None = None,
    ) -> dict[str, Any]:
        """Fill absent context, intersect supplied restrictions, force managed isolation."""
        server = self._server_entries(worker, plan_root, binary)
        client_entries: dict[Path, int] | None = None
        if client is not None:
            if not isinstance(client, dict):
                raise ValueError("Malformed client sandbox")
            if client.get("cwd") is not None and native_path(client["cwd"]).resolve() != self.cwd:
                raise ValueError("Client sandbox cwd differs from Session authority")
            roots = client.get("workspaceRoots", [])
            if roots and [native_path(root).resolve() for root in roots] != [self.cwd]:
                raise ValueError("Client workspace roots differ from Session authority")
            permissions = client.get("permissions")
            if not isinstance(permissions, dict) or permissions.get("type") != "managed":
                raise ValueError("Client cannot disable or externalize executor isolation")
            fs = permissions.get("file_system")
            if not isinstance(fs, dict) or fs.get("type") != "restricted":
                raise ValueError("Client filesystem must be restricted")
            raw_entries = fs.get("entries")
            if not isinstance(raw_entries, list):
                raise ValueError("Client filesystem entries are missing")
            client_entries = {Path("/"): 0}
            for entry in raw_entries:
                if not isinstance(entry, dict) or entry.get("access") not in _ACCESS:
                    raise ValueError("Invalid client filesystem entry")
                item = entry.get("path")
                if not isinstance(item, dict):
                    raise ValueError("Invalid client filesystem path")
                if item.get("type") == "path":
                    roots = [native_path(item.get("path")).resolve()]
                elif item.get("type") == "special" and isinstance(item.get("value"), dict):
                    special = item["value"]
                    kind = special.get("kind")
                    if kind == "root":
                        roots = [Path("/")]
                    elif kind == "project_roots":
                        subpath = special.get("subpath") or ""
                        target = (self.cwd / subpath).resolve()
                        if not target.is_relative_to(self.cwd):
                            raise ValueError("Client project root escapes Session")
                        roots = [target]
                    elif kind == "slash_tmp":
                        roots = [Path("/tmp")] if Path("/tmp").is_dir() else []
                    elif kind == "tmpdir":
                        value = dict(self.environment).get("TMPDIR")
                        roots = [Path(value)] if value and Path(value).is_absolute() else []
                    elif kind == "minimal":
                        roots = (
                            [Path(value) for value in _LINUX_MINIMAL_READ_ROOTS]
                            if _ACCESS[entry["access"]]
                            else []
                        )
                    else:
                        raise ValueError("Unsupported client special filesystem restriction")
                else:
                    raise ValueError("Unsupported client filesystem restriction")
                for root in roots:
                    access = _ACCESS[entry["access"]]
                    if item.get("type") == "special" and item["value"].get("kind") == "minimal":
                        access = min(access, 1)
                    previous = client_entries.get(root)
                    client_entries[root] = (
                        access
                        if previous is None
                        else (0 if 0 in (previous, access) else max(previous, access))
                    )
        boundaries = server.keys() | (client_entries.keys() if client_entries else set())
        merged = {
            path: min(_access(server, path), _access(client_entries, path))
            if client_entries is not None
            else _access(server, path)
            for path in boundaries
        }
        # The trusted bootstrap and immutable plan are infrastructure, not client data grants.
        merged[plan_root], merged[worker] = 1, 1
        runtime = _ensure_executable_visible([str(worker)], self.cwd)
        if binary is not None:
            runtime += _ensure_executable_visible([str(binary)], self.cwd)
        for index in range(0, len(runtime), 3):
            root = Path(runtime[index + 2])
            if any(
                root.resolve().is_relative_to(path.resolve()) for path in self.required.write_roots
            ):
                raise ValueError("Trusted Python runtime overlaps tool write grants")
            merged[root] = 1
        reduced: dict[Path, int] = {}
        for path in sorted(merged, key=lambda item: len(item.parts)):
            if merged[path] != _access(reduced, path):
                reduced[path] = merged[path]
        return {
            "permissions": {
                "type": "managed",
                "file_system": {
                    "type": "restricted",
                    "entries": [
                        {
                            "path": {"type": "path", "path": path.as_uri()},
                            "access": ("deny", "read", "write")[access],
                        }
                        for path, access in sorted(reduced.items(), key=lambda item: str(item[0]))
                    ],
                },
                "network": "restricted",
            },
            "cwd": self.cwd.as_uri(),
            "workspaceRoots": [self.cwd.as_uri()],
            "windowsSandboxLevel": "disabled",
            "useLegacyLandlock": False,
        }

    def check_path(self, context: dict[str, Any], path: Path, *, write: bool) -> None:
        """Constrain explicit FS calls before they enter the kernel sandbox."""
        permissions = context["permissions"]
        entries = permissions["file_system"]["entries"]
        grants = {
            native_path(entry["path"]["path"]).resolve(): _ACCESS[entry["access"]]
            for entry in entries
        }
        resolved = path.resolve()
        original = self.required
        _assert_within_reach(self.cwd, original, resolved, need_write=write)
        if write:
            _assert_write_allowed(original, resolved)
        else:
            _assert_read_allowed(original, resolved, self.cwd)
        if write and any(name in path.parts or name in resolved.parts for name in _METADATA):
            raise PermissionError("Codex metadata is read-only")
        if _access(grants, resolved) < (2 if write else 1):
            raise PermissionError("Executor path is outside Session grants")
