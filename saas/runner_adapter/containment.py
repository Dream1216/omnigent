"""Fail-closed Linux cgroup-v2 evidence behind the Runner containment contract."""

from __future__ import annotations

import math
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from saas.control_plane.isolation import SandboxLaunchContract
from saas.runner_adapter.isolation import RunnerIsolationAdapterError

_HOST_SOCKET_PATHS = frozenset(
    {
        "/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
        "/run/podman/podman.sock",
        "/var/run/docker.sock",
    }
)


def _read(path: Path, *, code: str) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise RunnerIsolationAdapterError(
            code, "required containment evidence is unavailable"
        ) from exc


def _integer_limit(path: Path, *, code: str) -> int:
    raw = _read(path, code=code)
    if raw == "max":
        raise RunnerIsolationAdapterError(code, "containment resource limit is unbounded")
    try:
        value = int(raw)
    except ValueError as exc:
        raise RunnerIsolationAdapterError(code, "containment resource limit is invalid") from exc
    if value <= 0:
        raise RunnerIsolationAdapterError(code, "containment resource limit must be positive")
    return value


def _status_fields(status: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in status.splitlines():
        name, separator, value = line.partition(":")
        if separator:
            fields[name] = value.strip()
    return fields


def _current_effective_uid() -> int:
    get_effective_uid = getattr(os, "geteuid", None)
    if get_effective_uid is None:
        raise RunnerIsolationAdapterError(
            "containment_platform_unsupported", "Linux cgroup containment is unavailable"
        )
    return int(get_effective_uid())


def _root_mount_is_readonly_and_socket_free(mountinfo: str) -> bool:
    root_readonly = False
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) < 7 or "-" not in fields:
            continue
        mountpoint = fields[4].replace("\\040", " ")
        mount_root = fields[3].replace("\\040", " ")
        options = set(fields[5].split(","))
        if mountpoint == "/":
            root_readonly = "ro" in options
        if (
            mountpoint.rstrip("/") in _HOST_SOCKET_PATHS
            or mountpoint.endswith(".sock")
            or mount_root.endswith(".sock")
        ):
            return False
    return root_readonly


@dataclass(frozen=True, slots=True)
class LinuxCgroupV2ContainmentVerifier:
    """Verify an exact server-configured Runner cgroup before each launch.

    This class does not create cgroups. The deployment unit must create a
    dedicated cgroup/container for the Runner, set a read-only root filesystem,
    drop capabilities, enable ``no_new_privs`` and a seccomp filter, and pass
    the exact observed cgroup path as trusted configuration. The verifier then
    rejects drift or looser limits before any Secret is redeemed.
    """

    runner_id: UUID
    expected_cgroup_path: str
    proc_root: Path = Path("/proc")
    cgroup_root: Path = Path("/sys/fs/cgroup")
    effective_uid: Callable[[], int] = _current_effective_uid
    process_id: Callable[[], int] = os.getpid

    def __post_init__(self) -> None:
        path = self.expected_cgroup_path
        if (
            not path.startswith("/")
            or path == "/"
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
            or len(path) > 4096
        ):
            raise RunnerIsolationAdapterError(
                "containment_cgroup_path_invalid", "expected cgroup path is invalid"
            )

    def require_enforced(
        self,
        *,
        runner_id: UUID,
        contract: SandboxLaunchContract,
    ) -> None:
        if runner_id != self.runner_id:
            raise RunnerIsolationAdapterError(
                "containment_runner_mismatch", "containment evidence belongs to another Runner"
            )
        if contract.backend != "linux_bwrap":
            raise RunnerIsolationAdapterError(
                "containment_backend_mismatch", "Linux cgroup containment requires bubblewrap"
            )
        if self.effective_uid() <= 0:
            raise RunnerIsolationAdapterError(
                "containment_outer_root_denied", "outer Runner process must be non-root"
            )

        membership = _read(
            self.proc_root / "self" / "cgroup", code="containment_cgroup_membership_missing"
        )
        lines = [line for line in membership.splitlines() if line]
        expected_line = f"0::{self.expected_cgroup_path}"
        if lines != [expected_line]:
            raise RunnerIsolationAdapterError(
                "containment_cgroup_membership_mismatch",
                "Runner process is not in the exact unified cgroup",
            )

        root = self.cgroup_root.resolve(strict=True)
        cgroup = (root / self.expected_cgroup_path.lstrip("/")).resolve(strict=True)
        try:
            cgroup.relative_to(root)
        except ValueError as exc:
            raise RunnerIsolationAdapterError(
                "containment_cgroup_path_escape", "cgroup path escapes the unified hierarchy"
            ) from exc
        if not cgroup.is_dir() or cgroup.is_symlink():
            raise RunnerIsolationAdapterError(
                "containment_cgroup_missing", "Runner cgroup is not a real directory"
            )

        memory_limit = _integer_limit(
            cgroup / "memory.max", code="containment_memory_limit_invalid"
        )
        pids_limit = _integer_limit(cgroup / "pids.max", code="containment_pids_limit_invalid")
        if memory_limit > contract.memory_bytes:
            raise RunnerIsolationAdapterError(
                "containment_memory_limit_loose", "outer memory limit exceeds the launch contract"
            )
        if pids_limit > contract.pids_limit:
            raise RunnerIsolationAdapterError(
                "containment_pids_limit_loose", "outer PID limit exceeds the launch contract"
            )

        cpu = _read(cgroup / "cpu.max", code="containment_cpu_limit_invalid").split()
        if len(cpu) != 2 or cpu[0] == "max":
            raise RunnerIsolationAdapterError(
                "containment_cpu_limit_invalid", "outer CPU limit is missing or unbounded"
            )
        try:
            quota, period = (int(value) for value in cpu)
        except ValueError as exc:
            raise RunnerIsolationAdapterError(
                "containment_cpu_limit_invalid", "outer CPU limit is invalid"
            ) from exc
        if quota <= 0 or not 1_000 <= period <= 1_000_000:
            raise RunnerIsolationAdapterError(
                "containment_cpu_limit_invalid", "outer CPU quota or period is invalid"
            )
        cpu_millis = math.ceil(quota * 1000 / period)
        if cpu_millis > contract.cpu_millis:
            raise RunnerIsolationAdapterError(
                "containment_cpu_limit_loose", "outer CPU limit exceeds the launch contract"
            )
        burst = cgroup / "cpu.max.burst"
        if burst.exists() and _read(burst, code="containment_cpu_burst_invalid") != "0":
            raise RunnerIsolationAdapterError(
                "containment_cpu_burst_enabled", "outer CPU burst must be disabled"
            )
        if _read(cgroup / "memory.swap.max", code="containment_swap_limit_invalid") != "0":
            raise RunnerIsolationAdapterError(
                "containment_swap_enabled", "outer memory swap must be disabled"
            )
        if _read(cgroup / "memory.oom.group", code="containment_oom_group_invalid") != "1":
            raise RunnerIsolationAdapterError(
                "containment_oom_group_disabled", "outer cgroup must kill the complete Run on OOM"
            )

        pid = str(self.process_id())
        cgroup_processes = set(
            _read(
                cgroup / "cgroup.procs", code="containment_cgroup_processes_missing"
            ).splitlines()
        )
        if pid not in cgroup_processes:
            raise RunnerIsolationAdapterError(
                "containment_process_membership_mismatch", "Runner PID is absent from its cgroup"
            )

        status = _status_fields(
            _read(self.proc_root / "self" / "status", code="containment_process_status_missing")
        )
        if status.get("NoNewPrivs") != "1":
            raise RunnerIsolationAdapterError(
                "containment_no_new_privileges_missing", "outer Runner lacks no_new_privs"
            )
        if status.get("Seccomp") != "2":
            raise RunnerIsolationAdapterError(
                "containment_seccomp_missing", "outer Runner lacks an enforcing seccomp filter"
            )
        try:
            capabilities = int(status.get("CapEff", "invalid"), 16)
        except ValueError as exc:
            raise RunnerIsolationAdapterError(
                "containment_capabilities_invalid", "outer capability evidence is invalid"
            ) from exc
        if capabilities != 0:
            raise RunnerIsolationAdapterError(
                "containment_capabilities_present", "outer Runner retains Linux capabilities"
            )

        mountinfo = _read(
            self.proc_root / "self" / "mountinfo", code="containment_mountinfo_missing"
        )
        if not _root_mount_is_readonly_and_socket_free(mountinfo):
            raise RunnerIsolationAdapterError(
                "containment_mount_boundary_unsafe",
                "outer root must be read-only and host runtime sockets must not be mounted",
            )
