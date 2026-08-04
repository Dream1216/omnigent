from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from saas.control_plane import SandboxLaunchContract, ToolPolicy
from saas.runner_adapter import LinuxCgroupV2ContainmentVerifier, RunnerIsolationAdapterError


def _contract() -> SandboxLaunchContract:
    return SandboxLaunchContract(
        backend="linux_bwrap",
        network_mode="proxy_only",
        root_read_only=True,
        run_as_uid=65532,
        run_as_gid=65532,
        no_new_privileges=True,
        host_socket_access=False,
        syscall_profile_ref="oci-default-v1",
        cpu_millis=1000,
        memory_bytes=1_073_741_824,
        pids_limit=256,
        tool_policy=ToolPolicy(
            allowed=("sys_os_read",), approval_required=(), denied=("host.socket",)
        ),
        egress_rules=("GET example.com/**",),
        allow_private_destinations=False,
        required_runner_capabilities=("sandbox.linux_bwrap",),
        config_hash="c" * 64,
    )


def _verifier(
    tmp_path: Path, runner_id: UUID
) -> tuple[LinuxCgroupV2ContainmentVerifier, Path, Path]:
    proc = tmp_path / "proc"
    cgroup_root = tmp_path / "cgroup"
    cgroup = cgroup_root / "kubepods" / "runner-a"
    (proc / "self").mkdir(parents=True)
    cgroup.mkdir(parents=True)
    (proc / "self" / "cgroup").write_text("0::/kubepods/runner-a\n", encoding="utf-8")
    (proc / "self" / "status").write_text(
        "Name:\trunner\nNoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000000000\n",
        encoding="utf-8",
    )
    (proc / "self" / "mountinfo").write_text(
        "36 25 0:32 / / ro,nosuid,nodev - overlay overlay ro\n",
        encoding="utf-8",
    )
    values = {
        "memory.max": "1073741824\n",
        "memory.swap.max": "0\n",
        "memory.oom.group": "1\n",
        "pids.max": "256\n",
        "cpu.max": "100000 100000\n",
        "cpu.max.burst": "0\n",
        "cgroup.procs": "321\n",
    }
    for name, value in values.items():
        (cgroup / name).write_text(value, encoding="utf-8")
    verifier = LinuxCgroupV2ContainmentVerifier(
        runner_id=runner_id,
        expected_cgroup_path="/kubepods/runner-a",
        proc_root=proc,
        cgroup_root=cgroup_root,
        effective_uid=lambda: 65532,
        process_id=lambda: 321,
    )
    return verifier, proc, cgroup


def test_linux_cgroup_v2_verifier_accepts_exact_hardened_runner_boundary(
    tmp_path: Path,
) -> None:
    runner_id = uuid4()
    verifier, _, _ = _verifier(tmp_path, runner_id)
    verifier.require_enforced(runner_id=runner_id, contract=_contract())


@pytest.mark.parametrize(
    ("file_name", "value", "code"),
    [
        ("memory.max", "max\n", "containment_memory_limit_invalid"),
        ("memory.max", "1073741825\n", "containment_memory_limit_loose"),
        ("pids.max", "257\n", "containment_pids_limit_loose"),
        ("cpu.max", "100001 100000\n", "containment_cpu_limit_loose"),
        ("cpu.max.burst", "1\n", "containment_cpu_burst_enabled"),
        ("memory.swap.max", "1\n", "containment_swap_enabled"),
        ("memory.oom.group", "0\n", "containment_oom_group_disabled"),
    ],
)
def test_linux_cgroup_v2_verifier_rejects_looser_resource_controls(
    tmp_path: Path,
    file_name: str,
    value: str,
    code: str,
) -> None:
    runner_id = uuid4()
    verifier, _, cgroup = _verifier(tmp_path, runner_id)
    (cgroup / file_name).write_text(value, encoding="utf-8")
    with pytest.raises(RunnerIsolationAdapterError) as error:
        verifier.require_enforced(runner_id=runner_id, contract=_contract())
    assert error.value.code == code


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (
            "Name:\trunner\nNoNewPrivs:\t0\nSeccomp:\t2\nCapEff:\t0\n",
            "containment_no_new_privileges_missing",
        ),
        (
            "Name:\trunner\nNoNewPrivs:\t1\nSeccomp:\t0\nCapEff:\t0\n",
            "containment_seccomp_missing",
        ),
        (
            "Name:\trunner\nNoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t1\n",
            "containment_capabilities_present",
        ),
    ],
)
def test_linux_cgroup_v2_verifier_rejects_unsafe_process_state(
    tmp_path: Path,
    status: str,
    code: str,
) -> None:
    runner_id = uuid4()
    verifier, proc, _ = _verifier(tmp_path, runner_id)
    (proc / "self" / "status").write_text(status, encoding="utf-8")
    with pytest.raises(RunnerIsolationAdapterError) as error:
        verifier.require_enforced(runner_id=runner_id, contract=_contract())
    assert error.value.code == code


@pytest.mark.parametrize(
    "mountinfo",
    [
        "36 25 0:32 / / rw,nosuid,nodev - overlay overlay rw\n",
        (
            "36 25 0:32 / / ro,nosuid,nodev - overlay overlay ro\n"
            "42 36 0:44 /docker.sock /var/run/docker.sock rw - tmpfs tmpfs rw\n"
        ),
        (
            "36 25 0:32 / / ro,nosuid,nodev - overlay overlay ro\n"
            "42 36 0:44 /containerd.sock /alternate/runtime-api rw - tmpfs tmpfs rw\n"
        ),
    ],
)
def test_linux_cgroup_v2_verifier_rejects_writable_root_or_host_socket(
    tmp_path: Path,
    mountinfo: str,
) -> None:
    runner_id = uuid4()
    verifier, proc, _ = _verifier(tmp_path, runner_id)
    (proc / "self" / "mountinfo").write_text(mountinfo, encoding="utf-8")
    with pytest.raises(RunnerIsolationAdapterError) as error:
        verifier.require_enforced(runner_id=runner_id, contract=_contract())
    assert error.value.code == "containment_mount_boundary_unsafe"


def test_linux_cgroup_v2_verifier_binds_runner_and_exact_cgroup_membership(
    tmp_path: Path,
) -> None:
    runner_id = uuid4()
    verifier, proc, _ = _verifier(tmp_path, runner_id)
    with pytest.raises(RunnerIsolationAdapterError) as wrong_runner:
        verifier.require_enforced(runner_id=uuid4(), contract=_contract())
    assert wrong_runner.value.code == "containment_runner_mismatch"

    (proc / "self" / "cgroup").write_text("0::/kubepods/runner-b\n", encoding="utf-8")
    with pytest.raises(RunnerIsolationAdapterError) as wrong_cgroup:
        verifier.require_enforced(runner_id=runner_id, contract=_contract())
    assert wrong_cgroup.value.code == "containment_cgroup_membership_mismatch"
