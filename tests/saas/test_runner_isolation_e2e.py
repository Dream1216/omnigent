from __future__ import annotations

import asyncio
import os
import shutil
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

import omnigent
from omnigent.inner.credential_proxy import SYNTHETIC_CREDENTIAL_PREFIX
from saas.control_plane import (
    SandboxLaunchContract,
    SecretLeaseReference,
    SecretMaterial,
    ToolPolicy,
    TrustedRunnerLaunchGrant,
)
from saas.runner_adapter import (
    PhysicalWorktree,
    RunnerIsolationAdapter,
    reap_orphaned_secret_directories,
)
from saas.runner_adapter import isolation as isolation_adapter

_ACTIVE_BACKEND = (
    "linux_bwrap"
    if sys.platform.startswith("linux") and shutil.which("bwrap")
    else "darwin_seatbelt"
    if sys.platform == "darwin" and shutil.which("sandbox-exec")
    else None
)


class _Authority:
    def __init__(self, grant: TrustedRunnerLaunchGrant, material: SecretMaterial) -> None:
        self.grant = grant
        self.material = material
        self.launch_tokens: list[str] = []
        self.secret_tokens: list[str] = []

    def redeem_launch_grant(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
    ) -> TrustedRunnerLaunchGrant:
        assert token == "launch-token"
        assert runner_id == self.grant.runner_id
        assert run_id == self.grant.run_id
        self.launch_tokens.append(token)
        return self.grant

    def redeem_secret(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
        provider: object,
    ) -> SecretMaterial:
        assert token == "secret-token"
        assert runner_id == self.grant.runner_id
        assert run_id == self.grant.run_id
        assert provider is not None
        self.secret_tokens.append(token)
        return self.material


class _Containment:
    def __init__(self) -> None:
        self.verified = False

    def require_enforced(
        self,
        *,
        runner_id: UUID,
        contract: SandboxLaunchContract,
    ) -> None:
        assert runner_id
        assert contract.backend == _ACTIVE_BACKEND
        assert contract.root_read_only
        assert contract.no_new_privileges
        assert not contract.host_socket_access
        self.verified = True


class _SecretProvider:
    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str:
        raise AssertionError(
            f"test authority must redeem the staged value: {provider}/{vault_ref}/{version_ref}"
        )


@pytest.mark.skipif(_ACTIVE_BACKEND is None, reason="a hard OS sandbox backend is required")
def test_runner_adapter_boots_official_hard_sandbox_without_exposing_broker_secret(
    tmp_path: Path,
) -> None:
    """Exercise the downstream grant adapter through the real official helper process."""

    worktree_id = uuid4()
    runner_id = uuid4()
    run_id = uuid4()
    binding_id = uuid4()
    worktree_path = tmp_path / "worktree"
    worktree_path.mkdir(mode=0o700)
    (worktree_path / ".git").write_text("gitdir: /parent-only\n", encoding="utf-8")
    (worktree_path / "source.py").write_text("print('safe')\n", encoding="utf-8")
    contract = SandboxLaunchContract(
        backend=str(_ACTIVE_BACKEND),
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
            allowed=("sys_os_read", "sys_os_write", "sys_os_shell"),
            approval_required=("sys_os_shell",),
            denied=("host.docker_socket",),
        ),
        egress_rules=("GET example.com/**",),
        allow_private_destinations=False,
        required_runner_capabilities=(f"sandbox.{_ACTIVE_BACKEND}",),
        config_hash="c" * 64,
    )
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    grant = TrustedRunnerLaunchGrant(
        grant_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        run_id=run_id,
        runner_id=runner_id,
        worktree_id=worktree_id,
        worktree_access_mode="writer",
        worktree_lease_generation=1,
        run_fence_token=1,
        runner_connection_generation=1,
        contract=contract,
        secret_leases=(
            SecretLeaseReference(
                binding_id=binding_id,
                name="github-api",
                host="example.com",
                credential_scheme="bearer",
                username=None,
                inject_env=("GH_TOKEN",),
                token="secret-token",
                expires_at=expires_at,
            ),
        ),
        expires_at=expires_at,
    )
    real_secret = "runner-parent-only-secret-7f88"
    authority = _Authority(
        grant,
        SecretMaterial(
            binding_id=binding_id,
            name="github-api",
            host="example.com",
            credential_scheme="bearer",
            username=None,
            inject_env=("GH_TOKEN",),
            value=real_secret,
        ),
    )
    containment = _Containment()
    staging_root = tmp_path / "secret-staging"
    adapter = RunnerIsolationAdapter(
        staging_root=staging_root,
        authority=authority,
        secret_authority=authority,
        secret_provider=_SecretProvider(),
        containment=containment,
    )
    physical = PhysicalWorktree(
        worktree_id=worktree_id,
        worktree_path=worktree_path,
        head_revision="a" * 40,
        actual_bytes=1024,
        readonly=False,
    )

    prepared = adapter.prepare(
        grant_token="launch-token",
        runner_id=runner_id,
        run_id=run_id,
        physical_worktree=physical,
    )
    staged_files = tuple(prepared.secret_directory.glob("material-*"))
    assert len(staged_files) == 1
    lease_file = prepared.secret_directory / ".omnigent-saas-secret-lease"
    assert stat.S_IMODE(prepared.secret_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(lease_file.stat().st_mode) == 0o600
    assert real_secret not in lease_file.read_text(encoding="utf-8")
    assert stat.S_IMODE(staged_files[0].stat().st_mode) == 0o600
    assert staged_files[0].read_text(encoding="utf-8") == real_secret
    assert containment.verified
    package_root = Path(omnigent.__file__ or "").resolve().parent
    assert prepared.os_env_spec.sandbox is not None
    mounted_read_paths = {
        Path(path).resolve() for path in prepared.os_env_spec.sandbox.read_paths or []
    }
    assert package_root in mounted_read_paths
    for linked_asset in package_root.rglob("*"):
        if linked_asset.is_symlink():
            assert linked_asset.resolve(strict=True) in mounted_read_paths

    async def exercise():
        environment = await prepared.start()
        assert prepared.secret_directory.exists()
        assert all(path.is_file() for path in staged_files)
        try:
            return (
                await environment.shell('printf "%s" "$GH_TOKEN"'),
                await environment.shell("cat .git 2>&1 || true"),
                await environment.shell("printf isolated > adapter-e2e.txt"),
            )
        finally:
            environment.close()
            prepared.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        synthetic, hidden_git, write_result = executor.submit(
            lambda: asyncio.run(exercise())
        ).result(timeout=30)

    assert synthetic.get("exit_code") == 0
    assert str(synthetic.get("stdout", "")).startswith(SYNTHETIC_CREDENTIAL_PREFIX)
    assert real_secret not in str(synthetic)
    assert "parent-only" not in str(hidden_git.get("stdout", ""))
    assert "parent-only" not in str(hidden_git.get("stderr", ""))
    assert write_result.get("exit_code") == 0
    assert (worktree_path / "adapter-e2e.txt").read_text(encoding="utf-8") == "isolated"
    assert not prepared.secret_directory.exists()
    assert authority.launch_tokens == ["launch-token"]
    assert authority.secret_tokens == ["secret-token"]


@pytest.mark.skipif(sys.platform == "win32", reason="crash-safe staging uses POSIX locks")
def test_crash_reaper_skips_live_lease_then_removes_released_secret_material(
    tmp_path: Path,
) -> None:
    staging_root = tmp_path / "secret-staging"
    staging_root.mkdir(mode=0o700)
    directory, descriptor = isolation_adapter._create_secret_directory(
        staging_root,
        runner_id=uuid4(),
        run_id=uuid4(),
        grant_id=uuid4(),
    )
    material = directory / f"material-{'a' * 48}"
    material.write_text("crash-residual-secret", encoding="utf-8")
    material.chmod(0o600)

    try:
        assert reap_orphaned_secret_directories(staging_root) == 0
        assert directory.exists()
        assert material.exists()

        os.close(descriptor)
        descriptor = -1
        assert reap_orphaned_secret_directories(staging_root) == 1
        assert not directory.exists()
        assert not material.exists()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
