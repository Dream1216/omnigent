"""Runner-side adapter from SaaS isolation grants to official sandbox primitives."""

from __future__ import annotations

import json
import os
import secrets
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Protocol
from uuid import UUID

import omnigent
from omnigent.inner.datamodel import (
    CredentialProxyEntry,
    CredentialProxySpec,
    CredentialSourceSpec,
    OSEnvSandboxSpec,
    OSEnvSpec,
)
from omnigent.inner.os_env import OSEnvironment, create_os_environment
from saas.control_plane.isolation import (
    IsolationControlPlaneError,
    SandboxLaunchContract,
    SecretMaterial,
    SecretValueProvider,
    TrustedRunnerLaunchGrant,
)
from saas.runner_adapter.worktrees import PhysicalWorktree


class IsolationAuthority(Protocol):
    """Narrow trusted control-plane surface consumed by one Runner."""

    def redeem_launch_grant(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
    ) -> TrustedRunnerLaunchGrant: ...

    def redeem_secret(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
        provider: SecretValueProvider,
    ) -> SecretMaterial: ...


class ContainmentVerifier(Protocol):
    """Verify outer cgroup/container/microVM controls before sandbox launch."""

    def require_enforced(
        self,
        *,
        runner_id: UUID,
        contract: SandboxLaunchContract,
    ) -> None: ...


class RunnerIsolationAdapterError(RuntimeError):
    """Stable fail-closed Runner isolation error surface."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _private_root(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise RunnerIsolationAdapterError(
            "secret_staging_root_relative", "secret staging root must be absolute"
        )
    for component in (path, *path.parents):
        if component.exists() and component.is_symlink():
            raise RunnerIsolationAdapterError(
                "secret_staging_root_unsafe",
                "secret staging root must not contain symbolic-link components",
            )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = path.resolve(strict=True)
    mode = resolved.stat().st_mode & 0o777
    if (
        path.is_symlink()
        or not resolved.is_dir()
        or mode & 0o077
        or resolved.stat().st_uid != os.geteuid()
    ):
        raise RunnerIsolationAdapterError(
            "secret_staging_root_unsafe", "secret staging root must be a private real directory"
        )
    return resolved


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("secret staging write made no progress")
        remaining = remaining[written:]


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _spec_fingerprint(spec: OSEnvSpec) -> str:
    rendered = json.dumps(asdict(spec), sort_keys=True, separators=(",", ":"), default=str)
    return sha256(rendered.encode()).hexdigest()


def _official_package_root() -> Path:
    """Return only the trusted official package tree needed by the helper import."""

    module_file = omnigent.__file__
    if module_file is None:
        raise RunnerIsolationAdapterError(
            "official_package_root_missing", "official package root cannot be resolved"
        )
    package_root = Path(module_file).resolve(strict=True).parent
    if not package_root.is_dir() or package_root.is_symlink():
        raise RunnerIsolationAdapterError(
            "official_package_root_unsafe", "official package root must be a real directory"
        )
    return package_root


@dataclass(slots=True)
class PreparedRunnerIsolation:
    """Prepared official spec whose short-lived secret files are parent-only."""

    launch_grant: TrustedRunnerLaunchGrant
    os_env_spec: OSEnvSpec
    secret_directory: Path
    _fingerprint: str = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    async def start(self) -> OSEnvironment:
        """Fail loud, eagerly boot the helper, then remove broker material from disk."""

        if self._closed:
            raise RunnerIsolationAdapterError(
                "isolation_preparation_closed", "prepared isolation has already been closed"
            )
        if not secrets.compare_digest(self._fingerprint, _spec_fingerprint(self.os_env_spec)):
            self.close()
            raise RunnerIsolationAdapterError(
                "sandbox_contract_tampered", "sandbox specification changed after grant redemption"
            )
        environment = create_os_environment(self.os_env_spec)
        if environment is None:
            self.close()
            raise RunnerIsolationAdapterError(
                "sandbox_environment_missing", "official sandbox environment was not created"
            )
        try:
            result = await environment.shell("true", timeout=15, max_output=1024)
            if "error" in result or result.get("exit_code") not in {None, 0}:
                failure = result.get("error")
                detail = (
                    str(failure)[:512]
                    if failure is not None
                    else f"exit code {result.get('exit_code')}"
                )
                raise RunnerIsolationAdapterError(
                    "sandbox_bootstrap_failed",
                    f"official sandbox helper failed to start ({detail})",
                )
        except Exception:
            environment.close()
            self.close()
            raise
        self._remove_secret_files()
        return environment

    def close(self) -> None:
        """Remove parent-only broker material; safe to call more than once."""

        if self._closed:
            return
        self._remove_secret_files()
        self._closed = True

    def _remove_secret_files(self) -> None:
        if not self.secret_directory.exists():
            return
        for child in self.secret_directory.iterdir():
            if child.is_file() and not child.is_symlink():
                child.unlink(missing_ok=True)
        with suppress(OSError):
            self.secret_directory.rmdir()

    def __enter__(self) -> PreparedRunnerIsolation:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class RunnerIsolationAdapter:
    """Redeem fenced grants and produce a non-downgradable official OS sandbox spec."""

    def __init__(
        self,
        *,
        staging_root: Path | str,
        authority: IsolationAuthority,
        secret_provider: SecretValueProvider,
        containment: ContainmentVerifier,
    ) -> None:
        self._staging_root = _private_root(staging_root)
        self._authority = authority
        self._secret_provider = secret_provider
        self._containment = containment

    def prepare(
        self,
        *,
        grant_token: str,
        runner_id: UUID,
        run_id: UUID,
        physical_worktree: PhysicalWorktree,
    ) -> PreparedRunnerIsolation:
        """Prepare a server-selected spec; there is intentionally no client override input."""

        try:
            grant = self._authority.redeem_launch_grant(
                token=grant_token,
                runner_id=runner_id,
                run_id=run_id,
            )
        except IsolationControlPlaneError as exc:
            raise RunnerIsolationAdapterError(exc.code, str(exc)) from exc
        if (
            grant.runner_id != runner_id
            or grant.run_id != run_id
            or grant.worktree_id != physical_worktree.worktree_id
            or (grant.worktree_access_mode == "readonly") != physical_worktree.readonly
        ):
            raise RunnerIsolationAdapterError(
                "physical_worktree_grant_mismatch",
                "physical Worktree does not match the isolation grant",
            )
        worktree_path = physical_worktree.worktree_path.resolve(strict=True)
        if _is_relative_to(self._staging_root, worktree_path) or _is_relative_to(
            worktree_path, self._staging_root
        ):
            raise RunnerIsolationAdapterError(
                "secret_staging_worktree_overlap",
                "secret staging and Worktree roots must not overlap",
            )
        contract = grant.contract
        if (
            contract.backend not in {"linux_bwrap", "darwin_seatbelt"}
            or contract.network_mode != "proxy_only"
            or not contract.root_read_only
            or contract.run_as_uid <= 0
            or contract.run_as_gid <= 0
            or not contract.no_new_privileges
            or contract.host_socket_access
            or contract.allow_private_destinations
        ):
            raise RunnerIsolationAdapterError(
                "sandbox_contract_unsafe", "isolation grant contains an unsafe sandbox contract"
            )
        self._containment.require_enforced(runner_id=runner_id, contract=contract)
        secret_directory = self._staging_root / f"sec-{secrets.token_hex(24)}"
        secret_directory.mkdir(mode=0o700)
        entries: list[CredentialProxyEntry] = []
        try:
            for reference in grant.secret_leases:
                material = self._authority.redeem_secret(
                    token=reference.token,
                    runner_id=runner_id,
                    run_id=run_id,
                    provider=self._secret_provider,
                )
                if (
                    material.binding_id != reference.binding_id
                    or material.name != reference.name
                    or material.host != reference.host
                ):
                    raise RunnerIsolationAdapterError(
                        "secret_material_binding_mismatch",
                        "Secret Broker material does not match the launch grant",
                    )
                path = secret_directory / f"material-{secrets.token_hex(24)}"
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    _write_all(descriptor, material.value.encode())
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                entries.append(
                    CredentialProxyEntry(
                        host=material.host,
                        scheme=material.credential_scheme,  # type: ignore[arg-type]
                        source=CredentialSourceSpec(kind="file", path=str(path)),
                        username=material.username,
                        inject_env=list(material.inject_env),
                    )
                )
            sandbox = OSEnvSandboxSpec(
                type=contract.backend,
                read_paths=[str(_official_package_root())],
                write_paths=(
                    [str(worktree_path)] if grant.worktree_access_mode == "writer" else None
                ),
                write_files=None,
                allow_network=False,
                cwd_allow_hidden=[],
                cwd_hidden_scan_max_entries=100_000,
                cwd_hidden_scan_overflow="error",
                cwd_hidden_scan_recursive=True,
                mask_paths=[str(worktree_path / ".git")],
                env_passthrough=[],
                egress_rules=list(contract.egress_rules) or None,
                egress_allow_private_destinations=False,
                credential_proxy=(CredentialProxySpec(entries=entries) if entries else None),
            )
            if entries and not sandbox.egress_rules:
                raise RunnerIsolationAdapterError(
                    "secret_without_egress_policy",
                    "credential proxy requires a non-empty egress policy",
                )
            spec = OSEnvSpec(
                type="caller_process",
                cwd=str(worktree_path),
                sandbox=sandbox,
                fork=False,
                start_in_scratch=False,
            )
            return PreparedRunnerIsolation(
                grant,
                spec,
                secret_directory,
                _spec_fingerprint(spec),
            )
        except Exception:
            for child in secret_directory.iterdir():
                if child.is_file() and not child.is_symlink():
                    child.unlink(missing_ok=True)
            secret_directory.rmdir()
            raise
