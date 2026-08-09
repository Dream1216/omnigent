"""Runner-side adapter from SaaS isolation grants to official sandbox primitives."""

from __future__ import annotations

import json
import os
import re
import secrets
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from hashlib import sha256
from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast
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
from saas.secret_broker_transport import SecretBrokerTransportError

_SECRET_DIRECTORY = re.compile(r"^sec-(?P<nonce>[0-9a-f]{48})$")
_CREATING_DIRECTORY = re.compile(r"^\.creating-(?P<nonce>[0-9a-f]{48})$")
_SECRET_MATERIAL = re.compile(r"^material-[0-9a-f]{48}$")
_SECRET_LEASE_FILE = ".omnigent-saas-secret-lease"
_SECRET_LEASE_KIND = "omnigent-saas-secret-staging"
_SECRET_LEASE_SCHEMA = 1


class LaunchGrantAuthority(Protocol):
    """Trusted launch-grant authority consumed by one Runner."""

    def redeem_launch_grant(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
    ) -> TrustedRunnerLaunchGrant: ...


class SecretRedemptionAuthority(Protocol):
    """Trusted Secret Broker authority, commonly backed by an mTLS client."""

    def redeem_secret(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
        provider: SecretValueProvider,
    ) -> SecretMaterial: ...


class IsolationAuthority(LaunchGrantAuthority, SecretRedemptionAuthority, Protocol):
    """Backward-compatible combined authority for in-process compositions."""


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


@lru_cache(maxsize=1)
def _fcntl() -> ModuleType:
    if os.name != "posix":
        raise RunnerIsolationAdapterError(
            "secret_staging_lock_unsupported",
            "crash-safe Secret staging requires POSIX advisory locks",
        )
    return import_module("fcntl")


def _open_lock(path: Path, *, create: bool) -> int:
    flags = os.O_RDWR | (os.O_CREAT | os.O_EXCL if create else 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags | nofollow, 0o600)
    try:
        _fcntl().flock(descriptor, _fcntl().LOCK_EX | _fcntl().LOCK_NB)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _lease_document(
    *,
    nonce: str,
    runner_id: UUID,
    run_id: UUID,
    grant_id: UUID,
) -> bytes:
    return json.dumps(
        {
            "schema": _SECRET_LEASE_SCHEMA,
            "kind": _SECRET_LEASE_KIND,
            "nonce": nonce,
            "runner_id": str(runner_id),
            "run_id": str(run_id),
            "grant_id": str(grant_id),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _read_lease_document(descriptor: int, *, nonce: str) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    encoded = os.read(descriptor, 4097)
    if len(encoded) > 4096:
        raise RunnerIsolationAdapterError(
            "secret_staging_lease_invalid", "Secret staging lease metadata is oversized"
        )
    try:
        document = json.loads(encoded)
        valid = (
            isinstance(document, dict)
            and document.get("schema") == _SECRET_LEASE_SCHEMA
            and document.get("kind") == _SECRET_LEASE_KIND
            and document.get("nonce") == nonce
            and all(
                isinstance(document.get(field), str)
                and str(UUID(document[field])) == document[field]
                for field in ("runner_id", "run_id", "grant_id")
            )
        )
    except (UnicodeDecodeError, ValueError, TypeError):
        valid = False
    if not valid:
        raise RunnerIsolationAdapterError(
            "secret_staging_lease_invalid", "Secret staging lease metadata is invalid"
        )


def _remove_locked_secret_directory(directory: Path, descriptor: int) -> None:
    try:
        if directory.exists():
            for child in directory.iterdir():
                if child.is_dir() and not child.is_symlink():
                    raise RunnerIsolationAdapterError(
                        "secret_staging_entry_invalid",
                        "Secret staging directory contains an unexpected nested directory",
                    )
                child.unlink(missing_ok=True)
            directory.rmdir()
    finally:
        with suppress(OSError):
            _fcntl().flock(descriptor, _fcntl().LOCK_UN)
        with suppress(OSError):
            os.close(descriptor)


def _create_secret_directory(
    root: Path,
    *,
    runner_id: UUID,
    run_id: UUID,
    grant_id: UUID,
) -> tuple[Path, int]:
    nonce = secrets.token_hex(24)
    creating = root / f".creating-{nonce}"
    directory = root / f"sec-{nonce}"
    creating.mkdir(mode=0o700)
    descriptor = -1
    try:
        descriptor = _open_lock(creating / _SECRET_LEASE_FILE, create=True)
        _write_all(
            descriptor,
            _lease_document(
                nonce=nonce,
                runner_id=runner_id,
                run_id=run_id,
                grant_id=grant_id,
            ),
        )
        os.fsync(descriptor)
        creating.rename(directory)
        return directory, descriptor
    except Exception:
        if descriptor >= 0:
            _remove_locked_secret_directory(creating, descriptor)
        elif creating.exists():
            with suppress(OSError):
                creating.rmdir()
        raise


def reap_orphaned_secret_directories(staging_root: Path | str) -> int:
    """Remove only validated Secret directories whose owner lock was released.

    The lease file is held with an exclusive advisory lock for the complete
    Prepared lifecycle. Process termination releases that kernel lock, so a new
    Runner process can distinguish crash residue from a live peer without PID
    probing or age guesses. Unknown/corrupt entries fail closed instead of being
    recursively deleted.
    """

    root = _private_root(staging_root)
    reaped = 0
    for directory in sorted(root.iterdir(), key=lambda path: path.name):
        match = _SECRET_DIRECTORY.fullmatch(directory.name) or _CREATING_DIRECTORY.fullmatch(
            directory.name
        )
        if match is None:
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise RunnerIsolationAdapterError(
                "secret_staging_entry_invalid", "Secret staging entry is not a real directory"
            )
        lease_path = directory / _SECRET_LEASE_FILE
        try:
            descriptor = _open_lock(lease_path, create=False)
        except BlockingIOError:
            continue
        except FileNotFoundError as exc:
            raise RunnerIsolationAdapterError(
                "secret_staging_lease_missing", "Secret staging directory has no lease metadata"
            ) from exc
        try:
            _read_lease_document(descriptor, nonce=match.group("nonce"))
            for child in directory.iterdir():
                if child.name == _SECRET_LEASE_FILE:
                    continue
                if (
                    not _SECRET_MATERIAL.fullmatch(child.name)
                    or child.is_symlink()
                    or not child.is_file()
                ):
                    raise RunnerIsolationAdapterError(
                        "secret_staging_entry_invalid",
                        "Secret staging directory contains an unexpected entry",
                    )
            _remove_locked_secret_directory(directory, descriptor)
            descriptor = -1
            reaped += 1
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    _fcntl().flock(descriptor, _fcntl().LOCK_UN)
                with suppress(OSError):
                    os.close(descriptor)
    return reaped


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


@lru_cache(maxsize=1)
def _official_runtime_read_paths() -> tuple[Path, ...]:
    """Return the package plus only validated linked official example assets.

    Editable installs keep ``omnigent/resources/examples/*`` as symlinks into
    the repository's ``examples`` directory. The bwrap backend correctly masks
    a symlink whose target is outside the mounted roots, so each such official
    asset target must be mounted explicitly. Targets outside the fixed official
    examples root fail closed instead of widening the sandbox to the checkout.
    """

    package_root = _official_package_root()
    checkout_root = package_root.parent
    examples_root = checkout_root / "examples"
    roots = {package_root}
    for candidate in package_root.rglob("*"):
        if not candidate.is_symlink():
            continue
        try:
            target = candidate.resolve(strict=True)
            allowed_root = examples_root.resolve(strict=True)
        except OSError as exc:
            raise RunnerIsolationAdapterError(
                "official_package_link_invalid",
                "official package contains an unresolved runtime asset link",
            ) from exc
        if not _is_relative_to(target, allowed_root):
            raise RunnerIsolationAdapterError(
                "official_package_link_unsafe",
                "official package runtime asset link escapes the allowed asset root",
            )
        roots.add(target)
    return tuple(sorted(roots, key=str))


@dataclass(slots=True)
class PreparedRunnerIsolation:
    """Prepared official spec whose lifetime-bound secret files are parent-only."""

    launch_grant: TrustedRunnerLaunchGrant
    os_env_spec: OSEnvSpec
    secret_directory: Path
    _lock_descriptor: int = field(repr=False)
    _fingerprint: str = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    async def start(self) -> OSEnvironment:
        """Fail loud and eagerly boot the helper before returning it to the Runner.

        Credential source files remain until :meth:`close` because the official
        environment may transparently restart a failed helper and must rebuild
        its parent-side credential proxy. They remain outside the Worktree in a
        0700 directory as 0600 files and are never mounted into the sandbox.
        """

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
        return environment

    def close(self) -> None:
        """Remove parent-only broker material; safe to call more than once."""

        if self._closed:
            return
        self._remove_secret_files()
        self._closed = True

    def _remove_secret_files(self) -> None:
        descriptor = self._lock_descriptor
        self._lock_descriptor = -1
        if descriptor >= 0:
            _remove_locked_secret_directory(self.secret_directory, descriptor)

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
        authority: LaunchGrantAuthority,
        secret_authority: SecretRedemptionAuthority | None = None,
        secret_provider: SecretValueProvider,
        containment: ContainmentVerifier,
    ) -> None:
        self._staging_root = _private_root(staging_root)
        reap_orphaned_secret_directories(self._staging_root)
        self._authority = authority
        if secret_authority is None:
            if not callable(getattr(authority, "redeem_secret", None)):
                raise ValueError("Runner isolation requires an explicit Secret Broker authority")
            secret_authority = cast(SecretRedemptionAuthority, authority)
        self._secret_authority = secret_authority
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
        secret_directory, lock_descriptor = _create_secret_directory(
            self._staging_root,
            runner_id=runner_id,
            run_id=run_id,
            grant_id=grant.grant_id,
        )
        entries: list[CredentialProxyEntry] = []
        try:
            for reference in grant.secret_leases:
                try:
                    material = self._secret_authority.redeem_secret(
                        token=reference.token,
                        runner_id=runner_id,
                        run_id=run_id,
                        provider=self._secret_provider,
                    )
                except (IsolationControlPlaneError, SecretBrokerTransportError) as exc:
                    raise RunnerIsolationAdapterError(exc.code, str(exc)) from exc
                if (
                    material.binding_id != reference.binding_id
                    or material.name != reference.name
                    or material.host != reference.host
                    or material.credential_scheme != reference.credential_scheme
                    or material.username != reference.username
                    or material.inject_env != reference.inject_env
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
                read_paths=[str(path) for path in _official_runtime_read_paths()],
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
                lock_descriptor,
                _spec_fingerprint(spec),
            )
        except Exception:
            _remove_locked_secret_directory(secret_directory, lock_descriptor)
            raise
