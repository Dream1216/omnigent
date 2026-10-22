"""Fenced, path-opaque physical Git Worktree operations for SaaS Runners.

This module deliberately does not reuse the OSS host helper that accepts a
repository path from a caller. A SaaS Runner resolves a credential-free source
binding through local configuration, derives every physical path from the
control-plane opaque key, and reports only logical facts back to the control
plane.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID

from saas.control_plane import (
    WorktreeDeletionGrant,
    WorktreeLease,
    WorktreeMaterializationGrant,
    WorktreeMutation,
)

_OPAQUE_KEY = re.compile(r"^wti_[0-9a-f]{48}$")
_OPAQUE_BINDING = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_FULL_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ARTIFACT_REF = re.compile(r"^wta_sha256_([0-9a-f]{64})$")
_GIT_TIMEOUT_SECONDS = 120
_METADATA_VERSION = 1
_ARTIFACT_VERSION = 1


class RunnerWorktreeAdapterError(RuntimeError):
    """Stable fail-closed error raised before unsafe physical I/O."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class WorktreeLifecycleAuthority(Protocol):
    """Control-plane contract used by a local or remote Runner client."""

    def begin_materialization(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        trace_id: str,
    ) -> WorktreeMutation: ...

    def materialization_grant(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
    ) -> WorktreeMaterializationGrant: ...

    def acknowledge_ready(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        actual_bytes: int,
        trace_id: str,
    ) -> WorktreeMutation: ...

    def heartbeat(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        actual_bytes: int,
        dirty: bool,
        lease_duration: timedelta | None = None,
    ) -> WorktreeMutation: ...

    def checkpoint(
        self,
        *,
        worktree_id: UUID,
        runner_id: UUID,
        lease_generation: int,
        run_fence_token: int,
        lease_token: str,
        head_revision: str,
        recovery_artifact_ref: str,
        environment_snapshot_ref: str,
        dirty_after: bool,
        trace_id: str,
    ) -> WorktreeMutation: ...

    def deletion_grant(
        self,
        *,
        worktree_id: UUID,
        expected_lease_generation: int,
        opaque_runtime_key: str,
    ) -> WorktreeDeletionGrant: ...

    def confirm_deleted(
        self,
        *,
        worktree_id: UUID,
        expected_lease_generation: int,
        opaque_runtime_key: str,
        trace_id: str,
    ) -> WorktreeMutation: ...


class RepositoryMirrorResolver(Protocol):
    """Resolve one credential-free control-plane binding inside the Runner."""

    def resolve(self, source_binding_key: str) -> Path: ...


class RecoveryArtifactStore(Protocol):
    """Durable checkpoint interface; implementations may use object storage."""

    def put(self, artifact: CheckpointArtifact) -> str: ...

    def get(self, artifact_ref: str) -> CheckpointArtifact: ...


class BinaryArtifactStore(Protocol):
    """Minimal official ArtifactStore surface used by durable recovery."""

    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class CheckpointArtifact:
    repository_binding_digest: str
    base_revision: str
    head_revision: str
    bundle: bytes


@dataclass(frozen=True, slots=True)
class PhysicalWorktree:
    worktree_id: UUID
    worktree_path: Path
    head_revision: str
    actual_bytes: int
    readonly: bool


@dataclass(frozen=True, slots=True)
class PhysicalCheckpoint:
    worktree_id: UUID
    head_revision: str
    recovery_artifact_ref: str
    actual_bytes: int


class StaticRepositoryMirrorResolver:
    """Runner-local binding registry; keys and paths are never client supplied."""

    def __init__(self, bindings: Mapping[str, Path | str]) -> None:
        self._bindings = {key: Path(value) for key, value in bindings.items()}

    def resolve(self, source_binding_key: str) -> Path:
        try:
            return self._bindings[source_binding_key]
        except KeyError as exc:
            raise RunnerWorktreeAdapterError(
                "repository_binding_unknown", "Repository binding is not registered on Runner"
            ) from exc


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _validate_object_id(value: str, *, field: str) -> str:
    if not _FULL_OBJECT_ID.fullmatch(value):
        raise RunnerWorktreeAdapterError(
            f"{field}_invalid", f"{field} must be a full lowercase Git object ID"
        )
    return value


def _validate_binding_key(value: str) -> str:
    if (
        not _OPAQUE_BINDING.fullmatch(value)
        or ".." in value
        or "/" in value
        or "\\" in value
        or "://" in value
    ):
        raise RunnerWorktreeAdapterError(
            "repository_binding_invalid",
            "Repository binding must be opaque and credential-free",
        )
    return value


def _is_relative_to(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _private_root(path: Path | str, *, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise RunnerWorktreeAdapterError(f"{label}_invalid", f"{label} must be absolute")
    candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
    if candidate.is_symlink():
        raise RunnerWorktreeAdapterError(f"{label}_symlink", f"{label} must not be a symlink")
    resolved = candidate.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise RunnerWorktreeAdapterError(f"{label}_invalid", f"{label} must be a directory")
    effective_uid = getattr(os, "geteuid", lambda: info.st_uid)()
    if info.st_uid != effective_uid:
        raise RunnerWorktreeAdapterError(f"{label}_owner", f"{label} must be Runner-owned")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RunnerWorktreeAdapterError(
            f"{label}_permissions", f"{label} must not be accessible by group or other"
        )
    return resolved


def _ensure_distinct_roots(roots: Mapping[str, Path]) -> None:
    items = tuple(roots.items())
    for index, (left_name, left) in enumerate(items):
        for right_name, right in items[index + 1 :]:
            if _is_relative_to(left, right) or _is_relative_to(right, left):
                raise RunnerWorktreeAdapterError(
                    "runner_root_overlap",
                    f"Runner roots {left_name} and {right_name} must not overlap",
                )


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise RunnerWorktreeAdapterError(
            "runner_directory_symlink", "Runner-managed directory must not be a symlink"
        )
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RunnerWorktreeAdapterError(
            "runner_directory_permissions",
            "Runner-managed directory must remain private",
        )


def _atomic_write(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    _ensure_private_directory(path.parent)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_regular_private_file(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise RunnerWorktreeAdapterError(
            "runner_state_unsafe", "Runner state file is not private and regular"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class FilesystemRecoveryArtifactStore:
    """Content-addressed checkpoint store for a private persistent volume.

    Production may replace this with an object-store implementation of the same
    protocol. The reference contains only a digest; physical paths stay local.
    """

    def __init__(
        self,
        root: Path | str,
        *,
        maximum_bundle_bytes: int = 512 * 1024 * 1024,
    ) -> None:
        if maximum_bundle_bytes <= 0 or maximum_bundle_bytes > 8 * 1024 * 1024 * 1024:
            raise RunnerWorktreeAdapterError(
                "artifact_size_limit_invalid",
                "Checkpoint bundle limit must be between 1 byte and 8 GiB",
            )
        self._root = _private_root(root, label="recovery_artifact_root")
        self._maximum_bundle_bytes = maximum_bundle_bytes

    def put(self, artifact: CheckpointArtifact) -> str:
        _validate_object_id(artifact.base_revision, field="base_revision")
        _validate_object_id(artifact.head_revision, field="head_revision")
        if not re.fullmatch(r"[0-9a-f]{64}", artifact.repository_binding_digest):
            raise RunnerWorktreeAdapterError(
                "artifact_repository_digest_invalid",
                "Checkpoint Repository digest is invalid",
            )
        if len(artifact.bundle) > self._maximum_bundle_bytes:
            raise RunnerWorktreeAdapterError(
                "artifact_too_large", "Checkpoint bundle exceeds the configured size limit"
            )
        manifest = {
            "format_version": _ARTIFACT_VERSION,
            "repository_binding_digest": artifact.repository_binding_digest,
            "base_revision": artifact.base_revision,
            "head_revision": artifact.head_revision,
            "bundle_sha256": hashlib.sha256(artifact.bundle).hexdigest(),
        }
        manifest_bytes = _canonical_json(manifest)
        digest = hashlib.sha256(manifest_bytes + b"\0" + artifact.bundle).hexdigest()
        shard = self._root / digest[:2]
        _ensure_private_directory(shard)
        manifest_path = shard / f"{digest}.json"
        bundle_path = shard / f"{digest}.bundle"
        if manifest_path.exists() or bundle_path.exists():
            existing = self.get(f"wta_sha256_{digest}")
            if existing != artifact:
                raise RunnerWorktreeAdapterError(
                    "artifact_digest_collision", "Checkpoint digest content mismatch"
                )
            return f"wta_sha256_{digest}"
        _atomic_write(bundle_path, artifact.bundle)
        _atomic_write(manifest_path, manifest_bytes)
        return f"wta_sha256_{digest}"

    def get(self, artifact_ref: str) -> CheckpointArtifact:
        match = _ARTIFACT_REF.fullmatch(artifact_ref)
        if match is None:
            raise RunnerWorktreeAdapterError(
                "artifact_ref_invalid", "Checkpoint reference is not content-addressed"
            )
        digest = match.group(1)
        shard = self._root / digest[:2]
        manifest_path = shard / f"{digest}.json"
        bundle_path = shard / f"{digest}.bundle"
        try:
            if bundle_path.lstat().st_size > self._maximum_bundle_bytes:
                raise RunnerWorktreeAdapterError(
                    "artifact_too_large",
                    "Checkpoint bundle exceeds the configured size limit",
                )
            manifest_bytes = _read_regular_private_file(manifest_path)
            bundle = _read_regular_private_file(bundle_path)
        except FileNotFoundError as exc:
            raise RunnerWorktreeAdapterError(
                "artifact_unavailable", "Checkpoint artifact is unavailable"
            ) from exc
        try:
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerWorktreeAdapterError(
                "artifact_manifest_invalid", "Checkpoint manifest is invalid"
            ) from exc
        if not isinstance(manifest, dict) or manifest.get("format_version") != _ARTIFACT_VERSION:
            raise RunnerWorktreeAdapterError(
                "artifact_manifest_invalid", "Checkpoint manifest version is invalid"
            )
        canonical = _canonical_json(manifest)
        actual_digest = hashlib.sha256(canonical + b"\0" + bundle).hexdigest()
        if (
            actual_digest != digest
            or manifest.get("bundle_sha256") != hashlib.sha256(bundle).hexdigest()
        ):
            raise RunnerWorktreeAdapterError(
                "artifact_integrity_failed", "Checkpoint artifact integrity check failed"
            )
        repository_digest = manifest.get("repository_binding_digest")
        base_revision = manifest.get("base_revision")
        head_revision = manifest.get("head_revision")
        if not all(
            isinstance(item, str) for item in (repository_digest, base_revision, head_revision)
        ):
            raise RunnerWorktreeAdapterError(
                "artifact_manifest_invalid", "Checkpoint manifest fields are invalid"
            )
        assert isinstance(repository_digest, str)
        assert isinstance(base_revision, str)
        assert isinstance(head_revision, str)
        if not re.fullmatch(r"[0-9a-f]{64}", repository_digest):
            raise RunnerWorktreeAdapterError(
                "artifact_manifest_invalid", "Checkpoint Repository digest is invalid"
            )
        _validate_object_id(base_revision, field="artifact_base_revision")
        _validate_object_id(head_revision, field="artifact_head_revision")
        return CheckpointArtifact(repository_digest, base_revision, head_revision, bundle)


class ObjectRecoveryArtifactStore:
    """Content-addressed Worktree recovery over a durable binary object store."""

    def __init__(
        self,
        store: BinaryArtifactStore,
        *,
        maximum_bundle_bytes: int = 512 * 1024 * 1024,
    ) -> None:
        if maximum_bundle_bytes <= 0 or maximum_bundle_bytes > 8 * 1024 * 1024 * 1024:
            raise RunnerWorktreeAdapterError(
                "artifact_size_limit_invalid",
                "Checkpoint bundle limit must be between 1 byte and 8 GiB",
            )
        self._store = store
        self._maximum_bundle_bytes = maximum_bundle_bytes

    @staticmethod
    def _keys(digest: str) -> tuple[str, str]:
        prefix = f"worktree-recovery/v1/sha256/{digest[:2]}/{digest}"
        return f"{prefix}.json", f"{prefix}.bundle"

    def _put_exact(self, key: str, payload: bytes) -> None:
        if self._store.exists(key):
            if self._store.get(key) != payload:
                raise RunnerWorktreeAdapterError(
                    "artifact_digest_collision", "Checkpoint digest content mismatch"
                )
            return
        self._store.put(key, payload)
        if self._store.get(key) != payload:
            raise RunnerWorktreeAdapterError(
                "artifact_persistence_failed", "Checkpoint artifact persistence failed"
            )

    def put(self, artifact: CheckpointArtifact) -> str:
        _validate_object_id(artifact.base_revision, field="base_revision")
        _validate_object_id(artifact.head_revision, field="head_revision")
        if not re.fullmatch(r"[0-9a-f]{64}", artifact.repository_binding_digest):
            raise RunnerWorktreeAdapterError(
                "artifact_repository_digest_invalid",
                "Checkpoint Repository digest is invalid",
            )
        if len(artifact.bundle) > self._maximum_bundle_bytes:
            raise RunnerWorktreeAdapterError(
                "artifact_too_large", "Checkpoint bundle exceeds the configured size limit"
            )
        manifest = {
            "format_version": _ARTIFACT_VERSION,
            "repository_binding_digest": artifact.repository_binding_digest,
            "base_revision": artifact.base_revision,
            "head_revision": artifact.head_revision,
            "bundle_sha256": hashlib.sha256(artifact.bundle).hexdigest(),
        }
        manifest_bytes = _canonical_json(manifest)
        digest = hashlib.sha256(manifest_bytes + b"\0" + artifact.bundle).hexdigest()
        manifest_key, bundle_key = self._keys(digest)
        # Publish payload first and the validating manifest last.  Exact reads
        # after each write turn eventual/partial persistence into a fail-closed
        # error while allowing an identical interrupted upload to resume.
        self._put_exact(bundle_key, artifact.bundle)
        self._put_exact(manifest_key, manifest_bytes)
        return f"wta_sha256_{digest}"

    def get(self, artifact_ref: str) -> CheckpointArtifact:
        match = _ARTIFACT_REF.fullmatch(artifact_ref)
        if match is None:
            raise RunnerWorktreeAdapterError(
                "artifact_ref_invalid", "Checkpoint reference is not content-addressed"
            )
        digest = match.group(1)
        manifest_key, bundle_key = self._keys(digest)
        try:
            manifest_bytes = self._store.get(manifest_key)
            bundle = self._store.get(bundle_key)
        except KeyError as error:
            raise RunnerWorktreeAdapterError(
                "artifact_unavailable", "Checkpoint artifact is unavailable"
            ) from error
        if (
            not isinstance(manifest_bytes, bytes)
            or not isinstance(bundle, bytes)
            or len(manifest_bytes) > 65_536
            or len(bundle) > self._maximum_bundle_bytes
        ):
            raise RunnerWorktreeAdapterError(
                "artifact_too_large", "Checkpoint artifact exceeds its configured size limit"
            )
        try:
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RunnerWorktreeAdapterError(
                "artifact_manifest_invalid", "Checkpoint manifest is invalid"
            ) from error
        if (
            not isinstance(manifest, dict)
            or manifest.get("format_version") != _ARTIFACT_VERSION
            or _canonical_json(manifest) != manifest_bytes
            or hashlib.sha256(manifest_bytes + b"\0" + bundle).hexdigest() != digest
            or manifest.get("bundle_sha256") != hashlib.sha256(bundle).hexdigest()
        ):
            raise RunnerWorktreeAdapterError(
                "artifact_integrity_failed", "Checkpoint artifact integrity check failed"
            )
        repository_digest = manifest.get("repository_binding_digest")
        base_revision = manifest.get("base_revision")
        head_revision = manifest.get("head_revision")
        if not all(
            isinstance(item, str) for item in (repository_digest, base_revision, head_revision)
        ):
            raise RunnerWorktreeAdapterError(
                "artifact_manifest_invalid", "Checkpoint manifest fields are invalid"
            )
        assert isinstance(repository_digest, str)
        assert isinstance(base_revision, str)
        assert isinstance(head_revision, str)
        if not re.fullmatch(r"[0-9a-f]{64}", repository_digest):
            raise RunnerWorktreeAdapterError(
                "artifact_manifest_invalid", "Checkpoint Repository digest is invalid"
            )
        _validate_object_id(base_revision, field="artifact_base_revision")
        _validate_object_id(head_revision, field="artifact_head_revision")
        return CheckpointArtifact(repository_digest, base_revision, head_revision, bundle)


class RunnerWorktreeAdapter:
    """Materialize, checkpoint, rebuild, and delete one fenced physical checkout."""

    def __init__(
        self,
        *,
        managed_root: Path | str,
        mirror_root: Path | str,
        state_root: Path | str,
        authority: WorktreeLifecycleAuthority,
        mirrors: RepositoryMirrorResolver,
        recovery_artifacts: RecoveryArtifactStore,
        runner_id: UUID | None = None,
        git_timeout_seconds: int = _GIT_TIMEOUT_SECONDS,
    ) -> None:
        if git_timeout_seconds <= 0 or git_timeout_seconds > 900:
            raise RunnerWorktreeAdapterError(
                "git_timeout_invalid", "Git timeout must be between 1 and 900 seconds"
            )
        self._managed_root = _private_root(managed_root, label="managed_worktree_root")
        self._mirror_root = _private_root(mirror_root, label="repository_mirror_root")
        self._state_root = _private_root(state_root, label="runner_worktree_state_root")
        _ensure_distinct_roots(
            {
                "managed": self._managed_root,
                "mirrors": self._mirror_root,
                "state": self._state_root,
            }
        )
        self._authority = authority
        if runner_id is not None and runner_id.int == 0:
            raise RunnerWorktreeAdapterError(
                "runner_identity_invalid", "Runner identity must not be nil"
            )
        self._runner_id = runner_id
        self._mirrors = mirrors
        self._recovery_artifacts = recovery_artifacts
        self._git_timeout_seconds = git_timeout_seconds
        self._managed_device = self._managed_root.stat().st_dev

    def materialize(self, lease: WorktreeLease, *, trace_id: str) -> PhysicalWorktree:
        """Fence the lease, resolve trusted inputs, and create a detached checkout."""

        if self._runner_id is not None and lease.runner_id != self._runner_id:
            raise RunnerWorktreeAdapterError(
                "worktree_runner_mismatch", "Worktree lease belongs to another Runner"
            )

        self._authority.begin_materialization(
            worktree_id=lease.worktree_id,
            runner_id=lease.runner_id,
            lease_generation=lease.lease_generation,
            run_fence_token=lease.run_fence_token,
            lease_token=lease.lease_token,
            trace_id=trace_id,
        )
        grant = self._authority.materialization_grant(
            worktree_id=lease.worktree_id,
            runner_id=lease.runner_id,
            lease_generation=lease.lease_generation,
            run_fence_token=lease.run_fence_token,
            lease_token=lease.lease_token,
        )
        self._verify_lease_grant(lease, grant)
        target = self._target_path(grant.opaque_runtime_key)
        state_path = self._state_path(grant.opaque_runtime_key)
        with self._operation_lock(grant.opaque_runtime_key):
            mirror = self._resolve_mirror(grant.repository_source_binding_key)
            expected_head = self._expected_head(grant)
            identity = self._identity(grant)
            metadata: dict[str, object] | None = (
                self._load_state(state_path) if state_path.exists() else None
            )
            if metadata is not None and metadata.get("identity") != identity:
                raise RunnerWorktreeAdapterError(
                    "worktree_state_fence_mismatch",
                    "Runner state does not match the active Worktree fence",
                )
            if metadata is None:
                if target.exists() or target.is_symlink():
                    raise RunnerWorktreeAdapterError(
                        "worktree_path_collision",
                        "Derived Worktree path exists without matching Runner state",
                    )
                metadata = {
                    "format_version": _METADATA_VERSION,
                    "phase": "materializing",
                    "identity": identity,
                    "head_revision": None,
                    "recovery_artifact_ref": grant.recovery_artifact_ref,
                    "device": None,
                    "inode": None,
                    "actual_bytes": 0,
                    "physical_deleted": False,
                }
                self._store_state(state_path, metadata)
            self._ensure_checkout(mirror=mirror, target=target, grant=grant)
            target_info = target.lstat()
            metadata.update(
                {
                    "phase": "physical_created",
                    "device": target_info.st_dev,
                    "inode": target_info.st_ino,
                }
            )
            self._store_state(state_path, metadata)
            actual_head = self._head_revision(target)
            if actual_head != expected_head:
                raise RunnerWorktreeAdapterError(
                    "worktree_head_mismatch",
                    "Physical Worktree HEAD does not match the trusted recovery grant",
                )
            actual_bytes = self._inspect_tree(target, maximum_bytes=grant.reserved_bytes)
            if grant.access_mode == "readonly":
                self._make_readonly(target)
            else:
                target.chmod(0o700)
            metadata.update(
                {
                    "phase": "physical_ready",
                    "head_revision": actual_head,
                    "recovery_artifact_ref": grant.recovery_artifact_ref,
                    "device": target_info.st_dev,
                    "inode": target_info.st_ino,
                    "actual_bytes": actual_bytes,
                }
            )
            self._store_state(state_path, metadata)
            self._authority.acknowledge_ready(
                worktree_id=lease.worktree_id,
                runner_id=lease.runner_id,
                lease_generation=lease.lease_generation,
                run_fence_token=lease.run_fence_token,
                lease_token=lease.lease_token,
                actual_bytes=actual_bytes,
                trace_id=trace_id,
            )
            metadata["phase"] = "ready"
            self._store_state(state_path, metadata)
            return PhysicalWorktree(
                lease.worktree_id,
                target,
                actual_head,
                actual_bytes,
                grant.access_mode == "readonly",
            )

    def heartbeat(
        self,
        lease: WorktreeLease,
        *,
        lease_duration: timedelta,
        physical_worktree: PhysicalWorktree | None = None,
    ) -> WorktreeMutation:
        """Renew one exact physical checkout fence and refresh its measured usage."""

        if self._runner_id is not None and lease.runner_id != self._runner_id:
            raise RunnerWorktreeAdapterError(
                "worktree_runner_mismatch", "Worktree lease belongs to another Runner"
            )
        actual_bytes = 0
        dirty = False
        if physical_worktree is not None:
            if physical_worktree.worktree_id != lease.worktree_id:
                raise RunnerWorktreeAdapterError(
                    "worktree_state_fence_mismatch",
                    "Physical Worktree does not match the active lease",
                )
            target = self._target_path(lease.opaque_runtime_key)
            state_path = self._state_path(lease.opaque_runtime_key)
            with self._operation_lock(lease.opaque_runtime_key):
                metadata = self._load_state(state_path)
                self._verify_state_lease(metadata, lease)
                if metadata.get("phase") != "ready":
                    raise RunnerWorktreeAdapterError(
                        "worktree_not_ready", "Physical Worktree is not ready for heartbeat"
                    )
                identity = metadata.get("identity")
                if not isinstance(identity, dict):
                    raise RunnerWorktreeAdapterError(
                        "worktree_state_invalid", "Runner Worktree state is invalid"
                    )
                self._verify_target_identity(target, metadata)
                actual_bytes = self._inspect_tree(
                    target, maximum_bytes=int(identity["reserved_bytes"])
                )
                # A live writer is conservatively dirty.  This avoids racing
                # Git index locks with the command and prevents unchecked release.
                dirty = identity.get("access_mode") == "writer"
        mutation = self._authority.heartbeat(
            worktree_id=lease.worktree_id,
            runner_id=lease.runner_id,
            lease_generation=lease.lease_generation,
            run_fence_token=lease.run_fence_token,
            lease_token=lease.lease_token,
            actual_bytes=actual_bytes,
            dirty=dirty,
            lease_duration=lease_duration,
        )
        if (
            mutation.worktree_id != lease.worktree_id
            or mutation.lease_generation != lease.lease_generation
            or mutation.status not in {"reserved", "materializing", "ready", "checkpointing"}
            or mutation.lease_expires_at is None
        ):
            raise RunnerWorktreeAdapterError(
                "worktree_heartbeat_result_invalid",
                "Control-plane Worktree heartbeat result is invalid",
            )
        return mutation

    def renew_fence(
        self,
        lease: WorktreeLease,
        *,
        lease_duration: timedelta,
        physical_worktree: PhysicalWorktree | None,
    ) -> WorktreeMutation:
        """Renew an already-verified fence while checkpoint owns the local Git lock.

        Checkpointing intentionally serializes every local Git/state mutation under
        ``_operation_lock``.  A normal heartbeat would block behind a large bundle
        upload and could let the durable lease expire.  Once command execution has
        stopped, this narrow path may renew only the exact control-plane fence using
        the last verified size and a conservative dirty bit; checkpoint performs the
        next physical inspection before it can publish or release anything.
        """

        if self._runner_id is not None and lease.runner_id != self._runner_id:
            raise RunnerWorktreeAdapterError(
                "worktree_runner_mismatch", "Worktree lease belongs to another Runner"
            )
        if physical_worktree is not None and (
            physical_worktree.worktree_id != lease.worktree_id
            or physical_worktree.readonly != (lease.access_mode == "readonly")
        ):
            raise RunnerWorktreeAdapterError(
                "worktree_state_fence_mismatch",
                "Physical Worktree does not match the active lease",
            )
        mutation = self._authority.heartbeat(
            worktree_id=lease.worktree_id,
            runner_id=lease.runner_id,
            lease_generation=lease.lease_generation,
            run_fence_token=lease.run_fence_token,
            lease_token=lease.lease_token,
            actual_bytes=(0 if physical_worktree is None else physical_worktree.actual_bytes),
            dirty=physical_worktree is not None and lease.access_mode == "writer",
            lease_duration=lease_duration,
        )
        if (
            mutation.worktree_id != lease.worktree_id
            or mutation.lease_generation != lease.lease_generation
            or mutation.status not in {"reserved", "materializing", "ready", "checkpointing"}
            or mutation.lease_expires_at is None
        ):
            raise RunnerWorktreeAdapterError(
                "worktree_heartbeat_result_invalid",
                "Control-plane Worktree heartbeat result is invalid",
            )
        return mutation

    def checkpoint(
        self,
        lease: WorktreeLease,
        *,
        environment_snapshot_ref: str,
        trace_id: str,
    ) -> PhysicalCheckpoint:
        """Commit a writer snapshot and publish a content-addressed recovery bundle."""

        target = self._target_path(lease.opaque_runtime_key)
        state_path = self._state_path(lease.opaque_runtime_key)
        with self._operation_lock(lease.opaque_runtime_key):
            metadata = self._load_state(state_path)
            self._verify_state_lease(metadata, lease)
            if metadata.get("phase") != "ready":
                raise RunnerWorktreeAdapterError(
                    "worktree_not_ready", "Physical Worktree is not ready for checkpoint"
                )
            identity = metadata["identity"]
            if not isinstance(identity, dict) or identity.get("access_mode") != "writer":
                raise RunnerWorktreeAdapterError(
                    "worktree_readonly_write_denied", "Readonly Worktree cannot checkpoint"
                )
            base_revision = identity.get("base_revision")
            repository_digest = identity.get("repository_binding_digest")
            if not isinstance(base_revision, str) or not isinstance(repository_digest, str):
                raise RunnerWorktreeAdapterError(
                    "worktree_state_invalid", "Runner Worktree state is invalid"
                )
            self._verify_target_identity(target, metadata)
            actual_bytes = self._inspect_tree(
                target, maximum_bytes=int(identity["reserved_bytes"])
            )
            dirty = self._is_dirty(target)
            self._authority.heartbeat(
                worktree_id=lease.worktree_id,
                runner_id=lease.runner_id,
                lease_generation=lease.lease_generation,
                run_fence_token=lease.run_fence_token,
                lease_token=lease.lease_token,
                actual_bytes=actual_bytes,
                dirty=dirty,
            )
            if dirty:
                self._git(["add", "-A"], cwd=target)
                self._git(
                    [
                        "-c",
                        "user.name=Omnigent SaaS Runner",
                        "-c",
                        "user.email=runner@invalid",
                        "commit",
                        "--no-verify",
                        "--no-gpg-sign",
                        "-m",
                        f"checkpoint {lease.worktree_id}",
                    ],
                    cwd=target,
                )
            head_revision = self._head_revision(target)
            bundle = self._create_bundle(
                target=target,
                base_revision=base_revision,
                head_revision=head_revision,
                opaque_runtime_key=lease.opaque_runtime_key,
            )
            artifact_ref = self._recovery_artifacts.put(
                CheckpointArtifact(
                    repository_binding_digest=repository_digest,
                    base_revision=base_revision,
                    head_revision=head_revision,
                    bundle=bundle,
                )
            )
            actual_bytes = self._inspect_tree(
                target, maximum_bytes=int(identity["reserved_bytes"])
            )
            self._authority.checkpoint(
                worktree_id=lease.worktree_id,
                runner_id=lease.runner_id,
                lease_generation=lease.lease_generation,
                run_fence_token=lease.run_fence_token,
                lease_token=lease.lease_token,
                head_revision=head_revision,
                recovery_artifact_ref=artifact_ref,
                environment_snapshot_ref=environment_snapshot_ref,
                dirty_after=False,
                trace_id=trace_id,
            )
            metadata["head_revision"] = head_revision
            metadata["recovery_artifact_ref"] = artifact_ref
            metadata["actual_bytes"] = actual_bytes
            self._store_state(state_path, metadata)
            return PhysicalCheckpoint(
                lease.worktree_id,
                head_revision,
                artifact_ref,
                actual_bytes,
            )

    def delete(
        self,
        *,
        worktree_id: UUID,
        expected_lease_generation: int,
        opaque_runtime_key: str,
        trace_id: str,
    ) -> WorktreeMutation:
        """Delete only an exact GC grant and then persist deletion confirmation."""

        if not _OPAQUE_KEY.fullmatch(opaque_runtime_key):
            raise RunnerWorktreeAdapterError(
                "opaque_runtime_key_invalid", "Worktree runtime key is invalid"
            )
        grant = self._authority.deletion_grant(
            worktree_id=worktree_id,
            expected_lease_generation=expected_lease_generation,
            opaque_runtime_key=opaque_runtime_key,
        )
        if (
            grant.worktree_id != worktree_id
            or (self._runner_id is not None and grant.runner_id != self._runner_id)
            or grant.opaque_runtime_key != opaque_runtime_key
            or grant.lease_generation != expected_lease_generation
        ):
            raise RunnerWorktreeAdapterError(
                "worktree_delete_grant_mismatch", "Control-plane deletion grant is invalid"
            )
        target = self._target_path(opaque_runtime_key)
        state_path = self._state_path(opaque_runtime_key)
        with self._operation_lock(opaque_runtime_key):
            if not state_path.exists():
                if target.exists() or target.is_symlink():
                    raise RunnerWorktreeAdapterError(
                        "worktree_delete_state_missing",
                        "Physical Worktree exists without exact Runner deletion state",
                    )
                return self._authority.confirm_deleted(
                    worktree_id=worktree_id,
                    expected_lease_generation=expected_lease_generation,
                    opaque_runtime_key=opaque_runtime_key,
                    trace_id=trace_id,
                )
            metadata = self._load_state(state_path)
            identity = metadata.get("identity")
            if (
                not isinstance(identity, dict)
                or identity.get("worktree_id") != str(worktree_id)
                or identity.get("runner_id") != str(grant.runner_id)
                or identity.get("opaque_runtime_key_digest") != _digest_text(opaque_runtime_key)
                or identity.get("repository_binding_digest")
                != _digest_text(grant.repository_source_binding_key)
                or expected_lease_generation != int(identity.get("lease_generation", 0)) + 1
            ):
                raise RunnerWorktreeAdapterError(
                    "worktree_delete_state_mismatch",
                    "Runner state does not match the exact deletion fence",
                )
            mirror = self._resolve_mirror(grant.repository_source_binding_key)
            if target.exists() or target.is_symlink():
                if metadata.get("device") is None or metadata.get("inode") is None:
                    if metadata.get("phase") != "materializing":
                        raise RunnerWorktreeAdapterError(
                            "worktree_delete_state_mismatch",
                            "Runner deletion state lacks a physical identity",
                        )
                    if not target.is_dir() or target.is_symlink():
                        raise RunnerWorktreeAdapterError(
                            "worktree_path_unsafe",
                            "Partial physical Worktree path is unsafe",
                        )
                    partial_info = target.lstat()
                    if partial_info.st_dev != self._managed_device:
                        raise RunnerWorktreeAdapterError(
                            "worktree_mount_boundary",
                            "Partial Worktree crossed a filesystem device boundary",
                        )
                    metadata["device"] = partial_info.st_dev
                    metadata["inode"] = partial_info.st_ino
                    metadata["phase"] = "physical_created"
                    self._store_state(state_path, metadata)
                else:
                    self._verify_target_identity(target, metadata)
                self._inspect_tree(
                    target,
                    maximum_bytes=int(identity["reserved_bytes"]),
                    allow_external_symlinks=True,
                )
                self._make_writable(target)
                self._git(
                    ["worktree", "remove", "--force", str(target)],
                    git_dir=mirror,
                )
                if target.exists() or target.is_symlink():
                    raise RunnerWorktreeAdapterError(
                        "worktree_physical_delete_failed",
                        "Git reported success but the Worktree path still exists",
                    )
            metadata["phase"] = "physical_deleted"
            metadata["physical_deleted"] = True
            metadata["deletion_generation"] = expected_lease_generation
            self._store_state(state_path, metadata)
            mutation = self._authority.confirm_deleted(
                worktree_id=worktree_id,
                expected_lease_generation=expected_lease_generation,
                opaque_runtime_key=opaque_runtime_key,
                trace_id=trace_id,
            )
            state_path.unlink()
            return mutation

    def _verify_lease_grant(
        self, lease: WorktreeLease, grant: WorktreeMaterializationGrant
    ) -> None:
        if not _OPAQUE_KEY.fullmatch(grant.opaque_runtime_key):
            raise RunnerWorktreeAdapterError(
                "opaque_runtime_key_invalid", "Control-plane runtime key is invalid"
            )
        _validate_binding_key(grant.repository_source_binding_key)
        _validate_object_id(grant.base_revision, field="base_revision")
        if grant.head_revision is not None:
            _validate_object_id(grant.head_revision, field="head_revision")
        if (
            lease.worktree_id != grant.worktree_id
            or lease.change_set_id != grant.change_set_id
            or lease.run_id != grant.run_id
            or lease.runner_id != grant.runner_id
            or lease.opaque_runtime_key != grant.opaque_runtime_key
            or lease.access_mode != grant.access_mode
            or lease.lease_generation != grant.lease_generation
            or lease.run_fence_token != grant.run_fence_token
            or grant.access_mode not in {"writer", "readonly"}
            or grant.reserved_bytes <= 0
        ):
            raise RunnerWorktreeAdapterError(
                "worktree_grant_mismatch", "Materialization grant does not match the lease"
            )

    @staticmethod
    def _expected_head(grant: WorktreeMaterializationGrant) -> str:
        if grant.recovery_artifact_ref is None:
            if grant.head_revision is not None and grant.head_revision != grant.base_revision:
                raise RunnerWorktreeAdapterError(
                    "worktree_recovery_artifact_required",
                    "ChangeSet HEAD cannot be materialized without recovery material",
                )
            return grant.base_revision
        if grant.head_revision is None:
            raise RunnerWorktreeAdapterError(
                "worktree_recovery_head_missing",
                "Recovery material requires an authoritative ChangeSet HEAD",
            )
        return grant.head_revision

    def _identity(self, grant: WorktreeMaterializationGrant) -> dict[str, object]:
        return {
            "worktree_id": str(grant.worktree_id),
            "change_set_id": str(grant.change_set_id),
            "run_id": str(grant.run_id),
            "runner_id": str(grant.runner_id),
            "opaque_runtime_key_digest": _digest_text(grant.opaque_runtime_key),
            "access_mode": grant.access_mode,
            "lease_generation": grant.lease_generation,
            "run_fence_token": grant.run_fence_token,
            "runner_connection_generation": grant.runner_connection_generation,
            "reserved_bytes": grant.reserved_bytes,
            "repository_binding_digest": _digest_text(grant.repository_source_binding_key),
            "base_revision": grant.base_revision,
            "branch_ref_digest": _digest_text(grant.branch_ref),
        }

    def _verify_state_lease(self, metadata: dict[str, object], lease: WorktreeLease) -> None:
        identity = metadata.get("identity")
        if (
            not isinstance(identity, dict)
            or identity.get("worktree_id") != str(lease.worktree_id)
            or identity.get("change_set_id") != str(lease.change_set_id)
            or identity.get("run_id") != str(lease.run_id)
            or identity.get("runner_id") != str(lease.runner_id)
            or identity.get("opaque_runtime_key_digest") != _digest_text(lease.opaque_runtime_key)
            or identity.get("access_mode") != lease.access_mode
            or identity.get("lease_generation") != lease.lease_generation
            or identity.get("run_fence_token") != lease.run_fence_token
        ):
            raise RunnerWorktreeAdapterError(
                "worktree_state_fence_mismatch",
                "Runner state does not match the active Worktree lease",
            )

    def _target_path(self, opaque_runtime_key: str) -> Path:
        if not _OPAQUE_KEY.fullmatch(opaque_runtime_key):
            raise RunnerWorktreeAdapterError(
                "opaque_runtime_key_invalid", "Worktree runtime key is invalid"
            )
        digest = _digest_text(opaque_runtime_key)
        shard = self._managed_root / digest[:2]
        _ensure_private_directory(shard)
        target = shard / digest
        if not _is_relative_to(target, self._managed_root):
            raise RunnerWorktreeAdapterError(
                "worktree_path_escape", "Derived Worktree path escaped the managed root"
            )
        return target

    def _state_path(self, opaque_runtime_key: str) -> Path:
        digest = _digest_text(opaque_runtime_key)
        shard = self._state_root / digest[:2]
        _ensure_private_directory(shard)
        return shard / f"{digest}.json"

    def _lock_path(self, opaque_runtime_key: str) -> Path:
        digest = _digest_text(opaque_runtime_key)
        shard = self._state_root / "locks" / digest[:2]
        _ensure_private_directory(shard)
        return shard / f"{digest}.lock"

    @contextlib.contextmanager
    def _operation_lock(self, opaque_runtime_key: str) -> Iterator[None]:
        lock_path = self._lock_path(opaque_runtime_key)
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _load_state(path: Path) -> dict[str, object]:
        try:
            value = json.loads(_read_regular_private_file(path))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerWorktreeAdapterError(
                "worktree_state_invalid", "Runner Worktree state is invalid"
            ) from exc
        if not isinstance(value, dict) or value.get("format_version") != _METADATA_VERSION:
            raise RunnerWorktreeAdapterError(
                "worktree_state_invalid", "Runner Worktree state version is invalid"
            )
        return value

    @staticmethod
    def _store_state(path: Path, metadata: dict[str, object]) -> None:
        _atomic_write(path, _canonical_json(metadata))

    def _resolve_mirror(self, source_binding_key: str) -> Path:
        _validate_binding_key(source_binding_key)
        candidate = self._mirrors.resolve(source_binding_key)
        if not candidate.is_absolute() or candidate.is_symlink():
            raise RunnerWorktreeAdapterError(
                "repository_mirror_invalid", "Repository mirror must be an absolute directory"
            )
        try:
            mirror = candidate.resolve(strict=True)
        except OSError as exc:
            raise RunnerWorktreeAdapterError(
                "repository_mirror_missing", "Repository mirror is unavailable"
            ) from exc
        if not _is_relative_to(mirror, self._mirror_root):
            raise RunnerWorktreeAdapterError(
                "repository_mirror_escape", "Repository mirror escaped the Runner mirror root"
            )
        info = mirror.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise RunnerWorktreeAdapterError(
                "repository_mirror_permissions",
                "Repository mirror must not be group/other writable",
            )
        bare = self._git(["rev-parse", "--is-bare-repository"], git_dir=mirror)
        if bare.stdout.strip() != "true":
            raise RunnerWorktreeAdapterError(
                "repository_mirror_not_bare", "Repository source must be a bare mirror"
            )
        self._validate_mirror_config(mirror)
        return mirror

    def _validate_mirror_config(self, mirror: Path) -> None:
        result = self._git(
            ["config", "--local", "--name-only", "--null", "--list"],
            git_dir=mirror,
        )
        keys = tuple(key.lower() for key in result.stdout.split("\0") if key)
        denied_prefixes = (
            "alias.",
            "browser.",
            "credential.",
            "diff.",
            "difftool.",
            "filter.",
            "gpg.",
            "gui.",
            "help.",
            "http.",
            "include.",
            "includeif.",
            "instaweb.",
            "merge.",
            "mergetool.",
            "pager.",
            "protocol.",
            "sendemail.",
            "sequence.",
            "submodule.",
            "tar.",
            "url.",
            "web.",
        )
        denied_exact = {
            "commit.gpgsign",
            "core.askpass",
            "core.attributesfile",
            "core.editor",
            "core.excludesfile",
            "core.fsmonitor",
            "core.gitproxy",
            "core.hookspath",
            "core.pager",
            "core.sshcommand",
            "core.worktree",
            "interactive.difffilter",
            "tag.gpgsign",
        }
        denied_remote_suffixes = (".proxy", ".receivepack", ".uploadpack")
        unsafe = sorted(
            key
            for key in keys
            if key.startswith(denied_prefixes)
            or key in denied_exact
            or (key.startswith("remote.") and key.endswith(denied_remote_suffixes))
        )
        if unsafe:
            raise RunnerWorktreeAdapterError(
                "repository_mirror_config_unsafe",
                f"Repository mirror has executable Git config: {unsafe}",
            )
        urls = self._git(
            ["config", "--local", "--null", "--get-regexp", r"^remote\..*\.url$"],
            git_dir=mirror,
            allowed_returncodes={0, 1},
        )
        for record in urls.stdout.split("\0"):
            if not record:
                continue
            _, _, value = record.partition("\n")
            parsed = urlsplit(value)
            if parsed.password is not None or (parsed.username and parsed.scheme not in {"ssh"}):
                raise RunnerWorktreeAdapterError(
                    "repository_mirror_credentials_exposed",
                    "Repository mirror config must not contain embedded credentials",
                )

    def _ensure_checkout(
        self,
        *,
        mirror: Path,
        target: Path,
        grant: WorktreeMaterializationGrant,
    ) -> None:
        base_revision = _validate_object_id(grant.base_revision, field="base_revision")
        self._git(
            ["cat-file", "-e", f"{base_revision}^{{commit}}"],
            git_dir=mirror,
        )
        if not target.exists():
            self._git(
                ["worktree", "add", "--detach", str(target), base_revision],
                git_dir=mirror,
            )
        if not target.is_dir() or target.is_symlink():
            raise RunnerWorktreeAdapterError(
                "worktree_path_unsafe", "Physical Worktree is not a regular directory"
            )
        current = self._head_revision(target)
        if grant.recovery_artifact_ref is None:
            if current != base_revision:
                raise RunnerWorktreeAdapterError(
                    "worktree_partial_materialization",
                    "Existing partial Worktree does not match its base revision",
                )
            return
        expected_head = self._expected_head(grant)
        if current == expected_head:
            return
        if current != base_revision:
            raise RunnerWorktreeAdapterError(
                "worktree_partial_materialization",
                "Existing partial Worktree is neither base nor recovery HEAD",
            )
        artifact = self._recovery_artifacts.get(grant.recovery_artifact_ref)
        if (
            artifact.repository_binding_digest != _digest_text(grant.repository_source_binding_key)
            or artifact.base_revision != base_revision
            or artifact.head_revision != expected_head
        ):
            raise RunnerWorktreeAdapterError(
                "worktree_recovery_mismatch",
                "Checkpoint artifact does not match the Worktree grant",
            )
        if not artifact.bundle:
            if expected_head != base_revision:
                raise RunnerWorktreeAdapterError(
                    "worktree_recovery_bundle_missing",
                    "Non-base recovery HEAD requires a Git bundle",
                )
            return
        bundle_path = self._temporary_bundle(grant.opaque_runtime_key, artifact.bundle)
        try:
            self._git(["bundle", "verify", str(bundle_path)], cwd=target)
            self._git(
                ["fetch", "--no-tags", str(bundle_path), expected_head],
                cwd=target,
            )
            self._git(["reset", "--hard", expected_head], cwd=target)
        finally:
            bundle_path.unlink(missing_ok=True)

    def _temporary_bundle(self, opaque_runtime_key: str, payload: bytes) -> Path:
        digest = _digest_text(opaque_runtime_key)
        directory = self._state_root / "tmp" / digest[:2]
        _ensure_private_directory(directory)
        path = directory / f"{digest}.{secrets.token_hex(8)}.bundle"
        _atomic_write(path, payload)
        return path

    def _create_bundle(
        self,
        *,
        target: Path,
        base_revision: str,
        head_revision: str,
        opaque_runtime_key: str,
    ) -> bytes:
        if head_revision == base_revision:
            return b""
        path = self._temporary_bundle(opaque_runtime_key, b"")
        path.unlink()
        try:
            self._git(
                ["bundle", "create", str(path), "HEAD", f"^{base_revision}"],
                cwd=target,
            )
            path.chmod(0o600)
            return _read_regular_private_file(path)
        finally:
            path.unlink(missing_ok=True)

    def _head_revision(self, target: Path) -> str:
        value = self._git(["rev-parse", "--verify", "HEAD"], cwd=target).stdout.strip()
        return _validate_object_id(value, field="head_revision")

    def _is_dirty(self, target: Path) -> bool:
        return bool(self._git(["status", "--porcelain=v1", "-z"], cwd=target).stdout)

    def _verify_target_identity(self, target: Path, metadata: dict[str, object]) -> None:
        if not target.is_dir() or target.is_symlink():
            raise RunnerWorktreeAdapterError(
                "worktree_path_unsafe", "Physical Worktree path is missing or replaced"
            )
        info = target.lstat()
        if info.st_dev != metadata.get("device") or info.st_ino != metadata.get("inode"):
            raise RunnerWorktreeAdapterError(
                "worktree_inode_mismatch",
                "Physical Worktree inode or device changed after materialization",
            )

    def _inspect_tree(
        self,
        target: Path,
        *,
        maximum_bytes: int,
        allow_external_symlinks: bool = False,
    ) -> int:
        self._assert_no_nested_mounts(target)
        total = 0
        for current, directories, files in os.walk(target, topdown=True, followlinks=False):
            current_path = Path(current)
            current_info = current_path.lstat()
            if current_info.st_dev != self._managed_device:
                raise RunnerWorktreeAdapterError(
                    "worktree_mount_boundary", "Worktree crossed a filesystem device boundary"
                )
            for name in [*directories, *files]:
                item = current_path / name
                info = item.lstat()
                if info.st_dev != self._managed_device:
                    raise RunnerWorktreeAdapterError(
                        "worktree_mount_boundary",
                        "Worktree entry crossed a filesystem device boundary",
                    )
                if stat.S_ISLNK(info.st_mode):
                    if allow_external_symlinks:
                        total += info.st_size
                        continue
                    try:
                        resolved = item.resolve(strict=True)
                    except OSError as exc:
                        raise RunnerWorktreeAdapterError(
                            "worktree_symlink_invalid",
                            "Worktree contains a broken or cyclic symlink",
                        ) from exc
                    if not _is_relative_to(resolved, target):
                        raise RunnerWorktreeAdapterError(
                            "worktree_symlink_escape",
                            "Worktree symlink resolves outside its managed checkout",
                        )
                    total += info.st_size
                elif stat.S_ISREG(info.st_mode):
                    blocks = getattr(info, "st_blocks", 0) * 512
                    total += max(info.st_size, blocks)
                if total > maximum_bytes:
                    raise RunnerWorktreeAdapterError(
                        "worktree_reservation_exceeded",
                        "Physical checkout exceeds its control-plane reservation",
                    )
        return total

    @staticmethod
    def _assert_no_nested_mounts(target: Path) -> None:
        target_resolved = target.resolve(strict=True)
        mountinfo = Path("/proc/self/mountinfo")
        if mountinfo.exists():
            try:
                lines = mountinfo.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                raise RunnerWorktreeAdapterError(
                    "mount_table_unavailable", "Runner cannot verify mount boundaries"
                ) from exc
            for line in lines:
                fields = line.split()
                if len(fields) < 5:
                    continue
                mount_path = Path(fields[4].replace("\\040", " "))
                if mount_path != target_resolved and _is_relative_to(mount_path, target_resolved):
                    raise RunnerWorktreeAdapterError(
                        "worktree_nested_mount",
                        "Worktree contains an unexpected nested mount",
                    )
        for current, directories, _ in os.walk(target_resolved, followlinks=False):
            for name in directories:
                candidate = Path(current) / name
                if candidate.is_symlink():
                    continue
                if os.path.ismount(candidate):
                    raise RunnerWorktreeAdapterError(
                        "worktree_nested_mount",
                        "Worktree contains an unexpected nested mount",
                    )

    @staticmethod
    def _make_readonly(target: Path) -> None:
        for current, directories, files in os.walk(target, topdown=False, followlinks=False):
            current_path = Path(current)
            for name in files:
                item = current_path / name
                info = item.lstat()
                if stat.S_ISLNK(info.st_mode):
                    continue
                mode = 0o500 if info.st_mode & 0o111 else 0o400
                item.chmod(mode)
            for name in directories:
                item = current_path / name
                if not item.is_symlink():
                    item.chmod(0o500)
            current_path.chmod(0o500)

    @staticmethod
    def _make_writable(target: Path) -> None:
        for current, directories, files in os.walk(target, topdown=True, followlinks=False):
            current_path = Path(current)
            current_path.chmod(0o700)
            for name in directories:
                item = current_path / name
                if not item.is_symlink():
                    item.chmod(0o700)
            for name in files:
                item = current_path / name
                info = item.lstat()
                if stat.S_ISLNK(info.st_mode):
                    continue
                item.chmod(0o700 if info.st_mode & 0o111 else 0o600)

    def _git(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        git_dir: Path | None = None,
        allowed_returncodes: set[int] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "protocol.file.allow=always",
        ]
        if git_dir is not None:
            command.extend(["--git-dir", str(git_dir)])
        command.extend(args)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": os.devnull,
                "SSH_ASKPASS": os.devnull,
                "LC_ALL": "C",
            }
        )
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                env=environment,
                capture_output=True,
                text=True,
                timeout=self._git_timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RunnerWorktreeAdapterError("git_unavailable", "Git is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise RunnerWorktreeAdapterError(
                "git_timeout", "Git operation exceeded the Runner timeout"
            ) from exc
        accepted = allowed_returncodes or {0}
        if result.returncode not in accepted:
            detail = result.stderr.strip()[-2048:]
            for root in (self._managed_root, self._mirror_root, self._state_root):
                detail = detail.replace(str(root), "<runner-root>")
            detail = re.sub(r"://[^/@\s]+@", "://<redacted>@", detail)
            suffix = f": {detail}" if detail else ""
            raise RunnerWorktreeAdapterError(
                "git_operation_failed",
                f"Git operation failed with exit {result.returncode}{suffix}",
            )
        return result
