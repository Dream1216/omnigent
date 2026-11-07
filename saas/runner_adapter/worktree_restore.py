"""Consume an operator-delivered full user checkout before native readiness.

The backup owner decrypts and independently verifies the original archive, then
delivers only its user checkout under ``delivery_path`` and seals it with the
original native checkpoint grant. Runner state, locks and leases stay outside
this tree. A seal is a local delivery receipt, never an execution authorization.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from saas.control_plane import WorktreeMaterializationGrant
from saas.runner_adapter.worktrees import (
    RunnerWorktreeAdapterError,
    _atomic_write,
    _canonical_json,
    _digest_text,
    _private_root,
    _read_regular_private_file,
)


def _require(condition: bool) -> None:
    if not condition:
        raise RunnerWorktreeAdapterError(
            "worktree_full_restore_invalid", "Full checkout delivery is unavailable or changed"
        )


def _stable(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def _xattr(operation: str, path: int | Path, name: str = "", value: bytes = b"") -> bytes:
    # CPython exposes these calls only on Linux. Use the same native FD calls
    # on Darwin so local Git lifecycle verification retains extended metadata.
    _require(sys.platform in {"linux", "darwin"})
    descriptor = isinstance(path, int)
    prefix = "f" if descriptor else ("l" if sys.platform == "linux" else "")
    function = getattr(ctypes.CDLL(None, use_errno=True), prefix + operation + "xattr")
    function.restype = ctypes.c_ssize_t
    location = ctypes.c_int(path) if descriptor else ctypes.c_char_p(os.fsencode(path))
    arguments = [location]
    if operation != "list":
        arguments.append(ctypes.c_char_p(os.fsencode(name)))
    suffix: list[ctypes.c_int | ctypes.c_uint32] = []
    if sys.platform == "darwin":
        if operation != "list":
            suffix.append(ctypes.c_uint32(0))
        suffix.append(ctypes.c_int(0 if descriptor else 1))
    elif operation == "set":
        suffix.append(ctypes.c_int(0))
    if operation == "set":
        _require(
            function(*arguments, ctypes.c_char_p(value), ctypes.c_size_t(len(value)), *suffix) == 0
        )
        return b""
    size = function(*arguments, None, ctypes.c_size_t(0), *suffix)
    _require(0 <= size <= 1024 * 1024)
    buffer = ctypes.create_string_buffer(size + 1)
    count = function(*arguments, buffer, ctypes.c_size_t(size), *suffix)
    _require(count == size)
    return buffer.raw[:size]


def _attributes(path: int | Path) -> dict[str, str]:
    names = [os.fsdecode(name) for name in _xattr("list", path).split(b"\0") if name]
    return {name: _xattr("get", path, name).hex() for name in sorted(names)}


def _open_directory(path: Path | str, *, parent: int | None = None) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)


def _tree_digest(root: Path, *, check_active: Callable[[], None], maximum_bytes: int) -> str:
    """Compare every entry, including ignored files, private Git and hardlinks."""
    rows: list[dict[str, object]] = []
    links: dict[tuple[int, int], str] = {}
    total = 0
    device = root.lstat().st_dev

    def walk(directory: int, relative: str) -> None:
        nonlocal total
        before = os.fstat(directory)
        _require(before.st_dev == device)
        names = sorted(os.listdir(directory), key=os.fsencode)
        for name in names:
            check_active()
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            _require(info.st_dev == device)
            path = root / relative / name
            member = str(Path(relative) / name)
            row: dict[str, object] = {
                "path": member,
                "mode": info.st_mode,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mtime_ns": info.st_mtime_ns,
            }
            if stat.S_ISDIR(info.st_mode):
                child = _open_directory(name, parent=directory)
                try:
                    _require(_stable(os.fstat(child)) == _stable(info))
                    row["xattrs"] = _attributes(child)
                    walk(child, member)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                child = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                )
                try:
                    _require(_stable(os.fstat(child)) == _stable(info))
                    digest = hashlib.sha256()
                    count = 0
                    while block := os.read(child, 1024 * 1024):
                        check_active()
                        count += len(block)
                        total += len(block)
                        _require(total <= maximum_bytes)
                        digest.update(block)
                    _require(count == info.st_size and _stable(os.fstat(child)) == _stable(info))
                    row.update(bytes=count, sha256=digest.hexdigest(), xattrs=_attributes(child))
                    row["hardlink"] = links.setdefault((info.st_dev, info.st_ino), member)
                finally:
                    os.close(child)
            elif stat.S_ISLNK(info.st_mode):
                row.update(target=os.readlink(name, dir_fd=directory), xattrs=_attributes(path))
            else:
                _require(False)
            rows.append(row)
            _require(
                _stable(os.stat(name, dir_fd=directory, follow_symlinks=False)) == _stable(info)
            )
        _require(names == sorted(os.listdir(directory), key=os.fsencode))
        _require(_stable(before) == _stable(os.fstat(directory)))

    descriptor = _open_directory(root)
    try:
        info = os.fstat(descriptor)
        rows.append(
            {
                "path": ".",
                "mode": info.st_mode,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mtime_ns": info.st_mtime_ns,
                "xattrs": _attributes(descriptor),
            }
        )
        walk(descriptor, "")
    finally:
        os.close(descriptor)
    return hashlib.sha256(_canonical_json(rows)).hexdigest()


def _copy_tree(
    source: Path, target: Path, *, check_active: Callable[[], None], maximum_bytes: int
) -> None:
    links: dict[tuple[int, int], Path] = {}
    total = 0
    device = source.lstat().st_dev

    def metadata(source_fd: int | Path, destination: int | Path, info: os.stat_result) -> None:
        if isinstance(destination, int):
            current = os.fstat(destination)
            if (current.st_uid, current.st_gid) != (info.st_uid, info.st_gid):
                os.fchown(destination, info.st_uid, info.st_gid)
            for key, value in _attributes(source_fd).items():
                _xattr("set", destination, key, bytes.fromhex(value))
            os.fchmod(destination, stat.S_IMODE(info.st_mode))
            os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns))
        else:
            current = destination.lstat()
            if (current.st_uid, current.st_gid) != (info.st_uid, info.st_gid):
                os.chown(destination, info.st_uid, info.st_gid, follow_symlinks=False)
            for key, value in _attributes(source_fd).items():
                _xattr("set", destination, key, bytes.fromhex(value))
            os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns), follow_symlinks=False)

    def walk(source_fd: int, destination_fd: int, relative: Path) -> None:
        nonlocal total
        initial = os.fstat(source_fd)
        _require(initial.st_dev == device)
        for name in sorted(os.listdir(source_fd), key=os.fsencode):
            check_active()
            info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            _require(info.st_dev == device)
            output = target / relative / name
            if stat.S_ISDIR(info.st_mode):
                os.mkdir(name, mode=0o700, dir_fd=destination_fd)
                with contextlib.ExitStack() as descriptors:
                    child = _open_directory(name, parent=source_fd)
                    descriptors.callback(os.close, child)
                    new_child = _open_directory(name, parent=destination_fd)
                    descriptors.callback(os.close, new_child)
                    _require(_stable(os.fstat(child)) == _stable(info))
                    walk(child, new_child, relative / name)
            elif stat.S_ISREG(info.st_mode):
                key = (info.st_dev, info.st_ino)
                if key in links:
                    os.link(links[key], output, follow_symlinks=False)
                else:
                    with contextlib.ExitStack() as descriptors:
                        child = os.open(
                            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd
                        )
                        descriptors.callback(os.close, child)
                        new_child = os.open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600,
                            dir_fd=destination_fd,
                        )
                        descriptors.callback(os.close, new_child)
                        _require(_stable(os.fstat(child)) == _stable(info))
                        while block := os.read(child, 1024 * 1024):
                            check_active()
                            total += len(block)
                            _require(total <= maximum_bytes)
                            view = memoryview(block)
                            while view:
                                view = view[os.write(new_child, view) :]
                        metadata(child, new_child, info)
                        os.fsync(new_child)
                        _require(_stable(os.fstat(child)) == _stable(info))
                    links[key] = output
            elif stat.S_ISLNK(info.st_mode):
                os.symlink(os.readlink(name, dir_fd=source_fd), name, dir_fd=destination_fd)
                metadata(source / relative / name, output, info)
            else:
                _require(False)
            _require(
                _stable(os.stat(name, dir_fd=source_fd, follow_symlinks=False)) == _stable(info)
            )
        metadata(source_fd, destination_fd, initial)
        os.fsync(destination_fd)
        _require(_stable(os.fstat(source_fd)) == _stable(initial))

    target.mkdir(mode=0o700)
    source_fd = _open_directory(source)
    target_fd = _open_directory(target)
    try:
        walk(source_fd, target_fd, Path())
    finally:
        os.close(source_fd)
        os.close(target_fd)


class PreparedWorktreeRestores:
    """Owner-only local delivery consumer, wired into production materialization."""

    def __init__(self, root: Path) -> None:
        self.root = _private_root(root, label="worktree_restore_root")

    def delivery_path(self, snapshot_ref: str) -> Path:
        _require(isinstance(snapshot_ref, str) and 0 < len(snapshot_ref) <= 1024)
        directory = _private_root(
            self.root / _digest_text(snapshot_ref), label="worktree_restore_delivery"
        )
        return directory / "checkout"

    @staticmethod
    def _binding(grant: WorktreeMaterializationGrant) -> dict[str, object]:
        _require(
            grant.environment_snapshot_ref is not None and grant.recovery_artifact_ref is not None
        )
        return {
            "change_set_id": str(grant.change_set_id),
            "snapshot_ref": grant.environment_snapshot_ref,
            "recovery_artifact_ref": grant.recovery_artifact_ref,
            "repository_binding_digest": _digest_text(grant.repository_source_binding_key),
            "base_revision": grant.base_revision,
            "head_revision": grant.head_revision,
        }

    def seal(self, checkpoint_grant: WorktreeMaterializationGrant) -> str:
        """Seal a quiesced, independently verified delivery using its actual old grant.

        Capture that grant through the original native authority after checkpoint
        and before releasing its lease. No old Runner identity is transplanted.
        """
        binding = self._binding(checkpoint_grant)
        assert checkpoint_grant.environment_snapshot_ref is not None
        tree = self.delivery_path(checkpoint_grant.environment_snapshot_ref)
        _require(tree.exists() and not tree.is_symlink())
        _private_root(tree, label="worktree_restore_checkout")
        digest = _tree_digest(
            tree, check_active=lambda: None, maximum_bytes=checkpoint_grant.reserved_bytes
        )
        payload = _canonical_json({"binding": binding, "tree_sha256": digest})
        receipt = tree.parent / "receipt.json"
        if receipt.exists():
            _require(_read_regular_private_file(receipt) == payload)
        else:
            _atomic_write(receipt, payload)
        return digest

    def prepare(self, checkpoint_grant: WorktreeMaterializationGrant, source: Path) -> str:
        """Stage the owner's verified, quiesced user tree; retain its native ref."""
        self._binding(checkpoint_grant)
        assert checkpoint_grant.environment_snapshot_ref is not None
        target = self.delivery_path(checkpoint_grant.environment_snapshot_ref)
        _require(not target.exists() and not target.is_symlink())
        digest = _tree_digest(
            source, check_active=lambda: None, maximum_bytes=checkpoint_grant.reserved_bytes
        )
        with tempfile.TemporaryDirectory(prefix=".delivery-", dir=target.parent) as temporary:
            staged = Path(temporary) / "checkout"
            _copy_tree(
                source,
                staged,
                check_active=lambda: None,
                maximum_bytes=checkpoint_grant.reserved_bytes,
            )
            _require(
                _tree_digest(
                    staged,
                    check_active=lambda: None,
                    maximum_bytes=checkpoint_grant.reserved_bytes,
                )
                == digest
            )
            _require(
                _tree_digest(
                    source,
                    check_active=lambda: None,
                    maximum_bytes=checkpoint_grant.reserved_bytes,
                )
                == digest
            )
            os.replace(staged, target)
        _require(self.seal(checkpoint_grant) == digest)
        return digest

    def restore(
        self,
        grant: WorktreeMaterializationGrant,
        target: Path,
        *,
        check_active: Callable[[], None],
        validate: Callable[[Path], None],
    ) -> str:
        """Validate every byte before replacing the fresh, never-started checkout."""
        binding = self._binding(grant)
        assert grant.environment_snapshot_ref is not None
        source = self.delivery_path(grant.environment_snapshot_ref)
        try:
            _require(source.exists() and not source.is_symlink())
            _private_root(source, label="worktree_restore_checkout")
            receipt = json.loads(_read_regular_private_file(source.parent / "receipt.json"))
            _require(isinstance(receipt, dict) and receipt.get("binding") == binding)
            expected = receipt.get("tree_sha256")
            _require(isinstance(expected, str) and len(expected) == 64)
            check_active()
            _require(
                _tree_digest(source, check_active=check_active, maximum_bytes=grant.reserved_bytes)
                == expected
            )
            with tempfile.TemporaryDirectory(prefix=".restore-", dir=target.parent) as temporary:
                staged = Path(temporary) / "checkout"
                _copy_tree(
                    source, staged, check_active=check_active, maximum_bytes=grant.reserved_bytes
                )
                _require(
                    _tree_digest(
                        staged, check_active=check_active, maximum_bytes=grant.reserved_bytes
                    )
                    == expected
                )
                _require(
                    _tree_digest(
                        source, check_active=check_active, maximum_bytes=grant.reserved_bytes
                    )
                    == expected
                )
                validate(staged)
                check_active()
                # Only the fresh native baseline is moved aside. User recovery
                # data stays in its immutable delivery; native state stays put.
                previous = Path(temporary) / "baseline"
                os.replace(target, previous)
                try:
                    os.replace(staged, target)
                except BaseException:
                    os.replace(previous, target)
                    raise
                parent = _open_directory(target.parent)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            return expected
        except (OSError, ValueError, TypeError):
            raise RunnerWorktreeAdapterError(
                "worktree_full_restore_invalid", "Full checkout delivery is unavailable or changed"
            ) from None
