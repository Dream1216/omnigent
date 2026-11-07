"""Restore an operator-pinned original Session workspace before Host bootstrap.

The existing Session/storage authority selects the identity. The recovery input
is an owner-only, hash-pinned backup descriptor, never a browser/Agent argument.
The two independently admitted OSS mounts retain their existing identities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, cast
from uuid import UUID

from saas.compatibility.runtime_partition import RuntimeContext
from saas.production.aliyun_storage import AliyunOssSession
from saas.production.tenant_model_keys import _read_file
from saas.runner_adapter.worktree_restore import _attributes, _tree_digest, _xattr

WORKSPACE = Path("/home/user/workspace")
_MOUNTS = frozenset({"inputs", "artifacts"})
_MAX_BYTES = 8 * 1024**3
_MAX_ARCHIVE_BYTES = 9 * 1024**3
_MAX_PAX_HEADER_BYTES = 1024**2
_MAX_PAX_METADATA_BYTES = 64 * 1024**2
_SHA = re.compile(r"[0-9a-f]{64}")
_FIELDS = {
    "schema_version",
    "tenant_id",
    "space_id",
    "project_id",
    "workspace_id",
    "session_id",
    "host_id",
    "source_sandbox_id",
    "archive_relative_path",
    "archive_sha256",
    "tree_sha256",
}


def _require(ok: bool) -> None:
    if not ok:
        raise ValueError("Original Session workspace recovery is unavailable")


@dataclass(frozen=True)
class AliyunWorkspaceRecovery:
    descriptor_file: Path
    descriptor_sha256: str

    def load(self) -> dict[str, object]:
        raw = _read_file(self.descriptor_file, private=True, maximum=16384)
        _require(_SHA.fullmatch(self.descriptor_sha256) is not None)
        _require(hashlib.sha256(raw).hexdigest() == self.descriptor_sha256)
        value = json.loads(raw)
        _require(isinstance(value, dict) and set(value) in (_FIELDS, _FIELDS | {"archive_mount"}))
        _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
        for key in ("tenant_id", "space_id", "project_id", "session_id", "host_id"):
            if key == "project_id" and value[key] is None:
                continue
            _require(isinstance(value[key], str))
            identifier = UUID(value[key])
            _require(identifier.int > 0 and value[key] in (str(identifier), identifier.hex))
            value[key] = identifier.hex if key == "host_id" else str(identifier)
        _require(type(value["workspace_id"]) is int and value["workspace_id"] > 0)
        _require(
            isinstance(value["source_sandbox_id"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value["source_sandbox_id"])
            is not None
        )
        for key in ("archive_sha256", "tree_sha256"):
            _require(isinstance(value[key], str) and _SHA.fullmatch(value[key]) is not None)
        relative = value["archive_relative_path"]
        _require(isinstance(relative, str))
        path = PurePosixPath(relative)
        _require(bool(path.parts) and not path.is_absolute() and ".." not in path.parts)
        _require(str(path) == relative and "\x00" not in relative)
        mount = value.get("archive_mount", "inputs")
        _require(isinstance(mount, str) and mount in _MOUNTS)
        return value

    def for_session(
        self,
        runtime: RuntimeContext,
        storage: AliyunOssSession,
        *,
        host_id: str,
        sandbox_id: str,
        fresh: bool,
        repositories: list[str],
    ) -> dict[str, object] | None:
        value = self.load()
        if value["session_id"] != str(storage.session_id):
            return None
        expected = {
            "tenant_id": str(runtime.tenant_id),
            "space_id": str(runtime.space_id),
            "project_id": str(runtime.project_id) if runtime.project_id is not None else None,
            "workspace_id": runtime.physical_workspace_id,
            "host_id": host_id,
        }
        _require(all(value[key] == item for key, item in expected.items()))
        _require(all(volume.project_id == runtime.project_id for volume in storage.volumes))
        _require(isinstance(value["source_sandbox_id"], str))
        return {
            **value,
            "target_sandbox_id": sandbox_id,
            "fresh": fresh,
            "repositories": repositories,
            "storage_bindings": storage.metadata,
        }


class _PaxMetadataReader:
    """Bound reads before tarfile allocates extended-header/metadata buffers."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.read_bytes = 0

    def read(self, size: int = -1) -> bytes:
        _require(0 <= size <= min(_MAX_BYTES, _MAX_PAX_HEADER_BYTES))
        _require(self.read_bytes + size <= min(_MAX_BYTES, _MAX_PAX_METADATA_BYTES))
        data = self.stream.read(size)
        self.read_bytes += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        position = self.stream.seek(offset, whence)
        _require(0 <= position <= _MAX_ARCHIVE_BYTES)
        return position

    def tell(self) -> int:
        return self.stream.tell()


def validate_workspace_pax(stream: BinaryIO) -> None:
    """Reuse the original full-user PAX path/link rules before any extraction."""
    kinds: dict[str, str] = {}
    links: dict[str, str] = {}
    total = 0

    def member_path(name: str) -> str:
        path = PurePosixPath(name)
        _require(bool(path.parts) and not path.is_absolute() and ".." not in path.parts)
        _require(path.parts[0] == "workspace" and "\x00" not in name)
        _require(str(path) == name.rstrip("/") and len(os.fsencode(name)) <= 4096)
        _require(len(path.parts) < 2 or path.parts[1] not in _MOUNTS)
        return str(path)

    # Native capture is uncompressed PAX. Refuse compression before expansion;
    # each header read and the cumulative metadata budget are checked first.
    bounded = cast(BinaryIO, _PaxMetadataReader(stream))
    with tarfile.open(fileobj=bounded, mode="r:") as archive:
        for item in archive:
            name = member_path(item.name)
            _require(name not in kinds and len(kinds) < 200000)
            _require(item.isdir() or item.isfile() or item.islnk() or item.issym())
            _require(0 <= item.size <= _MAX_BYTES)
            total += item.size
            _require(total <= _MAX_BYTES)
            kinds[name] = "directory" if item.isdir() else "file" if item.isfile() else "link"
            if item.islnk():
                links[name] = member_path(item.linkname)
            if item.issym():
                _require("\x00" not in item.linkname)
            members: list[tarfile.TarInfo] = vars(archive)["members"]
            members.clear()
    _require(kinds.get("workspace") == "directory")
    for name in kinds:
        for parent in PurePosixPath(name).parents:
            if str(parent) != ".":
                _require(kinds.get(str(parent)) == "directory")
    for name, target in links.items():
        seen = {name}
        while target in links:
            _require(target not in seen)
            seen.add(target)
            target = links[target]
        _require(kinds.get(target) == "file")


@contextmanager
def _private_archive(descriptor: int, *, directory: Path, expected: object) -> Iterator[int]:
    """Snapshot shared storage before validating or executing its archive bytes."""
    with tempfile.TemporaryFile(dir=directory) as snapshot:
        total = 0
        digest = hashlib.sha256()
        with os.fdopen(os.dup(descriptor), "rb") as source:
            while chunk := source.read(1024**2):
                total += len(chunk)
                _require(total <= _MAX_ARCHIVE_BYTES)
                digest.update(chunk)
                snapshot.write(chunk)
        _require(total > 0 and digest.hexdigest() == expected)
        snapshot.flush()
        snapshot.seek(0)
        validate_workspace_pax(snapshot)
        snapshot.seek(0)
        yield snapshot.fileno()


def _digest(root: Path) -> str:
    return _tree_digest(
        root, check_active=lambda: None, maximum_bytes=_MAX_BYTES, excluded_root_names=_MOUNTS
    )


def _root_metadata(root: Path, metadata: os.stat_result, attributes: dict[str, str]) -> None:
    current = root.stat()
    _require(current.st_uid == metadata.st_uid and current.st_gid == metadata.st_gid)
    for name in _attributes(root).keys() - attributes.keys():
        _xattr("remove", root, name)
    for name, value in attributes.items():
        _xattr("set", root, name, bytes.fromhex(value))
    os.chmod(root, stat.S_IMODE(metadata.st_mode))
    os.utime(root, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))


def _repositories(root: Path, names: list[str]) -> None:
    for name in names:
        relative = PurePosixPath(name)
        _require(not relative.is_absolute() and ".." not in relative.parts)
        target = root
        for part in relative.parts:
            target = target / part
            _require(target.is_dir() and not target.is_symlink())
        _require((target / ".git").is_dir() and not (target / ".git").is_symlink())


def restore_workspace(
    plan: dict[str, object], *, workspace: Path = WORKSPACE, tar: str = "tar"
) -> None:
    """Import only a fresh VM; never roll a live resumed workspace backwards."""
    _require(workspace.is_dir() and not workspace.is_symlink())
    for name in _MOUNTS:
        _require((workspace / name).is_dir() and not (workspace / name).is_symlink())
    _require(str(UUID(str(plan["session_id"]))) == plan["session_id"])
    relative = PurePosixPath(str(plan["archive_relative_path"]))
    _require(bool(relative.parts) and not relative.is_absolute() and ".." not in relative.parts)
    raw_repositories = plan["repositories"]
    if not isinstance(raw_repositories, list) or not all(
        isinstance(value, str) for value in raw_repositories
    ):
        raise ValueError("Original Session repositories are unavailable")
    repositories = [str(value) for value in raw_repositories]
    if plan["target_sandbox_id"] == plan["source_sandbox_id"]:
        _repositories(workspace, repositories)
        return
    identity = hashlib.sha256(
        json.dumps({k: v for k, v in plan.items() if k != "fresh"}, sort_keys=True).encode()
    ).hexdigest()
    private = workspace.parent / ".omnigent/runtime/workspace-recovery"
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (workspace.parent / ".omnigent", private.parent, private):
        info = directory.lstat()
        _require(
            stat.S_ISDIR(info.st_mode)
            and not directory.is_symlink()
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o022
        )
        directory.chmod(0o700)
    receipt = private / (str(plan["session_id"]) + ".json")
    if receipt.exists() or receipt.is_symlink():
        saved = json.loads(_read_file(receipt, private=True, maximum=16384))
        _require(saved == {"identity": identity, "tree_sha256": plan["tree_sha256"]})
        _repositories(workspace, repositories)
        return
    _require(plan["fresh"] is True)
    mount = plan.get("archive_mount", "inputs")
    _require(isinstance(mount, str) and mount in _MOUNTS)
    current = os.open(workspace / str(mount), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = -1
    try:
        parts = PurePosixPath(str(plan["archive_relative_path"])).parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= _MAX_ARCHIVE_BYTES)
        with (
            _private_archive(
                descriptor, directory=private, expected=plan["archive_sha256"]
            ) as archive_descriptor,
            tempfile.TemporaryDirectory(prefix=".workspace-import-", dir=workspace.parent) as temp,
        ):
            stage = Path(temp)
            subprocess.run(
                [
                    tar,
                    "--extract",
                    "--file",
                    f"/dev/fd/{archive_descriptor}",
                    "--directory",
                    str(stage),
                    "--xattrs",
                    "--acls",
                    "--numeric-owner",
                    "--same-permissions",
                ],
                pass_fds=(archive_descriptor,),
                check=True,
                capture_output=True,
            )
            restored = stage / "workspace"
            _require(_digest(restored) == plan["tree_sha256"])
            _repositories(restored, repositories)
            metadata = restored.stat()
            attributes = _attributes(restored)
            os.lseek(archive_descriptor, 0, os.SEEK_SET)
            with os.fdopen(os.dup(archive_descriptor), "rb") as stream:
                _require(
                    hashlib.file_digest(stream, "sha256").hexdigest() == plan["archive_sha256"]
                )
            previous = stage / "previous"
            previous.mkdir()
            original_metadata = workspace.stat()
            original_attributes = _attributes(workspace)
            moved: list[str] = []
            installed: list[str] = []
            try:
                for child in workspace.iterdir():
                    if child.name not in _MOUNTS:
                        os.replace(child, previous / child.name)
                        moved.append(child.name)
                for child in restored.iterdir():
                    os.replace(child, workspace / child.name)
                    installed.append(child.name)
                _root_metadata(workspace, metadata, attributes)
                _require(_digest(workspace) == plan["tree_sha256"])
            except BaseException:
                for name in installed:
                    os.replace(workspace / name, restored / name)
                for name in moved:
                    os.replace(previous / name, workspace / name)
                _root_metadata(workspace, original_metadata, original_attributes)
                raise
        with tempfile.NamedTemporaryFile(dir=private) as temporary:
            os.fchmod(temporary.fileno(), 0o400)
            temporary.write(
                json.dumps({"identity": identity, "tree_sha256": plan["tree_sha256"]}).encode()
            )
            temporary.flush()
            os.fsync(temporary.fileno())
            # Exclusive publication refuses an existing or dangling symlink.
            os.link(temporary.name, receipt)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(current)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("descriptor", type=Path)
    args = parser.parse_args()
    plan = json.loads(_read_file(args.descriptor, private=True, maximum=16384))
    restore_workspace(plan)


if __name__ == "__main__":
    main()
