from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from uuid import uuid4

import pytest

from saas.production import aliyun_workspace_recovery as recovery
from saas.production.aliyun_workspace_recovery import (
    AliyunWorkspaceRecovery,
    _digest,
    restore_workspace,
    validate_workspace_pax,
)
from saas.runner_adapter.worktree_restore import _xattr


def _archive(entries: list[tuple[str, bytes | str, bytes]]) -> io.BytesIO:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, kind, content in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            if kind == tarfile.REGTYPE:
                item.size = len(content)
            elif kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                item.linkname = content.decode()
            archive.addfile(item, io.BytesIO(content) if item.isfile() else None)
    data.seek(0)
    return data


def test_full_pax_keeps_ignored_private_git_and_unicode() -> None:
    validate_workspace_pax(
        _archive(
            [
                ("workspace", tarfile.DIRTYPE, b""),
                ("workspace/.git", tarfile.DIRTYPE, b""),
                ("workspace/.git/private-ref", tarfile.REGTYPE, b"private branch"),
                ("workspace/ignored.bin", tarfile.REGTYPE, b"\x00" * 65536),
                ("workspace/中文.txt", tarfile.LNKTYPE, b"workspace/ignored.bin"),
                ("workspace/symlink", tarfile.SYMTYPE, b"ignored.bin"),
            ]
        )
    )


@pytest.mark.parametrize(
    "entries",
    [
        [("workspace/../escape", tarfile.REGTYPE, b"data")],
        [("/workspace/escape", tarfile.REGTYPE, b"data")],
        [("workspace/inputs", tarfile.DIRTYPE, b"")],
        [("workspace/artifacts/file", tarfile.REGTYPE, b"data")],
        [("workspace/device", tarfile.CHRTYPE, b"")],
        [
            ("workspace/link", tarfile.SYMTYPE, b"/tmp"),
            ("workspace/link/file", tarfile.REGTYPE, b"data"),
        ],
        [("workspace/file", tarfile.REGTYPE, b"one"), ("workspace/file", tarfile.REGTYPE, b"two")],
        [("workspace/link", tarfile.LNKTYPE, b"workspace/missing")],
        [("workspace/link", tarfile.LNKTYPE, b"/etc/passwd")],
        [
            ("workspace/a", tarfile.LNKTYPE, b"workspace/b"),
            ("workspace/b", tarfile.LNKTYPE, b"workspace/a"),
        ],
    ],
)
def test_pax_rejects_escaping_redefined_or_unbacked_entries(entries) -> None:
    with pytest.raises(ValueError):
        validate_workspace_pax(_archive([("workspace", tarfile.DIRTYPE, b""), *entries]))


def test_descriptor_hash_and_owner_mode_are_mandatory(tmp_path: Path) -> None:
    path = tmp_path / "recovery.json"
    raw = json.dumps(
        {
            "schema_version": 1,
            "tenant_id": str(uuid4()),
            "space_id": str(uuid4()),
            "project_id": str(uuid4()),
            "workspace_id": 91,
            "session_id": str(uuid4()),
            "host_id": uuid4().hex,
            "source_sandbox_id": "sbx-source",
            "archive_relative_path": "recovery/workspace.pax",
            "archive_sha256": "a" * 64,
            "tree_sha256": "b" * 64,
        }
    ).encode()
    path.write_bytes(raw)
    path.chmod(0o400)
    source = AliyunWorkspaceRecovery(path, hashlib.sha256(raw).hexdigest())
    assert source.load()["archive_relative_path"] == "recovery/workspace.pax"
    with pytest.raises(ValueError):
        AliyunWorkspaceRecovery(path, "c" * 64).load()
    path.chmod(0o644)
    with pytest.raises(ValueError):
        source.load()


@pytest.mark.parametrize("compressed", [False, True])
def test_pax_metadata_is_bounded_before_header_allocation(
    monkeypatch: pytest.MonkeyPatch, compressed: bool
) -> None:
    data = io.BytesIO()
    with tarfile.open(
        fileobj=data, mode="w:gz" if compressed else "w", format=tarfile.PAX_FORMAT
    ) as archive:
        root = tarfile.TarInfo("workspace")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        item = tarfile.TarInfo("workspace/empty")
        item.pax_headers = {"SCHILY.xattr.user.large": "x" * 8192}
        archive.addfile(item)
    monkeypatch.setattr(recovery, "_MAX_PAX_HEADER_BYTES", 1024)
    data.seek(0)
    with pytest.raises((ValueError, tarfile.ReadError)):
        validate_workspace_pax(data)


def test_pax_cumulative_metadata_has_an_independent_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _archive(
        [("workspace", tarfile.DIRTYPE, b"")]
        + [(f"workspace/empty-{index}", tarfile.REGTYPE, b"") for index in range(8)]
    )
    monkeypatch.setattr(recovery, "_MAX_PAX_METADATA_BYTES", 2048)
    with pytest.raises(ValueError):
        validate_workspace_pax(data)


@pytest.mark.parametrize("mutate_source", [False, True])
def test_actual_full_pax_import_precedes_any_clone_and_preserves_oss_mounts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate_source: bool,
) -> None:
    source = tmp_path / "original/workspace"
    checkout = source / "repos/project"
    checkout.mkdir(parents=True)
    subprocess.run(["git", "init", str(checkout)], check=True, capture_output=True)
    (checkout / ".gitignore").write_text("ignored.bin\n")
    (checkout / "README.txt").write_text("original committed business data")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "-c",
            "user.name=Recovery test",
            "-c",
            "user.email=recovery@example.test",
            "commit",
            "-m",
            "Original user state",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "branch",
            "private-only",
        ],
        check=True,
        capture_output=True,
    )
    (checkout / "ignored.bin").write_bytes(b"\x00private" * 8192)
    (checkout / "中文.txt").write_text("retained user files")
    os.link(checkout / "ignored.bin", checkout / "hardlink")
    (checkout / "symlink").symlink_to("中文.txt")
    (source / "inputs").mkdir()
    (source / "artifacts").mkdir()
    digest = _digest(source)
    archive = tmp_path / "full.pax"
    subprocess.run(
        [
            "tar",
            "--format=pax",
            "--xattrs",
            "--acls",
            "--numeric-owner",
            "--exclude=workspace/inputs",
            "--exclude=workspace/artifacts",
            "-cpf",
            str(archive),
            "-C",
            str(source.parent),
            "workspace",
        ],
        check=True,
        capture_output=True,
        env={**os.environ, "COPYFILE_DISABLE": "1"},
    )
    assert _digest(source) == digest
    target = tmp_path / "fresh/workspace"
    (target / "inputs/recovery").mkdir(parents=True)
    (target / "artifacts").mkdir()
    (target / "artifacts/retained-OSS.txt").write_text("separate admitted volume")
    mount = "artifacts" if mutate_source else "inputs"
    (target / mount / "recovery").mkdir(exist_ok=True)
    shared_archive = target / mount / "recovery/full.pax"
    shutil.copyfile(archive, shared_archive)
    (target / "template-baseline.txt").write_text("fresh image only")
    _xattr("set", target, "user.template-extra", b"fresh image metadata")
    plan = {
        "session_id": str(uuid4()),
        "source_sandbox_id": "sbx-source",
        "target_sandbox_id": "sbx-fresh",
        "fresh": True,
        "archive_mount": mount,
        "archive_relative_path": "recovery/full.pax",
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "tree_sha256": digest,
        "repositories": ["repos/project"],
    }
    original_run = subprocess.run
    changed = False

    def extract_after_shared_source_changes(command, **options):
        nonlocal changed
        if mutate_source and "--extract" in command:
            shared_archive.write_bytes(b"changed after validation, before actual tar extraction")
            changed = True
        return original_run(command, **options)

    monkeypatch.setattr(recovery.subprocess, "run", extract_after_shared_source_changes)
    restore_workspace(plan, workspace=target)
    assert changed is mutate_source
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == plan["archive_sha256"]
    if mutate_source:
        assert shared_archive.read_bytes().startswith(b"changed after validation")
    assert _digest(target) == digest
    assert (target / "artifacts/retained-OSS.txt").read_text() == "separate admitted volume"
    assert (target / "repos/project/ignored.bin").stat().st_ino == (
        target / "repos/project/hardlink"
    ).stat().st_ino
    # Reinitializing a restored VM preserves later user edits instead of replaying old data.
    (target / "repos/project/中文.txt").write_text("newer work after first restore")
    restore_workspace({**plan, "fresh": False}, workspace=target)
    assert (target / "repos/project/中文.txt").read_text() == "newer work after first restore"
