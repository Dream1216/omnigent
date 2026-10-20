"""Private fixture material guards; not physical replacement-Pod acceptance."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from tests.saas.interactive_cold_restore import (
    find_cold_checkpoint,
    load_cold_checkpoint,
    write_cold_checkpoint,
)
from tests.saas.test_interactive_controller_factory_process import _private


def test_cold_fixture_reuses_identical_private_material_without_rewriting(tmp_path):
    path = tmp_path / "credential"
    assert _private(path, "owned material") == str(path)
    before = path.stat()
    assert _private(path, "owned material") == str(path)
    after = path.stat()
    assert (before.st_ino, before.st_mode, before.st_mtime_ns) == (
        after.st_ino,
        after.st_mode,
        after.st_mtime_ns,
    )
    assert path.read_text() == "owned material"


@pytest.mark.parametrize("drift", ["content", "permissions", "symlink"])
def test_cold_fixture_refuses_to_repair_or_replace_existing_material(tmp_path, drift):
    path = tmp_path / "credential"
    _private(path, "owned material")
    value = "replacement" if drift == "content" else "owned material"
    if drift == "permissions":
        path.chmod(0o600)
    elif drift == "symlink":
        original = tmp_path / "original"
        path.rename(original)
        path.symlink_to(original)
    before = path.lstat()
    with pytest.raises(ValueError, match="private fixture material"):
        _private(path, value)
    after = path.lstat()
    assert (before.st_ino, before.st_mode, before.st_mtime_ns) == (
        after.st_ino,
        after.st_mode,
        after.st_mtime_ns,
    )
    assert path.read_text() == "owned material"
    assert after.st_uid == os.getuid()


def test_checkpoint_reloads_in_a_fresh_process_without_inherited_objects(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    material = root / "original-key"
    _private(material, "original fixture identity")
    payload = {"original_run_id": "known-run", "must_not_reseed": True}
    write_cold_checkpoint(root, payload, [material])
    code = (
        "import json,sys; from pathlib import Path; "
        "from tests.saas.interactive_cold_restore import load_cold_checkpoint; "
        "print(json.dumps(load_cold_checkpoint(Path(sys.argv[1]))['payload']))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(root)], capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == payload
    assert load_cold_checkpoint(root)["payload"] == payload


@pytest.mark.parametrize("drift", ["content", "permissions", "symlink", "root_permissions"])
def test_cold_checkpoint_refuses_changed_material_without_repair(tmp_path, drift):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    material = root / "original-key"
    _private(material, "original fixture identity")
    write_cold_checkpoint(root, {"must_not_reseed": True}, [material])
    if drift == "content":
        material.chmod(0o600)
        material.write_text("changed fixture identity")
        material.chmod(0o400)
    elif drift == "permissions":
        material.chmod(0o600)
    elif drift == "symlink":
        original = root / "renamed-key"
        material.rename(original)
        material.symlink_to(original)
    else:
        root.chmod(0o750)
    before = (root.lstat(), material.lstat(), material.read_bytes())
    with pytest.raises(ValueError, match="cold fixture checkpoint"):
        load_cold_checkpoint(root)
    assert (root.lstat(), material.lstat(), material.read_bytes()) == before


@pytest.mark.parametrize("layout", ["single", "pytest_alias", "two_real_roots"])
def test_cold_discovery_ignores_alias_but_rejects_real_ambiguity(tmp_path, layout):
    base = tmp_path / "test-case"
    base.mkdir(mode=0o700)
    root = base / "case0"
    root.mkdir(mode=0o700)
    material = root / "original-key"
    _private(material, "original fixture identity")
    expected = write_cold_checkpoint(root, {"must_not_reseed": True}, [material])
    if layout == "pytest_alias":
        (base / "casecurrent").symlink_to(root, target_is_directory=True)
        assert len(list(base.glob("*/cold-restore.json"))) == 2
    elif layout == "two_real_roots":
        other = base / "case1"
        other.mkdir(mode=0o700)
        material = other / "different-key"
        _private(material, "different fixture identity")
        write_cold_checkpoint(other, {"must_not_reseed": True}, [material])
    if layout == "two_real_roots":
        with pytest.raises(ValueError, match="cold fixture checkpoint"):
            find_cold_checkpoint(base)
    else:
        assert find_cold_checkpoint(base) == expected
