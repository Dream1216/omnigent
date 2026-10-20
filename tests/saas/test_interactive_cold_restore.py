"""Private fixture material guards; not physical replacement-Pod acceptance."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID

import pytest

from tests.saas.interactive_cold_restore import (
    find_cold_checkpoint,
    load_cold_checkpoint,
    write_cold_checkpoint,
)
from tests.saas.test_interactive_controller_factory_process import _private


@pytest.fixture
def active_checkpoint(tmp_path, monkeypatch):
    from tests.saas import interactive_cold_restore as cold

    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    spool = root / "pending"
    spool.mkdir(mode=0o700)
    _private(spool / "original.pending.json", "unconfirmed reference")
    run_id = UUID(int=1)
    bearer = "isolated-fixture-material"
    _private(root / "crash-state.json", json.dumps({"run_id": str(run_id), "old_bearer": bearer}))
    record = SimpleNamespace(
        run_id=run_id,
        phase="dispatching",
        process_stopped=False,
        outcome=None,
        managed_resources=object(),
        managed_creation=SimpleNamespace(pod_uid=str(UUID(int=2))),
        grant=SimpleNamespace(spool_directory=spool),
    )
    values = {
        "root": root,
        "bootstrap": {},
        "source": {},
        "record": record,
        "old_bearer": bearer,
        "cluster": {
            "managed_cold_restore": True,
            "managed_cold_active": True,
            "provider": "agent_sandbox",
            "scenario": "controller_crash_recovery",
        },
    }
    monkeypatch.setattr(cold, "_checkpoint_fixture", lambda **kwargs: kwargs)
    return cold.checkpoint_active_fixture, values


def test_active_checkpoint_preserves_unknown_reference_without_inventing_stop(active_checkpoint):
    checkpoint, values = active_checkpoint
    result = checkpoint(**values)
    assert result["details"]["checkpoint_kind"] == "active"
    assert result["evidence"] == {
        "original_phase": "dispatching",
        "original_pending_references": 1,
    }
    assert result["extra_paths"] == [values["root"] / "crash-state.json"]
    assert "old_physical_stop_sha256" not in result["details"]


@pytest.mark.parametrize("drift", ["phase", "process_stopped", "outcome", "resources", "pod"])
def test_active_checkpoint_rejects_wrong_lifecycle(active_checkpoint, drift):
    checkpoint, values = active_checkpoint
    record = values["record"]
    if drift == "phase":
        record.phase = "terminal"
    elif drift == "process_stopped":
        record.process_stopped = True
    elif drift == "outcome":
        record.outcome = "orphaned"
    elif drift == "resources":
        record.managed_resources = None
    else:
        record.managed_creation.pod_uid = None
    with pytest.raises(ValueError, match="active cold fixture"):
        checkpoint(**values)


@pytest.mark.parametrize("count", [0, 2])
def test_active_checkpoint_rejects_missing_or_ambiguous_pending(active_checkpoint, count):
    checkpoint, values = active_checkpoint
    spool = values["record"].grant.spool_directory
    if count == 0:
        (spool / "original.pending.json").rename(spool / "not-pending.json")
    else:
        _private(spool / "different.pending.json", "different reference")
    with pytest.raises(ValueError, match="active cold fixture"):
        checkpoint(**values)


@pytest.mark.parametrize("changed", ["run_id", "old_bearer"])
def test_active_checkpoint_rejects_other_run_or_credential(active_checkpoint, changed):
    checkpoint, values = active_checkpoint
    path = values["root"] / "crash-state.json"
    content = json.loads(path.read_text())
    content[changed] = "different"
    path.chmod(0o600)
    path.write_text(json.dumps(content))
    path.chmod(0o400)
    with pytest.raises(ValueError, match="active cold fixture"):
        checkpoint(**values)


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
