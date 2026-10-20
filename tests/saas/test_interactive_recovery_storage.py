from __future__ import annotations

import stat
from pathlib import Path

import pytest

from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    InteractiveRecoveryJournal,
)


def test_new_private_journal_removes_only_inherited_setgid(tmp_path, monkeypatch):
    root = tmp_path / "journal"
    mkdir = Path.mkdir

    def inherited(path, *args, **kwargs):
        mkdir(path, *args, **kwargs)
        if path == root:
            # Linux fsGroup volumes pass this bit to newly created directories.
            path.chmod(0o2700)

    monkeypatch.setattr(Path, "mkdir", inherited)
    journal = InteractiveRecoveryJournal(root)
    try:
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert journal.records() == []
    finally:
        journal.close()


@pytest.mark.parametrize("mode", (0o2700, 0o770, 0o750, 0o777))
def test_existing_unsafe_journal_is_never_repaired_silently(tmp_path, mode):
    root = tmp_path / "existing"
    root.mkdir()
    root.chmod(mode)
    with pytest.raises(InteractiveRecoveryError):
        InteractiveRecoveryJournal(root)
    assert stat.S_IMODE(root.stat().st_mode) == mode


def test_existing_private_journal_remains_locked_and_reopenable(tmp_path):
    root = tmp_path / "existing"
    root.mkdir(mode=0o700)
    first = InteractiveRecoveryJournal(root)
    try:
        with pytest.raises(InteractiveRecoveryError):
            InteractiveRecoveryJournal(root)
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
    finally:
        first.close()
    second = InteractiveRecoveryJournal(root)
    second.close()


def test_symlinked_journal_does_not_change_target_permissions(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    target.chmod(0o2700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(InteractiveRecoveryError):
        InteractiveRecoveryJournal(link)
    assert stat.S_IMODE(target.stat().st_mode) == 0o2700
