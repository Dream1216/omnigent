from __future__ import annotations

import os
from pathlib import Path

import pytest

from saas.scripts import bind_runtime_build_revision as binder


class _Distribution:
    def __init__(self, target: Path) -> None:
        self._target = target

    def locate_file(self, _relative: str) -> Path:
        return self._target


def _installed_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    prefix = tmp_path / "venv"
    target = prefix / "lib/python3.12/site-packages/omnigent/_build_info.py"
    target.parent.mkdir(parents=True)
    target.write_text('COMMIT_SHA = ""\nBUILD_TIME_EPOCH = 0\n', encoding="utf-8")
    monkeypatch.setattr(binder.sys, "prefix", str(prefix))
    monkeypatch.setattr(
        binder.importlib.metadata,
        "distribution",
        lambda _name: _Distribution(target),
    )
    return target


def test_binder_writes_exact_deterministic_runtime_coordinates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _installed_target(tmp_path, monkeypatch)
    revision = "a" * 40
    epoch = 1_788_626_773

    assert (
        binder.bind_runtime_build_revision(
            source_revision=revision,
            source_date_epoch=epoch,
        )
        == target
    )

    namespace: dict[str, object] = {}
    exec(compile(target.read_text(encoding="utf-8"), str(target), "exec"), namespace)
    assert namespace["COMMIT_SHA"] == revision
    assert namespace["BUILD_TIME_EPOCH"] == epoch
    assert target.stat().st_mtime_ns == epoch * 1_000_000_000
    assert target.stat().st_mode & 0o777 == 0o644
    assert not target.with_name(f".{target.name}.tmp").exists()


@pytest.mark.parametrize(
    "revision",
    ["", "unknown", "A" * 40, "a" * 39, "g" * 40, "a" * 41],
)
def test_binder_rejects_noncanonical_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    revision: str,
) -> None:
    target = _installed_target(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="lowercase 40-character Git SHA"):
        binder.bind_runtime_build_revision(
            source_revision=revision,
            source_date_epoch=1,
        )

    assert target.read_text(encoding="utf-8") == 'COMMIT_SHA = ""\nBUILD_TIME_EPOCH = 0\n'


def test_binder_rejects_negative_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _installed_target(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="non-negative integer"):
        binder.bind_runtime_build_revision(
            source_revision="a" * 40,
            source_date_epoch=-1,
        )

    assert target.read_text(encoding="utf-8") == 'COMMIT_SHA = ""\nBUILD_TIME_EPOCH = 0\n'


def test_binder_rejects_metadata_outside_runtime_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "venv"
    prefix.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text('COMMIT_SHA = ""\n', encoding="utf-8")
    monkeypatch.setattr(binder.sys, "prefix", str(prefix))
    monkeypatch.setattr(
        binder.importlib.metadata,
        "distribution",
        lambda _name: _Distribution(outside),
    )

    with pytest.raises(RuntimeError, match="escapes the runtime prefix"):
        binder.bind_runtime_build_revision(
            source_revision="a" * 40,
            source_date_epoch=1,
        )


def test_binder_rejects_symlinked_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "venv"
    target = prefix / "lib/python3.12/site-packages/omnigent/_build_info.py"
    target.parent.mkdir(parents=True)
    outside = tmp_path / "outside.py"
    outside.write_text('COMMIT_SHA = ""\n', encoding="utf-8")
    target.symlink_to(outside)
    monkeypatch.setattr(binder.sys, "prefix", str(prefix))
    monkeypatch.setattr(
        binder.importlib.metadata,
        "distribution",
        lambda _name: _Distribution(target),
    )

    with pytest.raises(RuntimeError, match="must be a regular file"):
        binder.bind_runtime_build_revision(
            source_revision="a" * 40,
            source_date_epoch=1,
        )

    assert os.path.islink(target)
