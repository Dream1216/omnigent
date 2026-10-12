"""Cache cleanup is scoped and cannot admit or delete candidate OCI inputs."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from saas.scripts import reclaim_candidate_build_cache as storage


@pytest.fixture
def archives(tmp_path: Path) -> Path:
    for index, name in enumerate(storage.ARCHIVES, start=1):
        (tmp_path / name).write_bytes(b"fixture-archive" * index)
    return tmp_path


def test_reclaims_only_named_builder_and_preserves_all_inputs(archives, monkeypatch):
    original = {name: (archives / name).read_bytes() for name in storage.ARCHIVES}
    run = Mock()
    monkeypatch.setattr(storage.subprocess, "run", run)
    monkeypatch.setattr(
        storage.shutil,
        "disk_usage",
        Mock(side_effect=[SimpleNamespace(free=0), SimpleNamespace(free=10 * 1024**3)]),
    )
    result = storage.reclaim_build_cache(archives, "builder-synthetic-fixture")
    run.assert_called_once_with(
        [
            "docker",
            "buildx",
            "prune",
            "--builder",
            "builder-synthetic-fixture",
            "--all",
            "--force",
        ],
        check=True,
        timeout=300,
    )
    assert {name: (archives / name).read_bytes() for name in storage.ARCHIVES} == original
    assert result["exported_archive_metadata_unchanged"] is True
    assert result["required_inspection_bytes"] == max(map(len, original.values())) + 1024**3


@pytest.mark.parametrize("builder", ["", "default", "desktop-linux", "-a", "builder-foo;bad"])
def test_rejects_implicit_or_untrusted_builder(archives, monkeypatch, builder):
    run = Mock()
    monkeypatch.setattr(storage.subprocess, "run", run)
    with pytest.raises(ValueError, match="explicitly named ephemeral"):
        storage.reclaim_build_cache(archives, builder)
    run.assert_not_called()


@pytest.mark.parametrize("replacement", ["missing", "empty", "symlink"])
def test_requires_four_retained_regular_archives(archives, monkeypatch, replacement):
    path = archives / "host-2.tar"
    path.unlink()
    if replacement == "empty":
        path.write_bytes(b"")
    elif replacement == "symlink":
        path.symlink_to(archives / "host-1.tar")
    run = Mock()
    monkeypatch.setattr(storage.subprocess, "run", run)
    with pytest.raises((ValueError, FileNotFoundError)):
        storage.reclaim_build_cache(archives, "builder-synthetic-fixture")
    run.assert_not_called()


def test_rejects_insufficient_space_after_prune(archives, monkeypatch):
    monkeypatch.setattr(storage.subprocess, "run", Mock())
    monkeypatch.setattr(storage.shutil, "disk_usage", Mock(return_value=SimpleNamespace(free=0)))
    with pytest.raises(RuntimeError, match="insufficient OCI inspection space"):
        storage.reclaim_build_cache(archives, "builder-synthetic-fixture")


def test_rejects_archive_changes_during_prune(archives, monkeypatch):
    def change_archive(*args, **kwargs):
        (archives / "host-1.tar").write_bytes(b"changed")

    monkeypatch.setattr(storage.subprocess, "run", change_archive)
    monkeypatch.setattr(
        storage.shutil, "disk_usage", Mock(return_value=SimpleNamespace(free=10 * 1024**3))
    )
    with pytest.raises(RuntimeError, match="archives changed"):
        storage.reclaim_build_cache(archives, "builder-synthetic-fixture")


def test_prune_failure_is_not_ignored(archives, monkeypatch):
    monkeypatch.setattr(
        storage.subprocess,
        "run",
        Mock(side_effect=storage.subprocess.CalledProcessError(1, "docker")),
    )
    monkeypatch.setattr(storage.shutil, "disk_usage", Mock(return_value=SimpleNamespace(free=0)))
    with pytest.raises(storage.subprocess.CalledProcessError):
        storage.reclaim_build_cache(archives, "builder-synthetic-fixture")


def test_workflow_reclaims_after_builds_without_removing_any_gate():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/saas-image-candidate.yml").read_text())
    candidate = workflow["jobs"]["build-candidate"]
    steps = candidate["steps"]
    names = [step.get("name") for step in steps]
    cleanup = names.index("Reclaim ephemeral builder cache before OCI inspection")
    assert (
        names.index("Build host candidate attempt 2")
        < cleanup
        < names.index("Compare repeated executable image facts")
    )
    assert (
        cleanup
        < names.index("Scan exact OCI candidates on both architectures")
        < names.index("Seal exact admitted OCI archives and raw scan evidence")
    )
    assert (
        steps[cleanup]["env"]["CANDIDATE_BUILDER_NAME"]
        == "${{ steps.candidate-builder.outputs.name }}"
    )
    assert "continue-on-error" not in steps[cleanup]
    assert 'echo "TMPDIR=$RUNNER_TEMP" >> "$GITHUB_ENV"' in steps[cleanup]["run"]
