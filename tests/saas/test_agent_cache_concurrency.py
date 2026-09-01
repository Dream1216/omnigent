"""Concurrency contracts for the official runtime AgentCache seam."""

from __future__ import annotations

import concurrent.futures
import errno
import io
import tarfile
import threading
from pathlib import Path

import pytest
import yaml

import omnigent.runtime.agent_cache as agent_cache_module
from omnigent.errors import OmnigentError
from omnigent.runtime.agent_cache import AgentCache
from omnigent.stores.artifact_store.local import LocalArtifactStore


def _bundle_bytes(*, name: str = "concurrent-agent") -> bytes:
    """Build one minimal valid agent bundle in memory."""

    config = yaml.dump(
        {
            "spec_version": 1,
            "name": name,
            "executor": {
                "type": "omnigent",
                "config": {"harness": "claude-sdk"},
            },
        },
        sort_keys=False,
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("config.yaml")
        info.size = len(config)
        archive.addfile(info, io.BytesIO(config))
    return buffer.getvalue()


def test_concurrent_cache_miss_never_exposes_partial_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second reader waits until the first extraction is atomically published.

    The previous implementation extracted directly into ``cache/<agent_id>``.
    This test pauses the first extraction after creating an empty config file:
    an unlocked second load then observes the final directory and fails parsing
    ``NoneType`` YAML, reproducing the remote server-integration failure.
    """

    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    location = "concurrent-agent/revision-1"
    artifact_store.put(location, _bundle_bytes())
    cache_dir = tmp_path / "cache"
    cache = AgentCache(artifact_store=artifact_store, cache_dir=cache_dir)

    real_load_spec = agent_cache_module.load_spec
    first_extract_started = threading.Event()
    release_first_extract = threading.Event()
    extraction_calls = 0
    calls_guard = threading.Lock()

    def _paused_load_spec(
        source: Path | bytes,
        *,
        dest: Path | None = None,
        **kwargs: object,
    ) -> object:
        nonlocal extraction_calls
        if dest is not None:
            with calls_guard:
                extraction_calls += 1
                call_number = extraction_calls
            if call_number == 1:
                dest.mkdir(parents=True, exist_ok=True)
                (dest / "config.yaml").write_text("", encoding="utf-8")
                first_extract_started.set()
                assert release_first_extract.wait(timeout=5)
        return real_load_spec(source, dest=dest, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(agent_cache_module, "load_spec", _paused_load_spec)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(cache.load, "concurrent-agent", location)
        assert first_extract_started.wait(timeout=5)
        second = pool.submit(cache.load, "concurrent-agent", location)
        try:
            # The old implementation extracts straight into the public path,
            # so this assertion fails deterministically before timing enters
            # the contract.  The fixed implementation exposes only a hidden
            # staging directory until parsing succeeds.
            assert not (cache_dir / "concurrent-agent").exists()
            # The second call must be waiting on the per-agent lock.  On the
            # old implementation it completes here with the empty-YAML error.
            with pytest.raises(concurrent.futures.TimeoutError):
                second.result(timeout=0.25)
        finally:
            release_first_extract.set()

        first_loaded = first.result(timeout=5)
        second_loaded = second.result(timeout=5)

    assert extraction_calls == 1
    assert first_loaded.spec is second_loaded.spec
    assert first_loaded.workdir == cache_dir / "concurrent-agent"
    assert (first_loaded.workdir / "config.yaml").read_text(encoding="utf-8")
    assert list(cache_dir.glob(".concurrent-agent-extract-*")) == []


def test_failed_cache_miss_does_not_publish_partial_directory(tmp_path: Path) -> None:
    """A parse failure removes private staging and leaves Tier 2 absent."""

    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    location = "invalid-agent/revision-1"
    artifact_store.put(location, _bundle_bytes(name=""))
    cache_dir = tmp_path / "cache"
    cache = AgentCache(artifact_store=artifact_store, cache_dir=cache_dir)

    with pytest.raises(OmnigentError, match="name"):
        cache.load("invalid-agent", location)

    assert not (cache_dir / "invalid-agent").exists()
    assert list(cache_dir.glob(".invalid-agent-extract-*")) == []


@pytest.mark.parametrize(
    "legacy_config",
    [
        None,
        "",
        "spec_version: [\n",
    ],
)
def test_legacy_partial_disk_cache_is_rebuilt_from_artifact_store(
    tmp_path: Path,
    legacy_config: str | None,
) -> None:
    """An old directly extracted partial directory self-heals after upgrade."""

    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    location = "legacy-agent/revision-1"
    artifact_store.put(location, _bundle_bytes(name="rebuilt-agent"))
    cache_dir = tmp_path / "cache"
    workdir = cache_dir / "legacy-agent"
    workdir.mkdir(parents=True)
    if legacy_config is not None:
        (workdir / "config.yaml").write_text(legacy_config, encoding="utf-8")
    cache = AgentCache(artifact_store=artifact_store, cache_dir=cache_dir)

    loaded = cache.load("legacy-agent", location)

    assert loaded.spec.name == "rebuilt-agent"
    assert yaml.safe_load((workdir / "config.yaml").read_text(encoding="utf-8"))["name"] == (
        "rebuilt-agent"
    )
    assert list(cache_dir.glob(".legacy-agent-extract-*")) == []


def test_cross_instance_publish_loser_consumes_complete_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ENOTEMPTY from an atomic publish race consumes the winning directory."""

    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    location = "publish-race/revision-1"
    artifact_store.put(location, _bundle_bytes(name="loser"))
    cache_dir = tmp_path / "cache"
    cache = AgentCache(artifact_store=artifact_store, cache_dir=cache_dir)
    workdir = cache_dir / "publish-race"
    real_rename = Path.rename

    def _publish_winner_then_lose(source: Path, target: Path) -> Path:
        if source.name.startswith(".publish-race-extract-") and target == workdir:
            workdir.mkdir()
            (workdir / "config.yaml").write_text(
                yaml.dump(
                    {
                        "spec_version": 1,
                        "name": "winner",
                        "executor": {
                            "type": "omnigent",
                            "config": {"harness": "claude-sdk"},
                        },
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            raise OSError(errno.ENOTEMPTY, "simulated cross-instance publish race")
        return real_rename(source, target)

    monkeypatch.setattr(Path, "rename", _publish_winner_then_lose)

    loaded = cache.load("publish-race", location)

    assert loaded.spec.name == "winner"
    assert loaded.workdir == workdir
    assert list(cache_dir.glob(".publish-race-extract-*")) == []


def test_replace_publish_failure_restores_previous_complete_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed staging publish restores the previous disk and memory tiers."""

    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    location = "replace-agent/revision-1"
    artifact_store.put(location, _bundle_bytes(name="replace-agent-v1"))
    cache_dir = tmp_path / "cache"
    cache = AgentCache(artifact_store=artifact_store, cache_dir=cache_dir)
    original = cache.load("replace-agent", location)

    real_rename = Path.rename
    workdir = cache_dir / "replace-agent"

    def _fail_staging_publish(source: Path, target: Path) -> Path:
        if source.name.startswith(".replace-agent-staging-") and target == workdir:
            raise OSError("simulated atomic publish failure")
        return real_rename(source, target)

    monkeypatch.setattr(Path, "rename", _fail_staging_publish)

    with pytest.raises(OSError, match="simulated atomic publish failure"):
        cache.replace(
            "replace-agent",
            "replace-agent/revision-2",
            _bundle_bytes(name="replace-agent-v2"),
        )

    loaded = cache.load("replace-agent", location)
    assert loaded.spec is original.spec
    assert loaded.spec.name == "replace-agent-v1"
    assert workdir.is_dir()
    assert yaml.safe_load((workdir / "config.yaml").read_text(encoding="utf-8"))["name"] == (
        "replace-agent-v1"
    )
    assert list(cache_dir.glob(".replace-agent-staging-*")) == []
    assert list(cache_dir.glob(".replace-agent-backup-*")) == []


def test_replace_publish_and_rollback_failure_clears_memory_tier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A double filesystem failure never leaves a stale in-memory cache hit."""

    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    location = "double-failure-agent/revision-1"
    artifact_store.put(location, _bundle_bytes(name="double-failure-v1"))
    cache_dir = tmp_path / "cache"
    cache = AgentCache(artifact_store=artifact_store, cache_dir=cache_dir)
    cache.load("double-failure-agent", location)

    real_rename = Path.rename
    workdir = cache_dir / "double-failure-agent"

    def _fail_publish_and_restore(source: Path, target: Path) -> Path:
        if target == workdir and (
            source.name.startswith(".double-failure-agent-staging-")
            or source.name.startswith(".double-failure-agent-backup-")
        ):
            raise OSError("simulated publish or rollback failure")
        return real_rename(source, target)

    monkeypatch.setattr(Path, "rename", _fail_publish_and_restore)

    with pytest.raises(RuntimeError, match="publish and rollback both failed"):
        cache.replace(
            "double-failure-agent",
            "double-failure-agent/revision-2",
            _bundle_bytes(name="double-failure-v2"),
        )

    assert not workdir.exists()
    assert len(list(cache_dir.glob(".double-failure-agent-backup-*"))) == 1
    artifact_store.delete(location)
    with pytest.raises(KeyError):
        cache.load("double-failure-agent", location)
