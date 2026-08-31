"""Two-tier agent cache — disk + in-memory — backed by ArtifactStore."""

from __future__ import annotations

import errno
import os
import shutil
import tempfile
import threading
from pathlib import Path

from yaml import YAMLError

from omnigent.entities import LoadedAgent
from omnigent.errors import OmnigentError
from omnigent.spec import AgentSpec
from omnigent.spec import load as load_spec
from omnigent.stores.artifact_store import ArtifactStore


class AgentCache:
    """
    Two-tier cache for loaded agents.

    Tier 1 (in-memory): parsed AgentSpec objects keyed by agent_id.
    Tier 2 (disk): extracted agent directories under cache_dir/<agent_id>/.
    Source of truth: ArtifactStore (tarball bytes).

    On cache miss the bundle is downloaded from the ArtifactStore,
    extracted to disk, parsed, validated, and stored in both tiers.

    This is an **execution** load path, so it loads with
    ``prune_invalid_sub_agents=True``: a sub-agent that fails
    validation here means this server is older than whatever produced
    the bundle and can't run that sub-agent (version skew), so it is
    dropped (with a WARNING) and the parent agent still dispatches.
    Authoring/upload validation stays strict elsewhere
    (:func:`omnigent.server.bundles.validate_agent_bundle`). See
    :func:`omnigent.spec.load`.

    ``cache_dir`` is a process-local derived cache, not a shared durable
    artifact store.  One application process owns one ``AgentCache`` instance;
    independent processes may race only on first-load publication, which is
    handled defensively by the atomic staging rename below.  Cross-process
    replace/evict coordination belongs at the durable agent-store boundary.
    """

    _LOCK_STRIPES = 64

    def __init__(self, artifact_store: ArtifactStore, cache_dir: Path) -> None:
        """
        Initialize the two-tier agent cache.

        :param artifact_store: The ArtifactStore holding agent
            bundle tarballs (source of truth).
        :param cache_dir: Root directory for the disk cache.
            Each agent is extracted to
            ``<cache_dir>/<agent_id>/``.
        """
        self._artifact_store = artifact_store
        self._cache_dir = cache_dir
        self._specs: dict[str, AgentSpec] = {}
        # Loading is commonly offloaded with ``asyncio.to_thread``.  Without a
        # per-agent lock, two first readers can both miss Tier 1/Tier 2 while
        # one is extracting directly into the final directory.  The loser then
        # parses a half-published ``config.yaml``.  Fixed lock striping bounds
        # memory in long-lived multi-tenant processes while still serializing
        # every operation for the same immutable agent id.
        self._agent_locks = tuple(threading.Lock() for _ in range(self._LOCK_STRIPES))

    def _lock_for(self, agent_id: str) -> threading.Lock:
        """Return the stable process-local lock for one agent cache key."""

        return self._agent_locks[hash(agent_id) % len(self._agent_locks)]

    def load(
        self,
        agent_id: str,
        bundle_location: str,
        *,
        expand_env: bool = False,
    ) -> LoadedAgent:
        """
        Load an agent, populating caches on miss.

        Raises KeyError if the agent bundle does not exist in the
        ArtifactStore. Raises ValueError if the spec is invalid.

        :param agent_id: Unique agent identifier,
            e.g. ``"ag_abc123"``.
        :param bundle_location: Artifact store key for the bundle,
            e.g. ``"ag_abc123/a1b2c3d4e5f6..."``.
        :param expand_env: Whether to expand ``${VAR}`` references in
            the spec against the server process environment. Defaults
            to ``False`` and MUST stay ``False`` for tenant-supplied
            (session-scoped) agents: expanding their ``${VAR}``
            against the server env leaks secrets into a spec-controlled
            MCP/LLM connection. Callers pass
            ``expand_env=True`` only for operator-authored template
            agents (``Agent.session_id is None`` — ``--agent`` /
            built-ins). The default is fail-safe: a caller that
            forgets the flag gets no expansion (a template agent may
            fail to resolve, loudly) rather than a silent leak.
        :returns: A LoadedAgent with the parsed spec and the
            on-disk working directory.
        """
        workdir = self._cache_dir / agent_id
        with self._lock_for(agent_id):
            # Tier 1: in-memory spec. The cached spec was parsed with the
            # *expand_env* value of whichever caller populated it first.
            # That is consistent across callers because *expand_env* is
            # derived from the agent's immutable ``session_id`` provenance,
            # which never changes for a given ``agent_id``.
            if agent_id in self._specs:
                return LoadedAgent(spec=self._specs[agent_id], workdir=workdir)

            # Tier 2: disk cache (directory already atomically published)
            if workdir.is_dir():
                try:
                    spec = load_spec(
                        workdir,
                        expand_env=expand_env,
                        prune_invalid_sub_agents=True,
                    )
                except (FileNotFoundError, UnicodeDecodeError, YAMLError, OmnigentError):
                    # Versions before atomic publication extracted directly
                    # into the public path.  A crash could therefore leave an
                    # empty or partial config that survives an upgrade.  Tier
                    # 2 is derived data, so quarantine it by deletion and
                    # rebuild from the ArtifactStore source of truth below.
                    shutil.rmtree(workdir)
                else:
                    self._specs[agent_id] = spec
                    return LoadedAgent(spec=spec, workdir=workdir)

            # Cache miss — download bundle, extract privately, then publish.
            bundle_bytes = self._artifact_store.get(bundle_location)
            return self._extract_and_cache(
                agent_id,
                bundle_bytes,
                workdir,
                expand_env=expand_env,
            )

    def replace(
        self,
        agent_id: str,
        bundle_location: str,
        bundle_bytes: bytes,
        *,
        expand_env: bool = False,
    ) -> LoadedAgent:
        """
        Warm-swap an agent's cached spec and disk directory.

        Extracts the new bundle to a temp directory, swaps the
        in-memory spec entry, renames into the cache location, and
        cleans up the old directory. Concurrent readers see either
        the old spec or the new spec, never an empty cache.

        :param agent_id: Unique agent identifier,
            e.g. ``"ag_abc123"``.
        :param bundle_location: New artifact store key (unused
            during extraction but passed for consistency),
            e.g. ``"ag_abc123/a1b2c3d4e5f6..."``.
        :param bundle_bytes: Raw bytes of the new ``.tar.gz``
            bundle.
        :param expand_env: Whether to expand ``${VAR}`` references
            against the server process environment. Defaults to
            ``False`` (fail-safe); pass ``True`` only for
            operator-authored template agents. See :meth:`load` for
            the full rationale.
        :returns: A LoadedAgent with the new spec and working
            directory.
        """
        workdir = self._cache_dir / agent_id
        with self._lock_for(agent_id):
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            staging_dir = Path(
                tempfile.mkdtemp(prefix=f".{agent_id}-staging-", dir=self._cache_dir)
            )
            backup_dir: Path | None = None
            published = False
            tmp_fd, tmp_name = tempfile.mkstemp(suffix=".tar.gz")
            os.close(tmp_fd)
            tmp_path = Path(tmp_name)
            try:
                tmp_path.write_bytes(bundle_bytes)
                spec = load_spec(
                    tmp_path,
                    dest=staging_dir,
                    expand_env=expand_env,
                    prune_invalid_sub_agents=True,
                )

                # The same-agent lock keeps readers on the old complete
                # directory until the replacement is ready.  Move the old
                # directory aside rather than deleting it so a failed publish
                # can restore both cache tiers to the previous complete state.
                if workdir.is_dir():
                    backup_dir = Path(
                        tempfile.mkdtemp(
                            prefix=f".{agent_id}-backup-",
                            dir=self._cache_dir,
                        )
                    )
                    backup_dir.rmdir()
                    workdir.rename(backup_dir)
                try:
                    staging_dir.rename(workdir)
                except Exception as publish_error:
                    if backup_dir is not None and backup_dir.exists():
                        try:
                            backup_dir.rename(workdir)
                        except Exception as restore_error:
                            # Never retain a Tier 1 object whose workdir no
                            # longer exists.  Preserve the hidden backup for
                            # operator recovery and force the next load to use
                            # the ArtifactStore rather than returning stale
                            # memory state.
                            self._specs.pop(agent_id, None)
                            raise RuntimeError(
                                "agent cache publish and rollback both failed; "
                                f"previous cache retained at {backup_dir}"
                            ) from restore_error
                    assert publish_error is not None
                    raise
                published = True
                self._specs[agent_id] = spec
                return LoadedAgent(spec=spec, workdir=workdir)
            finally:
                tmp_path.unlink(missing_ok=True)
                shutil.rmtree(staging_dir, ignore_errors=True)
                if published and backup_dir is not None:
                    shutil.rmtree(backup_dir, ignore_errors=True)

    def evict(self, agent_id: str) -> None:
        """
        Remove an agent from both cache tiers. Called when an
        agent is deleted. No-op if the agent is not cached.

        :param agent_id: Unique agent identifier,
            e.g. ``"ag_abc123"``.
        """
        with self._lock_for(agent_id):
            self._specs.pop(agent_id, None)
            workdir = self._cache_dir / agent_id
            if workdir.is_dir():
                shutil.rmtree(workdir)

    def _extract_and_cache(
        self,
        agent_id: str,
        bundle_bytes: bytes,
        workdir: Path,
        *,
        expand_env: bool = False,
    ) -> LoadedAgent:
        """
        Extract bundle bytes to disk and populate both cache tiers.

        :param agent_id: Unique agent identifier.
        :param bundle_bytes: Raw bytes of the ``.tar.gz`` bundle.
        :param workdir: Target directory for extraction.
        :param expand_env: Whether to expand ``${VAR}`` references
            against the server process environment. Forwarded from
            :meth:`load`; defaults to ``False`` (fail-safe). See
            :meth:`load` for the rationale.
        :returns: A LoadedAgent with the parsed spec and workdir.
        """
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(tempfile.mkdtemp(prefix=f".{agent_id}-extract-", dir=self._cache_dir))
        tmp_fd, tmp_name = tempfile.mkstemp(suffix=".tar.gz")
        os.close(tmp_fd)
        tmp_path = Path(tmp_name)
        try:
            tmp_path.write_bytes(bundle_bytes)
            spec = load_spec(
                tmp_path,
                dest=staging_dir,
                expand_env=expand_env,
                prune_invalid_sub_agents=True,
            )
            try:
                staging_dir.rename(workdir)
            except OSError as exc:
                # A separate AgentCache instance may share the same local
                # cache root.  Its atomic publish won; consume that complete
                # directory instead of exposing or parsing our staging path.
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY} or not workdir.is_dir():
                    raise
                spec = load_spec(
                    workdir,
                    expand_env=expand_env,
                    prune_invalid_sub_agents=True,
                )
        finally:
            tmp_path.unlink(missing_ok=True)
            shutil.rmtree(staging_dir, ignore_errors=True)

        self._specs[agent_id] = spec
        return LoadedAgent(spec=spec, workdir=workdir)
