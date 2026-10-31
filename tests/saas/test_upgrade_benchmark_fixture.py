"""The unchanged seeded corpus must reference actual readable agent artifacts."""

from __future__ import annotations

from pathlib import Path

import pytest

from dev.benchmarks.omnigent.environment import BenchEnvironment
from dev.benchmarks.omnigent.seed import _AGENT_BUNDLE, seed
from omnigent.runtime.agent_cache import AgentCache
from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
from omnigent.stores.artifact_store.local import LocalArtifactStore
from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore


@pytest.mark.parametrize("with_runner", [False, True])
def test_every_seeded_agent_loads_its_real_bundle_and_missing_bundles_still_fail(
    tmp_path: Path, with_runner: bool
) -> None:
    location = f"sqlite:///{tmp_path / 'corpus.db'}"
    assert seed(location, sessions=4, items_per_session=3, projects=2) == 4
    environment = BenchEnvironment(with_runner=with_runner, database_uri=location)
    environment.mock_url = "http://127.0.0.1:1"  # Parse only; no provider request.
    artifacts = tmp_path / "artifacts"
    environment._seed_agent_artifact(artifacts)
    store = LocalArtifactStore(str(artifacts))
    cache = AgentCache(artifact_store=store, cache_dir=tmp_path / "cache")
    conversations = SqlAlchemyConversationStore(location).list_conversations(limit=4)
    assert len(conversations.data) == 4
    agents = SqlAlchemyAgentStore(location).get_many(
        [conversation.agent_id for conversation in conversations.data]
    )
    assert len(agents) == 4
    for agent in agents.values():
        assert agent.bundle_location == _AGENT_BUNDLE
        loaded = cache.load(agent.id, agent.bundle_location)
        assert loaded.spec.executor.config["harness"] == environment.harness
        assert cache.load(agent.id, agent.bundle_location).spec is loaded.spec
    with pytest.raises(KeyError):
        cache.load("missing-agent", "missing/bundle")
