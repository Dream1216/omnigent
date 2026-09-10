from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import sqlalchemy as sa

from omnigent.db.db_models import current_workspace_id
from omnigent.runtime.agent_cache import AgentCache
from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
from omnigent.stores.artifact_store.local import LocalArtifactStore
from saas.compatibility import OmnigentStoreAdapter, RuntimeContext
from saas.control_plane.http_auth import RuntimeInitializerError
from saas.production.agent_catalog import TenantAgentCatalogInitializer


def _runtime() -> RuntimeContext:
    return RuntimeContext(
        actor_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        runtime_partition_id=uuid4(),
        placement_id=uuid4(),
        placement_generation=2,
        binding_generation=3,
        data_region="cn-east-1",
        physical_workspace_id=91,
        runtime_user_key="runtime-user",
        runtime_type="omnigent",
        source_revision="reviewed-revision",
        adapter_contract_version="0.2.0",
        trace_id="agent-catalog-test",
    )


@pytest.mark.asyncio
async def test_agent_catalog_initializes_once_per_workspace_under_bound_context() -> None:
    engine = sa.create_engine("sqlite://")
    seeded: list[int] = []

    def seed(*_stores: Any) -> None:
        seeded.append(current_workspace_id())

    initializer = TenantAgentCatalogInitializer(
        runtime_engine=engine,
        agent_store=object(),
        artifact_store=object(),
        agent_cache=object(),
        seed=seed,
    )
    adapter = OmnigentStoreAdapter("0.2.0")
    runtime = _runtime()
    try:
        with adapter.bind(runtime):
            await asyncio.gather(*(initializer.ensure(runtime) for _ in range(8)))
        second = replace(runtime, physical_workspace_id=92)
        with adapter.bind(second):
            await initializer.ensure(second)
        assert seeded == [91, 92]
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_agent_catalog_real_seed_is_visible_and_isolated_per_workspace(
    db_uri: str,
    tmp_path: Path,
) -> None:
    engine = sa.create_engine(db_uri)
    agent_store = SqlAlchemyAgentStore(db_uri)
    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    agent_cache = AgentCache(artifact_store=artifact_store, cache_dir=tmp_path / "cache")
    initializer = TenantAgentCatalogInitializer(
        runtime_engine=engine,
        agent_store=agent_store,
        artifact_store=artifact_store,
        agent_cache=agent_cache,
    )
    adapter = OmnigentStoreAdapter("0.2.0")
    first = _runtime()
    second = replace(first, physical_workspace_id=92)
    try:
        with adapter.bind(first):
            assert not agent_store.list(limit=100).data
            await initializer.ensure(first)
            first_agents = agent_store.list(limit=100).data
        with adapter.bind(second):
            assert not agent_store.list(limit=100).data
            await initializer.ensure(second)
            second_agents = agent_store.list(limit=100).data

        assert first_agents
        assert {agent.id for agent in first_agents} == {agent.id for agent in second_agents}
        assert {agent.name for agent in first_agents} == {agent.name for agent in second_agents}
        assert all(artifact_store.exists(agent.bundle_location) for agent in first_agents)
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_agent_catalog_failure_is_redacted_and_retried() -> None:
    engine = sa.create_engine("sqlite://")
    attempts = 0

    def seed(*_stores: Any) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("secret backend detail")

    initializer = TenantAgentCatalogInitializer(
        runtime_engine=engine,
        agent_store=object(),
        artifact_store=object(),
        agent_cache=object(),
        seed=seed,
    )
    adapter = OmnigentStoreAdapter("0.2.0")
    runtime = _runtime()
    try:
        with adapter.bind(runtime):
            with pytest.raises(RuntimeInitializerError) as exc_info:
                await initializer.ensure(runtime)
            await initializer.ensure(runtime)
        assert exc_info.value.code == "runtime_catalog_unavailable"
        assert "secret backend detail" not in str(exc_info.value)
        assert attempts == 2
    finally:
        engine.dispose()


def test_agent_catalog_initializes_only_agent_consuming_runtime_routes() -> None:
    engine = sa.create_engine("sqlite://")
    initializer = TenantAgentCatalogInitializer(
        runtime_engine=engine,
        agent_store=object(),
        artifact_store=object(),
        agent_cache=object(),
    )
    try:
        assert initializer.should_initialize("/v1/agents")
        assert initializer.should_initialize("/v1/sessions/conv-1")
        assert initializer.should_initialize("/v1/execution-readyz")
        assert not initializer.should_initialize("/v1/hosts/host-1/tunnel")
        assert not initializer.should_initialize("/v1/info")
    finally:
        engine.dispose()
