from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from omnigent.db.db_models import current_workspace_id
from omnigent.runtime.agent_cache import AgentCache
from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
from omnigent.stores.artifact_store.local import LocalArtifactStore
from omnigent.stores.host_store import HOST_LIVENESS_TTL_S, Host
from saas.compatibility import OmnigentStoreAdapter, RuntimeContext
from saas.control_plane.http_auth import RuntimeInitializerError, SaasAuthContextMiddleware
from saas.production.agent_catalog import (
    TenantAgentCatalogInitializer,
    create_execution_readiness_router,
)
from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login


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


def test_execution_readiness_requires_authentication_and_preserves_runtime_scope() -> None:
    app, scope = _build_fastapi_app()
    auth = next(
        middleware.kwargs["auth_provider"]
        for middleware in app.user_middleware
        if middleware.cls is SaasAuthContextMiddleware
    )
    initializer = Mock(spec=TenantAgentCatalogInitializer)
    initializer.ensure = AsyncMock()
    agent_store = Mock()
    agent_store.list.return_value = SimpleNamespace(data=[object()])
    host = Host(
        host_id="readiness-host",
        name="Readiness Host",
        user_id="runtime-user",
        status="online",
        created_at=int(time.time()),
        updated_at=int(time.time()),
    )
    host_reads: list[tuple[int, str]] = []

    def list_hosts(user_id: str) -> list[Host]:
        host_reads.append((current_workspace_id(), user_id))
        return [host]

    host_store = Mock()
    host_store.list_hosts.side_effect = list_hosts
    app.include_router(
        create_execution_readiness_router(
            auth_provider=auth,
            initializer=initializer,
            agent_store=agent_store,
            host_store=host_store,
        ),
        prefix="/v1",
    )
    try:
        with TestClient(app) as client:
            anonymous = client.get("/v1/execution-readyz")
            assert anonymous.status_code == 401
            initializer.ensure.assert_not_awaited()
            agent_store.list.assert_not_called()
            assert not host_reads

            _login(client)
            bound = client.get("/v1/protected").json()
            ready = client.get("/v1/execution-readyz")
            assert ready.status_code == 200
            assert ready.json()["ready"] is True
            assert ready.headers["cache-control"] == "private, no-store"
            assert host_reads == [(bound["workspace_id"], bound["user_id"])]
            assert str(initializer.ensure.call_args.args[0].tenant_id) == scope["tenant_id"]

            denied = client.get(
                "/v1/execution-readyz",
                headers={"X-SaaS-Tenant-ID": str(uuid4()), "X-SaaS-Space-ID": str(uuid4())},
            )
            assert denied.status_code == 403
            assert len(host_reads) == 1

            host.updated_at = int(time.time()) - HOST_LIVENESS_TTL_S - 1
            stale = client.get("/v1/execution-readyz")
            assert stale.status_code == 503
            assert stale.json()["reasons"] == ["no_online_host"]
            assert stale.json()["online_host_count"] == 0

            host.updated_at = int(time.time())
            agent_store.list.return_value = SimpleNamespace(data=[])
            empty = client.get("/v1/execution-readyz")
            assert empty.status_code == 503
            assert empty.json()["reasons"] == ["agent_catalog_empty"]
    finally:
        app.state.saas_test_engine.dispose()
