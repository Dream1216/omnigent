"""Tenant-scoped built-in Agent catalog initialization and readiness."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Callable
from typing import Any

import sqlalchemy as sa
from fastapi import APIRouter, Response
from sqlalchemy.engine import Engine

from omnigent.server.app import _ensure_default_agents
from omnigent.stores.host_store import host_is_live
from saas.compatibility import RuntimeContext, current_runtime_context
from saas.control_plane.http_auth import RuntimeInitializerError

logger = logging.getLogger("omnigent-saas-agent-catalog")


class TenantAgentCatalogInitializer:
    """Initialize packaged Agents once per Runtime Partition and release.

    The caller must already have bound the reviewed :class:`RuntimeContext`.
    A PostgreSQL session advisory lock serializes the content-aware official
    seed across server replicas; an in-process lock collapses concurrent first
    requests on one replica.  Failed attempts are never cached and may be
    retried by the next request.
    """

    _ROUTE_PREFIXES = ("/v1/agents", "/v1/sessions", "/v1/execution-readyz")

    def __init__(
        self,
        *,
        runtime_engine: Engine,
        agent_store: Any,
        artifact_store: Any,
        agent_cache: Any,
        seed: Callable[[Any, Any, Any], None] = _ensure_default_agents,
    ) -> None:
        self._runtime_engine = runtime_engine
        self._agent_store = agent_store
        self._artifact_store = artifact_store
        self._agent_cache = agent_cache
        self._seed = seed
        self._initialized: set[int] = set()
        self._locks: dict[int, asyncio.Lock] = {}

    def should_initialize(self, path: str) -> bool:
        """Return whether *path* consumes tenant Agent catalog state."""

        return any(
            path == prefix or path.startswith(f"{prefix}/") for prefix in self._ROUTE_PREFIXES
        )

    async def ensure(self, runtime: RuntimeContext) -> None:
        """Ensure the current tenant workspace has the packaged Agent catalog."""

        workspace_id = runtime.physical_workspace_id
        if workspace_id <= 0:
            raise RuntimeInitializerError(
                "runtime_catalog_workspace_invalid",
                "runtime Agent catalog requires a positive workspace",
            )
        if workspace_id in self._initialized:
            return
        lock = self._locks.setdefault(workspace_id, asyncio.Lock())
        async with lock:
            if workspace_id in self._initialized:
                return
            try:
                await asyncio.to_thread(self._seed_with_replica_lock, workspace_id)
            except Exception:
                logger.exception(
                    "tenant Agent catalog initialization failed workspace_id=%s",
                    workspace_id,
                )
                raise RuntimeInitializerError(
                    "runtime_catalog_unavailable",
                    "runtime Agent catalog is temporarily unavailable",
                ) from None
            self._initialized.add(workspace_id)
            logger.info("tenant Agent catalog initialized workspace_id=%s", workspace_id)

    def _seed_with_replica_lock(self, workspace_id: int) -> None:
        if self._runtime_engine.dialect.name != "postgresql":
            self._seed(self._agent_store, self._artifact_store, self._agent_cache)
            return
        key_bytes = hashlib.sha256(
            f"omnigent-agent-catalog:{workspace_id}".encode("ascii")
        ).digest()[:8]
        advisory_key = int.from_bytes(key_bytes, byteorder="big", signed=True)
        with self._runtime_engine.connect() as connection:
            connection.execute(
                sa.text("SELECT pg_advisory_lock(:advisory_key)"),
                {"advisory_key": advisory_key},
            )
            try:
                self._seed(self._agent_store, self._artifact_store, self._agent_cache)
            finally:
                connection.execute(
                    sa.text("SELECT pg_advisory_unlock(:advisory_key)"),
                    {"advisory_key": advisory_key},
                )


def create_execution_readiness_router(
    *,
    initializer: TenantAgentCatalogInitializer,
    agent_store: Any,
    host_store: Any,
) -> APIRouter:
    """Expose authenticated, RuntimeContext-scoped execution readiness."""

    router = APIRouter()

    @router.get("/execution-readyz", include_in_schema=False)
    async def execution_ready(response: Response) -> dict[str, object]:
        runtime = current_runtime_context()
        await initializer.ensure(runtime)
        agents, hosts = await asyncio.gather(
            asyncio.to_thread(agent_store.list, limit=1),
            asyncio.to_thread(host_store.list_hosts, runtime.runtime_user_key),
        )
        online_hosts = [host for host in hosts if host_is_live(host)]
        reasons: list[str] = []
        if not agents.data:
            reasons.append("agent_catalog_empty")
        if not online_hosts:
            reasons.append("no_online_host")
        response.status_code = 200 if not reasons else 503
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "ready": not reasons,
            "workspace_id": runtime.physical_workspace_id,
            "agent_catalog_available": bool(agents.data),
            "online_host_count": len(online_hosts),
            "reasons": reasons,
        }

    return router


__all__ = ["TenantAgentCatalogInitializer", "create_execution_readiness_router"]
