"""Display caching must preserve workspace, revision, override and ACL boundaries."""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from omnigent.db.db_models import current_workspace_id, workspace_scope
from omnigent.server.auth import LEVEL_OWNER, UnifiedAuthProvider
from omnigent.server.routes import sessions as routes
from omnigent.stores.agent_store import sqlalchemy_store as agents_sql
from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore


@pytest.mark.asyncio
async def test_harness_cache_is_workspace_and_revision_scoped_and_never_grants_access(
    db_uri: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agents_sql, "now_epoch", lambda: 1)
    agents = agents_sql.SqlAlchemyAgentStore(db_uri)
    conversations = SqlAlchemyConversationStore(db_uri)
    permissions = SqlAlchemyPermissionStore(db_uri)
    agent_id = uuid4().hex
    ids = {}
    for workspace in (101, 202):
        with workspace_scope(workspace):
            agents.create(agent_id, "same-agent", "bundle/v1")
            conversation = conversations.create_conversation(agent_id=agent_id)
            permissions.grant("reader@example.com", conversation.id, LEVEL_OWNER)
            ids[workspace] = conversation.id
    resolved = []

    def resolve(conversation, **kwargs):
        agent = kwargs["agents_by_id"][conversation.agent_id]
        resolved.append((current_workspace_id(), agent.version, conversation.harness_override))
        return conversation.harness_override or (
            "claude-sdk"
            if agent.bundle_location == "bundle/v2"
            else "codex"
            if current_workspace_id() == 202
            else "openai-agents"
        )

    monkeypatch.setattr(routes, "_resolve_harness", resolve)
    app = FastAPI()
    app.include_router(
        routes.create_sessions_router(
            conversation_store=conversations,
            agent_store=agents,
            permission_store=permissions,
            auth_provider=UnifiedAuthProvider(source="header", local_single_user=False),
        ),
        prefix="/v1",
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:

        async def read(workspace):
            with workspace_scope(workspace):
                response = await client.get(
                    "/v1/sessions", headers={"X-Forwarded-Email": "reader@example.com"}
                )
            assert response.status_code == 200, response.text
            return response.json()["data"]

        for workspace, expected in ((101, "openai-agents"), (202, "codex")):
            assert (await read(workspace))[0]["harness"] == expected
            assert (await read(workspace))[0]["harness"] == expected
        assert len(resolved) == 2
        with workspace_scope(101):
            agents.update(agent_id, "bundle/v2")
        assert (await read(101))[0]["harness"] == "claude-sdk"
        assert len(resolved) == 3
        with workspace_scope(101):
            conversations.update_conversation(ids[101], harness_override="codex")
        assert (await read(101))[0]["harness"] == "codex"
        assert len(resolved) == 4
        with workspace_scope(101):
            permissions.revoke("reader@example.com", ids[101])
        assert await read(101) == []
        assert (await read(202))[0]["harness"] == "codex"
        assert len(resolved) == 4


@pytest.mark.asyncio
async def test_missing_harness_is_retried_and_repair_becomes_visible(
    db_uri: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    agents = agents_sql.SqlAlchemyAgentStore(db_uri)
    conversations = SqlAlchemyConversationStore(db_uri)
    agent = agents.create(uuid4().hex, "repair", "bundle/v1")
    conversation = conversations.create_conversation(agent_id=agent.id)
    permissions = SqlAlchemyPermissionStore(db_uri)
    permissions.grant("local", conversation.id, LEVEL_OWNER)
    state = {"calls": 0, "repaired": False}

    def resolve(*args, **kwargs):
        state["calls"] += 1
        return "openai-agents" if state["repaired"] else None

    monkeypatch.setattr(routes, "_resolve_harness", resolve)
    app = FastAPI()
    app.include_router(
        routes.create_sessions_router(
            conversation_store=conversations,
            agent_store=agents,
            permission_store=permissions,
            auth_provider=UnifiedAuthProvider(source="header", local_single_user=True),
        ),
        prefix="/v1",
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for _ in range(2):
            assert (await client.get("/v1/sessions")).json()["data"][0].get("harness") is None
        assert state["calls"] == 2
        state["repaired"] = True
        for _ in range(2):
            assert (await client.get("/v1/sessions")).json()["data"][0][
                "harness"
            ] == "openai-agents"
        assert state["calls"] == 3
