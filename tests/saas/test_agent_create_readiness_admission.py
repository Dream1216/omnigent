"""Session-create admission against managed Host readiness reports."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from omnigent.errors import OmnigentError
from omnigent.server.routes._sessions.orchestration import (
    _reject_unavailable_harness_for_create,
)
from omnigent.server.schemas import SessionCreateRequest
from omnigent.stores.host_store import Host


def _host(name: str, status: str, readiness: dict[str, bool | str] | None) -> Host:
    return Host(
        host_id=name,
        name=name,
        user_id="alice",
        status=status,
        created_at=int(time.time()),
        updated_at=int(time.time()),
        sandbox_provider="agent_sandbox",
        configured_harnesses=readiness,
    )


@pytest.mark.asyncio
async def test_managed_create_rejects_any_online_host_reporting_unavailable() -> None:
    hosts = [
        _host("ready", "online", {"kiro-native": True}),
        _host("needs-login", "online", {"kiro-native": "needs-auth"}),
        _host("old", "offline", {"kiro-native": True}),
    ]
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                host_store=SimpleNamespace(list_hosts=lambda user_id: hosts),
                sandbox_config=SimpleNamespace(default=SimpleNamespace(provider="agent_sandbox")),
            )
        )
    )
    body = SessionCreateRequest(agent_id="agent", host_type="managed")
    with pytest.raises(OmnigentError, match="needs authentication"):
        await _reject_unavailable_harness_for_create(body, request, "alice", "kiro-native")


@pytest.mark.asyncio
async def test_managed_create_prefers_online_report_over_old_offline_failure() -> None:
    hosts = [
        _host("ready", "online", {"kiro-native": True}),
        _host("old", "offline", {"kiro-native": "needs-auth"}),
    ]
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                host_store=SimpleNamespace(list_hosts=lambda user_id: hosts),
                sandbox_config=SimpleNamespace(default=SimpleNamespace(provider="agent_sandbox")),
            )
        )
    )
    body = SessionCreateRequest(agent_id="agent", host_type="managed")
    await _reject_unavailable_harness_for_create(body, request, "alice", "kiro-native")


@pytest.mark.asyncio
async def test_managed_create_rejects_unresolvable_agent_bundle_before_a_session_exists() -> None:
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    body = SessionCreateRequest(agent_id="agent", host_type="managed")
    with pytest.raises(OmnigentError, match="Agent configuration is unavailable"):
        await _reject_unavailable_harness_for_create(body, request, "alice", None)
