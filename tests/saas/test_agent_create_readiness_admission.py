"""Session-create admission against managed Host readiness reports."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from omnigent.errors import OmnigentError
from omnigent.harness_availability import HarnessAvailability
from omnigent.server.routes._session_harness_readiness import (
    validate_create_harness_readiness,
)
from omnigent.server.routes._sessions.orchestration import (
    _reject_unavailable_harness_for_create,
)
from omnigent.server.schemas import SessionCreateRequest
from omnigent.stores.host_store import Host


def _host(
    readiness: dict[str, HarnessAvailability] | None,
    *,
    name: str = "managed-host",
    status: str = "online",
) -> Host:
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


class _HostStore:
    def __init__(self, host: Host) -> None:
        self.host = host

    def get_host(self, host_id: str) -> Host | None:
        return self.host if host_id == self.host.host_id else None


async def _validate(host: Host) -> None:
    await validate_create_harness_readiness(
        harness="kiro-native",
        host_id=host.host_id,
        parent_session_id=None,
        inherited_runner_id=None,
        user_id="alice",
        conversation_store=object(),  # type: ignore[arg-type]
        host_store=_HostStore(host),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_managed_create_rejects_target_host_missing_harness() -> None:
    with pytest.raises(OmnigentError, match="binary-missing"):
        await _validate(_host({"kiro-native": "binary-missing"}))


@pytest.mark.asyncio
async def test_managed_create_allows_host_auth_to_be_supplied_by_session() -> None:
    await _validate(_host({"kiro-native": "needs-auth"}))


@pytest.mark.asyncio
async def test_managed_create_rejects_any_online_host_reporting_missing_binary() -> None:
    hosts = [
        _host({"kiro-native": True}, name="ready"),
        _host({"kiro-native": "binary-missing"}, name="missing"),
        _host({"kiro-native": True}, name="old", status="offline"),
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
    with pytest.raises(OmnigentError, match="not configured"):
        await _reject_unavailable_harness_for_create(body, request, "alice", "kiro-native")


@pytest.mark.asyncio
async def test_managed_create_prefers_online_report_over_old_offline_failure() -> None:
    hosts = [
        _host({"kiro-native": True}, name="ready"),
        _host({"kiro-native": "binary-missing"}, name="old", status="offline"),
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
