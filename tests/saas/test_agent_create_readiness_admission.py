"""Session-create admission against managed Host readiness reports."""

from __future__ import annotations

import time

import pytest

from omnigent.errors import OmnigentError
from omnigent.harness_availability import HarnessAvailability
from omnigent.server.routes._session_harness_readiness import (
    validate_create_harness_readiness,
)
from omnigent.stores.host_store import Host


def _host(readiness: dict[str, HarnessAvailability] | None) -> Host:
    return Host(
        host_id="managed-host",
        name="managed-host",
        user_id="alice",
        status="online",
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
