"""Keep standalone Agent installs outside the initial production rollout."""

from __future__ import annotations

from typing import Any, cast

from omnigent.stores import AgentStore


class _SessionAgentStore:
    def __init__(self, store: AgentStore) -> None:
        self._store = store

    @property
    def supports_user_agents(self) -> bool:
        # Unbound user agents need an N-1 owner check before installs can open.
        return False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)


def disable_standalone_agent_installs(store: AgentStore) -> AgentStore:
    """Preserve session/builtin operations while disabling the install capability."""
    return cast(AgentStore, _SessionAgentStore(store))
