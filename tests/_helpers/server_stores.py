"""Fixed seeding operations for an isolated local server's own schema."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tests._helpers.compat import apply_server_env, compat_server_cwd, server_executable


def _store_result(database_uri: str, body: str, payload: dict[str, Any]) -> Any:
    """Run a fixed native operation; never accept a network database or SQL."""
    prefix = "sqlite:///"
    if not database_uri.startswith(prefix):
        raise ValueError("fixture store requires the spawned server's local SQLite database")
    database = database_uri.removeprefix(prefix)
    if not Path(database).is_absolute() or "?" in database or "#" in database:
        raise ValueError("fixture store requires an absolute local SQLite database")
    code = (
        "import contextlib, json, sys\n"
        "p = json.load(sys.stdin)\n"
        "with contextlib.redirect_stdout(sys.stderr):\n"
        + textwrap.indent(textwrap.dedent(body).strip() + "\n", "    ")
        + "print(json.dumps(result))\n"
    )
    completed = subprocess.run(
        [server_executable(), "-c", code],
        input=json.dumps({**payload, "database_uri": database_uri}),
        env=apply_server_env(dict(os.environ), Path(__file__).resolve().parents[2]),
        cwd=compat_server_cwd(),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(completed.stdout)


def append_server_items(
    database_uri: str, session_id: str, items: list[Any], *, at_epoch: int | None = None
) -> None:
    """Append unchanged items, optionally retaining a caller's scoped append clock."""
    _store_result(
        database_uri,
        """
        from contextlib import nullcontext
        from unittest.mock import patch
        from omnigent.entities import NewConversationItem
        from omnigent.stores.conversation_store import sqlalchemy_store
        store = sqlalchemy_store.SqlAlchemyConversationStore(p['database_uri'])
        clock = (nullcontext() if p['at_epoch'] is None else
                 patch.object(sqlalchemy_store, 'now_epoch', return_value=p['at_epoch']))
        with clock:
            store.append(
                p['session_id'], [NewConversationItem.model_validate(x) for x in p['items']]
            )
        result = None
        """,
        {
            "session_id": session_id,
            "items": [item.model_dump(mode="json") for item in items],
            "at_epoch": at_epoch,
        },
    )


def set_server_task_summary(database_uri: str, session_id: str, task_summary: str) -> None:
    """Set the existing fixture session's task-derived title."""
    _store_result(
        database_uri,
        """
        from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
        SqlAlchemyConversationStore(p['database_uri']).set_task_summary(
            p['session_id'], p['summary']
        )
        result = None
        """,
        {"session_id": session_id, "summary": task_summary},
    )


def set_server_usage(database_uri: str, session_id: str, usage: dict[str, Any]) -> None:
    """Seed usage with the selected server's original Store API."""
    _store_result(
        database_uri,
        """
        from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
        SqlAlchemyConversationStore(p['database_uri']).set_session_usage(
            p['session_id'], p['usage']
        )
        result = None
        """,
        {"session_id": session_id, "usage": usage},
    )


@dataclass(frozen=True)
class FixtureConversationIdentity:
    id: str
    agent_id: str | None


def get_server_conversation(
    database_uri: str, session_id: str
) -> FixtureConversationIdentity | None:
    """Return only the real native conversation identity needed for fixture setup."""
    value = _store_result(
        database_uri,
        """
        from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
        row = SqlAlchemyConversationStore(p['database_uri']).get_conversation(p['session_id'])
        result = None if row is None else {'id': row.id, 'agent_id': row.agent_id}
        """,
        {"session_id": session_id},
    )
    return None if value is None else FixtureConversationIdentity(**value)


def update_server_conversation(
    database_uri: str, session_id: str, *, title: str | None = None, archived: bool | None = None
) -> None:
    """Update only the title/archive fields used by the usage fixture."""
    changes: dict[str, Any] = {}
    if title is not None:
        changes["title"] = title
    if archived is not None:
        changes["archived"] = archived
    _store_result(
        database_uri,
        """
        from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
        SqlAlchemyConversationStore(p['database_uri']).update_conversation(
            p['session_id'], **p['changes']
        )
        result = None
        """,
        {"session_id": session_id, "changes": changes},
    )


def create_server_subagent(
    database_uri: str, *, agent_id: str | None, parent_conversation_id: str
) -> FixtureConversationIdentity:
    """Create the same native sub-agent row and return its actual identity."""
    value = _store_result(
        database_uri,
        """
        from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
        row = SqlAlchemyConversationStore(p['database_uri']).create_conversation(
            agent_id=p['agent_id'], kind='sub_agent', parent_conversation_id=p['parent_id'])
        result = {'id': row.id, 'agent_id': row.agent_id}
        """,
        {"agent_id": agent_id, "parent_id": parent_conversation_id},
    )
    return FixtureConversationIdentity(**value)


def delete_server_agent(database_uri: str, agent_id: str) -> bool:
    """Return the selected server Store's real deletion result."""
    value = _store_result(
        database_uri,
        """
        from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
        result = SqlAlchemyAgentStore(p['database_uri']).delete(p['agent_id'])
        """,
        {"agent_id": agent_id},
    )
    if type(value) is not bool:
        raise TypeError("native AgentStore.delete did not return a bool")
    return value
