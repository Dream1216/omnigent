"""Frozen Host/Sandbox selection carried with an interactive Run."""

from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from omnigent.entities import Conversation
from omnigent.harness_aliases import canonicalize_harness
from omnigent.server.managed_hosts import parse_repo_workspace
from saas.control_plane.interactive_run_route import InteractiveRunRouteError

MANAGED_LAUNCH_SNAPSHOT_KEY = "managed_launch"
_ID = re.compile(r"^[0-9a-f]{32}$")


def decode_interactive_launch(value: object) -> dict[str, Any]:
    """Accept the closed intent, not an arbitrary command or provider override."""
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "host_type",
        "host_id",
        "sandbox_provider",
        "workspaces",
        "workspace",
        "git_branch",
        "agent_id",
        "harness",
        "reasoning_effort",
        "terminal_launch_args",
    }:
        raise InteractiveRunRouteError("interactive_launch_invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["host_type"] not in ("external", "managed")
        or not isinstance(value["agent_id"], str)
        or _ID.fullmatch(value["agent_id"]) is None
        or not isinstance(value["harness"], str)
        or not 1 <= len(value["harness"]) <= 128
        or not isinstance(value["workspaces"], list)
        or len(value["workspaces"]) > 10
    ):
        raise InteractiveRunRouteError("interactive_launch_invalid")
    for key in ("workspace", "git_branch", "reasoning_effort"):
        item = value[key]
        if item is not None and (
            not isinstance(item, str) or not item or len(item) > 4096 or "\x00" in item
        ):
            raise InteractiveRunRouteError("interactive_launch_invalid")
    args = value["terminal_launch_args"]
    if args is not None and (
        not isinstance(args, list)
        or len(args) > 128
        or any(not isinstance(arg, str) or len(arg) > 4096 or "\x00" in arg for arg in args)
    ):
        raise InteractiveRunRouteError("interactive_launch_invalid")
    if value["host_type"] == "external":
        if (
            not isinstance(value["host_id"], str)
            or _ID.fullmatch(value["host_id"]) is None
            or value["sandbox_provider"] is not None
            or value["workspaces"]
            or not isinstance(value["workspace"], str)
            or not (
                PurePosixPath(value["workspace"]).is_absolute()
                or PureWindowsPath(value["workspace"]).is_absolute()
            )
        ):
            raise InteractiveRunRouteError("interactive_launch_invalid")
    else:
        provider = value["sandbox_provider"]
        if (
            value["host_id"] is not None
            or not isinstance(provider, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", provider) is None
            or value["workspace"] is not None
            or value["git_branch"] is not None
        ):
            raise InteractiveRunRouteError("interactive_launch_invalid")
        for repo in value["workspaces"]:
            if not isinstance(repo, str) or len(repo) > 4096:
                raise InteractiveRunRouteError("interactive_launch_invalid")
            try:
                parse_repo_workspace(repo)
            except ValueError:
                raise InteractiveRunRouteError("interactive_launch_invalid") from None
    return value


def interactive_conversation_launch(conversation: Conversation) -> dict[str, Any]:
    """Reject mutations rather than retarget an already accepted launch."""
    launch = decode_interactive_launch(
        (conversation.inference_snapshot or {}).get(MANAGED_LAUNCH_SNAPSHOT_KEY)
    )
    if (
        launch["agent_id"] != conversation.agent_id
        or (
            conversation.harness_override is not None
            and canonicalize_harness(launch["harness"])
            != canonicalize_harness(conversation.harness_override)
        )
        or launch["reasoning_effort"] != conversation.reasoning_effort
        or launch["terminal_launch_args"] != conversation.terminal_launch_args
        or (
            launch["host_type"] == "external"
            and (
                launch["host_id"] != conversation.host_id
                or launch["workspace"] != conversation.workspace
                or launch["git_branch"] != conversation.git_branch
            )
        )
    ):
        raise InteractiveRunRouteError("interactive_launch_changed")
    return launch
