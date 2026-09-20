"""Managed Host daemon workspace-selector regression."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from omnigent.cli import _build_host_daemon_env
from omnigent.host.connect import _build_runner_env
from omnigent.host.identity import (
    HOST_WORKSPACE_ID_ENV_VAR,
    load_host_tunnel_workspace_id,
)
from omnigent.runner.identity import RUNNER_TUNNEL_WORKSPACE_ID_ENV_VAR


def test_managed_host_workspace_id_reaches_remote_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The managed partition selector survives both background process hops."""
    monkeypatch.setenv(HOST_WORKSPACE_ID_ENV_VAR, "260871827932501")

    daemon_env = _build_host_daemon_env(server_url="https://example.databricksapps.com")
    with patch.dict(os.environ, daemon_env, clear=True):
        workspace_id = load_host_tunnel_workspace_id()
    runner_env = _build_runner_env(
        daemon_env,
        server_url="https://example.databricksapps.com",
        runner_id="runner_workspace",
        binding_token="binding-workspace",
        workspace="/tmp/workspace",
        parent_pid=12345,
        workspace_id=workspace_id,
    )

    assert daemon_env[HOST_WORKSPACE_ID_ENV_VAR] == "260871827932501"
    assert runner_env[RUNNER_TUNNEL_WORKSPACE_ID_ENV_VAR] == "260871827932501"
