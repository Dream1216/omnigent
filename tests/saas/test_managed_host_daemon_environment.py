"""Retain the private managed Host workspace binding across CLI daemon startup."""

from __future__ import annotations

import pytest

from omnigent import cli
from omnigent.cli import _build_host_daemon_env


@pytest.fixture(autouse=True)
def _stable_current_host_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep daemon-reuse tests independent of the developer's real config."""
    monkeypatch.setattr(cli, "_load_existing_host_id", lambda: "host_abc")


def test_build_host_daemon_env_remote_preserves_host_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Remote daemon spawns must retain the requested host identity."""
    monkeypatch.setenv("OMNIGENT_HOST_ID", "d6d0ccebce7b4b706d21e23696bb462a")
    monkeypatch.setenv("OMNIGENT_HOST_NAME", "isolated-host")
    monkeypatch.setenv("OMNIGENT_HOST_TOKEN", "managed-token")
    monkeypatch.setenv("OMNIGENT_HOST_WORKSPACE_ID", "260871827932501")

    env = _build_host_daemon_env(server_url="https://example.databricksapps.com")

    assert env["OMNIGENT_HOST_ID"] == "d6d0ccebce7b4b706d21e23696bb462a"
    assert env["OMNIGENT_HOST_NAME"] == "isolated-host"
    assert env["OMNIGENT_HOST_TOKEN"] == "managed-token"
    assert env["OMNIGENT_HOST_WORKSPACE_ID"] == "260871827932501"
