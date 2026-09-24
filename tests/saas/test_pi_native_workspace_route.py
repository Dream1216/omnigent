from __future__ import annotations

import json
from pathlib import Path

import pytest

from omnigent.harnesses.pi_native.bridge import write_extension_files
from omnigent.runner.identity import (
    RUNNER_TUNNEL_WORKSPACE_HEADER,
    RUNNER_TUNNEL_WORKSPACE_ID_ENV_VAR,
)


def test_pi_extension_config_inherits_runner_workspace_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pi callbacks carry the managed Runner's physical workspace selector."""
    monkeypatch.setenv(RUNNER_TUNNEL_WORKSPACE_ID_ENV_VAR, "41")

    _extension, config_path = write_extension_files(
        tmp_path,
        session_id="conv_pi_workspace_route",
        server_url="https://next.example.test",
        conversation_url="https://next.example.test/c/conv_pi_workspace_route",
        auth_headers={"Authorization": "Bearer test"},
    )

    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["authHeaders"] == {
        "Authorization": "Bearer test",
        RUNNER_TUNNEL_WORKSPACE_HEADER: "41",
    }
