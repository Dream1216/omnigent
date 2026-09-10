"""Contracts for the thin official-code bridge used by an external SaaS Host."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from omnigent.host.connect import HostProcess
from omnigent.host.identity import (
    HOST_TOKEN_ENV_VAR,
    HOST_TOKEN_FILE_ENV_VAR,
    HOST_WORKSPACE_ID_ENV_VAR,
    HostIdentity,
    load_host_tunnel_token,
    load_host_tunnel_workspace_id,
)
from omnigent.server.routes import host_tunnel
from omnigent.stores.host_store import HostStore


def _token_file(path: Path, value: str) -> Path:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_host_token_file_is_owner_only_exclusive_and_reread(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token_path = _token_file(tmp_path / "host-token", "first-secret\n")
    monkeypatch.delenv(HOST_TOKEN_ENV_VAR, raising=False)
    monkeypatch.setenv(HOST_TOKEN_FILE_ENV_VAR, str(token_path))

    assert load_host_tunnel_token() == "first-secret"
    _token_file(token_path, "rotated-secret\n")
    assert load_host_tunnel_token() == "rotated-secret"

    token_path.chmod(0o640)
    with pytest.raises(ValueError, match="owner-only"):
        load_host_tunnel_token()

    token_path.chmod(0o600)
    monkeypatch.setenv(HOST_TOKEN_ENV_VAR, "ambiguous-secret")
    with pytest.raises(ValueError, match="set only one"):
        load_host_tunnel_token()


def test_host_token_file_refuses_symlink(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = _token_file(tmp_path / "target", "file-secret")
    link = tmp_path / "host-token"
    link.symlink_to(target)
    monkeypatch.delenv(HOST_TOKEN_ENV_VAR, raising=False)
    monkeypatch.setenv(HOST_TOKEN_FILE_ENV_VAR, str(link))

    with pytest.raises(OSError):
        load_host_tunnel_token()


@pytest.mark.parametrize("value", ["", "0", "01", "+1", "-1", " 1", "1 ", "１"])
def test_host_workspace_selector_requires_canonical_positive_integer(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(HOST_WORKSPACE_ID_ENV_VAR, value)
    with pytest.raises(ValueError, match="canonical positive integer"):
        load_host_tunnel_workspace_id()


def test_host_reconnect_rereads_file_and_never_mixes_bearer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token_path = _token_file(tmp_path / "host-token", "generation-one")
    monkeypatch.delenv(HOST_TOKEN_ENV_VAR, raising=False)
    monkeypatch.setenv(HOST_TOKEN_FILE_ENV_VAR, str(token_path))
    monkeypatch.setenv(HOST_WORKSPACE_ID_ENV_VAR, "260871827932501")
    monkeypatch.setattr(
        "omnigent.cli_auth.databricks_request_headers",
        lambda *_args, **_kwargs: {"Authorization": "Bearer must-not-survive"},
    )
    process = HostProcess(
        HostIdentity(host_id="ce5bb44730f64f47ac427f216e64bb33", name="beta-runner"),
        "https://next.jxhh.com",
    )

    first = process._build_connect_headers()
    _token_file(token_path, "generation-two")
    second = process._build_connect_headers()

    assert first["X-Omnigent-Host-Token"] == "generation-one"
    assert second["X-Omnigent-Host-Token"] == "generation-two"
    assert second["X-Omnigent-Workspace-Id"] == "260871827932501"
    assert "Authorization" not in first
    assert "Authorization" not in second
    assert process._current_auth_token() is None


@pytest.mark.asyncio
async def test_live_tunnel_closes_after_machine_credential_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Socket:
        closed: tuple[int, str] | None = None

        async def close(self, *, code: int, reason: str) -> None:
            self.closed = (code, reason)

    class _Store:
        def resolve_launch_token(self, host_id: str, token: str) -> None:
            assert host_id == "ce5bb44730f64f47ac427f216e64bb33"
            assert token == "revoked-secret"
            return

    socket = _Socket()
    monkeypatch.setattr(host_tunnel, "PING_INTERVAL_S", 0)
    await host_tunnel._ping_loop(
        socket,  # type: ignore[arg-type]
        SimpleNamespace(last_frame_at=time.time(), outbound_queue=asyncio.Queue()),
        "ce5bb44730f64f47ac427f216e64bb33",
        _Store(),  # type: ignore[arg-type]
        presented_host_token="revoked-secret",
    )

    assert socket.closed == (4004, "credential revoked or expired")


def test_launch_token_expires_at_exact_boundary(
    monkeypatch: pytest.MonkeyPatch, db_uri: str
) -> None:
    store = HostStore(db_uri)
    boundary = 1_800_000_000
    store.register_managed_host(
        host_id="9163189460484d4dbfed9c9176a4d8bf",
        name="external-expiry-boundary",
        user_id="runtime-beta",
        token="boundary-token",
        provider="external-test",
        sandbox_id="external-test",
        token_expires_at=boundary,
    )
    monkeypatch.setattr("omnigent.stores.host_store.now_epoch", lambda: boundary)

    assert store.resolve_launch_token("9163189460484d4dbfed9c9176a4d8bf", "boundary-token") is None
