"""Unit tests for TCP transport helper functions (no subprocess spawning).

Tests the pure-logic helpers in ``omnigent.runner.transports.tcp``:
socket probing, port allocation, client factory, and subprocess
configuration — all without launching real uvicorn.
"""

from __future__ import annotations

import os
import socket
from unittest.mock import MagicMock, patch

import httpx
import pytest

from omnigent.runner.transports import tcp
from omnigent.runner.transports.tcp import (
    RunnerTCPSubprocess,
    _is_tcp_listening,
    _pick_free_port,
    create_tcp_client,
)

# ── _is_tcp_listening ───────────────────────────────────


def test_is_tcp_listening_returns_false_when_refused() -> None:
    """Connection-refused on a port that nothing is listening on."""
    # Port 1 is almost certainly not listening on localhost.
    assert _is_tcp_listening("127.0.0.1", 1) is False


def test_is_tcp_listening_returns_true_when_connected() -> None:
    """A bound TCP socket is detected as listening."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert _is_tcp_listening("127.0.0.1", port) is True
    finally:
        server.close()


def test_is_tcp_listening_returns_false_on_os_error() -> None:
    """OSError (e.g. network unreachable) is caught gracefully."""
    with patch("omnigent.runner.transports.tcp.socket.create_connection", side_effect=OSError):
        assert _is_tcp_listening("192.0.2.1", 9999) is False


# ── _pick_free_port ─────────────────────────────────────


def test_pick_free_port_returns_valid_port() -> None:
    """The OS allocates a port in the valid range."""
    port = _pick_free_port()
    assert 1 <= port <= 65535


def test_pick_free_port_returns_different_ports() -> None:
    """Successive calls generally return different ports."""
    ports = {_pick_free_port() for _ in range(5)}
    # With 5 calls, at least 2 should be distinct (astronomically unlikely otherwise).
    assert len(ports) >= 2


# ── create_tcp_client ───────────────────────────────────


@pytest.mark.asyncio
async def test_create_tcp_client_returns_async_client() -> None:
    """Factory returns a correctly-configured httpx.AsyncClient."""
    client = create_tcp_client("http://127.0.0.1:8080")
    try:
        assert isinstance(client, httpx.AsyncClient)
        assert str(client.base_url) == "http://127.0.0.1:8080"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_create_tcp_client_applies_auth_headers() -> None:
    """Auth headers are injected as defaults on the client."""
    client = create_tcp_client(
        "http://127.0.0.1:8080",
        auth_headers={"Authorization": "Bearer tok-test"},
    )
    try:
        assert client.headers["Authorization"] == "Bearer tok-test"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_create_tcp_client_without_auth_headers() -> None:
    """No auth headers means an empty default header dict."""
    client = create_tcp_client("http://127.0.0.1:8080")
    try:
        assert "Authorization" not in client.headers
    finally:
        await client.aclose()


# ── RunnerTCPSubprocess config ──────────────────────────


def test_runner_tcp_subprocess_base_url() -> None:
    """base_url builds correctly from host and port."""
    sub = RunnerTCPSubprocess(host="10.0.0.1", port=9090)
    assert sub.base_url == "http://10.0.0.1:9090"


def test_runner_tcp_subprocess_defaults() -> None:
    """Default field values are sensible."""
    sub = RunnerTCPSubprocess()
    assert sub.host == "127.0.0.1"
    assert sub.port == 0
    assert sub.startup_timeout_s == 30.0
    assert sub._process is None


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_spawn_transfers_the_owned_socket_and_waits_for_child_readiness(platform) -> None:
    listener = MagicMock()
    listener.__enter__.return_value = listener
    listener.getsockname.return_value = ("127.0.0.1", 43210)
    listener.fileno.return_value = 17
    listener.share.return_value = b"shared-owned-listener"
    process = MagicMock()
    process.poll.return_value = None
    stdin = process.stdin

    def spawn(*args, **kwargs):
        listener.bind.assert_called_once()
        if platform == "win32":
            listener.listen.assert_not_called()
        else:
            listener.listen.assert_called_once()
            os.write(kwargs["pass_fds"][1], b"1")
        return process

    with (
        patch.object(tcp.sys, "platform", platform),
        patch.object(tcp.socket, "SO_EXCLUSIVEADDRUSE", 4, create=True),
        patch.object(tcp.socket, "socket", return_value=listener),
        patch.object(tcp.subprocess, "Popen", side_effect=spawn) as popen,
        patch.object(tcp, "_is_tcp_listening", return_value=True),
    ):
        runner = RunnerTCPSubprocess().__enter__()
    assert runner.port == 43210
    listener.__exit__.assert_called_once()
    if platform == "win32":
        assert "pass_fds" not in popen.call_args.kwargs
        listener.share.assert_called_once_with(process.pid)
        stdin.write.assert_called_once_with(b"shared-owned-listener")
        stdin.close.assert_called_once()
        assert process.stdin is None
    else:
        assert popen.call_args.kwargs["pass_fds"][0] == 17
        assert len(popen.call_args.kwargs["pass_fds"]) == 2
        listener.share.assert_not_called()


def test_runner_tcp_subprocess_kill_noop_when_no_process() -> None:
    """_kill is safe to call before __enter__."""
    sub = RunnerTCPSubprocess()
    sub._kill()  # Should not raise.


def test_parent_listener_cannot_replace_the_child_startup_signal() -> None:
    listener = MagicMock()
    listener.__enter__.return_value = listener
    listener.getsockname.return_value = ("127.0.0.1", 43210)
    listener.fileno.return_value = 17
    process = MagicMock()
    process.poll.return_value = None
    runner = RunnerTCPSubprocess()
    with (
        patch.object(tcp.sys, "platform", "linux"),
        patch.object(tcp.socket, "socket", return_value=listener),
        patch.object(tcp.subprocess, "Popen", return_value=process),
        patch.object(tcp, "_is_tcp_listening", return_value=True),
        patch.object(tcp.time, "time", side_effect=[0, 1, 31]),
        patch.object(tcp.time, "sleep"),
        patch.object(runner, "_kill") as kill,
    ):
        with pytest.raises(TimeoutError, match=r"within 30\.0s"):
            runner.__enter__()
    listener.listen.assert_called_once()
    kill.assert_called_once()


def test_runner_tcp_subprocess_kill_noop_when_already_dead() -> None:
    """_kill handles an already-exited process gracefully."""
    sub = RunnerTCPSubprocess()
    mock_proc = MagicMock()
    mock_proc.poll.return_value = 0  # Already exited
    sub._process = mock_proc
    sub._kill()  # Should not raise or call killpg.


def test_runner_tcp_subprocess_exit_calls_kill() -> None:
    """__exit__ delegates to _kill."""
    sub = RunnerTCPSubprocess()
    mock_proc = MagicMock()
    mock_proc.poll.return_value = 0
    sub._process = mock_proc
    sub.__exit__(None, None, None)
    # Verify _kill was effectively invoked (poll was checked).
    mock_proc.poll.assert_called()
