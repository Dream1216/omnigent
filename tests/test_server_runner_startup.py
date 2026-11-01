"""Real startup collisions must not change an already-used fixture endpoint."""

import socket
from contextlib import closing

import httpx
import pytest

from tests._helpers.live_server import terminate_process
from tests._helpers.server_runner import ServerRunner, server_runner


def test_initial_server_reselects_after_a_real_bind_collision(tmp_path, monkeypatch):
    original_spawn = ServerRunner._spawn
    attempted_ports = []
    with closing(socket.socket()) as collider:

        def collide_once(stack, name, *args, **kwargs):
            if name == "server" and not attempted_ports:
                collider.bind(("127.0.0.1", stack.port))
                collider.listen()
                attempted_ports.append(stack.port)
            return original_spawn(stack, name, *args, **kwargs)

        monkeypatch.setattr(ServerRunner, "_spawn", collide_once)
        with server_runner(tmp_path / "stack", health_timeout=30, poll_interval=0.05) as stack:
            assert stack.port != attempted_ports[0]
            assert stack.server is not None and stack.server.poll() is None
            with httpx.Client(trust_env=False) as client:
                assert client.get(stack.base_url + "/health").status_code == 200
            assert "Address already in use" in stack.log_path("server").read_text()
        assert collider.getsockname()[1] == attempted_ports[0]


def test_unrelated_bootstrap_failure_is_not_retried(tmp_path, monkeypatch):
    original_spawn = ServerRunner._spawn
    started = []

    def observe(stack, name, *args, **kwargs):
        started.append(name)
        return original_spawn(stack, name, *args, **kwargs)

    monkeypatch.setattr(ServerRunner, "_spawn", observe)
    with pytest.raises(AssertionError, match="bootstrap sentinel"):
        with server_runner(
            tmp_path / "stack",
            server_bootstrap="raise RuntimeError('bootstrap sentinel')",
            health_timeout=30,
            poll_interval=0.05,
        ):
            pytest.fail("unexpected healthy server")
    assert started == ["server"]


def test_restart_bind_collision_keeps_the_existing_endpoint(tmp_path):
    with server_runner(tmp_path / "stack", health_timeout=30, poll_interval=0.05) as stack:
        endpoint, port = stack.base_url, stack.port
        terminate_process(stack.server)
        with closing(socket.socket()) as collider:
            collider.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            collider.bind(("127.0.0.1", port))
            collider.listen()
            with pytest.raises(AssertionError, match="Address already in use"):
                stack.restart_server()
            assert stack.base_url == endpoint
            assert stack.port == port
