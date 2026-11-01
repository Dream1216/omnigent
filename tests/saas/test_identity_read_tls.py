from __future__ import annotations

import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import httpx
import pytest

from saas.control_plane.identity_events import IdentitySyncError
from saas.control_plane.identity_private_channel import PrivateIdentityKeys
from saas.control_plane.identity_read_protocol import IDENTITY_READ_PATH
from saas.production.identity_process_config import IdentityProcessTls
from saas.production.identity_process_server import create_private_identity_server
from saas.production.identity_read_broker import (
    IdentityReadBrokerPins,
    create_identity_read_broker,
)
from saas.production.identity_read_client import IdentityReadClient, IdentityReadClientConfig
from tests.saas.test_identity_process_config import certificate
from tests.saas.test_identity_read_broker import HEADERS, REVISION, SECRET, SOURCE_LOCK, Reader
from tests.saas.test_identity_sync import ISSUER, SUBJECT


@contextmanager
def serve(tmp_path, *, concurrency=4, loopback_certificate=True):
    cert, key = certificate(tmp_path, loopback=loopback_certificate)
    context = ssl.create_default_context(cafile=cert)
    provider = Reader()
    pins = IdentityReadBrokerPins(ISSUER, "customers", REVISION, SOURCE_LOCK)
    app = create_identity_read_broker(
        provider, pins=pins, keys=PrivateIdentityKeys({"current": SECRET}), concurrency=concurrency
    )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(32)
    port = sock.getsockname()[1]
    server = create_private_identity_server(
        app, tls=IdentityProcessTls(cert, key), host="127.0.0.1", port=port
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            assert thread.is_alive(), "private identity server stopped during startup"
            assert time.monotonic() < deadline, "private identity TLS startup timed out"
            time.sleep(0.01)
        yield provider, pins, port, context
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "owned private identity server did not stop"


def client(pins, port, context):
    return IdentityReadClient(
        IdentityReadClientConfig(
            f"https://127.0.0.1:{port}", "current", SECRET, pins, tls_context=context
        ),
    )


def test_real_tls_read_channel_validates_owned_ca_and_rejects_provider_api_writes(tmp_path):
    with serve(tmp_path) as (provider, pins, port, context):
        assert client(pins, port, context).read_identity(SUBJECT) == provider.state
        with httpx.Client(verify=context, trust_env=False, timeout=5) as api:
            response = api.get(f"https://127.0.0.1:{port}/healthz")
            assert response.status_code == 200 and "server" not in response.headers
            response = api.post(
                f"https://127.0.0.1:{port}/api/update-user",
                json={"owner": "built-in"},
                headers=HEADERS,
            )
            assert response.status_code == 404
            response = api.get(
                f"https://127.0.0.1:{port}" + IDENTITY_READ_PATH,
                params={"subject": SUBJECT, "organization": "built-in"},
                headers=HEADERS,
            )
            assert response.status_code == 400
        assert provider.calls == [SUBJECT]


def test_untrusted_ca_or_plain_http_cannot_reach_identity_application(tmp_path):
    with serve(tmp_path) as (provider, pins, port, _context):
        with pytest.raises(IdentitySyncError, match="reader_unavailable"):
            client(pins, port, ssl.create_default_context()).read_identity(SUBJECT)
        with httpx.Client(timeout=5, trust_env=False) as api:
            with pytest.raises(httpx.HTTPError):
                api.get(
                    f"http://127.0.0.1:{port}" + IDENTITY_READ_PATH,
                    params={"subject": SUBJECT},
                    headers={**HEADERS, "X-Forwarded-Proto": "https"},
                )
        assert provider.calls == [] and provider.verifications == 0


def test_wrong_hostname_is_not_accepted_even_with_the_correct_ca(tmp_path):
    with serve(tmp_path, loopback_certificate=False) as (provider, pins, port, context):
        reader = IdentityReadClient(
            IdentityReadClientConfig(
                f"https://127.0.0.1:{port}", "current", SECRET, pins, tls_context=context
            )
        )
        with pytest.raises(IdentitySyncError, match="reader_unavailable"):
            reader.read_identity(SUBJECT)
        assert provider.calls == []


def test_authenticated_load_is_bounded_without_queueing_provider_credentials(tmp_path):
    with serve(tmp_path, concurrency=1) as (provider, pins, port, context):
        entered, release = threading.Event(), threading.Event()

        def block():
            entered.set()
            assert release.wait(10)

        provider.before_read = block
        with ThreadPoolExecutor(1) as pool:
            pending = pool.submit(client(pins, port, context).read_identity, SUBJECT)
            try:
                assert entered.wait(5)
                with httpx.Client(verify=context, trust_env=False, timeout=2) as api:
                    response = api.get(
                        f"https://127.0.0.1:{port}" + IDENTITY_READ_PATH,
                        params={"subject": SUBJECT},
                        headers=HEADERS,
                    )
                    assert (
                        response.status_code == 503
                        and response.json()["error"] == "identity_reader_busy"
                    )
                assert not pending.done()
            finally:
                release.set()
            assert pending.result(timeout=5) == provider.state
        assert provider.verifications == 1 and provider.calls == [SUBJECT]
