from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import threading
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from omnigent.onboarding.provider_config import _loopback_transport_url
from saas.production.platform_model_relay import PlatformModelRelay
from saas.runner_adapter.platform_model_gateway import (
    PlatformModelGatewayTokenAuthority,
    PlatformModelGatewayTokenError,
    PlatformModelGatewayTokenExpired,
)
from saas.runner_adapter.platform_models import PLATFORM_MODEL_RELAY_BASE_URL_ENV


def _authority():
    return PlatformModelGatewayTokenAuthority(signing_key=b"s" * 32, tenant_id=uuid4())


def _relay(handler, *, clock=lambda: 1000):
    authority = _authority()
    relay = PlatformModelRelay(
        authority=authority,
        session_id=uuid4(),
        ttl_seconds=28800,
        clock=clock,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    return relay, authority


def _success():
    return httpx.Response(200, stream=httpx.ByteStream(b'data: {"done":true}\n\n'))


def _expired():
    return httpx.Response(401, json={"error": {"code": "platform_model_authentication_expired"}})


def test_default_token_lifetime_is_eight_hours_and_expiry_is_specific():
    authority = _authority()
    token = authority.issue(session_id=uuid4(), now=1000)
    claims = authority.validate(token, now=1000)
    assert claims.expires_at - claims.issued_at == 28800
    with pytest.raises(PlatformModelGatewayTokenExpired):
        authority.validate(token, now=29800)
    with pytest.raises(PlatformModelGatewayTokenError) as error:
        authority.validate(token + "tampered", now=29800)
    assert not isinstance(error.value, PlatformModelGatewayTokenExpired)


def test_long_lived_agent_uses_new_bearer_before_expiry_without_env_changes():
    now = [1000]
    outbound = []

    def upstream(request):
        outbound.append(request.headers["authorization"].removeprefix("Bearer "))
        return _success()

    relay, authority = _relay(upstream, clock=lambda: now[0])
    with TestClient(relay.app) as client:
        headers = {"Authorization": f"Bearer {relay.capability}"}
        assert client.post("/v1/responses", headers=headers, json={}).status_code == 200
        now[0] = 29501  # Inside the five-minute pre-expiry renewal window.
        assert client.post("/v1/responses", headers=headers, json={}).status_code == 200
        assert len(set(outbound)) == 2
        claims = authority.validate(outbound[-1], now=now[0])
        assert claims.issued_at == now[0]
        assert claims.expires_at - claims.issued_at == 28800
        now[0] = 90000  # Also recovers after an idle interval exceeding a token lifetime.
        assert client.post("/v1/responses", headers=headers, json={}).status_code == 200
        assert authority.validate(outbound[-1], now=now[0]).issued_at == now[0]


@pytest.mark.parametrize("route", ["/v1/responses", "/v1/chat/completions"])
def test_explicit_expiry_retries_only_identical_http_request_once(route):
    requests = []

    def upstream(request):
        requests.append(request)
        return _expired() if len(requests) == 1 else _success()

    relay, _ = _relay(upstream)
    with TestClient(relay.app) as client:
        result = client.post(
            route,
            headers={"Authorization": f"Bearer {relay.capability}"},
            json={"model": "allowed-model", "input": "never restart this task"},
        )
    assert result.status_code == 200
    assert result.content == b'data: {"done":true}\n\n'
    assert len(requests) == 2
    assert requests[0].content == requests[1].content
    assert requests[0].url == requests[1].url
    assert all(relay.capability not in str(request.headers) for request in requests)


def test_ambiguous_network_failure_is_not_retried():
    requests = []

    def upstream(request):
        requests.append(request)
        raise httpx.ReadTimeout("provider outcome unknown")

    relay, _ = _relay(upstream)
    with TestClient(relay.app) as client:
        response = client.post(
            "/v1/responses", headers={"Authorization": f"Bearer {relay.capability}"}, json={}
        )
    assert response.status_code == 502
    assert len(requests) == 1


def test_started_stream_is_never_replayed():
    requests = []

    class PartialStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"delta":"already delivered"}\n\n'
            raise httpx.ReadError("stream interrupted")

    def upstream(request):
        requests.append(request)
        return httpx.Response(200, stream=PartialStream())

    relay, _ = _relay(upstream)
    with TestClient(relay.app) as client:
        with pytest.raises(httpx.ReadError):
            client.post(
                "/v1/responses", headers={"Authorization": f"Bearer {relay.capability}"}, json={}
            )
    assert len(requests) == 1


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "platform_model_authentication_invalid"),
        (403, "denied"),
        (429, "budget_exhausted"),
        (502, "platform_model_provider_rejected"),
    ],
)
def test_other_rejections_are_not_refreshed_or_replayed(status, code):
    requests = []

    def upstream(request):
        requests.append(request)
        return httpx.Response(status, json={"error": {"code": code}})

    relay, _ = _relay(upstream)
    with TestClient(relay.app) as client:
        result = client.post(
            "/v1/responses", headers={"Authorization": f"Bearer {relay.capability}"}, json={}
        )
    assert result.status_code == status
    assert len(requests) == 1


def test_second_expiry_fails_closed_without_login_hint_or_third_request():
    requests = []

    def upstream(request):
        requests.append(request)
        return _expired()

    relay, _ = _relay(upstream)
    with TestClient(relay.app) as client:
        result = client.post(
            "/v1/responses", headers={"Authorization": f"Bearer {relay.capability}"}, json={}
        )
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "platform_model_authentication_recovery_failed"
    assert "codex login" not in result.text
    assert len(requests) == 2


def test_local_capability_and_frozen_routes_are_required():
    requests = []

    def upstream(request):
        requests.append(request)
        return _success()

    relay, _ = _relay(upstream)
    with TestClient(relay.app) as client:
        assert client.post("/v1/responses", json={}).status_code == 403
        assert (
            client.post(
                "/v1/responses", headers={"Authorization": "Bearer foreign-session"}, json={}
            ).status_code
            == 403
        )
        assert client.post("/v1/renew", json={}).status_code == 404
        assert client.get("/v1/responses").status_code == 405
        assert (
            client.post(
                "/v1/responses",
                headers={"Authorization": f"Bearer {relay.capability}"},
                content=b"x" * (2 * 1024 * 1024 + 1),
            ).status_code
            == 413
        )
    assert not requests


@pytest.mark.asyncio
async def test_concurrent_expiry_rejections_share_one_renewal():
    gate = asyncio.Event()
    rejected = 0
    issued = []
    now = [1000]

    async def upstream(request):
        nonlocal rejected
        token = request.headers["authorization"].removeprefix("Bearer ")
        if token == issued[0]:
            rejected += 1
            if rejected == 2:
                now[0] += 1
                gate.set()
            await gate.wait()
            return _expired()
        return _success()

    relay, authority = _relay(upstream, clock=lambda: now[0])
    issue = authority.issue

    def counted_issue(**kwargs):
        token = issue(**kwargs)
        issued.append(token)
        return token

    authority.issue = counted_issue
    async with relay.app.router.lifespan_context(relay.app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=relay.app), base_url="http://runner"
        ) as client:
            results = await asyncio.gather(
                *(
                    client.post(
                        "/v1/responses",
                        headers={"Authorization": f"Bearer {relay.capability}"},
                        json={},
                    )
                    for _ in range(2)
                )
            )
    assert all(result.status_code == 200 for result in results)
    assert len(issued) == 2


@pytest.mark.asyncio
async def test_blocking_remote_credential_issuer_does_not_block_the_relay_event_loop():
    authority = _authority()
    released = threading.Event()
    loop_thread = threading.get_ident()

    class RemoteIssuer:
        def issue(self, **kwargs):
            assert threading.get_ident() != loop_thread
            assert released.wait(1), "relay event loop could not release the HTTP issuer"
            return authority.issue(**kwargs)

    relay = PlatformModelRelay(authority=RemoteIssuer(), session_id=uuid4(), ttl_seconds=300)
    asyncio.get_running_loop().call_later(0.02, released.set)
    async with relay.app.router.lifespan_context(relay.app):
        assert await relay.credentials.token_for_request()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://example.com/v1",
        "http://127.0.0.1:80/other",
        "http://user@127.0.0.1:80/v1",
        "http://[::1]:80/v1",
        "http://127.0.0.1:80/v1?forward=evil",
    ],
)
def test_transport_override_rejects_noncanonical_endpoints(monkeypatch, endpoint):
    monkeypatch.setenv(
        PLATFORM_MODEL_RELAY_BASE_URL_ENV, json.dumps({"platform-deepseek": {"openai": endpoint}})
    )
    with pytest.raises(ValueError, match="Host provider transport"):
        _loopback_transport_url("platform-deepseek", "openai", "http://gateway/v1")


def test_relay_is_revoked_when_runner_exits():
    relay, _ = _relay(lambda request: _success())
    done = threading.Event()

    class Process:
        def wait(self):
            done.wait(5)
            return 0

    endpoint = relay.start()
    try:
        relay.follow(Process())
        with httpx.Client(trust_env=False) as client:
            assert (
                client.post(
                    f"{endpoint}/responses",
                    headers={"Authorization": f"Bearer {relay.capability}"},
                    json={},
                ).status_code
                == 200
            )
        done.set()
        relay._thread.join(5)
        assert not relay._thread.is_alive()
    finally:
        done.set()
        relay.close()


def test_child_process_with_frozen_credentials_survives_gateway_token_renewal():
    now = [1000]
    tokens = []

    def upstream(request):
        tokens.append(request.headers["authorization"].removeprefix("Bearer "))
        return _success()

    relay, authority = _relay(upstream, clock=lambda: now[0])
    endpoint = relay.start()
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import os, sys, httpx
headers = {"Authorization": "Bearer " + os.environ["MODEL_CHANNEL_CAPABILITY"]}
with httpx.Client(trust_env=False, timeout=5) as client:
    for _ in sys.stdin:
        result = client.post(sys.argv[1] + "/responses", headers=headers, json={})
        print(result.status_code, flush=True)
""",
            endpoint,
        ],
        env={"MODEL_CHANNEL_CAPABILITY": relay.capability},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        relay.follow(child)
        assert child.stdin is not None and child.stdout is not None
        for moment in (1000, 29501, 90000):
            now[0] = moment
            child.stdin.write("next request\n")
            child.stdin.flush()
            assert child.stdout.readline().strip() == "200"
            assert authority.validate(tokens[-1], now=moment).expires_at > moment
        assert len(set(tokens)) == 3
        assert all(token != relay.capability for token in tokens)
        child.stdin.close()
        assert child.wait(timeout=10) == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        relay.close()
