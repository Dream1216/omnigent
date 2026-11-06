from __future__ import annotations

import asyncio
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from saas.production.aliyun_model_ingress import MODEL_INGRESS_BASE_PATH, AliyunModelIngress
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority
from saas.runner_adapter.platform_models import PLATFORM_MODEL_GATEWAY_BASE_URL


def _case(handler, *, now=None, follow_redirects=False):
    current = [1000.0] if now is None else now
    authority = PlatformModelGatewayTokenAuthority(signing_key=b"k" * 32, tenant_id=uuid4())
    ingress = AliyunModelIngress(
        {authority.tenant_id: authority},
        clock=lambda: current[0],
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=follow_redirects
        ),
    )
    app = FastAPI()
    app.include_router(ingress.router(), prefix="/saas")
    token = authority.issue(session_id=uuid4(), ttl_seconds=300, now=1000)
    return app, ingress, authority, token, current


def _success(**headers):
    return httpx.Response(
        200,
        headers={"Content-Type": "text/event-stream", **headers},
        stream=httpx.ByteStream(b'data: {"done":true}\n\n'),
    )


@pytest.mark.parametrize("route", ["responses", "chat/completions"])
def test_only_model_bearer_and_exact_body_reach_the_fixed_internal_gateway(route):
    requests = []

    def upstream(request):
        requests.append(request)
        return _success(**{"Set-Cookie": "private=secret", "X-Internal": "private"})

    app, _, _, token, _ = _case(upstream)
    with TestClient(app) as client:
        result = client.post(
            f"{MODEL_INGRESS_BASE_PATH}/{route}",
            headers={"Authorization": f"Bearer {token}", "X-Untrusted": "not-forwarded"},
            json={"model": "allowed", "stream": True},
        )
    assert result.status_code == 200
    assert result.content == b'data: {"done":true}\n\n'
    assert result.headers["cache-control"] == "no-store"
    assert result.headers["x-accel-buffering"] == "no"
    assert "set-cookie" not in result.headers and "x-internal" not in result.headers
    assert len(requests) == 1
    request = requests[0]
    assert str(request.url) == f"{PLATFORM_MODEL_GATEWAY_BASE_URL}/{route}"
    assert request.headers["authorization"] == f"Bearer {token}"
    assert "x-untrusted" not in request.headers and "cookie" not in request.headers
    assert request.content == b'{"model":"allowed","stream":true}'


@pytest.mark.parametrize(
    "extra",
    [
        {"Cookie": "session=browser"},
        {"Origin": "https://browser.example"},
        {"X-Omnigent-Host-Token": "host"},
        {"X-Omnigent-Model-Lease": "lease"},
        {"X-Omnigent-Workspace-Id": "41"},
        {"X-Omnigent-Runner-Tunnel-Token": "runner"},
    ],
)
def test_mixed_browser_and_machine_credentials_never_reach_gateway(extra):
    calls = []
    app, _, _, token, _ = _case(lambda request: calls.append(request) or _success())
    with TestClient(app) as client:
        result = client.post(
            f"{MODEL_INGRESS_BASE_PATH}/responses",
            headers={"Authorization": f"Bearer {token}", **extra},
            json={},
        )
    assert result.status_code == 401
    assert calls == []


@pytest.mark.parametrize("kind", ["missing", "tampered", "foreign", "long", "duplicate"])
def test_invalid_or_non_cloud_token_is_rejected_before_forwarding(kind):
    calls = []
    app, _, authority, token, _ = _case(lambda request: calls.append(request) or _success())
    if kind == "tampered":
        token += "changed"
    elif kind == "foreign":
        token = PlatformModelGatewayTokenAuthority(signing_key=b"f" * 32, tenant_id=uuid4()).issue(
            session_id=uuid4(), ttl_seconds=300, now=1000
        )
    elif kind == "long":
        token = authority.issue(session_id=uuid4(), ttl_seconds=301, now=1000)
    headers = [] if kind == "missing" else [("Authorization", f"Bearer {token}")]
    if kind == "duplicate":
        headers *= 2
    with TestClient(app) as client:
        result = client.post(f"{MODEL_INGRESS_BASE_PATH}/responses", headers=headers, json={})
    assert result.status_code == 401
    assert result.json()["error"]["code"] == "platform_model_authentication_invalid"
    assert calls == []


def test_expired_scoped_token_gets_a_pre_admission_expiry_without_gateway_call():
    calls = []
    app, _, _, token, now = _case(lambda request: calls.append(request) or _success())
    now[0] = 1300
    with TestClient(app) as client:
        result = client.post(
            f"{MODEL_INGRESS_BASE_PATH}/responses",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
    assert result.status_code == 401
    assert result.json()["error"]["code"] == "platform_model_authentication_expired"
    assert calls == []


@pytest.mark.parametrize("kind", ["query", "type", "oversize"])
def test_request_limits_are_enforced_before_forwarding(kind):
    calls = []
    app, _, _, token, _ = _case(lambda request: calls.append(request) or _success())
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if kind == "type":
        headers["Content-Type"] = "application/octet-stream"
    path = f"{MODEL_INGRESS_BASE_PATH}/responses" + (
        "?target=elsewhere" if kind == "query" else ""
    )
    with TestClient(app) as client:
        result = client.post(
            path,
            headers=headers,
            content=b"x" * (2 * 1024 * 1024 + 1) if kind == "oversize" else b"{}",
        )
    assert result.status_code == {"query": 401, "type": 400, "oversize": 413}[kind]
    assert calls == []


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_cannot_export_bearers_even_if_injected_client_follows_redirects(status):
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(status, headers={"Location": "https://untrusted.example/"})

    app, _, _, token, _ = _case(upstream, follow_redirects=True)
    with TestClient(app) as client:
        result = client.post(
            f"{MODEL_INGRESS_BASE_PATH}/responses",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
    assert result.status_code == 502
    assert len(calls) == 1
    assert "location" not in result.headers


@pytest.mark.parametrize("exception", [httpx.ReadTimeout("unknown"), TimeoutError("deadline")])
def test_ambiguous_failure_is_not_replayed_or_labelled_pre_admission_expiry(exception):
    calls = []

    def upstream(request):
        calls.append(request)
        raise exception

    app, _, _, token, _ = _case(upstream)
    with TestClient(app) as client:
        result = client.post(
            f"{MODEL_INGRESS_BASE_PATH}/responses",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
    assert result.status_code == 502
    assert result.json()["error"]["code"] != "platform_model_authentication_expired"
    assert len(calls) == 1


@pytest.mark.parametrize("expired", [True, False])
def test_only_explicit_gateway_expiry_is_preserved_without_retry(expired):
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(
            401,
            json={
                "error": {"code": "platform_model_authentication_expired" if expired else "secret"}
            },
        )

    app, _, _, token, _ = _case(upstream)
    with TestClient(app) as client:
        result = client.post(
            f"{MODEL_INGRESS_BASE_PATH}/responses",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
    assert result.status_code == 401
    assert result.json()["error"]["code"] == (
        "platform_model_authentication_expired"
        if expired
        else "platform_model_authentication_invalid"
    )
    assert b"secret" not in result.content
    assert len(calls) == 1


@pytest.mark.parametrize("status", [400, 403, 409, 413, 429, 502, 503])
def test_gateway_rejections_preserve_status_without_exporting_private_error_body(status):
    app, _, _, token, _ = _case(lambda _: httpx.Response(status, json={"internal": "secret"}))
    with TestClient(app) as client:
        result = client.post(
            f"{MODEL_INGRESS_BASE_PATH}/responses",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
    assert result.status_code == status
    assert b"secret" not in result.content


def test_large_internal_errors_are_bounded():
    app, _, _, token, _ = _case(lambda _: httpx.Response(429, content=b"s" * 16385))
    with TestClient(app) as client:
        result = client.post(
            f"{MODEL_INGRESS_BASE_PATH}/responses",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
    assert result.status_code == 502
    assert len(result.content) < 256


def test_stream_is_closed_at_token_expiry_without_forwarding_more_output():
    now = [1000.0]
    closed = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"data: first\n\n"
            now[0] = 1300
            yield b"data: after-expiry\n\n"

        async def aclose(self):
            closed.append(True)

    app, _, _, token, _ = _case(
        lambda _: httpx.Response(
            200, headers={"Content-Type": "text/event-stream"}, stream=Stream()
        ),
        now=now,
    )
    with TestClient(app) as client:
        with pytest.raises(RuntimeError, match="Model stream interrupted"):
            client.post(
                f"{MODEL_INGRESS_BASE_PATH}/responses",
                headers={"Authorization": f"Bearer {token}"},
                json={},
            )
    assert closed == [True]


@pytest.mark.parametrize("error", [httpx.ReadError("private transport detail"), TimeoutError()])
def test_partial_stream_failure_aborts_without_replay_or_private_error_detail(error):
    calls, closed = [], []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"data: first\n\n"
            raise error

        async def aclose(self):
            closed.append(True)

    def upstream(request):
        calls.append(request)
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=Stream())

    app, _, _, token, _ = _case(upstream)
    with TestClient(app) as client:
        with pytest.raises(RuntimeError, match="Model stream interrupted") as raised:
            client.post(
                f"{MODEL_INGRESS_BASE_PATH}/responses",
                headers={"Authorization": f"Bearer {token}"},
                json={},
            )
    assert "private transport detail" not in str(raised.value)
    assert token not in str(raised.value)
    assert len(calls) == 1 and closed == [True]


@pytest.mark.asyncio
async def test_client_disconnect_closes_upstream_and_client():
    stream_closed = asyncio.Event()
    client_closed = asyncio.Event()
    disconnect = asyncio.Event()

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"data: first\n\n"
            await asyncio.Event().wait()

        async def aclose(self):
            stream_closed.set()

    class Client(httpx.AsyncClient):
        async def aclose(self):
            await super().aclose()
            client_closed.set()

    _, ingress, _, token, _ = _case(lambda _: _success())
    ingress._client_factory = lambda: Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, headers={"Content-Type": "text/event-stream"}, stream=Stream()
            )
        )
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": f"{MODEL_INGRESS_BASE_PATH}/responses",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {token}".encode()),
            (b"content-type", b"application/json"),
        ],
        "asgi": {"spec_version": "2.3"},
    }
    body_read = False

    async def receive():
        nonlocal body_read
        if not body_read:
            body_read = True
            return {"type": "http.request", "body": b"{}", "more_body": False}
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == "http.response.body" and message.get("body"):
            disconnect.set()

    response = await ingress.proxy(Request(scope, receive), path="responses")
    await asyncio.wait_for(response(scope, receive, send), timeout=2)
    assert stream_closed.is_set() and client_closed.is_set()
