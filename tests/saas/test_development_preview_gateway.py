"""Exercise real gateway HTTP authorization and payload boundaries."""

import time
from contextlib import asynccontextmanager

import httpx
import pytest
from fastapi import HTTPException

from saas.production.development_preview import DevelopmentPreviewBroker
from tests.saas.test_development_preview import grants as grants
from tests.saas.test_development_preview import scope, seed_scope


@pytest.fixture
def gateway(grants):
    state = {"live": True, "forwarded": []}

    async def service(request):
        state["forwarded"].append(request)
        return httpx.Response(
            200,
            stream=httpx.ByteStream(b"<html>development app</html>"),
            headers={"content-type": "text/html", "set-cookie": "upstream=secret"},
        )

    transport = httpx.MockTransport(service)

    @asynccontextmanager
    async def live(_scope):
        if not state["live"]:
            raise HTTPException(403)
        async with httpx.AsyncClient(transport=transport, base_url="http://runner") as client:
            yield client

    broker = DevelopmentPreviewBroker(
        grants=grants,
        root_domain="preview.example.test",
        release_incarnation="f" * 32,
        primary_origin="https://app.example.test",
        principal=lambda _: None,
        live=live,
    )
    target = scope()
    seed_scope(grants, target)
    launch = grants.issue(target, int(time.time()) + 3600)
    return broker, target, launch, state


@pytest.mark.asyncio
async def test_gateway_exchange_is_origin_bound_post_once_and_strips_credentials(gateway):
    broker, target, launch, state = gateway
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=broker.gateway),
        base_url="https://" + broker.host(target.id),
    ) as client:
        assert (await client.get("/")).status_code == 403
        assert (
            await client.post(
                "/__omnigent/authorize",
                data={"token": launch},
                headers={"origin": "https://evil.example.test"},
            )
        ).status_code == 403
        response = await client.post(
            "/__omnigent/authorize",
            data={"token": launch},
            headers={"origin": broker.primary_origin},
        )
        assert response.status_code == 200
        assert 'content="0;url=/"' in response.text and launch not in response.text
        cookie = response.headers["set-cookie"]
        assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
        assert (
            await client.post(
                "/__omnigent/authorize",
                data={"token": launch},
                headers={"origin": broker.primary_origin},
            )
        ).status_code == 403
        response = await client.get(
            "/main.js?version=1", headers={"authorization": "Bearer platform-secret"}
        )
        assert response.status_code == 200 and response.text == "<html>development app</html>"
        assert "set-cookie" not in response.headers
        assert (
            "frame-ancestors https://app.example.test"
            in response.headers["content-security-policy"]
        )
        forwarded = state["forwarded"][-1]
        assert "authorization" not in forwarded.headers and "cookie" not in forwarded.headers
        assert forwarded.url.query == b"version=1"
        state["live"] = False
        assert (await client.get("/")).status_code == 403
        state["live"] = True
        broker.grants.revoke(target)
        assert (await client.get("/")).status_code == 403


@pytest.mark.asyncio
async def test_gateway_rejects_oversized_and_malformed_handoffs(gateway):
    broker, target, _, _ = gateway
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=broker.gateway),
        base_url="https://" + broker.host(target.id),
        headers={
            "origin": broker.primary_origin,
            "content-type": "application/x-www-form-urlencoded",
        },
    ) as client:
        assert (await client.post("/__omnigent/authorize", content=b"x" * 8193)).status_code == 413
        assert (await client.post("/__omnigent/authorize", content=b"\xff")).status_code == 400
        assert (
            await client.post("/__omnigent/authorize", content="token=a&token=b")
        ).status_code == 400
        assert (
            await client.post("/__omnigent/authorize?token=secret", content="token=a")
        ).status_code == 400


@pytest.mark.asyncio
async def test_gateway_rejects_grants_from_another_release_incarnation(gateway):
    broker, target, launch, _ = gateway
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=broker.gateway),
        base_url="https://" + broker.host(target.id),
    ) as client:
        broker.release_incarnation = "e" * 32
        assert (
            await client.post(
                "/__omnigent/authorize",
                data={"token": launch},
                headers={"origin": broker.primary_origin},
            )
        ).status_code == 403
        broker.release_incarnation = target.release_incarnation
        assert (
            await client.post(
                "/__omnigent/authorize",
                data={"token": launch},
                headers={"origin": broker.primary_origin},
            )
        ).status_code == 200
        assert (await client.get("/")).status_code == 200
        broker.release_incarnation = "e" * 32
        assert (await client.get("/")).status_code == 403


@pytest.mark.parametrize(
    "origin",
    [
        "http://app.example.test",
        "https://user:pass@app.example.test",
        "https://app.example.test/path",
        "https://app.example.test?next=evil",
        "https://preview.example.test",
        "https://dev.preview.example.test",
    ],
)
def test_gateway_requires_an_isolated_canonical_origin(grants, origin):
    with pytest.raises(ValueError):
        DevelopmentPreviewBroker(
            grants=grants,
            root_domain="preview.example.test",
            release_incarnation="f" * 32,
            primary_origin=origin,
            principal=lambda _: None,
            live=lambda _: None,
        )
