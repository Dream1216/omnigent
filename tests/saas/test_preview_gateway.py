from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from saas.control_plane import PreviewRouteGrant
from saas.control_plane.preview_sessions import (
    PreviewBrowserSessionGrant,
    PreviewSessionError,
)
from saas.preview_gateway import (
    PREVIEW_COOKIE_NAME,
    PreviewTunnelRequest,
    PreviewTunnelResponse,
    create_preview_gateway_app,
    create_preview_session_gateway_app,
)


class _Authority:
    def __init__(self, *, host: str, token: str) -> None:
        self.host = host
        self.token = token
        self.calls: list[tuple[str, str, dict[str, str]]] = []
        self.route = PreviewRouteGrant(
            preview_id=uuid4(),
            tenant_id=uuid4(),
            space_id=uuid4(),
            project_id=uuid4(),
            runner_id=uuid4(),
            runner_connection_generation=3,
            run_id=uuid4(),
            run_fence_token=7,
            worktree_id=uuid4(),
            worktree_lease_generation=5,
            opaque_preview_key="pvr_test",
            preview_token_hash="b" * 64,
            upstream_request_headers={
                "accept": "text/html",
                "content-type": "application/json",
                "user-agent": "preview-test",
            },
            response_headers={
                "Content-Security-Policy": "sandbox; frame-ancestors 'none'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            },
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )

    def authorize_preview_request(
        self,
        *,
        host: str,
        token: str,
        incoming_headers: dict[str, str],
    ) -> PreviewRouteGrant:
        self.calls.append((host, token, incoming_headers))
        assert host == self.host
        assert token == self.token
        assert "cookie" not in incoming_headers
        assert "authorization" not in incoming_headers
        return self.route


class _Tunnel:
    def __init__(self) -> None:
        self.requests: list[PreviewTunnelRequest] = []

    async def forward(self, request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        self.requests.append(request)
        return PreviewTunnelResponse(
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": "unsafe=must-not-pass",
                "Connection": "upgrade",
                "X-Frame-Options": "ALLOWALL",
            },
            body=b"<h1>preview</h1>",
        )


def test_preview_gateway_exchanges_body_token_for_host_cookie_and_strips_credentials() -> None:
    host = "pv-aabbcc.preview.example.net"
    token = "pv_parent_capability"
    authority = _Authority(host=host, token=token)
    tunnel = _Tunnel()
    app = create_preview_gateway_app(authority=authority, tunnel=tunnel)

    with TestClient(app, base_url=f"https://{host}", follow_redirects=False) as client:
        exchange = client.post(
            "/__omnigent/authorize",
            data={"token": token},
        )
        assert exchange.status_code == 303
        assert exchange.headers["location"] == "/"
        cookie = exchange.headers["set-cookie"]
        assert cookie.startswith(f"{PREVIEW_COOKIE_NAME}=")
        assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
        assert "Domain=" not in cookie
        assert token not in exchange.headers["location"]

        response = client.get(
            "/nested/app?mode=test",
            headers={
                "Accept": "text/html",
                "User-Agent": "preview-test",
                "X-Forwarded-For": "198.51.100.10",
            },
        )
        assert response.status_code == 200
        assert response.text == "<h1>preview</h1>"
        assert "set-cookie" not in response.headers
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["cache-control"] == "no-store"

    assert len(tunnel.requests) == 1
    forwarded = tunnel.requests[0]
    assert forwarded.route == authority.route
    assert forwarded.method == "GET"
    assert forwarded.path == "/nested/app"
    assert forwarded.query == "mode=test"
    assert forwarded.headers == {
        "accept": "text/html",
        "content-type": "application/json",
        "user-agent": "preview-test",
    }
    assert authority.calls[0] == (host, token, {})
    assert authority.calls[1][0:2] == (host, token)
    assert "x-forwarded-for" not in authority.calls[1][2]


def test_preview_gateway_rejects_ambient_cookies_authorization_and_oversized_body() -> None:
    host = "pv-ddeeff.preview.example.net"
    token = "pv_isolated"
    authority = _Authority(host=host, token=token)
    tunnel = _Tunnel()
    app = create_preview_gateway_app(
        authority=authority,
        tunnel=tunnel,
        maximum_request_bytes=4,
    )
    with TestClient(app, base_url=f"https://{host}", follow_redirects=False) as client:
        client.cookies.set(PREVIEW_COOKIE_NAME, token, path="/")
        client.cookies.set("omnigent_session", "ambient", path="/")
        ambient_cookie = client.get("/")
        assert ambient_cookie.status_code == 403
        assert ambient_cookie.json()["detail"]["code"] == "preview_ambient_cookie_denied"
        client.cookies.delete("omnigent_session")

        ambient_auth = client.get("/", headers={"Authorization": "Bearer app-token"})
        assert ambient_auth.status_code == 403
        assert ambient_auth.json()["detail"]["code"] == ("preview_ambient_authorization_denied")

        oversized = client.post("/api", content=b"12345")
        assert oversized.status_code == 403
        assert oversized.json()["detail"]["code"] == "preview_body_too_large"

        chunked = client.post(
            "/api",
            content=iter([b"12", b"345"]),
            headers={"Transfer-Encoding": "chunked"},
        )
        assert chunked.status_code == 403
        assert chunked.json()["detail"]["code"] == "preview_body_too_large"
    assert not tunnel.requests


def test_preview_gateway_rejects_host_header_path_smuggling() -> None:
    host = "pv-aabbcc.preview.example.net"
    token = "pv_host_bound"
    authority = _Authority(host=host, token=token)
    tunnel = _Tunnel()
    app = create_preview_gateway_app(authority=authority, tunnel=tunnel)

    with TestClient(app, base_url=f"https://{host}", follow_redirects=False) as client:
        response = client.post(
            "/__omnigent/authorize",
            data={"token": token},
            headers={"Host": f"{host}/smuggled"},
        )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "preview_host_invalid"
    assert not authority.calls


class _SessionAuthority:
    def __init__(self, route: PreviewRouteGrant, exchange_token: str) -> None:
        self.route = route
        self.exchange_token = exchange_token
        self.current = "session_" + "s" * 48
        self.next = "session_" + "n" * 48
        self.exchanged = False
        self.authorized: list[str] = []

    def exchange(self, *, host: str, exchange_token: str) -> PreviewBrowserSessionGrant:
        if (
            self.exchanged
            or host != self.route.preview_host
            or exchange_token != self.exchange_token
        ):
            raise PreviewSessionError("preview_exchange_invalid")
        self.exchanged = True
        return PreviewBrowserSessionGrant(self.route, self.current)

    def authorize_and_rotate(
        self,
        *,
        host: str,
        session_token: str,
        incoming_headers: dict[str, str],
    ) -> PreviewBrowserSessionGrant:
        del incoming_headers
        if host != self.route.preview_host or session_token not in {self.current, self.next}:
            raise PreviewSessionError("preview_session_invalid")
        self.authorized.append(session_token)
        if session_token == self.current:
            return PreviewBrowserSessionGrant(self.route, self.next)
        return PreviewBrowserSessionGrant(self.route)


def test_p0s9_gateway_consumes_url_bearer_once_and_rotates_independent_cookie() -> None:
    host = "pv-session.preview.example.net"
    exchange_token = "exchange_" + "e" * 48
    base = _Authority(host=host, token=exchange_token)
    route = replace(base.route, preview_host=host)
    authority = _SessionAuthority(route, exchange_token)
    tunnel = _Tunnel()
    app = create_preview_session_gateway_app(authority=authority, tunnel=tunnel)

    with TestClient(app, base_url=f"https://{host}", follow_redirects=False) as client:
        exchange = client.post("/__omnigent/authorize", data={"token": exchange_token})
        assert exchange.status_code == 303
        exchange_cookie = exchange.headers["set-cookie"]
        assert authority.current in exchange_cookie
        assert exchange_token not in exchange_cookie

        first = client.get("/")
        assert first.status_code == 200
        assert authority.next in first.headers["set-cookie"]
        second = client.get("/")
        assert second.status_code == 200
        assert "set-cookie" not in second.headers
        assert authority.authorized == [authority.current, authority.next]

    with TestClient(app, base_url=f"https://{host}", follow_redirects=False) as replay:
        denied = replay.post("/__omnigent/authorize", data={"token": exchange_token})
        assert denied.status_code == 403
        assert denied.json()["detail"]["code"] == "preview_exchange_invalid"


def test_p0s9_fragment_bootstrap_is_content_blind_no_store_and_clears_url() -> None:
    host = "pv-session.preview.example.net"
    exchange_token = "exchange_" + "e" * 48
    base = _Authority(host=host, token=exchange_token)
    route = replace(base.route, preview_host=host)
    authority = _SessionAuthority(route, exchange_token)
    app = create_preview_session_gateway_app(authority=authority, tunnel=_Tunnel())

    with TestClient(app, base_url=f"https://{host}", follow_redirects=False) as client:
        bootstrap = client.get("/__omnigent/bootstrap")
        assert bootstrap.status_code == 200
        assert bootstrap.request.url.query == b""
        assert exchange_token not in str(bootstrap.request.url)
        assert exchange_token not in bootstrap.text
        assert bootstrap.headers["cache-control"] == "no-store, max-age=0"
        assert bootstrap.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in bootstrap.headers["content-security-policy"]
        assert "script-src 'self'" in bootstrap.headers["content-security-policy"]

        script = client.get("/__omnigent/bootstrap.js")
        assert script.status_code == 200
        assert script.headers["cache-control"] == "no-store, max-age=0"
        assert "window.history.replaceState" in script.text
        assert script.text.index("window.history.replaceState") < script.text.index(
            "form.submit()"
        )
        assert exchange_token not in script.text

        leaked_query = client.get(f"/__omnigent/bootstrap?token={exchange_token}")
        assert leaked_query.status_code == 403
        assert authority.exchanged is False


def test_p0s9_gateway_rejects_forged_host_and_empty_session_cookie() -> None:
    host = "pv-session.preview.example.net"
    exchange_token = "exchange_" + "e" * 48
    base = _Authority(host=host, token=exchange_token)
    route = replace(base.route, preview_host=host)
    authority = _SessionAuthority(route, exchange_token)
    app = create_preview_session_gateway_app(authority=authority, tunnel=_Tunnel())

    with TestClient(app, base_url=f"https://{host}", follow_redirects=False) as client:
        assert client.get("/").status_code == 401
        exchange = client.post("/__omnigent/authorize", data={"token": exchange_token})
        assert exchange.status_code == 303
        forged = client.get("/", headers={"Host": "forged.preview.example.net"})
        assert forged.status_code == 403
        assert forged.json()["detail"]["code"] == "preview_session_invalid"
