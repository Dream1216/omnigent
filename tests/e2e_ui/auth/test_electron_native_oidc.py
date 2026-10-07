"""Browser-level coverage for Electron's RFC 8252 system-browser sign-in."""

from __future__ import annotations

import base64
import hashlib
import os
import queue
import re
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from playwright.sync_api import Page, expect

from tests.e2e_ui.auth._oidc_server import OIDCServer, spawn_oidc_server

# CI and developer shells can force HTTP(S) through an egress proxy. The OIDC
# server, fake IdP, mock LLM, and RFC 8252 callback are all loopback-only.
for _proxy_bypass_var in ("NO_PROXY", "no_proxy"):
    _proxy_bypass = os.environ.get(_proxy_bypass_var, "")
    os.environ[_proxy_bypass_var] = ",".join(
        part for part in (_proxy_bypass, "127.0.0.1", "localhost") if part
    )


@pytest.fixture(scope="module")
def electron_oidc_server(
    mock_llm_server_url: str,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[OIDCServer]:
    """Run OIDC on the literal loopback origin used by the native callback."""
    server_tmp = tmp_path_factory.mktemp("e2e_ui_electron_oidc")
    yield from spawn_oidc_server(
        mock_llm_server_url,
        server_tmp,
        public_origin=False,
    )


def test_electron_system_browser_oidc_completes_native_loopback_sign_in(
    electron_oidc_server: OIDCServer,
    page: Page,
) -> None:
    """Sign in at the IdP, receive the loopback code, and exchange it once."""
    callback_paths: queue.Queue[str] = queue.Queue()

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            callback_paths.put(self.path)
            body = b"Desktop sign-in complete"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    callback = ThreadingHTTPServer(("127.0.0.1", 0), CallbackHandler)
    callback_thread = threading.Thread(target=callback.serve_forever, daemon=True)
    callback_thread.start()
    redirect_uri = f"http://127.0.0.1:{callback.server_port}/callback"
    verifier = "electron-e2e-pkce-verifier-" + "v" * 40
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    native_state = "electron-system-browser-e2e"

    try:
        login_query = urlencode(
            {
                "native_redirect_uri": redirect_uri,
                "native_state": native_state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        page.goto(f"{electron_oidc_server.public_url}/auth/login?{login_query}")
        continue_link = page.locator("#fake-idp-continue")
        expect(continue_link).to_be_visible(timeout=15_000)
        continue_link.click()
        expect(page).to_have_url(re.compile(r"^http://127\.0\.0\.1:\d+/callback\?"))

        callback_url = urlparse(callback_paths.get(timeout=5))
        callback_query = {key: values[0] for key, values in parse_qs(callback_url.query).items()}
        assert callback_query["state"] == native_state
        assert callback_query["code"]
        assert "error" not in callback_query

        exchange = page.request.post(
            f"{electron_oidc_server.base_url}/auth/native-token",
            form={
                "code": callback_query["code"],
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
            },
        )
        assert exchange.status == 200
        token = exchange.json()
        assert token["user_id"] == electron_oidc_server.idp.email
        assert token["token"]
        assert token["expires_in"] > 0

        replay = page.request.post(
            f"{electron_oidc_server.base_url}/auth/native-token",
            form={
                "code": callback_query["code"],
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
            },
        )
        assert replay.status == 400
        assert replay.json() == {"error": "invalid_grant"}
    finally:
        callback.shutdown()
        callback.server_close()
        callback_thread.join(timeout=5)
