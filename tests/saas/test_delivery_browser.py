from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).parents[2] / "saas" / "admin_ui"
PROJECT = "11111111-1111-4111-8111-111111111111"
PREVIEW = "12345678-1234-1234-1234-123456789abc"
HOST = "app-r" + PREVIEW.replace("-", "") + ".jxhh.com"
TOKEN = "local-browser-smoke-one-use-token"
observed = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, body, content_type, extra=None):
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/saas/delivery":
            self.send(
                200,
                (ROOT / "delivery.html").read_bytes(),
                "text/html; charset=utf-8",
                {
                    "Content-Security-Policy": (
                        "default-src 'none'; script-src 'self'; style-src 'self'; "
                        "connect-src 'self'; img-src 'self'; "
                        "form-action 'self' https://*.jxhh.com; "
                        "base-uri 'none'; frame-ancestors 'none'"
                    )
                },
            )
        elif self.path == "/saas/delivery/assets/delivery.js":
            self.send(200, (ROOT / "delivery.js").read_bytes(), "text/javascript")
        elif self.path == "/saas/delivery/assets/delivery.css":
            self.send(200, (ROOT / "delivery.css").read_bytes(), "text/css")
        elif self.path == "/saas/delivery/projects":
            self.send(
                200,
                json.dumps(
                    {
                        "configured": True,
                        "live_preview_enabled": False,
                        "projects": [
                            {
                                "id": PROJECT,
                                "name": "Local Smoke",
                                "tenant_id": "22222222-2222-4222-8222-222222222222",
                                "space_id": "33333333-3333-4333-8333-333333333333",
                                "production_environment": "production",
                                "actions": {"build": False, "rollback": False, "publish": False},
                            }
                        ],
                    }
                ),
                "application/json",
            )
        elif self.path == f"/saas/delivery/projects/{PROJECT}/runs":
            self.send(200, "[]", "application/json")
        elif self.path == f"/saas/delivery/projects/{PROJECT}":
            self.send(
                200,
                json.dumps(
                    {
                        "snapshots": [],
                        "releases": [],
                        "history": [],
                        "builds": [],
                        "deliveries": [
                            {
                                "id": "44444444-4444-4444-8444-444444444444",
                                "created_at": "2026-09-29T00:00:00+00:00",
                                "status": "ready",
                                "preview_id": PREVIEW,
                                "release_id": None,
                                "build_id": None,
                            }
                        ],
                    }
                ),
                "application/json",
            )
        else:
            self.send(404, "missing", "text/plain")

    def do_POST(self):
        if self.path == f"/saas/delivery/projects/{PROJECT}/previews/{PREVIEW}/open":
            observed["csrf"] = self.headers.get("X-CSRF-Token")
            observed["method"] = "POST"
            self.send(
                201, json.dumps({"url": "https://" + HOST, "token": TOKEN}), "application/json"
            )
        else:
            self.send(404, "missing", "text/plain")


def test_release_preview_button_posts_one_use_credential_without_url_leak():
    observed.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context()
            context.add_init_script("sessionStorage.setItem('omnigent.saas.csrf', 'csrf-test')")

            def edge_route(route):
                request = route.request
                observed["edge_method"] = request.method
                observed["edge_url"] = request.url
                observed["edge_body"] = request.post_data
                route.fulfill(status=200, content_type="text/html", body="EDGE_AUTH_OK")

            context.route("https://" + HOST + "/__omnigent/authorize", edge_route)
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{server.server_port}/saas/delivery")
            page.get_by_role("button", name="查看预览").wait_for()
            with page.expect_popup() as popup_info:
                page.get_by_role("button", name="查看预览").click()
            popup = popup_info.value
            popup.get_by_text("EDGE_AUTH_OK").wait_for(timeout=10000)
            assert observed == {
                "csrf": "csrf-test",
                "method": "POST",
                "edge_method": "POST",
                "edge_url": "https://" + HOST + "/__omnigent/authorize",
                "edge_body": "token=" + TOKEN,
            }, observed
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
