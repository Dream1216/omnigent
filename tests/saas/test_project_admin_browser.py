from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
import uvicorn
from playwright.sync_api import Page, expect

from tests.saas.test_http_cookie_auth import _build_fastapi_app


@dataclass(frozen=True, slots=True)
class BrowserFixture:
    origin: str
    scope: dict[str, str]


@pytest.fixture
def project_admin_server() -> Iterator[BrowserFixture]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    app, scope = _build_fastapi_app(origin)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [sock]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        raise RuntimeError("Project Admin browser fixture did not start")
    try:
        yield BrowserFixture(origin, scope)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


def test_real_browser_project_permission_deny_grant_allow_revoke_deny(
    page: Page,
    project_admin_server: BrowserFixture,
) -> None:
    fixture = project_admin_server
    browser_errors: list[str] = []
    page.on(
        "console",
        lambda message: browser_errors.append(message.text) if message.type == "error" else None,
    )
    page.on("pageerror", lambda error: browser_errors.append(str(error)))
    page.goto(
        f"{fixture.origin}/saas/admin/projects"
        f"?tenant={fixture.scope['tenant_id']}&space={fixture.scope['space_id']}"
    )

    page.get_by_test_id("login-email").fill("http@example.com")
    page.get_by_test_id("login-password").fill("initial-http-password")
    page.get_by_test_id("login-submit").click()
    expect(page.get_by_test_id("scope-connect")).to_be_visible()
    expect(page.locator("#permission-count")).to_contain_text("2026-08-04.p4")

    page.get_by_test_id("scope-connect").click()
    expect(page.get_by_test_id("context-state")).to_contain_text("SPACE /")

    page.get_by_test_id("project-name").fill("Browser Permission Matrix")
    page.get_by_test_id("project-create").click()
    expect(page.get_by_test_id("selected-project-name")).to_have_text("Browser Permission Matrix")
    expect(page.locator("#project-version")).to_have_text("V1")

    page.get_by_test_id("decision-subject").fill(fixture.scope["member_id"])
    page.get_by_test_id("decision-run").click()
    expect(page.get_by_test_id("decision-result")).to_contain_text("DENIED")
    expect(page.get_by_test_id("decision-result")).to_contain_text("permission_not_granted · V1")

    page.get_by_test_id("member-subject").fill(fixture.scope["member_id"])
    page.get_by_test_id("member-grant").click()
    expect(page.locator("#project-version")).to_have_text("V2")
    page.get_by_test_id("decision-run").click()
    expect(page.get_by_test_id("decision-result")).to_contain_text("ALLOWED")
    expect(page.get_by_test_id("decision-result")).to_contain_text("allowed · V2")
    expect(page.locator("#decision-sources")).to_contain_text("project_membership / read")

    page.get_by_test_id("member-revoke").click()
    expect(page.locator("#project-version")).to_have_text("V3")
    page.get_by_test_id("decision-run").click()
    expect(page.get_by_test_id("decision-result")).to_contain_text("DENIED")
    expect(page.get_by_test_id("decision-result")).to_contain_text("permission_not_granted · V3")
    expect(page.get_by_test_id("event-log")).to_contain_text("Membership revoked at V3")
    assert browser_errors == []
