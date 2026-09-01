"""Browser E2E: packaged self-service UI through workspace readiness.

The production mail provider and control plane are deliberately not used here.
The real packaged FastAPI UI is served by an isolated local server, while
same-origin routes return deterministic catalog, registration, verification,
login, and provisioning responses. This keeps the journey browser-real without
credentials or mutable production state.
"""

from __future__ import annotations

import os
import re
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient
from playwright.sync_api import Page, Request, Route, expect, sync_playwright

from saas.control_plane.onboarding_http import create_onboarding_ui_router

_REGISTRATION_ID = "11111111-1111-4111-8111-111111111111"
_ONBOARDING_ID = "22222222-2222-4222-8222-222222222222"
_USER_ID = "33333333-3333-4333-8333-333333333333"
_TENANT_ID = "44444444-4444-4444-8444-444444444444"
_SPACE_ID = "55555555-5555-4555-8555-555555555555"
_SUBSCRIPTION_ID = "66666666-6666-4666-8666-666666666666"
_RUNTIME_PARTITION_ID = "77777777-7777-4777-8777-777777777777"
_PROJECT_ID = "88888888-8888-4888-8888-888888888888"
_VERIFICATION_TOKEN = "e2e-fragment-only-token"
_CSRF_TOKEN = "e2e-tab-scoped-csrf"
_EMAIL = "founder@example.test"


@pytest.fixture
def onboarding_ui_page() -> Iterator[tuple[Page, str]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    app = FastAPI()
    app.include_router(create_onboarding_ui_router())
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        raise RuntimeError("onboarding browser server failed to start")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        try:
            yield page, f"http://127.0.0.1:{port}"
        finally:
            browser.close()
            server.should_exit = True
            thread.join(timeout=10)
            listener.close()


@dataclass
class _SaasRequests:
    """Captured browser requests for assertions after the rendered journey."""

    urls: list[str] = field(default_factory=list)
    referers: list[str] = field(default_factory=list)
    registration: list[dict[str, Any]] = field(default_factory=list)
    registration_headers: list[dict[str, str]] = field(default_factory=list)
    verification: list[dict[str, Any]] = field(default_factory=list)
    login: list[dict[str, Any]] = field(default_factory=list)
    status_cookies: list[str] = field(default_factory=list)
    status_calls: int = 0


def _catalog() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "revision": "a" * 64,
        "plans": [
            {
                "key": "starter",
                "currency": "USD",
                "trial_days": 14,
                "trial_run_limit": 100,
                "trial_concurrency_limit": 2,
            },
            {
                "key": "team",
                "currency": "USD",
                "trial_days": 30,
                "trial_run_limit": 1_000,
                "trial_concurrency_limit": 10,
            },
        ],
        "regions": ["us-east-1", "eu-west-1"],
        "verification_ttl_seconds": 1_800,
    }


def test_packaged_pages_and_assets_have_locked_down_headers() -> None:
    app = FastAPI()
    app.include_router(create_onboarding_ui_router())

    with TestClient(app) as client:
        for path in ("/signup", "/signup/verify", "/signup/status", "/saas/login"):
            response = client.get(path)
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["referrer-policy"] == "no-referrer"
            assert "default-src 'none'" in response.headers["content-security-policy"]
            assert "script-src 'self'" in response.headers["content-security-policy"]
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
            assert response.headers["x-content-type-options"] == "nosniff"
        assert (
            client.get("/saas/onboarding-assets/onboarding.css")
            .headers["content-type"]
            .startswith("text/css")
        )
        assert (
            client.get("/saas/onboarding-assets/onboarding.js")
            .headers["content-type"]
            .startswith("text/javascript")
        )


def _install_saas_routes(page: Page) -> _SaasRequests:
    captured = _SaasRequests()

    def capture_request(request: Request) -> None:
        captured.urls.append(request.url)
        captured.referers.append(request.headers.get("referer", ""))

    page.on("request", capture_request)

    page.route(
        "**/v1/info",
        lambda route: route.fulfill(
            json={
                "accounts_enabled": False,
                "needs_setup": False,
                "login_url": "/saas/login",
                "features": {},
            }
        ),
    )
    page.route(
        "**/v1/me",
        lambda route: route.fulfill(
            status=401,
            json={"user_id": None, "login_url": "/saas/login"},
        ),
    )
    page.route("**/saas/onboarding/catalog", lambda route: route.fulfill(json=_catalog()))

    def register(route: Route) -> None:
        payload = route.request.post_data_json
        assert isinstance(payload, dict)
        captured.registration.append(payload)
        captured.registration_headers.append(route.request.headers)
        route.fulfill(
            status=202,
            json={"registration_id": _REGISTRATION_ID, "status": "verification_pending"},
        )

    def verify(route: Route) -> None:
        payload = route.request.post_data_json
        assert isinstance(payload, dict)
        captured.verification.append(payload)
        route.fulfill(
            json={
                "registration_id": _REGISTRATION_ID,
                "status": "tenant_provisioning",
                "onboarding_id": _ONBOARDING_ID,
                "user_id": _USER_ID,
                "tenant_id": _TENANT_ID,
                "space_id": _SPACE_ID,
                "subscription_id": _SUBSCRIPTION_ID,
                "runtime_partition_id": _RUNTIME_PARTITION_ID,
                "default_project_id": _PROJECT_ID,
            }
        )

    def login(route: Route) -> None:
        payload = route.request.post_data_json
        assert isinstance(payload, dict)
        captured.login.append(payload)
        route.fulfill(
            headers={
                "set-cookie": ("omnigent_saas_session=e2e-session; Path=/; HttpOnly; SameSite=Lax")
            },
            json={
                "user_id": _USER_ID,
                "csrf_token": _CSRF_TOKEN,
                "expires_at": "2026-09-02T12:00:00Z",
            },
        )

    def status(route: Route) -> None:
        captured.status_calls += 1
        captured.status_cookies.append(route.request.headers.get("cookie", ""))
        if captured.status_calls == 1:
            route.fulfill(
                json={
                    "state": "provisioning",
                    "stage": "runtime",
                    "version": 1,
                    "updated_at": "2026-09-02T00:00:00Z",
                    "can_start_first_run": False,
                    "tenant_id": _TENANT_ID,
                    "space_id": _SPACE_ID,
                    "default_project_id": _PROJECT_ID,
                }
            )
            return
        route.fulfill(
            json={
                "state": "ready_for_first_run",
                "stage": "first_run",
                "version": 2,
                "updated_at": "2026-09-02T00:00:02Z",
                "can_start_first_run": True,
                "tenant_id": _TENANT_ID,
                "space_id": _SPACE_ID,
                "default_project_id": _PROJECT_ID,
                "trial_ends_at": "2026-10-02T00:00:00Z",
            }
        )

    page.route("**/saas/onboarding/registrations", register)
    page.route(
        re.compile(rf"/saas/onboarding/registrations/{_REGISTRATION_ID}/verify$"),
        verify,
    )
    page.route("**/saas/auth/login", login)
    page.route("**/saas/onboarding/status", status)
    return captured


def _screenshot(page: Page, name: str) -> None:
    output = os.environ.get("E2E_SCREENSHOT_DIR")
    if output is None:
        return
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(directory / name), full_page=True)


def test_registration_journey_reaches_ready_workspace(
    onboarding_ui_page: tuple[Page, str],
) -> None:
    """Register, consume the fragment token, sign in, and observe readiness."""
    page, live_server = onboarding_ui_page
    captured = _install_saas_routes(page)

    page.goto(f"{live_server}/saas/login")
    expect(page.get_by_role("heading", name="Sign in to your workspace")).to_be_visible(
        timeout=30_000
    )
    create_workspace = page.get_by_role("link", name="Create a workspace")
    expect(create_workspace).to_be_visible()
    create_workspace.click()

    expect(page.get_by_role("heading", name="Create your organization")).to_be_visible()
    expect(page.get_by_text("Starter", exact=True)).to_be_visible()
    expect(page.get_by_text("Team", exact=True)).to_be_visible()
    region = page.get_by_label("Home region")
    expect(region).to_have_value("us-east-1")
    expect(region.locator("option")).to_have_count(2)

    page.get_by_label("Work email").fill(_EMAIL)
    page.get_by_label("Your name").fill("E2E Founder")
    page.get_by_label("Organization name").fill("Example Automation")
    expect(page.get_by_label("Organization URL")).to_have_value("example-automation")
    page.get_by_label("First space").fill("Product Engineering")
    expect(page.get_by_label("Space URL")).to_have_value("product-engineering")
    team_plan = page.get_by_role("radio", name=re.compile(r"Team"))
    team_plan.check()
    expect(team_plan).to_be_checked()
    region.select_option("eu-west-1")
    _screenshot(page, "saas-registration-catalog.png")

    page.get_by_role("button", name="Continue").click()
    pending_url = f"{live_server}/signup/verify?registration_id={_REGISTRATION_ID}"
    expect(page).to_have_url(pending_url)
    expect(page.get_by_role("heading", name="Verify your work email")).to_be_visible()

    # The email link starts a new document navigation, rather than a same-page
    # hash update on the already-mounted check-inbox view.
    page.goto(f"{live_server}/saas/login")
    verification_url = f"{pending_url}#token={_VERIFICATION_TOKEN}"
    page.goto(verification_url)
    expect(page.get_by_role("heading", name="Secure your account")).to_be_visible()
    expect(page).to_have_url(pending_url)
    assert page.evaluate("window.location.hash") == ""

    email = page.get_by_label("Work email")
    expect(email).to_have_value(_EMAIL)
    page.get_by_label("Password", exact=True).fill("correct-horse-battery")
    page.get_by_label("Confirm password").fill("correct-horse-battery")
    page.get_by_role("button", name="Verify and continue").click()

    expect(page).to_have_url(f"{live_server}/signup/status")
    expect(page.get_by_role("heading", name="Your workspace is taking shape")).to_be_visible()
    expect(page.get_by_role("heading", name="Your organization is ready")).to_be_visible(
        timeout=10_000
    )
    expect(page.get_by_role("button", name="Open workspace")).to_be_visible()
    _screenshot(page, "saas-workspace-ready.png")

    assert captured.registration == [
        {
            "email": _EMAIL,
            "display_name": "E2E Founder",
            "tenant_name": "Example Automation",
            "tenant_slug": "example-automation",
            "default_space_name": "Product Engineering",
            "default_space_slug": "product-engineering",
            "plan_key": "team",
            "home_region": "eu-west-1",
        }
    ]
    idempotency_key = captured.registration_headers[0].get("idempotency-key", "")
    assert idempotency_key.startswith("signup-")
    assert captured.verification == [
        {
            "verification_token": _VERIFICATION_TOKEN,
            "password": "correct-horse-battery",
        }
    ]
    assert captured.login == [{"email": _EMAIL, "password": "correct-horse-battery"}]
    assert captured.status_calls >= 2
    assert any("omnigent_saas_session=e2e-session" in value for value in captured.status_cookies)
    assert page.evaluate("sessionStorage.getItem('omnigent.saas.csrf')") == _CSRF_TOKEN

    # URL fragments are browser-local. The token is sent only in the explicit
    # verification body, never in a request URL or Referer, and is removed from
    # browser history before the form can submit.
    assert all(_VERIFICATION_TOKEN not in url for url in captured.urls)
    assert all(_VERIFICATION_TOKEN not in referer for referer in captured.referers)
