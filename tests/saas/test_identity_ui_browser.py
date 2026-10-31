from __future__ import annotations

import os
import socket
import threading
import time
from collections.abc import Iterator
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import uvicorn
from fastapi import FastAPI
from playwright.sync_api import Browser, Page, Route, expect, sync_playwright

from saas.control_plane.oidc_browser import completion_document
from saas.control_plane.onboarding_http import create_onboarding_ui_router

_ACCOUNT = "8df963a8-b46b-4922-9391-5ad101755524"
_ORIGIN = "https://identity.example.test"
_CSRF = "omnigent.saas.csrf"


def _options(mode: str = "dual") -> dict:
    return {
        "mode": mode,
        "password_enabled": mode != "casdoor",
        "providers": [
            {
                "name": "casdoor",
                "start_path": "/saas/auth/oidc/casdoor/start",
                "signup_path": "/saas/auth/oidc/casdoor/start?intent=signup",
                "link_path": "/saas/auth/oidc/casdoor/link/start",
                "authorization_origin": _ORIGIN,
            }
        ],
    }


@pytest.mark.parametrize("surface", ["project_admin", "delivery"])
@pytest.mark.parametrize("mode", ["legacy", "dual", "casdoor", "unavailable"])
def test_customer_console_login_respects_mode_and_preserves_return_path(
    identity_ui_server: str, identity_browser: Browser, surface: str, mode: str
) -> None:
    page = identity_browser.new_page()
    resources = files("saas.admin_ui")
    path = "/saas/admin/projects" if surface == "project_admin" else "/saas/delivery"
    query = "?session_id=acceptance"
    page.route(
        "**" + path + query,
        lambda route: route.fulfill(
            body=resources.joinpath(surface + ".html").read_text(), content_type="text/html"
        ),
    )

    def asset_response(name: str):
        def respond(route: Route) -> None:
            route.fulfill(
                body=resources.joinpath(name).read_text(),
                content_type="text/css" if name.endswith(".css") else "text/javascript",
            )

        return respond

    for url, name in {
        "**/saas/auth/assets/session.js": "browser_session.js",
        "**/saas/admin/assets/project-admin.js": "project_admin.js",
        "**/saas/admin/assets/project-admin.css": "project_admin.css",
        "**/saas/delivery/assets/delivery.js": "delivery.js",
        "**/saas/delivery/assets/delivery.css": "delivery.css",
    }.items():
        page.route(url, asset_response(name))
    page.route(
        "**/saas/auth/options",
        lambda route: route.fulfill(
            status=503 if mode == "unavailable" else 200,
            json={} if mode == "unavailable" else _options(mode),
        ),
    )
    page.route(
        "**/saas/delivery/projects",
        lambda route: route.fulfill(status=401, json={"detail": {"code": "login_required"}}),
    )
    page.goto(identity_ui_server + path + query)
    link = page.get_by_role("link", name="前往统一登录")
    expect(link).to_be_visible()
    target = parse_qs(urlsplit(link.get_attribute("href") or "").query)["return_to"]
    assert target == [path + query]
    form = page.locator("#login-form" if surface == "project_admin" else "#login")
    if mode == "casdoor":
        expect(form.locator("fieldset")).to_be_hidden()
    elif mode == "unavailable":
        expect(form.locator("button[type=submit]")).to_be_disabled()
        expect(page.get_by_text("暂时无法获取登录方式，请刷新重试。")).to_be_visible()
    else:
        expect(form.locator("button[type=submit]")).to_be_enabled()
    page.close()


@pytest.fixture(scope="module")
def identity_ui_server() -> Iterator[str]:
    app = FastAPI()
    app.include_router(create_onboarding_ui_router())

    @app.get("/__test/complete")
    def complete():
        return completion_document(
            csrf_token="new-browser-csrf", return_to="/saas/account/identities", ui_locale="en-US"
        )

    @app.get("/__test/conflict")
    def conflict():
        return completion_document(
            error_code="identity_confirmation_required", ui_locale="en-US", status_code=409
        )

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    worker.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        server.should_exit = True
        worker.join(timeout=10)
        listener.close()


@pytest.fixture
def identity_browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            yield browser
        finally:
            browser.close()


def _account(page: Page, *, conflicts: bool = False, mode: str = "dual") -> None:
    page.route("**/saas/auth/options", lambda route: route.fulfill(json=_options(mode)))
    page.route(
        "**/saas/auth/bootstrap",
        lambda route: route.fulfill(json={"authenticated": True, "user_id": _ACCOUNT}),
    )
    page.route(
        "**/saas/identities",
        lambda route: route.fulfill(
            json=[
                {
                    "id": "identity-a",
                    "provider": "existing",
                    "email_normalized": "owner@example.test",
                    "email_verified": True,
                    "status": "active",
                }
            ]
        ),
    )
    page.route(
        "**/saas/auth/identity-conflicts",
        lambda route: route.fulfill(
            json=[
                {
                    "id": "conflict-a",
                    "provider": "casdoor",
                    "email": "owner@example.test",
                    "display_name": None,
                    "review_status": "unreviewed",
                }
            ]
            if conflicts
            else []
        ),
    )


def _capture(page: Page, name: str) -> None:
    directory = os.environ.get("E2E_SCREENSHOT_DIR")
    if directory:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path / name), full_page=True)


def test_dual_login_uses_fixed_local_start_and_preserves_reauthentication_and_locale(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context()
    try:
        page = context.new_page()
        page.route("**/saas/auth/options", lambda route: route.fulfill(json=_options()))
        page.goto(
            identity_ui_server + "/saas/login?return_to=%2Fsaas%2Faccount%2Fidentities"
            "&reauthenticate=1&ui_locale=zh-CN"
        )
        expect(page.get_by_role("link", name="继续登录", exact=True)).to_be_visible()
        expect(page.get_by_label("工作邮箱")).to_be_visible()
        href = page.get_by_role("link", name="继续登录", exact=True).get_attribute("href")
        assert href is not None
        assert urlsplit(href).path == "/saas/auth/oidc/casdoor/start"
        assert parse_qs(urlsplit(href).query) == {
            "return_to": ["/saas/account/identities"],
            "ui_locale": ["zh-CN"],
            "reauthenticate": ["true"],
        }
        _capture(page, "dual-login-zh.png")
    finally:
        context.close()


def test_casdoor_login_and_signup_hide_legacy_forms(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context()
    try:
        page = context.new_page()
        page.route("**/saas/auth/options", lambda route: route.fulfill(json=_options("casdoor")))
        page.goto(identity_ui_server + "/saas/login")
        expect(page.get_by_role("link", name="Continue to sign in", exact=True)).to_be_visible()
        expect(page.get_by_label("Work email")).to_have_count(0)
        page.goto(identity_ui_server + "/signup")
        expect(page.get_by_role("heading", name="Create an account.")).to_be_visible()
        expect(page.get_by_label("Organization name")).to_have_count(0)
        link = page.get_by_role("link", name="Create an account", exact=True).get_attribute("href")
        assert link is not None
        assert parse_qs(urlsplit(link).query) == {
            "intent": ["signup"],
            "return_to": ["/setup"],
            "ui_locale": ["en-US"],
        }
        _capture(page, "central-signup-entry.png")
    finally:
        context.close()


def test_identity_settings_consent_latest_csrf_and_retry_without_navigation(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context(viewport={"width": 390, "height": 844})
    try:
        page = context.new_page()
        _account(page, conflicts=True)
        calls = []

        def link(route: Route):
            calls.append(route.request.headers)
            route.fulfill(status=409, json={"detail": {"code": "recent_authentication_required"}})

        page.route("**/saas/auth/oidc/casdoor/link/start?**", link)
        page.goto(identity_ui_server + "/saas/account/identities")
        expect(
            page.get_by_role("heading", name="An identity needs your confirmation")
        ).to_be_visible()
        button = page.get_by_role("button", name="Confirm and connect", exact=True)
        expect(button).to_be_disabled()
        page.get_by_role("checkbox").check()
        page.evaluate(
            "sessionStorage.setItem('omnigent.saas.csrf', 'stale');"
            "localStorage.setItem('omnigent.saas.csrf', 'latest')"
        )
        button.click()
        expect(page.get_by_role("alert", name="Sign-in method error")).to_contain_text(
            "Sign in again with your current account"
        )
        assert calls[0]["x-csrf-token"] == "latest"
        assert calls[0]["accept"] == "application/json"
        expect(button).to_be_enabled()
        expect(page.get_by_role("checkbox")).to_be_checked()
        assert page.url == identity_ui_server + "/saas/account/identities"
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        _capture(page, "identity-confirmation-mobile.png")
    finally:
        context.close()


def test_link_rejects_an_untrusted_redirect_then_allows_the_configured_provider(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context()
    try:
        page = context.new_page()
        _account(page)
        calls = 0

        def link(route: Route):
            nonlocal calls
            calls += 1
            route.fulfill(
                json={
                    "authorization_url": "https://attacker.example/steal"
                    if calls == 1
                    else _ORIGIN + "/authorize?state=verified"
                }
            )

        page.route("**/saas/auth/oidc/casdoor/link/start?**", link)
        page.route(_ORIGIN + "/**", lambda route: route.fulfill(body="Select your identity"))
        page.goto(identity_ui_server + "/saas/account/identities")
        page.get_by_role("checkbox").check()
        page.get_by_role("button", name="Confirm and connect", exact=True).click()
        expect(page.get_by_role("alert", name="Sign-in method error")).to_contain_text(
            "invalid response"
        )
        assert page.url == identity_ui_server + "/saas/account/identities"
        page.get_by_role("button", name="Confirm and connect", exact=True).click()
        expect(page).to_have_url(_ORIGIN + "/authorize?state=verified")
    finally:
        context.close()


def test_packaged_conflict_completion_uses_csp_and_guides_existing_account_login(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context()
    try:
        page = context.new_page()
        referers = []
        page.on("request", lambda request: referers.append(request.headers.get("referer", "")))
        response = page.goto(identity_ui_server + "/__test/conflict?code=never-leak")
        assert response is not None and response.status == 409
        assert "unsafe-inline" not in response.headers["content-security-policy"]
        assert response.headers["referrer-policy"] == "no-referrer"
        expect(
            page.get_by_role("heading", name="This email already has an account.")
        ).to_be_visible()
        expect(page).to_have_url(identity_ui_server + "/saas/auth/result")
        link = page.get_by_role(
            "link", name="Sign in with existing account", exact=True
        ).get_attribute("href")
        assert link is not None and parse_qs(urlsplit(link).query)["reauthenticate"] == ["1"]
        assert all("never-leak" not in value for value in referers)
        _capture(page, "identity-conflict-completion.png")
    finally:
        context.close()


def test_packaged_completion_shares_new_csrf_with_existing_tab(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context()
    try:
        first, signing_in = context.new_page(), context.new_page()
        for page in (first, signing_in):
            _account(page)
        first.goto(identity_ui_server + "/saas/account/identities")
        expect(first.get_by_role("checkbox")).to_be_visible()
        first.evaluate(
            "sessionStorage.setItem('omnigent.saas.csrf', 'old');"
            "localStorage.setItem('omnigent.saas.csrf', 'old')"
        )
        signing_in.goto(identity_ui_server + "/__test/complete")
        expect(signing_in).to_have_url(identity_ui_server + "/saas/account/identities")
        first.wait_for_function(
            "sessionStorage.getItem('omnigent.saas.csrf') === 'new-browser-csrf'"
        )
        assert first.evaluate("localStorage.getItem('omnigent.saas.csrf')") == "new-browser-csrf"
        third = context.new_page()
        _account(third)
        third.goto(identity_ui_server + "/saas/account/identities")
        expect(third.get_by_role("checkbox")).to_be_visible()
        assert third.evaluate("localStorage.getItem('omnigent.saas.csrf')") == "new-browser-csrf"
    finally:
        context.close()


def test_packaged_completion_storage_failure_is_localized_and_retryable(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context()
    try:
        context.add_init_script(
            "for (const name of ['localStorage','sessionStorage']) "
            "Object.defineProperty(window,name,{get(){throw new Error('restricted')}})"
        )
        page = context.new_page()
        page.goto(identity_ui_server + "/__test/complete")
        expect(page.get_by_role("status")).to_contain_text("Browser storage is unavailable")
        expect(page.get_by_role("link", name="Sign in again", exact=True)).to_be_visible()
        assert page.url == identity_ui_server + "/saas/auth/result"
    finally:
        context.close()


def test_account_logout_clears_csrf_only_after_local_success(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context()
    try:
        page = context.new_page()
        _account(page)
        page.route(
            "**/saas/auth/logout",
            lambda route: route.fulfill(
                status=503, json={"error": {"code": "dependency_unavailable"}}
            ),
        )
        page.goto(identity_ui_server + "/saas/account/identities")
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        page.evaluate("localStorage.setItem('omnigent.saas.csrf','keep-on-failure')")
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.get_by_role("alert", name="Sign-in method error")).to_be_visible()
        assert page.evaluate("localStorage.getItem('omnigent.saas.csrf')") == "keep-on-failure"
        page.route(
            "**/saas/auth/logout",
            lambda route: route.fulfill(json={"logout_url": _ORIGIN + "/logout"}),
        )
        page.route(_ORIGIN + "/logout", lambda route: route.fulfill(body="Signed out"))
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page).to_have_url(_ORIGIN + "/logout")
        assert all(
            item["name"] != _CSRF
            for origin in context.storage_state()["origins"]
            for item in origin["localStorage"]
        )
    finally:
        context.close()
