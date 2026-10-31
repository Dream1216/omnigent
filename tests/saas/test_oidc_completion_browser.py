from __future__ import annotations

from collections.abc import Iterator
from importlib import resources

import pytest
from playwright.sync_api import Browser, BrowserContext, Route, expect, sync_playwright

from saas.control_plane.oidc_browser import (
    OIDC_COMPLETE_SCRIPT,
    SECURITY_HEADERS,
    completion_document,
)


@pytest.fixture
def oidc_browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            yield browser
        finally:
            browser.close()


def _install(context: BrowserContext) -> None:
    def respond(route: Route) -> None:
        path = route.request.url.split("oidc.example.test", 1)[1]
        if path == "/complete":
            document = completion_document(
                csrf_token="browser-verified-csrf", return_to="/setup", ui_locale="en-US"
            )
            route.fulfill(status=200, headers=dict(document.headers), body=document.body)
        elif path == "/saas/auth/assets/session.js":
            route.fulfill(
                content_type="application/javascript",
                body=resources.files("saas.admin_ui").joinpath("browser_session.js").read_text(),
                headers=SECURITY_HEADERS,
            )
        elif path == "/saas/auth/assets/oidc-complete.js":
            route.fulfill(
                content_type="application/javascript",
                body=OIDC_COMPLETE_SCRIPT,
                headers=SECURITY_HEADERS,
            )
        else:
            route.fulfill(
                content_type="text/html",
                body="<h1>Workspace setup</h1>"
                '<script src="/saas/auth/assets/session.js"></script>',
            )

    context.route("http://oidc.example.test/**", respond)


def test_completion_csp_runs_scripts_and_shares_csrf_with_existing_and_new_tabs(
    oidc_browser: Browser,
) -> None:
    context = oidc_browser.new_context()
    try:
        _install(context)
        existing = context.new_page()
        existing.goto("http://oidc.example.test/setup")
        existing.add_script_tag(url="http://oidc.example.test/saas/auth/assets/session.js")
        existing.evaluate("window.OmnigentSaasSession.write('stale-csrf')")
        signing_in = context.new_page()
        signing_in.goto("http://oidc.example.test/complete")
        expect(signing_in).to_have_url("http://oidc.example.test/setup")
        assert (
            signing_in.evaluate("localStorage.getItem('omnigent.saas.csrf')")
            == "browser-verified-csrf"
        )
        assert (
            signing_in.evaluate("sessionStorage.getItem('omnigent.saas.csrf')")
            == "browser-verified-csrf"
        )
        existing.wait_for_function(
            "sessionStorage.getItem('omnigent.saas.csrf') === 'browser-verified-csrf'"
        )
        assert existing.evaluate("window.OmnigentSaasSession.read()") == "browser-verified-csrf"
        new_tab = context.new_page()
        new_tab.goto("http://oidc.example.test/setup")
        new_tab.add_script_tag(url="http://oidc.example.test/saas/auth/assets/session.js")
        assert new_tab.evaluate("window.OmnigentSaasSession.read()") == "browser-verified-csrf"
        existing.evaluate("window.OmnigentSaasSession.clear()")
        signing_in.wait_for_function("sessionStorage.getItem('omnigent.saas.csrf') === ''")
        assert new_tab.evaluate("window.OmnigentSaasSession.read()") == ""
    finally:
        context.close()


def test_completion_storage_failure_stays_on_recoverable_document(oidc_browser: Browser) -> None:
    context = oidc_browser.new_context()
    try:
        _install(context)
        context.add_init_script("""
            for (const name of ['localStorage', 'sessionStorage']) {
              Object.defineProperty(window, name, { get() { throw new Error('restricted'); } });
            }
        """)
        page = context.new_page()
        page.goto("http://oidc.example.test/complete")
        expect(page.get_by_role("status")).to_contain_text("Browser storage is unavailable")
        expect(page).to_have_url("http://oidc.example.test/complete")
        expect(page.get_by_role("link", name="Try signing in again")).to_have_attribute(
            "href", "/saas/login"
        )
    finally:
        context.close()


def test_browser_completion_escapes_injected_json() -> None:
    response = completion_document(csrf_token='</script><script>alert("bad")</script>')
    assert b"</script><script>alert" not in response.body
    assert b"\\u003c/script\\u003e" in response.body
