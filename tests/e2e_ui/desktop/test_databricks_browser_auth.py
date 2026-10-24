"""Browser coverage for the Electron Databricks sign-in and recovery surface.

The setup page is the user-visible half of the native system-browser OAuth
flow. Exercise its real bundled HTML and shared URL module, with only the
Electron preload IPC stubbed; the native main-process tests cover sign-out,
credential clearing and fresh browser sign-in, and OAuth tests cover token exchange.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode

from playwright.sync_api import Page, expect

_SETUP_PAGE = Path(__file__).resolve().parents[3] / "web" / "electron" / "setup" / "index.html"
_WORKSPACE = "https://dbc-example.cloud.databricks.com/?o=123"

_PRELOAD = """
window.__databricksAuth = { calls: [], cancellations: [] };
window.omnigentSetup = {
  getServerUrl: () => Promise.resolve(""),
  getManagedServers: () => Promise.resolve([]),
  getRecentServers: () => Promise.resolve([]),
  onConnectionProgress: (callback) => {
    window.__databricksAuth.progress = callback;
    return () => { window.__databricksAuth.progress = null; };
  },
  setServerUrl: (url, options) => {
    window.__databricksAuth.calls.push({ url, options });
    return new Promise(() => {});
  },
  cancelServerConnection: (requestId) => {
    window.__databricksAuth.cancellations.push(requestId);
    return Promise.resolve(true);
  },
};
"""


def _open_recovery(
    page: Page, *, error: str = "Session expired. Connect to sign in again."
) -> None:
    page.add_init_script(_PRELOAD)
    query = urlencode({"url": _WORKSPACE, "error": error})
    page.goto(f"{_SETUP_PAGE.as_uri()}?{query}")
    expect(page.locator("#url")).to_have_value(_WORKSPACE)
    expect(page.locator("#err")).to_have_text(error)


def test_databricks_expired_session_can_retry_and_cancel_browser_sign_in(page: Page) -> None:
    """A rejected workspace session remains recoverable without an embedded login."""
    _open_recovery(page)
    page.locator("#connect").click()

    page.wait_for_function("() => window.__databricksAuth.calls.length === 1")
    attempt = page.evaluate("() => window.__databricksAuth.calls[0]")
    assert attempt["url"] == _WORKSPACE
    assert attempt["options"]["requestId"]
    assert "browserSignIn" not in attempt["options"]
    expect(page.locator("#connect-label")).to_have_text("Connecting…")
    expect(page.locator("#url")).to_be_disabled()

    page.evaluate(
        "requestId => window.__databricksAuth.progress({requestId, phase: 'authenticating'})",
        attempt["options"]["requestId"],
    )
    expect(page.locator("#connect-label")).to_have_text("Authenticating…")
    page.get_by_role("button", name="Cancel sign-in").click()
    expect(page.locator("#connect-label")).to_have_text("Connect")
    expect(page.locator("#url")).to_be_enabled()
    assert page.evaluate("() => window.__databricksAuth.cancellations") == [
        attempt["options"]["requestId"]
    ]
    assert page.evaluate("() => window.__databricksAuth.calls.length") == 1


def test_databricks_signed_out_account_switch_uses_native_reconnect(page: Page) -> None:
    """Sign-out returns to Connect; the shell owns fresh browser-auth state."""
    _open_recovery(page, error="You're signed out of dbc-example.cloud.databricks.com.")
    expect(page.get_by_role("button", name="Sign in with a different account")).to_have_count(0)
    page.locator("#connect").click()

    page.wait_for_function("() => window.__databricksAuth.calls.length === 1")
    attempt = page.evaluate("() => window.__databricksAuth.calls[0]")
    assert attempt["url"] == _WORKSPACE
    assert attempt["options"]["requestId"]
    assert "browserSignIn" not in attempt["options"]
    expect(page.locator("#connect-label")).to_have_text("Connecting…")
