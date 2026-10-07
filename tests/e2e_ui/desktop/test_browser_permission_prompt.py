"""E2E coverage for the Electron shell's local-network permission prompt.

The native shell owns this prompt outside the server SPA.  The e2e_ui lane
loads the exact bundled page and injects the same narrow preload contract as
``browser_permission_preload.js`` so Chromium exercises the user-visible
origin, reload warning, focus order, and one-shot permission decision.

The separate real-Electron lane in
``web/electron/e2e/desktop_oidc_browser_sign_in.e2e.js`` covers the system-
browser OIDC round trip.  Together these tests cover the two native-shell
surfaces added by the 0.18 desktop flow without contacting a real identity
provider or local-network service.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

_PERMISSION_PAGE = (
    Path(__file__).resolve().parents[3] / "web" / "electron" / "browser-permission" / "index.html"
)

_PERMISSION_BRIDGE = """
(() => {
  const state = { choices: [] };
  window.__permissionTest = state;
  window.omnigentBrowserPermission = {
    getInfo: () => Promise.resolve({
      origin: "https://workspace.example.test",
      reload: __RELOAD__,
    }),
    choose: (choice) => {
      state.choices.push(choice);
      return Promise.resolve();
    },
  };
})()
"""


def _open_permission_prompt(page: Page, *, reload: bool) -> None:
    page.add_init_script(
        _PERMISSION_BRIDGE.replace("__RELOAD__", json.dumps(reload)),
    )
    page.goto(_PERMISSION_PAGE.as_uri())
    expect(page.locator("#origin")).to_have_text("https://workspace.example.test")
    expect(page.locator("#close")).to_be_focused()


@pytest.mark.parametrize(
    ("control", "decision"),
    [
        ("#once", "allow-once"),
        ("#always", "always-allow"),
        ("#deny", "deny"),
        ("#close", "dismiss"),
    ],
)
def test_local_network_prompt_submits_one_native_decision(
    page: Page, control: str, decision: str
) -> None:
    """Every visible choice sends exactly one accepted main-process value."""
    _open_permission_prompt(page, reload=True)

    expect(page.get_by_role("heading", name="Allow local network access?")).to_be_visible()
    expect(page.locator("#reload")).to_be_visible()
    page.locator(control).click()

    footer_buttons = page.locator("footer button")
    expect(footer_buttons).to_have_count(3)
    assert footer_buttons.evaluate_all("buttons => buttons.every(button => button.disabled)")
    assert page.evaluate("() => window.__permissionTest.choices") == [decision]

    # A second activation cannot race a second IPC decision while the native
    # window is being destroyed.
    page.locator(control).dispatch_event("click")
    assert page.evaluate("() => window.__permissionTest.choices") == [decision]


def test_escape_dismisses_without_showing_reload_copy(page: Page) -> None:
    """Escape is the keyboard-equivalent safe denial when reload is unnecessary."""
    _open_permission_prompt(page, reload=False)

    expect(page.locator("#reload")).to_be_hidden()
    page.keyboard.press("Escape")

    assert page.evaluate("() => window.__permissionTest.choices") == ["dismiss"]
