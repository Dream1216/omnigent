"""E2E: authenticated-shell language switching persists across navigation and reloads."""

from __future__ import annotations

from playwright.sync_api import Page, expect


def test_authenticated_language_switching_persists(page: Page, live_server: str) -> None:
    """The sidebar and Appearance controls share one persisted locale preference."""
    page.goto(f"{live_server}/")
    expect(page.get_by_test_id("new-chat-landing")).to_be_visible(timeout=30_000)
    expect(page.get_by_role("heading", name="What should we build?", exact=True)).to_be_visible()

    page.get_by_test_id("language-menu-button").click()
    page.get_by_test_id("language-option-zh-CN").click()

    expect(page.get_by_role("heading", name="今天想构建什么？", exact=True)).to_be_visible()
    expect(page.get_by_text("新建会话", exact=True)).to_be_visible()
    expect(page.get_by_text("自动化", exact=True)).to_be_visible()
    expect(page.get_by_text("收件箱", exact=True)).to_be_visible()
    expect(page.locator("html")).to_have_attribute("lang", "zh-CN")
    assert page.evaluate("() => window.localStorage.getItem('omnigent.locale')") == "zh-CN"

    page.reload()
    expect(page.get_by_role("heading", name="今天想构建什么？", exact=True)).to_be_visible(
        timeout=30_000
    )
    expect(page.locator("html")).to_have_attribute("lang", "zh-CN")

    page.goto(f"{live_server}/settings/appearance")
    language_control = page.get_by_test_id("language-setting-control")
    expect(language_control.get_by_text("语言", exact=True)).to_be_visible(timeout=30_000)
    language_control.get_by_role("button", name="英文", exact=True).click()

    expect(language_control.get_by_text("Language", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="Appearance", exact=True)).to_be_visible()
    expect(page.locator("html")).to_have_attribute("lang", "en-US")
    assert page.evaluate("() => window.localStorage.getItem('omnigent.locale')") == "en-US"

    page.goto(f"{live_server}/")
    expect(page.get_by_role("heading", name="What should we build?", exact=True)).to_be_visible(
        timeout=30_000
    )
