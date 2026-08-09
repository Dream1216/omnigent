from __future__ import annotations

from pathlib import Path

import pytest


def _chromium_is_installed() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).is_file()
    except Exception:
        return False


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    browser_items = [item for item in items if item.path.name.endswith("_browser.py")]
    if not browser_items or _chromium_is_installed():
        return
    missing_browser = pytest.mark.skip(
        reason="Chromium is not installed in this generic test lane; SaaS compatibility runs it"
    )
    for item in browser_items:
        item.add_marker(missing_browser)
