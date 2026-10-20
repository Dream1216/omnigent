"""Customer model-menu contracts; all backend edges are explicit synthetic fixtures."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from playwright.sync_api import Page, expect


@pytest.mark.parametrize("surface", ["session", "landing"])
@pytest.mark.parametrize("mobile", [False, True], ids=["desktop", "mobile"])
@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "available"])
@pytest.mark.parametrize("paged", [False, True], ids=["single-page", "paged-retry"])
def test_customer_model_availability_and_selection(
    page: Page, chat_session_contract, surface: str, mobile: bool, enabled: bool, paged: bool
) -> None:
    handle = chat_session_contract
    handle.info_updates.update(login_url="/saas/login", single_user=False)
    handle.contract.json("/v1/me", {"user_id": "tenant-user", "is_admin": False})
    handle.contract.json(f"/v1/sessions/{handle.session_id}/owner", {"owner": "tenant-user"})
    handle.contract.json(
        f"/v1/sessions/{handle.session_id}/permissions",
        {"object": "list", "data": [], "has_more": False},
    )
    handle.contract.json(
        f"/saas/delivery/sessions/{handle.session_id}",
        {"detail": {"code": "delivery_unavailable"}},
        status=404,
    )
    handle.set_catalog(
        harness="claude-native",
        models=[{"id": "sonnet", "displayName": "Existing approved model", "isDefault": True}],
        selected_model="sonnet",
    )
    reads = []
    cursor = "00000000-0000-0000-0000-000000000025"
    failed_pages = []

    def catalog(request):
        reads.append(request.method)
        result = {
            "runtime_enabled": enabled,
            "models": [
                {
                    "model_id": "deepseek-isolated-contract",
                    "display_name": "DeepSeek customer candidate",
                    "provider_id": "deepseek",
                    "channel_id": "deepseek",
                    "transport": "litellm",
                    "wire_api": "openai_responses",
                    "generation": 1,
                    "configuration_revision": f"managed-model:openai_responses:1:{'a' * 64}",
                    "available": enabled,
                    "unavailable_reason": None if enabled else "runtime_not_enabled",
                }
            ],
        }
        continuation = parse_qs(urlparse(request.url).query).get("cursor", [None])[0]
        assert continuation in (None, cursor)
        result["next_cursor"] = cursor if paged and continuation is None else None
        if continuation:
            result["models"][0].update(
                model_id="deepseek-second-page",
                display_name="DeepSeek second page",
                configuration_revision=f"managed-model:openai_responses:1:{'b' * 64}",
            )
        return result

    handle.contract.json("/v1/managed-model-catalog", catalog)
    if paged:

        def fail_once(route):
            if f"cursor={cursor}" in route.request.url and not failed_pages:
                failed_pages.append(route.request.method)
                route.fulfill(
                    status=503,
                    content_type="application/json",
                    body='{"detail":"synthetic read failure"}',
                )
            else:
                route.fallback()

        page.route("**/v1/managed-model-catalog?**", fail_once)
    handle.contract.json(
        re.compile(r"/v1/hosts/[^/]+/filesystem(?:/[^?]*)?(?:\?.*)?$"),
        {"object": "list", "data": [], "has_more": False},
    )
    if mobile:
        page.set_viewport_size({"width": 390, "height": 844})
    page.goto(handle.url if surface == "session" else handle.base_url + "/")
    if surface == "session":
        page.get_by_test_id("composer-config-gear").click()
        page.get_by_test_id("composer-agent-edit").click()
    else:
        page.get_by_test_id("new-chat-landing-agent-select").click()
        row = page.get_by_test_id(f"new-chat-landing-agent-config-{handle.agent_id}")
        if row.count() == 0:
            page.get_by_test_id("new-chat-landing-harness-more").click()
        row.get_by_text("Edit", exact=True).click()
    section = page.get_by_test_id("tenant-managed-model-candidates")
    expect(section).to_be_visible()
    expect(section).to_contain_text("DeepSeek · via LiteLLM · Responses")
    if not enabled:
        expect(section).to_contain_text("Candidates only. Runtime access is not enabled.")
    elif surface == "session":
        expect(section).to_contain_text("Start a new session to select this model")
    candidate = section.get_by_role(
        "menuitemcheckbox", name=re.compile("DeepSeek customer candidate")
    )
    selectable = enabled and surface == "landing"
    if selectable:
        expect(candidate).not_to_have_attribute("aria-disabled", "true")
    else:
        expect(candidate).to_have_attribute("aria-disabled", "true")
    before = list(handle.session_patches)
    candidate.scroll_into_view_if_needed()
    expect(candidate).to_be_in_viewport()
    candidate.click(force=True)
    expect(candidate).to_have_attribute("aria-checked", "true" if selectable else "false")
    if paged:
        assert len(reads) == 1
        section.get_by_role("menuitem", name="Load more models", exact=True).click()
        expect(
            section.get_by_text("Platform model catalog is temporarily unavailable.", exact=True)
        ).to_be_visible()
        expect(candidate).to_have_attribute("aria-checked", "true" if selectable else "false")
        assert failed_pages == ["GET"] and len(reads) == 1
        section.get_by_role("menuitem", name="Retry model catalog", exact=True).click()
        second = section.get_by_role("menuitemcheckbox", name=re.compile("DeepSeek second page"))
        expect(second).to_be_visible()
        expect(section.get_by_role("menuitem", name="Load more models", exact=True)).to_have_count(
            0
        )
        second.scroll_into_view_if_needed()
        expect(second).to_be_in_viewport()
        second.click(force=True)
        expect(second).to_have_attribute("aria-checked", "true" if selectable else "false")
        expect(candidate).to_have_attribute("aria-checked", "false")
        assert len(reads) == 2
    assert handle.session_patches == before
    assert reads and set(reads) == {"GET"}
    assert not handle.event_posts
    bounds = section.bounding_box()
    assert bounds and bounds["x"] >= 0
    assert bounds["x"] + bounds["width"] <= page.viewport_size["width"] + 1
    # Separators deliberately bleed into the menu padding; text must not overflow.
    for content in section.locator('[role="status"], [role="menuitemcheckbox"]').all():
        assert content.evaluate("element => element.scrollWidth <= element.clientWidth + 1")
    evidence = os.environ.get("OMNIGENT_SAAS_BROWSER_EVIDENCE_DIR")
    if evidence:
        target = Path(evidence)
        target.mkdir(parents=True, exist_ok=True)
        filename = (
            f"tenant-candidates-{surface}-{'mobile' if mobile else 'desktop'}"
            f"-{enabled}{'-paged' if paged else ''}.png"
        )
        page.screenshot(path=str(target / filename))
