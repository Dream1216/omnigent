"""Customer model-menu contracts; all backend edges are explicit synthetic fixtures."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect


@pytest.mark.parametrize("surface", ["session", "landing"])
@pytest.mark.parametrize("mobile", [False, True], ids=["desktop", "mobile"])
def test_customer_can_inspect_model_candidates_but_cannot_select_them(
    page: Page, chat_session_contract, surface: str, mobile: bool
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

    def catalog(request):
        reads.append(request.method)
        return {
            "runtime_enabled": False,
            "models": [
                {
                    "model_id": "deepseek-isolated-contract",
                    "display_name": "DeepSeek customer candidate",
                    "provider_id": "deepseek",
                    "channel_id": "deepseek",
                    "transport": "litellm",
                    "wire_api": "openai_responses",
                    "generation": 1,
                    "available": False,
                    "unavailable_reason": "runtime_not_enabled",
                }
            ],
        }

    handle.contract.json("/v1/managed-model-catalog", catalog)
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
    expect(section).to_contain_text("Candidates only. Runtime access is not enabled.")
    candidate = section.get_by_role(
        "menuitemcheckbox", name=re.compile("DeepSeek customer candidate")
    )
    expect(candidate).to_have_attribute("aria-disabled", "true")
    before = list(handle.session_patches)
    candidate.click(force=True)
    expect(candidate).to_have_attribute("aria-checked", "false")
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
        page.screenshot(
            path=str(
                target / f"tenant-candidates-{surface}-{'mobile' if mobile else 'desktop'}.png"
            )
        )
