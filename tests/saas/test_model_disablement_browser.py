from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from playwright.sync_api import Browser, expect

from tests.saas.test_platform_admin_browser import (
    PlatformAdminFixture,
    _context,
    _model_publication_journey,
    _open_console,
    _run_in_browser_thread,
    _submit_dialog,
)
from tests.saas.test_platform_admin_browser import (
    platform_admin_server as platform_admin_server,
)


def _disablement_journey(
    browser: Browser, fixture: PlatformAdminFixture, *, lost_status: int, catalog_unavailable: bool
) -> None:
    _model_publication_journey(browser, fixture)
    context = _context(browser, fixture, fixture.operator)
    receipt_id = None
    before = list(fixture.model_projection_calls)
    evidence = os.environ.get("OMNIGENT_SAAS_BROWSER_EVIDENCE_DIR")
    directory = (
        Path(evidence) / f"response-{lost_status}-catalog-error-{catalog_unavailable}"
        if evidence
        else None
    )
    if directory:
        directory.mkdir(parents=True, exist_ok=True)
    try:
        page = _open_console(context, fixture)
        page.get_by_test_id("nav-model-connections").click()
        expect(page.locator("#model-publication-status")).to_have_text("NO SCOPE")
        held = []
        page.route(
            "**/v2/platform-admin/model-publications?*", lambda route: held.append(route), times=1
        )
        page.locator("#model-publication-tenant").fill(str(fixture.tenant_id))
        page.get_by_role("button", name="核对租户候选目录", exact=False).click()
        other = str(uuid4())
        page.locator("#model-publication-tenant").fill(other)
        assert len(held) == 1
        held[0].fulfill(response=held[0].fetch())
        page.wait_for_load_state("networkidle")
        expect(page.locator("#model-publication-status")).to_have_text("NEEDS CHECK")
        expect(page.locator("#model-publication-tenant")).to_have_value(other)
        expect(page.get_by_test_id("model-publication-disable")).to_have_count(0)
        page.get_by_role("button", name="核对租户候选目录", exact=False).click()
        expect(page.locator("#model-publication-list")).to_contain_text("尚无候选目录")
        page.locator("#model-publication-tenant").fill(str(fixture.tenant_id))
        page.get_by_role("button", name="核对租户候选目录", exact=False).click()
        expect(page.get_by_test_id("model-publication-disable")).to_be_enabled()
        posts = []
        page.on(
            "request",
            lambda request: (
                posts.append(request)
                if request.method == "POST" and request.url.endswith("/disable")
                else None
            ),
        )
        page.get_by_test_id("model-publication-disable").click()
        expect(page.locator("#dialog-summary")).to_contain_text(str(fixture.tenant_id))
        expect(page.locator("#dialog-summary")).to_contain_text("不会主动中止")
        if directory:
            page.locator("#action-dialog").screenshot(
                path=str(directory / "model-disablement-confirm.png")
            )
        page.locator("#dialog-cancel").click()
        assert posts == []

        def lose_receipt(route):
            response = route.fetch()
            assert response.status == 200
            if catalog_unavailable:
                route.fulfill(response=response)
                return
            route.fulfill(
                status=lost_status,
                content_type="application/json",
                body="{}" if lost_status == 200 else '{"error":{"code":"test_lost_receipt"}}',
            )

        page.route("**/v2/platform-admin/model-publications/*/disable", lose_receipt, times=1)
        if catalog_unavailable:
            page.route(
                "**/v2/platform-admin/model-publications?*",
                lambda route: route.fulfill(
                    status=503, content_type="application/json", body="{}"
                ),
                times=1,
            )
        page.get_by_test_id("model-publication-disable").click()
        _submit_dialog(page, {})
        expect(page.locator("#model-disablement-status")).to_have_text(
            "DISABLED" if catalog_unavailable else "CHECK RECEIPT"
        )
        if catalog_unavailable:
            expect(page.locator("#model-connection-operation-detail")).to_contain_text(
                "停用回执已确认"
            )
            expect(page.get_by_test_id("model-publication-disable")).to_have_count(0)
            expect(page.locator("#model-publication-list")).to_contain_text("目录查询失败")
        else:
            expect(page.locator("#model-connection-new-command")).to_be_disabled()
            expect(page.get_by_test_id("model-publication-disable")).to_be_disabled()
        assert len(posts) == 1
        page.reload()
        expect(page.locator("#model-disablement-status")).to_have_text("DISABLED")
        expect(page.locator("#model-connection-operation-status")).to_have_text("DISABLED")
        expect(page.locator("#model-disablement-detail")).to_contain_text("至 V1（含）")
        expect(page.locator("#model-disablement-detail")).to_contain_text(
            "实际投递请在共享审计链核对"
        )
        expect(page.get_by_test_id("model-publication-disable")).to_be_disabled()
        expect(page.locator("#model-connection-new-command")).to_be_enabled()
        receipt_id = page.locator("#model-connection-operation-id").inner_text()
        listing = page.request.get(
            fixture.origin + f"/v2/platform-admin/model-publications?tenant_id={fixture.tenant_id}"
        ).json()
        assert listing["items"][0]["disabled"] is True
        assert listing["items"][0]["disablement_id"] == receipt_id
        receipt = page.request.get(
            fixture.origin + f"/v2/platform-admin/model-publication-disablements/{receipt_id}"
        )
        assert receipt.status == 200 and receipt.json()["through_generation"] == 1
        commands = page.evaluate(
            "JSON.stringify(Object.entries(sessionStorage)"
            ".filter(([key]) => key.includes('model-command')))"
        )
        assert (
            "expected_generation" not in commands
            and "browser-draft-secret-never-public" not in commands
        )
        assert len(posts) == 1 and fixture.model_projection_calls == before
        page.locator("#model-disablement-refresh").click()
        expect(page.locator("#model-disablement-status")).to_have_text("DISABLED")
        assert len(posts) == 1
        if directory:
            page.locator("#model-disablement-detail").scroll_into_view_if_needed()
            page.locator("#model-disablement-detail").screenshot(
                path=str(directory / "model-disablement-desktop.png")
            )
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        if directory:
            page.locator("#model-disablement-detail").scroll_into_view_if_needed()
            page.locator("#model-disablement-detail").screenshot(
                path=str(directory / "model-disablement-mobile.png")
            )
            page.evaluate("window.scrollTo(0,0)")
            page.screenshot(
                path=str(directory / "model-disablement-mobile-full.png"), full_page=True
            )
        page.reload()
        expect(page.locator("#model-disablement-status")).to_have_text("DISABLED")
        assert len(posts) == 1 and fixture.model_projection_calls == before
    finally:
        context.close()
    context = _context(browser, fixture, fixture.privacy_reader)
    try:
        page = _open_console(context, fixture, fragment="#model-connections")
        page.locator("#model-publication-tenant").fill(str(fixture.tenant_id))
        page.get_by_role("button", name="核对租户候选目录", exact=False).click()
        expect(page.locator("#model-publication-list")).to_contain_text("已停用至 V1")
        expect(page.get_by_test_id("model-publication-disable")).to_be_disabled()
        page.get_by_test_id("model-disablement-read").click()
        expect(page.locator("#model-disablement-detail")).to_contain_text(receipt_id)
        expect(page.locator("#model-disablement-status")).to_have_text("DISABLED")
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    finally:
        context.close()


@pytest.mark.parametrize("platform_admin_server", ["publication"], indirect=True)
@pytest.mark.parametrize(
    "lost_status,catalog_unavailable", ((200, False), (503, False), (200, True))
)
def test_real_chromium_model_disablement_scope_recovery_readonly_and_mobile(
    platform_admin_server: PlatformAdminFixture,
    lost_status: int,
    catalog_unavailable: bool,
) -> None:
    _run_in_browser_thread(
        platform_admin_server,
        lambda browser, fixture: _disablement_journey(
            browser, fixture, lost_status=lost_status, catalog_unavailable=catalog_unavailable
        ),
    )
