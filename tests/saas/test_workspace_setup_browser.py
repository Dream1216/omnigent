from __future__ import annotations

import os
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page, Route, expect

from tests.saas.test_identity_ui_browser import identity_browser as identity_browser
from tests.saas.test_identity_ui_browser import identity_ui_server as identity_ui_server

_INTENT = "154c148d-daf0-49d9-a1f7-ec7ec5fcefd7"
_TENANT = "4e3b4229-c665-4229-932a-6e80105249a6"
_SPACE = "4acfd1a9-8930-49c7-b4c4-f56434b8c8ee"
_CSRF = "omnigent.saas.csrf"


def _setup(page: Page, *, scopes: list | None = None, intents: list | None = None) -> None:
    page.route(
        "**/saas/auth/bootstrap",
        lambda route: route.fulfill(
            json={
                "authenticated": True,
                "user_id": "a67e8369-8383-40f4-b615-c930d804aab4",
                "scopes": scopes or [],
                "next": "/setup",
            }
        ),
    )
    page.route(
        "**/saas/onboarding/catalog",
        lambda route: route.fulfill(
            json={
                "plans": [{"key": "starter", "trial_days": 14}],
                "regions": ["cn-east-1"],
            }
        ),
    )
    page.route("**/saas/onboarding/workspaces", lambda route: route.fulfill(json=intents or []))
    page.add_init_script(f"localStorage.setItem('{_CSRF}', 'initial-test-csrf')")


def _capture(page: Page, filename: str) -> None:
    if location := os.environ.get("E2E_SCREENSHOT_DIR"):
        path = Path(location)
        path.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path / filename), full_page=True)


@pytest.mark.parametrize(
    "locale,submit,message,retry,signin",
    [
        (
            "en-US",
            "Create a workspace",
            "We are checking your sign-in information.",
            "Try again",
            "Sign in again",
        ),
        ("zh-CN", "创建工作空间", "正在核对登录信息", "重试", "重新登录"),
    ],
)
def test_pending_phone_readback_keeps_draft_and_request_key_for_safe_retry(
    identity_browser: Browser,
    identity_ui_server: str,
    locale: str,
    submit: str,
    message: str,
    retry: str,
    signin: str,
) -> None:
    page = identity_browser.new_page()
    _setup(page)
    requests = []
    alert = page.get_by_role(
        "alert", name="工作空间开通错误" if locale == "zh-CN" else "Workspace setup error"
    )

    def create(route: Route) -> None:
        if route.request.method == "GET":
            route.fulfill(json=[])
            return
        requests.append(
            (route.request.headers.get("idempotency-key"), route.request.post_data_json)
        )
        if len(requests) == 1:
            route.fulfill(
                status=503,
                headers={"Retry-After": "5", "Cache-Control": "no-store"},
                json={"detail": {"code": "identity_verification_pending"}},
            )
        else:
            route.fulfill(status=202, json={"id": _INTENT, "name": "Phone workspace"})

    page.route("**/saas/onboarding/workspaces", create)
    page.route(
        f"**/saas/onboarding/workspaces/{_INTENT}/status",
        lambda route: route.fulfill(json={"state": "provisioning", "stage": "runtime"}),
    )
    page.goto(identity_ui_server + "/setup?new=1&ui_locale=" + locale)
    page.locator("#workspace-name").fill("Phone workspace")
    page.get_by_role("button", name=submit, exact=True).click()
    expect(alert).to_contain_text(message)
    expect(page.get_by_role("link", name=signin, exact=True)).to_have_count(0)
    expect(page.locator("#workspace-name")).to_have_value("Phone workspace")
    _capture(page, "phone-readback-pending-" + locale + ".png")
    page.get_by_role("button", name=retry, exact=True).click()
    expect(alert).to_have_count(0)
    # Retrying the error reloads safe reads; submission reuses the same request.
    page.get_by_role("button", name=submit, exact=True).click()
    expect(
        page.get_by_role(
            "heading",
            name="工作空间正在准备中" if locale == "zh-CN" else "Your workspace is taking shape",
        )
    ).to_be_visible()
    assert f"intent={_INTENT}" in page.url
    assert len(requests) == 2 and requests[0] == requests[1]
    _capture(page, "phone-readback-retried-" + locale + ".png")
    page.close()


def test_setup_retains_language_draft_and_request_key_across_network_retry_and_reload(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context(locale="zh-CN", viewport={"width": 390, "height": 844})
    page = context.new_page()
    _setup(page)
    requests = []
    accepted = False

    def create(route: Route) -> None:
        nonlocal accepted
        if route.request.method == "GET":
            route.fulfill(json=[])
            return
        requests.append(
            {
                "body": route.request.post_data_json,
                "key": route.request.headers.get("idempotency-key"),
                "csrf": route.request.headers.get("x-csrf-token"),
            }
        )
        if not accepted:
            accepted = True
            route.abort("failed")
        else:
            route.fulfill(status=202, json={"id": _INTENT, "name": "探索空间"})

    page.route("**/saas/onboarding/workspaces", create)
    page.route(
        f"**/saas/onboarding/workspaces/{_INTENT}/status",
        lambda route: route.fulfill(
            json={
                "state": "ready_for_first_run",
                "stage": "first_run",
                "tenant_id": _TENANT,
                "space_id": _SPACE,
            }
        ),
    )
    opened = []

    def select(route: Route) -> None:
        opened.append(route.request.post_data_json)
        route.fulfill(status=204)

    page.route("**/saas/auth/active-scope", select)
    page.route(
        identity_ui_server + "/",
        lambda route: route.fulfill(body="<h1>Workspace opened</h1>", content_type="text/html"),
    )
    page.goto(identity_ui_server + "/setup?new=1")
    page.get_by_label("工作空间名称").fill("探索空间")
    page.get_by_role("button", name="英文", exact=True).click()
    expect(page.get_by_label("Workspace name")).to_have_value("探索空间")
    _capture(page, "workspace-setup-mobile.png")
    page.evaluate(f"localStorage.setItem('{_CSRF}', 'current-test-csrf')")
    page.get_by_role("button", name="Create a workspace", exact=True).click()
    expect(page.get_by_role("alert", name="Workspace setup error")).to_contain_text(
        "Could not reach"
    )
    page.reload()
    page.get_by_label("Workspace name").fill("探索空间")
    page.get_by_role("button", name="Create a workspace", exact=True).click()
    expect(page.get_by_role("heading", name="Your workspace is ready")).to_be_visible()
    assert len(requests) == 2 and requests[0]["key"] == requests[1]["key"]
    assert requests[0]["body"] == requests[1]["body"] == {"tenant_name": "探索空间"}
    assert requests[0]["csrf"] == "current-test-csrf"
    assert "workspace-request" not in page.evaluate("JSON.stringify(sessionStorage)")
    _capture(page, "workspace-ready.png")
    page.get_by_role("button", name="Open workspace", exact=True).click()
    expect(page.get_by_role("heading", name="Workspace opened")).to_be_visible()
    assert opened == [{"tenant_id": _TENANT, "space_id": _SPACE}]
    context.close()


def test_workspace_picker_selects_server_scope_and_rejects_external_return_target(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    page = identity_browser.new_page()
    _setup(
        page,
        scopes=[
            {
                "tenant_id": _TENANT,
                "space_id": _SPACE,
                "tenant_name": "Research team",
                "space_name": "Default",
            },
            {
                "tenant_id": _SPACE,
                "space_id": _TENANT,
                "tenant_name": "Operations",
                "space_name": "Shared",
            },
        ],
    )
    captured = []

    def select(route: Route) -> None:
        captured.append(route.request.post_data_json)
        route.fulfill(status=204)

    page.route("**/saas/auth/active-scope", select)
    page.route(
        identity_ui_server + "/",
        lambda route: route.fulfill(body="<h1>Chosen workspace</h1>", content_type="text/html"),
    )
    page.goto(identity_ui_server + "/setup?new=1&return_to=https%3A%2F%2Fevil.example")
    expect(page.get_by_label("Workspace name")).to_be_visible()
    _capture(page, "workspace-picker-desktop.png")
    page.get_by_role("button", name="Research team Default").click()
    expect(page.get_by_role("heading", name="Chosen workspace")).to_be_visible()
    assert captured == [{"tenant_id": _TENANT, "space_id": _SPACE}]
    assert page.url == identity_ui_server + "/"
    page.close()


def test_setup_recovers_same_pending_intent_without_creating_another_workspace(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    page = identity_browser.new_page()
    _setup(page, intents=[{"id": _INTENT, "name": "Pending workspace"}])
    failed = True
    posts = []

    def status(route: Route) -> None:
        route.fulfill(
            status=503 if failed else 200,
            json={}
            if failed
            else {
                "state": "provisioning",
                "stage": "runtime",
            },
        )

    page.route(f"**/saas/onboarding/workspaces/{_INTENT}/status", status)
    page.on(
        "request", lambda request: posts.append(request.url) if request.method == "POST" else None
    )
    page.goto(identity_ui_server + "/setup")
    expect(page.get_by_role("alert", name="Workspace setup error")).to_be_visible()
    failed = False
    page.get_by_role("button", name="Try again", exact=True).click()
    expect(page.get_by_role("alert", name="Workspace setup error")).to_have_count(0)
    expect(
        page.get_by_text("Setup continues safely in the background", exact=False)
    ).to_be_visible()
    assert posts == []
    page.close()


def test_setup_invitation_uses_only_the_existing_acceptance_contract_and_clears_token(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    page = identity_browser.new_page()
    _setup(page)
    accepted = []

    def accept(route: Route) -> None:
        accepted.append(route.request.post_data_json)
        route.fulfill(json={"tenant_id": _TENANT, "space_id": _SPACE})

    page.route("**/saas/membership-invitations/accept", accept)
    page.goto(identity_ui_server + "/setup?new=1")
    page.get_by_role("button", name="Have an invitation?").click()
    invitation = "synthetic-invitation-code-00000001"
    page.get_by_label("Invitation code").fill(invitation)
    page.get_by_role("button", name="Accept invitation", exact=True).click()
    expect(page.get_by_text("Invitation accepted.", exact=False)).to_be_visible()
    expect(page.get_by_label("Invitation code")).to_have_value("")
    assert accepted == [{"token": invitation}]
    assert (
        page.evaluate("JSON.stringify(localStorage)+JSON.stringify(sessionStorage)").find(
            invitation
        )
        == -1
    )
    page.close()


def test_setup_storage_failure_prevents_non_recoverable_workspace_submission(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    context = identity_browser.new_context()
    context.add_init_script(
        "Object.defineProperty(window,'sessionStorage',{get(){throw new Error('blocked')}})"
    )
    page = context.new_page()
    _setup(page)
    posts = []
    page.on(
        "request", lambda request: posts.append(request.url) if request.method == "POST" else None
    )
    page.goto(identity_ui_server + "/setup?new=1")
    page.get_by_label("Workspace name").fill("Storage unavailable")
    page.get_by_role("button", name="Create a workspace", exact=True).click()
    expect(page.get_by_role("alert", name="Workspace setup error")).to_contain_text(
        "Browser storage is unavailable"
    )
    assert posts == []
    context.close()


def test_signed_out_setup_never_offers_workspace_creation(
    identity_browser: Browser,
    identity_ui_server: str,
) -> None:
    page = identity_browser.new_page()
    _setup(page)
    page.route(
        "**/saas/auth/bootstrap",
        lambda route: route.fulfill(json={"authenticated": False, "scopes": []}),
    )
    page.goto(identity_ui_server + "/setup")
    expect(page.get_by_role("link", name="Sign in again", exact=True)).to_have_attribute(
        "href", "/saas/login?return_to=%2Fsetup"
    )
    expect(page.get_by_label("Workspace name")).to_have_count(0)
    page.close()
