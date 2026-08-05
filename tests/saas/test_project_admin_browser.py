from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
import uvicorn
from playwright.sync_api import Locator, Page, expect

from tests.saas.test_http_cookie_auth import _build_fastapi_app


@dataclass(frozen=True, slots=True)
class BrowserFixture:
    origin: str
    scope: dict[str, str]


@pytest.fixture
def project_admin_server() -> Iterator[BrowserFixture]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    app, scope = _build_fastapi_app(origin)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [sock]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        raise RuntimeError("Project Admin browser fixture did not start")
    try:
        yield BrowserFixture(origin, scope)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


def test_real_browser_project_permission_deny_grant_allow_revoke_deny(
    page: Page,
    project_admin_server: BrowserFixture,
) -> None:
    fixture = project_admin_server
    browser_errors: list[str] = []
    failed_responses: list[str] = []
    page.on(
        "console",
        lambda message: browser_errors.append(message.text) if message.type == "error" else None,
    )
    page.on("pageerror", lambda error: browser_errors.append(str(error)))
    page.on(
        "response",
        lambda response: (
            failed_responses.append(f"{response.status} {response.url}")
            if response.status >= 400
            else None
        ),
    )
    page.goto(
        f"{fixture.origin}/saas/admin/projects"
        f"?tenant={fixture.scope['tenant_id']}&space={fixture.scope['space_id']}"
    )

    page.get_by_test_id("login-email").fill("http@example.com")
    page.get_by_test_id("login-password").fill("initial-http-password")
    page.get_by_test_id("login-submit").click()
    expect(page.get_by_test_id("scope-connect")).to_be_visible()
    expect(page.locator("#permission-count")).to_contain_text("2026-08-05.p6")

    page.get_by_test_id("scope-connect").click()
    expect(page.get_by_test_id("context-state")).to_contain_text("SPACE /")

    page.get_by_test_id("project-name").fill("Browser Permission Matrix")
    page.get_by_test_id("project-create").click()
    expect(page.get_by_test_id("selected-project-name")).to_have_text("Browser Permission Matrix")
    expect(page.locator("#project-version")).to_have_text("V1")

    page.get_by_test_id("decision-subject").fill(fixture.scope["member_id"])
    page.get_by_test_id("decision-run").click()
    expect(page.get_by_test_id("decision-result")).to_contain_text("DENIED")
    expect(page.get_by_test_id("decision-result")).to_contain_text("permission_not_granted · V1")

    page.get_by_test_id("member-subject").fill(fixture.scope["member_id"])
    page.get_by_test_id("member-grant").click()
    expect(page.locator("#project-version")).to_have_text("V2")
    page.get_by_test_id("decision-run").click()
    expect(page.get_by_test_id("decision-result")).to_contain_text("ALLOWED")
    expect(page.get_by_test_id("decision-result")).to_contain_text("allowed · V2")
    expect(page.locator("#decision-sources")).to_contain_text("project_membership / read")

    page.get_by_test_id("member-revoke").click()
    expect(page.locator("#project-version")).to_have_text("V3")
    page.get_by_test_id("decision-run").click()
    expect(page.get_by_test_id("decision-result")).to_contain_text("DENIED")
    expect(page.get_by_test_id("decision-result")).to_contain_text("permission_not_granted · V3")
    expect(page.get_by_test_id("event-log")).to_contain_text("Membership revoked at V3")
    assert browser_errors == [], failed_responses


def _login_and_connect(page: Page, email: str, password: str) -> None:
    page.get_by_test_id("login-email").fill(email)
    page.get_by_test_id("login-password").fill(password)
    page.get_by_test_id("login-submit").click()
    expect(page.get_by_test_id("scope-connect")).to_be_visible()
    page.get_by_test_id("scope-connect").click()
    expect(page.get_by_test_id("context-state")).to_contain_text("SPACE /")


def _confirm_dialog(page: Page, reason: str) -> None:
    expect(page.get_by_test_id("action-dialog")).to_be_visible()
    page.get_by_test_id("action-reason").fill(reason)
    page.get_by_test_id("action-confirm").click()
    expect(page.get_by_test_id("action-dialog")).not_to_be_visible()


def _approval_card(page: Page, list_testid: str, target_name: str) -> Locator:
    return page.get_by_test_id(list_testid).locator(".approval-card").filter(has_text=target_name)


def test_real_browser_enterprise_approval_desk_separates_request_decision_and_execution(
    page: Page,
    project_admin_server: BrowserFixture,
) -> None:
    fixture = project_admin_server
    browser_errors: list[str] = []
    failed_responses: list[str] = []
    page.on(
        "console",
        lambda message: browser_errors.append(message.text) if message.type == "error" else None,
    )
    page.on("pageerror", lambda error: browser_errors.append(str(error)))
    page.on(
        "response",
        lambda response: (
            failed_responses.append(f"{response.status} {response.url}")
            if response.status >= 400
            else None
        ),
    )
    page.goto(f"{fixture.origin}/saas/admin/projects")

    _login_and_connect(page, "http@example.com", "initial-http-password")
    page.get_by_test_id("project-name").fill("Approval Browser Project")
    page.get_by_test_id("project-create").click()
    expect(page.get_by_test_id("selected-project-name")).to_have_text("Approval Browser Project")
    page.get_by_test_id("member-subject").fill(fixture.scope["member_id"])
    page.get_by_test_id("member-role").select_option("manage")
    page.get_by_test_id("member-grant").click()
    expect(page.locator("#project-version")).to_have_text("V2")

    page.evaluate(
        """
        () => {
          const nativeFetch = window.fetch.bind(window);
          let delayFirstGroupRead = true;
          window.fetch = async (input, init = {}) => {
            const url = typeof input === "string" ? input : input.url;
            const method = (init.method || "GET").toUpperCase();
            if (delayFirstGroupRead && method === "GET" && url.includes("/groups?limit=100")) {
              delayFirstGroupRead = false;
              const staleResponse = await nativeFetch(input, init);
              await new Promise((resolve) => window.setTimeout(resolve, 750));
              return staleResponse;
            }
            return nativeFetch(input, init);
          };
        }
        """
    )
    page.get_by_test_id("view-approvals").click()
    expect(page.get_by_test_id("approval-board")).to_be_visible()
    for name in ("Archive Candidate", "Rejected Candidate"):
        page.get_by_test_id("group-name").fill(name)
        page.get_by_test_id("group-create").click()
        expect(page.get_by_test_id("group-list")).to_contain_text(name)
    page.wait_for_timeout(900)
    expect(page.get_by_test_id("group-list")).to_contain_text("Archive Candidate")
    expect(page.get_by_test_id("group-list")).to_contain_text("Rejected Candidate")
    page.get_by_test_id("role-name").fill("Retire Candidate")
    page.get_by_test_id("role-create").click()
    expect(page.get_by_test_id("role-list")).to_contain_text("Retire Candidate")

    group_list = page.get_by_test_id("group-list")
    group_list.locator(".governance-row").filter(has_text="Archive Candidate").get_by_role(
        "button", name="PREPARE ARCHIVE"
    ).click()
    _confirm_dialog(page, "replace archive candidate with directory group")
    expect(page.get_by_test_id("my-preflights")).to_contain_text("Archive Candidate")

    group_list.locator(".governance-row").filter(has_text="Rejected Candidate").get_by_role(
        "button", name="PREPARE ARCHIVE"
    ).click()
    _confirm_dialog(page, "evaluate rejected candidate dependencies")
    expect(page.get_by_test_id("my-preflights")).to_contain_text("Rejected Candidate")

    page.get_by_test_id("role-list").locator(".governance-row").filter(
        has_text="Retire Candidate"
    ).get_by_role("button", name="PREPARE RETIRE").click()
    _confirm_dialog(page, "replace custom role with managed policy")
    expect(page.get_by_test_id("my-preflights")).to_contain_text("Retire Candidate")

    page.locator("#logout-button").click()
    expect(page.get_by_test_id("login-submit")).to_be_visible()
    _login_and_connect(page, "member@example.com", "initial-member-password")
    page.get_by_test_id("project-list").locator(".project-row").filter(
        has_text="Approval Browser Project"
    ).click()
    page.get_by_test_id("view-approvals").click()
    expect(page.locator("#approval-count")).to_have_text("03")

    archive_card = _approval_card(page, "approval-inbox", "Archive Candidate")
    archive_card.get_by_role("button", name="APPROVE").click()
    _confirm_dialog(page, "directory group has been verified")

    rejected_card = _approval_card(page, "approval-inbox", "Rejected Candidate")
    rejected_card.get_by_role("button", name="REJECT").click()
    _confirm_dialog(page, "active integration still depends on this group")

    role_card = _approval_card(page, "approval-inbox", "Retire Candidate")
    role_card.get_by_role("button", name="APPROVE").click()
    _confirm_dialog(page, "managed policy replacement is active")
    expect(page.locator("#approval-count")).to_have_text("00")

    page.locator("#logout-button").click()
    _login_and_connect(page, "http@example.com", "initial-http-password")
    page.get_by_test_id("project-list").locator(".project-row").filter(
        has_text="Approval Browser Project"
    ).click()
    page.get_by_test_id("view-approvals").click()

    owner_archive = _approval_card(page, "my-preflights", "Archive Candidate")
    expect(owner_archive).to_contain_text("APPROVED")
    owner_archive.get_by_role("button", name="EXECUTE APPROVED CHANGE").click()
    expect(page.get_by_test_id("action-reason")).to_have_value(
        "replace archive candidate with directory group"
    )
    page.get_by_test_id("action-confirm").click()
    expect(page.get_by_test_id("action-dialog")).not_to_be_visible()

    owner_role = _approval_card(page, "my-preflights", "Retire Candidate")
    expect(owner_role).to_contain_text("APPROVED")
    owner_role.get_by_role("button", name="EXECUTE APPROVED CHANGE").click()
    expect(page.get_by_test_id("action-reason")).to_have_value(
        "replace custom role with managed policy"
    )
    page.get_by_test_id("action-confirm").click()
    expect(page.get_by_test_id("action-dialog")).not_to_be_visible()

    rejected_owner = _approval_card(page, "my-preflights", "Rejected Candidate")
    expect(rejected_owner).to_contain_text("REJECTED")
    expect(rejected_owner.get_by_role("button", name="EXECUTE APPROVED CHANGE")).to_have_count(0)
    expect(
        page.get_by_test_id("group-list")
        .locator(".governance-row")
        .filter(has_text="Archive Candidate")
    ).to_contain_text("ARCHIVED")
    expect(
        page.get_by_test_id("role-list")
        .locator(".governance-row")
        .filter(has_text="Retire Candidate")
    ).to_contain_text("RETIRED")
    expect(page.get_by_test_id("event-log")).to_contain_text("executed")
    assert browser_errors == [], failed_responses
