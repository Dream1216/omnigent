"""Persisted output browsing with both execution processes offline."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from playwright.sync_api import Page, Route, expect

from tests.browser_ui.files.test_file_line_navigation import BrowserSession
from tests.browser_ui.files.test_file_line_navigation import seeded_session as seeded_session

_SCOPE = "a" * 64
_TENANT = "11111111-1111-1111-1111-111111111111"
_SPACE = "22222222-2222-2222-2222-222222222222"
_ETAG = '"' + "b" * 32 + '"'
_PAYLOAD = "Persisted output: 中文 100%\n".encode()


def _file(path: str) -> dict[str, object]:
    return {
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "type": "file",
        "bytes": len(_PAYLOAD),
        "etag": _ETAG,
    }


def _offline(session: BrowserSession) -> str:
    session.runner_online = session.host_online = False
    api = f"/v1/sessions/{session.session_id}"
    for suffix in ("", "/filesystem", "/changes"):
        session.contract.json(
            f"{api}/resources/environments/default{suffix}",
            {"error": {"code": "runner_unavailable"}},
            status=503,
        )
    return api + "/artifacts"


def _open(page: Page, session: BrowserSession, *, mobile: bool, tab: str):
    page.set_viewport_size({"width": 390 if mobile else 1600, "height": 844 if mobile else 1000})
    page.add_init_script("localStorage.setItem('omnigent:default-workspace-panel', 'open')")
    page.goto(f"{session.contract.base_url}/c/{session.session_id}")
    if mobile:
        page.get_by_role("button", name=re.compile(r"^(Conversation|Session) actions$")).click()
        page.get_by_role("menuitem", name=tab, exact=True).click()
        panel = page.get_by_test_id("files-panel-drawer")
        expect(panel).to_have_attribute("data-state", "open")
    else:
        panel = page.get_by_role("complementary", name="Workspace", exact=True)
        panel.get_by_role("tab", name=re.compile(rf"^{tab}\b")).click()
    return panel


@pytest.mark.parametrize("mobile", [False, True], ids=["desktop", "mobile"])
@pytest.mark.parametrize("tab", ["Files", "Changes"])
def test_saved_outputs_download_without_waking_runner_or_host(
    page: Page,
    seeded_session: BrowserSession,
    mobile: bool,
    tab: str,
    tmp_path: Path,
    output_path: str,
) -> None:
    session = seeded_session
    api = _offline(session)
    session.contract.json(
        api + "/availability",
        {
            "object": "session.artifacts.availability",
            "available": True,
            "scope_key": _SCOPE,
            "tenant_id": _TENANT,
            "space_id": _SPACE,
        },
    )
    queries: list[dict[str, list[str]]] = []
    denied = False

    def listing(route: Route):
        query = parse_qs(urlparse(route.request.url).query, keep_blank_values=True)
        queries.append(query)
        assert route.request.method == "GET" and query["scope"] == [_SCOPE]
        if denied:
            route.fulfill(status=403, json={"error": {"code": "forbidden"}})
            return
        prefix = query.get("prefix", [""])[0]
        if prefix == "":
            data = [
                {
                    "path": "reports",
                    "name": "reports",
                    "type": "directory",
                    "bytes": None,
                    "etag": None,
                },
                _file("summary.txt"),
            ]
            cursor = None
        else:
            assert prefix == "reports"
            second = query.get("cursor") == ["page-two"]
            data = [_file("reports/checksum.txt" if second else "reports/中文 %.txt")]
            cursor = None if second else "page-two"
        route.fulfill(json={"object": "session.artifacts", "data": data, "next_cursor": cursor})

    session.contract.route(session.contract._matcher(api), listing)
    download_url = (
        api
        + "/content?"
        + urlencode(
            {
                "path": "reports/中文 %.txt",
                "etag": _ETAG,
                "scope": _SCOPE,
                "tenant_id": _TENANT,
                "space_id": _SPACE,
            }
        )
    )
    attachment = session.contract.attachment(
        download_url,
        _PAYLOAD,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Disposition": 'attachment; filename="report.txt"',
            "Cache-Control": "private, no-store",
        },
    )
    panel = _open(page, session, mobile=mobile, tab=tab)
    saved = panel.get_by_role("region", name="Saved outputs", exact=True)
    expect(saved).to_be_visible()
    assert queries == [] and attachment.requests == []
    saved.get_by_role("button", name="Saved outputs", exact=True).click()
    expect(saved.get_by_text("summary.txt", exact=True)).to_be_visible()
    saved.get_by_role("button", name="reports", exact=True).click()
    expect(saved.get_by_text("中文 %.txt", exact=True)).to_be_visible()
    assert attachment.requests == []
    with page.expect_download() as download_info:
        saved.get_by_role("button", name="Download 中文 %.txt", exact=True).click()
    downloaded = tmp_path / "downloaded.txt"
    download_info.value.save_as(downloaded)
    assert hashlib.sha256(downloaded.read_bytes()).digest() == hashlib.sha256(_PAYLOAD).digest()
    assert attachment.requests == [download_url]
    saved.get_by_role("button", name="Load more outputs", exact=True).click()
    expect(saved.get_by_text("checksum.txt", exact=True)).to_be_visible()
    expect(saved.get_by_text("中文 %.txt", exact=True)).to_be_visible()
    assert any(query.get("cursor") == ["page-two"] for query in queries)
    evidence = Path(output_path)
    evidence.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(evidence / "saved-outputs-offline.png"))
    assert saved.evaluate("element => element.scrollWidth <= element.clientWidth")
    denied = True
    saved.get_by_role("button", name="Refresh saved outputs", exact=True).click()
    expect(saved.get_by_role("alert")).to_have_text("You no longer have access to these outputs.")
    expect(saved.get_by_role("button", name="Download 中文 %.txt", exact=True)).to_have_count(0)
    assert not session.contract.violations


@pytest.mark.parametrize("mobile", [False, True], ids=["desktop", "mobile"])
def test_optional_saved_outputs_are_hidden_on_legacy_servers(
    page: Page, seeded_session: BrowserSession, mobile: bool
) -> None:
    _offline(seeded_session)
    panel = _open(page, seeded_session, mobile=mobile, tab="Files")
    expect(panel.get_by_role("region", name="Saved outputs", exact=True)).to_have_count(0)
