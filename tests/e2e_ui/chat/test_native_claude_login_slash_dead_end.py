r"""Web /login gives a sign-in remedy without reaching the native model.

The real Claude CLI first answers a scripted expired-login message. The web
command must then be rejected explicitly, render the host sign-in remedy,
and appear in neither the canonical transcript nor model input as escaped prose.
"""

from __future__ import annotations

import json
import time

import httpx
import pytest
from playwright.sync_api import Page, expect

from tests.e2e_ui.conftest import reset_mock_llm, set_fallback_mock_llm

_COMPOSER = "Send a message…"
_ASSISTANT = '[data-testid="message-bubble"][data-role="assistant"]'
_USER = '[data-testid="message-bubble"][data-role="user"]'
_WORKING = '[data-testid="working-indicator"]'

# Must match the model in the mock anthropic provider config written by the
# native_claude_mock_session fixture (conftest._CLAUDE_MOCK_MODEL).
_CLAUDE_MOCK_MODEL = "claude-sonnet-4-20250514"

# The dead-end answer an expired Claude Code login gives every turn. The
# mock LLM plays it as the fallback for all requests, exactly reproducing
# the reported session state.
_LOGIN_EXPIRED_LINE = "Login expired · Please run /login"

# What _escape_unsupported_slash_command turns the composer's /login into
# before the bridge injects it into Claude Code's TUI: a space prefixed to
# defeat command parsing.
_ESCAPED_LOGIN = " /login"

# claude-native auto-launch + first-run pre-accept + first mock turn.
_FIRST_TURN_TIMEOUT_MS = 180_000

# How long to watch for the buggy /login turn to surface after sending.
# On the bug this trips within one mock turn (seconds); on a fixed build
# nothing arrives and the watch simply expires, letting the test pass.
_LOGIN_TURN_WATCH_S = 90.0


def _send(page: Page, text: str) -> None:
    """Type *text* into the web composer and click Send.

    :param page: The Playwright page, on the session's chat surface.
    :param text: The message body to send.
    """
    composer = page.get_by_placeholder(_COMPOSER)
    expect(composer).to_be_visible(timeout=30_000)
    composer.fill(text)
    page.get_by_role("button", name="Send", exact=True).click()


def _ensure_chat_view(page: Page) -> None:
    """Switch the terminal-first native session to its chat bubble view.

    :param page: The Playwright page, on the session's chat surface.
    """
    toggle = page.get_by_test_id("view-mode-toggle")
    expect(toggle).to_be_visible(timeout=_FIRST_TURN_TIMEOUT_MS)
    segment = page.get_by_test_id("view-mode-chat")
    expect(segment).to_be_enabled(timeout=30_000)
    segment.click()


def _user_item_texts(base_url: str, session_id: str) -> list[str]:
    """Return the canonical transcript's user-message texts, in order.

    Reads ``GET /v1/sessions/{id}/items`` — the same API both the SPA chat
    view and the TUI-parity forwarder render from — so an assertion here is
    an assertion about what the session actually recorded, not about a
    transient DOM state.

    :param base_url: Spawned server base URL.
    :param session_id: The session/conversation id.
    :returns: Each user message item's concatenated text.
    """
    resp = httpx.get(
        f"{base_url}/v1/sessions/{session_id}/items",
        params={"limit": 100, "order": "asc"},
        timeout=15.0,
    )
    resp.raise_for_status()
    texts: list[str] = []
    for item in resp.json().get("data", []):
        if item.get("type") != "message" or item.get("role") != "user":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        texts.append(
            " ".join(
                block["text"]
                for block in content
                if isinstance(block, dict) and isinstance(block.get("text"), str)
            )
        )
    return texts


def _captured_request_blob(mock_url: str) -> str:
    """Return every request body the mock LLM captured, as one JSON string.

    :param mock_url: Mock LLM server base URL.
    :returns: The serialized captured requests (``""`` when none).
    """
    resp = httpx.get(f"{mock_url}/mock/requests", timeout=15.0)
    resp.raise_for_status()
    return json.dumps(resp.json().get("requests", []), ensure_ascii=False)


@pytest.mark.nightly
@pytest.mark.timeout(600)
def test_login_slash_is_not_silently_spent_on_the_model(
    page: Page,
    native_claude_mock_session: tuple[str, str],
    mock_llm_server_url: str,
) -> None:
    """Reject web authentication commands with the host sign-in remedy.

    The first real native turn proves the browser-to-model pipeline works.
    The following command must be rejected before recording or model dispatch,
    while the browser exposes the sign-in action the user can perform.

    :param page: Playwright page with a fresh browser context.
    :param native_claude_mock_session: Native session backed by the local mock.
    :param mock_llm_server_url: Mock server whose requests are checked below.
    """
    base_url, session_id = native_claude_mock_session

    # Every model call answers with the expired-login line — the exact
    # session state the report describes. Fallbacks survive /mock/reset,
    # so Claude's background requests can't drain them.
    set_fallback_mock_llm(mock_llm_server_url, "default", _LOGIN_EXPIRED_LINE)
    set_fallback_mock_llm(mock_llm_server_url, _CLAUDE_MOCK_MODEL, _LOGIN_EXPIRED_LINE)

    page.goto(f"{base_url}/c/{session_id}")
    _ensure_chat_view(page)

    # Turn 1 — any ordinary message comes back as the dead-end line. This
    # both reproduces the reported state and proves the composer → bridge →
    # CLI → mock-LLM → transcript pipeline is live before /login is judged.
    _send(page, "hello, are you there?")
    expect(page.locator(_ASSISTANT, has_text=_LOGIN_EXPIRED_LINE).first).to_be_visible(
        timeout=_FIRST_TURN_TIMEOUT_MS
    )
    expect(page.locator(_WORKING)).to_have_count(0, timeout=60_000)

    # Clear the capture log so the /login verdict below scans only traffic
    # from the /login turn onward (set_fallback survives this reset).
    reset_mock_llm(mock_llm_server_url)

    # Turn 2 — the user does exactly what the error told them to.
    with page.expect_response(
        lambda response: (
            response.request.method == "POST"
            and response.url.endswith(f"/v1/sessions/{session_id}/events")
        ),
        timeout=30_000,
    ) as rejected:
        _send(page, "/login")
    assert rejected.value.status == 400
    error = rejected.value.json()["error"]
    assert error["code"] == "invalid_input"
    assert "Run omni setup on the host" in error["message"]
    page.get_by_test_id("error-headline").last.click()
    expect(page.get_by_text(error["message"], exact=True)).to_be_visible(timeout=30_000)
    expect(page.locator(_USER, has_text="/login")).to_have_count(0, timeout=30_000)

    # Watch for either observable half of the bug: the transcript records
    # the escaped user message, or the model receives it. On a fixed
    # build neither ever arrives and the watch expires cleanly.
    escaped_in_transcript = False
    escaped_at_model = False
    deadline = time.monotonic() + _LOGIN_TURN_WATCH_S
    while time.monotonic() < deadline:
        if any(text == _ESCAPED_LOGIN for text in _user_item_texts(base_url, session_id)):
            escaped_in_transcript = True
            break
        # Match the whole JSON string: "Please run /login" also contains " /login".
        if json.dumps(_ESCAPED_LOGIN) in _captured_request_blob(mock_llm_server_url):
            escaped_at_model = True
            break
        time.sleep(2.0)

    if escaped_in_transcript or escaped_at_model:
        where = (
            "the canonical transcript recorded the composer's /login as the "
            f"escaped prose message {_ESCAPED_LOGIN!r}"
            if escaped_in_transcript
            else f"the model received a request carrying {_ESCAPED_LOGIN!r}"
        )
        pytest.fail(
            "/login typed into a claude-native session's web "
            f"composer was silently spent as an ordinary model turn — {where}. "
            "On an expired login the model answers with the same "
            f"{_LOGIN_EXPIRED_LINE!r} dead-end, so the session can never be "
            "recovered from the web UI. /login (and /logout) must be "
            "intercepted before injection and answered with what actually "
            "re-authenticates (e.g. `omni setup` on the host) instead."
        )
