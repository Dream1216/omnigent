"""Browser contracts for text that dictation and snippet tools put in the composer.

These tools paste by putting text on the clipboard, sending the paste shortcut,
and restoring the old clipboard right after. That needs a focused composer once
a session opens, and a paste that survives the clipboard changing mid-paste.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

from tests.browser_ui.chat.session_contract import ChatSessionContract

_DICTATED = "dictated words"
# Rewrites the clipboard after the page's paste handlers ran, while the browser is
# still inserting, as a tool restoring the old clipboard does. Chrome 155+ then
# drops the paste; this lane's older Chromium pastes the restored text instead.
_RESTORE_CLIPBOARD_MID_PASTE = """
window.addEventListener("paste", () => {
  const restore = (event) => {
    event.clipboardData.setData("text/plain", "old clipboard");
    event.preventDefault();
  };
  document.addEventListener("copy", restore, { once: true });
  document.execCommand("copy");
}, { once: true });
"""


@pytest.mark.parametrize("surface", ["session", "landing"])
def test_paste_keeps_its_text_when_the_clipboard_changes_mid_paste(
    page: Page, chat_session_contract: ChatSessionContract, surface: str
) -> None:
    chat = chat_session_contract
    page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=chat.base_url)
    if surface == "session":
        page.goto(chat.url)
        composer = page.get_by_role("textbox", name="Message the agent")
    else:
        chat.contract.json(f"/v1/hosts/{chat.host_id}/filesystem", {"path": "/", "entries": []})
        page.goto(chat.base_url)
        composer = page.get_by_test_id("new-chat-landing-input")
    expect(composer).to_be_enabled(timeout=30_000)
    composer.click()
    page.evaluate("text => navigator.clipboard.writeText(text)", _DICTATED)
    page.evaluate(_RESTORE_CLIPBOARD_MID_PASTE)

    page.keyboard.press("ControlOrMeta+V")

    expect(composer).to_have_value(_DICTATED)


def test_composer_takes_focus_once_it_enables(
    page: Page, chat_session_contract: ChatSessionContract
) -> None:
    """A composer mounted before its session agent binding arrives focuses when enabled.

    Session hydration now precedes the composer's mount. Start with an unbound
    session, then deliver the ordinary binding event while keeping the same
    mounted composer; no agent-list request or transient timing is assumed.
    """
    chat = chat_session_contract
    chat.update_session(agent_id=None, agent_name=None)
    page.goto(chat.url)
    composer = page.get_by_role("textbox", name="Message the agent")
    expect(composer).to_be_disabled(timeout=30_000)
    mounted_composer = composer.element_handle()
    assert mounted_composer is not None
    chat.wait_for_stream()

    chat.update_session(agent_id=chat.agent_id, agent_name=chat.agent_id)
    chat.emit(
        {
            "event": "session.agent_changed",
            "data": {
                "type": "session.agent_changed",
                "conversation_id": chat.session_id,
                "agent_id": chat.agent_id,
                "agent_name": chat.agent_id,
            },
        }
    )

    expect(composer).to_be_enabled()
    assert composer.evaluate("(current, original) => current === original", mounted_composer)
    expect(composer).to_be_focused()
