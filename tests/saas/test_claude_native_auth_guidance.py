"""Compatibility contracts for the upstream Claude-native auth-guidance backport."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from omnigent.harnesses.claude_native import bridge
from omnigent.inner import claude_native_executor
from omnigent.inner.executor import ExecutorConfig, ExecutorError, TurnComplete


@pytest.mark.parametrize(
    "text", ["/login", " /login ", "\n/logout", "/login help", "/logout\t now"]
)
def test_interactive_auth_commands_are_recognized(text: str) -> None:
    assert bridge.is_auth_slash_command(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "hello",
        "explain /login",
        "/LOGIN",
        "/login-helper",
        "/login/path",
        "/loginfoo",
        "/model",
        "/clear",
        "/skill",
        "https://example.test/login",
    ],
)
def test_ordinary_messages_and_commands_are_unchanged(text: str) -> None:
    assert not bridge.is_auth_slash_command(text)


def _read_text(tmp_path: Path, raw: str, flag: Any, nested: bool, blocks: bool) -> str:
    message: dict[str, Any] = {
        "role": "assistant",
        "content": [{"type": "text", "text": raw}] if blocks else raw,
    }
    entry: dict[str, Any] = {"type": "assistant", "uuid": "auth-error", "message": message}
    (message if nested else entry)["isApiErrorMessage"] = flag
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    _, _, items = bridge.read_transcript_items_since(transcript, 0, agent_name="claude-native-ui")
    assert len(items) == 1
    return items[0].data["content"][0]["text"]


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("blocks", [False, True])
@pytest.mark.parametrize(
    "raw",
    [
        "Not logged in · Please run /login",
        "Login expired · Please run /login\n",
        "Unset CLAUDE_CODE_OAUTH_TOKEN, then /logout and /login.",
        "Credit balance too low; check billing before /login.",
    ],
)
def test_flagged_login_errors_keep_original_remedy(
    tmp_path: Path, raw: str, nested: bool, blocks: bool
) -> None:
    text = _read_text(tmp_path, raw, True, nested, blocks)
    assert text == raw.rstrip() + (
        "\n\n`/login` is not available from the Omnigent web chat — run "
        "`omni setup` on the host to sign in again."
    )


@pytest.mark.parametrize("flag", [None, False, 1, "true"])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("blocks", [False, True])
def test_model_prose_and_non_boolean_flags_are_not_rewritten(
    tmp_path: Path, flag: Any, nested: bool, blocks: bool
) -> None:
    raw = "Not logged in · Please run /login"
    assert _read_text(tmp_path, raw, flag, nested, blocks) == raw


@pytest.mark.parametrize(
    "raw",
    [
        "Unset ANTHROPIC_API_KEY, then /logout",
        "See https://example.test/login",
        "Read /tmp/login",
        "Try /loginfoo",
        "Try /LOGIN",
        "Ordinary text",
    ],
)
def test_unrelated_flagged_errors_keep_exact_text(tmp_path: Path, raw: str) -> None:
    assert _read_text(tmp_path, raw, True, False, True) == raw


def test_context_overflow_guidance_keeps_precedence(tmp_path: Path) -> None:
    text = _read_text(tmp_path, "Prompt is too long; /login", True, True, True)
    assert text == bridge._CONTEXT_OVERFLOW_REPLACEMENT


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["/login", " /logout ", "\n/login help"])
@pytest.mark.parametrize("steering", [False, True])
async def test_auth_turn_and_live_steering_never_inject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str, steering: bool
) -> None:
    calls: list[str] = []

    def capture(*args: Any, **kwargs: Any) -> None:
        calls.append(str(kwargs.get("content", "slash-command")))

    monkeypatch.setattr(claude_native_executor, "inject_user_message", capture)
    monkeypatch.setattr(claude_native_executor, "inject_slash_command", capture)
    executor = claude_native_executor.ClaudeNativeExecutor(tmp_path)
    if steering:
        assert not await executor.enqueue_session_message("session", text)
        assert calls == []
        return
    events = [
        event
        async for event in executor.run_turn(
            messages=[{"role": "user", "content": text}],
            tools=[],
            system_prompt="",
            config=ExecutorConfig(model="sonnet"),
        )
    ]
    assert len(events) == 1
    assert isinstance(events[0], ExecutorError)
    assert "omni setup on the host" in events[0].message
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["hello", "explain /login", "/model", "/clear", "/my-skill"])
async def test_normal_turns_and_steering_still_inject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    calls: list[str] = []

    def capture(*args: Any, **kwargs: Any) -> None:
        calls.append(kwargs["content"])

    monkeypatch.setattr(claude_native_executor, "inject_user_message", capture)
    executor = claude_native_executor.ClaudeNativeExecutor(tmp_path)
    assert await executor.enqueue_session_message("session", text)
    events = [
        event
        async for event in executor.run_turn(
            messages=[{"role": "user", "content": text}], tools=[], system_prompt=""
        )
    ]
    assert events == [TurnComplete(response=None)]
    assert calls == [text, text]
