from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest


@pytest.fixture
def supplier(monkeypatch):
    monkeypatch.setenv("PROBE_PROVIDER_KEY", "isolated-not-a-provider-key")
    return runpy.run_path(str(Path(__file__).parent / "fixtures/litellm/upstream.py"))[
        "managed_terminal_tool"
    ]


def _document(*returns, followup=False):
    rows = [{"role": "user", "content": "P0_MANAGED_TOOL"}]
    rows.extend({"role": "tool", "tool_call_id": name, "content": "OK"} for name in returns)
    if followup:
        rows.append({"role": "user", "content": "Continue without writing again"})
    return {
        "messages": rows,
        "tools": [
            {"type": "function", "function": {"name": name}}
            for name in ("sys_terminal_launch", "sys_terminal_send")
        ],
    }


def test_managed_supplier_drives_only_the_declared_terminal_sequence(supplier):
    launch = supplier(_document())
    assert launch["function"]["name"] == "sys_terminal_launch"
    assert json.loads(launch["function"]["arguments"]) == {
        "terminal": "shell",
        "session": "managed-probe",
    }
    send = supplier(_document("call_managed_launch"))
    assert send["function"]["name"] == "sys_terminal_send"
    assert (
        "LITELLM_TOOL_ONCE >> /workspace/litellm-once.txt"
        in json.loads(send["function"]["arguments"])["text"]
    )
    assert supplier(_document("call_managed_launch", "call_managed_send")) is None
    assert supplier(_document("call_managed_launch", "call_managed_send", followup=True)) is None


def test_managed_supplier_never_guesses_an_undeclared_tool(supplier):
    document = _document()
    document["tools"] = []
    with pytest.raises(ValueError, match="managed_probe_terminal_tool_missing"):
        supplier(document)


@pytest.mark.parametrize("encode", [json.dumps, repr])
def test_pvc_supplier_requires_tool_success_and_does_not_repeat_the_write(supplier, encode):
    document = _document("call_managed_launch")
    document["messages"][0]["content"] += " P0_PVC_WRITE"
    document["messages"][1]["content"] = encode({"status": "launched", "has_os_env": True})
    send = supplier(document)
    assert json.loads(send["function"]["arguments"])["text"].endswith(
        'LITELLM_PVC_ONCE >> "$HOME/workspace/litellm-pvc-once.txt"'
    )
    document["messages"].append(
        {
            "role": "tool",
            "tool_call_id": "call_managed_send",
            "content": encode({"status": "sent"}),
        }
    )
    assert supplier(document) is None
    document["messages"][-1]["content"] = encode({"error": "send failed"})
    with pytest.raises(ValueError, match="managed_probe_terminal_execution_failed"):
        supplier(document)
    document["messages"].append({"role": "user", "content": "Continue without writing again"})
    assert supplier(document) is None


def test_partial_stream_requires_streaming_and_does_not_leak_into_the_next_turn(monkeypatch):
    monkeypatch.setenv("PROBE_PROVIDER_KEY", "isolated-not-a-provider-key")
    requested = runpy.run_path(str(Path(__file__).parent / "fixtures/litellm/upstream.py"))[
        "partial_stream_requested"
    ]
    document = {"stream": True, "messages": [{"role": "user", "content": "P0_CANCEL_STREAM"}]}
    assert requested(document)
    document["stream"] = False
    with pytest.raises(ValueError, match="managed_probe_streaming_required"):
        requested(document)
    document["messages"].append({"role": "user", "content": "A fresh turn"})
    assert not requested(document)


def test_crash_stream_waits_for_the_real_marker_tool_return(monkeypatch):
    monkeypatch.setenv("PROBE_PROVIDER_KEY", "isolated-not-a-provider-key")
    requested = runpy.run_path(str(Path(__file__).parent / "fixtures/litellm/upstream.py"))[
        "partial_stream_requested"
    ]
    document = _document("call_managed_launch")
    document["stream"] = True
    document["messages"][0]["content"] += " P0_CRASH_RECOVERY"
    assert not requested(document)
    document["messages"].append(
        {"role": "tool", "tool_call_id": "call_managed_send", "content": "OK"}
    )
    assert requested(document)
    document["messages"].append({"role": "user", "content": "A fresh turn"})
    assert not requested(document)
