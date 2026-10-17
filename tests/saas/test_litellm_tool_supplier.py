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
