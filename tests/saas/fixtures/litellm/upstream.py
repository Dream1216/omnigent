"""Disposable protocol simulator, never a production model endpoint."""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

_REQUESTS: list[dict[str, object]] = []
_LOCK = threading.Lock()
_KEY = os.environ["PROBE_PROVIDER_KEY"]


def partial_stream_requested(document):
    latest = next(
        (r for r in reversed(document.get("messages", [])) if r.get("role") == "user"), {}
    )
    if "P0_CANCEL_STREAM" not in str(latest.get("content", "")):
        return False
    if document.get("stream") is not True:
        raise ValueError("managed_probe_streaming_required")
    return True


def managed_terminal_tool(document):
    messages = document.get("messages", [])
    latest = next((r for r in reversed(messages) if r.get("role") == "user"), {})
    if "P0_MANAGED_TOOL" not in str(latest.get("content", "")):
        return None
    returned = {r.get("tool_call_id") for r in messages if r.get("role") == "tool"}
    if "call_managed_send" in returned:
        return None
    sending = "call_managed_launch" in returned
    name = "sys_terminal_send" if sending else "sys_terminal_launch"
    candidates = [
        row.get("function", {}).get("name")
        for row in document.get("tools") or []
        if row.get("function", {}).get("name") in {name, "mcp__omnigent__" + name}
    ]
    if len(candidates) != 1:
        raise ValueError("managed_probe_terminal_tool_missing")
    arguments = {"terminal": "shell", "session": "managed-probe"}
    if sending:
        arguments["text"] = "printf '%s\\n' LITELLM_TOOL_ONCE >> /workspace/litellm-once.txt"
    return {
        "id": "call_managed_send" if sending else "call_managed_launch",
        "type": "function",
        "function": {"name": candidates[0], "arguments": json.dumps(arguments)},
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/evidence":
            with _LOCK:
                body = json.dumps({"requests": list(_REQUESTS)}).encode()
            self._send(200, body)
        elif self.path == "/health":
            self._send(200, b'{"ready":true}')
        else:
            self._send(404, b'{"error":"unknown_probe_route"}')

    def do_POST(self) -> None:
        if not secrets.compare_digest(self.headers.get("Authorization", ""), f"Bearer {_KEY}"):
            self._send(401, b'{"error":{"message":"probe credential denied"}}')
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 1024 * 1024:
            self._send(400, b'{"error":"probe size rejected"}')
            return
        document = json.loads(self.rfile.read(length))
        messages = document.get("messages", [])
        text = " ".join(str(row.get("content", "")) for row in messages if isinstance(row, dict))
        tool_returned = any(
            isinstance(row, dict) and row.get("role") == "tool" for row in messages
        )
        mode = (
            "rate-limit"
            if "P0_RATE_LIMIT" in text
            else "tool"
            if "P0_TOOL" in text and not tool_returned
            else "text"
        )
        try:
            managed_tool = managed_terminal_tool(document)
            partial_stream = partial_stream_requested(document)
        except ValueError:
            self._send(422, b'{"error":{"message":"managed_probe_terminal_tool_missing"}}')
            return
        if managed_tool is not None:
            mode = "tool"
        if partial_stream:
            mode = "partial-stream"
        with _LOCK:
            record = {
                "path": self.path,
                "model": document.get("model"),
                "stream": document.get("stream"),
                "max_tokens": document.get("max_tokens"),
                "mode": mode,
                "tool_names": [
                    r.get("function", {}).get("name") for r in document.get("tools") or []
                ],
                "tool_result_ids": [
                    r.get("tool_call_id") for r in messages if r.get("role") == "tool"
                ],
            }
            _REQUESTS.append(record)
        if mode == "rate-limit":
            self._send(429, b'{"error":{"message":"probe rate limit","type":"rate_limit_error"}}')
            return
        if self.path != "/v1/chat/completions":
            self._send(404, b'{"error":{"message":"probe only serves chat completions"}}')
            return
        identifier = "chatcmpl-" + uuid4().hex
        model = document["model"]
        usage = {
            "prompt_tokens": 17,
            "completion_tokens": 5,
            "total_tokens": 22,
            "prompt_cache_hit_tokens": 9,
            "prompt_cache_miss_tokens": 8,
            "prompt_tokens_details": {"cached_tokens": 9},
        }
        tool = {
            "id": "call_p0_add",
            "type": "function",
            "function": {"name": "p0_add", "arguments": '{"a":1,"b":2}'},
        }
        if managed_tool is not None:
            tool = managed_tool
        if not document.get("stream"):
            message = {"role": "assistant", "content": "OK"}
            if mode == "tool":
                message = {"role": "assistant", "content": None, "tool_calls": [tool]}
            self._send(
                200,
                json.dumps(
                    {
                        "id": identifier,
                        "object": "chat.completion",
                        "created": int(time.time()),
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "message": message,
                                "finish_reason": "tool_calls" if mode == "tool" else "stop",
                            }
                        ],
                        "usage": usage,
                    }
                ).encode(),
            )
            return
        delta = {"content": "OK"}
        if mode == "tool":
            delta = {"tool_calls": [{"index": 0, **tool}]}
        common = {
            "id": identifier,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
        }
        events = [
            {
                **common,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            },
            {**common, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
            {
                **common,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": "tool_calls" if mode == "tool" else "stop",
                    }
                ],
            },
            {**common, "choices": [], "usage": usage},
        ]
        if partial_stream:
            prefix = "".join("data: " + json.dumps(event) + "\n\n" for event in events[:2])
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(prefix.encode())
            self.wfile.flush()
            with _LOCK:
                record["stream_started"] = True
            time.sleep(30)
            self.close_connection = True
            return
        body = "".join("data: " + json.dumps(event) + "\n\n" for event in events)
        self._send(200, (body + "data: [DONE]\n\n").encode(), "text/event-stream")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
