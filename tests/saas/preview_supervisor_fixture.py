"""Subprocess fixture for the Runner-local Preview supervisor tests."""

from __future__ import annotations

import json
import os
import signal
import time

import uvicorn
from starlette.types import Receive, Scope, Send

_late_mode_broadened = False


async def _app(scope: Scope, receive: Receive, send: Send) -> None:
    global _late_mode_broadened
    health_path = os.environ["OMNIGENT_PREVIEW_HEALTH_PATH"]
    path = str(scope.get("path", ""))
    if path == health_path:
        if (
            os.environ.get("PREVIEW_FIXTURE_LATE_BROADEN_SOCKET") == "1"
            and not _late_mode_broadened
        ):
            # Deterministically reproduce servers that broaden their UDS mode
            # after the listener first becomes visible to the supervisor.
            os.chmod(os.environ["OMNIGENT_PREVIEW_SOCKET_PATH"], 0o666)
            _late_mode_broadened = True
        if os.environ.get("PREVIEW_FIXTURE_IGNORE_TERM") == "1":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        unhealthy = os.environ.get("PREVIEW_FIXTURE_UNHEALTHY") == "1"
        body = b"unhealthy" if unhealthy else b"healthy"
        status = 503 if unhealthy else 200
    else:
        request_body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            request_body.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = json.dumps(
            {
                "body": bytes(request_body).decode(),
                "parent_api_token_present": "API_TOKEN" in os.environ,
                "method": scope.get("method"),
                "path": path,
            },
            sort_keys=True,
        ).encode()
        status = 200
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def main() -> None:
    os.umask(0o077)
    if os.environ.get("PREVIEW_FIXTURE_NEVER_BINDS") == "1":
        time.sleep(60)
        return
    if os.environ.get("PREVIEW_FIXTURE_STUBBORN_CHILD") == "1":
        child_pid = os.fork()
        if child_pid == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            while True:
                time.sleep(60)
    uvicorn.run(
        _app,
        uds=os.environ["OMNIGENT_PREVIEW_SOCKET_PATH"],
        lifespan="off",
        access_log=False,
        log_level="critical",
    )


if __name__ == "__main__":
    main()
