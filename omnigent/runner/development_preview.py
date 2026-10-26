"""Discover and relay HTTP services owned by a session's terminal processes."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import os
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode

import httpx
import psutil
from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import StreamingResponse
from websockets.asyncio.client import connect
from websockets.typing import Origin, Subprotocol

_MAX_PROCESSES = 256
_MAX_ENDPOINTS = 16
_MAX_BODY = 10 * 1024 * 1024
_FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "host",
        "connection",
        "upgrade",
        "transfer-encoding",
        "proxy-authorization",
        "proxy-authenticate",
        "x-forwarded-for",
        "x-forwarded-host",
    }
)


@dataclass(frozen=True)
class DevelopmentEndpoint:
    """An opaque identity changes when a listener's owning process is replaced."""

    id: str
    pid: int
    created_at: float
    port: int
    ipv6: bool = False

    @property
    def origin(self) -> str:
        host = "[::1]" if self.ipv6 else "127.0.0.1"
        return f"http://{host}:{self.port}"


class DevelopmentPreviewServices:
    def __init__(self, roots: Callable[[str], Iterable[int]]) -> None:
        self._roots = roots
        self._key = secrets.token_bytes(32)

    def listeners(self, session_id: str) -> list[DevelopmentEndpoint]:
        processes: dict[int, psutil.Process] = {}
        owned_sessions: set[int] = set()
        for pid in self._roots(session_id):
            try:
                root = psutil.Process(pid)
                if hasattr(os, "getsid") and os.getsid(pid) == pid:
                    owned_sessions.add(pid)
                for process in (root, *root.children(recursive=True)):
                    processes[process.pid] = process
                    if len(processes) > _MAX_PROCESSES:
                        raise RuntimeError("Preview process limit exceeded")
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
        # A background shell may exit before its server, but its kernel session stays owned.
        if owned_sessions:
            for process in psutil.process_iter():
                try:
                    if os.getsid(process.pid) in owned_sessions:
                        processes[process.pid] = process
                        if len(processes) > _MAX_PROCESSES:
                            raise RuntimeError("Preview process limit exceeded")
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        endpoints: dict[tuple[int, bool], DevelopmentEndpoint] = {}
        for process in processes.values():
            try:
                created = process.create_time()
                for connection in process.net_connections(kind="tcp"):
                    if connection.status != psutil.CONN_LISTEN or not connection.laddr:
                        continue
                    address, port = connection.laddr
                    if address not in {"127.0.0.1", "0.0.0.0", "::1", "::"}:
                        continue
                    ipv6 = ":" in address
                    identity = f"{session_id}\0{process.pid}\0{created}\0{port}\0{ipv6}"
                    endpoint_id = hmac.new(
                        self._key, identity.encode(), hashlib.sha256
                    ).hexdigest()[:32]
                    endpoints[(port, ipv6)] = DevelopmentEndpoint(
                        endpoint_id, process.pid, created, port, ipv6
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sorted(endpoints.values(), key=lambda endpoint: endpoint.port)[:_MAX_ENDPOINTS]

    async def resolve(self, session_id: str, endpoint_id: str) -> DevelopmentEndpoint:
        endpoints = await asyncio.to_thread(self.listeners, session_id)
        endpoint = next((item for item in endpoints if item.id == endpoint_id), None)
        if endpoint is None:
            raise HTTPException(404, detail={"code": "preview_listener_gone"})
        return endpoint

    async def discover(self, session_id: str) -> list[dict[str, object]]:
        endpoints = await asyncio.to_thread(self.listeners, session_id)

        async def probe(endpoint: DevelopmentEndpoint) -> dict[str, object]:
            status, kind = "unavailable", "http"
            try:
                async with (
                    httpx.AsyncClient(trust_env=False, timeout=1.5) as client,
                    client.stream("GET", endpoint.origin) as response,
                ):
                    status = "ready" if 200 <= response.status_code < 400 else "unhealthy"
                    if "text/html" in response.headers.get("content-type", ""):
                        kind = "web"
                await self.resolve(session_id, endpoint.id)
            except (httpx.HTTPError, HTTPException):
                status = "unavailable"
            return {"id": endpoint.id, "port": endpoint.port, "status": status, "kind": kind}

        return list(await asyncio.gather(*(probe(endpoint) for endpoint in endpoints)))


def register_development_preview_routes(
    app: FastAPI, roots: Callable[[str], Iterable[int]]
) -> None:
    services = DevelopmentPreviewServices(roots)
    install_development_preview_routes(app, services)


def install_development_preview_routes(app: FastAPI, services: DevelopmentPreviewServices) -> None:
    base = "/v1/sessions/{session_id}/resources/development-preview"

    @app.get(base)
    async def discover(session_id: str) -> dict[str, object]:
        return {"services": await services.discover(session_id)}

    @app.api_route(
        base + "/{endpoint_id}/http/{path:path}",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    async def forward(session_id: str, endpoint_id: str, path: str, request: Request):
        endpoint = await services.resolve(session_id, endpoint_id)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > _MAX_BODY:
                raise HTTPException(413)
        headers = {
            name: value
            for name, value in request.headers.items()
            if name.lower() not in _FORBIDDEN_HEADERS
            and not name.lower().startswith("x-omnigent-")
        }
        client = httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(30, read=None))
        try:
            upstream = await client.send(
                client.build_request(
                    request.method,
                    f"{endpoint.origin}/{path}",
                    params=request.query_params,
                    headers=headers,
                    content=bytes(body),
                ),
                stream=True,
            )
        except BaseException:
            await client.aclose()
            raise

        async def chunks():
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()
                await client.aclose()

        return StreamingResponse(
            chunks(),
            status_code=upstream.status_code,
            headers={
                name: value
                for name, value in upstream.headers.items()
                if name.lower() not in _FORBIDDEN_HEADERS | {"set-cookie", "content-length"}
            },
        )

    @app.websocket(base + "/{endpoint_id}/ws/{path:path}")
    async def websocket(session_id: str, endpoint_id: str, path: str, browser: WebSocket):
        try:
            endpoint = await services.resolve(session_id, endpoint_id)
        except HTTPException:
            await browser.close(code=1008)
            return
        query = list(parse_qsl(browser.url.query, keep_blank_values=True))
        protocols = [value for name, value in query if name == "__omnigent_protocol"]
        if len(protocols) > 8 or any(not value or len(value) > 128 for value in protocols):
            await browser.close(code=1008)
            return
        query = [(name, value) for name, value in query if name != "__omnigent_protocol"]
        url = endpoint.origin.replace("http:", "ws:", 1) + f"/{path}"
        if query:
            url += "?" + urlencode(query)
        async with connect(
            url,
            subprotocols=[Subprotocol(value) for value in protocols] or None,
            origin=Origin(endpoint.origin),
            max_size=_MAX_BODY,
        ) as upstream:
            await browser.accept()

            async def to_service():
                while True:
                    message = await browser.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    payload = message.get("text", message.get("bytes"))
                    if not isinstance(payload, (str, bytes)):
                        return
                    await upstream.send(payload)

            async def to_browser():
                async for message in upstream:
                    if isinstance(message, str):
                        await browser.send_text(message)
                    else:
                        await browser.send_bytes(message)

            async def owner_watch():
                while True:
                    await asyncio.sleep(1)
                    await services.resolve(session_id, endpoint_id)

            tasks = [asyncio.create_task(task()) for task in (to_service, to_browser, owner_watch)]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                with contextlib.suppress(RuntimeError):
                    await browser.close(code=1001)
