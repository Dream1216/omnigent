"""Host-owned, Runner-lifetime model transport with renewable gateway credentials."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import secrets
import socket
import threading
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Protocol
from uuid import UUID

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from omnigent.inner.model_auth import ProviderAuthRequired
from omnigent.inner.model_credential import CredentialLifecycle
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority
from saas.runner_adapter.platform_models import PLATFORM_MODEL_GATEWAY_BASE_URL

_MAX_BODY_BYTES = 2 * 1024 * 1024
_MAX_ERROR_BYTES = 16 * 1024


class RunnerProcess(Protocol):
    def wait(self) -> int: ...


class PlatformModelRelay:
    """A session-scoped capability channel; never exports signing or gateway keys.

    Harnesses may cache the local capability for their entire process lifetime.
    Only this Host-side transport reads and renews the actual gateway bearer.
    """

    def __init__(
        self,
        *,
        authority: PlatformModelGatewayTokenAuthority,
        session_id: UUID,
        ttl_seconds: int,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.capability = secrets.token_urlsafe(32)
        self._last_token = ""
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(
                timeout=httpx.Timeout(120.0, connect=10.0),
                trust_env=False,
            )
        )
        self._client: httpx.AsyncClient | None = None

        async def mint() -> str:
            self._last_token = authority.issue(
                session_id=session_id,
                ttl_seconds=ttl_seconds,
                now=int(clock()),
            )
            return self._last_token

        self.credentials = CredentialLifecycle(
            helper=mint,
            auth_required=lambda: ProviderAuthRequired("会话认证恢复失败，请联系管理员"),
            max_cache_age_s=ttl_seconds,
            refresh_skew_s=min(300, ttl_seconds / 4),
            min_refresh_interval_s=1,
            backoff_base_s=1,
            backoff_max_s=30,
            clock=clock,
        )
        self.app = self._create_app()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None

    def _create_app(self) -> FastAPI:
        @asynccontextmanager
        async def lifespan(_app: FastAPI):
            self._client = self._client_factory()
            try:
                await self.credentials.start()
                yield
            finally:
                await self.credentials.close()
                await self._client.aclose()

        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

        @app.post("/v1/responses")
        @app.post("/v1/chat/completions")
        async def model_request(request: Request):
            return await self._proxy(request)

        return app

    async def _proxy(self, request: Request) -> Response:
        if not hmac.compare_digest(
            request.headers.get("authorization", "").encode(),
            f"Bearer {self.capability}".encode(),
        ):
            return self._error(403, "platform_model_channel_invalid", "会话认证通道不可用")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > _MAX_BODY_BYTES:
                return self._error(413, "platform_model_request_invalid", "模型请求过大")
            body.extend(chunk)
        assert self._client is not None
        response: httpx.Response | None = None
        try:
            token = await self.credentials.token_for_request()
            for attempt in range(2):
                response = await self._client.send(
                    self._client.build_request(
                        "POST",
                        f"{PLATFORM_MODEL_GATEWAY_BASE_URL}{request.url.path.removeprefix('/v1')}",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json",
                            "Accept": "text/event-stream",
                        },
                        content=bytes(body),
                    ),
                    stream=True,
                )
                if response.status_code == 200:
                    return StreamingResponse(
                        self._stream(response),
                        media_type="text/event-stream",
                        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
                    )
                error_body = await self._error_body(response)
                await response.aclose()
                if not self._expired(response.status_code, error_body):
                    return Response(
                        error_body,
                        status_code=response.status_code,
                        media_type="application/json",
                        headers={"Cache-Control": "no-store"},
                    )
                if attempt == 1:
                    break
                # Only the gateway's pre-admission expiry rejection is replayable.
                # A concurrent request may already have replaced this exact token.
                if token == self._last_token:
                    self.credentials.invalidate_after_unauthorized()
                token = await self.credentials.token_for_request()
        except ProviderAuthRequired:
            return self._error(
                503,
                "platform_model_authentication_recovery_failed",
                "会话认证恢复失败，请联系管理员；未重放用户任务",
            )
        except httpx.HTTPError:
            if response is not None:
                await response.aclose()
            return self._error(502, "platform_model_transport_failed", "模型连接中断；未自动重试")
        return self._error(
            503,
            "platform_model_authentication_recovery_failed",
            "会话认证恢复失败，请联系管理员；未重放用户任务",
        )

    @staticmethod
    async def _stream(response: httpx.Response) -> AsyncIterator[bytes]:
        try:
            async for chunk in response.aiter_raw():
                yield chunk
        finally:
            await response.aclose()

    @staticmethod
    async def _error_body(response: httpx.Response) -> bytes:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > _MAX_ERROR_BYTES:
                return b'{"error":{"code":"platform_model_gateway_error"}}'
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _expired(status: int, body: bytes) -> bool:
        if status != 401:
            return False
        try:
            return json.loads(body)["error"]["code"] == "platform_model_authentication_expired"
        except (ValueError, KeyError, TypeError):
            return False

    @staticmethod
    def _error(status: int, code: str, message: str) -> JSONResponse:
        return JSONResponse(
            status_code=status,
            content={"error": {"code": code, "message": message}},
            headers={"Cache-Control": "no-store"},
        )

    def start(self) -> str:
        """Bind only loopback before starting the Runner; fail closed on startup."""
        listener = socket.socket()
        self._socket = listener
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        config = uvicorn.Config(
            self.app,
            access_log=False,
            log_level="warning",
            timeout_graceful_shutdown=2,
        )
        server = uvicorn.Server(config)
        self._server = server
        self._thread = threading.Thread(
            target=lambda: asyncio.run(server.serve(sockets=[listener])),
            daemon=True,
            name="platform-model-relay",
        )
        self._thread.start()
        deadline = time.monotonic() + 10
        while not server.started:
            if not self._thread.is_alive() or time.monotonic() >= deadline:
                self.close()
                raise OSError("Platform model authentication channel failed to start")
            time.sleep(0.01)
        return f"http://127.0.0.1:{port}/v1"

    def follow(self, process: RunnerProcess) -> None:
        """Revoke the channel when this Runner exits, including abandoned spawns."""

        def watch() -> None:
            try:
                process.wait()
            finally:
                self.close()

        threading.Thread(target=watch, daemon=True, name="platform-model-relay-owner").start()

    def close(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=4)
        if self._socket is not None:
            with contextlib.suppress(OSError):
                self._socket.close()
