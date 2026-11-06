"""Bearer-only HTTPS entry for cloud Hosts using the existing internal model gateway."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable, Mapping
from uuid import UUID

import httpx
from anyio import CancelScope
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from omnigent.host.identity import MANAGED_HOST_TOKEN_HEADER, MANAGED_HOST_WORKSPACE_HEADER
from omnigent.runner.identity import RUNNER_TUNNEL_TOKEN_HEADER
from saas.runner_adapter.platform_model_gateway import (
    PlatformModelGatewayClaims,
    PlatformModelGatewayTokenAuthority,
    PlatformModelGatewayTokenError,
    PlatformModelGatewayTokenExpired,
)
from saas.runner_adapter.platform_models import PLATFORM_MODEL_GATEWAY_BASE_URL

MODEL_INGRESS_BASE_PATH = "/saas/models/v1"
_MAX_BODY_BYTES = 2 * 1024 * 1024
_MAX_ERROR_BYTES = 16 * 1024
_FORBIDDEN_HEADERS = frozenset(
    {
        "cookie",
        "origin",
        MANAGED_HOST_TOKEN_HEADER.lower(),
        "x-omnigent-model-lease",
        MANAGED_HOST_WORKSPACE_HEADER.lower(),
        RUNNER_TUNNEL_TOKEN_HEADER.lower(),
    }
)


class _ModelStreamInterrupted(RuntimeError):
    """The admitted stream failed without a replayable pre-admission rejection."""


class AliyunModelIngress:
    """Forward one admitted request without exporting keys or replaying model work."""

    def __init__(
        self,
        authorities: Mapping[UUID, PlatformModelGatewayTokenAuthority],
        *,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not 1 <= len(authorities) <= 32 or any(
            tenant.int == 0 or tenant != authority.tenant_id
            for tenant, authority in authorities.items()
        ):
            raise ValueError("Model ingress authorities are invalid")
        self._authorities = tuple(authorities.values())
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(
                timeout=httpx.Timeout(120.0, connect=10.0),
                trust_env=False,
                follow_redirects=False,
            )
        )
        self._clock = clock

    def router(self) -> APIRouter:
        router = APIRouter(prefix="/models/v1")

        @router.post("/responses", include_in_schema=False)
        async def responses(request: Request):
            return await self.proxy(request, path="responses")

        @router.post("/chat/completions", include_in_schema=False)
        async def chat_completions(request: Request):
            return await self.proxy(request, path="chat/completions")

        return router

    def _authenticate(self, request: Request) -> tuple[str, PlatformModelGatewayClaims]:
        headers = request.headers
        authorization = headers.getlist("authorization")
        if (
            request.url.query
            or any(name in headers for name in _FORBIDDEN_HEADERS)
            or len(authorization) != 1
            or not authorization[0].startswith("Bearer ")
            or len(authorization[0]) > 8192
        ):
            raise PlatformModelGatewayTokenError("Model ingress credentials are invalid")
        token = authorization[0][7:]
        now = int(self._clock())
        for authority in self._authorities:
            try:
                claims = authority.validate(token, now=now)
            except PlatformModelGatewayTokenExpired:
                raise
            except PlatformModelGatewayTokenError:
                continue
            if claims.expires_at - claims.issued_at > 300:
                break
            return token, claims
        raise PlatformModelGatewayTokenError("Model ingress credentials are invalid")

    async def proxy(self, request: Request, *, path: str) -> Response:
        if path not in {"responses", "chat/completions"}:
            raise ValueError("Model ingress route is invalid")
        try:
            token, claims = self._authenticate(request)
        except PlatformModelGatewayTokenExpired:
            return _error(401, "platform_model_authentication_expired")
        except PlatformModelGatewayTokenError:
            return _error(401, "platform_model_authentication_invalid")
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
            return _error(400, "platform_model_request_invalid")

        client: httpx.AsyncClient | None = None
        response: httpx.Response | None = None
        handed_off = False
        submitted = False

        async def close() -> None:
            nonlocal client, response
            with CancelScope(shield=True):
                try:
                    if response is not None:
                        current, response = response, None
                        await current.aclose()
                finally:
                    if client is not None:
                        current_client, client = client, None
                        await current_client.aclose()

        try:
            async with asyncio.timeout(max(0, claims.expires_at - self._clock())):
                body = bytearray()
                async for chunk in request.stream():
                    if len(body) + len(chunk) > _MAX_BODY_BYTES:
                        return _error(413, "platform_model_request_invalid")
                    body.extend(chunk)
                client = self._client_factory()
                submitted = True
                response = await client.send(
                    client.build_request(
                        "POST",
                        f"{PLATFORM_MODEL_GATEWAY_BASE_URL}/{path}",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json",
                            "Accept": "text/event-stream",
                            "Accept-Encoding": "identity",
                        },
                        content=bytes(body),
                    ),
                    stream=True,
                    follow_redirects=False,
                )
                if response.status_code != 200:
                    return await self._upstream_error(response)
                if (
                    response.headers.get("content-type", "").split(";", 1)[0]
                    != "text/event-stream"
                    or response.headers.get("content-encoding", "identity") != "identity"
                ):
                    return _error(502, "platform_model_transport_failed")
                streaming_response = response

                async def stream() -> AsyncIterator[bytes]:
                    try:
                        async with asyncio.timeout(max(0, claims.expires_at - self._clock())):
                            async for chunk in streaming_response.aiter_raw():
                                if self._clock() >= claims.expires_at:
                                    raise _ModelStreamInterrupted("Model stream interrupted")
                                yield chunk
                    except (TimeoutError, httpx.HTTPError):
                        raise _ModelStreamInterrupted("Model stream interrupted") from None
                    finally:
                        await close()

                result = StreamingResponse(
                    stream(),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
                    background=BackgroundTask(close),
                )
                handed_off = True
                return result
        except TimeoutError:
            return (
                _error(502, "platform_model_transport_failed")
                if submitted
                else _error(401, "platform_model_authentication_expired")
            )
        except httpx.HTTPError:
            return _error(502, "platform_model_transport_failed")
        finally:
            if not handed_off:
                await close()

    @staticmethod
    async def _upstream_error(response: httpx.Response) -> Response:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > _MAX_ERROR_BYTES:
                return _error(502, "platform_model_transport_failed")
            body.extend(chunk)
        # Only an explicit pre-admission expiry rejection permits Host renewal/retry.
        if response.status_code == 401:
            try:
                expired = (
                    json.loads(body)["error"]["code"] == "platform_model_authentication_expired"
                )
            except (ValueError, TypeError, KeyError):
                expired = False
            return _error(
                401,
                "platform_model_authentication_expired"
                if expired
                else "platform_model_authentication_invalid",
            )
        status = response.status_code
        if status in {400, 403, 409, 413, 429, 502, 503}:
            return _error(status, "platform_model_gateway_rejected")
        return _error(502, "platform_model_transport_failed")


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code}},
        headers={"Cache-Control": "no-store"},
    )
