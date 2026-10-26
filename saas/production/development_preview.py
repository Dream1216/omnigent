"""Isolated-origin gateway for interactive HTTP and HMR over the Runner tunnel."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send

from omnigent.runtime import get_runner_ws_factory
from omnigent.server.routes.terminal_attach import _shuttle_ws_frames
from saas.control_plane.development_preview import (
    DevelopmentPreviewGrants,
    DevelopmentPreviewScope,
)
from saas.control_plane.http_auth import SaasPrincipal

_COOKIE = "__Host-omnigent_dev_preview"
_LOGGER = logging.getLogger(__name__)
_BODY_LIMIT = 10 * 1024 * 1024
_REQUEST_HEADERS = frozenset(
    {"accept", "accept-language", "content-type", "if-none-match", "if-modified-since", "range"}
)
_RESPONSE_HEADERS = frozenset(
    {"content-type", "content-encoding", "etag", "last-modified", "content-range", "accept-ranges"}
)


class DevelopmentPreviewBroker:
    def __init__(
        self,
        *,
        grants: DevelopmentPreviewGrants,
        root_domain: str,
        primary_origin: str,
        release_incarnation: str,
        principal: Callable[[HTTPConnection], SaasPrincipal | None],
        live: Callable[[DevelopmentPreviewScope], AbstractAsyncContextManager[httpx.AsyncClient]],
    ) -> None:
        if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)+", root_domain):
            raise ValueError("Development preview root domain is invalid")
        origin = urlsplit(primary_origin)
        port = f":{origin.port}" if origin.port not in (None, 443) else ""
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.username
            or origin.password
            or origin.path
            or origin.query
            or origin.fragment
            or primary_origin != f"https://{origin.hostname}{port}"
            or origin.hostname == root_domain
            or origin.hostname.endswith("." + root_domain)
        ):
            raise ValueError("Development preview primary origin must be canonical HTTPS")
        self.grants, self.root_domain, self.primary_origin = grants, root_domain, primary_origin
        if re.fullmatch(r"[0-9a-f]{32}", release_incarnation) is None:
            raise ValueError("Development preview release incarnation is invalid")
        self.release_incarnation = release_incarnation
        self._port = port
        self.principal, self.live = principal, live
        self.host_pattern = re.compile(rf"^dev-([0-9a-f]{{32}})\.{re.escape(root_domain)}$")
        self.gateway = self._gateway()

    def host(self, preview_id: UUID) -> str:
        return f"dev-{preview_id.hex}.{self.root_domain}"

    def origin(self, preview_id: UUID) -> str:
        return f"https://{self.host(preview_id)}{self._port}"

    def preview_id(self, connection: HTTPConnection) -> UUID:
        match = self.host_pattern.fullmatch(connection.url.hostname or "")
        if match is None:
            raise HTTPException(403)
        return UUID(match[1])

    async def open(self, request: Request, session_id: str, endpoint_id: str) -> dict[str, str]:
        principal = self.principal(request)
        if principal is None or principal.runtime_context is None:
            raise HTTPException(403)
        runtime, session = principal.runtime_context, principal.session
        scope = DevelopmentPreviewScope(
            id=uuid4(),
            actor_id=session.user_id,
            tenant_id=runtime.tenant_id,
            space_id=runtime.space_id,
            auth_session_id=session.session_id,
            security_version=session.security_version,
            runtime_partition_id=runtime.runtime_partition_id,
            release_incarnation=self.release_incarnation,
            session_id=session_id,
            endpoint_id=endpoint_id,
        )
        async with self.live(scope):
            expires = min(
                int(session.expires_at.timestamp()),
                int(datetime.now(timezone.utc).timestamp()) + 3600,
            )
            launch = await asyncio.to_thread(self.grants.issue, scope, expires)
        return {
            "preview_id": str(scope.id),
            "url": f"{self.origin(scope.id)}/__omnigent/authorize",
            "token": launch,
            "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
        }

    async def stop(self, request: Request, session_id: str, preview_id: str) -> None:
        principal = self.principal(request)
        if principal is None or principal.runtime_context is None:
            raise HTTPException(403)
        runtime = principal.runtime_context
        try:
            grant_id = UUID(preview_id)
        except ValueError:
            raise HTTPException(404) from None

        def revoke() -> None:
            scope = self.grants.owned_scope(
                grant_id,
                actor_id=principal.session.user_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
            )
            if scope.session_id != session_id:
                raise HTTPException(404)
            self.grants.revoke(scope)

        await asyncio.to_thread(revoke)

    async def _authorized(self, connection: HTTPConnection) -> DevelopmentPreviewScope:
        scope = await asyncio.to_thread(
            self.grants.authorize, connection.cookies.get(_COOKIE, ""), self.preview_id(connection)
        )
        if scope.release_incarnation != self.release_incarnation:
            raise HTTPException(403)
        return scope

    def _gateway(self) -> FastAPI:
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        @app.exception_handler(HTTPException)
        async def denied(_request: Request, error: HTTPException):
            return JSONResponse(
                {"detail": "Development preview unavailable"},
                status_code=error.status_code,
                headers={"Cache-Control": "no-store"},
            )

        @app.post("/__omnigent/authorize")
        async def exchange(request: Request):
            if request.headers.get("origin") != self.primary_origin:
                raise HTTPException(403)
            if (
                request.url.query
                or request.headers.get("content-type", "").split(";")[0]
                != "application/x-www-form-urlencoded"
            ):
                raise HTTPException(400)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 8192:
                    raise HTTPException(413)
            try:
                values = parse_qs(body.decode("ascii"), max_num_fields=1, strict_parsing=True)
                if set(values) != {"token"} or len(values["token"]) != 1:
                    raise ValueError("invalid handoff")
                token = values["token"][0]
            except (UnicodeError, ValueError):
                raise HTTPException(400) from None
            claims = self.grants.decode(token, "launch").scope_value()
            if claims.release_incarnation != self.release_incarnation:
                raise HTTPException(403)
            async with self.live(claims):
                cookie, _ = await asyncio.to_thread(
                    self.grants.exchange, token, self.preview_id(request)
                )
            # Commit a document on the preview site before navigating with its Strict cookie.
            response = HTMLResponse(
                '<!doctype html><html><head><meta charset="utf-8">'
                '<meta http-equiv="refresh" content="0;url=/"><title>打开预览</title>'
                '</head><body><a href="/">继续打开预览</a></body></html>',
                headers={
                    "Cache-Control": "no-store",
                    "Referrer-Policy": "no-referrer",
                    "Content-Security-Policy": (
                        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
                    ),
                },
            )
            response.set_cookie(
                _COOKIE,
                cookie,
                secure=True,
                httponly=True,
                samesite="strict",
                path="/",
                max_age=max(
                    0,
                    self.grants.decode(cookie, "session").exp
                    - int(datetime.now(timezone.utc).timestamp()),
                ),
            )
            return response

        @app.api_route(
            "/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        )
        async def proxy(path: str, request: Request):
            scope = await self._authorized(request)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > _BODY_LIMIT:
                    raise HTTPException(413)
            runner_path = (
                f"/v1/sessions/{scope.session_id}/resources/development-preview/"
                f"{scope.endpoint_id}/http/{quote(path, safe='/')}"
            )
            async with self.live(scope) as client:
                upstream = await client.send(
                    client.build_request(
                        request.method,
                        runner_path,
                        params=request.query_params,
                        headers={
                            name: value
                            for name, value in request.headers.items()
                            if name.lower() in _REQUEST_HEADERS
                        },
                        content=bytes(body),
                    ),
                    stream=True,
                )
            headers = {
                name: value
                for name, value in upstream.headers.items()
                if name.lower() in _RESPONSE_HEADERS
            }
            headers.update(
                {
                    "Cache-Control": "no-store",
                    "Referrer-Policy": "no-referrer",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": (
                        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                        "font-src 'self' data:; connect-src 'self' wss://"
                        + self.host(scope.id)
                        + self._port
                        + "; "
                        "worker-src 'self' blob:; object-src 'none'; base-uri 'self'; "
                        "frame-ancestors " + self.primary_origin
                    ),
                }
            )
            location = upstream.headers.get("location")
            if location is not None:
                if not location.startswith("/") or location.startswith("//"):
                    await upstream.aclose()
                    raise HTTPException(502)
                headers["Location"] = location

            async def chunks() -> AsyncIterator[bytes]:
                try:
                    async for chunk in upstream.aiter_raw():
                        await self._authorized(request)
                        async with self.live(scope):
                            pass
                        yield chunk
                finally:
                    await upstream.aclose()

            return StreamingResponse(chunks(), status_code=upstream.status_code, headers=headers)

        @app.websocket("/{path:path}")
        async def websocket(path: str, browser: WebSocket):
            try:
                scope = await self._authorized(browser)
                if browser.headers.get("origin") != self.origin(scope.id):
                    raise HTTPException(403)
                protocols = browser.headers.get("sec-websocket-protocol", "").split(",")
                protocols = [value.strip() for value in protocols if value.strip()]
                if len(protocols) > 8 or any(len(value) > 128 for value in protocols):
                    raise HTTPException(400)
                query = list(browser.query_params.multi_items())
                if any(name == "__omnigent_protocol" for name, _ in query):
                    raise HTTPException(400)
                query.extend(("__omnigent_protocol", value) for value in protocols)
                runner_path = (
                    f"/v1/sessions/{scope.session_id}/resources/development-preview/"
                    f"{scope.endpoint_id}/ws/{quote(path, safe='/')}?{urlencode(query)}"
                )
                factory = get_runner_ws_factory()
                if factory is None:
                    raise HTTPException(503)
                async with self.live(scope):
                    connection = factory(runner_path)
                async with connection as upstream:
                    await browser.accept(subprotocol=protocols[0] if protocols else None)

                    async def watch() -> None:
                        while True:
                            await asyncio.sleep(1)
                            await self._authorized(browser)
                            async with self.live(scope):
                                pass

                    tasks = [
                        asyncio.create_task(_shuttle_ws_frames(browser, upstream)),
                        asyncio.create_task(watch()),
                    ]
                    try:
                        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    finally:
                        for task in tasks:
                            task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
                        with contextlib.suppress(RuntimeError):
                            await browser.close(code=1008)
            except Exception as error:  # noqa: BLE001 - relay failures must not expose internal endpoints.
                _LOGGER.debug("Development preview socket denied (%s)", type(error).__name__)
                with contextlib.suppress(RuntimeError):
                    await browser.close(code=1008)

        return app


class DevelopmentPreviewHostMiddleware:
    """Keep user HTML outside the primary SaaS origin and authentication stack."""

    def __init__(self, app: ASGIApp, broker: DevelopmentPreviewBroker) -> None:
        self.app, self.broker = app, broker

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in {"http", "websocket"}:
            connection = HTTPConnection(scope)
            if self.broker.host_pattern.fullmatch(connection.url.hostname or ""):
                await self.broker.gateway(scope, receive, send)
                return
        await self.app(scope, receive, send)
