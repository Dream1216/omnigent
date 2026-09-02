"""Cookie-isolated Preview gateway transport for fenced Runner routes."""

from __future__ import annotations

import re
from collections.abc import AsyncIterable, AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

from saas.control_plane import (
    IsolationControlPlaneError,
    PreviewRouteGrant,
)
from saas.control_plane.preview_sessions import PreviewSessionError

PREVIEW_COOKIE_NAME = "__Host-omnigent_preview"
_EXCHANGE_PATH = "/__omnigent/authorize"
_BOOTSTRAP_PATH = "/__omnigent/bootstrap"
_BOOTSTRAP_SCRIPT_PATH = "/__omnigent/bootstrap.js"
_INTERNAL_PATHS = frozenset({_EXCHANGE_PATH, _BOOTSTRAP_PATH, _BOOTSTRAP_SCRIPT_PATH})
_BOOTSTRAP_CSP = (
    "default-src 'none'; script-src 'self'; form-action 'self'; "
    "connect-src 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
_BOOTSTRAP_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": _BOOTSTRAP_CSP,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
_BOOTSTRAP_HTML = (
    b"<!doctype html><html><head><meta charset=utf-8>"
    b"<meta name=referrer content=no-referrer><title>Opening Preview</title>"
    b"<script src=/__omnigent/bootstrap.js defer></script></head>"
    b"<body><p id=status>Opening Preview...</p></body></html>"
)
_BOOTSTRAP_SCRIPT = b"""(() => {
  'use strict';
  const fragment = window.location.hash;
  window.history.replaceState(null, '', window.location.pathname);
  const fail = () => {
    document.getElementById('status').textContent = 'Preview authorization failed.';
  };
  if (!fragment.startsWith('#token=')) { fail(); return; }
  let token;
  try { token = decodeURIComponent(fragment.slice(7)); }
  catch (_error) { fail(); return; }
  if (!/^[A-Za-z0-9_-]{32,512}$/.test(token)) { fail(); return; }
  const form = document.createElement('form');
  form.method = 'post';
  form.action = '/__omnigent/authorize';
  form.autocomplete = 'off';
  const field = document.createElement('input');
  field.type = 'hidden';
  field.name = 'token';
  field.value = token;
  form.appendChild(field);
  document.body.appendChild(form);
  form.submit();
})();
"""
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_UPSTREAM_RESPONSE_HEADERS = frozenset(
    {"cache-control", "content-language", "content-type", "etag", "last-modified"}
)
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class PreviewAuthority(Protocol):
    """Exact token/host/fence authorization supplied by the control plane."""

    def authorize_preview_request(
        self,
        *,
        host: str,
        token: str,
        incoming_headers: dict[str, str],
    ) -> PreviewRouteGrant: ...


class PreviewBrowserSessionGrantLike(Protocol):
    @property
    def route(self) -> PreviewRouteGrant: ...

    @property
    def session_token(self) -> str | None: ...


class PreviewBrowserSessionAuthority(Protocol):
    """One-use exchange plus independent rotating browser-session authority."""

    def exchange(
        self,
        *,
        host: str,
        exchange_token: str,
        now: datetime | None = None,
    ) -> PreviewBrowserSessionGrantLike: ...

    def authorize_and_rotate(
        self,
        *,
        host: str,
        session_token: str,
        incoming_headers: dict[str, str],
        now: datetime | None = None,
    ) -> PreviewBrowserSessionGrantLike: ...


@dataclass(frozen=True, slots=True)
class PreviewTunnelRequest:
    route: PreviewRouteGrant
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class PreviewTunnelResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes | AsyncIterable[bytes]


class PreviewTunnel(Protocol):
    """Runner-facing transport; production implementations authenticate both peers."""

    async def forward(self, request: PreviewTunnelRequest) -> PreviewTunnelResponse: ...


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": {"code": code, "message": message}})


def _host(request: Request) -> str:
    raw = request.headers.get("host", "").strip()
    if (
        not raw
        or any(character.isspace() for character in raw)
        or any(separator in raw for separator in "/?#")
    ):
        raise IsolationControlPlaneError("preview_host_invalid", "Preview host is invalid")
    try:
        parsed = urlsplit(f"//{raw}")
        hostname = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError as exc:
        raise IsolationControlPlaneError(
            "preview_host_invalid", "Preview host port is invalid"
        ) from exc
    if (
        not hostname
        or not _HOST.fullmatch(hostname)
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise IsolationControlPlaneError("preview_host_invalid", "Preview host is invalid")
    if port not in {None, 443}:
        raise IsolationControlPlaneError("preview_host_invalid", "Preview host port is invalid")
    return hostname


async def _body(request: Request, *, maximum: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise IsolationControlPlaneError(
                "preview_content_length_invalid", "Preview content length is invalid"
            ) from exc
        if declared < 0 or declared > maximum:
            raise IsolationControlPlaneError(
                "preview_body_too_large", "Preview request body is too large"
            )
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > maximum:
            raise IsolationControlPlaneError(
                "preview_body_too_large", "Preview request body is too large"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _exchange_token(request: Request, body: bytes) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        return authorization[7:].strip()
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/x-www-form-urlencoded":
        return ""
    try:
        form = parse_qs(body.decode("utf-8", errors="strict"), keep_blank_values=True)
    except UnicodeError:
        return ""
    tokens = form.get("token", [])
    return tokens[0].strip() if len(tokens) == 1 else ""


def _request_headers(request: Request) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in request.headers.items()
        if key.lower()
        not in _HOP_BY_HOP
        | {
            "authorization",
            "cookie",
            "host",
            "x-forwarded-access-token",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
        }
    }


def _path(request: Request) -> tuple[str, str]:
    path = request.url.path
    query = request.url.query
    if (
        not path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(segment == ".." for segment in path.split("/"))
        or len(path) > 4096
        or len(query) > 8192
    ):
        raise IsolationControlPlaneError("preview_path_invalid", "Preview path is invalid")
    return path, query


def _response_headers(response: PreviewTunnelResponse, route: PreviewRouteGrant) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in response.headers.items():
        lowered = key.lower()
        if lowered in _UPSTREAM_RESPONSE_HEADERS and "\r" not in value and "\n" not in value:
            safe[lowered] = value
    safe.update(route.response_headers)
    safe["Cache-Control"] = "no-store"
    return safe


async def _close_response_body(body: bytes | AsyncIterable[bytes]) -> None:
    if isinstance(body, bytes):
        return
    close = getattr(body, "aclose", None)
    if close is not None:
        await close()


async def _bounded_response_body(
    body: bytes | AsyncIterable[bytes], *, maximum: int
) -> AsyncIterator[bytes]:
    received = 0
    try:
        if isinstance(body, bytes):
            chunks: AsyncIterable[bytes] = _one_chunk(body)
        else:
            chunks = body
        async for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise ValueError("Preview tunnel emitted a non-bytes response chunk")
            received += len(chunk)
            if received > maximum:
                raise ValueError("Preview tunnel response exceeded the byte limit")
            if chunk:
                yield chunk
    finally:
        await _close_response_body(body)


async def _one_chunk(body: bytes) -> AsyncIterator[bytes]:
    if body:
        yield body


def create_preview_gateway_app(
    *,
    authority: PreviewAuthority,
    tunnel: PreviewTunnel,
    maximum_request_bytes: int = 1_048_576,
    maximum_response_bytes: int = 10_485_760,
) -> FastAPI:
    """Create the independent Preview-origin app; never mount it on the SaaS cookie domain."""

    if maximum_request_bytes <= 0 or maximum_response_bytes <= 0:
        raise ValueError("Preview gateway byte limits must be positive")
    app = FastAPI(title="Omnigent Preview Gateway", docs_url=None, redoc_url=None)

    @app.post(_EXCHANGE_PATH, include_in_schema=False)
    async def exchange(request: Request) -> Response:
        try:
            if any(name != PREVIEW_COOKIE_NAME for name in request.cookies):
                raise IsolationControlPlaneError(
                    "preview_ambient_cookie_denied", "Ambient cookies are not accepted"
                )
            body = await _body(request, maximum=4096)
            token = _exchange_token(request, body)
            if not token:
                raise IsolationControlPlaneError(
                    "preview_token_required", "Preview token is required"
                )
            route = await run_in_threadpool(
                authority.authorize_preview_request,
                host=_host(request),
                token=token,
                incoming_headers={},
            )
        except IsolationControlPlaneError as error:
            return _error(403, error.code, str(error))
        maximum_age = max(
            1,
            int((route.expires_at - datetime.now(timezone.utc)).total_seconds()),
        )
        response = Response(
            status_code=303,
            headers={
                "Location": "/",
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
            },
        )
        response.set_cookie(
            PREVIEW_COOKIE_NAME,
            token,
            max_age=maximum_age,
            secure=True,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return response

    @app.api_route(
        "/{preview_path:path}",
        methods=sorted(_METHODS),
        include_in_schema=False,
    )
    async def proxy(preview_path: str, request: Request) -> Response:
        del preview_path
        if request.url.path == _EXCHANGE_PATH:
            return _error(405, "preview_method_denied", "Preview exchange requires POST")
        token = request.cookies.get(PREVIEW_COOKIE_NAME, "")
        if not token:
            return _error(401, "preview_token_required", "Preview authorization is required")
        if any(name != PREVIEW_COOKIE_NAME for name in request.cookies):
            return _error(403, "preview_ambient_cookie_denied", "Ambient cookies are not accepted")
        if request.headers.get("authorization"):
            return _error(
                403,
                "preview_ambient_authorization_denied",
                "Ambient authorization is not accepted",
            )
        try:
            host = _host(request)
            path, query = _path(request)
            headers = _request_headers(request)
            body = await _body(request, maximum=maximum_request_bytes)
            route = await run_in_threadpool(
                authority.authorize_preview_request,
                host=host,
                token=token,
                incoming_headers=headers,
            )
            upstream = await tunnel.forward(
                PreviewTunnelRequest(
                    route=route,
                    method=request.method,
                    path=path,
                    query=query,
                    headers=route.upstream_request_headers,
                    body=body,
                )
            )
            if not 200 <= upstream.status_code <= 599:
                raise ValueError("Preview tunnel returned an invalid status")
            if isinstance(upstream.body, bytes) and len(upstream.body) > maximum_response_bytes:
                raise ValueError("Preview tunnel response exceeded the byte limit")
            content_length = next(
                (
                    value
                    for key, value in upstream.headers.items()
                    if key.lower() == "content-length"
                ),
                None,
            )
            if content_length is not None and (
                not content_length.isdigit() or int(content_length) > maximum_response_bytes
            ):
                raise ValueError("Preview tunnel response exceeded the byte limit")
        except IsolationControlPlaneError as error:
            return _error(403, error.code, str(error))
        except Exception:  # noqa: BLE001 - tunnel failures must collapse to a secretless 502
            return _error(502, "preview_tunnel_unavailable", "Preview tunnel is unavailable")
        headers = _response_headers(upstream, route)
        if request.method == "HEAD":
            try:
                await _close_response_body(upstream.body)
            except Exception:  # noqa: BLE001 - collapse transport details at the gateway
                return _error(502, "preview_tunnel_unavailable", "Preview tunnel is unavailable")
            return Response(content=b"", status_code=upstream.status_code, headers=headers)
        return StreamingResponse(
            _bounded_response_body(upstream.body, maximum=maximum_response_bytes),
            status_code=upstream.status_code,
            headers=headers,
        )

    return app


def _set_session_cookie(response: Response, grant: PreviewBrowserSessionGrantLike) -> None:
    token = grant.session_token
    if token is None:
        return
    maximum_age = max(
        1,
        int((grant.route.expires_at - datetime.now(timezone.utc)).total_seconds()),
    )
    response.set_cookie(
        PREVIEW_COOKIE_NAME,
        token,
        max_age=maximum_age,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/",
    )


def create_preview_session_gateway_app(
    *,
    authority: PreviewBrowserSessionAuthority,
    tunnel: PreviewTunnel,
    maximum_request_bytes: int = 1_048_576,
    maximum_response_bytes: int = 10_485_760,
) -> FastAPI:
    """Create the production P0S9 gateway without placing the URL bearer in a cookie."""

    if maximum_request_bytes <= 0 or maximum_response_bytes <= 0:
        raise ValueError("Preview gateway byte limits must be positive")
    app = FastAPI(title="Omnigent Preview Gateway", docs_url=None, redoc_url=None)

    def bootstrap_request(request: Request) -> Response | None:
        try:
            if request.url.query or request.cookies or request.headers.get("authorization"):
                raise PreviewSessionError("preview_bootstrap_invalid")
            _host(request)
        except (IsolationControlPlaneError, PreviewSessionError) as error:
            return _error(403, error.code, str(error))
        return None

    @app.get(_BOOTSTRAP_PATH, include_in_schema=False)
    async def bootstrap(request: Request) -> Response:
        denied = bootstrap_request(request)
        if denied is not None:
            return denied
        return Response(
            content=_BOOTSTRAP_HTML,
            media_type="text/html",
            headers=_BOOTSTRAP_HEADERS,
        )

    @app.get(_BOOTSTRAP_SCRIPT_PATH, include_in_schema=False)
    async def bootstrap_script(request: Request) -> Response:
        denied = bootstrap_request(request)
        if denied is not None:
            return denied
        return Response(
            content=_BOOTSTRAP_SCRIPT,
            media_type="text/javascript",
            headers=_BOOTSTRAP_HEADERS,
        )

    @app.post(_EXCHANGE_PATH, include_in_schema=False)
    async def exchange(request: Request) -> Response:
        try:
            if request.cookies:
                raise PreviewSessionError("preview_ambient_cookie_denied")
            body = await _body(request, maximum=4096)
            exchange_token = _exchange_token(request, body)
            if not exchange_token:
                raise PreviewSessionError("preview_exchange_required")
            grant = await run_in_threadpool(
                authority.exchange,
                host=_host(request),
                exchange_token=exchange_token,
            )
            if grant.session_token is None or grant.session_token == exchange_token:
                raise PreviewSessionError("preview_session_invalid")
        except (IsolationControlPlaneError, PreviewSessionError) as error:
            return _error(403, error.code, str(error))
        response = Response(
            status_code=303,
            headers={
                "Location": "/",
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
            },
        )
        _set_session_cookie(response, grant)
        return response

    @app.api_route(
        "/{preview_path:path}",
        methods=sorted(_METHODS),
        include_in_schema=False,
    )
    async def proxy(preview_path: str, request: Request) -> Response:
        del preview_path
        if request.url.path in _INTERNAL_PATHS:
            return _error(405, "preview_method_denied", "Preview internal method is denied")
        session_token = request.cookies.get(PREVIEW_COOKIE_NAME, "")
        if not session_token:
            return _error(401, "preview_session_required", "Preview authorization is required")
        if any(name != PREVIEW_COOKIE_NAME for name in request.cookies):
            return _error(403, "preview_ambient_cookie_denied", "Ambient cookies are not accepted")
        if request.headers.get("authorization"):
            return _error(
                403,
                "preview_ambient_authorization_denied",
                "Ambient authorization is not accepted",
            )
        try:
            host = _host(request)
            path, query = _path(request)
            incoming_headers = _request_headers(request)
            body = await _body(request, maximum=maximum_request_bytes)
            grant = await run_in_threadpool(
                authority.authorize_and_rotate,
                host=host,
                session_token=session_token,
                incoming_headers=incoming_headers,
            )
        except (IsolationControlPlaneError, PreviewSessionError) as error:
            return _error(403, error.code, str(error))

        route = grant.route
        try:
            upstream = await tunnel.forward(
                PreviewTunnelRequest(
                    route=route,
                    method=request.method,
                    path=path,
                    query=query,
                    headers=route.upstream_request_headers,
                    body=body,
                )
            )
            if not 200 <= upstream.status_code <= 599:
                raise ValueError("Preview tunnel returned an invalid status")
            if isinstance(upstream.body, bytes) and len(upstream.body) > maximum_response_bytes:
                raise ValueError("Preview tunnel response exceeded the byte limit")
            content_length = next(
                (
                    value
                    for key, value in upstream.headers.items()
                    if key.lower() == "content-length"
                ),
                None,
            )
            if content_length is not None and (
                not content_length.isdigit() or int(content_length) > maximum_response_bytes
            ):
                raise ValueError("Preview tunnel response exceeded the byte limit")
        except Exception:  # noqa: BLE001 - tunnel details never cross the isolated origin.
            response = _error(502, "preview_tunnel_unavailable", "Preview tunnel is unavailable")
            _set_session_cookie(response, grant)
            return response

        headers = _response_headers(upstream, route)
        if request.method == "HEAD":
            try:
                await _close_response_body(upstream.body)
            except Exception:  # noqa: BLE001 - collapse transport details at the gateway.
                response = _error(
                    502, "preview_tunnel_unavailable", "Preview tunnel is unavailable"
                )
                _set_session_cookie(response, grant)
                return response
            response = Response(content=b"", status_code=upstream.status_code, headers=headers)
        else:
            response = StreamingResponse(
                _bounded_response_body(upstream.body, maximum=maximum_response_bytes),
                status_code=upstream.status_code,
                headers=headers,
            )
        _set_session_cookie(response, grant)
        return response

    return app
