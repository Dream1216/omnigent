"""Synchronous client for `/api/v1`; mutation retries stay caller-controlled."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from typing import TypeVar, cast
from urllib.parse import quote, urlsplit

import httpx

from .errors import (
    ApiError,
    ApiTimeoutError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    PreconditionFailedError,
    ProtocolError,
    RateLimitError,
    TransportError,
    ValidationError,
)
from .models import Page, Project, Run, RunContent, RunCreate, RunEvent, RunRetry, page_from_dict

SDK_VERSION = "0.1.0"
_ETAG = re.compile(r'^W/"[1-9][0-9]*"$')
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_ResponseT = TypeVar("_ResponseT")
_QueryValue = str | int | float | bool | None


def _identifier(value: str, field: str) -> str:
    cleaned = value.strip()
    if not cleaned or "/" in cleaned or len(cleaned) > 128:
        raise ValueError(f"{field} is invalid")
    return quote(cleaned, safe="")


def _idempotency_key(value: str) -> str:
    if not value or len(value) > 128 or value != value.strip():
        raise ValueError("idempotency_key must contain 1 to 128 trimmed characters")
    return value


def _if_match(value: str) -> str:
    if not _ETAG.fullmatch(value):
        raise ValueError('if_match must be a weak version ETag such as W/"3"')
    return value


def _base_url(value: str, *, allow_insecure_localhost: bool) -> str:
    parsed = urlsplit(value)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("base_url cannot contain credentials, query, or fragment")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base_url must be an absolute HTTP(S) URL")
    if parsed.scheme != "https" and not (
        allow_insecure_localhost and parsed.hostname in _LOCAL_HOSTS
    ):
        raise ValueError("base_url must use HTTPS except for explicit local development")
    return value.rstrip("/")


class OmnigentSaasClient:
    """Finite-timeout, typed client with opaque cursors and explicit concurrency."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout: float | httpx.Timeout = 30.0,
        allow_insecure_localhost: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key or len(api_key) > 4096:
            raise ValueError("api_key is invalid")
        resolved_url = _base_url(
            base_url,
            allow_insecure_localhost=allow_insecure_localhost,
        )
        self._client = httpx.Client(
            base_url=resolved_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": f"omnigent-saas-python/{SDK_VERSION}",
            },
            timeout=timeout,
            transport=transport,
            follow_redirects=False,
        )

    def __enter__(self) -> OmnigentSaasClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(base_url={str(self._client.base_url)!r}, api_key=<redacted>)"
        )

    def close(self) -> None:
        self._client.close()

    def list_projects(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        status: str | None = None,
    ) -> Page[Project]:
        payload = self._request(
            "GET",
            "/api/v1/projects",
            params=self._page_params(
                limit=limit,
                max_limit=100,
                cursor=cursor,
                extras=(("status", status),),
            ),
            expected={200},
        )
        return self._page(payload, Project.from_dict)

    def get_project(self, project_id: str) -> Project:
        payload = self._request(
            "GET",
            f"/api/v1/projects/{_identifier(project_id, 'project_id')}",
            expected={200},
        )
        return self._resource(payload, Project.from_dict)

    def create_run(
        self,
        project_id: str,
        request: RunCreate,
        *,
        idempotency_key: str,
    ) -> Run:
        payload = self._request(
            "POST",
            f"/api/v1/projects/{_identifier(project_id, 'project_id')}/runs",
            body=request.to_dict(),
            idempotency_key=_idempotency_key(idempotency_key),
            expected={201},
        )
        return self._resource(payload, Run.from_dict)

    def list_runs(
        self,
        project_id: str,
        *,
        limit: int = 50,
        cursor: str | None = None,
        status: Iterable[str] | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
    ) -> Page[Run]:
        extras: list[tuple[str, str | int]] = []
        if status is not None:
            extras.extend(("status", item) for item in status)
        for name, value in (("created_after", created_after), ("created_before", created_before)):
            if value is not None:
                extras.append((name, value))
        payload = self._request(
            "GET",
            f"/api/v1/projects/{_identifier(project_id, 'project_id')}/runs",
            params=self._page_params(
                limit=limit,
                max_limit=100,
                cursor=cursor,
                extras=extras,
            ),
            expected={200},
        )
        return self._page(payload, Run.from_dict)

    def get_run(self, project_id: str, run_id: str) -> Run:
        payload = self._request(
            "GET",
            self._run_path(project_id, run_id),
            expected={200},
        )
        return self._resource(payload, Run.from_dict)

    def get_run_content(self, project_id: str, run_id: str) -> RunContent:
        payload = self._request(
            "GET",
            f"{self._run_path(project_id, run_id)}/content",
            expected={200},
        )
        return self._resource(payload, RunContent.from_dict)

    def cancel_run(
        self,
        project_id: str,
        run_id: str,
        *,
        if_match: str,
        idempotency_key: str,
        reason: str | None = None,
    ) -> Run:
        payload = self._request(
            "POST",
            f"{self._run_path(project_id, run_id)}/cancel",
            body={"reason": reason},
            if_match=_if_match(if_match),
            idempotency_key=_idempotency_key(idempotency_key),
            expected={200},
        )
        return self._resource(payload, Run.from_dict)

    def retry_run(
        self,
        project_id: str,
        run_id: str,
        request: RunRetry | None = None,
        *,
        if_match: str,
        idempotency_key: str,
    ) -> Run:
        payload = self._request(
            "POST",
            f"{self._run_path(project_id, run_id)}/retry",
            body=(request or RunRetry()).to_dict(),
            if_match=_if_match(if_match),
            idempotency_key=_idempotency_key(idempotency_key),
            expected={201},
        )
        return self._resource(payload, Run.from_dict)

    def list_run_events(
        self,
        project_id: str,
        run_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        after_sequence: int | None = None,
    ) -> Page[RunEvent]:
        if after_sequence is not None and (
            not isinstance(after_sequence, int)
            or isinstance(after_sequence, bool)
            or after_sequence < 0
        ):
            raise ValueError("after_sequence must be a non-negative integer")
        payload = self._request(
            "GET",
            f"{self._run_path(project_id, run_id)}/events",
            params=self._page_params(
                limit=limit,
                max_limit=500,
                cursor=cursor,
                extras=(("after_sequence", after_sequence),),
            ),
            expected={200},
        )
        return self._page(payload, RunEvent.from_dict)

    @staticmethod
    def _page_params(
        *,
        limit: int,
        max_limit: int,
        cursor: str | None,
        extras: Iterable[tuple[str, _QueryValue]],
    ) -> list[tuple[str, _QueryValue]]:
        if not 1 <= limit <= max_limit:
            raise ValueError(f"limit must be between 1 and {max_limit}")
        params: list[tuple[str, _QueryValue]] = [("limit", limit)]
        if cursor is not None:
            if not cursor or len(cursor) > 4096:
                raise ValueError("cursor is invalid")
            params.append(("cursor", cursor))
        params.extend((name, value) for name, value in extras if value is not None)
        return params

    @staticmethod
    def _run_path(project_id: str, run_id: str) -> str:
        return (
            f"/api/v1/projects/{_identifier(project_id, 'project_id')}/runs/"
            f"{_identifier(run_id, 'run_id')}"
        )

    @staticmethod
    def _page(payload: object, parser: Callable[[object], _ResponseT]) -> Page[_ResponseT]:
        try:
            return page_from_dict(payload, parser)
        except (TypeError, ValueError) as error:
            raise ProtocolError(f"invalid collection response: {error}") from error

    @staticmethod
    def _resource(payload: object, parser: Callable[[object], _ResponseT]) -> _ResponseT:
        try:
            return parser(payload)
        except ValueError as error:
            raise ProtocolError(f"invalid resource response: {error}") from error

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, object] | None = None,
        params: list[tuple[str, _QueryValue]] | None = None,
        idempotency_key: str | None = None,
        if_match: str | None = None,
        expected: set[int],
    ) -> object:
        headers: dict[str, str] = {}
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        if if_match is not None:
            headers["If-Match"] = if_match
        try:
            response = self._client.request(
                method,
                path,
                json=body,
                params=httpx.QueryParams(params) if params is not None else None,
                headers=headers,
            )
        except httpx.TimeoutException as error:
            raise ApiTimeoutError("public API request timed out") from error
        except httpx.RequestError as error:
            raise TransportError("public API transport failed") from error
        if response.status_code not in expected:
            self._raise_api_error(response)
        try:
            return response.json()
        except ValueError as error:
            raise ProtocolError("public API returned non-JSON success response") from error

    @staticmethod
    def _raise_api_error(response: httpx.Response) -> None:
        request_id = response.headers.get("X-Request-Id")
        code = "http_error"
        message = f"public API returned HTTP {response.status_code}"
        details: Mapping[str, object] = {}
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            error_payload = cast(dict[str, object], payload["error"])
            if isinstance(error_payload.get("code"), str):
                code = cast(str, error_payload["code"])
            if isinstance(error_payload.get("message"), str):
                message = cast(str, error_payload["message"])
            if isinstance(error_payload.get("request_id"), str):
                request_id = cast(str, error_payload["request_id"])
            if isinstance(error_payload.get("details"), dict):
                details = cast(dict[str, object], error_payload["details"])
        error_type: type[ApiError] = {
            401: AuthenticationError,
            403: AuthorizationError,
            404: NotFoundError,
            409: ConflictError,
            412: PreconditionFailedError,
            422: ValidationError,
            429: RateLimitError,
        }.get(response.status_code, ApiError)
        raise error_type(
            status_code=response.status_code,
            code=code,
            message=message,
            request_id=request_id,
            details=details,
            retry_after=response.headers.get("Retry-After"),
        )


__all__ = ["SDK_VERSION", "OmnigentSaasClient"]
