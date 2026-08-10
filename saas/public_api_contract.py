"""Stable public API v1 contract primitives, schemas, and OpenAPI source.

This module is deliberately isolated from the official Omnigent API and from
the SaaS persistence models.  The HTTP implementation may import these public
schemas, but this module must never import an ORM record or expose an upstream
runtime object.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import Body, FastAPI, Header, Path, Query, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

PUBLIC_API_PREFIX = "/api/v1"
PUBLIC_API_VERSION = "2026-08-10"
CURSOR_VERSION = 1
MAX_CURSOR_BYTES = 4096
PROJECT_CURSOR_SORT = ("created_at", "id")
RUN_CURSOR_SORT = ("created_at", "id")
RUN_EVENT_CURSOR_SORT = ("sequence", "id")

RunStatus = Literal[
    "created",
    "queued",
    "leased",
    "starting",
    "running",
    "waiting_input",
    "waiting_approval",
    "cancelling",
    "cancelled",
    "succeeded",
    "failed",
    "timed_out",
    "orphaned",
]


class PublicModel(BaseModel):
    """Strict base class so newly added server fields remain intentional."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def reject_non_finite_json(self) -> PublicModel:
        """Keep hashes and every generated SDK on strict RFC 8259 JSON."""

        _require_finite_json(self.model_dump(mode="python"))
        return self


def _require_finite_json(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("JSON numbers must be finite")
    if isinstance(value, dict):
        for nested in value.values():
            _require_finite_json(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _require_finite_json(nested)


class ProjectMetadata(PublicModel):
    """Content-blind Project metadata visible to the machine principal."""

    id: UUID
    space_id: UUID
    name: str = Field(min_length=1, max_length=256)
    visibility: Literal["private", "space", "restricted"]
    status: Literal["active", "suspended", "archived"]
    authorization_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    etag: str = Field(pattern=r'^W/"[1-9][0-9]*"$')


class ProjectPage(PublicModel):
    items: list[ProjectMetadata]
    next_cursor: str | None = None


class RunCreateRequest(PublicModel):
    """Public admission request; server-owned revisions are never client supplied."""

    title: str = Field(min_length=1, max_length=256)
    input: dict[str, JsonValue]
    session_id: UUID | None = None
    queue_class: str = Field(default="interactive", min_length=1, max_length=64)
    priority: int = Field(default=0, ge=-1000, le=1000)
    quota_resource: str = Field(default="run", min_length=1, max_length=64)
    quota_units: int = Field(default=1, ge=1, le=1_000_000)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class RunRetryRequest(PublicModel):
    """Retry policy creates a new Run and never reopens terminal history."""

    input_override: dict[str, JsonValue] | None = None
    queue_class: str | None = Field(default=None, min_length=1, max_length=64)
    priority: int | None = Field(default=None, ge=-1000, le=1000)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class RunCancelRequest(PublicModel):
    reason: str | None = Field(default=None, max_length=512)


class RunResource(PublicModel):
    id: UUID
    project_id: UUID
    task_id: UUID
    session_id: UUID | None
    parent_run_id: UUID | None = None
    status: RunStatus
    version: int = Field(ge=1)
    event_sequence: int = Field(ge=0)
    queue_class: str
    priority: int
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    terminal_at: datetime | None
    etag: str = Field(pattern=r'^W/"[1-9][0-9]*"$')


class RunContent(PublicModel):
    """Sensitive Run body returned only by the run.read_content endpoint."""

    run_id: UUID
    input: dict[str, JsonValue]
    product_revision: str = Field(min_length=1, max_length=64)
    upstream_revision: str = Field(min_length=1, max_length=64)
    schema_revision: str = Field(min_length=1, max_length=64)
    adapter_contract_version: str = Field(min_length=1, max_length=32)
    etag: str = Field(pattern=r'^W/"[1-9][0-9]*"$')


class RunPage(PublicModel):
    items: list[RunResource]
    next_cursor: str | None = None


class RunEvent(PublicModel):
    id: UUID
    run_id: UUID
    sequence: int = Field(ge=1)
    type: str = Field(min_length=1, max_length=128)
    data: dict[str, JsonValue]
    trace_id: str = Field(min_length=1, max_length=128)
    created_at: datetime


class RunEventPage(PublicModel):
    items: list[RunEvent]
    next_cursor: str | None = None


class ErrorDetail(PublicModel):
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=1024)
    request_id: str = Field(min_length=1, max_length=128)
    details: dict[str, JsonValue] = Field(default_factory=dict)


class ErrorEnvelope(PublicModel):
    error: ErrorDetail


class CursorError(ValueError):
    """Stable, content-blind error raised for every invalid cursor condition."""

    code = "cursor_invalid"

    def __init__(self) -> None:
        super().__init__("cursor is invalid")


@dataclass(frozen=True, slots=True)
class CursorState:
    """Verified opaque keyset position returned to a collection implementation."""

    position: dict[str, JsonValue]
    issued_at: datetime
    expires_at: datetime


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise CursorError from error


def _canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise CursorError from error
    return encoded.encode("ascii")


def filters_fingerprint(
    *,
    resource: str,
    scope: str,
    filters: Mapping[str, JsonValue],
    sort: tuple[str, ...],
) -> str:
    """Hash every authority/filter dimension that a cursor is allowed to resume."""

    if not resource or not scope or not sort:
        raise CursorError
    payload = {
        "resource": resource,
        "scope": scope,
        "filters": dict(filters),
        "sort": list(sort),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


class FilterBoundCursorCodec:
    """HMAC-signed, expiring keyset cursor with rotation and filter binding."""

    def __init__(
        self,
        *,
        keys: Mapping[str, bytes],
        active_key_id: str,
        lifetime: timedelta = timedelta(hours=24),
    ) -> None:
        copied = dict(keys)
        if active_key_id not in copied or not active_key_id or len(active_key_id) > 64:
            raise ValueError("active cursor key id is invalid")
        if any(not key_id or len(key_id) > 64 for key_id in copied):
            raise ValueError("cursor key id is invalid")
        if any(len(secret) < 32 for secret in copied.values()):
            raise ValueError("cursor HMAC keys must contain at least 32 bytes")
        if lifetime <= timedelta(0) or lifetime > timedelta(days=7):
            raise ValueError("cursor lifetime must be between zero and seven days")
        self._keys = copied
        self._active_key_id = active_key_id
        self._lifetime = lifetime

    def encode(
        self,
        *,
        resource: str,
        scope: str,
        filters: Mapping[str, JsonValue],
        sort: tuple[str, ...],
        position: Mapping[str, JsonValue],
        now: datetime | None = None,
    ) -> str:
        issued_at = self._time(now)
        expires_at = issued_at + self._lifetime
        payload = {
            "v": CURSOR_VERSION,
            "kid": self._active_key_id,
            "fp": filters_fingerprint(
                resource=resource,
                scope=scope,
                filters=filters,
                sort=sort,
            ),
            "pos": dict(position),
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        body = _canonical_json(payload)
        signature = hmac.digest(self._keys[self._active_key_id], body, "sha256")
        return f"{_base64url_encode(body)}.{_base64url_encode(signature)}"

    def decode(
        self,
        token: str,
        *,
        resource: str,
        scope: str,
        filters: Mapping[str, JsonValue],
        sort: tuple[str, ...],
        now: datetime | None = None,
    ) -> CursorState:
        if not token or len(token.encode("utf-8")) > MAX_CURSOR_BYTES or token.count(".") != 1:
            raise CursorError
        encoded_body, encoded_signature = token.split(".", 1)
        body = _base64url_decode(encoded_body)
        signature = _base64url_decode(encoded_signature)
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise CursorError from error
        if not isinstance(parsed, dict):
            raise CursorError
        key_id = parsed.get("kid")
        if not isinstance(key_id, str) or key_id not in self._keys:
            raise CursorError
        expected_signature = hmac.digest(self._keys[key_id], body, "sha256")
        if len(signature) != len(expected_signature) or not hmac.compare_digest(
            signature, expected_signature
        ):
            raise CursorError
        expected_fingerprint = filters_fingerprint(
            resource=resource,
            scope=scope,
            filters=filters,
            sort=sort,
        )
        version = parsed.get("v")
        fingerprint = parsed.get("fp")
        issued_timestamp = parsed.get("iat")
        expiry_timestamp = parsed.get("exp")
        position = parsed.get("pos")
        if (
            version != CURSOR_VERSION
            or not isinstance(fingerprint, str)
            or not hmac.compare_digest(fingerprint, expected_fingerprint)
            or not isinstance(issued_timestamp, int)
            or not isinstance(expiry_timestamp, int)
            or not isinstance(position, dict)
        ):
            raise CursorError
        current = self._time(now)
        try:
            issued_at = datetime.fromtimestamp(issued_timestamp, timezone.utc)
            expires_at = datetime.fromtimestamp(expiry_timestamp, timezone.utc)
        except (OverflowError, OSError, ValueError) as error:
            raise CursorError from error
        if expires_at <= current or issued_at > current + timedelta(minutes=5):
            raise CursorError
        if expires_at - issued_at != self._lifetime:
            raise CursorError
        _canonical_json(position)
        return CursorState(
            position=cast(dict[str, JsonValue], position),
            issued_at=issued_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _time(value: datetime | None) -> datetime:
        resolved = value or datetime.now(timezone.utc)
        if resolved.tzinfo is None:
            raise ValueError("cursor time must include a timezone")
        return resolved.astimezone(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True, slots=True)
class ApiVersionPolicy:
    """Response header policy for a dated API contract and retirement window."""

    version: str = PUBLIC_API_VERSION
    deprecated: bool = False
    sunset_at: datetime | None = None
    deprecation_document: str | None = None

    def headers(self) -> dict[str, str]:
        headers = {"X-Omnigent-API-Version": self.version}
        if not self.deprecated:
            if self.sunset_at is not None or self.deprecation_document is not None:
                raise ValueError("active API version cannot declare deprecation metadata")
            return headers
        if self.sunset_at is None or self.sunset_at.tzinfo is None:
            raise ValueError("deprecated API version requires a timezone-aware sunset")
        if not self.deprecation_document or not self.deprecation_document.startswith("https://"):
            raise ValueError("deprecated API version requires an HTTPS documentation URL")
        headers.update(
            {
                "Deprecation": "true",
                "Sunset": format_datetime(self.sunset_at.astimezone(timezone.utc), usegmt=True),
                "Link": f'<{self.deprecation_document}>; rel="deprecation"; type="text/html"',
            }
        )
        return headers


_bearer = HTTPBearer(auto_error=False, scheme_name="BearerAuth")


def _error_responses() -> dict[int | str, dict[str, object]]:
    descriptions = {
        400: "Malformed request or invalid cursor",
        401: "Missing, invalid, expired, or revoked credential",
        403: "Credential lacks the required scope or Project authority",
        404: "Resource is absent or intentionally content-blind",
        409: "Idempotency conflict or state conflict",
        412: "If-Match precondition failed",
        422: "Request validation failed",
        429: "Shared rate limit exceeded",
        500: "Internal error with a stable request identifier",
    }
    return {
        status: {
            "description": description,
            "model": ErrorEnvelope,
            "headers": {
                "X-Request-Id": {"schema": {"type": "string"}},
                "X-Omnigent-API-Version": {"schema": {"type": "string"}},
            },
        }
        for status, description in descriptions.items()
    }


def _success_headers(*, etag: bool = False, location: bool = False) -> dict[str, object]:
    headers: dict[str, object] = {
        "X-Request-Id": {"schema": {"type": "string"}},
        "X-Omnigent-API-Version": {"schema": {"type": "string"}},
        "RateLimit-Limit": {"schema": {"type": "integer"}},
        "RateLimit-Remaining": {"schema": {"type": "integer"}},
        "RateLimit-Reset": {"schema": {"type": "integer"}},
    }
    if etag:
        headers["ETag"] = {"schema": {"type": "string"}}
    if location:
        headers["Location"] = {"schema": {"type": "string", "format": "uri-reference"}}
        headers["Idempotent-Replayed"] = {"schema": {"type": "boolean"}}
    return headers


def create_public_api_contract_app() -> FastAPI:
    """Build a non-runtime FastAPI app used only to produce the frozen OpenAPI file."""

    app = FastAPI(
        title="Omnigent SaaS Public API",
        version=PUBLIC_API_VERSION,
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
        description=(
            "Machine-to-machine API isolated from the official Omnigent HTTP surface. "
            "Every operation is Project-authorized; cursors are opaque and filter-bound."
        ),
    )

    @app.get(
        f"{PUBLIC_API_PREFIX}/projects",
        operation_id="listProjects",
        response_model=ProjectPage,
        responses={200: {"headers": _success_headers()}, **_error_responses()},
        tags=["Projects"],
        summary="List authorized Project metadata",
    )
    def list_projects(
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        cursor: Annotated[str | None, Query(min_length=1, max_length=4096)] = None,
        status: Annotated[Literal["active", "suspended", "archived"] | None, Query()] = None,
    ) -> ProjectPage:
        _ = (credential, limit, cursor, status)
        raise NotImplementedError("contract-only endpoint")

    @app.get(
        f"{PUBLIC_API_PREFIX}/projects/{{project_id}}",
        operation_id="getProject",
        response_model=ProjectMetadata,
        responses={200: {"headers": _success_headers(etag=True)}, **_error_responses()},
        tags=["Projects"],
        summary="Get authorized Project metadata",
    )
    def get_project(
        project_id: Annotated[UUID, Path()],
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    ) -> ProjectMetadata:
        _ = (project_id, credential)
        raise NotImplementedError("contract-only endpoint")

    @app.post(
        f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs",
        operation_id="createRun",
        response_model=RunResource,
        status_code=201,
        responses={
            201: {"headers": _success_headers(etag=True, location=True)},
            **_error_responses(),
        },
        tags=["Runs"],
        summary="Create and queue a Run",
    )
    def create_run(
        body: Annotated[RunCreateRequest, Body()],
        project_id: Annotated[UUID, Path()],
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=128)
        ],
    ) -> RunResource:
        _ = (body, project_id, credential, idempotency_key)
        raise NotImplementedError("contract-only endpoint")

    @app.get(
        f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs",
        operation_id="listRuns",
        response_model=RunPage,
        responses={200: {"headers": _success_headers()}, **_error_responses()},
        tags=["Runs"],
        summary="List Runs with an opaque filter-bound cursor",
    )
    def list_runs(
        project_id: Annotated[UUID, Path()],
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        cursor: Annotated[str | None, Query(min_length=1, max_length=4096)] = None,
        status: Annotated[list[RunStatus] | None, Query()] = None,
        created_after: Annotated[datetime | None, Query()] = None,
        created_before: Annotated[datetime | None, Query()] = None,
    ) -> RunPage:
        _ = (project_id, credential, limit, cursor, status, created_after, created_before)
        raise NotImplementedError("contract-only endpoint")

    @app.get(
        f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}",
        operation_id="getRun",
        response_model=RunResource,
        responses={200: {"headers": _success_headers(etag=True)}, **_error_responses()},
        tags=["Runs"],
        summary="Get one Run",
    )
    def get_run(
        project_id: Annotated[UUID, Path()],
        run_id: Annotated[UUID, Path()],
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    ) -> RunResource:
        _ = (project_id, run_id, credential)
        raise NotImplementedError("contract-only endpoint")

    @app.get(
        f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}/content",
        operation_id="getRunContent",
        response_model=RunContent,
        responses={200: {"headers": _success_headers(etag=True)}, **_error_responses()},
        tags=["Run content"],
        summary="Get sensitive Run input and immutable revision pins",
        description=(
            "Requires the explicit run.read_content scope. Run metadata endpoints never "
            "include input or revision content."
        ),
    )
    def get_run_content(
        project_id: Annotated[UUID, Path()],
        run_id: Annotated[UUID, Path()],
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    ) -> RunContent:
        _ = (project_id, run_id, credential)
        raise NotImplementedError("contract-only endpoint")

    @app.post(
        f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}/cancel",
        operation_id="cancelRun",
        response_model=RunResource,
        responses={200: {"headers": _success_headers(etag=True)}, **_error_responses()},
        tags=["Runs"],
        summary="Request cancellation using optimistic concurrency",
    )
    def cancel_run(
        body: Annotated[RunCancelRequest, Body()],
        project_id: Annotated[UUID, Path()],
        run_id: Annotated[UUID, Path()],
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=128)
        ],
        if_match: Annotated[str, Header(alias="If-Match", pattern=r'^W/"[1-9][0-9]*"$')],
    ) -> RunResource:
        _ = (body, project_id, run_id, credential, idempotency_key, if_match)
        raise NotImplementedError("contract-only endpoint")

    @app.post(
        f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}/retry",
        operation_id="retryRun",
        response_model=RunResource,
        status_code=201,
        responses={
            201: {"headers": _success_headers(etag=True, location=True)},
            **_error_responses(),
        },
        tags=["Runs"],
        summary="Create a successor Run from terminal history",
    )
    def retry_run(
        body: Annotated[RunRetryRequest, Body()],
        project_id: Annotated[UUID, Path()],
        run_id: Annotated[UUID, Path()],
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=128)
        ],
        if_match: Annotated[str, Header(alias="If-Match", pattern=r'^W/"[1-9][0-9]*"$')],
    ) -> RunResource:
        _ = (body, project_id, run_id, credential, idempotency_key, if_match)
        raise NotImplementedError("contract-only endpoint")

    @app.get(
        f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}/events",
        operation_id="listRunEvents",
        response_model=RunEventPage,
        responses={200: {"headers": _success_headers()}, **_error_responses()},
        tags=["Run events"],
        summary="Replay persisted Run events",
    )
    def list_run_events(
        project_id: Annotated[UUID, Path()],
        run_id: Annotated[UUID, Path()],
        credential: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        cursor: Annotated[str | None, Query(min_length=1, max_length=4096)] = None,
        after_sequence: Annotated[int | None, Query(ge=0)] = None,
    ) -> RunEventPage:
        _ = (project_id, run_id, credential, limit, cursor, after_sequence)
        raise NotImplementedError("contract-only endpoint")

    schema = app.openapi()
    schema["x-omnigent-api-version"] = PUBLIC_API_VERSION
    schema["x-omnigent-stability"] = "stable"
    schema["x-omnigent-deprecation-policy"] = {
        "minimum_notice_days": 180,
        "headers": ["Deprecation", "Sunset", "Link"],
    }
    schema_paths = cast(dict[str, object], schema["paths"])
    projects_path = cast(dict[str, object], schema_paths[f"{PUBLIC_API_PREFIX}/projects"])
    projects_list = cast(dict[str, object], projects_path["get"])
    projects_list["x-omnigent-required-permission"] = "project.read_metadata"
    projects_list["x-omnigent-cursor-binding"] = {
        "scope": ["machine_tenant_id", "machine_space_id"],
        "filters": ["status"],
        "sort": list(PROJECT_CURSOR_SORT),
    }
    project_path = cast(
        dict[str, object],
        schema_paths[f"{PUBLIC_API_PREFIX}/projects/{{project_id}}"],
    )
    cast(dict[str, object], project_path["get"])["x-omnigent-required-permission"] = (
        "project.read_metadata"
    )
    runs_path = cast(
        dict[str, object],
        schema_paths[f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs"],
    )
    cast(dict[str, object], runs_path["post"])["x-omnigent-required-permission"] = "run.create"
    runs_list = cast(dict[str, object], runs_path["get"])
    runs_list["x-omnigent-required-permission"] = "run.read_metadata"
    runs_list["x-omnigent-cursor-binding"] = {
        "scope": ["machine_tenant_id", "machine_space_id", "project_id"],
        "filters": ["status", "created_after", "created_before"],
        "sort": list(RUN_CURSOR_SORT),
    }
    run_path = cast(
        dict[str, object],
        schema_paths[f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}"],
    )
    cast(dict[str, object], run_path["get"])["x-omnigent-required-permission"] = (
        "run.read_metadata"
    )
    content_path = cast(
        dict[str, object],
        schema_paths[f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}/content"],
    )
    cast(dict[str, object], content_path["get"])["x-omnigent-required-permission"] = (
        "run.read_content"
    )
    for action, permission in (("cancel", "run.cancel"), ("retry", "run.retry")):
        action_path = cast(
            dict[str, object],
            schema_paths[f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}/{action}"],
        )
        cast(dict[str, object], action_path["post"])["x-omnigent-required-permission"] = permission
    events_path = cast(
        dict[str, object],
        schema_paths[f"{PUBLIC_API_PREFIX}/projects/{{project_id}}/runs/{{run_id}}/events"],
    )
    events_list = cast(dict[str, object], events_path["get"])
    events_list["x-omnigent-required-permission"] = "run.read_content"
    events_list["x-omnigent-cursor-binding"] = {
        "scope": ["machine_tenant_id", "machine_space_id", "project_id", "run_id"],
        "filters": ["after_sequence"],
        "sort": list(RUN_EVENT_CURSOR_SORT),
    }
    app.openapi_schema = schema
    return app


def public_openapi_document() -> dict[str, object]:
    """Return the deterministic source document for `saas/openapi-v1.json`."""

    return cast(dict[str, object], create_public_api_contract_app().openapi())


__all__ = [
    "PROJECT_CURSOR_SORT",
    "PUBLIC_API_PREFIX",
    "PUBLIC_API_VERSION",
    "RUN_CURSOR_SORT",
    "RUN_EVENT_CURSOR_SORT",
    "ApiVersionPolicy",
    "CursorError",
    "CursorState",
    "ErrorDetail",
    "ErrorEnvelope",
    "FilterBoundCursorCodec",
    "ProjectMetadata",
    "ProjectPage",
    "RunCancelRequest",
    "RunContent",
    "RunCreateRequest",
    "RunEvent",
    "RunEventPage",
    "RunPage",
    "RunResource",
    "RunRetryRequest",
    "create_public_api_contract_app",
    "filters_fingerprint",
    "public_openapi_document",
]
