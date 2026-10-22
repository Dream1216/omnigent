"""Stable public resources and separately mounted API credential administration."""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Literal, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

from saas.control_plane.api_credentials import (
    ApiCredentialError,
    ApiCredentialService,
    ApiCredentialView,
    IssuedApiCredential,
    ServiceAccountView,
)
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.public_api import (
    PublicApiError,
    PublicApiExecutionService,
    PublicApiProjectView,
    PublicApiRateLimitView,
    PublicApiRunContentView,
    PublicApiRunEventView,
    PublicApiRunView,
)
from saas.public_api_contract import (
    ApiVersionPolicy,
    ProjectMetadata,
    ProjectPage,
    RunCancelRequest,
    RunContent,
    RunCreateRequest,
    RunEventPage,
    RunPage,
    RunResource,
    RunRetryRequest,
    RunStatus,
    _bearer,
    _error_responses,
    _success_headers,
    public_openapi_document,
)

if TYPE_CHECKING:
    from saas.control_plane.http_auth import SaasAuthProvider, SaasMachinePrincipal, SaasPrincipal


class ServiceAccountCreateRequest(BaseModel):
    space_id: UUID
    project_id: UUID
    steward_user_id: UUID
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)


class ApiCredentialCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    permission_scopes: tuple[str, ...] = Field(min_length=1, max_length=64)
    allowed_networks: tuple[str, ...] = Field(default=(), max_length=32)
    expires_at: datetime


class ApiCredentialRotateRequest(BaseModel):
    expires_at: datetime


class ServiceAccountStewardTransferRequest(BaseModel):
    to_user_id: UUID
    expected_security_version: int = Field(ge=1)


class ServiceAccountSuspendRequest(BaseModel):
    expected_security_version: int = Field(ge=1)


def create_api_credential_management_router(
    *,
    auth_provider: SaasAuthProvider,
    api_credentials: ApiCredentialService,
) -> APIRouter:
    """Create human credential administration outside the frozen public API."""

    router = APIRouter()

    @router.post("/tenants/{tenant_id}/service-accounts", status_code=201)
    def create_service_account(
        tenant_id: UUID,
        body: ServiceAccountCreateRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        human = _require_human(auth_provider, request)
        try:
            account = api_credentials.create_service_account(
                actor_id=human.session.user_id,
                tenant_id=tenant_id,
                space_id=body.space_id,
                project_id=body.project_id,
                steward_user_id=body.steward_user_id,
                name=body.name,
                description=body.description,
                authenticated_at=human.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except ApiCredentialError as error:
            raise _http_error(error, _status_for(error)) from error
        return _account_payload(account)

    @router.get("/tenants/{tenant_id}/service-accounts")
    def list_service_accounts(
        tenant_id: UUID, request: Request, response: Response
    ) -> list[dict[str, object]]:
        human = _require_human(auth_provider, request)
        response.headers["Cache-Control"] = "private, no-store"
        try:
            accounts = api_credentials.list_service_accounts(
                actor_id=human.session.user_id, tenant_id=tenant_id
            )
        except ApiCredentialError as error:
            raise _http_error(error, _status_for(error)) from error
        return [_account_payload(account) for account in accounts]

    @router.post(
        "/tenants/{tenant_id}/service-accounts/{service_account_id}/api-keys",
        status_code=201,
    )
    def issue_api_key(
        tenant_id: UUID,
        service_account_id: UUID,
        body: ApiCredentialCreateRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        human = _require_human(auth_provider, request)
        response.headers["Cache-Control"] = "private, no-store"
        try:
            issued = api_credentials.issue_api_credential(
                actor_id=human.session.user_id,
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                name=body.name,
                permission_scopes=body.permission_scopes,
                allowed_networks=body.allowed_networks,
                expires_at=body.expires_at,
                authenticated_at=human.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except ApiCredentialError as error:
            raise _http_error(error, _status_for(error)) from error
        return _issued_payload(issued)

    @router.get("/tenants/{tenant_id}/service-accounts/{service_account_id}/api-keys")
    def list_api_keys(
        tenant_id: UUID,
        service_account_id: UUID,
        request: Request,
        response: Response,
    ) -> list[dict[str, object]]:
        human = _require_human(auth_provider, request)
        response.headers["Cache-Control"] = "private, no-store"
        try:
            credentials = api_credentials.list_api_credentials(
                actor_id=human.session.user_id,
                tenant_id=tenant_id,
                service_account_id=service_account_id,
            )
        except ApiCredentialError as error:
            raise _http_error(error, _status_for(error)) from error
        return [_credential_payload(credential) for credential in credentials]

    @router.post(
        "/tenants/{tenant_id}/service-accounts/{service_account_id}/api-keys/"
        "{credential_id}/rotate",
        status_code=201,
    )
    def rotate_api_key(
        tenant_id: UUID,
        service_account_id: UUID,
        credential_id: UUID,
        body: ApiCredentialRotateRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        human = _require_human(auth_provider, request)
        response.headers["Cache-Control"] = "private, no-store"
        try:
            issued = api_credentials.rotate_api_credential(
                actor_id=human.session.user_id,
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                credential_id=credential_id,
                expires_at=body.expires_at,
                authenticated_at=human.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except ApiCredentialError as error:
            raise _http_error(error, _status_for(error)) from error
        return _issued_payload(issued)

    @router.delete(
        "/tenants/{tenant_id}/service-accounts/{service_account_id}/api-keys/{credential_id}",
        status_code=204,
    )
    def revoke_api_key(
        tenant_id: UUID,
        service_account_id: UUID,
        credential_id: UUID,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> Response:
        human = _require_human(auth_provider, request)
        try:
            api_credentials.revoke_api_credential(
                actor_id=human.session.user_id,
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                credential_id=credential_id,
                authenticated_at=human.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except ApiCredentialError as error:
            raise _http_error(error, _status_for(error)) from error
        response.status_code = 204
        return response

    @router.post("/tenants/{tenant_id}/service-accounts/{service_account_id}/steward-transfer")
    def transfer_steward(
        tenant_id: UUID,
        service_account_id: UUID,
        body: ServiceAccountStewardTransferRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        human = _require_human(auth_provider, request)
        try:
            changed = api_credentials.transfer_steward(
                actor_id=human.session.user_id,
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                to_user_id=body.to_user_id,
                expected_security_version=body.expected_security_version,
                authenticated_at=human.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except ApiCredentialError as error:
            raise _http_error(error, _status_for(error)) from error
        return {
            "service_account_id": str(changed.service_account_id),
            "security_version": changed.security_version,
            "revoked_credential_count": changed.revoked_credential_count,
            "replayed": changed.replayed,
        }

    @router.post("/tenants/{tenant_id}/service-accounts/{service_account_id}/suspend")
    def suspend_service_account(
        tenant_id: UUID,
        service_account_id: UUID,
        body: ServiceAccountSuspendRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        human = _require_human(auth_provider, request)
        try:
            changed = api_credentials.suspend_service_account(
                actor_id=human.session.user_id,
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                expected_security_version=body.expected_security_version,
                authenticated_at=human.session.authenticated_at,
                idempotency_key=idempotency_key,
            )
        except ApiCredentialError as error:
            raise _http_error(error, _status_for(error)) from error
        return {
            "service_account_id": str(changed.service_account_id),
            "security_version": changed.security_version,
            "revoked_credential_count": changed.revoked_credential_count,
            "replayed": changed.replayed,
        }

    return router


def create_public_api_router(
    *,
    auth_provider: SaasAuthProvider,
    public_execution: PublicApiExecutionService,
) -> APIRouter:
    """Create only operations declared by the frozen public OpenAPI document."""

    router = APIRouter(route_class=_StablePublicApiRoute)

    @router.get("/openapi.json", include_in_schema=False)
    def public_openapi(request: Request) -> JSONResponse:
        request_id = _public_request_id(request)
        return JSONResponse(
            content=public_openapi_document(),
            headers={"X-Request-Id": request_id, **_VERSION_POLICY.headers()},
        )

    router.include_router(
        _create_public_execution_router(
            auth_provider=auth_provider,
            execution=public_execution,
        )
    )
    return router


_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_VERSION_POLICY = ApiVersionPolicy()


class _StablePublicApiRoute(APIRoute):
    """Normalize every resource response to the frozen v1 error/header contract."""

    def get_route_handler(self):  # type: ignore[no-untyped-def]
        original = super().get_route_handler()

        async def handler(request: Request):  # type: ignore[no-untyped-def]
            request_id = _public_request_id(request)
            request.state.public_api_request_id = request_id
            try:
                response = await original(request)
            except PublicApiError as error:
                return _public_error_response(error, request_id=request_id)
            except RequestValidationError as error:
                details: dict[str, object] = {
                    "errors": [
                        {
                            "path": ".".join(str(part) for part in item["loc"]),
                            "type": item["type"],
                        }
                        for item in error.errors()
                    ]
                }
                return _public_error_response(
                    PublicApiError(
                        "request_validation_failed",
                        "Request validation failed",
                        details=details,
                    ),
                    request_id=request_id,
                    status_code=422,
                )
            except HTTPException as error:
                detail = error.detail if isinstance(error.detail, dict) else {}
                return _public_error_response(
                    PublicApiError(
                        str(detail.get("code", "request_failed")),
                        str(detail.get("message", "Request failed")),
                    ),
                    request_id=request_id,
                    status_code=error.status_code,
                )
            response.headers.setdefault("X-Request-Id", request_id)
            for name, value in _VERSION_POLICY.headers().items():
                response.headers.setdefault(name, value)
            return response

        return handler


def _create_public_execution_router(
    *,
    auth_provider: SaasAuthProvider,
    execution: PublicApiExecutionService,
) -> APIRouter:
    router = APIRouter(
        route_class=_StablePublicApiRoute,
        dependencies=[Security(_bearer)],
    )

    @router.get(
        "/projects",
        operation_id="listProjects",
        response_model=ProjectPage,
        responses={200: {"headers": _success_headers()}, **_error_responses()},
    )
    def list_projects(
        request: Request,
        response: Response,
        limit: int = Query(default=50, ge=1, le=100),
        cursor: str | None = Query(default=None, min_length=1, max_length=4096),
        status: Annotated[
            Literal["active", "suspended", "archived"] | None,
            Query(),
        ] = None,
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        project_id = _machine_project_id(machine)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="project.read_metadata",
            route_class="projects.read",
        )
        page = execution.list_projects(
            machine.credential,
            cursor=cursor,
            limit=limit,
            status=status,
        )
        _set_public_headers(response, rate=rate)
        return {
            "items": [_project_resource(cast(PublicApiProjectView, item)) for item in page.items],
            "next_cursor": page.next_cursor,
        }

    @router.get(
        "/projects/{project_id}",
        operation_id="getProject",
        response_model=ProjectMetadata,
        responses={
            200: {"headers": _success_headers(etag=True)},
            **_error_responses(),
        },
    )
    def get_project(
        project_id: UUID,
        request: Request,
        response: Response,
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="project.read_metadata",
            route_class="projects.read",
        )
        project = execution.get_project(machine.credential, project_id=project_id)
        _set_public_headers(response, rate=rate, etag=project.etag)
        return _project_resource(project)

    @router.post(
        "/projects/{project_id}/runs",
        operation_id="createRun",
        response_model=RunResource,
        status_code=201,
        responses={
            201: {"headers": _success_headers(etag=True, location=True)},
            **_error_responses(),
        },
    )
    def create_run(
        project_id: UUID,
        body: RunCreateRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="run.create",
            route_class="runs.write",
        )
        run = execution.create_run(
            machine.credential,
            project_id=project_id,
            title=body.title,
            input_payload=cast(dict[str, object], body.input),
            session_id=body.session_id,
            metadata=cast(dict[str, object], body.metadata),
            idempotency_key=idempotency_key,
            trace_id=_public_request_id(request),
            queue_class=body.queue_class,
            priority=body.priority,
            quota_resource=body.quota_resource,
            quota_units=body.quota_units,
        )
        _set_public_headers(response, rate=rate, etag=run.etag)
        response.headers["Location"] = f"/api/v1/projects/{project_id}/runs/{run.id}"
        response.headers["Idempotent-Replayed"] = str(run.replayed).lower()
        return _run_resource(run)

    @router.get(
        "/projects/{project_id}/runs",
        operation_id="listRuns",
        response_model=RunPage,
        responses={200: {"headers": _success_headers()}, **_error_responses()},
    )
    def list_runs(
        project_id: UUID,
        request: Request,
        response: Response,
        limit: int = Query(default=50, ge=1, le=100),
        cursor: str | None = Query(default=None, min_length=1, max_length=4096),
        status: Annotated[list[RunStatus] | None, Query()] = None,
        created_after: Annotated[datetime | None, Query()] = None,
        created_before: Annotated[datetime | None, Query()] = None,
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="run.read_metadata",
            route_class="runs.read",
        )
        page = execution.list_runs(
            machine.credential,
            project_id=project_id,
            cursor=cursor,
            limit=limit,
            statuses=tuple(status or ()),
            created_after=created_after,
            created_before=created_before,
        )
        _set_public_headers(response, rate=rate)
        return {
            "items": [_run_resource(cast(PublicApiRunView, item)) for item in page.items],
            "next_cursor": page.next_cursor,
        }

    @router.get(
        "/projects/{project_id}/runs/{run_id}",
        operation_id="getRun",
        response_model=RunResource,
        responses={
            200: {"headers": _success_headers(etag=True)},
            **_error_responses(),
        },
    )
    def get_run(
        project_id: UUID,
        run_id: UUID,
        request: Request,
        response: Response,
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="run.read_metadata",
            route_class="runs.read",
        )
        run = execution.get_run(machine.credential, project_id=project_id, run_id=run_id)
        _set_public_headers(response, rate=rate, etag=run.etag)
        return _run_resource(run)

    @router.get(
        "/projects/{project_id}/runs/{run_id}/content",
        operation_id="getRunContent",
        response_model=RunContent,
        responses={
            200: {"headers": _success_headers(etag=True)},
            **_error_responses(),
        },
    )
    def get_run_content(
        project_id: UUID,
        run_id: UUID,
        request: Request,
        response: Response,
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="run.read_content",
            route_class="runs.read",
        )
        content = execution.get_run_content(
            machine.credential,
            project_id=project_id,
            run_id=run_id,
        )
        _set_public_headers(response, rate=rate, etag=content.etag)
        return _run_content_resource(content)

    @router.post(
        "/projects/{project_id}/runs/{run_id}/cancel",
        operation_id="cancelRun",
        response_model=RunResource,
        responses={
            200: {"headers": _success_headers(etag=True)},
            **_error_responses(),
        },
    )
    def cancel_run(
        project_id: UUID,
        run_id: UUID,
        body: RunCancelRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
        if_match: str = Header(alias="If-Match", pattern=r'^W/"[1-9][0-9]*"$'),
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="run.cancel",
            route_class="runs.write",
        )
        run = execution.cancel_run(
            machine.credential,
            project_id=project_id,
            run_id=run_id,
            reason=body.reason or "public_api_request",
            expected_version=_etag_version(if_match),
            idempotency_key=idempotency_key,
            trace_id=_public_request_id(request),
        )
        _set_public_headers(response, rate=rate, etag=run.etag)
        response.headers["Idempotent-Replayed"] = str(run.replayed).lower()
        return _run_resource(run)

    @router.post(
        "/projects/{project_id}/runs/{run_id}/retry",
        operation_id="retryRun",
        response_model=RunResource,
        status_code=201,
        responses={
            201: {"headers": _success_headers(etag=True, location=True)},
            **_error_responses(),
        },
    )
    def retry_run(
        project_id: UUID,
        run_id: UUID,
        body: RunRetryRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
        if_match: str = Header(alias="If-Match", pattern=r'^W/"[1-9][0-9]*"$'),
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="run.retry",
            route_class="runs.write",
        )
        run = execution.retry_run(
            machine.credential,
            project_id=project_id,
            run_id=run_id,
            expected_version=_etag_version(if_match),
            idempotency_key=idempotency_key,
            trace_id=_public_request_id(request),
            input_override=(
                cast(dict[str, object], body.input_override)
                if body.input_override is not None
                else None
            ),
            metadata=cast(dict[str, object], body.metadata),
            queue_class=body.queue_class,
            priority=body.priority,
        )
        _set_public_headers(response, rate=rate, etag=run.etag)
        response.headers["Location"] = f"/api/v1/projects/{project_id}/runs/{run.id}"
        response.headers["Idempotent-Replayed"] = str(run.replayed).lower()
        return _run_resource(run)

    @router.get(
        "/projects/{project_id}/runs/{run_id}/events",
        operation_id="listRunEvents",
        response_model=RunEventPage,
        responses={200: {"headers": _success_headers()}, **_error_responses()},
    )
    def list_run_events(
        project_id: UUID,
        run_id: UUID,
        request: Request,
        response: Response,
        limit: int = Query(default=100, ge=1, le=500),
        cursor: str | None = Query(default=None, min_length=1, max_length=4096),
        after_sequence: int | None = Query(default=None, ge=0),
    ) -> dict[str, object]:
        machine = _require_public_machine(auth_provider, request)
        rate = execution.consume_rate_limit(
            machine.credential,
            project_id=project_id,
            permission="run.read_content",
            route_class="events.read",
        )
        page = execution.list_run_events(
            machine.credential,
            project_id=project_id,
            run_id=run_id,
            cursor=cursor,
            limit=limit,
            after_sequence=after_sequence,
        )
        _set_public_headers(response, rate=rate)
        return {
            "items": [_event_resource(cast(PublicApiRunEventView, item)) for item in page.items],
            "next_cursor": page.next_cursor,
        }

    return router


def _public_request_id(request: Request) -> str:
    existing = getattr(request.state, "public_api_request_id", None)
    if isinstance(existing, str):
        return existing
    supplied = request.headers.get("X-Request-Id", "")
    if _REQUEST_ID_PATTERN.fullmatch(supplied):
        return supplied
    return str(uuid4())


def _public_error_response(
    error: PublicApiError,
    *,
    request_id: str,
    status_code: int | None = None,
) -> JSONResponse:
    resolved_status = status_code or _public_status(error.code)
    headers = {"X-Request-Id": request_id, **_VERSION_POLICY.headers()}
    if error.code == "rate_limit_exceeded":
        headers.update(
            {
                "RateLimit-Limit": str(error.details.get("limit", 0)),
                "RateLimit-Remaining": "0",
                "RateLimit-Reset": str(error.details.get("reset", 0)),
                "Retry-After": str(error.details.get("retry_after", 1)),
            }
        )
    return JSONResponse(
        status_code=resolved_status,
        headers=headers,
        content={
            "error": {
                "code": error.code,
                "message": str(error),
                "request_id": request_id,
                "details": error.details,
            }
        },
    )


def _public_status(code: str) -> int:
    if code == "public_api_database_role_required":
        return 500
    if code in {"invalid_api_credential", "service_account_authentication_required"}:
        return 401
    if code in {"permission_denied", "project_scope_required"}:
        return 403
    if code in {"project_not_found", "run_not_found", "session_not_found"}:
        return 404
    if code == "precondition_failed":
        return 412
    if code == "rate_limit_exceeded":
        return 429
    if code in {
        "idempotency_conflict",
        "run_terminal",
        "run_cancelling",
        "run_cancel_invalid",
        "run_not_terminal",
        "session_closed",
        "quota_exceeded",
        "quota_not_configured",
    }:
        return 409
    return 400


def _require_public_machine(
    auth_provider: SaasAuthProvider,
    request: Request,
) -> SaasMachinePrincipal:
    principal = auth_provider.get_machine_principal(request)
    if principal is None:
        raise PublicApiError(
            "service_account_authentication_required",
            "Service Account authentication is required",
        )
    return principal


def _machine_project_id(machine: SaasMachinePrincipal) -> UUID:
    project_id = machine.credential.project_id
    if machine.credential.space_id is None or project_id is None:
        raise PublicApiError(
            "project_scope_required", "Public execution requires a project-scoped credential"
        )
    return project_id


def _set_public_headers(
    response: Response,
    *,
    rate: PublicApiRateLimitView,
    etag: str | None = None,
) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["RateLimit-Limit"] = str(rate.limit)
    response.headers["RateLimit-Remaining"] = str(rate.remaining)
    response.headers["RateLimit-Reset"] = str(rate.reset_epoch)
    if etag is not None:
        response.headers["ETag"] = etag


def _etag_version(value: str) -> int:
    if not re.fullmatch(r'W/"[1-9][0-9]*"', value):
        raise PublicApiError("if_match_invalid", "If-Match is invalid")
    return int(value[3:-1])


def _project_resource(view: PublicApiProjectView) -> dict[str, object]:
    return {
        "id": view.id,
        "space_id": view.space_id,
        "name": view.name,
        "visibility": view.visibility,
        "status": view.status,
        "authorization_version": view.authorization_version,
        "created_at": view.created_at,
        "updated_at": view.updated_at,
        "etag": view.etag,
    }


def _run_resource(view: PublicApiRunView) -> dict[str, object]:
    return {
        "id": view.id,
        "project_id": view.project_id,
        "task_id": view.task_id,
        "session_id": view.session_id,
        "parent_run_id": view.parent_run_id,
        "status": view.status,
        "version": view.version,
        "event_sequence": view.event_sequence,
        "queue_class": view.queue_class,
        "priority": view.priority,
        "metadata": view.metadata,
        "created_at": view.created_at,
        "updated_at": view.updated_at,
        "terminal_at": view.terminal_at,
        "etag": view.etag,
    }


def _run_content_resource(view: PublicApiRunContentView) -> dict[str, object]:
    return {
        "run_id": view.run_id,
        "input": view.input,
        "product_revision": view.product_revision,
        "upstream_revision": view.upstream_revision,
        "schema_revision": view.schema_revision,
        "adapter_contract_version": view.adapter_contract_version,
        "etag": view.etag,
    }


def _event_resource(view: PublicApiRunEventView) -> dict[str, object]:
    return {
        "id": view.id,
        "run_id": view.run_id,
        "sequence": view.sequence,
        "type": view.event_type,
        "data": view.payload or {},
        "trace_id": view.trace_id,
        "created_at": view.created_at,
    }


def _require_human(auth_provider: SaasAuthProvider, request: Request) -> SaasPrincipal:
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise _http_error(LifecycleError("authentication_required", "login required"), 401)
    return principal


def _status_for(error: ApiCredentialError) -> int:
    if error.code in {"forbidden", "permission_escalation_forbidden"}:
        return 403
    if error.code in {"service_account_not_found"}:
        return 404
    if error.code.startswith("invalid_"):
        return 400
    return 409


def _http_error(error: object, status_code: int) -> Exception:
    from fastapi import HTTPException

    return HTTPException(
        status_code=status_code,
        detail={
            "code": str(getattr(error, "code", "request_invalid")),
            "message": str(error),
        },
    )


def _account_payload(account: ServiceAccountView) -> dict[str, object]:
    return {
        "id": str(account.id),
        "tenant_id": str(account.tenant_id),
        "space_id": str(account.space_id) if account.space_id else None,
        "project_id": str(account.project_id) if account.project_id else None,
        "name": account.name,
        "description": account.description,
        "steward_user_id": str(account.steward_user_id),
        "status": account.status,
        "security_version": account.security_version,
        "replayed": account.replayed,
    }


def _issued_payload(issued: IssuedApiCredential) -> dict[str, object]:
    return {
        "id": str(issued.credential_id),
        "service_account_id": str(issued.service_account_id),
        "display_prefix": issued.display_prefix,
        "token": issued.token,
        "permission_scopes": list(issued.permission_scopes),
        "allowed_networks": list(issued.allowed_networks),
        "expires_at": issued.expires_at.isoformat(),
        "replayed": issued.replayed,
    }


def _credential_payload(credential: ApiCredentialView) -> dict[str, object]:
    return {
        "id": str(credential.id),
        "service_account_id": str(credential.service_account_id),
        "name": credential.name,
        "display_prefix": credential.display_prefix,
        "permission_scopes": list(credential.permission_scopes),
        "allowed_networks": list(credential.allowed_networks),
        "status": credential.status,
        "expires_at": credential.expires_at.isoformat(),
        "last_used_at": credential.last_used_at.isoformat() if credential.last_used_at else None,
        "last_used_ip": credential.last_used_ip,
        "revoked_at": credential.revoked_at.isoformat() if credential.revoked_at else None,
    }
