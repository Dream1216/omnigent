"""Independent PC1 Platform Admin HTTP application and Realm boundary."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from saas.control_plane.permissions import POLICY_VERSION, permission_catalog_payload
from saas.control_plane.platform_lifecycle import PlatformLifecycleResult, PlatformLifecycleService
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSecurityError,
    PlatformSessionService,
    ValidatedPlatformPrincipal,
)

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class _LifecycleCommand(BaseModel):
    expected_version: int = Field(ge=1)
    approval_ref: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1024)


class _SessionRevocationCommand(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


class _OwnerRecoveryCommand(BaseModel):
    target_user_id: UUID
    expected_tenant_version: int = Field(ge=1)
    expected_source_membership_version: int = Field(ge=1)
    expected_target_membership_version: int = Field(ge=1)
    preview_hash: str = Field(min_length=64, max_length=64)
    approval_ref: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1024)


class _IdentityConflictAssignmentCommand(BaseModel):
    candidate_user_id: UUID
    expected_version: int = Field(ge=1)
    approval_ref: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1024)


class _IdentityConflictBlockCommand(BaseModel):
    expected_version: int = Field(ge=1)
    approval_ref: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1024)


@dataclass(frozen=True, slots=True)
class PlatformHttpConfig:
    """Feature flag and independent browser trust configuration."""

    enabled: bool
    origin: str
    audience: str
    cookie_name: str = "__Host-omnigent_platform_session"
    tenant_cookie_names: frozenset[str] = frozenset({"__Host-omnigent_saas_session"})

    def __post_init__(self) -> None:
        if not self.origin.startswith("https://") or not self.audience:
            raise ValueError("Platform Admin requires an HTTPS Origin and Audience")
        if not self.cookie_name.startswith("__Host-"):
            raise ValueError("Platform Admin session cookie must use the __Host- prefix")
        if self.cookie_name in self.tenant_cookie_names:
            raise ValueError("Platform and Tenant Realm cookies must differ")


def _request_id(request: Request) -> str:
    supplied = request.headers.get("x-request-id", "").strip()
    return supplied[:128] if supplied else uuid4().hex


def _status_for(error: PlatformSecurityError) -> int:
    if error.code == "platform_feature_disabled":
        return 404
    if error.code in {
        "platform_authentication_required",
        "platform_realm_mismatch",
        "platform_session_invalid",
        "platform_principal_inactive",
    }:
        return 401
    if error.code in {"platform_permission_denied", "platform_csrf_invalid"}:
        return 403
    if error.code in {"platform_fresh_auth_required"}:
        return 403
    if error.code == "platform_lifecycle_unavailable":
        return 503
    if error.code.endswith("_not_found"):
        return 404
    if error.code.endswith("_conflict") or error.code.endswith("_blocked"):
        return 409
    return 400


def create_platform_admin_app(
    *,
    config: PlatformHttpConfig,
    sessions: PlatformSessionService,
    authorization: PlatformAuthorizationService,
    projections: PlatformProjectionService,
    lifecycle: PlatformLifecycleService | None = None,
) -> FastAPI:
    """Build the standalone Platform Control Plane API, never the Tenant app."""

    if sessions.origin != config.origin.rstrip("/") or sessions.audience != config.audience:
        raise ValueError("Platform Session and HTTP Realm contracts differ")
    app = FastAPI(
        title="Omnigent Platform Control Plane",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def platform_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Request-ID"] = _request_id(request)
        response.headers["X-Platform-Policy-Version"] = POLICY_VERSION
        return response

    @app.exception_handler(PlatformSecurityError)
    async def platform_security_error(request: Request, error: PlatformSecurityError):
        return JSONResponse(
            status_code=_status_for(error),
            content={
                "error": {"code": error.code, "message": str(error)},
                "request_id": _request_id(request),
                "policy_version": POLICY_VERSION,
            },
        )

    def authenticate(request: Request) -> tuple[ValidatedPlatformPrincipal, str]:
        if not config.enabled:
            raise PlatformSecurityError(
                "platform_feature_disabled", "Platform Admin is not enabled"
            )
        request_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
        origin_header = request.headers.get("origin")
        if request_origin != config.origin.rstrip("/"):
            raise PlatformSecurityError(
                "platform_realm_mismatch", "request reached the wrong Platform Origin"
            )
        if origin_header is not None and origin_header.rstrip("/") != config.origin.rstrip("/"):
            raise PlatformSecurityError(
                "platform_realm_mismatch", "request Origin does not match the Staff Realm"
            )
        if request.method in _UNSAFE_METHODS and origin_header is None:
            raise PlatformSecurityError(
                "platform_realm_mismatch", "unsafe Platform request requires an exact Origin"
            )
        if request.headers.get("authorization"):
            raise PlatformSecurityError(
                "platform_realm_mismatch", "browser Platform API does not accept bearer tokens"
            )
        tenant_cookie_present = any(
            request.cookies.get(name) for name in config.tenant_cookie_names
        )
        token = request.cookies.get(config.cookie_name, "")
        if tenant_cookie_present:
            raise PlatformSecurityError(
                "platform_realm_mismatch", "Tenant and Staff Realm sessions cannot be combined"
            )
        if not token:
            raise PlatformSecurityError(
                "platform_authentication_required", "Staff authentication is required"
            )
        principal = sessions.validate_session(
            token,
            origin=config.origin,
            audience=config.audience,
        )
        if request.method in _UNSAFE_METHODS:
            sessions.validate_csrf(token, request.headers.get("x-csrf-token", ""))
        return principal, token

    def lifecycle_service() -> PlatformLifecycleService:
        if lifecycle is None:
            raise PlatformSecurityError(
                "platform_lifecycle_unavailable", "Platform lifecycle authority is unavailable"
            )
        return lifecycle

    def mutation_result(request: Request, value: PlatformLifecycleResult) -> dict[str, object]:
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "operation_id": str(value.operation_id),
            "action": value.action,
            "target_id": str(value.target_id),
            "result": value.result,
            "replayed": value.replayed,
        }

    @app.get("/v2/platform-admin/context")
    def context(request: Request) -> dict[str, object]:
        principal, _token = authenticate(request)
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "realm": "staff",
            "principal_id": str(principal.principal_id),
            "session_id": str(principal.session_id),
            "roles": sorted(principal.roles),
            "permissions": sorted(principal.permissions),
            "content_access": "none",
            "audience": config.audience,
        }

    @app.get("/v2/platform-admin/permissions")
    def permissions(request: Request) -> dict[str, object]:
        principal, _token = authenticate(request)
        authorization.require(principal, "platform.permission.read")
        return {
            "request_id": _request_id(request),
            **permission_catalog_payload(),
        }

    @app.get("/v2/platform-admin/tenants")
    def tenants(
        request: Request,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = projections.list_tenants(principal, cursor=cursor, limit=limit)
        return {
            "request_id": _request_id(request),
            "policy_version": page.policy_version,
            "items": list(page.items),
            "next_cursor": page.next_cursor,
        }

    @app.get("/v2/platform-admin/users")
    def users(
        request: Request,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = projections.list_users(principal, cursor=cursor, limit=limit)
        return {
            "request_id": _request_id(request),
            "policy_version": page.policy_version,
            "items": list(page.items),
            "next_cursor": page.next_cursor,
        }

    @app.get("/v2/platform-admin/identity-conflicts")
    def identity_conflicts(
        request: Request,
        status: str | None = "pending",
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        values = lifecycle_service().list_identity_conflicts(
            principal,
            status=status,
            cursor=cursor,
            limit=limit,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "items": [
                {
                    "conflict_id": str(value.conflict_id),
                    "provider": value.provider,
                    "candidate_user_id": (
                        str(value.candidate_user_id)
                        if value.candidate_user_id is not None
                        else None
                    ),
                    "status": value.status,
                    "version": value.version,
                    "platform_review_status": value.platform_review_status,
                    "platform_reviewed_by_principal_id": (
                        str(value.platform_reviewed_by_principal_id)
                        if value.platform_reviewed_by_principal_id is not None
                        else None
                    ),
                    "platform_reviewed_at": (
                        value.platform_reviewed_at.isoformat()
                        if value.platform_reviewed_at is not None
                        else None
                    ),
                    "created_at": value.created_at.isoformat(),
                    "updated_at": value.updated_at.isoformat(),
                }
                for value in values
            ],
            "next_cursor": (str(values[-1].conflict_id) if len(values) == limit else None),
            "content_access": "none",
        }

    @app.post("/v2/platform-admin/identity-conflicts/{conflict_id}/assign")
    def assign_identity_conflict(
        conflict_id: UUID,
        command: _IdentityConflictAssignmentCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = lifecycle_service().review_identity_conflict(
            principal,
            conflict_id=conflict_id,
            decision="assign",
            candidate_user_id=command.candidate_user_id,
            expected_version=command.expected_version,
            approval_ref=command.approval_ref,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return mutation_result(request, value)

    @app.post("/v2/platform-admin/identity-conflicts/{conflict_id}/block")
    def block_identity_conflict(
        conflict_id: UUID,
        command: _IdentityConflictBlockCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = lifecycle_service().review_identity_conflict(
            principal,
            conflict_id=conflict_id,
            decision="block",
            candidate_user_id=None,
            expected_version=command.expected_version,
            approval_ref=command.approval_ref,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return mutation_result(request, value)

    @app.post("/v2/platform-admin/users/{user_id}/suspend")
    def suspend_user(
        user_id: UUID,
        command: _LifecycleCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = lifecycle_service().suspend_user(
            principal,
            user_id=user_id,
            expected_security_version=command.expected_version,
            approval_ref=command.approval_ref,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return mutation_result(request, value)

    @app.post("/v2/platform-admin/users/{user_id}/restore")
    def restore_user(
        user_id: UUID,
        command: _LifecycleCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = lifecycle_service().restore_user(
            principal,
            user_id=user_id,
            expected_security_version=command.expected_version,
            approval_ref=command.approval_ref,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return mutation_result(request, value)

    @app.post("/v2/platform-admin/users/{user_id}/revoke-sessions")
    def revoke_user_sessions(
        user_id: UUID,
        command: _SessionRevocationCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = lifecycle_service().revoke_user_sessions(
            principal,
            user_id=user_id,
            expected_security_version=command.expected_version,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return mutation_result(request, value)

    @app.post("/v2/platform-admin/tenants/{tenant_id}/suspend")
    def suspend_tenant(
        tenant_id: UUID,
        command: _LifecycleCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = lifecycle_service().suspend_tenant(
            principal,
            tenant_id=tenant_id,
            expected_lifecycle_version=command.expected_version,
            approval_ref=command.approval_ref,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return mutation_result(request, value)

    @app.post("/v2/platform-admin/tenants/{tenant_id}/restore")
    def restore_tenant(
        tenant_id: UUID,
        command: _LifecycleCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = lifecycle_service().restore_tenant(
            principal,
            tenant_id=tenant_id,
            expected_lifecycle_version=command.expected_version,
            approval_ref=command.approval_ref,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return mutation_result(request, value)

    @app.get("/v2/platform-admin/tenants/{tenant_id}/owner-recovery-preview")
    def owner_recovery_preview(
        tenant_id: UUID,
        request: Request,
        target_user_id: UUID,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        preview = lifecycle_service().preview_owner_recovery(
            principal,
            tenant_id=tenant_id,
            target_user_id=target_user_id,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "tenant_id": str(preview.tenant_id),
            "source_owner_id": (
                str(preview.source_owner_id) if preview.source_owner_id is not None else None
            ),
            "target_user_id": str(preview.target_user_id),
            "tenant_version": preview.tenant_version,
            "source_membership_version": preview.source_membership_version,
            "target_membership_version": preview.target_membership_version,
            "blockers": list(preview.blockers),
            "preview_hash": preview.preview_hash,
        }

    @app.post("/v2/platform-admin/tenants/{tenant_id}/owner-recovery")
    def recover_tenant_owner(
        tenant_id: UUID,
        command: _OwnerRecoveryCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = lifecycle_service().recover_tenant_owner(
            principal,
            tenant_id=tenant_id,
            target_user_id=command.target_user_id,
            expected_tenant_version=command.expected_tenant_version,
            expected_source_membership_version=command.expected_source_membership_version,
            expected_target_membership_version=command.expected_target_membership_version,
            preview_hash=command.preview_hash,
            approval_ref=command.approval_ref,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return mutation_result(request, value)

    @app.post("/v2/platform-admin/session/logout", status_code=204)
    def logout(request: Request, response: Response) -> Response:
        _principal, token = authenticate(request)
        sessions.revoke_session(token)
        response.delete_cookie(
            config.cookie_name,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        response.status_code = 204
        return response

    return app
