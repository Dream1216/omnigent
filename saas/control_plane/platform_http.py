"""Independent PC1 Platform Admin HTTP application and Realm boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Literal
from uuid import UUID, uuid4

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from saas.control_plane.permissions import POLICY_VERSION, permission_catalog_payload
from saas.control_plane.platform_governed_access import (
    AdminOperationView,
    AuditEventView,
    PlatformGovernedAccessService,
    SupportGrantView,
)
from saas.control_plane.platform_lifecycle import (
    PlatformLifecycleOperationView,
    PlatformLifecycleResult,
    PlatformLifecycleService,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSecurityError,
    PlatformSessionService,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.privacy_lifecycle import (
    DeletionSurfaceEvidence,
    PrivacyDeletionManifestView,
    PrivacyLifecycleService,
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


class _SupportGrantRequestCommand(BaseModel):
    tenant_id: UUID
    mode: Literal["standard", "break_glass"]
    scopes: tuple[str, ...] = Field(min_length=1, max_length=3)
    project_ids: tuple[UUID, ...] = Field(default=(), max_length=100)
    reason: str = Field(min_length=1, max_length=1024)
    incident_ref: str | None = Field(default=None, max_length=256)
    expires_at: datetime


class _GovernedDecisionCommand(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


class _SupportSessionCommand(BaseModel):
    expected_version: int = Field(ge=1)


class _AuditExportRequestCommand(BaseModel):
    tenant_id: UUID | None = None
    from_sequence: int = Field(ge=1)
    to_sequence: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


class _AuditExportApprovalCommand(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


class _LegalHoldCommand(BaseModel):
    scope: tuple[str, ...] = Field(min_length=1, max_length=32)
    authority_ref: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1024)
    review_due_at: datetime


class _LegalHoldReleaseCommand(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


class _PrivacyDeletionCommand(BaseModel):
    expected_target_version: int = Field(ge=1)
    preview_hash: str = Field(min_length=64, max_length=64)
    approval_ref: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1024)


class _DeletionSurfaceCommand(BaseModel):
    expected_manifest_version: int = Field(ge=1)
    surface: str = Field(min_length=1, max_length=96)
    disposition: str = Field(min_length=1, max_length=32)
    status: str = Field(min_length=1, max_length=32)
    evidence_sha256: str = Field(min_length=64, max_length=64)
    remaining_item_count: int = Field(ge=0)
    runtime_accessible: bool
    direct_identifiers_remaining: bool
    observed_at: datetime
    retention_until: datetime | None = None
    retention_basis: str | None = Field(default=None, max_length=96)
    tombstone_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    key_id: str = Field(min_length=1, max_length=256)
    signature: str = Field(min_length=1, max_length=4096)


class _PrivacyFinalizeCommand(BaseModel):
    expected_manifest_version: int = Field(ge=1)
    approval_ref: str = Field(min_length=1, max_length=256)


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
    if error.code.endswith("_unavailable"):
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
    governed_access: PlatformGovernedAccessService | None = None,
    privacy: PrivacyLifecycleService | None = None,
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
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
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

    def governed_access_service() -> PlatformGovernedAccessService:
        if governed_access is None:
            raise PlatformSecurityError(
                "platform_governed_access_unavailable",
                "Platform governed access authority is unavailable",
            )
        return governed_access

    def privacy_service() -> PrivacyLifecycleService:
        if privacy is None:
            raise PlatformSecurityError(
                "platform_privacy_unavailable", "Platform privacy authority is unavailable"
            )
        return privacy

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

    @app.get("/platform-admin", include_in_schema=False)
    @app.get("/platform-admin/", include_in_schema=False)
    def platform_admin_ui(request: Request) -> HTMLResponse:
        authenticate(request)
        return HTMLResponse(
            files("saas.admin_ui").joinpath("platform_admin.html").read_text(encoding="utf-8"),
            headers={
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
                    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
                )
            },
        )

    @app.get("/platform-admin/assets/platform-admin.css", include_in_schema=False)
    def platform_admin_css(request: Request) -> Response:
        authenticate(request)
        return _platform_admin_asset("platform_admin.css", "text/css")

    @app.get("/platform-admin/assets/platform-admin.js", include_in_schema=False)
    def platform_admin_javascript(request: Request) -> Response:
        authenticate(request)
        return _platform_admin_asset("platform_admin.js", "text/javascript")

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

    @app.get("/v2/platform-admin/tenants/{tenant_id}/lifecycle-preview")
    def tenant_lifecycle_preview(tenant_id: UUID, request: Request) -> dict[str, object]:
        principal, _token = authenticate(request)
        preview = lifecycle_service().preview_tenant_lifecycle(
            principal,
            tenant_id=tenant_id,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "tenant_id": str(preview.target_id),
            "status": preview.status,
            "lifecycle_version": preview.version,
            "content_access": "none",
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

    @app.get("/v2/platform-admin/users/{user_id}/lifecycle-preview")
    def user_lifecycle_preview(user_id: UUID, request: Request) -> dict[str, object]:
        principal, _token = authenticate(request)
        preview = lifecycle_service().preview_user_lifecycle(
            principal,
            user_id=user_id,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "user_id": str(preview.target_id),
            "status": preview.status,
            "security_version": preview.version,
            "content_access": "none",
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

    @app.get("/v2/platform-admin/privacy/{target_type}/{target_id}/deletion-preview")
    def privacy_deletion_preview(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = privacy_service().preview_deletion(
            principal,
            target_type=target_type,
            target_id=target_id,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "target_type": value.target_type,
            "target_id": str(value.target_id),
            "target_status": value.target_status,
            "target_version": value.target_version,
            "blockers": list(value.blockers),
            "impact_counts": value.impact_counts,
            "preview_hash": value.preview_hash,
            "content_access": "none",
        }

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/legal-holds",
        status_code=201,
    )
    def place_privacy_legal_hold(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        command: _LegalHoldCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = privacy_service().place_legal_hold(
            principal,
            target_type=target_type,
            target_id=target_id,
            scope=command.scope,
            authority_ref=command.authority_ref,
            reason=command.reason,
            review_due_at=command.review_due_at,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "hold_id": str(value.hold_id),
            "target_type": value.target_type,
            "target_id": str(value.target_id),
            "status": value.status,
            "scope": list(value.scope),
            "authority_ref": value.authority_ref,
            "version": value.version,
            "created_at": value.created_at.isoformat(),
            "review_due_at": value.review_due_at.isoformat(),
            "released_at": value.released_at.isoformat() if value.released_at else None,
        }

    @app.post("/v2/platform-admin/privacy/{target_type}/{target_id}/legal-holds/{hold_id}/release")
    def release_privacy_legal_hold(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        hold_id: UUID,
        command: _LegalHoldReleaseCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = privacy_service().release_legal_hold(
            principal,
            target_type=target_type,
            target_id=target_id,
            hold_id=hold_id,
            expected_version=command.expected_version,
            reason=command.reason,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "hold_id": str(value.hold_id),
            "status": value.status,
            "version": value.version,
            "released_at": value.released_at.isoformat() if value.released_at else None,
        }

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions",
        status_code=202,
    )
    def start_privacy_deletion(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        command: _PrivacyDeletionCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = privacy_service().start_deletion(
            principal,
            target_type=target_type,
            target_id=target_id,
            expected_target_version=command.expected_target_version,
            preview_hash=command.preview_hash,
            approval_ref=command.approval_ref,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _privacy_manifest_payload(request, value)

    @app.get("/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}")
    def get_privacy_deletion(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = privacy_service().get_manifest(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
        )
        return _privacy_manifest_payload(request, value)

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}/surfaces"
    )
    def record_privacy_deletion_surface(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        command: _DeletionSurfaceCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = privacy_service().record_surface_evidence(
            principal,
            target_type=target_type,
            target_id=target_id,
            evidence=DeletionSurfaceEvidence(
                manifest_id=manifest_id,
                surface=command.surface,
                disposition=command.disposition,
                status=command.status,
                evidence_sha256=command.evidence_sha256,
                remaining_item_count=command.remaining_item_count,
                runtime_accessible=command.runtime_accessible,
                direct_identifiers_remaining=command.direct_identifiers_remaining,
                observed_at=command.observed_at,
                retention_until=command.retention_until,
                retention_basis=command.retention_basis,
                tombstone_sha256=command.tombstone_sha256,
                key_id=command.key_id,
                signature=command.signature,
            ),
            expected_manifest_version=command.expected_manifest_version,
        )
        return _privacy_manifest_payload(request, value)

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}/finalize"
    )
    def finalize_privacy_deletion(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        command: _PrivacyFinalizeCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = privacy_service().finalize_deletion(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            expected_manifest_version=command.expected_manifest_version,
            approval_ref=command.approval_ref,
        )
        return _privacy_manifest_payload(request, value)

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

    @app.get("/v2/platform-admin/support-access-grants")
    def support_access_grants(
        request: Request,
        tenant_id: UUID | None = None,
        status: str | None = Query(default=None, max_length=32),
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        values = governed_access_service().list_support_grants(
            principal,
            tenant_id=tenant_id,
            status=status,
            cursor=cursor,
            limit=limit,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "items": [_support_grant_payload(value) for value in values],
            "next_cursor": str(values[-1].grant_id) if len(values) == limit else None,
            "content_access": "grant_scoped_only",
        }

    @app.post("/v2/platform-admin/support-access-grants", status_code=201)
    def request_support_access(
        command: _SupportGrantRequestCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = governed_access_service().request_support_grant(
            principal,
            tenant_id=command.tenant_id,
            mode=command.mode,
            scopes=command.scopes,
            project_ids=command.project_ids,
            reason=command.reason,
            incident_ref=command.incident_ref,
            expires_at=command.expires_at,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            **_support_grant_payload(value),
        }

    @app.post("/v2/platform-admin/support-access-grants/{grant_id}/approve")
    def approve_support_access(
        grant_id: UUID,
        command: _GovernedDecisionCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = governed_access_service().decide_staff_approval(
            principal,
            grant_id=grant_id,
            expected_version=command.expected_version,
            decision="approve",
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _support_grant_payload(value)

    @app.post("/v2/platform-admin/support-access-grants/{grant_id}/reject")
    def reject_support_access(
        grant_id: UUID,
        command: _GovernedDecisionCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = governed_access_service().decide_staff_approval(
            principal,
            grant_id=grant_id,
            expected_version=command.expected_version,
            decision="reject",
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _support_grant_payload(value)

    @app.post("/v2/platform-admin/support-access-grants/{grant_id}/revoke")
    def revoke_support_access(
        grant_id: UUID,
        command: _GovernedDecisionCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = governed_access_service().revoke_support_grant(
            principal,
            grant_id=grant_id,
            expected_version=command.expected_version,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _support_grant_payload(value)

    @app.post("/v2/platform-admin/support-access-grants/{grant_id}/sessions", status_code=201)
    def issue_support_session(
        grant_id: UUID,
        command: _SupportSessionCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = governed_access_service().issue_support_session(
            principal,
            grant_id=grant_id,
            expected_version=command.expected_version,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return {
            "session_id": str(value.session_id),
            "grant_id": str(value.grant_id),
            "tenant_id": str(value.tenant_id),
            "principal_id": str(value.principal_id),
            "scopes": list(value.scopes),
            "token": value.token,
            "expires_at": value.expires_at.isoformat(),
            "one_time_disclosure": True,
        }

    @app.get("/v2/platform-admin/operations")
    def operations(
        request: Request,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        governed_values = (
            governed_access.list_admin_operations(principal, cursor=cursor, limit=limit)
            if governed_access is not None
            else ()
        )
        lifecycle_values = (
            lifecycle.list_operations(principal, cursor=cursor, limit=limit)
            if lifecycle is not None
            else ()
        )
        if governed_access is None and lifecycle is None:
            raise PlatformSecurityError(
                "platform_governed_access_unavailable",
                "Platform operation authorities are unavailable",
            )
        items = sorted(
            [
                *(_operation_payload(value) for value in governed_values),
                *(_lifecycle_operation_payload(value) for value in lifecycle_values),
            ],
            key=lambda item: str(item["operation_id"]),
        )
        has_more = (
            len(items) > limit or len(governed_values) == limit or len(lifecycle_values) == limit
        )
        visible = items[:limit]
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "items": visible,
            "next_cursor": visible[-1]["operation_id"] if has_more and visible else None,
        }

    @app.get("/v2/platform-admin/audit-events")
    def audit_events(
        request: Request,
        tenant_id: UUID | None = None,
        after_sequence: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        values = governed_access_service().list_audit_events(
            principal,
            tenant_id=tenant_id,
            after_sequence=after_sequence,
            limit=limit,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "items": [_audit_event_payload(value) for value in values],
            "next_sequence": values[-1].sequence_no if len(values) == limit else None,
        }

    @app.post("/v2/platform-admin/audit-exports", status_code=202)
    def request_audit_export(
        command: _AuditExportRequestCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = governed_access_service().request_audit_export(
            principal,
            tenant_id=command.tenant_id,
            from_sequence=command.from_sequence,
            to_sequence=command.to_sequence,
            reason=command.reason,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return {
            "operation_id": str(value.operation_id),
            "export_id": str(value.export_id),
            "status": value.status,
            "version": value.version,
            "replayed": value.replayed,
        }

    @app.post("/v2/platform-admin/operations/{operation_id}/approve")
    def approve_audit_export(
        operation_id: UUID,
        command: _AuditExportApprovalCommand,
        request: Request,
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        value = governed_access_service().approve_audit_export(
            principal,
            operation_id=operation_id,
            expected_version=command.expected_version,
            approval_reason=command.reason,
        )
        return {
            "export_id": str(value.export_id),
            "operation_id": str(value.operation_id),
            "manifest": value.manifest,
            "content_hash": value.content_hash,
            "signing_key_id": value.signing_key_id,
            "signature": value.signature,
            "replayed": value.replayed,
        }

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


def _support_grant_payload(value: SupportGrantView) -> dict[str, object]:
    return {
        "grant_id": str(value.grant_id),
        "operation_id": str(value.operation_id),
        "tenant_id": str(value.tenant_id),
        "requested_by_principal_id": str(value.requested_by_principal_id),
        "mode": value.mode,
        "scopes": list(value.scopes),
        "project_ids": [str(item) for item in value.project_ids],
        "status": value.status,
        "version": value.version,
        "customer_approval_required": value.customer_approval_required,
        "customer_approved_by_user_id": (
            str(value.customer_approved_by_user_id)
            if value.customer_approved_by_user_id is not None
            else None
        ),
        "staff_approved_by_principal_id": (
            str(value.staff_approved_by_principal_id)
            if value.staff_approved_by_principal_id is not None
            else None
        ),
        "requested_at": value.requested_at.isoformat(),
        "starts_at": value.starts_at.isoformat() if value.starts_at is not None else None,
        "expires_at": value.expires_at.isoformat(),
        "incident_ref": value.incident_ref,
    }


def _privacy_manifest_payload(
    request: Request,
    value: PrivacyDeletionManifestView,
) -> dict[str, object]:
    return {
        "request_id": _request_id(request),
        "policy_version": POLICY_VERSION,
        "manifest_id": str(value.manifest_id),
        "target_type": value.target_type,
        "target_id": str(value.target_id),
        "status": value.status,
        "version": value.version,
        "blockers": list(value.blockers),
        "surface_outcomes": value.surface_outcomes,
        "manifest_hash": value.manifest_hash,
        "completion_approval_ref": value.completion_approval_ref,
        "started_at": value.started_at.isoformat(),
        "completed_at": value.completed_at.isoformat() if value.completed_at else None,
        "replayed": value.replayed,
        "content_access": "none",
    }


def _operation_payload(value: AdminOperationView) -> dict[str, object]:
    return {
        "operation_id": str(value.operation_id),
        "action": value.action,
        "risk_level": value.risk_level,
        "tenant_id": str(value.tenant_id) if value.tenant_id is not None else None,
        "target_type": value.target_type,
        "target_id": str(value.target_id),
        "requested_by_principal_id": str(value.requested_by_principal_id),
        "approved_by_principal_id": (
            str(value.approved_by_principal_id)
            if value.approved_by_principal_id is not None
            else None
        ),
        "status": value.status,
        "version": value.version,
        "created_at": value.created_at.isoformat(),
        "updated_at": value.updated_at.isoformat(),
    }


def _lifecycle_operation_payload(value: PlatformLifecycleOperationView) -> dict[str, object]:
    return {
        "operation_id": str(value.operation_id),
        "action": value.action,
        "risk_level": value.risk_level,
        "tenant_id": str(value.tenant_id) if value.tenant_id is not None else None,
        "target_type": value.target_type,
        "target_id": str(value.target_id),
        "requested_by_principal_id": str(value.requested_by_principal_id),
        "approved_by_principal_id": None,
        "status": value.status,
        "version": value.version,
        "created_at": value.occurred_at.isoformat(),
        "updated_at": value.occurred_at.isoformat(),
        "receipt_source": "pc2_lifecycle",
    }


def _audit_event_payload(value: AuditEventView) -> dict[str, object]:
    return {
        "event_id": str(value.event_id),
        "sequence_no": value.sequence_no,
        "tenant_id": str(value.tenant_id) if value.tenant_id is not None else None,
        "actor_type": value.actor_type,
        "actor_id": str(value.actor_id),
        "event_type": value.event_type,
        "target_type": value.target_type,
        "target_id": str(value.target_id),
        "operation_id": str(value.operation_id) if value.operation_id is not None else None,
        "payload": value.payload,
        "previous_hash": value.previous_hash,
        "event_hash": value.event_hash,
        "occurred_at": value.occurred_at.isoformat(),
    }


def _platform_admin_asset(name: str, media_type: str) -> Response:
    return Response(
        files("saas.admin_ui").joinpath(name).read_bytes(),
        media_type=media_type,
        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"},
    )
