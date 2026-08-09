"""Independent PC1 Platform Admin HTTP application and Realm boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Literal, TypeVar
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

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
    PrivacyDeletionManifestView,
    PrivacyLegalHoldView,
    PrivacyLifecycleService,
)
from saas.control_plane.privacy_operations import (
    PrivacyAttemptView,
    PrivacyAttestationView,
    PrivacyBackupView,
    PrivacyOperationService,
    PrivacyOperationView,
    PrivacyWorkItemView,
)

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_MAX_PRIVACY_COMMAND_BYTES = 16 * 1024
_PrivacyCommandT = TypeVar("_PrivacyCommandT", bound=BaseModel)


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


class _StrictPrivacyOperationCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _PrivacyApprovalRequestCommand(_StrictPrivacyOperationCommand):
    reason_code: Literal[
        "contract_expiry",
        "data_subject_request",
        "legal_authority",
        "security_response",
        "tenant_termination",
        "verified_operational_replay",
    ]
    case_reference: str = Field(min_length=1, max_length=256)
    expires_at: datetime


class _PrivacyDeletionRequestCommand(_PrivacyApprovalRequestCommand):
    expected_target_version: int = Field(ge=1)
    preview_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class _PrivacyFinalizationRequestCommand(_PrivacyApprovalRequestCommand):
    expected_manifest_version: int = Field(ge=1)


class _PrivacyReplayRequestCommand(_PrivacyApprovalRequestCommand):
    expected_version: int = Field(ge=1)


class _PrivacyOperationDecisionCommand(_StrictPrivacyOperationCommand):
    expected_version: int = Field(ge=1)
    decision: Literal["approve", "reject"]
    decision_code: Literal[
        "policy_confirmed",
        "scope_rejected",
        "stale_request",
        "verified_replay",
    ]


def _parse_privacy_operation_command(
    body: bytes,
    content_type: str,
    model: type[_PrivacyCommandT],
) -> _PrivacyCommandT:
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type != "application/json" or not body or len(body) > _MAX_PRIVACY_COMMAND_BYTES:
        raise PlatformSecurityError(
            "platform_privacy_invalid", "Privacy operation command is invalid"
        )
    try:
        return model.model_validate_json(body)
    except ValidationError as error:
        raise PlatformSecurityError(
            "platform_privacy_invalid", "Privacy operation command is invalid"
        ) from error


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
    if error.code == "platform_privacy_legacy_endpoint_retired":
        return 410
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
    privacy_operations: PrivacyOperationService | None = None,
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

    def privacy_operation_service() -> PrivacyOperationService:
        if privacy_operations is None:
            raise PlatformSecurityError(
                "platform_privacy_operations_unavailable",
                "Platform Privacy operation authority is unavailable",
            )
        return privacy_operations

    async def privacy_operation_command_context(
        request: Request,
        model: type[_PrivacyCommandT],
    ) -> tuple[ValidatedPlatformPrincipal, PrivacyOperationService, _PrivacyCommandT]:
        principal, _token = authenticate(request)
        authority = privacy_operation_service()
        command = _parse_privacy_operation_command(
            await request.body(),
            request.headers.get("content-type", ""),
            model,
        )
        return principal, authority, command

    async def privacy_deletion_request_context(
        request: Request,
    ) -> tuple[
        ValidatedPlatformPrincipal,
        PrivacyOperationService,
        _PrivacyDeletionRequestCommand,
    ]:
        return await privacy_operation_command_context(request, _PrivacyDeletionRequestCommand)

    async def privacy_finalization_request_context(
        request: Request,
    ) -> tuple[
        ValidatedPlatformPrincipal,
        PrivacyOperationService,
        _PrivacyFinalizationRequestCommand,
    ]:
        return await privacy_operation_command_context(request, _PrivacyFinalizationRequestCommand)

    async def privacy_replay_request_context(
        request: Request,
    ) -> tuple[
        ValidatedPlatformPrincipal,
        PrivacyOperationService,
        _PrivacyReplayRequestCommand,
    ]:
        return await privacy_operation_command_context(request, _PrivacyReplayRequestCommand)

    async def privacy_operation_decision_context(
        request: Request,
    ) -> tuple[
        ValidatedPlatformPrincipal,
        PrivacyOperationService,
        _PrivacyOperationDecisionCommand,
    ]:
        return await privacy_operation_command_context(request, _PrivacyOperationDecisionCommand)

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

    @app.get("/platform-admin/assets/platform-privacy.css", include_in_schema=False)
    def platform_privacy_css(request: Request) -> Response:
        authenticate(request)
        return _platform_admin_asset("platform_privacy.css", "text/css")

    @app.get("/platform-admin/assets/platform-privacy.js", include_in_schema=False)
    def platform_privacy_javascript(request: Request) -> Response:
        authenticate(request)
        return _platform_admin_asset("platform_privacy.js", "text/javascript")

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
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletion-requests",
        status_code=202,
    )
    def request_privacy_deletion(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        request: Request,
        context: tuple[
            ValidatedPlatformPrincipal,
            PrivacyOperationService,
            _PrivacyDeletionRequestCommand,
        ] = Depends(privacy_deletion_request_context),
    ) -> dict[str, object]:
        principal, authority, command = context
        value = authority.request_deletion_start(
            principal,
            target_type=target_type,
            target_id=target_id,
            expected_target_version=command.expected_target_version,
            preview_hash=command.preview_hash,
            reason_code=command.reason_code,
            case_reference=command.case_reference,
            expires_at=command.expires_at,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _privacy_operation_payload(
            request, value, viewer_principal_id=principal.principal_id
        )

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/"
        "{manifest_id}/finalization-requests",
        status_code=202,
    )
    def request_privacy_deletion_finalization(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        request: Request,
        context: tuple[
            ValidatedPlatformPrincipal,
            PrivacyOperationService,
            _PrivacyFinalizationRequestCommand,
        ] = Depends(privacy_finalization_request_context),
    ) -> dict[str, object]:
        principal, authority, command = context
        value = authority.request_deletion_finalize(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            expected_manifest_version=command.expected_manifest_version,
            reason_code=command.reason_code,
            case_reference=command.case_reference,
            expires_at=command.expires_at,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _privacy_operation_payload(
            request, value, viewer_principal_id=principal.principal_id
        )

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/"
        "{manifest_id}/work-items/{work_item_id}/replay-requests",
        status_code=202,
    )
    def request_privacy_work_item_replay(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        work_item_id: UUID,
        request: Request,
        context: tuple[
            ValidatedPlatformPrincipal,
            PrivacyOperationService,
            _PrivacyReplayRequestCommand,
        ] = Depends(privacy_replay_request_context),
    ) -> dict[str, object]:
        principal, authority, command = context
        value = authority.request_dead_letter_replay(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            subject_id=work_item_id,
            subject_kind="work_item",
            expected_version=command.expected_version,
            reason_code=command.reason_code,
            case_reference=command.case_reference,
            expires_at=command.expires_at,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _privacy_operation_payload(
            request, value, viewer_principal_id=principal.principal_id
        )

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/"
        "{manifest_id}/backups/{backup_item_id}/replay-requests",
        status_code=202,
    )
    def request_privacy_backup_replay(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        backup_item_id: UUID,
        request: Request,
        context: tuple[
            ValidatedPlatformPrincipal,
            PrivacyOperationService,
            _PrivacyReplayRequestCommand,
        ] = Depends(privacy_replay_request_context),
    ) -> dict[str, object]:
        principal, authority, command = context
        value = authority.request_dead_letter_replay(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            subject_id=backup_item_id,
            subject_kind="backup_item",
            expected_version=command.expected_version,
            reason_code=command.reason_code,
            case_reference=command.case_reference,
            expires_at=command.expires_at,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _privacy_operation_payload(
            request, value, viewer_principal_id=principal.principal_id
        )

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/operations/{operation_id}/decision"
    )
    def decide_privacy_operation(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        operation_id: UUID,
        request: Request,
        context: tuple[
            ValidatedPlatformPrincipal,
            PrivacyOperationService,
            _PrivacyOperationDecisionCommand,
        ] = Depends(privacy_operation_decision_context),
    ) -> dict[str, object]:
        principal, authority, command = context
        value = authority.decide(
            principal,
            target_type=target_type,
            target_id=target_id,
            operation_id=operation_id,
            expected_version=command.expected_version,
            decision=command.decision,
            decision_code=command.decision_code,
            idempotency_key=request.headers.get("idempotency-key", ""),
        )
        return _privacy_operation_payload(
            request, value, viewer_principal_id=principal.principal_id
        )

    @app.get("/v2/platform-admin/privacy/{target_type}/{target_id}/operations")
    def list_privacy_operations(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        request: Request,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = privacy_operation_service().list_operations(
            principal,
            target_type=target_type,
            target_id=target_id,
            cursor=cursor,
            limit=limit,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "target_type": target_type,
            "target_id": str(target_id),
            "items": [
                _privacy_operation_item(value, viewer_principal_id=principal.principal_id)
                for value in page.items
            ],
            "next_cursor": str(page.next_cursor) if page.next_cursor is not None else None,
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
            **_privacy_hold_item(value),
        }

    @app.get("/v2/platform-admin/privacy/{target_type}/{target_id}/legal-holds")
    def list_privacy_legal_holds(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        request: Request,
        status: Literal["active", "released"] | None = None,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = privacy_service().list_legal_holds(
            principal,
            target_type=target_type,
            target_id=target_id,
            status=status,
            cursor=cursor,
            limit=limit,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "target_type": target_type,
            "target_id": str(target_id),
            "items": [_privacy_hold_item(value) for value in page.items],
            "next_cursor": str(page.next_cursor) if page.next_cursor is not None else None,
            "content_access": "none",
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

    def reject_legacy_privacy_mutation(request: Request) -> None:
        """Retire direct Staff mutations in v0.3.0; governed operations replace them."""

        authenticate(request)
        raise PlatformSecurityError(
            "platform_privacy_legacy_endpoint_retired",
            "Direct Privacy mutation is retired; use a governed operation request",
        )

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions",
        status_code=410,
    )
    def start_privacy_deletion(
        request: Request,
    ) -> None:
        reject_legacy_privacy_mutation(request)

    @app.get("/v2/platform-admin/privacy/{target_type}/{target_id}/deletions")
    def list_privacy_deletions(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        request: Request,
        status: Literal["executing", "ready_to_finalize", "completed"] | None = None,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = privacy_service().list_manifests(
            principal,
            target_type=target_type,
            target_id=target_id,
            status=status,
            cursor=cursor,
            limit=limit,
        )
        return {
            "request_id": _request_id(request),
            "policy_version": POLICY_VERSION,
            "target_type": target_type,
            "target_id": str(target_id),
            "items": [_privacy_manifest_item(value) for value in page.items],
            "next_cursor": str(page.next_cursor) if page.next_cursor is not None else None,
            "content_access": "none",
        }

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

    @app.get(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}/work-items"
    )
    def list_privacy_work_items(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        request: Request,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = privacy_operation_service().list_work_items(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            cursor=cursor,
            limit=limit,
        )
        return _privacy_resource_page_payload(
            request,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            items=[_privacy_work_item_item(value) for value in page.items],
            next_cursor=page.next_cursor,
        )

    @app.get(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}/attempts"
    )
    def list_privacy_attempts(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        request: Request,
        surface: str | None = Query(default=None, min_length=1, max_length=96),
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = privacy_operation_service().list_attempts(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            surface=surface,
            cursor=cursor,
            limit=limit,
        )
        return _privacy_resource_page_payload(
            request,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            items=[_privacy_attempt_item(value) for value in page.items],
            next_cursor=page.next_cursor,
        )

    @app.get(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}/attestations"
    )
    def list_privacy_attestations(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        request: Request,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = privacy_operation_service().list_attestations(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            cursor=cursor,
            limit=limit,
        )
        return _privacy_resource_page_payload(
            request,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            items=[_privacy_attestation_item(value) for value in page.items],
            next_cursor=page.next_cursor,
        )

    @app.get(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}/backups"
    )
    def list_privacy_backups(
        target_type: Literal["global_user", "tenant"],
        target_id: UUID,
        manifest_id: UUID,
        request: Request,
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        principal, _token = authenticate(request)
        page = privacy_operation_service().list_backups(
            principal,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            cursor=cursor,
            limit=limit,
        )
        return _privacy_resource_page_payload(
            request,
            target_type=target_type,
            target_id=target_id,
            manifest_id=manifest_id,
            items=[_privacy_backup_item(value) for value in page.items],
            next_cursor=page.next_cursor,
        )

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}/surfaces"
    )
    def record_privacy_deletion_surface(
        request: Request,
    ) -> None:
        reject_legacy_privacy_mutation(request)

    @app.post(
        "/v2/platform-admin/privacy/{target_type}/{target_id}/deletions/{manifest_id}/finalize"
    )
    def finalize_privacy_deletion(
        request: Request,
    ) -> None:
        reject_legacy_privacy_mutation(request)

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
        **_privacy_manifest_item(value),
    }


def _privacy_hold_item(value: PrivacyLegalHoldView) -> dict[str, object]:
    return {
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


def _privacy_public_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _privacy_public_value(item)
            for key, item in value.items()
            if key not in {"signature", "approval_ref", "completion_approval_ref", "reason"}
        }
    if isinstance(value, list):
        return [_privacy_public_value(item) for item in value]
    return value


def _privacy_manifest_item(value: PrivacyDeletionManifestView) -> dict[str, object]:
    surface_outcomes = _privacy_public_value(value.surface_outcomes)
    return {
        "manifest_id": str(value.manifest_id),
        "target_type": value.target_type,
        "target_id": str(value.target_id),
        "status": value.status,
        "version": value.version,
        "blockers": list(value.blockers),
        "surface_outcomes": surface_outcomes,
        "manifest_hash": value.manifest_hash,
        "started_at": value.started_at.isoformat(),
        "completed_at": value.completed_at.isoformat() if value.completed_at else None,
        "replayed": value.replayed,
        "content_access": "none",
    }


def _privacy_resource_page_payload(
    request: Request,
    *,
    target_type: str,
    target_id: UUID,
    manifest_id: UUID,
    items: list[dict[str, object]],
    next_cursor: UUID | None,
) -> dict[str, object]:
    return {
        "request_id": _request_id(request),
        "policy_version": POLICY_VERSION,
        "target_type": target_type,
        "target_id": str(target_id),
        "manifest_id": str(manifest_id),
        "items": items,
        "next_cursor": str(next_cursor) if next_cursor is not None else None,
        "content_access": "none",
    }


def _privacy_work_item_item(value: PrivacyWorkItemView) -> dict[str, object]:
    return {
        "work_item_id": str(value.work_item_id),
        "surface": value.surface,
        "disposition": value.disposition,
        "adapter_type": value.adapter_type,
        "status": value.status,
        "attempt_count": value.attempt_count,
        "max_attempts": value.max_attempts,
        "available_at": value.available_at.isoformat(),
        "leased_at": value.leased_at.isoformat() if value.leased_at else None,
        "lease_expires_at": (
            value.lease_expires_at.isoformat() if value.lease_expires_at else None
        ),
        "lease_generation": value.lease_generation,
        "replay_generation": value.replay_generation,
        "last_error_code": value.last_error_code,
        "last_error_sha256": value.last_error_sha256,
        "outcome_content_sha256": value.outcome_content_sha256,
        "version": value.version,
        "created_at": value.created_at.isoformat(),
        "updated_at": value.updated_at.isoformat(),
    }


def _privacy_attempt_item(value: PrivacyAttemptView) -> dict[str, object]:
    return {
        "attempt_id": str(value.attempt_id),
        "work_item_id": str(value.work_item_id) if value.work_item_id is not None else None,
        "backup_item_id": (
            str(value.backup_item_id) if value.backup_item_id is not None else None
        ),
        "surface": value.surface,
        "attempt_number": value.attempt_number,
        "lease_generation": value.lease_generation,
        "replay_generation": value.replay_generation,
        "provider_idempotency_sha256": value.provider_idempotency_sha256,
        "outcome": value.outcome,
        "error_code": value.error_code,
        "error_sha256": value.error_sha256,
        "evidence_payload_sha256": value.evidence_payload_sha256,
        "started_at": value.started_at.isoformat(),
        "completed_at": value.completed_at.isoformat(),
    }


def _privacy_attestation_item(value: PrivacyAttestationView) -> dict[str, object]:
    return {
        "attestation_id": str(value.attestation_id),
        "subject_kind": value.subject_kind,
        "subject_id": str(value.subject_id),
        "surface": value.surface,
        "payload_type": value.payload_type,
        "payload_sha256": value.payload_sha256,
        "envelope_sha256": value.envelope_sha256,
        "immutability_receipt_sha256": value.immutability_receipt_sha256,
        "kms_audit_receipt_sha256": value.kms_audit_receipt_sha256,
        "signature_algorithm": value.signature_algorithm,
        "record_sha256": value.record_sha256,
        "product_revision": value.product_revision,
        "upstream_revision": value.upstream_revision,
        "schema_revision": value.schema_revision,
        "adapter_contract_version": value.adapter_contract_version,
        "verifier_policy_version": value.verifier_policy_version,
        "signed_at": value.signed_at.isoformat(),
        "verified_at": value.verified_at.isoformat(),
        "created_at": value.created_at.isoformat(),
    }


def _privacy_backup_item(value: PrivacyBackupView) -> dict[str, object]:
    return {
        "backup_item_id": str(value.backup_item_id),
        "provider": value.provider,
        "backup_data_class": value.backup_data_class,
        "catalog_snapshot_sha256": value.catalog_snapshot_sha256,
        "tombstone_sha256": value.tombstone_sha256,
        "object_lock_until": (
            value.object_lock_until.isoformat() if value.object_lock_until else None
        ),
        "purge_due_at": value.purge_due_at.isoformat(),
        "status": value.status,
        "attempt_count": value.attempt_count,
        "max_attempts": value.max_attempts,
        "available_at": value.available_at.isoformat(),
        "leased_at": value.leased_at.isoformat() if value.leased_at else None,
        "lease_expires_at": (
            value.lease_expires_at.isoformat() if value.lease_expires_at else None
        ),
        "lease_generation": value.lease_generation,
        "replay_generation": value.replay_generation,
        "last_error_code": value.last_error_code,
        "last_error_sha256": value.last_error_sha256,
        "purge_evidence_sha256": value.purge_evidence_sha256,
        "purged_at": value.purged_at.isoformat() if value.purged_at else None,
        "version": value.version,
        "created_at": value.created_at.isoformat(),
        "updated_at": value.updated_at.isoformat(),
    }


def _privacy_operation_payload(
    request: Request,
    value: PrivacyOperationView,
    *,
    viewer_principal_id: UUID,
) -> dict[str, object]:
    return {
        "request_id": _request_id(request),
        "policy_version": POLICY_VERSION,
        **_privacy_operation_item(value, viewer_principal_id=viewer_principal_id),
    }


def _privacy_operation_item(
    value: PrivacyOperationView,
    *,
    viewer_principal_id: UUID,
) -> dict[str, object]:
    """Return operational metadata without request, case, signature, or raw-error content."""

    return {
        "operation_id": str(value.operation_id),
        "phase": value.phase,
        "target_type": value.target_type,
        "target_id": str(value.target_id),
        "manifest_id": str(value.manifest_id) if value.manifest_id is not None else None,
        "subject_id": str(value.subject_id) if value.subject_id is not None else None,
        "status": value.status,
        "version": value.version,
        "snapshot_hash": value.snapshot_hash,
        "requested_by_me": value.requested_by_principal_id == viewer_principal_id,
        "decision_by_me": value.approved_by_principal_id == viewer_principal_id,
        "decision_recorded": value.approved_by_principal_id is not None,
        "expires_at": value.expires_at.isoformat(),
        "created_at": value.created_at.isoformat(),
        "completed_at": value.completed_at.isoformat() if value.completed_at else None,
        "error_code": value.error_code,
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
