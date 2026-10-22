"""Staff Realm HTTP surface for content-blind approval and notification operations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse

from saas.control_plane.approval_operations import ApprovalActor
from saas.control_plane.notification_http import (
    ApprovalOperationsProtocol,
    NotificationOperationsProtocol,
    _console_asset,
    _console_html,
    _ContentBlindRoute,
    _register_operations_routes,
)
from saas.control_plane.platform_http import PlatformHttpConfig
from saas.control_plane.platform_security import (
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class PlatformSessionProtocol(Protocol):
    """Narrow Staff-session boundary used by the independent router and fakes."""

    @property
    def origin(self) -> str: ...

    @property
    def audience(self) -> str: ...

    def validate_session(
        self,
        token: str,
        *,
        origin: str,
        audience: str,
        now: datetime | None = None,
    ) -> ValidatedPlatformPrincipal: ...

    def validate_csrf(self, token: str, csrf_token: str) -> None: ...


Clock = Callable[[], datetime]


def create_platform_notification_router(
    *,
    config: PlatformHttpConfig,
    sessions: PlatformSessionProtocol,
    approvals: ApprovalOperationsProtocol,
    notifications: NotificationOperationsProtocol,
    now: Clock | None = None,
) -> APIRouter:
    """Create the independent, browser-only Staff notification operations router."""

    if sessions.origin.rstrip("/") != config.origin.rstrip("/"):
        raise ValueError("Platform notification Origin contract differs from session authority")
    if sessions.audience != config.audience:
        raise ValueError("Platform notification Audience contract differs from session authority")
    clock = now or (lambda: datetime.now(timezone.utc))
    router = APIRouter(route_class=_ContentBlindRoute)

    def actor_for_request(request: Request) -> ApprovalActor:
        if not config.enabled:
            raise _platform_http_error("platform_feature_disabled")
        request_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
        if request_origin != config.origin.rstrip("/"):
            raise _platform_http_error("platform_origin_forbidden")
        if request.headers.get("authorization"):
            raise _platform_http_error("platform_cookie_auth_required")
        if any(request.cookies.get(name) for name in config.tenant_cookie_names):
            raise _platform_http_error("platform_realm_mismatch")
        token = request.cookies.get(config.cookie_name, "")
        if not token:
            raise _platform_http_error("platform_authentication_required")
        if request.method in _UNSAFE_METHODS:
            origin = request.headers.get("origin", "").rstrip("/")
            if origin != config.origin.rstrip("/"):
                raise _platform_http_error("platform_origin_forbidden")
            try:
                sessions.validate_csrf(token, request.headers.get("x-csrf-token", ""))
            except PlatformSecurityError as error:
                raise _platform_http_error("platform_csrf_invalid") from error
        try:
            principal = sessions.validate_session(
                token,
                origin=config.origin,
                audience=config.audience,
                now=clock(),
            )
        except PlatformSecurityError as error:
            raise _platform_http_error(error.code) from error
        required_permission = _required_permission(request)
        if required_permission not in principal.permissions:
            raise _platform_http_error("platform_permission_denied")
        return ApprovalActor(
            realm="staff",
            actor_id=principal.principal_id,
            tenant_id=None,
            security_version=principal.security_version,
            authenticated_at=principal.authenticated_at,
            expires_at=principal.expires_at,
            permissions=principal.permissions,
        )

    _register_operations_routes(
        router,
        prefix="/v2/platform-admin/notification-operations",
        actor_for_request=actor_for_request,
        approvals=approvals,
        notifications=notifications,
        clock=clock,
        allow_template_mutations=True,
    )

    @router.get("/platform-notification-ops", include_in_schema=False)
    def platform_notification_console(request: Request) -> HTMLResponse:
        actor_for_request(request)
        return _console_html("staff")

    @router.get(
        "/platform-notification-ops/assets/notification-ops.css",
        include_in_schema=False,
    )
    def platform_notification_css(request: Request) -> Response:
        actor_for_request(request)
        return _console_asset("notification_ops.css", "text/css")

    @router.get(
        "/platform-notification-ops/assets/notification-ops.js",
        include_in_schema=False,
    )
    def platform_notification_javascript(request: Request) -> Response:
        actor_for_request(request)
        return _console_asset("notification_ops.js", "text/javascript")

    return router


def _platform_http_error(code: str) -> HTTPException:
    if code == "platform_feature_disabled":
        status = 404
    elif code in {
        "platform_authentication_required",
        "platform_cookie_auth_required",
        "platform_realm_mismatch",
        "platform_session_invalid",
        "platform_principal_inactive",
    }:
        status = 401
    elif code in {
        "platform_csrf_invalid",
        "platform_origin_forbidden",
        "platform_fresh_auth_required",
        "platform_permission_denied",
    }:
        status = 403
    elif code.endswith("_unavailable"):
        status = 503
    else:
        status = 400
    return HTTPException(status_code=status, detail={"code": code})


def _required_permission(request: Request) -> str:
    path = request.url.path
    if request.method not in _UNSAFE_METHODS:
        return "platform.notification.read"
    if "/templates" in path:
        return "platform.notification_template.manage"
    if path.endswith("/replay"):
        return "platform.notification.replay"
    if any(segment in path for segment in ("/inbox/", "/delegations", "/batches")):
        return "platform.operation.approve"
    return "platform.notification.read"
