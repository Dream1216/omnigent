"""Tenant Realm HTTP surface for content-blind approval and notification operations."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from typing import Any, Literal, Protocol, cast
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from saas.control_plane.approval_operations import (
    ApprovalActor,
    ApprovalDelegationView,
    ApprovalOperationsError,
    ApprovalWorkItemPage,
    ApprovalWorkItemView,
    BatchDecisionCommand,
    OperationBatchView,
)
from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.notification_delivery import NotificationDeliveryError

_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_IDEMPOTENCY_MAX = 128
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class ApprovalOperationsProtocol(Protocol):
    """Stable orchestration boundary; source authorities remain the sole deciders."""

    def list_work_items(
        self,
        actor: ApprovalActor,
        *,
        status: str | None = None,
        limit: int = 50,
        cursor: UUID | None = None,
        now: datetime | None = None,
    ) -> ApprovalWorkItemPage: ...

    def create_delegation(
        self,
        actor: ApprovalActor,
        *,
        work_item_id: UUID,
        expected_version: int,
        delegate_id: UUID,
        starts_at: datetime,
        expires_at: datetime,
        reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ApprovalDelegationView: ...

    def list_delegations(
        self,
        actor: ApprovalActor,
        *,
        status: str | None = None,
        limit: int = 50,
        cursor: UUID | None = None,
        now: datetime | None = None,
    ) -> object: ...

    def revoke_delegation(
        self,
        actor: ApprovalActor,
        *,
        delegation_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ApprovalDelegationView: ...

    def decide(
        self,
        actor: ApprovalActor,
        *,
        work_item_id: UUID,
        expected_version: int,
        decision: Literal["approve", "reject"],
        decision_code: str,
        decision_reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ApprovalWorkItemView: ...

    def preview_batch(
        self,
        actor: ApprovalActor,
        *,
        commands: tuple[BatchDecisionCommand, ...],
        decision: Literal["approve", "reject"],
        decision_code: str,
        decision_reason: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> OperationBatchView: ...

    def execute_batch(
        self,
        actor: ApprovalActor,
        *,
        batch_id: UUID,
        expected_version: int,
        decision_reason: str,
        now: datetime | None = None,
    ) -> OperationBatchView: ...


class NotificationOperationsProtocol(Protocol):
    """Content-blind delivery, preference, and template read model."""

    def list_deliveries(
        self,
        actor: ApprovalActor,
        *,
        status: str | None = None,
        limit: int = 50,
        cursor: UUID | None = None,
        now: datetime | None = None,
    ) -> object: ...

    def replay(
        self,
        actor: ApprovalActor,
        *,
        delivery_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> object: ...

    def mark_read(
        self,
        actor: ApprovalActor,
        *,
        delivery_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> object: ...

    def list_preferences(
        self,
        actor: ApprovalActor,
        *,
        now: datetime | None = None,
    ) -> tuple[object, ...]: ...

    def update_preference(
        self,
        actor: ApprovalActor,
        *,
        preference_id: UUID,
        expected_version: int,
        enabled: bool,
        locale: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> object: ...

    def list_templates(
        self,
        actor: ApprovalActor,
        *,
        now: datetime | None = None,
    ) -> tuple[object, ...]: ...

    def create_template(
        self,
        actor: ApprovalActor,
        *,
        tenant_id: UUID | None,
        template_key: str,
        channel: Literal["in_app", "email"],
        locale: str,
        version: int,
        content_artifact_handle: str,
        content_sha256: str,
        variables_schema_sha256: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> object: ...

    def retire_template(
        self,
        actor: ApprovalActor,
        *,
        template_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class TenantNotificationHttpConfig:
    """Browser-only Tenant Realm origin and asset contract."""

    origin: str

    def __post_init__(self) -> None:
        if not self.origin.startswith("https://"):
            raise ValueError("Tenant notification operations require an HTTPS Origin")


class _StrictCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ApprovalDecisionBody(_StrictCommand):
    expected_version: StrictInt = Field(ge=1)
    decision: Literal["approve", "reject"]
    decision_code: StrictStr = Field(min_length=1, max_length=128)
    reason: StrictStr = Field(min_length=1, max_length=1024, repr=False)


class DelegationCreateBody(_StrictCommand):
    work_item_id: UUID
    expected_version: StrictInt = Field(ge=1)
    delegate_id: UUID
    starts_at: datetime
    expires_at: datetime
    reason: StrictStr = Field(min_length=1, max_length=1024)


class DelegationRevokeBody(_StrictCommand):
    expected_version: StrictInt = Field(ge=1)


class BatchItemBody(_StrictCommand):
    work_item_id: UUID
    expected_version: StrictInt = Field(ge=1)


class BatchPreviewBody(_StrictCommand):
    decision: Literal["approve", "reject"]
    decision_code: StrictStr = Field(min_length=1, max_length=128)
    reason: StrictStr = Field(min_length=1, max_length=1024, repr=False)
    items: list[BatchItemBody] = Field(min_length=1, max_length=25)


class BatchExecuteBody(_StrictCommand):
    expected_version: StrictInt = Field(ge=1)
    reason: StrictStr = Field(min_length=1, max_length=1024, repr=False)


class DeliveryReplayBody(_StrictCommand):
    expected_version: StrictInt = Field(ge=1)


class DeliveryReadBody(_StrictCommand):
    expected_version: StrictInt = Field(ge=1)


class PreferenceUpdateBody(_StrictCommand):
    expected_version: StrictInt = Field(ge=1)
    enabled: StrictBool
    locale: StrictStr = Field(min_length=2, max_length=32)


class TemplateCreateBody(_StrictCommand):
    tenant_id: UUID | None = None
    template_key: StrictStr = Field(min_length=1, max_length=128)
    channel: Literal["in_app", "email"]
    locale: StrictStr = Field(min_length=2, max_length=32)
    version: StrictInt = Field(ge=1)
    content_artifact_handle: StrictStr = Field(min_length=16, max_length=128, repr=False)
    content_sha256: StrictStr = Field(min_length=64, max_length=64, repr=False)
    variables_schema_sha256: StrictStr = Field(min_length=64, max_length=64, repr=False)


class TemplateRetireBody(_StrictCommand):
    expected_version: StrictInt = Field(ge=1)


ApprovalActorResolver = Callable[[Request], ApprovalActor]
Clock = Callable[[], datetime]


class _ContentBlindRoute(APIRoute):
    """Collapse parser diagnostics so rejected input never enters a response."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def content_blind_handler(request: Request) -> Response:
            try:
                return await original(request)
            except RequestValidationError:
                return JSONResponse(
                    status_code=422,
                    content={"detail": {"code": "notification_request_invalid"}},
                )

        return content_blind_handler


def create_notification_router(
    *,
    config: TenantNotificationHttpConfig,
    auth_provider: SaasAuthProvider,
    approvals: ApprovalOperationsProtocol,
    notifications: NotificationOperationsProtocol,
    now: Clock | None = None,
) -> APIRouter:
    """Create the independent Tenant approval inbox and notification operations router."""

    clock = now or (lambda: datetime.now(timezone.utc))
    router = APIRouter(route_class=_ContentBlindRoute)

    def actor_for_request(request: Request) -> ApprovalActor:
        try:
            tenant_id = UUID(cast(str, request.path_params["tenant_id"]))
        except (KeyError, ValueError) as error:
            raise _http_code("notification_tenant_scope_required") from error
        token, source = auth_provider.extract_token(request)
        if token is None:
            raise _http_code("notification_authentication_required")
        if source != "cookie":
            raise _http_code("notification_cookie_auth_required")
        if request.method in _UNSAFE_METHODS:
            _require_origin(request, config.origin)
            try:
                auth_provider.validate_csrf(token, request.headers.get("x-csrf-token", ""))
            except LifecycleError as error:
                raise _http_code("notification_csrf_invalid") from error
        principal = auth_provider.get_principal(request)
        if principal is None:
            raise _http_code("notification_authentication_required")
        return ApprovalActor(
            realm="tenant",
            actor_id=principal.session.user_id,
            tenant_id=tenant_id,
            security_version=principal.session.security_version,
            authenticated_at=principal.session.authenticated_at,
            expires_at=principal.session.expires_at,
            permissions=frozenset(),
        )

    _register_operations_routes(
        router,
        prefix="/tenants/{tenant_id}/notification-operations",
        actor_for_request=actor_for_request,
        approvals=approvals,
        notifications=notifications,
        clock=clock,
    )

    @router.get("/tenants/{tenant_id}/notification-operations/capabilities")
    def tenant_notification_capabilities(
        tenant_id: UUID, request: Request, response: Response
    ) -> dict[str, object]:
        _ = tenant_id
        actor_for_request(request)
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "notification_operations_enabled": True,
            "template_management": "read_only",
            "content_access": "none",
        }

    @router.get("/tenants/{tenant_id}/notification-ops", include_in_schema=False)
    def tenant_notification_console(tenant_id: UUID, request: Request) -> HTMLResponse:
        _ = tenant_id
        actor_for_request(request)
        return _console_html("tenant")

    @router.get(
        "/tenants/{tenant_id}/notification-ops/assets/notification-ops.css",
        include_in_schema=False,
    )
    def tenant_notification_css(tenant_id: UUID, request: Request) -> Response:
        _ = tenant_id
        actor_for_request(request)
        return _console_asset("notification_ops.css", "text/css")

    @router.get(
        "/tenants/{tenant_id}/notification-ops/assets/notification-ops.js",
        include_in_schema=False,
    )
    def tenant_notification_javascript(tenant_id: UUID, request: Request) -> Response:
        _ = tenant_id
        actor_for_request(request)
        return _console_asset("notification_ops.js", "text/javascript")

    return router


def _register_operations_routes(
    router: APIRouter,
    *,
    prefix: str,
    actor_for_request: ApprovalActorResolver,
    approvals: ApprovalOperationsProtocol,
    notifications: NotificationOperationsProtocol,
    clock: Clock,
    allow_template_mutations: bool = False,
) -> None:
    @router.get(f"{prefix}/inbox")
    def list_inbox(
        request: Request,
        response: Response,
        status: str | None = Query(default=None, max_length=32),
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        actor = actor_for_request(request)
        at = clock()
        try:
            page = approvals.list_work_items(
                actor, status=status, cursor=cursor, limit=limit, now=at
            )
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "items": [_work_item_payload(value, actor) for value in page.items],
            "next_cursor": str(page.next_cursor) if page.next_cursor else None,
            "content_access": "none",
        }

    @router.post(f"{prefix}/inbox/{{work_item_id}}/decision")
    def decide_work_item(
        work_item_id: UUID,
        body: ApprovalDecisionBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
        try:
            value = approvals.decide(
                actor,
                work_item_id=work_item_id,
                expected_version=body.expected_version,
                decision=body.decision,
                decision_code=body.decision_code,
                decision_reason=body.reason,
                idempotency_key=idempotency_key,
                now=at,
            )
        except ApprovalOperationsError as error:
            raise _http_error(error) from error
        return _work_item_payload(value, actor)

    @router.post(f"{prefix}/delegations", status_code=201)
    def create_delegation(
        body: DelegationCreateBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
        try:
            value = approvals.create_delegation(
                actor,
                work_item_id=body.work_item_id,
                expected_version=body.expected_version,
                delegate_id=body.delegate_id,
                starts_at=body.starts_at,
                expires_at=body.expires_at,
                reason=body.reason,
                idempotency_key=idempotency_key,
                now=at,
            )
        except ApprovalOperationsError as error:
            raise _http_error(error) from error
        return _delegation_payload(value, actor)

    @router.get(f"{prefix}/delegations")
    def list_delegations(
        request: Request,
        response: Response,
        status: str | None = Query(default=None, max_length=32),
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        actor = actor_for_request(request)
        try:
            page = approvals.list_delegations(
                actor, status=status, cursor=cursor, limit=limit, now=clock()
            )
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        items, next_cursor = _page_values(page)
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "items": [
                _delegation_payload(cast(ApprovalDelegationView, value), actor)
                for value in items
            ],
            "next_cursor": str(next_cursor) if next_cursor else None,
            "content_access": "none",
        }

    @router.post(f"{prefix}/delegations/{{delegation_id}}/revoke")
    def revoke_delegation(
        delegation_id: UUID,
        body: DelegationRevokeBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
        try:
            value = approvals.revoke_delegation(
                actor,
                delegation_id=delegation_id,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
                now=at,
            )
        except ApprovalOperationsError as error:
            raise _http_error(error) from error
        return _delegation_payload(value, actor)

    @router.post(f"{prefix}/batches/preview", status_code=201)
    def preview_batch(
        body: BatchPreviewBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
        try:
            value = approvals.preview_batch(
                actor,
                commands=tuple(
                    BatchDecisionCommand(
                        work_item_id=item.work_item_id,
                        expected_version=item.expected_version,
                    )
                    for item in body.items
                ),
                decision=body.decision,
                decision_code=body.decision_code,
                decision_reason=body.reason,
                idempotency_key=idempotency_key,
                now=at,
            )
        except ApprovalOperationsError as error:
            raise _http_error(error) from error
        return _batch_payload(value)

    @router.post(f"{prefix}/batches/{{batch_id}}/execute")
    def execute_batch(
        batch_id: UUID,
        body: BatchExecuteBody,
        request: Request,
    ) -> dict[str, object]:
        actor, at = _fresh_mutation_actor(request, actor_for_request, clock)
        try:
            value = approvals.execute_batch(
                actor,
                batch_id=batch_id,
                expected_version=body.expected_version,
                decision_reason=body.reason,
                now=at,
            )
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        return _batch_payload(value)

    @router.get(f"{prefix}/deliveries")
    def list_deliveries(
        request: Request,
        response: Response,
        status: str | None = Query(default=None, max_length=32),
        cursor: UUID | None = None,
        limit: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, object]:
        actor = actor_for_request(request)
        at = clock()
        try:
            page = notifications.list_deliveries(
                actor, status=status, cursor=cursor, limit=limit, now=at
            )
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        items, next_cursor = _page_values(page)
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "items": [_delivery_payload(value) for value in items],
            "next_cursor": str(next_cursor) if next_cursor else None,
            "content_access": "none",
        }

    @router.post(f"{prefix}/deliveries/{{delivery_id}}/replay")
    def replay_delivery(
        delivery_id: UUID,
        body: DeliveryReplayBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
        try:
            value = notifications.replay(
                actor,
                delivery_id=delivery_id,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
                now=at,
            )
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        return _delivery_payload(value)

    @router.post(f"{prefix}/deliveries/{{delivery_id}}/read")
    def mark_delivery_read(
        delivery_id: UUID,
        body: DeliveryReadBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
        try:
            value = notifications.mark_read(
                actor,
                delivery_id=delivery_id,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
                now=at,
            )
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        return _delivery_payload(value)

    @router.get(f"{prefix}/preferences")
    def list_preferences(request: Request, response: Response) -> dict[str, object]:
        actor = actor_for_request(request)
        try:
            values = notifications.list_preferences(actor, now=clock())
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "items": [_preference_payload(value) for value in values],
            "management": "recipient",
            "content_access": "none",
        }

    @router.patch(f"{prefix}/preferences/{{preference_id}}")
    def update_preference(
        preference_id: UUID,
        body: PreferenceUpdateBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
        try:
            value = notifications.update_preference(
                actor,
                preference_id=preference_id,
                expected_version=body.expected_version,
                enabled=body.enabled,
                locale=body.locale,
                idempotency_key=idempotency_key,
                now=at,
            )
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        return _preference_payload(value)

    @router.get(f"{prefix}/templates")
    def list_templates(request: Request, response: Response) -> dict[str, object]:
        actor = actor_for_request(request)
        try:
            values = notifications.list_templates(actor, now=clock())
        except (ApprovalOperationsError, NotificationDeliveryError) as error:
            raise _http_error(error) from error
        response.headers["Cache-Control"] = "private, no-store"
        return {
            "items": [_template_payload(value) for value in values],
            "management": "platform_staff" if allow_template_mutations else "read_only",
            "content_access": "none",
        }

    if allow_template_mutations:

        @router.post(f"{prefix}/templates", status_code=201)
        def create_template(
            body: TemplateCreateBody,
            request: Request,
            idempotency_key: str = Header(
                alias="Idempotency-Key", min_length=1, max_length=128
            ),
        ) -> dict[str, object]:
            actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
            try:
                value = notifications.create_template(
                    actor,
                    tenant_id=body.tenant_id,
                    template_key=body.template_key,
                    channel=body.channel,
                    locale=body.locale,
                    version=body.version,
                    content_artifact_handle=body.content_artifact_handle,
                    content_sha256=body.content_sha256,
                    variables_schema_sha256=body.variables_schema_sha256,
                    idempotency_key=idempotency_key,
                    now=at,
                )
            except (ApprovalOperationsError, NotificationDeliveryError) as error:
                raise _http_error(error) from error
            return _template_payload(value)

        @router.post(f"{prefix}/templates/{{template_id}}/retire")
        def retire_template(
            template_id: UUID,
            body: TemplateRetireBody,
            request: Request,
            idempotency_key: str = Header(
                alias="Idempotency-Key", min_length=1, max_length=128
            ),
        ) -> dict[str, object]:
            actor, at = _mutation_actor(request, actor_for_request, clock, idempotency_key)
            try:
                value = notifications.retire_template(
                    actor,
                    template_id=template_id,
                    expected_version=body.expected_version,
                    idempotency_key=idempotency_key,
                    now=at,
                )
            except (ApprovalOperationsError, NotificationDeliveryError) as error:
                raise _http_error(error) from error
            return _template_payload(value)


def _mutation_actor(
    request: Request,
    actor_for_request: ApprovalActorResolver,
    clock: Clock,
    idempotency_key: str,
) -> tuple[ApprovalActor, datetime]:
    if not idempotency_key.strip() or len(idempotency_key) > _IDEMPOTENCY_MAX:
        raise _http_code("notification_idempotency_key_invalid")
    return _fresh_mutation_actor(request, actor_for_request, clock)


def _fresh_mutation_actor(
    request: Request,
    actor_for_request: ApprovalActorResolver,
    clock: Clock,
) -> tuple[ApprovalActor, datetime]:
    actor = actor_for_request(request)
    at = _aware(clock())
    authenticated_at = _aware(actor.authenticated_at)
    if authenticated_at > at or at - authenticated_at > _FRESH_AUTH_WINDOW:
        raise _http_code("notification_fresh_auth_required")
    if _aware(actor.expires_at) <= at:
        raise _http_code("notification_authentication_required")
    return actor, at


def _require_origin(request: Request, expected_origin: str) -> None:
    origin = request.headers.get("origin", "").rstrip("/")
    request_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
    if origin != expected_origin.rstrip("/") or request_origin != expected_origin.rstrip("/"):
        raise _http_code("notification_origin_forbidden")


def _http_error(error: ApprovalOperationsError | NotificationDeliveryError) -> HTTPException:
    return _http_code(error.code)


def _http_code(code: str) -> HTTPException:
    if code.endswith("_not_found"):
        status = 404
    elif code.endswith(("_conflict", "_stale")):
        status = 409
    elif any(value in code for value in ("forbidden", "permission", "fresh_auth")):
        status = 403
    elif "authentication" in code or "cookie_auth" in code:
        status = 401
    elif code.endswith("_unavailable"):
        status = 503
    else:
        status = 400
    return HTTPException(status_code=status, detail={"code": code})


def _work_item_payload(value: ApprovalWorkItemView, actor: ApprovalActor) -> dict[str, object]:
    routing = (
        "permission_pool"
        if value.assignee_id is None
        else "assigned_to_me"
        if value.assignee_id == actor.actor_id
        else "assigned"
    )
    return {
        "work_item_id": str(value.id),
        "realm": value.realm,
        "tenant_id": str(value.tenant_id) if value.tenant_id else None,
        "requested_by_me": (
            value.requester_realm == actor.realm and value.requester_id == actor.actor_id
        ),
        "routing": routing,
        "operation_kind": value.operation_kind,
        "operation_id": str(value.operation_id),
        "action": value.action,
        "target_type": value.target_type,
        "required_permission": value.required_permission,
        "risk_level": value.risk_level,
        "status": value.status,
        "priority": value.priority,
        "due_at": value.due_at.isoformat(),
        "escalation_at": value.escalation_at.isoformat(),
        "escalation_count": value.escalation_count,
        "decision_code": value.decision_code,
        "decided_at": value.decided_at.isoformat() if value.decided_at else None,
        "version": value.version,
        "content_access": "none",
    }


def _delegation_payload(value: ApprovalDelegationView, actor: ApprovalActor) -> dict[str, object]:
    return {
        "delegation_id": str(value.id),
        "realm": value.realm,
        "tenant_id": str(value.tenant_id) if value.tenant_id else None,
        "delegated_by_me": value.delegator_id == actor.actor_id,
        "delegated_to_me": value.delegate_id == actor.actor_id,
        "permission_code": value.permission_code,
        "scope_type": value.scope_type,
        "scope_id": str(value.scope_id),
        "starts_at": value.starts_at.isoformat(),
        "expires_at": value.expires_at.isoformat(),
        "status": value.status,
        "version": value.version,
        "content_access": "none",
    }


def _batch_payload(value: OperationBatchView) -> dict[str, object]:
    return {
        "batch_id": str(value.id),
        "realm": value.realm,
        "tenant_id": str(value.tenant_id) if value.tenant_id else None,
        "operation_kind": value.operation_kind,
        "action": value.action,
        "decision": value.decision,
        "item_count": value.item_count,
        "status": value.status,
        "success_count": value.success_count,
        "failure_count": value.failure_count,
        "version": value.version,
        "created_at": value.created_at.isoformat(),
        "items": [
            {
                "batch_item_id": str(item.id),
                "sequence": item.sequence,
                "work_item_id": str(item.work_item_id),
                "expected_work_item_version": item.expected_work_item_version,
                "target_type": item.target_type,
                "operation_id": str(item.operation_id) if item.operation_id else None,
                "status": item.status,
                "error_code": item.error_code,
            }
            for item in value.items
        ],
        "replayed": value.replayed,
        "content_access": "none",
    }


def _delivery_payload(value: object) -> dict[str, object]:
    return {
        "delivery_id": str(_value(value, "id")),
        "realm": _value(value, "realm"),
        "tenant_id": _uuid_value(value, "tenant_id"),
        "event_type": _value(value, "event_type"),
        "channel": _value(value, "channel"),
        "source_delivery_id": _uuid_value(value, "source_delivery_id"),
        "status": _value(value, "status"),
        "attempt_count": _value(value, "attempt_count"),
        "max_attempts": _value(value, "max_attempts"),
        "available_at": _time_value(value, "available_at"),
        "recipient_read_at": _time_value(value, "recipient_read_at"),
        "acknowledged_at": _time_value(value, "acknowledged_at"),
        "last_error_code": _value(value, "last_error_code", None),
        "version": _value(value, "version"),
        "content_access": "none",
    }


def _preference_payload(value: object) -> dict[str, object]:
    return {
        "preference_id": str(_value(value, "id")),
        "event_type": _value(value, "event_type"),
        "channel": _value(value, "channel"),
        "enabled": _value(value, "enabled"),
        "locale": _value(value, "locale"),
        "version": _value(value, "version"),
    }


def _template_payload(value: object) -> dict[str, object]:
    return {
        "template_id": str(_value(value, "id")),
        "template_key": _value(value, "template_key"),
        "channel": _value(value, "channel"),
        "locale": _value(value, "locale"),
        "version": _value(value, "version"),
        "status": _value(value, "status"),
        "created_at": _time_value(value, "created_at"),
        "retired_at": _time_value(value, "retired_at"),
    }


def _page_values(value: object) -> tuple[tuple[object, ...], UUID | None]:
    items = cast(tuple[object, ...], _value(value, "items"))
    next_cursor = cast(UUID | None, _value(value, "next_cursor", None))
    return items, next_cursor


def _value(value: object, name: str, default: object = ...) -> object:
    if hasattr(value, name):
        return getattr(value, name)
    if default is not ...:
        return default
    raise ApprovalOperationsError("notification_projection_invalid")


def _uuid_value(value: object, name: str) -> str | None:
    selected = _value(value, name, None)
    return str(selected) if selected is not None else None


def _time_value(value: object, name: str) -> str | None:
    selected = _value(value, name, None)
    return selected.isoformat() if isinstance(selected, datetime) else None


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ApprovalOperationsError("notification_time_invalid")
    return value.astimezone(timezone.utc)


def _console_html(realm: Literal["tenant", "staff"]) -> HTMLResponse:
    name = "notification_ops_tenant.html" if realm == "tenant" else "notification_ops_staff.html"
    return HTMLResponse(
        files("saas.admin_ui").joinpath(name).read_text(encoding="utf-8"),
        headers={
            "Content-Security-Policy": (
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
                "form-action 'self'; frame-ancestors 'none'"
            ),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


def _console_asset(name: str, media_type: str) -> Response:
    return Response(
        files("saas.admin_ui").joinpath(name).read_bytes(),
        media_type=media_type,
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )
