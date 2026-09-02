"""Public HTTP contract for self-service SaaS tenant onboarding."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from datetime import datetime
from importlib.resources import files
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from saas.control_plane.client_network import (
    ClientNetworkUnavailableError,
    TrustedClientNetworkResolver,
)
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.onboarding import (
    OnboardingError,
    OnboardingRequested,
    RegistrationAccepted,
    SelfServiceOnboardingService,
)
from saas.control_plane.onboarding_status import (
    OnboardingCustomerStage,
    OnboardingCustomerState,
    OnboardingStatusError,
    OnboardingStatusService,
    OnboardingStatusView,
)

if TYPE_CHECKING:
    from saas.control_plane.http_auth import SaasAuthProvider


_MAX_RETRY_AFTER_SECONDS = 86_400
_CATALOG_CACHE_CONTROL = "public, max-age=60, must-revalidate"
_UI_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}
_NETWORK_RATE_LIMIT_ROUTES = {
    "request_registration": ("/onboarding/registrations", "registration.request"),
    "resend_verification": (
        "/onboarding/registrations/{registration_id}/resend",
        "registration.resend",
    ),
    "verify_registration": (
        "/onboarding/registrations/{registration_id}/verify",
        "registration.verify",
    ),
}


class _StrictRequest(BaseModel):
    """Reject coercion and unknown fields at the public onboarding boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)


class OnboardingRegistrationRequest(_StrictRequest):
    email: str = Field(min_length=3, max_length=320)
    display_name: str | None = Field(default=None, min_length=1, max_length=256)
    tenant_name: str = Field(min_length=1, max_length=256)
    tenant_slug: str = Field(min_length=1, max_length=63)
    default_space_name: str = Field(min_length=1, max_length=256)
    default_space_slug: str = Field(min_length=1, max_length=63)
    plan_key: str = Field(min_length=1, max_length=64)
    home_region: str = Field(min_length=1, max_length=64)


class OnboardingResendRequest(_StrictRequest):
    email: str = Field(min_length=3, max_length=320)


class OnboardingVerificationRequest(_StrictRequest):
    verification_token: str = Field(min_length=1, max_length=1024)
    password: str = Field(min_length=12, max_length=1024)


class OnboardingRegistrationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    registration_id: UUID
    status: Literal["verification_pending"] = "verification_pending"


class OnboardingRequestedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    registration_id: UUID
    status: Literal["tenant_provisioning"] = "tenant_provisioning"
    onboarding_id: UUID
    user_id: UUID
    tenant_id: UUID
    space_id: UUID
    subscription_id: UUID
    runtime_partition_id: UUID
    default_project_id: UUID


class OnboardingStatusResponse(BaseModel):
    """Allowlisted authenticated projection of the customer's current journey."""

    model_config = ConfigDict(extra="forbid", strict=True)

    state: OnboardingCustomerState
    stage: OnboardingCustomerStage
    version: int
    updated_at: datetime
    can_start_first_run: bool
    tenant_id: UUID | None = None
    space_id: UUID | None = None
    default_project_id: UUID | None = None
    trial_ends_at: datetime | None = None
    support_reference: str | None = None


class OnboardingCatalogPlanResponse(BaseModel):
    """Allowlisted commercial facts for one currently selectable plan."""

    model_config = ConfigDict(extra="forbid", strict=True)

    key: str = Field(min_length=1, max_length=64)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    trial_days: int = Field(ge=1, le=90)
    trial_run_limit: int = Field(ge=1)
    trial_concurrency_limit: int = Field(ge=1)


class OnboardingCatalogResponse(BaseModel):
    """Atomic anonymous plan and region catalog bound to one semantic revision."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1] = 1
    revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    plans: list[OnboardingCatalogPlanResponse] = Field(min_length=1)
    regions: list[str] = Field(min_length=1)
    verification_ttl_seconds: int = Field(ge=300, le=86_400)


def create_onboarding_router(
    *,
    onboarding: SelfServiceOnboardingService,
    onboarding_status: OnboardingStatusService,
    auth_provider: SaasAuthProvider,
    client_network: TrustedClientNetworkResolver,
) -> APIRouter:
    """Expose non-enumerating registration, resend, and verification routes."""

    if not isinstance(client_network, TrustedClientNetworkResolver):
        raise TypeError("onboarding client network resolver is invalid")
    router = APIRouter(
        route_class=_network_rate_limited_route_class(
            onboarding=onboarding,
            client_network=client_network,
        )
    )

    @router.get(
        "/onboarding/catalog",
        response_model=OnboardingCatalogResponse,
        responses={304: {"description": "Catalog revision is unchanged"}},
    )
    def public_catalog(
        request: Request, response: Response
    ) -> OnboardingCatalogResponse | Response:
        catalog = OnboardingCatalogResponse.model_validate(onboarding.public_catalog())
        etag = f'W/"{catalog.revision}"'
        headers = {
            "Cache-Control": _CATALOG_CACHE_CONTROL,
            "ETag": etag,
        }
        if _if_none_match(request.headers.get("if-none-match"), etag):
            return Response(status_code=304, headers=headers)
        for name, value in headers.items():
            response.headers[name] = value
        return catalog

    @router.get(
        "/onboarding/status",
        response_model=OnboardingStatusResponse,
        response_model_exclude_none=True,
    )
    def current_status(request: Request, response: Response) -> OnboardingStatusResponse:
        response.headers["Cache-Control"] = "private, no-store"
        authorization_present = "authorization" in request.headers
        token, source = auth_provider.extract_token(request)
        principal = auth_provider.get_principal(request) if token and source == "cookie" else None
        if principal is None or authorization_present:
            raise HTTPException(
                status_code=401,
                detail={"code": "authentication_required", "message": "login required"},
                headers={"Cache-Control": "private, no-store"},
            )
        try:
            status = onboarding_status.for_actor(principal.session.user_id)
        except OnboardingStatusError as error:
            raise HTTPException(
                status_code=404,
                detail={"code": error.code, "message": str(error)},
                headers={"Cache-Control": "private, no-store"},
            ) from error
        return _status_payload(status)

    @router.post(
        "/onboarding/registrations",
        response_model=OnboardingRegistrationResponse,
        status_code=202,
    )
    def request_registration(
        body: OnboardingRegistrationRequest,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> OnboardingRegistrationResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            accepted = onboarding.request_registration(
                email=body.email,
                display_name=body.display_name,
                tenant_name=body.tenant_name,
                tenant_slug=body.tenant_slug,
                default_space_name=body.default_space_name,
                default_space_slug=body.default_space_slug,
                plan_key=body.plan_key,
                home_region=body.home_region,
                idempotency_key=idempotency_key,
            )
        except (OnboardingError, LifecycleError) as error:
            raise _http_error(error) from error
        return _registration_payload(accepted)

    @router.post(
        "/onboarding/registrations/{registration_id}/resend",
        response_model=OnboardingRegistrationResponse,
        status_code=202,
    )
    def resend_verification(
        registration_id: UUID,
        body: OnboardingResendRequest,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> OnboardingRegistrationResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            accepted = onboarding.resend_verification(
                registration_id=registration_id,
                email=body.email,
                idempotency_key=idempotency_key,
            )
        except (OnboardingError, LifecycleError) as error:
            raise _http_error(error) from error
        return _registration_payload(accepted)

    @router.post(
        "/onboarding/registrations/{registration_id}/verify",
        response_model=OnboardingRequestedResponse,
        status_code=202,
    )
    def verify_registration(
        registration_id: UUID,
        body: OnboardingVerificationRequest,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> OnboardingRequestedResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            completed = onboarding.verify_and_provision(
                registration_id=registration_id,
                verification_token=body.verification_token,
                password=body.password,
                idempotency_key=idempotency_key,
            )
        except (OnboardingError, LifecycleError) as error:
            raise _http_error(error) from error
        return _completion_payload(completed)

    return router


def create_onboarding_ui_router() -> APIRouter:
    """Serve the build-free onboarding UI outside the official web bundle."""

    router = APIRouter()

    @router.get("/signup", include_in_schema=False)
    @router.get("/signup/verify", include_in_schema=False)
    @router.get("/signup/status", include_in_schema=False)
    @router.get("/saas/login", include_in_schema=False)
    def onboarding_shell() -> HTMLResponse:
        return HTMLResponse(
            files("saas.onboarding_ui").joinpath("onboarding.html").read_text(encoding="utf-8"),
            headers=_UI_HEADERS,
        )

    @router.get("/saas/onboarding-assets/onboarding.css", include_in_schema=False)
    def onboarding_css() -> Response:
        return _ui_asset("onboarding.css", "text/css")

    @router.get("/saas/onboarding-assets/onboarding.js", include_in_schema=False)
    def onboarding_javascript() -> Response:
        return _ui_asset("onboarding.js", "text/javascript")

    return router


def _ui_asset(name: str, media_type: str) -> Response:
    return Response(
        files("saas.onboarding_ui").joinpath(name).read_bytes(),
        media_type=media_type,
        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"},
    )


def _network_rate_limited_route_class(
    *,
    onboarding: SelfServiceOnboardingService,
    client_network: TrustedClientNetworkResolver,
) -> type[APIRoute]:
    """Build a route wrapper that runs before FastAPI reads or validates a body."""

    require_network_rate_limit = getattr(onboarding, "require_network_rate_limit", None)
    if not callable(require_network_rate_limit):
        raise TypeError("onboarding service must provide require_network_rate_limit()")

    class OnboardingNetworkRateLimitedRoute(APIRoute):
        def get_route_handler(
            self,
        ) -> Callable[[Request], Coroutine[Any, Any, Response]]:
            route_handler = super().get_route_handler()
            methods = frozenset(self.methods or ())
            if methods != {"POST"}:
                return route_handler

            route_contract = _NETWORK_RATE_LIMIT_ROUTES.get(self.endpoint.__name__)
            if route_contract is None:
                raise RuntimeError("public onboarding POST route is missing a network rate limit")
            expected_suffix, action = route_contract
            if not self.path_format.endswith(expected_suffix):
                raise RuntimeError(
                    "public onboarding POST route path does not match its rate limit"
                )

            async def network_rate_limited(request: Request) -> Response:
                try:
                    subject = client_network.resolve(request)
                    await run_in_threadpool(
                        require_network_rate_limit,
                        action=action,
                        subject=subject,
                    )
                except ClientNetworkUnavailableError:
                    raise _rate_limit_unavailable_http_error() from None
                except OnboardingError as error:
                    raise _http_error(error) from error
                return await route_handler(request)

            return network_rate_limited

    return OnboardingNetworkRateLimitedRoute


def _registration_payload(value: RegistrationAccepted) -> OnboardingRegistrationResponse:
    return OnboardingRegistrationResponse(
        registration_id=value.registration_id,
    )


def _completion_payload(value: OnboardingRequested) -> OnboardingRequestedResponse:
    return OnboardingRequestedResponse(
        registration_id=value.registration_id,
        onboarding_id=value.onboarding_id,
        user_id=value.user_id,
        tenant_id=value.tenant_id,
        space_id=value.space_id,
        subscription_id=value.subscription_id,
        runtime_partition_id=value.runtime_partition_id,
        default_project_id=value.default_project_id,
    )


def _status_payload(value: OnboardingStatusView) -> OnboardingStatusResponse:
    return OnboardingStatusResponse(
        state=value.state,
        stage=value.stage,
        version=value.version,
        updated_at=value.updated_at,
        can_start_first_run=value.can_start_first_run,
        tenant_id=value.tenant_id,
        space_id=value.space_id,
        default_project_id=value.default_project_id,
        trial_ends_at=value.trial_ends_at,
        support_reference=value.support_reference,
    )


def _http_error(error: OnboardingError | LifecycleError) -> HTTPException:
    headers = {"Cache-Control": "no-store"}
    if error.code == "registration_rate_limited":
        status = 429
        message = "registration request rate limit exceeded"
        retry_after = getattr(error, "retry_after_seconds", None)
        if type(retry_after) is not int:
            retry_after = 1
        headers["Retry-After"] = str(min(_MAX_RETRY_AFTER_SECONDS, max(1, retry_after)))
    elif error.code == "registration_rate_limit_unavailable":
        status = 503
        message = "registration abuse protection is unavailable"
    elif error.code in {
        "idempotency_conflict",
        "registration_conflict",
        "registration_unavailable",
    }:
        status = 409
        message = str(error)
    else:
        status = 400
        message = str(error)
    return HTTPException(
        status_code=status,
        detail={"code": error.code, "message": message},
        headers=headers,
    )


def _rate_limit_unavailable_http_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={
            "code": "registration_rate_limit_unavailable",
            "message": "registration abuse protection is unavailable",
        },
        headers={"Cache-Control": "no-store"},
    )


def _if_none_match(value: str | None, current_etag: str) -> bool:
    """Apply weak comparison for one bounded, server-generated catalog ETag."""

    if value is None:
        return False

    def normalized(candidate: str) -> str:
        stripped = candidate.strip()
        return stripped[2:].strip() if stripped.startswith("W/") else stripped

    current = normalized(current_etag)
    return any(normalized(candidate) in {"*", current} for candidate in value.split(","))
