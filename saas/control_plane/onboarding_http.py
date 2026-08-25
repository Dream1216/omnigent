"""Public HTTP contract for self-service SaaS tenant onboarding."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

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
    plan_key: str = Field(min_length=1, max_length=128)
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


def create_onboarding_router(
    *,
    onboarding: SelfServiceOnboardingService,
    onboarding_status: OnboardingStatusService,
    auth_provider: SaasAuthProvider,
) -> APIRouter:
    """Expose non-enumerating registration, resend, and verification routes."""

    router = APIRouter()

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
    if error.code == "registration_rate_limited":
        status = 429
    elif error.code == "registration_rate_limit_unavailable":
        status = 503
    elif error.code in {
        "idempotency_conflict",
        "registration_conflict",
        "registration_unavailable",
    }:
        status = 409
    else:
        status = 400
    return HTTPException(
        status_code=status,
        detail={"code": error.code, "message": str(error)},
        headers={"Cache-Control": "no-store"},
    )
