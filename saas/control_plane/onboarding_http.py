"""Public HTTP contract for self-service SaaS tenant onboarding."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.onboarding import (
    OnboardingError,
    OnboardingRequested,
    RegistrationAccepted,
    SelfServiceOnboardingService,
)


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


def create_onboarding_router(*, onboarding: SelfServiceOnboardingService) -> APIRouter:
    """Expose non-enumerating registration, resend, and verification routes."""

    router = APIRouter()

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
    )


def _http_error(error: OnboardingError | LifecycleError) -> HTTPException:
    if error.code in {
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
