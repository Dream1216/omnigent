"""Stable `/api/v1` HTTP contract for machine identity administration and use."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Header, Request, Response
from pydantic import BaseModel, Field

from saas.control_plane.api_credentials import (
    ApiCredentialError,
    ApiCredentialService,
    ApiCredentialView,
    IssuedApiCredential,
    ServiceAccountView,
)
from saas.control_plane.lifecycle import LifecycleError

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


class MachineAuthorizeRequest(BaseModel):
    permission: str = Field(min_length=1, max_length=128)
    tenant_id: UUID
    space_id: UUID | None = None
    project_id: UUID | None = None


def create_public_api_router(
    *,
    auth_provider: SaasAuthProvider,
    api_credentials: ApiCredentialService,
) -> APIRouter:
    """Create the explicit, versioned API without exposing upstream models."""

    router = APIRouter()

    @router.get("/auth/whoami")
    def whoami(request: Request, response: Response) -> dict[str, object]:
        response.headers["Cache-Control"] = "private, no-store"
        machine = auth_provider.get_machine_principal(request)
        if machine is not None:
            credential = machine.credential
            return {
                "actor_type": "service_account",
                "service_account_id": str(credential.service_account_id),
                "credential_id": str(credential.credential_id),
                "tenant_id": str(credential.tenant_id),
                "space_id": str(credential.space_id) if credential.space_id else None,
                "project_id": str(credential.project_id) if credential.project_id else None,
                "permission_scopes": sorted(credential.permission_scopes),
                "expires_at": credential.expires_at.isoformat(),
            }
        human = _require_human(auth_provider, request)
        return {
            "actor_type": "user",
            "user_id": str(human.session.user_id),
            "security_version": human.session.security_version,
        }

    @router.post("/auth/authorize")
    def authorize_machine(body: MachineAuthorizeRequest, request: Request) -> dict[str, object]:
        machine = _require_machine(auth_provider, request)
        try:
            api_credentials.require_permission(
                machine.credential,
                permission=body.permission,
                tenant_id=body.tenant_id,
                space_id=body.space_id,
                project_id=body.project_id,
            )
        except ApiCredentialError as error:
            raise _http_error(error, 403) from error
        return {
            "allowed": True,
            "permission": body.permission,
            "service_account_id": str(machine.credential.service_account_id),
        }

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


def _require_human(auth_provider: SaasAuthProvider, request: Request) -> SaasPrincipal:
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise _http_error(LifecycleError("authentication_required", "login required"), 401)
    return principal


def _require_machine(auth_provider: SaasAuthProvider, request: Request) -> SaasMachinePrincipal:
    principal = auth_provider.get_machine_principal(request)
    if principal is None:
        raise _http_error(
            ApiCredentialError(
                "service_account_authentication_required",
                "Service Account authentication is required",
            ),
            401,
        )
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
