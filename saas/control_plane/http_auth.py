"""FastAPI/ASGI integration for revocable SaaS sessions and runtime context."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send

from omnigent.server.auth import AuthProvider
from saas.compatibility import RuntimeContext, bind_runtime_context
from saas.control_plane.governance import MembershipGovernanceService
from saas.control_plane.identity import IdentityManagementService, PasswordCredentialService
from saas.control_plane.lifecycle import (
    LifecycleError,
    MembershipLifecycleService,
    ValidatedAuthSession,
)
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True, slots=True)
class SaasCookieConfig:
    """Browser-session cookie and origin policy."""

    name: str = "__Host-omnigent_saas_session"
    secure: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"
    ttl: timedelta = timedelta(hours=8)
    trusted_origins: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.name or self.ttl <= timedelta(0):
            raise ValueError("SaaS Cookie name and TTL must be valid")
        if self.name.startswith("__Host-") and not self.secure:
            raise ValueError("__Host- cookies require secure=True")
        if self.same_site == "none" and not self.secure:
            raise ValueError("SameSite=None cookies require secure=True")


@dataclass(frozen=True, slots=True)
class SaasPrincipal:
    """Authenticated Global User and optional resolved runtime projection."""

    session: ValidatedAuthSession
    runtime_context: RuntimeContext | None


@dataclass(frozen=True, slots=True)
class SaasHttpIntegration:
    """Components passed through official `create_app` extension points."""

    auth_provider: SaasAuthProvider
    router: APIRouter
    context_resolver: SqlAlchemyContextResolver
    cookie_config: SaasCookieConfig

    @property
    def extra_router(self) -> tuple[APIRouter, str, list[str]]:
        """Official `create_app(extra_routers=...)` registration tuple."""

        return self.router, "/saas", ["saas"]

    def install_middleware(self, app: FastAPI) -> None:
        """Install context binding after official `create_app` returns."""

        app.add_middleware(
            SaasAuthContextMiddleware,
            auth_provider=self.auth_provider,
            context_resolver=self.context_resolver,
            cookie_config=self.cookie_config,
        )


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChangeRequest(BaseModel):
    new_password: str = Field(min_length=12, max_length=1024)
    current_password: str | None = Field(default=None, max_length=1024)
    expected_version: int | None = Field(default=None, ge=1)


class OwnershipTransferRequest(BaseModel):
    to_user_id: UUID
    source_expected_version: int = Field(ge=1)
    target_expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)
    space_id: UUID | None = None


class RemovalPreflightRequest(BaseModel):
    space_id: UUID | None = None


class RemovalExecutionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)


class SaasAuthProvider(AuthProvider):
    """Official AuthProvider adapter backed by the revocable SaaS session table."""

    login_url = "/saas/login"

    def __init__(
        self,
        lifecycle: MembershipLifecycleService,
        cookie_config: SaasCookieConfig,
    ) -> None:
        self._lifecycle = lifecycle
        self._cookie = cookie_config

    def extract_token(self, connection: HTTPConnection) -> tuple[str | None, str | None]:
        """Return opaque token and source (`cookie` or `bearer`)."""

        cookie = connection.cookies.get(self._cookie.name)
        if cookie:
            return cookie, "cookie"
        authorization = connection.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            return authorization[7:], "bearer"
        return None, None

    def get_principal(self, connection: HTTPConnection) -> SaasPrincipal | None:
        """Return the middleware-bound principal or validate a bare request once."""

        state = connection.scope.get("state")
        if isinstance(state, dict):
            principal = state.get("saas_principal")
            if isinstance(principal, SaasPrincipal):
                return principal
        token, _ = self.extract_token(connection)
        if token is None:
            return None
        try:
            session = self._lifecycle.validate_auth_session(token)
        except LifecycleError:
            return None
        return SaasPrincipal(session=session, runtime_context=None)

    def validate_token(self, token: str) -> ValidatedAuthSession:
        """Validate one opaque session token through the control plane."""

        return self._lifecycle.validate_auth_session(token)

    def validate_csrf(self, token: str, csrf_token: str) -> None:
        """Validate the browser's CSRF header for this session."""

        self._lifecycle.validate_csrf(token, csrf_token)

    def get_user_id(self, request: HTTPConnection) -> str | None:
        """Project Global User to the official runtime alias when context is bound."""

        principal = self.get_principal(request)
        if principal is None:
            return None
        if principal.runtime_context is not None:
            return principal.runtime_context.runtime_user_key
        return str(principal.session.user_id)

    def get_actor_id(self, request: HTTPConnection) -> UUID | None:
        principal = self.get_principal(request)
        return principal.session.user_id if principal else None


class SaasAuthContextMiddleware:
    """Authenticate once, enforce CSRF, and bind server-resolved Runtime Context."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        auth_provider: SaasAuthProvider,
        context_resolver: SqlAlchemyContextResolver,
        cookie_config: SaasCookieConfig,
        runtime_prefixes: tuple[str, ...] = ("/v1/",),
        runtime_exclusions: frozenset[str] = frozenset({"/v1/info", "/v1/me"}),
        public_paths: frozenset[str] = frozenset({"/saas/auth/login"}),
    ) -> None:
        self._app = app
        self._auth = auth_provider
        self._resolver = context_resolver
        self._cookie = cookie_config
        self._runtime_prefixes = runtime_prefixes
        self._runtime_exclusions = runtime_exclusions
        self._public_paths = public_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self._app(scope, receive, send)
            return
        connection = HTTPConnection(scope)
        token, token_source = self._auth.extract_token(connection)
        if connection.url.path in self._public_paths:
            await self._app(scope, receive, send)
            return
        if token is None:
            await self._app(scope, receive, send)
            return
        try:
            session = self._auth.validate_token(token)
            if token_source == "cookie":
                self._enforce_browser_request(connection, token, scope)
            runtime_context = self._resolve_runtime_context(connection, session)
        except (LifecycleError, ControlPlaneResolutionError, ValueError) as error:
            code = getattr(error, "code", "request_context_invalid")
            status = 401 if code in {"invalid_session", "csrf_invalid"} else 403
            await JSONResponse(
                status_code=status,
                content={"error": {"code": code, "message": str(error)}},
            )(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        state["saas_principal"] = SaasPrincipal(
            session=session,
            runtime_context=runtime_context,
        )
        if runtime_context is None:
            await self._app(scope, receive, send)
            return
        with bind_runtime_context(runtime_context):
            await self._app(scope, receive, send)

    def _enforce_browser_request(
        self, connection: HTTPConnection, token: str, scope: Scope
    ) -> None:
        method = cast(str, scope.get("method", "GET"))
        origin = connection.headers.get("origin")
        if scope["type"] == "websocket" or method in _UNSAFE_METHODS:
            if not origin or (
                not self._cookie.trusted_origins or origin not in self._cookie.trusted_origins
            ):
                raise LifecycleError("origin_forbidden", "browser request Origin is forbidden")
        if scope["type"] == "http" and method in _UNSAFE_METHODS:
            csrf_token = connection.headers.get("x-csrf-token", "")
            self._auth.validate_csrf(token, csrf_token)

    def _resolve_runtime_context(
        self, connection: HTTPConnection, session: ValidatedAuthSession
    ) -> RuntimeContext | None:
        path = connection.url.path
        if path in self._runtime_exclusions or not any(
            path.startswith(prefix) for prefix in self._runtime_prefixes
        ):
            return None
        tenant_raw = connection.headers.get("x-saas-tenant-id")
        space_raw = connection.headers.get("x-saas-space-id")
        if not tenant_raw or not space_raw:
            raise LifecycleError(
                "runtime_context_required", "Tenant and Space headers are required"
            )
        request_context = self._resolver.resolve_request_context(
            actor_id=session.user_id,
            tenant_id=UUID(tenant_raw),
            space_id=UUID(space_raw),
            trace_id=connection.headers.get("x-request-id") or uuid4().hex,
        )
        if request_context.user_security_version != session.security_version:
            raise LifecycleError(
                "authorization_snapshot_stale", "session security version is stale"
            )
        return self._resolver.resolve_space_allocation(request_context)


def create_saas_auth_router(
    *,
    auth_provider: SaasAuthProvider,
    lifecycle: MembershipLifecycleService,
    identities: IdentityManagementService,
    passwords: PasswordCredentialService,
    cookie_config: SaasCookieConfig,
    governance: MembershipGovernanceService | None = None,
) -> APIRouter:
    """Build login/logout/self-service identity routes for downstream app wiring."""

    router = APIRouter()

    @router.post("/auth/login")
    def login(body: LoginRequest, response: Response) -> dict[str, object]:
        try:
            user_id = passwords.authenticate(body.email, body.password)
            now = datetime.now(timezone.utc)
            issued = lifecycle.issue_auth_session(
                user_id=user_id,
                authn_method="password",
                expires_at=now + cookie_config.ttl,
                now=now,
            )
        except LifecycleError as error:
            raise _http_error(error, 401) from error
        response.set_cookie(
            key=cookie_config.name,
            value=issued.token,
            max_age=int(cookie_config.ttl.total_seconds()),
            path="/",
            secure=cookie_config.secure,
            httponly=True,
            samesite=cookie_config.same_site,
        )
        return {
            "user_id": str(user_id),
            "csrf_token": issued.csrf_token,
            "expires_at": issued.expires_at.isoformat(),
        }

    @router.post("/auth/logout", status_code=204)
    def logout(request: Request, response: Response) -> Response:
        token, _ = auth_provider.extract_token(request)
        if token:
            lifecycle.revoke_auth_session(token)
        _clear_cookie(response, cookie_config)
        response.status_code = 204
        return response

    @router.get("/auth/me")
    def me(request: Request) -> dict[str, object]:
        principal = _require_principal(auth_provider, request)
        return {
            "user_id": str(principal.session.user_id),
            "security_version": principal.session.security_version,
            "authn_method": principal.session.authn_method,
        }

    @router.get("/identities")
    def list_identities(request: Request) -> list[dict[str, object]]:
        principal = _require_principal(auth_provider, request)
        return [
            {
                "id": str(identity.id),
                "provider": identity.provider,
                "issuer": identity.issuer,
                "email_normalized": identity.email_normalized,
                "email_verified": identity.email_verified,
                "status": identity.status,
            }
            for identity in identities.list_identities(principal.session.user_id)
        ]

    @router.delete("/identities/{connection_id}", status_code=204)
    def revoke_identity(
        connection_id: UUID,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> Response:
        principal = _require_principal(auth_provider, request)
        try:
            identities.revoke_identity(
                user_id=principal.session.user_id,
                connection_id=connection_id,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, 409) from error
        _clear_cookie(response, cookie_config)
        response.status_code = 204
        return response

    @router.put("/password")
    def change_password(
        body: PasswordChangeRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        principal = _require_principal(auth_provider, request)
        try:
            changed = passwords.set_password(
                user_id=principal.session.user_id,
                new_password=body.new_password,
                current_password=body.current_password,
                expected_version=body.expected_version,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _http_error(error, 409) from error
        _clear_cookie(response, cookie_config)
        return {
            "password_version": changed.password_version,
            "security_version": changed.security_version,
            "reauthentication_required": True,
        }

    if governance is not None:

        @router.post("/tenants/{tenant_id}/ownership-transfers", status_code=201)
        def transfer_ownership(
            tenant_id: UUID,
            body: OwnershipTransferRequest,
            request: Request,
            response: Response,
            idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
        ) -> dict[str, object]:
            principal = _require_principal(auth_provider, request)
            try:
                transferred = governance.transfer_ownership(
                    actor_id=principal.session.user_id,
                    tenant_id=tenant_id,
                    space_id=body.space_id,
                    from_user_id=principal.session.user_id,
                    to_user_id=body.to_user_id,
                    source_expected_version=body.source_expected_version,
                    target_expected_version=body.target_expected_version,
                    reason=body.reason,
                    reauthenticated_at=principal.session.authenticated_at,
                    idempotency_key=idempotency_key,
                )
            except LifecycleError as error:
                raise _http_error(error, 409) from error
            _clear_cookie(response, cookie_config)
            return {
                "transfer_id": str(transferred.transfer_id),
                "scope": transferred.scope,
                "source_version": transferred.source_version,
                "target_version": transferred.target_version,
                "replayed": transferred.replayed,
                "reauthentication_required": True,
            }

        @router.post(
            "/tenants/{tenant_id}/members/{user_id}/removal-preflights",
            status_code=201,
        )
        def create_removal_preflight(
            tenant_id: UUID,
            user_id: UUID,
            body: RemovalPreflightRequest,
            request: Request,
            idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
        ) -> dict[str, object]:
            principal = _require_principal(auth_provider, request)
            try:
                preflight = governance.create_removal_preflight(
                    actor_id=principal.session.user_id,
                    tenant_id=tenant_id,
                    space_id=body.space_id,
                    user_id=user_id,
                    idempotency_key=idempotency_key,
                )
            except LifecycleError as error:
                raise _http_error(error, 409) from error
            return {
                "preflight_id": str(preflight.preflight_id),
                "status": preflight.status,
                "blocking_count": preflight.blocking_count,
                "snapshot_hash": preflight.snapshot_hash,
                "expires_at": preflight.expires_at.isoformat(),
                "replayed": preflight.replayed,
            }

        @router.post("/tenants/{tenant_id}/member-removal-preflights/{preflight_id}/execute")
        def execute_member_removal(
            tenant_id: UUID,
            preflight_id: UUID,
            body: RemovalExecutionRequest,
            request: Request,
            idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
        ) -> dict[str, object]:
            principal = _require_principal(auth_provider, request)
            try:
                removed = governance.execute_member_removal(
                    actor_id=principal.session.user_id,
                    tenant_id=tenant_id,
                    preflight_id=preflight_id,
                    reason=body.reason,
                    reauthenticated_at=principal.session.authenticated_at,
                    idempotency_key=idempotency_key,
                )
            except LifecycleError as error:
                raise _http_error(error, 409) from error
            return {
                "scope": removed.scope,
                "membership_version": removed.membership_version,
                "removed_space_memberships": removed.removed_space_memberships,
                "security_version": removed.security_version,
                "revoked_session_count": removed.revoked_session_count,
                "replayed": removed.replayed,
            }

    return router


def create_saas_http_integration(
    *,
    lifecycle: MembershipLifecycleService,
    identities: IdentityManagementService,
    passwords: PasswordCredentialService,
    context_resolver: SqlAlchemyContextResolver,
    cookie_config: SaasCookieConfig,
    governance: MembershipGovernanceService | None = None,
) -> SaasHttpIntegration:
    """Build the custom provider, official extra-router tuple, and middleware hook."""

    auth_provider = SaasAuthProvider(lifecycle, cookie_config)
    router = create_saas_auth_router(
        auth_provider=auth_provider,
        lifecycle=lifecycle,
        identities=identities,
        passwords=passwords,
        cookie_config=cookie_config,
        governance=governance,
    )
    return SaasHttpIntegration(
        auth_provider=auth_provider,
        router=router,
        context_resolver=context_resolver,
        cookie_config=cookie_config,
    )


def _clear_cookie(response: Response, cookie_config: SaasCookieConfig) -> None:
    response.delete_cookie(
        cookie_config.name,
        path="/",
        secure=cookie_config.secure,
        httponly=True,
        samesite=cookie_config.same_site,
    )


def _require_principal(auth_provider: SaasAuthProvider, request: Request) -> SaasPrincipal:
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise _http_error(LifecycleError("authentication_required", "login required"), 401)
    return principal


def _http_error(error: LifecycleError, status_code: int) -> Exception:
    from fastapi import HTTPException

    return HTTPException(
        status_code=status_code,
        detail={"code": error.code, "message": str(error)},
    )
