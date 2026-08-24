"""FastAPI/ASGI integration for revocable SaaS sessions and runtime context."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Literal, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as SqlAlchemyTimeoutError
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from omnigent.server.auth import AuthProvider
from saas.compatibility import RuntimeContext, bind_runtime_context
from saas.control_plane.api_credentials import (
    ApiCredentialError,
    ApiCredentialService,
    ValidatedApiCredential,
)
from saas.control_plane.context_snapshot import (
    ContextSnapshotError,
    ContextSnapshotService,
    ControlPlaneAvailabilityGate,
    ControlPlaneDependencyUnavailable,
    VerifiedContextSnapshot,
)
from saas.control_plane.governance import MembershipGovernanceService
from saas.control_plane.identity import IdentityManagementService, PasswordCredentialService
from saas.control_plane.lifecycle import (
    LifecycleError,
    MembershipLifecycleService,
    ValidatedAuthSession,
)
from saas.control_plane.oidc import OidcAuthorizationService
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver
from saas.public_api_contract import ApiVersionPolicy

if TYPE_CHECKING:
    from saas.control_plane.authorization import ProjectAuthorizer
    from saas.control_plane.billing import BillingControlPlane
    from saas.control_plane.bindings import RuntimeBindingService
    from saas.control_plane.enterprise_access import EnterpriseAccessService
    from saas.control_plane.enterprise_identity import EnterpriseScimService
    from saas.control_plane.member_admin import TenantMemberAdministrationService
    from saas.control_plane.notification_http import (
        ApprovalOperationsProtocol,
        NotificationOperationsProtocol,
    )
    from saas.control_plane.onboarding import SelfServiceOnboardingService
    from saas.control_plane.platform_governed_access import PlatformGovernedAccessService
    from saas.control_plane.projects import ProjectAdministrationService
    from saas.control_plane.public_api import PublicApiExecutionService

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_PUBLIC_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PUBLIC_VERSION_POLICY = ApiVersionPolicy()


@dataclass(frozen=True, slots=True)
class SaasCookieConfig:
    """Browser-session cookie and origin policy."""

    name: str = "__Host-omnigent_saas_session"
    secure: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"
    ttl: timedelta = timedelta(hours=8)
    trusted_origins: frozenset[str] = frozenset()
    oidc_transaction_name: str | None = None

    def __post_init__(self) -> None:
        if not self.name or self.ttl <= timedelta(0):
            raise ValueError("SaaS Cookie name and TTL must be valid")
        if self.name.startswith("__Host-") and not self.secure:
            raise ValueError("__Host- cookies require secure=True")
        if self.same_site == "none" and not self.secure:
            raise ValueError("SameSite=None cookies require secure=True")
        transaction_name = self.oidc_transaction_cookie_name
        if transaction_name == self.name:
            raise ValueError("OIDC transaction cookie must differ from the session cookie")
        if transaction_name.startswith("__Host-") and not self.secure:
            raise ValueError("__Host- cookies require secure=True")

    @property
    def oidc_transaction_cookie_name(self) -> str:
        """Return a distinct browser-binding cookie with matching prefix posture."""

        return self.oidc_transaction_name or f"{self.name}_oidc"


@dataclass(frozen=True, slots=True)
class SaasPrincipal:
    """Authenticated Global User and optional resolved runtime projection."""

    session: ValidatedAuthSession
    runtime_context: RuntimeContext | None


@dataclass(frozen=True, slots=True)
class SaasMachinePrincipal:
    """Authenticated non-interactive Service Account principal."""

    credential: ValidatedApiCredential


@dataclass(frozen=True, slots=True)
class SaasHttpIntegration:
    """Components passed through official `create_app` extension points."""

    auth_provider: SaasAuthProvider
    router: APIRouter
    context_resolver: SqlAlchemyContextResolver
    cookie_config: SaasCookieConfig
    context_snapshots: ContextSnapshotService | None = None
    availability_gate: ControlPlaneAvailabilityGate | None = None
    degraded_read_paths: frozenset[str] = frozenset()
    public_api_router: APIRouter | None = None

    @property
    def extra_router(self) -> tuple[APIRouter, str, list[str | Enum]]:
        """Official `create_app(extra_routers=...)` registration tuple."""

        return self.router, "/saas", ["saas"]

    @property
    def extra_routers(self) -> tuple[tuple[APIRouter, str, list[str | Enum]], ...]:
        """Return backward-compatible internal routes plus the stable public API."""

        routers = [self.extra_router]
        if self.public_api_router is not None:
            routers.append((self.public_api_router, "/api/v1", ["saas-public-v1"]))
        return tuple(routers)

    def install_middleware(self, app: FastAPI) -> None:
        """Install context binding after official `create_app` returns."""

        app.add_middleware(
            SaasAuthContextMiddleware,
            auth_provider=self.auth_provider,
            context_resolver=self.context_resolver,
            cookie_config=self.cookie_config,
            context_snapshots=self.context_snapshots,
            availability_gate=self.availability_gate,
            degraded_read_paths=self.degraded_read_paths,
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


class IdentityConflictResolutionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=1, max_length=1024)


class ContextSnapshotRequest(BaseModel):
    tenant_id: UUID
    space_id: UUID


class SaasAuthProvider(AuthProvider):
    """Official AuthProvider adapter backed by the revocable SaaS session table."""

    login_url = "/saas/login"

    def __init__(
        self,
        lifecycle: MembershipLifecycleService,
        cookie_config: SaasCookieConfig,
        api_credentials: ApiCredentialService | None = None,
    ) -> None:
        self._lifecycle = lifecycle
        self._cookie = cookie_config
        self._api_credentials = api_credentials

    def extract_token(self, connection: HTTPConnection) -> tuple[str | None, str | None]:
        """Return opaque token and source (`cookie` or `bearer`)."""

        cookie = connection.cookies.get(self._cookie.name)
        authorization = connection.headers.get("authorization", "")
        bearer = authorization[7:] if authorization.startswith("Bearer ") else None
        if cookie and bearer:
            return bearer, "ambiguous"
        if cookie:
            return cookie, "cookie"
        if bearer:
            return bearer, "bearer"
        return None, None

    def get_principal(self, connection: HTTPConnection) -> SaasPrincipal | None:
        """Return the middleware-bound principal or validate a bare request once."""

        state = connection.scope.get("state")
        if isinstance(state, dict):
            principal = state.get("saas_principal")
            if isinstance(principal, SaasPrincipal):
                return principal
        token, source = self.extract_token(connection)
        if token is None or source == "ambiguous":
            return None
        if self.is_machine_token(token):
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

    def is_machine_token(self, token: str) -> bool:
        """Return whether a token belongs to the distinct machine namespace."""

        return bool(
            self._api_credentials is not None and self._api_credentials.is_api_credential(token)
        )

    def validate_machine_token(
        self, token: str, *, source_ip: str | None
    ) -> ValidatedApiCredential:
        """Validate a machine bearer token without trusting forwarded IP headers."""

        if self._api_credentials is None:
            raise ApiCredentialError("invalid_api_credential", "API credential is invalid")
        return self._api_credentials.authenticate(token, source_ip=source_ip)

    def get_machine_principal(self, connection: HTTPConnection) -> SaasMachinePrincipal | None:
        """Return only middleware-validated Service Account state."""

        state = connection.scope.get("state")
        if isinstance(state, dict):
            principal = state.get("saas_machine_principal")
            if isinstance(principal, SaasMachinePrincipal):
                return principal
        return None

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
        context_snapshots: ContextSnapshotService | None = None,
        availability_gate: ControlPlaneAvailabilityGate | None = None,
        degraded_read_paths: frozenset[str] = frozenset(),
    ) -> None:
        self._app = app
        self._auth = auth_provider
        self._resolver = context_resolver
        self._cookie = cookie_config
        self._runtime_prefixes = runtime_prefixes
        self._runtime_exclusions = runtime_exclusions
        self._public_paths = public_paths
        self._context_snapshots = context_snapshots
        self._availability = availability_gate or ControlPlaneAvailabilityGate()
        self._degraded_read_paths = degraded_read_paths
        if degraded_read_paths and context_snapshots is None:
            raise ValueError("degraded read paths require a Context Snapshot service")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self._app(scope, receive, send)
            return
        connection = HTTPConnection(scope)
        token, token_source = self._auth.extract_token(connection)
        if self._is_public_request(connection.url.path, cast(str, scope.get("method", "GET"))):
            try:
                self._enforce_public_browser_origin(connection, scope)
                self._availability.require_available()
                await self._app(scope, receive, send)
            except LifecycleError as error:
                await self._reject(scope, receive, send, status=403, error=error)
            except (ControlPlaneDependencyUnavailable, OperationalError, SqlAlchemyTimeoutError):
                await self._reject_dependency(scope, receive, send)
            return
        if token is None:
            await self._app(scope, receive, send)
            return
        if token_source == "ambiguous":
            await self._reject(
                scope,
                receive,
                send,
                status=400,
                error=LifecycleError(
                    "ambiguous_authentication",
                    "send either a session Cookie or Authorization Bearer token, not both",
                ),
            )
            return
        if token_source == "bearer" and self._auth.is_machine_token(token):
            await self._authenticate_machine(connection, token, scope, receive, send)
            return
        try:
            self._availability.require_available()
            session = self._auth.validate_token(token)
            if token_source == "cookie":
                self._enforce_browser_request(connection, token, scope)
            runtime_context = self._resolve_runtime_context(connection, token, session)
        except (ControlPlaneDependencyUnavailable, OperationalError, SqlAlchemyTimeoutError):
            await self._degraded_or_reject(
                connection=connection,
                token=token,
                scope=scope,
                receive=receive,
                send=send,
            )
            return
        except (
            LifecycleError,
            ControlPlaneResolutionError,
            ContextSnapshotError,
            ValueError,
        ) as error:
            code = getattr(error, "code", "request_context_invalid")
            status = 401 if code in {"invalid_session", "csrf_invalid"} else 403
            await self._reject(scope, receive, send, status=status, error=error)
            return

        state = scope.setdefault("state", {})
        state["saas_principal"] = SaasPrincipal(
            session=session,
            runtime_context=runtime_context,
        )
        if runtime_context is None:
            response_started = False

            async def guarded_send(message: Message) -> None:
                nonlocal response_started
                if message.get("type") == "http.response.start":
                    response_started = True
                await send(message)

            try:
                await self._app(scope, receive, guarded_send)
            except (
                ControlPlaneDependencyUnavailable,
                OperationalError,
                SqlAlchemyTimeoutError,
            ):
                if response_started:
                    raise
                await self._reject_dependency(scope, receive, send)
            return
        with bind_runtime_context(runtime_context):
            await self._app(scope, receive, send)

    async def _authenticate_machine(
        self,
        connection: HTTPConnection,
        token: str,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Authenticate Service Accounts only on the stable external API surface."""

        if scope["type"] != "http" or not connection.url.path.startswith("/api/v1/"):
            await self._reject(
                scope,
                receive,
                send,
                status=403,
                error=ApiCredentialError(
                    "machine_token_route_forbidden",
                    "Service Account credentials are accepted only by /api/v1",
                ),
            )
            return
        try:
            self._availability.require_available()
            source_ip = connection.client.host if connection.client is not None else None
            credential = self._auth.validate_machine_token(token, source_ip=source_ip)
        except (ControlPlaneDependencyUnavailable, OperationalError, SqlAlchemyTimeoutError):
            await self._reject_dependency(scope, receive, send)
            return
        except (ApiCredentialError, ValueError) as error:
            status = 401 if getattr(error, "code", "") == "invalid_api_credential" else 403
            await self._reject(scope, receive, send, status=status, error=error)
            return
        state = scope.setdefault("state", {})
        state["saas_machine_principal"] = SaasMachinePrincipal(credential=credential)
        state["saas_actor_kind"] = "service_account"
        await self._app(scope, receive, send)

    async def _degraded_or_reject(
        self,
        *,
        connection: HTTPConnection,
        token: str,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        path = connection.url.path
        method = cast(str, scope.get("method", "GET"))
        if (
            scope["type"] != "http"
            or method not in {"GET", "HEAD"}
            or path not in self._degraded_read_paths
            or not self._is_runtime_path(path)
            or self._context_snapshots is None
        ):
            await self._reject_dependency(scope, receive, send)
            return
        snapshot_token = connection.headers.get("x-saas-context-snapshot", "")
        try:
            verified = self._context_snapshots.verify(token=snapshot_token, auth_token=token)
            self._validate_selector_headers(connection, verified.runtime_context)
        except (ContextSnapshotError, ValueError):
            await self._reject_dependency(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        state["saas_principal"] = SaasPrincipal(
            session=verified.session,
            runtime_context=verified.runtime_context,
        )
        state["saas_degraded_authorization"] = True
        state["saas_context_snapshot_id"] = verified.snapshot_id

        async def degraded_send(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers = list(cast(list[tuple[bytes, bytes]], message.get("headers", [])))
                headers.append((b"x-saas-degraded-authorization", b"snapshot"))
                headers.append((b"cache-control", b"private, no-store"))
                message["headers"] = headers
            await send(message)

        with bind_runtime_context(verified.runtime_context):
            await self._app(scope, receive, degraded_send)

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

    def _enforce_public_browser_origin(self, connection: HTTPConnection, scope: Scope) -> None:
        """Reject cross-site browser login while preserving non-browser API clients."""

        method = cast(str, scope.get("method", "GET"))
        origin = connection.headers.get("origin")
        if method not in _UNSAFE_METHODS or origin is None:
            return
        if not self._cookie.trusted_origins or origin not in self._cookie.trusted_origins:
            raise LifecycleError("origin_forbidden", "browser request Origin is forbidden")

    def _is_public_request(self, path: str, method: str) -> bool:
        if path in self._public_paths:
            return True
        if method == "POST":
            if path == "/saas/onboarding/registrations":
                return True
            onboarding_parts = path.split("/")
            if (
                len(onboarding_parts) == 6
                and onboarding_parts[1:4] == ["saas", "onboarding", "registrations"]
                and bool(onboarding_parts[4])
                and onboarding_parts[5] in {"resend", "verify"}
            ):
                return True
        scim_resources = (
            "/saas/scim/v2/Users",
            "/saas/scim/v2/Groups",
            "/saas/scim/v2/Bulk",
            "/saas/scim/v2/ResourceTypes",
            "/saas/scim/v2/Schemas",
        )
        if path == "/saas/scim/v2/ServiceProviderConfig" or any(
            path == resource or path.startswith(f"{resource}/") for resource in scim_resources
        ):
            return True
        parts = path.split("/")
        return (
            method == "GET"
            and len(parts) == 6
            and parts[1:4] == ["saas", "auth", "oidc"]
            and bool(parts[4])
            and parts[5] in {"start", "callback"}
        )

    def _resolve_runtime_context(
        self,
        connection: HTTPConnection,
        token: str,
        session: ValidatedAuthSession,
    ) -> RuntimeContext | None:
        path = connection.url.path
        if not self._is_runtime_path(path):
            return None
        tenant_raw = connection.headers.get("x-saas-tenant-id")
        space_raw = connection.headers.get("x-saas-space-id")
        verified: VerifiedContextSnapshot | None = None
        snapshot_token = connection.headers.get("x-saas-context-snapshot")
        if snapshot_token:
            if self._context_snapshots is None:
                raise LifecycleError(
                    "context_snapshot_unsupported", "context snapshots are not configured"
                )
            verified = self._context_snapshots.verify(token=snapshot_token, auth_token=token)
            self._validate_live_snapshot_session(verified, session)
            self._validate_selector_headers(connection, verified.runtime_context)
            tenant_id = verified.runtime_context.tenant_id
            space_id = verified.runtime_context.space_id
        elif tenant_raw and space_raw:
            tenant_id = UUID(tenant_raw)
            space_id = UUID(space_raw)
        else:
            raise LifecycleError(
                "runtime_context_required",
                "a Context Snapshot or Tenant and Space selectors are required",
            )
        request_context = self._resolver.resolve_request_context(
            actor_id=session.user_id,
            tenant_id=tenant_id,
            space_id=space_id,
            trace_id=connection.headers.get("x-request-id") or uuid4().hex,
        )
        if request_context.user_security_version != session.security_version:
            raise LifecycleError(
                "authorization_snapshot_stale", "session security version is stale"
            )
        runtime_context = self._resolver.resolve_space_allocation(request_context)
        if verified is not None:
            self._validate_live_snapshot_runtime(verified.runtime_context, runtime_context)
        return runtime_context

    def _is_runtime_path(self, path: str) -> bool:
        return path not in self._runtime_exclusions and any(
            path.startswith(prefix) for prefix in self._runtime_prefixes
        )

    @staticmethod
    def _validate_live_snapshot_session(
        verified: VerifiedContextSnapshot,
        session: ValidatedAuthSession,
    ) -> None:
        snapshot_session = verified.session
        if (
            snapshot_session.session_id != session.session_id
            or snapshot_session.user_id != session.user_id
            or snapshot_session.security_version != session.security_version
        ):
            raise LifecycleError(
                "authorization_snapshot_stale", "snapshot session facts are stale"
            )

    @staticmethod
    def _validate_live_snapshot_runtime(
        snapshot: RuntimeContext,
        current: RuntimeContext,
    ) -> None:
        fields = (
            "actor_id",
            "tenant_id",
            "space_id",
            "project_id",
            "user_security_version",
            "tenant_membership_version",
            "space_membership_version",
            "runtime_partition_id",
            "placement_id",
            "placement_generation",
            "binding_generation",
            "data_region",
            "physical_workspace_id",
            "runtime_user_key",
            "runtime_type",
            "source_revision",
            "adapter_contract_version",
        )
        if any(getattr(snapshot, field) != getattr(current, field) for field in fields):
            raise LifecycleError(
                "authorization_snapshot_stale",
                "membership, policy, placement, or binding facts changed",
            )

    @staticmethod
    def _validate_selector_headers(
        connection: HTTPConnection,
        runtime_context: RuntimeContext,
    ) -> None:
        expected = {
            "x-saas-tenant-id": runtime_context.tenant_id,
            "x-saas-space-id": runtime_context.space_id,
        }
        for header, expected_id in expected.items():
            supplied = connection.headers.get(header)
            if supplied is not None and UUID(supplied) != expected_id:
                raise LifecycleError(
                    "context_selector_conflict", "selector conflicts with signed context"
                )

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status: int,
        error: object,
    ) -> None:
        code = str(getattr(error, "code", "request_context_invalid"))
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008, "reason": code})
            return
        path = str(scope.get("path", ""))
        public_api = path == "/api/v1" or path.startswith("/api/v1/")
        if public_api:
            connection = HTTPConnection(scope)
            supplied = connection.headers.get("x-request-id", "")
            request_id = (
                supplied if _PUBLIC_REQUEST_ID_PATTERN.fullmatch(supplied) else str(uuid4())
            )
            await JSONResponse(
                status_code=status,
                content={
                    "error": {
                        "code": code,
                        "message": str(error),
                        "request_id": request_id,
                        "details": {},
                    }
                },
                headers={
                    "Cache-Control": "no-store",
                    "X-Request-Id": request_id,
                    **_PUBLIC_VERSION_POLICY.headers(),
                },
            )(scope, receive, send)
            return
        await JSONResponse(
            status_code=status,
            content={"error": {"code": code, "message": str(error)}},
            headers={"Cache-Control": "no-store"},
        )(scope, receive, send)

    @classmethod
    async def _reject_dependency(cls, scope: Scope, receive: Receive, send: Send) -> None:
        await cls._reject(
            scope,
            receive,
            send,
            status=503,
            error=ControlPlaneDependencyUnavailable("control plane is unavailable"),
        )


def create_saas_auth_router(
    *,
    auth_provider: SaasAuthProvider,
    lifecycle: MembershipLifecycleService,
    identities: IdentityManagementService,
    passwords: PasswordCredentialService,
    context_resolver: SqlAlchemyContextResolver,
    cookie_config: SaasCookieConfig,
    governance: MembershipGovernanceService | None = None,
    oidc: OidcAuthorizationService | None = None,
    context_snapshots: ContextSnapshotService | None = None,
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
        _set_session_cookie(response, cookie_config, issued.token)
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

    @router.get("/auth/status")
    def auth_status(request: Request) -> dict[str, object]:
        """Return a non-error browser bootstrap result without exposing session facts."""

        principal = auth_provider.get_principal(request)
        if principal is None:
            return {"authenticated": False, "user_id": None}
        return {
            "authenticated": True,
            "user_id": str(principal.session.user_id),
        }

    @router.get("/context/scopes")
    def list_context_scopes(
        request: Request,
        response: Response,
    ) -> list[dict[str, object]]:
        principal = _require_principal(auth_provider, request)
        response.headers["Cache-Control"] = "private, no-store"
        try:
            scopes = context_resolver.list_available_scopes(actor_id=principal.session.user_id)
        except ControlPlaneResolutionError as error:
            raise _control_plane_http_error(error, 403) from error
        return [
            {
                "tenant_id": str(scope.tenant_id),
                "tenant_slug": scope.tenant_slug,
                "tenant_name": scope.tenant_name,
                "tenant_role": scope.tenant_role,
                "tenant_membership_version": scope.tenant_membership_version,
                "space_id": str(scope.space_id),
                "space_slug": scope.space_slug,
                "space_name": scope.space_name,
                "space_role": scope.space_role,
                "space_membership_version": scope.space_membership_version,
                "user_security_version": scope.user_security_version,
            }
            for scope in scopes
        ]

    if context_snapshots is not None:

        @router.post("/context/snapshots", status_code=201)
        def issue_context_snapshot(
            body: ContextSnapshotRequest,
            request: Request,
            response: Response,
        ) -> dict[str, object]:
            principal = _require_principal(auth_provider, request)
            response.headers["Cache-Control"] = "private, no-store"
            auth_token, _source = auth_provider.extract_token(request)
            if auth_token is None:
                raise _http_error(LifecycleError("authentication_required", "login required"), 401)
            try:
                request_context = context_resolver.resolve_request_context(
                    actor_id=principal.session.user_id,
                    tenant_id=body.tenant_id,
                    space_id=body.space_id,
                    trace_id=request.headers.get("x-request-id") or uuid4().hex,
                )
                if request_context.user_security_version != principal.session.security_version:
                    raise LifecycleError(
                        "authorization_snapshot_stale", "session security version is stale"
                    )
                runtime_context = context_resolver.resolve_space_allocation(request_context)
                issued = context_snapshots.issue(
                    auth_token=auth_token,
                    session=principal.session,
                    runtime_context=runtime_context,
                )
            except ControlPlaneResolutionError as error:
                raise _control_plane_http_error(error, 403) from error
            except (LifecycleError, ContextSnapshotError) as error:
                raise _http_error(error, 403) from error
            return {
                "context_snapshot": issued.token,
                "tenant_id": issued.tenant_id,
                "space_id": issued.space_id,
                "issued_at": issued.issued_at.isoformat(),
                "expires_at": issued.expires_at.isoformat(),
                "max_age_seconds": int((issued.expires_at - issued.issued_at).total_seconds()),
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

    if oidc is not None:

        @router.get("/auth/oidc/{provider}/start")
        def start_oidc_login(provider: str) -> Response:
            try:
                started = oidc.begin(provider)
            except LifecycleError as error:
                raise _http_error(error, 400) from error
            response = RedirectResponse(started.authorization_url, status_code=302)
            _set_oidc_transaction_cookie(
                response,
                cookie_config,
                started.browser_binding,
                started.expires_at,
            )
            return response

        @router.post("/auth/oidc/{provider}/link/start")
        def start_oidc_link(provider: str, request: Request) -> Response:
            principal = _require_principal(auth_provider, request)
            try:
                started = oidc.begin(
                    provider,
                    purpose="link",
                    target_session=principal.session,
                )
            except LifecycleError as error:
                raise _http_error(error, 409) from error
            response = RedirectResponse(started.authorization_url, status_code=303)
            _set_oidc_transaction_cookie(
                response,
                cookie_config,
                started.browser_binding,
                started.expires_at,
            )
            return response

        @router.get("/auth/oidc/{provider}/callback")
        async def complete_oidc(
            provider: str,
            request: Request,
            code: str | None = None,
            state: str = "",
            error: str | None = None,
        ) -> Response:
            browser_binding = request.cookies.get(cookie_config.oidc_transaction_cookie_name, "")
            try:
                if error is not None:
                    oidc.abort(
                        provider,
                        state=state,
                        browser_binding=browser_binding,
                    )
                    raise LifecycleError(
                        "oidc_authorization_declined", "OIDC authorization was declined"
                    )
                completed = await oidc.complete(
                    provider,
                    code=code or "",
                    state=state,
                    browser_binding=browser_binding,
                )
            except LifecycleError as lifecycle_error:
                response = JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "code": lifecycle_error.code,
                            "message": str(lifecycle_error),
                        }
                    },
                )
                _clear_oidc_transaction_cookie(response, cookie_config)
                return response

            if completed.conflict_id is not None:
                response = JSONResponse(
                    status_code=409,
                    content={
                        "error": {
                            "code": "identity_confirmation_required",
                            "message": "explicit account confirmation is required",
                        },
                        "identity_conflict_id": str(completed.conflict_id),
                    },
                )
                _clear_oidc_transaction_cookie(response, cookie_config)
                return response

            user_id = cast(UUID, completed.user_id)
            issued_at = datetime.now(timezone.utc)
            issued = lifecycle.issue_auth_session(
                user_id=user_id,
                authn_method=f"oidc:{provider}",
                expires_at=issued_at + cookie_config.ttl,
                now=issued_at,
            )
            response = JSONResponse(
                status_code=200,
                content={
                    "user_id": str(user_id),
                    "csrf_token": issued.csrf_token,
                    "expires_at": issued.expires_at.isoformat(),
                    "purpose": completed.purpose,
                },
            )
            _set_session_cookie(response, cookie_config, issued.token)
            _clear_oidc_transaction_cookie(response, cookie_config)
            return response

        @router.post("/auth/identity-conflicts/{conflict_id}")
        def resolve_identity_conflict(
            conflict_id: UUID,
            body: IdentityConflictResolutionRequest,
            request: Request,
            response: Response,
            idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
        ) -> dict[str, object]:
            principal = _require_principal(auth_provider, request)
            try:
                resolved = identities.resolve_identity_conflict(
                    user_id=principal.session.user_id,
                    conflict_id=conflict_id,
                    decision=body.decision,
                    reason=body.reason,
                    reauthenticated_at=principal.session.authenticated_at,
                    idempotency_key=idempotency_key,
                    expected_security_version=principal.session.security_version,
                )
            except LifecycleError as lifecycle_error:
                raise _http_error(lifecycle_error, 409) from lifecycle_error
            _clear_cookie(response, cookie_config)
            return {
                "identity_conflict_id": str(resolved.conflict_id),
                "decision": resolved.decision,
                "identity_connection_id": (
                    str(resolved.identity_connection_id)
                    if resolved.identity_connection_id is not None
                    else None
                ),
                "replayed": resolved.replayed,
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
                "revoked_project_memberships": removed.revoked_project_memberships,
                "revoked_resource_grants": removed.revoked_resource_grants,
                "changed_project_authorizations": removed.changed_project_authorizations,
                "revoked_group_memberships": removed.revoked_group_memberships,
                "changed_group_project_authorizations": (
                    removed.changed_group_project_authorizations
                ),
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
    project_admin: ProjectAdministrationService | None = None,
    project_authorizer: ProjectAuthorizer | None = None,
    runtime_bindings: RuntimeBindingService | None = None,
    oidc: OidcAuthorizationService | None = None,
    context_snapshots: ContextSnapshotService | None = None,
    availability_gate: ControlPlaneAvailabilityGate | None = None,
    degraded_read_paths: frozenset[str] = frozenset(),
    api_credentials: ApiCredentialService | None = None,
    public_api_execution: PublicApiExecutionService | None = None,
    enterprise_access: EnterpriseAccessService | None = None,
    enterprise_scim: EnterpriseScimService | None = None,
    member_admin: TenantMemberAdministrationService | None = None,
    member_lifecycle: MembershipLifecycleService | None = None,
    billing: BillingControlPlane | None = None,
    platform_support_access: PlatformGovernedAccessService | None = None,
    approval_operations: ApprovalOperationsProtocol | None = None,
    notification_operations: NotificationOperationsProtocol | None = None,
    notification_origin: str | None = None,
    onboarding: SelfServiceOnboardingService | None = None,
) -> SaasHttpIntegration:
    """Build the custom provider, official extra-router tuple, and middleware hook."""

    auth_provider = SaasAuthProvider(lifecycle, cookie_config, api_credentials)
    router = create_saas_auth_router(
        auth_provider=auth_provider,
        lifecycle=lifecycle,
        identities=identities,
        passwords=passwords,
        context_resolver=context_resolver,
        cookie_config=cookie_config,
        governance=governance,
        oidc=oidc,
        context_snapshots=context_snapshots,
    )
    if onboarding is not None:
        from saas.control_plane.onboarding_http import create_onboarding_router

        router.include_router(create_onboarding_router(onboarding=onboarding))
    if (project_admin is None) != (project_authorizer is None):
        raise ValueError("Project Admin service and Authorizer must be configured together")
    if project_admin is not None and project_authorizer is not None:
        from saas.control_plane.project_http import create_project_admin_router

        router.include_router(
            create_project_admin_router(
                auth_provider=auth_provider,
                resolver=context_resolver,
                projects=project_admin,
                authorizer=project_authorizer,
                bindings=runtime_bindings,
            )
        )
    if enterprise_access is not None:
        from saas.control_plane.enterprise_http import create_enterprise_admin_router

        router.include_router(
            create_enterprise_admin_router(
                auth_provider=auth_provider,
                resolver=context_resolver,
                enterprise_access=enterprise_access,
            )
        )
    if enterprise_scim is not None:
        from saas.control_plane.enterprise_scim_http import create_enterprise_scim_router

        router.include_router(
            create_enterprise_scim_router(
                auth_provider=auth_provider,
                resolver=context_resolver,
                service=enterprise_scim,
            )
        )
    if (member_admin is None) != (member_lifecycle is None):
        raise ValueError("Tenant Member Admin and Member Lifecycle must be configured together")
    if member_admin is not None and member_lifecycle is not None:
        from saas.control_plane.member_http import create_member_admin_router

        router.include_router(
            create_member_admin_router(
                auth_provider=auth_provider,
                lifecycle=member_lifecycle,
                members=member_admin,
                invitation_acceptance=lifecycle,
            )
        )
    if billing is not None:
        from saas.control_plane.billing_http import create_billing_admin_router

        router.include_router(
            create_billing_admin_router(auth_provider=auth_provider, billing=billing)
        )
    if platform_support_access is not None:
        from saas.control_plane.platform_support_http import create_tenant_support_access_router

        router.include_router(
            create_tenant_support_access_router(
                auth_provider=auth_provider,
                governed_access=platform_support_access,
            )
        )
    notification_dependencies = (
        approval_operations,
        notification_operations,
        notification_origin,
    )
    if any(value is not None for value in notification_dependencies) and not all(
        value is not None for value in notification_dependencies
    ):
        raise ValueError(
            "Approval operations, notification operations, and notification Origin "
            "must be configured together"
        )
    if (
        approval_operations is not None
        and notification_operations is not None
        and notification_origin is not None
    ):
        from saas.control_plane.notification_http import (
            TenantNotificationHttpConfig,
            create_notification_router,
        )

        router.include_router(
            create_notification_router(
                config=TenantNotificationHttpConfig(origin=notification_origin),
                auth_provider=auth_provider,
                approvals=approval_operations,
                notifications=notification_operations,
            )
        )
    else:

        @router.get("/tenants/{tenant_id}/notification-operations/capabilities")
        def disabled_notification_capabilities(
            tenant_id: UUID, request: Request, response: Response
        ) -> dict[str, object]:
            """Expose a stable, authenticated capability probe when operations are unwired."""

            _ = tenant_id
            _require_principal(auth_provider, request)
            response.headers["Cache-Control"] = "private, no-store"
            return {
                "notification_operations_enabled": False,
                "template_management": "unavailable",
                "content_access": "none",
            }

    public_api_router = None
    if public_api_execution is not None and api_credentials is None:
        raise ValueError("Public API execution requires API credentials")
    if api_credentials is not None:
        from saas.control_plane.api_http import (
            create_api_credential_management_router,
            create_public_api_router,
        )

        router.include_router(
            create_api_credential_management_router(
                auth_provider=auth_provider,
                api_credentials=api_credentials,
            ),
            prefix="/api-credentials",
        )
        if public_api_execution is not None:
            public_api_router = create_public_api_router(
                auth_provider=auth_provider,
                public_execution=public_api_execution,
            )
    return SaasHttpIntegration(
        auth_provider=auth_provider,
        router=router,
        context_resolver=context_resolver,
        cookie_config=cookie_config,
        context_snapshots=context_snapshots,
        availability_gate=availability_gate,
        degraded_read_paths=degraded_read_paths,
        public_api_router=public_api_router,
    )


def _clear_cookie(response: Response, cookie_config: SaasCookieConfig) -> None:
    response.delete_cookie(
        cookie_config.name,
        path="/",
        secure=cookie_config.secure,
        httponly=True,
        samesite=cookie_config.same_site,
    )


def _set_session_cookie(response: Response, cookie_config: SaasCookieConfig, token: str) -> None:
    response.set_cookie(
        key=cookie_config.name,
        value=token,
        max_age=int(cookie_config.ttl.total_seconds()),
        path="/",
        secure=cookie_config.secure,
        httponly=True,
        samesite=cookie_config.same_site,
    )


def _set_oidc_transaction_cookie(
    response: Response,
    cookie_config: SaasCookieConfig,
    browser_binding: str,
    expires_at: datetime,
) -> None:
    max_age = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
    response.set_cookie(
        key=cookie_config.oidc_transaction_cookie_name,
        value=browser_binding,
        max_age=max_age,
        path="/",
        secure=cookie_config.secure,
        httponly=True,
        samesite="lax",
    )


def _clear_oidc_transaction_cookie(response: Response, cookie_config: SaasCookieConfig) -> None:
    response.delete_cookie(
        cookie_config.oidc_transaction_cookie_name,
        path="/",
        secure=cookie_config.secure,
        httponly=True,
        samesite="lax",
    )


def _require_principal(auth_provider: SaasAuthProvider, request: Request) -> SaasPrincipal:
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise _http_error(LifecycleError("authentication_required", "login required"), 401)
    return principal


def _http_error(error: object, status_code: int) -> Exception:
    from fastapi import HTTPException

    return HTTPException(
        status_code=status_code,
        detail={
            "code": str(getattr(error, "code", "request_invalid")),
            "message": str(error),
        },
    )


def _control_plane_http_error(error: ControlPlaneResolutionError, status_code: int) -> Exception:
    return _http_error(error, status_code)
