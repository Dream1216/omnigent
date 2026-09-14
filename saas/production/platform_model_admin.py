"""Single-Owner Beta bridge for configuring the Platform-managed model.

This is deliberately a separate process from the public Omnigent server.  It
accepts the existing Tenant browser cookie only for one allowlisted Global User
who remains an active Owner of one allowlisted Tenant, then projects that
identity onto one pre-provisioned Staff principal.  The bridge exposes only the
three model-provider operations and is not a replacement for the Staff IdP.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Literal
from uuid import UUID

import sqlalchemy as sa
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.client_network import TrustedClientNetworkConfig
from saas.control_plane.db_models import TenantMembership
from saas.control_plane.lifecycle import LifecycleError, MembershipLifecycleService
from saas.control_plane.model_provider import (
    ModelProviderConfigurationService,
    ModelProviderConfigurationUpdate,
    ModelProviderConfigurationView,
)
from saas.control_plane.permissions import POLICY_VERSION
from saas.control_plane.platform_models import PlatformStaffPrincipalRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.rls import (
    PlatformRlsContext,
    RlsContext,
    apply_platform_rls_context,
    apply_rls_context,
)
from saas.production.onboarding import build_production_secret_cipher
from saas.production.postgresql_migration import _inspect_service_login
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_database_url_file,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindingsError,
    load_platform_model_service_role_bindings,
)

_MODEL_PERMISSIONS = frozenset(
    {
        "platform.model_provider.read",
        "platform.model_provider.manage",
        "platform.model_provider.test",
    }
)
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_MAX_COMMAND_BYTES = 16 * 1024


class _ConfigurationCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_version: int = Field(ge=0)
    enabled: bool
    base_url: str = Field(min_length=1, max_length=512)
    api_type: Literal["openai_chat_completions"]
    api_key: SecretStr | None = Field(default=None, min_length=16, max_length=4096)
    allowed_models: tuple[str, ...] = Field(min_length=1, max_length=16)
    default_model: str = Field(min_length=1, max_length=128)
    monthly_budget_microusd: int = Field(ge=1, le=10**15)
    per_tenant_daily_token_limit: int = Field(ge=1, le=10**12)


class _TestCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_version: int = Field(ge=1)
    model: str | None = Field(default=None, min_length=1, max_length=128)


@dataclass(frozen=True, slots=True)
class SingleOwnerModelAdminConfig:
    """Exact Beta governance boundary; every identity is deployment-pinned."""

    origin: str
    tenant_id: UUID
    user_id: UUID
    platform_principal_id: UUID
    cookie_name: str = "__Host-omnigent_saas_session"

    def __post_init__(self) -> None:
        if (
            not self.origin.startswith("https://")
            or self.origin != self.origin.rstrip("/")
            or any(
                value.int == 0
                for value in (self.tenant_id, self.user_id, self.platform_principal_id)
            )
            or not self.cookie_name.startswith("__Host-")
        ):
            raise ValueError("Single-Owner model admin configuration is invalid")


class SingleOwnerModelAdminAuthenticator:
    """Continuously revalidate Tenant Owner and Staff projection authorities."""

    def __init__(
        self,
        *,
        config: SingleOwnerModelAdminConfig,
        sessions: MembershipLifecycleService,
        tenant_sessions: sessionmaker[Session],
        platform_sessions: sessionmaker[Session],
    ) -> None:
        self.config = config
        self._sessions = sessions
        self._tenant_sessions = tenant_sessions
        self._platform_sessions = platform_sessions

    def authenticate(self, request: Request) -> tuple[ValidatedPlatformPrincipal, str]:
        request_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
        supplied_origin = request.headers.get("origin")
        if request_origin != self.config.origin or (
            supplied_origin is not None and supplied_origin.rstrip("/") != self.config.origin
        ):
            raise PlatformSecurityError(
                "platform_realm_mismatch", "request reached the wrong model admin Origin"
            )
        if request.method in _UNSAFE_METHODS and supplied_origin is None:
            raise PlatformSecurityError(
                "platform_realm_mismatch", "unsafe model admin request requires an exact Origin"
            )
        if request.headers.get("authorization"):
            raise PlatformSecurityError(
                "platform_realm_mismatch", "model admin browser API does not accept bearer tokens"
            )
        token = request.cookies.get(self.config.cookie_name, "")
        try:
            session = self._sessions.validate_auth_session(token)
            if request.method in _UNSAFE_METHODS:
                self._sessions.validate_csrf(token, request.headers.get("x-csrf-token", ""))
        except LifecycleError as error:
            raise PlatformSecurityError(
                "platform_authentication_required", "Tenant authentication is required"
            ) from error
        if session.user_id != self.config.user_id:
            raise PlatformSecurityError(
                "platform_permission_denied", "Single-Owner Beta bridge access is denied"
            )
        with self._tenant_sessions.begin() as db:
            apply_rls_context(
                db,
                RlsContext(actor_id=session.user_id, tenant_id=self.config.tenant_id),
            )
            membership = db.get(
                TenantMembership,
                (self.config.tenant_id, session.user_id),
            )
            if membership is None or membership.status != "active" or membership.role != "owner":
                raise PlatformSecurityError(
                    "platform_permission_denied", "active Tenant Owner access is required"
                )
        with self._platform_sessions.begin() as db:
            apply_platform_rls_context(
                db,
                PlatformRlsContext(principal_id=self.config.platform_principal_id),
            )
            principal = db.get(PlatformStaffPrincipalRecord, self.config.platform_principal_id)
            if principal is None or principal.status != "active":
                raise PlatformSecurityError(
                    "platform_principal_inactive", "Beta bridge Staff projection is inactive"
                )
            security_version = principal.security_version
        return (
            ValidatedPlatformPrincipal(
                session_id=session.session_id,
                principal_id=self.config.platform_principal_id,
                security_version=security_version,
                authn_method=f"single_owner_beta_bridge:{session.authn_method}",
                authenticated_at=session.authenticated_at,
                expires_at=session.expires_at,
                roles=frozenset({"platform_operator"}),
                permissions=_MODEL_PERMISSIONS,
            ),
            token,
        )


def create_single_owner_model_admin_app(
    *,
    config: SingleOwnerModelAdminConfig,
    authenticator: SingleOwnerModelAdminAuthenticator,
    model_provider: ModelProviderConfigurationService,
) -> FastAPI:
    app = FastAPI(
        title="Omnigent Single-Owner Beta Model Admin",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "private, no-store"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Governance-Mode"] = "single-owner-beta-tenant-bridge"
        return response

    @app.exception_handler(PlatformSecurityError)
    async def platform_error(_request: Request, error: PlatformSecurityError):
        status = 403
        if error.code in {"platform_authentication_required", "platform_principal_inactive"}:
            status = 401
        elif error.code.endswith("_conflict"):
            status = 409
        elif error.code.endswith("_unavailable"):
            status = 503
        return JSONResponse(
            status_code=status,
            content={"error": {"code": error.code, "message": str(error)}},
        )

    @app.get("/saas/admin/platform-model-provider", include_in_schema=False)
    def console(request: Request) -> HTMLResponse:
        authenticator.authenticate(request)
        return HTMLResponse(
            files("saas.admin_ui")
            .joinpath("model_provider_admin.html")
            .read_text(encoding="utf-8")
        )

    @app.get("/saas/admin/assets/model-provider-admin.css", include_in_schema=False)
    def stylesheet(request: Request) -> Response:
        authenticator.authenticate(request)
        return _asset("model_provider_admin.css", "text/css")

    @app.get("/saas/admin/assets/model-provider-admin.js", include_in_schema=False)
    def javascript(request: Request) -> Response:
        authenticator.authenticate(request)
        return _asset("model_provider_admin.js", "text/javascript")

    @app.get("/saas/admin/platform-model-provider/context")
    def context(request: Request) -> dict[str, object]:
        actor, _ = authenticator.authenticate(request)
        return {
            "realm": "single_owner_beta_tenant_bridge",
            "policy_version": POLICY_VERSION,
            "tenant_id": str(config.tenant_id),
            "user_id": str(config.user_id),
            "platform_principal_id": str(actor.principal_id),
            "permissions": sorted(actor.permissions),
        }

    @app.get("/saas/admin/platform-model-provider/configuration")
    def get_configuration(request: Request) -> dict[str, object]:
        actor, _ = authenticator.authenticate(request)
        return _payload(model_provider.get(actor))

    @app.put("/saas/admin/platform-model-provider/configuration")
    async def put_configuration(request: Request) -> dict[str, object]:
        actor, _ = authenticator.authenticate(request)
        command = _parse(
            await request.body(), request.headers.get("content-type", ""), _ConfigurationCommand
        )
        assert isinstance(command, _ConfigurationCommand)
        return _payload(
            model_provider.update(
                actor,
                expected_version=command.expected_version,
                configuration=ModelProviderConfigurationUpdate(
                    enabled=command.enabled,
                    base_url=command.base_url,
                    api_type=command.api_type,
                    api_key=(command.api_key.get_secret_value() if command.api_key else None),
                    allowed_models=command.allowed_models,
                    default_model=command.default_model,
                    monthly_budget_microusd=command.monthly_budget_microusd,
                    per_tenant_daily_token_limit=command.per_tenant_daily_token_limit,
                ),
            )
        )

    @app.post("/saas/admin/platform-model-provider/test")
    async def test_configuration(request: Request) -> dict[str, object]:
        actor, _ = authenticator.authenticate(request)
        command = _parse(
            await request.body(), request.headers.get("content-type", ""), _TestCommand
        )
        assert isinstance(command, _TestCommand)
        return _payload(
            model_provider.verify(
                actor,
                expected_version=command.expected_version,
                model=command.model,
            )
        )

    return app


def build_single_owner_model_admin(
    environ: Mapping[str, str],
) -> tuple[FastAPI, tuple[Engine, Engine, Engine]]:
    """Compose exact authenticator, Tenant read, and Platform write authorities."""

    try:
        config = SingleOwnerModelAdminConfig(
            origin=_required(environ, "OMNIGENT_SAAS_PLATFORM_MODEL_ADMIN_ORIGIN"),
            tenant_id=UUID(_required(environ, "OMNIGENT_SAAS_PLATFORM_MODEL_ADMIN_TENANT_ID")),
            user_id=UUID(_required(environ, "OMNIGENT_SAAS_PLATFORM_MODEL_ADMIN_USER_ID")),
            platform_principal_id=UUID(
                _required(environ, "OMNIGENT_SAAS_PLATFORM_MODEL_ADMIN_PRINCIPAL_ID")
            ),
        )
        bindings = load_platform_model_service_role_bindings(environ)
        resolved = {
            role: load_production_database_url_file(environ, role)
            for role in ("authenticator", "app", "platform_app")
        }
    except (
        ValueError,
        ProductionServerConfigError,
        ProductionServiceRoleBindingsError,
    ):
        raise ValueError("Single-Owner model admin authority is invalid") from None
    engines: tuple[Engine, Engine, Engine] = (
        sa.create_engine(resolved["authenticator"][0], pool_pre_ping=True),
        sa.create_engine(resolved["app"][0], pool_pre_ping=True),
        sa.create_engine(resolved["platform_app"][0], pool_pre_ping=True),
    )
    try:
        for role, engine in zip(("authenticator", "app", "platform_app"), engines, strict=True):
            if resolved[role][1].username != bindings.login_for(role):
                raise ValueError("Single-Owner model admin authority is invalid")
            _inspect_service_login(
                engine,
                expected_login=bindings.login_for(role),
                expected_role=f"saas_{role}",
            )
        factories = tuple(
            sessionmaker(engine, expire_on_commit=False, class_=Session) for engine in engines
        )
        lifecycle = MembershipLifecycleService(factories[0])
        authorization = PlatformAuthorizationService(factories[2])
        cipher = build_production_secret_cipher(environ)
        if cipher is None:
            raise ValueError("Single-Owner model admin cipher is unavailable")
        provider = ModelProviderConfigurationService(
            factories[2],
            authorization=authorization,
            secret_cipher=cipher,
        )
        authenticator = SingleOwnerModelAdminAuthenticator(
            config=config,
            sessions=lifecycle,
            tenant_sessions=factories[1],
            platform_sessions=factories[2],
        )
        return (
            create_single_owner_model_admin_app(
                config=config,
                authenticator=authenticator,
                model_provider=provider,
            ),
            engines,
        )
    except Exception:
        for engine in engines:
            engine.dispose()
        raise


def main() -> None:
    import uvicorn

    app, _engines = build_single_owner_model_admin(os.environ)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8091,
        proxy_headers=True,
        forwarded_allow_ips=_trusted_proxy_cidrs(os.environ),
        server_header=False,
    )


def _trusted_proxy_cidrs(source: Mapping[str, str]) -> list[str]:
    """Return only canonical IP networks trusted to supply proxy headers."""

    raw = _required(source, "OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS")
    values = raw.split(",")
    if any(not value or value != value.strip() or value == "*" for value in values):
        raise ValueError("Single-Owner model admin trusted proxy CIDRs are invalid")
    try:
        networks = TrustedClientNetworkConfig(trusted_proxy_cidrs=tuple(values))
    except ValueError:
        raise ValueError("Single-Owner model admin trusted proxy CIDRs are invalid") from None
    if list(networks.trusted_proxy_cidrs) != values:
        raise ValueError("Single-Owner model admin trusted proxy CIDRs are invalid")
    return values


def _parse(raw: bytes, content_type: str, model: type[BaseModel]) -> BaseModel:
    if (
        content_type.partition(";")[0].strip().lower() != "application/json"
        or not raw
        or len(raw) > _MAX_COMMAND_BYTES
    ):
        raise PlatformSecurityError(
            "platform_model_provider_invalid", "Model Provider configuration is invalid"
        )
    try:
        return model.model_validate_json(raw)
    except ValidationError:
        raise PlatformSecurityError(
            "platform_model_provider_invalid", "Model Provider configuration is invalid"
        ) from None


def _payload(value: ModelProviderConfigurationView) -> dict[str, object]:
    return {
        "provider_id": value.provider_id,
        "configured": value.configured,
        "enabled": value.enabled,
        "state": value.state,
        "base_url": value.base_url,
        "api_type": value.api_type,
        "allowed_models": list(value.allowed_models),
        "default_model": value.default_model,
        "monthly_budget_microusd": value.monthly_budget_microusd,
        "per_tenant_daily_token_limit": value.per_tenant_daily_token_limit,
        "api_key_configured": value.api_key_configured,
        "verification_status": value.verification_status,
        "last_verified_model": value.last_verified_model,
        "last_verified_at": value.last_verified_at.isoformat() if value.last_verified_at else None,
        "version": value.version,
        "updated_at": value.updated_at.isoformat() if value.updated_at else None,
    }


def _asset(name: str, media_type: str) -> Response:
    return Response(
        files("saas.admin_ui").joinpath(name).read_bytes(),
        media_type=media_type,
        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"},
    )


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{name} is invalid")
    return value


if __name__ == "__main__":
    main()


__all__ = [
    "SingleOwnerModelAdminAuthenticator",
    "SingleOwnerModelAdminConfig",
    "build_single_owner_model_admin",
    "create_single_owner_model_admin_app",
]
