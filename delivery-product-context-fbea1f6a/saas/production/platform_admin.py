"""Production composition for the independent local-password Staff Realm."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from urllib.parse import urlsplit
from uuid import UUID

import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from saas.control_plane.client_network import TrustedClientNetworkConfig
from saas.control_plane.platform_http import PlatformHttpConfig, create_platform_admin_app
from saas.control_plane.platform_password_auth import PlatformPasswordAuthenticationService
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSessionService,
)
from saas.production.postgresql_migration import PostgreSqlMigrationError, _inspect_service_login
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_database_url_file,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindings,
    ProductionServiceRoleBindingsError,
    load_platform_admin_service_role_bindings,
)

_AUDIENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_WEB_SERVICES = ("platform_authenticator", "platform_app")


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{name} is invalid")
    return value


def _origin(source: Mapping[str, str]) -> str:
    value = _required(source, "OMNIGENT_SAAS_PLATFORM_ADMIN_ORIGIN")
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ValueError("Platform Admin Origin is invalid") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != f"https://{parsed.netloc}"
    ):
        raise ValueError("Platform Admin Origin is invalid")
    return value


def _config(source: Mapping[str, str]) -> PlatformHttpConfig:
    if _required(source, "OMNIGENT_SAAS_PLATFORM_ADMIN_ENABLED") != "true":
        raise ValueError("Platform Admin must be explicitly enabled")
    audience = _required(source, "OMNIGENT_SAAS_PLATFORM_ADMIN_AUDIENCE")
    if _AUDIENCE.fullmatch(audience) is None:
        raise ValueError("Platform Admin Audience is invalid")
    return PlatformHttpConfig(enabled=True, origin=_origin(source), audience=audience)


def _trusted_proxy_cidrs(source: Mapping[str, str]) -> list[str]:
    raw = _required(source, "OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS")
    values = raw.split(",")
    if any(not value or value != value.strip() or value == "*" for value in values):
        raise ValueError("Platform Admin trusted proxy CIDRs are invalid")
    try:
        networks = TrustedClientNetworkConfig(trusted_proxy_cidrs=tuple(values))
    except ValueError:
        raise ValueError("Platform Admin trusted proxy CIDRs are invalid") from None
    if list(networks.trusted_proxy_cidrs) != values:
        raise ValueError("Platform Admin trusted proxy CIDRs are invalid")
    return values


def _engines(
    source: Mapping[str, str], services: tuple[str, ...]
) -> tuple[tuple[Engine, ...], ProductionServiceRoleBindings]:
    bindings = load_platform_admin_service_role_bindings(source)
    resolved = {
        service: load_production_database_url_file(source, service) for service in services
    }
    urls = [resolved[service][0] for service in services]
    paths = [resolved[service][2] for service in services]
    if len(set(urls)) != len(urls) or len(set(paths)) != len(paths):
        raise ValueError("Platform Admin database authorities must be distinct")
    endpoints = {
        (
            resolved[service][1].host,
            resolved[service][1].port or 5432,
            resolved[service][1].database,
        )
        for service in services
    }
    if len(endpoints) != 1:
        raise ValueError("Platform Admin database authorities must target one database")
    engines = tuple(sa.create_engine(url, pool_pre_ping=True, poolclass=NullPool) for url in urls)
    try:
        for service, engine in zip(services, engines, strict=True):
            binding = bindings.by_service[service]
            if resolved[service][1].username != binding.login:
                raise ValueError("Platform Admin database authority is invalid")
            _inspect_service_login(
                engine,
                expected_login=binding.login,
                expected_role=binding.base_role,
            )
    except Exception:
        for engine in engines:
            engine.dispose()
        raise
    return engines, bindings


def build_platform_admin(
    environ: Mapping[str, str],
) -> tuple[FastAPI, tuple[Engine, Engine]]:
    """Compose only the authenticator and read-only Platform application roles."""

    try:
        config = _config(environ)
        raw_engines, bindings = _engines(environ, _WEB_SERVICES)
    except (
        KeyError,
        ValueError,
        ProductionServerConfigError,
        ProductionServiceRoleBindingsError,
        PostgreSqlMigrationError,
    ):
        raise ValueError("Platform Admin production authority is invalid") from None
    engines = (raw_engines[0], raw_engines[1])
    try:
        authenticator = sessionmaker(engines[0], expire_on_commit=False, class_=Session)
        application = sessionmaker(engines[1], expire_on_commit=False, class_=Session)
        sessions = PlatformSessionService(
            authenticator,
            origin=config.origin,
            audience=config.audience,
        )
        app = create_platform_admin_app(
            config=config,
            sessions=sessions,
            authorization=PlatformAuthorizationService(application),
            projections=PlatformProjectionService(application),
            password_authentication=PlatformPasswordAuthenticationService(
                authenticator,
                sessions,
            ),
        )

        @app.get("/healthz", include_in_schema=False)
        def healthz() -> JSONResponse:
            try:
                for service, engine in zip(_WEB_SERVICES, engines, strict=True):
                    binding = bindings.by_service[service]
                    _inspect_service_login(
                        engine,
                        expected_login=binding.login,
                        expected_role=binding.base_role,
                    )
            except (sa.exc.SQLAlchemyError, PostgreSqlMigrationError):
                return JSONResponse(status_code=503, content={"status": "unavailable"})
            return JSONResponse(content={"status": "ok"})

        return app, engines
    except Exception:
        for engine in engines:
            engine.dispose()
        raise


def transition_local_operator(
    environ: Mapping[str, str],
    *,
    username: str,
    password: str,
    authorized_by_principal_id: UUID,
    approval_ref: str,
    reason: str,
) -> UUID:
    """Run the one-time legacy-operator to local-password transition."""

    config = _config(environ)
    engines, _bindings = _engines(
        environ,
        ("platform_authenticator", "platform_governance"),
    )
    try:
        authenticator = sessionmaker(engines[0], expire_on_commit=False, class_=Session)
        governance = sessionmaker(engines[1], expire_on_commit=False, class_=Session)
        sessions = PlatformSessionService(
            authenticator,
            origin=config.origin,
            audience=config.audience,
        )
        return PlatformPasswordAuthenticationService(
            authenticator,
            sessions,
            governance_factory=governance,
        ).transition_local_operator(
            username=username,
            password=password,
            authorized_by_principal_id=authorized_by_principal_id,
            approval_ref=approval_ref,
            reason=reason,
        )
    finally:
        for engine in engines:
            engine.dispose()


def main() -> None:
    import uvicorn

    app, _engines = build_platform_admin(os.environ)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8092,
        proxy_headers=True,
        forwarded_allow_ips=_trusted_proxy_cidrs(os.environ),
        server_header=False,
    )


if __name__ == "__main__":
    main()


__all__ = [
    "build_platform_admin",
    "main",
    "transition_local_operator",
]
