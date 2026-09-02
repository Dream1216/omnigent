"""Production Preview-origin composition over fenced leases and mTLS relay.

The public Preview origin is deliberately a separate process and cookie domain
from the SaaS application.  PostgreSQL ``saas_preview_edge`` authority
validates the exact host/token/Run/Runner/Worktree fences on every request.  A
deployment-owned tunnel factory must provide the existing authenticated
Placement-routed relay; a local/process-only tunnel is not accepted as
production-ready by this composition.
"""

from __future__ import annotations

import asyncio
import hmac
import importlib
import inspect
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

import sqlalchemy as sa
import uvicorn
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.preview_sessions import PreviewSessionAuthority
from saas.preview_gateway import PreviewTunnel, create_preview_session_gateway_app
from saas.production.preview_readiness import (
    TlsPreviewReadinessServer,
    build_preview_readiness_server_tls_context,
)
from saas.production.server_config import (
    ProductionMigrationReceipt,
    ProductionServerConfigError,
    load_production_database_url_file,
    load_production_migration_receipt,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindings,
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_INTERNAL_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_FACTORY_REFERENCE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*:[A-Za-z][A-Za-z0-9_]*$"
)
_FORBIDDEN_DATABASE_ENVIRONMENTS = frozenset(
    {
        "DATABASE_URL",
        "OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL",
        "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL",
        "OMNIGENT_SAAS_DATABASE_OWNER_DATABASE_URL",
        "OMNIGENT_SAAS_OFFICIAL_MIGRATION_DATABASE_URL",
        "OMNIGENT_SAAS_CONTROL_PLANE_MIGRATION_DATABASE_URL",
        "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_DATABASE_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_OFFICIAL_MIGRATION_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_CONTROL_PLANE_MIGRATION_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_APP_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_GOVERNANCE_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_PUBLIC_API_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_DISPATCHER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_SECRET_BROKER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_PREVIEW_GATEWAY_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_PREVIEW_OWNER_DATABASE_URL_FILE",
    }
)


class ProductionPreviewEdgeError(RuntimeError):
    """Stable fail-closed Preview composition error."""


class ProductionPreviewTunnel(PreviewTunnel, Protocol):
    """Authenticated cross-host tunnel plus content-blind readiness proof."""

    def assert_production_ready(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ProductionPreviewEdgeConfig:
    source_revision: str
    product_revision: str
    image_digest: str
    official_schema_revision: str
    control_plane_schema_revision: str
    preview_database_url: str = field(repr=False)
    service_role_bindings: ProductionServiceRoleBindings = field(repr=False)
    migration_receipt: ProductionMigrationReceipt
    tunnel_factory: str
    relay_ca_path: Path
    relay_certificate_path: Path
    relay_key_path: Path = field(repr=False)
    relay_trust_bundle_versions: tuple[str, ...]
    relay_allowed_dns_suffixes: tuple[str, ...]
    relay_allowed_cidrs: tuple[str, ...]
    relay_allowed_ports: tuple[int, ...]
    host: str
    port: int
    readiness_bind_host: str
    readiness_port: int
    readiness_server_name: str
    readiness_certificate_path: Path
    readiness_key_path: Path = field(repr=False)
    maximum_request_bytes: int
    maximum_response_bytes: int


@dataclass(slots=True)
class BuiltProductionPreviewEdge:
    app: FastAPI
    engine: Engine = field(repr=False)
    tunnel: ProductionPreviewTunnel = field(repr=False)
    readiness_failures: Callable[[], list[str]] = field(repr=False)

    def assert_production_ready(self) -> None:
        if self.readiness_failures():
            raise ProductionPreviewEdgeError("Preview edge is not ready")

    def close(self) -> None:
        try:
            close = getattr(self.tunnel, "close", None)
            if close is not None:
                close()
        finally:
            self.engine.dispose()


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip() or value != value.strip() or "\x00" in value:
        raise ProductionPreviewEdgeError(f"{name} is required and must be well formed")
    return value


def _revision(source: Mapping[str, str], name: str) -> str:
    value = _required(source, name)
    if _REVISION.fullmatch(value) is None:
        raise ProductionPreviewEdgeError(f"{name} is invalid")
    return value


def _csv(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    raw = _required(source, name)
    values = tuple(item.strip() for item in raw.split(","))
    if any(not item or "\x00" in item for item in values) or len(set(values)) != len(values):
        raise ProductionPreviewEdgeError(f"{name} is invalid")
    return values


def _integer(
    source: Mapping[str, str], name: str, *, default: int, minimum: int, maximum: int
) -> int:
    raw = source.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise ProductionPreviewEdgeError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ProductionPreviewEdgeError(f"{name} is outside its bounded range")
    return value


def _secure_file(source: Mapping[str, str], name: str, *, secret: bool) -> Path:
    path = Path(_required(source, name))
    if not path.is_absolute():
        raise ProductionPreviewEdgeError(f"{name} must be an absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProductionPreviewEdgeError(f"{name} is unavailable") from error
    forbidden = 0o077 if secret else 0o022
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & forbidden
        or not 1 <= metadata.st_size <= 1_048_576
    ):
        raise ProductionPreviewEdgeError(f"{name} ownership or mode is invalid")
    return path


def load_production_preview_edge_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionPreviewEdgeConfig:
    """Validate release, narrow DB login, relay PKI, and fixed byte limits."""

    source: Mapping[str, str] = os.environ if environ is None else environ
    if any(source.get(name, "").strip() for name in _FORBIDDEN_DATABASE_ENVIRONMENTS):
        raise ProductionPreviewEdgeError(
            "Preview edge must not receive ambient, owner, server, or other service DSNs"
        )
    source_revision = _required(source, "OMNIGENT_SAAS_SOURCE_SHA")
    product_revision = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
    image_digest = _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
    if (
        _FULL_GIT_SHA.fullmatch(source_revision) is None
        or _FULL_GIT_SHA.fullmatch(product_revision) is None
        or not hmac.compare_digest(source_revision, product_revision)
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
    ):
        raise ProductionPreviewEdgeError("Preview edge release identity is invalid")
    official_head = _revision(source, "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION")
    saas_head = _revision(source, "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION")
    try:
        bindings = load_production_service_role_bindings(source)
        database_url, parsed, _path = load_production_database_url_file(source, "preview_edge")
        receipt = load_production_migration_receipt(
            source,
            product_revision=product_revision,
            official_head=official_head,
            saas_head=saas_head,
            service_role_bindings_sha256=bindings.sha256,
        )
    except (ProductionServerConfigError, ProductionServiceRoleBindingsError) as error:
        raise ProductionPreviewEdgeError(str(error)) from error
    if parsed.username != bindings.login_for("preview_edge"):
        raise ProductionPreviewEdgeError(
            "Preview database login does not match service-role bindings"
        )
    tunnel_factory = _required(source, "OMNIGENT_SAAS_PREVIEW_TUNNEL_FACTORY")
    if _FACTORY_REFERENCE.fullmatch(tunnel_factory) is None or any(
        part.startswith("_") for part in tunnel_factory.replace(":", ".").split(".")
    ):
        raise ProductionPreviewEdgeError("Preview tunnel factory is invalid")
    host = _required(source, "OMNIGENT_SAAS_PREVIEW_EDGE_HOST")
    if host not in {"0.0.0.0", "::"}:
        raise ProductionPreviewEdgeError("Preview edge must bind an explicit Pod address")
    readiness_bind_host = _required(source, "OMNIGENT_SAAS_PREVIEW_READINESS_BIND_HOST")
    if readiness_bind_host not in {"0.0.0.0", "::"}:
        raise ProductionPreviewEdgeError("Preview readiness must bind an explicit Pod address")
    readiness_server_name = _required(
        source, "OMNIGENT_SAAS_PREVIEW_READINESS_SERVER_NAME"
    ).lower()
    readiness_suffixes = tuple(
        value.lower().lstrip(".").rstrip(".")
        for value in _csv(source, "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_DNS_SUFFIXES")
    )
    if (
        _INTERNAL_HOST.fullmatch(readiness_server_name) is None
        or any(_INTERNAL_HOST.fullmatch(value) is None for value in readiness_suffixes)
        or not any(
            readiness_server_name == suffix or readiness_server_name.endswith(f".{suffix}")
            for suffix in readiness_suffixes
        )
    ):
        raise ProductionPreviewEdgeError("Preview readiness server name is invalid")
    readiness_port = _integer(
        source,
        "OMNIGENT_SAAS_PREVIEW_READINESS_PORT",
        default=8443,
        minimum=1,
        maximum=65_535,
    )
    try:
        readiness_allowed_ports = {
            int(value) for value in _csv(source, "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_PORTS")
        }
    except ValueError as error:
        raise ProductionPreviewEdgeError("Preview readiness allowed ports are invalid") from error
    if readiness_port not in readiness_allowed_ports:
        raise ProductionPreviewEdgeError("Preview readiness port is not allowed")
    port = _integer(
        source, "OMNIGENT_SAAS_PREVIEW_EDGE_PORT", default=8080, minimum=1, maximum=65535
    )
    if readiness_port == port:
        raise ProductionPreviewEdgeError("Preview HTTP and readiness ports must be distinct")
    return ProductionPreviewEdgeConfig(
        source_revision=source_revision,
        product_revision=product_revision,
        image_digest=image_digest,
        official_schema_revision=official_head,
        control_plane_schema_revision=saas_head,
        preview_database_url=database_url,
        service_role_bindings=bindings,
        migration_receipt=receipt,
        tunnel_factory=tunnel_factory,
        relay_ca_path=_secure_file(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_CA_CERTIFICATE_FILE", secret=False
        ),
        relay_certificate_path=_secure_file(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_CLIENT_CERTIFICATE_FILE", secret=False
        ),
        relay_key_path=_secure_file(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_CLIENT_KEY_FILE", secret=True
        ),
        relay_trust_bundle_versions=_csv(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_TRUST_BUNDLE_VERSIONS"
        ),
        relay_allowed_dns_suffixes=_csv(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_DNS_SUFFIXES"
        ),
        relay_allowed_cidrs=_csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS"),
        relay_allowed_ports=tuple(
            _integer(
                {"value": value},
                "value",
                default=9443,
                minimum=1,
                maximum=65_535,
            )
            for value in _csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS")
        ),
        host=host,
        port=port,
        readiness_bind_host=readiness_bind_host,
        readiness_port=readiness_port,
        readiness_server_name=readiness_server_name,
        readiness_certificate_path=_secure_file(
            source,
            "OMNIGENT_SAAS_PREVIEW_READINESS_SERVER_CERTIFICATE_FILE",
            secret=False,
        ),
        readiness_key_path=_secure_file(
            source,
            "OMNIGENT_SAAS_PREVIEW_READINESS_SERVER_KEY_FILE",
            secret=True,
        ),
        maximum_request_bytes=_integer(
            source,
            "OMNIGENT_SAAS_PREVIEW_MAX_REQUEST_BYTES",
            default=1_048_576,
            minimum=1024,
            maximum=10_485_760,
        ),
        maximum_response_bytes=_integer(
            source,
            "OMNIGENT_SAAS_PREVIEW_MAX_RESPONSE_BYTES",
            default=10_485_760,
            minimum=1024,
            maximum=104_857_600,
        ),
    )


def _call_factory(factory: Callable[..., object], config: ProductionPreviewEdgeConfig) -> object:
    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError) as error:
        raise ProductionPreviewEdgeError("Preview tunnel factory is not inspectable") from error
    parameters = signature.parameters
    if "config" in parameters or any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
    ):
        return factory(config=config)
    required = [
        parameter
        for parameter in parameters.values()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if required:
        raise ProductionPreviewEdgeError(
            "Preview tunnel factory must be zero-argument or accept config"
        )
    return factory()


def load_production_preview_tunnel(
    config: ProductionPreviewEdgeConfig,
) -> ProductionPreviewTunnel:
    module_name, attribute = config.tunnel_factory.split(":", 1)
    try:
        candidate = getattr(importlib.import_module(module_name), attribute)
        value = _call_factory(candidate, config) if callable(candidate) else candidate
    except ProductionPreviewEdgeError:
        raise
    except Exception as error:
        raise ProductionPreviewEdgeError("Preview tunnel factory failed") from error
    if not callable(getattr(value, "forward", None)) or not callable(
        getattr(value, "assert_production_ready", None)
    ):
        raise ProductionPreviewEdgeError(
            "Preview tunnel must provide authenticated forward and readiness methods"
        )
    return cast(ProductionPreviewTunnel, value)


def verify_preview_database_authority(
    engine: Engine,
    *,
    expected_login: str,
    expected_base_role: str = "saas_preview_edge",
) -> None:
    """Prove this process has only the receipt-bound Preview service role."""

    with engine.connect() as connection:
        row = connection.execute(
            sa.text(
                "SELECT current_user, current_role, "
                "pg_has_role(current_user, :base_role, 'member'), "
                "usesuper, usecreatedb, usecreaterole, userepl, usebypassrls "
                "FROM pg_user WHERE usename = current_user"
            ),
            {"base_role": expected_base_role},
        ).one()
    if (
        row[0] != expected_login
        or row[1] != expected_login
        or row[2] is not True
        or any(value is not False for value in row[3:])
    ):
        raise ProductionPreviewEdgeError("Preview database authority is invalid")


def _readiness_failures(
    factory: sessionmaker[Session],
    tunnel: ProductionPreviewTunnel,
) -> Callable[[], list[str]]:
    def failures() -> list[str]:
        result: list[str] = []
        try:
            with factory() as database:
                database.execute(sa.text("SELECT 1"))
        except Exception:  # noqa: BLE001 - readiness must redact topology/provider details.
            result.append("database.preview_edge")
        try:
            tunnel.assert_production_ready()
        except Exception:  # noqa: BLE001 - readiness must redact topology/provider details.
            result.append("transport.preview_relay")
        return result

    return failures


def _readiness_app(
    failures: Callable[[], list[str]],
    gateway: FastAPI,
) -> FastAPI:
    edge = FastAPI(title="Omnigent Production Preview Edge", docs_url=None, redoc_url=None)

    @edge.get("/livez", include_in_schema=False)
    def livez(response: Response) -> dict[str, str]:
        response.headers["Cache-Control"] = "no-store"
        return {"status": "live"}

    @edge.get("/readyz", include_in_schema=False, response_model=None)
    def readyz(response: Response) -> dict[str, str] | JSONResponse:
        failed = failures()
        if failed:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "failed_dependencies": failed},
                headers={"Cache-Control": "no-store"},
            )
        response.headers["Cache-Control"] = "no-store"
        return {"status": "ready"}

    edge.mount("/", gateway)
    return edge


def build_production_preview_edge(
    config: ProductionPreviewEdgeConfig,
    *,
    engine_factory: Callable[[str], Engine] = lambda url: sa.create_engine(
        url, pool_pre_ping=True
    ),
    tunnel_loader: Callable[[ProductionPreviewEdgeConfig], ProductionPreviewTunnel] = (
        load_production_preview_tunnel
    ),
) -> BuiltProductionPreviewEdge:
    """Compose only after live narrow-role and authenticated-relay checks pass."""

    engine = engine_factory(config.preview_database_url)
    try:
        if engine.dialect.name != "postgresql":
            raise ProductionPreviewEdgeError("Preview edge requires PostgreSQL")
        verify_preview_database_authority(
            engine,
            expected_login=config.service_role_bindings.login_for("preview_edge"),
            expected_base_role="saas_preview_edge",
        )
        factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
        tunnel = tunnel_loader(config)
        tunnel.assert_production_ready()
        gateway = create_preview_session_gateway_app(
            authority=PreviewSessionAuthority(factory),
            tunnel=tunnel,
            maximum_request_bytes=config.maximum_request_bytes,
            maximum_response_bytes=config.maximum_response_bytes,
        )
        readiness_failures = _readiness_failures(factory, tunnel)
        return BuiltProductionPreviewEdge(
            app=_readiness_app(readiness_failures, gateway),
            engine=engine,
            tunnel=tunnel,
            readiness_failures=readiness_failures,
        )
    except Exception:
        engine.dispose()
        raise


def verify_installed_preview_lineage(config: ProductionPreviewEdgeConfig) -> None:
    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError) as error:
        raise ProductionPreviewEdgeError("installed build revision is unavailable") from error
    if installed_revision != config.product_revision:
        raise ProductionPreviewEdgeError(
            "installed build revision does not match Preview product revision"
        )


async def _run(config: ProductionPreviewEdgeConfig) -> int:
    built = build_production_preview_edge(config)
    readiness = TlsPreviewReadinessServer(
        build_preview_readiness_server_tls_context(
            certificate_path=config.readiness_certificate_path,
            key_path=config.readiness_key_path,
        ),
        server_name=config.readiness_server_name,
        readiness_probe=built.assert_production_ready,
    )
    try:
        await readiness.start(
            host=config.readiness_bind_host,
            port=config.readiness_port,
        )
        server = uvicorn.Server(
            uvicorn.Config(
                built.app,
                host=config.host,
                port=config.port,
                proxy_headers=False,
                server_header=False,
            )
        )
        await server.serve()
        return 0
    finally:
        await readiness.aclose()
        built.close()


def main() -> int:
    config = load_production_preview_edge_config()
    verify_installed_preview_lineage(config)
    return asyncio.run(_run(config))


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BuiltProductionPreviewEdge",
    "ProductionPreviewEdgeConfig",
    "ProductionPreviewEdgeError",
    "ProductionPreviewTunnel",
    "build_production_preview_edge",
    "load_production_preview_edge_config",
    "load_production_preview_tunnel",
    "main",
    "verify_installed_preview_lineage",
    "verify_preview_database_authority",
]
