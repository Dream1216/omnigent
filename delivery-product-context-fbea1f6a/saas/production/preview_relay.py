"""Concrete production composition for Preview relay clients and owners.

The public Preview Edge and each standalone Preview Owner share the same durable
PostgreSQL Placement, endpoint, and certificate authorities. Edge replicas are
relay-only clients. Every Owner process creates and owns its official
``TunnelRegistry`` plus exact-generation bindings for the whole process lifetime;
the main SaaS Server never receives this registry or the Owner database authority.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import re
import ssl
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from omnigent.runner.transports.ws_tunnel.registry import TunnelRegistry
from saas.control_plane import (
    PreviewGatewayCertificateAuthority,
    PreviewGatewayDirectoryAuthority,
)
from saas.control_plane.preview_sessions import PreviewSessionAuthority
from saas.preview_gateway import PreviewTunnelRequest, PreviewTunnelResponse
from saas.preview_relay_transport import (
    MutualTlsPreviewRelayClient,
    MutualTlsPreviewRelayServer,
    PolicyBoundPreviewRelayEndpointResolver,
    PreviewRelayEndpointPolicy,
)
from saas.preview_tunnel import (
    LocalRunnerTunnelBindings,
    OfficialRunnerPreviewTunnel,
    PlacementRoutedPreviewTunnel,
    PreviewTunnelAdapterError,
)
from saas.production.preview_edge import (
    ProductionPreviewEdgeConfig,
    verify_preview_database_authority,
)
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_database_url_file,
    load_production_migration_receipt,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_GATEWAY_SPIFFE_ID = re.compile(
    r"^spiffe://omnigent/preview-gateway/(?P<gateway>[A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FORBIDDEN_OWNER_DATABASE_ENVIRONMENTS = frozenset(
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
        "OMNIGENT_SAAS_PREVIEW_EDGE_DATABASE_URL_FILE",
    }
)


class ProductionPreviewRelayError(RuntimeError):
    """Stable fail-closed error without certificate, DNS, or topology detail."""


def _csv(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    raw = source.get(name, "")
    values = tuple(value.strip() for value in raw.split(","))
    if (
        not raw
        or any(not value or "\x00" in value for value in values)
        or len(set(values)) != len(values)
    ):
        raise ProductionPreviewRelayError(f"{name} is required and must be well formed")
    return values


def _ports(source: Mapping[str, str], name: str) -> tuple[int, ...]:
    try:
        values = tuple(int(value) for value in _csv(source, name))
    except ValueError as exc:
        raise ProductionPreviewRelayError(f"{name} is invalid") from exc
    if any(not 1 <= value <= 65_535 for value in values):
        raise ProductionPreviewRelayError(f"{name} is invalid")
    return values


def _integer(
    source: Mapping[str, str], name: str, *, default: int, minimum: int, maximum: int
) -> int:
    try:
        value = int(source.get(name, str(default)))
    except ValueError as exc:
        raise ProductionPreviewRelayError(f"{name} is invalid") from exc
    if not minimum <= value <= maximum:
        raise ProductionPreviewRelayError(f"{name} is invalid")
    return value


def _secure_file(source: Mapping[str, str], name: str, *, secret: bool) -> Path:
    raw = source.get(name, "")
    path = Path(raw)
    if not raw or raw != raw.strip() or not path.is_absolute():
        raise ProductionPreviewRelayError(f"{name} is unavailable")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProductionPreviewRelayError(f"{name} is unavailable") from exc
    forbidden = 0o077 if secret else 0o022
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & forbidden
        or not 1 <= metadata.st_size <= 1_048_576
    ):
        raise ProductionPreviewRelayError(f"{name} ownership or mode is invalid")
    return path


def _certificate(path: Path) -> tuple[x509.Certificate, bytes, str]:
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (OSError, ValueError, x509.ExtensionNotFound) as exc:
        raise ProductionPreviewRelayError("Preview Relay certificate is invalid") from exc
    uri_names = san.get_values_for_type(x509.UniformResourceIdentifier)
    match = _GATEWAY_SPIFFE_ID.fullmatch(uri_names[0]) if len(uri_names) == 1 else None
    if match is None:
        raise ProductionPreviewRelayError("Preview Relay certificate identity is invalid")
    return (
        certificate,
        certificate.public_bytes(serialization.Encoding.DER),
        match.group("gateway"),
    )


def _client_tls_context(ca: Path, certificate: Path, key: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_cert_chain(str(certificate), str(key))
    return context


def _server_tls_context(ca: Path, certificate: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca))
    context.load_cert_chain(str(certificate), str(key))
    return context


def _policy(
    *, dns_suffixes: tuple[str, ...], cidrs: tuple[str, ...], ports: tuple[int, ...]
) -> PreviewRelayEndpointPolicy:
    try:
        return PreviewRelayEndpointPolicy.from_strings(
            allowed_dns_suffixes=dns_suffixes,
            allowed_cidrs=cidrs,
            allowed_ports=ports,
        )
    except ValueError as exc:
        raise ProductionPreviewRelayError("Preview Relay endpoint policy is invalid") from exc


class _RelayOnlyLocalTunnel:
    async def forward(self, _request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        raise PreviewTunnelAdapterError(
            "preview_edge_local_owner_denied",
            "Preview Edge does not own Runner tunnel sessions",
        )


@dataclass(slots=True)
class ProductionPreviewTunnelRuntime:
    """Relay-only Preview Edge tunnel with live PostgreSQL/certificate readiness."""

    engine: Engine = field(repr=False)
    router: PlacementRoutedPreviewTunnel = field(repr=False)
    certificates: PreviewGatewayCertificateAuthority = field(repr=False)
    gateway_instance_id: str
    client_certificate_der: bytes = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    async def forward(self, request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        if self._closed:
            raise PreviewTunnelAdapterError("preview_relay_closed", "Preview Relay is unavailable")
        return await self.router.forward(request)

    def assert_production_ready(self) -> None:
        if self._closed:
            raise ProductionPreviewRelayError("Preview Relay is closed")
        with self.engine.connect() as connection:
            connection.execute(sa.text("SELECT 1"))
        if not self.certificates.is_preview_gateway_certificate_authorized(
            gateway_instance_id=self.gateway_instance_id,
            certificate_der=self.client_certificate_der,
            purpose="preview_relay_client",
        ):
            raise ProductionPreviewRelayError("Preview Relay client identity is not active")

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.engine.dispose()


def build_production_preview_tunnel(
    *, config: ProductionPreviewEdgeConfig
) -> ProductionPreviewTunnelRuntime:
    """Concrete ``OMNIGENT_SAAS_PREVIEW_TUNNEL_FACTORY`` implementation."""

    engine = sa.create_engine(config.preview_database_url, pool_pre_ping=True)
    try:
        if engine.dialect.name != "postgresql":
            raise ProductionPreviewRelayError("Preview Relay requires PostgreSQL")
        verify_preview_database_authority(
            engine,
            expected_login=config.service_role_bindings.login_for("preview_edge"),
            expected_base_role="saas_preview_edge",
        )
        sessions = sessionmaker(engine, expire_on_commit=False, class_=Session)
        _leaf, certificate_der, gateway_instance_id = _certificate(config.relay_certificate_path)
        certificates = PreviewGatewayCertificateAuthority(
            sessions,
            accepted_trust_bundle_versions=config.relay_trust_bundle_versions,
        )
        placements = PreviewSessionAuthority(sessions)
        directory = PreviewGatewayDirectoryAuthority(
            sessions,
            service_session_factory=sessions,
        )
        endpoints = PolicyBoundPreviewRelayEndpointResolver(
            directory,
            _policy(
                dns_suffixes=config.relay_allowed_dns_suffixes,
                cidrs=config.relay_allowed_cidrs,
                ports=config.relay_allowed_ports,
            ),
        )
        relay = MutualTlsPreviewRelayClient(
            gateway_instance_id=gateway_instance_id,
            endpoint_resolver=endpoints,
            tls_context=_client_tls_context(
                config.relay_ca_path,
                config.relay_certificate_path,
                config.relay_key_path,
            ),
            certificate_authorizer=certificates,
            maximum_request_bytes=config.maximum_request_bytes,
            maximum_response_bytes=config.maximum_response_bytes,
        )
        router = PlacementRoutedPreviewTunnel(
            gateway_instance_id=gateway_instance_id,
            placements=placements,
            local_tunnel=cast(OfficialRunnerPreviewTunnel, _RelayOnlyLocalTunnel()),
            relay=relay,
        )
        runtime = ProductionPreviewTunnelRuntime(
            engine=engine,
            router=router,
            certificates=certificates,
            gateway_instance_id=gateway_instance_id,
            client_certificate_der=certificate_der,
        )
        runtime.assert_production_ready()
        return runtime
    except Exception:
        engine.dispose()
        raise


@dataclass(frozen=True, slots=True)
class ProductionPreviewRelayOwnerConfig:
    source_revision: str
    product_revision: str
    preview_database_url: str = field(repr=False)
    expected_preview_login: str
    gateway_instance_id: str
    relay_ca_path: Path
    relay_client_certificate_path: Path
    relay_client_key_path: Path = field(repr=False)
    relay_server_certificate_path: Path
    relay_server_key_path: Path = field(repr=False)
    relay_trust_bundle_versions: tuple[str, ...]
    relay_endpoint_policy: PreviewRelayEndpointPolicy
    bind_host: str
    bind_port: int
    maximum_request_bytes: int
    maximum_response_bytes: int


def load_production_preview_relay_owner_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionPreviewRelayOwnerConfig:
    source: Mapping[str, str] = os.environ if environ is None else environ
    source_revision = source.get("OMNIGENT_SAAS_SOURCE_SHA", "")
    product_revision = source.get("OMNIGENT_SAAS_PRODUCT_REVISION", "")
    image_digest = source.get("OMNIGENT_SAAS_IMAGE_DIGEST", "")
    official_head = source.get("OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION", "")
    saas_head = source.get("OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION", "")
    if (
        re.fullmatch(r"[0-9a-f]{40}", source_revision) is None
        or re.fullmatch(r"[0-9a-f]{40}", product_revision) is None
        or not hmac.compare_digest(source_revision, product_revision)
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
        or _REVISION.fullmatch(official_head) is None
        or _REVISION.fullmatch(saas_head) is None
    ):
        raise ProductionPreviewRelayError("Preview Relay release identity is invalid")
    if any(source.get(name, "").strip() for name in _FORBIDDEN_OWNER_DATABASE_ENVIRONMENTS):
        raise ProductionPreviewRelayError(
            "Preview Relay owner must not receive ambient, owner, server, or other service DSNs"
        )
    try:
        bindings = load_production_service_role_bindings(source)
        database_url, parsed, _path = load_production_database_url_file(source, "preview_owner")
        _ = load_production_migration_receipt(
            source,
            product_revision=product_revision,
            official_head=official_head,
            saas_head=saas_head,
            service_role_bindings_sha256=bindings.sha256,
        )
    except (ProductionServerConfigError, ProductionServiceRoleBindingsError) as exc:
        raise ProductionPreviewRelayError(str(exc)) from exc
    expected_login = bindings.login_for("preview_owner")
    if parsed.username != expected_login:
        raise ProductionPreviewRelayError(
            "Preview Relay owner database login does not match service-role bindings"
        )
    gateway_instance_id = source.get("OMNIGENT_SAAS_PREVIEW_GATEWAY_INSTANCE_ID", "")
    if (
        _GATEWAY_SPIFFE_ID.fullmatch(f"spiffe://omnigent/preview-gateway/{gateway_instance_id}")
        is None
    ):
        raise ProductionPreviewRelayError("Preview Relay Gateway identity is invalid")
    bind_host = source.get("OMNIGENT_SAAS_PREVIEW_RELAY_BIND_HOST", "")
    if bind_host not in {"0.0.0.0", "::"}:
        raise ProductionPreviewRelayError("Preview Relay owner bind host is invalid")
    return ProductionPreviewRelayOwnerConfig(
        source_revision=source_revision,
        product_revision=product_revision,
        preview_database_url=database_url,
        expected_preview_login=expected_login,
        gateway_instance_id=gateway_instance_id,
        relay_ca_path=_secure_file(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_CA_CERTIFICATE_FILE", secret=False
        ),
        relay_client_certificate_path=_secure_file(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_CLIENT_CERTIFICATE_FILE", secret=False
        ),
        relay_client_key_path=_secure_file(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_CLIENT_KEY_FILE", secret=True
        ),
        relay_server_certificate_path=_secure_file(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_SERVER_CERTIFICATE_FILE", secret=False
        ),
        relay_server_key_path=_secure_file(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_SERVER_KEY_FILE", secret=True
        ),
        relay_trust_bundle_versions=_csv(
            source, "OMNIGENT_SAAS_PREVIEW_RELAY_TRUST_BUNDLE_VERSIONS"
        ),
        relay_endpoint_policy=_policy(
            dns_suffixes=_csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_DNS_SUFFIXES"),
            cidrs=_csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS"),
            ports=_ports(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS"),
        ),
        bind_host=bind_host,
        bind_port=_integer(
            source,
            "OMNIGENT_SAAS_PREVIEW_RELAY_BIND_PORT",
            default=9443,
            minimum=1,
            maximum=65_535,
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


class ProductionPreviewRelayOwner:
    """One standalone mTLS owner with a process-local official tunnel registry."""

    def __init__(self, config: ProductionPreviewRelayOwnerConfig, engine: Engine) -> None:
        self.config = config
        self._engine = engine
        self._sessions = sessionmaker(engine, expire_on_commit=False, class_=Session)
        self._certificates = PreviewGatewayCertificateAuthority(
            self._sessions,
            accepted_trust_bundle_versions=config.relay_trust_bundle_versions,
        )
        self._directory = PreviewGatewayDirectoryAuthority(
            self._sessions,
            service_session_factory=self._sessions,
        )
        # The relay receiver must authorize the browser session and rebuild the
        # complete PreviewRouteGrant, not merely check the Runner Placement.
        # This same narrow definer-backed authority is used by the Edge sender.
        self._placements = PreviewSessionAuthority(self._sessions)
        _client, self._client_der, client_gateway_id = _certificate(
            config.relay_client_certificate_path
        )
        _server, self._server_der, server_gateway_id = _certificate(
            config.relay_server_certificate_path
        )
        if {client_gateway_id, server_gateway_id} != {config.gateway_instance_id}:
            raise ProductionPreviewRelayError(
                "Preview Relay leaves do not match the configured Gateway identity"
            )
        self._client_tls = _client_tls_context(
            config.relay_ca_path,
            config.relay_client_certificate_path,
            config.relay_client_key_path,
        )
        self._server_tls = _server_tls_context(
            config.relay_ca_path,
            config.relay_server_certificate_path,
            config.relay_server_key_path,
        )
        self._registry = TunnelRegistry()
        self._bindings = LocalRunnerTunnelBindings(self._registry)
        local_tunnel = OfficialRunnerPreviewTunnel(self._registry, self._bindings)
        endpoints = PolicyBoundPreviewRelayEndpointResolver(
            self._directory,
            self.config.relay_endpoint_policy,
        )
        relay_client = MutualTlsPreviewRelayClient(
            gateway_instance_id=self.config.gateway_instance_id,
            endpoint_resolver=endpoints,
            tls_context=self._client_tls,
            certificate_authorizer=self._certificates,
            maximum_request_bytes=self.config.maximum_request_bytes,
            maximum_response_bytes=self.config.maximum_response_bytes,
        )
        router = PlacementRoutedPreviewTunnel(
            gateway_instance_id=self.config.gateway_instance_id,
            placements=self._placements,
            local_tunnel=local_tunnel,
            relay=relay_client,
        )
        self._relay_server = MutualTlsPreviewRelayServer(
            gateway_instance_id=self.config.gateway_instance_id,
            router=router,
            tls_context=self._server_tls,
            certificate_authorizer=self._certificates,
            maximum_request_bytes=self.config.maximum_request_bytes,
            maximum_response_bytes=self.config.maximum_response_bytes,
        )
        self._lifecycle_lock = asyncio.Lock()
        self._startup_attempted = False
        self._listening = False

    def _assert_authority_ready(self) -> None:
        with self._engine.connect() as connection:
            connection.execute(sa.text("SELECT 1"))
        for purpose, certificate_der in (
            ("preview_relay_client", self._client_der),
            ("preview_relay_server", self._server_der),
        ):
            if not self._certificates.is_preview_gateway_certificate_authorized(
                gateway_instance_id=self.config.gateway_instance_id,
                certificate_der=certificate_der,
                purpose=purpose,
            ):
                raise ProductionPreviewRelayError("Preview Relay owner identity is not active")

    def assert_production_ready(self) -> None:
        self._assert_authority_ready()
        if self._startup_attempted and not self._listening:
            raise ProductionPreviewRelayError("Preview Relay owner is not listening")

    async def start(self) -> None:
        """Bind the Relay only after database and both leaf identities are active."""

        async with self._lifecycle_lock:
            if self._startup_attempted:
                raise ProductionPreviewRelayError("Preview Relay owner is already started")
            self._startup_attempted = True
            try:
                await asyncio.to_thread(self._assert_authority_ready)
                await self._relay_server.start(
                    host=self.config.bind_host,
                    port=self.config.bind_port,
                )
                if self._relay_server.port != self.config.bind_port:
                    raise ProductionPreviewRelayError(
                        "Preview Relay owner bound an unexpected port"
                    )
                self._listening = True
            except Exception:
                await self._relay_server.aclose()
                raise

    async def run(self, stop: asyncio.Event) -> None:
        """Run until the process coordinator requests a fail-closed shutdown."""

        await self.start()
        try:
            await stop.wait()
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        async with self._lifecycle_lock:
            self._listening = False
            await self._relay_server.aclose()

    @property
    def bindings(self) -> LocalRunnerTunnelBindings:
        """Return the exact-session resolver for the authenticated WS lifecycle.

        Only the downstream one-use Runner tunnel registration seam may call
        ``bind``/``unbind``.  Preview requests only receive the resolver through
        ``OfficialRunnerPreviewTunnel`` and cannot populate it themselves.
        """

        return self._bindings

    @property
    def registry(self) -> TunnelRegistry:
        """Registry owned by the downstream authenticated Runner-WS endpoint only."""

        return self._registry

    @property
    def session_factory(self) -> sessionmaker[Session]:
        """Owner-scoped sessions for narrow Preview authority wrappers only."""

        return self._sessions

    @property
    def port(self) -> int:
        return self._relay_server.port

    def close(self) -> None:
        self._engine.dispose()


def build_production_preview_relay_owner(
    *, config: ProductionPreviewRelayOwnerConfig | None = None
) -> ProductionPreviewRelayOwner:
    """Build one standalone production Preview Owner composition."""

    owner_config = config or load_production_preview_relay_owner_config()
    engine = sa.create_engine(owner_config.preview_database_url, pool_pre_ping=True)
    try:
        if engine.dialect.name != "postgresql":
            raise ProductionPreviewRelayError("Preview Relay owner requires PostgreSQL")
        verify_preview_database_authority(
            engine,
            expected_login=owner_config.expected_preview_login,
            expected_base_role="saas_preview_owner",
        )
        owner = ProductionPreviewRelayOwner(owner_config, engine)
        owner.assert_production_ready()
        return owner
    except Exception:
        engine.dispose()
        raise


__all__ = [
    "ProductionPreviewRelayError",
    "ProductionPreviewRelayOwner",
    "ProductionPreviewRelayOwnerConfig",
    "ProductionPreviewTunnelRuntime",
    "build_production_preview_relay_owner",
    "build_production_preview_tunnel",
    "load_production_preview_relay_owner_config",
]
