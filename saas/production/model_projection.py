"""Opt-in model projection inside the existing production Outbox consumer chain."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from uuid import UUID

import sqlalchemy as sa

from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_projection import (
    MODEL_CREDENTIAL_PROJECTION_ROUTE,
    ModelCredentialProjectionPublisher,
)
from saas.control_plane.outbox import OutboxPublisher
from saas.onboarding_composition import validate_production_outbox_publisher
from saas.production.onboarding import _read_bytes, _regular_file, build_production_secret_cipher
from saas.production.postgresql_migration import verify_model_projection_postgresql_state
from saas.production.server_config import (
    ProductionMigrationReceipt,
    load_production_database_url_file,
    load_production_migration_receipt,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindings,
    ProductionServiceRoleGraph,
    compose_production_service_role_graph,
    load_model_projection_service_role_bindings,
    load_platform_admin_service_role_bindings,
    load_platform_model_service_role_bindings,
    load_production_service_role_bindings,
)

_ENABLED = "OMNIGENT_SAAS_MODEL_PROJECTION_ENABLED"
_KEY_FILE = "OMNIGENT_SAAS_LITELLM_MANAGEMENT_KEY_FILE"
_INTERNAL_HTTP_HOSTS = (
    "omnigent-litellm",
    "omnigent-litellm.omnigent-next-beta.svc.cluster.local",
)


class ProductionModelProjectionError(ValueError):
    """Content-free configuration or startup rejection."""


@dataclass(frozen=True, slots=True)
class ProductionModelProjectionConfig:
    product_revision: str
    official_schema_revision: str
    control_plane_schema_revision: str
    service_role_bindings: ProductionServiceRoleBindings
    service_role_graph: ProductionServiceRoleGraph
    migration_receipt: ProductionMigrationReceipt
    database_url: str = field(repr=False)
    management: LiteLLMManagementConfiguration = field(repr=False)


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise ProductionModelProjectionError("model_projection_configuration_invalid")
    return value


def model_projection_enabled(source: Mapping[str, str]) -> bool:
    value = source.get(_ENABLED, "false")
    if value not in {"true", "false"}:
        raise ProductionModelProjectionError("model_projection_flag_invalid")
    return value == "true"


def load_production_model_projection_config(
    source: Mapping[str, str],
) -> ProductionModelProjectionConfig:
    try:
        if not model_projection_enabled(source):
            raise ValueError
        if source.get("OMNIGENT_SAAS_LITELLM_MANAGEMENT_KEY"):
            raise ValueError
        revision = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
        if re.fullmatch(r"[0-9a-f]{40}", revision) is None or revision != _required(
            source, "OMNIGENT_SAAS_SOURCE_SHA"
        ):
            raise ValueError
        core = load_production_service_role_bindings(source)
        graph = compose_production_service_role_graph(
            core,
            load_platform_model_service_role_bindings(source),
            load_platform_admin_service_role_bindings(source),
            load_model_projection_service_role_bindings(source),
        )
        database_url, parsed, _path = load_production_database_url_file(source, "model_projection")
        if parsed.username != graph.login_for("model_projection"):
            raise ValueError
        official_head = _required(source, "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION")
        saas_head = _required(source, "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION")
        receipt = load_production_migration_receipt(
            source,
            product_revision=revision,
            official_head=official_head,
            saas_head=saas_head,
            service_role_bindings_sha256=core.sha256,
            service_role_graph_sha256=graph.sha256,
        )
        path = _regular_file(source, _KEY_FILE, maximum_bytes=4098)
        key = _read_bytes(path, _KEY_FILE, maximum_bytes=4098).decode("ascii").rstrip("\r\n")
        return ProductionModelProjectionConfig(
            revision,
            official_head,
            saas_head,
            core,
            graph,
            receipt,
            database_url,
            LiteLLMManagementConfiguration(
                base_url=_required(source, "OMNIGENT_SAAS_LITELLM_MANAGEMENT_BASE_URL"),
                management_key=key,
                allowed_http_hosts=_INTERNAL_HTTP_HOSTS,
            ),
        )
    except Exception:  # noqa: BLE001 - never retain a secret-bearing exception chain.
        raise ProductionModelProjectionError("model_projection_configuration_invalid") from None


@dataclass(slots=True)
class ProductionModelProjectionPublisher:
    config: ProductionModelProjectionConfig = field(repr=False)
    engine: sa.Engine = field(repr=False)
    projection: ModelCredentialProjectionPublisher = field(repr=False)
    fallback: OutboxPublisher = field(repr=False)

    def validate_outbox_configuration(self) -> None:
        verify_model_projection_postgresql_state(
            engine=self.engine, database_url=self.config.database_url, config=self.config
        )
        validate_production_outbox_publisher(self.fallback)

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        route = MODEL_CREDENTIAL_PROJECTION_ROUTE
        target = (
            self.projection
            if (
                event_type == route.event_type
                or payload.get("event_type") == route.payload_event_type
            )
            else self.fallback
        )
        target.publish(
            event_id=event_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_key=aggregate_key,
            payload=payload,
        )

    def close(self) -> None:
        try:
            close = getattr(self.fallback, "close", None)
            if callable(close):
                close()
        finally:
            self.engine.dispose()


def wrap_production_model_projection(
    source: Mapping[str, str],
    *,
    fallback: OutboxPublisher,
    engine_factory: Callable[[str], sa.Engine] = lambda url: sa.create_engine(
        url, pool_pre_ping=True, hide_parameters=True, poolclass=sa.pool.NullPool
    ),
    secret_cipher_loader: Callable[
        [Mapping[str, str]], SecretCipher | None
    ] = build_production_secret_cipher,
) -> OutboxPublisher:
    """Keep disabled deployments unchanged; enabled workers need only one new DSN."""

    if not model_projection_enabled(source):
        return fallback
    engine: sa.Engine | None = None
    try:
        config = load_production_model_projection_config(source)
        cipher = secret_cipher_loader(source)
        if cipher is None:
            raise ValueError
        engine = engine_factory(config.database_url)
        publisher = ProductionModelProjectionPublisher(
            config,
            engine,
            ModelCredentialProjectionPublisher(
                engine, secret_cipher=cipher, management=LiteLLMManagementClient(config.management)
            ),
            fallback,
        )
        publisher.validate_outbox_configuration()
        return publisher
    except Exception:  # noqa: BLE001 - the caller retains ownership of the fallback on failure.
        if engine is not None:
            with suppress(Exception):
                engine.dispose()
        raise ProductionModelProjectionError("model_projection_startup_rejected") from None
