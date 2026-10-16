"""Opt-in model projection inside the existing production Outbox consumer chain."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from contextlib import ExitStack, suppress
from dataclasses import dataclass, field
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_projection import (
    MODEL_CREDENTIAL_PROJECTION_ROUTE,
    ModelCredentialProjectionPublisher,
)
from saas.control_plane.outbox import OutboxPublisher, OutboxPublishError
from saas.control_plane.schema_revision import CONTROL_PLANE_SCHEMA_REVISION
from saas.onboarding_composition import validate_production_outbox_publisher
from saas.production.litellm_configuration_attestation import (
    ATTESTATION_LOGIN,
    LiteLLMConfigurationAttestor,
)
from saas.production.model_protocol_probe import (
    ModelProtocolProbe,
    ModelProtocolProbeConfiguration,
)
from saas.production.model_verification import (
    MODEL_VERIFICATION_ROUTE,
    ModelVerificationPublisher,
    model_configuration_attestation_enabled,
    model_verification_enabled,
)
from saas.production.onboarding import _read_bytes, _regular_file, build_production_secret_cipher
from saas.production.postgresql_migration import (
    _inspect_service_login,
    verify_model_projection_postgresql_state,
)
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
    verification: ModelVerificationPublisher | None = field(default=None, repr=False)
    billing_engine: sa.Engine | None = field(default=None, repr=False)
    storage_attestation: LiteLLMConfigurationAttestor | None = field(default=None, repr=False)

    def validate_outbox_configuration(self) -> None:
        verify_model_projection_postgresql_state(
            engine=self.engine, database_url=self.config.database_url, config=self.config
        )
        if self.billing_engine is not None:
            _inspect_service_login(
                self.billing_engine,
                expected_login=self.config.service_role_graph.login_for("billing"),
                expected_role="saas_billing",
            )
        if self.storage_attestation is not None:
            self.storage_attestation.validate_authority()
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
        verification_route = MODEL_VERIFICATION_ROUTE
        if (
            event_type == verification_route.event_type
            or payload.get("event_type") == verification_route.payload_event_type
        ):
            if self.verification is None:
                raise OutboxPublishError(
                    "model_verification_unavailable", retryable=True, pre_side_effect=False
                )
            target = self.verification
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
            with ExitStack() as cleanup:
                engines = {self.engine}
                if self.billing_engine is not None:
                    engines.add(self.billing_engine)
                if self.storage_attestation is not None:
                    engines.add(self.storage_attestation.engine)
                for engine in engines:
                    cleanup.callback(engine.dispose)


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
    """Projection owns its login; optional priced tests use a separate Billing login."""

    if not model_projection_enabled(source):
        if model_verification_enabled(source) or model_configuration_attestation_enabled(source):
            raise ProductionModelProjectionError("model_verification_requires_projection")
        return fallback
    engine: sa.Engine | None = None
    billing_engine: sa.Engine | None = None
    attestation_engine: sa.Engine | None = None
    try:
        config = load_production_model_projection_config(source)
        cipher = secret_cipher_loader(source)
        if cipher is None:
            raise ValueError
        engine = engine_factory(config.database_url)
        verification = None
        storage_attestation = None
        verification_enabled = model_verification_enabled(source)
        attestation_enabled = model_configuration_attestation_enabled(source)
        if (attestation_enabled and not verification_enabled) or (
            verification_enabled
            and config.control_plane_schema_revision != CONTROL_PLANE_SCHEMA_REVISION
        ):
            raise ValueError
        if attestation_enabled:
            attestation_url, attestation_parsed, _path = load_production_database_url_file(
                source, "litellm_attestation"
            )
            if (
                attestation_parsed.username != ATTESTATION_LOGIN
                or not attestation_parsed.database
                or attestation_parsed.database == sa.make_url(config.database_url).database
                or source.get("OMNIGENT_SAAS_LITELLM_SALT_KEY")
            ):
                raise ValueError
            salt_path = _regular_file(
                source, "OMNIGENT_SAAS_LITELLM_SALT_KEY_FILE", maximum_bytes=4098
            )
            salt = (
                _read_bytes(salt_path, "OMNIGENT_SAAS_LITELLM_SALT_KEY_FILE", maximum_bytes=4098)
                .decode("ascii")
                .rstrip("\r\n")
            )
            attestation_engine = engine_factory(attestation_url)
            storage_attestation = LiteLLMConfigurationAttestor(
                attestation_engine,
                salt_key=salt,
                expected_database=attestation_parsed.database,
            )
        if verification_enabled:
            billing_url, parsed, _path = load_production_database_url_file(source, "billing")
            if parsed.username != config.service_role_graph.login_for("billing"):
                raise ValueError
            billing_engine = engine_factory(billing_url)
            verification = ModelVerificationPublisher(
                engine,
                management=LiteLLMManagementClient(config.management),
                budget=ModelProviderBudgetAdmissionService(
                    sessionmaker(billing_engine, expire_on_commit=False)
                ),
                probe=ModelProtocolProbe(
                    ModelProtocolProbeConfiguration(
                        base_url=config.management.base_url,
                        allowed_http_hosts=config.management.allowed_http_hosts,
                    )
                ),
                attestor=storage_attestation,
                secret_cipher=cipher if storage_attestation is not None else None,
            )
        publisher = ProductionModelProjectionPublisher(
            config,
            engine,
            ModelCredentialProjectionPublisher(
                engine, secret_cipher=cipher, management=LiteLLMManagementClient(config.management)
            ),
            fallback,
            verification,
            billing_engine,
            storage_attestation,
        )
        publisher.validate_outbox_configuration()
        return publisher
    except Exception:  # noqa: BLE001 - the caller retains ownership of the fallback on failure.
        if engine is not None:
            with suppress(Exception):
                engine.dispose()
        if billing_engine is not None and billing_engine is not engine:
            with suppress(Exception):
                billing_engine.dispose()
        if attestation_engine is not None and attestation_engine not in (engine, billing_engine):
            with suppress(Exception):
                attestation_engine.dispose()
        raise ProductionModelProjectionError("model_projection_startup_rejected") from None
