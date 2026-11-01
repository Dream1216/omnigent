"""Release-bound configuration holding only the credential worker's database login."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.production.credential_migration import (
    CredentialIdentityPins,
    load_credential_identity_pins,
)
from saas.production.postgresql_migration import verify_credential_worker_postgresql_state
from saas.production.server_config import (
    _FULL_GIT_SHA,
    _IMAGE_DIGEST,
    ProductionMigrationReceipt,
    ProductionServerConfigError,
    _required,
    _revision,
    load_production_database_url_file,
    load_production_migration_receipt,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindings,
    ProductionServiceRoleGraph,
    load_production_service_role_bindings,
    load_production_service_role_graph,
)


@dataclass(frozen=True, slots=True)
class CredentialWorkerConfig:
    product_revision: str
    upstream_revision: str
    image_digest: str
    official_schema_revision: str
    control_plane_schema_revision: str
    service_role_bindings: ProductionServiceRoleBindings
    service_role_graph: ProductionServiceRoleGraph
    migration_receipt: ProductionMigrationReceipt
    identity: CredentialIdentityPins
    database_url: str = field(repr=False)


_FORBIDDEN_SECRETS = frozenset(
    {
        "DATABASE_URL",
        "PGPASSWORD",
        "PGPASSFILE",
        "PGSERVICE",
        "PGOPTIONS",
        "OMNIGENT_SAAS_CASDOOR_CLIENT_SECRET_FILE",
        "OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE",
        "OMNIGENT_SAAS_API_CREDENTIAL_PEPPER_FILE",
        "OMNIGENT_SAAS_CURSOR_HMAC_KEY_FILE",
        "OMNIGENT_SAAS_IDEMPOTENCY_HMAC_KEY_FILE",
        "OMNIGENT_SAAS_CONTEXT_SNAPSHOT_KEY_FILE",
        "OMNIGENT_SAAS_PREVIEW_EXCHANGE_HMAC_KEY_FILE",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE",
    }
)

CREDENTIAL_MAINTENANCE_RELEASE_INPUTS = frozenset(
    {
        "OMNIGENT_SAAS_PRODUCT_REVISION",
        "OMNIGENT_SAAS_SOURCE_SHA",
        "OMNIGENT_SAAS_UPSTREAM_REVISION",
        "OMNIGENT_SAAS_IMAGE_DIGEST",
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION",
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION",
        "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE",
        "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE",
        "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_CASDOOR_CONFIG_FILE",
        "OMNIGENT_SAAS_PLATFORM_MODEL_SERVICE_ROLE_BINDINGS_FILE",
        "OMNIGENT_SAAS_PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS_FILE",
        "OMNIGENT_SAAS_MODEL_PROJECTION_SERVICE_ROLE_BINDINGS_FILE",
    }
)


def load_credential_maintenance_config(
    source: Mapping[str, str],
    *,
    extra_inputs: frozenset[str] = frozenset(),
) -> CredentialWorkerConfig:
    allowed = CREDENTIAL_MAINTENANCE_RELEASE_INPUTS | extra_inputs
    if any(
        name.startswith("OMNIGENT_SAAS_") and value.strip() and name not in allowed
        for name, value in source.items()
    ):
        raise ProductionServerConfigError("credential maintenance received unrelated authority")
    return load_credential_worker_config(source)


def load_credential_worker_config(
    environ: Mapping[str, str] | None = None,
) -> CredentialWorkerConfig:
    source = os.environ if environ is None else environ
    allowed_url = "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE"
    if any(
        value.strip()
        and (
            name in _FORBIDDEN_SECRETS
            or (
                name.startswith("OMNIGENT_SAAS_")
                and "DATABASE_URL" in name
                and name != allowed_url
            )
        )
        for name, value in source.items()
    ):
        raise ProductionServerConfigError("credential worker received unrelated secret authority")
    product = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
    upstream = _required(source, "OMNIGENT_SAAS_UPSTREAM_REVISION")
    if (
        not _FULL_GIT_SHA.fullmatch(product)
        or not _FULL_GIT_SHA.fullmatch(upstream)
        or _required(source, "OMNIGENT_SAAS_SOURCE_SHA") != product
    ):
        raise ProductionServerConfigError("credential worker source lineage is invalid")
    image = _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
    if not _IMAGE_DIGEST.fullmatch(image):
        raise ProductionServerConfigError("credential worker image digest is invalid")
    official = _revision(source, "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION")
    saas = _revision(source, "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION")
    bindings = load_production_service_role_bindings(source)
    graph = load_production_service_role_graph(source, production=bindings)
    url, parsed, _path = load_production_database_url_file(source, "authenticator")
    if parsed.username != graph.login_for("authenticator"):
        raise ProductionServerConfigError(
            "credential worker login does not match release bindings"
        )
    receipt = load_production_migration_receipt(
        source,
        product_revision=product,
        official_head=official,
        saas_head=saas,
        service_role_bindings_sha256=bindings.sha256,
        service_role_graph_sha256=graph.sha256,
    )
    return CredentialWorkerConfig(
        product,
        upstream,
        image,
        official,
        saas,
        bindings,
        graph,
        receipt,
        load_credential_identity_pins(source),
        url,
    )


@dataclass(slots=True)
class CredentialWorkerSessions:
    authenticator: sessionmaker[Session]
    _engine: Engine = field(repr=False)

    def close(self) -> None:
        self._engine.dispose()


@dataclass(frozen=True, slots=True)
class CredentialWorkerDatabaseLimits:
    pool_size: int = 6
    pool_timeout_seconds: int = 5
    connect_timeout_seconds: int = 5
    lock_timeout_ms: int = 5000
    statement_timeout_ms: int = 10000
    idle_transaction_timeout_ms: int = 15000

    def __post_init__(self) -> None:
        values = (
            self.pool_size,
            self.pool_timeout_seconds,
            self.connect_timeout_seconds,
            self.lock_timeout_ms,
            self.statement_timeout_ms,
            self.idle_transaction_timeout_ms,
        )
        if (
            any(type(value) is not int for value in values)
            or not 1 <= self.pool_size <= 8
            or not 1 <= self.pool_timeout_seconds <= 5
            or not 1 <= self.connect_timeout_seconds <= 5
            or not 1 <= self.lock_timeout_ms < self.statement_timeout_ms <= 10000
            or not self.statement_timeout_ms <= self.idle_transaction_timeout_ms <= 20000
        ):
            raise ValueError("credential worker database limits are invalid")


def create_credential_worker_engine(
    database_url: str, *, limits: CredentialWorkerDatabaseLimits | None = None
) -> Engine:
    if limits is None:
        return sa.create_engine(database_url, pool_pre_ping=True)
    # Source-owned timeout options apply before catalog verification or any
    # application transaction; no ambient PGOPTIONS or role defaults are changed.
    return sa.create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=limits.pool_size,
        max_overflow=0,
        pool_timeout=limits.pool_timeout_seconds,
        connect_args={
            "connect_timeout": limits.connect_timeout_seconds,
            "options": (
                f"-c lock_timeout={limits.lock_timeout_ms} "
                f"-c statement_timeout={limits.statement_timeout_ms} "
                f"-c idle_in_transaction_session_timeout={limits.idle_transaction_timeout_ms}"
            ),
        },
    )


def create_credential_worker_sessions(
    config: CredentialWorkerConfig, *, limits: CredentialWorkerDatabaseLimits | None = None
) -> CredentialWorkerSessions:
    engine = create_credential_worker_engine(config.database_url, limits=limits)
    try:
        if engine.dialect.name != "postgresql":
            raise ProductionServerConfigError("credential worker requires PostgreSQL")
        verify_credential_worker_postgresql_state(
            engine=engine, database_url=config.database_url, config=config
        )
        return CredentialWorkerSessions(sessionmaker(engine, expire_on_commit=False), engine)
    except Exception:
        engine.dispose()
        raise
