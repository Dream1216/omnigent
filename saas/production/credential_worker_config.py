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


def create_credential_worker_sessions(config: CredentialWorkerConfig) -> CredentialWorkerSessions:
    engine = sa.create_engine(config.database_url, pool_pre_ping=True)
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
