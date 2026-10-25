"""Dedicated production machine-metering receiver over the existing mTLS protocol."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import math
import os
import re
import signal
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from saas.billing_metering_transport import MutualTlsBillingMeteringServer
from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.production.postgresql_migration import (
    PostgreSqlMigrationError,
    verify_machine_metering_postgresql_state,
)
from saas.production.runner_control import _secure_file, build_server_tls_context
from saas.production.server_config import (
    ProductionMigrationReceipt,
    load_production_database_url_file,
    load_production_migration_receipt,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindings,
    ProductionServiceRoleGraph,
    load_machine_metering_service_role_bindings,
    load_production_service_role_bindings,
    load_production_service_role_graph,
)

_LOGGER = logging.getLogger("omnigent-saas-machine-metering")
_PREFIX = "OMNIGENT_SAAS_METERING_"
_DATABASE_FILE = _PREFIX + "DATABASE_URL_FILE"


class ProductionMachineMeteringError(ValueError):
    """A content-free configuration or admission refusal."""


@dataclass(frozen=True, slots=True)
class ProductionMachineMeteringConfig:
    product_revision: str
    official_schema_revision: str
    control_plane_schema_revision: str
    service_role_bindings: ProductionServiceRoleBindings
    service_role_graph: ProductionServiceRoleGraph
    migration_receipt: ProductionMigrationReceipt
    database_url: str = field(repr=False)
    ca_certificate_path: Path
    server_certificate_path: Path
    server_key_path: Path = field(repr=False)
    trust_bundle_version: str
    bind_host: str
    bind_port: int
    expected_host: str
    request_timeout_seconds: float


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise ProductionMachineMeteringError("machine_metering_configuration_invalid")
    return value


def load_production_machine_metering_config(
    source: Mapping[str, str],
) -> ProductionMachineMeteringConfig:
    """Load immutable release/profile evidence and only the dedicated service DSN."""
    try:
        if any(
            value.strip()
            for name, value in source.items()
            if (name == "DATABASE_URL" or name.endswith(("_DATABASE_URL", "_DATABASE_URL_FILE")))
            and name != _DATABASE_FILE
        ):
            raise ValueError("unexpected database authority")
        revision = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
        if (
            re.fullmatch(r"[0-9a-f]{40}", revision) is None
            or revision == "0" * 40
            or revision != _required(source, "OMNIGENT_SAAS_SOURCE_SHA")
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}", _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
            )
            is None
        ):
            raise ValueError("invalid release identity")
        core = load_production_service_role_bindings(source)
        metering = load_machine_metering_service_role_bindings(source)
        graph = load_production_service_role_graph(source, production=core)
        database_url, parsed, _path = load_production_database_url_file(source, "metering")
        if parsed.username != metering.login_for("metering") or parsed.username == "saas_metering":
            raise ValueError("wrong service login")
        official = _required(source, "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION")
        control = _required(source, "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION")
        receipt = load_production_migration_receipt(
            source,
            product_revision=revision,
            official_head=official,
            saas_head=control,
            service_role_bindings_sha256=core.sha256,
            service_role_graph_sha256=graph.sha256,
        )
        host = source.get(_PREFIX + "BIND_HOST", "127.0.0.1")
        address = ipaddress.ip_address(host)
        if not (address.is_private or address.is_loopback or address.is_unspecified):
            raise ValueError("public bind address")
        port = int(source.get(_PREFIX + "PORT", "9446"))
        timeout = float(source.get(_PREFIX + "REQUEST_TIMEOUT_SECONDS", "5"))
        if not 1 <= port <= 65535 or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("unbounded listener")
        expected_host = source.get(_PREFIX + "EXPECTED_HOST", "billing-metering.internal")
        if re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", expected_host
        ) is None or not expected_host.endswith((".internal", ".svc", ".svc.cluster.local")):
            raise ValueError("noninternal receiver name")
        bundle = _required(source, _PREFIX + "TRUST_BUNDLE_VERSION")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", bundle) is None:
            raise ValueError("invalid trust bundle")
        return ProductionMachineMeteringConfig(
            revision,
            official,
            control,
            core,
            graph,
            receipt,
            database_url,
            _secure_file(source, _PREFIX + "CLIENT_CA_FILE", secret=False),
            _secure_file(source, _PREFIX + "TLS_CERT_FILE", secret=False),
            _secure_file(source, _PREFIX + "TLS_KEY_FILE", secret=True),
            bundle,
            host,
            port,
            expected_host,
            timeout,
        )
    except Exception:  # noqa: BLE001 - configuration errors must never include secrets.
        raise ProductionMachineMeteringError("machine_metering_configuration_invalid") from None


def verify_installed_machine_metering_lineage(config: ProductionMachineMeteringConfig) -> None:
    """Reject wrong or unpackaged code before PostgreSQL access or listener bind."""
    try:
        from omnigent import _build_info

        if config.product_revision != _build_info.COMMIT_SHA:
            raise ValueError
    except (AttributeError, ImportError, ValueError):
        raise ProductionMachineMeteringError(
            "machine_metering_installed_revision_mismatch"
        ) from None


def build_production_machine_metering_server(
    config: ProductionMachineMeteringConfig, engine: sa.Engine
) -> MutualTlsBillingMeteringServer:
    """No listener exists until the complete live receipt/catalog verifier succeeds."""
    verify_machine_metering_postgresql_state(
        engine=engine, database_url=config.database_url, config=config
    )
    sessions = sessionmaker(engine, expire_on_commit=False)
    return MutualTlsBillingMeteringServer(
        BillingMeteringAuthority(sessions),
        build_server_tls_context(config),
        RunnerCertificateAuthority(
            sessions, accepted_trust_bundle_versions=(config.trust_bundle_version,)
        ),
        expected_host=config.expected_host,
        request_timeout_seconds=config.request_timeout_seconds,
    )


async def _run(config: ProductionMachineMeteringConfig, *, check_only: bool) -> None:
    engine = sa.create_engine(
        config.database_url,
        pool_size=2,
        max_overflow=0,
        pool_timeout=5,
        pool_pre_ping=True,
        hide_parameters=True,
    )
    try:
        server = build_production_machine_metering_server(config, engine)
        if check_only:
            return
        await server.start(host=config.bind_host, port=config.bind_port)
        try:
            stopped = asyncio.Event()
            loop = asyncio.get_running_loop()
            for value in (signal.SIGTERM, signal.SIGINT):
                with suppress(NotImplementedError):
                    loop.add_signal_handler(value, stopped.set)
            await stopped.wait()
        finally:
            await server.aclose()
    finally:
        engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify admission without binding")
    args = parser.parse_args(argv)
    try:
        config = load_production_machine_metering_config(os.environ)
        verify_installed_machine_metering_lineage(config)
        asyncio.run(_run(config, check_only=args.check))
    except Exception as error:  # noqa: BLE001 - never print a DSN-bearing exception.
        if (
            isinstance(error, PostgreSqlMigrationError)
            and error.code == "machine_metering_source_catalog_baseline_missing"
        ):
            _LOGGER.error(
                "machine_metering_unavailable:machine_metering_source_catalog_baseline_missing"
            )
        else:
            _LOGGER.error("machine_metering_startup_rejected")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
