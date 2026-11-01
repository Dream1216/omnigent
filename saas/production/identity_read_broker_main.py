"""Run the database-free private Casdoor state service from its pinned image."""

from __future__ import annotations

import sys

from fastapi import FastAPI

from saas.control_plane.identity_events import IdentitySyncError
from saas.production.casdoor_identity_sync import CasdoorIdentityStateProvider
from saas.production.identity_process_config import (
    IdentityReadBrokerConfig,
    load_identity_read_broker_config,
)
from saas.production.identity_process_server import run_private_identity_app
from saas.production.identity_read_broker import create_identity_read_broker
from saas.production.server import ProductionServerCompositionError, verify_installed_build_lineage
from saas.production.server_config import ProductionServerConfigError


def build_identity_read_broker(config: IdentityReadBrokerConfig) -> FastAPI:
    verify_installed_build_lineage(config.build)
    provider = CasdoorIdentityStateProvider(
        config.provider, tls_context=config.provider_tls_context
    )
    provider.verify_organization()
    return create_identity_read_broker(
        provider, pins=config.pins, keys=config.keys, concurrency=config.concurrency
    )


def main() -> None:
    try:
        config = load_identity_read_broker_config()
        app = build_identity_read_broker(config)
        run_private_identity_app(app, tls=config.tls)
    except (ProductionServerConfigError, ProductionServerCompositionError, IdentitySyncError):
        print("identity read broker startup rejected", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
