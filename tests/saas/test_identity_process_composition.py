from __future__ import annotations

import ssl
from dataclasses import replace

import pytest

from saas.production import identity_read_broker_main as broker_main
from saas.production import identity_sync_main as worker_main
from saas.production import identity_sync_server as worker_server
from saas.production.casdoor_identity_sync import CasdoorIdentityStateProvider
from saas.production.identity_process_config import (
    load_identity_read_broker_config,
    load_identity_worker_config,
)
from saas.production.server import ProductionServerCompositionError
from tests.saas.test_casdoor_identity_events import config as config
from tests.saas.test_identity_process_config import processes as processes


def test_wrong_installed_source_stops_broker_before_provider_contact(processes, monkeypatch):
    broker, _worker = processes
    config = load_identity_read_broker_config(broker)

    def wrong(_):
        raise ProductionServerCompositionError("installed source mismatch")

    def never(*_args, **_kwargs):
        raise AssertionError("provider credentials must not be used")

    monkeypatch.setattr(broker_main, "verify_installed_build_lineage", wrong)
    monkeypatch.setattr(broker_main, "CasdoorIdentityStateProvider", never)
    with pytest.raises(ProductionServerCompositionError):
        broker_main.build_identity_read_broker(config)


def test_wrong_installed_source_stops_worker_before_opening_database(processes, monkeypatch):
    _broker, worker = processes
    config = load_identity_worker_config(worker)

    def wrong(_):
        raise ProductionServerCompositionError("installed source mismatch")

    def never(*_args, **_kwargs):
        raise AssertionError("database authority must remain unopened")

    monkeypatch.setattr(worker_server, "verify_installed_build_lineage", wrong)
    monkeypatch.setattr(worker_server, "create_credential_worker_sessions", never)
    with pytest.raises(ProductionServerCompositionError):
        worker_server.build_identity_sync_server(config)


@pytest.mark.parametrize("context", [False, ssl._create_unverified_context()])
def test_provider_reader_cannot_disable_certificate_or_hostname_verification(config, context):
    with pytest.raises(ValueError, match="TLS verification"):
        CasdoorIdentityStateProvider(
            replace(config, marker_keyring=None),
            application="private-state-reader",
            tls_context=context,
        )


def test_worker_startup_does_not_print_driver_parameters_or_credentials(
    processes, monkeypatch, capsys
):
    _broker, worker = processes
    config = load_identity_worker_config(worker)
    monkeypatch.setattr(worker_main, "load_identity_worker_config", lambda: config)

    def fail(_):
        raise RuntimeError("postgresql://private:unprintable-password@db/failed")

    monkeypatch.setattr(worker_main, "build_identity_sync_server", fail)
    with pytest.raises(SystemExit) as rejected:
        worker_main.main()
    assert rejected.value.code == 1
    assert capsys.readouterr().err == "identity sync startup rejected\n"
