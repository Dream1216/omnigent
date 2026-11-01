from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from saas.production.identity_process_config import (
    load_identity_read_broker_config,
    load_identity_worker_config,
)
from saas.production.server_config import ProductionServerConfigError
from tests.saas.test_credential_worker_config import minimal_environment

READER_SECRET = "dedicated-reader-" + "r" * 40
PROVIDER_SECRET = "provider-administration-" + "p" * 40
WEBHOOK_SECRET = "independent-webhook-" + "w" * 40


def write(path, value, *, private=False):
    path.write_text(value if isinstance(value, str) else json.dumps(value))
    path.chmod(0o600 if private else 0o644)
    return str(path)


def certificate(tmp_path, *, loopback=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "identity-reader.example.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("identity-reader.example.test"),
                    *([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))] if loopback else []),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = tmp_path / "tls.key", tmp_path / "tls.crt"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert_path.chmod(0o644)
    return str(cert_path), str(key_path)


@pytest.fixture
def processes(tmp_path):
    worker = minimal_environment(tmp_path)
    common = {
        k: v
        for k, v in worker.items()
        if k
        in {
            "OMNIGENT_SAAS_PRODUCT_REVISION",
            "OMNIGENT_SAAS_UPSTREAM_REVISION",
            "OMNIGENT_SAAS_SOURCE_SHA",
            "OMNIGENT_SAAS_IMAGE_DIGEST",
            "OMNIGENT_SAAS_CASDOOR_CONFIG_FILE",
        }
    }
    common["OMNIGENT_SAAS_IDENTITY_SYNC_CONFIG_FILE"] = write(
        tmp_path / "identity-sync.json",
        {
            "schema_version": 1,
            "reader_origin": "https://identity-reader.example.test",
            "reader_key_id": "current",
            "reader_ca_file": None,
            "provider_source_lock_sha256": sha256(
                Path("saas/production/casdoor/source-lock.json").read_bytes()
            ).hexdigest(),
            "concurrency": 4,
            "reconcile_seconds": 60,
            "poll_seconds": 1,
        },
    )
    cert, key = certificate(tmp_path)
    common["OMNIGENT_SAAS_IDENTITY_TLS_CERT_FILE"] = cert
    common["OMNIGENT_SAAS_IDENTITY_TLS_KEY_FILE"] = key
    broker = dict(common)
    broker["OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_CONFIG_FILE"] = write(
        tmp_path / "broker-provider.json",
        {
            "schema_version": 1,
            "provider_application": "private-state-reader",
            "provider_client_id": "dedicated-broker-admin-client",
            "provider_ca_file": None,
        },
    )
    broker["OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_SECRET_FILE"] = write(
        tmp_path / "provider.secret", PROVIDER_SECRET, private=True
    )
    broker["OMNIGENT_SAAS_IDENTITY_READER_KEYS_FILE"] = write(
        tmp_path / "reader-keys.json",
        {
            "schema_version": 1,
            "keys": {"current": READER_SECRET, "previous": "previous-" + "r" * 40},
        },
        private=True,
    )
    worker.update(common)
    worker["OMNIGENT_SAAS_IDENTITY_READER_SECRET_FILE"] = write(
        tmp_path / "reader.secret", READER_SECRET, private=True
    )
    worker["OMNIGENT_SAAS_CASDOOR_WEBHOOK_SECRET_FILE"] = write(
        tmp_path / "webhook-keys.json",
        {
            "schema_version": 1,
            "keys": {"current": WEBHOOK_SECRET},
        },
        private=True,
    )
    return broker, worker


def test_processes_load_separate_credential_surfaces_and_no_disabled_tls_or_import_keys(processes):
    broker, worker = processes
    a = load_identity_read_broker_config(broker)
    b = load_identity_worker_config(worker)
    assert a.provider.marker_keyring is None
    assert a.provider.migration_client_secret == PROVIDER_SECRET
    assert b.reader.secret == READER_SECRET and b.webhook_keys.keys["current"] == WEBHOOK_SECRET
    assert not hasattr(a, "database_url") and not hasattr(a, "release")
    assert not hasattr(b, "provider")
    assert b.release.service_role_graph.login_for("authenticator") == "authenticator_login"
    assert a.pins == b.reader.pins and a.concurrency == b.concurrency == 4
    assert b.reconcile_seconds == 60 and b.poll_seconds == 1
    assert all(
        secret not in repr(a) + repr(b)
        for secret in (PROVIDER_SECRET, READER_SECRET, WEBHOOK_SECRET)
    )
    assert "postgresql" not in repr(b)


@pytest.mark.parametrize(
    "name",
    [
        "DATABASE_URL",
        "PGPASSWORD",
        "PGOPTIONS",
        "SQLALCHEMY_DATABASE_URI",
        "OMNIGENT_SAAS_TEST_POSTGRES_URL",
        "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_CASDOOR_CLIENT_SECRET_FILE",
        "OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE",
        "OMNIGENT_SAAS_CASDOOR_WEBHOOK_SECRET_FILE",
        "OMNIGENT_SAAS_IDENTITY_READER_SECRET_FILE",
        "OMNIGENT_SAAS_CREDENTIAL_IMPORT_MARKER_KEYRING_FILE",
    ],
)
def test_broker_rejects_every_product_database_and_unrelated_secret_before_reading(
    processes, name
):
    broker, _worker = processes
    broker[name] = "/never-read/unrelated-authority"
    with pytest.raises(ProductionServerConfigError, match="unrelated secret authority"):
        load_identity_read_broker_config(broker)


@pytest.mark.parametrize(
    "name",
    [
        "OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_CONFIG_FILE",
        "OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_SECRET_FILE",
        "OMNIGENT_SAAS_IDENTITY_READER_KEYS_FILE",
        "OMNIGENT_SAAS_CREDENTIAL_IMPORT_CONFIG_FILE",
        "OMNIGENT_SAAS_CREDENTIAL_RECOVERY_PUBLIC_KEYS_FILE",
        "OMNIGENT_SAAS_CASDOOR_CLIENT_SECRET_FILE",
        "OMNIGENT_SAAS_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_OIDC_TRANSACTION_KEY_FILE",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE",
    ],
)
def test_worker_rejects_provider_administration_import_recovery_web_and_other_db_authority(
    processes, name
):
    _broker, worker = processes
    worker[name] = "/never-read/unrelated-authority"
    with pytest.raises(ProductionServerConfigError, match="unrelated secret authority"):
        load_identity_worker_config(worker)


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"concurrency": 17},
        {"concurrency": True},
        {"poll_seconds": 6},
        {"reconcile_seconds": 61},
        {"provider_source_lock_sha256": "e" * 64},
        {"reader_origin": "http://identity-reader.example.test"},
        {"reader_origin": "https://auth.example.test"},
        {"reader_origin": "https://identity-reader.example.test/extra"},
        {"unexpected": "authority"},
    ],
)
def test_both_processes_reject_drift_and_unbounded_common_configuration(processes, change):
    broker, worker = processes
    path = Path(broker["OMNIGENT_SAAS_IDENTITY_SYNC_CONFIG_FILE"])
    document = json.loads(path.read_text())
    document.update(change)
    path.write_text(json.dumps(document))
    for loader, source in (
        (load_identity_read_broker_config, broker),
        (load_identity_worker_config, worker),
    ):
        with pytest.raises(ProductionServerConfigError):
            loader(source)


def test_broker_does_not_reuse_web_application_or_reader_secret_as_provider_authority(processes):
    broker, _worker = processes
    config = Path(broker["OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_CONFIG_FILE"])
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider_application": "private-state-reader",
                "provider_client_id": "public-oidc-client",
                "provider_ca_file": None,
            }
        )
    )
    with pytest.raises(ProductionServerConfigError):
        load_identity_read_broker_config(broker)
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider_application": "private-state-reader",
                "provider_client_id": "dedicated-broker-admin-client",
                "provider_ca_file": None,
            }
        )
    )
    Path(broker["OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_SECRET_FILE"]).write_text(READER_SECRET)
    with pytest.raises(ProductionServerConfigError):
        load_identity_read_broker_config(broker)


def test_worker_requires_independent_reader_and_webhook_keys(processes):
    _broker, worker = processes
    Path(worker["OMNIGENT_SAAS_IDENTITY_READER_SECRET_FILE"]).write_text(WEBHOOK_SECRET)
    with pytest.raises(ProductionServerConfigError):
        load_identity_worker_config(worker)


@pytest.mark.parametrize("process", ["broker", "worker"])
def test_private_keys_cannot_be_world_readable_or_symlinked(processes, process):
    broker, worker = processes
    source, loader = (
        (broker, load_identity_read_broker_config)
        if process == "broker"
        else (worker, load_identity_worker_config)
    )
    path = Path(source["OMNIGENT_SAAS_IDENTITY_TLS_KEY_FILE"])
    path.chmod(0o644)
    with pytest.raises(ProductionServerConfigError):
        loader(source)
    path.chmod(0o600)
    link = path.with_name("tls-link.key")
    link.symlink_to(path)
    source["OMNIGENT_SAAS_IDENTITY_TLS_KEY_FILE"] = str(link)
    with pytest.raises(ProductionServerConfigError):
        loader(source)


def test_wrong_tls_pair_missing_reader_ca_and_duplicate_json_keys_stop_startup(processes):
    broker, worker = processes
    key = Path(broker["OMNIGENT_SAAS_IDENTITY_TLS_KEY_FILE"])
    original = key.read_bytes()
    key.write_text("not a private key")
    with pytest.raises(ProductionServerConfigError):
        load_identity_read_broker_config(broker)
    key.write_bytes(original)
    path = Path(worker["OMNIGENT_SAAS_IDENTITY_SYNC_CONFIG_FILE"])
    document = json.loads(path.read_text())
    document["reader_ca_file"] = "/missing/ca.crt"
    path.write_text(json.dumps(document))
    with pytest.raises(ProductionServerConfigError):
        load_identity_worker_config(worker)
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ProductionServerConfigError):
        load_identity_read_broker_config(broker)


def test_lineage_mismatch_is_refused_by_both_processes(processes):
    broker, worker = processes
    for loader, source in (
        (load_identity_read_broker_config, broker),
        (load_identity_worker_config, worker),
    ):
        source["OMNIGENT_SAAS_SOURCE_SHA"] = "0" * 40
        with pytest.raises(ProductionServerConfigError, match="lineage"):
            loader(source)
