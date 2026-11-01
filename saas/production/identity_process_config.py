"""Separate read-broker and authenticator-worker secret surfaces and release pins."""

from __future__ import annotations

import hmac
import json
import os
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from saas.control_plane.identity_events import _unique_object
from saas.control_plane.identity_private_channel import PrivateIdentityKeys
from saas.production.credential_migration import (
    CasdoorCredentialImportConfig,
    CredentialIdentityPins,
    load_credential_identity_pins,
)
from saas.production.credential_worker_config import (
    CredentialWorkerConfig,
    load_credential_worker_config,
)
from saas.production.identity_read_broker import IdentityReadBrokerPins
from saas.production.identity_read_client import IdentityReadClientConfig
from saas.production.server_config import (
    _FULL_GIT_SHA,
    _IMAGE_DIGEST,
    ProductionServerConfigError,
    _absolute_regular_file,
    _required,
    _secret_bytes,
)

_SYNC_CONFIG = "OMNIGENT_SAAS_IDENTITY_SYNC_CONFIG_FILE"
_READER_KEYS = "OMNIGENT_SAAS_IDENTITY_READER_KEYS_FILE"
_READER_SECRET = "OMNIGENT_SAAS_IDENTITY_READER_SECRET_FILE"
_PROVIDER_CONFIG = "OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_CONFIG_FILE"
_PROVIDER_SECRET = "OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_SECRET_FILE"
_WEBHOOK_KEYS = "OMNIGENT_SAAS_CASDOOR_WEBHOOK_SECRET_FILE"
_TLS_CERT = "OMNIGENT_SAAS_IDENTITY_TLS_CERT_FILE"
_TLS_KEY = "OMNIGENT_SAAS_IDENTITY_TLS_KEY_FILE"
_DATABASE = "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE"


@dataclass(frozen=True, slots=True)
class IdentityProcessBuild:
    product_revision: str
    upstream_revision: str
    image_digest: str


@dataclass(frozen=True, slots=True)
class IdentityProcessTls:
    certificate: Path
    private_key: Path = field(repr=False)


@dataclass(frozen=True, slots=True)
class IdentityReadBrokerConfig:
    build: IdentityProcessBuild
    pins: IdentityReadBrokerPins
    provider: CasdoorCredentialImportConfig
    keys: PrivateIdentityKeys
    tls: IdentityProcessTls
    concurrency: int
    provider_application: str
    provider_tls_context: ssl.SSLContext | bool = field(default=True, repr=False)


@dataclass(frozen=True, slots=True)
class IdentityWorkerConfig:
    release: CredentialWorkerConfig
    reader: IdentityReadClientConfig
    webhook_keys: PrivateIdentityKeys
    tls: IdentityProcessTls
    concurrency: int
    reconcile_seconds: int
    poll_seconds: int


def _reject_unrelated_authority(source: Mapping[str, str], *, broker: bool) -> None:
    allowed = (
        {_PROVIDER_SECRET, _READER_KEYS, _TLS_KEY}
        if broker
        else {
            _READER_SECRET,
            _WEBHOOK_KEYS,
            _TLS_KEY,
            _DATABASE,
        }
    )
    for name, value in source.items():
        if not value.strip():
            continue
        if name in {
            "DATABASE_URL",
            "SQLALCHEMY_DATABASE_URI",
            "PGPASSWORD",
            "PGPASSFILE",
            "PGSERVICE",
            "PGOPTIONS",
        }:
            raise ProductionServerConfigError(
                "identity process received unrelated secret authority"
            )
        if name.startswith("OMNIGENT_SAAS_") and (
            (("DATABASE_URL" in name or "POSTGRES_URL" in name) and (broker or name != _DATABASE))
            or name.startswith("OMNIGENT_SAAS_CREDENTIAL_")
            or (not broker and name.startswith("OMNIGENT_SAAS_IDENTITY_BROKER_"))
            or (broker and name in {_READER_SECRET, _WEBHOOK_KEYS})
            or (
                name.endswith(
                    (
                        "_SECRET_FILE",
                        "_KEY_FILE",
                        "_KEYRING_FILE",
                        "_KEYS_FILE",
                        "_PEPPER_FILE",
                        "_CREDENTIALS_FILE",
                    )
                )
                and name not in allowed
            )
        ):
            raise ProductionServerConfigError(
                "identity process received unrelated secret authority"
            )


def _build(source: Mapping[str, str]) -> IdentityProcessBuild:
    product = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
    upstream = _required(source, "OMNIGENT_SAAS_UPSTREAM_REVISION")
    image = _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
    if (
        not _FULL_GIT_SHA.fullmatch(product)
        or not _FULL_GIT_SHA.fullmatch(upstream)
        or _required(source, "OMNIGENT_SAAS_SOURCE_SHA") != product
        or not _IMAGE_DIGEST.fullmatch(image)
    ):
        raise ProductionServerConfigError("identity process source lineage is invalid")
    return IdentityProcessBuild(product, upstream, image)


def _document(source: Mapping[str, str], name: str, *, secret: bool = False):
    path = _absolute_regular_file(_required(source, name), name=name, owner_only=secret)
    return json.loads(path.read_bytes(), object_pairs_hook=_unique_object)


def load_private_identity_keys(source: Mapping[str, str], name: str) -> PrivateIdentityKeys:
    try:
        document = _document(source, name, secret=True)
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "keys"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or not isinstance(document["keys"], dict)
        ):
            raise ValueError
        return PrivateIdentityKeys(document["keys"])
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ProductionServerConfigError(
            "private identity authentication keys are invalid"
        ) from None


def _tls(source: Mapping[str, str]) -> IdentityProcessTls:
    certificate = _absolute_regular_file(
        _required(source, _TLS_CERT), name=_TLS_CERT, owner_only=False
    )
    key = _absolute_regular_file(_required(source, _TLS_KEY), name=_TLS_KEY, owner_only=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certificate, key)
    except (OSError, ValueError):
        raise ProductionServerConfigError(
            "identity process TLS certificate/key is invalid"
        ) from None
    return IdentityProcessTls(certificate, key)


def _settings(
    source: Mapping[str, str], *, build: IdentityProcessBuild, identity: CredentialIdentityPins
):
    payload = _document(source, _SYNC_CONFIG)
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "schema_version",
            "reader_origin",
            "reader_key_id",
            "reader_ca_file",
            "provider_source_lock_sha256",
            "concurrency",
            "reconcile_seconds",
            "poll_seconds",
        }
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or any(
            not isinstance(payload[name], str)
            for name in ("reader_origin", "reader_key_id", "provider_source_lock_sha256")
        )
        or (
            payload["reader_ca_file"] is not None
            and not isinstance(payload["reader_ca_file"], str)
        )
        or any(
            type(payload[name]) is not int
            for name in ("concurrency", "reconcile_seconds", "poll_seconds")
        )
        or not 1 <= payload["concurrency"] <= 16
        or not 1 <= payload["reconcile_seconds"] <= 60
        or not 1 <= payload["poll_seconds"] <= 5
        or payload["provider_source_lock_sha256"]
        != sha256((Path(__file__).parent / "casdoor/source-lock.json").read_bytes()).hexdigest()
    ):
        raise ValueError
    pins = IdentityReadBrokerPins(
        identity.issuer,
        identity.organization,
        build.product_revision,
        payload["provider_source_lock_sha256"],
    )
    IdentityReadClientConfig(payload["reader_origin"], payload["reader_key_id"], "x" * 40, pins)
    if payload["reader_origin"] == identity.issuer:
        raise ValueError
    return payload, pins


def load_identity_read_broker_config(
    environ: Mapping[str, str] | None = None,
) -> IdentityReadBrokerConfig:
    source = os.environ if environ is None else environ
    _reject_unrelated_authority(source, broker=True)
    build = _build(source)
    try:
        identity = load_credential_identity_pins(source)
        settings, pins = _settings(source, build=build, identity=identity)
        provider_config = _document(source, _PROVIDER_CONFIG)
        if (
            not isinstance(provider_config, dict)
            or set(provider_config)
            != {"schema_version", "provider_application", "provider_client_id", "provider_ca_file"}
            or type(provider_config["schema_version"]) is not int
            or provider_config["schema_version"] != 1
            or not isinstance(provider_config["provider_client_id"], str)
            or provider_config["provider_client_id"] == identity.client_id
            or not isinstance(provider_config["provider_application"], str)
            or provider_config["provider_application"] in {"app-built-in", identity.application}
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", provider_config["provider_application"]
            )
            is None
            or (
                provider_config["provider_ca_file"] is not None
                and not isinstance(provider_config["provider_ca_file"], str)
            )
        ):
            raise ValueError
        keys = load_private_identity_keys(source, _READER_KEYS)
        secret = _secret_bytes(source, _PROVIDER_SECRET, minimum=16).decode()
        if any(hmac.compare_digest(secret, value) for value in keys.keys.values()):
            raise ValueError
        provider = CasdoorCredentialImportConfig(
            issuer=identity.issuer,
            organization=identity.organization,
            customer_application=identity.application,
            migration_client_id=provider_config["provider_client_id"],
            migration_client_secret=secret,
            source_lock_sha256=pins.provider_source_lock_sha256,
            policy_revision="identity-read-broker-v1",
        )
        context: ssl.SSLContext | bool = True
        if provider_config["provider_ca_file"] is not None:
            ca = _absolute_regular_file(
                provider_config["provider_ca_file"], name="provider CA", owner_only=False
            )
            context = ssl.create_default_context(cafile=str(ca))
        return IdentityReadBrokerConfig(
            build,
            pins,
            provider,
            keys,
            _tls(source),
            settings["concurrency"],
            provider_config["provider_application"],
            context,
        )
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ProductionServerConfigError(
            "identity read broker configuration is invalid"
        ) from None


def load_identity_worker_config(environ: Mapping[str, str] | None = None) -> IdentityWorkerConfig:
    source = os.environ if environ is None else environ
    _reject_unrelated_authority(source, broker=False)
    build = _build(source)
    try:
        release = load_credential_worker_config(source)
        settings, pins = _settings(source, build=build, identity=release.identity)
        context: ssl.SSLContext | bool = True
        if settings["reader_ca_file"] is not None:
            ca = _absolute_regular_file(
                settings["reader_ca_file"], name="identity reader CA", owner_only=False
            )
            context = ssl.create_default_context(cafile=str(ca))
        secret = _secret_bytes(source, _READER_SECRET).decode()
        webhook = load_private_identity_keys(source, _WEBHOOK_KEYS)
        if any(hmac.compare_digest(secret, value) for value in webhook.keys.values()):
            raise ValueError
        reader = IdentityReadClientConfig(
            settings["reader_origin"],
            settings["reader_key_id"],
            secret,
            pins,
            tls_context=context,
            timeout_seconds=20,
        )
        return IdentityWorkerConfig(
            release,
            reader,
            webhook,
            _tls(source),
            settings["concurrency"],
            settings["reconcile_seconds"],
            settings["poll_seconds"],
        )
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ProductionServerConfigError("identity worker configuration is invalid") from None
