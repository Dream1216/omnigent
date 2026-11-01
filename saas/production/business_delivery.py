"""Native typed receiver/follower composition; no ambient authority or import I/O."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from omnigent.stores.credential_store.vault_cipher import VaultSecretCipher
from saas.control_plane.outbox import OutboxPublishError
from saas.control_plane.outbox_delivery import (
    PlatformAuditJournalConsumer,
    UsageReconciliationConsumer,
)
from saas.control_plane.revocation import (
    NativeRevocationFollower,
    ReplicaRevocationConsumer,
    RevocationFanoutPublisher,
)
from saas.observability import current_runtime, ensure_observed_factory
from saas.production.kubernetes_runtime_provider import OpenBaoTransitReceiptAuthority
from saas.production.observability import _private, _validated_ca
from saas.production.slo_witness import S3WitnessStore


def _https(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("business delivery endpoint requires an explicit HTTPS authority")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("business delivery endpoint requires an explicit HTTPS authority")
    return value


class AuditJournalTransitSigner:
    """Existing native Transit signer, restricted to independent Audit-purpose keys."""

    algorithm = "ed25519"

    def __init__(self, config: dict) -> None:
        import hvac

        expected = {
            "address",
            "ca_file",
            "token_file",
            "mount",
            "cipher_key",
            "signing_key",
            "key_version",
            "public_key_sha256",
            "policy_name",
        }
        if (
            set(config) != expected
            or type(config["key_version"]) is not int
            or config["key_version"] < 1
        ):
            raise ValueError("Audit KMS configuration fields are invalid")
        for name in ("mount", "cipher_key", "signing_key", "policy_name"):
            if (
                not isinstance(config[name], str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", config[name]) is None
            ):
                raise ValueError("Audit KMS authority names are invalid")
        if (
            config["cipher_key"] == config["signing_key"]
            or re.fullmatch(r"[0-9a-f]{64}", config["public_key_sha256"]) is None
        ):
            raise ValueError("Audit KMS key identities are invalid")
        token = _private(config["token_file"], 16384).decode("ascii")
        if not token or any(ord(c) < 33 for c in token) or token != token.strip():
            raise ValueError("Audit KMS identity file is invalid")
        self.client = hvac.Client(
            url=_https(config["address"]),
            token=token,
            verify=_validated_ca(config["ca_file"]),
            timeout=6,
        )
        identity = self.client.auth.token.lookup_self()["data"]
        if (
            identity["policies"] != [config["policy_name"]]
            or identity.get("meta", {}).get("purpose") != "platform-audit-journal"
        ):
            raise ValueError("Audit KMS requires its independent purpose-bound identity")
        encryption = self.client.secrets.transit.read_key(
            config["cipher_key"], mount_point=config["mount"]
        )["data"]
        signing = self.client.secrets.transit.read_key(
            config["signing_key"], mount_point=config["mount"]
        )["data"]
        if (
            encryption.get("type") != "aes256-gcm96"
            or encryption.get("derived") is not True
            or encryption.get("exportable") is not False
            or encryption.get("allow_plaintext_backup") is not False
        ):
            raise ValueError("Audit cipher key must be derived and nonexportable")
        if (
            signing.get("type") != "ed25519"
            or signing.get("derived") is not False
            or signing.get("exportable") is not False
            or signing.get("allow_plaintext_backup") is not False
        ):
            raise ValueError("Audit signing key must be nonexportable Ed25519")
        public = base64.b64decode(
            signing["keys"][str(config["key_version"])]["public_key"], validate=True
        )
        if len(public) != 32 or hashlib.sha256(public).hexdigest() != config["public_key_sha256"]:
            raise ValueError("Audit signing public identity changed")
        client = self.client

        class BoundAuthority(OpenBaoTransitReceiptAuthority):
            def _client(self):
                return client

        self._authority = BoundAuthority(
            address=config["address"],
            ca_file=Path(config["ca_file"]),
            token_file=Path(config["token_file"]),
            mount_point=config["mount"],
            key_name=config["signing_key"],
            key_version=config["key_version"],
        )
        self.key_id = self._authority.signature_key_id
        self.cipher = VaultSecretCipher(
            config["cipher_key"], mount_point=config["mount"], client=client
        )

    def sign(self, content_hash: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", content_hash) is None:
            raise ValueError("Audit content hash is invalid")
        return self._authority.sign(content_hash.encode())

    def verify(self, content_hash: str, signature: str) -> bool:
        if re.fullmatch(r"[0-9a-f]{64}", content_hash) is None:
            return False
        return self._authority.verify_signature(content_hash.encode(), signature)

    def close(self) -> None:
        self.client.adapter.close()


def _audit_destination(config: dict):
    import boto3
    from botocore.config import Config

    if (
        set(config)
        != {
            "endpoint",
            "bucket",
            "prefix",
            "ca_file",
            "credentials_file",
            "retention_days",
            "maximum_body_bytes",
        }
        or config["prefix"] != "platform-audit-journal"
    ):
        raise ValueError("Audit journal storage configuration is invalid")
    credentials = json.loads(_private(config["credentials_file"], 16384))
    if set(credentials) not in (
        {"access_key", "secret_key"},
        {"access_key", "secret_key", "session_token"},
    ) or any(not isinstance(v, str) or not v for v in credentials.values()):
        raise ValueError("Audit journal requires its explicit storage profile")
    client = boto3.client(
        "s3",
        endpoint_url=_https(config["endpoint"]),
        verify=_validated_ca(config["ca_file"]),
        region_name="us-east-1",
        aws_access_key_id=credentials["access_key"],
        aws_secret_access_key=credentials["secret_key"],
        aws_session_token=credentials.get("session_token"),
        config=Config(
            signature_version="s3v4",
            connect_timeout=2,
            read_timeout=3,
            retries={"total_max_attempts": 1},
            proxies={},
            s3={"addressing_style": "path"},
        ),
    )
    try:
        store = S3WitnessStore(
            client,
            bucket=config["bucket"],
            prefix=config["prefix"],
            retention_days=config["retention_days"],
            maximum_body_bytes=config["maximum_body_bytes"],
        )
        store.preflight()
        return client, store
    except BaseException:
        client.close()
        raise


class BusinessDeliveryPublisher:
    """Only the five original typed business routes; unsupported events remain unclaimed."""

    def __init__(self, usage, audit, revocation, *, engines, signer, storage_client):
        self._consumers = (usage, audit, revocation)
        self.claim_routes = tuple(route for c in self._consumers for route in c.claim_routes)
        self._engines, self._signer, self._storage_client = engines, signer, storage_client
        if len(set(self.claim_routes)) != 5:
            raise ValueError("typed business delivery requires its exact five unique routes")

    def publish(self, **event):
        for consumer in self._consumers:
            if any(
                route.aggregate_type == event["aggregate_type"]
                and route.event_type == event["event_type"]
                for route in consumer.claim_routes
            ):
                consumer.publish(**event)
                return
        raise OutboxPublishError(
            "unsupported_business_route", retryable=False, pre_side_effect=True
        )

    def close(self):
        try:
            self._signer.close()
        finally:
            self._storage_client.close()
            for engine in self._engines.values():
                engine.dispose()


def create_business_delivery_publisher():
    """Generic worker plugin; every enabled LOGIN uses the native receipt verifier."""
    from omnigent import _build_info
    from saas.production.postgresql_migration import verify_business_delivery_postgresql_state
    from saas.production.server_config import (
        load_production_database_url_file,
        load_production_migration_receipt,
    )
    from saas.production.service_bindings import (
        EXPECTED_BUSINESS_DELIVERY_SERVICE_ROLES,
        load_production_service_role_bindings,
        load_production_service_role_graph,
    )

    config = json.loads(_private(os.environ["OMNIGENT_SAAS_BUSINESS_DELIVERY_CONFIG_FILE"], 65536))
    if (
        set(config)
        != {
            "schema_version",
            "purpose",
            "product_revision",
            "official_head",
            "saas_head",
            "kms",
            "storage",
        }
        or config["schema_version"] != 1
        or config["purpose"] != "platform-audit-journal"
        or config["product_revision"] != _build_info.COMMIT_SHA
        or config["official_head"] != "nf12ab34cd56"
        or config["saas_head"] != "p0s000000018"
    ):
        raise ValueError("typed business delivery configuration/product lineage is invalid")
    core = load_production_service_role_bindings(os.environ)
    graph = load_production_service_role_graph(os.environ, production=core)
    receipt = load_production_migration_receipt(
        os.environ,
        product_revision=config["product_revision"],
        official_head=config["official_head"],
        saas_head=config["saas_head"],
        service_role_bindings_sha256=core.sha256,
        service_role_graph_sha256=graph.sha256,
    )
    runtime_config = SimpleNamespace(
        product_revision=config["product_revision"],
        official_schema_revision=config["official_head"],
        control_plane_schema_revision=config["saas_head"],
        service_role_bindings=core,
        service_role_graph=graph,
        migration_receipt=receipt,
    )
    urls = {
        role: load_production_database_url_file(os.environ, role)[0]
        for role in EXPECTED_BUSINESS_DELIVERY_SERVICE_ROLES
    }
    engines = {}
    signer = None
    client = None
    try:
        for role, url in urls.items():
            parsed = sa.make_url(url)
            if role == "revocation_consumer":
                parsed = parsed.update_query_dict({"application_name": "saas-revocation-worker"})
            engines[role] = sa.create_engine(parsed, pool_pre_ping=True)
        verify_business_delivery_postgresql_state(
            engines=engines, database_urls=urls, config=runtime_config
        )
        factories = {
            role: sessionmaker(engine, expire_on_commit=False) for role, engine in engines.items()
        }
        for factory in factories.values():
            ensure_observed_factory(factory)
        runtime = current_runtime()
        metrics = None if runtime is None else runtime.metrics
        signer = AuditJournalTransitSigner(config["kms"])
        client, store = _audit_destination(config["storage"])
        product = config["product_revision"]
        return BusinessDeliveryPublisher(
            UsageReconciliationConsumer(
                factories["usage_consumer"], product_revision=product, metrics=metrics
            ),
            PlatformAuditJournalConsumer(
                factories["audit_delivery"],
                store,
                signer.cipher,
                signer,
                product_revision=product,
                metrics=metrics,
            ),
            RevocationFanoutPublisher(factories["revocation_consumer"], product_revision=product),
            engines=engines,
            signer=signer,
            storage_client=client,
        )
    except BaseException:
        if signer is not None:
            signer.close()
        if client is not None:
            client.close()
        for engine in engines.values():
            engine.dispose()
        raise


def start_revocation_follower(factory, cache, *, product_revision: str, pod_uid: str):
    """Own a dedicated LISTEN connection; every start/reconnect needs actual apply."""
    import psycopg

    replica_uid = UUID(pod_uid)
    if str(replica_uid) != pod_uid:
        raise ValueError("native invalidation requires the canonical actual Pod UID")
    engine = factory.kw["bind"]
    if engine.dialect.name != "postgresql":
        raise ValueError("native invalidation requires its dedicated PostgreSQL authority")
    ensure_observed_factory(factory)
    runtime = current_runtime()
    consumer = ReplicaRevocationConsumer(
        factory,
        cache,
        product_revision=product_revision,
        replica_uid=replica_uid,
        metrics=None if runtime is None else runtime.metrics,
    )
    args, kwargs = engine.dialect.create_connect_args(engine.url)
    kwargs["connect_timeout"] = 2

    def connect():
        return psycopg.connect(*args, **kwargs, autocommit=True)

    follower = NativeRevocationFollower(consumer, connect)
    follower.start()
    return follower
