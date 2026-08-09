from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    ControlPlaneOutboxEvent,
    PreviewGatewayCertificateAuthority,
    PreviewGatewayCertificateRecord,
    PreviewGatewayDirectoryAuthority,
    PreviewGatewayInstanceRecord,
    PreviewGatewayLifecycleError,
    SaasBase,
)
from saas.preview_gateway_runtime import (
    PreviewGatewayRuntime,
    PreviewGatewayRuntimeCertificateSet,
    PreviewGatewayRuntimeConfig,
    PreviewGatewayRuntimeError,
    PreviewGatewayRuntimeLeaf,
    run_preview_gateway_runtime,
)


def _leaf(
    gateway_instance_id: str,
    *,
    purpose: str,
    now: datetime,
    not_after: datetime,
    serial: int,
    server_name: str = "localhost",
) -> PreviewGatewayRuntimeLeaf:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(f"spiffe://omnigent/preview-gateway/{gateway_instance_id}")
    ]
    eku = (
        ExtendedKeyUsageOID.CLIENT_AUTH
        if purpose == "preview_relay_client"
        else ExtendedKeyUsageOID.SERVER_AUTH
    )
    if purpose == "preview_relay_server":
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(server_name)))
        except ValueError:
            sans.append(x509.DNSName(server_name))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gateway")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Runtime CA")]))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return PreviewGatewayRuntimeLeaf(
        purpose=purpose,
        certificate_der=certificate.public_bytes(serialization.Encoding.DER),
        trust_bundle_version="bundle-v1",
        not_after=not_after,
    )


def _certificate_set(
    gateway_instance_id: str,
    *,
    now: datetime,
    not_after: datetime,
    generation: int,
) -> PreviewGatewayRuntimeCertificateSet:
    return PreviewGatewayRuntimeCertificateSet(
        client=_leaf(
            gateway_instance_id,
            purpose="preview_relay_client",
            now=now,
            not_after=not_after,
            serial=generation * 2 + 1,
        ),
        server=_leaf(
            gateway_instance_id,
            purpose="preview_relay_server",
            now=now,
            not_after=not_after,
            serial=generation * 2 + 2,
        ),
    )


class _Provider:
    def __init__(
        self,
        gateway_instance_id: str,
        *,
        now: datetime,
        first_not_after: datetime,
    ) -> None:
        self.gateway_instance_id = gateway_instance_id
        self.now = now
        self.first_not_after = first_not_after
        self.prepared = 0
        self.installed: list[PreviewGatewayRuntimeCertificateSet] = []
        self.discarded: list[PreviewGatewayRuntimeCertificateSet] = []

    async def prepare(
        self, *, gateway_instance_id: str, server_name: str
    ) -> PreviewGatewayRuntimeCertificateSet:
        assert gateway_instance_id == self.gateway_instance_id
        assert server_name == "localhost"
        self.prepared += 1
        not_after = (
            self.first_not_after
            if self.prepared == 1
            else self.now + timedelta(hours=1 + self.prepared)
        )
        return _certificate_set(
            gateway_instance_id,
            now=self.now,
            not_after=not_after,
            generation=self.prepared,
        )

    async def install(self, certificates: PreviewGatewayRuntimeCertificateSet) -> None:
        self.installed.append(certificates)

    async def discard(self, certificates: PreviewGatewayRuntimeCertificateSet) -> None:
        self.discarded.append(certificates)


class _RelayServer:
    def __init__(self, factory: sessionmaker[Session], gateway_instance_id: str) -> None:
        self._factory = factory
        self._gateway_instance_id = gateway_instance_id
        self.started = False
        self.closed = False
        self.observed_registration_before_bind = False

    @property
    def port(self) -> int:
        if not self.started:
            raise RuntimeError("not started")
        return 9443

    async def start(self, *, host: str, port: int) -> None:
        assert (host, port) == ("127.0.0.1", 0)
        with self._factory() as db:
            self.observed_registration_before_bind = (
                db.get(PreviewGatewayInstanceRecord, self._gateway_instance_id) is not None
            )
        self.started = True

    async def aclose(self) -> None:
        self.closed = True
        self.started = False


class _Readiness:
    def __init__(self, directory: PreviewGatewayDirectoryAuthority, *, fail: bool = False) -> None:
        self._directory = directory
        self._fail = fail
        self.calls = 0

    async def verify(self, **values: object) -> None:
        self.calls += 1
        gateway_instance_id = values["gateway_instance_id"]
        assert isinstance(gateway_instance_id, str)
        assert (
            values["connect_host"],
            values["connect_port"],
            values["server_name"],
        ) == ("127.0.0.1", 9443, "localhost")
        placement = type("Placement", (), {"gateway_instance_id": gateway_instance_id})()
        with pytest.raises(PreviewGatewayLifecycleError) as not_routable:
            self._directory.resolve(placement)
        assert not_routable.value.code == "preview_gateway_route_unavailable"
        if self._fail:
            raise RuntimeError("probe failure")


class _BlockingReadiness(_Readiness):
    def __init__(self, directory: PreviewGatewayDirectoryAuthority) -> None:
        super().__init__(directory)
        self.started = asyncio.Event()

    async def verify(self, **values: object) -> None:
        await super().verify(**values)
        self.started.set()
        await asyncio.Event().wait()


class _DrainObserver:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory
        self.calls = 0

    async def wait_until_drained(
        self, *, gateway_instance_id: str, timeout_seconds: float
    ) -> bool:
        self.calls += 1
        assert timeout_seconds > 0
        with self._factory() as db:
            record = db.get(PreviewGatewayInstanceRecord, gateway_instance_id)
            assert record is not None and record.status == "draining"
        return True


class _HeartbeatFailureDirectory:
    def __init__(
        self,
        delegate: PreviewGatewayDirectoryAuthority,
        *,
        registration_delay: float = 0,
    ) -> None:
        self._delegate = delegate
        self._registration_delay = registration_delay

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)

    def register_gateway(self, **values: object):
        registered = self._delegate.register_gateway(**values)  # type: ignore[arg-type]
        time.sleep(self._registration_delay)
        return registered

    def heartbeat_gateway(self, **_values: object):
        raise RuntimeError("database heartbeat failed")


class _SecondCertificateFailureAuthority:
    def __init__(self, delegate: PreviewGatewayCertificateAuthority) -> None:
        self._delegate = delegate

    def activate_certificate(self, **values: object):
        if values["purpose"] == "preview_relay_server":
            raise RuntimeError("server certificate activation failed")
        return self._delegate.activate_certificate(**values)  # type: ignore[arg-type]

    def revoke_certificate(self, **values: object):
        return self._delegate.revoke_certificate(**values)  # type: ignore[arg-type]


@pytest.fixture
def runtime_fixture():
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    directory = PreviewGatewayDirectoryAuthority(factory, service_session_factory=factory)
    certificates = PreviewGatewayCertificateAuthority(
        factory,
        accepted_trust_bundle_versions=("bundle-v1",),
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    yield engine, factory, directory, certificates, now
    engine.dispose()


def _config(gateway_instance_id: str, **changes: object) -> PreviewGatewayRuntimeConfig:
    values: dict[str, object] = {
        "gateway_instance_id": gateway_instance_id,
        "registration_token": f"runtime-token-{gateway_instance_id}-" + "x" * 40,
        "bind_host": "127.0.0.1",
        "bind_port": 0,
        "connect_host": "127.0.0.1",
        "server_name": "localhost",
        "failure_domain": "cn-east-1a",
        "source_revision": "runtime-revision",
        "adapter_contract_version": "0.2.0",
        "lease_duration": timedelta(seconds=3),
        "heartbeat_interval": timedelta(seconds=1),
        "renewal_before": timedelta(minutes=10),
        "rotation_overlap": timedelta(minutes=5),
        "readiness_timeout": timedelta(seconds=1),
        "drain_timeout": timedelta(seconds=1),
    }
    values.update(changes)
    return PreviewGatewayRuntimeConfig(**values)  # type: ignore[arg-type]


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for runtime acceptance")
    return value


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _role_factory(engine: sa.Engine, role: str) -> sessionmaker[Session]:
    factory = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(factory, "after_begin")
    def _bind_role(
        _session: Session,
        _transaction: object,
        connection: sa.Connection,
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")

    return factory


def test_runtime_leaf_rejects_declared_expiry_that_does_not_match_der() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    leaf = _leaf(
        "gateway-runtime-metadata",
        purpose="preview_relay_client",
        now=now,
        not_after=now + timedelta(hours=1),
        serial=101,
    )

    with pytest.raises(ValueError, match="runtime leaf is invalid"):
        PreviewGatewayRuntimeLeaf(
            purpose=leaf.purpose,
            certificate_der=leaf.certificate_der,
            trust_bundle_version=leaf.trust_bundle_version,
            not_after=leaf.not_after + timedelta(seconds=1),
        )


@pytest.mark.asyncio
async def test_runtime_binds_before_registration_activates_after_certificates_and_drains(
    runtime_fixture,
) -> None:
    _, factory, directory, authority, now = runtime_fixture
    gateway_id = "gateway-runtime-a"
    provider = _Provider(
        gateway_id,
        now=now,
        first_not_after=now + timedelta(hours=1),
    )
    relay = _RelayServer(factory, gateway_id)
    readiness = _Readiness(directory)
    drain = _DrainObserver(factory)
    runtime = PreviewGatewayRuntime(
        _config(gateway_id),
        directory=directory,
        certificate_authority=authority,
        certificate_provider=provider,
        relay_server=relay,
        readiness_probe=readiness,
        drain_observer=drain,
        clock=lambda: now,
    )

    await runtime.start()
    assert runtime.state == "active" and runtime.ready
    assert not relay.observed_registration_before_bind
    assert readiness.calls == 1 and len(provider.installed) == 1
    with factory() as db:
        record = db.get(PreviewGatewayInstanceRecord, gateway_id)
        assert record is not None
        assert record.status == "active" and record.activated_at is not None

    assert await runtime.aclose(reason="test_shutdown")
    assert runtime.state == "stopped" and not runtime.ready
    assert relay.closed and drain.calls == 1 and len(provider.discarded) == 1
    with factory() as db:
        record = db.get(PreviewGatewayInstanceRecord, gateway_id)
        assert record is not None and record.status == "released"
        assert record.activated_at is not None
        certificate_statuses = set(
            db.scalars(
                sa.select(PreviewGatewayCertificateRecord.status).where(
                    PreviewGatewayCertificateRecord.gateway_instance_id == gateway_id
                )
            )
        )
        assert certificate_statuses == {"revoked"}
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent.event_type).where(
                    ControlPlaneOutboxEvent.aggregate_key == gateway_id
                )
            )
        )
        assert len(events) == 4
        assert set(events) == {
            "preview.gateway.registered",
            "preview.gateway.activated",
            "preview.gateway.draining",
            "preview.gateway.released",
        }


@pytest.mark.asyncio
async def test_runtime_revokes_partial_certificate_pair_before_releasing_startup_identity(
    runtime_fixture,
) -> None:
    _, factory, directory, authority, now = runtime_fixture
    gateway_id = "gateway-runtime-cert-pair-fail"
    provider = _Provider(
        gateway_id,
        now=now,
        first_not_after=now + timedelta(hours=1),
    )
    runtime = PreviewGatewayRuntime(
        _config(gateway_id),
        directory=directory,
        certificate_authority=_SecondCertificateFailureAuthority(authority),  # type: ignore[arg-type]
        certificate_provider=provider,
        relay_server=_RelayServer(factory, gateway_id),
        readiness_probe=_Readiness(directory),
        drain_observer=_DrainObserver(factory),
        clock=lambda: now,
    )

    with pytest.raises(PreviewGatewayRuntimeError):
        await runtime.start()
    with factory() as db:
        gateway = db.get(PreviewGatewayInstanceRecord, gateway_id)
        assert gateway is not None and gateway.status == "released"
        certificates = list(
            db.scalars(
                sa.select(PreviewGatewayCertificateRecord).where(
                    PreviewGatewayCertificateRecord.gateway_instance_id == gateway_id
                )
            )
        )
        assert len(certificates) == 1 and certificates[0].status == "revoked"
    assert len(provider.discarded) == 1


@pytest.mark.asyncio
async def test_runtime_readiness_failure_closes_listener_and_releases_startup_identity(
    runtime_fixture,
) -> None:
    _, factory, directory, authority, now = runtime_fixture
    gateway_id = "gateway-runtime-probe-fail"
    provider = _Provider(
        gateway_id,
        now=now,
        first_not_after=now + timedelta(hours=1),
    )
    relay = _RelayServer(factory, gateway_id)
    runtime = PreviewGatewayRuntime(
        _config(gateway_id),
        directory=directory,
        certificate_authority=authority,
        certificate_provider=provider,
        relay_server=relay,
        readiness_probe=_Readiness(directory, fail=True),
        drain_observer=_DrainObserver(factory),
        clock=lambda: now,
    )

    with pytest.raises(PreviewGatewayRuntimeError) as failed:
        await runtime.start()
    assert failed.value.code == "preview_gateway_runtime_start_failed"
    assert runtime.state == "failed" and not runtime.ready and relay.closed
    with factory() as db:
        record = db.get(PreviewGatewayInstanceRecord, gateway_id)
        assert record is not None and record.status == "released"
        assert record.activated_at is None
        certificate_statuses = set(
            db.scalars(
                sa.select(PreviewGatewayCertificateRecord.status).where(
                    PreviewGatewayCertificateRecord.gateway_instance_id == gateway_id
                )
            )
        )
        assert certificate_statuses == {"revoked"}
    assert provider.discarded == provider.installed


@pytest.mark.asyncio
async def test_process_signal_during_startup_releases_identity_certificates_and_listener(
    runtime_fixture,
) -> None:
    _, factory, directory, authority, now = runtime_fixture
    gateway_id = "gateway-runtime-startup-signal"
    provider = _Provider(
        gateway_id,
        now=now,
        first_not_after=now + timedelta(hours=1),
    )
    relay = _RelayServer(factory, gateway_id)
    readiness = _BlockingReadiness(directory)
    runtime = PreviewGatewayRuntime(
        _config(gateway_id),
        directory=directory,
        certificate_authority=authority,
        certificate_provider=provider,
        relay_server=relay,
        readiness_probe=readiness,
        drain_observer=_DrainObserver(factory),
        clock=lambda: now,
    )
    stop = asyncio.Event()
    process = asyncio.create_task(run_preview_gateway_runtime(runtime, stop_event=stop))
    await asyncio.wait_for(readiness.started.wait(), timeout=1)

    stop.set()
    await asyncio.wait_for(process, timeout=2)

    assert runtime.state == "stopped" and not runtime.ready
    assert relay.closed and provider.discarded == provider.installed
    with factory() as db:
        gateway = db.get(PreviewGatewayInstanceRecord, gateway_id)
        assert gateway is not None and gateway.status == "released"
        statuses = set(
            db.scalars(
                sa.select(PreviewGatewayCertificateRecord.status).where(
                    PreviewGatewayCertificateRecord.gateway_instance_id == gateway_id
                )
            )
        )
        assert statuses == {"revoked"}


@pytest.mark.asyncio
async def test_runtime_renews_both_leaves_before_expiry(runtime_fixture) -> None:
    _, factory, directory, authority, now = runtime_fixture
    gateway_id = "gateway-runtime-renew"
    clock = [now]
    provider = _Provider(
        gateway_id,
        now=now,
        first_not_after=now + timedelta(seconds=20),
    )
    runtime = PreviewGatewayRuntime(
        _config(
            gateway_id,
            # This test advances the authoritative clock by ten seconds to force
            # certificate renewal; keep the unrelated gateway lease valid.
            lease_duration=timedelta(seconds=30),
            heartbeat_interval=timedelta(milliseconds=50),
            renewal_before=timedelta(seconds=15),
            rotation_overlap=timedelta(seconds=5),
        ),
        directory=directory,
        certificate_authority=authority,
        certificate_provider=provider,
        relay_server=_RelayServer(factory, gateway_id),
        readiness_probe=_Readiness(directory),
        drain_observer=_DrainObserver(factory),
        clock=lambda: clock[0],
    )
    await runtime.start()
    clock[0] = now + timedelta(seconds=10)
    for _ in range(50):
        if len(provider.installed) >= 2:
            break
        await asyncio.sleep(0.02)
    assert len(provider.installed) == 2
    with factory() as db:
        generations = list(
            db.execute(
                sa.text(
                    "SELECT purpose, max(rotation_generation) "
                    "FROM saas_preview_gateway_certificates GROUP BY purpose"
                )
            )
        )
        assert set(generations) == {
            ("preview_relay_client", 2),
            ("preview_relay_server", 2),
        }
    await runtime.aclose(reason="renewal_test_complete")


@pytest.mark.asyncio
async def test_runtime_heartbeat_failure_removes_readiness_and_closes_listener(
    runtime_fixture,
) -> None:
    _, factory, directory, authority, now = runtime_fixture
    gateway_id = "gateway-runtime-heartbeat-fail"
    provider = _Provider(
        gateway_id,
        now=now,
        first_not_after=now + timedelta(hours=1),
    )
    relay = _RelayServer(factory, gateway_id)
    # The logical authority clock is deliberately fixed while real scheduling is
    # delayed beyond the tiny lease. Runtime must never mix this injected clock
    # with wall-clock calls in Directory or Certificate Authority operations.
    failing_directory = _HeartbeatFailureDirectory(directory, registration_delay=0.35)
    runtime = PreviewGatewayRuntime(
        _config(
            gateway_id,
            lease_duration=timedelta(milliseconds=300),
            heartbeat_interval=timedelta(milliseconds=50),
        ),
        directory=failing_directory,  # type: ignore[arg-type]
        certificate_authority=authority,
        certificate_provider=provider,
        relay_server=relay,
        readiness_probe=_Readiness(directory),
        drain_observer=_DrainObserver(factory),
        clock=lambda: now,
    )
    await runtime.start()
    with pytest.raises(PreviewGatewayRuntimeError) as stopped:
        await asyncio.wait_for(runtime.wait(), timeout=2)
    assert stopped.value.code == "preview_gateway_runtime_failed"
    assert runtime.state == "failed" and not runtime.ready and relay.closed
    with factory() as db:
        record = db.get(PreviewGatewayInstanceRecord, gateway_id)
        assert record is not None and record.status == "released"


@pytest.mark.asyncio
async def test_real_postgresql_runtime_two_phase_activation_and_drain() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
    platform_factory = _role_factory(engine, "saas_platform")
    gateway_factory = _role_factory(engine, "saas_preview_gateway")
    directory = PreviewGatewayDirectoryAuthority(
        platform_factory,
        service_session_factory=gateway_factory,
    )
    authority = PreviewGatewayCertificateAuthority(
        platform_factory,
        accepted_trust_bundle_versions=("bundle-v1",),
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    gateway_id = f"gateway-runtime-pg-{uuid4().hex[:12]}"
    provider = _Provider(
        gateway_id,
        now=now,
        first_not_after=now + timedelta(hours=1),
    )
    relay = _RelayServer(platform_factory, gateway_id)
    runtime = PreviewGatewayRuntime(
        _config(gateway_id),
        directory=directory,
        certificate_authority=authority,
        certificate_provider=provider,
        relay_server=relay,
        readiness_probe=_Readiness(directory),
        drain_observer=_DrainObserver(platform_factory),
        clock=lambda: now,
    )
    await runtime.start()
    assert runtime.ready and not relay.observed_registration_before_bind
    with platform_factory() as db:
        record = db.get(PreviewGatewayInstanceRecord, gateway_id)
        assert record is not None and record.status == "active"
        assert record.activated_at is not None
    await runtime.aclose(reason="postgresql_runtime_acceptance")
    with platform_factory() as db:
        record = db.get(PreviewGatewayInstanceRecord, gateway_id)
        assert record is not None and record.status == "released"
    engine.dispose()
