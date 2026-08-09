from __future__ import annotations

import hashlib
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypedDict
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.exc import DBAPIError
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
from saas.control_plane.placements import RunnerTunnelPlacement


class _GatewayCertificateOptions(TypedDict, total=False):
    server_name: str
    identity_gateway_instance_id: str | None
    lifetime: timedelta
    wrong_eku: bool
    extra_dns_san: bool
    is_ca: bool


def _gateway_certificate(
    gateway_instance_id: str,
    *,
    purpose: str,
    now: datetime,
    server_name: str = "localhost",
    identity_gateway_instance_id: str | None = None,
    lifetime: timedelta = timedelta(hours=1),
    wrong_eku: bool = False,
    extra_dns_san: bool = False,
    is_ca: bool = False,
) -> bytes:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gateway Test CA")])
    key = ec.generate_private_key(ec.SECP256R1())
    identity = identity_gateway_instance_id or gateway_instance_id
    sans: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(f"spiffe://omnigent/preview-gateway/{identity}")
    ]
    expected_eku = (
        ExtendedKeyUsageOID.CLIENT_AUTH
        if purpose == "preview_relay_client"
        else ExtendedKeyUsageOID.SERVER_AUTH
    )
    if purpose == "preview_relay_server":
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(server_name)))
        except ValueError:
            sans.append(x509.DNSName(server_name))
    if extra_dns_san:
        sans.append(x509.DNSName("unregistered.invalid"))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gateway")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + lifetime)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    (
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if expected_eku == ExtendedKeyUsageOID.CLIENT_AUTH
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    )
                    if wrong_eku
                    else expected_eku
                ]
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _placement(gateway_instance_id: str) -> RunnerTunnelPlacement:
    return RunnerTunnelPlacement(
        placement_id=uuid4(),
        runner_id=uuid4(),
        runner_connection_generation=1,
        routing_generation=1,
        gateway_instance_id=gateway_instance_id,
        relay_subject=f"rtp_{uuid4().hex}",
        status="active",
        lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


@pytest.fixture
def gateway_fixture():
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @sa.event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    directory = PreviewGatewayDirectoryAuthority(factory, service_session_factory=factory)
    certificates = PreviewGatewayCertificateAuthority(
        factory,
        accepted_trust_bundle_versions=("bundle-v1", "bundle-v2"),
    )
    yield engine, factory, directory, certificates, now
    engine.dispose()


def _register(
    directory: PreviewGatewayDirectoryAuthority,
    *,
    gateway_instance_id: str,
    token: str,
    now: datetime,
    server_name: str = "localhost",
) -> None:
    directory.register_gateway(
        gateway_instance_id=gateway_instance_id,
        connect_host="127.0.0.1",
        connect_port=8443,
        server_name=server_name,
        failure_domain="cn-east-1a",
        source_revision="upstream-revision",
        adapter_contract_version="0.2.0",
        registration_token=token,
        lease_duration=timedelta(minutes=2),
        now=now,
    )


def _activate_gateway(
    directory: PreviewGatewayDirectoryAuthority,
    certificates: PreviewGatewayCertificateAuthority,
    *,
    gateway_instance_id: str,
    token: str,
    now: datetime,
    server_name: str = "localhost",
) -> tuple[bytes, bytes]:
    client_der = _gateway_certificate(
        gateway_instance_id,
        purpose="preview_relay_client",
        now=now,
        server_name=server_name,
    )
    server_der = _gateway_certificate(
        gateway_instance_id,
        purpose="preview_relay_server",
        now=now,
        server_name=server_name,
    )
    for purpose, certificate_der in (
        ("preview_relay_client", client_der),
        ("preview_relay_server", server_der),
    ):
        certificates.activate_certificate(
            gateway_instance_id=gateway_instance_id,
            purpose=purpose,
            certificate_der=certificate_der,
            trust_bundle_version="bundle-v1",
            now=now,
        )
    directory.activate_gateway(
        gateway_instance_id=gateway_instance_id,
        registration_token=token,
        now=now,
    )
    return client_der, server_der


def test_gateway_directory_token_lifecycle_discovery_and_non_reuse(gateway_fixture) -> None:
    _, factory, directory, certificates, now = gateway_fixture
    token = "gateway-registration-" + "x" * 40
    _register(directory, gateway_instance_id="gateway-a", token=token, now=now)
    with pytest.raises(PreviewGatewayLifecycleError) as starting:
        directory.resolve(_placement("gateway-a"))
    assert starting.value.code == "preview_gateway_route_unavailable"
    with pytest.raises(PreviewGatewayLifecycleError) as incomplete:
        directory.activate_gateway(
            gateway_instance_id="gateway-a",
            registration_token=token,
            now=now,
        )
    assert incomplete.value.code == "preview_gateway_certificates_incomplete"
    _activate_gateway(
        directory,
        certificates,
        gateway_instance_id="gateway-a",
        token=token,
        now=now,
    )
    endpoint = directory.resolve(_placement("gateway-a"))
    assert (endpoint.connect_host, endpoint.port, endpoint.server_name) == (
        "127.0.0.1",
        8443,
        "localhost",
    )
    heartbeat = directory.heartbeat_gateway(
        gateway_instance_id="gateway-a",
        registration_token=token,
        now=now + timedelta(seconds=30),
    )
    assert heartbeat.lease_expires_at == now + timedelta(minutes=2)
    with pytest.raises(PreviewGatewayLifecycleError) as denied:
        directory.heartbeat_gateway(
            gateway_instance_id="gateway-a",
            registration_token="wrong-token-" + "y" * 40,
            now=now + timedelta(seconds=31),
        )
    assert denied.value.code == "preview_gateway_token_denied"
    assert directory.begin_draining(gateway_instance_id="gateway-a", registration_token=token)
    assert not directory.begin_draining(gateway_instance_id="gateway-a", registration_token=token)
    assert directory.release_gateway(
        gateway_instance_id="gateway-a",
        registration_token=token,
        reason="planned shutdown",
        now=now + timedelta(seconds=40),
    )
    assert not directory.release_gateway(
        gateway_instance_id="gateway-a",
        registration_token=token,
        reason="idempotent retry",
        now=now + timedelta(seconds=41),
    )
    with pytest.raises(PreviewGatewayLifecycleError) as unavailable:
        directory.resolve(_placement("gateway-a"))
    assert unavailable.value.code == "preview_gateway_route_unavailable"
    with pytest.raises(PreviewGatewayLifecycleError) as reused:
        _register(directory, gateway_instance_id="gateway-a", token=token, now=now)
    assert reused.value.code == "preview_gateway_identity_reused"
    with factory() as db:
        record = db.get(PreviewGatewayInstanceRecord, "gateway-a")
        assert record is not None and record.registration_token_hash != token
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_type == "preview_gateway_instance"
                )
            )
        )
        assert [event.event_type for event in events] == [
            "preview.gateway.registered",
            "preview.gateway.activated",
            "preview.gateway.draining",
            "preview.gateway.released",
        ]
        assert token not in str([event.payload for event in events])


def test_gateway_activation_rejects_mixed_trust_bundle_pair(gateway_fixture) -> None:
    _, factory, directory, _, now = gateway_fixture
    gateway_id = "gateway-mixed-bundle"
    token = "gateway-mixed-bundle-token-" + "x" * 40
    certificates = PreviewGatewayCertificateAuthority(
        factory,
        accepted_trust_bundle_versions=("bundle-v1", "bundle-v2"),
    )
    _register(directory, gateway_instance_id=gateway_id, token=token, now=now)
    for purpose, bundle in (
        ("preview_relay_client", "bundle-v1"),
        ("preview_relay_server", "bundle-v2"),
    ):
        certificates.activate_certificate(
            gateway_instance_id=gateway_id,
            purpose=purpose,
            certificate_der=_gateway_certificate(gateway_id, purpose=purpose, now=now),
            trust_bundle_version=bundle,
            now=now,
        )

    with pytest.raises(PreviewGatewayLifecycleError) as inconsistent:
        directory.activate_gateway(
            gateway_instance_id=gateway_id,
            registration_token=token,
            now=now,
        )
    assert inconsistent.value.code == "preview_gateway_certificates_incomplete"
    with pytest.raises(PreviewGatewayLifecycleError) as unavailable:
        directory.resolve(_placement(gateway_id))
    assert unavailable.value.code == "preview_gateway_route_unavailable"


def test_gateway_reconcile_expires_without_reviving_stale_token(gateway_fixture) -> None:
    _, _, directory, _, now = gateway_fixture
    token = "gateway-expiry-token-" + "x" * 40
    _register(directory, gateway_instance_id="gateway-expiring", token=token, now=now)
    assert directory.reconcile_expired(now=now + timedelta(minutes=3)) == ("gateway-expiring",)
    with pytest.raises(PreviewGatewayLifecycleError) as stale:
        directory.heartbeat_gateway(
            gateway_instance_id="gateway-expiring",
            registration_token=token,
            now=now + timedelta(minutes=3, seconds=1),
        )
    assert stale.value.code == "preview_gateway_lease_stale"


def test_gateway_certificates_are_purpose_separated_rotatable_and_revocable(
    gateway_fixture,
) -> None:
    _, factory, directory, certificates, now = gateway_fixture
    token = "gateway-cert-token-" + "x" * 40
    _register(directory, gateway_instance_id="gateway-cert", token=token, now=now)
    client_der = _gateway_certificate("gateway-cert", purpose="preview_relay_client", now=now)
    server_der = _gateway_certificate("gateway-cert", purpose="preview_relay_server", now=now)
    client = certificates.activate_certificate(
        gateway_instance_id="gateway-cert",
        purpose="preview_relay_client",
        certificate_der=client_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    server = certificates.activate_certificate(
        gateway_instance_id="gateway-cert",
        purpose="preview_relay_server",
        certificate_der=server_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    directory.activate_gateway(
        gateway_instance_id="gateway-cert",
        registration_token=token,
        now=now,
    )
    assert certificates.is_preview_gateway_certificate_authorized(
        gateway_instance_id="gateway-cert",
        certificate_der=client_der,
        purpose="preview_relay_client",
        now=now + timedelta(minutes=1),
    )
    assert not certificates.is_preview_gateway_certificate_authorized(
        gateway_instance_id="gateway-cert",
        certificate_der=client_der,
        purpose="preview_relay_server",
        now=now + timedelta(minutes=1),
    )
    rotated_der = _gateway_certificate(
        "gateway-cert", purpose="preview_relay_client", now=now + timedelta(minutes=1)
    )
    rotated = certificates.activate_certificate(
        gateway_instance_id="gateway-cert",
        purpose="preview_relay_client",
        certificate_der=rotated_der,
        trust_bundle_version="bundle-v2",
        rotation_overlap=timedelta(seconds=30),
        now=now + timedelta(minutes=1),
    )
    assert rotated.rotation_generation == client.rotation_generation + 1
    assert certificates.is_preview_gateway_certificate_authorized(
        gateway_instance_id="gateway-cert",
        certificate_der=client_der,
        purpose="preview_relay_client",
        now=now + timedelta(minutes=1, seconds=20),
    )
    assert not certificates.is_preview_gateway_certificate_authorized(
        gateway_instance_id="gateway-cert",
        certificate_der=client_der,
        purpose="preview_relay_client",
        now=now + timedelta(minutes=1, seconds=40),
    )
    assert certificates.revoke_certificate(
        fingerprint_sha256=server.fingerprint_sha256,
        reason="server leaf compromised",
        now=now + timedelta(minutes=1, seconds=30),
    )
    assert not certificates.is_preview_gateway_certificate_authorized(
        gateway_instance_id="gateway-cert",
        certificate_der=server_der,
        purpose="preview_relay_server",
        now=now + timedelta(minutes=1, seconds=31),
    )
    with factory() as db:
        records = list(
            db.scalars(
                sa.select(PreviewGatewayCertificateRecord).order_by(
                    PreviewGatewayCertificateRecord.purpose,
                    PreviewGatewayCertificateRecord.rotation_generation,
                )
            )
        )
        assert len(records) == 3
        assert all(record.spiffe_id.endswith("/gateway-cert") for record in records)


@pytest.mark.parametrize(
    ("purpose", "options", "expected_code"),
    [
        (
            "preview_relay_client",
            {"identity_gateway_instance_id": "other-gateway"},
            "preview_gateway_certificate_identity_mismatch",
        ),
        (
            "preview_relay_client",
            {"wrong_eku": True},
            "preview_gateway_certificate_profile_invalid",
        ),
        (
            "preview_relay_client",
            {"extra_dns_san": True},
            "preview_gateway_certificate_profile_invalid",
        ),
        (
            "preview_relay_server",
            {"server_name": "other.internal"},
            "preview_gateway_certificate_endpoint_mismatch",
        ),
        (
            "preview_relay_server",
            {"lifetime": timedelta(days=2)},
            "preview_gateway_certificate_validity_invalid",
        ),
    ],
)
def test_gateway_certificate_rejects_wrong_identity_profile_endpoint_and_lifetime(
    gateway_fixture,
    purpose: str,
    options: _GatewayCertificateOptions,
    expected_code: str,
) -> None:
    _, _, directory, certificates, now = gateway_fixture
    token = "gateway-invalid-cert-token-" + "x" * 40
    _register(directory, gateway_instance_id="gateway-invalid", token=token, now=now)
    certificate_der = _gateway_certificate("gateway-invalid", purpose=purpose, now=now, **options)
    with pytest.raises(PreviewGatewayLifecycleError) as denied:
        certificates.activate_certificate(
            gateway_instance_id="gateway-invalid",
            purpose=purpose,
            certificate_der=certificate_der,
            trust_bundle_version="bundle-v1",
            now=now,
        )
    assert denied.value.code == expected_code


def test_gateway_release_invalidates_active_certificates(gateway_fixture) -> None:
    _, _, directory, certificates, now = gateway_fixture
    token = "gateway-release-token-" + "x" * 40
    _register(directory, gateway_instance_id="gateway-release", token=token, now=now)
    certificate_der = _gateway_certificate(
        "gateway-release", purpose="preview_relay_client", now=now
    )
    certificates.activate_certificate(
        gateway_instance_id="gateway-release",
        purpose="preview_relay_client",
        certificate_der=certificate_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    server_der = _gateway_certificate("gateway-release", purpose="preview_relay_server", now=now)
    certificates.activate_certificate(
        gateway_instance_id="gateway-release",
        purpose="preview_relay_server",
        certificate_der=server_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    directory.activate_gateway(
        gateway_instance_id="gateway-release",
        registration_token=token,
        now=now,
    )
    directory.release_gateway(
        gateway_instance_id="gateway-release",
        registration_token=token,
        reason="process stopped",
        now=now + timedelta(seconds=10),
    )
    assert not certificates.is_preview_gateway_certificate_authorized(
        gateway_instance_id="gateway-release",
        certificate_der=certificate_der,
        purpose="preview_relay_client",
        now=now + timedelta(seconds=11),
    )


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for Gateway RLS acceptance")
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


def test_real_postgresql_gateway_rls_token_certificate_and_monotonic_guards() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    now = datetime.now(timezone.utc).replace(microsecond=0)
    gateway_instance_id = f"gateway-rls-{uuid4().hex[:12]}"
    token = f"gateway-rls-token-{uuid4().hex}" + "x" * 16
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
    platform_factory = _role_factory(engine, "saas_platform")
    gateway_factory = _role_factory(engine, "saas_preview_gateway")
    directory = PreviewGatewayDirectoryAuthority(
        platform_factory, service_session_factory=gateway_factory
    )
    _register(
        directory,
        gateway_instance_id=gateway_instance_id,
        token=token,
        now=now,
    )
    directory.heartbeat_gateway(
        gateway_instance_id=gateway_instance_id,
        registration_token=token,
        now=now + timedelta(seconds=10),
    )
    with pytest.raises(PreviewGatewayLifecycleError) as wrong_token:
        directory.heartbeat_gateway(
            gateway_instance_id=gateway_instance_id,
            registration_token="wrong-postgresql-token-" + "x" * 40,
            now=now + timedelta(seconds=11),
        )
    assert wrong_token.value.code == "preview_gateway_token_denied"
    with pytest.raises(DBAPIError, match="lifecycle is monotonic"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_preview_gateway")
            connection.execute(
                sa.text("SELECT set_config('app.gateway_registration_token_hash', :digest, true)"),
                {"digest": hashlib.sha256(token.encode()).hexdigest()},
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_gateway_instances SET status = 'active' WHERE id = :id"
                ),
                {"id": gateway_instance_id},
            )
    with pytest.raises(DBAPIError, match="permission denied"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_preview_gateway")
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_gateway_instances SET activated_at = :now WHERE id = :id"
                ),
                {"id": gateway_instance_id, "now": now + timedelta(seconds=10)},
            )
    with pytest.raises(DBAPIError, match="lifecycle is monotonic"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_gateway_instances "
                    "SET status = 'active', activated_at = :now WHERE id = :id"
                ),
                {"id": gateway_instance_id, "now": now + timedelta(seconds=10)},
            )

    client_der = _gateway_certificate(gateway_instance_id, purpose="preview_relay_client", now=now)
    server_der = _gateway_certificate(gateway_instance_id, purpose="preview_relay_server", now=now)
    platform_certificates = PreviewGatewayCertificateAuthority(
        platform_factory, accepted_trust_bundle_versions=("bundle-v1",)
    )
    gateway_certificates = PreviewGatewayCertificateAuthority(
        gateway_factory, accepted_trust_bundle_versions=("bundle-v1",)
    )
    activated = platform_certificates.activate_certificate(
        gateway_instance_id=gateway_instance_id,
        purpose="preview_relay_client",
        certificate_der=client_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    platform_certificates.activate_certificate(
        gateway_instance_id=gateway_instance_id,
        purpose="preview_relay_server",
        certificate_der=server_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    directory.activate_gateway(
        gateway_instance_id=gateway_instance_id,
        registration_token=token,
        now=now + timedelta(seconds=10),
    )
    with pytest.raises(DBAPIError, match="lifecycle is monotonic"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_gateway_instances SET activated_at = :now WHERE id = :id"
                ),
                {"id": gateway_instance_id, "now": now + timedelta(seconds=11)},
            )
    assert gateway_certificates.is_preview_gateway_certificate_authorized(
        gateway_instance_id=gateway_instance_id,
        certificate_der=client_der,
        purpose="preview_relay_client",
        now=now + timedelta(seconds=20),
    )
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_gateway")
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_preview_gateway_certificates")
            ).scalar_one()
            == 0
        )
    with pytest.raises(DBAPIError, match="permission denied"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_preview_gateway")
            connection.execute(
                sa.text("SELECT registration_token_hash FROM saas_preview_gateway_instances")
            ).all()
    with pytest.raises(DBAPIError, match="authority fields are immutable"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_gateway_instances SET connect_port = 9443 WHERE id = :id"
                ),
                {"id": gateway_instance_id},
            )
    assert platform_certificates.revoke_certificate(
        fingerprint_sha256=activated.fingerprint_sha256,
        reason="RLS revocation probe",
        now=now + timedelta(seconds=25),
    )
    with pytest.raises(DBAPIError, match="certificate lifecycle is monotonic"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_gateway_certificates SET status = 'active', "
                    "revoked_at = NULL, revocation_reason = NULL, retire_at = NULL "
                    "WHERE fingerprint_sha256 = :fingerprint"
                ),
                {"fingerprint": activated.fingerprint_sha256},
            )
    with pytest.raises(DBAPIError, match="certificate records are append-only"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "DELETE FROM saas_preview_gateway_certificates "
                    "WHERE fingerprint_sha256 = :fingerprint"
                ),
                {"fingerprint": activated.fingerprint_sha256},
            )
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text("DELETE FROM saas_preview_gateway_instances WHERE id = :id"),
                {"id": gateway_instance_id},
            )
    directory.release_gateway(
        gateway_instance_id=gateway_instance_id,
        registration_token=token,
        reason="rls acceptance complete",
        now=now + timedelta(seconds=30),
    )
    assert not gateway_certificates.is_preview_gateway_certificate_authorized(
        gateway_instance_id=gateway_instance_id,
        certificate_der=client_der,
        purpose="preview_relay_client",
        now=now + timedelta(seconds=31),
    )
    engine.dispose()
