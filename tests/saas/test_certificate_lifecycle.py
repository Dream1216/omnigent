from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from typing import TypedDict
from uuid import UUID, uuid4

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

from saas.control_plane import (
    ActivatedRunnerCertificate,
    CertificateLifecycleError,
    ControlPlaneOutboxEvent,
    RunnerCertificateAuthority,
    RunnerCertificateRecord,
    SaasBase,
)
from saas.control_plane.db_models import RuntimePlacementRecord
from saas.control_plane.scheduling_models import RunnerPoolRecord, RunnerRegistrationRecord


class _CertificateOptions(TypedDict, total=False):
    lifetime: timedelta
    identity_runner_id: UUID | None
    extra_dns_san: bool
    server_eku: bool
    is_ca: bool


def _runner_certificate(
    runner_id: UUID,
    *,
    now: datetime,
    lifetime: timedelta = timedelta(hours=1),
    identity_runner_id: UUID | None = None,
    extra_dns_san: bool = False,
    server_eku: bool = False,
    is_ca: bool = False,
) -> bytes:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Omnigent Lifecycle CA")])
    key = ec.generate_private_key(ec.SECP256R1())
    san_values: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(
            f"spiffe://omnigent/runner/{identity_runner_id or runner_id}"
        )
    ]
    if extra_dns_san:
        san_values.append(x509.DNSName("runner.invalid"))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Runner")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + lifetime)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH
                    if server_eku
                    else ExtendedKeyUsageOID.CLIENT_AUTH
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


def _seed_runner(factory: sessionmaker[Session], *, now: datetime) -> tuple[UUID, UUID]:
    placement_id, pool_id, runner_id = uuid4(), uuid4(), uuid4()
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="db-cert",
                object_store_ref="objects-cert",
                kms_key_ref="kms-cert",
                official_schema_revision="runtime-schema-v1",
                capacity_class="shared-small",
                status="active",
            )
        )
        db.flush()
        db.add(
            RunnerPoolRecord(
                id=pool_id,
                placement_id=placement_id,
                failure_domain="cn-east-1a",
                name="certificate-pool",
                queue_class="interactive",
                capacity_slots=2,
                reserved_slots=0,
                status="active",
                protocol_version=2,
                source_revision="upstream",
                schema_revision="runtime-schema-v1",
                adapter_contract_version="0.2.0",
            )
        )
        db.flush()
        db.add(
            RunnerRegistrationRecord(
                id=runner_id,
                pool_id=pool_id,
                placement_id=placement_id,
                instance_key="runner-certificate-instance",
                failure_domain="cn-east-1a",
                status="online",
                connection_generation=1,
                connection_token_hash="a" * 64,
                protocol_version=2,
                source_revision="upstream",
                schema_revision="runtime-schema-v1",
                adapter_contract_version="0.2.0",
                capabilities=["shell"],
                capabilities_hash="b" * 64,
                max_concurrency=2,
                active_leases=0,
                last_heartbeat_at=now,
                registered_at=now,
            )
        )
    return runner_id, pool_id


@pytest.fixture
def certificate_fixture(tmp_path: Path):
    engine = sa.create_engine(f"sqlite+pysqlite:///{tmp_path / 'certificates.db'}")
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    now = datetime(2026, 8, 5, 9, 0, tzinfo=timezone.utc)
    runner_id, _ = _seed_runner(factory, now=now)
    authority = RunnerCertificateAuthority(
        factory,
        accepted_trust_bundle_versions=("bundle-v1", "bundle-v2"),
    )
    yield engine, factory, authority, runner_id, now
    engine.dispose()


def test_certificate_activation_is_idempotent_and_emits_non_secret_outbox(
    certificate_fixture,
) -> None:
    _, factory, authority, runner_id, now = certificate_fixture
    certificate_der = _runner_certificate(runner_id, now=now)
    activated = authority.activate_certificate(
        runner_id=runner_id,
        runner_connection_generation=1,
        purpose="secret_broker",
        certificate_der=certificate_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    repeated = authority.activate_certificate(
        runner_id=runner_id,
        runner_connection_generation=1,
        purpose="secret_broker",
        certificate_der=certificate_der,
        trust_bundle_version="bundle-v1",
        now=now + timedelta(seconds=1),
    )
    assert repeated == activated
    assert authority.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=certificate_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=1),
    )
    assert not authority.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=certificate_der,
        purpose="preview_tunnel",
        now=now + timedelta(minutes=1),
    )
    with factory() as db:
        events = list(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        assert len(events) == 1
        assert events[0].event_type == "runner.certificate.activated"
        assert "certificate" not in events[0].payload
        assert "private" not in str(events[0].payload).lower()


def test_certificate_rotation_has_bounded_overlap_and_revocation_is_immediate(
    certificate_fixture,
) -> None:
    _, factory, authority, runner_id, now = certificate_fixture
    first_der = _runner_certificate(runner_id, now=now)
    first = authority.activate_certificate(
        runner_id=runner_id,
        runner_connection_generation=1,
        purpose="secret_broker",
        certificate_der=first_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    with pytest.raises(CertificateLifecycleError) as backdated_rotation:
        authority.activate_certificate(
            runner_id=runner_id,
            runner_connection_generation=1,
            purpose="secret_broker",
            certificate_der=_runner_certificate(runner_id, now=now),
            trust_bundle_version="bundle-v1",
            now=now - timedelta(seconds=30),
        )
    assert backdated_rotation.value.code == "runner_certificate_rotation_invalid"
    second_der = _runner_certificate(runner_id, now=now + timedelta(minutes=1))
    second = authority.activate_certificate(
        runner_id=runner_id,
        runner_connection_generation=1,
        purpose="secret_broker",
        certificate_der=second_der,
        trust_bundle_version="bundle-v2",
        rotation_overlap=timedelta(minutes=5),
        now=now + timedelta(minutes=1),
    )
    assert second.rotation_generation == first.rotation_generation + 1
    assert authority.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=first_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=5),
    )
    assert not authority.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=first_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=7),
    )
    with pytest.raises(CertificateLifecycleError) as backdated_revocation:
        authority.revoke_certificate(
            fingerprint_sha256=second.fingerprint_sha256,
            reason="invalid clock",
            now=now + timedelta(seconds=30),
        )
    assert backdated_revocation.value.code == "runner_certificate_revocation_time_invalid"
    assert authority.revoke_certificate(
        fingerprint_sha256=second.fingerprint_sha256,
        reason="runner drained",
        now=now + timedelta(minutes=3),
    )
    assert authority.revoke_certificate(
        fingerprint_sha256=second.fingerprint_sha256,
        reason="idempotent retry",
        now=now + timedelta(minutes=4),
    )
    assert not authority.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=second_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=4),
    )
    with factory() as db:
        records = list(
            db.scalars(
                sa.select(RunnerCertificateRecord).order_by(
                    RunnerCertificateRecord.rotation_generation
                )
            )
        )
        assert [record.status for record in records] == ["retiring", "revoked"]
        assert len(list(db.scalars(sa.select(ControlPlaneOutboxEvent)))) == 3


def test_certificate_authorization_tracks_runner_generation_status_and_bundle(
    certificate_fixture,
) -> None:
    _, factory, authority, runner_id, now = certificate_fixture
    certificate_der = _runner_certificate(runner_id, now=now)
    authority.activate_certificate(
        runner_id=runner_id,
        runner_connection_generation=1,
        purpose="preview_tunnel",
        certificate_der=certificate_der,
        trust_bundle_version="bundle-v1",
        now=now,
    )
    with factory.begin() as db:
        runner = db.get(RunnerRegistrationRecord, runner_id)
        assert runner is not None
        runner.connection_generation = 2
    assert not authority.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=certificate_der,
        purpose="preview_tunnel",
        now=now + timedelta(minutes=1),
    )
    with pytest.raises(CertificateLifecycleError) as stale:
        authority.activate_certificate(
            runner_id=runner_id,
            runner_connection_generation=1,
            purpose="preview_tunnel",
            certificate_der=_runner_certificate(runner_id, now=now),
            trust_bundle_version="bundle-v1",
            now=now + timedelta(minutes=1),
        )
    assert stale.value.code == "runner_certificate_runner_stale"


@pytest.mark.parametrize(
    ("certificate_options", "expected_code"),
    [
        ({"identity_runner_id": uuid4()}, "runner_certificate_identity_mismatch"),
        ({"extra_dns_san": True}, "runner_certificate_profile_invalid"),
        ({"server_eku": True}, "runner_certificate_profile_invalid"),
        ({"is_ca": True}, "runner_certificate_profile_invalid"),
        ({"lifetime": timedelta(days=2)}, "runner_certificate_validity_invalid"),
    ],
)
def test_certificate_activation_rejects_wrong_identity_profile_and_lifetime(
    certificate_fixture,
    certificate_options: _CertificateOptions,
    expected_code: str,
) -> None:
    _, factory, authority, runner_id, now = certificate_fixture
    certificate_der = _runner_certificate(runner_id, now=now, **certificate_options)
    with pytest.raises(CertificateLifecycleError) as denied:
        authority.activate_certificate(
            runner_id=runner_id,
            runner_connection_generation=1,
            purpose="secret_broker",
            certificate_der=certificate_der,
            trust_bundle_version="bundle-v1",
            now=now,
        )
    assert denied.value.code == expected_code
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunnerCertificateRecord)) == 0


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for certificate RLS acceptance")
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


def test_real_postgresql_certificate_rls_rotation_revocation_and_monotonicity() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
    platform_factory = _role_factory(engine, "saas_platform")
    runner_id, _ = _seed_runner(platform_factory, now=now)
    platform = RunnerCertificateAuthority(
        platform_factory,
        accepted_trust_bundle_versions=("bundle-v1", "bundle-v2"),
    )
    secret_broker = RunnerCertificateAuthority(
        _role_factory(engine, "saas_secret_broker"),
        accepted_trust_bundle_versions=("bundle-v1", "bundle-v2"),
    )
    preview_gateway = RunnerCertificateAuthority(
        _role_factory(engine, "saas_preview_gateway"),
        accepted_trust_bundle_versions=("bundle-v1", "bundle-v2"),
    )
    first_der = _runner_certificate(runner_id, now=now)
    activation_barrier = Barrier(2)

    def activate_first() -> ActivatedRunnerCertificate:
        activation_barrier.wait()
        return platform.activate_certificate(
            runner_id=runner_id,
            runner_connection_generation=1,
            purpose="secret_broker",
            certificate_der=first_der,
            trust_bundle_version="bundle-v1",
            now=now,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        receipts = [executor.submit(activate_first) for _ in range(2)]
        first, retry = [future.result() for future in receipts]
    assert retry == first
    with platform_factory() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(RunnerCertificateRecord)
                .where(RunnerCertificateRecord.fingerprint_sha256 == first.fingerprint_sha256)
            )
            == 1
        )
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(ControlPlaneOutboxEvent.event_type == "runner.certificate.activated")
            )
            == 1
        )
    second_der = _runner_certificate(runner_id, now=now + timedelta(seconds=1))
    second = platform.activate_certificate(
        runner_id=runner_id,
        runner_connection_generation=1,
        purpose="secret_broker",
        certificate_der=second_der,
        trust_bundle_version="bundle-v2",
        rotation_overlap=timedelta(minutes=5),
        now=now + timedelta(seconds=1),
    )
    for unrelated_role in ("saas_app", "saas_governance", "saas_executor"):
        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {unrelated_role}")
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_runner_certificates")
                ).scalar_one()
                == 0
            )
    assert secret_broker.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=first_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=1),
    )
    assert secret_broker.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=second_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=1),
    )
    assert not preview_gateway.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=second_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=1),
    )
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_secret_broker")
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_runner_certificates")
            ).scalar_one()
            == 0
        )
        connection.execute(
            sa.text(
                "SELECT set_config('app.presented_certificate_fingerprint', :value, true), "
                "set_config('app.presented_certificate_purpose', 'secret_broker', true)"
            ),
            {"value": first.fingerprint_sha256},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_runner_certificates")
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_runner_registrations")
            ).scalar_one()
            == 1
        )
    assert platform.revoke_certificate(
        fingerprint_sha256=second.fingerprint_sha256,
        reason="incident revocation",
        now=now + timedelta(minutes=2),
    )
    assert not secret_broker.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=second_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=2),
    )
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_secret_broker")
        connection.execute(
            sa.text(
                "SELECT set_config('app.presented_certificate_fingerprint', :value, true), "
                "set_config('app.presented_certificate_purpose', 'secret_broker', true)"
            ),
            {"value": second.fingerprint_sha256},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_runner_certificates")
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_runner_registrations")
            ).scalar_one()
            == 0
        )
    with pytest.raises(DBAPIError, match="append-only"):
        with platform_factory.begin() as db:
            db.execute(
                sa.delete(RunnerCertificateRecord).where(
                    RunnerCertificateRecord.id == second.certificate_id
                )
            )
    with pytest.raises(DBAPIError, match="monotonic"):
        with platform_factory.begin() as db:
            db.execute(
                sa.update(RunnerCertificateRecord)
                .where(RunnerCertificateRecord.id == second.certificate_id)
                .values(status="active", revoked_at=None, revocation_reason=None)
            )
    with platform_factory.begin() as db:
        runner = db.get(RunnerRegistrationRecord, runner_id)
        assert runner is not None
        runner.connection_generation = 2
    assert not secret_broker.is_runner_certificate_authorized(
        runner_id=runner_id,
        certificate_der=first_der,
        purpose="secret_broker",
        now=now + timedelta(minutes=3),
    )
    engine.dispose()
