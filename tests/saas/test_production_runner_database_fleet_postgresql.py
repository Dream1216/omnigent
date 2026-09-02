from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session, sessionmaker

from omnigent import _build_info
from saas.control_plane import (
    RunnerPoolRecord,
    RunnerRegistrationRecord,
    RuntimePlacementRecord,
)
from saas.control_plane.isolation import IsolationControlPlane
from saas.control_plane.worktrees import WorktreeControlPlane
from saas.production.runner_control import RunnerControlError
from saas.production.runner_database_fleet import (
    RUNNER_DATABASE_FLEET_ATTESTATION_FILE_ENV,
    RUNNER_DATABASE_FLEET_ATTESTATION_PUBLIC_KEY_FILE_ENV,
    RUNNER_DATABASE_FLEET_ATTESTATION_SIGNATURE_FILE_ENV,
    RUNNER_DATABASE_FLEET_CONTEXT_FILE_ENV,
    RUNNER_DATABASE_FLEET_CONTEXT_SHA256_ENV,
    RUNNER_DATABASE_FLEET_FILE_ENV,
    RUNNER_DATABASE_FLEET_NAMESPACE_ENV,
    RUNNER_DATABASE_FLEET_RECEIPT_FILE_ENV,
    RUNNER_DATABASE_FLEET_RECEIPT_PRIVATE_KEY_FILE_ENV,
    RUNNER_DATABASE_FLEET_RECEIPT_PUBLIC_KEY_FILE_ENV,
    RUNNER_DATABASE_FLEET_RECEIPT_SIGNATURE_FILE_ENV,
    RUNNER_DATABASE_FLEET_SHA256_ENV,
    RUNNER_DATABASE_FLEET_TRUST_PINS_FILE_ENV,
    RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV,
    RunnerDatabaseFleetError,
    RunnerDatabaseFleetEvidenceContext,
    RunnerDatabaseFleetEvidenceMember,
    RunnerDatabaseFleetMember,
    RunnerDatabaseFleetStageSpec,
    RunnerDatabaseFleetTrustPins,
    _canonical_json,
    _public_key_fingerprint,
    admission_signature_payload,
    load_and_verify_runner_database_fleet_environment_attestation,
    load_runner_database_fleet,
    load_runner_database_fleet_evidence_context,
    load_runner_database_fleet_trust_pins,
    promote_runner_database_fleet_after_admission,
    render_runner_database_fleet,
    render_runner_database_fleet_evidence_context,
    render_runner_database_fleet_trust_pins,
    run_runner_database_fleet_admission,
    runner_database_fleet_environment_attestation_document,
    runner_database_fleet_source_sha256s,
    sign_runner_database_fleet_admission_receipt,
    stage_runner_database_fleet,
    verify_runner_database_fleet_runtime_admission,
    verify_runner_database_fleet_runtime_catalog_binding,
)
from saas.production.runner_executor import (
    ProductionHostIsolationExecutor,
    _verify_runner_agent_database_authority,
)
from saas.runner_adapter import RunnerIsolationAdapter, RunnerWorktreeAdapter
from tests.saas.test_production_runner_postgresql import (
    _converge_external_runner_database_boundary,
    _public_database_privileges,
    _restore_external_public_database_privileges,
)
from tests.saas.test_scheduling_postgresql import _migrate


def _write_0400(path: Path, value: str) -> None:
    path.write_text(value, encoding="ascii")
    path.chmod(0o400)


def _capabilities_sha256(capabilities: tuple[str, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            list(capabilities),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _run_cluster_wrapper(owner_engine: sa.Engine, root: Path) -> None:
    psql = shutil.which("psql")
    assert psql is not None
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PGHOST": str(owner_engine.url.host),
        "PGPORT": str(owner_engine.url.port),
        "PGUSER": str(owner_engine.url.username),
        "PGDATABASE": str(owner_engine.url.database),
        "PGSSLMODE": "require",
    }
    if owner_engine.url.password is not None:
        environment["PGPASSWORD"] = owner_engine.url.password
    subprocess.run(
        [
            psql,
            "-X",
            "--no-password",
            "-f",
            str(root / "saas/control_plane/postgresql_runner_agent_cluster.psql"),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )


def test_pg18_signed_exact_two_runner_fleet_lifecycle_and_sticky_poison(
    isolated_postgres_url: str,
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    owner_engine = sa.create_engine(isolated_postgres_url, pool_pre_ping=True)
    with owner_engine.connect() as connection:
        server_major = int(connection.scalar(sa.text("SHOW server_version_num"))) // 10_000
        tls = bool(
            connection.scalar(sa.text("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"))
        )
    if server_major != 18 or not tls:
        owner_engine.dispose()
        pytest.skip("exact fleet admission requires a TLS PostgreSQL 18 acceptance cluster")

    product_revision = _build_info.COMMIT_SHA
    assert len(product_revision) == 40
    image_digest = "sha256:" + "b" * 64
    schema_revision = "p0s000000010"
    capabilities = ("shell",)
    capabilities_sha256 = _capabilities_sha256(capabilities)
    suffix = uuid4().hex[:12]
    schema_owner = f"saas_test_fleet_owner_{suffix}"
    runner_ids = tuple(sorted((uuid4(), uuid4()), key=str))
    third_runner_id = uuid4()
    placement_id = uuid4()
    pool_id = uuid4()
    quoted_owner = owner_engine.dialect.identifier_preparer.quote(schema_owner)
    database_name = cast(str, owner_engine.url.database)
    quoted_database = owner_engine.dialect.identifier_preparer.quote(database_name)
    login_engines: list[sa.Engine] = []
    executor: ProductionHostIsolationExecutor | None = None
    external_public_database_privileges: dict[str, frozenset[str]] = {}

    try:
        with owner_engine.begin() as connection:
            external_public_database_privileges = _public_database_privileges(connection)
            _converge_external_runner_database_boundary(connection)
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_owner} NOLOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1"
            )
            connection.exec_driver_sql(f"GRANT USAGE, CREATE ON SCHEMA public TO {quoted_owner}")
            connection.exec_driver_sql("CREATE EXTENSION pg_trgm WITH SCHEMA public")
            connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_owner}")
            _migrate(connection, root)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
            connection.exec_driver_sql("RESET ROLE")
        _run_cluster_wrapper(owner_engine, root)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted_database} TO saas_runner_agent"
            )

        factory = sessionmaker(owner_engine, expire_on_commit=False, class_=Session)
        with factory.begin() as database:
            database.add(
                RuntimePlacementRecord(
                    id=placement_id,
                    runtime_type="omnigent",
                    data_region="cn-east-1",
                    failure_domain="cn-east-1a",
                    database_cluster_ref="omnigent-next-beta-postgres",
                    object_store_ref="omnigent-next-beta-artifacts",
                    kms_key_ref="omnigent-next-beta-kms",
                    official_schema_revision=schema_revision,
                    capacity_class="runner-dedicated",
                    status="active",
                )
            )
            database.add(
                RunnerPoolRecord(
                    id=pool_id,
                    placement_id=placement_id,
                    failure_domain="cn-east-1a",
                    name="runner-fleet",
                    queue_class="interactive",
                    capacity_slots=2,
                    reserved_slots=0,
                    status="active",
                    protocol_version=1,
                    source_revision=product_revision,
                    schema_revision=schema_revision,
                    adapter_contract_version="0.2.0",
                )
            )
        specs = cast(
            tuple[RunnerDatabaseFleetStageSpec, RunnerDatabaseFleetStageSpec],
            tuple(
                RunnerDatabaseFleetStageSpec(
                    runner_id=runner_id,
                    pool_id=pool_id,
                    placement_id=placement_id,
                    instance_key=f"runner-{slot}",
                    failure_domain="cn-east-1a",
                    protocol_version=1,
                    source_revision=product_revision,
                    schema_revision=schema_revision,
                    adapter_contract_version="0.2.0",
                    capabilities=capabilities,
                    max_concurrency=1,
                )
                for slot, runner_id in zip(("a", "b"), runner_ids, strict=True)
            ),
        )
        staged = stage_runner_database_fleet(factory, specs=specs)
        assert [member.status for member in staged] == ["draining", "draining"]
        fleet_members = cast(
            tuple[RunnerDatabaseFleetMember, RunnerDatabaseFleetMember],
            tuple(
                RunnerDatabaseFleetMember(
                    runner_id=member.runner_id,
                    connection_generation=member.connection_generation,
                )
                for member in staged
            ),
        )

        passwords: dict[UUID, str] = {}
        with owner_engine.begin() as connection:
            for member in fleet_members:
                password = uuid4().hex
                passwords[member.runner_id] = password
                quoted_login = connection.dialect.identifier_preparer.quote(member.login)
                connection.exec_driver_sql(
                    f"CREATE ROLE {quoted_login} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 "
                    f"PASSWORD '{password}'"
                )
                connection.exec_driver_sql(
                    f"GRANT saas_runner_agent TO {quoted_login} "
                    "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
                )
            database_oid, system_identifier = connection.execute(
                sa.text(
                    "SELECT database.oid::bigint, control.system_identifier::text "
                    "FROM pg_database database CROSS JOIN LATERAL pg_control_system() control "
                    "WHERE database.datname = current_database()"
                )
            ).one()

        fleet_path = tmp_path / "runner-database-fleet.json"
        fleet_raw = render_runner_database_fleet(fleet_members)
        _write_0400(fleet_path, fleet_raw)
        source: dict[str, str] = {
            RUNNER_DATABASE_FLEET_FILE_ENV: str(fleet_path),
            RUNNER_DATABASE_FLEET_SHA256_ENV: hashlib.sha256(
                fleet_raw.encode("ascii")
            ).hexdigest(),
        }
        fleet = load_runner_database_fleet(source)
        context_path = tmp_path / "runner-database-fleet-context.json"
        context_members = tuple(
            RunnerDatabaseFleetEvidenceMember(
                slot=slot,
                runner_id=member.runner_id,
                connection_generation=member.connection_generation,
                pool_id=pool_id,
                placement_id=placement_id,
                instance_key=f"runner-{slot}",
                failure_domain="cn-east-1a",
                protocol_version=1,
                source_revision=product_revision,
                schema_revision=schema_revision,
                adapter_contract_version="0.2.0",
                capabilities=capabilities,
                capabilities_sha256=capabilities_sha256,
                max_concurrency=1,
                deployment_name=f"omnigent-saas-runner-agent-{slot}",
                deployment_uid=uuid4(),
                deployment_template_sha256=("4" if slot == "a" else "5") * 64,
                deployment_yaml_sha256=("6" if slot == "a" else "7") * 64,
                database_secret_name=(
                    f"omnigent-saas-runner-agent-{slot}-database-g{member.connection_generation}"
                ),
                database_secret_uid=uuid4(),
                database_secret_resource_version=("1001" if slot == "a" else "1002"),
            )
            for slot, member in zip(("a", "b"), fleet_members, strict=True)
        )
        unsigned_context = RunnerDatabaseFleetEvidenceContext(
            path=context_path,
            sha256="c" * 64,
            product_revision=product_revision,
            image_digest=image_digest,
            schema_revision=schema_revision,
            namespace="omnigent-next-beta",
            release_incarnation="3" * 32,
            admission_epoch=1,
            cnpg_cluster_namespace="omnigent-next-beta-data",
            cnpg_cluster_name="omnigent-next-beta-postgres",
            cnpg_cluster_uid=uuid4(),
            cnpg_cluster_resource_version="2001",
            cnpg_postgresql_major=18,
            database=database_name,
            database_oid=int(database_oid),
            database_system_identifier=str(system_identifier),
            database_service_name="omnigent-next-beta-postgres-rw",
            database_service_uid=uuid4(),
            database_service_resource_version="3001",
            database_service_dns=("omnigent-next-beta-postgres-rw.omnigent-next-beta-data.svc"),
            database_service_port=5432,
            database_service_cluster_ip="10.43.12.34",
            database_service_selector_sha256="8" * 64,
            database_endpoint_slices_sha256="9" * 64,
            runners=cast(
                tuple[
                    RunnerDatabaseFleetEvidenceMember,
                    RunnerDatabaseFleetEvidenceMember,
                ],
                context_members,
            ),
        )
        context_raw = render_runner_database_fleet_evidence_context(unsigned_context)
        _write_0400(context_path, context_raw)
        source.update(
            {
                RUNNER_DATABASE_FLEET_CONTEXT_FILE_ENV: str(context_path),
                RUNNER_DATABASE_FLEET_CONTEXT_SHA256_ENV: hashlib.sha256(
                    context_raw.encode("ascii")
                ).hexdigest(),
            }
        )
        context = load_runner_database_fleet_evidence_context(source, fleet=fleet)

        attestation_private = Ed25519PrivateKey.generate()
        receipt_private = Ed25519PrivateKey.generate()
        attestation_public_path = tmp_path / "environment-attestation-public.pem"
        receipt_public_path = tmp_path / "owner-receipt-public.pem"
        receipt_private_path = tmp_path / "owner-receipt-private.pem"
        _write_0400(
            attestation_public_path,
            attestation_private.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii"),
        )
        _write_0400(
            receipt_public_path,
            receipt_private.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii"),
        )
        _write_0400(
            receipt_private_path,
            receipt_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
        )
        issued_at = datetime.now(UTC).replace(microsecond=0)
        attestation_document = runner_database_fleet_environment_attestation_document(
            fleet=fleet,
            context=context,
            issuer="omnigent.gitops",
            key_id="environment-key-v1",
            issued_at=issued_at,
            expires_at=issued_at + timedelta(minutes=10),
        )
        attestation_raw = _canonical_json(attestation_document)
        attestation_signature = attestation_private.sign(
            admission_signature_payload(attestation_document)
        )
        attestation_path = tmp_path / "environment-attestation.json"
        attestation_signature_path = tmp_path / "environment-attestation.signature"
        _write_0400(attestation_path, attestation_raw)
        _write_0400(
            attestation_signature_path,
            base64.b64encode(attestation_signature).decode("ascii"),
        )
        trust_pins_path = tmp_path / "runner-database-fleet-trust-pins.json"
        admission_pins = RunnerDatabaseFleetTrustPins(
            path=trust_pins_path,
            sha256="d" * 64,
            stage="admission",
            admission_epoch=context.admission_epoch,
            product_revision=context.product_revision,
            schema_revision=context.schema_revision,
            fleet_sha256=fleet.sha256,
            evidence_context_sha256=context.sha256,
            attestation_issuer="omnigent.gitops",
            attestation_key_id="environment-key-v1",
            attestation_public_key_sha256=_public_key_fingerprint(
                attestation_private.public_key()
            ),
            attestation_sha256=hashlib.sha256(attestation_raw.encode("ascii")).hexdigest(),
            attestation_signature_sha256=hashlib.sha256(attestation_signature).hexdigest(),
            receipt_issuer="omnigent.database-owner",
            receipt_key_id="receipt-key-v1",
            receipt_public_key_sha256=_public_key_fingerprint(receipt_private.public_key()),
            receipt_sha256=None,
            receipt_signature_sha256=None,
        )
        admission_pins_raw = render_runner_database_fleet_trust_pins(admission_pins)
        _write_0400(trust_pins_path, admission_pins_raw)
        source.update(
            {
                RUNNER_DATABASE_FLEET_TRUST_PINS_FILE_ENV: str(trust_pins_path),
                RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV: hashlib.sha256(
                    admission_pins_raw.encode("ascii")
                ).hexdigest(),
                RUNNER_DATABASE_FLEET_ATTESTATION_FILE_ENV: str(attestation_path),
                RUNNER_DATABASE_FLEET_ATTESTATION_SIGNATURE_FILE_ENV: str(
                    attestation_signature_path
                ),
                RUNNER_DATABASE_FLEET_ATTESTATION_PUBLIC_KEY_FILE_ENV: str(
                    attestation_public_path
                ),
                RUNNER_DATABASE_FLEET_RECEIPT_PRIVATE_KEY_FILE_ENV: str(receipt_private_path),
                RUNNER_DATABASE_FLEET_RECEIPT_PUBLIC_KEY_FILE_ENV: str(receipt_public_path),
            }
        )
        loaded_admission_pins = load_runner_database_fleet_trust_pins(
            source,
            fleet=fleet,
            context=context,
        )
        attestation = load_and_verify_runner_database_fleet_environment_attestation(
            source,
            fleet=fleet,
            context=context,
            pins=loaded_admission_pins,
            now=issued_at,
        )

        third_login = f"runner_{third_runner_id.hex}_g1"
        quoted_third_login = owner_engine.dialect.identifier_preparer.quote(third_login)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_third_login} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8"
            )
        with pytest.raises(RunnerDatabaseFleetError, match="role flags or role set"):
            run_runner_database_fleet_admission(
                engine=owner_engine,
                fleet=fleet,
                context=context,
                trust_pins=loaded_admission_pins,
                environment_attestation=attestation,
                source_sha256s=runner_database_fleet_source_sha256s(),
                now=lambda: issued_at,
            )
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP ROLE {quoted_third_login}")

        receipt = run_runner_database_fleet_admission(
            engine=owner_engine,
            fleet=fleet,
            context=context,
            trust_pins=loaded_admission_pins,
            environment_attestation=attestation,
            source_sha256s=runner_database_fleet_source_sha256s(),
            now=lambda: issued_at,
        )
        signed = sign_runner_database_fleet_admission_receipt(
            source,
            receipt=receipt,
            trust_pins=loaded_admission_pins,
        )
        receipt_path = tmp_path / "runner-database-fleet-admission.json"
        receipt_signature_path = tmp_path / "runner-database-fleet-admission.signature"
        _write_0400(receipt_path, signed.receipt)
        _write_0400(receipt_signature_path, signed.signature)
        runtime_pins = replace(
            loaded_admission_pins,
            stage="runtime",
            receipt_sha256=signed.receipt_sha256,
            receipt_signature_sha256=signed.signature_sha256,
        )
        runtime_pins_raw = render_runner_database_fleet_trust_pins(runtime_pins)
        trust_pins_path.chmod(0o600)
        _write_0400(trust_pins_path, runtime_pins_raw)
        source.update(
            {
                RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV: hashlib.sha256(
                    runtime_pins_raw.encode("ascii")
                ).hexdigest(),
                RUNNER_DATABASE_FLEET_RECEIPT_FILE_ENV: str(receipt_path),
                RUNNER_DATABASE_FLEET_RECEIPT_SIGNATURE_FILE_ENV: str(receipt_signature_path),
                "OMNIGENT_SAAS_PRODUCT_REVISION": context.product_revision,
                "OMNIGENT_SAAS_SOURCE_SHA": context.product_revision,
                "OMNIGENT_SAAS_IMAGE_DIGEST": context.image_digest,
                "OMNIGENT_SAAS_RELEASE_INCARNATION": context.release_incarnation,
                "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": context.schema_revision,
                RUNNER_DATABASE_FLEET_NAMESPACE_ENV: context.namespace,
            }
        )
        source.pop(RUNNER_DATABASE_FLEET_RECEIPT_PRIVATE_KEY_FILE_ENV)
        assert promote_runner_database_fleet_after_admission(factory, source) == runner_ids
        with factory() as database:
            registrations = tuple(
                database.scalars(
                    sa.select(RunnerRegistrationRecord).order_by(RunnerRegistrationRecord.id)
                )
            )
        assert [registration.status for registration in registrations] == ["online", "online"]

        runtime_checked_at = issued_at + timedelta(minutes=10)
        runtime_members = cast(
            tuple[tuple[UUID, int], tuple[UUID, int]],
            tuple((member.runner_id, member.connection_generation) for member in fleet.runners),
        )
        for member in fleet.runners:
            login_engine = sa.create_engine(
                owner_engine.url.set(
                    username=member.login,
                    password=passwords[member.runner_id],
                ),
                pool_pre_ping=True,
            )
            login_engines.append(login_engine)
            admission, members = verify_runner_database_fleet_runtime_admission(
                source,
                runner_id=member.runner_id,
                connection_generation=member.connection_generation,
                now=lambda: runtime_checked_at,
            )
            assert members == runtime_members
            contract_sha256 = _verify_runner_agent_database_authority(
                login_engine,
                runner_id=member.runner_id,
                connection_generation=member.connection_generation,
                fleet_members=members,
            )
            verify_runner_database_fleet_runtime_catalog_binding(
                admission,
                runtime_authority_contract_sha256=contract_sha256,
            )

        first_member = fleet.runners[0]

        def verify_first_runtime() -> None:
            try:
                admission, members = verify_runner_database_fleet_runtime_admission(
                    source,
                    runner_id=first_member.runner_id,
                    connection_generation=first_member.connection_generation,
                    now=lambda: runtime_checked_at,
                )
                contract_sha256 = _verify_runner_agent_database_authority(
                    login_engines[0],
                    runner_id=first_member.runner_id,
                    connection_generation=first_member.connection_generation,
                    fleet_members=members,
                )
                verify_runner_database_fleet_runtime_catalog_binding(
                    admission,
                    runtime_authority_contract_sha256=contract_sha256,
                )
            except (RunnerDatabaseFleetError, RunnerControlError):
                raise RunnerControlError(
                    "runner_executor_not_ready",
                    "Runner database fleet admission is unavailable",
                ) from None

        executor = ProductionHostIsolationExecutor(
            config=SimpleNamespace(
                product_revision=product_revision,
                image_digest=image_digest,
                runner_id=first_member.runner_id,
                connection_generation=first_member.connection_generation,
            ),
            engine=login_engines[0],
            sessions=sessionmaker(login_engines[0], expire_on_commit=False, class_=Session),
            worktrees=cast(WorktreeControlPlane, object()),
            isolation=cast(IsolationControlPlane, object()),
            worktree_adapter=cast(RunnerWorktreeAdapter, object()),
            isolation_adapter=cast(RunnerIsolationAdapter, object()),
            reserved_bytes=1,
            worktree_lease_seconds=30,
            command_timeout_seconds=30,
            database_fleet_verifier=verify_first_runtime,
        )
        executor.assert_claimable()
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_third_login} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8"
            )
        for member, login_engine in zip(fleet.runners, login_engines, strict=True):
            with pytest.raises(RunnerControlError) as rejected:
                _verify_runner_agent_database_authority(
                    login_engine,
                    runner_id=member.runner_id,
                    connection_generation=member.connection_generation,
                    fleet_members=runtime_members,
                )
            assert rejected.value.code == "runner_executor_not_ready"
        with pytest.raises(RunnerControlError) as drifted:
            executor.assert_claimable()
        assert drifted.value.code == "runner_database_authority_drifted"
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP ROLE {quoted_third_login}")
        with pytest.raises(RunnerControlError) as poisoned:
            executor.assert_claimable()
        assert poisoned.value.code == "runner_database_authority_poisoned"
    finally:
        for login_engine in login_engines:
            login_engine.dispose()
        with owner_engine.begin() as connection:
            quoted_third_login = connection.dialect.identifier_preparer.quote(
                f"runner_{third_runner_id.hex}_g1"
            )
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_third_login}")
            for runner_id in runner_ids:
                rows = connection.execute(
                    sa.text(
                        "SELECT rolname FROM pg_roles WHERE rolname ~ :pattern ORDER BY rolname"
                    ),
                    {"pattern": f"^runner_{runner_id.hex}_g[1-9][0-9]*$"},
                ).scalars()
                for login in rows:
                    quoted_login = connection.dialect.identifier_preparer.quote(login)
                    connection.exec_driver_sql(f"REVOKE saas_runner_agent FROM {quoted_login}")
                    connection.exec_driver_sql(f"DROP ROLE {quoted_login}")
            if external_public_database_privileges:
                _restore_external_public_database_privileges(
                    connection,
                    external_public_database_privileges,
                )
            connection.exec_driver_sql(f"REASSIGN OWNED BY {quoted_owner} TO CURRENT_USER")
            connection.exec_driver_sql(f"DROP OWNED BY {quoted_owner}")
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_owner}")
        owner_engine.dispose()
