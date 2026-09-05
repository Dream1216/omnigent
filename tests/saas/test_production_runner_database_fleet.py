from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import saas.production.runner_database_fleet as fleet_module
import saas.production.runner_executor as runner_executor_module
from saas.control_plane import (
    RunnerPoolRecord,
    RunnerRegistrationRecord,
    RuntimePlacementRecord,
    SaasBase,
)
from saas.production.runner_database_fleet import (
    RUNNER_DATABASE_FLEET_ADMIN_URL_FILE_ENV,
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
    RUNNER_DATABASE_FLEET_STAGE_FILE_ENV,
    RUNNER_DATABASE_FLEET_STAGE_SHA256_ENV,
    RUNNER_DATABASE_FLEET_TRUST_PINS_FILE_ENV,
    RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV,
    RunnerDatabaseFleet,
    RunnerDatabaseFleetCatalogProjection,
    RunnerDatabaseFleetError,
    RunnerDatabaseFleetEvidenceContext,
    RunnerDatabaseFleetEvidenceMember,
    RunnerDatabaseFleetMember,
    RunnerDatabaseFleetStageSpec,
    RunnerDatabaseFleetTrustPins,
    RunnerDatabaseIdentityProjection,
    RunnerDatabaseMembershipProjection,
    RunnerDatabaseRegistrationProjection,
    RunnerDatabaseRoleProjection,
    VerifiedRunnerDatabaseFleetAttestation,
    load_and_verify_runner_database_fleet_admission_receipt,
    load_and_verify_runner_database_fleet_environment_attestation,
    load_runner_database_fleet,
    load_runner_database_fleet_admin_database_url,
    load_runner_database_fleet_evidence_context,
    load_runner_database_fleet_stage_specs,
    load_runner_database_fleet_trust_pins,
    render_runner_database_fleet,
    render_runner_database_fleet_evidence_context,
    render_runner_database_fleet_stage_specs,
    render_runner_database_fleet_trust_pins,
    run_runner_database_fleet_admission,
    runner_database_fleet_environment_attestation_document,
    sign_runner_database_fleet_admission_receipt,
    validate_runner_database_fleet_projection,
    verify_runner_database_fleet_release_facts,
)

_RUNNER_A = UUID("11111111-1111-4111-8111-111111111111")
_RUNNER_B = UUID("22222222-2222-4222-8222-222222222222")
_DEPLOYMENT_A = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_DEPLOYMENT_B = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
_SECRET_A = UUID("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
_SECRET_B = UUID("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
_POOL = UUID("44444444-4444-4444-8444-444444444444")
_PLACEMENT = UUID("55555555-5555-4555-8555-555555555555")
_SERVICE = UUID("66666666-6666-4666-8666-666666666666")
_CAPABILITIES = ("shell",)
_CAPABILITIES_SHA256 = hashlib.sha256(b'["shell"]').hexdigest()


def _members() -> tuple[RunnerDatabaseFleetMember, ...]:
    return (
        RunnerDatabaseFleetMember(_RUNNER_A, 1),
        RunnerDatabaseFleetMember(_RUNNER_B, 2),
    )


def _context(*, path: Path = Path("/context"), sha256: str = "c" * 64):
    return RunnerDatabaseFleetEvidenceContext(
        path=path,
        sha256=sha256,
        product_revision="1" * 40,
        image_digest="sha256:" + "2" * 64,
        schema_revision="p0s000000012",
        namespace="omnigent-next-beta",
        release_incarnation="3" * 32,
        admission_epoch=7,
        cnpg_cluster_namespace="omnigent-next-beta-data",
        cnpg_cluster_name="omnigent-next-beta-postgres",
        cnpg_cluster_uid=UUID("33333333-3333-4333-8333-333333333333"),
        cnpg_cluster_resource_version="2001",
        cnpg_postgresql_major=18,
        database="omnigent_next_beta",
        database_oid=16384,
        database_system_identifier="7543210987654321000",
        database_service_name="omnigent-next-beta-postgres-rw",
        database_service_uid=_SERVICE,
        database_service_resource_version="3001",
        database_service_dns=("omnigent-next-beta-postgres-rw.omnigent-next-beta-data.svc"),
        database_service_port=5432,
        database_service_cluster_ip="10.43.12.34",
        database_service_selector_sha256="8" * 64,
        database_endpoint_slices_sha256="9" * 64,
        runners=(
            RunnerDatabaseFleetEvidenceMember(
                slot="a",
                runner_id=_RUNNER_A,
                connection_generation=1,
                pool_id=_POOL,
                placement_id=_PLACEMENT,
                instance_key="runner-a",
                failure_domain="cn-east-1a",
                protocol_version=1,
                source_revision="1" * 40,
                schema_revision="p0s000000012",
                adapter_contract_version="0.2.0",
                capabilities=_CAPABILITIES,
                capabilities_sha256=_CAPABILITIES_SHA256,
                max_concurrency=1,
                deployment_name="omnigent-saas-runner-agent-a",
                deployment_uid=_DEPLOYMENT_A,
                deployment_template_sha256="4" * 64,
                deployment_yaml_sha256="5" * 64,
                database_secret_name="omnigent-saas-runner-agent-a-database-g1",
                database_secret_uid=_SECRET_A,
                database_secret_resource_version="1001",
            ),
            RunnerDatabaseFleetEvidenceMember(
                slot="b",
                runner_id=_RUNNER_B,
                connection_generation=2,
                pool_id=_POOL,
                placement_id=_PLACEMENT,
                instance_key="runner-b",
                failure_domain="cn-east-1a",
                protocol_version=1,
                source_revision="1" * 40,
                schema_revision="p0s000000012",
                adapter_contract_version="0.2.0",
                capabilities=_CAPABILITIES,
                capabilities_sha256=_CAPABILITIES_SHA256,
                max_concurrency=1,
                deployment_name="omnigent-saas-runner-agent-b",
                deployment_uid=_DEPLOYMENT_B,
                deployment_template_sha256="6" * 64,
                deployment_yaml_sha256="7" * 64,
                database_secret_name="omnigent-saas-runner-agent-b-database-g2",
                database_secret_uid=_SECRET_B,
                database_secret_resource_version="1002",
            ),
        ),
    )


def _write_0400(path: Path, value: str) -> None:
    path.write_text(value, encoding="ascii")
    path.chmod(0o400)


def _write_inputs(tmp_path: Path) -> tuple[dict[str, str], RunnerDatabaseFleet]:
    fleet_path = tmp_path / "fleet.json"
    fleet_raw = render_runner_database_fleet(_members())
    _write_0400(fleet_path, fleet_raw)
    context_path = tmp_path / "context.json"
    context_raw = render_runner_database_fleet_evidence_context(_context(path=context_path))
    _write_0400(context_path, context_raw)
    source = {
        RUNNER_DATABASE_FLEET_FILE_ENV: str(fleet_path),
        RUNNER_DATABASE_FLEET_SHA256_ENV: hashlib.sha256(fleet_raw.encode("ascii")).hexdigest(),
        RUNNER_DATABASE_FLEET_CONTEXT_FILE_ENV: str(context_path),
        RUNNER_DATABASE_FLEET_CONTEXT_SHA256_ENV: hashlib.sha256(
            context_raw.encode("ascii")
        ).hexdigest(),
    }
    return source, load_runner_database_fleet(source)


def _role(name: str, *, can_login: bool, connection_limit: int) -> RunnerDatabaseRoleProjection:
    return RunnerDatabaseRoleProjection(
        name=name,
        can_login=can_login,
        is_superuser=False,
        can_create_database=False,
        can_create_role=False,
        can_replicate=False,
        bypasses_rls=False,
        inherits_roles=True,
        connection_limit=connection_limit,
        role_config_is_null=True,
        valid_until_is_null=True,
    )


def _fleet() -> RunnerDatabaseFleet:
    return RunnerDatabaseFleet(Path("/fleet"), "f" * 64, _members())


def _projection() -> RunnerDatabaseFleetCatalogProjection:
    runners = _members()
    roles = tuple(
        sorted(
            (
                _role("saas_runner_agent", can_login=False, connection_limit=-1),
                _role(runners[0].login, can_login=True, connection_limit=8),
                _role(runners[1].login, can_login=True, connection_limit=8),
            ),
            key=lambda item: item.name,
        )
    )
    memberships = tuple(
        RunnerDatabaseMembershipProjection(
            member=runner.login,
            granted_role="saas_runner_agent",
            admin_option=False,
            inherit_option=True,
            set_option=False,
        )
        for runner in runners
    )
    context_members = {member.runner_id: member for member in _context().runners}
    registrations = tuple(
        RunnerDatabaseRegistrationProjection(
            runner_id=runner.runner_id,
            pool_id=context_members[runner.runner_id].pool_id,
            placement_id=context_members[runner.runner_id].placement_id,
            instance_key=context_members[runner.runner_id].instance_key,
            failure_domain=context_members[runner.runner_id].failure_domain,
            connection_generation=runner.connection_generation,
            status="draining",
            connection_token_sha256=("a" if runner.runner_id == _RUNNER_A else "b") * 64,
            protocol_version=context_members[runner.runner_id].protocol_version,
            source_revision=context_members[runner.runner_id].source_revision,
            schema_revision=context_members[runner.runner_id].schema_revision,
            adapter_contract_version=context_members[runner.runner_id].adapter_contract_version,
            capabilities=context_members[runner.runner_id].capabilities,
            capabilities_sha256=context_members[runner.runner_id].capabilities_sha256,
            max_concurrency=context_members[runner.runner_id].max_concurrency,
            active_leases=0,
        )
        for runner in runners
    )
    return RunnerDatabaseFleetCatalogProjection(
        identity=RunnerDatabaseIdentityProjection(
            operator="postgres",
            session_user="postgres",
            database="omnigent_next_beta",
            database_oid=16384,
            server_version_num=180004,
            system_identifier="7543210987654321000",
            in_recovery=False,
            tls=True,
            transaction_read_only=True,
            operator_is_superuser=True,
        ),
        schema_revision="p0s000000012",
        cluster_settings=(
            ("max_notify_queue_pages", "64", "postmaster", False, "configuration file"),
            ("max_prepared_transactions", "0", "postmaster", False, "configuration file"),
        ),
        prepared_transaction_count=0,
        roles=roles,
        memberships=memberships,
        direct_acl_count=0,
        owned_object_count=0,
        role_setting_count=0,
        user_mapping_count=0,
        direct_policy_count=0,
        registrations=registrations,
    )


def _trust_pins() -> RunnerDatabaseFleetTrustPins:
    return RunnerDatabaseFleetTrustPins(
        path=Path("/trust-pins"),
        sha256="d" * 64,
        stage="admission",
        admission_epoch=7,
        product_revision="1" * 40,
        schema_revision="p0s000000012",
        fleet_sha256="f" * 64,
        evidence_context_sha256="c" * 64,
        attestation_issuer="omnigent.gitops",
        attestation_key_id="environment-key-v1",
        attestation_public_key_sha256="e" * 64,
        attestation_sha256="9" * 64,
        attestation_signature_sha256="8" * 64,
        receipt_issuer="omnigent.database-owner",
        receipt_key_id="receipt-key-v1",
        receipt_public_key_sha256="7" * 64,
        receipt_sha256=None,
        receipt_signature_sha256=None,
    )


def _attestation() -> VerifiedRunnerDatabaseFleetAttestation:
    return VerifiedRunnerDatabaseFleetAttestation(
        document={},
        sha256="9" * 64,
        signature_sha256="8" * 64,
        public_key_sha256="e" * 64,
        issued_at=datetime(2026, 9, 2, 11, 55, tzinfo=UTC),
        expires_at=datetime(2026, 9, 2, 12, 5, tzinfo=UTC),
    )


def _stage_specs() -> tuple[RunnerDatabaseFleetStageSpec, RunnerDatabaseFleetStageSpec]:
    return (
        RunnerDatabaseFleetStageSpec(
            runner_id=_RUNNER_A,
            pool_id=_POOL,
            placement_id=_PLACEMENT,
            instance_key="runner-a",
            failure_domain="cn-east-1a",
            protocol_version=1,
            source_revision="1" * 40,
            schema_revision="p0s000000012",
            adapter_contract_version="0.2.0",
            capabilities=_CAPABILITIES,
            max_concurrency=1,
        ),
        RunnerDatabaseFleetStageSpec(
            runner_id=_RUNNER_B,
            pool_id=_POOL,
            placement_id=_PLACEMENT,
            instance_key="runner-b",
            failure_domain="cn-east-1a",
            protocol_version=1,
            source_revision="1" * 40,
            schema_revision="p0s000000012",
            adapter_contract_version="0.2.0",
            capabilities=_CAPABILITIES,
            max_concurrency=1,
        ),
    )


def _promotion_database(
    *,
    third_runner: bool = False,
    drift_max_concurrency: bool = False,
) -> tuple[Engine, sessionmaker[Session]]:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
    projection = _projection()
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=_PLACEMENT,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="runner-db",
                object_store_ref="runner-objects",
                kms_key_ref="runner-kms",
                official_schema_revision="p0s000000012",
                capacity_class="runner-dedicated",
                status="active",
            )
        )
        db.add(
            RunnerPoolRecord(
                id=_POOL,
                placement_id=_PLACEMENT,
                failure_domain="cn-east-1a",
                name="runner-fleet",
                queue_class="interactive",
                capacity_slots=3,
                reserved_slots=0,
                status="active",
                protocol_version=1,
                source_revision="1" * 40,
                schema_revision="p0s000000012",
                adapter_contract_version="0.2.0",
            )
        )
        for index, registration in enumerate(projection.registrations):
            db.add(
                RunnerRegistrationRecord(
                    id=registration.runner_id,
                    pool_id=registration.pool_id,
                    placement_id=registration.placement_id,
                    instance_key=registration.instance_key,
                    failure_domain=registration.failure_domain,
                    status=registration.status,
                    connection_generation=registration.connection_generation,
                    connection_token_hash=registration.connection_token_sha256,
                    protocol_version=registration.protocol_version,
                    source_revision=registration.source_revision,
                    schema_revision=registration.schema_revision,
                    adapter_contract_version=registration.adapter_contract_version,
                    capabilities=list(registration.capabilities),
                    capabilities_hash=registration.capabilities_sha256,
                    max_concurrency=(
                        2 if drift_max_concurrency and index == 0 else registration.max_concurrency
                    ),
                    active_leases=registration.active_leases,
                    last_heartbeat_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
                    registered_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
                )
            )
        if third_runner:
            db.add(
                RunnerRegistrationRecord(
                    id=UUID("77777777-7777-4777-8777-777777777777"),
                    pool_id=_POOL,
                    placement_id=_PLACEMENT,
                    instance_key="runner-c",
                    failure_domain="cn-east-1a",
                    status="online",
                    connection_generation=1,
                    connection_token_hash="7" * 64,
                    protocol_version=1,
                    source_revision="1" * 40,
                    schema_revision="p0s000000012",
                    adapter_contract_version="0.2.0",
                    capabilities=["shell"],
                    capabilities_hash=_CAPABILITIES_SHA256,
                    max_concurrency=1,
                    active_leases=0,
                    last_heartbeat_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
                    registered_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
                )
            )
    return engine, factory


def test_exact_two_runner_database_fleet_is_canonical_and_hash_bound(tmp_path: Path) -> None:
    source, fleet = _write_inputs(tmp_path)

    assert fleet.runners == _members()
    assert fleet.sha256 == source[RUNNER_DATABASE_FLEET_SHA256_ENV]
    assert [runner.login for runner in fleet.runners] == [
        "runner_11111111111141118111111111111111_g1",
        "runner_22222222222242228222222222222222_g2",
    ]
    assert fleet.path.read_text(encoding="ascii") == render_runner_database_fleet(fleet.runners)


def test_stage_specs_are_canonical_and_reject_wrong_scalar_types(tmp_path: Path) -> None:
    raw = render_runner_database_fleet_stage_specs(_stage_specs())
    path = tmp_path / "stage.json"
    _write_0400(path, raw)
    source = {
        RUNNER_DATABASE_FLEET_STAGE_FILE_ENV: str(path),
        RUNNER_DATABASE_FLEET_STAGE_SHA256_ENV: hashlib.sha256(raw.encode("ascii")).hexdigest(),
    }
    assert load_runner_database_fleet_stage_specs(source) == _stage_specs()

    document = json.loads(raw)
    document["runners"][0]["protocol_version"] = "1"
    invalid = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    path.chmod(0o600)
    _write_0400(path, invalid)
    source[RUNNER_DATABASE_FLEET_STAGE_SHA256_ENV] = hashlib.sha256(
        invalid.encode("ascii")
    ).hexdigest()
    with pytest.raises(RunnerDatabaseFleetError, match="member values"):
        load_runner_database_fleet_stage_specs(source)


def test_owner_stage_has_no_online_window_and_rolls_back_partial_or_third_runner() -> None:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
    staged_at = datetime(2026, 9, 2, 9, 0, tzinfo=UTC)
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=_PLACEMENT,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="runner-db",
                object_store_ref="runner-objects",
                kms_key_ref="runner-kms",
                official_schema_revision="p0s000000012",
                capacity_class="runner-dedicated",
                status="active",
            )
        )
        db.add(
            RunnerPoolRecord(
                id=_POOL,
                placement_id=_PLACEMENT,
                failure_domain="cn-east-1a",
                name="runner-fleet",
                queue_class="interactive",
                capacity_slots=2,
                reserved_slots=0,
                status="active",
                protocol_version=1,
                source_revision="1" * 40,
                schema_revision="p0s000000012",
                adapter_contract_version="0.2.0",
            )
        )
    with factory.begin() as db:
        staged = fleet_module._stage_runner_database_fleet_in_transaction(
            db,
            specs=_stage_specs(),
            staged_at=staged_at,
        )
    assert [(row.connection_generation, row.status) for row in staged] == [
        (1, "draining"),
        (1, "draining"),
    ]
    with factory() as db:
        rows = tuple(
            db.scalars(sa.select(RunnerRegistrationRecord).order_by(RunnerRegistrationRecord.id))
        )
        assert [(row.id, row.status, row.active_leases) for row in rows] == [
            (_RUNNER_A, "draining", 0),
            (_RUNNER_B, "draining", 0),
        ]
        assert [row.connection_token_hash for row in rows] == [
            hashlib.sha256(staged[0].connection_token.encode()).hexdigest(),
            hashlib.sha256(staged[1].connection_token.encode()).hexdigest(),
        ]

    with factory.begin() as db:
        first = db.get(RunnerRegistrationRecord, _RUNNER_A)
        second = db.get(RunnerRegistrationRecord, _RUNNER_B)
        assert first is not None and second is not None
        first.status = "offline"
        second.status = "online"
    with pytest.raises(RunnerDatabaseFleetError, match="drained or offline"):
        with factory.begin() as db:
            fleet_module._stage_runner_database_fleet_in_transaction(
                db,
                specs=_stage_specs(),
                staged_at=staged_at,
            )
    with factory() as db:
        first = db.get(RunnerRegistrationRecord, _RUNNER_A)
        assert first is not None
        assert (first.status, first.connection_generation) == ("offline", 1)

    third_id = UUID("77777777-7777-4777-8777-777777777777")
    with factory.begin() as db:
        second = db.get(RunnerRegistrationRecord, _RUNNER_B)
        assert second is not None
        second.status = "draining"
        db.add(
            RunnerRegistrationRecord(
                id=third_id,
                pool_id=_POOL,
                placement_id=_PLACEMENT,
                instance_key="runner-c",
                failure_domain="cn-east-1a",
                status="online",
                connection_generation=1,
                connection_token_hash="7" * 64,
                protocol_version=1,
                source_revision="1" * 40,
                schema_revision="p0s000000012",
                adapter_contract_version="0.2.0",
                capabilities=["shell"],
                capabilities_hash=_CAPABILITIES_SHA256,
                max_concurrency=1,
                active_leases=0,
                last_heartbeat_at=staged_at,
                registered_at=staged_at,
            )
        )
    with pytest.raises(RunnerDatabaseFleetError, match="third active"):
        with factory.begin() as db:
            fleet_module._stage_runner_database_fleet_in_transaction(
                db,
                specs=_stage_specs(),
                staged_at=staged_at,
            )
    engine.dispose()


@pytest.mark.parametrize(
    "mutator, message",
    [
        (lambda document: document["runners"].pop(), "exactly two"),
        (
            lambda document: document["runners"][0].update(connection_generation=True),
            "positive bigint",
        ),
        (
            lambda document: document["runners"][0].update(runner_id=str(_RUNNER_B)),
            "unique",
        ),
        (lambda document: document.update(extra=True), "document shape"),
    ],
)
def test_runner_database_fleet_rejects_non_exact_documents(
    tmp_path: Path,
    mutator: Any,
    message: str,
) -> None:
    raw = render_runner_database_fleet(_members())
    document = json.loads(raw)
    mutator(document)
    invalid = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    path = tmp_path / "fleet.json"
    _write_0400(path, invalid)
    source = {
        RUNNER_DATABASE_FLEET_FILE_ENV: str(path),
        RUNNER_DATABASE_FLEET_SHA256_ENV: hashlib.sha256(invalid.encode("ascii")).hexdigest(),
    }

    with pytest.raises(RunnerDatabaseFleetError, match=message):
        load_runner_database_fleet(source)


def test_runner_database_fleet_rejects_mutable_symlink_and_wrong_hash(tmp_path: Path) -> None:
    raw = render_runner_database_fleet(_members())
    path = tmp_path / "fleet.json"
    path.write_text(raw, encoding="ascii")
    source = {
        RUNNER_DATABASE_FLEET_FILE_ENV: str(path),
        RUNNER_DATABASE_FLEET_SHA256_ENV: hashlib.sha256(raw.encode("ascii")).hexdigest(),
    }
    with pytest.raises(RunnerDatabaseFleetError, match=r"owner-readable|inspected"):
        load_runner_database_fleet(source)

    path.chmod(0o400)
    source[RUNNER_DATABASE_FLEET_SHA256_ENV] = "9" * 64
    with pytest.raises(RunnerDatabaseFleetError, match="SHA256"):
        load_runner_database_fleet(source)

    source[RUNNER_DATABASE_FLEET_SHA256_ENV] = hashlib.sha256(raw.encode("ascii")).hexdigest()
    link = tmp_path / "fleet-link.json"
    link.symlink_to(path)
    source[RUNNER_DATABASE_FLEET_FILE_ENV] = str(link)
    with pytest.raises(RunnerDatabaseFleetError, match=r"owner-readable|inspected"):
        load_runner_database_fleet(source)


def test_evidence_context_binds_deployments_templates_secret_metadata_and_fleet(
    tmp_path: Path,
) -> None:
    source, fleet = _write_inputs(tmp_path)
    context = load_runner_database_fleet_evidence_context(source, fleet=fleet)

    assert context.namespace == "omnigent-next-beta"
    assert context.cnpg_cluster_namespace == "omnigent-next-beta-data"
    assert context.runners[0].deployment_uid == _DEPLOYMENT_A
    assert context.runners[1].deployment_template_sha256 == "6" * 64
    assert context.runners[0].database_secret_uid == _SECRET_A
    rendered = context.path.read_text(encoding="ascii")
    assert "database_secret_resource_version" in rendered
    assert "deployment_template_sha256" in rendered
    assert "database_secret_value" not in rendered
    assert "postgresql+psycopg" not in rendered


def test_evidence_context_rejects_pair_or_metadata_drift(tmp_path: Path) -> None:
    source, fleet = _write_inputs(tmp_path)
    context_path = Path(source[RUNNER_DATABASE_FLEET_CONTEXT_FILE_ENV])
    document = json.loads(context_path.read_text(encoding="ascii"))
    document["runners"][1]["runner_id"] = str(_RUNNER_A)
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    context_path.chmod(0o600)
    _write_0400(context_path, raw)
    source[RUNNER_DATABASE_FLEET_CONTEXT_SHA256_ENV] = hashlib.sha256(
        raw.encode("ascii")
    ).hexdigest()
    with pytest.raises(RunnerDatabaseFleetError, match="identities must be unique"):
        load_runner_database_fleet_evidence_context(source, fleet=fleet)

    document["runners"][1]["runner_id"] = str(_RUNNER_B)
    document["runners"][1]["database_secret_name"] = "shared-executor-database"
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    context_path.chmod(0o600)
    _write_0400(context_path, raw)
    source[RUNNER_DATABASE_FLEET_CONTEXT_SHA256_ENV] = hashlib.sha256(
        raw.encode("ascii")
    ).hexdigest()
    with pytest.raises(RunnerDatabaseFleetError, match="Secret name"):
        load_runner_database_fleet_evidence_context(source, fleet=fleet)


def test_release_facts_must_match_the_evidence_context() -> None:
    context = _context()
    source = {
        "OMNIGENT_SAAS_PRODUCT_REVISION": context.product_revision,
        "OMNIGENT_SAAS_SOURCE_SHA": context.product_revision,
        "OMNIGENT_SAAS_IMAGE_DIGEST": context.image_digest,
        "OMNIGENT_SAAS_RELEASE_INCARNATION": context.release_incarnation,
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": context.schema_revision,
        RUNNER_DATABASE_FLEET_NAMESPACE_ENV: context.namespace,
    }
    verify_runner_database_fleet_release_facts(source, context)

    source["OMNIGENT_SAAS_IMAGE_DIGEST"] = "sha256:" + "9" * 64
    with pytest.raises(RunnerDatabaseFleetError, match="release facts"):
        verify_runner_database_fleet_release_facts(source, context)


def test_admin_database_authority_is_only_loaded_from_one_exact_0400_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "admin-url"
    raw = (
        "postgresql+psycopg://managed_admin:do-not-print@"
        "omnigent-next-beta-postgres-rw.omnigent-next-beta-data.svc:5432/"
        "omnigent_next_beta?"
        "sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt&"
        "target_session_attrs=read-write"
    )
    _write_0400(path, raw)
    source = {RUNNER_DATABASE_FLEET_ADMIN_URL_FILE_ENV: str(path)}

    loaded, parsed, loaded_path = load_runner_database_fleet_admin_database_url(
        source,
        context=_context(),
    )

    assert loaded == raw
    assert parsed.username == "managed_admin"
    assert loaded_path == path

    source["DATABASE_URL"] = raw
    with pytest.raises(RunnerDatabaseFleetError, match="ambient database authority"):
        load_runner_database_fleet_admin_database_url(source, context=_context())


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda projection: replace(projection, direct_acl_count=1), "direct database"),
        (lambda projection: replace(projection, owned_object_count=1), "direct database"),
        (lambda projection: replace(projection, direct_policy_count=1), "direct database"),
        (
            lambda projection: replace(
                projection,
                roles=(
                    *projection.roles,
                    _role("runner_" + "3" * 32 + "_g1", can_login=True, connection_limit=8),
                ),
            ),
            "role flags or role set",
        ),
        (
            lambda projection: replace(
                projection,
                roles=(
                    replace(projection.roles[0], role_config_is_null=False),
                    *projection.roles[1:],
                ),
            ),
            "role flags or role set",
        ),
        (
            lambda projection: replace(
                projection,
                memberships=(
                    *projection.memberships,
                    RunnerDatabaseMembershipProjection(
                        member="saas_runner_agent",
                        granted_role="pg_read_all_data",
                        admin_option=False,
                        inherit_option=True,
                        set_option=False,
                    ),
                ),
            ),
            "membership graph",
        ),
        (
            lambda projection: replace(
                projection,
                memberships=(
                    *projection.memberships,
                    RunnerDatabaseMembershipProjection(
                        member="postgres",
                        granted_role=_members()[0].login,
                        admin_option=False,
                        inherit_option=True,
                        set_option=False,
                    ),
                ),
            ),
            "membership graph",
        ),
        (
            lambda projection: replace(
                projection,
                registrations=(
                    replace(projection.registrations[0], status="online"),
                    *projection.registrations[1:],
                ),
            ),
            "registrations",
        ),
        (
            lambda projection: replace(
                projection,
                cluster_settings=(
                    ("max_notify_queue_pages", "32", "postmaster", False, "configuration file"),
                    projection.cluster_settings[1],
                ),
            ),
            "settings",
        ),
    ],
)
def test_projection_rejects_stale_login_membership_acl_and_registration_drift(
    change: Any,
    message: str,
) -> None:
    with pytest.raises(RunnerDatabaseFleetError, match=message):
        validate_runner_database_fleet_projection(
            fleet=_fleet(),
            context=_context(),
            projection=change(_projection()),
        )


def test_valid_projection_has_stable_role_acl_digest() -> None:
    projection = _projection()
    digest = validate_runner_database_fleet_projection(
        fleet=_fleet(),
        context=_context(),
        projection=projection,
    )

    assert len(digest) == 64
    assert digest == validate_runner_database_fleet_projection(
        fleet=_fleet(),
        context=_context(),
        projection=projection,
    )


class _Transaction:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_args: object) -> None:
        return None


class _Connection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def begin(self) -> _Transaction:
        return _Transaction()

    def exec_driver_sql(self, statement: str) -> None:
        self.statements.append(statement)


class _Engine:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self) -> None:
        self.connection = _Connection()

    def connect(self) -> _Connection:
        return self.connection


def test_owner_admission_is_read_only_and_receipt_binds_all_nonsecret_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = _projection()
    monkeypatch.setattr(
        fleet_module,
        "inspect_runner_database_fleet_projection",
        lambda _connection, *, fleet: projection,
    )
    monkeypatch.setattr(
        runner_executor_module,
        "_verify_runner_agent_database_authority",
        lambda *_args, **_kwargs: "e" * 64,
    )
    engine = _Engine()
    source_hashes = {
        "cluster_sql": "1" * 64,
        "roles_sql": "2" * 64,
        "runner_database_fleet": "3" * 64,
        "runner_executor": "4" * 64,
        "verify_runner_database_fleet": "5" * 64,
    }

    receipt = run_runner_database_fleet_admission(
        engine=engine,  # type: ignore[arg-type]
        fleet=_fleet(),
        context=_context(),
        trust_pins=_trust_pins(),
        environment_attestation=_attestation(),
        source_sha256s=source_hashes,
        now=lambda: datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert engine.connection.statements == [
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
        "SET LOCAL SESSION AUTHORIZATION 'runner_11111111111141118111111111111111_g1'",
        "RESET SESSION AUTHORIZATION",
        "SET LOCAL SESSION AUTHORIZATION 'runner_22222222222242228222222222222222_g2'",
        "RESET SESSION AUTHORIZATION",
    ]
    assert receipt["runner_database_fleet_sha256"] == "f" * 64
    assert receipt["evidence_context_sha256"] == "c" * 64
    assert receipt["source_sha256s"] == source_hashes
    assert receipt["operator"] == "postgres"
    assert receipt["verified_at"] == "2026-09-02T12:00:00Z"
    assert receipt["runner_registrations"] == [
        {
            "active_leases": 0,
            "connection_generation": 1,
            "runner_id": str(_RUNNER_A),
            "status": "draining",
        },
        {
            "active_leases": 0,
            "connection_generation": 2,
            "runner_id": str(_RUNNER_B),
            "status": "draining",
        },
    ]
    rendered = repr(receipt)
    assert "do-not-print" not in rendered
    assert "database_secret" not in rendered


def test_environment_and_receipt_signatures_are_pinned_and_runtime_survives_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, fleet = _write_inputs(tmp_path)
    context = load_runner_database_fleet_evidence_context(source, fleet=fleet)
    attestation_private = Ed25519PrivateKey.generate()
    receipt_private = Ed25519PrivateKey.generate()
    attestation_public_path = tmp_path / "attestation-public.pem"
    receipt_public_path = tmp_path / "receipt-public.pem"
    receipt_private_path = tmp_path / "receipt-private.pem"
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
    issued_at = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
    attestation_document = runner_database_fleet_environment_attestation_document(
        fleet=fleet,
        context=context,
        issuer="omnigent.gitops",
        key_id="environment-key-v1",
        issued_at=issued_at,
        expires_at=issued_at.replace(minute=10),
    )
    attestation_raw = fleet_module._canonical_json(attestation_document)
    attestation_signature = attestation_private.sign(
        fleet_module.admission_signature_payload(attestation_document)
    )
    attestation_path = tmp_path / "attestation.json"
    attestation_signature_path = tmp_path / "attestation.signature"
    _write_0400(attestation_path, attestation_raw)
    _write_0400(
        attestation_signature_path,
        fleet_module.base64.b64encode(attestation_signature).decode("ascii"),
    )
    admission_pins = RunnerDatabaseFleetTrustPins(
        path=tmp_path / "trust-pins.json",
        sha256="d" * 64,
        stage="admission",
        admission_epoch=context.admission_epoch,
        product_revision=context.product_revision,
        schema_revision=context.schema_revision,
        fleet_sha256=fleet.sha256,
        evidence_context_sha256=context.sha256,
        attestation_issuer="omnigent.gitops",
        attestation_key_id="environment-key-v1",
        attestation_public_key_sha256=fleet_module._public_key_fingerprint(
            attestation_private.public_key()
        ),
        attestation_sha256=hashlib.sha256(attestation_raw.encode()).hexdigest(),
        attestation_signature_sha256=hashlib.sha256(attestation_signature).hexdigest(),
        receipt_issuer="omnigent.database-owner",
        receipt_key_id="receipt-key-v1",
        receipt_public_key_sha256=fleet_module._public_key_fingerprint(
            receipt_private.public_key()
        ),
        receipt_sha256=None,
        receipt_signature_sha256=None,
    )
    pins_raw = render_runner_database_fleet_trust_pins(admission_pins)
    _write_0400(admission_pins.path, pins_raw)
    source.update(
        {
            RUNNER_DATABASE_FLEET_TRUST_PINS_FILE_ENV: str(admission_pins.path),
            RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV: hashlib.sha256(
                pins_raw.encode()
            ).hexdigest(),
            RUNNER_DATABASE_FLEET_ATTESTATION_FILE_ENV: str(attestation_path),
            RUNNER_DATABASE_FLEET_ATTESTATION_SIGNATURE_FILE_ENV: str(attestation_signature_path),
            RUNNER_DATABASE_FLEET_ATTESTATION_PUBLIC_KEY_FILE_ENV: str(attestation_public_path),
            RUNNER_DATABASE_FLEET_RECEIPT_PRIVATE_KEY_FILE_ENV: str(receipt_private_path),
            RUNNER_DATABASE_FLEET_RECEIPT_PUBLIC_KEY_FILE_ENV: str(receipt_public_path),
        }
    )
    loaded_pins = load_runner_database_fleet_trust_pins(
        source,
        fleet=fleet,
        context=context,
    )
    attestation = load_and_verify_runner_database_fleet_environment_attestation(
        source,
        fleet=fleet,
        context=context,
        pins=loaded_pins,
        now=issued_at,
    )
    projection = _projection()
    monkeypatch.setattr(
        fleet_module,
        "inspect_runner_database_fleet_projection",
        lambda _connection, *, fleet: projection,
    )
    monkeypatch.setattr(
        runner_executor_module,
        "_verify_runner_agent_database_authority",
        lambda *_args, **_kwargs: "e" * 64,
    )
    source_hashes = {
        "cluster_sql": "1" * 64,
        "roles_sql": "2" * 64,
        "runner_database_fleet": "3" * 64,
        "runner_executor": "4" * 64,
        "verify_runner_database_fleet": "5" * 64,
    }
    receipt = run_runner_database_fleet_admission(
        engine=_Engine(),  # type: ignore[arg-type]
        fleet=fleet,
        context=context,
        trust_pins=loaded_pins,
        environment_attestation=attestation,
        source_sha256s=source_hashes,
        now=lambda: issued_at,
    )
    signed = sign_runner_database_fleet_admission_receipt(
        source,
        receipt=receipt,
        trust_pins=loaded_pins,
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_signature_path = tmp_path / "receipt.signature"
    _write_0400(receipt_path, signed.receipt)
    _write_0400(receipt_signature_path, signed.signature)
    runtime_pins = replace(
        loaded_pins,
        stage="runtime",
        receipt_sha256=signed.receipt_sha256,
        receipt_signature_sha256=signed.signature_sha256,
    )
    runtime_pins_raw = render_runner_database_fleet_trust_pins(runtime_pins)
    admission_pins.path.chmod(0o600)
    _write_0400(admission_pins.path, runtime_pins_raw)
    source.update(
        {
            RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256_ENV: hashlib.sha256(
                runtime_pins_raw.encode()
            ).hexdigest(),
            RUNNER_DATABASE_FLEET_RECEIPT_FILE_ENV: str(receipt_path),
            RUNNER_DATABASE_FLEET_RECEIPT_SIGNATURE_FILE_ENV: str(receipt_signature_path),
        }
    )
    loaded_runtime_pins = load_runner_database_fleet_trust_pins(
        source,
        fleet=fleet,
        context=context,
    )
    runtime_attestation = load_and_verify_runner_database_fleet_environment_attestation(
        source,
        fleet=fleet,
        context=context,
        pins=loaded_runtime_pins,
        now=issued_at.replace(minute=20),
        enforce_expiry=False,
    )
    with pytest.raises(RunnerDatabaseFleetError, match="expired"):
        load_and_verify_runner_database_fleet_admission_receipt(
            source,
            fleet=fleet,
            context=context,
            trust_pins=loaded_runtime_pins,
            environment_attestation=runtime_attestation,
            now=issued_at.replace(minute=20),
        )
    verified = load_and_verify_runner_database_fleet_admission_receipt(
        source,
        fleet=fleet,
        context=context,
        trust_pins=loaded_runtime_pins,
        environment_attestation=runtime_attestation,
        now=issued_at.replace(minute=20),
        enforce_promotion_deadline=False,
    )
    assert verified.receipt_sha256 == signed.receipt_sha256

    promotion_engine, promotion_factory = _promotion_database()
    monkeypatch.setattr(
        fleet_module,
        "_require_postgresql_fleet_table_lock",
        lambda _db: issued_at.replace(minute=4),
    )
    assert fleet_module.promote_runner_database_fleet_after_admission(
        promotion_factory,
        source,
    ) == (_RUNNER_A, _RUNNER_B)
    with promotion_factory() as db:
        promoted = tuple(
            db.scalars(sa.select(RunnerRegistrationRecord).order_by(RunnerRegistrationRecord.id))
        )
        event = db.scalar(
            sa.select(fleet_module.ControlPlaneOutboxEvent).where(
                fleet_module.ControlPlaneOutboxEvent.event_type == "runner.fleet.promoted"
            )
        )
    assert [(row.id, row.connection_generation, row.status) for row in promoted] == [
        (_RUNNER_A, 1, "online"),
        (_RUNNER_B, 2, "online"),
    ]
    assert [row.connection_token_hash for row in promoted] == ["a" * 64, "b" * 64]
    assert event is not None
    assert event.payload["admission_epoch"] == context.admission_epoch
    promotion_engine.dispose()

    expired_engine, expired_factory = _promotion_database()
    monkeypatch.setattr(
        fleet_module,
        "_require_postgresql_fleet_table_lock",
        lambda _db: issued_at.replace(minute=6),
    )
    with pytest.raises(RunnerDatabaseFleetError, match="expired"):
        fleet_module.promote_runner_database_fleet_after_admission(expired_factory, source)
    with expired_factory() as db:
        assert set(db.scalars(sa.select(RunnerRegistrationRecord.status))) == {"draining"}
    expired_engine.dispose()

    for database_options, message in (
        ({"third_runner": True}, "registrations"),
        ({"drift_max_concurrency": True}, "registrations"),
    ):
        rejected_engine, rejected_factory = _promotion_database(**database_options)
        monkeypatch.setattr(
            fleet_module,
            "_require_postgresql_fleet_table_lock",
            lambda _db: issued_at.replace(minute=4),
        )
        with pytest.raises(RunnerDatabaseFleetError, match=message):
            fleet_module.promote_runner_database_fleet_after_admission(
                rejected_factory,
                source,
            )
        with rejected_factory() as db:
            target_statuses = set(
                db.scalars(
                    sa.select(RunnerRegistrationRecord.status).where(
                        RunnerRegistrationRecord.id.in_((_RUNNER_A, _RUNNER_B))
                    )
                )
            )
            assert target_statuses == {"draining"}
        rejected_engine.dispose()

    receipt_signature_path.chmod(0o600)
    _write_0400(receipt_signature_path, fleet_module.base64.b64encode(b"x" * 64).decode())
    with pytest.raises(RunnerDatabaseFleetError, match="signature"):
        load_and_verify_runner_database_fleet_admission_receipt(
            source,
            fleet=fleet,
            context=context,
            trust_pins=loaded_runtime_pins,
            environment_attestation=runtime_attestation,
            now=issued_at.replace(minute=20),
            enforce_promotion_deadline=False,
        )
