from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_security import PlatformSecurityError, ValidatedPlatformPrincipal
from saas.control_plane.privacy_attestation import (
    PrivacyAttestationVerifier,
    canonical_json,
    privacy_verifier_receipt_sha256,
)
from saas.control_plane.privacy_execution import (
    PrivacyExecutionPolicy,
    PrivacyExecutionService,
    WorkloadIdentity,
)
from saas.control_plane.privacy_lifecycle import DeletionEvidenceKey, PrivacyLifecycleService
from saas.privacy_worker import verify_privacy_worker_database_role

_OUTBOX_INSERT = sa.text(
    "INSERT INTO saas_control_plane_outbox "
    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
    "idempotency_key, request_hash, attempt_count) VALUES "
    "(:id, :tenant_id, 'privacy_manifest', :aggregate_key, :event_type, "
    "jsonb_build_object('schema_version', 1, "
    "'manifest_id', CAST(:manifest_id AS text), 'target_type', 'tenant', "
    "'target_locator_hmac', CAST(:target_locator_hmac AS text), "
    "'item_id', CAST(:item_id AS text), 'attempt_id', CAST(:attempt_id AS text), "
    "'attempt_number', CAST(:attempt_number AS integer), "
    "'replay_generation', CAST(:replay_generation AS integer), "
    "'surface', CAST(:surface AS text), 'status', CAST(:status AS text), "
    "'content_sha256', CAST(:content_sha256 AS text), "
    "'error_code', CAST(:error_code AS text), "
    "'available_at', CAST(:available_at AS text)), "
    ":idempotency_key, :request_hash, 0)"
)


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip(
            "OMNIGENT_SAAS_TEST_POSTGRES_URL is required for Privacy dispatcher acceptance"
        )
    return value


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _set_dispatch_scope(
    connection: sa.Connection,
    *,
    tenant_id: UUID,
    manifest_id: UUID,
    locator_hash: str = "",
) -> None:
    connection.execute(
        sa.text(
            "SELECT "
            "set_config('app.platform_target_tenant_id', :tenant_id, true), "
            "set_config('app.platform_target_user_id', '', true), "
            "set_config('app.platform_privacy_manifest_id', :manifest_id, true), "
            "set_config('app.privacy_locator_hash', :locator_hash, true)"
        ),
        {
            "tenant_id": str(tenant_id),
            "manifest_id": str(manifest_id),
            "locator_hash": locator_hash,
        },
    )


def _assert_sqlstate(
    engine: sa.Engine,
    statement: str,
    parameters: dict[str, object],
    *,
    expected_sqlstate: str,
    role: str | None = None,
) -> None:
    with engine.connect() as connection:
        transaction = connection.begin()
        if role is not None:
            connection.exec_driver_sql(f'SET LOCAL ROLE "{role}"')
        with pytest.raises(DBAPIError) as captured:
            connection.execute(sa.text(statement), parameters)
        transaction.rollback()
    assert getattr(captured.value.orig, "sqlstate", None) == expected_sqlstate


def _assert_outbox_insert_denied(
    engine: sa.Engine,
    *,
    scope_tenant_id: UUID,
    scope_manifest_id: UUID,
    values: dict[str, object],
) -> None:
    with engine.connect() as connection:
        transaction = connection.begin()
        _set_dispatch_scope(
            connection,
            tenant_id=scope_tenant_id,
            manifest_id=scope_manifest_id,
        )
        with pytest.raises(DBAPIError) as captured:
            connection.execute(_OUTBOX_INSERT, values)
        transaction.rollback()
    assert getattr(captured.value.orig, "sqlstate", None) == "42501"


def _seed_privacy_execution(
    connection: sa.Connection,
    *,
    principal_id: UUID,
    tenant_a: UUID,
    tenant_b: UUID,
    manifest_a: UUID,
    manifest_b: UUID,
    work_a: UUID,
    work_b: UUID,
    backup_a: UUID,
    backup_b: UUID,
    suffix: str,
    now: datetime,
) -> None:
    connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
    connection.execute(
        sa.text(
            "INSERT INTO saas_platform_staff_principals "
            "(id, identity_connection_ref, issuer, subject, status, security_version) "
            "VALUES (:id, :identity_ref, :issuer, :subject, 'active', 1)"
        ),
        {
            "id": principal_id,
            "identity_ref": f"privacy-dispatcher-test:{suffix}",
            "issuer": "https://staff-idp.example.test",
            "subject": f"privacy-dispatcher-{suffix}",
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_platform_role_assignments "
            "(id, principal_id, role, status, version, assigned_by_principal_id, "
            "approval_ref, reason) VALUES "
            "(:id, :principal, 'compliance_operator', 'active', 1, :principal, "
            "'privacy-hold-fence-acceptance', 'Privacy Hold fence acceptance')"
        ),
        {"id": uuid4(), "principal": principal_id},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_tenants "
            "(id, slug, name, status, plan, home_region) VALUES "
            "(:tenant_a, :slug_a, 'Privacy RLS A', 'active', 'enterprise', 'cn-east-1'), "
            "(:tenant_b, :slug_b, 'Privacy RLS B', 'active', 'enterprise', 'cn-east-1')"
        ),
        {
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "slug_a": f"privacy-rls-a-{suffix}",
            "slug_b": f"privacy-rls-b-{suffix}",
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_privacy_deletion_manifests "
            "(id, target_type, target_id, tenant_id, requested_by_principal_id, "
            "idempotency_key, request_hash, approval_ref, reason, expected_target_version, "
            "preview_hash, status, blockers, surface_outcomes, version, started_at) VALUES "
            "(:manifest_a, 'tenant', :tenant_a, :tenant_a, :principal, :key_a, :hash_a, "
            "'privacy-rls-approval-a', 'Privacy dispatcher RLS acceptance A', 1, :preview_a, "
            "'executing', CAST('[]' AS json), CAST('{}' AS json), 1, :now), "
            "(:manifest_b, 'tenant', :tenant_b, :tenant_b, :principal, :key_b, :hash_b, "
            "'privacy-rls-approval-b', 'Privacy dispatcher RLS acceptance B', 1, :preview_b, "
            "'executing', CAST('[]' AS json), CAST('{}' AS json), 1, :now)"
        ),
        {
            "manifest_a": manifest_a,
            "manifest_b": manifest_b,
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "principal": principal_id,
            "key_a": f"privacy-dispatch-a-{suffix}",
            "key_b": f"privacy-dispatch-b-{suffix}",
            "hash_a": "a" * 64,
            "hash_b": "b" * 64,
            "preview_a": "c" * 64,
            "preview_b": "d" * 64,
            "now": now,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_privacy_deletion_work_items "
            "(id, manifest_id, target_type, target_id, tenant_id, surface, disposition, "
            "resource_scope_hmac, adapter_type, status, attempt_count, max_attempts, "
            "available_at, lease_generation, replay_generation, version) VALUES "
            "(:work_a, :manifest_a, 'tenant', :tenant_a, :tenant_a, 'runs', 'delete', "
            ":scope_a, 'postgresql-acceptance', 'pending', 0, 8, :now, 0, 0, 1), "
            "(:work_b, :manifest_b, 'tenant', :tenant_b, :tenant_b, 'runs', 'delete', "
            ":scope_b, 'postgresql-acceptance', 'pending', 0, 8, :now, 0, 0, 1)"
        ),
        {
            "work_a": work_a,
            "work_b": work_b,
            "manifest_a": manifest_a,
            "manifest_b": manifest_b,
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "scope_a": "e" * 64,
            "scope_b": "f" * 64,
            "now": now,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_privacy_backup_retention_items "
            "(id, manifest_id, target_type, target_id, tenant_id, provider, "
            "backup_data_class, backup_locator_hmac, resource_handle_ref, "
            "catalog_snapshot_sha256, tombstone_sha256, purge_due_at, status, "
            "attempt_count, max_attempts, available_at, lease_generation, "
            "replay_generation, version) VALUES "
            "(:backup_a, :manifest_a, 'tenant', :tenant_a, :tenant_a, 'test-provider', "
            "'control_plane', :locator_a, :handle_a, :catalog_a, :tombstone_a, :purge_due, "
            "'retention_wait', 0, 8, :now, 0, 0, 1), "
            "(:backup_b, :manifest_b, 'tenant', :tenant_b, :tenant_b, 'test-provider', "
            "'control_plane', :locator_b, :handle_b, :catalog_b, :tombstone_b, :purge_due, "
            "'retention_wait', 0, 8, :now, 0, 0, 1)"
        ),
        {
            "backup_a": backup_a,
            "backup_b": backup_b,
            "manifest_a": manifest_a,
            "manifest_b": manifest_b,
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "locator_a": "1" * 64,
            "locator_b": "2" * 64,
            "handle_a": f"opaque-backup-a-{suffix}",
            "handle_b": f"opaque-backup-b-{suffix}",
            "catalog_a": "3" * 64,
            "catalog_b": "4" * 64,
            "tombstone_a": "5" * 64,
            "tombstone_b": "6" * 64,
            "purge_due": now + timedelta(hours=1),
            "now": now,
        },
    )


def test_real_postgresql_privacy_dispatcher_is_exact_content_blind_and_immutable() -> None:
    root = Path(__file__).resolve().parents[2]
    base_url = sa.engine.make_url(_postgres_url())
    suffix = uuid4().hex[:12]
    database_name = f"omnigent_privacy_dispatch_{suffix}"
    dispatcher_login_role = f"privacy_dispatch_login_{suffix}"
    verifier_login_role = f"privacy_verify_login_{suffix}"
    dispatcher_login_password = f"privacy-dispatch-{uuid4().hex}"
    verifier_login_password = f"privacy-verify-{uuid4().hex}"
    database_url = base_url.set(database=database_name)
    dispatcher_url = database_url.set(
        username=dispatcher_login_role, password=dispatcher_login_password
    )
    verifier_url = database_url.set(username=verifier_login_role, password=verifier_login_password)

    admin_engine = sa.create_engine(base_url, isolation_level="AUTOCOMMIT")
    owner_engine: sa.Engine | None = None
    dispatcher_engine: sa.Engine | None = None
    verifier_engine: sa.Engine | None = None
    database_created = False

    principal_id = uuid4()
    tenant_a, tenant_b = uuid4(), uuid4()
    manifest_a, manifest_b = uuid4(), uuid4()
    work_a, work_b = uuid4(), uuid4()
    backup_a, backup_b = uuid4(), uuid4()
    attempt_a, attestation_a = uuid4(), uuid4()
    now = datetime.now(timezone.utc)

    try:
        with admin_engine.connect() as connection:
            server_version = connection.exec_driver_sql("SHOW server_version_num").scalar_one()
            assert int(server_version) >= 180000
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
        database_created = True

        owner_engine = sa.create_engine(database_url, pool_pre_ping=True)
        with owner_engine.begin() as connection:
            _migrate(connection, root)
            role_authority_sql = (root / "saas/control_plane/postgresql_roles.sql").read_text(
                encoding="utf-8"
            )
            connection.exec_driver_sql(role_authority_sql)
            connection.exec_driver_sql(role_authority_sql)
        with owner_engine.begin() as connection:
            assert (
                connection.execute(
                    sa.text("SELECT version_num FROM saas_alembic_version")
                ).scalar_one()
                == "pc5a00000004"
            )
            connection.exec_driver_sql(
                f'CREATE ROLE "{dispatcher_login_role}" LOGIN PASSWORD '
                f"'{dispatcher_login_password}' "
                "NOSUPERUSER NOBYPASSRLS INHERIT"
            )
            connection.exec_driver_sql(
                f'GRANT saas_privacy_dispatcher TO "{dispatcher_login_role}"'
            )
            connection.exec_driver_sql(
                f'CREATE ROLE "{verifier_login_role}" LOGIN PASSWORD '
                f"'{verifier_login_password}' "
                "NOSUPERUSER NOBYPASSRLS INHERIT"
            )
            connection.exec_driver_sql(f'GRANT saas_privacy_verifier TO "{verifier_login_role}"')
        with owner_engine.begin() as connection:
            _seed_privacy_execution(
                connection,
                principal_id=principal_id,
                tenant_a=tenant_a,
                tenant_b=tenant_b,
                manifest_a=manifest_a,
                manifest_b=manifest_b,
                work_a=work_a,
                work_b=work_b,
                backup_a=backup_a,
                backup_b=backup_b,
                suffix=suffix,
                now=now,
            )

        with owner_engine.begin() as connection:
            role_attributes = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolbypassrls, rolinherit "
                    "FROM pg_roles WHERE rolname = :role"
                ),
                {"role": dispatcher_login_role},
            ).one()
            assert role_attributes == (True, False, False, True)
            assert connection.execute(
                sa.text("SELECT pg_has_role(:role, 'saas_privacy_dispatcher', 'member')"),
                {"role": dispatcher_login_role},
            ).scalar_one()
            for forbidden_role in ("saas_platform_governance", "saas_privacy_executor"):
                assert not connection.execute(
                    sa.text("SELECT pg_has_role(:role, :forbidden, 'member')"),
                    {"role": dispatcher_login_role, "forbidden": forbidden_role},
                ).scalar_one()
                assert not connection.execute(
                    sa.text("SELECT pg_has_role('saas_privacy_dispatcher', :forbidden, 'member')"),
                    {"forbidden": forbidden_role},
                ).scalar_one()

            rls_rows = connection.execute(
                sa.text(
                    "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relname IN ('saas_privacy_deletion_work_items', "
                    "'saas_privacy_deletion_attempts', "
                    "'saas_privacy_evidence_attestations', "
                    "'saas_privacy_backup_retention_items')"
                )
            ).all()
            assert {row[0] for row in rls_rows} == {
                "saas_privacy_deletion_work_items",
                "saas_privacy_deletion_attempts",
                "saas_privacy_evidence_attestations",
                "saas_privacy_backup_retention_items",
            }
            assert all(row[1] and row[2] for row in rls_rows)

            for pii_table in (
                "saas_global_users",
                "saas_identity_connections",
                "saas_password_credentials",
            ):
                assert not connection.execute(
                    sa.text("SELECT has_table_privilege(:role, :table_name, 'SELECT')"),
                    {"role": dispatcher_login_role, "table_name": pii_table},
                ).scalar_one()
            for protected_table in (
                "saas_privacy_deletion_work_items",
                "saas_privacy_deletion_attempts",
                "saas_privacy_evidence_attestations",
                "saas_privacy_backup_retention_items",
            ):
                assert not connection.execute(
                    sa.text("SELECT has_table_privilege(:role, :table_name, 'DELETE')"),
                    {"role": dispatcher_login_role, "table_name": protected_table},
                ).scalar_one()

        dispatcher_engine = sa.create_engine(dispatcher_url, pool_pre_ping=True)
        verifier_engine = sa.create_engine(verifier_url, pool_pre_ping=True)
        verify_privacy_worker_database_role(dispatcher_engine, authority="dispatcher")
        verify_privacy_worker_database_role(verifier_engine, authority="verifier")
        with pytest.raises(RuntimeError):
            verify_privacy_worker_database_role(owner_engine)
        with dispatcher_engine.begin() as connection:
            assert (
                connection.exec_driver_sql("SELECT current_user").scalar_one()
                == dispatcher_login_role
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_privacy_deletion_work_items")
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_privacy_backup_retention_items")
                ).scalar_one()
                == 0
            )
        with verifier_engine.begin() as connection:
            assert (
                connection.exec_driver_sql("SELECT current_user").scalar_one()
                == verifier_login_role
            )
            _set_dispatch_scope(connection, tenant_id=tenant_a, manifest_id=manifest_a)
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_privacy_deletion_work_items")
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_privacy_backup_retention_items")
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(principal_id) FROM saas_platform_role_assignments")
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(principal_id) FROM saas_platform_support_sessions")
                ).scalar_one()
                == 0
            )

        _assert_sqlstate(
            dispatcher_engine,
            "SELECT count(*) FROM saas_global_users",
            {},
            expected_sqlstate="42501",
        )

        with dispatcher_engine.begin() as connection:
            _set_dispatch_scope(connection, tenant_id=tenant_a, manifest_id=manifest_a)
            assert set(
                connection.execute(
                    sa.text("SELECT id FROM saas_privacy_deletion_work_items ORDER BY id")
                ).scalars()
            ) == {work_a}
            assert set(
                connection.execute(
                    sa.text("SELECT id FROM saas_privacy_backup_retention_items ORDER BY id")
                ).scalars()
            ) == {backup_a}
            assert (
                connection.execute(
                    sa.text(
                        "SELECT count(*) FROM saas_privacy_deletion_work_items WHERE id = :work_b"
                    ),
                    {"work_b": work_b},
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    sa.text(
                        "SELECT count(*) FROM saas_privacy_backup_retention_items "
                        "WHERE id = :backup_b"
                    ),
                    {"backup_b": backup_b},
                ).scalar_one()
                == 0
            )

            work_result = connection.execute(
                sa.text(
                    "UPDATE saas_privacy_deletion_work_items "
                    "SET status = 'leased', attempt_count = 1, leased_at = :leased_at, "
                    "lease_expires_at = :lease_expires_at, lease_token_hash = :token_hash, "
                    "executor_identity_sha256 = :executor_hash, lease_generation = 1, "
                    "version = version + 1 WHERE id = :id"
                ),
                {
                    "leased_at": now,
                    "lease_expires_at": now + timedelta(minutes=5),
                    "token_hash": "7" * 64,
                    "executor_hash": "8" * 64,
                    "id": work_a,
                },
            )
            hidden_work_result = connection.execute(
                sa.text(
                    "UPDATE saas_privacy_deletion_work_items "
                    "SET available_at = :available_at WHERE id = :id"
                ),
                {"available_at": now + timedelta(minutes=2), "id": work_b},
            )
            hidden_backup_result = connection.execute(
                sa.text(
                    "UPDATE saas_privacy_backup_retention_items "
                    "SET available_at = :available_at WHERE id = :id"
                ),
                {"available_at": now + timedelta(minutes=2), "id": backup_b},
            )
            assert work_result.rowcount == 1
            assert hidden_work_result.rowcount == 0
            assert hidden_backup_result.rowcount == 0

        _assert_sqlstate(
            dispatcher_engine,
            "INSERT INTO saas_privacy_evidence_attestations (id) VALUES (:id)",
            {"id": uuid4()},
            expected_sqlstate="42501",
        )
        _assert_sqlstate(
            verifier_engine,
            "UPDATE saas_privacy_deletion_work_items SET version = version + 1 WHERE id = :id",
            {"id": work_a},
            expected_sqlstate="42501",
        )
        _assert_sqlstate(
            verifier_engine,
            "INSERT INTO saas_privacy_deletion_attempts (id) VALUES (:id)",
            {"id": uuid4()},
            expected_sqlstate="42501",
        )
        _assert_sqlstate(
            verifier_engine,
            "INSERT INTO saas_control_plane_outbox (id) VALUES (:id)",
            {"id": uuid4()},
            expected_sqlstate="42501",
        )

        with dispatcher_engine.connect() as connection:
            transaction = connection.begin()
            _set_dispatch_scope(connection, tenant_id=tenant_a, manifest_id=manifest_a)
            with pytest.raises(DBAPIError) as missing_receipt:
                connection.execute(
                    sa.text(
                        "UPDATE saas_privacy_deletion_work_items SET status = 'succeeded', "
                        "outcome_content_sha256 = :payload_hash, "
                        "evidence_attestation_id = :attestation_id, leased_at = NULL, "
                        "lease_expires_at = NULL, lease_token_hash = NULL, "
                        "executor_identity_sha256 = NULL, version = version + 1 "
                        "WHERE id = :id"
                    ),
                    {
                        "payload_hash": "a" * 64,
                        "attestation_id": uuid4(),
                        "id": work_a,
                    },
                )
            transaction.rollback()
        assert getattr(missing_receipt.value.orig, "sqlstate", None) == "55000"

        payload_hash = "a" * 64
        envelope: dict[str, object] = {}
        envelope_hash = sha256(canonical_json(envelope)).hexdigest()
        observed_at = now
        signed_at = now + timedelta(seconds=1)
        verified_at = now + timedelta(seconds=2)
        artifact_uri = f"s3://immutable-privacy-evidence/{attestation_a}.dsse.json"
        receipt_facts = {
            "schema_version": 1,
            "attestation_id": str(attestation_a),
            "manifest_id": str(manifest_a),
            "target_type": "tenant",
            "target_id": str(tenant_a),
            "subject_kind": "surface",
            "subject_id": str(work_a),
            "execution_attempt_id": str(attempt_a),
            "attempt_number": 1,
            "lease_generation": 1,
            "replay_generation": 0,
            "surface": "runs",
            "payload_sha256": payload_hash,
            "envelope_sha256": envelope_hash,
            "artifact_uri": artifact_uri,
            "immutability_receipt_sha256": "c" * 64,
            "kms_audit_receipt_sha256": "d" * 64,
            "signer_key_id": "privacy-test-key",
            "workflow_identity": "spiffe://prod/privacy-verifier",
            "observed_at": observed_at.isoformat(),
            "signed_at": signed_at.isoformat(),
            "verified_at": verified_at.isoformat(),
            "verifier_policy_version": "privacy-dsse-v1",
        }
        verifier_receipt = privacy_verifier_receipt_sha256(receipt_facts)

        with dispatcher_engine.begin() as connection:
            _set_dispatch_scope(connection, tenant_id=tenant_a, manifest_id=manifest_a)
            connection.execute(
                sa.text(
                    "INSERT INTO saas_privacy_deletion_attempts "
                    "(id, work_item_id, manifest_id, target_type, target_id, tenant_id, "
                    "surface, attempt_number, lease_generation, replay_generation, "
                    "provider_idempotency_sha256, executor_identity_sha256, outcome, "
                    "error_code, error_sha256, evidence_payload_sha256, started_at, "
                    "completed_at) VALUES "
                    "(:id, :work, :manifest, 'tenant', :tenant, :tenant, 'runs', 1, 1, 0, "
                    ":provider_hash, :executor_hash, 'succeeded', NULL, NULL, "
                    ":payload_hash, :started_at, :completed_at)"
                ),
                {
                    "id": attempt_a,
                    "work": work_a,
                    "manifest": manifest_a,
                    "tenant": tenant_a,
                    "provider_hash": "7" * 64,
                    "executor_hash": "8" * 64,
                    "payload_hash": payload_hash,
                    "started_at": now,
                    "completed_at": verified_at,
                },
            )

        with verifier_engine.begin() as connection:
            _set_dispatch_scope(connection, tenant_id=tenant_a, manifest_id=manifest_a)
            connection.execute(
                sa.text(
                    "INSERT INTO saas_privacy_evidence_attestations "
                    "(id, manifest_id, target_type, target_id, tenant_id, subject_kind, "
                    "subject_id, execution_attempt_id, attempt_number, lease_generation, "
                    "replay_generation, surface, payload_type, payload_sha256, envelope_sha256, "
                    "envelope, "
                    "envelope_uri, immutability_receipt_sha256, kms_audit_receipt_sha256, "
                    "signature_algorithm, signer_key_id, workflow_identity, product_revision, "
                    "upstream_revision, schema_revision, adapter_contract_version, "
                    "verifier_policy_version, verifier_receipt_sha256, observed_at, signed_at, "
                    "verified_at) VALUES "
                    "(:id, :manifest, 'tenant', :tenant, :tenant, 'surface', :subject, "
                    ":attempt_id, 1, 1, 0, 'runs', 'application/vnd.in-toto+json', "
                    ":payload_hash, :envelope_hash, CAST(:envelope AS json), :uri, "
                    ":immutable_hash, :kms_hash, 'ed25519', 'privacy-test-key', "
                    "'spiffe://prod/privacy-verifier', :product_revision, "
                    ":upstream_revision, 'pc5b00000003', 'privacy-adapter-v1', "
                    "'privacy-dsse-v1', :verifier_receipt, :observed_at, :signed_at, "
                    ":verified_at)"
                ),
                {
                    "id": attestation_a,
                    "manifest": manifest_a,
                    "tenant": tenant_a,
                    "subject": work_a,
                    "attempt_id": attempt_a,
                    "payload_hash": payload_hash,
                    "envelope_hash": envelope_hash,
                    "envelope": "{}",
                    "uri": artifact_uri,
                    "immutable_hash": "c" * 64,
                    "kms_hash": "d" * 64,
                    "product_revision": "e" * 40,
                    "upstream_revision": "f" * 40,
                    "verifier_receipt": verifier_receipt,
                    "observed_at": observed_at,
                    "signed_at": signed_at,
                    "verified_at": verified_at,
                },
            )

        with dispatcher_engine.begin() as connection:
            _set_dispatch_scope(
                connection,
                tenant_id=tenant_a,
                manifest_id=manifest_a,
                locator_hash="e" * 64,
            )
            completion_result = connection.execute(
                sa.text(
                    "UPDATE saas_privacy_deletion_work_items SET status = 'succeeded', "
                    "outcome_content_sha256 = :payload_hash, "
                    "evidence_attestation_id = :attestation_id, leased_at = NULL, "
                    "lease_expires_at = NULL, lease_token_hash = NULL, "
                    "executor_identity_sha256 = NULL, version = version + 1 "
                    "WHERE id = :id"
                ),
                {
                    "payload_hash": payload_hash,
                    "attestation_id": attestation_a,
                    "id": work_a,
                },
            )
            assert completion_result.rowcount == 1
            outbox_result = connection.execute(
                _OUTBOX_INSERT,
                {
                    "id": uuid4(),
                    "tenant_id": tenant_a,
                    "aggregate_key": str(manifest_a),
                    "event_type": "privacy.execution.work_succeeded",
                    "manifest_id": str(manifest_a),
                    "target_locator_hmac": "e" * 64,
                    "item_id": str(work_a),
                    "attempt_id": str(attempt_a),
                    "attempt_number": 1,
                    "replay_generation": 0,
                    "surface": "runs",
                    "status": "succeeded",
                    "content_sha256": payload_hash,
                    "error_code": None,
                    "available_at": None,
                    "idempotency_key": f"privacy-execution-outbox-{suffix}",
                    "request_hash": "f" * 64,
                },
            )
            assert outbox_result.rowcount == 1
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_privacy_deletion_attempts")
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_privacy_evidence_attestations")
                ).scalar_one()
                == 1
            )

        with dispatcher_engine.connect() as connection:
            transaction = connection.begin()
            _set_dispatch_scope(connection, tenant_id=tenant_a, manifest_id=manifest_a)
            with pytest.raises(DBAPIError) as captured:
                connection.execute(
                    sa.text(
                        "INSERT INTO saas_privacy_deletion_attempts "
                        "(id, work_item_id, manifest_id, target_type, target_id, tenant_id, "
                        "surface, attempt_number, lease_generation, replay_generation, "
                        "provider_idempotency_sha256, executor_identity_sha256, outcome, "
                        "error_code, error_sha256, started_at, completed_at) VALUES "
                        "(:id, :work, :manifest, 'tenant', :tenant, :tenant, 'runs', 1, 1, 0, "
                        ":provider_hash, :executor_hash, 'retry', 'provider_unavailable', "
                        ":error_hash, :started_at, :completed_at)"
                    ),
                    {
                        "id": uuid4(),
                        "work": work_b,
                        "manifest": manifest_b,
                        "tenant": tenant_b,
                        "provider_hash": "0" * 64,
                        "executor_hash": "1" * 64,
                        "error_hash": "2" * 64,
                        "started_at": now,
                        "completed_at": now + timedelta(seconds=1),
                    },
                )
            transaction.rollback()
        assert getattr(captured.value.orig, "sqlstate", None) == "42501"

        _assert_outbox_insert_denied(
            dispatcher_engine,
            scope_tenant_id=tenant_a,
            scope_manifest_id=manifest_a,
            values={
                "id": uuid4(),
                "tenant_id": tenant_a,
                "aggregate_key": str(manifest_a),
                "event_type": "privacy.execution.untrusted_event",
                "manifest_id": str(manifest_a),
                "target_locator_hmac": "e" * 64,
                "item_id": str(work_a),
                "attempt_id": str(attempt_a),
                "attempt_number": 1,
                "replay_generation": 0,
                "surface": "runs",
                "status": "retry",
                "content_sha256": "0" * 64,
                "error_code": "provider_unavailable",
                "available_at": now.isoformat(),
                "idempotency_key": f"privacy-untrusted-outbox-{suffix}",
                "request_hash": "1" * 64,
            },
        )
        _assert_outbox_insert_denied(
            dispatcher_engine,
            scope_tenant_id=tenant_a,
            scope_manifest_id=manifest_a,
            values={
                "id": uuid4(),
                "tenant_id": tenant_b,
                "aggregate_key": str(manifest_b),
                "event_type": "privacy.execution.work_retry_scheduled",
                "manifest_id": str(manifest_b),
                "target_locator_hmac": "f" * 64,
                "item_id": str(work_b),
                "attempt_id": str(uuid4()),
                "attempt_number": 1,
                "replay_generation": 0,
                "surface": "runs",
                "status": "retry",
                "content_sha256": "2" * 64,
                "error_code": "provider_unavailable",
                "available_at": now.isoformat(),
                "idempotency_key": f"privacy-cross-outbox-{suffix}",
                "request_hash": "3" * 64,
            },
        )

        with dispatcher_engine.begin() as connection:
            _set_dispatch_scope(connection, tenant_id=tenant_a, manifest_id=manifest_b)
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_privacy_deletion_work_items")
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_privacy_backup_retention_items")
                ).scalar_one()
                == 0
            )

        owner_sessions = sessionmaker(owner_engine, expire_on_commit=False)
        race_at = now + timedelta(minutes=2)
        execution = PrivacyExecutionService(
            owner_sessions,
            verifier_session_factory=owner_sessions,
            verifier=PrivacyAttestationVerifier(()),
            policy=PrivacyExecutionPolicy(
                audience="omnigent:privacy-execution",
                trusted_issuers=frozenset({"https://workload-id.example.test"}),
                product_revision="a" * 40,
                upstream_revision="b" * 40,
                schema_revision="pc5b00000003",
                adapter_contract_version="privacy-adapter.v1",
                verifier_policy_version="privacy-hold-fence-v1",
            ),
            locator_hmac_key=b"h" * 32,
        )
        lifecycle = PrivacyLifecycleService(
            owner_sessions,
            evidence_verifier=DeletionEvidenceKey("hold-fence-test", b"e" * 32),
        )
        workload = WorkloadIdentity(
            issuer="https://workload-id.example.test",
            subject="spiffe://prod/privacy-hold-race",
            audience="omnigent:privacy-execution",
            authenticated_at=race_at - timedelta(minutes=1),
            expires_at=race_at + timedelta(hours=1),
        )
        actor = ValidatedPlatformPrincipal(
            session_id=uuid4(),
            principal_id=principal_id,
            security_version=1,
            authn_method="passkey",
            authenticated_at=race_at,
            expires_at=race_at + timedelta(hours=1),
            roles=frozenset({"compliance_operator"}),
            permissions=PLATFORM_ROLE_PERMISSIONS["compliance_operator"],
        )
        barrier = Barrier(2)

        def _race_claim() -> object:
            barrier.wait()
            return execution.claim_work_item(
                workload,
                target_type="tenant",
                target_id=tenant_b,
                manifest_id=manifest_b,
                now=race_at,
            )

        def _race_hold() -> object:
            barrier.wait()
            try:
                return lifecycle.place_legal_hold(
                    actor,
                    target_type="tenant",
                    target_id=tenant_b,
                    scope=("all",),
                    authority_ref=f"race-{suffix}",
                    reason="PostgreSQL claim and Hold serialization acceptance",
                    review_due_at=race_at + timedelta(days=30),
                    now=race_at,
                )
            except PlatformSecurityError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as pool:
            claim_result = pool.submit(_race_claim)
            hold_result = pool.submit(_race_hold)
            claim_value = claim_result.result(timeout=10)
            hold_value = hold_result.result(timeout=10)
        if claim_value is None:
            assert not isinstance(hold_value, PlatformSecurityError)
        else:
            assert isinstance(hold_value, PlatformSecurityError)
            assert hold_value.code == "platform_privacy_hold_execution_in_progress"

        assert owner_engine is not None
        _assert_sqlstate(
            owner_engine,
            "UPDATE saas_privacy_deletion_attempts SET error_code = 'mutated' WHERE id = :id",
            {"id": attempt_a},
            expected_sqlstate="55000",
            role="saas_platform",
        )
        _assert_sqlstate(
            owner_engine,
            "DELETE FROM saas_privacy_evidence_attestations WHERE id = :id",
            {"id": attestation_a},
            expected_sqlstate="55000",
            role="saas_platform",
        )
        _assert_sqlstate(
            owner_engine,
            "DELETE FROM saas_privacy_deletion_work_items WHERE id = :id",
            {"id": work_a},
            expected_sqlstate="55000",
            role="saas_platform",
        )
        _assert_sqlstate(
            owner_engine,
            "DELETE FROM saas_privacy_backup_retention_items WHERE id = :id",
            {"id": backup_a},
            expected_sqlstate="55000",
            role="saas_platform",
        )
    finally:
        if verifier_engine is not None:
            verifier_engine.dispose()
        if dispatcher_engine is not None:
            dispatcher_engine.dispose()
        if owner_engine is not None:
            owner_engine.dispose()
        with admin_engine.connect() as connection:
            if database_created:
                connection.exec_driver_sql(
                    f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)'
                )
            connection.exec_driver_sql(f'DROP ROLE IF EXISTS "{dispatcher_login_role}"')
            connection.exec_driver_sql(f'DROP ROLE IF EXISTS "{verifier_login_role}"')
        admin_engine.dispose()
